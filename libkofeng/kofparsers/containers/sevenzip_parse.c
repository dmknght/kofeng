/*
 * sevenzip_parse.c - the 7z container, structure only.
 *
 * A fixed 32 byte header at the front that points at a variable header at the back,
 * with the coded streams in between. Three fields matter and all three are in the
 * front header: where the back header is, how large it is, and - once you look at
 * its first bytes - what was done to it.
 *
 *
 * WHY THIS STOPS WHERE IT DOES
 *
 * Because the file list is compressed. Measured over 44 real archives, 43 put their
 * header through a coder, so reading a single filename means running a decoder over
 * it first. This parse does not: identifying an object must not cost the
 * decompression of it, and a parser that decoded here would be one that decodes on
 * every file that happens to start with six bytes.
 *
 * What it does instead is answer the question that can be answered for nothing and
 * is worth more than the names: IS THIS READABLE AT ALL. 19 of those 44 encrypt the
 * header, and the coder id that says so sits in the clear at the front of the coded
 * header - four bytes, no decoding. An archive whose file list is ciphertext must
 * not come back clean, and that verdict is available here.
 *
 *
 * READING THE CODER ID WITHOUT DECODING ANYTHING
 *
 * The coded header opens with a PackInfo and an UnPackInfo describing how the
 * header itself was stored, and those are NOT coded - they cannot be, since they
 * are what tells a reader how to decode. So the walk below steps through them with
 * the format's variable length number encoding and stops at the first coder id.
 *
 * Every step is bounded against the object and against a step count, because this
 * is a structure read out of an untrusted file and the numbers in it decide how far
 * the cursor moves.
 */

#include "sevenzip_parse.h"
#include "../runlist.h"
#include "../../kofdecomp/lzma.h"

#include <string.h>

static const uint8_t SEVENZ_SIG[6] = { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c };

#define S_MAJOR      6u
#define S_MINOR      7u
#define S_NEXT_OFF   12u
#define S_NEXT_SIZE  20u

/* How far the small walk into the coded header may go. It only has to cross a
 * PackInfo and reach the first coder id; anything longer is a file describing
 * something other than its own header. */
#define HDR_PROBE_STEPS 64u

/*
 * The format's variable length number.
 *
 * The high bits of the first byte say how many bytes follow; what is left of that
 * byte is the top of the value. Returns zero and clears `ok` when the object ends
 * inside it, which is the only way this can fail.
 */
static uint64_t sz_num(kof_buf f, uint64_t *at, int *ok)
{
	uint8_t first = 0, b = 0;
	uint64_t v = 0;
	uint32_t i, mask = 0x80;

	*ok = 0;
	if (!kof_rd_u8(f, *at, &first))
		return 0;
	(*at)++;
	for (i = 0; i < 8; i++) {
		if (!(first & mask)) {
			v += (uint64_t)(first & (mask - 1u)) << (8u * i);
			*ok = 1;
			return v;
		}
		if (!kof_rd_u8(f, *at, &b))
			return 0;
		(*at)++;
		v |= (uint64_t)b << (8u * i);
		mask >>= 1;
	}
	*ok = 1;
	return v;
}

/*
 * Everything the coded header states about itself, in the clear.
 *
 * A 7z opens its coded header with a PackInfo and an UnPackInfo describing how that
 * header was stored, and those two cannot themselves be coded - they are what tells
 * a reader how to decode. So this walk reads: where the coded bytes are, how many
 * there are, what coder made them, its properties, and how long the result will be.
 *
 * That is exactly the set a decoder needs, which is why it is gathered here rather
 * than in the module: the walk is fiddly and format specific, and a module that had
 * to do it would be a second implementation of a variable length number decoder
 * inside a blob with no writable data.
 *
 * Every step is bounded against the object and against a step count, because this is
 * a structure read out of an untrusted file and the numbers in it decide how far the
 * cursor moves.
 */
static void hdr_probe(kof_buf f, uint64_t at, uint64_t end, struct kof_7z_info *z)
{
	uint64_t n_pack = 0, pack_pos = 0, pack_size = 0;
	uint32_t steps = 0, coder = 0;
	uint8_t id = 0, flags = 0;
	int ok;

	if (!kof_rd_u8(f, at, &id))
		return;
	at++;

	if (id == KOF_7Z_ID_PACKINFO) {
		pack_pos = sz_num(f, &at, &ok);
		if (!ok)
			return;
		n_pack = sz_num(f, &at, &ok);
		if (!ok || n_pack == 0 || n_pack > 4096u)
			return;
		for (;;) {
			if (++steps > HDR_PROBE_STEPS || at >= end)
				return;
			if (!kof_rd_u8(f, at, &id))
				return;
			at++;
			if (id == KOF_7Z_ID_END)
				break;
			if (id == KOF_7Z_ID_SIZE) {
				uint64_t k;

				for (k = 0; k < n_pack; k++) {
					uint64_t v = sz_num(f, &at, &ok);

					if (!ok)
						return;
					if (k == 0)
						pack_size = v;
				}
			}
		}
		if (!kof_rd_u8(f, at, &id))
			return;
		at++;
	}

	if (id != KOF_7Z_ID_UNPACK)
		return;
	if (!kof_rd_u8(f, at, &id) || id != KOF_7Z_ID_FOLDER)
		return;
	at++;

	sz_num(f, &at, &ok);                          /* numFolders */
	if (!ok)
		return;
	at++;                                         /* external */
	sz_num(f, &at, &ok);                          /* numCoders */
	if (!ok)
		return;
	if (!kof_rd_u8(f, at, &flags))
		return;
	at++;

	{
		uint32_t len = flags & 0x0fu, i;
		uint8_t c;

		if (len == 0 || len > 4u)
			return;
		for (i = 0; i < len; i++) {
			if (!kof_rd_u8(f, at + i, &c))
				return;
			coder = (coder << 8) | c;
		}
		at += len;
	}
	z->hdr_coder = coder;

	/*
	 * The coder's properties. For LZMA that is one packed byte holding lc, lp and
	 * pb, then a dictionary size this engine does not need - its decoder sizes its
	 * own window from the output buffer.
	 */
	if (flags & 0x20u) {
		uint64_t plen = sz_num(f, &at, &ok);
		uint8_t d;

		if (!ok)
			return;
		if (coder == KOF_7Z_CODER_LZMA && plen >= 1u &&
		    kof_rd_u8(f, at, &d)) {
			z->hdr_lc = (uint8_t)(d % 9u);
			z->hdr_lp = (uint8_t)((d / 9u) % 5u);
			z->hdr_pb = (uint8_t)(d / 45u);
			if (z->hdr_lc > KOF_LZMA_MAX_LC ||
			    z->hdr_lp > KOF_LZMA_MAX_LP ||
			    z->hdr_pb > KOF_LZMA_MAX_PB) {
				z->anomalies |= KOF_7Z_ANOM_UNKNOWN_CODER;
				return;
			}
		}
		at += plen;
	}

	/* kCodersUnPackSize: how long the decode will be. Bounded search, because
	 * anything between here and it is a property this does not need. */
	for (;;) {
		if (++steps > HDR_PROBE_STEPS || at >= end)
			return;
		if (!kof_rd_u8(f, at, &id))
			return;
		at++;
		if (id == KOF_7Z_ID_CODERS_SIZE)
			break;
		if (id == KOF_7Z_ID_END)
			return;
	}
	z->hdr_unpack_size = sz_num(f, &at, &ok);
	if (!ok) {
		z->hdr_unpack_size = 0;
		return;
	}

	/*
	 * Where the coded bytes are. packPos is stated from the end of the signature
	 * header, like everything else in this format, and both it and the size come
	 * out of the file - so the sum saturates and the caller checks it.
	 */
	z->hdr_pack_off = kof_sat_add(KOF_7Z_SIG_LEN, pack_pos);
	z->hdr_pack_size = pack_size;
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t sz_cls_bit[KOF_7Z_CLS_COUNT] = {
	KOF_SCAN_7Z_HEADERS,
	KOF_SCAN_7Z_PACKED
};

/*
 * The archive's whole layout, as settled runs.
 *
 * One function so the per-class totals the parse records and the ranges the resolve
 * hands out can never describe the object differently.
 */
static void sz_runs(const struct kof_7z_info *z, uint64_t obj_size,
		    struct kof_runs *l, struct kof_run *buf, uint64_t *bytes)
{
	kof_runs_init(l, buf, 3u, KOF_7Z_CLS_COUNT);
	kof_runs_add(l, obj_size, 0, KOF_7Z_SIG_LEN, KOF_7Z_CLS_HEADERS);
	if (z->next_hdr_size && z->next_hdr_off > KOF_7Z_SIG_LEN)
		kof_runs_add(l, obj_size, KOF_7Z_SIG_LEN,
			     z->next_hdr_off - KOF_7Z_SIG_LEN, KOF_7Z_CLS_PACKED);
	if (z->next_hdr_size)
		kof_runs_add(l, obj_size, z->next_hdr_off, z->next_hdr_size,
			     KOF_7Z_CLS_HEADERS);
	kof_runs_settle(l, bytes);
}

static uint32_t sz_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				struct kof_range *out, uint32_t max_out)
{
	const struct kof_7z_info *z = (const struct kof_7z_info *)ctx->file_header;
	struct kof_run run[3];
	struct kof_runs l;
	uint64_t bytes[KOF_7Z_CLS_COUNT];

	if (!z || !z->valid || !out || max_out == 0)
		return 0;

	/*
	 * Three runs at most, so they are built here rather than kept in the view.
	 * The other containers store theirs because a walk discovered them one at a
	 * time and there is no second chance to work them out; here the whole layout
	 * is four numbers from the start header.
	 *
	 * They go through the same add-and-settle the parse uses, and that is not
	 * ceremony for three runs. The offsets are fields a file chose, so nothing
	 * stops a header claiming to live INSIDE the start header - and then the
	 * third run overlaps the first, in an order the resolve's complement walk
	 * reads as descending. Building them by hand skipped the settle, and a
	 * hostile-header fuzz round found it: overlapping regions mean a pattern
	 * matched twice in bytes that exist once.
	 */
	sz_runs(z, ctx->obj_size, &l, run, bytes);
	return kof_runs_resolve(l.v, l.n, mask, sz_cls_bit, KOF_SCAN_7Z_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_7z_sniff(kof_buf file)
{
	return file.n >= sizeof SEVENZ_SIG &&
	       memcmp(file.p, SEVENZ_SIG, sizeof SEVENZ_SIG) == 0;
}

int kof_7z_parse(kof_buf file, struct kof_7z_info *z, struct kof_obj_ctx *ctx)
{
	struct kof_runs l;
	struct kof_run run[3];
	uint64_t off = 0, size = 0;
	uint8_t first = 0;

	memset(z, 0, sizeof *z);
	z->version = KOF_7Z_INFO_VERSION;

	if (!kof_7z_sniff(file))
		return 0;
	z->valid = 1;
	z->header_kind = KOF_7Z_HDR_MISSING;

	if (!kof_rd_u8(file, S_MAJOR, &z->major) ||
	    !kof_rd_u8(file, S_MINOR, &z->minor) ||
	    !kof_rd_u64(file, S_NEXT_OFF, 0, &off) ||
	    !kof_rd_u64(file, S_NEXT_SIZE, 0, &size)) {
		z->anomalies |= KOF_7Z_ANOM_BAD_START;
		goto done;
	}
	if (z->major != 0)
		z->anomalies |= KOF_7Z_ANOM_BAD_VERSION;

	/*
	 * Both fields are stated relative to the END of the start header, and both
	 * come out of the file - so the sum is saturating and the result is checked
	 * against the object rather than believed.
	 */
	z->next_hdr_off = kof_sat_add(KOF_7Z_SIG_LEN, off);
	z->next_hdr_size = size;

	if (size == 0) {
		z->anomalies |= KOF_7Z_ANOM_HDR_EMPTY;
		goto done;
	}
	if (kof_clip_len(file.n, z->next_hdr_off, size) != size) {
		z->anomalies |= KOF_7Z_ANOM_HDR_PAST_EOF;
		goto done;
	}

	if (!kof_rd_u8(file, z->next_hdr_off, &first))
		goto done;

	if (first == KOF_7Z_ID_HEADER) {
		z->header_kind = KOF_7Z_HDR_PLAIN;
	} else if (first == KOF_7Z_ID_ENCODED) {
		hdr_probe(file, z->next_hdr_off + 1, z->next_hdr_off + size, z);
		if (z->hdr_pack_size &&
		    kof_clip_len(file.n, z->hdr_pack_off, z->hdr_pack_size) !=
		    z->hdr_pack_size) {
			/* The archive says its own header is somewhere the file does
			 * not reach. Cleared rather than clamped: a module handed a
			 * short range would decode whatever happens to be there. */
			z->hdr_pack_off = 0;
			z->hdr_pack_size = 0;
			z->anomalies |= KOF_7Z_ANOM_HDR_PAST_EOF;
		}
		if (z->hdr_coder == KOF_7Z_CODER_AES) {
			/*
			 * Not merely compressed: the file list is ciphertext. No
			 * build of this engine will read it, which is a different
			 * answer from "this build lacks a decoder" and is why the
			 * two are separate kinds.
			 */
			z->header_kind = KOF_7Z_HDR_ENCRYPTED;
			z->anomalies |= KOF_7Z_ANOM_ENCRYPTED;
		} else {
			z->header_kind = KOF_7Z_HDR_CODED;
			if (z->hdr_coder != KOF_7Z_CODER_LZMA &&
			    z->hdr_coder != KOF_7Z_CODER_LZMA2 &&
			    z->hdr_coder != KOF_7Z_CODER_COPY)
				z->anomalies |= KOF_7Z_ANOM_UNKNOWN_CODER;
		}
	} else {
		z->anomalies |= KOF_7Z_ANOM_UNKNOWN_CODER;
	}

done:
	/* The same three runs the resolve builds - the same call, so they cannot
	 * differ - settled once so the per-class totals are available to a module
	 * without resolving anything. */
	sz_runs(z, file.n, &l, run, z->region_bytes);
	if (l.overlapped)
		z->anomalies |= KOF_7Z_ANOM_OVERLAP;

	ctx->format = KOF_FMT_7Z;
	ctx->obj_size = file.n;
	ctx->file_header = z;
	ctx->resolve_scan = sz_resolve_scan;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define SZ_REGIONS(X)          \
	X(KOF_SCAN_7Z_HEADERS)   \
	X(KOF_SCAN_7Z_PACKED)    \
	X(KOF_SCAN_7Z_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_7z_region_bits[] = { SZ_REGIONS(X_BIT) };
_Static_assert(sizeof kof_7z_region_bits / sizeof kof_7z_region_bits[0] ==
	       KOF_7Z_REGION_COUNT, "region list and its count disagree");

const char *kof_7z_region_name(uint32_t bit)
{
	switch (bit) {
	SZ_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_7z_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_START", "HDR_PAST_EOF", "HDR_EMPTY", "ENCRYPTED",
		"UNKNOWN_CODER", "BAD_VERSION", "OVERLAP"
	};

	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}

const char *kof_7z_header_kind_name(uint32_t kind)
{
	switch (kind) {
	case KOF_7Z_HDR_PLAIN:     return "plain";
	case KOF_7Z_HDR_CODED:     return "compressed";
	case KOF_7Z_HDR_ENCRYPTED: return "ENCRYPTED";
	default:                   return "missing";
	}
}
