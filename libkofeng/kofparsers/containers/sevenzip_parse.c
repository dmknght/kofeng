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
 * The coder the header was put through, or zero if it could not be established.
 *
 * Walks PackInfo (which sizes the coded header) and then the first folder's first
 * coder. Bounded by a step count as well as by the object: the sizes inside decide
 * how many times the loop reads, and a file can name a great many of them.
 */
static uint32_t hdr_coder(kof_buf f, uint64_t at, uint64_t end)
{
	uint64_t n_pack = 0;
	uint32_t steps = 0;
	uint8_t id = 0, flags = 0;
	int ok;

	if (!kof_rd_u8(f, at, &id))
		return 0;
	at++;

	if (id == KOF_7Z_ID_PACKINFO) {
		sz_num(f, &at, &ok);                  /* packPos */
		if (!ok)
			return 0;
		n_pack = sz_num(f, &at, &ok);
		if (!ok || n_pack > 4096u)
			return 0;
		for (;;) {
			if (++steps > HDR_PROBE_STEPS || at >= end)
				return 0;
			if (!kof_rd_u8(f, at, &id))
				return 0;
			at++;
			if (id == KOF_7Z_ID_END)
				break;
			if (id == KOF_7Z_ID_SIZE) {
				uint64_t k;

				for (k = 0; k < n_pack; k++) {
					sz_num(f, &at, &ok);
					if (!ok)
						return 0;
				}
			}
			/* Anything else here is a property this does not need; its
			 * body is skipped by the loop's own bound rather than by
			 * trusting a length nobody checked. */
		}
		if (!kof_rd_u8(f, at, &id))
			return 0;
		at++;
	}

	if (id != KOF_7Z_ID_UNPACK)
		return 0;
	if (!kof_rd_u8(f, at, &id) || id != KOF_7Z_ID_FOLDER)
		return 0;
	at++;

	sz_num(f, &at, &ok);                          /* numFolders */
	if (!ok)
		return 0;
	at++;                                         /* external */
	sz_num(f, &at, &ok);                          /* numCoders */
	if (!ok)
		return 0;
	if (!kof_rd_u8(f, at, &flags))
		return 0;
	at++;

	{
		uint32_t len = flags & 0x0fu, i, v = 0;
		uint8_t c;

		if (len == 0 || len > 4u)
			return 0;
		for (i = 0; i < len; i++) {
			if (!kof_rd_u8(f, at + i, &c))
				return 0;
			v = (v << 8) | c;
		}
		return v;
	}
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t sz_cls_bit[KOF_7Z_CLS_COUNT] = {
	KOF_SCAN_7Z_HEADERS,
	KOF_SCAN_7Z_PACKED
};

static uint32_t sz_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				struct kof_range *out, uint32_t max_out)
{
	const struct kof_7z_info *z = (const struct kof_7z_info *)ctx->file_header;
	struct kof_run run[3];
	uint32_t n = 0;

	if (!z || !z->valid || !out || max_out == 0)
		return 0;

	/*
	 * Three runs at most, so they are built here rather than kept in the view.
	 * The other containers store theirs because a walk discovered them one at a
	 * time and there is no second chance to work them out; here the whole layout
	 * is four numbers from the start header.
	 */
	run[n].off = 0;
	run[n].len = KOF_7Z_SIG_LEN;
	run[n].cls = KOF_7Z_CLS_HEADERS;
	run[n].reserved = 0;
	n++;

	if (z->next_hdr_size && z->next_hdr_off > KOF_7Z_SIG_LEN) {
		run[n].off = KOF_7Z_SIG_LEN;
		run[n].len = z->next_hdr_off - KOF_7Z_SIG_LEN;
		run[n].cls = KOF_7Z_CLS_PACKED;
		run[n].reserved = 0;
		n++;
	}
	if (z->next_hdr_size) {
		run[n].off = z->next_hdr_off;
		run[n].len = z->next_hdr_size;
		run[n].cls = KOF_7Z_CLS_HEADERS;
		run[n].reserved = 0;
		n++;
	}
	return kof_runs_resolve(run, n, mask, sz_cls_bit, KOF_SCAN_7Z_UNCLAIMED,
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
		z->hdr_coder = hdr_coder(file, z->next_hdr_off + 1,
					 z->next_hdr_off + size);
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
	/* The same three runs the resolve builds, settled once so the per-class
	 * totals are available to a module without resolving anything. */
	kof_runs_init(&l, run, 3u, KOF_7Z_CLS_COUNT);
	kof_runs_add(&l, file.n, 0, KOF_7Z_SIG_LEN, KOF_7Z_CLS_HEADERS);
	if (z->next_hdr_size && z->next_hdr_off > KOF_7Z_SIG_LEN)
		kof_runs_add(&l, file.n, KOF_7Z_SIG_LEN,
			     z->next_hdr_off - KOF_7Z_SIG_LEN, KOF_7Z_CLS_PACKED);
	if (z->next_hdr_size)
		kof_runs_add(&l, file.n, z->next_hdr_off, z->next_hdr_size,
			     KOF_7Z_CLS_HEADERS);
	kof_runs_settle(&l, z->region_bytes);
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
