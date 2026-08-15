/*
 * xz_parse.c - walking an xz stream from both ends.
 *
 * The order is forced by the format. A block header states its sizes only if it
 * feels like it - two flag bits say whether each is present, and the common
 * encoder writes neither - so a walk forward from the stream header reads the
 * first block header and then has no idea how far to step. The Index at the end
 * lists every block's size and is what makes them findable.
 *
 * So: the twelve byte footer gives the index, the index gives the blocks, and each
 * block header is then read in place for the one thing the index does not carry -
 * which filter chain codes it.
 */

#include <string.h>

#include "xz_parse.h"
#include "../runlist.h"

static const uint8_t XZ_MAGIC[KOF_XZ_MAGIC_LEN] = {
	0xfd, '7', 'z', 'X', 'Z', 0x00
};

/* ---- reads -------------------------------------------------------------------- */

static uint32_t rd32le(kof_buf f, uint64_t off)
{
	uint32_t v = 0;

	kof_rd_u32(f, off, 0, &v);
	return v;
}

/*
 * A multibyte integer, xz's own encoding.
 *
 * Seven bits per byte, low first, the top bit meaning "another follows". Nine
 * bytes is the format's own maximum and the loop is held to it - without that a
 * run of 0x80 bytes walks the whole object one bit at a time.
 *
 * Deliberately NOT the same as the number encoding in 7z, which packs its length
 * into the first byte rather than into a continuation bit. Two containers, two
 * conventions, and reading one with the other yields plausible wrong numbers.
 */
static uint64_t xz_num(kof_buf f, uint64_t *at, int *ok)
{
	uint64_t v = 0;
	uint32_t i;

	*ok = 0;
	for (i = 0; i < 9u; i++) {
		uint8_t b = 0;

		if (!kof_rd_u8(f, *at, &b))
			return 0;
		(*at)++;
		v |= (uint64_t)(b & 0x7fu) << (7u * i);
		if (!(b & 0x80u)) {
			*ok = 1;
			return v;
		}
	}
	return 0;
}

/* Round up to the next multiple of four, saturating rather than wrapping. */
static uint64_t round4(uint64_t v)
{
	uint64_t r = v & 3u;

	return r ? kof_sat_add(v, 4u - r) : v;
}

/*
 * Where the stream's footer is, searching back from the end.
 *
 * Not simply the last twelve bytes, though that is where a lone stream puts it.
 * Three things get in the way and all three are ordinary: the format allows STREAM
 * PADDING of zero bytes after a stream, streams CONCATENATE so a file may hold
 * several, and an xz is routinely glued onto something else. Measured, one file in
 * this collection carries 430 stream headers and 2077 bytes of tail - reading its
 * last twelve bytes as a footer said the stream was broken, which was true of those
 * twelve bytes and false of the file.
 *
 * So the magic is searched for, backwards, at the four byte alignment every stream
 * keeps, within a bounded window. Same shape as the zip parser looking back for an
 * end-of-central-directory record, and bounded for the same reason: an unbounded
 * search is a scan of the whole object for two bytes that occur by chance.
 */
#define XZ_FOOTER_SEARCH (64u << 10)

static uint64_t find_footer(kof_buf f)
{
	uint64_t span = f.n < XZ_FOOTER_SEARCH ? f.n : XZ_FOOTER_SEARCH;
	uint64_t at;

	if (f.n < KOF_XZ_HEADER_LEN + KOF_XZ_FOOTER_LEN)
		return UINT64_MAX;

	/* The last position a footer could start at, aligned down to four. */
	at = (f.n - KOF_XZ_FOOTER_LEN) & ~(uint64_t)3u;
	while (at + KOF_XZ_FOOTER_LEN <= f.n &&
	       at + span >= f.n - KOF_XZ_FOOTER_LEN) {
		if (f.p[at + 10u] == 'Y' && f.p[at + 11u] == 'Z')
			return at;
		if (at < 4u)
			break;
		at -= 4u;
	}
	return UINT64_MAX;
}

/* ---- the walk's own state ----------------------------------------------------- */

struct xw {
	kof_buf f;
	struct kof_xz_info *x;
	struct kof_runs runs;
};

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t xz_cls_bit[KOF_XZ_CLS_COUNT] = {
	KOF_SCAN_XZ_HEADERS,
	KOF_SCAN_XZ_PACKED
};

static uint32_t xz_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				struct kof_range *out, uint32_t max_out)
{
	const struct kof_xz_info *x = (const struct kof_xz_info *)ctx->file_header;

	if (!x || !x->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof x->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)x->run, x->n_runs, mask,
				xz_cls_bit, KOF_SCAN_XZ_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- the block header --------------------------------------------------------- */

/*
 * Read one block header for its filters.
 *
 * Everything else in it - the two optional sizes - is ignored on purpose: the
 * index already said what they are, and the two are allowed to disagree only in
 * a file built to make a reader choose wrong. Taking the index's answer for every
 * block means one source rather than two.
 */
static void block_header(struct xw *s, struct kof_xz_block *bl)
{
	uint64_t at = bl->hdr_off + 2u;
	uint8_t flags = 0;
	uint32_t i, n;
	int ok;

	if (!kof_rd_u8(s->f, bl->hdr_off + 1u, &flags))
		return;
	n = (uint32_t)(flags & 0x03u) + 1u;
	bl->n_filters = n;

	if (flags & 0x40u)
		xz_num(s->f, &at, &ok);         /* compressed size, unused */
	if (flags & 0x80u)
		xz_num(s->f, &at, &ok);         /* uncompressed size, unused */

	for (i = 0; i < n; i++) {
		uint64_t id, psize;

		id = xz_num(s->f, &at, &ok);
		if (!ok)
			return;
		psize = xz_num(s->f, &at, &ok);
		if (!ok || psize > bl->hdr_len)
			return;
		at = kof_sat_add(at, psize);
		/* The LAST filter is the one that produces the bytes; the ones
		 * before it are transforms applied to its output. */
		bl->filter = (uint32_t)id;
	}

	if (n > 1u) {
		bl->suspicious |= KOF_XZ_BLK_CHAIN;
		s->x->anomalies |= KOF_XZ_ANOM_FILTER_CHAIN;
	}
	if (bl->filter != KOF_XZ_FILTER_LZMA2)
		s->x->anomalies |= KOF_XZ_ANOM_UNKNOWN_FILTER;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_xz_sniff(kof_buf file)
{
	return kof_in_range(file, 0, KOF_XZ_MAGIC_LEN) &&
	       memcmp(file.p, XZ_MAGIC, KOF_XZ_MAGIC_LEN) == 0;
}

int kof_xz_parse(kof_buf file, struct kof_xz_info *x, struct kof_obj_ctx *ctx)
{
	struct xw s;
	uint64_t foot, idx, at, block_at;
	uint32_t back;
	uint8_t b = 0;
	uint64_t count, i;
	int ok;

	memset(x, 0, sizeof *x);
	x->version = KOF_XZ_INFO_VERSION;

	if (!kof_xz_sniff(file))
		return 0;
	x->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.x = x;
	kof_runs_init(&s.runs, (struct kof_run *)x->run, KOF_XZ_MAX_EXTENTS,
		      KOF_XZ_CLS_COUNT);

	/* ---- the stream header ---- */
	if (!kof_in_range(file, 0, KOF_XZ_HEADER_LEN)) {
		x->anomalies |= KOF_XZ_ANOM_BAD_HEADER;
		goto done;
	}
	kof_runs_add(&s.runs, file.n, 0, KOF_XZ_HEADER_LEN, KOF_XZ_CLS_HEADERS);
	kof_rd_u8(file, 7, &b);
	x->check = b & 0x0fu;
	x->check_len = kof_xz_check_len(x->check);
	if (x->check != KOF_XZ_CHECK_NONE && x->check != KOF_XZ_CHECK_CRC32 &&
	    x->check != KOF_XZ_CHECK_CRC64 && x->check != KOF_XZ_CHECK_SHA256)
		x->anomalies |= KOF_XZ_ANOM_BAD_CHECK;

	/* ---- the footer, which is the only way to the index ---- */
	foot = find_footer(file);
	if (foot == UINT64_MAX) {
		x->anomalies |= KOF_XZ_ANOM_BAD_FOOTER;
		goto done;
	}
	x->footer_off = foot;
	kof_runs_add(&s.runs, file.n, foot, KOF_XZ_FOOTER_LEN, KOF_XZ_CLS_HEADERS);
	/* Anything after the footer is not part of this stream. Another stream may
	 * follow - they concatenate - or it may be padding, or a file that had one
	 * glued to its front. All three are worth knowing and none is an error. */
	if (foot + KOF_XZ_FOOTER_LEN < file.n)
		x->anomalies |= KOF_XZ_ANOM_MULTI_STREAM;

	/*
	 * Backward size counts four byte units and is stored one less than it is,
	 * which is the format's way of saying an index is never empty.
	 */
	back = rd32le(file, foot + 4u);
	idx = kof_sat_add((uint64_t)back + 1u, 0) * 4u;
	if (idx == 0 || idx > foot) {
		x->anomalies |= KOF_XZ_ANOM_NO_INDEX;
		goto done;
	}
	x->index_off = foot - idx;
	x->index_len = idx;
	kof_runs_add(&s.runs, file.n, x->index_off, idx, KOF_XZ_CLS_HEADERS);

	/* ---- the index ---- */
	at = x->index_off;
	if (!kof_rd_u8(file, at, &b) || b != 0x00u) {
		x->anomalies |= KOF_XZ_ANOM_NO_INDEX;
		goto done;
	}
	at++;
	count = xz_num(file, &at, &ok);
	if (!ok) {
		x->anomalies |= KOF_XZ_ANOM_NO_INDEX;
		goto done;
	}
	x->declared_blocks = (uint32_t)(count > 0xffffffffu ? 0xffffffffu : count);
	if (count > KOF_XZ_MAX_BLOCKS) {
		x->anomalies |= KOF_XZ_ANOM_BLOCKS_FULL;
		count = KOF_XZ_MAX_BLOCKS;
	}

	/*
	 * Each record is the block's unpadded size and what it decodes to. Unpadded
	 * means header plus data plus check and NOT the padding after them, so the
	 * data length is that less the two ends and the next block begins at the
	 * whole thing rounded up to four.
	 */
	block_at = KOF_XZ_HEADER_LEN;
	for (i = 0; i < count; i++) {
		struct kof_xz_block *bl = &x->block[x->n_blocks];
		uint64_t unpadded, uncomp, hdr_len;
		uint8_t hs = 0;

		unpadded = xz_num(file, &at, &ok);
		if (!ok)
			break;
		uncomp = xz_num(file, &at, &ok);
		if (!ok)
			break;

		if (!kof_rd_u8(file, block_at, &hs) || hs == 0) {
			x->anomalies |= KOF_XZ_ANOM_BAD_BLOCK;
			break;
		}
		hdr_len = ((uint64_t)hs + 1u) * 4u;
		if (unpadded <= hdr_len + x->check_len) {
			x->anomalies |= KOF_XZ_ANOM_BAD_BLOCK;
			break;
		}

		memset(bl, 0, sizeof *bl);
		bl->hdr_off     = block_at;
		bl->hdr_len     = (uint32_t)hdr_len;
		bl->data_off    = block_at + hdr_len;
		bl->comp_size   = unpadded - hdr_len - x->check_len;
		bl->uncomp_size = uncomp;

		if (!kof_in_range(file, bl->hdr_off, hdr_len) ||
		    !kof_in_range(file, bl->data_off, bl->comp_size)) {
			bl->suspicious |= KOF_XZ_BLK_PAST_EOF;
			x->anomalies |= KOF_XZ_ANOM_TRUNCATED;
			x->n_blocks++;
			break;
		}
		if (bl->comp_size &&
		    bl->uncomp_size / bl->comp_size >= KOF_XZ_RATIO_ABSURD) {
			bl->suspicious |= KOF_XZ_BLK_RATIO;
			x->anomalies |= KOF_XZ_ANOM_RATIO_ABSURD;
		}

		block_header(&s, bl);

		kof_runs_add(&s.runs, file.n, bl->hdr_off, hdr_len,
			     KOF_XZ_CLS_HEADERS);
		kof_runs_add(&s.runs, file.n, bl->data_off, bl->comp_size,
			     KOF_XZ_CLS_PACKED);
		/* The check sits after the data and is structure, not content. */
		if (x->check_len)
			kof_runs_add(&s.runs, file.n, bl->data_off + bl->comp_size,
				     x->check_len, KOF_XZ_CLS_HEADERS);

		x->total_comp = kof_sat_add(x->total_comp, bl->comp_size);
		x->total_uncomp = kof_sat_add(x->total_uncomp, bl->uncomp_size);
		x->n_blocks++;

		block_at = kof_sat_add(block_at, round4(unpadded));
		if (block_at >= x->index_off)
			break;
	}

	if (x->n_blocks < x->declared_blocks)
		x->anomalies |= KOF_XZ_ANOM_BLOCKS_FULL;

done:
	if (s.runs.full)
		x->anomalies |= KOF_XZ_ANOM_EXTENTS_FULL;
	if (s.runs.overlapped)
		x->anomalies |= KOF_XZ_ANOM_OVERLAP;
	kof_runs_settle(&s.runs, x->region_bytes);
	x->n_runs = s.runs.n;

	ctx->obj_size     = file.n;
	ctx->format       = KOF_FMT_XZ;
	ctx->file_header  = x;
	ctx->resolve_scan = xz_resolve_scan;
	return 1;
}

/* ---- names -------------------------------------------------------------------- */

#define XZ_REGIONS(X)          \
	X(KOF_SCAN_XZ_HEADERS)   \
	X(KOF_SCAN_XZ_PACKED)    \
	X(KOF_SCAN_XZ_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_xz_region_bits[] = { XZ_REGIONS(X_BIT) };
_Static_assert(sizeof kof_xz_region_bits / sizeof kof_xz_region_bits[0] ==
	       KOF_XZ_REGION_COUNT, "region list and its count disagree");

const char *kof_xz_region_name(uint32_t bit)
{
	switch (bit) {
	XZ_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_xz_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_HEADER", "BAD_FOOTER", "NO_INDEX", "BAD_BLOCK", "TRUNCATED",
		"BLOCKS_FULL", "EXTENTS_FULL", "FILTER_CHAIN", "UNKNOWN_FILTER",
		"BAD_CHECK", "RATIO_ABSURD", "OVERLAP", "MULTI_STREAM"
	};

	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
