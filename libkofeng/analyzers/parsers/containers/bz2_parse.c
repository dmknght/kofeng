/*
 * bz2_parse.c - the bzip2 wrapper, which is four bytes and a marker.
 *
 * There is less here than in any other collector because there is less in the
 * format: everything after the fourth byte is a bit stream with no alignment,
 * so a parse that does not decode can say where the coded part starts and
 * nothing else about it. What that buys is the whole point - see bz2.h.
 */

#include <string.h>

#include "bz2_parse.h"
#include "../../../kofcore/rangelist.h"

#define BZ2_HDR 4u          /* "BZh" and the level digit */
#define BZ2_MARK 6u         /* either marker, right behind the header */

/* The two markers, as the bytes they are when they land on a boundary - which
 * is only ever here, immediately after the header. */
static const uint8_t bz2_block_mark[BZ2_MARK] = {
	0x31u, 0x41u, 0x59u, 0x26u, 0x53u, 0x59u
};
static const uint8_t bz2_end_mark[BZ2_MARK] = {
	0x17u, 0x72u, 0x45u, 0x38u, 0x50u, 0x90u
};

/* ---- regions ----------------------------------------------------------------- */

static uint32_t bz2_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_bz2_info *b = (const struct kof_bz2_info *)ctx->file_header;
	struct kof_rlist l;

	if (!b || !b->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);
	if (mask & KOF_SCAN_BZ2_HEADER)
		kof_rl_add(&l, ctx->obj_size, 0, BZ2_HDR);
	if (mask & KOF_SCAN_BZ2_DATA)
		kof_rl_add(&l, ctx->obj_size, b->data_off, b->data_len);

	if (mask & KOF_SCAN_BZ2_UNCLAIMED) {
		/* The complement, obtained by asking for everything else - see
		 * the note in pe_parse.c on why the claimants are not listed
		 * twice. */
		struct kof_range cv[4];
		struct kof_rlist c;

		kof_rl_init(&c, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		c.n = bz2_resolve_scan(ctx, KOF_SCAN_BZ2_CLAIMED, cv, c.cap);
		kof_rl_complement(&l, &c, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_bz2_sniff(kof_buf file)
{
	if (!file.p || file.n < BZ2_HDR + BZ2_MARK)
		return 0;
	if (file.p[0] != 'B' || file.p[1] != 'Z' || file.p[2] != 'h')
		return 0;
	if (file.p[3] < '1' || file.p[3] > '9')
		return 0;
	return memcmp(file.p + BZ2_HDR, bz2_block_mark, BZ2_MARK) == 0 ||
	       memcmp(file.p + BZ2_HDR, bz2_end_mark, BZ2_MARK) == 0;
}

int kof_bz2_parse(kof_buf file, struct kof_bz2_info *b, struct kof_obj_ctx *ctx)
{
	memset(b, 0, sizeof *b);
	b->version = KOF_BZ2_INFO_VERSION;

	/*
	 * THE MAGIC ALONE HERE, NOT THE SNIFF.
	 *
	 * The sniff is stricter on purpose - it decides whether this format
	 * claims the object at all, and three letters and a digit would claim
	 * text. Once something else has decided this IS a bzip2, a missing
	 * marker is a FACT ABOUT THE FILE to record rather than a reason to
	 * hand back nothing: a wrapper with no block behind it is exactly what
	 * a hand built file looks like, and refusing to parse it would leave
	 * the object unclaimed and the anomaly unsaid.
	 */
	if (!file.p || file.n < BZ2_HDR ||
	    file.p[0] != 'B' || file.p[1] != 'Z' || file.p[2] != 'h')
		return 0;

	b->valid = 1;
	b->level = file.p[3];
	if (b->level < '1' || b->level > '9') {
		b->anomalies |= KOF_BZ2_ANOM_BAD_LEVEL;
		b->level = 0;
	} else {
		b->level = (uint8_t)(b->level - '0');
		b->block_size = (uint32_t)b->level * 100000u;
	}

	b->data_off = BZ2_HDR;
	b->data_len = file.n > BZ2_HDR ? file.n - BZ2_HDR : 0;

	if (file.n < BZ2_HDR + BZ2_MARK) {
		b->anomalies |= KOF_BZ2_ANOM_TRUNCATED;
	} else if (memcmp(file.p + BZ2_HDR, bz2_end_mark, BZ2_MARK) == 0) {
		b->anomalies |= KOF_BZ2_ANOM_EMPTY;
	} else if (memcmp(file.p + BZ2_HDR, bz2_block_mark, BZ2_MARK) != 0) {
		b->anomalies |= KOF_BZ2_ANOM_NO_BLOCK;
	}

	ctx->format = KOF_FMT_BZIP2;
	ctx->obj_size = file.n;
	ctx->file_header = b;
	ctx->resolve_scan = bz2_resolve_scan;
	/* No architecture and no entry point: a container is not code - the same
	 * note gzip's parse ends on, and for the same reason. */
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_bz2_region_bits[] = { BZ2_REGIONS(X_BIT) };
_Static_assert(sizeof kof_bz2_region_bits / sizeof kof_bz2_region_bits[0] ==
	       KOF_BZ2_REGION_COUNT, "region list and its count disagree");

const char *kof_bz2_region_name(uint32_t bit)
{
	switch (bit) {
	BZ2_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_bz2_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_LEVEL", "TRUNCATED", "EMPTY", "NO_BLOCK"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_BZ2_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
