/*
 * lha_parse.c - the header chain, walked and bounded.
 *
 * THE WALK IS A CHAIN AND THAT DECIDES THE ERROR POLICY. Each header states how
 * long it is and how long its body is, and the next header is at the end of
 * that body. There is no directory to cross-check it against, so a single wrong
 * length does not corrupt one entry - it points the walk at whatever follows,
 * which then parses as a header if the bytes happen to look like one.
 *
 * So the walk STOPS at the first thing that does not add up, and says so. It
 * does not resynchronise by searching forward for the next "-lh": in a file
 * chosen by somebody else, that search finds exactly what they put there.
 *
 * Everything is little endian, and every length is compared against what is
 * left of the object before it is used.
 */

#include <string.h>

#include "lha_parse.h"
#include "../rangelist.h"

#define LHA_METHOD_AT   2u
#define LHA_METHOD_LEN  5u
#define LHA_L0_MIN      22u     /* through the name length byte */
#define LHA_L2_MIN      24u

/* ---- regions ----------------------------------------------------------------- */

static uint32_t lha_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_lha_info *l = (const struct kof_lha_info *)ctx->file_header;
	struct kof_rlist rl;

	if (!l || !l->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&rl, out, max_out);
	/*
	 * ONE RANGE EACH FOR THE THREE, and not one per entry.
	 *
	 * A region is a set of extents and could hold every header separately,
	 * which would be more precise and would cost a run per entry on an
	 * archive with a thousand of them - and buy nothing, because what a
	 * rule asks of this format is "is that name in here" and "how large is
	 * the coded part". The names are contiguous in practice: every header
	 * carries one, and the headers are interleaved with the bodies, so
	 * NAMES spans from the first to the last and HEADERS is what surrounds
	 * it. The partition still holds because the three are taken in order
	 * and the complement takes the rest.
	 */
	if (mask & KOF_SCAN_LHA_HEADERS)
		kof_rl_add(&rl, ctx->obj_size, 0,
			   l->names_off ? l->names_off : LHA_L0_MIN);
	if (mask & KOF_SCAN_LHA_NAMES)
		kof_rl_add(&rl, ctx->obj_size, l->names_off, l->names_len);
	if (mask & KOF_SCAN_LHA_DATA) {
		uint64_t from = l->data_off;
		uint64_t names_end = l->names_off + l->names_len;

		if (from < names_end)
			from = names_end;
		if (from < ctx->obj_size && l->data_len)
			kof_rl_add(&rl, ctx->obj_size, from,
				   l->data_off + l->data_len > from
				   ? l->data_off + l->data_len - from : 0);
	}

	if (mask & KOF_SCAN_LHA_UNCLAIMED) {
		struct kof_range cv[8];
		struct kof_rlist cl;

		kof_rl_init(&cl, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		cl.n = lha_resolve_scan(ctx, KOF_SCAN_LHA_CLAIMED, cv, cl.cap);
		kof_rl_complement(&rl, &cl, ctx->obj_size);
	}
	return kof_rl_normalise(&rl);
}

static uint32_t lha_entries(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out)
{
	const struct kof_lha_info *l = (const struct kof_lha_info *)ctx->file_header;

	if (!l || !l->valid || !out)
		return 0;
	*out = l->entry;
	return l->n_entries;
}

/* ---- helpers ------------------------------------------------------------------ */

/* "-lh0-" through "-lh7-", "-lhd-" for a directory, and the two "-lz" ones
 * that predate them. The shape is fixed and only the middle two bytes vary,
 * which is what makes this cheap to test and weak on its own - see the sniff. */
static int lha_method(kof_buf f, uint64_t at, char *out)
{
	uint8_t m[LHA_METHOD_LEN];
	uint32_t i;

	for (i = 0; i < LHA_METHOD_LEN; i++)
		if (!kof_rd_u8(f, at + i, &m[i]))
			return 0;
	if (m[0] != '-' || m[4] != '-')
		return 0;
	if (!(m[1] == 'l' && (m[2] == 'h' || m[2] == 'z')))
		return 0;
	for (i = 0; i < LHA_METHOD_LEN; i++)
		out[i] = (char)m[i];
	out[LHA_METHOD_LEN] = 0;
	return 1;
}

/* Stored: the body IS the file. "-lh0-" and "-lz4-" are the two, and "-lhd-"
 * is a directory with no body at all. */
static int lha_stored(const char *m)
{
	return strcmp(m, "-lh0-") == 0 || strcmp(m, "-lz4-") == 0;
}

/* The sum of the header's bytes, which levels 0 and 1 carry at offset 1. It is
 * a checksum and not a hash: what it catches is an edit nobody meant. */
static int lha_checksum_ok(kof_buf f, uint64_t at, uint32_t hdr_size,
			   uint8_t want)
{
	uint32_t i, sum = 0;

	for (i = 0; i < hdr_size; i++) {
		uint8_t b;

		if (!kof_rd_u8(f, at + 2u + i, &b))
			return 1;      /* truncated: said elsewhere, not here */
		sum += b;
	}
	return (uint8_t)sum == want;
}

static int lha_traversal(kof_buf f, uint64_t at, uint32_t len)
{
	uint32_t i;

	for (i = 0; i + 1u < len; i++) {
		uint8_t a, b;

		if (!kof_rd_u8(f, at + i, &a) || !kof_rd_u8(f, at + i + 1u, &b))
			return 0;
		if (a == '.' && b == '.')
			return 1;
		if (i == 0 && (a == '\\' || a == '/' || b == ':'))
			return 1;
	}
	return 0;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_lha_sniff(kof_buf file)
{
	char m[LHA_METHOD_LEN + 1];
	uint8_t level;

	if (!kof_in_range(file, 0, LHA_L0_MIN))
		return 0;
	if (!lha_method(file, LHA_METHOD_AT, m))
		return 0;
	if (!kof_rd_u8(file, 20u, &level))
		return 0;
	return level <= 2u;
}

int kof_lha_parse(kof_buf file, struct kof_lha_info *l, struct kof_obj_ctx *ctx)
{
	char m[LHA_METHOD_LEN + 1];
	uint64_t at = 0;
	int first = 1;

	memset(l, 0, sizeof *l);
	l->version = KOF_LHA_INFO_VERSION;

	if (!kof_in_range(file, 0, LHA_L0_MIN) ||
	    !lha_method(file, LHA_METHOD_AT, m))
		return 0;
	l->valid = 1;
	kof_rd_u8(file, 20u, &l->level);

	while (at < file.n) {
		uint64_t hdr_end, name_at = 0, body;
		uint32_t csize = 0, osize = 0, name_len = 0;
		uint8_t  hsize8 = 0, sum = 0, level = 0;

		if (!kof_rd_u8(file, at, &hsize8))
			break;
		/*
		 * A ZERO LENGTH HEADER IS THE END MARK, which is how an LHA
		 * archive says it is finished - one byte, and whatever follows
		 * it is not this archive's.
		 *
		 * READ BEFORE THE HEADER IS BOUNDED, and that is the whole
		 * reason the loop is written this way: the mark is ONE byte, so
		 * a loop that asks for a header's worth of room first runs out
		 * of object with the mark still unread and reports an archive
		 * that ended properly as one that just stopped.
		 */
		if (hsize8 == 0)
			goto ended;
		if (at + LHA_L0_MIN > file.n) {
			l->anomalies |= KOF_LHA_ANOM_TRUNCATED;
			break;
		}
		if (!lha_method(file, at + LHA_METHOD_AT, m)) {
			l->anomalies |= KOF_LHA_ANOM_TRUNCATED;
			break;
		}
		kof_rd_u8(file, at + 1u, &sum);
		kof_rd_u32(file, at + 7u, 0, &csize);
		kof_rd_u32(file, at + 11u, 0, &osize);
		kof_rd_u8(file, at + 20u, &level);

		if (level > 2u) {
			l->anomalies |= KOF_LHA_ANOM_BAD_LEVEL;
			break;
		}

		if (level <= 1u) {
			/* The size byte counts from offset two, so the header
			 * ends two bytes further on than it says. */
			hdr_end = at + 2u + hsize8;
			if (!kof_rd_u8(file, at + 21u, &(uint8_t){0}))
				break;
			{
				uint8_t nl = 0;

				kof_rd_u8(file, at + 21u, &nl);
				name_len = nl;
			}
			name_at = at + 22u;
			if (name_len > KOF_LHA_MAX_NAME ||
			    name_at + name_len > hdr_end) {
				l->anomalies |= KOF_LHA_ANOM_TRUNCATED;
				break;
			}
			if (!lha_checksum_ok(file, at, hsize8, sum))
				l->anomalies |= KOF_LHA_ANOM_BAD_CHECKSUM;
		} else {
			/*
			 * LEVEL 2 STATES THE WHOLE HEADER AT OFFSET ZERO, in
			 * two bytes - and has no name in the base header at
			 * all: the name arrives in an extension header, which
			 * this walk does not enter. So the entry is recorded
			 * without one rather than with a guess, and the name
			 * region ends where the names it did find end.
			 */
			uint16_t h16 = 0;

			kof_rd_u16(file, at, 0, &h16);
			if (h16 < LHA_L2_MIN) {
				l->anomalies |= KOF_LHA_ANOM_TRUNCATED;
				break;
			}
			hdr_end = at + h16;
			name_len = 0;
		}

		if (hdr_end > file.n || hdr_end <= at) {
			l->anomalies |= KOF_LHA_ANOM_TRUNCATED;
			break;
		}
		body = hdr_end;
		if ((uint64_t)csize > file.n - body) {
			l->anomalies |= KOF_LHA_ANOM_TRUNCATED;
			break;
		}

		if (first) {
			l->data_off = body;
			first = 0;
		}
		if (name_len) {
			if (!l->names_off)
				l->names_off = name_at;
			l->names_len = name_at + name_len - l->names_off;
			if (lha_traversal(file, name_at, name_len))
				l->anomalies |= KOF_LHA_ANOM_TRAVERSAL;
		}
		l->data_len = body + csize - l->data_off;

		if (strcmp(m, "-lhd-") == 0) {
			l->n_dirs++;
		} else if (!lha_stored(m) || !csize) {
			l->n_coded++;
			l->anomalies |= KOF_LHA_ANOM_CODED;
		} else if (l->n_entries >= KOF_LHA_MAX_ENTRIES) {
			l->anomalies |= KOF_LHA_ANOM_ENTRIES_FULL;
			break;
		} else {
			struct kof_entry *e = &l->entry[l->n_entries];

			memset(e, 0, sizeof *e);
			e->index    = l->n_entries;
			e->kind     = KOF_ENT_EMBEDDED;
			e->format   = KOF_FMT_UNKNOWN;
			e->name_off = name_at;
			e->name_len = name_len;
			e->off      = body;
			e->len      = csize;
			/* Stored, so the declared original size is a claim
			 * that can be checked rather than a hint. */
			if (osize && osize != csize)
				e->out_hint = osize;
			l->n_entries++;
		}

		at = body + csize;
	}
	/* The chain ran into the end of the object rather than stopping at an
	 * end mark - an archive that was cut, or one that never had one. */
	l->anomalies |= KOF_LHA_ANOM_NO_END;

ended:
	ctx->format = KOF_FMT_LHA;
	ctx->obj_size = file.n;
	ctx->file_header = l;
	ctx->resolve_scan = lha_resolve_scan;
	ctx->entries = lha_entries;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_lha_region_bits[] = { LHA_REGIONS(X_BIT) };
_Static_assert(sizeof kof_lha_region_bits / sizeof kof_lha_region_bits[0] ==
	       KOF_LHA_REGION_COUNT, "region list and its count disagree");

const char *kof_lha_region_name(uint32_t bit)
{
	switch (bit) {
	LHA_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_lha_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"TRUNCATED", "BAD_LEVEL", "BAD_CHECKSUM", "CODED",
		"TRAVERSAL", "ENTRIES_FULL", "NO_END"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_LHA_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
