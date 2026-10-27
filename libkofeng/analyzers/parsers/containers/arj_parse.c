/*
 * arj_parse.c - the framed header chain.
 *
 * A header is: the magic 0x60 0xEA, a two byte basic header length, that many
 * bytes of header, a four byte CRC of them, and then a chain of EXTENDED
 * headers - each a two byte length, its bytes and its own CRC - ending with a
 * zero length. The body follows, and the next header follows that.
 *
 * The basic header holds a fixed part, then the file name and the comment, both
 * NUL terminated, both inside it. That containment is what makes the names
 * cheap to bound: they cannot be longer than the header that holds them, and
 * the format caps that at 2600 bytes.
 *
 * A ZERO LENGTH BASIC HEADER ENDS THE ARCHIVE, which is the only way an ARJ
 * says it is finished.
 *
 * Every length here is checked against what is left of the object before it is
 * used, and the walk stops at the first one that does not fit rather than
 * hunting forward for the next magic - see the note in lha_parse.c, which is
 * the same argument.
 */

#include <string.h>

#include "arj_parse.h"
#include "cname.h"
#include "../../../kofcore/rangelist.h"
#include "../../../kofcore/tabgrow.h"

#define ARJ_MAGIC0 0x60u
#define ARJ_MAGIC1 0xeau
#define ARJ_BASIC_MIN KOF_ARJ_BASIC_MIN     /* through the file access field */
#define ARJ_NAME_AT   0u      /* relative to the end of first_hdr_size */

/* arj_flags, the bits this parse reads. */
enum {
	ARJ_F_GARBLED = 0x01u,    /* encrypted */
	ARJ_F_VOLUME  = 0x04u,    /* one of several */
	ARJ_F_EXTFILE = 0x08u     /* a file continued from the previous volume */
};

/* ---- regions ----------------------------------------------------------------- */

static uint32_t arj_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_arj_info *a = (const struct kof_arj_info *)ctx->file_header;
	struct kof_rlist rl;

	if (!a || !a->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&rl, out, max_out);
	/* One range each, in order, for the reason lha_parse.c gives: what a
	 * rule asks of this format is whether a name is in it. */
	if (mask & KOF_SCAN_ARJ_HEADERS)
		kof_rl_add(&rl, ctx->obj_size, 0,
			   a->names_off ? a->names_off : ARJ_BASIC_MIN);
	if (mask & KOF_SCAN_ARJ_NAMES)
		kof_rl_add(&rl, ctx->obj_size, a->names_off, a->names_len);
	if (mask & KOF_SCAN_ARJ_DATA) {
		uint64_t from = a->data_off;
		uint64_t names_end = a->names_off + a->names_len;

		if (from < names_end)
			from = names_end;
		if (a->data_len && from < a->data_off + a->data_len)
			kof_rl_add(&rl, ctx->obj_size, from,
				   a->data_off + a->data_len - from);
	}

	if (mask & KOF_SCAN_ARJ_UNCLAIMED) {
		struct kof_range cv[8];
		struct kof_rlist cl;

		kof_rl_init(&cl, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		cl.n = arj_resolve_scan(ctx, KOF_SCAN_ARJ_CLAIMED, cv, cl.cap);
		kof_rl_complement(&rl, &cl, ctx->obj_size);
	}
	return kof_rl_finish(&rl);
}

static uint32_t arj_entries(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out)
{
	const struct kof_arj_info *a = (const struct kof_arj_info *)ctx->file_header;

	if (!a || !a->valid || !out)
		return 0;
	*out = a->entry;
	return a->n_entries;
}

/* ---- helpers ------------------------------------------------------------------ */



/*
 * Past the extended headers that follow a basic one.
 *
 * Each is a two byte length and, when it is non-zero, that many bytes plus a
 * four byte CRC. A zero length ends the chain. NO COUNT BOUNDS IT: every step
 * consumes at least the two bytes of its own length, so the walk ends within
 * the object whatever the file chains, and its cost is the object's length. It
 * had a guard of 64 steps, which made an archive with a sixty-fifth extended
 * header (a hostile one, and a legitimate one has none or one) read as cut and
 * lose every entry after it.
 */
static int arj_skip_ext(kof_buf f, uint64_t *at)
{
	for (;;) {
		uint16_t n = 0;

		if (!kof_rd_u16(f, *at, 0, &n))
			return 0;
		*at += 2u;
		if (!n)
			return 1;
		if ((uint64_t)n + 4u > f.n - *at)
			return 0;
		*at += (uint64_t)n + 4u;
	}
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_arj_sniff(kof_buf file)
{
	uint16_t basic = 0;
	uint8_t first = 0;

	if (!kof_in_range(file, 0, 4u))
		return 0;
	if (file.p[0] != ARJ_MAGIC0 || file.p[1] != ARJ_MAGIC1)
		return 0;
	if (!kof_rd_u16(file, 2u, 0, &basic))
		return 0;
	if (basic < ARJ_BASIC_MIN || basic > KOF_ARJ_MAX_BASIC)
		return 0;
	/* The first byte of the basic header is its own fixed part's size, and
	 * it cannot be larger than the header holding it. */
	if (!kof_rd_u8(file, 4u, &first))
		return 0;
	return first >= ARJ_BASIC_MIN && first <= basic;
}

void kof_arj_release(struct kof_arj_info *a)
{
	kof_tab_free((void **)&a->entry);
	a->n_entries = 0;
	a->mem.held = 0;
	a->mem.rows = 0;
}

KOF_VIEW_HANDLES(arj, struct kof_arj_info, entry, n_entries)

int kof_arj_parse(kof_buf file, struct kof_arj_info *a, struct kof_obj_ctx *ctx)
{
	uint64_t at = 0, room, rows_limit;
	uint32_t cap_entry = 0;
	int first_header = 1;

	/* The whole view is cleared (it is small); what the last parse left is let go first and
	 * the caller's room is put back - zip_parse.c says why. */
	room = a->mem.room;
	kof_arj_release(a);
	memset(a, 0, sizeof *a);
	a->mem.room = room;
	a->version = KOF_ARJ_INFO_VERSION;
	/* What the FILE can hold, and not what it says: a header is at least KOF_ARJ_HEADER_MIN. */
	rows_limit = file.n / KOF_ARJ_HEADER_MIN;

	if (!kof_in_range(file, 0, 4u) ||
	    file.p[0] != ARJ_MAGIC0 || file.p[1] != ARJ_MAGIC1)
		return 0;
	a->valid = 1;

	while (at + 4u <= file.n) {
		uint64_t base, name_at, body;
		uint16_t basic = 0;
		uint32_t csize = 0, osize = 0, name_len, cmt_len;
		uint8_t  first_size = 0, method = 0, ftype = 0, flags = 0;

		if (file.p[at] != ARJ_MAGIC0 || file.p[at + 1u] != ARJ_MAGIC1) {
			a->anomalies |= KOF_ARJ_ANOM_TRUNCATED;
			break;
		}
		kof_rd_u16(file, at + 2u, 0, &basic);
		/*
		 * A ZERO LENGTH BASIC HEADER IS THE END, and it is read before
		 * anything is bounded for the reason lha_parse.c gives about
		 * its own end mark: the marker is smaller than a header, so a
		 * loop that demands room for a header first never sees it.
		 */
		if (!basic)
			goto ended;
		if (basic < ARJ_BASIC_MIN || basic > KOF_ARJ_MAX_BASIC ||
		    at + 4u + basic + 4u > file.n) {
			a->anomalies |= KOF_ARJ_ANOM_BAD_HEADER;
			break;
		}

		base = at + 4u;
		kof_rd_u8(file, base + 0u, &first_size);
		if (first_size < ARJ_BASIC_MIN || first_size > basic) {
			a->anomalies |= KOF_ARJ_ANOM_BAD_HEADER;
			break;
		}
		/*
		 * THE FIXED PART, at the offsets the format states: first
		 * header size, two versions and the host OS, then the flags at
		 * four, the method at five and the file type at six; the two
		 * sizes at twelve and sixteen, behind the modification time.
		 *
		 * Written out because the first draft of this had them four
		 * bytes further on - reading the date where the method is - and
		 * every entry came back as method zero, which is STORED. A
		 * coded entry then looked like a plain range and the parse
		 * offered the coded bytes under the file's name. It is the
		 * quietest kind of wrong: the walk completes, the counts look
		 * ordinary, and every entry points at nonsense.
		 */
		kof_rd_u8(file, base + 4u, &flags);
		kof_rd_u8(file, base + 5u, &method);
		kof_rd_u8(file, base + 6u, &ftype);
		kof_rd_u32(file, base + 12u, 0, &csize);
		kof_rd_u32(file, base + 16u, 0, &osize);

		if (flags & ARJ_F_GARBLED)
			a->anomalies |= KOF_ARJ_ANOM_ENCRYPTED;
		if (flags & (ARJ_F_VOLUME | ARJ_F_EXTFILE))
			a->anomalies |= KOF_ARJ_ANOM_VOLUME;

		/* The name and the comment sit after the fixed part, inside the
		 * basic header - so both are bounded by it and not by the
		 * object. */
		name_at = base + first_size;
		name_len = kof_cname_len(file, name_at, basic - first_size);
		if (!name_len) {
			a->anomalies |= KOF_ARJ_ANOM_BAD_HEADER;
			break;
		}
		cmt_len = kof_cname_len(file, name_at + name_len,
				     basic - first_size - name_len);

		at = base + basic + 4u;       /* past the basic header's CRC */
		if (!arj_skip_ext(file, &at)) {
			a->anomalies |= KOF_ARJ_ANOM_TRUNCATED;
			break;
		}

		if (first_header) {
			/*
			 * THE FIRST HEADER IS THE ARCHIVE'S OWN: its name is
			 * the archive's, it has no body, and the fields that
			 * matter are what wrote the file.
			 */
			kof_rd_u8(file, base + 1u, &a->archiver_ver);
			kof_rd_u8(file, base + 2u, &a->min_ver);
			kof_rd_u8(file, base + 3u, &a->host_os);
			a->arj_flags = flags;
			a->names_off = name_at;
			a->names_len = name_len + cmt_len;
			a->data_off = at;
			first_header = 0;
			continue;
		}

		/* KNOWN DEFECT WP2-D1b (2026-10-24, M) [sev M]: The arj member walk ends silently on a packed size
		 * past EOF (as WP2-D1). Trigger: middle of 3 members claims 0xfffffff0. Effect: 1 of 3
		 * opened, broken 0. Reproducer: tests/unit/ctr_liars.c arj/claimBoth, arj/claimPack. Fix: as
		 * WP2-D1, from KOF_ARJ_ANOM_TRUNCATED. */
		if ((uint64_t)csize > file.n - at) {
			a->anomalies |= KOF_ARJ_ANOM_TRUNCATED;
			break;
		}
		body = at;
		at += csize;

		if (!a->names_off)
			a->names_off = name_at;
		a->names_len = name_at + name_len + cmt_len - a->names_off;
		a->data_len = at > a->data_off ? at - a->data_off : 0;
		if (kof_cname_traversal(file, name_at, name_len - 1u))
			a->anomalies |= KOF_ARJ_ANOM_TRAVERSAL;

		/* File type 3 is a directory and 2 is a volume label: neither
		 * is content, and neither has a body worth pointing at. */
		if (ftype == 3u || ftype == 2u) {
			a->n_dirs++;
			continue;
		}
		/*
		 * WHAT THE METHOD MEANS FOR THE ENTRY.
		 *
		 * Zero is stored: the body IS the file, and it becomes a child
		 * with no module at all. One to three are a single coding -
		 * see KOF_UNP_LZHUF_ARJ - so they become entries too, naming
		 * that coding and carrying the original size, which is the only
		 * thing that ends the stream.
		 *
		 * Four is a different coding with no decoder here, and a
		 * GARBLED entry is encrypted: both are counted and left, which
		 * is the same answer this build gives everywhere it cannot
		 * open something.
		 */
		if ((flags & ARJ_F_GARBLED) || !csize ||
		    (method != 0u && (method > 3u || !osize))) {
			a->n_coded++;
			if (method != 0u)
				a->anomalies |= KOF_ARJ_ANOM_CODED;
			continue;
		}
		if (a->n_entries >= cap_entry) {
			void *t = a->entry;

			/* The walk stops HERE and says so: the headers that follow are in the archive
			 * and not in the table. */
			if (!kof_tab_grow(&a->mem, &t, &cap_entry, sizeof *a->entry,
					  (uint64_t)a->n_entries + 1u, rows_limit)) {
				a->anomalies |= KOF_ARJ_ANOM_ENTRIES_FULL;
				break;
			}
			a->entry = (struct kof_entry *)t;
		}
		{
			struct kof_entry *e = &a->entry[a->n_entries];

			memset(e, 0, sizeof *e);
			e->index    = a->n_entries;
			e->kind     = KOF_ENT_EMBEDDED;
			e->format   = KOF_FMT_UNKNOWN;
			e->name_off = name_at;
			e->name_len = name_len - 1u;   /* without the NUL */
			e->off      = body;
			e->len      = csize;
			if (method != 0u) {
				a->n_coded++;
				a->anomalies |= KOF_ARJ_ANOM_CODED;
				e->coding[0] = KOF_UNP_LZHUF_ARJ;
				e->out_hint  = osize;
			} else if (osize && osize != csize) {
				e->out_hint = osize;
			}
			a->n_entries++;
		}
	}
	a->anomalies |= KOF_ARJ_ANOM_NO_END;

ended:
	a->mem.rows = a->n_entries;
	ctx->format = KOF_FMT_ARJ;
	ctx->obj_size = file.n;
	ctx->file_header = a;
	ctx->resolve_scan = arj_resolve_scan;
	ctx->entries = arj_entries;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_arj_region_bits[] = { ARJ_REGIONS(X_BIT) };
_Static_assert(sizeof kof_arj_region_bits / sizeof kof_arj_region_bits[0] ==
	       KOF_ARJ_REGION_COUNT, "region list and its count disagree");

const char *kof_arj_region_name(uint32_t bit)
{
	switch (bit) {
	ARJ_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_arj_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"TRUNCATED", "BAD_HEADER", "CODED", "VOLUME", "ENCRYPTED",
		"TRAVERSAL", "ENTRIES_FULL", "NO_END"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_ARJ_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
