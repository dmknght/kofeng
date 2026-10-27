/*
 * ctr_check.h - the invariants every container parse answers to, as functions that SAY what failed (NULL: nothing), so that the
 * fuzz adapters (tests/fuzz/container/parse.c, which turns a reason into FZ_CHECK) and the deterministic sweeps
 * (tests/unit/ctr_cuts.c, which turns it into CK) share one copy. A second copy of a check is a second thing that can be wrong
 * in a way that agrees with the code it is testing (partition_check.h says so).
 *
 *   ctr_partition   the regions the parse declares partition the object: every byte in exactly one region, no extent empty,
 *                   wrapping or past the end. The KNOWN overlaps are carved out per format and counted, never hidden:
 *                     WP2-D9   a CAB's DATA / a CHM's CONTENT region that starts before the regions ahead of it end
 *                     WP2-D10  a CAB's HEADERS, FOLDERS and NAMES overlapping one another
 *                   (tests/unit/ctr_regions.c holds each as a KM_CHECK that turns red the day the engine is fixed).
 *   ctr_entries     the entry table is in range, does not amplify, has real kinds and methods (entry_check.h). WP2-D11 (a CAB's or
 *                   CHM's file records naming one range twice) is carved out per format.
 *
 * Needs tests/unit/entry_check.h's includes (<kofmod/kofsig.h>) before it.
 */
#ifndef KOF_TESTS_CTR_CHECK_H
#define KOF_TESTS_CTR_CHECK_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/kofsig.h>
#include <kofmod/cab.h>
#include <kofmod/chm.h>
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../unit/entry_check.h"

#define CCK_UNUSED __attribute__((unused))

struct cck_policy {
	uint32_t data_bit;      /* a region that may start inside the ones before it (the known defect), 0: none */
	uint32_t set_mask;      /* regions that may overlap one another (the known defect), 0: none */
	int      same_range_ok; /* entries over one range are not reported */
};

/* The policy of a format: only CAB and CHM carry known defects. */
static CCK_UNUSED struct cck_policy cck_policy_of(uint8_t fmt)
{
	struct cck_policy p = { 0, 0, 0 };

	if (fmt == KOF_FMT_CAB) {
		p.data_bit = KOF_SCAN_CAB_DATA;
		p.set_mask = KOF_SCAN_CAB_HEADERS | KOF_SCAN_CAB_FOLDERS | KOF_SCAN_CAB_NAMES;
		p.same_range_ok = 1;
	} else if (fmt == KOF_FMT_CHM) {
		p.data_bit = KOF_SCAN_CHM_CONTENT;
		p.same_range_ok = 1;
	}
	return p;
}

struct cck_ext {
	uint64_t off, len;
	uint32_t reg;
};

static CCK_UNUSED int cck_cmp(const void *a, const void *b)
{
	const struct cck_ext *x = (const struct cck_ext *)a, *y = (const struct cck_ext *)b;

	return x->off < y->off ? -1 : x->off > y->off ? 1 : x->len < y->len ? -1 : x->len > y->len ? 1 : 0;
}

/* NULL when the regions partition [0, n), else why not. *known counts the carved-out overlaps taken. */
static CCK_UNUSED const char *ctr_partition(const struct kof_obj_ctx *ctx, const struct kof_parser *p, uint64_t n, const struct cck_policy *pol,
					    uint64_t *known)
{
	static struct cck_ext all[KOF_SCAN_MAX_EXTENTS * 8];
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t na = 0, i, k, holder = 0;
	uint64_t cursor = 0;

	if (known)
		*known = 0;
	for (i = 0; i < p->n_regions; i++) {
		uint32_t m = ctx->resolve_scan ? ctx->resolve_scan(ctx, p->regions[i], ext, KOF_SCAN_MAX_EXTENTS) : 0;

		if (m == KOF_SCAN_MAX_EXTENTS)
			return NULL;                             /* the extent cap: the part is not the whole, by design */
		for (k = 0; k < m; k++) {
			if (na == sizeof all / sizeof all[0])
				return "more extents than the pool holds";
			all[na].off = ext[k].off;
			all[na].len = ext[k].len;
			all[na].reg = p->regions[i];
			na++;
		}
	}
	qsort(all, na, sizeof all[0], cck_cmp);
	for (i = 0; i < na; i++) {
		uint64_t end = all[i].off + all[i].len;

		if (all[i].len == 0)
			return "an empty extent";
		if (end < all[i].off)
			return "an extent wraps";
		if (end > n)
			return "an extent past the end of the object";
		if (all[i].off > cursor)
			return "a byte in no region";
		if (all[i].off < cursor) {
			if ((pol->data_bit && (all[i].reg == pol->data_bit || holder == pol->data_bit)) ||
			    ((pol->set_mask & all[i].reg) && (pol->set_mask & holder))) {
				if (known)
					(*known)++;
			} else {
				return "two regions overlap";
			}
		}
		if (end > cursor) {
			cursor = end;
			holder = all[i].reg;
		}
	}
	if (cursor != n && na)
		return "the regions do not cover the object";
	if (!na && n)
		return "no region at all";
	return NULL;
}

/* NULL when the entry table is sound, else a fixed reason. *rows is how many rows were examined. */
static CCK_UNUSED const char *ctr_entries(const struct kof_obj_ctx *ctx, uint64_t n, const struct cck_policy *pol, uint64_t *rows)
{
	struct ec_report er;

	memset(&er, 0, sizeof er);
	er.quiet = 1;
	er.allow_same_range = pol->same_range_ok;
	ec_check("ctr", ctx, n, &er);
	if (rows)
		*rows = er.entries;
	return er.failed ? "an entry is out of range, amplifies, repeats or has an impossible kind or method" : NULL;
}

#endif
