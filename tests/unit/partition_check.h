/*
 * partition_check.h - the invariant every collector has to hold.
 *
 * The regions a format defines cover every byte of the object exactly once. Not
 * approximately: the lengths sum to the file size, and no two regions return the
 * same offset.
 *
 * Shared by the tests that check it on real files and the one that checks it on
 * files built to break it, because a second copy of the check is a second thing
 * that can be wrong in a way that agrees with the code it is testing.
 *
 * The whole scan-scoping design rests on this. A module asking for CODE | DATA
 * gets one pass over the union, which is only correct if the two are disjoint; a
 * byte in no region is a byte no signature can reach; a byte in two is searched
 * twice with nothing to notice it. Fuzzing found a real violation here within
 * four hundred samples, so it is not a theoretical property.
 */

#ifndef KOFENG_PARTITION_CHECK_H
#define KOFENG_PARTITION_CHECK_H

#include <stdio.h>
#include <stdlib.h>
#include <kofmod/kofsig.h>

struct pc_report {
	uint64_t checked, failed;
	int      quiet;          /* count failures without printing every one */
};

static int pc_cmp(const void *a, const void *b)
{
	const struct kof_range *x = a, *y = b;

	if (x->off < y->off)
		return -1;
	return x->off > y->off;
}

/*
 * Ask for every region in turn, pool the extents, and walk them in order.
 *
 * Sorting rather than painting a bitmap over the object: a bitmap is the obvious
 * way and needs memory proportional to the file, which is the one thing this has
 * to avoid to be usable over a directory of them.
 */
static int pc_check(const char *what, const struct kof_obj_ctx *ctx,
		    uint64_t obj_size, const uint32_t *regions,
		    uint32_t n_regions, struct pc_report *rep)
{
	/* Every region can independently reach the extent cap, so the pool has to
	 * hold all of them at once or a full run would look like a gap. */
	static struct kof_range all[KOF_SCAN_MAX_EXTENTS * 8];
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t n_all = 0, i, k;
	uint64_t covered = 0, cursor = 0;
	const char *why = 0;
	uint64_t where = 0;

	rep->checked++;

	for (i = 0; i < n_regions; i++) {
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS)
			   : 0;
		for (k = 0; k < n; k++) {
			if (n_all == sizeof all / sizeof all[0]) {
				why = "more extents than the pool holds";
				goto done;
			}
			all[n_all++] = ext[k];
		}
	}

	qsort(all, n_all, sizeof all[0], pc_cmp);

	for (i = 0; i < n_all; i++) {
		if (all[i].len == 0) {
			why = "zero length extent";
			where = all[i].off;
			goto done;
		}
		if (all[i].off + all[i].len < all[i].off) {
			why = "extent wraps";
			where = all[i].off;
			goto done;
		}
		if (all[i].off + all[i].len > obj_size) {
			why = "extent past the end of the object";
			where = all[i].off;
			goto done;
		}
		if (all[i].off < cursor) {
			why = "regions overlap";
			where = all[i].off;
			goto done;
		}
		if (all[i].off > cursor) {
			why = "byte in no region";
			where = cursor;
			goto done;
		}
		cursor = all[i].off + all[i].len;
		covered += all[i].len;
	}
	if (covered != obj_size) {
		why = "regions do not cover the object";
		where = covered;
	}
done:
	if (why) {
		rep->failed++;
		if (!rep->quiet)
			printf("  FAIL %s: %s at %llu (object %llu)\n", what, why,
			       (unsigned long long)where,
			       (unsigned long long)obj_size);
		return 1;
	}
	return 0;
}

#endif /* KOFENG_PARTITION_CHECK_H */