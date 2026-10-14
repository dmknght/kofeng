/*
 * scan_ext.c - where a region resolve puts its extents, and how that place grows.
 *
 * WHAT THIS SERVES: every search, gather and similarity feed over a region of a parsed
 * object. A region comes back as a list of ranges, and how many there are is a property of
 * the FILE: a zip stores each entry's name between two pieces of header, twice, so its
 * NAMES region is two ranges an entry; a PDF's streams are one range each. The buffer was
 * 4096 ranges, chosen from the largest archive of the day, and 2100 entries were enough to
 * make "names" not fit - after which the scan was told the object was cut and opened none
 * of its members (tests/unit/limits_children.c, 2100 entries: 0 children, broken=LIMIT).
 *
 * The buffer now starts at that size, in the scanner (no allocation, no new fixed cost) and
 * is grown when a resolve fills it, to the size the answer needs: a resolve that comes
 * back full is run again into a larger buffer, which is what a cut answer was never
 * allowed to be. What bounds it is not a count but the two things that are about cost: the
 * object (a range is at least a byte, so no region has more ranges than the object has
 * bytes) and the per-object ledger, which the larger buffer is charged to for as long as
 * the object is being scanned and given back with it (sx_ext_release). When the ledger
 * cannot afford the larger buffer the answer is the part that fits and the object is said
 * to be cut, exactly as before - the degradation order of CLAUDE.md section 12.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objctx_int.h"
#include <stdlib.h>

/*
 * The two buffers - one answers a search, one feeds a copy, see struct kof_scan_cache -
 * set up on first use: the scanner is calloc'd, so a pointer that is not there yet is
 * the state of a scanner that has not resolved a region.
 */
struct kof_ext_buf *kof_scan_ext_buf(struct kof_scanner *sc, int gather)
{
	struct kof_ext_buf *eb = gather ? &sc->cache.gather_buf : &sc->cache.ext_buf;

	if (!eb->v) {
		eb->v = gather ? sc->cache.ext_gather : sc->cache.ext;
		eb->cap = KOF_SCAN_MAX_EXTENTS;
	}
	return eb;
}

/* A buffer of at least twice the size, charged to the ledger, or 0 and `eb` is as it was.
 * Never past the object: a region of an object of n bytes has at most n ranges, so a
 * buffer of n + 1 cannot come back full and there is nothing to grow into beyond it. */
static int ext_grow(struct kof_scanner *sc, struct kof_ext_buf *eb, uint64_t obj_size)
{
	uint64_t nc = (uint64_t)eb->cap * 2u, delta, bytes;
	struct kof_range *t;

	if (eb->fixed || (uint64_t)eb->cap > obj_size)
		return 0;
	if (nc > obj_size + 1u)
		nc = obj_size + 1u;
	if (nc > 0x7fffffffu)
		nc = 0x7fffffffu;
	if (nc <= eb->cap)
		return 0;
	bytes = nc * sizeof *t;
	delta = bytes - (eb->heap ? (uint64_t)eb->cap * sizeof *t : 0u);
	if (delta > oc_scan_room(sc))
		return 0;
	t = malloc((size_t)bytes);
	if (!t)
		return 0;
	scan_charge(sc, delta);
	eb->charged += delta;
	free(eb->heap);
	eb->heap = t;
	eb->v = t;
	eb->cap = (uint32_t)nc;
	return 1;
}

/*
 * Turn a named range into extents.
 *
 * Here rather than in objctx.c because only the parse knows where a region is, and this
 * is the file that ran it. KOF_SCAN_ALL needs no parse at all, which is what lets a
 * module naming only that region run against input nothing identified.
 *
 * `eb` is where the answer goes; read it from `eb->v` AFTER the call - a resolve that
 * came back full has run again into a larger buffer. A caller-owned buffer (`fixed`, a
 * tool's) is never grown and a full answer is cut and said, as it always was.
 */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				struct kof_ext_buf *eb)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t n;

	if (scan_mask & KOF_SCAN_ALL) {
		eb->v[0].off = 0;
		eb->v[0].len = ctx->obj_size;
		return ctx->obj_size ? 1u : 0u;
	}
	if (!ctx->resolve_scan)
		return 0;
	for (;;) {
		n = ctx->resolve_scan(ctx, scan_mask, eb->v, eb->cap);
		if (n < eb->cap)
			return n;
		/*
		 * A buffer that filled exactly is indistinguishable from one that filled and
		 * had more to write (a resolver says the same when it DROPPED a range:
		 * struct kof_rlist .overflow, handed back by kof_rl_finish as n == max_out),
		 * so it is run again into a larger one. Only when none can be had does what
		 * follows search part of the region.
		 */
		if (!sc || !ext_grow(sc, eb, ctx->obj_size))
			break;
	}
	/*
	 * The region did not fit, so what follows searches part of it.
	 *
	 * Said rather than swallowed: a search over some of a region, reported as a search
	 * over the region, is the one answer this engine must never give quietly. It is a
	 * limit like any other - the ledger (or the caller's buffer) set the size, and the
	 * caller can be told it bound.
	 *
	 * A CUT AND NOT A STOP. This used to set the object's `broken`, which is what ends the open
	 * stage (scan_unpack.c: the module loop runs only while nothing is broken) - so a region that
	 * did not fit, asked about by any rule before the members were opened, took every member with
	 * it, and the whole of what a zip of 2100 entries holds was gone for a buffer that held
	 * 2048 of its names. oc_scan_limit is the other kind of limit: the object reads
	 * KOF_BROKEN_LIMIT when it is reported (scan_pipeline.c), and what the tables did hold is
	 * still opened - the degrade order of CLAUDE.md section 12, where the object is refused last.
	 */
	if (sc)
		oc_scan_limit(sc);      /* said at the end of the object, and counted once */
	return eb->cap;
}

/*
 * THE PIECES OF ONE ENTRY, into the gather buffer, grown until the answer fits.
 *
 * resolve_entry (cab, chm and docole answer it) was handed a fixed KOF_SCAN_MAX_EXTENTS-range
 * array at five call sites, and a resolver that fills what it is given says the same as one
 * that dropped ranges (struct kof_rlist .overflow, n == max_out), so an entry of more than
 * 4096 pieces - a cabinet file over 256 MB of 64 KiB blocks, a help file's long member -
 * was decoded from its first 4096 and handed on as the file, with nothing said. It is the
 * loop kof_scan_resolve_range runs for a region, for the same reason, into the same buffer
 * (charged to the ledger, given back with the object by sx_ext_release).
 *
 * When no larger buffer can be had (the ledger's room, or a buffer already as long as the
 * object has bytes) the answer is ZERO PIECES and the object is said to have hit a limit
 * (oc_scan_limit): a decode from some of an entry's pieces is a different file, and
 * QUALITY_AUDIT I.C forbids handing one on as if it were the entry. Read the ranges from
 * `eb->v` after the call; the pointer may have moved.
 */
uint32_t kof_scan_resolve_entry(const struct kof_obj_ctx *ctx, uint32_t index,
				struct kof_ext_buf *eb)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t n;

	if (!ctx->resolve_entry)
		return 0;
	for (;;) {
		n = ctx->resolve_entry(ctx, index, eb->v, eb->cap);
		if (n < eb->cap)
			return n;
		if (!sc || !ext_grow(sc, eb, ctx->obj_size))
			break;
	}
	if (sc)
		oc_scan_limit(sc);
	return 0;
}

/*
 * Give back what the buffers grew to, at the end of the object that grew them: the ledger
 * is per tree and what this charged was for this object. The scanner keeps the floor.
 */
void sx_ext_release(struct kof_scanner *sc)
{
	struct kof_ext_buf *eb[2] = { &sc->cache.ext_buf, &sc->cache.gather_buf };
	int i;

	for (i = 0; i < 2; i++) {
		if (!eb[i]->heap)
			continue;
		free(eb[i]->heap);
		eb[i]->heap = NULL;
		oc_scan_release(sc, eb[i]->charged);
		eb[i]->charged = 0;
		eb[i]->v = i ? sc->cache.ext_gather : sc->cache.ext;
		eb[i]->cap = KOF_SCAN_MAX_EXTENTS;
	}
}
