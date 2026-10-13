/*
 * runlist.h - regions built by walking, rather than by listing.
 *
 * rangelist.h answers a region mask from structures a parser already holds: an ELF
 * has its segments in an array, so resolving CODE is a loop over them and needs no
 * memory of its own. The container formats cannot work that way. A CFB stream is a
 * chain through an allocation table and a zip entry's data is found by reading a
 * local header at an offset the central directory gives - so which bytes belong to
 * which region is discovered by WALKING, once, and there is nothing left afterwards
 * to resolve a mask against.
 *
 * So these parsers record what they found as they found it, and this is where it
 * goes: a flat pool of runs, each tagged with the class that claims it. Flat rather
 * than a list per class because a view whose size multiplies by the number of
 * classes is a view that gets smaller as formats get richer, and because a run
 * discovered during a walk has no idea what came before it.
 *
 *
 * WHAT THIS GUARANTEES, AND WHY IT HAS TO
 *
 * That the runs PARTITION the object: every byte in at most one, and the gaps
 * available as the complement. Every region mask in this engine rests on it - two
 * regions sharing a byte means OR-ing their masks scans that byte twice, and a
 * pattern's match count stops meaning anything.
 *
 * Neither format can promise it by construction. Nothing in a compound file stops a
 * stream's chain running through the directory, and nothing in a zip stops two
 * entries pointing at the same data; a single flipped field is enough in a file
 * nobody built to be hostile. So it is settled rather than assumed: sorted by
 * offset, and where two runs collide the lower numbered class keeps the bytes.
 * Class order is the priority, which is why both formats number their classes from
 * the container's own structures outward to the content.
 *
 * Header only and static inline for the same reason rangelist.h is: this is on the
 * resolve path, which runs per region per object.
 */

#ifndef KOFENG_RUNLIST_H
#define KOFENG_RUNLIST_H

#include <stdint.h>
#include "kofcore.h"   /* kof_clip_len */
#include "rangelist.h"        /* kof_rlist, for answering a mask */
#include "heapsort.h"         /* KOF_HEAPSORT */

/* struct kof_run - one run of bytes and what claims it - is range.h's: the parsers'
 * info structs in kofmod/ hold the same array, so the type is shared. */

/*
 * TWELVE, AND IT WAS EIGHT.
 *
 * A bound rather than a parameter because it sizes the coalescing hint below, and a
 * hint that had to be allocated would put a malloc in front of every parse to save
 * twenty bytes of a structure that is allocated once per scanner.
 *
 * Eight was "two more than the format with the most classes uses", and that stopped
 * being true: PDF reached seven the moment its stream regions were split by what the
 * bytes ARE - pixels, fonts, script - rather than by how they are coded, and the
 * eighth was the last. Rationing the last one is the wrong shape of decision to be
 * making: which categories a format can express should be settled by whether the
 * format can decide them, not by a constant sizing a hint array. Four more costs
 * sixteen bytes of a per-parse structure.
 */
#define KOF_RUNS_MAX_CLS 12u

struct kof_runs {
	struct kof_run *v;
	uint32_t n, cap;
	uint32_t ncls;

	/*
	 * The index, plus one, of the most recent run of each class.
	 *
	 * Consecutive sectors of one chain, or consecutive entries of one archive,
	 * are one extent - and joining them as they arrive is what keeps a stream
	 * fragmented at 64 byte granularity from filling the pool. Only the LAST run
	 * of the class is tried: a walk lays its runs down in order, so that is where
	 * a join can be, and searching further back would cost more than it saves.
	 */
	uint32_t last[KOF_RUNS_MAX_CLS];

	/* Set when a run was dropped for want of room. The caller turns it into
	 * whatever its format calls that, because it is a fact about the file. */
	uint32_t full;
	/* Set when a run had to be clipped to the object: the file named bytes it
	 * does not contain. */
	uint32_t clipped;
	/*
	 * Set by settle when two runs claimed the same bytes.
	 *
	 * Worth reporting rather than silently resolving. In both formats that use
	 * this it is a thing a file has to be built to do - two archive entries
	 * pointing at one blob, a stream chained through the directory - and it is one
	 * of the ways an archive is made to read differently to two different readers.
	 */
	uint32_t overlapped;
};

static inline void kof_runs_init(struct kof_runs *l, struct kof_run *buf,
				 uint32_t cap, uint32_t ncls)
{
	uint32_t i;

	l->v = buf;
	l->n = 0;
	l->cap = cap;
	l->ncls = ncls < KOF_RUNS_MAX_CLS ? ncls : KOF_RUNS_MAX_CLS;
	l->full = 0;
	l->clipped = 0;
	l->overlapped = 0;
	for (i = 0; i < KOF_RUNS_MAX_CLS; i++)
		l->last[i] = 0;
}

/*
 * Claim [off, off+n) for `cls`, clipped to the object.
 *
 * Both values come from fields a file chose, so clipping is the normal case rather
 * than the hostile one, and it is recorded rather than refused: a truncated archive
 * is still worth what is left of it.
 */
static inline void kof_runs_add(struct kof_runs *l, uint64_t obj_size,
				uint64_t off, uint64_t n, uint32_t cls)
{
	uint64_t got = kof_clip_len(obj_size, off, n);

	if (n == 0 || cls >= l->ncls)
		return;
	if (got != n)
		l->clipped = 1;
	if (got == 0)
		return;

	if (l->last[cls]) {
		struct kof_run *r = &l->v[l->last[cls] - 1u];

		if (r->off + r->len == off) {
			r->len += got;
			return;
		}
	}
	if (l->n >= l->cap) {
		l->full = 1;
		return;
	}
	l->v[l->n].off = off;
	l->v[l->n].len = got;
	l->v[l->n].cls = cls;
	l->v[l->n].reserved = 0;
	l->n++;
	l->last[cls] = l->n;
}

/* Ordered by where a run starts, and by class where two start together - the lower
 * numbered class wins a tie, which is what makes the settle below deterministic. */
static inline int kof_run_before(const struct kof_run *a, const struct kof_run *b)
{
	return a->off < b->off || (a->off == b->off && a->cls < b->cls);
}

/*
 * Sort the runs, in a way an archive cannot make expensive.
 *
 * This was an insertion sort, chosen because a walk lays its runs down close to
 * sorted and that makes it linear. The first half of that is still true and is why
 * the sortedness check below comes first; the second half was only true of files
 * nobody built to be difficult.
 *
 * A zip states the order of its own central directory, so an archive that lists its
 * entries by DECREASING offset hands the insertion sort its worst case. Measured at
 * the 8192 run cap that is 21.7ms of pure sorting for one object - so a few hundred
 * such archives inside one tar is a scan that stops, from an input of a few tens of
 * megabytes. Nothing about it looks like a bomb: no ratio to notice, no memory to
 * refuse, just time.
 *
 * So: one pass to see whether there is anything to do, which keeps the ordinary
 * file at O(n) and faster than it was; and heapsort when there is, which is
 * O(n log n) with no worst case to find, in place, and needing no allocation on a
 * path that must not fail.
 */
KOF_HEAPSORT(kof_runs, struct kof_run, kof_run_before)

/*
 * Make the runs disjoint and ordered, and total what each class ended up with.
 *
 * `bytes` receives the covered total per class, which is NOT what the file declared
 * - a stream whose chain runs off the end, or whose bytes another structure already
 * claimed, declares more than it owns. The difference between the two is worth
 * having: a module that checked a gather against the declared size would report a
 * limit on a file that reached no limit, only damage.
 *
 * Front trimming alone leaves every run contiguous: taken in order, a run can only
 * collide with what is already behind it. The ordering itself is kof_runs_sort's
 * job, and the note there says why it is not the insertion sort this used to be.
 */
static inline void kof_runs_settle(struct kof_runs *l, uint64_t *bytes)
{
	uint64_t end = 0;
	uint32_t i, w = 0;

	for (i = 0; i < l->ncls; i++)
		bytes[i] = 0;

	kof_runs_sort(l->v, l->n);

	for (i = 0; i < l->n; i++) {
		uint64_t off = l->v[i].off, lim = off + l->v[i].len;

		if (off < end) {
			off = end;
			l->overlapped = 1;
		}
		if (off >= lim) {
			l->overlapped = 1;
			continue;
		}
		end = lim;
		l->v[w].off = off;
		l->v[w].len = lim - off;
		l->v[w].cls = l->v[i].cls;
		l->v[w].reserved = 0;
		bytes[l->v[w].cls] += l->v[w].len;
		w++;
	}
	l->n = w;
}

/*
 * Answer a region mask from settled runs.
 *
 * `cls_bit` maps a class to the region bit that names it, so this stays free of
 * every format's enum. `unclaimed` is the bit for the complement, or zero for a
 * format without one.
 *
 * The complement is taken straight from the gaps rather than by resolving the
 * claimed mask a second time and inverting it: the runs are already settled and in
 * offset order, so the gaps between them ARE the answer, with no second sort.
 */
static inline uint32_t kof_runs_resolve(const struct kof_run *v, uint32_t n,
					uint32_t mask, const uint32_t *cls_bit,
					uint32_t unclaimed, uint64_t obj_size,
					struct kof_range *out, uint32_t max_out)
{
	struct kof_rlist l;
	uint32_t i;

	kof_rl_init(&l, out, max_out);

	for (i = 0; i < n; i++)
		if (mask & cls_bit[v[i].cls])
			kof_rl_add(&l, obj_size, v[i].off, v[i].len);

	if (unclaimed && (mask & unclaimed)) {
		uint64_t cursor = 0;

		for (i = 0; i < n; i++) {
			if (v[i].off > cursor)
				kof_rl_add(&l, obj_size, cursor, v[i].off - cursor);
			cursor = v[i].off + v[i].len;
		}
		if (cursor < obj_size)
			kof_rl_add(&l, obj_size, cursor, obj_size - cursor);
	}
	return kof_rl_normalise(&l);
}

/*
 * THE resolve_scan OF A FORMAT WHOSE VIEW CARRIES SETTLED RUNS, written once.
 *
 * Eight parsers (tar, rtf, rar, docole, zip, reg, pdf, xz) each carried a
 * line-for-line copy of this function; they differed only in the view struct
 * (the type behind ctx->file_header), the class-to-bit table, and the bit for
 * the complement. Those three are the parameters. The view must have the
 * members `valid`, `run[]` and `n_runs`, and its run must have the shape of
 * struct kof_run - the cast is to that shared shape, which the ABI header of
 * the format spells out field for field rather than including a host header,
 * so a mismatch would be a memory bug and is asserted at compile time instead
 * of trusted.
 *
 * Expands to a static function `<fmt>_resolve_scan`, the signature of
 * ctx->resolve_scan. A macro and not a function because the view types are
 * different structs with the fields at different offsets: a function would
 * need a wrapper per format, which is the copy this removes. Needs
 * <kofmod/kofsig.h> (struct kof_obj_ctx) at the point of use.
 */
#define KOF_RUNS_RESOLVER(fmt, view_t, cls_bit_tab, unclaimed_bit)          \
static uint32_t fmt##_resolve_scan(const struct kof_obj_ctx *ctx,          \
				   uint32_t mask, struct kof_range *out,    \
				   uint32_t max_out)                       \
{                                                                          \
	const view_t *v = (const view_t *)ctx->file_header;                \
									   \
	if (!v || !v->valid || !out || max_out == 0)                       \
		return 0;                                                  \
	_Static_assert(sizeof v->run[0] == sizeof(struct kof_run),         \
		       "the view's run and runlist.h's have drifted apart");\
	return kof_runs_resolve((const struct kof_run *)v->run, v->n_runs, \
				mask, cls_bit_tab, unclaimed_bit,          \
				ctx->obj_size, out, max_out);              \
}

#endif /* KOFENG_RUNLIST_H */