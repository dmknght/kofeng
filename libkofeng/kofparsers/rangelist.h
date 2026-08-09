/*
 * rangelist.h - building a set of byte ranges over an object.
 *
 * Every parser answers the same question in the same shape: given a region mask,
 * which byte ranges of this object does it name? The geometry of that answer -
 * clipping to the object, sorting, merging what touches, inverting to get a
 * complement - has nothing to do with any format, so it lives here and each parser
 * supplies only the format specific part: which structures claim which bytes.
 *
 * Header only and static inline: this is on the resolve path, which runs per region
 * per object, and the alternative is a call through a translation unit boundary for
 * a function that appends four fields.
 *
 * The invariant every parser must hold, and the reason this file exists: the regions
 * of a format partition the object. Every byte is in exactly one, so OR-ing masks
 * together scans no byte twice, and coalescing is all the deduplication a union
 * needs. ELF proved it on 319 of 319 objects; a new format is expected to prove it
 * the same way rather than to assume it.
 */

#ifndef KOFENG_RANGELIST_H
#define KOFENG_RANGELIST_H

#include <stdint.h>
#include <kofmod/kofsig.h>
#include "../core/kofcore.h"   /* kof_clip_len */

/* A range list under construction, bounded by the caller's buffer. */
struct kof_rlist {
	struct kof_range *v;
	uint32_t n;
	uint32_t cap;
};

static inline void kof_rl_init(struct kof_rlist *l, struct kof_range *buf,
			       uint32_t cap)
{
	l->v = buf;
	l->n = 0;
	l->cap = cap;
}

/*
 * Append [o, o+n) clipped to the object. Saturating on the end, since both values
 * come from header fields that may be hostile.
 *
 * Order does not matter here; the caller sorts once at the end rather than keeping
 * the list ordered through every insert.
 */
static inline void kof_rl_add(struct kof_rlist *l, uint64_t obj_size,
			      uint64_t o, uint64_t n)
{
	uint64_t got = kof_clip_len(obj_size, o, n);

	if (got == 0 || l->n >= l->cap)
		return;
	l->v[l->n].off = o;
	l->v[l->n].len = got;
	l->n++;
}

/*
 * Sort by offset, then merge anything that touches or overlaps.
 *
 * Insertion sort on purpose: segments and sections are almost always already in
 * offset order, which makes this a linear scan, and the list is bounded by the
 * segment and section counts. A comparison sort with better worst case would be
 * slower on every real input.
 *
 * Merging on touch, not just on overlap, is what lets a pattern spanning the join
 * between two adjacent regions be found - if code ends exactly where data begins,
 * the union is one range.
 */
static inline uint32_t kof_rl_normalise(struct kof_rlist *l)
{
	uint32_t i, j, w;

	for (i = 1; i < l->n; i++) {
		struct kof_range t = l->v[i];
		for (j = i; j > 0 && l->v[j - 1].off > t.off; j--)
			l->v[j] = l->v[j - 1];
		l->v[j] = t;
	}

	w = 0;
	for (i = 0; i < l->n; i++) {
		if (w > 0) {
			uint64_t we = l->v[w - 1].off + l->v[w - 1].len;
			if (l->v[i].off <= we) {
				uint64_t ie = l->v[i].off + l->v[i].len;
				if (ie > we)
					l->v[w - 1].len = ie - l->v[w - 1].off;
				continue;
			}
		}
		l->v[w++] = l->v[i];
	}
	l->n = w;
	return w;
}

/*
 * Append the complement of `claimed` to `out`.
 *
 * `claimed` must already be normalised: the gaps between ranges are only the right
 * answer once overlaps have been merged, which is why this does not do it here -
 * a caller that forgets would get a plausible wrong answer instead of a failure.
 *
 * This is what makes an UNCLAIMED region mean something: bytes no structure in the
 * file admitted to owning.
 */
static inline void kof_rl_complement(struct kof_rlist *out,
				     const struct kof_rlist *claimed,
				     uint64_t obj_size)
{
	uint64_t cursor = 0;
	uint32_t i;

	for (i = 0; i < claimed->n; i++) {
		if (claimed->v[i].off > cursor)
			kof_rl_add(out, obj_size, cursor,
				   claimed->v[i].off - cursor);
		cursor = claimed->v[i].off + claimed->v[i].len;
	}
	if (cursor < obj_size)
		kof_rl_add(out, obj_size, cursor, obj_size - cursor);
}

/*
 * One structure's claim on part of an object, before and after settling.
 *
 * `rank` breaks a tie when two claimants start at the same offset, and lower
 * wins: it is what lets a header block outrank a segment that also begins at
 * zero. `tag` is the caller's, carried through untouched so it can scatter the
 * results back where they came from.
 */
struct kof_claim {
	uint64_t off, len;          /* what the structure declared */
	uint64_t got_off, got_len;  /* what it owns once settled; 0 if nothing */
	uint32_t rank;
	uint32_t tag;
};

/*
 * Decide which claimant owns which bytes, so that the claims are disjoint.
 *
 * Both formats need this and neither can do without it. ELF describes the same
 * file twice on purpose, through segments and sections, so overlap is the normal
 * case rather than the hostile one; PE has one description, but nothing stops two
 * section headers pointing at the same bytes, and a single flipped byte in a real
 * file was enough to make it happen. Regions built from overlapping claims are not
 * a partition, and every property that rests on the partition quietly stops being
 * true.
 *
 * Taken in offset order with the earlier claimant keeping the bytes. Front
 * trimming alone is enough to leave every claim contiguous: sorted by offset, a
 * claimant can only ever collide with what is already behind it.
 *
 * The declared values are left alone. A module reading what the file said still
 * gets it; only the region machinery uses what was settled.
 */
static inline void kof_rl_settle(struct kof_claim *c, uint32_t n,
				 uint64_t obj_size)
{
	uint64_t end = 0;
	uint32_t i, j;

	/* Insertion sort by offset then rank: bounded by the segment and section
	 * maxima, and a real object is already in order, so this is a linear scan
	 * on everything that is not trying to be difficult. */
	for (i = 1; i < n; i++) {
		struct kof_claim t = c[i];
		for (j = i; j > 0 && (c[j - 1].off > t.off ||
		     (c[j - 1].off == t.off && c[j - 1].rank > t.rank)); j--)
			c[j] = c[j - 1];
		c[j] = t;
	}

	for (i = 0; i < n; i++) {
		uint64_t off = c[i].off;
		uint64_t lim = kof_sat_add(off, c[i].len);

		c[i].got_off = 0;
		c[i].got_len = 0;
		if (lim > obj_size)
			lim = obj_size;
		if (off < end)
			off = end;
		if (off >= lim)
			continue;
		c[i].got_off = off;
		c[i].got_len = lim - off;
		end = lim;
	}
}

#endif /* KOFENG_RANGELIST_H */