/*
 * tabgrow.h - a table that is as long as the file says, and an account of what it holds.
 *
 * The container views (zip, pdf) used to carry fixed arrays whose length was chosen
 * from a corpus and then enforced as a limit on the FILE: the 4097th member of a zip was
 * not there, and neither were the members whose names no longer fitted in the extents
 * the scan could resolve. A cap is a bound on COST (CLAUDE.md rule 4), and the cost of a
 * table is its bytes - so the table grows to what the structure needs, and the two things
 * that bound it are the ones that are about cost:
 *
 *   `limit`  what the FILE can physically hold. The caller derives it from the object's
 *            byte length and the smallest record there is (a zip central record is 46
 *            bytes, a PDF object is "N G obj" and "endobj"), so a count the file merely
 *            CLAIMS - 65535 in the end record, a /Size of a billion - can never size an
 *            allocation: the allocation follows the bytes that are really there.
 *   `room`   what the engine's per-object ledger has left (struct kof_view_mem.room).
 *            When it cannot be had the table stays as it is, kof_tab_grow answers 0, and
 *            the parse raises its "table full" anomaly: the rows past the end are REPORTED
 *            (KOF_BROKEN_LIMIT through kof_parser_cut_bits), never dropped quietly.
 *
 * Header only, engine side: a module never allocates and never includes this.
 */

#ifndef KOFENG_TABGROW_H
#define KOFENG_TABGROW_H

#include <stdint.h>
#include <stdlib.h>
#include "range.h"

/* What the account still allows: room less held, or no limit at all for a caller that set
 * none (struct kof_view_mem.room == 0 - see range.h). */
static inline uint64_t kof_view_room(const struct kof_view_mem *m)
{
	if (!m->room)
		return UINT64_MAX;
	return m->held < m->room ? m->room - m->held : 0;
}

/*
 * Make `*tab` (rows of `elem` bytes, `*cap` of them) hold at least `want` rows.
 *
 * 1 when it does, 0 when `want` is past `limit`, past the room, or the allocator said no;
 * in every 0 case the table is exactly as it was and still valid for the rows it had.
 *
 * Grown by doubling, so a table filled one row at a time costs a handful of reallocs and
 * not one per row; when the doubled size does not fit the room the exact size asked for is
 * tried before giving up, because the last rows of a file are worth more than the slack.
 * Sizes are computed in 64 bits and `limit` is at most 2^32 - 1 rows.
 */
static inline int kof_tab_grow(struct kof_view_mem *m, void **tab, uint32_t *cap,
			       size_t elem, uint64_t want, uint64_t limit)
{
	uint64_t nc, old_bytes, delta;
	void *t;

	if (want <= *cap)
		return 1;
	if (want > limit || want > 0xffffffffu)
		return 0;
	nc = (uint64_t)*cap * 2u;
	if (nc < 16u)
		nc = 16u;
	if (nc < want)
		nc = want;
	if (nc > limit)
		nc = limit;
	old_bytes = (uint64_t)*cap * elem;
	for (;;) {
		delta = nc * elem - old_bytes;
		if (delta <= kof_view_room(m))
			break;
		if (nc == want)
			return 0;          /* not even the exact size fits the ledger */
		nc = want;
	}
	t = realloc(*tab, (size_t)(nc * elem));
	if (!t)
		return 0;
	*tab = t;
	*cap = (uint32_t)nc;
	m->held += delta;
	return 1;
}

/* Give a table back. The caller zeroes `held` when it frees them all (the view's release),
 * which is the only way tables are given back - a table is not shrunk. */
static inline void kof_tab_free(void **tab)
{
	free(*tab);
	*tab = NULL;
}

/* Give back a table that is not the view's own to keep - a work area the parse needs while it
 * runs and not after: freed, and what it held is taken off the account, which is the one place a
 * table is ever shrunk. */
static inline void kof_tab_drop(struct kof_view_mem *m, void **tab, uint32_t *cap, size_t elem)
{
	uint64_t b = (uint64_t)*cap * elem;

	free(*tab);
	*tab = NULL;
	*cap = 0;
	m->held = m->held > b ? m->held - b : 0;
}

/*
 * THE TWO HANDLES EVERY TABLE-OWNING VIEW GIVES THE HOST besides its release (struct
 * kof_view_ops, kofformat.h): `kof_<fmt>_mem`, the view's account, and `kof_<fmt>_row`, the walk
 * a module's kof_<fmt>_next reaches. One definition for all of them, because they are the same
 * three lines over a different view: `tab` is the member that points at the rows and `count`
 * the one that says how many there are. The call is counted before anything is decided, so a
 * walk that finds nothing still says a module asked (struct kof_view_mem.walked). Not const
 * because of that count - the view is the host's, and a module reaches this only through the
 * vtable slot. The prototypes are the format's own header's.
 */
#define KOF_VIEW_HANDLES(fmt, view_t, tab, count)                                  \
struct kof_view_mem *kof_##fmt##_mem(void *view)                                  \
{                                                                                  \
	return &((view_t *)view)->mem;                                             \
}                                                                                  \
const void *kof_##fmt##_row(void *view, uint32_t *cursor)                         \
{                                                                                  \
	view_t *v = (view_t *)view;                                                \
                                                                                   \
	if (!v)                                                                    \
		return NULL;                                                       \
	v->mem.walked++;                                                           \
	if (!v->valid || !v->tab || *cursor >= v->count)                           \
		return NULL;                                                       \
	return &v->tab[(*cursor)++];                                               \
}

#endif /* KOFENG_TABGROW_H */
