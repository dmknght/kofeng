#define _GNU_SOURCE

/*
 * kofeditor_block.c - the block table of a draft: picking a block, reserving room for more, and the moves and permutations that keep the groups pointing at the right ones.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"





/*
 * TICK OR UNTICK A BLOCK, and the find_similar matcher for it comes and goes
 * with the tick.
 *
 * A block is ticked to be used, and the one thing a block can be used for is a
 * similarity matcher over it, so choosing the matcher by hand was a second
 * gesture that said the same thing - and a ticked block with no matcher was a
 * state the panel then had to warn about. Ticking adds the matcher, holding
 * that one block at the default threshold; unticking drops it, and grp_remove
 * renumbers the conditions that named it, which is why this is one call and not
 * three.
 *
 * A rule read from a file brings its own matchers and sets the tick itself,
 * not through here, so what a rule declared is never added twice.
 *
 * AN OLDER RULE'S MATCHER MAY HOLD SEVERAL BLOCKS. Unticking takes this block
 * out of it and removes the matcher only when nothing is left in it: the other
 * blocks are the author's and stay measured.
 */
void blk_set_picked(struct kof_editor *e, uint32_t i, int on)
{
	uint32_t g;

	if (i >= e->dr.n_blk)
		return;
	e->dr.blk[i].picked = (uint8_t)(on != 0);
	if (on) {
		if (grp_of_block(e, i) < MAX_GROUP || e->dr.n_grp >= MAX_GROUP)
			return;
		grp_add(e);
		grp_make_sim(e, e->dr.n_grp - 1u);
		grp_sim_add(e, e->dr.n_grp - 1u, SIM_IT_BLOCK, i);
		return;
	}
	while ((g = grp_of_block(e, i)) < MAX_GROUP) {
		uint32_t k;

		for (k = e->dr.grp[g].n_sim; k--; )
			if (e->dr.grp[g].sim[k].what == SIM_IT_BLOCK &&
			    e->dr.grp[g].sim[k].blk == i)
				grp_sim_del(e, g, k);
		if (!e->dr.grp[g].n_sim)
			grp_remove(e, g);
	}
}


/*
 * Does this block clear what the rule demands of it.
 *
 * The demand is on the MATCHER that names the block, not on the block - a block
 * is a run of bytes and has no opinion about how much of it is enough. A block
 * no matcher names has no demand to clear.
 */
int blk_clears(const struct kof_editor *e, uint32_t i)
{
	uint32_t g = grp_of_block(e, i);

	/* The demand is the MATCHER'S threshold, which every measure it names
	 * has to reach - see struct group.pct. */
	return g < MAX_GROUP && i < e->dr.n_blk &&
	       e->dr.blk[i].score >= e->dr.grp[g].pct;
}

/*
 * ROOM FOR `want` BLOCK ROWS. The table follows what the engine offers (no constant bounds it), so it grows by doubling and, when memory
 * refuses, by exactly what was asked; if that is refused too the table keeps what it holds and the draft SAYS so (say_err) - a refusal is
 * reported, never a row dropped without a word. Answers 1 when `want` rows fit.
 */
int blk_reserve(struct kof_editor *e, uint32_t want)
{
	struct mtn_block *p;
	size_t n;

	if (want <= e->dr.cap_blk)
		return 1;
	n = e->dr.cap_blk ? e->dr.cap_blk : 1u;
	while (n < want && n <= SIZE_MAX / 4u / sizeof *p)
		n *= 2u;
	p = n >= want ? realloc(e->dr.blk, n * sizeof *p) : NULL;
	if (!p) {
		n = want;
		p = n <= SIZE_MAX / sizeof *p ? realloc(e->dr.blk, n * sizeof *p) : NULL;
	}
	if (!p) {
		say_err(e, "out of memory: the block table keeps its %u rows, the rest of the object's blocks are not listed", e->dr.n_blk);
		return 0;
	}
	e->dr.blk = p;
	e->dr.cap_blk = (uint32_t)n;
	return 1;
}

/*
 * A BLOCK MOVED, SO WHATEVER NAMES IT MOVES WITH IT.
 *
 * A matcher holds the block's INDEX, and the list is rebuilt whenever the
 * object changes: unticked blocks dropped, ticked ones compacted to the front,
 * the whole thing sorted into file order. Each of those moves a block to a
 * different index, and a matcher left pointing at the old one is a matcher
 * about a different block, or about nothing.
 *
 * Called with the OLD index and the new one, before the record is copied, so a
 * matcher is updated exactly once per move.
 */
void blk_moved(struct kof_editor *e, uint32_t from, uint32_t to)
{
	uint32_t g;

	if (from == to)
		return;
	for (g = 0; g < e->dr.n_grp; g++) {
		uint32_t i;

		if (e->dr.grp[g].kind != GRP_KIND_SIM)
			continue;
		for (i = 0; i < e->dr.grp[g].n_sim; i++)
			if (e->dr.grp[g].sim[i].what == SIM_IT_BLOCK &&
			    e->dr.grp[g].sim[i].blk == from)
				e->dr.grp[g].sim[i].blk = to;
	}
}

/*
 * A WHOLE REORDERING OF THE BLOCKS, applied to every matcher once.
 *
 * `to[old]` is where the block that WAS at `old` is now. It is not a series of
 * blk_moved calls, because a series cannot express a permutation: moving 0 to
 * 53 and then 53 to 4 moves the item that was just moved a second time, so a
 * matcher ended up naming a block it never named - and the draft read as edited
 * the moment a rule was opened, which refuses to switch file.
 */
void blk_permute(struct kof_editor *e, const uint32_t *to, uint32_t n)
{
	uint32_t g, i;

	for (g = 0; g < e->dr.n_grp; g++) {
		if (e->dr.grp[g].kind != GRP_KIND_SIM)
			continue;
		for (i = 0; i < e->dr.grp[g].n_sim; i++)
			if (e->dr.grp[g].sim[i].what == SIM_IT_BLOCK &&
			    e->dr.grp[g].sim[i].blk < n)
				e->dr.grp[g].sim[i].blk =
					to[e->dr.grp[g].sim[i].blk];
	}
}
