#define _GNU_SOURCE
#include "kv.h"


/*
 * Which signature has a marker covering this file offset.
 *
 * Any of them, not just the one being lit: the point is to be able to click a
 * highlighted run and find out whose it is. In-region markers win over
 * elsewhere ones when two overlap, because that is the one that counts for its
 * owner. -1 for none.
 */
int hit_owner(struct view *v, uint64_t off)
{
	struct object *ob = cur_obj(v);
	int best = -1;
	uint32_t i, j;

	for (i = 0; i < ob->n_touch; i++) {
		const struct kof_touch *t = &ob->touch[i];

		for (j = 0; j < t->n_str; j++) {
			const struct kof_touch_str *st = &t->str[j];

			if (st->at == KGENOME_BROKEN)
				continue;
			/* `off` is an offset in whatever the pane is showing
			 * and st->at is in whatever buffer it was found in;
			 * comparing across the two lights an unrelated byte at
			 * the same number. */
			if (sym_which_of(st->sym) !=
			    v->node[v->sel_node].sym)
				continue;
			/* span_min, not the pool length: for a hex marker the
			 * pool holds a compiled program, and lighting its
			 * length lit the marker plus whatever followed it in
			 * the object. */
			if (off < st->at || off >= st->at + st->span_at)
				continue;
			if (st->in_rgn)
				return (int)i;
			if (best < 0)
				best = (int)i;
		}
	}
	return best;
}

int hit_kind(struct view *v, uint64_t off)
{
	struct object *ob = cur_obj(v);
	const struct kof_touch *t;
	uint32_t j;

	if (v->sel_touch >= ob->n_touch)
		return 0;
	t = &ob->touch[v->sel_touch];
	for (j = 0; j < t->n_str; j++) {
		const struct kof_touch_str *st = &t->str[j];

		if (st->at == KGENOME_BROKEN)
			continue;
		/* Same space only - see touch_at_off. */
		if (sym_which_of(st->sym) != v->node[v->sel_node].sym)
			continue;
		if (off >= st->at && off < st->at + st->span_at) {
			/*
			 * A MODULE RULED OUT BY ITS PRECONDITION HAS NO
			 * REGIONS TO BE OUTSIDE OF.
			 *
			 * kof_touch_object sets in_rgn to zero for one, and
			 * says why in its own note: the module never had its
			 * regions looked at, so "inside them" is not a
			 * comparison that was made and answering yes would
			 * invent one. Answering NO here invented the opposite.
			 * The pane painted every marker of a skipped module in
			 * the colour that means "found, but not where this
			 * module searches" - on a script, whose normalised
			 * view often has no format and therefore no regions at
			 * all, that reads as a region complaint about a file
			 * that has no regions. The row above the pane already
			 * says the real reason: "targets another format".
			 */
			if (t->kind == KOF_TOUCH_INELIGIBLE)
				return 1;
			return st->in_rgn ? 1 : 2;
		}
	}
	return 0;
}

/*
 * Where a declared string sits in this object, searched for once.
 *
 * A string declared by selecting bytes already knows; one loaded from a
 * database row knows too. One read out of a source file does not - the file
 * says what to look for, not where it was found - and that is the case this is
 * for. Case folding is honoured because the declaration honours it.
 */


/* Is this file offset inside a string the draft declares. */
int decl_kind(struct view *v, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < v->ed.dr.n_decl; i++) {
		const struct decl *d = &v->ed.dr.decl[i];

		uint32_t j;

		/*
		 * `off` is an offset in whatever the pane is showing, and a
		 * marker's hits are in whatever space it was found in. Compare
		 * them only when those are the same space - otherwise a block
		 * offset lights an unrelated byte at the same number in a
		 * region the marker is not in.
		 */
		if (sym_which_of(d->sym) != v->node[v->sel_node].sym ||
		    d->obj != v->node[v->sel_node].obj)
			continue;
		if (!d->n_hits) {
			/* Set by a path that never searched. One is still
			 * better than none. */
			if (d->at != KGENOME_BROKEN &&
			    off >= d->at && off < d->at + d->len)
				return 1;
			continue;
		}
		for (j = 0; j < d->n_hits; j++) {
			if (off < d->hits[j])
				break;  /* sorted: nothing later can contain it */
			if (off < d->hits[j] + d->hit_len[j])
				return 1;
		}
	}
	return 0;
}
