#define _GNU_SOURCE
#include "kv.h"


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
