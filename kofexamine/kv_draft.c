#define _GNU_SOURCE
#include "kv.h"

/*
 * Throw the draft away, and put the PANEL'S SCROLL back with it.
 *
 * The model half is the editor's - see draft_clear there. The three offsets are
 * this file's, because they are where a pane happens to be scrolled to and
 * nothing in the model knows a pane exists.
 */
void draft_wipe(struct view *v)
{
	draft_clear(&v->ed);
	v->note_off = 0;
	v->prow_off = 0;
	v->prow_home = 1;
}

/*
 * Give the draft's tables back when the view ends: the strings (each owns its bytes), the table itself and the columns the panel
 * recorded for them. The block table is freed by the view's own teardown, as it always was.
 */
void draft_release(struct view *v)
{
	uint32_t i;

	for (i = 0; i < v->ed.dr.n_decl; i++)
		free(v->ed.dr.decl[i].bytes);
	free(v->ed.dr.decl);
	v->ed.dr.decl = NULL;
	v->ed.dr.n_decl = v->ed.dr.cap_decl = 0;
	decl_cols_free(v);
}
