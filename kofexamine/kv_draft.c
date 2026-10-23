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
	v->gen_preview = 0;     /* the output listed a draft that is gone */
	v->note_off = 0;
	v->prow_off = 0;
	v->prow_seen = 0;
	v->prow_home = 1;
}
