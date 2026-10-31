#define _GNU_SOURCE
#include "kv.h"
#include "kv_ftext.h"

/* kv_ftext_view.c - the text field on the screen: open, draw, key. See kv_ftext.h. It sits on field_draw and field_key, the
 * functions every text area of the viewer is drawn and typed with. */

/* Pre-fill, open and give it the caret (at the end of the text). */
void kv_ftext_open(struct view *v, struct kv_ftext *f, const char *text)
{
	kv_ft_set(f, text);
	v->edit = f->id;
	v->edit_prev = f->id;
	v->caret = (uint32_t)strlen(f->buf);
	fsel_clear(v);
}

/* Give the caret to an open field (a press on it): field_key puts the caret at the end on the first key. */
void kv_ftext_focus(struct view *v, const struct kv_ftext *f)
{
	v->edit = f->id;
}

/* The field gives the caret back (it was committed or cancelled). */
static void kv_ftext_release(struct view *v, const struct kv_ftext *f)
{
	if (v->edit == f->id)
		v->edit = 0;
}

/* Draw where the cursor already is, `w` characters wide, and keep the span for the hit test. */
void kv_ftext_draw_here(struct out *o, struct view *v, struct kv_ftext *f, int w)
{
	int focused = f->open && v->edit == f->id;

	f->y = o->row_hint;
	f->x0 = o->col_base + (int)o->col_hint;
	if (f->bracket)
		out_fmt(o, "%s[", focused ? A_SEL : A_ID);
	else
		out_str(o, A_SEL);
	field_draw(o, f->buf, v->caret, &f->off, w, focused, "");
	out_str(o, f->bracket ? "]" A_OFF : A_OFF);
	f->x1 = o->col_base + (int)o->col_hint - 1;
}

/* Draw at screen row y, column x. */
void kv_ftext_draw_at(struct out *o, struct view *v, struct kv_ftext *f, int y, int x, int w)
{
	out_at(o, y, x);
	o->col_hint = 0;
	kv_ftext_draw_here(o, v, f, w);
}

/* A key for the field: Enter and Esc are answered by its owner (commit, cancel); everything else edits the text. */
enum kv_ft_key kv_ftext_key(struct view *v, struct kv_ftext *f, int k)
{
	if (k == 27)
		return KV_FT_ESC;
	if (k == '\r' || k == '\n')
		return KV_FT_ENTER;
	v->edit = f->id;
	field_key(v, f->buf, f->cap, k, f->accept);
	return KV_FT_EDIT;
}

/* kv_ft_commit, and a field that was taken gives the caret back. */
int kv_ftext_commit(struct view *v, struct kv_ftext *f)
{
	int r = kv_ft_commit(f);

	if (r && !f->open)
		kv_ftext_release(v, f);
	return r;
}

/* kv_ft_cancel, and the caret goes back. */
void kv_ftext_cancel(struct view *v, struct kv_ftext *f)
{
	kv_ft_cancel(f);
	kv_ftext_release(v, f);
}
