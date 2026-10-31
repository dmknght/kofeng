/*
 * kv_ftext.h - ONE TEXT FIELD for the Pathogens dialogs: the form's Name and Comment rows and the comment cell edited in the table.
 *
 * A field is a small struct (kv_ftext: its text, size, scroll, edit id, typing filter, the library's rule as a callback, the commit
 * callback, the line an error is said on, the span it was drawn at) and a few functions. Two layers, one job each:
 *
 *   kv_ftext.c       (no terminal, no view: asserted on by tests/unit/kx_famdata.c) set, accepts, validate, commit, cancel, hit.
 *   kv_ftext_view.c  open, draw, key: the same three the viewer's other text areas use underneath (field_draw, field_key; the
 *                    draft panel's Comment draws with field_draw and types with field_key, with a buffer chosen by edit id, so it
 *                    has no wrapper of its own to share).
 *
 * WHERE the field is drawn and WHAT commit does are the only differences between the form's row and the table's cell, and both are
 * parameters, not a second implementation: `bracket` (the form draws "[ ]" around it) and `mode`. A HELD field keeps its text until
 * the form's OK reads it (kv_ft_commit only validates); a LIVE field gives the text to its commit callback at once and closes.
 *
 * KNOWN NOT OPTIMAL, to be done in the restructuring after the features (owner, 2026-10-28; see the note in kv_dash_dialog.h):
 *   - the form validates in dlg_ok (the library, so errors keep their order) and the cell validates twice (the field's check, then
 *     kof_famcat_set_comment): one validation path with the order the form needs should serve both, and HELD's kv_ft_commit has no
 *     real call site yet;
 *   - which buffer a key goes to is still chosen by the viewer's global edit id (v->edit), the way the draft panel does it, so the
 *     field is not self-contained: the focus should belong to the dialog and the key arrive as an event with the field it is for;
 *   - three layers (this file, kv_ftext_view.c, field_draw/field_key underneath) where the lowest one could take a kv_ftext
 *     directly, which also lets the draft panel use the same struct.
 */
#ifndef KV_FTEXT_H
#define KV_FTEXT_H

#include <stddef.h>
#include <stdint.h>

/* The longest text a field holds, with the NUL and the one spare character field_key keeps (the library then says "too long"). */
#define KV_FT_BUF 128

enum kv_ft_mode { KV_FT_HELD = 0, KV_FT_LIVE };
/* What a key did to the field: it edited the text, or it asked to commit (Enter) or cancel (Esc), which the owner of the field answers. */
enum kv_ft_key { KV_FT_EDIT = 0, KV_FT_ENTER, KV_FT_ESC };

/* A callback answers 1 when the text is acceptable / was taken, else 0 and ONE line in err[cap]. */
typedef int (*kv_ft_fn)(void *user, const char *text, char *err, size_t cap);

struct kv_ftext {
	char buf[KV_FT_BUF];
	size_t cap;             /* bytes of buf in use: the limit plus the NUL and the spare */
	uint32_t off;           /* how far the field is scrolled */
	int id;                 /* the viewer's edit id: v->edit == id says it has the caret */
	int (*accept)(int);     /* the typing filter (NULL: any printable) */
	kv_ft_fn check;         /* the library's rule for the text (NULL: none) */
	kv_ft_fn commit;        /* LIVE: what to do with the text (NULL: nothing) */
	void *user;
	enum kv_ft_mode mode;
	int bracket;            /* draw "[" and "]" around the field */
	char *err;              /* the line a refusal is said on (the dialog's bottom rule or error row) */
	size_t err_cap;
	int open;               /* LIVE: being edited; HELD: set by kv_ft_set, cleared by kv_ft_cancel */
	int y, x0, x1;          /* the span of the last draw, for the hit test */
};

/* Fill the field: its id, size, filter, rule, commit, user, mode, error line. Not open. */
void kv_ft_init(struct kv_ftext *f, int id, size_t cap, int (*accept)(int), kv_ft_fn check, kv_ft_fn commit, void *user,
		enum kv_ft_mode mode, int bracket, char *err, size_t err_cap);
/* Pre-fill with `text` (cut to what fits), scrolled to the start, no error, open. */
void kv_ft_set(struct kv_ftext *f, const char *text);
/* Would typing character `k` be taken? The filter, printable only, room for it and the spare. */
int kv_ft_accepts(const struct kv_ftext *f, int k);
/* The library's rule on the text: 1 acceptable, else 0 and the error line says why. */
int kv_ft_validate(struct kv_ftext *f);
/* Validate, then (LIVE) hand the text to the commit callback. 1 = taken (a LIVE field is then closed); 0 = refused, the error line
 * says why and the field stays as it is. A field that is not open answers 1 and does nothing. */
int kv_ft_commit(struct kv_ftext *f);
/* Close without committing; the error line is cleared. */
void kv_ft_cancel(struct kv_ftext *f);
/* Is screen point (y, x) inside the span the field was drawn at? */
int kv_ft_hit(const struct kv_ftext *f, int y, int x);

/* ---- kv_ftext_view.c: the same field on the screen ---- */
struct view;
struct out;
/* Pre-fill, open and give it the caret (at the end of the text). */
void kv_ftext_open(struct view *v, struct kv_ftext *f, const char *text);
/* Give the caret to an open field (a press on it). */
void kv_ftext_focus(struct view *v, const struct kv_ftext *f);
/* Draw `w` characters wide where the cursor is (a form row) or at screen row y, column x (a table cell); the span is kept for kv_ft_hit. */
void kv_ftext_draw_here(struct out *o, struct view *v, struct kv_ftext *f, int w);
void kv_ftext_draw_at(struct out *o, struct view *v, struct kv_ftext *f, int y, int x, int w);
/* A key: Enter and Esc come back for the owner to commit or cancel; any other edits the text. */
enum kv_ft_key kv_ftext_key(struct view *v, struct kv_ftext *f, int k);
/* kv_ft_commit / kv_ft_cancel, and the caret goes back when the field closed. */
int kv_ftext_commit(struct view *v, struct kv_ftext *f);
void kv_ftext_cancel(struct view *v, struct kv_ftext *f);

#endif /* KV_FTEXT_H */
