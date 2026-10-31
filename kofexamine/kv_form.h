/*
 * kv_form.h - what Manage > Pathogens and Manage > Syndromes SHARE on the screen (kv_form.c). Include it after "kv.h" (it uses struct
 * dframe, struct out, struct view, struct kv_menu), as kv_families.h does.
 *
 * Four parts, each one code for both dialogs:
 *   FORM    the small dialog (add / edit): the frame is dframe_*, the rows are a text row, a field row (kv_ftext) and a tick grid
 *           of any list of labels over a bit mask; the footer is the error line and [ OK ] [ Cancel ] at the left with a red
 *           [ Delete ] alone at the right (an Edit mode); the size, the hit test of a tick cell and of a button are here.
 *   MENU    the 2-column check-mark menu of a table cell (kv_menu): its look, where it opens, which item a press is on.
 *   COVER   the rectangles a dialog covered, so the panes under it are painted again only when a box moved, shrank or closed.
 *   MAIN    the table dialog: the frame (kv_dash_dialog), the table with no heading (kv_table), the bottom row of buttons, the wheel,
 *           the drag and the press on the close box / the buttons / a table row.
 * What differs is a parameter or a callback: the title, the add button's label, the table spec, the list of labels.
 */
#ifndef KV_FORM_H
#define KV_FORM_H

#include "kv_dash_dialog.h"
#include "kv_pick.h"
#include "kv_formdata.h"
#include "kv_table.h"

/* ---- FORM ---- */

#define KV_FORM_SLOTS 24u       /* tick cells one form can keep spans for (all its grids and the deleted-names row of Add variant) */

struct kv_form {
	struct dframe f;
	int ok_x[2], cancel_x[2], delete_x[2], btn_y;
	int tick_y[KV_FORM_SLOTS], tick_x0[KV_FORM_SLOTS], tick_x1[KV_FORM_SLOTS];
};

/* The measures (the size, the width of a cell and a grid, the text of a cell) are kv_formdata.h's: pure and tested; what is drawn here is
 * made with exactly those. */
/* Forget every tick cell's span (a cell is found only when it is drawn). Call at the top of a draw. */
void kv_form_reset(struct kv_form *fm);
/* A labelled read-only line, and a labelled text field row (the label is `label`, the field `cols` wide). */
void kv_form_row_text(struct out *o, struct kv_form *fm, int row, const char *label, const char *text, int text_cols);
void kv_form_row_field(struct out *o, struct view *v, struct kv_form *fm, int row, struct kv_ftext *f, const char *label, int cols);
/* One tick cell kept at slot `slot` (its text is kv_form_cell_text) (enabled 0: drawn greyed, still found, the press does nothing). */
void kv_form_tick_cell(struct out *o, struct kv_form *fm, uint32_t slot, int y, const char *label, int on, int enabled, int w);
/* A title row then the grid of the list `l` (kv_pick.h), items down a column and then the next; the cells take slots slot0.. . Returns the next row. */
int kv_form_ticks(struct out *o, struct kv_form *fm, int row, const char *title, const struct kv_pick *l, uint32_t mask,
		  uint32_t slot0);
/* Which slot a screen point is on among slots [0, n), or -1. */
int kv_form_tick_at(const struct kv_form *fm, uint32_t n, int y, int x);
/* The Comment field of either catalog's form, ONE pair for both: the typing filter (kof_comment_char) and the rule (kof_catcomment_check)
 * with its one line, as kv_ft_init takes them. */
int kv_form_comment_accept(int k);
int kv_form_comment_check(void *user, const char *text, char *err, size_t cap);
/* The error line row then the button row; `edit` adds [ Delete ] at the right. Returns the next row. */
int kv_form_footer(struct out *o, struct kv_form *fm, int row, const char *err, int edit);
enum kv_form_btn { KV_FORM_NONE = 0, KV_FORM_OK, KV_FORM_CANCEL, KV_FORM_DELETE };
/* The button under a screen point (Delete only in an Edit mode). */
enum kv_form_btn kv_form_press(const struct kv_form *fm, int edit, int y, int x);
int kv_form_in_span(int y, int x, int y0, int x0, int x1);

/* ---- MENU ---- */

/* The two-column check-mark menu of the list `l` (as wide as its longest word, never under 16): item i is labelled by `label(ud, i)` and
 * ticked by `checked(ud, i)`. */
struct kv_menu kv_form_menu(const struct kv_pick *l, void *ud, const char *(*label)(void *, int), int (*checked)(void *, int));
/* Where a menu of `m` opens for a press at (y, x): kept on the screen and below the bar. */
void kv_form_menu_place(const struct kv_menu *m, int y, int x, int *oy, int *ox);
/* The item a press at screen (my, mx) is on in a menu opened at (y, x): >= 0 an item, -1 inside the menu on no item, -2 outside. */
int kv_form_menu_hit(const struct kv_menu *m, int y, int x, int my, int mx);
/* Draw it and give its rectangle. */
void kv_form_menu_draw(struct out *o, const struct kv_menu *m, int y, int x);

/* ---- COVER ---- */

struct kv_form_rect {
	int y0, x0, y1, x1;
};
#define KV_COVER_N 3            /* the main box, the small dialog, the tick menu */
struct kv_cover {
	struct kv_form_rect cover[KV_COVER_N], painted[KV_COVER_N];
};
/* Start a frame: nothing covered yet. Then set the rectangles that were drawn. */
void kv_cover_begin(struct kv_cover *c);
void kv_cover_set(struct kv_cover *c, int i, int y0, int x0, int y1, int x1);
/* After the frame: did a rectangle of the last frame stop being inside one of this frame's? Remembers this frame's. */
int kv_cover_uncovered(struct kv_cover *c);
/* What a form dialog sets after drawing each of its three boxes, once for both dialogs (slots 0, 1, 2 of the cover): the main box when its
 * geometry is known, the small dialog's frame, and the tick menu (drawn, and its rectangle set). */
struct kv_main;
void kv_form_cover_main(struct kv_cover *c, const struct kv_main *m);
void kv_form_cover_dialog(struct kv_cover *c, const struct kv_form *fm);
void kv_form_draw_menu(struct out *o, struct kv_cover *c, const struct kv_menu *m, int y, int x);

/* ---- MAIN ---- */

struct kv_main {
	struct dlg_off move;            /* where the dialog was dragged; reset when it opens */
	struct kv_dd_geo geo;
	struct kv_tab_geo tg;
	uint32_t off, hoff;             /* the first row shown, the sideways offset */
	int tab_y;                      /* screen row of the table's first line */
	struct kv_dd_btn btn[KV_DD_BTN_COUNT];
	uint32_t n_btn;
};
/* A body that is not a table: `n_row` rows of at most `n_col` columns, produced one at a time (the CFG dialog's graph and facts). The dialog scrolls it down and sideways
 * with the wheel exactly as it scrolls a table (shift or ctrl: sideways); `row` writes row `row` from column `hoff`, `ncols` columns wide, escapes allowed, into `out`. */
struct kv_main_body {
	uint32_t n_row, n_col;
	void (*row)(const void *user, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap);
	const void *user;
};
struct kv_main_in {
	const struct kv_main_body *body;/* NULL: the table below; set: the body rows, no button row (add_label NULL) and no table spec */
	const char *title, *add_label;
	const char *count;              /* the count text at the right of the bottom rule */
	const char *act;                /* a refusal on the bottom rule, or NULL */
	const struct kv_tab_spec *spec; /* columns measured, attributes set; the cell callback is the caller's */
	uint32_t n_row;
	int want_w, want_h, dirty;
	const char *const *tab;         /* the labels of the tab strip in the top rule (at most KV_DD_TABS), NULL / 0: none, the title is drawn */
	int n_tab, tab_sel;
};
#define KV_MAIN_WHEEL_ROWS 3
#define KV_MAIN_WHEEL_COLS 8
/* Draw the box, the table and the button row; keeps the geometry in `m`. Returns 1 when the box is big enough to draw. */
int kv_main_draw(struct out *o, struct view *v, struct kv_main *m, const struct kv_main_in *in);
/* A press on the dialog: KV_MAIN_CLOSE (the [x]), KV_MAIN_HELD (the title: a drag started), KV_MAIN_TAB(i) (a tab label), a button's kv_dd_btn_id, or KV_MAIN_NONE. */
#define KV_MAIN_NONE (-1)
#define KV_MAIN_CLOSE (-2)
#define KV_MAIN_HELD (-3)
/* A press on a tab label of the strip: KV_MAIN_TAB(i) for the i-th label (only when the dialog has a strip). */
#define KV_MAIN_TAB(i) (-10 - (i))
int kv_main_press(struct view *v, struct kv_main *m);
/* The row of the table under the mouse (index among `n_row`) and the column from the table line's start; 0 when it is not on a row. */
int kv_main_row_at(const struct kv_main *m, uint32_t n_row, uint32_t *row, int *col);
/* Drag, release and wheel (shift or ctrl = sideways). 1 when the key was one of those (and so is answered); `scroll` 0 ignores the wheel. */
int kv_main_key(struct view *v, struct kv_main *m, int k, int scroll);
/* The start both dialogs' key handlers share, once the dialog is known to be open: -1 for a mouse event (not a key: the click path takes
 * it), 1 when the table's own keys or an open tick menu took the key, 0 to go on with the dialog's own rules. */
int kv_form_key_prologue(struct view *v, struct kv_main *m, int k, int dlg_open, int *menu_open);

#endif /* KV_FORM_H */
