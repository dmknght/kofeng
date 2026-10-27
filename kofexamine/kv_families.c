#define _GNU_SOURCE
#include "kv.h"
#include "kv_families.h"

/*
 * Manage > Pathogens: the dialogs, placed on the screen.
 *
 * It decides nothing. The catalog and every validation are the engine's (<verdictor/famcat.h>), the rows, cells,
 * buttons' spans and the tick menu's items are kv_famdata.c's, the frame is the dashboard dialog's (kv_dash_dialog.c),
 * the table is the one renderer (kv_table.c, no heading), the two small dialogs are the framed dialogs of kv_dialogs.c
 * (dframe_*) with the one text field every dialog uses (field_draw / field_key), and the tick menu is the viewer's
 * dropdown (kv_menu_draw, with its check marks). What is here is the placement and the routing of a click.
 *
 * KEYS: none are bound for opening or navigating. A dialog inherits what the existing dialogs do: Esc closes (or
 * cancels), Enter closes the main dialog and is OK in a small one (in the comment cell being edited in place: Enter commits,
 * Esc cancels, a press outside commits), the wheel scrolls the table, the typed characters
 * and the editing keys go to the text field through field_key.
 *
 * ONE FORM serves the four small dialogs (Add family, Add variant, Edit family, Edit variant): fam_draw_dlg lays out the rows a mode has
 * (fam_form_rows), and the draw, the size, the hit test, the keys, OK / Cancel / [x] and the error line are that one code. The
 * frame, the title row, the [x], the position and the drag are dframe_* (kv_dialogs.c), the same functions Find, Go to and Decode
 * string are drawn and grabbed with. The main dialog's position is a dlg_off the kv_dd layout applies (kv_dash_dialog.c) and
 * the same dlg_hold starts its drag.
 */

/* The width of the tick menu: "[x] " and the longest type. */
#define FAM_MENU_W 16
#define FAM_MENU_COLS 2         /* the type menu is a grid of two columns */
#define FAM_WHEEL_ROWS 3
#define FAM_WHEEL_COLS 8
/* What the small dialogs are made of; fam_dlg_size derives their one size from these and nothing else. */
#define FAM_TICK_COLS 2         /* the tick grid: columns, filled down the first and then the next */
#define FAM_TICK_CELL 14        /* "[x] Hacktool" and a gap */
#define FAM_TICK_GAP 2
#define FAM_FIELD_COLS 24       /* the name field (names are 1..63 characters; the field scrolls) */
#define FAM_COMMENT_COLS 40     /* the comment field (up to KOF_FAMCAT_COMMENT_MAX characters; the field scrolls) */
#define FAM_ERR_COLS 32         /* the widest error line (the texts of kof_famcat_status_text fit) */
static const char fam_label_name[] = "Name    ";       /* the three labels are one width so the fields line up */
static const char fam_label_variant[] = "Variant ";
static const char fam_label_comment[] = "Comment ";
static const char fam_label_types[] = "Malware types";
static const char fam_label_ok[] = "[ OK ]";
static const char fam_label_cancel[] = "[ Cancel ]";
static const char fam_label_delete[] = "[ Delete ]";
static const char fam_label_reuse[] = "Reuse a deleted name";

static struct kv_fam_ui *fam_ui(const struct view *v)
{
	return v->fam;
}

int fam_up(const struct view *v)
{
	return v->fam && v->fam->open;
}

void fam_open(struct view *v)
{
	struct kv_fam_ui *u = v->fam;
	int first = !u;

	if (first) {
		u = calloc(1, sizeof *u);
		if (!u)
			return;
		kof_famcat_init(&u->cat, u->fam, KV_FAM_MAX_FAMILY, u->var, KV_FAM_MAX_VARIANT);
		kof_famcat_init(&u->snap, u->snap_fam, KV_FAM_MAX_FAMILY, u->snap_var, KV_FAM_MAX_VARIANT);
		v->fam = u;
		/* The first time the dialog opens it reads the directory. Later opens keep what is in memory, so an unsaved change
		 * is not lost by closing the dialog. */
		kof_famcat_load(&u->cat, &u->store, v->pathdir);
		kof_famcat_snapshot(&u->cat, &u->snap);
	}
	u->open = 1;
	u->main_move.dx = u->main_move.dy = 0;      /* a dialog opens centred; where it was dragged is forgotten */
	u->hoff = 0;
	u->dlg = KV_FAM_DLG_NONE;
	u->menu_open = 0;
	u->cedit_on = 0;
	u->off = 0;
	u->n_btn = 0;
	/* The line the load had to say (files not loaded, lines ignored, no directory) is on the bottom rule at the first open. */
	snprintf(u->err, sizeof u->err, "%s", first ? u->store.note : "");
}

void fam_free(struct view *v)
{
	free(v->fam);
	v->fam = NULL;
}

static void fam_close(struct view *v)
{
	v->fam->open = 0;
	v->fam->dlg = KV_FAM_DLG_NONE;
	v->fam->menu_open = 0;
	v->fam->cedit_on = 0;
	v->edit = 0;
}

/* What a mode of the one small form has. Add family and Edit family have the Name field; every mode but Edit family has the
 * variant part (the Comment field and the tick grid); the two Edit modes have [ Delete ]. */
static int has_name_field(enum kv_fam_dlg d)
{
	return d == KV_FAM_DLG_FAMILY || d == KV_FAM_DLG_EDIT_FAMILY;
}

static int has_variant_part(enum kv_fam_dlg d)
{
	return d != KV_FAM_DLG_EDIT_FAMILY;
}

static int is_edit(enum kv_fam_dlg d)
{
	return d == KV_FAM_DLG_EDIT_FAMILY || d == KV_FAM_DLG_EDIT_VARIANT;
}

/* Open a small dialog. `index` is the family (Add variant, Edit family) or the variant (Edit variant) it is about; Add family
 * ignores it. An Edit mode starts from what the catalog holds. */
static void dlg_open(struct view *v, enum kv_fam_dlg d, uint32_t index)
{
	struct kv_fam_ui *u = v->fam;

	u->dlg = d;
	u->dlg_idx = index;
	u->name[0] = 0;
	u->name_off = 0;
	u->comment[0] = 0;
	u->cmt_off = 0;
	u->types = 0;
	u->err[0] = 0;
	u->menu_open = 0;
	u->vname[0] = 0;
	u->reuse = 0;
	u->f.off.dx = u->f.off.dy = 0;
	v->edit_prev = 0;
	v->caret = 0;
	if (d == KV_FAM_DLG_EDIT_FAMILY) {
		snprintf(u->name, sizeof u->name, "%s", u->cat.fam[index].name);
	} else if (d == KV_FAM_DLG_EDIT_VARIANT) {
		snprintf(u->comment, sizeof u->comment, "%s", kof_famcat_comment(&u->cat, index));
		snprintf(u->vname, sizeof u->vname, "%s", u->cat.var[index].name);
		u->types = u->cat.var[index].types;
	} else if (d == KV_FAM_DLG_VARIANT) {
		/* The name is the library's: what is shown is what OK creates. A refusal (no next name) is said at once. */
		kv_fam_error_text(&u->cat, kof_famcat_variant_name(&u->cat, index, 0, u->vname, sizeof u->vname), u->err,
				  sizeof u->err);
	}
	v->edit = has_name_field(d) ? ED_FAM_NAME : ED_FAM_COMMENT;
}

static void dlg_close(struct view *v)
{
	v->fam->dlg = KV_FAM_DLG_NONE;
	v->fam->err[0] = 0;
	v->edit = 0;
}

/* OK: the engine validates and changes the catalog; a refusal is its status as one line and the dialog stays open. */
static void dlg_ok(struct view *v)
{
	struct kv_fam_ui *u = v->fam;
	enum kof_famcat_status st;

	switch (u->dlg) {
	case KV_FAM_DLG_FAMILY:
		st = kof_famcat_add_family(&u->cat, u->name, u->comment, u->types, NULL);
		break;
	case KV_FAM_DLG_VARIANT:
		st = kof_famcat_add_variant(&u->cat, u->dlg_idx, u->comment, u->types, u->reuse, NULL);
		break;
	case KV_FAM_DLG_EDIT_FAMILY:
		st = kof_famcat_rename_family(&u->cat, u->dlg_idx, u->name);
		break;
	default:
		st = kof_famcat_set_variant(&u->cat, u->dlg_idx, u->comment, u->types);
		break;
	}
	kv_fam_error_text(&u->cat, st, u->err, sizeof u->err);
	if (st == KOF_FAMCAT_OK)
		dlg_close(v);
}

/* [ Delete ] of an Edit mode: the family with its variants, or the variant, at once. */
static void dlg_delete(struct view *v)
{
	struct kv_fam_ui *u = v->fam;
	enum kof_famcat_status st = u->dlg == KV_FAM_DLG_EDIT_FAMILY ? kof_famcat_delete_family(&u->cat, u->dlg_idx)
								       : kof_famcat_delete_variant(&u->cat, u->dlg_idx);

	kv_fam_error_text(&u->cat, st, u->err, sizeof u->err);
	if (st == KOF_FAMCAT_OK)
		dlg_close(v);
}

/* ---- the comment cell edited in place --------------------------------------------------------------------- */

/* A click on a variant's comment cell: the cell becomes a field holding the comment (the caret at its end). One edit at a time. */
static void cedit_open(struct view *v, struct kv_fam_ui *u, uint32_t var)
{
	u->cedit_on = 1;
	u->cedit_var = var;
	u->cbuf_off = 0;
	snprintf(u->cbuf, sizeof u->cbuf, "%s", kof_famcat_comment(&u->cat, var));
	u->err[0] = 0;
	v->edit = ED_FAM_CELL;
	v->edit_prev = ED_FAM_CELL;
	v->caret = (uint32_t)strlen(u->cbuf);
	fsel_clear(v);
}

static void cedit_stop(struct view *v, struct kv_fam_ui *u)
{
	u->cedit_on = 0;
	if (v->edit == ED_FAM_CELL)
		v->edit = 0;
}

/* Enter, or a click outside the field: the library's comment rules decide. A refusal is ONE line on the bottom rule and the field
 * stays open (0); on success the cell shows the new comment (1). */
static int cedit_commit(struct view *v, struct kv_fam_ui *u)
{
	enum kof_famcat_status st = kof_famcat_set_comment(&u->cat, u->cedit_var, u->cbuf);

	kv_fam_error_text(&u->cat, st, u->err, sizeof u->err);
	if (st != KOF_FAMCAT_OK)
		return 0;
	cedit_stop(v, u);
	return 1;
}

/* ---- the main dialog -------------------------------------------------------------------------------------- */

static const char *fam_rowattr(void *user, uint32_t row)
{
	const struct kv_fam_tab *ft = user;

	switch (ft->row[row].kind) {
	case KV_FAM_FAMILY: return A_BOLD;
	case KV_FAM_ADDVAR: return A_ID;
	default:            return NULL;
	}
}

#define FAM_MAX_LINES 64u

/* The bottom row: the buttons' labels at the columns kv_fam_buttons gave, an enabled one in the button colour and a greyed
 * one (Save, Discard while the catalog equals its snapshot) in the viewer's disabled-button style. */
static void fam_button_row(const struct kv_dd_geo *g, const struct kv_fam_btn *b, uint32_t n, char *out, size_t cap)
{
	size_t at = 0;
	int col = 0;
	uint32_t i;

	out[0] = 0;
	for (i = 0; i < n; i++) {
		int gap = b[i].x0 - g->body_x0 - col;

		at += (size_t)snprintf(out + at, at < cap ? cap - at : 0u, "%*s%s%s" A_OFF, gap > 0 ? gap : 0, "",
				       b[i].enabled ? A_ID : A_BTN_OFF, b[i].label);
		col = b[i].x1 - g->body_x0 + 1;
	}
}

/* The rows, the content size, the measured columns and the dirty flag follow the catalog and its snapshot; a frame in which neither
 * revision moved (typing in a field, a scroll, a drag, the menu) reuses them. */
static void fam_derive(struct kv_fam_ui *u)
{
	struct kv_tab_spec t;
	struct kv_fam_tab ft;

	if (u->derived && u->rev_cat == u->cat.rev && u->rev_snap == u->snap.rev)
		return;
	u->n_row = kv_fam_rows(&u->cat, u->row, KV_FAM_MAX_ROW);
	kv_fam_content_size(&u->cat, u->row, u->n_row, &u->want_w, &u->want_h);
	kv_fam_spec(&t, &ft, &u->cat, u->row, u->n_row);
	memcpy(u->width, t.width, sizeof u->width);
	u->dirty = kof_famcat_dirty(&u->cat, &u->snap);
	u->rev_cat = u->cat.rev;
	u->rev_snap = u->snap.rev;
	u->derived = 1;
}

static void fam_draw_box(struct out *o, struct view *v, struct kv_fam_ui *u)
{
	struct kv_dd_in in;
	struct kv_dd_geo *g = &u->geo;
	struct kv_tab_spec t;
	struct kv_fam_tab ft;
	struct kv_tab_in ti;
	char line[FAM_MAX_LINES][KV_TAB_LINE];     /* the visible rows only: FAM_MAX_LINES bounds them, no allocation per frame */
	char rule[1024], count[32];
	uint32_t room, nl, y;
	struct kv_fam_btn btn[KV_FAM_BTN_COUNT];

	memset(&in, 0, sizeof in);
	in.cols = g_cols;
	in.rows = g_rows;
	in.title = "Pathogens";
	fam_derive(u);
	in.want_w = u->want_w;
	in.want_h = u->want_h;
	in.dx = u->main_move.dx;
	in.dy = u->main_move.dy;
	kv_dd_layout(&in, g);
	u->main_move.dx = g->dx;            /* what is kept is what the screen allows */
	u->main_move.dy = g->dy;
	if (!g->ok)
		return;
	kv_fam_spec_widths(&t, &ft, &u->cat, u->row, u->n_row, u->width);
	ft.edit_var = u->cedit_on ? (int32_t)u->cedit_var : -1;
	t.n_sticky = 1;
	t.colattr[1] = A_S_TYPE;
	t.colattr[KV_FAM_COL_COMMENT] = A_DIM;
	t.rowattr = fam_rowattr;
	/* The last body row holds [ Add family ]; one blank row above it. */
	room = g->body_rows > 2 ? (uint32_t)g->body_rows - 2u : 0u;
	if (room > FAM_MAX_LINES)
		room = FAM_MAX_LINES;
	u->off = kv_tab_clamp(u->off, u->n_row, room);
	snprintf(count, sizeof count, u->cat.n_fam == 1u ? "%u family" : "%u families", (unsigned)u->cat.n_fam);
	in.count = count;
	/* A refused tick (a variant must keep a type, and none may repeat a sibling's set) is said on the bottom rule. */
	in.act = !u->dlg && u->err[0] ? u->err : NULL;
	in.act_ok = 0;
	in.total = u->n_row;
	in.off = u->off;
	in.shown = room;
	kv_dd_fill(&in, g);
	ti.row0 = u->off;
	ti.rows = room;
	ti.hoff = u->hoff;
	ti.width = g->body_cols;
	ti.margin = 1;
	ti.heading = 0;
	nl = kv_tab_render(&t, &ti, line, FAM_MAX_LINES, &u->tg, NULL);
	u->hoff = u->tg.hoff;
	u->tab_y = g->body_y0;
	u->n_btn = kv_fam_buttons(g, u->dirty, btn);
	memcpy(u->btn, btn, sizeof btn);
	out_at(o, g->top, g->left);
	kv_dd_top(&in, g, rule, sizeof rule);
	out_str(o, rule);
	out_at(o, g->top + g->h - 1, g->left);
	kv_dd_bottom(&in, g, rule, sizeof rule);
	out_str(o, rule);
	for (y = 0; y < (uint32_t)g->body_rows; y++) {
		char left[64], right[64];

		kv_dd_walls(&in, g, (int)y, left, right, sizeof left);
		out_at(o, g->body_y0 + (int)y, g->left);
		out_str(o, left);
		if (y < nl) {
			prop_put(o, line[y], g->body_cols, -1, -1);
		} else if (u->n_btn && u->btn[0].y == g->body_y0 + (int)y) {
			char row[256];

			fam_button_row(g, u->btn, u->n_btn, row, sizeof row);
			prop_put(o, row, g->body_cols, -1, -1);
		} else {
			prop_put(o, "", g->body_cols, -1, -1);
		}
		out_str(o, right);
	}
	/* The comment being edited: its field is drawn over the (blank) cell, as wide as the cell's visible part. */
	if (u->cedit_on && u->tg.n_col > KV_FAM_COL_COMMENT && u->tg.cw[KV_FAM_COL_COMMENT] > 0) {
		for (y = 0; y < nl; y++) {
			const struct kv_fam_row *r = &u->row[u->tg.row0 + y];

			if (r->kind != KV_FAM_VARIANT || (uint32_t)r->variant != u->cedit_var)
				continue;
			out_at(o, g->body_y0 + (int)y, g->body_x0 + u->tg.cx[KV_FAM_COL_COMMENT]);
			o->col_hint = 0;
			out_str(o, A_SEL);
			field_draw(o, u->cbuf, v->caret, &u->cbuf_off, u->tg.cw[KV_FAM_COL_COMMENT], 1, "");
			out_str(o, A_OFF);
			break;
		}
	}
	/* The box claims its rectangle, both buttons: a press on it never reaches a pane under it. */
	hit_zone(v, g->top, g->left, g->top + g->h - 1, g->left + g->w - 1, (uint8_t)(HIT_L | HIT_R), hit_row_none, 0);
}

/* ---- the small dialogs ------------------------------------------------------------------------------------ */

static int in_span(int y, int x, int y0, int x0, int x1)
{
	return y == y0 && x >= x0 && x <= x1;
}

/* THE SIZE of a small dialog: one width for every mode (the widest of label + field, the tick grid, the button row with [ Delete ]
 * and the error line, plus the frame) and the rows its mode has: the Name field (Add family, Edit family), the variant's name line
 * (every mode but Edit family; Add family's is the first variant's), the Comment field and the "Malware types" title with the grid
 * (every mode but Edit family), the error line, the buttons. dframe_begin clips it to the screen. */
static void fam_dlg_size(enum kv_fam_dlg d, int *w, int *h)
{
	int nt = (int)kv_fam_menu_count(), rows = (nt + FAM_TICK_COLS - 1) / FAM_TICK_COLS;
	int name = (int)strlen(fam_label_name) + FAM_FIELD_COLS + 2;
	int cmt = (int)strlen(fam_label_comment) + FAM_COMMENT_COLS + 2;
	int grid = FAM_TICK_COLS * FAM_TICK_CELL - FAM_TICK_GAP;
	int btn = (int)strlen(fam_label_ok) + 2 + (int)strlen(fam_label_cancel) + 2 + (int)strlen(fam_label_delete);
	int in = name, form = (d == KV_FAM_DLG_FAMILY ? 2 : 1) + (has_variant_part(d) ? 1 : 0);

	in = cmt > in ? cmt : in;
	in = grid > in ? grid : in;
	in = btn > in ? btn : in;
	in = FAM_ERR_COLS > in ? FAM_ERR_COLS : in;
	*w = in + 4;
	*h = 2 + form + (has_variant_part(d) ? 1 + rows : 0) + (d == KV_FAM_DLG_VARIANT ? 1 : 0) + 1 + 1;
}

/* ONE TICK CELL, for a type of the grid and for the reuse tick under it: "[x] label", its span kept at slot `i` for fam_tick_at.
 * A cell that is not enabled is drawn in the greyed-button style and fam_tick_at still finds it (the click then does nothing). */
static void fam_tick_cell(struct out *o, struct kv_fam_ui *u, uint32_t i, int y, const char *label, int on, int enabled, int w)
{
	u->tick_y[i] = y;
	u->tick_x0[i] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%c] %-*s" A_OFF, enabled ? A_ID : A_BTN_OFF, on ? 'x' : ' ', w - 4, label);
	u->tick_x1[i] = u->tick_x0[i] + (int)strlen(label) + 3;
}

/* The tick grid of the dialogs with a variant, drawn from row `row` of the frame; the spans of every cell are kept for fam_tick_at.
 * Items run down a column, then the next column. Returns the next row. */
static int fam_draw_ticks(struct out *o, struct kv_fam_ui *u, int row)
{
	const struct dframe *f = &u->f;
	uint32_t i, nt = kv_fam_menu_count(), rows = (nt + FAM_TICK_COLS - 1) / FAM_TICK_COLS, r, c;

	dframe_row(o, f, row++);
	out_fmt(o, A_DIM "%s" A_OFF, fam_label_types);
	dframe_edge(o, f);

	for (r = 0; r < rows; r++) {
		dframe_row(o, f, row++);
		for (c = 0; c < FAM_TICK_COLS; c++) {
			i = c * rows + r;
			if (i >= nt)
				break;
			fam_tick_cell(o, u, i, f->y + row, kv_fam_menu_label(i), kv_fam_mask_has(u->types, i), 1, FAM_TICK_CELL);
		}
		dframe_edge(o, f);
	}
	return row;
}

/* The reuse tick, directly under the Variant row (Add variant only): reuse the smallest deleted name instead of a new one. It is the
 * tick cell after the types', greyed when the family has no deleted name. Returns the next row. */
static int fam_draw_reuse(struct out *o, struct kv_fam_ui *u, int row)
{
	const struct dframe *f = &u->f;

	dframe_row(o, f, row++);
	out_str(o, "  ");
	fam_tick_cell(o, u, kv_fam_menu_count(), f->y + row, fam_label_reuse, u->reuse,
		      kof_famcat_free_letters(&u->cat, u->dlg_idx) > 0u, (int)strlen(fam_label_reuse) + 4);
	dframe_edge(o, f);
	return row;
}

/* Which tick cell a screen point is on (a type's index, or the reuse tick's: the number of types), or -1. */
static int fam_tick_at(const struct kv_fam_ui *u, int y, int x)
{
	uint32_t i;

	for (i = 0; i <= kv_fam_menu_count(); i++)
		if (in_span(y, x, u->tick_y[i], u->tick_x0[i], u->tick_x1[i]))
			return (int)i;
	return -1;
}

/* A labelled read-only line (the first variant's name, the new variant's, the name of what a comment belongs to). */
static void fam_row_text(struct out *o, struct kv_fam_ui *u, int row, const char *label, const char *text)
{
	dframe_row(o, &u->f, row);
	out_fmt(o, A_DIM "%s" A_OFF "%s%.*s" A_OFF, label, text[0] ? A_ID : A_DIM, FAM_COMMENT_COLS, text[0] ? text : "-");
	dframe_edge(o, &u->f);
}

/* A labelled text field, with the span it took kept for the hit test. `ed` is the edit id that says it has the caret. */
static void fam_row_field(struct out *o, struct view *v, struct kv_fam_ui *u, int row, enum kv_fam_fld i, const char *label,
			  const char *text, uint32_t *off, int cols, int ed)
{
	dframe_row(o, &u->f, row);
	out_fmt(o, A_DIM "%s" A_OFF, label);
	u->fld[i].y = u->f.y + 1 + row;
	u->fld[i].x0 = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == ed ? A_SEL : A_ID);
	field_draw(o, text, v->caret, off, cols, v->edit == ed, "");
	out_str(o, "]" A_OFF);
	u->fld[i].x1 = o->col_base + (int)o->col_hint - 1;
	dframe_edge(o, &u->f);
}

/* THE ONE FORM of the four small dialogs (fam_dlg_size says which rows a mode has). Add family: Name field, the first variant's
 * name as the library numbers it (follows the typing; a dim dash while there is none), Comment, tick grid. Add variant: the new
 * variant's name, Comment, tick grid. Edit family: the Name field alone. Edit variant: the variant's name, Comment, tick grid,
 * all filled from the catalog. The edit modes add [ Delete ] to the buttons. */
static void fam_draw_dlg(struct out *o, struct view *v, struct kv_fam_ui *u)
{
	static const char *const title[] = { "", "Add family", "Add variant", "Edit family", "Edit variant" };
	struct dframe *f = &u->f;
	char first[KOF_FAMCAT_NAME_MAX + 1];
	int row = 0, w, h;

	fam_dlg_size(u->dlg, &w, &h);
	if (!dframe_begin(o, f, title[u->dlg], w, h, 2))
		return;
	if (has_name_field(u->dlg))
		fam_row_field(o, v, u, row++, FAM_FLD_NAME, fam_label_name, u->name, &u->name_off, FAM_FIELD_COLS, ED_FAM_NAME);
	if (u->dlg == KV_FAM_DLG_FAMILY) {
		const char *shown = !u->name[0] || kof_famcat_first_variant_name(&u->cat, u->name, first, sizeof first) != KOF_FAMCAT_OK
				    ? "" : first;

		memcpy(u->vname, shown, strlen(shown) + 1u);
	} else if (u->dlg == KV_FAM_DLG_VARIANT) {
		/* The name follows the reuse tick at once: what is shown is what OK creates. */
		if (kof_famcat_variant_name(&u->cat, u->dlg_idx, u->reuse, u->vname, sizeof u->vname) != KOF_FAMCAT_OK)
			u->vname[0] = 0;
	}
	u->tick_y[kv_fam_menu_count()] = -1;      /* the reuse tick's slot: found only when it is drawn */
	if (has_variant_part(u->dlg)) {
		fam_row_text(o, u, row++, fam_label_variant, u->vname);
		if (u->dlg == KV_FAM_DLG_VARIANT)
			row = fam_draw_reuse(o, u, row);
		fam_row_field(o, v, u, row++, FAM_FLD_COMMENT, fam_label_comment, u->comment, &u->cmt_off, FAM_COMMENT_COLS,
			      ED_FAM_COMMENT);
		row = fam_draw_ticks(o, u, row);
	}
	dframe_row(o, f, row++);
	out_fmt(o, "%s%.*s" A_OFF, A_WARN, FAM_ERR_COLS, u->err);
	dframe_edge(o, f);
	dframe_row(o, f, row++);
	u->btn_y = f->y + row;
	/*
	 * [ OK ] [ Cancel ] at the left and [ Delete ] alone at the right edge: the one button that destroys something is as
	 * far from the others as the row allows, so a press that misses OK or Cancel by a little cannot land on it. The row is
	 * the same in every mode, so OK and Cancel stay where they are whether Delete is there or not.
	 */
	{
		int bw, bh, inner, del = is_edit(u->dlg) ? (int)strlen(fam_label_delete) : 0;
		int left = (int)strlen(fam_label_ok) + 2 + (int)strlen(fam_label_cancel), pad;

		fam_dlg_size(u->dlg, &bw, &bh);
		inner = bw - 4;
		pad = inner - del - left;
		u->ok_x[0] = o->col_base + (int)o->col_hint;
		out_fmt(o, A_BTN_OK "%s" A_OFF, fam_label_ok);
		u->ok_x[1] = o->col_base + (int)o->col_hint - 1;
		out_str(o, "  ");
		u->cancel_x[0] = o->col_base + (int)o->col_hint;
		out_fmt(o, A_BTN_CANCEL "%s" A_OFF, fam_label_cancel);
		u->cancel_x[1] = o->col_base + (int)o->col_hint - 1;
		u->delete_x[0] = u->delete_x[1] = -1;
		if (del) {
			out_fmt(o, "%*s", pad > 2 ? pad : 2, "");
			u->delete_x[0] = o->col_base + (int)o->col_hint;
			out_fmt(o, A_BTN_DEL "%s" A_OFF, fam_label_delete);
			u->delete_x[1] = o->col_base + (int)o->col_hint - 1;
		}
	}
	dframe_edge(o, f);
	dframe_end(o, f, NULL);
	dframe_done(o, f);
}

/* ---- the tick menu ---------------------------------------------------------------------------------------- */

static int tm_checked(void *ud, int i)
{
	const struct kv_fam_ui *u = ud;

	return kv_fam_menu_checked(&u->cat, u->menu_var, (uint32_t)i);
}

static const char *tm_label(void *ud, int i)
{
	(void)ud;
	return kv_fam_menu_label((uint32_t)i);
}

static struct kv_menu fam_menu(struct kv_fam_ui *u)
{
	struct kv_menu m;

	memset(&m, 0, sizeof m);
	m.n = (int)kv_fam_menu_count();
	m.ud = u;
	m.label = tm_label;
	m.checked = tm_checked;
	m.w = FAM_MENU_W;
	m.cols = FAM_MENU_COLS;
	m.c_on = BAR_ON;
	m.c_off = BAR_OFF;
	m.c_cur = BAR_CUR;
	return m;
}

static void menu_place(struct kv_fam_ui *u, int y, int x)
{
	struct kv_menu m = fam_menu(u);
	int rows = kv_menu_rows(&m);

	u->menu_y = y + rows > g_rows ? g_rows - rows : y;
	u->menu_x = x + FAM_MENU_W * FAM_MENU_COLS > g_cols ? g_cols - FAM_MENU_W * FAM_MENU_COLS : x;
	if (u->menu_y < 1)
		u->menu_y = 1;
	if (u->menu_x < 1)
		u->menu_x = 1;
}

void draw_fam(struct out *o, struct view *v)
{
	struct kv_fam_ui *u = fam_ui(v);

	if (!u || !u->open)
		return;
	memset(u->cover, 0, sizeof u->cover);
	fam_draw_box(o, v, u);
	if (u->geo.ok) {
		u->cover[0].y0 = u->geo.top;
		u->cover[0].x0 = u->geo.left;
		u->cover[0].y1 = u->geo.top + u->geo.h - 1;
		u->cover[0].x1 = u->geo.left + u->geo.w - 1;
	}
	if (u->dlg) {
		fam_draw_dlg(o, v, u);
		u->cover[1].y0 = u->f.y;
		u->cover[1].x0 = u->f.x;
		u->cover[1].y1 = u->f.y + u->f.h - 1;
		u->cover[1].x1 = u->f.x + u->f.w - 1;
	}
	if (u->menu_open) {
		struct kv_menu m = fam_menu(u);

		kv_menu_draw(o, &m, u->menu_y, u->menu_x, -1, -1);
		u->cover[2].y0 = u->menu_y;
		u->cover[2].x0 = u->menu_x;
		u->cover[2].y1 = u->menu_y + kv_menu_rows(&m) - 1;
		u->cover[2].x1 = u->menu_x + FAM_MENU_W * FAM_MENU_COLS - 1;
	}
}

/* Is rectangle `p` (not empty) inside one of the rectangles this frame covers? */
static int rect_inside(const struct kv_fam_rect *p, const struct kv_fam_rect c[KV_FAM_COVER])
{
	int i;

	for (i = 0; i < KV_FAM_COVER; i++)
		if ((c[i].y1 || c[i].x1) && p->y0 >= c[i].y0 && p->y1 <= c[i].y1 && p->x0 >= c[i].x0 && p->x1 <= c[i].x1)
			return 1;
	return 0;
}

/* What a smaller, moved or closed box uncovers is erased only by what was beneath it, so the panes are painted again on a frame in
 * which a rectangle of the last one is not inside a rectangle of this one. A box that only GROWS (a small dialog or the menu opening
 * over the table) uncovers nothing: every box is drawn whole on every frame. */
int fam_uncovered(struct view *v)
{
	struct kv_fam_ui *u = fam_ui(v);
	int i, diff = 0;

	if (!u || !u->open)
		return 0;
	for (i = 0; i < KV_FAM_COVER; i++)
		if ((u->painted[i].y1 || u->painted[i].x1) && !rect_inside(&u->painted[i], u->cover))
			diff = 1;
	memcpy(u->painted, u->cover, sizeof u->cover);
	return diff;
}

/* ---- the mouse -------------------------------------------------------------------------------------------- */

static int click_menu_items(struct view *v, struct kv_fam_ui *u)
{
	struct kv_menu m = fam_menu(u);
	int k = g_my - u->menu_y;

	/* A tick keeps the menu up, so several types are set in one visit; a press anywhere else puts it away. */
	if (g_mx >= u->menu_x && g_mx < u->menu_x + FAM_MENU_W * FAM_MENU_COLS && k >= 0 && k < kv_menu_rows(&m)) {
		int a = kv_menu_at_cell(&m, k, (g_mx - u->menu_x) / FAM_MENU_W);

		if (a >= 0)
			kv_fam_error_text(&u->cat, kv_fam_menu_toggle(&u->cat, u->menu_var, (uint32_t)a), u->err, sizeof u->err);
		return 1;
	}
	u->menu_open = 0;
	(void)v;
	return 1;
}

static int click_dlg(struct view *v, struct kv_fam_ui *u)
{
	const struct dframe *f = &u->f;
	int t;

	if (dframe_grab(v, &u->f))          /* the title row takes hold of the box, as in Find and Go to */
		return 1;
	if (dframe_hit_close(f, g_my, g_mx)) {
		dlg_close(v);
		return 1;
	}
	if (has_name_field(u->dlg) && in_span(g_my, g_mx, u->fld[FAM_FLD_NAME].y, u->fld[FAM_FLD_NAME].x0, u->fld[FAM_FLD_NAME].x1)) {
		v->edit = ED_FAM_NAME;
		return 1;
	}
	if (has_variant_part(u->dlg) &&
	    in_span(g_my, g_mx, u->fld[FAM_FLD_COMMENT].y, u->fld[FAM_FLD_COMMENT].x0, u->fld[FAM_FLD_COMMENT].x1)) {
		v->edit = ED_FAM_COMMENT;
		return 1;
	}
	if (has_variant_part(u->dlg) && (t = fam_tick_at(u, g_my, g_mx)) >= 0) {
		if ((uint32_t)t < kv_fam_menu_count())
			u->types = kv_fam_mask_flip(u->types, (uint32_t)t);
		else if (kof_famcat_free_letters(&u->cat, u->dlg_idx) > 0u)
			u->reuse = !u->reuse;
		return 1;
	}
	if (in_span(g_my, g_mx, u->btn_y, u->cancel_x[0], u->cancel_x[1]))
		dlg_close(v);
	else if (in_span(g_my, g_mx, u->btn_y, u->ok_x[0], u->ok_x[1]))
		dlg_ok(v);
	else if (is_edit(u->dlg) && in_span(g_my, g_mx, u->btn_y, u->delete_x[0], u->delete_x[1]))
		dlg_delete(v);
	return 1;
}

static int click_table(struct view *v, struct kv_fam_ui *u)
{
	uint32_t row, index;
	int k;

	if (kv_tab_hit(&u->tg, g_my - u->tab_y, g_mx - u->geo.body_x0, &row, &k) != 2)
		return 0;
	row += u->tg.row0;
	if (row >= u->n_row)
		return 0;
	if (u->row[row].kind == KV_FAM_ADDVAR) {
		if (kv_fam_button_at(&u->tg, g_mx - u->geo.body_x0))
			dlg_open(v, KV_FAM_DLG_VARIANT, u->row[row].family);
		return 1;
	}
	switch (kv_fam_hit_of(&u->cat, &u->row[row], &u->tg, g_mx - u->geo.body_x0, &index)) {
	case KV_FAM_HIT_FAMILY:
		dlg_open(v, KV_FAM_DLG_EDIT_FAMILY, index);
		break;
	case KV_FAM_HIT_VARIANT:
		dlg_open(v, KV_FAM_DLG_EDIT_VARIANT, index);
		break;
	case KV_FAM_HIT_COMMENT:
		cedit_open(v, u, index);
		break;
	case KV_FAM_HIT_TYPES:
		u->menu_open = 1;
		u->err[0] = 0;
		u->menu_var = index;
		menu_place(u, g_my, g_mx);
		break;
	default:
		break;
	}
	return 1;
}

/* [ Save ]: the library writes the files and says in one line what it refused; on success the snapshot is the saved state, on a
 * failure the catalog and the snapshot stay as they were (the buttons stay enabled). */
static void fam_save(struct kv_fam_ui *u, const char *dir)
{
	if (kof_famcat_save(&u->cat, &u->store, dir) == KOF_FAMCAT_IO_OK) {
		kof_famcat_snapshot(&u->cat, &u->snap);
		u->err[0] = 0;
	} else {
		snprintf(u->err, sizeof u->err, "%s", u->store.note);
	}
}

/* A press while the dialog is up: it is modal, so every press is answered here (1). The menu bar was asked first. */
int fam_click(struct view *v, int rclick)
{
	struct kv_fam_ui *u = fam_ui(v);

	if (!u || !u->open)
		return 0;
	if (rclick)
		return 1;
	/* A press outside the field commits the comment, like Enter; a refused one is said and keeps the field (and the press). */
	if (u->cedit_on && !u->dlg && !u->menu_open && !cedit_commit(v, u))
		return 1;
	if (u->menu_open)
		return click_menu_items(v, u);
	if (u->dlg)
		return click_dlg(v, u);
	if (kv_dd_close_at(&u->geo, g_my, g_mx)) {
		fam_close(v);
		return 1;
	}
	if (kv_dd_grab_at(&u->geo, g_my, g_mx)) {
		dlg_hold(v, &u->main_move);
		return 1;
	}
	switch (kv_fam_btn_at(u->btn, u->n_btn, g_my, g_mx)) {
	case (int)KV_FAM_BTN_ADD_FAMILY:
		dlg_open(v, KV_FAM_DLG_FAMILY, 0);
		return 1;
	case (int)KV_FAM_BTN_SAVE:
		fam_save(u, v->pathdir);
		return 1;
	case (int)KV_FAM_BTN_DISCARD:
		kof_famcat_restore(&u->cat, &u->snap);
		u->err[0] = 0;
		return 1;
	default:
		break;
	}
	click_table(v, u);
	return 1;
}

/* ---- the keyboard ----------------------------------------------------------------------------------------- */

/* The typing filter is the engine's name rule, character by character. */
static int name_accept(int k)
{
	return kof_name_char(k);
}

/* The comment's typing filter is the engine's comment rule, character by character. */
static int comment_accept(int k)
{
	return kof_comment_char(k);
}

/* -1: not mine. While the dialog is up every key is its own; a press goes on to fam_click through click(). */
int handle_fam_key(struct view *v, int k)
{
	struct kv_fam_ui *u = fam_ui(v);

	if (!u || !u->open)
		return -1;
	if (k == K_CLICK || k == K_RCLICK)
		return -1;
	if (k == K_DRAG) {
		if (v->dlg_move)
			on_drag(v);         /* a box being moved owns the motion; any other drag is swallowed */
		return 1;
	}
	if (k == K_RELEASE) {
		v->dlg_move = NULL;
		return 1;
	}
	if (k == K_WHEEL_UP || k == K_WHEEL_DOWN) {
		if (!u->dlg && !u->menu_open) {
			uint32_t d = g_mod_shift || g_mod_ctrl ? FAM_WHEEL_COLS : FAM_WHEEL_ROWS;
			uint32_t *at = g_mod_shift || g_mod_ctrl ? &u->hoff : &u->off;

			*at = k == K_WHEEL_UP ? (*at > d ? *at - d : 0u) : *at + d;  /* clamped where it is drawn */
		}
		return 1;
	}
	if (u->menu_open) {
		if (k == 27)
			u->menu_open = 0;
		return 1;
	}
	if (u->cedit_on && !u->dlg) {
		if (k == 27)
			cedit_stop(v, u);
		else if (k == '\r' || k == '\n')
			cedit_commit(v, u);
		else
			field_key(v, u->cbuf, sizeof u->cbuf, k, comment_accept);
		return 1;
	}
	if (u->dlg) {
		if (k == 27)
			dlg_close(v);
		else if (k == '\r' || k == '\n')
			dlg_ok(v);
		else if (has_name_field(u->dlg) && (v->edit == ED_FAM_NAME || !has_variant_part(u->dlg)))
			field_key(v, u->name, sizeof u->name, k, name_accept);
		else {
			v->edit = ED_FAM_COMMENT;
			field_key(v, u->comment, sizeof u->comment, k, comment_accept);
		}
		return 1;
	}
	if (k == 27 || k == '\r' || k == '\n')
		fam_close(v);
	return 1;
}
