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

/* What the small dialogs are made of; fam_dlg_size derives their one size from these and the shared form (kv_form.h). */
#define FAM_FIELD_COLS 24       /* the name field (names are 1..63 characters; the field scrolls) */
#define FAM_COMMENT_COLS 40     /* the comment field (up to KOF_FAMCAT_COMMENT_MAX characters; the field scrolls) */
static const char fam_label_name[] = "Name    ";       /* the labels are one width so the fields line up */
static const char fam_label_variant[] = "Variant ";
static const char fam_label_comment[] = "Comment ";
static const char fam_label_fcomment[] = "Note    ";   /* the FAMILY's own comment, directly under Name; a distinct label from
							   * "Comment " so the two never read as the same field (Add family shows both) */
static const char fam_label_types[] = "Malware types";
static const char fam_label_names[] = "Reuse a deleted name";

/* The typing filters and the library's rules, as the three fields use them. */
static int name_accept(int k)
{
	return kof_name_char(k);
}

static int say_status(const struct kv_fam_ui *u, enum kof_famcat_status st, char *err, size_t cap)
{
	kv_fam_error_text(&u->cat, st, err, cap);
	return st == KOF_FAMCAT_OK;
}

static int name_check(void *user, const char *text, char *err, size_t cap)
{
	return say_status(user, kof_famcat_name_check(text), err, cap);
}

/* The commit of the comment cell: the library takes the comment of the variant being edited. */
static int cell_commit(void *user, const char *text, char *err, size_t cap)
{
	struct kv_fam_ui *u = user;

	return say_status(u, kof_famcat_set_comment(&u->cat, u->cell_var, text), err, cap);
}

static void fam_fields_init(struct kv_fam_ui *u)
{
	size_t ec = sizeof u->err;

	kv_ft_init(&u->f_name, ED_FAM_NAME, KOF_FAMCAT_NAME_MAX + 3, name_accept, name_check, NULL, u, KV_FT_HELD, 1, u->err, ec);
	kv_ft_init(&u->f_family_comment, ED_FAM_FCOMMENT, KOF_FAMCAT_COMMENT_MAX + 3, kv_form_comment_accept, kv_form_comment_check, NULL, u,
		   KV_FT_HELD, 1, u->err, ec);
	kv_ft_init(&u->f_comment, ED_FAM_COMMENT, KOF_FAMCAT_COMMENT_MAX + 3, kv_form_comment_accept, kv_form_comment_check, NULL, u, KV_FT_HELD, 1,
		   u->err, ec);
	kv_ft_init(&u->f_cell, ED_FAM_CELL, KOF_FAMCAT_COMMENT_MAX + 3, kv_form_comment_accept, kv_form_comment_check, cell_commit, u, KV_FT_LIVE, 0,
		   u->err, ec);
}

static struct kv_fam_ui *fam_ui(const struct view *v)
{
	return v->fam;
}

int fam_up(const struct view *v)
{
	return v->fam && v->fam->open;
}

/*
 * THE SESSION'S PATHOGENS CATALOG, made and loaded on first use: by the dialog's first open and by the diagnose panel's family and
 * variant lists, so there is one catalog and one load. *created is 1 when this call made it (its load note is then on u->store).
 */
struct kv_fam_ui *fam_ensure(struct view *v, int *created)
{
	struct kv_fam_ui *u = v->fam;

	*created = !u;
	if (u)
		return u;
	u = calloc(1, sizeof *u);
	if (!u)
		return NULL;
	kof_famcat_init(&u->cat, u->fam, KV_FAM_MAX_FAMILY, u->var, KV_FAM_MAX_VARIANT);
	kof_famcat_init(&u->snap, u->snap_fam, KV_FAM_MAX_FAMILY, u->snap_var, KV_FAM_MAX_VARIANT);
	v->fam = u;
	fam_fields_init(u);
	/* The first time it is needed it reads the directory. Later uses keep what is in memory, so an unsaved change is not lost by
	 * closing the dialog. */
	kof_famcat_load(&u->cat, &u->store, v->pathdir);
	kof_famcat_snapshot(&u->cat, &u->snap);
	return u;
}

void fam_open(struct view *v)
{
	int first;
	struct kv_fam_ui *u = fam_ensure(v, &first);

	if (!u)
		return;
	u->open = 1;
	u->m.move.dx = u->m.move.dy = 0;      /* a dialog opens centred; where it was dragged is forgotten */
	u->m.hoff = 0;
	u->dlg = KV_FAM_DLG_NONE;
	u->menu_open = 0;
	kv_ft_cancel(&u->f_cell);
	u->m.off = 0;
	u->m.n_btn = 0;
	/* The line the load had to say (files not loaded, lines ignored, no directory) is on the bottom rule at the first open OF THE
	 * DIALOG, whoever loaded the catalog: the diagnose panel's Family list loads it too, and `first` is then 0. */
	(void)first;
	snprintf(u->err, sizeof u->err, "%s", u->note_shown ? "" : u->store.note);
	u->note_shown = 1;
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
	kv_ft_cancel(&v->fam->f_cell);
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
	kv_ft_set(&u->f_name, "");
	kv_ft_set(&u->f_family_comment, "");
	kv_ft_set(&u->f_comment, "");
	u->types = 0;
	u->err[0] = 0;
	u->menu_open = 0;
	u->vname[0] = 0;
	u->letter = 0u;
	u->fm.f.off.dx = u->fm.f.off.dy = 0;
	v->edit_prev = 0;
	v->caret = 0;
	if (d == KV_FAM_DLG_EDIT_FAMILY) {
		kv_ft_set(&u->f_name, u->cat.fam[index].name);
		kv_ft_set(&u->f_family_comment, kof_famcat_family_comment(&u->cat, index));
	} else if (d == KV_FAM_DLG_EDIT_VARIANT) {
		kv_ft_set(&u->f_comment, kof_famcat_comment(&u->cat, index));
		snprintf(u->vname, sizeof u->vname, "%s", u->cat.var[index].name);
		u->types = u->cat.var[index].types;
	} else if (d == KV_FAM_DLG_VARIANT) {
		/* The name is the library's: what is shown is what OK creates. A refusal (no next name) is said at once. */
		kv_fam_error_text(&u->cat, kof_famcat_variant_name(&u->cat, index, 0u, u->vname, sizeof u->vname), u->err,
				  sizeof u->err);
	}
	kv_ftext_focus(v, has_name_field(d) ? &u->f_name : &u->f_comment);
}

static void dlg_close(struct view *v)
{
	v->fam->dlg = KV_FAM_DLG_NONE;
	v->fam->err[0] = 0;
	v->edit = 0;
}

/* OK: the engine validates and changes the catalog; a refusal is its status as one line and the dialog stays open.
 *
 * Add family creates the family and its first variant in one call (kof_famcat_add_family, whose own `comment` parameter is the
 * FIRST VARIANT'S, unchanged); the family's OWN comment (the Note row) is a separate fact and is set right after, with
 * kof_famcat_set_family_comment, validated FIRST so the add is all-or-nothing from here: a bad Note is said and nothing is added. */
static void dlg_ok(struct view *v)
{
	struct kv_fam_ui *u = v->fam;
	enum kof_famcat_status st;
	uint32_t fam;

	switch (u->dlg) {
	case KV_FAM_DLG_FAMILY:
		st = kof_famcat_comment_check(u->f_family_comment.buf);
		if (st == KOF_FAMCAT_OK) {
			st = kof_famcat_add_family(&u->cat, u->f_name.buf, u->f_comment.buf, u->types, &fam);
			if (st == KOF_FAMCAT_OK)
				(void)kof_famcat_set_family_comment(&u->cat, fam, u->f_family_comment.buf);
		}
		break;
	case KV_FAM_DLG_VARIANT:
		st = kof_famcat_add_variant(&u->cat, u->dlg_idx, u->f_comment.buf, u->types, u->letter, NULL);
		break;
	case KV_FAM_DLG_EDIT_FAMILY:
		st = kof_famcat_set_family(&u->cat, u->dlg_idx, u->f_name.buf, u->f_family_comment.buf);
		break;
	default:
		st = kof_famcat_set_variant(&u->cat, u->dlg_idx, u->f_comment.buf, u->types);
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

/* A click on a variant's comment cell: the cell becomes the LIVE field, holding the comment. One edit at a time. */
static void cell_open(struct view *v, struct kv_fam_ui *u, uint32_t var)
{
	u->cell_var = var;
	kv_ftext_open(v, &u->f_cell, kof_famcat_comment(&u->cat, var));
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
	struct kv_tab_spec t;
	struct kv_fam_tab ft;
	struct kv_main_in in;
	char count[32];
	uint32_t y, nl;

	fam_derive(u);
	kv_fam_spec_widths(&t, &ft, &u->cat, u->row, u->n_row, u->width);
	ft.edit_var = u->f_cell.open ? (int32_t)u->cell_var : -1;
	t.n_sticky = 1;
	t.colattr[1] = A_S_TYPE;
	t.colattr[KV_FAM_COL_COMMENT] = A_DIM;
	t.rowattr = fam_rowattr;
	snprintf(count, sizeof count, u->cat.n_fam == 1u ? "%u family" : "%u families", (unsigned)u->cat.n_fam);
	memset(&in, 0, sizeof in);
	in.title = "Pathogens";
	in.add_label = kv_fam_label_add_family();
	in.count = count;
	/* A refused tick (a variant must keep a type, and none may repeat a sibling's set) is said on the bottom rule. */
	in.act = !u->dlg && u->err[0] ? u->err : NULL;
	in.spec = &t;
	in.n_row = u->n_row;
	in.want_w = u->want_w;
	in.want_h = u->want_h;
	in.dirty = u->dirty;
	if (!kv_main_draw(o, v, &u->m, &in))
		return;
	/* The comment being edited: its field is drawn over the (blank) cell, as wide as the cell's visible part. */
	nl = u->m.tg.shown;
	if (u->f_cell.open && u->m.tg.n_col > KV_FAM_COL_COMMENT && u->m.tg.cw[KV_FAM_COL_COMMENT] > 0) {
		for (y = 0; y < nl; y++) {
			const struct kv_fam_row *r = &u->row[u->m.tg.row0 + y];

			if (r->kind != KV_FAM_VARIANT || (uint32_t)r->variant != u->cell_var)
				continue;
			kv_ftext_draw_at(o, v, &u->f_cell, u->m.geo.body_y0 + (int)y, u->m.geo.body_x0 + u->m.tg.cx[KV_FAM_COL_COMMENT],
					 u->m.tg.cw[KV_FAM_COL_COMMENT]);
			break;
		}
	}
}

/* ---- the small dialogs ------------------------------------------------------------------------------------ */

/* THE SIZE of a small dialog: one width for every mode (the widest of label + field and the shared form's grid, button row and error
 * line, plus the frame) and the rows its mode has: the Name field (Add family, Edit family), the family's own Note field right under
 * it (Add family, Edit family), the variant's name line (every mode but Edit family; Add family's is the first variant's), the
 * deleted-names row (Add variant), the Comment field and the "Malware types" title with the grid (every mode but Edit family).
 * dframe_begin clips it to the screen. */
static void fam_dlg_size(enum kv_fam_dlg d, int *w, int *h)
{
	struct kv_pick tl = kv_fam_types();
	int row_w[4], n = 0;
	int form = (d == KV_FAM_DLG_FAMILY ? 2 : 1) + (has_variant_part(d) ? 1 : 0) + (has_name_field(d) ? 1 : 0);
	int rows = form + (has_variant_part(d) ? kv_form_ticks_rows(kv_fam_menu_count()) : 0) + (d == KV_FAM_DLG_VARIANT ? 1 : 0);

	/* The widths of every row this mode draws that the form cannot bound itself: the Name row, the family's Note row, the variant's
	 * Comment row and the grid. */
	row_w[n++] = kv_form_field_w(fam_label_name, FAM_FIELD_COLS);
	if (has_name_field(d))
		row_w[n++] = kv_form_field_w(fam_label_fcomment, FAM_COMMENT_COLS);
	if (has_variant_part(d)) {
		row_w[n++] = kv_form_field_w(fam_label_comment, FAM_COMMENT_COLS);
		row_w[n++] = kv_form_grid_w(&tl);
	}
	kv_form_size(rows, row_w, (uint32_t)n, w, h);
}

/* The deleted-names row, directly under the Variant row (Add variant only): its label opens a menu of the family's DELETED variant names
 * (kof_famcat_free_letter), and a press on one makes that name the new variant's (u->letter; the Variant row shows it). The label is the
 * cell after the types' in the form's spans, greyed when the family has no deleted name. Returns the next row. */
static int fam_draw_names(struct out *o, struct kv_fam_ui *u, int row)
{
	struct kv_form *fm = &u->fm;
	uint32_t slot = kv_fam_menu_count();
	int x0, on = kof_famcat_free_letters(&u->cat, u->dlg_idx) > 0u;

	dframe_row(o, &fm->f, row++);
	out_str(o, "  ");
	x0 = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s%s" A_OFF, on ? A_ID : A_BTN_OFF, fam_label_names);
	if (slot < KV_FORM_SLOTS) {
		fm->tick_y[slot] = fm->f.y + row;
		fm->tick_x0[slot] = x0;
		fm->tick_x1[slot] = x0 + (int)strlen(fam_label_names) - 1;
	}
	dframe_edge(o, &fm->f);
	return row;
}

/* THE ONE FORM of the four small dialogs (fam_dlg_size says which rows a mode has). Add family: Name field, the family's own Note
 * field directly under it, the first variant's name as the library numbers it (follows the typing; a dim dash while there is none),
 * Comment, tick grid. Add variant: the new variant's name, Comment, tick grid. Edit family: the Name field and its Note field.
 * Edit variant: the variant's name, Comment, tick grid, all filled from the catalog. The edit modes add [ Delete ] to the buttons. */
static void fam_draw_dlg(struct out *o, struct view *v, struct kv_fam_ui *u)
{
	static const char *const title[] = { "", "Add family", "Add variant", "Edit family", "Edit variant" };
	struct kv_form *fm = &u->fm;
	struct kv_pick tl = kv_fam_types();
	char first[KOF_FAMCAT_NAME_MAX + 1];
	int row = 0, w, h;

	fam_dlg_size(u->dlg, &w, &h);
	if (!dframe_begin(o, &fm->f, title[u->dlg], w, h, 2))
		return;
	if (has_name_field(u->dlg)) {
		kv_form_row_field(o, v, fm, row++, &u->f_name, fam_label_name, FAM_FIELD_COLS);
		kv_form_row_field(o, v, fm, row++, &u->f_family_comment, fam_label_fcomment, FAM_COMMENT_COLS);
	}
	if (u->dlg == KV_FAM_DLG_FAMILY) {
		const char *shown = !u->f_name.buf[0] || kof_famcat_first_variant_name(&u->cat, u->f_name.buf, first, sizeof first) != KOF_FAMCAT_OK
				    ? "" : first;

		memcpy(u->vname, shown, strlen(shown) + 1u);
	} else if (u->dlg == KV_FAM_DLG_VARIANT) {
		/* The name follows the chosen deleted name at once: what is shown is what OK creates. */
		if (kof_famcat_variant_name(&u->cat, u->dlg_idx, u->letter, u->vname, sizeof u->vname) != KOF_FAMCAT_OK)
			u->vname[0] = 0;
	}
	kv_form_reset(fm);                  /* the deleted-names row's span is found only when it is drawn */
	if (has_variant_part(u->dlg)) {
		kv_form_row_text(o, fm, row++, fam_label_variant, u->vname, FAM_COMMENT_COLS);
		if (u->dlg == KV_FAM_DLG_VARIANT)
			row = fam_draw_names(o, u, row);
		kv_form_row_field(o, v, fm, row++, &u->f_comment, fam_label_comment, FAM_COMMENT_COLS);
		row = kv_form_ticks(o, fm, row, fam_label_types, &tl, u->types, 0);
	}
	row = kv_form_footer(o, fm, row, u->err, is_edit(u->dlg));
	dframe_end(o, &fm->f, NULL);
	dframe_done(o, &fm->f);
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

/* The menu of deleted names: item i is the i-th deleted letter of the dialog's family spelled by the library (variant_name), a plain
 * list (no tick); the name is written into the state's buffer and copied by the pop-up at once. */
static const char *dn_label(void *ud, int i)
{
	struct kv_fam_ui *u = ud;
	char *buf = u->mname;

	if (kof_famcat_variant_name(&u->cat, u->dlg_idx, kof_famcat_free_letter(&u->cat, u->dlg_idx, (uint32_t)i), buf, sizeof u->mname) != KOF_FAMCAT_OK)
		buf[0] = 0;
	return buf;
}

static struct kv_menu fam_menu(struct kv_fam_ui *u)
{
	struct kv_pick l = kv_fam_types();
	struct kv_menu m;

	if (!u->menu_names)
		return kv_form_menu(&l, u, tm_label, tm_checked);
	memset(&m, 0, sizeof m);
	m.n = (int)kof_famcat_free_letters(&u->cat, u->dlg_idx);
	m.ud = u;
	m.label = dn_label;
	m.w = (int)strlen(u->cat.fam[u->dlg_idx].name) + 2 + 3;   /* "<family>_" and up to three letters: the pop-up widens for a longer one */
	m.cols = 1;
	return m;
}

void draw_fam(struct out *o, struct view *v)
{
	struct kv_fam_ui *u = fam_ui(v);

	if (!u || !u->open)
		return;
	kv_cover_begin(&u->cv);
	fam_draw_box(o, v, u);
	kv_form_cover_main(&u->cv, &u->m);
	if (u->dlg) {
		fam_draw_dlg(o, v, u);
		kv_form_cover_dialog(&u->cv, &u->fm);
	}
	if (u->menu_open) {
		struct kv_menu m = fam_menu(u);

		/* A press goes to the menu first, though the names menu opens over the dialog's focused Comment field, which would otherwise
		 * take the press (click_field runs before fam_click). */
		g_fld.room = 0;
		kv_form_draw_menu(o, &u->cv, &m, u->menu_y, u->menu_x);
	}
}

int fam_uncovered(struct view *v)
{
	struct kv_fam_ui *u = fam_ui(v);

	return u && u->open && kv_cover_uncovered(&u->cv);
}

/* ---- the mouse -------------------------------------------------------------------------------------------- */

static int click_menu_items(struct view *v, struct kv_fam_ui *u)
{
	struct kv_menu m = fam_menu(u);
	int a = kv_form_menu_hit(&m, u->menu_y, u->menu_x, g_my, g_mx);

	/* The names menu: a press on a name takes it and puts the menu away. */
	if (u->menu_names && a >= 0) {
		u->letter = kof_famcat_free_letter(&u->cat, u->dlg_idx, (uint32_t)a);
		u->menu_open = 0;
		return 1;
	}
	/* A tick keeps the menu up, so several types are set in one visit; a press anywhere else puts it away. */
	if (a != -2) {
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
	int t;

	if (dframe_grab(v, &u->fm.f))       /* the title row takes hold of the box, as in Find and Go to */
		return 1;
	if (dframe_hit_close(&u->fm.f, g_my, g_mx)) {
		dlg_close(v);
		return 1;
	}
	if (has_name_field(u->dlg) && kv_ft_hit(&u->f_name, g_my, g_mx)) {
		kv_ftext_focus(v, &u->f_name);
		return 1;
	}
	if (has_name_field(u->dlg) && kv_ft_hit(&u->f_family_comment, g_my, g_mx)) {
		kv_ftext_focus(v, &u->f_family_comment);
		return 1;
	}
	if (has_variant_part(u->dlg) && kv_ft_hit(&u->f_comment, g_my, g_mx)) {
		kv_ftext_focus(v, &u->f_comment);
		return 1;
	}
	if (has_variant_part(u->dlg) && (t = kv_form_tick_at(&u->fm, kv_fam_menu_count() + 1u, g_my, g_mx)) >= 0) {
		struct kv_pick tl = kv_fam_types();

		if ((uint32_t)t < kv_fam_menu_count())
			u->types = kv_pick_flip(&tl, u->types, (uint32_t)t);
		else if (kof_famcat_free_letters(&u->cat, u->dlg_idx) > 0u) {
			struct kv_menu m;

			u->menu_names = 1;
			u->menu_open = 1;
			m = fam_menu(u);
			kv_form_menu_place(&m, g_my, g_mx, &u->menu_y, &u->menu_x);
		}
		return 1;
	}
	switch (kv_form_press(&u->fm, is_edit(u->dlg), g_my, g_mx)) {
	case KV_FORM_CANCEL: dlg_close(v); break;
	case KV_FORM_OK:     dlg_ok(v); break;
	case KV_FORM_DELETE: dlg_delete(v); break;
	default: break;
	}
	return 1;
}

static int click_table(struct view *v, struct kv_fam_ui *u)
{
	uint32_t row, index;
	int col;

	if (!kv_main_row_at(&u->m, u->n_row, &row, &col))
		return 0;
	if (u->row[row].kind == KV_FAM_ADDVAR) {
		if (kv_fam_button_at(&u->m.tg, col))
			dlg_open(v, KV_FAM_DLG_VARIANT, u->row[row].family);
		return 1;
	}
	switch (kv_fam_hit_of(&u->cat, &u->row[row], &u->m.tg, col, &index)) {
	case KV_FAM_HIT_FAMILY:
		dlg_open(v, KV_FAM_DLG_EDIT_FAMILY, index);
		break;
	case KV_FAM_HIT_VARIANT:
		dlg_open(v, KV_FAM_DLG_EDIT_VARIANT, index);
		break;
	case KV_FAM_HIT_COMMENT:
		cell_open(v, u, index);
		break;
	case KV_FAM_HIT_TYPES:
		u->menu_names = 0;
		u->menu_open = 1;
		u->err[0] = 0;
		u->menu_var = index;
		{
			struct kv_menu m = fam_menu(u);

			kv_form_menu_place(&m, g_my, g_mx, &u->menu_y, &u->menu_x);
		}
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
	if (kof_famcat_save(&u->cat, &u->store, dir) == KOF_CATSTORE_IO_OK) {
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
	if (u->f_cell.open && !u->dlg && !u->menu_open && !kv_ftext_commit(v, &u->f_cell))
		return 1;
	if (u->menu_open)
		return click_menu_items(v, u);
	if (u->dlg)
		return click_dlg(v, u);
	switch (kv_main_press(v, &u->m)) {
	case KV_MAIN_CLOSE:
		fam_close(v);
		return 1;
	case KV_MAIN_HELD:
		return 1;
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

/* -1: not mine. While the dialog is up every key is its own; a press goes on to fam_click through click(). */
int handle_fam_key(struct view *v, int k)
{
	struct kv_fam_ui *u = fam_ui(v);
	int r;

	if (!u || !u->open)
		return -1;
	r = kv_form_key_prologue(v, &u->m, k, u->dlg != 0, &u->menu_open);
	if (r)
		return r;
	if (u->f_cell.open && !u->dlg) {
		switch (kv_ftext_key(v, &u->f_cell, k)) {
		case KV_FT_ESC:
			kv_ftext_cancel(v, &u->f_cell);
			break;
		case KV_FT_ENTER:
			(void)kv_ftext_commit(v, &u->f_cell);
			break;
		default:
			break;
		}
		return 1;
	}
	if (u->dlg) {
		if (k == 27)
			dlg_close(v);
		else if (k == '\r' || k == '\n')
			dlg_ok(v);
		else {
			/* Three fields may be on screen at once (Add family: Name, the family's Note, the first variant's Comment); the
			 * focused one is whichever field's id v->edit carries, not a guess from the dialog's mode. */
			struct kv_ftext *f = v->edit == ED_FAM_FCOMMENT ? &u->f_family_comment
					   : v->edit == ED_FAM_COMMENT ? &u->f_comment : &u->f_name;

			(void)kv_ftext_key(v, f, k);
		}
		return 1;
	}
	if (k == 27 || k == '\r' || k == '\n')
		fam_close(v);
	return 1;
}
