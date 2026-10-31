#define _GNU_SOURCE
#include "kv.h"
#include "kv_tags.h"

/*
 * Manage > Syndromes: the dialogs, placed on the screen.
 *
 * It decides nothing. The catalog and every validation are the engine's (<verdictor/tagcat.h>), the rows, cells and the tick lists are
 * kv_tagdata.c's, and the frame, the table, the buttons, the small form, the tick grid, the tick menu and the covered rectangles are
 * the code Manage > Pathogens uses (kv_form.c, kv_dash_dialog.c, kv_table.c, kv_ftext.c, dframe_*). What is here is the placement and the
 * routing of a click for a catalog of tags: a name, a set of activities (at least one) and a set of objects (may be empty).
 *
 * HOW THE TWO SETS COMBINE INTO DISEASES (pairs) IS THE VERDICT DESIGN'S, LATER: this dialog only edits the sets.
 *
 * KEYS: the same as Pathogens, and none is bound for opening or navigating. Esc closes (or cancels), Enter closes the main dialog and is
 * OK in the small one, the wheel scrolls the table (shift or ctrl: sideways), the typed characters and the editing keys go to the Name
 * field through kv_ftext.
 */

static const char tag_label_name[] = "Name    ";        /* the two labels are one width so the fields line up */
static const char tag_label_comment[] = "Comment ";
static const char tag_title_acts[] = "Activities";
static const char tag_title_objs[] = "Objects";
#define TAG_FIELD_COLS 24       /* the name field (names are 1..63 characters; the field scrolls) */
#define TAG_COMMENT_COLS 40     /* the comment field (up to KOF_TAGCAT_COMMENT_MAX characters; the field scrolls) */

static int name_accept(int k)
{
	return kof_tag_name_char(k);
}

static int name_check(void *user, const char *text, char *err, size_t cap)
{
	struct kv_tag_ui *u = user;
	enum kof_tagcat_status st = kof_tagcat_name_check(text);

	kv_tag_error_text(&u->cat, st, err, cap);
	return st == KOF_TAGCAT_OK;
}

static struct kv_tag_ui *tag_ui(const struct view *v)
{
	return v->tag;
}

int tags_up(const struct view *v)
{
	return v->tag && v->tag->open;
}

/* THE SESSION'S SYNDROMES CATALOG, made on first use: by the dialog's first open and by the diagnose panel's Tag list. */
struct kv_tag_ui *tags_ensure(struct view *v)
{
	struct kv_tag_ui *u = v->tag;

	if (u)
		return u;
	u = calloc(1, sizeof *u);
	if (!u)
		return NULL;
	kof_tagcat_init(&u->cat, u->tag, KV_TAG_MAX);
	kof_tagcat_init(&u->snap, u->snap_tag, KV_TAG_MAX);
	v->tag = u;
	kv_ft_init(&u->f_name, ED_TAG_NAME, KOF_TAGCAT_NAME_MAX + 3, name_accept, name_check, NULL, u, KV_FT_HELD, 1, u->err,
		   sizeof u->err);
	kv_ft_init(&u->f_comment, ED_TAG_COMMENT, KOF_TAGCAT_COMMENT_MAX + 3, kv_form_comment_accept, kv_form_comment_check, NULL, u, KV_FT_HELD, 1,
		   u->err, sizeof u->err);
	/* The first time it is needed it reads the directory. Later uses keep what is in memory, so an unsaved change is not lost by
	 * closing the dialog. */
	kof_tagcat_load(&u->cat, &u->store, v->syndir);
	kof_tagcat_snapshot(&u->cat, &u->snap);
	u->note_pending = 1;
	return u;
}

void tags_open(struct view *v)
{
	struct kv_tag_ui *u = tags_ensure(v);

	if (!u)
		return;
	u->open = 1;
	u->m.move.dx = u->m.move.dy = 0;      /* a dialog opens centred; where it was dragged is forgotten */
	u->m.hoff = 0;
	u->m.off = 0;
	u->m.n_btn = 0;
	u->dlg = KV_TAG_DLG_NONE;
	u->menu_open = 0;
	/* The line the load had to say (files not loaded, lines ignored, no directory) is on the bottom rule at the first open. */
	snprintf(u->err, sizeof u->err, "%s", u->note_pending ? u->store.note : "");
	u->note_pending = 0;
}

void tags_free(struct view *v)
{
	free(v->tag);
	v->tag = NULL;
}

static void tags_close(struct view *v)
{
	v->tag->open = 0;
	v->tag->dlg = KV_TAG_DLG_NONE;
	v->tag->menu_open = 0;
	v->edit = 0;
}

/* Open the small form: Add starts empty, Edit from what the catalog holds for tag `idx`. */
static void dlg_open(struct view *v, enum kv_tag_dlg d, uint32_t idx)
{
	struct kv_tag_ui *u = v->tag;
	const struct kof_tagcat_tag *t = kof_tagcat_get(&u->cat, idx);

	u->dlg = d;
	u->dlg_idx = idx;
	u->acts = u->objs = 0;
	kv_ft_set(&u->f_name, "");
	kv_ft_set(&u->f_comment, "");
	if (d == KV_TAG_DLG_EDIT && t) {
		kv_ft_set(&u->f_name, t->name);
		kv_ft_set(&u->f_comment, t->comment);
		u->acts = t->acts;
		u->objs = t->objs;
	}
	u->err[0] = 0;
	u->menu_open = 0;
	u->fm.f.off.dx = u->fm.f.off.dy = 0;
	v->edit_prev = 0;
	v->caret = 0;
	kv_ftext_focus(v, &u->f_name);
}

static void dlg_close(struct view *v)
{
	v->tag->dlg = KV_TAG_DLG_NONE;
	v->tag->err[0] = 0;
	v->edit = 0;
}

/* OK: the engine validates and changes the catalog; a refusal is its status as one line and the dialog stays open. */
static void dlg_ok(struct view *v)
{
	struct kv_tag_ui *u = v->tag;
	struct kof_tagcat_fields f = { u->f_name.buf, u->f_comment.buf, u->acts, u->objs };
	enum kof_tagcat_status st = u->dlg == KV_TAG_DLG_ADD
		? kof_tagcat_add_fields(&u->cat, &f, NULL)
		: kof_tagcat_edit_fields(&u->cat, u->dlg_idx, &f);

	kv_tag_error_text(&u->cat, st, u->err, sizeof u->err);
	if (st == KOF_TAGCAT_OK)
		dlg_close(v);
}

/* [ Delete ] of Edit: the tag, at once. */
static void dlg_delete(struct view *v)
{
	struct kv_tag_ui *u = v->tag;
	enum kof_tagcat_status st = kof_tagcat_delete(&u->cat, u->dlg_idx);

	kv_tag_error_text(&u->cat, st, u->err, sizeof u->err);
	if (st == KOF_TAGCAT_OK)
		dlg_close(v);
}

/* ---- the main dialog -------------------------------------------------------------------------------------- */

static const char *tag_rowattr(void *user, uint32_t row)
{
	(void)user;
	(void)row;
	return NULL;
}

/* The content size and the measured columns follow the catalog; a frame in which its revision did not move (typing in a field, a
 * scroll, a drag, the menu) reuses them. */
static void tags_derive(struct kv_tag_ui *u)
{
	struct kv_tab_spec t;
	struct kv_tag_tab tt;

	if (u->derived && u->rev_cat == u->cat.rev && u->rev_snap == u->snap.rev)
		return;
	kv_tag_content_size(&u->cat, &u->want_w, &u->want_h);
	kv_tag_spec(&t, &tt, &u->cat);
	memcpy(u->width, t.width, sizeof u->width);
	u->dirty = kof_tagcat_dirty(&u->cat, &u->snap);
	u->rev_cat = u->cat.rev;
	u->rev_snap = u->snap.rev;
	u->derived = 1;
}

static void tags_draw_box(struct out *o, struct view *v, struct kv_tag_ui *u)
{
	struct kv_tab_spec t;
	struct kv_tag_tab tt;
	struct kv_main_in in;
	char count[32];

	tags_derive(u);
	kv_tag_spec_widths(&t, &tt, &u->cat, u->width);
	t.n_sticky = 1;
	t.colattr[0] = A_BOLD;
	t.colattr[KV_TAG_COL_ACTS] = A_S_TYPE;
	t.colattr[KV_TAG_COL_OBJS] = A_S_TYPE;
	t.colattr[KV_TAG_COL_COMMENT] = A_DIM;
	t.rowattr = tag_rowattr;
	snprintf(count, sizeof count, "Syndromes: %u", (unsigned)u->cat.n);
	memset(&in, 0, sizeof in);
	in.title = "Syndromes";
	in.add_label = kv_tag_label_add();
	in.count = count;
	in.act = !u->dlg && u->err[0] ? u->err : NULL;      /* a refused tick is said on the bottom rule */
	in.spec = &t;
	in.n_row = u->cat.n;
	in.want_w = u->want_w;
	in.want_h = u->want_h;
	in.dirty = u->dirty;
	(void)kv_main_draw(o, v, &u->m, &in);
}

/* ---- the small dialog ------------------------------------------------------------------------------------- */

/* THE SIZE of the form: the Name row, the Comment row, the Activities title with its grid, the Objects title with its grid, the error line,
 * the buttons. */
static void tags_dlg_size(int *w, int *h)
{
	struct kv_pick a = kv_tag_acts(), b = kv_tag_objs();
	int row_w[4] = { kv_form_field_w(tag_label_name, TAG_FIELD_COLS), kv_form_field_w(tag_label_comment, TAG_COMMENT_COLS),
			 kv_form_grid_w(&a), kv_form_grid_w(&b) };

	kv_form_size(2 + kv_form_ticks_rows(a.n) + kv_form_ticks_rows(b.n), row_w, 4, w, h);
}

/* ONE FORM for Add and Edit (Edit has [ Delete ] at the right and is filled from the catalog). The tick cells of the activities take
 * the slots from 0, those of the objects the slots after them. */
static void tags_draw_dlg(struct out *o, struct view *v, struct kv_tag_ui *u)
{
	struct kv_form *fm = &u->fm;
	struct kv_pick a = kv_tag_acts(), b = kv_tag_objs();
	int row = 0, w, h;

	tags_dlg_size(&w, &h);
	if (!dframe_begin(o, &fm->f, u->dlg == KV_TAG_DLG_ADD ? "Add Syndrome" : "Edit Syndrome", w, h, 2))
		return;
	kv_form_reset(fm);
	kv_form_row_field(o, v, fm, row++, &u->f_name, tag_label_name, TAG_FIELD_COLS);
	kv_form_row_field(o, v, fm, row++, &u->f_comment, tag_label_comment, TAG_COMMENT_COLS);
	row = kv_form_ticks(o, fm, row, tag_title_acts, &a, u->acts, 0);
	row = kv_form_ticks(o, fm, row, tag_title_objs, &b, u->objs, a.n);
	row = kv_form_footer(o, fm, row, u->err, u->dlg == KV_TAG_DLG_EDIT);
	dframe_end(o, &fm->f, NULL);
	dframe_done(o, &fm->f);
}

/* ---- the tick menu ---------------------------------------------------------------------------------------- */

static int tm_checked(void *ud, int i)
{
	const struct kv_tag_ui *u = ud;

	return kv_tag_menu_checked(&u->cat, u->menu_idx, u->menu_list, (uint32_t)i);
}

static const char *tm_label(void *ud, int i)
{
	struct kv_tag_ui *u = ud;
	struct kv_pick l = kv_tag_list_of(u->menu_list);

	return l.label((uint32_t)i, u->lbl);     /* drawn at once: one scratch is enough */
}

static struct kv_menu tags_menu(struct kv_tag_ui *u)
{
	struct kv_pick l = kv_tag_list_of(u->menu_list);

	return kv_form_menu(&l, u, tm_label, tm_checked);
}

void draw_tags(struct out *o, struct view *v)
{
	struct kv_tag_ui *u = tag_ui(v);

	if (!u || !u->open)
		return;
	kv_cover_begin(&u->cv);
	tags_draw_box(o, v, u);
	kv_form_cover_main(&u->cv, &u->m);
	if (u->dlg) {
		tags_draw_dlg(o, v, u);
		kv_form_cover_dialog(&u->cv, &u->fm);
	}
	if (u->menu_open) {
		struct kv_menu m = tags_menu(u);

		kv_form_draw_menu(o, &u->cv, &m, u->menu_y, u->menu_x);
	}
}

int tags_uncovered(struct view *v)
{
	struct kv_tag_ui *u = tag_ui(v);

	return u && u->open && kv_cover_uncovered(&u->cv);
}

/* ---- the mouse -------------------------------------------------------------------------------------------- */

static int click_menu_items(struct kv_tag_ui *u)
{
	struct kv_menu m = tags_menu(u);
	int a = kv_form_menu_hit(&m, u->menu_y, u->menu_x, g_my, g_mx);

	/* A tick keeps the menu up, so several are set in one visit; a press anywhere else puts it away. */
	if (a == -2)
		u->menu_open = 0;
	else if (a >= 0)
		kv_tag_error_text(&u->cat, kv_tag_menu_toggle(&u->cat, u->menu_idx, u->menu_list, (uint32_t)a), u->err, sizeof u->err);
	return 1;
}

static int click_dlg(struct view *v, struct kv_tag_ui *u)
{
	struct kv_pick a = kv_tag_acts(), b = kv_tag_objs();
	int t;

	if (dframe_grab(v, &u->fm.f))       /* the title row takes hold of the box, as in Find and Go to */
		return 1;
	if (dframe_hit_close(&u->fm.f, g_my, g_mx)) {
		dlg_close(v);
		return 1;
	}
	if (kv_ft_hit(&u->f_name, g_my, g_mx)) {
		kv_ftext_focus(v, &u->f_name);
		return 1;
	}
	if (kv_ft_hit(&u->f_comment, g_my, g_mx)) {
		kv_ftext_focus(v, &u->f_comment);
		return 1;
	}
	if ((t = kv_form_tick_at(&u->fm, a.n + b.n, g_my, g_mx)) >= 0) {
		if ((uint32_t)t < a.n)
			u->acts = kv_pick_flip(&a, u->acts, (uint32_t)t);
		else
			u->objs = kv_pick_flip(&b, u->objs, (uint32_t)t - a.n);
		return 1;
	}
	switch (kv_form_press(&u->fm, u->dlg == KV_TAG_DLG_EDIT, g_my, g_mx)) {
	case KV_FORM_CANCEL: dlg_close(v); break;
	case KV_FORM_OK:     dlg_ok(v); break;
	case KV_FORM_DELETE: dlg_delete(v); break;
	default: break;
	}
	return 1;
}

static void click_table(struct view *v, struct kv_tag_ui *u)
{
	uint32_t row;
	int col;
	enum kv_tag_hit h;

	if (!kv_main_row_at(&u->m, u->cat.n, &row, &col))
		return;
	h = kv_tag_hit_of(&u->cat, row, &u->m.tg, col);
	if (h == KV_TAG_HIT_NAME) {
		dlg_open(v, KV_TAG_DLG_EDIT, row);
	} else if (h == KV_TAG_HIT_ACTS || h == KV_TAG_HIT_OBJS) {
		struct kv_menu m;

		u->menu_open = 1;
		u->err[0] = 0;
		u->menu_idx = row;
		u->menu_list = h == KV_TAG_HIT_ACTS ? KV_TAG_ACTS : KV_TAG_OBJS;
		m = tags_menu(u);
		kv_form_menu_place(&m, g_my, g_mx, &u->menu_y, &u->menu_x);
	}
}

/* [ Save ]: the library writes the files and says in one line what it refused; on success the snapshot is the saved state, on a
 * failure the catalog and the snapshot stay as they were (the buttons stay enabled). */
static void tags_save(struct kv_tag_ui *u, const char *dir)
{
	if (kof_tagcat_save(&u->cat, &u->store, dir) == KOF_CATSTORE_IO_OK) {
		kof_tagcat_snapshot(&u->cat, &u->snap);
		u->err[0] = 0;
	} else {
		snprintf(u->err, sizeof u->err, "%s", u->store.note);
	}
}

/* A press while the dialog is up: it is modal, so every press is answered here (1). The menu bar was asked first. */
int tags_click(struct view *v, int rclick)
{
	struct kv_tag_ui *u = tag_ui(v);

	if (!u || !u->open)
		return 0;
	if (rclick)
		return 1;
	if (u->menu_open)
		return click_menu_items(u);
	if (u->dlg)
		return click_dlg(v, u);
	switch (kv_main_press(v, &u->m)) {
	case KV_MAIN_CLOSE:
		tags_close(v);
		break;
	case (int)KV_DD_BTN_ADD:
		dlg_open(v, KV_TAG_DLG_ADD, 0);
		break;
	case (int)KV_DD_BTN_SAVE:
		tags_save(u, v->syndir);
		break;
	case (int)KV_DD_BTN_DISCARD:
		kof_tagcat_restore(&u->cat, &u->snap);
		u->err[0] = 0;
		break;
	case KV_MAIN_NONE:
		click_table(v, u);
		break;
	default:                            /* the drag started, or a greyed button */
		break;
	}
	return 1;
}

/* ---- the keyboard ----------------------------------------------------------------------------------------- */

/* -1: not mine. While the dialog is up every key is its own; a press goes on to tags_click through click(). */
int handle_tags_key(struct view *v, int k)
{
	struct kv_tag_ui *u = tag_ui(v);
	int r;

	if (!u || !u->open)
		return -1;
	r = kv_form_key_prologue(v, &u->m, k, u->dlg != 0, &u->menu_open);
	if (r)
		return r;
	if (u->dlg) {
		if (k == 27)
			dlg_close(v);
		else if (k == '\r' || k == '\n')
			dlg_ok(v);
		else
			(void)kv_ftext_key(v, v->edit == ED_TAG_COMMENT ? &u->f_comment : &u->f_name, k);
		return 1;
	}
	if (k == 27 || k == '\r' || k == '\n')
		tags_close(v);
	return 1;
}
