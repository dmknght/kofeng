#define _GNU_SOURCE
#include "kv.h"
#include "kv_ftext.h"
#include "kv_form.h"
#include <verdictor/catstore.h>

/*
 * kv_form.c - the screen code Manage > Pathogens (kv_families.c) and Manage > Syndromes (kv_tags.c) share. See kv_form.h. It decides
 * nothing about a catalog: it places rows, ticks, buttons and menus and answers where a press landed.
 */

#define FORM_MENU_W 16          /* the least width of a menu column: "[x] " and a word of 12 */
#define FORM_MENU_COLS 2

static const char label_ok[] = "[ OK ]";
static const char label_cancel[] = "[ Cancel ]";
static const char label_delete[] = "[ Delete ]";

int kv_form_in_span(int y, int x, int y0, int x0, int x1)
{
	return y == y0 && x >= x0 && x <= x1;
}

/* ---- FORM ---------------------------------------------------------------------------------------------------- */

void kv_form_reset(struct kv_form *fm)
{
	uint32_t i;

	for (i = 0; i < KV_FORM_SLOTS; i++)
		fm->tick_y[i] = -1;
}

void kv_form_row_text(struct out *o, struct kv_form *fm, int row, const char *label, const char *text, int text_cols)
{
	dframe_row(o, &fm->f, row);
	out_fmt(o, A_DIM "%s" A_OFF "%s%.*s" A_OFF, label, text[0] ? A_ID : A_DIM, text_cols, text[0] ? text : "-");
	dframe_edge(o, &fm->f);
}

void kv_form_row_field(struct out *o, struct view *v, struct kv_form *fm, int row, struct kv_ftext *f, const char *label, int cols)
{
	dframe_row(o, &fm->f, row);
	out_fmt(o, A_DIM "%s" A_OFF, label);
	kv_ftext_draw_here(o, v, f, cols);
	dframe_edge(o, &fm->f);
}

/* A cell past the table is drawn but keeps no span (it cannot be pressed): the arrays are KV_FORM_SLOTS long and a slot past the
 * end is the next array's slot 0 or past the struct. kv_form_tick_at already stops at KV_FORM_SLOTS. */
void kv_form_tick_cell(struct out *o, struct kv_form *fm, uint32_t slot, int y, const char *label, int on, int enabled, int w)
{
	char text[KV_PICK_LABEL + 16];

	int x0 = o->col_base + (int)o->col_hint;

	kv_form_cell_text(text, sizeof text, label, on, w);
	out_fmt(o, "%s%s" A_OFF, enabled ? A_ID : A_BTN_OFF, text);
	if (slot >= KV_FORM_SLOTS)
		return;
	fm->tick_y[slot] = y;
	fm->tick_x0[slot] = x0;
	fm->tick_x1[slot] = x0 + (int)strlen(label) + 3;
}

int kv_form_ticks(struct out *o, struct kv_form *fm, int row, const char *title, const struct kv_pick *l, uint32_t mask,
		  uint32_t slot0)
{
	char buf[KV_PICK_LABEL];
	uint32_t rows = (l->n + KV_FORM_TICK_COLS - 1u) / KV_FORM_TICK_COLS, r, c;
	int w = kv_form_cell_w(l);

	dframe_row(o, &fm->f, row++);
	out_fmt(o, A_DIM "%s" A_OFF, title);
	dframe_edge(o, &fm->f);
	for (r = 0; r < rows; r++) {
		dframe_row(o, &fm->f, row++);
		for (c = 0; c < KV_FORM_TICK_COLS; c++) {
			int i = kv_form_grid_item(l->n, r, c);

			if (i < 0)
				break;
			kv_form_tick_cell(o, fm, slot0 + (uint32_t)i, fm->f.y + row, l->label((uint32_t)i, buf),
					  kv_pick_has(l, mask, (uint32_t)i), 1, w);
		}
		dframe_edge(o, &fm->f);
	}
	return row;
}

int kv_form_tick_at(const struct kv_form *fm, uint32_t n, int y, int x)
{
	uint32_t i;

	for (i = 0; i < n && i < KV_FORM_SLOTS; i++)
		if (kv_form_in_span(y, x, fm->tick_y[i], fm->tick_x0[i], fm->tick_x1[i]))
			return (int)i;
	return -1;
}

/*
 * [ OK ] [ Cancel ] at the left and [ Delete ] alone at the right edge: the one button that destroys something is as far from the
 * others as the row allows, so a press that misses OK or Cancel by a little cannot land on it. The row is the same in every mode,
 * so OK and Cancel stay where they are whether Delete is there or not.
 */
int kv_form_footer(struct out *o, struct kv_form *fm, int row, const char *err, int edit)
{
	const struct dframe *f = &fm->f;
	int inner = f->w - 4, del = edit ? (int)strlen(label_delete) : 0;
	int left = (int)strlen(label_ok) + 2 + (int)strlen(label_cancel), pad = inner - del - left;

	dframe_row(o, f, row++);
	out_fmt(o, "%s%.*s" A_OFF, A_WARN, KV_FORM_ERR_COLS, err);
	dframe_edge(o, f);
	dframe_row(o, f, row++);
	fm->btn_y = f->y + row;
	fm->ok_x[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_BTN_OK "%s" A_OFF, label_ok);
	fm->ok_x[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	fm->cancel_x[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_BTN_CANCEL "%s" A_OFF, label_cancel);
	fm->cancel_x[1] = o->col_base + (int)o->col_hint - 1;
	fm->delete_x[0] = fm->delete_x[1] = -1;
	if (del) {
		out_fmt(o, "%*s", pad > 2 ? pad : 2, "");
		fm->delete_x[0] = o->col_base + (int)o->col_hint;
		out_fmt(o, A_BTN_DEL "%s" A_OFF, label_delete);
		fm->delete_x[1] = o->col_base + (int)o->col_hint - 1;
	}
	dframe_edge(o, f);
	return row;
}

enum kv_form_btn kv_form_press(const struct kv_form *fm, int edit, int y, int x)
{
	if (kv_form_in_span(y, x, fm->btn_y, fm->cancel_x[0], fm->cancel_x[1]))
		return KV_FORM_CANCEL;
	if (kv_form_in_span(y, x, fm->btn_y, fm->ok_x[0], fm->ok_x[1]))
		return KV_FORM_OK;
	if (edit && kv_form_in_span(y, x, fm->btn_y, fm->delete_x[0], fm->delete_x[1]))
		return KV_FORM_DELETE;
	return KV_FORM_NONE;
}

/* ---- MENU ---------------------------------------------------------------------------------------------------- */

struct kv_menu kv_form_menu(const struct kv_pick *l, void *ud, const char *(*label)(void *, int), int (*checked)(void *, int))
{
	struct kv_menu m;

	memset(&m, 0, sizeof m);
	m.n = (int)l->n;
	m.ud = ud;
	m.label = label;
	m.checked = checked;
	m.w = kv_form_cell_w(l) - KV_FORM_TICK_GAP + 1 > FORM_MENU_W ? kv_form_cell_w(l) - KV_FORM_TICK_GAP + 1 : FORM_MENU_W;
	m.cols = FORM_MENU_COLS;
	return m;
}

/* The menu as a pop-up in the box it has at (y, x): kv_popup_place keeps a placed box where it is, so the draw and the hit test agree with where it was put. */
static void form_menu_popup(const struct kv_menu *m, int y, int x, struct kv_popup *p)
{
	struct kv_popup_req q;

	kv_menu_popup(m, p);
	kv_menu_req(m, y, x, 0, &q);
	kv_popup_place(p, &q);
}

void kv_form_menu_place(const struct kv_menu *m, int y, int x, int *oy, int *ox)
{
	struct kv_popup p;

	form_menu_popup(m, y, x, &p);
	*oy = p.box.y;
	*ox = p.box.x;
}

int kv_form_menu_hit(const struct kv_menu *m, int y, int x, int my, int mx)
{
	struct kv_popup p;
	int r;

	form_menu_popup(m, y, x, &p);
	r = kv_popup_hit(&p, my, mx);
	return r < 0 ? (r == -1 ? -1 : -2) : p.row[r].id;
}

void kv_form_menu_draw(struct out *o, const struct kv_menu *m, int y, int x)
{
	struct kv_popup p;

	form_menu_popup(m, y, x, &p);
	kv_popup_draw(o, &p, -1, -1);
}

/* ---- COVER --------------------------------------------------------------------------------------------------- */

void kv_cover_begin(struct kv_cover *c)
{
	memset(c->cover, 0, sizeof c->cover);
}

void kv_cover_set(struct kv_cover *c, int i, int y0, int x0, int y1, int x1)
{
	c->cover[i].y0 = y0;
	c->cover[i].x0 = x0;
	c->cover[i].y1 = y1;
	c->cover[i].x1 = x1;
}

/* Is rectangle `p` (not empty) inside one of the rectangles this frame covers? */
static int rect_inside(const struct kv_form_rect *p, const struct kv_form_rect c[KV_COVER_N])
{
	int i;

	for (i = 0; i < KV_COVER_N; i++)
		if ((c[i].y1 || c[i].x1) && p->y0 >= c[i].y0 && p->y1 <= c[i].y1 && p->x0 >= c[i].x0 && p->x1 <= c[i].x1)
			return 1;
	return 0;
}

/* What a smaller, moved or closed box uncovers is erased only by what was beneath it, so the panes are painted again on a frame in
 * which a rectangle of the last one is not inside a rectangle of this one. A box that only GROWS (a small dialog or the menu opening
 * over the table) uncovers nothing: every box is drawn whole on every frame. */
int kv_cover_uncovered(struct kv_cover *c)
{
	int i, diff = 0;

	for (i = 0; i < KV_COVER_N; i++)
		if ((c->painted[i].y1 || c->painted[i].x1) && !rect_inside(&c->painted[i], c->cover))
			diff = 1;
	memcpy(c->painted, c->cover, sizeof c->cover);
	return diff;
}

void kv_form_cover_main(struct kv_cover *c, const struct kv_main *m)
{
	if (m->geo.ok)
		kv_cover_set(c, 0, m->geo.top, m->geo.left, m->geo.top + m->geo.h - 1, m->geo.left + m->geo.w - 1);
}

void kv_form_cover_dialog(struct kv_cover *c, const struct kv_form *fm)
{
	kv_cover_set(c, 1, fm->f.y, fm->f.x, fm->f.y + fm->f.h - 1, fm->f.x + fm->f.w - 1);
}

void kv_form_draw_menu(struct out *o, struct kv_cover *c, const struct kv_menu *m, int y, int x)
{
	kv_form_menu_draw(o, m, y, x);
	kv_cover_set(c, 2, y, x, y + kv_menu_rows(m) - 1, x + m->w * m->cols - 1);
}

int kv_form_key_prologue(struct view *v, struct kv_main *m, int k, int dlg_open, int *menu_open)
{
	if (k == K_CLICK || k == K_RCLICK)
		return -1;
	if (kv_main_key(v, m, k, !dlg_open && !*menu_open))
		return 1;
	if (*menu_open) {
		if (k == 27)
			*menu_open = 0;
		return 1;
	}
	return 0;
}

/* ---- MAIN ---------------------------------------------------------------------------------------------------- */

#define MAIN_MAX_LINES 64u

/* The bottom row: the buttons' labels at the columns kv_dd_buttons gave, an enabled one in the button colour and a greyed
 * one (Save, Discard while nothing changed) in the viewer's disabled-button style. */
static void button_row(const struct kv_dd_geo *g, const struct kv_dd_btn *b, uint32_t n, char *out, size_t cap)
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

int kv_main_draw(struct out *o, struct view *v, struct kv_main *m, const struct kv_main_in *mi)
{
	struct kv_dd_in in;
	struct kv_dd_geo *g = &m->geo;
	struct kv_tab_in ti;
	char line[MAIN_MAX_LINES][KV_TAB_LINE];     /* the visible rows only: MAIN_MAX_LINES bounds them, no allocation per frame */
	char rule[1024];
	uint32_t room, nl, y;

	memset(&in, 0, sizeof in);
	in.cols = g_cols;
	in.rows = g_rows;
	in.title = mi->title;
	in.n_tab = mi->n_tab < KV_DD_TABS ? mi->n_tab : KV_DD_TABS;
	in.tab_sel = mi->tab_sel;
	for (y = 0; mi->tab && y < (uint32_t)in.n_tab; y++)
		in.tab[y] = mi->tab[y];
	if (!mi->tab)
		in.n_tab = 0;
	in.want_w = mi->want_w;
	in.want_h = mi->want_h;
	in.dx = m->move.dx;
	in.dy = m->move.dy;
	kv_dd_layout(&in, g);
	m->move.dx = g->dx;                 /* what is kept is what the screen allows */
	m->move.dy = g->dy;
	if (!g->ok)
		return 0;
	/* The last body row holds the buttons; one blank row above it. A body of rows that are not a table has no buttons and takes every row. */
	room = mi->body ? (uint32_t)g->body_rows : g->body_rows > 2 ? (uint32_t)g->body_rows - 2u : 0u;
	if (room > MAIN_MAX_LINES && !mi->body)
		room = MAIN_MAX_LINES;
	if (mi->body) {
		const uint32_t cols = (uint32_t)g->body_cols;

		m->off = kv_tab_clamp(m->off, mi->body->n_row, room);
		m->hoff = m->hoff > (mi->body->n_col + 1u > cols ? mi->body->n_col + 1u - cols : 0u) ? (mi->body->n_col + 1u > cols ? mi->body->n_col + 1u - cols : 0u) : m->hoff;
	} else {
		m->off = kv_tab_clamp(m->off, mi->n_row, room);
	}
	in.count = mi->count;
	in.act = mi->act;
	in.act_ok = 0;
	in.total = mi->body ? mi->body->n_row : mi->n_row;
	in.off = m->off;
	in.shown = room;
	kv_dd_fill(&in, g);
	nl = 0;
	m->n_btn = 0;
	m->tab_y = g->body_y0;
	if (!mi->body) {
		ti.row0 = m->off;
		ti.rows = room;
		ti.hoff = m->hoff;
		ti.width = g->body_cols;
		ti.margin = 1;
		ti.heading = 0;
		nl = kv_tab_render(mi->spec, &ti, line, MAIN_MAX_LINES, &m->tg, NULL);
		m->hoff = m->tg.hoff;
		m->n_btn = kv_dd_buttons(g, mi->add_label, mi->dirty, m->btn);
	}
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
		if (mi->body) {
			char text[2048];

			text[0] = 0;
			if (m->off + y < mi->body->n_row)
				mi->body->row(mi->body->user, m->off + y, m->hoff, (uint32_t)g->body_cols, text, sizeof text);
			prop_put(o, text, g->body_cols, -1, -1);
		} else if (y < nl) {
			prop_put(o, line[y], g->body_cols, -1, -1);
		} else if (m->n_btn && m->btn[0].y == g->body_y0 + (int)y) {
			char row[256];

			button_row(g, m->btn, m->n_btn, row, sizeof row);
			prop_put(o, row, g->body_cols, -1, -1);
		} else {
			prop_put(o, "", g->body_cols, -1, -1);
		}
		out_str(o, right);
	}
	/* The box claims its rectangle, both buttons: a press on it never reaches a pane under it. */
	hit_zone(v, g->top, g->left, g->top + g->h - 1, g->left + g->w - 1, (uint8_t)(HIT_L | HIT_R), hit_row_none, 0);
	return 1;
}

int kv_main_press(struct view *v, struct kv_main *m)
{
	if (kv_dd_close_at(&m->geo, g_my, g_mx))
		return KV_MAIN_CLOSE;
	if (kv_dd_grab_at(&m->geo, g_my, g_mx)) {
		dlg_hold(v, &m->move);
		return KV_MAIN_HELD;
	}
	{
		const int t = kv_dd_tab_at(&m->geo, g_my, g_mx);

		if (t >= 0)
			return KV_MAIN_TAB(t);
	}
	return kv_dd_btn_at(m->btn, m->n_btn, g_my, g_mx);
}

int kv_main_row_at(const struct kv_main *m, uint32_t n_row, uint32_t *row, int *col)
{
	uint32_t r;
	int k;

	if (kv_tab_hit(&m->tg, g_my - m->tab_y, g_mx - m->geo.body_x0, &r, &k) != 2)
		return 0;
	r += m->tg.row0;
	if (r >= n_row)
		return 0;
	*row = r;
	*col = g_mx - m->geo.body_x0;
	return 1;
}

int kv_main_key(struct view *v, struct kv_main *m, int k, int scroll)
{
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
		if (scroll) {
			int side = g_mod_shift || g_mod_ctrl;
			uint32_t d = side ? KV_MAIN_WHEEL_COLS : KV_MAIN_WHEEL_ROWS;
			uint32_t *at = side ? &m->hoff : &m->off;

			*at = k == K_WHEEL_UP ? (*at > d ? *at - d : 0u) : *at + d;  /* clamped where it is drawn */
		}
		return 1;
	}
	return 0;
}

int kv_form_comment_accept(int k)
{
	return kof_comment_char(k);
}

int kv_form_comment_check(void *user, const char *text, char *err, size_t cap)
{
	enum kof_catcomment st = kof_catcomment_check(text);

	(void)user;
	snprintf(err, cap, "%s", kof_catcomment_text(st));
	return st == KOF_CATCOMMENT_OK;
}
