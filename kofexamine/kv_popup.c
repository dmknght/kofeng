/*
 * kv_popup.c - the pop-up list (kv_popup.h) and the adapter from a menu table to its rows (split from kofview.c, no change of body).
 */
#define _GNU_SOURCE
#include "kofview.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the pop-up list ------------------------------------------------------- *
 *
 * kv_popup.h says what it is for. The box, the text of a row, the hit test and the key step are decided HERE and nowhere else: the menu
 * bar, the right-click menu, the draft panel's pick-lists and the tick menu of a table cell all arrive at these functions, so a list
 * cannot be drawn one width and clicked at another (the chooser's rows were one column narrower than its box and its rule one column
 * wider), and a submenu cannot open beside the wrong row (the chooser's opened two rows under its parent and one column off).
 */

/* Columns of a UTF-8 string, one per code point (the labels are the engine's words and the user's names; no East-Asian width table here). */
static int pop_cols(const char *s)
{
	int n = 0;

	for (; *s; s++)
		n += ((unsigned char)*s & 0xc0u) != 0x80u;
	return n;
}

/* Append `s` cut to `room` columns, on a code-point boundary, and padded with spaces to exactly `room`; returns the byte length written. */
static size_t pop_put(char *out, size_t cap, size_t n, const char *s, int room)
{
	int used = 0;

	while (*s && used < room && n + 5 < cap) {
		out[n++] = *s++;
		while (((unsigned char)*s & 0xc0u) == 0x80u && n + 1 < cap)
			out[n++] = *s++;
		used++;
	}
	while (used < room && n + 1 < cap) {
		out[n++] = ' ';
		used++;
	}
	out[n] = 0;
	return n;
}

void kv_popup_init(struct kv_popup *p, int cols)
{
	memset(&p->box, 0, sizeof p->box);
	p->n = 0;
	p->cols = cols > 1 ? cols : 1;
}

int kv_popup_add(struct kv_popup *p, const char *text, unsigned flags, int id)
{
	struct kv_popup_row *r;

	if (p->n >= KV_POP_MAX)
		return -1;
	r = &p->row[p->n];
	snprintf(r->text, sizeof r->text, "%s", text ? text : "");
	r->flags = (unsigned char)flags;
	r->id = (flags & KV_PR_RULE) ? -1 : id;
	return p->n++;
}

static int pop_items(const struct kv_popup *p)
{
	int i, n = 0;

	for (i = 0; i < p->n; i++)
		n += (p->row[i].flags & KV_PR_RULE) ? 0 : 1;
	return n;
}

/* Rows a list takes: a grid its tallest column, a list every row (rules included). The one place it is counted. */
static int pop_rows(const struct kv_popup *p)
{
	return p->cols > 1 ? (pop_items(p) + p->cols - 1) / p->cols : p->n;
}

static int pop_tick_w(const struct kv_popup_row *r)
{
	return (r->flags & KV_PR_TICK) ? 4 : 0;
}

void kv_popup_place(struct kv_popup *p, const struct kv_popup_req *q)
{
	struct kv_popup_box *b = &p->box;
	int i, cell = 0, need_w, ncols = p->cols > 1 ? p->cols : 1, area = q->bottom - q->top + 1, cap, h_full, y, x;

	/* A column is as wide as its longest row needs: a space, the tick, the text, a space and, on a row that opens another list, the ">". */
	for (i = 0; i < p->n; i++) {
		int need;

		if (p->row[i].flags & KV_PR_RULE)
			continue;
		need = 1 + pop_tick_w(&p->row[i]) + pop_cols(p->row[i].text) + (ncols > 1 ? 0 : 1) + ((p->row[i].flags & KV_PR_SUB) ? 1 : 0);
		if (need > cell)
			cell = need;
	}
	need_w = cell;
	if (cell < q->min_w)
		cell = q->min_w;
	if (q->max_w > 0 && cell > q->max_w)
		cell = q->max_w;
	cap = (q->cols - 2) / ncols;
	if (cap < 1)
		cap = 1;
	if (cell > cap)
		cell = cap;
	if (cell < 1)
		cell = 1;
	if (need_w > cell)
		need_w = cell;
	if (area < 1)
		area = 1;
	h_full = pop_rows(p);
	if (h_full < 1)
		h_full = 1;

	b->cell_w = cell;
	b->w = cell * ncols;
	b->n_rows = h_full;
	y = q->ay;
	b->side = KV_SIDE_AT;
	if (q->parent) {
		y = q->parent_row;
	} else if (q->anchor_h) {
		int below = q->ay + 1;

		if (h_full <= q->bottom - below + 1) {
			y = below;
			b->side = KV_SIDE_BELOW;
		} else if (h_full <= q->ay - q->top) {
			y = q->ay - h_full;
			b->side = KV_SIDE_ABOVE;
		} else {
			y = q->top;
			b->side = KV_SIDE_COVER;
		}
	}
	b->h = h_full < area ? h_full : area;
	if (b->side == KV_SIDE_COVER)
		b->h = h_full < area ? h_full : area;
	x = q->ax;
	if (q->parent) {
		int right = q->parent->x + q->parent->w;

		/* Neither side has room for the LEAST width (a look): take only what the rows need, which may still fit beside the parent. */
		if (right + b->w - 1 > q->cols && q->parent->x - b->w < 1 && need_w < cell) {
			cell = need_w;
			b->cell_w = cell;
			b->w = cell * ncols;
		}
		if (right + b->w - 1 <= q->cols) {
			x = right;
			b->side = KV_SIDE_RIGHT;
		} else if (q->parent->x - b->w >= 1) {
			x = q->parent->x - b->w;
			b->side = KV_SIDE_LEFT;
		}
	}
	kv_box_fit(&y, &x, b->h, b->w, q->top, q->bottom, q->cols);
	b->y = y;
	b->x = x;
	b->off = q->off;
	if (b->off > b->n_rows - b->h)
		b->off = b->n_rows - b->h;
	if (b->off < 0)
		b->off = 0;
}

int kv_popup_text(const struct kv_popup *p, int r, int c, char *out, size_t cap)
{
	const struct kv_popup_box *b = &p->box;
	size_t n = 0;
	int w = b->cell_w, field, k, tick = 0;
	const struct kv_popup_row *row;

	if (cap < 8)
		return 0;
	out[0] = 0;
	if (p->cols > 1) {
		k = c * b->n_rows + r;
		if (c < 0 || c >= p->cols || r < 0 || r >= b->n_rows || k >= pop_items(p)) {
			pop_put(out, cap, 0, "", w);
			return w;
		}
		row = &p->row[k];
		tick = pop_tick_w(row);
		n = pop_put(out, cap, 0, " ", 1);
		if (tick)
			n = pop_put(out, cap, n, (row->flags & KV_PR_ON) ? "[x] " : "[ ] ", 4);
		field = w - 1 - tick;
		pop_put(out, cap, n, row->text, field > 0 ? field : 0);
		return w;
	}
	if (r < 0 || r >= p->n)
		return 0;
	row = &p->row[r];
	w = b->w;
	if (row->flags & KV_PR_RULE) {
		n = pop_put(out, cap, 0, " ", 1);
		for (k = 0; k < w - 2; k++)
			n = pop_put(out, cap, n, "-", 1);
		pop_put(out, cap, n, " ", 1);
		return w;
	}
	if ((r == b->off && b->off > 0) || (r == b->off + b->h - 1 && b->off + b->h < b->n_rows)) {
		n = pop_put(out, cap, 0, " ...", w > 1 ? w - 1 : w);
		if (w > 1)
			pop_put(out, cap, n, r == b->off ? "^" : "v", 1);
		return w;
	}
	tick = pop_tick_w(row);
	n = pop_put(out, cap, 0, " ", 1);
	if (tick)
		n = pop_put(out, cap, n, (row->flags & KV_PR_ON) ? "[x] " : "[ ] ", 4);
	field = w - 1 - tick - 1 - ((row->flags & KV_PR_SUB) ? 1 : 0);
	n = pop_put(out, cap, n, row->text, field > 0 ? field : 0);
	n = pop_put(out, cap, n, (row->flags & KV_PR_SUB) ? " >" : " ", (row->flags & KV_PR_SUB) ? 2 : 1);
	(void)n;
	return w;
}

int kv_popup_hit(const struct kv_popup *p, int my, int mx)
{
	const struct kv_popup_box *b = &p->box;
	int r = my - b->y, c = mx - b->x, k;

	if (r < 0 || r >= b->h || c < 0 || c >= b->w)
		return -2;
	if (p->cols > 1) {
		k = (c / b->cell_w) * b->n_rows + b->off + r;
		return k < pop_items(p) ? k : -1;
	}
	k = b->off + r;
	if (k >= p->n || (p->row[k].flags & KV_PR_RULE))
		return -1;
	return k;
}

static int pop_choosable(const struct kv_popup_row *r)
{
	return !(r->flags & (KV_PR_RULE | KV_PR_OFF));
}

int kv_popup_row_of(const struct kv_popup *p, int id)
{
	int i;

	for (i = 0; i < p->n; i++)
		if (!(p->row[i].flags & KV_PR_RULE) && p->row[i].id == id)
			return i;
	return -1;
}

int kv_popup_first(const struct kv_popup *p)
{
	int i;

	for (i = 0; i < p->n; i++)
		if (pop_choosable(&p->row[i]))
			return p->row[i].id;
	return -1;
}

int kv_popup_step(const struct kv_popup *p, int cur_id, int d)
{
	int i;

	if (cur_id < 0) {
		for (i = d > 0 ? 0 : p->n - 1; i >= 0 && i < p->n; i += d > 0 ? 1 : -1)
			if (pop_choosable(&p->row[i]))
				return p->row[i].id;
		return cur_id;
	}
	/* From an item that may not be on the list at all (hidden since): the next choosable one in the table's order, ids ascending down the list. */
	for (i = d > 0 ? 0 : p->n - 1; i >= 0 && i < p->n; i += d > 0 ? 1 : -1)
		if (pop_choosable(&p->row[i]) && (d > 0 ? p->row[i].id > cur_id : p->row[i].id < cur_id))
			return p->row[i].id;
	return cur_id;
}

int kv_popup_row_y(const struct kv_popup *p, int id)
{
	int r = kv_popup_row_of(p, id);

	if (r < 0 || r < p->box.off || r >= p->box.off + p->box.h)
		return -1;
	return p->box.y + r - p->box.off;
}

void kv_popup_follow(struct kv_popup *p, int id)
{
	struct kv_popup_box *b = &p->box;
	int r = kv_popup_row_of(p, id);

	if (r < 0 || b->n_rows <= b->h || p->cols > 1) {
		if (b->n_rows <= b->h)
			b->off = 0;
		return;
	}
	if (r < b->off)
		b->off = r;
	else if (r >= b->off + b->h)
		b->off = r - b->h + 1;
	if (b->off > b->n_rows - b->h)
		b->off = b->n_rows - b->h;
	if (b->off < 0)
		b->off = 0;
}

void kv_popup_screen(struct kv_popup_req *q)
{
	memset(q, 0, sizeof *q);
	q->rows = g_rows;
	q->cols = g_cols;
	q->top = 2;                     /* row 1 is the menu bar */
	q->bottom = g_rows - 1;         /* the status line stays uncovered */
}

void kv_popup_draw(struct out *o, const struct kv_popup *p, int sel, int sel2)
{
	const struct kv_popup_box *b = &p->box;
	struct out_clip cl;
	char t[KV_POP_TEXT * 4];
	int r, c;

	if (b->h < 1 || b->w < 1)
		return;
	/* A box is a box and stays in it: clipped to its own rectangle, so a row can never wrap onto the next line of the terminal. */
	cl = out_clip_set(o, b->y, b->x, b->y + b->h - 1, b->x + b->w - 1);
	for (r = 0; r < b->h; r++) {
		out_at(o, b->y + r, b->x);
		if (p->cols > 1) {
			for (c = 0; c < p->cols; c++) {
				int it = c * b->n_rows + b->off + r;
				const struct kv_popup_row *row = it < p->n ? &p->row[it] : NULL;

				kv_popup_text(p, b->off + r, c, t, sizeof t);
				out_str(o, row && (row->id == sel || row->id == sel2) ? BAR_CUR
					   : row && (row->flags & KV_PR_OFF) ? BAR_OFF : BAR_ON);
				out_str(o, t);
				out_str(o, A_OFF);
			}
			continue;
		}
		{
			const struct kv_popup_row *row = &p->row[b->off + r];

			if (row->flags & KV_PR_RULE) {
				int k;

				out_str(o, BAR_ON " ");
				for (k = 0; k < b->w - 2; k++)
					out_glyph(o, G_H);
				out_str(o, " " A_OFF);
				continue;
			}
			kv_popup_text(p, b->off + r, 0, t, sizeof t);
			out_str(o, (row->id == sel || row->id == sel2) ? BAR_CUR : (row->flags & KV_PR_OFF) ? BAR_OFF : BAR_ON);
			out_str(o, t);
			out_str(o, A_OFF);
		}
	}
	out_clip_restore(o, cl);
}

/* ---- a menu described by callbacks ------------------------------------------ */

static int kv_shown(const struct kv_menu *m, int i)
{
	return m->shown ? m->shown(m->ud, i) : 1;
}

/* The ONE adapter from a menu's own table (shown / enabled / rule_above / label / has_sub / checked) to the rows of a pop-up. */
void kv_menu_popup(const struct kv_menu *m, struct kv_popup *p)
{
	int i;

	kv_popup_init(p, m->cols);
	for (i = 0; i < m->n; i++) {
		unsigned fl = 0;

		if (!kv_shown(m, i))
			continue;
		if (p->cols == 1 && m->rule_above && m->rule_above(m->ud, i))
			kv_popup_add(p, "", KV_PR_RULE, -1);
		if (m->enabled && !m->enabled(m->ud, i))
			fl |= KV_PR_OFF;
		if (p->cols == 1 && m->has_sub && m->has_sub(m->ud, i))
			fl |= KV_PR_SUB;
		if (m->checked)
			fl |= KV_PR_TICK | (m->checked(m->ud, i) ? KV_PR_ON : 0u);
		kv_popup_add(p, m->label ? m->label(m->ud, i) : "", fl, i);
	}
}

/* Fill a request for a menu: the screen, the menu's least width, and the anchor; the caller adds a parent when it is a submenu. */
void kv_menu_req(const struct kv_menu *m, int ay, int ax, int anchor_h, struct kv_popup_req *q)
{
	kv_popup_screen(q);
	q->ay = ay;
	q->ax = ax;
	q->anchor_h = anchor_h;
	q->min_w = m->w;
}

/* Rows a menu takes (a grid: its tallest column) - what a caller covering the box asks. */
int kv_menu_rows(const struct kv_menu *m)
{
	struct kv_popup p;

	kv_menu_popup(m, &p);
	return pop_rows(&p);
}
