#define _GNU_SOURCE

/*
 * kv_table.c - the table renderer. See kv_table.h for the contract.
 *
 * Layout in one place (struct tab_lay): the natural width of each column, where it starts in the virtual row,
 * what the box leaves for the sliding part and how far that can pan. Every question - which characters of a cell
 * are visible, where a click lands - is asked of that one layout, so the drawing and the geometry returned cannot
 * differ.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofview.h"
#include "kv_table.h"

struct tab_lay {
	uint32_t n, n_sticky;
	uint32_t w[KV_TAB_COLS];    /* cell width (the unit of a column is w + 1: the gap after it) */
	uint32_t s[KV_TAB_COLS];    /* where the column starts in the virtual row */
	uint32_t nat;               /* the virtual row's width */
	uint32_t sticky;            /* width of the columns that do not slide, clipped to the box */
	uint32_t room;              /* the box's cells */
	uint32_t rp;                /* what the box leaves for the sliding columns */
	uint32_t hmax;
};

/* Largest start of `room` rows over `total` rows. */
uint32_t kv_tab_clamp(uint32_t off, uint32_t total, uint32_t room)
{
	uint32_t mx = total > room ? total - room : 0u;

	return off > mx ? mx : off;
}

static uint32_t head_w(const struct kv_tab_spec *t, uint32_t k)
{
	uint32_t w = t->width[k], h = t->col[k] ? (uint32_t)strlen(t->col[k]) : 0u;

	return w > h ? w : h;
}

/* Widths, starts, sticky part and pan range for a box `room` cells wide. */
static void lay_fit(const struct kv_tab_spec *t, uint32_t room, struct tab_lay *L)
{
	uint32_t k, x = 0, st = 0;

	memset(L, 0, sizeof *L);
	L->n = t->n_col < KV_TAB_COLS ? t->n_col : KV_TAB_COLS;
	L->n_sticky = t->n_sticky < L->n ? t->n_sticky : L->n;
	L->room = room;
	for (k = 0; k < L->n; k++)
		L->w[k] = head_w(t, k);
	for (k = 0; k < L->n; k++)
		x += L->w[k] + 1u;
	if (t->flex >= 0 && (uint32_t)t->flex < L->n && x < room) {
		L->w[t->flex] += room - x;
		x = room;
	}
	L->nat = x;
	for (x = 0, k = 0; k < L->n; k++) {
		L->s[k] = x;
		x += L->w[k] + 1u;
		if (k < L->n_sticky)
			st = x;
	}
	L->sticky = st < room ? st : room;
	L->rp = room - L->sticky;
	L->hmax = L->rp && L->nat - st > L->rp ? L->nat - st - L->rp : 0u;
}

/* The characters [*from, *to) of column k's unit (cell + gap) the box shows at offset `hoff`, and the screen
 * column of the first. A sliding column is shown through the window [sticky, room). */
static int lay_slice(const struct tab_lay *L, uint32_t k, uint32_t hoff, uint32_t *from, uint32_t *to,
		     uint32_t *at)
{
	uint32_t u = L->w[k] + 1u;
	int64_t x = k < L->n_sticky ? (int64_t)L->s[k] : (int64_t)L->s[k] - hoff;
	int64_t lo = k < L->n_sticky ? 0 : (int64_t)L->sticky;
	int64_t hi = k < L->n_sticky ? (int64_t)L->sticky : (int64_t)L->room;
	int64_t a = x < lo ? lo : x, b = x + u > hi ? hi : x + u;

	if (b <= a)
		return 0;
	*from = (uint32_t)(a - x);
	*to = (uint32_t)(b - x);
	*at = (uint32_t)a;
	return 1;
}

static unsigned char tab_char(unsigned char ch)
{
	return (ch < 0x20u || ch == 0x7fu) ? '?' : ch;
}

/* One produced character of a column's unit: the cell (left or right aligned), then the gap. */
static unsigned char unit_char(const char *c, uint32_t len, uint32_t w, int right, uint32_t j)
{
	uint32_t pad = right && len < w ? w - len : 0u;

	if (j >= w || j < pad || j - pad >= len)
		return ' ';
	return tab_char((unsigned char)c[j - pad]);
}

/* Append `attr`, the visible characters of the unit, and the reset to line[n..]; returns the new length. */
static uint32_t put_unit(char *line, uint32_t n, const char *attr, const char *c, uint32_t w, int right,
			 uint32_t from, uint32_t to)
{
	uint32_t len = (uint32_t)strnlen(c, w), j;

	if (attr)
		n += (uint32_t)snprintf(line + n, KV_TAB_LINE - n, "%s", attr);
	for (j = from; j < to && n + 8u < KV_TAB_LINE; j++)
		line[n++] = (char)unit_char(c, len, w, right, j);
	line[n] = 0;
	if (attr && n + 8u < KV_TAB_LINE)
		n += (uint32_t)snprintf(line + n, KV_TAB_LINE - n, "%s", A_OFF);
	return n;
}

/* One line: the margin, then every visible column. `cell` NULL entries are "". */
static void emit_line(char *line, const struct kv_tab_spec *t, const struct tab_lay *L, uint32_t hoff,
		      int margin, const char *const *cell, const char *row_attr, const char *head)
{
	uint32_t k, n = 0, from, to, at;

	for (; n < (uint32_t)margin && n + 1u < KV_TAB_LINE; n++)
		line[n] = ' ';
	line[n] = 0;
	for (k = 0; k < L->n && n + 16u < KV_TAB_LINE; k++) {
		const char *c = head ? (t->col[k] ? t->col[k] : "") : (cell[k] ? cell[k] : "");
		const char *at_s = head ? head : row_attr ? row_attr : t->colattr[k];

		if (lay_slice(L, k, hoff, &from, &to, &at))
			n = put_unit(line, n, at_s, c, L->w[k], t->right[k], from, to);
	}
}

static void geo_cols(const struct kv_tab_spec *t, const struct tab_lay *L, const struct kv_tab_in *in,
		     uint32_t hoff, struct kv_tab_geo *g)
{
	uint32_t k, from, to, at;

	g->n_col = L->n;
	for (k = 0; k < L->n; k++) {
		g->cx[k] = -1;
		g->cw[k] = 0;
		g->cfrom[k] = 0;
		if (!lay_slice(L, k, hoff, &from, &to, &at))
			continue;
		if (to > L->w[k])
			to = L->w[k];
		if (to <= from)
			continue;
		g->cx[k] = in->margin + (int)at;
		g->cw[k] = (int)(to - from);
		g->cfrom[k] = from;
	}
	(void)t;
}

/* ---- the record of full cell text ---------------------------------------------------------------------- */

static int rec_room(struct kv_tab_rec *r, size_t add, uint32_t add_off)
{
	if (r->n + add + 1u > r->cap) {
		size_t nc = r->cap ? r->cap : 1024u;
		char *p;

		while (nc < r->n + add + 1u)
			nc *= 2u;
		p = realloc(r->buf, nc);
		if (!p)
			return 0;
		r->buf = p;
		r->cap = nc;
	}
	if (r->n_off + add_off > r->cap_off) {
		uint32_t nc = r->cap_off ? r->cap_off : 64u;
		uint32_t *p;

		while (nc < r->n_off + add_off)
			nc *= 2u;
		p = realloc(r->off, nc * sizeof *p);
		if (!p)
			return 0;
		r->off = p;
		r->cap_off = nc;
	}
	return 1;
}

static void rec_row(struct kv_tab_rec *r, uint32_t n_col, const char *const *cell)
{
	uint32_t k;

	for (k = 0; k < n_col; k++) {
		const char *c = cell[k] ? cell[k] : "";
		size_t l = strlen(c), i;

		if (!rec_room(r, l, 1u)) {
			r->bad = 1;
			return;
		}
		r->off[r->n_off++] = (uint32_t)r->n;
		for (i = 0; i < l; i++)
			r->buf[r->n++] = (char)tab_char((unsigned char)c[i]);
		r->buf[r->n++] = 0;
	}
}

void kv_tab_rec_free(struct kv_tab_rec *r)
{
	free(r->buf);
	free(r->off);
	memset(r, 0, sizeof *r);
}

const char *kv_tab_rec_cell(const struct kv_tab_rec *r, const struct kv_tab_geo *g, uint32_t row, uint32_t k)
{
	size_t at = (size_t)row * r->n_col + k;

	if (r->bad || row >= g->shown || k >= r->n_col || at >= r->n_off)
		return NULL;
	return r->buf + r->off[at];
}

size_t kv_tab_rec_line(const struct kv_tab_rec *r, const struct kv_tab_geo *g, uint32_t row, char *out, size_t cap)
{
	size_t n = 0;
	uint32_t k;

	if (!cap)
		return 0;
	out[0] = 0;
	for (k = 0; k < r->n_col; k++) {
		const char *c = kv_tab_rec_cell(r, g, row, k);

		if (!c)
			return 0;
		n += (size_t)snprintf(out + n, cap - n, "%s%s", k ? "  " : "", c);
		if (n >= cap) {
			n = cap - 1u;
			break;
		}
	}
	while (n && out[n - 1u] == ' ')
		out[--n] = 0;
	return n;
}

/* ---- the render ------------------------------------------------------------------------------------------ */

uint32_t kv_tab_render(const struct kv_tab_spec *t, const struct kv_tab_in *in,
		       char (*line)[KV_TAB_LINE], uint32_t max_line,
		       struct kv_tab_geo *g, struct kv_tab_rec *rec)
{
	struct tab_lay L;
	uint32_t room, nl = 0, i, rows, row0, hoff;

	memset(g, 0, sizeof *g);
	if (rec) {
		rec->n = rec->n_off = 0;
		rec->bad = 0;
		rec->n_col = t->n_col < KV_TAB_COLS ? t->n_col : KV_TAB_COLS;
	}
	room = in->width > in->margin && in->margin >= 0 ? (uint32_t)(in->width - in->margin) : 0u;
	lay_fit(t, room, &L);
	hoff = in->hoff < L.hmax ? in->hoff : L.hmax;
	g->hoff = hoff;
	g->hmax = L.hmax;
	g->width = in->width > 0 ? in->width : 0;
	geo_cols(t, &L, in, hoff, g);
	if (in->heading && nl < max_line) {
		emit_line(line[nl++], t, &L, hoff, in->margin, NULL, NULL, t->head_attr ? t->head_attr : "");
		g->has_head = 1;
	}
	row0 = in->row0 < t->n_row ? in->row0 : t->n_row;
	rows = t->n_row - row0 < in->rows ? t->n_row - row0 : in->rows;
	if (rows > max_line - nl)
		rows = max_line - nl;
	g->row0 = row0;
	g->shown = rows;
	for (i = 0; i < rows; i++) {
		const char *cell[KV_TAB_COLS] = { NULL };

		t->cell(t->user, row0 + i, cell);
		emit_line(line[nl++], t, &L, hoff, in->margin, cell, t->rowattr ? t->rowattr(t->user, row0 + i) : NULL,
			  NULL);
		if (rec)
			rec_row(rec, rec->n_col, cell);
	}
	g->n_line = nl;
	return nl;
}

void kv_tab_measure(struct kv_tab_spec *t)
{
	uint32_t i, k, n = t->n_col < KV_TAB_COLS ? t->n_col : KV_TAB_COLS;
	uint8_t open[KV_TAB_COLS];

	for (k = 0; k < n; k++)
		open[k] = t->width[k] == 0;
	for (i = 0; i < t->n_row; i++) {
		const char *cell[KV_TAB_COLS] = { NULL };

		t->cell(t->user, i, cell);
		for (k = 0; k < n; k++) {
			size_t l = cell[k] ? strlen(cell[k]) : 0u;

			if (open[k] && l > t->width[k])
				t->width[k] = (uint16_t)(l > 0xffffu ? 0xffffu : l);
		}
	}
}

int kv_tab_hit(const struct kv_tab_geo *g, int line, int col, uint32_t *row, int *k)
{
	uint32_t j;

	*k = -1;
	*row = 0;
	if (line < 0 || (uint32_t)line >= g->n_line || col < 0 || col >= g->width)
		return 0;
	for (j = 0; j < g->n_col; j++)
		if (g->cw[j] > 0 && col >= g->cx[j] && col < g->cx[j] + g->cw[j])
			*k = (int)j;
	if (g->has_head && line == 0)
		return 1;
	*row = (uint32_t)line - (g->has_head ? 1u : 0u);
	return 2;
}
