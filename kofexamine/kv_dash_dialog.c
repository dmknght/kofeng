#define _GNU_SOURCE

/*
 * kv_dash_dialog.c - the dashboard dialog's frame. See kv_dash_dialog.h for the contract.
 */

#include <stdio.h>
#include <string.h>

#include "kofview.h"
#include "kv_table.h"
#include "kv_dash_dialog.h"

static const char kv_dd_close[] = "[ Close ]";
#define KV_DD_CLOSE_W ((int)sizeof kv_dd_close - 1)

/* The action message is shown only when at least this many columns are left for it. */
#define KV_DD_ACT_MIN 12

/* Columns the close button takes in the top rule: a space, the label. */
#define KV_DD_CLOSE_COLS (1 + KV_DD_CLOSE_W)

/* Columns the strip (or the title) takes in the top rule after the corner and its first rule. */
static int strip_used(const struct kv_dd_in *in, int n)
{
	int i, used = 0;

	if (in->n_tab <= 0)
		return (int)strlen(in->title ? in->title : "") + 2;
	for (i = 0; i < n; i++)
		used += (i ? 1 : 0) + (int)strlen(in->tab[i]) + 2;
	return used;
}

/* How many labels fit between the corner and the close button. */
static int strip_fit(const struct kv_dd_in *in, int w)
{
	int n = in->n_tab < KV_DD_TABS ? in->n_tab : KV_DD_TABS, k;

	for (k = n; k > 0; k--)
		if (strip_used(in, k) <= w - 4 - KV_DD_CLOSE_COLS - 1)
			return k;
	return 0;
}

static void layout_strip(const struct kv_dd_in *in, struct kv_dd_geo *g)
{
	int i, used = 0;

	g->n_tab = strip_fit(in, g->w);
	g->tab_y = g->top;
	for (i = 0; i < g->n_tab; i++) {
		int len = (int)strlen(in->tab[i]);

		used += i ? 1 : 0;
		g->tab_x0[i] = g->left + 2 + used;
		g->tab_x1[i] = g->tab_x0[i] + len + 1;
		used += len + 2;
	}
	g->close_y = g->top;
	g->close_x0 = g->left + g->w - 2 - KV_DD_CLOSE_W;
	g->close_x1 = g->close_x0 + KV_DD_CLOSE_W - 1;
}

/* Columns " text " takes on the bottom rule. */
static int count_cols(const struct kv_dd_in *in)
{
	return in->count ? (int)strlen(in->count) + 2 : 0;
}

static void layout_bottom(const struct kv_dd_in *in, struct kv_dd_geo *g)
{
	int room = g->w - 3;                    /* the corners and the first rule */
	int cl = count_cols(in);
	int lcols = in->count_left && cl <= room ? cl : 0;
	int rcols = !in->count_left && cl <= room ? cl : 0;

	g->count_y = g->top + g->h - 1;
	g->count_x = -1;
	if (lcols)
		g->count_x = g->left + 3;
	if (rcols)
		g->count_x = g->left + g->w - 2 - ((int)strlen(in->count));
	g->act_x = -1;
	if (in->act && in->act[0] && room - lcols - rcols - 2 > KV_DD_ACT_MIN)
		g->act_x = g->left + 2 + lcols + 1;
}

void kv_dd_fill(const struct kv_dd_in *in, struct kv_dd_geo *g)
{
	g->ok = g->w >= KV_DD_MIN_W && g->h >= KV_DD_MIN_H;
	g->close_y = g->count_y = -1;
	g->count_x = g->act_x = g->bar_x = -1;
	g->n_tab = 0;
	g->bar_rows = 0;
	if (!g->ok)
		return;
	g->body_y0 = g->top + 1;
	g->body_x0 = g->left + 2;
	g->body_rows = g->h - 2;
	g->body_cols = g->w - 4;
	layout_strip(in, g);
	layout_bottom(in, g);
	g->bar_x = g->left + g->w - 1;
	g->bar_y0 = g->body_y0 + (int)(in->fixed < (uint32_t)g->body_rows ? in->fixed : (uint32_t)g->body_rows);
	g->bar_rows = g->body_y0 + g->body_rows - g->bar_y0;
}

void kv_dd_place(const struct kv_dd_in *in, struct kv_dd_geo *g)
{
	int l0 = g->left, t0 = g->top;

	g->left += in->dx;
	g->top += in->dy;
	if (g->left + g->w - 1 > in->cols)
		g->left = in->cols - g->w + 1;
	if (g->left < 1)
		g->left = 1;
	if (g->top + g->h - 1 > in->rows)
		g->top = in->rows - g->h + 1;
	if (g->top < 2)
		g->top = 2;
	g->dx = g->left - l0;
	g->dy = g->top - t0;
}

void kv_dd_layout(const struct kv_dd_in *in, struct kv_dd_geo *g)
{
	memset(g, 0, sizeof *g);
	g->top = 2;
	g->w = in->cols - 4;
	g->h = in->rows - 3;
	if (in->want_w > 0 && in->want_w < g->w)
		g->w = in->want_w;
	if (in->want_h > 0 && in->want_h < g->h)
		g->h = in->want_h;
	g->left = (in->cols - g->w) / 2;
	/* A box sized to its content is centred between the bar and the bottom row; the dashboard fills the screen and stays at 2. */
	if (in->want_h > 0 && g->h < in->rows - 3)
		g->top = 2 + (in->rows - 3 - g->h) / 2;
	kv_dd_place(in, g);
	kv_dd_fill(in, g);
}

static size_t put_h(char *out, size_t n, size_t cap, int count)
{
	while (count-- > 0 && n + sizeof G_H < cap)
		n += (size_t)snprintf(out + n, cap - n, "%s", G_H);
	return n;
}

size_t kv_dd_top(const struct kv_dd_in *in, const struct kv_dd_geo *g, char *out, size_t cap)
{
	size_t n = 0;
	int i, fill;

	if (!g->ok || !cap)
		return 0;
	n += (size_t)snprintf(out + n, cap - n, A_DIM "%s%s", G_TL, G_H);
	if (in->n_tab <= 0)
		n += (size_t)snprintf(out + n, cap - n, A_OFF A_BOLD " %s " A_OFF A_DIM, in->title ? in->title : "");
	for (i = 0; i < g->n_tab; i++) {
		if (i)
			n = put_h(out, n, cap, 1);
		n += (size_t)snprintf(out + n, cap - n, A_OFF "%s %s " A_OFF A_DIM,
				      i == in->tab_sel ? A_SEL : A_DIM, in->tab[i]);
	}
	fill = g->w - 4 - strip_used(in, g->n_tab) - KV_DD_CLOSE_COLS;
	n = put_h(out, n, cap, fill);
	n += (size_t)snprintf(out + n, cap - n, " " A_OFF "\033[47;30m%s" A_OFF A_DIM "%s%s" A_OFF, kv_dd_close, G_H, G_TR);
	return n;
}

size_t kv_dd_bottom(const struct kv_dd_in *in, const struct kv_dd_geo *g, char *out, size_t cap)
{
	size_t n = 0;
	int used = 2, room, lcols, rcols;

	if (!g->ok || !cap)
		return 0;
	room = g->w - 3;
	lcols = g->count_x >= 0 && in->count_left ? count_cols(in) : 0;
	rcols = g->count_x >= 0 && !in->count_left ? count_cols(in) : 0;
	n += (size_t)snprintf(out + n, cap - n, A_DIM "%s%s", G_BL, G_H);
	if (lcols) {
		n += (size_t)snprintf(out + n, cap - n, " %s ", in->count);
		used += lcols;
	}
	if (g->act_x >= 0) {
		int len = (int)strlen(in->act), fit = room - lcols - rcols - 2;

		len = len > fit ? fit : len;
		n += (size_t)snprintf(out + n, cap - n, " " A_OFF "%s%.*s" A_OFF A_DIM " ", in->act_ok ? A_SIZE : A_WARN,
				      len, in->act);
		used += len + 2;
	}
	n = put_h(out, n, cap, room + 2 - used - rcols);
	if (rcols)
		n += (size_t)snprintf(out + n, cap - n, " %s ", in->count);
	n += (size_t)snprintf(out + n, cap - n, "%s" A_OFF, G_BR);
	return n;
}

void kv_dd_walls(const struct kv_dd_in *in, const struct kv_dd_geo *g, int row, char *left, char *right, size_t cap)
{
	const char *bar = NULL;
	int i = row - (g->bar_y0 - g->body_y0);

	snprintf(left, cap, A_DIM "%s" A_OFF " ", G_V);
	if (g->bar_rows > 0 && i >= 0)
		bar = kv_bar_at(g->bar_rows, i, in->off, in->total, in->shown, 0);
	snprintf(right, cap, " " A_DIM "%s" A_OFF, bar ? bar : G_V);
}

uint32_t kv_dd_bar_offset(const struct kv_dd_in *in, const struct kv_dd_geo *g, int y)
{
	int pos = y - g->bar_y0;
	uint32_t mx = in->total > in->shown ? in->total - in->shown : 0u;

	if (g->bar_rows <= 1 || !mx)
		return 0;
	pos = pos < 0 ? 0 : pos >= g->bar_rows ? g->bar_rows - 1 : pos;
	return (uint32_t)(((uint64_t)pos * mx) / (uint64_t)(g->bar_rows - 1));
}

int kv_dd_tab_at(const struct kv_dd_geo *g, int y, int x)
{
	int i;

	if (!g->ok || y != g->tab_y)
		return -1;
	for (i = 0; i < g->n_tab; i++)
		if (x >= g->tab_x0[i] && x <= g->tab_x1[i])
			return i;
	return -1;
}

int kv_dd_grab_at(const struct kv_dd_geo *g, int y, int x)
{
	return g->ok && y == g->top && x >= g->left && x < g->left + g->w && kv_dd_tab_at(g, y, x) < 0 &&
	       !kv_dd_close_at(g, y, x);
}

int kv_dd_close_at(const struct kv_dd_geo *g, int y, int x)
{
	return g->ok && g->close_y >= 0 && y == g->close_y && x >= g->close_x0 && x <= g->close_x1;
}
