/*
 * kx_dashapi - the dashboard's two rendering APIs as PURE functions, with no viewer and no screen:
 *
 *   TABLE   kv_table.c: for every width of the box from 1 to 200, every height 0..5, every first row (past the end included), every
 *           sideways offset to past the maximum, every sticky count and with/without a flexible column, the lines equal a model written
 *           here (margin, the sticky columns whole, a window of the rest); the geometry returned names exactly the columns drawn; a
 *           colour per column and a row override are present; offsets clamp; kv_tab_hit agrees with the geometry for every point of
 *           the box; the recorded text is the FULL text of a cell (a clipped cell, an empty cell, a NULL cell, a control byte) and a
 *           row's line.
 *   DIALOG  kv_dash_dialog.c: for every screen of 1..200 columns by 1..60 rows the box, strip, close button, body, scrollbar and count
 *           satisfy the geometry rules, and the strings drawn are exactly as wide as the box; a strip wider than the box loses whole
 *           labels; the count is at the right end of the bottom rule or absent whole; the scrollbar offset is monotone and clamped;
 *           the point queries agree with the rectangles.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/genome/hk.h"
#include "../../kofexamine/kofview.h"
#include "../../kofexamine/kv_table.h"
#include "../../kofexamine/kv_dash_dialog.h"

#include "../../kofexamine/kv_table.c"
#include "../../kofexamine/kv_dash_dialog.c"

/* ---- helpers --------------------------------------------------------------------------------------------- */

/* The line as the terminal shows it: escape sequences gone; multi-byte glyphs counted as one column in `cols`. */
static void plain(const char *s, char *out, size_t cap, int *cols)
{
	size_t n = 0;
	int c = 0;

	while (*s) {
		if (*s == '\033') {
			while (*s && *s != 'm')
				s++;
			if (*s)
				s++;
			continue;
		}
		if (((unsigned char)*s & 0xc0u) != 0x80u)
			c++;
		if (n + 1 < cap)
			out[n++] = *s;
		s++;
	}
	out[n] = 0;
	if (cols)
		*cols = c;
}

/* ================================================================================ TABLE */

struct td {
	uint32_t n_col, n_row;
	const char *cell[6][4];
};

static void tcell(void *user, uint32_t row, const char **out)
{
	const struct td *d = user;
	uint32_t k;

	for (k = 0; k < d->n_col; k++)
		out[k] = d->cell[row][k];
}

static const char *trow(void *user, uint32_t row)
{
	(void)user;
	return row == 2 ? "\033[41m" : NULL;
}

/* The model: the padded unit (cell, then the gap) of a column, aligned. */
static void unit_model(const char *c, uint32_t w, int right, char *out)
{
	uint32_t len = c ? (uint32_t)strnlen(c, w) : 0, pad = right && len < w ? w - len : 0, j;

	for (j = 0; j < w; j++)
		out[j] = j < pad || j - pad >= len ? ' ' : (c[j - pad] < 0x20 ? '?' : c[j - pad]);
	out[w] = ' ';
	out[w + 1] = 0;
}

/* The line the model says a row shows in a box `width` wide with this margin. */
static void model_line(const struct kv_tab_spec *t, const char *const *cell, int heading, int width, int margin, uint32_t hoff,
		       char *out, uint32_t *hmax_out)
{
	char virt[1024] = "", u[512];
	uint32_t k, n = t->n_col, w[4], room = width > margin ? (uint32_t)(width - margin) : 0u, nat = 0, st = 0, sv, rp, hmax;
	int i;

	for (k = 0; k < n; k++) {
		uint32_t hl = (uint32_t)strlen(t->col[k]);

		w[k] = t->width[k] > hl ? t->width[k] : hl;
		nat += w[k] + 1u;
	}
	if (t->flex >= 0 && nat < room) {
		w[t->flex] += room - nat;
		nat = room;
	}
	for (k = 0; k < n; k++) {
		unit_model(heading ? t->col[k] : cell[k], w[k], t->right[k], u);
		strcat(virt, u);
		if (k < t->n_sticky)
			st += w[k] + 1u;
	}
	sv = st < room ? st : room;
	rp = room - sv;
	hmax = rp && nat - st > rp ? nat - st - rp : 0u;
	if (hoff > hmax)
		hoff = hmax;
	*hmax_out = hmax;
	for (i = 0; i < margin; i++)
		out[i] = ' ';
	out[margin] = 0;
	memcpy(out + margin, virt, sv);
	out[(uint32_t)margin + sv] = 0;
	for (k = 0; k < rp && st + hoff + k < nat; k++) {
		char ch[2] = { virt[st + hoff + k], 0 };

		strcat(out, ch);
	}
}

static void table_suite(void)
{
	static struct td d;
	static char line[8][KV_TAB_LINE];
	static const char *const cols[4] = { "id", "name", "val", "x" };
	static const char *const attr[4] = { "\033[34m", "\033[35m", "\033[36m", "\033[32m" };
	uint32_t wset[3][4] = { { 2, 4, 3, 1 }, { 3, 9, 5, 2 }, { 0, 0, 0, 0 } };
	int width, margin, flex, ws;
	uint32_t sticky, hoff, row0, rows;

	d.n_col = 4;
	d.n_row = 5;
	d.cell[0][0] = "0"; d.cell[0][1] = "alpha"; d.cell[0][2] = "10"; d.cell[0][3] = "a";
	d.cell[1][0] = "1"; d.cell[1][1] = "b";     d.cell[1][2] = "2000000"; d.cell[1][3] = "";
	d.cell[2][0] = "22"; d.cell[2][1] = NULL;   d.cell[2][2] = "7"; d.cell[2][3] = "zz";
	d.cell[3][0] = "3"; d.cell[3][1] = "ctl\x01x"; d.cell[3][2] = "8"; d.cell[3][3] = "c";
	d.cell[4][0] = "4"; d.cell[4][1] = "last-row-name"; d.cell[4][2] = ""; d.cell[4][3] = "d";
	for (ws = 0; ws < 3; ws++)
		for (flex = -1; flex <= 1; flex += 2)
			for (sticky = 0; sticky <= 4; sticky += sticky == 2 ? 2 : 1)
				for (margin = 0; margin <= 2; margin += 2)
					for (width = 1; width <= 200; width += (width < 40 ? 1 : 13)) {
						struct kv_tab_spec t;
						uint32_t k;

						memset(&t, 0, sizeof t);
						for (k = 0; k < 4; k++) {
							t.col[k] = cols[k];
							t.width[k] = (uint16_t)wset[ws][k];
							t.colattr[k] = attr[k];
							t.right[k] = k == 2;
						}
						t.n_col = 4;
						t.n_row = d.n_row;
						t.n_sticky = sticky;
						t.flex = flex < 0 ? -1 : 1;
						t.head_attr = "\033[90m";
						t.cell = tcell;
						t.rowattr = trow;
						t.user = &d;
						if (ws == 2)
							kv_tab_measure(&t);
						for (hoff = 0; hoff < 400; hoff += hoff < 7 ? 1 : 100)
							for (row0 = 0; row0 <= 7; row0 += row0 < 1 ? 1 : 4)
								for (rows = 0; rows <= 5; rows += 2) {
									struct kv_tab_in in = { row0, rows, hoff, width, margin, 1 };
									struct kv_tab_geo g;
									struct kv_tab_rec rec = { 0 };
									char want[1024], got[1024];
									uint32_t n, i, exp_rows, r0, hmax = 0;

									n = kv_tab_render(&t, &in, line, 8, &g, &rec);
									r0 = row0 < d.n_row ? row0 : d.n_row;
									exp_rows = d.n_row - r0 < rows ? d.n_row - r0 : rows;
									CK(g.row0 == r0 && g.shown == exp_rows && n == 1u + exp_rows && g.n_line == n);
									CK(g.has_head == 1 && g.width == width);
									model_line(&t, NULL, 1, width, margin, hoff, want, &hmax);
									plain(line[0], got, sizeof got, NULL);
									CK(strcmp(got, want) == 0);
									CK(g.hmax == hmax && g.hoff == (hoff < hmax ? hoff : hmax));
									for (i = 0; i < exp_rows; i++) {
										const char *cell[4];
										uint32_t k2;

										tcell(&d, r0 + i, cell);
										model_line(&t, cell, 0, width, margin, hoff, want, &hmax);
										plain(line[1 + i], got, sizeof got, NULL);
										CK(strcmp(got, want) == 0);
										/* a colour per column, the row's own over it */
										for (k2 = 0; k2 < 4; k2++)
											if (g.cw[k2] > 0)
												CK(strstr(line[1 + i], r0 + i == 2 ? "\033[41m" : attr[k2]) != NULL);
										/* the geometry names exactly the drawn cells */
										for (k2 = 0; k2 < 4; k2++) {
											char unit[512];
											uint32_t w2 = t.width[k2] > strlen(cols[k2]) ? t.width[k2] : (uint32_t)strlen(cols[k2]);

											if (g.cw[k2] <= 0)
												continue;
											if (flex >= 0 && (int)k2 == 1) {
												uint32_t room = width > margin ? (uint32_t)(width - margin) : 0u, nat = 0, q;

												for (q = 0; q < 4; q++)
													nat += (t.width[q] > strlen(cols[q]) ? t.width[q] : (uint32_t)strlen(cols[q])) + 1u;
												if (nat < room)
													w2 += room - nat;
											}
											unit_model(cell[k2], w2, t.right[k2], unit);
											CK(g.cx[k2] >= margin && g.cx[k2] + g.cw[k2] <= width);
											CK(strncmp(got + g.cx[k2], unit + g.cfrom[k2], (size_t)g.cw[k2]) == 0);
										}
									}
									/* the box of one row holds the heading and nothing else */
									n = kv_tab_render(&t, &in, line, 1, &g, NULL);
									CK(n == 1u && g.shown == 0);
									kv_tab_rec_free(&rec);
								}
					}
}

/* kv_tab_hit agrees with the geometry for every point of the box, and the recorded text is the whole cell. */
static void hit_and_text(void)
{
	static struct td d;
	static char line[8][KV_TAB_LINE];
	struct kv_tab_spec t;
	struct kv_tab_rec rec = { 0 };
	struct kv_tab_geo g;
	char buf[256];
	uint32_t k, row, n;
	int x, y, cc, kk, kind;

	memset(&t, 0, sizeof t);
	d.n_col = 3;
	d.n_row = 3;
	d.cell[0][0] = "12"; d.cell[0][1] = "a-very-long-name-that-is-cut"; d.cell[0][2] = "x";
	d.cell[1][0] = "";   d.cell[1][1] = NULL;                          d.cell[1][2] = "y\x1bz";
	d.cell[2][0] = "7";  d.cell[2][1] = "short";                       d.cell[2][2] = "";
	for (k = 0; k < 3; k++) {
		static const char *const c[3] = { "n", "name", "q" };

		t.col[k] = c[k];
		t.width[k] = k == 1 ? 8u : 2u;                /* narrower than the long cell: the drawn part is cut */
	}
	t.n_col = 3;
	t.n_row = 3;
	t.n_sticky = 1;
	t.flex = -1;
	t.cell = tcell;
	t.user = &d;
	for (x = 5; x <= 40; x += 5) {
		struct kv_tab_in in = { 0, 3, 0, x, 2, 1 };

		n = kv_tab_render(&t, &in, line, 8, &g, &rec);
		for (y = -1; y <= (int)n; y++)
			for (cc = -1; cc <= x + 1; cc++) {
				int want_k = -2;

				kind = kv_tab_hit(&g, y, cc, &row, &want_k);
				if (y < 0 || y >= (int)n || cc < 0 || cc >= x) {
					CK(kind == 0);
					continue;
				}
				CK(kind == (y == 0 ? 1 : 2) && (y == 0 || row == (uint32_t)(y - 1)));
				for (k = 0, kk = -1; k < g.n_col; k++)
					if (g.cw[k] > 0 && cc >= g.cx[k] && cc < g.cx[k] + g.cw[k])
						kk = (int)k;
				CK(want_k == kk);
			}
	}
	{
		struct kv_tab_in in = { 0, 3, 0, 30, 2, 1 };

		kv_tab_render(&t, &in, line, 8, &g, &rec);
		/* the FULL text of a clipped cell, an empty one, a NULL one, one with a control byte */
		CK(strcmp(kv_tab_rec_cell(&rec, &g, 0, 1), "a-very-long-name-that-is-cut") == 0);
		CK(g.cw[1] < 28);                                    /* what was drawn of it is shorter than what a copy takes */
		CK(strcmp(kv_tab_rec_cell(&rec, &g, 1, 0), "") == 0 && strcmp(kv_tab_rec_cell(&rec, &g, 1, 1), "") == 0);
		CK(strcmp(kv_tab_rec_cell(&rec, &g, 1, 2), "y?z") == 0);
		CK(kv_tab_rec_cell(&rec, &g, 3, 0) == NULL && kv_tab_rec_cell(&rec, &g, 0, 3) == NULL);
		/* a whole line: the cells joined by two spaces, trailing blanks dropped */
		CK(kv_tab_rec_line(&rec, &g, 0, buf, sizeof buf) == strlen("12  a-very-long-name-that-is-cut  x") &&
		   strcmp(buf, "12  a-very-long-name-that-is-cut  x") == 0);
		CK(strcmp((kv_tab_rec_line(&rec, &g, 2, buf, sizeof buf), buf), "7  short") == 0);
		CK(strcmp((kv_tab_rec_line(&rec, &g, 1, buf, sizeof buf), buf), "    y?z") == 0);
		CK(kv_tab_rec_line(&rec, &g, 9, buf, sizeof buf) == 0);
		/* the sideways offset moves the drawn part and not the recorded text */
		{
			struct kv_tab_in in2 = { 0, 3, 7, 14, 2, 1 };

			kv_tab_render(&t, &in2, line, 8, &g, &rec);
			CK(strcmp(kv_tab_rec_cell(&rec, &g, 0, 1), "a-very-long-name-that-is-cut") == 0);
		}
	}
	kv_tab_rec_free(&rec);
	/* the one clamp */
	for (k = 0; k < 12; k++)
		for (row = 0; row < 12; row++) {
			uint32_t mx = k > 3 ? k - 3 : 0u;

			CK(kv_tab_clamp(row, k, 3) == (row > mx ? mx : row));
		}
}

/* ================================================================================ DIALOG */

static void dialog_one(int cols, int rows, int n_tab, const char *count, const char *act, int left_mode, uint32_t total, uint32_t off,
		       uint32_t shown)
{
	static const char *const names[KV_DD_TABS] = { "Overview", "Segments", "Sections", "Imports", "Exports" };
	struct kv_dd_in in;
	struct kv_dd_geo g;
	char top[2048], bot[2048], pl[2048], l[128], r[128];
	int c, i, y, x;

	memset(&in, 0, sizeof in);
	in.cols = cols;
	in.rows = rows;
	in.title = "Properties";
	in.n_tab = n_tab;
	in.tab_sel = n_tab ? 1 : 0;
	for (i = 0; i < n_tab; i++)
		in.tab[i] = names[i];
	in.count = count;
	in.count_left = left_mode;
	in.act = act;
	in.act_ok = 1;
	in.fixed = 2;
	in.total = total;
	in.off = off;
	in.shown = shown;
	kv_dd_layout(&in, &g);
	CK(g.ok == (cols - 4 >= KV_DD_MIN_W && rows - 3 >= KV_DD_MIN_H));
	if (!g.ok) {
		CK(kv_dd_top(&in, &g, top, sizeof top) == 0 && kv_dd_bottom(&in, &g, bot, sizeof bot) == 0);
		CK(kv_dd_tab_at(&g, 2, 5) == -1 && !kv_dd_close_at(&g, 2, 5));
		return;
	}
	CK(g.top == 2 && g.left == 2 && g.w == cols - 4 && g.h == rows - 3);
	CK(g.body_x0 == g.left + 2 && g.body_cols == g.w - 4 && g.body_y0 == g.top + 1 && g.body_rows == g.h - 2);
	/* the strings are as wide as the box */
	kv_dd_top(&in, &g, top, sizeof top);
	plain(top, pl, sizeof pl, &c);
	CK(c == g.w);
	kv_dd_bottom(&in, &g, bot, sizeof bot);
	plain(bot, pl, sizeof pl, &c);
	CK(c == g.w);
	for (y = 0; y < g.body_rows; y++) {
		kv_dd_walls(&in, &g, y, l, r, sizeof l);
		plain(l, pl, sizeof pl, &c);
		CK(c == 2);
		plain(r, pl, sizeof pl, &c);
		CK(c == 2);
	}
	/* the strip: whole labels, in order, inside the top rule and left of the close button */
	plain(top, pl, sizeof pl, NULL);
	CK(g.n_tab <= n_tab);
	for (i = 0; i < n_tab; i++) {
		int drawn = strstr(pl, names[i]) != NULL;

		CK(drawn == (i < g.n_tab));
	}
	for (i = 0; i < g.n_tab; i++) {
		CK(g.tab_x1[i] - g.tab_x0[i] + 1 == (int)strlen(names[i]) + 2);
		CK(g.tab_x0[i] > g.left && g.tab_x1[i] < g.close_x0);
		if (i)
			CK(g.tab_x0[i] > g.tab_x1[i - 1]);
		CK(kv_dd_tab_at(&g, g.tab_y, g.tab_x0[i]) == i && kv_dd_tab_at(&g, g.tab_y, g.tab_x1[i]) == i);
		CK(kv_dd_tab_at(&g, g.tab_y + 1, g.tab_x0[i]) == -1);
	}
	CK(g.close_x1 < g.left + g.w - 1 && g.close_x0 > g.left && kv_dd_close_at(&g, g.close_y, g.close_x0) &&
	   kv_dd_close_at(&g, g.close_y, g.close_x1) && !kv_dd_close_at(&g, g.close_y, g.close_x1 + 1));
	/* the count: whole at the right end of the bottom rule (before the corner), or absent whole */
	plain(bot, pl, sizeof pl, NULL);
	if (count) {
		size_t cl = strlen(count);

		if (g.count_x >= 0) {
			CK(strstr(pl, count) != NULL);
			if (!left_mode) {
				size_t L = strlen(pl);

				/* " text " then the corner glyph (3 bytes) */
				CK(L > cl + 6u && pl[L - 4u] == ' ' && strncmp(pl + L - 4u - cl, count, cl) == 0 && pl[L - 5u - cl] == ' ');
				CK(g.count_x + (int)cl == g.left + g.w - 2);
			}
		} else {
			CK(strstr(pl, count) == NULL);
			CK(g.w - 3 < (int)cl + 2);
		}
	} else {
		CK(g.count_x == -1);
	}
	/* the scrollbar: in the right wall, below the fixed rows, only when something scrolls */
	CK(g.bar_x == g.left + g.w - 1 && g.bar_y0 == g.body_y0 + (g.body_rows < 2 ? g.body_rows : 2));
	if (total > shown) {
		int thumbs = 0;

		for (y = 0; y < g.body_rows; y++) {
			kv_dd_walls(&in, &g, y, l, r, sizeof l);
			if (strstr(r, G_V) == NULL)
				thumbs++;
			if (y < 2)
				CK(strstr(r, G_V) != NULL);        /* the fixed rows have no bar */
		}
		CK(thumbs >= 1);
		CK(kv_dd_bar_offset(&in, &g, g.bar_y0) == 0);
		CK(kv_dd_bar_offset(&in, &g, g.bar_y0 - 5) == 0);
		if (g.bar_rows > 1) {
			uint32_t prev = 0, o;

			CK(kv_dd_bar_offset(&in, &g, g.bar_y0 + g.bar_rows - 1) == total - shown);
			CK(kv_dd_bar_offset(&in, &g, g.bar_y0 + g.bar_rows + 50) == total - shown);
			for (y = g.bar_y0; y < g.bar_y0 + g.bar_rows; y++) {
				o = kv_dd_bar_offset(&in, &g, y);
				CK(o >= prev && o <= total - shown);
				prev = o;
			}
		}
	}
	for (x = 0; x < cols; x += 3)
		for (y = 0; y < rows; y += 5)
			CK((kv_dd_tab_at(&g, y, x) >= 0) == (y == g.tab_y && kv_dd_tab_at(&g, y, x) >= 0));
}

static void dialog_suite(void)
{
	int cols, rows;
	static const char *const counts[3] = { NULL, "1-20 of 20 lines", "5-8 of 3000000 items" };
	int ci;

	for (cols = 1; cols <= 200; cols++)
		for (rows = 1; rows <= 60; rows += (rows < 12 ? 1 : 9))
			for (ci = 0; ci < 3; ci++) {
				dialog_one(cols, rows, 5, counts[ci], NULL, 0, 0, 0, 0);
				dialog_one(cols, rows, 5, counts[ci], "Copied 1 line(s)", 0, 100, 3, rows > 4 ? (uint32_t)rows - 4u : 1u);
				dialog_one(cols, rows, 0, counts[ci], NULL, 1, 7, 0, 7);
				dialog_one(cols, rows, 2, counts[ci], "x", 0, 1, 0, 1);
			}
	/* an empty page: nothing scrolls, nothing is hostile about it */
	dialog_one(120, 40, 5, "0 of 0 items", NULL, 0, 0, 0, 0);
	/* a count wider than any box is dropped whole */
	{
		char big[300];

		memset(big, '7', sizeof big - 1);
		big[sizeof big - 1] = 0;
		dialog_one(120, 40, 5, big, NULL, 0, 0, 0, 0);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	table_suite();
	hit_and_text();
	dialog_suite();
	printf("kx_dashapi: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
