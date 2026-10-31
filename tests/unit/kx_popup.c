/*
 * kx_popup - the pop-up list of the viewer (kofexamine/kv_popup.h, defined in kofview.c) on DATA: the box that kv_popup_place returns, the
 * text of every row, the hit test and the key step, with no terminal. What this pins is what the viewer got wrong on the screen: a pick-list
 * whose rows were one column narrower than its box and whose rule was one column wider (a ragged right edge), a submenu opened two rows under
 * its parent and one column off it, a submenu of the menu bar cut off at the right edge of a small terminal, a list that ran past the
 * bottom of a short one.
 *
 *   WIDTH      every row's text is exactly the box's width (the rule and the scroll rows included), for labels of 0..70 characters, with
 *              and without a tick, a submenu mark, a grey row; the width is the longest row's need (then the least, the cap, the screen);
 *              the tick column starts every ticked row; a label of several bytes a character is cut between characters
 *   PLACE      for every anchor on screens 12x60 .. 40x120 and lists of 1..40 rows: the box lies inside columns 1..cols and rows
 *              top..bottom; under a control it opens below when it fits, above when that fits, and never covers the control's row except when
 *              it fits nowhere (COVER); placing a placed box changes nothing
 *   SUBMENU    beside its parent with no gap and no overlap, its top on the parent's row (moved up only as far as the bottom needs),
 *              on the left when the right has no room
 *   HIT        every cell of the box answers with the row whose text is drawn there, a rule and a blank grid cell with -1, anything else -2
 *   STEP       skips rules and grey rows, stops at the ends, enters from nothing at either end, steps from an item that is gone
 *   SCROLL     a list taller than the room is as tall as the room, drawn from `off`, with a "..." row at each cut end; follow brings an item in
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../kofexamine/kofview.h"

static int fails, checks;

#define CK(c) do { checks++; if (!(c)) { if (fails < 25) printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static int cols_of(const char *s)
{
	int n = 0;

	for (; *s; s++)
		n += ((unsigned char)*s & 0xc0u) != 0x80u;
	return n;
}

static void req(struct kv_popup_req *q, int rows, int cols, int ay, int ax, int anchor_h)
{
	memset(q, 0, sizeof *q);
	q->rows = rows;
	q->cols = cols;
	q->top = 2;
	q->bottom = rows - 1;
	q->ay = ay;
	q->ax = ax;
	q->anchor_h = anchor_h;
}

static void fill(struct kv_popup *p, int n, int label_len, unsigned flags_mask)
{
	int i;
	char t[KV_POP_TEXT];

	kv_popup_init(p, 1);
	for (i = 0; i < n; i++) {
		unsigned fl = 0;
		int l = label_len < 0 ? (i * 7) % 20 + 1 : label_len;

		if (flags_mask & 1u && i % 5 == 4)
			kv_popup_add(p, "", KV_PR_RULE, -1);
		if (flags_mask & 2u && i % 3 == 0)
			fl |= KV_PR_SUB;
		if (flags_mask & 4u)
			fl |= KV_PR_TICK | (i % 2 ? KV_PR_ON : 0u);
		if (flags_mask & 8u && i % 4 == 1)
			fl |= KV_PR_OFF;
		memset(t, 'a' + i % 26, (size_t)l);
		t[l] = 0;
		kv_popup_add(p, t, fl, i);
	}
}

static void width_suite(void)
{
	static struct kv_popup p;
	int len, mask, cols, r;
	char t[KV_POP_TEXT * 4];

	for (len = 0; len <= 70; len++)
		for (mask = 0; mask < 16; mask++)
			for (cols = 60; cols <= 200; cols += 70) {
				struct kv_popup_req q;
				int longest = 0, i;

				fill(&p, 6, len, (unsigned)mask);
				req(&q, 40, cols, 10, 20, 1);
				q.min_w = 12;
				q.max_w = 64;
				kv_popup_place(&p, &q);
				for (r = 0; r < p.n; r++) {
					int n = kv_popup_text(&p, r, 0, t, sizeof t);

					CK(n == p.box.w && cols_of(t) == p.box.w);
				}
				for (i = 0; i < p.n; i++) {
					int need;

					if (p.row[i].flags & KV_PR_RULE)
						continue;
					need = 1 + ((p.row[i].flags & KV_PR_TICK) ? 4 : 0) + cols_of(p.row[i].text) + 1 + ((p.row[i].flags & KV_PR_SUB) ? 1 : 0);
					if (need > longest)
						longest = need;
				}
				if (longest < 12)
					longest = 12;
				if (longest > 64)
					longest = 64;
				if (longest > cols - 2)
					longest = cols - 2;
				CK(p.box.w == longest);
				CK(p.box.w <= cols - 2);
				/* a ticked row starts with the tick and a row that opens a list ends with the mark */
				for (r = 0; r < p.n; r++) {
					kv_popup_text(&p, r, 0, t, sizeof t);
					if (p.row[r].flags & KV_PR_TICK)
						CK(!strncmp(t, (p.row[r].flags & KV_PR_ON) ? " [x] " : " [ ] ", 5));
					if ((p.row[r].flags & KV_PR_SUB) && cols_of(p.row[r].text) <= p.box.w - 3 - ((p.row[r].flags & KV_PR_TICK) ? 4 : 0))
						CK(t[strlen(t) - 1] == '>');
				}
			}
	/* a rule is as wide as the rows; the old chooser drew it one column wider */
	fill(&p, 4, 8, 1u);
	{
		struct kv_popup_req q;

		req(&q, 30, 100, 5, 5, 1);
		kv_popup_place(&p, &q);
		for (r = 0; r < p.n; r++)
			if (p.row[r].flags & KV_PR_RULE) {
				kv_popup_text(&p, r, 0, t, sizeof t);
				CK(cols_of(t) == p.box.w && t[0] == ' ' && t[1] == '-');
			}
	}
	/* several bytes a character: cut between characters, columns counted by character */
	kv_popup_init(&p, 1);
	kv_popup_add(&p, "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", 0, 0);
	{
		struct kv_popup_req q;

		req(&q, 30, 100, 5, 5, 1);
		q.max_w = 10;
		kv_popup_place(&p, &q);
		kv_popup_text(&p, 0, 0, t, sizeof t);
		CK(p.box.w == 10 && cols_of(t) == 10);
		CK(!strncmp(t, " \xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9 ", 18));
	}
}

static void place_suite(void)
{
	static struct kv_popup p, p2;
	static const int scr[][2] = { { 12, 60 }, { 24, 80 }, { 40, 120 } };
	int s, n, ay, ax, h;

	for (s = 0; s < 3; s++)
		for (n = 1; n <= 40; n += (n < 8 ? 1 : 9))
			for (h = 0; h <= 1; h++)
				for (ay = 1; ay <= scr[s][0]; ay++)
					for (ax = 1; ax <= scr[s][1]; ax += 7) {
						struct kv_popup_req q;
						const struct kv_popup_box *b;
						int area = scr[s][0] - 2;

						fill(&p, n, -1, 2u);
						req(&q, scr[s][0], scr[s][1], ay, ax, h);
						q.min_w = 12;
						kv_popup_place(&p, &q);
						b = &p.box;
						CK(b->x >= 1 && b->x + b->w - 1 <= scr[s][1]);
						CK(b->y >= 2 && b->y + b->h - 1 <= scr[s][0] - 1);
						CK(b->h == (p.n < area ? p.n : area));
						CK(b->off == 0 && b->n_rows == p.n);
						if (h) {
							int covers = ay >= b->y && ay < b->y + b->h;

							if (b->side == KV_SIDE_BELOW)
								CK(b->y == ay + 1);
							if (b->side == KV_SIDE_ABOVE)
								CK(b->y + b->h == ay);
							if (b->side != KV_SIDE_COVER && ay >= 2 && ay <= scr[s][0] - 1)
								CK(!covers);
							/* below when it fits below; above only when it did not */
							if (p.n <= scr[s][0] - 1 - ay)
								CK(b->side == KV_SIDE_BELOW);
							else if (p.n <= ay - 2)
								CK(b->side == KV_SIDE_ABOVE);
							else
								CK(b->side == KV_SIDE_COVER);
						} else if (ay >= 2 && ay + p.n - 1 <= scr[s][0] - 1) {
							CK(b->y == ay);
						}
						p2 = p;
						q.ay = b->y;
						q.ax = b->x;
						q.anchor_h = 0;
						kv_popup_place(&p2, &q);
						CK(!memcmp(&p2.box.x, &b->x, sizeof(int)) && p2.box.y == b->y && p2.box.w == b->w && p2.box.h == b->h);
					}
}

static void sub_suite(void)
{
	static struct kv_popup par, sub;
	static const int scr[][2] = { { 12, 60 }, { 24, 80 }, { 40, 120 } };
	int s, px, pr, n;

	for (s = 0; s < 3; s++)
		for (n = 1; n <= 12; n += 3)
			for (px = 1; px + 13 <= scr[s][1]; px += 5)
				for (pr = 2; pr <= scr[s][0] - 1; pr++) {
					struct kv_popup_req q;
					const struct kv_popup_box *pb, *sb;

					fill(&par, 5, 10, 2u);
					req(&q, scr[s][0], scr[s][1], 2, px, 0);
					q.min_w = 12;
					kv_popup_place(&par, &q);
					pb = &par.box;
					fill(&sub, n, 14, 0);
					req(&q, scr[s][0], scr[s][1], pr, pb->x + pb->w, 0);
					q.min_w = 12;
					q.parent = pb;
					q.parent_row = pr;
					kv_popup_place(&sub, &q);
					sb = &sub.box;
					CK(sb->x >= 1 && sb->x + sb->w - 1 <= scr[s][1]);
					CK(sb->y >= 2 && sb->y + sb->h - 1 <= scr[s][0] - 1);
					if (pb->x + pb->w + sb->w - 1 <= scr[s][1]) {
						CK(sb->side == KV_SIDE_RIGHT && sb->x == pb->x + pb->w);       /* no gap, no overlap */
					} else if (pb->x - sb->w >= 1) {
						CK(sb->side == KV_SIDE_LEFT && sb->x + sb->w == pb->x);
					}
					if (pr + sb->h - 1 <= scr[s][0] - 1)
						CK(sb->y == pr);                                                  /* its top is on the parent's row */
					else
						CK(sb->y + sb->h - 1 == scr[s][0] - 1);                           /* moved up only as far as the bottom needs */
				}
}

/* A submenu whose least width has no room on either side takes the width its rows need: the menu bar's Dump submenu on a 60-column terminal. */
static void sub_narrow(void)
{
	static struct kv_popup par, sub;
	struct kv_popup_req q;
	int px;

	for (px = 1; px <= 30; px++) {
		fill(&par, 6, 24, 0);
		req(&q, 24, 60, 4, px, 0);
		q.min_w = 30;
		kv_popup_place(&par, &q);
		fill(&sub, 2, 15, 0);
		req(&q, 24, 60, 6, par.box.x + par.box.w, 0);
		q.min_w = 30;
		q.parent = &par.box;
		q.parent_row = 6;
		kv_popup_place(&sub, &q);
		CK(sub.box.x + sub.box.w - 1 <= 60 && sub.box.x >= 1);
		if (par.box.x + par.box.w + 17 - 1 <= 60 || par.box.x - 17 >= 1)
			CK(sub.box.x >= par.box.x + par.box.w || sub.box.x + sub.box.w <= par.box.x);     /* never over its parent when the rows fit beside it */
	}
}

static void hit_suite(void)
{
	static struct kv_popup p;
	int mask, my, mx, r, c;
	char t[KV_POP_TEXT * 4];

	for (mask = 0; mask < 16; mask++) {
		struct kv_popup_req q;

		fill(&p, 9, -1, (unsigned)mask);
		req(&q, 24, 80, 6, 30, 0);
		q.min_w = 14;
		kv_popup_place(&p, &q);
		for (my = 0; my <= 25; my++)
			for (mx = 0; mx <= 81; mx++) {
				int h = kv_popup_hit(&p, my, mx);
				int in = my >= p.box.y && my < p.box.y + p.box.h && mx >= p.box.x && mx < p.box.x + p.box.w;

				CK((h == -2) == !in);
				if (in && h >= 0)
					CK(!(p.row[h].flags & KV_PR_RULE) && h == p.box.off + my - p.box.y);
				if (in && h < 0)
					CK(p.row[p.box.off + my - p.box.y].flags & KV_PR_RULE);
			}
		(void)t;
	}
	/* a grid of two columns, items down a column and then the next: the cell hit is the item whose text is drawn there */
	{
		struct kv_popup_req q;
		int i;

		kv_popup_init(&p, 2);
		for (i = 0; i < 7; i++) {
			char w[16];

			snprintf(w, sizeof w, "type%d", i);
			kv_popup_add(&p, w, KV_PR_TICK | (i == 2 ? KV_PR_ON : 0u), i);
		}
		req(&q, 24, 80, 5, 10, 0);
		q.min_w = 16;
		kv_popup_place(&p, &q);
		CK(p.box.n_rows == 4 && p.box.cell_w == 16 && p.box.w == 32);
		for (r = 0; r < 4; r++)
			for (c = 0; c < 2; c++) {
				int h = kv_popup_hit(&p, p.box.y + r, p.box.x + c * 16 + 3);
				int k = c * 4 + r;

				CK(h == (k < 7 ? k : -1));
				kv_popup_text(&p, r, c, t, sizeof t);
				CK(cols_of(t) == 16);
				if (k < 7) {
					CK(!strncmp(t, k == 2 ? " [x] type" : " [ ] type", 9));
					CK(t[9] == '0' + k);
				} else {
					CK(!strcmp(t, "                "));
				}
			}
	}
}

static void step_suite(void)
{
	static struct kv_popup p;
	int mask, cur, d;

	for (mask = 0; mask < 16; mask++) {
		int n = 9, first = -1, last = -1, i;

		fill(&p, n, -1, (unsigned)mask);
		for (i = 0; i < p.n; i++)
			if (!(p.row[i].flags & (KV_PR_RULE | KV_PR_OFF))) {
				if (first < 0)
					first = p.row[i].id;
				last = p.row[i].id;
			}
		CK(kv_popup_first(&p) == first);
		CK(kv_popup_step(&p, -1, 1) == first && kv_popup_step(&p, -1, -1) == last);
		for (cur = 0; cur < n; cur++)
			for (d = -1; d <= 1; d += 2) {
				int want = cur;

				for (i = cur + d; i >= 0 && i < n; i += d) {
					int r = kv_popup_row_of(&p, i), ok = r >= 0 && !(p.row[r].flags & (KV_PR_RULE | KV_PR_OFF));

					if (ok) {
						want = i;
						break;
					}
				}
				CK(kv_popup_step(&p, cur, d) == want);
			}
	}
}

static void scroll_suite(void)
{
	static struct kv_popup p;
	struct kv_popup_req q;
	char t[KV_POP_TEXT * 4];
	int r, off, id;

	/* a tiny terminal (12 x 60): 10 usable rows for a list of 40 */
	for (off = -3; off <= 40; off++) {
		fill(&p, 40, 8, 0);
		req(&q, 12, 60, 3, 5, 1);
		q.off = off;
		kv_popup_place(&p, &q);
		CK(p.box.h == 10 && p.box.n_rows == 40 && p.box.side == KV_SIDE_COVER);
		CK(p.box.off >= 0 && p.box.off <= 30);
		CK(p.box.off == (off < 0 ? 0 : off > 30 ? 30 : off));
		for (r = p.box.off; r < p.box.off + p.box.h; r++) {
			int cut_top = r == p.box.off && p.box.off > 0, cut_bot = r == p.box.off + p.box.h - 1 && p.box.off + p.box.h < 40;

			kv_popup_text(&p, r, 0, t, sizeof t);
			CK(cols_of(t) == p.box.w);
			CK((cut_top || cut_bot) == (strstr(t, "...") != NULL));
			if (cut_top)
				CK(t[p.box.w - 1] == '^');
			if (cut_bot)
				CK(t[p.box.w - 1] == 'v');
		}
	}
	/* follow brings any item into the drawn rows, one step at a time as a key would */
	fill(&p, 40, 8, 0);
	req(&q, 12, 60, 3, 5, 1);
	kv_popup_place(&p, &q);
	for (id = 0; id < 40; id++) {
		kv_popup_follow(&p, id);
		CK(kv_popup_row_y(&p, id) >= p.box.y && kv_popup_row_y(&p, id) < p.box.y + p.box.h);
	}
	for (id = 39; id >= 0; id--) {
		kv_popup_follow(&p, id);
		CK(kv_popup_row_y(&p, id) >= 0);
	}
	/* a list that fits never scrolls */
	fill(&p, 5, 8, 0);
	req(&q, 40, 120, 3, 5, 1);
	q.off = 4;
	kv_popup_place(&p, &q);
	CK(p.box.off == 0 && p.box.h == 5);
}

int main(void)
{
	width_suite();
	place_suite();
	sub_suite();
	sub_narrow();
	hit_suite();
	step_suite();
	scroll_suite();
	printf("kx_popup: %d checks, %d failure(s)\n", checks, fails);
	return fails != 0;
}
