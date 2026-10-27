/*
 * kx_viewpure - the viewer's pure helpers of kofexamine/kofview.c that tests/unit/out_clip.c and the TUI tests do not reach by
 * name: the scrollbar geometry (kv_bar_thumb, kv_bar_at, kv_scrollbar, kv_scrollbar_h), the dropdown model (kv_menu_rows,
 * kv_menu_at_row, kv_menu_row_of, kv_menu_first, kv_menu_step) and what a format can be asked (kv_cap).
 *
 * Each suite is an exhaustive sweep of a small space against a model written here with exact (128-bit) arithmetic. Known defect
 * pinned: EX-10, the thumb arithmetic multiplies rows by `shown` in 64 bits and wraps for an object of 2^58 or more lines/bytes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../kofexamine/kofview.h"
#include "known_miss.h"

static int fails, checks;

#define CK(cond) do { checks++; if (!(cond)) { if (fails < 20) printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

typedef unsigned __int128 u128;

/* ---------------------------------------------------------------------------------------- kv_bar_thumb */

static void thumb_suite(void)
{
	int top, rows, len, t0;
	uint64_t total, shown, off;
	unsigned long n = 0;

	for (rows = 0; rows <= 12; rows++)
		for (total = 0; total <= 30; total++)
			for (shown = 0; shown <= 32; shown++)
				for (off = 0; off <= 33; off += (total > 8 ? 3 : 1)) {
					top = 5;
					len = -77;
					t0 = kv_bar_thumb(top, top + rows - 1, off, total, shown, &len);
					n++;
					if (rows < 2 || !total || shown >= total) {
						CK(t0 == -1 && len == -77);          /* nothing to scroll: no thumb, nothing written */
						continue;
					} else {
						uint64_t max = total - shown, o = off < max ? off : max;
						int wl = (int)((u128)(rows - 1) * shown / total), w0;

						if (wl < 1)
							wl = 1;
						w0 = (int)((u128)(rows - wl) * o / max);
						CK(len == wl && t0 == w0);
						CK(len >= 1 && len <= rows - 1 && t0 >= 0 && t0 + len <= rows);
					}
				}
	CK(n > 100000);
	/* the thumb never leaves the track as the offset sweeps, and it is monotonic */
	for (rows = 2; rows < 60; rows++) {
		int prev = -1;

		for (off = 0; off <= 1000; off++) {
			t0 = kv_bar_thumb(0, rows - 1, off, 1000 + 40, 40, &len);
			CK(t0 >= prev && t0 >= 0 && t0 + len <= rows);
			prev = t0;
		}
	}
	/* EX-10 (2026-10-27, R->M) [sev L]: rows * shown is computed in 64 bits (kofview.c: kv_bar_thumb, bar_halves), so for shown >=
	 * 2^64/rows it wraps and the thumb is the wrong size. Trigger: an object of 2^58 bytes or more (no file the engine reads).
	 * Latent; the row below holds the right answer and is red-in-waiting. */
	{
		uint64_t big = 1ull << 60;

		t0 = kv_bar_thumb(0, 39, 0, big + big / 2, big, &len);
		KM_CHECK(len == (int)((u128)39 * big / (big + big / 2)), "the thumb of a 2^60 object is the wrong size (rows * shown wraps in 64 bits)", "EX-10");
	}
}

static void bar_at_suite(void)
{
	int cells, i;
	uint64_t total, shown, off;
	struct out o, e;
	static const char *kinds[4];
	unsigned long n = 0;

	memset(&o, 0, sizeof o);
	memset(&e, 0, sizeof e);
	for (cells = 0; cells <= 9; cells++)
		for (total = 0; total <= 12; total++)
			for (shown = 0; shown <= 13; shown++)
				for (off = 0; off <= 13; off++) {
					int halves = cells * 2, t1, h0;

					if (cells < 2 || !total || shown >= total) {
						CK(kv_bar_at(cells, 0, off, total, shown, 0) == NULL);
						continue;
					}
					t1 = (int)((u128)halves * shown / total);
					if (t1 < 1)
						t1 = 1;
					h0 = (int)((u128)(halves - t1) * (off < total - shown ? off : total - shown) / (total - shown));
					for (i = 0; i < cells; i++) {
						int lo = 2 * i >= h0 && 2 * i < h0 + t1, hi = 2 * i + 1 >= h0 && 2 * i + 1 < h0 + t1;
						const char *v = kv_bar_at(cells, i, off, total, shown, 0), *hz = kv_bar_at(cells, i, off, total, shown, 1);

						n++;
						CK(v && hz);
						/* one bright shape for a covered cell, the same dim one for a free cell, in either direction */
						if (lo && hi)
							CK(!strcmp(v, hz) && strstr(v, "\033[1m"));
						else if (lo || hi)
							CK(strcmp(v, hz) != 0 && strstr(v, "\033[1m") && strstr(hz, "\033[1m"));
						else
							CK(strstr(v, A_DIM) && strstr(hz, A_DIM));
					}
				}
	CK(n > 5000);
	(void)kinds;
	/* the two drawn bars are the cells of kv_bar_at, in order, behind one cursor move */
	for (cells = 2; cells < 12; cells++) {
		o.n = e.n = 0;
		o.col_hint = e.col_hint = 0;
		kv_scrollbar_h(&o, 3, 4, 4 + cells - 1, 7, 50, 10);
		out_at(&e, 3, 4);
		for (i = 0; i < cells; i++)
			out_str(&e, kv_bar_at(cells, i, 7, 50, 10, 1));
		CK(o.n == e.n && !memcmp(o.p, e.p, e.n));
		o.n = e.n = 0;
		kv_scrollbar(&o, 9, 2, 2 + cells - 1, 7, 50, 10);
		for (i = 0; i < cells; i++) {
			out_at(&e, 2 + i, 9);
			out_str(&e, kv_bar_at(cells, i, 7, 50, 10, 0));
		}
		CK(o.n == e.n && !memcmp(o.p, e.p, e.n));
		/* nothing to scroll: nothing written */
		o.n = 0;
		kv_scrollbar_h(&o, 3, 4, 4 + cells - 1, 0, 10, 10);
		kv_scrollbar(&o, 9, 2, 2 + cells - 1, 0, 10, 10);
		kv_scrollbar(&o, 9, 2, 2, 0, 100, 1);
		CK(o.n == 0);
	}
	free(o.p);
	free(e.p);
}

/* ------------------------------------------------------------------------------------------- the menu */

struct mm {
	unsigned shown, enabled, rule;
};

static int m_shown(void *u, int i) { return (int)((((struct mm *)u)->shown >> i) & 1u); }
static int m_enabled(void *u, int i) { return (int)((((struct mm *)u)->enabled >> i) & 1u); }
static int m_rule(void *u, int i) { return (int)((((struct mm *)u)->rule >> i) & 1u); }

static void menu_suite(void)
{
	int n;
	unsigned sh, en, ru;
	unsigned long total = 0;

	for (n = 0; n <= 5; n++)
		for (sh = 0; sh < (1u << n); sh++)
			for (en = 0; en < (1u << n); en++)
				for (ru = 0; ru < (1u << n); ru++) {
					struct mm mm = { sh, en, ru };
					struct kv_menu m;
					int rowof[8], itemat[16], rows = 0, i, r, first = 0, found = 0, d, cur;

					memset(&m, 0, sizeof m);
					m.n = n;
					m.ud = &mm;
					m.shown = m_shown;
					m.enabled = m_enabled;
					m.rule_above = m_rule;
					for (i = 0; i < 16; i++)
						itemat[i] = -1;
					/* the model: a hidden item takes no row; a rule above a shown item takes one of its own */
					for (i = 0; i < n; i++) {
						rowof[i] = -1;
						if (!((sh >> i) & 1u))
							continue;
						if ((ru >> i) & 1u)
							rows++;
						rowof[i] = rows;
						itemat[rows] = i;
						rows++;
						if (!found && ((en >> i) & 1u)) {
							first = i;
							found = 1;
						}
					}
					total++;
					CK(kv_menu_rows(&m) == rows);
					for (r = -2; r < 14; r++)
						CK(kv_menu_at_row(&m, r) == (r >= 0 && r < 16 ? itemat[r] : -1));
					for (i = 0; i < n; i++)
						CK(kv_menu_row_of(&m, i) == rowof[i]);
					CK(kv_menu_row_of(&m, n) == -1 && kv_menu_row_of(&m, 99) == -1);
					CK(kv_menu_first(&m) == first);
					for (cur = 0; cur < n; cur++)
						for (d = -1; d <= 1; d += 2) {
							int k = cur, want = cur, steps;

							for (steps = 0; steps < n; steps++) {
								k += d;
								if (k < 0 || k >= n)
									break;
								if (((sh >> k) & 1u) && ((en >> k) & 1u)) {
									want = k;
									break;
								}
							}
							CK(kv_menu_step(&m, cur, d) == want);
						}
				}
	CK(total > 1000);
	/* a menu with no callbacks: every item shown, enabled, with no rules */
	{
		struct kv_menu m;

		memset(&m, 0, sizeof m);
		m.n = 4;
		CK(kv_menu_rows(&m) == 4 && kv_menu_at_row(&m, 3) == 3 && kv_menu_row_of(&m, 2) == 2 && kv_menu_first(&m) == 0 &&
		   kv_menu_step(&m, 0, 1) == 1 && kv_menu_step(&m, 3, 1) == 3 && kv_menu_step(&m, 0, -1) == 0);
	}
}

/* ------------------------------------------------------------------------------------------ kv_cap */

static void cap_suite(void)
{
	unsigned f, c;

	for (f = 0; f < 256; f++)
		for (c = 0; c < (unsigned)KV_CAP_COUNT + 3u; c++) {
			int want;

			switch (f) {
			case KOF_FMT_SCRIPT:
			case KOF_FMT_TEXT:
				want = c == KV_CAP_TEXT;
				break;
			case KOF_FMT_ELF:
			case KOF_FMT_PE:
			case KOF_FMT_MACHO:
				want = c == KV_CAP_SYMBOLS || c == KV_CAP_CODE || c == KV_CAP_UNPACK || c == KV_CAP_SHELLCODE;
				break;
			case KOF_FMT_UNKNOWN:
				want = c == KV_CAP_CODE || c == KV_CAP_UNPACK;
				break;
			default:
				want = 0;
			}
			CK((kv_cap((uint8_t)f, (int)c) != 0) == want);
		}
}

int main(void)
{
	thumb_suite();
	bar_at_suite();
	menu_suite();
	cap_suite();
	printf("kx_viewpure: %d checks, %s\n", checks, fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
