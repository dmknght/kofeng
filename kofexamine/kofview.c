/*
 * kofview.c - the terminal, and what is drawn on it. See kofview.h for the
 * boundary this file is on the far side of.
 */

/* _GNU_SOURCE, not _POSIX_C_SOURCE, and before any include: this file now
 * pulls in kofplatform.h for kof_write_all, and that header's POSIX branch
 * has an inline kof_memmem whose body calls memmem - a GNU extension the
 * compiler must see declared to compile the body at all, whether or not this
 * translation unit ever calls it. On glibc _POSIX_C_SOURCE does not merely
 * fail to enable memmem, it suppresses it. Same reasoning, same wording, as
 * dbloader.c and kofmatch.c. */
#define _GNU_SOURCE

#include "kofview.h"
/* For enum kof_format, which kv_cap answers about. kofview.h itself stays
 * free of it: the header is a terminal and a widget, and a caller that only
 * draws should not have to pull in the engine to do it. */
#include <kofmod/kofsig.h>
#include "kofplat.h"

#ifndef _WIN32
volatile sig_atomic_t kof_winch;
#endif
#include "../libkofeng/kofcore/kofplatform.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* ---- the terminal ---------------------------------------------------------
 *
 * Raw mode, alternate screen, no cursor - and every one of them put back on the
 * way out, including the way out nobody plans for. A tool that leaves a terminal
 * in raw mode after a crash is a tool people stop running, so the restore is
 * registered before the first change is made and is idempotent.
 */
/*
 * Everything this program puts on the terminal goes through one call.
 *
 * It used to be two - fputs for the mode changes, write for the frames - and
 * that was a real bug rather than untidiness. stdout to a terminal is line
 * buffered and a mode change carries no newline, so "turn the mouse on" sat in
 * stdio's buffer for the whole session while every frame went straight out
 * around it. The terminal was never asked to report a click, so it never did,
 * and the viewer looked like a viewer whose mouse did not work.
 *
 * It also makes the restore path correct: write is async-signal-safe and
 * fputs/fflush are not, and the restore runs from a signal handler.
 */
void term_write_n(const char *s, size_t n)
{
	/* A screen that could not be written is not worth an error path: the
	 * next redraw writes the whole thing again. */
	(void)kof_write_all(STDOUT_FILENO, s, n);
}

void term_write(const char *s)
{
	term_write_n(s, strlen(s));
}

static int g_tty_raw;
int g_rows = 24, g_cols = 80;

void term_restore(void)
{
	if (!g_tty_raw)
		return;
	g_tty_raw = 0;
	kof_tty_raw_leave();
	/* Cursor back, main screen back, in that order: the show has to happen
	 * on the screen that is about to be left, or it applies to the one being
	 * returned to and the user's shell gets it. */
	term_write("\033[?2004l\033[?1006l\033[?1002l\033[?1000l\033[?25h\033[?1049l");
}

static void on_signal(int sig)
{
	term_restore();
	/* Re-raise with the default handler so the exit status says what
	 * happened. Exiting 0 here would tell a script the run succeeded. */
	signal(sig, SIG_DFL);
	raise(sig);
}

int term_setup(void)
{
	if (!kof_tty_ok()) {
		fprintf(stderr, "kofviewer: needs a terminal\n");
		return 0;
	}

	atexit(term_restore);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
#ifdef SIGHUP
	signal(SIGHUP, on_signal);
#endif
#ifdef SIGQUIT
	signal(SIGQUIT, on_signal);
#endif
	signal(SIGSEGV, on_signal);

	if (!kof_tty_raw_enter())
		return 0;
	g_tty_raw = 1;
	/* Alternate screen, no cursor, and SGR mouse reporting - the last so a
	 * click can move the cursor to what it landed on. */
	/*
	 * Alternate screen, no cursor, and mouse reporting in three parts: 1000
	 * for press and release, 1002 for motion WHILE a button is down, 1006
	 * for the SGR encoding that has no coordinate ceiling.
	 *
	 * 1002 is what makes a drag a drag. It also takes the terminal's own
	 * text selection away, which is the point rather than a cost: a
	 * selection made of screen characters would span the tree pane, the
	 * offset column and the ASCII column, and none of those are what is
	 * being selected. Holding shift still bypasses all of this and gives
	 * back the terminal's copy, in every terminal that implements 1006.
	 */
	kof_tty_watch_size();
	/*
	 * ?2004h is bracketed paste. Without it a paste arrives as the keys it
	 * spells, so pasting a path into a field runs whatever those letters
	 * are bound to; with it the run is delimited and can be put where the
	 * caret is.
	 */
	term_write("\033[?1049h\033[?25l\033[?1000h\033[?1002h\033[?1006h"
		   "\033[?2004h");
	return 1;
}

int g_term_small;

void term_size(void)
{
	int r = 0, c = 0;

	g_term_small = 0;
	if (kof_tty_size(&r, &c)) {
		g_rows = r;
		g_cols = c;
		g_term_small = r < 12 || c < 60;   /* the layout below needs 12x60 */
	}
	if (g_rows < 12)
		g_rows = 12;
	if (g_cols < 60)
		g_cols = 60;
}

/* ---- drawing --------------------------------------------------------------
 *
 * One frame is built into a buffer and written with one call. Not for speed:
 * writing a screen in fifty pieces makes a resize or a slow link show the frame
 * being assembled, and the flicker looks like a bug in the tool.
 */

/*
 * The rectangle, and it narrows only.
 *
 * An unset one (cl_b == 0) is replaced outright, which is how the frame's
 * first call establishes the screen; after that every call is an intersection,
 * so a drawer cannot widen the region it was given by the drawer above it.
 */
struct out_clip out_clip_set(struct out *o, int t, int l, int b, int r)
{
	struct out_clip prev;

	prev.t = o->cl_t; prev.l = o->cl_l;
	prev.b = o->cl_b; prev.r = o->cl_r;
	if (!o->cl_b)
		o->cl_w = r;            /* the screen, set once per frame */
	if (o->cl_b) {
		if (t < o->cl_t) t = o->cl_t;
		if (l < o->cl_l) l = o->cl_l;
		if (b > o->cl_b) b = o->cl_b;
		if (r > o->cl_r) r = o->cl_r;
	}
	/* An empty intersection has to stay empty rather than wrap around:
	 * b < t with b non-zero refuses every cell, which is the answer. */
	o->cl_t = t; o->cl_l = l;
	o->cl_b = b < t ? t - 1 : b;
	o->cl_r = r;
	if (!o->cl_b)
		o->cl_b = -1;   /* "set, and admits nothing" */
	return prev;
}

void out_clip_restore(struct out *o, struct out_clip prev)
{
	o->cl_t = prev.t; o->cl_l = prev.l;
	o->cl_b = prev.b; o->cl_r = prev.r;
}

/* Bytes straight into the buffer, with no counting and no clipping: the two
 * places that know they are writing an escape rather than a cell. */
static void out_raw(struct out *o, const char *s, size_t n)
{
	/*
	 * THE DOUBLING IS WHAT OVERFLOWS, not the comparison.
	 *
	 * "while (want < needed) want *= 2" has no ceiling: a `want` past half
	 * of size_t doubles to zero, the loop then exits because zero is not
	 * less than the need, and realloc(p, 0) hands back a pointer to
	 * nothing that the writes below use anyway. The need is computed by
	 * subtraction for the same reason every other bound here is.
	 */
	if (o->n > o->cap || n + 1u > o->cap - o->n) {
		size_t need = o->n + n + 1u;
		size_t want = o->cap ? o->cap * 2u : 8192u;

		if (n + 1u < n)                 /* the need itself wrapped */
			exit(1);
		while (want < need) {
			if (want > (size_t)-1 / 2u)
				exit(1);
			want *= 2u;
		}
		o->p = realloc(o->p, want);
		if (!o->p)
			exit(1);
		o->cap = want;
	}
	memcpy(o->p + o->n, s, n);
	o->n += n;
}

/*
 * EVERY CELL THE SCREEN GETS COMES THROUGH HERE.
 *
 * Escapes are passed through untouched - dropping an SGR because the text it
 * colours was clipped would leave the colour state wrong for whatever is drawn
 * next - and printable cells are emitted only where the rectangle allows.
 *
 * A CELL, NOT A BYTE: a box-drawing character is three bytes in one column, so
 * the clip decision is made on the lead byte and the continuation bytes follow
 * it. Splitting one at the right edge would put half a character on the screen,
 * which is worse than the overflow the clip is there to stop.
 *
 * col_hint still counts per byte, the way it always has - the layout
 * arithmetic above is built on that count and out_glyph exists precisely
 * because of it.
 *
 * Runs, not bytes: the common case is a whole string inside the rectangle, and
 * it is appended with one memcpy the way it was before.
 */
void out_add(struct out *o, const char *s, size_t n)
{
	size_t i = 0, run = 0;
	int row_ok = !o->cl_b ||
		     (o->row_hint >= o->cl_t && o->row_hint <= o->cl_b);
	int cell_ok = 1;

	while (i < n) {
		unsigned char b = (unsigned char)s[i];

		if (b == 0x1b) {
			size_t j = i + 1u;

			if (run) {
				out_raw(o, s + i - run, run);
				run = 0;
			}
			while (j < n && s[j] != 'm' && s[j] != 'H' &&
			       s[j] != 'K')
				j++;
			if (j < n)
				j++;
			/*
			 * ERASE TO END OF LINE IS A DRAW, and it draws to the
			 * edge of the SCREEN. Inside a box narrower than the
			 * screen it would blank the pane to the right of it,
			 * so it is refused there - a box paints its own width
			 * and has no use for it.
			 */
			if (s[j - 1u] == 'K' && o->cl_b &&
			    o->cl_r < o->cl_w) {
				/*
				 * ERASED ONLY AS FAR AS THE RECTANGLE GOES.
				 *
				 * Passing it through would blank the pane to
				 * the right - which is what the tree pane was
				 * doing to the divider drawn beside it, every
				 * frame - and refusing it outright would leave
				 * the row's old text standing when a shorter
				 * one is drawn over it. So it is spaces to the
				 * edge of the region, and then the cursor is
				 * put back, because an erase does not move it.
				 */
				int c = o->cl_col;

				if (row_ok && c <= o->cl_r) {
					char t[32];
					int m;

					while (c <= o->cl_r) {
						out_raw(o, " ", 1);
						c++;
					}
					m = snprintf(t, sizeof t,
						     "\033[%d;%dH",
						     o->row_hint, o->cl_col);
					if (m > 0)
						out_raw(o, t, (size_t)m);
				}
				o->cl_drop++;
			} else {
				out_raw(o, s + i, j - i);
				if (o->bg && j - i == 4u && !memcmp(s + i, "\033[0m", 4))
					out_raw(o, o->bg, strlen(o->bg));
			}
			i = j;
			continue;
		}
		if ((b & 0xc0u) != 0x80u) {
			/* A new cell. Control bytes take no column: they are
			 * passed through and left out of the reckoning. */
			if (b < 0x20u) {
				cell_ok = 1;
				if (b == '\n')
					o->row_hint++;
				if (b == '\n' || b == '\r')
					o->cl_col = 1;
			} else {
				cell_ok = !o->cl_b ||
					  (row_ok && o->cl_col >= o->cl_l &&
					   o->cl_col <= o->cl_r);
				o->cl_col++;
			}
		}
		if (cell_ok) {
			run++;
		} else {
			if (run) {
				out_raw(o, s + i - run, run);
				run = 0;
			}
			o->cl_drop++;
		}
		o->col_hint++;
		i++;
	}
	if (run)
		out_raw(o, s + n - run, run);
}

void out_str(struct out *o, const char *s)
{
	out_add(o, s, strlen(s));
}

void out_glyph(struct out *o, const char *g)
{
	if (!o->cl_b ||
	    (o->row_hint >= o->cl_t && o->row_hint <= o->cl_b &&
	     o->cl_col >= o->cl_l && o->cl_col <= o->cl_r))
		out_raw(o, g, strlen(g));
	else
		o->cl_drop++;
	o->cl_col++;
	o->col_hint++;
}

void out_fmt(struct out *o, const char *fmt, ...)
{
	char t[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	if (n > 0) {
		size_t keep = (size_t)n < sizeof t ? (size_t)n : sizeof t - 1;

		t[keep] = 0;
		out_str(o, t);
	}
}

void out_at(struct out *o, int row, int col)
{
	out_fmt(o, "\033[%d;%dH", row, col);
	o->row_hint = row;
	o->col_base = col;
	o->cl_col = col;
}

/*
 * MAGENTA FOR A HEURISTIC, the colour the scanner has used for one since it had
 * colour at all.
 *
 * The three verdicts were painted in two here: anything that fired came out
 * red, so a structural guess and a named family looked alike on the one screen
 * where the difference is the point. A reader moving between the two tools
 * should not have to learn a second scheme.
 */
/*
 * AND and OR, told apart by colour.
 *
 * Both were A_WARN, so a condition read as one yellow word between blue ids and
 * the reader had to actually read it to know whether the rule was narrowing or
 * widening - which is the single most consequential thing on the row. AND is
 * cyan because it TIGHTENS (every id must be present); OR keeps the yellow it
 * had, because widening is the one that costs false positives and yellow is
 * what this panel already uses for "worth a second look".
 *
 * Named rather than written as escapes at the two sites: the operator inside a
 * condition and the join to the next one are drawn in different functions with
 * opposite polarity (`op` is 0-and-1-or, `join` is 0-or-1-and), and the pair
 * only stays consistent if the colour is chosen by the WORD, not by the field.
 */


/* ---- scrollbars ------------------------------------------------------------ */

/*
 * ONE CELL OF A BAR, as the string that draws it - attributes and all.
 *
 * The two ends of the cell are the two halves the thumb is counted in, and
 * which of the four glyphs that makes is the whole of what a bar looks like.
 * Written once because there are two bars and because the panes are not the
 * only things with one: a dialog builds its rows as strings and cannot call a
 * drawer that moves the cursor, so it asks for the cell and puts it in the row
 * itself. Two spellings of this would be two scrollbars that do not look alike.
 */
static const char *bar_cell(int h0, int h1, int i, int horiz)
{
	int a = i * 2, b = a + 1;          /* this cell's two halves */
	int lo = a >= h0 && a < h0 + h1;   /* the near half covered */
	int hi = b >= h0 && b < h0 + h1;   /* the far half covered */

	if (lo && hi)
		return A_BOLD G_THUMB A_OFF;
	if (lo)
		return horiz ? A_BOLD G_HALF_L A_OFF : A_BOLD G_HALF_T A_OFF;
	if (hi)
		return horiz ? A_BOLD G_HALF_R A_OFF : A_BOLD G_HALF_B A_OFF;
	return horiz ? A_DIM G_HBAR A_OFF : A_DIM G_V A_OFF;
}

/*
 * A vertical scrollbar in one column.
 *
 * Drawn only when there is more than fits, because a bar that is always full
 * height says nothing and costs a column of every pane it is in. The thumb is
 * at least one row so a very long object still shows where it is - proportional
 * alone would round it away and leave the track empty.
 *
 * ASCII, like the pane divider: this is read over ssh on whatever terminal is
 * at the other end.
 */
int kv_bar_thumb(int top, int bot, uint64_t off, uint64_t total,
		     uint64_t shown, int *out_len)
{
	int rows = bot - top + 1, t0, t1;
	uint64_t max;

	if (rows < 2 || !total || shown >= total)
		return -1;
	max = total - shown;
	t1 = (int)((uint64_t)(rows - 1) * shown / total);
	if (t1 < 1)
		t1 = 1;
	t0 = (int)((uint64_t)(rows - t1) * (off < max ? off : max) / max);
	*out_len = t1;
	return t0;
}

/*
 * A BAR, DRAWN AS ONE SHAPE IN TWO WEIGHTS.
 *
 * It was '#' for the thumb and ':' for the track - two different characters, so
 * the eye read it as a column of punctuation rather than as a rule with a
 * position on it. One character throughout, bright where the thumb is and dim
 * elsewhere, reads as what it is; and it is the same shape the panes are divided
 * by, so a vertical line means the same thing everywhere on the screen.
 *
 * Every pane's bar comes through here, so there is one style rather than one per
 * caller.
 */
/*
 * THE THUMB IN HALF CELLS, which is what makes the bar track smoothly.
 *
 * Whole cells are too coarse to read as motion: on a forty row pane over a
 * long file a whole page of scrolling moves the thumb by nothing, then by one
 * row. Counting in halves and drawing the odd end with a half block doubles the
 * resolution, and two is enough - the eye reads it as continuous and the cost
 * is one glyph.
 *
 * Returns the first half covered and writes how many halves the thumb is, or -1
 * when there is nothing to scroll.
 */
static int bar_halves(int cells, uint64_t off, uint64_t total, uint64_t shown,
		      int *out_len)
{
	int halves = cells * 2, t1;
	uint64_t max;

	if (cells < 2 || !total || shown >= total)
		return -1;
	max = total - shown;
	t1 = (int)((uint64_t)halves * shown / total);
	if (t1 < 1)
		t1 = 1;
	*out_len = t1;
	return (int)((uint64_t)(halves - t1) * (off < max ? off : max) / max);
}

void kv_scrollbar(struct out *o, int col, int top, int bot,
		      uint64_t off, uint64_t total, uint64_t shown)
{
	int rows = bot - top + 1, i, h0, h1;

	h0 = bar_halves(rows, off, total, shown, &h1);
	if (h0 < 0)
		return;
	for (i = 0; i < rows; i++) {
		out_at(o, top + i, col);
		out_str(o, bar_cell(h0, h1, i, 0));
	}
}

/*
 * The same bar lying down. A pane whose lines run off the right has no other
 * way to say how far right they go, or where in that width the reader is.
 */
void kv_scrollbar_h(struct out *o, int row, int left, int right,
			uint64_t off, uint64_t total, uint64_t shown)
{
	int cols = right - left + 1, i, h0, h1;

	h0 = bar_halves(cols, off, total, shown, &h1);
	if (h0 < 0)
		return;
	out_at(o, row, left);
	for (i = 0; i < cols; i++)
		out_str(o, bar_cell(h0, h1, i, 1));
}

/*
 * The same cell, asked for by a caller that has the geometry rather than the
 * halves - a row being built one column at a time. Recomputes the thumb per
 * cell, which is two divisions and keeps the caller from having to hold state
 * between rows.
 */
const char *kv_bar_at(int cells, int i, uint64_t off, uint64_t total,
		      uint64_t shown, int horiz)
{
	int h0, h1;

	h0 = bar_halves(cells, off, total, shown, &h1);
	if (h0 < 0)
		return NULL;
	return bar_cell(h0, h1, i, horiz);
}

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

/* ---- what a format can be asked - see kofview.h ---------------------------- */

int kv_cap(uint8_t format, int cap)
{
	switch (format) {
	/*
	 * THE TWO FORMATS THAT ARE MEANT TO BE READ.
	 *
	 * A script and a text file have no structure to dump - no header at a
	 * fixed place, no table to line up in columns - and a person is the
	 * thing that reads them. They can be nothing else on this table: no
	 * symbol table, no entry point, nothing to unpack, and shellcode in
	 * them is a string rather than a section.
	 */
	case KOF_FMT_SCRIPT:
	case KOF_FMT_TEXT:
		return cap == KV_CAP_TEXT;

	case KOF_FMT_ELF:
	case KOF_FMT_PE:
	case KOF_FMT_MACHO:
		/* All four: an executable image has a symbol table, code at an
		 * entry point, is the thing a packer packs, and is where a
		 * loader keeps the payload it will run. */
		return cap == KV_CAP_SYMBOLS || cap == KV_CAP_CODE ||
		       cap == KV_CAP_UNPACK || cap == KV_CAP_SHELLCODE;

	case KOF_FMT_UNKNOWN:
		/*
		 * Bytes nothing claimed. No symbol table to look for, but they
		 * may well BE code - a payload an unpacker peeled, a blob
		 * carved out of a variable - and that is the case the emulator
		 * and the disassembler exist for.
		 */
		return cap == KV_CAP_CODE || cap == KV_CAP_UNPACK;

	default:
		/*
		 * Every container and every document format. Their members come
		 * out by being READ, which the engine does on its own and which
		 * is not what any of these items mean, and none of them has a
		 * symbol table or an entry point.
		 *
		 * Written as a default rather than listed, because the list is
		 * the longer one and a format added tomorrow is far likelier to
		 * belong here than with the executables - so the safe answer is
		 * the one a new format gets by saying nothing.
		 */
		return 0;
	}
}
