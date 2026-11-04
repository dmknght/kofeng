/*
 * kv_scrollbar.c - the scrollbar: one cell, a vertical and a horizontal bar (split from kofview.c, no change of body).
 */
#define _GNU_SOURCE
#include "kofview.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

