#define _GNU_SOURCE
#include "kv.h"

/*
 * kv_dlgsel.c - the text selection every recorded page shares: a character selection over the
 * rows a page recorded while it drew them (the dashboard, About, Keyboard, the Decoder's result).
 *
 * It lived in the symbols dialog's file because that dialog was the first to record its rows.
 * The dialog is a page of the dashboard now (kv_props_tab.c) and this is what was left of the
 * file: the recording and the selection, moved unchanged.
 */

/* Presses in a row on one place, counted: 1, 2, 3 (a fourth starts again). "In a row" is 400 ms on the same recorded
 * place - a terminal reports presses and has no notion of a double click. THE ONE COUNTER of the recorded dialogs. */
int dlg_click_count(struct view *v, int r, int c)
{
	uint64_t now = now_ms();
	int again = r == v->dlg_click_r && c == v->dlg_click_c && now - v->dlg_click_ms < 400u;

	v->dlg_click_n = again && v->dlg_click_n < 3 ? v->dlg_click_n + 1 : 1;
	if (v->dlg_click_n == 1) {
		free(v->dlg_full);                  /* a press that starts over forgets the last pick's text */
		v->dlg_full = NULL;
	}
	v->dlg_click_r = r;
	v->dlg_click_c = c;
	v->dlg_click_ms = now;
	return v->dlg_click_n;
}

/* Select columns c0..c1 of line `r` and remember `text` (n bytes, NULL: none) as what a copy takes, for as long as
 * the selection's ends stay these. The lit part is what is on the screen; the text is the whole of what it stands for. */
void dlg_select_full(struct view *v, int r, int c0, int c1, const char *text, size_t n)
{
	char *p = text ? malloc(n + 1u) : NULL;

	free(v->dlg_full);
	v->dlg_full = p;
	v->dlg_full_n = 0;
	if (p) {
		memcpy(p, text, n);
		p[n] = 0;
		v->dlg_full_n = n;
	}
	v->dlg_ar = v->dlg_br = r;
	v->dlg_ac = c0;
	v->dlg_bc = c1;
	v->dlg_have = 1;
	v->dlg_drag = 0;
	v->dlg_full_end[0] = v->dlg_ar;
	v->dlg_full_end[1] = v->dlg_ac;
	v->dlg_full_end[2] = v->dlg_br;
	v->dlg_full_end[3] = v->dlg_bc;
}

/* ---- selecting and copying a dialog's text ---------------------------------
 *
 * A character selection over the rows a dialog recorded while it drew them.
 * Shared by every page that records its rows: they are tables of text a reader
 * wants to paste into a note, and none is a hex pane whose selection means
 * an extent of a file.
 *
 * The selection is over the TEXT, not over what the text describes. Dragging
 * across a symbol row copies the row as it reads on screen - which is the
 * point, because that is what a reader is looking at when they decide to keep
 * it.
 */

/* Start a fresh recording. Called by a dialog before it draws its rows, so a
 * box that has just changed what it shows cannot be selected against what it
 * showed before. */
void dlg_rec_begin(struct view *v, int y0, int x0)
{
	int i;

	v->dlg_rows = 0;
	v->dlg_y0 = y0;
	v->dlg_x0 = x0;
	for (i = 0; i < DLG_ROWS; i++)
		v->dlg_src[i] = -1;
}

/* Say which line of the list the row just recorded came from. Pages that
 * scroll call this; ones that do not leave it and get -1, which anchors the
 * selection to the row as before. */
void dlg_rec_src(struct view *v, uint32_t idx)
{
	if (v->dlg_rows > 0 && v->dlg_rows <= DLG_ROWS)
		v->dlg_src[v->dlg_rows - 1] = (int)idx;
}

/* The recorded row showing that line of the list, or -1. */
int dlg_row_of_src(const struct view *v, int src)
{
	int r;

	if (src < 0)
		return -1;
	for (r = 0; r < v->dlg_rows; r++)
		if (v->dlg_src[r] == src)
			return r;
	return -1;
}

/*
 * Index the row about to be counted: which byte each column starts at.
 *
 * Done once per row as it is recorded rather than per click, because every
 * consumer - the click, the drag, the paint, the copy - asks the same question
 * about the same rows, and a walk per query is a walk per mouse event.
 *
 * A sequence cut short by the end of the buffer is taken as the bytes that are
 * there. snprintf truncates at a byte boundary, so the last glyph of an
 * over-long row can be half of one; treating its bytes as columns of their own
 * is wrong by a column at the far right of a row nobody can see the end of,
 * and reading past the NUL to find out would be wrong everywhere.
 */
static void dlg_index(struct view *v)
{
	const char *s = v->dlg_line[v->dlg_rows];
	uint32_t b = 0, n = 0;

	while (s[b] && n < DLG_COLS) {
		unsigned char c = (unsigned char)s[b];
		uint32_t len = 1, k;

		if ((c & 0xe0u) == 0xc0u)
			len = 2;
		else if ((c & 0xf0u) == 0xe0u)
			len = 3;
		else if ((c & 0xf8u) == 0xf0u)
			len = 4;
		for (k = 1; k < len; k++)
			if (!s[b + k]) {
				len = k;
				break;
			}
		v->dlg_bx[v->dlg_rows][n++] = (uint16_t)b;
		b += len;
	}
	v->dlg_bx[v->dlg_rows][n] = (uint16_t)b;
	v->dlg_cols[v->dlg_rows] = (uint16_t)n;
}

/* The column a byte of a recorded row falls in - for the one place that finds
 * something in the text with strstr and has to say where it is on screen. */
int dlg_col_of_byte(const struct view *v, int row, uint32_t byte)
{
	int n;

	if (row < 0 || row >= v->dlg_rows)
		return -1;
	for (n = 0; n < (int)v->dlg_cols[row]; n++)
		if (v->dlg_bx[row][n] >= byte)
			return n;
	return (int)v->dlg_cols[row];
}

/*
 * Record a row that is already plain text.
 *
 * A page of pre-rendered lines has nothing to hook into: it draws one string and the plain form of
 * it is a separate call. This is that call, so every page ends up in the same recording and the
 * same selection code serves them all.
 */
void dlg_rec_text(struct view *v, const char *plain)
{
	if (v->dlg_rows >= DLG_ROWS)
		return;
	/* Explicitly cut to what the recording holds. A page line may be wider
	 * than DLG_COLS and the tail of it is off the screen anyway - the box
	 * is at most as wide as the terminal - so what is lost is text nobody
	 * could have selected. */
	snprintf(v->dlg_line[v->dlg_rows], DLG_COLS, "%.*s", DLG_COLS - 1, plain);
	dlg_index(v);
	v->dlg_rows++;
}

/*
 * The selection in reading order, as first/last row and the columns on each.
 * Zero when there is nothing selected.
 */
int dlg_span(const struct view *v, int *r0, int *c0, int *r1, int *c1)
{
	if (!v->dlg_have)
		return 0;
	if (v->dlg_ar < v->dlg_br ||
	    (v->dlg_ar == v->dlg_br && v->dlg_ac <= v->dlg_bc)) {
		*r0 = v->dlg_ar; *c0 = v->dlg_ac;
		*r1 = v->dlg_br; *c1 = v->dlg_bc;
	} else {
		*r0 = v->dlg_br; *c0 = v->dlg_bc;
		*r1 = v->dlg_ar; *c1 = v->dlg_ac;
	}
	return 1;
}

/*
 * Paint the selection over what has already been drawn.
 *
 * A SECOND PASS, on purpose. The alternative is to test every character
 * against the selection inside the clipper, which puts the selection's logic
 * into the one function that must stay simple enough to be obviously right
 * about clipping. Overwriting the span afterwards costs one repositioning per
 * selected row and cannot affect a row that is not selected at all.
 */
void dlg_paint_sel(struct out *o, struct view *v)
{
	int r0, c0, r1, c1, r;

	if (!dlg_span(v, &r0, &c0, &r1, &c1))
		return;
	for (r = r0; r <= r1; r++) {
		int row = dlg_row_of_src(v, r);
		int len;
		int from, to;

		/* Off the top or the bottom of the window: nothing to paint,
		 * and the selection is still that line's. */
		if (row < 0) {
			if (r >= v->dlg_rows + r0)
				break;
			continue;
		}
		len = (int)v->dlg_cols[row];
		/*
		 * THE HIGHLIGHT STOPS AT THE LAST CHARACTER, not at the end of
		 * the padded row.
		 *
		 * A table row is a value padded out to its column width and
		 * then a border glyph, so a drag that ran past the end of a
		 * short value swept the padding AND the wall into the
		 * selection - a highlight that leapt from the end of a word to
		 * a bar several columns away, with nothing between them that
		 * anybody had pointed at.
		 *
		 * Trimmed the same way dlg_copy already trims, so what is
		 * shown as selected and what lands in the clipboard are the
		 * same span. They were not: the copy dropped the padding and
		 * the paint kept it.
		 */
		while (len > 0 &&
		       v->dlg_line[row][v->dlg_bx[row][len - 1]] == ' ')
			len--;
		from = (r == r0) ? c0 : 0;
		to   = (r == r1) ? c1 + 1 : len;

		if (from < 0)
			from = 0;
		if (to > len)
			to = len;
		if (to <= from)
			continue;
		out_at(o, v->dlg_y0 + row, v->dlg_x0 + from);
		out_str(o, A_SEL);
		out_add(o, v->dlg_line[row] + v->dlg_bx[row][from],
			(size_t)(v->dlg_bx[row][to] - v->dlg_bx[row][from]));
		out_str(o, A_OFF);
	}
}

/* Which (row, column) of the recorded text a screen position is, or 0 when it
 * is not over the text at all. */
/*
 * Screen position to a place in the TEXT: `r` is the line of the list when the
 * page recorded one, and the recorded row otherwise.
 *
 * Answering in content space is what makes a selection survive a scroll - see
 * view.dlg_src. Everything that paints or copies turns it back into a row with
 * dlg_row_of_src, and a line scrolled out of the window simply has no row,
 * which is the honest answer: it is not on the screen.
 */
int dlg_at(const struct view *v, int row, int col, int *r, int *c)
{
	int rr = row - v->dlg_y0, cc = col - v->dlg_x0;

	if (rr < 0 || rr >= v->dlg_rows || cc < 0)
		return 0;
	if (cc >= (int)v->dlg_cols[rr])
		cc = (int)v->dlg_cols[rr] - 1;
	if (cc < 0)
		return 0;
	*r = v->dlg_src[rr] >= 0 ? v->dlg_src[rr] : rr;
	*c = cc;
	return 1;
}

/*
 * Copy the selection, rows joined by newlines and trailing blanks dropped.
 *
 * The blanks go because these tables are padded to their column widths, so a
 * row selected whole ends in a run of spaces that is part of the layout and
 * not part of what the reader picked out.
 */
void dlg_copy(struct view *v)
{
	int r0, c0, r1, c1, r, rows = 0;
	struct out d = { 0 };

	if (!dlg_span(v, &r0, &c0, &r1, &c1))
		return;
	/* A double or triple click took text that is not all on the screen: while the selection is still exactly that one,
	 * the copy is that text. */
	if (v->dlg_full && v->dlg_ar == v->dlg_full_end[0] && v->dlg_ac == v->dlg_full_end[1] &&
	    v->dlg_br == v->dlg_full_end[2] && v->dlg_bc == v->dlg_full_end[3]) {
		if (v->dlg_full_n) {
			copy_osc52(v->dlg_full, v->dlg_full_n);
			snprintf(v->act_msg, sizeof v->act_msg, "Copied 1 line(s)");
			v->act_ok = 1;
		}
		return;
	}
	for (r = r0; r <= r1; r++) {
		int row = dlg_row_of_src(v, r);
		int len, from, to;

		/* A line the window has scrolled past cannot be copied: the
		 * recording holds what is on the screen, and inventing bytes
		 * for a row nobody can see is the one thing worse than
		 * copying less than was asked for. */
		if (row < 0)
			continue;
		len = (int)v->dlg_cols[row];
		from = (r == r0) ? c0 : 0;
		to   = (r == r1) ? c1 + 1 : len;

		if (to > len)
			to = len;
		while (to > from &&
		       v->dlg_line[row][v->dlg_bx[row][to - 1]] == ' ')
			to--;
		if (rows)
			out_str(&d, "\n");
		if (to > from)
			out_add(&d, v->dlg_line[row] + v->dlg_bx[row][from],
				(size_t)(v->dlg_bx[row][to] -
					 v->dlg_bx[row][from]));
		rows++;
	}
	if (d.n) {
		copy_osc52(d.p, d.n);
		snprintf(v->act_msg, sizeof v->act_msg, "Copied %d line(s)",
			 rows);
		v->act_ok = 1;
	}
	free(d.p);
}
