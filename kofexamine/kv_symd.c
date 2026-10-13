#define _GNU_SOURCE
#include "kv.h"


/*
 * A ROW WRITER THAT CLIPS TO A WINDOW, so the table can be scrolled sideways.
 *
 * The problem it solves: the row is a fixed sequence of columns whose natural
 * width does not depend on the box. When the box is narrower, the row has to
 * stop at the border - and stopping by not writing the tail is what shortened
 * the name column instead, which loses data. Worse, getting that budget wrong
 * by one wrote THROUGH the border and the scrollbar beside it, because nothing
 * here turns autowrap off and a terminal has no clip region.
 *
 * So every field goes through this. It counts columns in the FULL row and emits
 * only those inside [from, to), which makes horizontal scrolling a change of
 * two numbers rather than a different layout, and makes writing past the border
 * impossible rather than merely avoided. The colour is emitted lazily - once,
 * before the first visible character of a run - so a field scrolled off costs
 * no escape sequence, and a field entering from the left is still coloured
 * even though its first characters are not drawn.
 */

struct sclip {
	struct out *o;
	int         vcol;               /* column in the unclipped row */
	int         from, to;           /* the visible window */
	/*
	 * WHERE THE VISIBLE CHARACTERS ARE ALSO WRITTEN, so they can be
	 * selected and copied.
	 *
	 * The row has to be recorded as it is drawn rather than rebuilt
	 * afterwards, because "afterwards" means a second copy of the format
	 * strings and the clipping - and the copy a reader takes would then be
	 * whatever that second version produced, not what they were looking at.
	 * Recorded here, the two cannot differ: there is one walk.
	 *
	 * NULL when a caller does not want a recording, which is what the
	 * heading rows use.
	 */
	char       *rec;
	int         rec_n;
};

static void symd_clamp(struct view *v);

/* The box drawing glyphs (G_TL, G_H, G_V and the rest) are defined beside
 * out_glyph, up with the output primitives: the scrollbar and the menu bar draw
 * with them too, and they are the one place where what to print depends on the
 * platform. */

/* ---- the symbols dialog ----------------------------------------------------
 *
 * The symbol records, decoded, over the top of whatever the reader was looking
 * at. A DIALOG and not a pane, because it answers a question about the object
 * rather than about the bytes on screen: it is opened, read, and closed, and
 * the place the reader was does not move underneath them.
 *
 * The two tree rows show the same records as BYTES, which is what a signature
 * matches. This is the other half of that: the same block, read as what the
 * fields mean. Neither is the "real" one - a reader needs both, and needs to be
 * able to see that they are the same thing, which is why the dialog names the
 * row it is showing rather than inventing a third view of its own.
 */

/* Sized to the screen and then capped. The cap is not tidiness: past about a
 * hundred columns the fields are all in place and the rest is a very long gap
 * between the size and the name, which is harder to read down, not easier. */
static int symd_w(void)
{
	int w = g_cols - 4;

	/*
	 * Wider than it was, and the cap is now derived rather than picked.
	 *
	 * Reordering the columns to follow the record moved the NAME into the
	 * middle, where it has to be a fixed width - a variable column between
	 * fixed ones cannot be read down. So the box has to be wide enough to
	 * hold every column at full size or the name loses characters it did
	 * not have to lose: 5 rec, 8 type, 7 bind, 10 vis, 6 flags, 41 name,
	 * 6 sec, 13 size, 16 value, plus the border, a space and the border.
	 * That is 116 for a table with 64-bit values in it, and there is no
	 * reason to go past what the columns can use: a box wider than its
	 * content is a stripe of empty inside a border. A table whose values
	 * all fit in 32 bits needs twelve fewer, and those twelve fall at the
	 * right edge as a margin rather than being taken off the name - the
	 * name is data, the margin is not.
	 */
	return w > 116 ? 116 : w;
}

static int symd_h(void)
{
	int h = g_rows - 6;

	return h > 28 ? 28 : h;
}

static int symd_x(void) { return (g_cols - symd_w()) / 2 + 1; }
static int symd_y(void) { return (g_rows - symd_h()) / 2 + 1; }

/* How many record rows the box has: its height less the two borders, the tab
 * row and the column heading. */
int symd_rows(void)
{
	int r = symd_h() - 4;

	return r > 0 ? r : 0;
}

/* The block the dialog is showing. One block now, so the tab decides only which
 * half's records are listed - see symd_rows_of. */
static const uint8_t *symd_block(struct view *v, uint64_t *n)
{
	const struct object *o = cur_obj(v);

	if (n)
		*n = o->sym_n;
	return o->sym;
}

/*
 * THE RECORDS THE TAB LISTS, as block-record indices in reading order.
 *
 * The dialog used to index a block this file had built by copying one half out,
 * so its row n was that copy's record n. There is one block now and the half is
 * the engine's answer, so the rows are the record indices kof_sym_extents
 * covers. Kept in a static rather than rebuilt per row: at most
 * KOF_SYM_MAX_RECS of them, one dialog is open at a time, and the screen is
 * drawn from one thread.
 */
/*
 * Compile the filter when it is being read as a regex.
 *
 * kof_regex_compile is the engine's, the same one a rule's pattern goes
 * through, so what this dialog accepts and what a signature accepts cannot
 * drift. It refuses a pattern with no concrete run in it - that refusal is
 * about the PREFILTER a rule needs and is not interesting here, but the
 * alternative is a second regex implementation, which is worse than a filter
 * that occasionally says "not yet".
 *
 * A refusal leaves sy_frx_bad set and the list unfiltered, so half a pattern
 * does not read as a search that found nothing.
 */
void symd_filter_compile(struct view *v)
{
	v->sy_prog_n = 0;
	v->sy_frx_bad = 0;
	if (!v->sy_frx || !v->sy_filt[0])
		return;
	if (!rx_compile(v->sy_filt, v->sy_prog, (uint32_t)sizeof v->sy_prog,
			&v->sy_prog_n, v->sy_rx_err, sizeof v->sy_rx_err))
		v->sy_frx_bad = 1;
}

/*
 * Does this record's name pass the filter - see view.sy_filt.
 *
 * Three ways of asking one question, and the engine answers two of them. A
 * regex is compiled once when the text changes and walked here with
 * kof_hex_walk_flags, which is what the matcher itself walks, so a pattern
 * that selects rows in this dialog selects the same bytes written into a rule.
 * A plain filter is a substring test, folded or not.
 *
 * An empty filter passes everything, and so does a regex that would not
 * compile: a pattern half typed must not read as a search that found nothing.
 */
static int symd_name_ok(struct view *v, const uint8_t *blk, uint32_t nb,
			const uint8_t *rec)
{
	uint32_t i, n = 0;
	const char *name = kof_sym_name(blk, nb, rec, &n);

	if (!v->sy_filt[0])
		return 1;
	if (v->sy_frx) {
		kof_buf d;

		/*
		 * A PATTERN THAT WILL NOT COMPILE MATCHES NOTHING, and the
		 * dialog says why - see where sy_rx_err is drawn.
		 *
		 * It used to pass everything, on the reasoning that a
		 * half-typed pattern should not look like a search that found
		 * nothing. Measured against a reader: it looks like a search
		 * that found EVERYTHING, which is worse - `xmrig[\d]+Pool` is
		 * refused for the "+", and the whole symbol table came back
		 * looking like the answer.
		 */
		if (v->sy_frx_bad || !v->sy_prog_n)
			return 0;
		d = kof_buf_make((const uint8_t *)name, n);
		for (i = 0; i <= n; i++)
			if (kof_hex_walk_flags(d, i, v->sy_prog,
					       v->sy_ficase
					       ? (uint8_t)KOF_STR_ICASE : 0u))
				return 1;
		return 0;
	}
	{
		size_t fl = strlen(v->sy_filt);

		if (fl > n)
			return 0;
		for (i = 0; i + fl <= n; i++) {
			size_t k;

			for (k = 0; k < fl; k++) {
				char a = name[i + k], b = v->sy_filt[k];

				if (v->sy_ficase) {
					if (a >= 'A' && a <= 'Z')
						a = (char)(a + 32);
					if (b >= 'A' && b <= 'Z')
						b = (char)(b + 32);
				}
				if (a != b)
					break;
			}
			if (k == fl)
				return 1;
		}
	}
	return 0;
}

static uint32_t *symd_rows_of(struct view *v, uint32_t *n)
{
	static uint32_t idx[KOF_SYM_MAX_RECS];
	const struct object *o = cur_obj(v);
	uint32_t got, keep = 0, i;
	uint64_t nb = 0;
	const uint8_t *b;

	got = v->probe ? sym_half_recs(o, sym_row_mask(v->sym_open), v->probe,
				       KOF_SCAN_MAX_EXTENTS, idx,
				       (uint32_t)(sizeof idx / sizeof *idx))
		       : 0u;
	if (!v->sy_filt[0]) {
		*n = got;
		return idx;
	}
	/* In place and in order: the filter removes rows, it does not reorder
	 * them, and a reader who clears it should find the list where it was. */
	b = symd_block(v, &nb);
	for (i = 0; i < got; i++) {
		const uint8_t *r = b ? kof_sym_rec(b, (uint32_t)nb, idx[i])
				     : 0;

		if (r && symd_name_ok(v, b, (uint32_t)nb, r))
			idx[keep++] = idx[i];
	}
	*n = keep;
	return idx;
}

uint64_t symd_max(struct view *v)
{
	uint64_t nb = 0;
	const uint8_t *b;
	uint32_t n, rows = (uint32_t)symd_rows();

	/*
	 * The block is fetched on its OWN LINE, and this is not style.
	 *
	 * It was `kof_sym_count(symd_block(v, &nb), (uint32_t)nb)`, and the order
	 * in which a compiler evaluates two arguments is unspecified: `nb` was
	 * read while it was still zero, sym_count saw a length shorter than a
	 * header and answered zero records, and so this returned a maximum
	 * scroll of zero. Every scroll clamped straight back to the top and the
	 * dialog looked as though its keys were not wired up at all - while the
	 * keys were arriving and doing exactly what they were told.
	 */
	(void)b; (void)nb;
	symd_rows_of(v, &n);
	return n > rows ? n - rows : 0u;
}

static void symd_clamp(struct view *v)
{
	if (v->sym_at > symd_max(v))
		v->sym_at = symd_max(v);
}

/* A row of the box, from its left edge, so col_base + col_hint is an absolute
 * column and every click box recorded below lands where its text is. */
static void symd_row(struct out *o, int y)
{
	out_at(o, y, symd_x());
	o->col_hint = 0;
}

/*
 * Fill to the right border and draw it.
 *
 * Every row of the box has to reach its own edge. Positioning the cursor at
 * the edge and drawing the border there is NOT the same thing: the box sits on
 * top of the hex pane, so whatever the row did not write is still the pane's
 * bytes, and the tab row and the column heading showed a stripe of hex running
 * through the middle of the dialog. col_hint counts BYTES, which is why the box
 * glyphs go through out_glyph and this counts in it rather than in strlen.
 */
static void symd_edge(struct out *o, int w)
{
	while ((int)o->col_hint < w - 1)
		out_str(o, " ");
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF);
}

static void sclip_puts(struct sclip *c, const char *attr, const char *t)
{
	int on = 0;

	for (; *t; t++, c->vcol++) {
		if (c->vcol < c->from || c->vcol >= c->to)
			continue;
		if (!on) {
			out_str(c->o, attr);
			on = 1;
		}
		out_fmt(c->o, "%c", *t);
		if (c->rec && c->rec_n < DLG_COLS - 1)
			c->rec[c->rec_n++] = *t;
	}
	if (on)
		out_str(c->o, A_OFF);
}

static void sclip_fmt(struct sclip *c, const char *attr, const char *fmt, ...)
{
	char t[96];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	sclip_puts(c, attr, t);
}

/* The name, WHOLE, written clipped to `nw` columns and padded to them so the
 * columns after it line up. It is copied out before being written, never
 * passed as a string: nothing here turns autowrap off, so a name written past
 * the edge would wrap and overwrite the screen outside the box. */
static void sclip_name(struct sclip *c, const uint8_t *b, uint32_t nb,
		       const uint8_t *r, int nw, const char *attr)
{
	char t[KOF_SYM_NAME_MAX + 1];
	uint32_t len = 0;
	const char *nm = kof_sym_name(b, nb, r, &len);
	int k;

	if (nw > (int)KOF_SYM_NAME_MAX)
		nw = (int)KOF_SYM_NAME_MAX;
	for (k = 0; k < nw && (uint32_t)k < len; k++)
		t[k] = nm[k];
	for (; k < nw; k++)
		t[k] = ' ';
	t[k] = 0;
	sclip_puts(c, attr ? attr : A_S_NAME, t);
}

/* ---- selecting and copying a dialog's text ---------------------------------
 *
 * A character selection over the rows a dialog recorded while it drew them.
 * Shared by the symbols and shellcode boxes: both are tables of text a reader
 * wants to paste into a note, and neither is a hex pane whose selection means
 * an extent of a file.
 *
 * The selection is over the TEXT, not over what the text describes. Dragging
 * across a symbols row copies the row as it reads on screen - which is the
 * point, because that is what a reader is looking at when they decide to keep
 * it.
 */

/*
 * Closing a dialog drops the selection in it.
 *
 * One function because there are four places a box closes - two buttons, Escape
 * and q - and a selection left behind by any of them would be painted over
 * whatever box opened next, since the recorded rows are shared. Written as a
 * helper rather than two statements at each site: the first attempt WAS two
 * statements, one of them fell outside an unbraced `if`, and the compiler's
 * misleading-indentation warning is what caught it.
 */
void dlg_close(struct view *v)
{
	/* The filter field belongs to the dialog, so it goes with it: an edit
	 * code left standing would send the next keystroke to a box nobody can
	 * see. */
	if (v->edit == ED_SYMFILT)
		v->edit = 0;
	v->sym_open = 0;
	v->dlg_have = 0;
	v->dlg_drag = 0;
}

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

/* Take the row the clipper just wrote. */
static void dlg_rec_row(struct view *v, struct sclip *c)
{
	if (v->dlg_rows >= DLG_ROWS)
		return;
	c->rec[c->rec_n] = 0;
	dlg_index(v);
	v->dlg_rows++;
}

/* The buffer the next row should be recorded into, or NULL when full. */
/*
 * Record a row that is already plain text.
 *
 * The symbol table builds its rows column by column through sclip, which writes
 * into dlg_rec_buf as it clips - so it records as a side effect of drawing. A
 * page of pre-rendered lines has nothing to hook into: it draws one string and
 * the plain form of it is a separate call. This is that call, so both kinds of
 * dialog end up in the same recording and the same selection code serves them.
 */

/* Widen [*a, *b] on a recorded row to the word they land in. */

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

static char *dlg_rec_buf(struct view *v)
{
	return v->dlg_rows < DLG_ROWS ? v->dlg_line[v->dlg_rows] : 0;
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

void draw_symbols(struct out *o, struct view *v)
{
	int x = symd_x(), y = symd_y(), w = symd_w(), h = symd_h();
	int rows = symd_rows(), i;
	uint64_t nb = 0;
	const uint8_t *b = symd_block(v, &nb);
	uint32_t n = 0;
	const uint32_t *rec = symd_rows_of(v, &n);
	int wd = 8, sw, fixed, nw = 0, natural, vis, hmax;
	struct sclip sc;
	struct out_clip cl;
	const struct object *ob = cur_obj(v);

	if (w < 40 || h < 8)
		return;                 /* no room to draw a box honestly */

	/* The box, stated once. Every row below positions itself from x and w,
	 * and this is what says those two are the whole of it. */
	cl = out_clip_set(o, y, x, y + h - 1, x + w - 1);

	/*
	 * Re-clamped every frame rather than only when it is scrolled, because
	 * the box's height follows the terminal's: making the window taller
	 * shows more records, which moves the last legal offset, and an offset
	 * left past it would draw a table of blank rows.
	 */
	symd_clamp(v);

	/* Same rule as the pane: one width for the whole table, decided by the
	 * whole table, or the column cannot be read down. */
	for (i = 0; (uint32_t)i < n; i++) {
		const uint8_t *r = kof_sym_rec(b, (uint32_t)nb, rec[i]);

		if (r && (kof_sym_u64(r, KOF_SYM_R_VALUE) > 0xffffffffull ||
			  kof_sym_u64(r, KOF_SYM_R_SIZE) > 0xffffffffull)) {
			wd = 16;
			break;
		}
	}
	/*
	 * THE COLUMNS, IN THE ORDER THE RECORD STORES THEM.
	 *
	 * type, bind, vis, flags, name, sec, size, value - the same order as
	 * the bytes in the two SYM rows, so a reader moving between the dialog
	 * and the hex is reading the same sequence twice rather than mentally
	 * transposing it. It used to end value, size, sec, name, which was a
	 * different order from the block it describes.
	 *
	 * The name is a FIXED width because it is no longer last. A variable
	 * column with fixed ones after it cannot be read down - every row's
	 * sec, size and value would start somewhere else. It gets everything
	 * the other columns do not want.
	 */
	sw = wd == 16 ? 12 : 8;             /* the size column */
	/*
	 * The value column is wd + 2: the digits, plus the "0x" in front of
	 * them. Counted here rather than left out, because this number is what
	 * the name column's width is derived from - and a column budget that
	 * forgets a separator is what put a row through the border once
	 * already.
	 */
	fixed = 5 + 8 + 7 + 10 + 6 + 6 + (sw + 1) + (wd + 2);
	/*
	 * THE NAME COLUMN IS AS WIDE AS THE LONGEST NAME IN THIS TABLE, and no
	 * longer sized from what the box has left over.
	 *
	 * Sizing it from the box was what forced the choice between losing
	 * characters off the name and writing past the border. Sizing it from
	 * the DATA removes the choice: the row has one natural width, the box
	 * shows as much of it as it can, and the rest is reached by scrolling
	 * sideways. It also means a table of short names does not carry a
	 * forty-column gutter it never uses.
	 */
	for (i = 0; (uint32_t)i < n; i++) {
		const uint8_t *r = kof_sym_rec(b, (uint32_t)nb, rec[i]);
		uint32_t len = 0;

		if (!r)
			continue;
		(void)kof_sym_name(b, (uint32_t)nb, r, &len);
		if ((int)len > nw)
			nw = (int)len;
	}
	if (nw < 4)
		nw = 4;                     /* the heading says "name" */
	natural = fixed + nw + 1;
	vis = w - 3;
	hmax = natural > vis ? natural - vis : 0;
	if (v->sym_hoff > hmax)
		v->sym_hoff = hmax;
	if (v->sym_hoff < 0)
		v->sym_hoff = 0;
	sc.o = o;
	sc.from = v->sym_hoff;
	sc.to = v->sym_hoff + vis;
	sc.rec = 0;
	sc.rec_n = 0;
	/* Row 0 of the recording is the first RECORD row, not the heading: a
	 * heading is not something a reader selects, and starting the text at
	 * the first row of data is what lets dlg_at be a subtraction. */
	dlg_rec_begin(v, y + 3, x + 2);

	/* Top border, with the title sunk into it. */
	symd_row(o, y);
	out_str(o, A_DIM);
	out_glyph(o, G_TL);
	out_glyph(o, G_H);
	out_str(o, A_OFF A_BOLD " Symbols " A_OFF A_DIM);
	/*
	 * w - 12, counted rather than guessed: the row is one corner, one rule,
	 * the nine characters of " Symbols ", the fill, and the other corner -
	 * so the fill is w - 12 and the row comes to w. It was w - 13, which
	 * drew the box one column narrower at the top than every row under it,
	 * and than every other dialog in the tool.
	 */
	for (i = 0; i < w - 12; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_TR);
	out_str(o, A_OFF);

	/*
	 * The tabs and the close button.
	 *
	 * Both halves are always offered, even the empty one, and each says how
	 * many records it has. A tab that disappeared when it was empty would
	 * make "this object imports nothing" indistinguishable from "there is
	 * no imports tab in this build", and the count is the answer to the
	 * question the reader opened the dialog with.
	 */
	symd_row(o, y + 1);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF " ");
	for (i = 0; i < 2; i++) {
		uint8_t which = i ? SYMN_EXP : SYMN_IMP;
		/* How many records the half holds, counted by the engine's
		 * extents like the tree row's size is. */
		uint32_t cnt = v->probe
			     ? sym_half(ob, sym_row_mask(which), v->probe,
					KOF_SCAN_MAX_EXTENTS, 0)
			     : 0u;

		v->sy_tab[i][0] = o->col_base + (int)o->col_hint;
		out_fmt(o, "%s[ %s %u ]" A_OFF " ",
			v->sym_open == which ? A_SEL : A_ID,
			i ? "SYM_EXP" : "SYM_IMP", cnt);
		v->sy_tab[i][1] = o->col_base + (int)o->col_hint - 1;
	}
	/*
	 * THE FILTER, WHERE THE STATUS LINE USED TO BE.
	 *
	 * What was here - ".symtab, 1662 records, TRUNCATED" - said three
	 * things a reader already has: both counts are on the tabs beside it,
	 * the origin section is the same for every row in the dialog, and
	 * TRUNCATED is a property of the block that the tree row reports. What
	 * they were occupying is the only place in the dialog wide enough for
	 * the thing somebody with 1662 symbols in front of them actually wants.
	 *
	 */
	{
		int room = w - (int)o->col_hint - 34;

		if (room < 8)
			room = 8;
		if (room > (int)sizeof v->sy_filt - 1)
			room = (int)sizeof v->sy_filt - 1;
		/*
		 * NO MARKER IN FRONT OF THE FIELD. A "/" there was a label for
		 * something that needs none: the field is the only place in
		 * this row that takes typing, it sits after a gap wide enough
		 * to separate it from the tabs, and a character whose whole
		 * job is to say "this is a box" is a character a reader has to
		 * decide to ignore.
		 */
		out_str(o, "   ");
		v->sy_fbox[0] = o->col_base + (int)o->col_hint;
		/*
		 * A_SEL while it is being typed into, like every other field
		 * in this program; A_BAD when the regex will not compile, so
		 * the reason the list stopped narrowing is on the field that
		 * caused it rather than in a message somewhere else.
		 */
		/*
		 * THROUGH field_draw, like every other text box in this
		 * program. Painted by hand it had no caret, no scroll and no
		 * selection - and the keys that go with those were written by
		 * hand too, which is how Ctrl+A came to do nothing here while
		 * working everywhere else.
		 */
		out_str(o, v->edit == ED_SYMFILT ? A_SEL
			   : (v->sy_frx && v->sy_frx_bad) ? A_BAD : A_DIM);
		field_draw(o, v->sy_filt, v->caret, &v->sy_foff, room,
			   v->edit == ED_SYMFILT, "filter");
		out_str(o, A_OFF);
		v->sy_fbox[1] = o->col_base + (int)o->col_hint - 1;
		out_str(o, " ");
		v->sy_ic_box[0] = o->col_base + (int)o->col_hint;
		out_fmt(o, "%s[%s] icase" A_OFF, v->sy_ficase ? A_SEL : A_DIM,
			v->sy_ficase ? "x" : " ");
		v->sy_ic_box[1] = o->col_base + (int)o->col_hint - 1;
		out_str(o, " ");
		v->sy_rx_box[0] = o->col_base + (int)o->col_hint;
		out_fmt(o, "%s[%s] regex" A_OFF, v->sy_frx ? A_SEL : A_DIM,
			v->sy_frx ? "x" : " ");
		v->sy_rx_box[1] = o->col_base + (int)o->col_hint - 1;
	}
	(void)b; (void)nb; (void)n;
	/* The close button hard against the right edge, where a close button
	 * is, rather than after text whose length changes with the object. The
	 * gap in front of it is padded, not skipped - see symd_edge. */
	while ((int)o->col_hint < w - 6)
		out_str(o, " ");
	v->sy_close[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[x]" A_OFF, A_WARN);
	v->sy_close[1] = o->col_base + (int)o->col_hint - 1;
	symd_edge(o, w);

	/* Column heading, to the same widths and separators as the rows. */
	symd_row(o, y + 2);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF " ");
	/*
	 * sec is RIGHT-aligned, unlike every other text column here.
	 *
	 * Its values are the short ones - "UND", "ABS", or an index of one to
	 * five digits - and size beside it is a right-aligned number, so
	 * left-aligning sec pushed the two apart by the whole of its unused
	 * width plus the whole of size's leading padding: "ABS" and a size of
	 * 0 sat ten columns apart with nothing in between. Right-aligned, the
	 * two columns meet at their values, which is also how two adjacent
	 * numeric columns should read. The width is unchanged - this is where
	 * the characters sit in the field, not how wide the field is.
	 */
	sc.vcol = 0;
	/*
	 * ONE CALL PER COLUMN, exactly as the rows below do it.
	 *
	 * It was a single format string for the whole heading, and that
	 * silently lost the last column: sclip_fmt renders into a fixed buffer
	 * before clipping, and a heading with a forty-column name field runs
	 * past it, so "value" was truncated away by vsnprintf with nothing to
	 * show that it had been. Per column, no single piece can outgrow the
	 * buffer however wide the name gets, and the heading is built the same
	 * way as the row it labels - which is the only way the two stay in step.
	 */
	sclip_fmt(&sc, A_S_HEAD, "%-4s ",   "rec");
	sclip_fmt(&sc, A_S_HEAD, "%-7s ",   "type");
	sclip_fmt(&sc, A_S_HEAD, "%-6s ",   "bind");
	sclip_fmt(&sc, A_S_HEAD, "%-9s ",   "vis");
	sclip_fmt(&sc, A_S_HEAD, "%-5s ",   "flags");
	sclip_fmt(&sc, A_S_HEAD, "%-*.*s ", nw, nw, "name");
	sclip_fmt(&sc, A_S_HEAD, "%5s ",    "sec");
	sclip_fmt(&sc, A_S_HEAD, "%*s ",    sw, "size");
	sclip_fmt(&sc, A_S_HEAD, "%*s",     wd + 2, "value");
	symd_edge(o, w);

	for (i = 0; i < rows; i++) {
		uint64_t at = v->sym_at + (uint64_t)i;
		const uint8_t *r = (at < (uint64_t)n)
				 ? kof_sym_rec(b, (uint32_t)nb, rec[at]) : 0;
		char fl[8], shn[8];
		const char *mark;

		symd_row(o, y + 3 + i);
		out_str(o, A_DIM);
		out_glyph(o, G_V);
		out_str(o, A_OFF " ");
		sc.rec = dlg_rec_buf(v);
		sc.rec_n = 0;

		if (!r) {
			/*
			 * WHY THERE IS NOTHING, on the first empty row and only
			 * there. A filter that refuses every record looks
			 * identical to a table with no records in it, and when
			 * the reason is a regex the compiler would not take,
			 * the reader needs the compiler's own words - see
			 * rx_compile, which copies them out.
			 */
			if (i == 0 && v->sy_frx && v->sy_frx_bad &&
			    v->sy_rx_err[0])
				sclip_fmt(&sc, A_BAD, "%s", v->sy_rx_err);
			else if (i == 0 && v->sy_filt[0] && n == 0)
				sclip_fmt(&sc, A_DIM, "%s",
					  "no symbol matches the filter");
			/* Otherwise nothing to draw, and the row still has to
			 * be blanked INSIDE the border: the box is over other
			 * content, and a clear-to-end-of-line would take the
			 * rest of the screen with it. symd_edge does it. */
		} else {
			sym_flag_str(r[KOF_SYM_R_FLAGS], fl);
			sym_shn_str(r, shn, sizeof shn);
			/*
			 * IS THIS THE ROW A HEURISTIC NAMED.
			 *
			 * Compared on the symbol's own VALUE against what the
			 * rule reported - which is exactly why the rule reports
			 * a value and not a record index. This table is the
			 * SPLIT one, imports and exports renumbered from zero,
			 * so an index taken from the engine's block would name
			 * the wrong row here.
			 *
			 * Nothing in this file repeats the test kofscfind made.
			 * It only asks "was it this one", which is what keeps
			 * the two from ever disagreeing about the answer.
			 *
			 * payload_at is guarded because the analysis may find
			 * nothing and zero IS a real symbol value - every
			 * undefined symbol has it - so "no payload" must not be
			 * spelled as an address.
			 */
			mark = (ob->payload_at &&
				kof_sym_u64(r, KOF_SYM_R_VALUE) == ob->payload_at)
			       ? A_S_FOUND : 0;
			sc.vcol = 0;
			/*
			 * DECIMAL, unlike everything else here. It is not a
			 * number the file contains - it is how many records in
			 * this one is, which the reader counts rather than
			 * reads - and printing a count in hex invites it to be
			 * read as an offset into something.
			 */
			sclip_fmt(&sc, mark ? mark : A_S_IDX, "%4llu ",
				  (unsigned long long)at);
			sclip_fmt(&sc, mark ? mark : A_S_TYPE, "%-7s ",
				  kof_sym_type_name(r[KOF_SYM_R_TYPE]));
			sclip_fmt(&sc, mark ? mark : A_S_BIND, "%-6s ",
				  kof_sym_bind_name(r[KOF_SYM_R_BIND]));
			sclip_fmt(&sc, mark ? mark : A_S_VIS, "%-9s ",
				  kof_sym_vis_name(r[KOF_SYM_R_VIS]));
			sclip_fmt(&sc, mark ? mark : A_S_FLAG, "%-5s ", fl);
			/*
			 * The name, in the middle now, and PADDED TO nw so the
			 * three columns after it line up.
			 *
			 * Printed as the bytes the record holds rather than as
			 * a C string: it is NUL-padded to a fixed 40 and not
			 * necessarily terminated, so a %s would run into the
			 * next field. Clipped to nw for the same reason it is
			 * padded to it - nothing here turns autowrap off, so a
			 * name written past the edge would wrap and overwrite
			 * the screen outside the box.
			 */
			sclip_name(&sc, b, (uint32_t)nb, r, nw, mark);
			sclip_puts(&sc, A_OFF, " ");
			sclip_fmt(&sc, mark ? mark : A_S_SHN, "%5s ", shn);
			sclip_fmt(&sc, mark ? mark : A_S_SIZE, "%*llu ", sw,
				  (unsigned long long)kof_sym_u64(r,
							KOF_SYM_R_SIZE));
			/* "0x", because this one IS a number out of the file
			 * and an address at that - and it now sits next to a
			 * decimal size and a decimal record number, where an
			 * unmarked base is a guess. */
			sclip_fmt(&sc, mark ? mark : A_S_VAL, "0x%0*llx", wd,
				  (unsigned long long)kof_sym_u64(r,
							KOF_SYM_R_VALUE));
		}
		symd_edge(o, w);
		if (sc.rec) {
			dlg_rec_row(v, &sc);
			dlg_rec_src(v, (uint32_t)at);   /* what dlg_row_of_src() looks rows up by */
		}
	}

	/* Bottom border. */
	symd_row(o, y + h - 1);
	out_str(o, A_DIM);
	out_glyph(o, G_BL);
	for (i = 0; i < w - 2; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_BR);
	out_str(o, A_OFF);

	/*
	 * The scrollbar ON the right border, not inside it.
	 *
	 * Inside, it drew a second vertical line one column in from the first,
	 * and since the track is the same dim U+2502 as the border the pair
	 * read as a doubled border with a bright spot in it rather than as a
	 * scrollbar. On the border there is one line, and the bold thumb says
	 * where in the table the reader is. Drawn last so it replaces the
	 * border on the rows it covers, and only when there is more than fits -
	 * the same rule the panes use.
	 */
	if (n > (uint32_t)rows)
		kv_scrollbar(o, x + w - 1, y + 3, y + 3 + rows - 1,
			  v->sym_at, n, (uint64_t)rows);
	/* Last, so the selection is over everything else the box drew. */
	dlg_paint_sel(o, v);
	out_clip_restore(o, cl);
}

/*
 * A click in the dialog. Returns non-zero when it was the dialog's, which is
 * how the caller knows not to route it on to whatever is underneath.
 *
 * EVERY click is swallowed while it is up, inside the box or outside it, which
 * is what makes it a modal rather than a floating panel. Two reasons, and the
 * second is the one that matters: a click on a record must not fall through and
 * select a byte in the pane behind it, and a click on the TREE must not move
 * the cursor to another object - the dialog shows the symbols of whichever
 * object is selected, so that would silently replace the table being read with
 * a different one. Closing is [x], Escape or q.
 */
int symd_click(struct view *v)
{
	int y = symd_y(), i;

	if (g_my == y + 1) {
		if (g_mx >= v->sy_close[0] && g_mx <= v->sy_close[1]) {
			dlg_close(v);
			return 1;
		}
		for (i = 0; i < 2; i++)
			if (g_mx >= v->sy_tab[i][0] &&
			    g_mx <= v->sy_tab[i][1]) {
				uint8_t which = i ? SYMN_EXP : SYMN_IMP;

				/* Switching tabs goes back to the top. The
				 * offset is a position in THIS table and means
				 * somewhere else in the other one. */
				if (v->sym_open != which) {
					v->sym_open = which;
					v->sym_at = 0;
					v->sym_hoff = 0;
				}
				return 1;
			}
		/*
		 * The filter and its two ticks, on the same row as the tabs.
		 * Each moves the list back to the top: an offset is a position
		 * in the rows the filter was showing and means somewhere else
		 * in the rows it shows now.
		 */
		if (g_mx >= v->sy_fbox[0] && g_mx <= v->sy_fbox[1]) {
			v->edit = ED_SYMFILT;
			return 1;
		}
		if (g_mx >= v->sy_ic_box[0] && g_mx <= v->sy_ic_box[1]) {
			v->sy_ficase = !v->sy_ficase;
			v->sym_at = 0;
			return 1;
		}
		if (g_mx >= v->sy_rx_box[0] && g_mx <= v->sy_rx_box[1]) {
			v->sy_frx = !v->sy_frx;
			symd_filter_compile(v);
			v->sym_at = 0;
			return 1;
		}
	}
	return 1;
}

/*
 * Sideways, in columns, positive to the right.
 *
 * The upper bound is NOT clamped here: it depends on the longest name in the
 * table and on the box's width, both of which draw_symbols works out, so it
 * clamps there on the way past. Clamping in two places from two different
 * derivations is how the two end up disagreeing.
 */
void symd_hscroll(struct view *v, int d)
{
	v->sym_hoff += d;
	if (v->sym_hoff < 0)
		v->sym_hoff = 0;
}

/* The wheel and the keys, in one place so they cannot disagree about the
 * clamp. `d` is in records, positive downwards. */
void symd_scroll(struct view *v, int64_t d)
{
	uint64_t max = symd_max(v);

	if (d < 0) {
		uint64_t up = (uint64_t)(-d);

		v->sym_at = v->sym_at > up ? v->sym_at - up : 0;
	} else {
		v->sym_at += (uint64_t)d;
	}
	if (v->sym_at > max)
		v->sym_at = max;
}

/*
 * Open the dialog on the half that has something in it.
 *
 * Exports first because that is what almost every object has and what a reader
 * asking about a shellcode loader is after, but an object with only imports -
 * a stripped dynamic executable, which is most of them - opens on imports
 * rather than on an empty table it has to be told to leave.
 */
void symd_open(struct view *v)
{
	const struct object *o = cur_obj(v);

	v->sym_at = 0;
	v->sym_hoff = 0;
	/* Exports first when there are any, since that is the half a reader
	 * opening this is usually after. Both counts come from the engine.
	 * That there ARE any is bar_enabled's to decide - see bar_why_off. */
	v->sym_open = SYMN_EXP;
	if (v->probe &&
	    !sym_half(o, KOF_SCAN_SYM_EXP, v->probe, KOF_SCAN_MAX_EXTENTS, 0) &&
	    sym_half(o, KOF_SCAN_SYM_IMP, v->probe, KOF_SCAN_MAX_EXTENTS, 0))
		v->sym_open = SYMN_IMP;
}
