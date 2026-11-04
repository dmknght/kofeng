#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The draft panel's Strings table (the Intron rows), the unit cells and the item lists a matcher row shares (glist_*). */

/* Defined below; a row registers its own callback before the callback is written. */
static void hit_row_str(struct view *v, uint32_t i);
static void hit_row_markers(struct view *v, uint32_t g);
static void hit_row_strhdr(struct view *v, uint32_t arg);
static void hit_row_addstr(struct view *v, uint32_t arg);
static void draw_tag_cell(struct out *o, struct view *v, const char *tag);
static uint32_t glist_hit(const int (*span)[2], uint32_t n);


static void hit_row_str(struct view *v, uint32_t i)
{
	if (i >= v->ed.dr.n_decl || i >= v->cap_str_col)
		return;
	v->ed.dr.sel_decl = i;
	if (g_mx >= g_cols - (int)STR_BTN_X) {
		decl_remove(&v->ed, i);
	} else if (g_mx >= g_cols - (int)STR_BTN_E &&
		   g_mx < g_cols - (int)STR_BTN_E + 3) {
		decl_edit_open(v, i);
	} else if (v->ed.dr.decl[i].n_hits > 1u &&
		   g_mx >= g_cols - (int)STR_BTN_PREV &&
		   g_mx < g_cols - (int)STR_BTN_PREV
			   + 3) {
		struct decl *d = &v->ed.dr.decl[i];

		d->cur_hit = (d->cur_hit + d->n_hits
			      - 1u) % d->n_hits;
		view_show_decl(v, d, d->hits[d->cur_hit]);
	} else if (v->ed.dr.decl[i].n_hits > 1u &&
		   g_mx >= g_cols - (int)STR_BTN_NEXT &&
		   g_mx < g_cols - (int)STR_BTN_NEXT
			   + 3) {
		struct decl *d = &v->ed.dr.decl[i];

		d->cur_hit = (d->cur_hit + 1u)
			     % d->n_hits;
		view_show_decl(v, d, d->hits[d->cur_hit]);
	} else if (v->edit == ED_STR + (int)i &&
		   g_mx >= v->str_by[i][0]) {
		/* A click inside the open field is a click in a text box, not
		 * a request to jump to the bytes. */
		return;
	} else if (v->str_wc[i][0] >= 0 &&
		   g_mx >= v->str_wc[i][0] &&
		   g_mx <= v->str_wc[i][1]) {
		/*
		 * ONE CELL, ONE LIST. It was two zones ten columns apart
		 * behind two lists; both attributes are now in one cell and
		 * in one form, and a regex records no zone at all - see where
		 * the columns are drawn.
		 */
		ch_open(v, CH_ATTR, i, g_my, g_mx);
	} else if (g_mx >= v->str_by[i][0] &&
		   g_mx <= v->str_by[i][1]) {
		/*
		 * The bytes are the one part of the row
		 * that names a place, so clicking them
		 * goes there - and the pane lights the
		 * run, which is the confirmation that
		 * it is the right one.
		 */
		/*
		 * BACK TO THE ONE YOU WERE ON.
		 *
		 * Not to the first: after stepping to
		 * an occurrence and scrolling the pane
		 * elsewhere, clicking the row is how
		 * you return to it. The first is where
		 * cur_hit starts, so nothing changes
		 * for a marker that occurs once.
		 */
		struct decl *d = &v->ed.dr.decl[i];

		if (d->n_hits) {
			if (d->cur_hit >= d->n_hits)
				d->cur_hit = 0;
			view_show_decl(v, d, d->hits[d->cur_hit]);
		} else if (d->at != KGENOME_BROKEN) {
			view_show_decl(v, d, d->at);
		} else {
			say_note(&v->ed, "String %u is "
				 "not in this object",
				 i + 1u);
		}
	}
}

static void hit_row_markers(struct view *v, uint32_t g)
{
	uint32_t i, slot;

	v->ed.dr.cur_grp = g;
	/*
	 * THE BUTTON THAT ADDS ONE, at the end of the row: it offers the
	 * markers this matcher has not taken.
	 */
	if (v->p_c0[g][0] > 0 && g_mx >= v->p_c0[g][0] &&
	    g_mx <= v->p_c0[g][1]) {
		ch_open(v, CH_MARKER, g, g_my, g_mx);
		return;
	}
	/*
	 * A MARKER ON THIS ROW IS TAKEN BACK OUT BY CLICKING IT.
	 *
	 * READ BACK FROM WHERE IT WAS DRAWN. This used to re-derive the
	 * columns - three apiece, which assumed every id was one digit. From the
	 * first two-digit id on, every id after it drifted a
	 * column left and the click removed the wrong marker or none. The
	 * drawing records each span now - see grp_list - so there is one copy
	 * of the arithmetic and it is the one that painted the row.
	 */
	if (!v->grp_it[g])
		return;
	slot = glist_hit(v->grp_it[g], v->cap_str_col);
	if (slot >= v->cap_str_col)
		return;
	/* The slot is a position in the row, so the marker it names is found
	 * by walking the declarations in the order the row drew them. */
	for (i = 0; i < v->ed.dr.n_decl; i++) {
		if (!(v->ed.dr.decl[i].grp & (1u << g)))
			continue;
		if (!slot--) {
			v->ed.dr.decl[i].grp &= ~(1u << g);
			return;
		}
	}
}

/* The Intron heading carries [Update string regions] - see where it is
 * drawn. */
static void hit_row_strhdr(struct view *v, uint32_t arg)
{
	(void)arg;
	if (g_mx >= v->rgf_c0 && g_mx <= v->rgf_c1) {
		draft_refresh(&v->ed);
		return;
	}
	/*
	 * A MARKER WRITTEN RATHER THAN FOUND - see BTN_ADDSTR.
	 *
	 * The declaration is created empty and opened for editing straight
	 * away, because an empty marker is not a state worth leaving behind:
	 * the reader pressed this to type something, and a row that appeared
	 * with nothing in it and no caret would be a row they then have to
	 * find a way into.
	 *
	 * `at` is KGENOME_BROKEN - the bytes are not in this object and may never
	 * be. That is a state struct decl already has, for a marker carried
	 * from another sample, and the table already draws it as "not here"
	 * rather than as an error.
	 */
}

/*
 * THE ROW AT THE FOOT OF THE STRINGS TABLE - see BTN_ADDSTR.
 *
 * Its own handler because it is its own row now. It was a column range tested
 * inside the HEADING's handler, which is where the button used to be drawn;
 * moving the button and leaving the test behind would have left a heading that
 * still created a marker when clicked near the middle.
 */
static void hit_row_addstr(struct view *v, uint32_t arg)
{
	(void)arg;
	/* WHICH KIND, asked before anything is created - see CH_DECLKIND. The
	 * three are not variations on one declaration: they are compiled by
	 * different front ends and spelled in different fields. */
	ch_open(v, CH_DECLKIND, 0, g_my, g_mx);
	return;
}

/*
 * draw_decl_strings - the markers, and the column widths they decide.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
/*
 * ROOM FOR `rows` STRING ROWS' COLUMNS, and for the item spans of every matcher's marker list (a matcher may name any marker).
 * The columns are recorded as they are drawn, so nothing here needs the old values: a fresh set replaces the old one whole or not at all,
 * and a refusal is said on the draft's line (say_err) and leaves the arrays as they were. Answers 1 when `rows` fit.
 */
int decl_cols_reserve(struct view *v, uint32_t rows)
{
	int (*wc)[2] = NULL, (*by)[2] = NULL, (*it[MAX_GROUP])[2];
	uint32_t g, n;

	if (rows <= v->cap_str_col && v->str_wc)
		return 1;
	n = v->cap_str_col ? v->cap_str_col : 16u;
	while (n < rows && n <= UINT32_MAX / 2u)
		n *= 2u;
	if (n < rows)
		n = rows;
	memset(it, 0, sizeof it);
	wc = malloc((size_t)n * sizeof *wc);
	by = malloc((size_t)n * sizeof *by);
	for (g = 0; g < MAX_GROUP; g++)
		it[g] = malloc((size_t)n * sizeof *it[g]);
	for (g = 0; g < MAX_GROUP && it[g]; g++)
		;
	if (!wc || !by || g < MAX_GROUP) {
		free(wc);
		free(by);
		for (g = 0; g < MAX_GROUP; g++)
			free(it[g]);
		say_err(&v->ed, "out of memory: the strings table cannot record the columns of %u rows, the rows past %u are not drawn", rows, v->cap_str_col);
		return 0;
	}
	memset(wc, 0xff, (size_t)n * sizeof *wc);
	memset(by, 0xff, (size_t)n * sizeof *by);
	free(v->str_wc);
	free(v->str_by);
	v->str_wc = wc;
	v->str_by = by;
	for (g = 0; g < MAX_GROUP; g++) {
		memset(it[g], 0xff, (size_t)n * sizeof *it[g]);
		free(v->grp_it[g]);
		v->grp_it[g] = it[g];
	}
	v->cap_str_col = n;
	return 1;
}

void decl_cols_free(struct view *v)
{
	uint32_t g;

	free(v->str_wc);
	free(v->str_by);
	v->str_wc = v->str_by = NULL;
	for (g = 0; g < MAX_GROUP; g++) {
		free(v->grp_it[g]);
		v->grp_it[g] = NULL;
	}
	v->cap_str_col = 0;
}

int draw_decl_strings(struct out *o, struct view *v, int r)
{
	uint32_t i, rows = v->ed.dr.n_decl;

	/* The rows that have columns to record are drawn; the rest are said (below), never dropped without a word. */
	if (!decl_cols_reserve(v, rows))
		rows = v->str_wc ? v->cap_str_col : 0u;

	/*
	 * The strings.
	 *
	 * "found in" rather than a bare region name: a string's region is where
	 * it WAS, and a matcher's range is where it will be LOOKED FOR. The two
	 * use the same words and are not the same fact, and the row that states
	 * provenance should not read like the row that states a search.
	 */
	/* A column heading instead of a preposition on every row: "found in
	 * CODE" said the same word once per string and read like a sentence
	 * where a table belongs. */
	/*
	 * How wide the region column has to be, asked of the rows rather than
	 * guessed.
	 *
	 * It was a fixed eighteen, sized for the widest label the column can
	 * ever hold - "UNCLAIMED>UNCLAIMED" and the like. Almost no draft has
	 * one, so almost every draft showed a region of four or five characters
	 * followed by a dozen spaces and then its size: two facts about the same
	 * marker, sitting at opposite ends of a gap.
	 *
	 * Measured once per frame over every row, so the columns still line up
	 * with each other - which is the thing a fixed width was there to buy -
	 * and the gap is only ever as wide as some row actually needs.
	 */
	{
		/*
		 * Six for the word "region", plus a space and the [r] button
		 * that now sits beside it - the heading has to fit in the
		 * column it names, or the button would land on "size".
		 */
		uint32_t w = 6u + 1u + (uint32_t)(sizeof BTN_UPDRGN - 1);

		for (i = 0; i < v->ed.dr.n_decl; i++) {
			const struct decl *d = &v->ed.dr.decl[i];
			uint32_t n = (uint32_t)strlen(d->rgn);

			if (d->off_rgn)
				n += 1u + (uint32_t)strlen(d->at_rgn);
			if (n > w)
				w = n;
		}
		v->rgn_w = (int)(w > 18u ? 18u : w);
	}
	/*
	 * DRAWN EVEN WITH NOTHING IN IT - see BTN_ADDSTR. An empty table is
	 * exactly when the button that fills it has to be reachable.
	 */
	if (PR_VIS(r)) {
		char hdr[120];
		uint32_t d2, off = 0;
		int c0;

		/* The heading follows the column, so the two cannot drift. */
		snprintf(hdr, sizeof hdr, STR_HDR_PRE "%*ssize  bytes",
			 v->rgn_w - 6 + 1, "");
		sec_bar(o, v, PR(r), hdr);
		/*
		 * [Update string regions] BELONGS HERE, beside the column it is
		 * about.
		 *
		 * It used to sit on the scan ranges row next to a control about
		 * a matcher's range, and the two read as one pair - but a
		 * string's region is where it WAS FOUND and a matcher's range is
		 * where it will be LOOKED FOR, which is the distinction this
		 * panel spends two column headings making. The button that
		 * re-locates strings goes with the strings.
		 */
		for (d2 = 0; d2 < v->ed.dr.n_decl; d2++)
			off += (uint32_t)(v->ed.dr.decl[d2].off_rgn != 0);
		/*
		 * PLACED PAST THE HEADING, never over it.
		 *
		 * sec_bar has already drawn the heading and padded the rest of
		 * the row with its own background, so the button is written
		 * onto that padding - positioned at the column after the text.
		 *
		 * Repositioning to column one and writing spaces to get there
		 * is what the first attempt did, and it blanked the heading it
		 * was supposed to sit beside: the whole title, "region" column
		 * and all, became a row of spaces with one button on it.
		 */
		{
			int w = (int)sizeof BTN_UPDRGN - 1;
			/*
			 * One column after the word "region", which is inside
			 * the region column's own width - rgn_w is held at a
			 * minimum that leaves room for it, so the heading and
			 * the data rows below still share one column layout.
			 */
			int bcol = (int)sizeof STR_HDR_PRE + 1;

			if (bcol + w <= g_cols) {
				out_at(o, PR(r), bcol);
				o->col_hint = 0;
				c0 = o->col_base;
				out_fmt(o, "%s%s" A_OFF,
					off ? "\033[43;30m" : "\033[100;37m",
					BTN_UPDRGN);
				v->rgf_c0 = c0;
				v->rgf_c1 = o->col_base + (int)o->col_hint - 1;
			} else {
				/* No room on this width: no button, and no
				 * stale columns left answering clicks. */
				v->rgf_c0 = v->rgf_c1 = -1;
			}
		}
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_strhdr, 0);
	} else {
		v->rgf_c0 = v->rgf_c1 = -1;
	}
	r += 1;
	v->row_str = PR(r);
	for (i = 0; i < rows; i++, r++) {
		const struct decl *d = &v->ed.dr.decl[i];
		uint32_t k;
		char sz[24];

		if (!PR_VIS(r)) {
			/*
			 * A ROW THAT IS NOT DRAWN HAS NO CLICK TARGETS.
			 *
			 * Left at last frame's columns, a scrolled-out row's
			 * ranges still answer a click - so a press at those
			 * columns on whatever row now sits there acted on THIS
			 * marker, which is the failure the per-row recording
			 * exists to prevent (see the note on grp_nt). The
			 * condition loop below already clears its own.
			 */
			v->str_wc[i][0] = v->str_wc[i][1] = -1;
			v->str_by[i][0] = v->str_by[i][1] = -1;
			continue;
		}
		row_start(o, PR(r), 1);
		/* Right aligned in a fixed width, so the columns after it do
		 * not step sideways when the list reaches ten. A third digit
		 * widens the cell, and the columns that follow are read back from
		 * where they were drawn (col_hint), so nothing is measured twice. */
		out_fmt(o, "  %s%2u." A_OFF " %s%-4s" A_OFF " ",
			i == v->ed.dr.sel_decl ? A_SEL : A_DIM, i + 1u,
			A_ID, d->hex ? "hex" : "str");
		v->str_wc[i][0] = 1 + (int)o->col_hint;
		/*
		 * A HEX PATTERN SHOWS ITS OPTIONS TOO, AND USED TO SHOW BLANK.
		 *
		 * It could carry none when this was written, so the two columns
		 * were left empty and the click targets refused the row. Both
		 * are real for it now: a hex marker that spells text is still a
		 * word, and "is it a word on its own" is still worth asking.
		 *
		 * DIMMED WHERE NOTHING WAS CHOSEN, which is most hex rows. A
		 * byte pattern has no case and no word to be part of, so
		 * "pattern exact-case" on every shellcode row would be noise on
		 * the many to serve the few - the same reason the generator
		 * writes the short form for them. Dim says "this is the default
		 * and it is here if you want it"; the normal colour says a
		 * choice was made. The control is there either way.
		 */
		{
			char attr[16];

			decl_attr_text(d, attr, sizeof attr);
			/*
			 * THE SAME ROWS DIM AS BEFORE THE TWO COLUMNS BECAME
			 * ONE: a hex marker that chose neither attribute.
			 * Dim says "this is the default and it is here if you
			 * want it"; the normal colour says a choice was made.
			 *
			 * A regex is dim as well, for a different reason: its
			 * cell is a dash because the fields do not apply to
			 * it, and there is nothing there to light up.
			 */
			out_fmt(o, "%s%-*s" A_OFF,
				(d->hex == DECL_HEX && decl_attr_default(d)) ||
				!decl_has_attr(d) ? A_DIM : A_WARN,
				STR_ATTR_W, attr);
		}
		/*
		 * NO CLICK TARGET ON A REGEX ROW. The columns are recorded
		 * only for a marker the list can say something about, so a
		 * press lands on the row rather than opening a form onto two
		 * fields the matcher never reads.
		 */
		if (!decl_has_attr(d))
			v->str_wc[i][0] = -1;
		v->str_wc[i][1] = (int)o->col_hint;
		/*
		 * The declared range, or - when the bytes are somewhere else
		 * entirely - both, in the colour that says look at this.
		 *
		 * "DATA" alone is what this said for a marker whose bytes are
		 * in CODE, and it is why a rule that cannot possibly fire read
		 * as correct on every row. The arrow is the whole diagnosis:
		 * searched there, found here.
		 */
		/*
		 * HOW MUCH OF THE FILE IT COVERS, WHICH MAY BE A RANGE.
		 *
		 * "6A 40 [4-6] 8D 4D" is six bytes long, or seven, or eight -
		 * the compiler answers both ends and the column shows both,
		 * because one number would have to be the wrong one.
		 */
		if (d->span_max > d->len)
			snprintf(sz, sizeof sz, "%u-%u", d->len, d->span_max);
		else
			snprintf(sz, sizeof sz, "%u", d->len);
		if (d->at == KGENOME_BROKEN) {
			/*
			 * Declared, and not in this object.
			 *
			 * GREY, not red. The colour is the whole message - the
			 * region stays because that is still where the module
			 * will look - but "absent" is the quiet case: nothing is
			 * wrong with the file, this marker simply is not in it.
			 * Red said "look at me" on every row of a rule being
			 * read against a sample it was not written for, which is
			 * most of them; dim says it without shouting, and is
			 * still far enough off the background to read.
			 */
			out_fmt(o, " %s%-*.*s" A_OFF " %s%5s" A_OFF "  ",
				A_DIM, v->rgn_w, v->rgn_w, d->rgn,
				A_SIZE, sz);
		} else if (d->off_rgn) {
			char both[2 * sizeof d->rgn + 2];

			snprintf(both, sizeof both, "%s>%s", d->rgn,
				 d->at_rgn);
			out_fmt(o, " %s%-*.*s" A_OFF " %s%5s" A_OFF "  ",
				A_WARN, v->rgn_w, v->rgn_w, both,
				A_SIZE, sz);
		} else {
			/* PRESENT: the marker is in the file, shown in the location colour. */
			out_fmt(o, " %s%-*.*s" A_OFF " %s%5s" A_OFF "  ",
				A_LOC,
				v->rgn_w, v->rgn_w, d->rgn,
				A_SIZE, sz);
		}
		v->str_by[i][0] = 1 + (int)o->col_hint;
		if (v->edit == ED_STR + (int)i) {
			/*
			 * The value, in the column the value was in.
			 *
			 * Editing in place rather than in a dialog: the row
			 * around it is the context - which region, how long,
			 * whether it was found - and a box over the top of that
			 * would hide the things being edited against.
			 */
			int room = g_cols - (int)(d->n_hits > 1u
						  ? STR_BTN_PREV + 1u
						  : STR_BTN_E + 1u)
				   - v->str_by[i][0];

			if (room < 8)
				room = 8;
			/*
			 * IN A_SEL, LIKE EVERY OTHER OPEN FIELD.
			 *
			 * This was the one box on the panel drawn without it -
			 * the family name, the comment, the variant and both
			 * dialog fields all light up when they take the caret,
			 * and the pattern, which is the field a researcher
			 * spends the most time in, did not. It read as text
			 * that happened to be on the row rather than as a
			 * control that is open.
			 *
			 * field_draw needs it too: a selection inside the box
			 * is drawn by CANCELLING the reverse, which is what
			 * makes it visible against it.
			 */
			out_str(o, A_SEL);
			field_draw(o, v->ed.dr.sedit, v->caret, &v->ed.dr.sedit_off, room,
				   1, d->hex ? "hex pairs" : "text");
			out_str(o, A_OFF);
		} else if (d->hexs[0]) {
			uint32_t n = (uint32_t)strlen(d->hexs);
			uint32_t from = v->decl_hoff > n ? n : v->decl_hoff;

			out_fmt(o, "%.32s", d->hexs + from);
			if (n > from + 32u)
				out_str(o, "...");
		} else {
			uint32_t from = v->decl_hoff / 2u;

			if (from > d->nbytes)
				from = d->nbytes;
			for (k = from; k < d->nbytes && k < from + 16u; k++)
				out_fmt(o, "%02X", d->bytes[k]);
			if (d->nbytes > from + 16u)
				out_str(o, "...");
		}
		v->str_by[i][1] = (int)o->col_hint;
		/*
		 * Edit before delete, and in a colour that is not the delete's.
		 *
		 * The order is the order of how much they cost to be wrong
		 * about: the reachable-by-accident end of the row should be the
		 * one that can be undone by typing, not the one that removes a
		 * marker. Red stays reserved for the button that destroys.
		 */
		if (d->n_hits > 1u) {
			char cnt[8];

			out_at(o, PR(r), g_cols - (int)STR_BTN_PREV);
			out_fmt(o, "%s[<]" A_OFF, A_ID);
			snprintf(cnt, sizeof cnt, "%u/%u%s",
				 d->cur_hit + 1u, d->n_hits,
				 d->hits_clipped ? "+" : "");
			out_at(o, PR(r), g_cols - (int)STR_CNT);
			/* "cur/total+" is at most "64/64+", six wide: the plus says
			 * the hit list was clipped (DECL_HITS_MAX) and must show.
			 * The field is the 19..14 columns from the right, the gap
			 * to [>] absorbs the sixth. */
			out_fmt(o, A_DIM "%6.6s" A_OFF, cnt);
			out_at(o, PR(r), g_cols - (int)STR_BTN_NEXT);
			out_fmt(o, "%s[>]" A_OFF, A_ID);
		}
		out_at(o, PR(r), g_cols - (int)STR_BTN_E);
		out_fmt(o, "%s[e]" A_OFF,
			v->edit == ED_STR + (int)i ? A_SEL : A_ID);
		out_at(o, PR(r), g_cols - (int)STR_BTN_X);
		out_str(o, A_BAD "[x]" A_OFF);
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_str, i);
	}

	if (rows < v->ed.dr.n_decl) {
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			out_fmt(o, "  " A_BAD "%u more marker(s) not drawn: out of memory" A_OFF, v->ed.dr.n_decl - rows);
			hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
		}
		r++;
	}

	/*
	 * AND THE ROW THAT ADDS ONE, closing the table - the shape the matchers
	 * and the conditions already have, and the reason it is not on the
	 * heading any more is written beside BTN_ADDSTR.
	 */
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->adds_c0 = 2;
		out_fmt(o, " " A_ID "%s" A_OFF, BTN_ADDSTR);
		v->adds_c1 = (int)o->col_hint;
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_addstr, 0);
	} else {
		v->adds_c0 = v->adds_c1 = -1;
	}
	r++;

	return r;
}

/*
 * draw_grp_note - the matcher's comment box, at the end of its first row.
 *
 * Every matcher has one and every matcher writes it the same way, so it is
 * written once: a block matcher that spelled its own would have drifted from
 * the search matchers the first time either changed.
 */
void draw_grp_note(struct out *o, struct view *v, uint32_t g)
{
	const struct group *q = &v->ed.dr.grp[g];
	int room;

	out_str(o, "   ");
	v->grp_nt[g][0] = 1 + (int)o->col_hint;
	/* Up to the remove control, which keeps the right hand end of every
	 * matcher row. */
	room = g_cols - v->grp_nt[g][0] - 7;
	if (room < 8)
		room = 8;
	/* Hugging, like every other box - see field_room. The [x] that ends
	 * the row is drawn at an absolute column. */
	room = field_room(q->note, "comment...", v->edit == 300 + (int)g, room);
	out_fmt(o, "%s[", v->edit == 300 + (int)g ? A_SEL : A_DIM);
	field_draw(o, q->note, v->caret, &v->ed.dr.grp[g].note_off, room,
		   v->edit == 300 + (int)g, "comment...");
	out_str(o, "]" A_OFF);
	v->grp_nt[g][1] = (int)o->col_hint;
}

/*
 * A TAG CELL: the name of the tag, "none" while nothing is chosen. A name the
 * Syndromes catalog no longer has (renamed or deleted in the dialog) says so in
 * red, because the diagnose it would write has nothing to say; while the catalog
 * has not been loaded there is nothing to check against and the name is shown.
 */
static void draw_tag_cell(struct out *o, struct view *v, const char *tag)
{
	if (!tag[0]) {
		out_str(o, A_DIM "none" A_OFF);
		return;
	}
	if (v->tag && kv_tag_find(&v->tag->cat, tag) < 0) {
		out_fmt(o, A_BAD "%s (not found)" A_OFF, tag);
		return;
	}
	out_fmt(o, "%s%s" A_OFF, A_ID, tag);
}

/*
 * THE TYPE AND TAG CELLS OF ONE DIAGNOSE UNIT, `Type: Botnet   Tag: flood`: the ONE function that draws them and
 * registers their hit zones, for a Patterns condition row and a Blocks matcher row alike (the unit is
 * `is_grp`/`idx`, the same pair the unit list uses). The type is greyed while the header has no variant (nothing
 * to choose from) and `?` in the warning colour while a variant is chosen and the unit has none. Call it AFTER the
 * row's own whole-row zone, so the cells win where they overlap (see hit_at). The zones carry the unit encoded the
 * way the chooser takes it (CH_UNIT_GRP for a matcher).
 */
void unit_cells(struct out *o, struct view *v, int y, int is_grp, uint32_t idx)
{
	uint8_t utype = is_grp ? v->ed.dr.grp[idx].utype : v->ed.dr.cnd[idx].utype;
	const char *tag = is_grp ? v->ed.dr.grp[idx].tag : v->ed.dr.cnd[idx].tag;
	uint32_t unit = is_grp ? (CH_UNIT_GRP | idx) : idx;
	int ty0, ty1, tg0, tg1;

	out_str(o, A_DIM "Type: " A_OFF);
	ty0 = 1 + (int)o->col_hint;
	if (utype)
		out_fmt(o, "%s%s" A_OFF, A_ID, kof_maltype_name((uint32_t)utype - 1u));
	else
		out_fmt(o, "%s?" A_OFF, decl_var_types(v) ? A_WARN : "\033[90m");
	ty1 = (int)o->col_hint;
	out_str(o, A_DIM "   Tag: " A_OFF);
	tg0 = 1 + (int)o->col_hint;
	draw_tag_cell(o, v, tag);
	tg1 = (int)o->col_hint;
	hit_add(v, y, ty0, ty1, hit_unit_type, unit);
	hit_add(v, y, tg0, tg1, hit_unit_tag, unit);
}

void glist_begin(struct grp_list *L, struct out *o, struct view *v,
			int y, uint32_t g, const char *title,
			int (*span)[2], uint32_t cap)
{
	uint32_t i;

	L->o = o; L->v = v; L->y = y; L->g = g;
	L->span = span; L->cap = cap; L->n = 0;
	for (i = 0; i < cap; i++)
		span[i][0] = span[i][1] = -1;
	row_start(o, y, 1);
	out_fmt(o, A_DIM "     %s: " A_OFF, title);
}

void glist_item(struct grp_list *L, const char *text)
{
	if (L->n)
		out_str(L->o, A_DIM ", " A_OFF);
	if (L->n < L->cap)
		L->span[L->n][0] = 1 + (int)L->o->col_hint;
	out_fmt(L->o, A_ID "%s" A_OFF, text);
	if (L->n < L->cap)
		L->span[L->n][1] = (int)L->o->col_hint;
	L->n++;
}

/*
 * `can_add` is the caller's answer to "is there anything left to offer": a
 * free declaration slot.
 */
void glist_end(struct grp_list *L, int can_add, const char *label)
{
	struct view *v = L->v;

	if (!L->n)
		out_str(L->o, A_DIM "none yet" A_OFF);
	v->p_c0[L->g][0] = v->p_c0[L->g][1] = -1;
	if (can_add) {
		v->p_c0[L->g][0] = 1 + (int)L->o->col_hint;
		out_fmt(L->o, "   " A_ID "[+ %s]" A_OFF, label);
		v->p_c0[L->g][1] = (int)L->o->col_hint;
	}
	hit_add(v, L->y, 0, g_cols - 1, hit_row_markers, L->g);
}

/* The row is scrolled out: it has no click targets this frame. */
void glist_gone(struct view *v, uint32_t g)
{
	uint32_t i;

	if (v->grp_it[g])
		for (i = 0; i < v->cap_str_col; i++)
			v->grp_it[g][i][0] = v->grp_it[g][i][1] = -1;
	v->p_c0[g][0] = v->p_c0[g][1] = -1;
}

/*
 * WHICH ITEM OF A LIST ROW THE POINTER IS ON, or `n` when it is on none.
 *
 * The other half of recording the spans: the hit test reads back exactly what
 * was drawn rather than measuring the row a second time.
 */
static uint32_t glist_hit(const int (*span)[2], uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (span[i][0] > 0 && g_mx >= span[i][0] && g_mx <= span[i][1])
			return i;
	return n;
}

/*
 * THE FIRST ROW OF A BLOCK MATCHER, up to the part that differs.
 *
 * The number a condition names it by, then what it is. The word is a label and
 * not a control: a block matcher is find_similar and nothing else, made by
 * ticking the block and dropped by unticking it, so there is no kind to choose
 * and nothing under the word to click.
 */
void ghead_lead(struct out *o, struct view *v, int y, uint32_t g,
		       const char *word)
{
	char lead[16];

	row_start(o, y, 1);
	/*
	 * THE WHOLE ROW FIRST, so the comment box and the controls registered
	 * after it win where they overlap - see hit_at.
	 */
	hit_add(v, y, 0, g_cols - 1, hit_row_matcher, g);
	snprintf(lead, sizeof lead, "  %u.", grp_loc(&v->ed, g));
	out_fmt(o, "%s%-6.6s" A_OFF,
		g == v->ed.dr.cur_grp ? A_SEL : A_DIM, lead);
	v->grp_rl[g][0] = v->grp_rl[g][1] = -1;
	out_fmt(o, "%s%s" A_OFF, A_WARN, word);
}

/* A row that is not drawn has no click targets this frame - see the same
 * clearing on the string rows. */
void grp_spans_off(struct view *v, uint32_t g)
{
	v->grp_rl[g][0] = v->grp_rl[g][1] = -1;
	v->grp_rg[g][0] = v->grp_rg[g][1] = -1;
	v->grp_sg[g][0] = v->grp_sg[g][1] = -1;
	v->grp_of[g][0] = v->grp_of[g][1] = -1;
	v->grp_th[g][0] = v->grp_th[g][1] = -1;
	v->grp_nt[g][0] = v->grp_nt[g][1] = -1;
}
