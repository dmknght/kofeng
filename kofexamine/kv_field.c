#define _GNU_SOURCE
#include "kv.h"


static void cseq_put(struct view *v, int kind, uint32_t idx)
{
	if (v->n_cseq >= sizeof v->cseq_kind / sizeof v->cseq_kind[0])
		return;
	v->cseq_kind[v->n_cseq] = (uint8_t)kind;
	v->cseq_idx[v->n_cseq] = idx;
	v->n_cseq++;
}

static void cnd_seq(struct view *v)
{
	uint32_t t;

	v->n_cseq = 0;
	/* Only the Patterns tab has conditions; each is a block of its own. */
	for (t = 0; v->ed.dr.tab == DT_PATTERNS && t < v->ed.dr.n_cnd; t++) {
		cseq_put(v, CS_MATCH, t);
		cseq_put(v, CS_COND, t);
	}
}

static void prow_add(struct view *v)
{
	v->n_prow++;
}

/*
 * THE ROWS OF EACH TAB'S TABLES, in the order draw_decl draws them. Split out
 * of prow_build only to keep that one short; each is the count of one drawer.
 */
static void prow_strings(struct view *v)
{
	uint32_t i;

	/*
	 * THE HEADING IS ALWAYS A ROW, BECAUSE IT IS ALWAYS DRAWN.
	 *
	 * draw_decl_strings paints it whether or not the table has anything in
	 * it - an empty table is exactly when the button that fills it has to
	 * be reachable, see BTN_ADDSTR - and this counted it only when there
	 * was a string, so a draft with no declared strings painted one row
	 * more than the model held and every row below was one out.
	 */
	prow_add(v);
	for (i = 0; i < v->ed.dr.n_decl; i++)
		prow_add(v);
	prow_add(v);
}

/* How many rows the panel may show at most: the preference (the divider) and what the terminal has. One answer for the layout and for the table window. */
uint32_t decl_cap_rows(const struct view *v)
{
	uint32_t room = g_rows > 8 ? (uint32_t)(g_rows - 8) : 1u;

	return v->ed.dr.decl_cap < room ? v->ed.dr.decl_cap : room;
}

static void prow_blocks(struct view *v)
{
	uint32_t i, nshown = 0, win;

	v->blk_nwin = v->blk_nshown = 0;
	v->blk_row0 = v->n_prow;

	prow_add(v);
	/* Two rows: the heading and the column names, or the heading and the
	 * reason an object that has no code has no table. */
	prow_add(v);
	if (!blk_section_shown(v))
		return;
	for (i = 0; i < v->ed.dr.n_blk; i++)
		if (blk_row_shown(v, i))
			nshown++;
	/* The window is what the panel has left for the table: its visible height at this row. At least one row, or there is nothing to scroll. */
	win = decl_cap_rows(v) > v->n_prow ? decl_cap_rows(v) - v->n_prow : 1u;
	if (win > nshown)
		win = nshown;
	if (v->blk_off > nshown - win)
		v->blk_off = nshown - win;
	v->blk_row0 = v->n_prow;
	v->blk_nwin = win;
	v->blk_nshown = nshown;
	for (i = 0; i < win; i++)
		prow_add(v);
}

static void prow_matchers(struct view *v)
{
	uint32_t i;

	prow_add(v);
	for (i = 0; i < v->ed.dr.n_grp; i++) {
		if (grp_tab(&v->ed, i) != v->ed.dr.tab)
			continue;
		prow_add(v);
		/* Every matcher is two rows. A search matcher: what it IS, and the markers it
		 * searches for. A block matcher: the hash, the function and the threshold, and
		 * the unit's Type and Tag under it (draw_block_matcher). */
		prow_add(v);
	}
	/* [+ Matcher] is the Patterns tab's: a block matcher is made by ticking
	 * the block. */
	if (v->ed.dr.tab == DT_PATTERNS)
		prow_add(v);
}

static void prow_conds(struct view *v)
{
	uint32_t i;

	prow_add(v);
	cnd_seq(v);
	for (i = 0; i < v->n_cseq; i++)
		prow_add(v);
	prow_add(v);
}

/* Every row the panel would show, in order, before deciding which fit. */
void prow_build(struct view *v)
{
	uint32_t i;

	v->n_prow = 0;
	/*
	 * IN THE ORDER THE PANEL DRAWS THEM - see the chain in draw_decl(),
	 * which is fmts, optbtn, opts, tabs, strings or blocks, ranges, matchers, conds. The
	 * head row is not here because it is not scrolled: draw_decl_head takes
	 * no row number and paints at a fixed line.
	 *
	 * ONLY THE COUNT EXISTS. What this produces is how many rows the panel
	 * has - and that number sizes the panel and bounds its scroll. A row the draw emits and this does not is a row that CANNOT
	 * BE REACHED: g_decl_rows comes out short by exactly that many, and the
	 * rows that fall off are the ones at the bottom.
	 *
	 * That is not hypothetical. The Format row and the [+ Options] button
	 * were added to the draw and not to here, and the panel lost its last
	 * two rows - which are the Conditions heading and [+ Condition]. The
	 * draft then could not be finished at all: Save says "Add a condition
	 * first" and the only control that adds one had no row to be drawn on.
	 *
	 * So the order is kept faithful to the draw even though nothing reads
	 * it, because the next person to add a row will copy whichever of the
	 * two lists they read first.
	 */
	prow_add(v);
	prow_add(v);
	for (i = 0; i < (uint32_t)OPT_COUNT; i++)
		if (v->ed.dr.opt_on[i])
			prow_add(v);
	/* The title bar of tabs: everything above it is shared by every
	 * diagnose the draft generates, everything below is the open tab's. */
	prow_add(v);
	switch (v->ed.dr.tab) {
	case DT_BLOCKS:
		prow_blocks(v);
		prow_matchers(v);     /* no conditions: each matcher is a unit of its own */
		break;
	case DT_GRAPHS:
		break;
	default:
		prow_strings(v);
		prow_add(v);      /* the region list, below [+ String] (draw_decl_ranges) */
		prow_matchers(v);
		prow_conds(v);
		break;
	}
}

void sec_bar(struct out *o, struct view *v, int row, const char *text)
{
	int i, n = (int)strlen(text);

	(void)v;
	row_start(o, row, 1);
	out_str(o, A_HEAD);
	out_str(o, text);
	for (i = n; i < g_cols; i++)
		out_str(o, " ");
	out_str(o, A_OFF);
}

/*
 * THE SELECTED RANGE, OR NOTHING - the one place both questions are answered.
 *
 * Nothing when the two ends meet, and nothing when the range was made in a
 * field that is no longer the open one: see fld_of.
 */
int fsel_range(const struct view *v, uint32_t *lo, uint32_t *hi)
{
	if (v->fld_of != v->edit || v->fld_a == v->fld_b)
		return 0;
	*lo = v->fld_a < v->fld_b ? v->fld_a : v->fld_b;
	*hi = v->fld_a < v->fld_b ? v->fld_b : v->fld_a;
	return 1;
}

void fsel_clear(struct view *v)
{
	v->fld_a = v->fld_b = 0;
}

/* Anchor a new range in the field that is open now. */
void fsel_set(struct view *v, uint32_t a, uint32_t b)
{
	v->fld_a = a;
	v->fld_b = b;
	v->fld_of = v->edit;
}

/*
 * HOW WIDE A BOX HAS TO BE FOR WHAT IS IN IT - never wider, never past `max`.
 *
 * A field drawn at a fixed width sits in a run of blank brackets, which reads
 * as a control still waiting for input rather than one holding an answer:
 * "mirai" in a 24 column box is five characters and nineteen spaces. So the
 * brackets close on the text.
 *
 * THREE CASES AND EACH IS A DIFFERENT NUMBER:
 *
 *   - empty and not focused: the PLACEHOLDER is what shows, so the box is as
 *     wide as that. Sized on the text instead, "Comment..." came out clipped to
 *     one character.
 *   - focused: one past the text, because the caret may sit after the last
 *     character - the same allowance field_draw makes when it decides how far
 *     to scroll.
 *   - otherwise the text.
 *
 * `max` is the cap, and past it field_draw scrolls the text inside the box as
 * it always has. Callers that are laid out against a fixed mark pad the
 * difference back AFTER the closing bracket, so the row does not move as the
 * field is typed into - see the note in draw_decl_head.
 */
int field_room(const char *text, const char *ph, int editing, int max)
{
	int n = (int)strlen(text);

	if (!n && !editing)
		n = ph ? (int)strlen(ph) : 1;
	else if (editing)
		n++;
	if (n > max)
		n = max;
	return n < 1 ? 1 : n;
}

void field_draw(struct out *o, const char *text, uint32_t caret,
		       uint32_t *off, int room, int editing, const char *ph)
{
	uint32_t len = (uint32_t)strlen(text), i;

	if (!text[0] && !editing) {
		/*
		 * PADDED TO THE BOX, which "%-.*s" does not do: the star there
		 * is a PRECISION and the width is absent, so this painted
		 * strlen(ph) columns and left the rest of its own box
		 * unwritten. Every other branch below fills `room` exactly, and
		 * a caller that lays out against the box - or draws it over
		 * something, as a dialog does - got a hole showing whatever was
		 * underneath.
		 */
		out_fmt(o, "%-*.*s", room, room, ph);
		return;
	}
	if (room < 1)
		room = 1;
	if (caret > len)
		caret = len;
	if (editing) {
		if (caret < *off)
			*off = caret;
		if (caret >= *off + (uint32_t)room)
			*off = caret - (uint32_t)room + 1u;
	}
	/*
	 * And never scrolled further right than the text needs.
	 *
	 * Keeping the caret in view is only half the rule; the other half is
	 * that scrolling right is pointless once what remains would fit. They
	 * were not both applied, so clearing a long comment and typing again
	 * left the window where the long text had pushed it: the caret was on
	 * screen at the left edge and the character just typed sat one column
	 * off it. Every field goes through here, so every field did it.
	 *
	 * The caret may sit one past the last character, which is why the text
	 * this has to fit is len + 1 while editing and len when not.
	 */
	{
		uint32_t want = editing ? len + 1u : len;

		if (*off + (uint32_t)room > want)
			*off = want > (uint32_t)room
			       ? want - (uint32_t)room : 0;
	}
	if (editing) {
		g_fld.row  = o->row_hint;
		g_fld.col  = o->col_base + (int)o->col_hint;
		g_fld.room = room;
		g_fld.off  = *off;
		g_fld.len  = len;
	}
	for (i = 0; i < (uint32_t)room; i++) {
		uint32_t at = *off + i;
		char t[2];

		/*
		 * Through out_str, never out_add.
		 *
		 * Only out_str counts printable columns, and the count is what
		 * every click range on the panel is recorded from. Emitting the
		 * characters with out_add drew them correctly and told the
		 * bookkeeping nothing, so a box holding a long string reported
		 * itself as ending where it began - and clicking the right hand
		 * part of it hit nothing, which looked like a field that had
		 * stopped accepting the caret.
		 */
		t[0] = at < len ? text[at] : ' ';
		t[1] = 0;
		/*
		 * THE SELECTION CANCELS THE BOX'S REVERSE, it does not add
		 * another one.
		 *
		 * AN OPEN FIELD IS DRAWN IN A_SEL BY ITS CALLER - every one of
		 * them does it - and A_SEL is reverse video. Reversing the
		 * selected span again is a no-op that LOOKS like one too: the
		 * old Ctrl+A did exactly that, and the only visible effect was
		 * that the "\033[27m" at the end of it turned the box's own
		 * reverse off for everything after the selection.
		 *
		 * So selected text is drawn upright on the inverted box, which
		 * is what a terminal does with a selection inside an inverted
		 * region, and the box's reverse is put back after it. No colour
		 * pair, because a pair would end in A_OFF and take the rest of
		 * the field back to plain.
		 */
		if (editing && at < len &&
		    at >= g_fsel.lo && at < g_fsel.hi) {
			out_str(o, "\033[27m");
			out_str(o, t);
			out_str(o, "\033[7m");
		} else if (editing && at == caret) {
			out_str(o, "\033[4m");
			out_str(o, t);
			out_str(o, "\033[24m");
		} else {
			out_str(o, t);
		}
	}
}
