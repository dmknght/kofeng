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
	for (t = 0; t < v->ed.dr.n_cnd; t++) {
		/* Only the open tab's conditions: each tab has its own list,
		 * and each condition is a block of its own. */
		if (v->ed.dr.cnd[t].tab != v->ed.dr.tab)
			continue;
		cseq_put(v, CS_MATCH, t);
		cseq_put(v, CS_COND, t);
	}
}

static void prow_add(struct view *v, int kind, uint32_t idx)
{
	if (v->n_prow >= sizeof v->prow_kind / sizeof v->prow_kind[0])
		return;
	v->prow_kind[v->n_prow] = (uint8_t)kind;
	v->prow_idx[v->n_prow] = idx;
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
	prow_add(v, RW_STRHDR, 0);
	for (i = 0; i < v->ed.dr.n_decl; i++)
		prow_add(v, RW_STR, i);
	prow_add(v, RW_ADDS, 0);
}

static void prow_lineage(struct view *v)
{
	struct object *dob = cur_obj(v);
	uint32_t i, n = diag_shown_n(v);

	prow_add(v, RW_DIAGHDR, 0);
	prow_add(v, RW_DIAGCOL, 0);
	if (v->diag_fold)
		return;
	/* An empty table says why on one row of its own. */
	if (!n)
		prow_add(v, RW_DIAG, 0);
	for (i = 0; n && i < dob->n_diag; i++)
		if (dob->diag[i].state == KOF_DIAG_ST_MATCH)
			prow_add(v, RW_DIAG, i);
}

static void prow_blocks(struct view *v)
{
	uint32_t i;

	prow_add(v, RW_BLKHDR, 0);
	/* Two rows: the heading and the column names, or the heading and the
	 * reason an object that has no code has no table. */
	prow_add(v, RW_BLKCOL, 0);
	if (!blk_section_shown(v))
		return;
	for (i = 0; i < v->ed.dr.n_blk; i++)
		if (blk_row_shown(v, i))
			prow_add(v, RW_BLK, i);
}

static void prow_matchers(struct view *v)
{
	uint32_t i;

	prow_add(v, RW_MATHDR, 0);
	for (i = 0; i < v->ed.dr.n_grp; i++) {
		if (grp_tab(&v->ed, i) != v->ed.dr.tab)
			continue;
		prow_add(v, RW_MATCH, i);
		/* A search matcher is two rows: what it IS, and the markers it
		 * searches for. A block matcher is one - the hash and the
		 * threshold. */
		if (v->ed.dr.grp[i].kind != GRP_KIND_SIM)
			prow_add(v, RW_MARKERS, i);
	}
	/* [+ Matcher] is the Patterns tab's: a block's matcher is made by
	 * ticking the block. */
	if (v->ed.dr.tab == DT_PATTERNS)
		prow_add(v, RW_ADDM, 0);
}

static void prow_conds(struct view *v)
{
	uint32_t i;

	prow_add(v, RW_CNDHDR, 0);
	cnd_seq(v);
	for (i = 0; i < v->n_cseq; i++)
		prow_add(v, RW_COND, i);
	prow_add(v, RW_ADDC, 0);
}

/* Every row the panel would show, in order, before deciding which fit. */
void prow_build(struct view *v)
{
	uint32_t i;

	v->n_prow = 0;
	/*
	 * IN THE ORDER THE PANEL DRAWS THEM - see the chain in draw_decl(),
	 * which is fmts, ranges, optbtn, opts, strings, matchers, conds. The
	 * head row is not here because it is not scrolled: draw_decl_head takes
	 * no row number and paints at a fixed line.
	 *
	 * ONLY THE COUNT IS READ. prow_kind and prow_idx are written and
	 * nothing looks at them, so what this really produces is how many rows
	 * the panel has - and that number sizes the panel and bounds its
	 * scroll. A row the draw emits and this does not is a row that CANNOT
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
	prow_add(v, RW_FMTS, 0);
	/*
	 * The scan range row while there is ANY range to show, which is not the
	 * same as "while there is a matcher".
	 *
	 * Gated on n_grp alone, removing the last matcher took the row with it -
	 * and with the row went every DECLARED range that no matcher had been
	 * given yet. Those still existed in rng_add, still blocked the save
	 * ("scan range X is in no matcher"), and now had nowhere to be seen and
	 * no menu to be removed from, because [Update scan range] lives on this
	 * row. A range one can neither use nor get rid of is a draft that cannot
	 * be finished.
	 */
	/*
	 * ALWAYS, like the Matchers and Conditions headings.
	 *
	 * Gated on having a matcher, removing the last one took the row away -
	 * and [+ Add scan range] lives on it, so there was then no way to
	 * declare a range at all: the draft could not be finished and nothing
	 * on the screen said why. A heading that disappears takes its controls
	 * with it, so this one does not disappear.
	 */
	prow_add(v, RW_RANGES, 0);
	prow_add(v, RW_OPTBTN, 0);
	for (i = 0; i < (uint32_t)OPT_COUNT; i++)
		if (v->ed.dr.opt_on[i])
			prow_add(v, RW_OPT, i);
	/* The title bar of tabs: everything above it is shared by every
	 * diagnose the draft generates, everything below is the open tab's. */
	prow_add(v, RW_TABS, 0);
	switch (v->ed.dr.tab) {
	case DT_BLOCKS:
		prow_blocks(v);
		prow_matchers(v);
		prow_conds(v);
		break;
	case DT_GRAPHS:
		prow_lineage(v);
		prow_add(v, RW_CNDHDR, 0);
		prow_add(v, RW_COND, 0);
		break;
	default:
		prow_strings(v);
		prow_matchers(v);
		prow_conds(v);
		break;
	}
	/* The output pane, when Generate has been pressed: the same count the
	 * drawing uses. */
	for (i = 0; i < preview_rows(v); i++)
		prow_add(v, RW_PREV, i);
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
