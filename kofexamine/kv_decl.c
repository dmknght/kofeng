#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The draft panel: the tab bar and the order its sections are drawn in. */

/* Defined below; a row registers its own callback before the callback is written. */
static void hit_tab(struct view *v, uint32_t tab);
static int draw_decl_tabs(struct out *o, struct view *v, int r);


/*
 * THE TITLE BAR OF THE DIAGNOSE PANEL: `Patterns | Blocks | Graphs`.
 *
 * Everything above it - the type, the family, the format, the regions and the
 * options - is declared once and shared by every diagnose the draft generates;
 * everything below it is one tab's own tables. A cell is a button. The open tab
 * is drawn reversed, the way the cursor is everywhere else in this panel.
 */
static const char *const tab_word[DT_COUNT] = {
	"Patterns", "Blocks", "Graphs"
};

/* A tab, by the mouse. A box open on a row of the tab being left is open on a
 * row that is no longer drawn, so it is closed with it. */
static void hit_tab(struct view *v, uint32_t tab)
{
	if (tab >= DT_COUNT || tab == v->ed.dr.tab)
		return;
	if (v->edit)
		v->edit = 0;
	v->ed.dr.tab = (uint8_t)tab;
}

static int draw_decl_tabs(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		char bar[256];
		int c0[DT_COUNT], c1[DT_COUNT];
		uint32_t t;

		row_start(o, PR(r), 1);
		/* The cells are the Syndrome table's widget too. */
		tabbar_text(bar, sizeof bar, tab_word, DT_COUNT, v->ed.dr.tab,
			    c0, c1);
		out_str(o, bar);
		for (t = 0; t < DT_COUNT; t++)
			hit_add(v, PR(r), c0[t], c1[t], hit_tab, t);
	}
	return r + 1;
}

void draw_decl(struct out *o, struct view *v)
{
	int top = decl_top();
	int r = 0;

	decl_sync_ranges(&v->ed);

	/*
	 * Rows that stop being drawn are erased at the end, not all of them at
	 * the start.
	 *
	 * Every row this paints already clears itself to the end of the line,
	 * so erasing the whole area up front only mattered for the rows that
	 * fall off when the draft shrinks - and it cost a visible flash of an
	 * empty panel on any terminal without synchronized output, which is
	 * most of them. The flash showed up as the panel blinking on a click
	 * that changed nothing but the highlighted row.
	 */

	/* ---- what the module declares ---- */
	/* The registry is cleared once for the whole frame - see redraw - and
	 * not here: the panes drawn before this one register their own
	 * rectangles, and clearing at the panel would throw them away. */
	/*
	 * MUTATION MODE TAKES THE WHOLE PANEL, header and all.
	 *
	 * Not a section added below the draft: the two are alternatives, and a
	 * screen showing a family name, a condition list and a block table at
	 * once would be showing a signature that is being written two ways.
	 */
	/*
	 * THE HEADER, THE FORMAT AND THE OPTIONS BELONG TO BOTH MODES.
	 *
	 * What a rule is FOR - its type, its family, the format it targets and
	 * how it is matched - is the same question whichever way the body is
	 * written. Only the body differs: patterns and conditions, or blocks.
	 * Replacing the whole panel was wrong; it took the family name away
	 * from the rule that needs it most, since a mutation rule has nothing
	 * else to be called.
	 */
	draw_decl_head(o, v);
	decl_types_sync(v);
	r = draw_decl_fmts(o, v, r);
	r = draw_decl_optbtn(o, v, r);
	r = draw_decl_opts(o, v, r);
	r = draw_decl_tabs(o, v, r);
	/*
	 * THE OPEN TAB'S OWN TABLES - see prow_build, which lists the same rows
	 * in the same order.
	 */
	switch (v->ed.dr.tab) {
	case DT_BLOCKS:
		r = draw_decl_blocks(o, v, r);
		r = draw_decl_matchers(o, v, r);       /* no conditions: each matcher is a unit */
		break;
	case DT_GRAPHS:
		break;
	default:
		r = draw_decl_strings(o, v, r);
		r = draw_decl_ranges(o, v, r);
		r = draw_decl_matchers(o, v, r);
		r = draw_decl_conds(o, v, r);
		break;
	}

	/*
	 * THE ROW MODEL AND THE DRAWING MUST AGREE, and they say so here.
	 *
	 * prow_build declares the panel's rows and the drawers emit them, and
	 * nothing but this connects the two. When they disagree every row below
	 * the discrepancy is one out: the clamp stops short, so the last rows
	 * cannot be scrolled to, and a click lands on the row above or below
	 * what it pointed at. Both happened the day the block table was added -
	 * the table draws two heading rows and the model counted one.
	 *
	 * Said in the status line rather than asserted, because a panel that
	 * refuses to draw is worse than one that draws slightly wrong, and
	 * because the person who can act on it is the one looking at the
	 * screen.
	 */
	/*
	 * AND IT OWNS ITS OWN MESSAGE, rather than borrowing the author's.
	 *
	 * `warn` is where the draft says what is wrong with itself, and writing
	 * into it every frame the counts disagree both buried whatever the
	 * author was being told and stayed on screen long after - it appeared
	 * at whatever they clicked next, which reads as that click having
	 * caused it. So it writes only when the slot is free or already holds
	 * this same sentence, and takes it back when the counts agree.
	 */
	if (r != (int)v->n_prow) {
		if (!v->ed.dr.warn[0] || v->rowchk) {
			snprintf(v->ed.dr.warn, sizeof v->ed.dr.warn,
				 "panel rows %d, model %u - a section is "
				 "miscounted", r, v->n_prow);
			/* It IS a fault, so it is coloured as one - see
			 * say_err. A panel that miscounts its rows sends
			 * clicks to the wrong row. */
			v->ed.dr.warn_bad = 1;
		}
		v->rowchk = 1;
	} else if (v->rowchk) {
		v->ed.dr.warn[0] = 0;
		v->rowchk = 0;
	}

	/* Whatever the draft used to reach and no longer does. */
	{
		int y = PR(r), bot = top + g_decl_rows - 2;

		for (; y <= bot; y++)
			if (y > top)
				row_start(o, y, 1);
	}
	kv_scrollbar(o, g_cols, top + 1, top + g_decl_rows - 2, v->prow_off,
		  v->n_prow, (uint64_t)(g_decl_rows - 2));

}
