#define _GNU_SOURCE
#include "kv.h"


/* ---- panes ---------------------------------------------------------------- */


/* Erase to end of line rather than clearing the screen.
 *
 * A full clear followed by a full repaint is one write and so cannot tear, but
 * it does make the terminal blank and refill every frame, which on a real
 * terminal is a visible flash at every keystroke. Erasing each line as it is
 * rewritten never leaves the screen empty. */
void row_start(struct out *o, int row, int col)
{
	out_at(o, row, col);
	out_str(o, "\033[K");
	o->col_hint = 0;
}

/*
 * Is the tree showing a scrollbar? The same question bar_thumb answers for
 * drawing it, asked here so the divider can get out of its way.
 */
static int tree_bar_on(const struct view *v)
{
	int t1;

	return kv_bar_thumb(hex_top(), hex_bot(), v->tree_top, v->n_node,
			 (uint64_t)(hex_bot() - hex_top() + 1), &t1) >= 0;
}

void draw_frame(struct out *o, struct view *v)
{
	/*
	 * THE SCROLLBAR IS THE BORDER WHEN THERE IS ONE.
	 *
	 * The bar is drawn in the tree's last column and the divider in the
	 * next, so a tree long enough to scroll showed TWO vertical lines side
	 * by side - one of them saying nothing the other did not. A bar already
	 * separates the panes; a second rule beside it is decoration.
	 *
	 * The column is still PAINTED when the divider is not drawn, with a
	 * space. A column no drawer owns keeps whatever was last put in it -
	 * see the note below, which is the bug that taught this file so.
	 */
	int bar = tree_bar_on(v);
	int i;

	for (i = hex_top(); i <= hex_bot(); i++) {
		out_at(o, i, TREE_W + 1);
		/*
		 * THE BLANK AFTER THE DIVIDER IS PAINTED TOO.
		 *
		 * Both bytes panes start their rows at TREE_W + 3, and this
		 * drew only TREE_W + 1 - so the column between them was
		 * written by NOBODY on a normal frame. Anything that landed
		 * there stayed: close a dialog whose box reached that column
		 * and one character of its border was left behind in the line
		 * number gutter, with nothing in the repaint to remove it.
		 *
		 * A column that no drawer owns is a column that keeps whatever
		 * was last put in it, so this one is given an owner.
		 */
		out_str(o, bar ? "  " : A_DIM "|" A_OFF " ");
	}
	/*
	 * The divider, which is also the handle that resizes the draft panel.
	 *
	 * Marked in the middle rather than announced in a legend: a row of
	 * dashes with a grip drawn on it is a thing people try to drag, and the
	 * ones who do not try lose nothing.
	 */
	row_start(o, hex_bot() + 1, 1);
	out_str(o, v->sizing ? A_WARN : A_DIM);
	for (i = 0; i < g_cols; i++)
		out_str(o, i >= g_cols / 2 - 3 && i <= g_cols / 2 + 3
			   ? "=" : "-");
	out_str(o, A_OFF);
}

/*
 * The colour an OBJECT row is drawn in: its verdict, or plain when it has none.
 *
 * Read from what the engine reported for that object rather than from anything
 * this panel worked out - the same rule the heuristic fields follow. A row with
 * no finding stays as it was, because most rows have none and a tree where
 * everything is coloured says nothing.
 */
static const char *tree_colour(const struct view *v, const struct node *n)
{
	const struct object *ob;
	uint32_t i;
	int worst = -1;

	if (n->obj >= v->n_obj)
		return A_BOLD;
	ob = &v->obj[n->obj];
	if (!ob->n_finding && !ob->heur.n)
		return A_BOLD;
	/* The strongest thing said about it - a row that matched a family and
	 * also scored on structure is a match. The order is the engine's, asked
	 * for rather than restated: the constants do not carry it. */
	for (i = 0; i < ob->heur.n; i++) {
		int lv = (int)ob->heur.v[i].level;

		if (worst < 0 || kverdict_level_rank((uint32_t)lv) >
				 kverdict_level_rank((uint32_t)worst))
			worst = lv;
	}
	if (worst == KOF_LEVEL_INFECT)
		return A_HIT1;                  /* the same red a match is */
	if (worst == KOF_LEVEL_SUSPECT)
		return A_HIT2;
	if (worst == KOF_LEVEL_HEUR)
		return A_WARN;
	/* A finding was recorded but its level is not in the result any more -
	 * still not a plain row. */
	return ob->n_finding ? A_HIT1 : A_BOLD;
}

/*
 * WHICH NODE THE TREE LAST SCROLLED ITSELF TO.
 *
 * The panel used to pull itself back to the selection on every frame, which is
 * right when the selection MOVED and wrong when the reader moved the panel: a
 * wheel that scrolls and a draw that scrolls back is a panel that does not
 * scroll at all. Snapping only when this disagrees with sel_node keeps the
 * arrow keys and a click on a marker bringing their row into view, and leaves
 * the wheel alone.
 */
static uint32_t g_tree_followed = 0xffffffffu;

void draw_tree(struct out *o, struct view *v)
{
	int top = hex_top(), bot = hex_bot();
	int rows = bot - top + 1;
	uint32_t i;

	static int g_tree_rows_seen;

	if (rows != g_tree_rows_seen) {
		g_tree_rows_seen = rows;
		g_tree_followed = 0xffffffffu;   /* the window changed height: follow the selection again */
	}
	if (v->sel_node != g_tree_followed) {
		g_tree_followed = v->sel_node;
		if (v->sel_node < v->tree_top)
			v->tree_top = v->sel_node;
		if (rows > 0 && v->sel_node >= v->tree_top + (uint32_t)rows)
			v->tree_top = v->sel_node - (uint32_t)rows + 1;
	}
	/* Never past the end, whichever moved it - a tree that shrank under a
	 * scrolled panel would otherwise draw a page of blanks. */
	if (rows > 0 && v->n_node > (uint32_t)rows) {
		if (v->tree_top > v->n_node - (uint32_t)rows)
			v->tree_top = v->n_node - (uint32_t)rows;
	} else {
		v->tree_top = 0;
	}

	for (i = 0; (int)i < rows; i++) {
		uint32_t k = v->tree_top + i;
		const struct node *n;
		int sel;

		row_start(o, top + (int)i, 1);
		if (k >= v->n_node)
			continue;
		n = &v->node[k];
		sel = k == v->sel_node;

		/* Indent and label as one string, so scrolling sideways moves
		 * the whole row and not the label out from under its own
		 * indentation. */
		{
			char row[96];
			size_t off;

			snprintf(row, sizeof row, "%*s%s", (int)n->depth, "",
				 n->label);
			off = v->tree_hoff < strlen(row) ? v->tree_hoff
							 : strlen(row);
			out_str(o, sel ? A_BOLD : "");
			/* A star, not a chevron: "> " reads as a thing that
			 * would open if it were pressed, and these rows are
			 * already all open. */
			out_str(o, sel ? "*" : " ");
			/*
			 * A region row is a place inside an object; an object
			 * row can hold a signature. Different colours because
			 * they are different kinds of answer.
			 *
			 * AN OBJECT THAT MATCHED SOMETHING IS NOT WHITE, and
			 * that is the point of the tree on a nested sample. An
			 * archive of forty entries, or a dropper unpacked three
			 * deep, is a column of rows that all look alike - and
			 * the one worth reading is the one a signature fired
			 * on, which the reader had to find by walking every row
			 * and watching the status line. The colour is the
			 * verdict's own, so a match, a suspicion and a
			 * heuristic are told apart without opening any of them.
			 *
			 * Applied to the SELECTED row as well. It was not, and
			 * the row selected when a file opens is the root - so
			 * the verdict on the object a reader is looking at was
			 * the one verdict the tree never showed.
			 */
			if (n->mask || n->sym) {
				if (!sel)
					out_str(o, A_ID);
			} else {
				out_str(o, tree_colour(v, n));
			}
			/* Truncated, not merely padded: a label wider than its
			 * column runs into the pane beside it, and the first
			 * file anyone opens has a sha256 for a name. */
			out_fmt(o, "%-19.19s", row + off);
		}
		if (!sel)
			out_str(o, A_OFF A_SIZE);
		out_fmt(o, "%9llu", (unsigned long long)n->bytes);
		out_str(o, A_OFF);
	}
	/* The tree's own bar, in the two columns its rows never reach: a row is
	 * a mark, nineteen of label and nine of size, and TREE_W is thirty one.
	 *
	 * Nineteen and not eighteen because "//0 Shellcode-x86" is seventeen
	 * and a depth-one row spends two on indentation - it came out
	 * "//0 Shellcode-x8", one character short, which is the worst width to
	 * be since it reads as a different architecture. */
	kv_scrollbar(o, TREE_W, top, bot, v->tree_top, v->n_node,
		  (uint64_t)(bot - top + 1));
}

/*
 * Is this file offset inside a marker of the module the markers line is on?
 *
 * The whole reason the two panes are on one screen. A row saying "three of six"
 * is a number; the same three lit up in the bytes is where they are, what is
 * around them, and whether the fourth is nearly there - which is the question
 * somebody writing a variant is actually asking.
 *
 * Returns 0 for no, 1 for a marker the module would have counted, 2 for one
 * that is present but outside the regions it searches. The second is not a
 * lesser version of the first: it is the interesting one.
 */
/* Is this region offset inside the current selection. */
int in_sel(const struct view *v, uint64_t at)
{
	uint64_t lo, hi;

	if (v->sel_a == KGENOME_BROKEN)
		return 0;
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	return at >= lo && at <= hi;
}
