/*
 * out_clip - the writer refuses to draw outside the region it was given.
 *
 * The viewer's panes and dialogs used to police their own edges: every drawer
 * worked out its own last column and was trusted to stop there. One that
 * measured wrong wrote across the pane beside it - the object tree was erasing
 * the divider drawn between it and the hex pane on every single frame - or past
 * the right edge, where a terminal wraps the overflow onto the next line and
 * scrolls the screen out from under everything.
 *
 * So the rectangle is enforced by the thing that writes the bytes, and this
 * asks it the questions the screen cannot be asked from a test: what reaches
 * the buffer, and what does not.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../kofexamine/kofview.h"

static int fails;

static void eq(struct out *o, const char *want, const char *why)
{
	if (o->n == strlen(want) && !memcmp(o->p, want, o->n))
		return;
	printf("  FAIL %-40s got \"%.*s\", wanted \"%s\"\n", why,
	       (int)o->n, o->p ? o->p : "", want);
	fails++;
}

static void reset(struct out *o)
{
	o->n = 0;
	o->col_hint = 0;
	o->cl_drop = 0;
}

int main(void)
{
	struct out o;
	struct out_clip a, b;

	memset(&o, 0, sizeof o);

	/*
	 * NO RECTANGLE IS NOT AN EMPTY ONE.
	 *
	 * A struct out is also used as a plain string builder - the clipboard
	 * is assembled with these same calls - and a builder that dropped what
	 * did not fit on a screen it is not writing to would corrupt a copy.
	 */
	out_str(&o, "hello");
	eq(&o, "hello", "unclipped: every byte");
	if (o.cl_drop) {
		printf("  FAIL unclipped writer counted a drop\n");
		fails++;
	}

	/* Now a screen, and a row across the middle of it. */
	out_clip_set(&o, 1, 1, 10, 10);
	reset(&o);
	out_at(&o, 5, 8);
	reset(&o);                      /* forget the positioning escape */
	out_str(&o, "abcdef");
	eq(&o, "abc", "columns past the right edge are refused");
	if (o.cl_drop != 3u) {
		printf("  FAIL wanted 3 drops, got %u\n", o.cl_drop);
		fails++;
	}

	/* A row outside the rectangle writes nothing at all. */
	out_at(&o, 11, 1);
	reset(&o);
	out_str(&o, "abc");
	eq(&o, "", "a row below the rectangle draws nothing");

	out_at(&o, 0, 1);
	reset(&o);
	out_str(&o, "abc");
	eq(&o, "", "a row above it draws nothing");

	/*
	 * COLOUR IS NOT A CELL.
	 *
	 * Dropping an SGR because the text it colours was clipped would leave
	 * the colour state wrong for whatever is drawn next - the clipped row
	 * would be invisible and the row after it would come out in the wrong
	 * colour, which is the harder bug of the two.
	 */
	out_at(&o, 5, 9);
	reset(&o);
	out_str(&o, "\033[31mxyz\033[0m");
	eq(&o, "\033[31mxy\033[0m", "escapes pass, cells clip");

	/*
	 * A CELL IS A WHOLE UTF-8 SEQUENCE.
	 *
	 * Cutting one at the right edge would put half a character on the
	 * screen, which is worse than the overflow the clip is there to stop.
	 */
	out_at(&o, 5, 10);
	reset(&o);
	out_glyph(&o, "\xe2\x94\x82");
	eq(&o, "\xe2\x94\x82", "the last column takes a whole glyph");
	out_at(&o, 5, 11);
	reset(&o);
	out_glyph(&o, "\xe2\x94\x82");
	eq(&o, "", "one past it takes none of it");

	out_at(&o, 5, 9);
	reset(&o);
	out_str(&o, "\xe2\x94\x82\xe2\x94\x82\xe2\x94\x82");
	eq(&o, "\xe2\x94\x82\xe2\x94\x82",
	   "out_str counts a sequence as one cell too");

	/*
	 * ERASE TO END OF LINE IS A DRAW, and it draws to the edge of the
	 * SCREEN. Inside a narrower region it becomes spaces to the region's
	 * edge, and the cursor is put back because an erase does not move it.
	 */
	out_at(&o, 5, 1);
	reset(&o);
	a = out_clip_set(&o, 1, 1, 10, 4);
	out_str(&o, "\033[K");
	eq(&o, "    \033[5;1H", "an erase stops at the region's edge");
	out_clip_restore(&o, a);
	out_at(&o, 5, 1);
	reset(&o);
	out_str(&o, "\033[K");
	eq(&o, "\033[K", "and passes through at the screen's");

	/*
	 * A RECTANGLE NARROWS, NEVER WIDENS. A box inside a pane cannot give
	 * itself more room than the pane it is in by asking for it.
	 */
	a = out_clip_set(&o, 3, 3, 8, 8);
	b = out_clip_set(&o, 1, 1, 20, 20);
	out_at(&o, 2, 3);
	reset(&o);
	out_str(&o, "x");
	eq(&o, "", "a nested rectangle cannot reach above its parent");
	out_at(&o, 3, 9);
	reset(&o);
	out_str(&o, "x");
	eq(&o, "", "nor right of it");
	out_at(&o, 3, 3);
	reset(&o);
	out_str(&o, "x");
	eq(&o, "x", "and still draws where both agree");
	out_clip_restore(&o, b);
	out_clip_restore(&o, a);
	out_at(&o, 2, 3);
	reset(&o);
	out_str(&o, "x");
	eq(&o, "x", "restoring gives the screen back");

	/*
	 * THE COLUMN COUNT IS UNCHANGED BY CLIPPING.
	 *
	 * col_hint is what the layout above measures rows with, and a caller
	 * that measured a row must get the same answer whether or not the row
	 * happened to run off the edge - otherwise a click box would move when
	 * the window got narrow.
	 */
	out_at(&o, 5, 8);
	reset(&o);
	out_str(&o, "abcdef");
	if (o.col_hint != 6u) {
		printf("  FAIL col_hint %u, wanted 6 (clipping must not "
		       "change the layout's arithmetic)\n",
		       (unsigned)o.col_hint);
		fails++;
	}

	free(o.p);
	if (fails) {
		printf("out_clip: %d check(s) failed\n", fails);
		return 1;
	}
	printf("out clip: region, escapes, glyphs, erase, nesting - ok\n");
	return 0;
}
