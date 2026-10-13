#define _GNU_SOURCE
#include "kv.h"



/*
 * The list, over the screen rather than beside it.
 *
 * Beside it costs its height on every object including the many that touch
 * nothing; over it costs nothing until it is asked for. Clicking a row is what
 * changes which signature the hex pane lights up, so the list is also the
 * control and not only the display.
 *
 * Four rows and it scrolls. A dialog that grows with its contents covers the
 * pane it is explaining as soon as the contents get interesting, and at database
 * scale they will. Four is enough to compare the top of a ranked list against
 * itself, which is what it is for.
 */
/*
 * How many rows the dialog offers, given the screen it is on.
 *
 * It was a flat four, whatever the terminal. On anything taller than a laptop
 * split that is four rows of a six row list with the rest below the fold, and
 * below the fold is where the interesting marker tends to be - the ones a rule
 * fails on come first because they are declared first. Bounded at a third of
 * the screen because it is an overlay: it is meant to answer a question about
 * what is underneath, not to replace it.
 */
#define LIST_ROWS_MIN 4u
#define LIST_ROWS_MAX 14u


static uint32_t list_rows(void)
{
	int third = (g_rows - 4) / 3;
	uint32_t n = third > 0 ? (uint32_t)third : LIST_ROWS_MIN;

	if (n < LIST_ROWS_MIN)
		n = LIST_ROWS_MIN;
	if (n > LIST_ROWS_MAX)
		n = LIST_ROWS_MAX;
	return n;
}

/* Does this signature belong in the dialog as it is filtered right now. */
static int list_keep(struct view *v, const struct kof_touch *t)
{
	if (v->list_filter == 1)
		return t->fired != 0;
	if (v->list_filter == 2)
		return t->fired == 0;
	return 1;
}

/* The i-th signature under the filter, or n_touch when there is no such row. */
uint32_t list_nth(struct view *v, uint32_t i)
{
	struct object *ob = cur_obj(v);
	uint32_t k, seen = 0;

	for (k = 0; k < ob->n_touch; k++) {
		if (!list_keep(v, &ob->touch[k]))
			continue;
		if (seen++ == i)
			return k;
	}
	return ob->n_touch;
}

uint32_t list_total(struct view *v)
{
	struct object *ob = cur_obj(v);
	uint32_t k, n = 0;

	if (v->list_depth)
		return v->sel_touch < ob->n_touch
		       ? ob->touch[v->sel_touch].n_str : 0;
	for (k = 0; k < ob->n_touch; k++)
		n += (uint32_t)list_keep(v, &ob->touch[k]);
	return n;
}

uint32_t list_shown(struct view *v)
{
	uint32_t n = list_total(v);

	return n < list_rows() ? n : list_rows();
}

/* The header row; the entries follow it, and the last one sits directly on the
 * bottom line - there is no spare row between them. */
int list_top(struct view *v)
{
	return g_rows - 2 - (int)list_shown(v);
}

/* Keep the cursor inside the window rather than the window on the cursor: a list
 * that jumps when it opens has lost the place it was opened to show. */
static void list_scroll(struct view *v)
{
	uint32_t shown = list_shown(v), n = list_total(v);

	if (!shown)
		return;
	if (v->list_depth) {
		if (v->str_off + shown > n)
			v->str_off = n - shown;
		return;
	}
	if (v->sel_touch < v->list_off)
		v->list_off = v->sel_touch;
	if (v->sel_touch >= v->list_off + shown)
		v->list_off = v->sel_touch - shown + 1u;
	if (v->list_off + shown > n)
		v->list_off = n - shown;
}

/*
 * The selected row keeps its own colour.
 *
 * It used to be drawn in reverse video, which paints it white and takes the
 * colour with it - so selecting a row was also hiding the one thing the row was
 * colour-coded to say. A caret marks the selection instead and the colour
 * survives, which matters most on exactly the row being looked at.
 */
static void list_row(struct out *o, int sel, const char *colour)
{
	out_str(o, colour);
	if (sel)
		out_str(o, "\033[1m");
	/* The same mark the object tree uses. Two cursors drawn two ways in one
	 * program is two things to learn for one idea. */
	out_str(o, sel ? "*" : " ");
}

/*
 * The frame around the dialog.
 *
 * Drawn after its contents, because every row inside clears to the end of the
 * line and would take the right edge with it. It is worth having: the dialog
 * opens over the hex and the draft, and without an edge the two run together -
 * a row of the list and a row of whatever it covers look alike.
 *
 * Plain ASCII, like the pane divider: this is meant to be read over ssh on
 * whatever terminal is at the other end.
 */
static void draw_list_box(struct out *o, struct view *v)
{
	int top = list_top(v) - 1, bot = g_rows - 1, i, y;

	for (y = top; y <= bot; y++) {
		out_at(o, y, 1);
		out_str(o, A_DIM);
		if (y == top || y == bot) {
			out_str(o, "+");
			for (i = 2; i < g_cols; i++)
				out_str(o, "-");
			out_str(o, "+" A_OFF);
			continue;
		}
		out_str(o, "| " A_OFF);
		out_at(o, y, g_cols - 1);
		out_str(o, A_DIM " |" A_OFF);
	}
}

void draw_list(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	const struct kof_touch *t = v->sel_touch < ob->n_touch
				   ? &ob->touch[v->sel_touch] : NULL;
	struct out_clip cl;
	int top, w = g_cols - 4;
	uint32_t shown, i, total;
	char range[40];

	list_scroll(v);
	shown = list_shown(v);
	top = list_top(v);
	total = list_total(v);
	/* Heading plus one row an entry, three columns in and w wide: the same
	 * numbers the rows below are positioned with, said once. */
	cl = out_clip_set(o, top, 3, top + (int)shown + 1, 2 + w);

	/* A window of four over a list of thirty has to say so somewhere, or it
	 * reads as a list of four. */
	/*
	 * The filter is named with the word that was clicked to set it.
	 *
	 * The header used to spell it out - "signatures that did not fire" -
	 * which is a sentence where a label belongs, and a different sentence
	 * from the "skip 5" that opened it. Echoing the word makes the dialog
	 * the answer to the click rather than a restatement of it.
	 */
	/*
	 * The note on the right says three things and has to stay unambiguous
	 * when only some of them apply: which filter is on, how many rows there
	 * are under it, and which of them are on screen. A bare "hit  1" said
	 * none of that clearly - the 1 could have been a row number.
	 */
	{
		const char *f = v->list_depth ? "" :
				v->list_filter == 1 ? "Hit: " :
				v->list_filter == 2 ? "Skip: " : "";
		uint32_t off = v->list_depth ? v->str_off : v->list_off;

		if (!total)
			snprintf(range, sizeof range, "%snone", f);
		else if (total > shown)
			snprintf(range, sizeof range, "%s%u-%u of %u", f,
				 off + 1u, off + shown, total);
		else
			snprintf(range, sizeof range, "%s%u", f, total);
	}

	row_start(o, top, 3);
	if (!v->list_depth)
		out_fmt(o, A_DIM " %-52s %-10s%*s" A_OFF, "Signatures",
			"Markers", w - 66, range);
	else
		out_fmt(o, A_DIM " %-14s %6s %8s  %-10s %-12s %-*s" A_OFF,
			"Marker", "db-id", "size", "at", "region",
			w - 59 > 0 ? w - 59 : 1, range);

	for (i = 0; i < shown; i++) {
		row_start(o, top + 1 + (int)i, 3);

		if (!v->list_depth) {
			uint32_t idx = list_nth(v, v->list_off + i);
			const struct kof_touch *e;

			if (idx >= ob->n_touch)
				continue;
			e = &ob->touch[idx];
			char name[80], head[24];

			kof_touch_name(e, name, sizeof name);
			touch_head(e, head, sizeof head);
			list_row(o, idx == v->sel_touch, touch_colour(e));
			{
				size_t off = v->list_hoff < strlen(name)
					     ? v->list_hoff : strlen(name);
				/*
				 * Why a module that matched everything still
				 * did not fire.
				 *
				 * The counts alone are actively misleading
				 * here: a rule ruled out by a precondition
				 * shows 5/5 next to the ones that fired, which
				 * reads as a detection and is the opposite of
				 * what happened. The engine already worked out
				 * the reason and put it in the touch; the list
				 * was throwing it away.
				 */
				const char *no = e->kind == KOF_TOUCH_INELIGIBLE
						 && e->ruled_out
						 ? e->ruled_out : "";
				int room = w - 64 > 0 ? w - 64 : 1;

				out_fmt(o, "%-52.52s %-10s %.*s", name + off,
					head, room, no);
			}
			out_str(o, A_OFF);
			continue;
		}

		/* The markers of one signature, the way kofexamine prints them:
		 * present ones in full, absent ones greyed with a dash where an
		 * offset would be. */
		if (t && v->str_off + i < t->n_str) {
			const struct kof_touch_str *st =
				&t->str[v->str_off + i];
			int miss = st->at == KGENOME_BROKEN;
			int sel = v->str_off + i == v->sel_str;
			char kind[16];

			/*
			 * Neither the size nor the content is read out of the
			 * pool here any more. A hex marker's pool entry is a
			 * compiled program, and every place that reached into
			 * it got that wrong at least once - so the spelling
			 * and the span are filled where the pool IS read, and
			 * this row just prints them.
			 */
			char hx[128], span[16];
			int is_hex = st->kind == KOF_STR_HEX;

			/* Both prefilled where the pool is read, so this row
			 * never has to know a program exists. */
			snprintf(hx, sizeof hx, "%s", st->text);
			snprintf(span, sizeof span, "%s", st->span);

			if (is_hex)
				snprintf(kind, sizeof kind, "hex");
			else
				snprintf(kind, sizeof kind, "str: %s-%s",
					 (st->flags & KOF_STR_FULLWORD) ? "fuw"
									: "sub",
					 (st->flags & KOF_STR_ICASE) ? "i" : "c");

			out_str(o, miss ? A_DIM : (st->in_rgn ? A_OFF : A_WARN));
			if (sel)
				out_str(o, "\033[1m");
			out_str(o, sel ? "*" : " ");
			out_fmt(o, "%-14s %6u %8s  ", kind, st->uid, span);
			if (miss)
				/* The word, not a dash: in a column of
				 * offsets a dash reads as "not applicable"
				 * when what it means is "looked for it and it
				 * is not in this object". */
				out_fmt(o, "%-10s ", "absent");
			else
				out_fmt(o, "%-10llu ",
					(unsigned long long)st->at);
			/*
			 * Where it turned out to be, and whether that is
			 * anywhere this module looks.
			 *
			 * The engine works both facts out and hands them over
			 * as `at` and `in_rgn`; this dialog was spending the
			 * second one on the row's colour alone. Colour says
			 * "something about this row is off", it does not say
			 * WHAT, and the answer here is the whole reason a rule
			 * with every marker present still cannot fire. The
			 * panel says it as CODE>DATA and this now says the
			 * same thing in the same words.
			 */
			{
				char rgn[16];

				if (miss) {
					snprintf(rgn, sizeof rgn, "%s", "-");
				} else {
					/*
					 * The mask the LOCATOR returned, named
					 * with the format's words. It used to
					 * be looked up here from `at`, which
					 * is a second answer to a question
					 * already answered - and no answer at
					 * all for an offset in the symbol
					 * block, where a file lookup said "?".
					 *
					 * The bang is the finding: found, and
					 * not where this module searches.
					 */
					char rw[40];

					if (st->at_mask)
						rng_name_of(cur_obj(v)->fmt,
							    st->at_mask, rw,
							    sizeof rw);
					else
						snprintf(rw, sizeof rw, "?");
					snprintf(rgn, sizeof rgn, "%.10s%s", rw,
						 st->in_rgn ? "" : " !");
				}
				out_fmt(o, "%-12.12s ", rgn);
			}
			/* The marker as it was written - a literal's bytes in
			 * hex, a pattern with its wildcards and gaps intact,
			 * and never the program that implements one. */
			out_fmt(o, "%.40s", hx);
			if (strlen(hx) > 40u)
				out_str(o, "...");
			out_str(o, A_OFF);
		}
	}
	out_clip_restore(o, cl);
	draw_list_box(o, v);
}
