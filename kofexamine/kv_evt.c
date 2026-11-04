#define _GNU_SOURCE
#include "kv.h"
#include "kv_evt_private.h"

/* The offset column: four hex digits and the space after them. It was
 * "0077+392" - offset and length - and the length has gone; see the drawer. */
#define EVT_OFF_W 5


/*
 * THE EVENT PANEL - what the record above it says, in the wording montrace
 * prints.
 *
 * Deliberately the same wording. A reader who has watched the tracer's output
 * scroll past and then opens the log in here is looking at the same events, and
 * two spellings of one record - "pid" in one place and "process id" in the
 * other - is two vocabularies to learn for one fact. kof_evt_field is the one
 * source for both, so they cannot drift.
 */
struct evt_zone {
	int meta[64], warn[64], nm, nw, objrow;
};

/* Every row the panel owns blanked, then the heading and the close control. */
static void evt_draw_head(struct out *o, const struct view *v, int col)
{
	int head = evt_top() - 1;
	int k;
	char note[48];

	/*
	 * EVERY ROW THE PANEL OWNS, BLANKED FIRST.
	 *
	 * The panel is given g_evt_rows rows out of the bottom of the hex pane
	 * and then fills them from several independent pieces - a table whose
	 * length is the record's, warnings the record may not have, a rule and
	 * a box that only exist when the record has an object. Any piece that
	 * does not run leaves its rows untouched, and what shows through is
	 * whatever the pane drew there on the last frame: hex bytes when the
	 * panel has just opened, the draft panel's own buttons when it has
	 * just grown.
	 *
	 * Every one of those was a separate bug with a separate cause. Blanking
	 * the rectangle once, here, answers all of them and any later piece
	 * that forgets - which is the same argument draw_decl's trailing loop
	 * already makes for the draft.
	 */
	for (k = 0; k < g_evt_rows; k++) {
		out_at(o, evt_top() + k, col);
		out_str(o, "\033[K");
	}

	/* The heading, and the same close control the other panel has - a
	 * reader who has closed one knows where the other's is. */
	out_at(o, head, col);
	snprintf(note, sizeof note, " Event %s ",
		 kof_evt_verb_name(v->evt.verb));
	out_fmt(o, A_DIM "--" A_OFF A_BOLD "%s" A_OFF, note);
	out_str(o, A_DIM);
	{
		int used = col + 2 + (int)strlen(note);

		for (k = used; k < g_cols - 4; k++)
			out_str(o, "-");
	}
	out_str(o, A_OFF);
	out_at(o, head, g_cols - 3);
	out_str(o, A_D_KEY "[x]" A_OFF);
}

/* The two-column table and the warnings under it. */
static void evt_draw_table(struct out *o, const struct view *v, int col,
			   const struct evt_zone *z)
{
	int half, k, row;
	int cw = (g_cols - col - 1) / 2;
	int nm = z->nm, nw = z->nw, objrow = z->objrow;
	const int *meta = z->meta, *warn = z->warn;

	/*
	 * THE TABLE, filled DOWN the left column and then down the right.
	 *
	 * Down-then-across, not across-then-down: the rows are in the record's
	 * own layout order, and reading a column top to bottom is then reading
	 * the record front to back. Filled across, consecutive fields would sit
	 * side by side and the eye would have to zigzag to follow the offsets.
	 */
	half = (nm + 1) / 2;
	/*
	 * THE LAST ROW THE TABLE AND THE WARNINGS MAY USE.
	 *
	 * The box is clamped into the panel - see evt_box_top - and its rule
	 * sits one row above it, so everything above stops two rows short of
	 * the box. Without this the table simply carried on and drew THROUGH
	 * the rule and the box, because the counts it walks are the record's
	 * and take no notice of how many rows the panel was given.
	 *
	 * Rows past the bound are dropped rather than scrolled. A record with
	 * more fields than a short terminal can show is a record to read on a
	 * taller one; inventing a second scrollbar for the table would put two
	 * of them in one panel, and the box already has the one that matters.
	 */
	{
		/*
		 * The rule and the box take the bottom of the panel when the
		 * record has an object; when it has none, draw_evt returns
		 * before either and the table may use every row.
		 *
		 * Reading evt_box_top() unconditionally is what broke it: with
		 * no box the value is meaningless, and once it was clamped into
		 * the panel it came out at the panel's own top - so the bound
		 * was above the first row and the table drew nothing at all.
		 */
		int table_last = objrow >= 0 ? evt_box_top(v) - 2 : hex_bot();

	for (k = 0; k < half && evt_top() + k <= table_last; k++) {
		int c2;

		row = evt_top() + k;
		out_at(o, row, col);
		for (c2 = 0; c2 < 2; c2++) {
			int idx = c2 == 0 ? k : half + k;
			char name[32], scratch[256];
			const char *val;
			uint16_t fo = 0, fl = 0;

			if (idx >= nm) {
				out_str(o, "\033[K");
				break;
			}
			if (c2)
				out_at(o, row, col + cw);
			if (!kof_evt_field(&v->evt, (unsigned)meta[idx], name,
					   sizeof name, scratch, sizeof scratch))
				continue;
			val = evt_row_value(v, meta[idx], scratch,
					    sizeof scratch);
			if (!val)
				continue;
			(void)kof_evt_field_extent(&v->evt,
						   (unsigned)meta[idx],
						   &fo, &fl);

			out_fmt(o, A_LOC "%0*X" A_OFF " ", EVT_OFF_W - 1,
				(unsigned)fo);
			out_str(o, evt_row_colour(name));
			out_fmt(o, " %-9.9s ", name);
			out_str(o, A_OFF);
			if (meta[idx] == v->evt_sel)
				out_str(o, A_BOLD);
			out_fmt(o, " %.*s", cw - EVT_OFF_W - 13, val);
			out_str(o, A_OFF);
			if (!c2)
				out_str(o, "\033[K");
		}
	}

	/* The warnings, full width and flush left - they are about the record
	 * as a whole and belong to neither zone. */
	for (k = 0; k < nw && evt_top() + half + k <= table_last; k++) {
		char name[32], scratch[256];

		row = evt_top() + half + k;
		out_at(o, row, col);
		if (kof_evt_field(&v->evt, (unsigned)warn[k], name,
				  sizeof name, scratch, sizeof scratch))
			out_fmt(o, A_WARN "! %s: %.*s" A_OFF, name,
				g_cols - col - 6, scratch);
		out_str(o, "\033[K");
	}
	}   /* table_last */
}

/* The rule above the box, carrying the field name and where its bytes are. */
static void evt_draw_box_rule(struct out *o, const struct view *v, int col, int objrow)
{
	int k, row;

	/*
	 * THE SUBMISSION, in a box of its own.
	 *
	 * A rule above it rather than a heading: the box is the rest of the
	 * panel, so what it holds needs no announcing, and a heading would cost
	 * one of the three lines it has to show text in.
	 */
	row = evt_box_top(v) - 1;
	out_at(o, row, col);
	{
		size_t n = 0;
		char lead[48], scratch[512], bname[32], bval[64];

		(void)evt_box_text(v, scratch, sizeof scratch, &n);
		if (!kof_evt_field(&v->evt, (unsigned)objrow, bname,
				   sizeof bname, bval, sizeof bval))
			bname[0] = '\0';
		{
			uint16_t bo = 0;

			/*
			 * The offset, in the same column format every field
			 * row uses. The box is a field like the others - it is
			 * only drawn differently - and a reader looking for
			 * where its bytes are should not have to click a row to
			 * find out.
			 */
			(void)evt_box_extent(v, &bo, NULL);
			snprintf(lead, sizeof lead, "  %04X  %u B%s ",
				 (unsigned)bo, (unsigned)n,
				 v->evt_wide ? " utf-16" : "");
		}
		/*
		 * THE NAME IN THE TITLE CARRIES THE FIELD'S OWN INK.
		 *
		 * The box is a field like any other and its bytes are lit in
		 * the dump; the title is the only place that says which field
		 * it is, so it is where the legend belongs. Without it the box
		 * was the one coloured run in the pane with nothing on screen
		 * naming it.
		 *
		 * The ink, not the chip. A chip is a block of ground and this
		 * sits inside a rule; the ink is what the dump uses, which is
		 * the thing being matched against.
		 *
		 * Not for `object`, whose bytes are deliberately left to the
		 * dump's own colouring - see evt_byte_colour. Colouring its
		 * title would point at a colour that is not there.
		 */
		out_str(o, A_DIM "--" A_OFF);
		if (strcmp(bname, "object"))
			out_fmt(o, "%s %s" A_OFF, evt_row_ink(bname), bname);
		else
			out_fmt(o, A_DIM " %s" A_OFF, bname);
		out_fmt(o, A_DIM "%s" A_OFF, lead);
		out_str(o, A_DIM);
		for (k = col + 2 + (int)strlen(bname) + 1 +
			 (int)strlen(lead); k < g_cols - 1; k++)
			out_str(o, "-");
		out_str(o, A_OFF);
	}
	out_str(o, "\033[K");
}

/* The box: the lines in view, the picked run, the scrollbar. */
static void evt_draw_box_text(struct out *o, struct view *v, int col)
{
	int lines, k;

	lines = evt_box_total(v);
	if (v->evt_scroll > lines - EVT_BOX_ROWS)
		v->evt_scroll = lines - EVT_BOX_ROWS;
	if (v->evt_scroll < 0)
		v->evt_scroll = 0;

	{
		char scratch[512];
		size_t n = 0;
		const char *t = evt_box_text(v, scratch, sizeof scratch, &n);
		int w = evt_box_w();

		for (k = 0; k < EVT_BOX_ROWS; k++) {
			int at = (v->evt_scroll + k) * w;
			int take = (int)n - at;
			int from = 0, to = 0, a, b;

			/*
			 * The panel's own column, with the indent PRINTED
			 * rather than skipped.
			 *
			 * Nothing else draws the two columns in front of the
			 * box, and the rows above are a table whose offset
			 * column starts exactly there. Jumping straight to
			 * evt_box_x() and clearing only to the right of it
			 * left the first two characters of the PREVIOUS
			 * record's offset standing in front of the text -
			 * "0072" in the table became "00bash -c ..." in the
			 * box when the next record had a shorter table.
			 */
			out_at(o, evt_box_top(v) + k, col);
			out_str(o, "  ");
			if (at >= (int)n || take <= 0) {
				out_str(o, "\033[K");
				continue;
			}
			if (take > w)
				take = w;

			/*
			 * The picked run, clipped to this line - three flat
			 * pieces rather than a colour per character, so the
			 * wrap and the selection cannot disagree about where a
			 * line begins.
			 */
			a = v->evt_txt_a < v->evt_txt_b ? v->evt_txt_a
							: v->evt_txt_b;
			b = v->evt_txt_a < v->evt_txt_b ? v->evt_txt_b
							: v->evt_txt_a;
			from = a - at;
			to   = b - at;
			if (from < 0) from = 0;
			if (to > take) to = take;
			if (a == b || to <= from) {
				out_fmt(o, "%.*s", take, t + at);
			} else {
				out_fmt(o, "%.*s", from, t + at);
				out_str(o, A_SELB);
				out_fmt(o, "%.*s", to - from, t + at + from);
				out_str(o, A_OFF);
				out_fmt(o, "%.*s", take - to, t + at + to);
			}
			out_str(o, A_OFF);
			out_str(o, "\033[K");
		}
		if (lines > EVT_BOX_ROWS)
			kv_scrollbar(o, g_cols, evt_box_top(v),
				  evt_box_top(v) + EVT_BOX_ROWS - 1,
				  (uint64_t)v->evt_scroll, (uint64_t)lines,
				  (uint64_t)EVT_BOX_ROWS);
	}
}

void draw_evt(struct out *o, struct view *v)
{
	int col = TREE_W + 3;
	struct evt_zone z;

	if (!g_evt_rows)
		return;
	z.nm = z.nw = 0;
	z.objrow = evt_zones(v, z.meta, &z.nm, z.warn, &z.nw);
	evt_draw_head(o, v, col);
	evt_draw_table(o, v, col, &z);
	if (z.objrow < 0)
		return;
	evt_draw_box_rule(o, v, col, z.objrow);
	evt_draw_box_text(o, v, col);
}
