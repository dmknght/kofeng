#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The draft panel's Blocks table: the heading controls, the window of drawn rows and the row hit callbacks. */

/* Defined below; a row registers its own callback before the callback is written. */
static void hit_fold(struct view *v, uint32_t which);
static void hit_plg_tick(struct view *v, uint32_t i);
static uint8_t obj_repr_fmt(const struct object *o);
static uint32_t mtn_n_picked(const struct view *v);
static void hit_plg_cfg(struct view *v, uint32_t i);
static void hit_plg_light(struct view *v, uint32_t i);
static int decl_table_head(struct out *o, struct view *v, int r, const char *name, int folded, uint32_t which, const char *cols, const char *summary);
static int blk_any_decided(const struct view *v, const struct kof_diag_report *dd, uint32_t n);




/*
 * THE BLOCK TABLE, which is the whole of Mutation mode's own screen.
 *
 * One row per marked block:
 *
 *     [x] 3a7f21c9   1024 B  CODE  raw   112 hash
 *      ^   ^
 *      |   the block's name, and what the mouse points at to light it
 *      the tick: does this block go into the generated rule
 *
 * THE NAME IS THE CONTROL, and that is the one thing about this layout worth
 * arguing for. A row of a table is not obviously clickable and a button labelled
 * "show" repeated down a column is noise; the value a reader is already looking
 * at to tell two blocks apart is the thing they reach for. Clicking it lights
 * the block in the hex pane and paints the value in that block's colour;
 * clicking it again puts both back.
 *
 * THE SWATCH IS THE VALUE ITSELF, not a separate square. Two facts drawn as one
 * cannot disagree, and a colour chip beside a name is a second place to get the
 * pairing wrong.
 */
/*
 * Clicking the tick chooses whether the block is written into the rule;
 * clicking the name lights it. Two controls on one row because they are two
 * independent questions - a block may be worth looking at and not worth
 * shipping, and the common case while choosing is exactly that.
 */
/* The fold handle, on the column row of the block table. */
static void hit_fold(struct view *v, uint32_t which)
{
	(void)which;
	v->blk_fold = !v->blk_fold;
}

static void hit_plg_tick(struct view *v, uint32_t i)
{
	if (mtn_foreign(v)) {
		say_err(&v->ed, "These blocks are not in this object");
		return;
	}
	/* A function the engine did not sign (mtn_block.nosig: below the floor, undecodable, ...) has no keys: a rule made of it would carry no hash, so it
	 * is not offered for ticking, and the status line says which reason the engine gave. A signed function row is ticked like every other row. */
	if (i < v->ed.dr.n_blk && v->ed.dr.blk[i].nosig && !v->ed.dr.blk[i].picked) {
		char why[160];

		snprintf(why, sizeof why, "This function has no similarity signature (%s%s): it cannot be ticked",
			 kof_cfgsign_state_name((enum kof_cfgsign_state)v->ed.dr.blk[i].why),
			 v->ed.dr.blk[i].why == KOF_CFGSIGN_BELOW_FLOOR ? ": fewer reachable blocks than the floor" : "");
		say_err(&v->ed, "%s", why);
		return;
	}
	if (i < v->ed.dr.n_blk)
		blk_set_picked(&v->ed, i, !v->ed.dr.blk[i].picked);
}

/*
 * IS THIS ROW STILL SHOWN WHEN ITS TABLE IS FOLDED?
 *
 * Folding hides what the rule is NOT made of. A block the researcher ticked is
 * what the rule IS made of, and hiding it would fold away the answer along with
 * the noise - the reader would have to open the table again to see what they
 * had already chosen.
 *
 * Two functions rather than a flag on the row, because prow_build and the
 * drawer both have to agree about which rows exist, and a predicate written
 * twice is a panel whose clicks land one row out.
 */
int blk_row_shown(const struct view *v, uint32_t i)
{
	return !v->blk_fold || v->ed.dr.blk[i].picked;
}

/*
 * WHETHER THE BLOCK TABLE BELONGS ON THE PANEL AT ALL.
 *
 * A similarity block is a span of an EXECUTABLE'S own bytes - the
 * block question is "did the same builder produce these two programs", and a process
 * record, an event or an archive entry is not a program. Drawn for them, the
 * table offered a researcher rows they could tick and generate nothing from.
 *
 * ASKED OF THE SELECTED OBJECT, NEVER OF THE FILE. A Windows event log can
 * carry an AMSI record and an AMSI record can carry a PE, so "this file is a
 * log" is the wrong question - the right one is what the reader has selected,
 * which is what cur_obj answers. The same log therefore shows the table on the
 * PE inside it and not on the records around it.
 *
 * ONE PREDICATE, TWO CALLERS. prow_build counts the panel's rows and
 * draw_decl_blocks draws them, and a row the draw emits and the count does not
 * is a row that cannot be reached - see the note at the top of prow_build,
 * which is the receipt for the last time those two disagreed.
 */
/*
 * WHAT THIS OBJECT REPRESENTS, which is not always what it IS.
 *
 * An ordinary object is its own format. A NORMALISED VIEW is raw bytes - the
 * engine declares it so, because its header describes a file that no longer
 * exists at those offsets - but what it represents is the ELF or PE it was made
 * from, and everything that asks "is this an executable" means that.
 */
static uint8_t obj_repr_fmt(const struct object *o)
{
	if (!o)
		return 0;
	return o->n_rgn ? o->rgn_fmt : o->ctx.format;
}

int blk_section_shown(struct view *v)
{
	/*
	 * THE VIEW COUNTS, and it is the object this panel is most use on.
	 *
	 * Blocks are cut per region by a rolling hash, so what they measure is
	 * whatever the bytes of that region are - and in a view those bytes are
	 * the region with its padding taken out and its wide text narrowed. Two
	 * samples of one family that differ only in how much padding the linker
	 * left produce different blocks in the file and the same blocks here.
	 *
	 * Asked through obj_repr_fmt because the view is declared raw. Reading
	 * ctx.format directly, this said no to every view - the panel was drawn
	 * for the file and vanished when the reader stepped onto its normalised
	 * form, which is the one place the blocks are most comparable.
	 */
	uint8_t fm = obj_repr_fmt(cur_obj(v));

	return v->ed.dr.n_blk &&
	       (fm == KOF_FMT_ELF || fm == KOF_FMT_PE);
}


/* How many blocks are ticked - what the smart-blocks row is measured over. */
static uint32_t mtn_n_picked(const struct view *v)
{
	uint32_t i, n = 0;

	for (i = 0; i < v->ed.dr.n_blk; i++)
		n += v->ed.dr.blk[i].picked != 0;
	return n;
}





/*
 * A press on the NAME of a function row (signed or not): the engine's CFG of that function (kof_cfgview_build, on request, nothing cached) is drawn by the CFG dialog (kv_cfgdlg.c: the
 * frame of the catalog dialogs, the graph laid out by kv_graph.c). Nothing here lays out or computes anything of the graph; a function the engine cannot make a graph of
 * gets the engine's own sentence in the dialog.
 */
static void hit_plg_cfg(struct view *v, uint32_t i)
{
	struct object *o = cur_obj(v);
	struct kof_cfgview_req rq;

	if (!o || !o->buf.p || i >= v->ed.dr.n_blk)
		return;
	memset(&rq, 0, sizeof rq);
	rq.ctx = &o->ctx;
	rq.data = o->buf;
	rq.func_off = v->ed.dr.blk[i].fn_off;
	rq.func_len = v->ed.dr.blk[i].fn_len;
	rq.funcs = mtn_funcs(v, o);
	rq.sym = o->sym;
	rq.sym_n = o->sym_n;
	rq.names = o->calls_done ? &o->calls : NULL;
	cfgd_open(v, &rq);
}

static void hit_plg_light(struct view *v, uint32_t i)
{
	if (i >= v->ed.dr.n_blk)
		return;
	/* A block with no place in this object has nothing to light and
	 * nowhere to go - see mtn_block.kept. */
	if (!v->ed.dr.blk[i].len)
		return;
	v->ed.dr.blk[i].lit = (uint8_t)!v->ed.dr.blk[i].lit;
	/*
	 * AND SCROLL TO IT, because a colour the pane is not showing is not a
	 * highlight.
	 *
	 * The blocks a carve produces are spread over the whole object - the
	 * first one on a small ELF was sixteen kilobytes in - so lighting one
	 * while the pane sat at the start painted nothing the reader could see,
	 * which reads exactly like the feature not working. Only on lighting:
	 * turning a block off is not a request to go anywhere.
	 */
	if (v->ed.dr.blk[i].lit)
		view_show_in(v, v->node[v->sel_node].obj,
			     v->node[v->sel_node].sym, v->ed.dr.blk[i].off, 0);
}

/*
 * What the step box takes: hex digits and the prefix that says they are hex.
 *
 * A sign is not among them - the row has a control for that, and two ways to
 * say which direction is two places for them to disagree.
 */
int at_digit(int c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F') || c == 'x' || c == 'X';
}

/*
 * Clicking the step of an AT place puts the caret in it.
 *
 * THE VALUE STAYS AND IS SELECTED, for the reason the threshold box gives
 * below: a box that empties itself on the click reads as a control that lost
 * the value rather than one offering to change it, and typing over a
 * selection replaces it anyway.
 *
 * WRITTEN WITH ITS 0x, and that is the whole answer to "hex or decimal". The
 * text is read back by strtoull with base 0 - the same rule the importer uses
 * on generated C - so a prefix means hex and its absence means decimal, and
 * there is no second syntax for the box to disagree with the file about. The
 * prefix being there already is what makes the common case, a hex offset
 * copied off the pane, need no thought.
 */
void at_off_edit_open(struct view *v, uint32_t g)
{
	if (g >= v->ed.dr.n_grp || !grp_is_at(v->ed.dr.grp[g].rule))
		return;
	v->edit = ED_AT_OFF + (int)g;
	snprintf(v->at_buf, sizeof v->at_buf, "0x%llx",
		 grp_at_mag(v->ed.dr.grp[g].at_off));
	v->at_buf_off = 0;
	v->edit_prev = v->edit;
	v->caret = (uint32_t)strlen(v->at_buf);
	/*
	 * THE DIGITS ARE SELECTED AND THE PREFIX IS NOT, which is the whole
	 * of what makes "0x means hex" survive being typed into.
	 *
	 * Selecting all of it, as the threshold box does, meant the first key
	 * replaced the "0x" as well - so clicking a box reading 0x7488 and
	 * typing 2ff left "2ff", which strtoull with base 0 reads as decimal
	 * and stops at the first f: the step became 2. The box said one thing
	 * and the rule held another, with nothing to see.
	 *
	 * Typing over the digits alone gives 0x2ff. Deleting the prefix is
	 * still possible and still means decimal, which is the rule; it is
	 * now something somebody does on purpose rather than by starting to
	 * type.
	 */
	fsel_set(v, v->caret > 2u ? 2u : 0u, v->caret);
}

/* The Tag cell of a unit (a condition, or a block matcher with CH_UNIT_GRP) opens the list of the Syndromes catalog's tags. */
void hit_unit_tag(struct view *v, uint32_t unit)
{
	if (unit & CH_UNIT_GRP) {
		if ((unit & 0xffffu) >= v->ed.dr.n_grp)
			return;
		v->ed.dr.cur_grp = unit & 0xffffu;
	} else {
		if (unit >= v->ed.dr.n_cnd)
			return;
		v->ed.dr.cur_cnd = unit;
	}
	ch_open(v, CH_UTAG, unit, g_my, g_mx);
}

/* The Type cell: the header variant's types; greyed (does nothing) while the header has no variant. */
void hit_unit_type(struct view *v, uint32_t unit)
{
	if (!decl_var_types(v))
		return;
	if (unit & CH_UNIT_GRP) {
		if ((unit & 0xffffu) >= v->ed.dr.n_grp)
			return;
		v->ed.dr.cur_grp = unit & 0xffffu;
	} else {
		if (unit >= v->ed.dr.n_cnd)
			return;
		v->ed.dr.cur_cnd = unit;
	}
	ch_open(v, CH_UTYPE, unit, g_my, g_mx);
}

/* Clicking the threshold puts the caret in it - see the note where it is
 * drawn. */
void hit_grp_pct(struct view *v, uint32_t g)
{
	/*
	 * THE ARGUMENT IS THE MATCHER, not a block.
	 *
	 * It used to be the row of the block table and was bounds-checked
	 * against n_blk, which was the wrong list even when a block matcher
	 * was the only kind with a threshold: what the box edits is a
	 * MATCHER'S number.
	 */
	if (g >= v->ed.dr.n_grp || v->ed.dr.grp[g].kind != GRP_KIND_SIM)
		return;
	v->edit = ED_GRP_PCT + (int)g;
	/*
	 * THE VALUE STAYS ON SCREEN AND IS SELECTED, so the first digit typed
	 * replaces it.
	 *
	 * Left alone, typing APPENDED the way a text field should - click a box
	 * reading 50, type 75, and it holds 5075. Emptying the box on the click
	 * fixed that and broke something worse: the number vanished the moment
	 * it was clicked, which reads as the control losing the value rather
	 * than offering to change it. Selecting it is what every other box does
	 * for Ctrl+A and what field_key already honours - typing over a
	 * selection replaces it.
	 *
	 * edit_prev is set here because field_key's "a field just opened" branch
	 * would otherwise run on the first key and clear the selection again.
	 */
	snprintf(v->grp_pct_buf, sizeof v->grp_pct_buf, "%u",
		 v->ed.dr.grp[g].pct);
	v->grp_pct_off = 0;
	v->edit_prev = v->edit;
	v->caret = (uint32_t)strlen(v->grp_pct_buf);
	fsel_set(v, 0, v->caret);
}

/*
 * THE SIMILARITY TABLE - three ways of being alike, and how alike this file is.
 *
 * ONE ROW PER MEASURE, ticked like a block: the tick is what puts the matcher
 * in the draft, so the control and the evidence for using it are the same row.
 * A menu would have offered the three without saying anything about the object
 * in front of the reader, which is the question that decides between them.
 *
 * THE PERCENTAGE IS THE ONE THE RULE WILL SEE. Each is the same call the
 * generated module makes - kof_mutation_score, kof_mutation_blocks, kof_mutation_shape -
 * so a row reading 64 is not an estimate of what the rule will do. It reads 100
 * on the sample the draft was built from, and means something the moment the
 * reader opens the next one.
 */
/*
 * THE HEAD OF A TABLE IN THE DRAFT PANEL - its name, its fold handle, and
 * either its column names or, folded, what is inside it.
 *
 * ONE DEFINITION, because there are two tables and they are the same object:
 * a heading, a row of column names carrying a handle, and rows underneath. It
 * was written twice for a day and the two already differed in where the handle
 * sat, which is exactly how the panel ends up with two gestures for one idea.
 *
 * The BODY is not shared and should not be. A block row carries a colour, a
 * place in the file and a region; a measure row carries a percentage. Forcing
 * one renderer over both would be a cell function and a width table to say
 * what two short loops already say.
 *
 * `which` is what the handle toggles - see hit_fold. Returns the next panel
 * row, so a caller adds rows after it the way it adds any other.
 */
static int decl_table_head(struct out *o, struct view *v, int r,
			   const char *name, int folded, uint32_t which,
			   const char *cols, const char *summary)
{
	if (PR_VIS(r))
		sec_bar(o, v, PR(r), name);
	r++;
	if (PR_VIS(r)) {
		int y = PR(r), c0;

		row_start(o, y, 1);
		c0 = 1 + (int)o->col_hint;
		/* IN THE TICK'S OWN CELLS, so the column names above the rows
		 * line up with the rows. Drawn as " [-]" because that is what
		 * a row draws, and a header half a cell out of step is a header
		 * that names the wrong column. */
		out_fmt(o, " %s[%c]" A_OFF, A_ID, folded ? '+' : '-');
		hit_add(v, y, c0, (int)o->col_hint, hit_fold, which);
		out_fmt(o, A_DIM "%s" A_OFF, folded ? summary : cols);
	}
	return r + 1;
}





/* Whether any block row of this object was decided by a matched form: the table then has the match column. */
static int blk_any_decided(const struct view *v, const struct kof_diag_report *dd, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < v->ed.dr.n_blk; i++)
		if (kdet_block_part(dd, n, v->ed.dr.blk[i].id, NULL))
			return 1;
	return 0;
}

#define BAND_BG "\033[48;5;236m"   /* a faint background for every second pair of block rows: a long table reads across */

int draw_decl_blocks(struct out *o, struct view *v, int r)
{
	uint32_t i;
	char hdr[96];
	struct object *cob = cur_obj(v);
	uint32_t ndd = 0, nshown = 0;
	const struct kof_diag_report *dd = decided_diags(v, cob, &ndd);

	/*
	 * THE TITLE ROW CARRIES THE ACTIONS.
	 *
	 * Marking a block and writing the rule act on THIS panel and on nothing
	 * else, so they sit on it - the same place the draft panel keeps its
	 * own Generate. They were menu items for one revision and that was
	 * wrong twice over: a menu row that only works while one panel is open
	 * is a row that is dead most of the time, and the Analysis menu is
	 * about the object rather than about whatever pane is showing.
	 */
	/*
	 * EVERY ROW GOES THROUGH PR_VIS, which the draft's drawers already do
	 * and this did not.
	 *
	 * The panel is a window onto a list that is longer than it: the engine
	 * carves as many blocks as the object has areas, and the panel is a
	 * dozen rows. Drawing all of them anyway wrote past the bottom, over
	 * the status line and off the screen - which reads as the table not
	 * being there at all.
	 */
	/*
	 * NO BLOCKS TO SHOW, AND THE TAB SAYS SO. It used to draw nothing at
	 * all, which was right while the table was one section among several;
	 * as a tab's first table, two rows saying why it is empty are what
	 * keeps the tab from reading as broken. prow_blocks counts the same two
	 * rows.
	 */
	if (!blk_section_shown(v)) {
		if (PR_VIS(r))
			sec_bar(o, v, PR(r), " Mutation blocks");
		r++;
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			out_str(o, A_DIM "      none - this object has no "
				"executable code to cut blocks from" A_OFF);
		}
		return r + 1;
	}
	{
		char cols[160], sum[48];

		snprintf(cols, sizeof cols,
			 " use  %-10s  %-8s  %-*s  %6s  %-6s%s",
			 "offset", "hash", (int)MTN_SYM_COL, "name", "size", "region",
			 mtn_kept_any(v) || blk_any_decided(v, dd, ndd) ? "  score" : "");
		snprintf(sum, sizeof sum, " %u block(s), %u ticked",
			 v->ed.dr.n_blk, mtn_n_picked(v));
		snprintf(hdr, sizeof hdr, " Mutation blocks");
		r = decl_table_head(o, v, r, hdr, v->blk_fold, 0u, cols, sum);
	}


	/*
	 * ONE ROW PER BLOCK, scrolled by the panel like every other section.
	 *
	 * It had a window of its own while the table WAS the panel - a band
	 * with fixed rows above and below it - and that band has no meaning now
	 * that the table is one section among several. PR_VIS is the whole of
	 * the clipping, the same as the markers above.
	 */
	for (i = 0; i < v->ed.dr.n_blk; i++) {
		struct mtn_block *b = &v->ed.dr.blk[i];
		int y, c0;
		uint32_t band, at;
		if (!blk_row_shown(v, i))
			continue;
		/* Only the WINDOW is drawn (blk_off, blk_nwin - prow_blocks counted the same rows); the others stay in the table. */
		at = nshown++;
		if (at < v->blk_off)
			continue;
		if (at >= v->blk_off + v->blk_nwin)
			break;
		band = (at / 2u) & 1u;
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		y = PR(r);
		row_start(o, y, 1);
		/* Two rows shaded, two plain: out_add puts the background back after each colour reset of the row. */
		if (band) {
			o->bg = BAND_BG;
			out_str(o, BAND_BG "\033[K");
		}
		/* Past the fold gutter - see decl_table_head. */
		out_str(o, "    ");
		/* The tick. */
		c0 = 2 + (int)o->col_hint;
		out_fmt(o, " [%c]", b->picked ? 'x' : ' ');
		hit_add(v, y, c0, (int)o->col_hint, hit_plg_tick, i);
		/*
		 * AND ONE SPACE THAT PUTS THE ROW UNDER ITS OWN HEADING.
		 *
		 * decl_table_head writes the fold handle as " [-]" - four
		 * cells - and then the column names; the row wrote "    " and
		 * " [x]", which is five. Every column after the tick therefore
		 * sat one cell left of the word naming it, all the way across
		 * both tables. The handle is the odd one out, so the row pays
		 * the cell here rather than the heading losing a space it
		 * needs.
		 */
		out_str(o, " ");

		/*
		 * WHERE IN THIS FILE IT IS. A carried block has no offset here:
		 * its bytes belong to the sample it was cut from, which is also
		 * why it cannot be lit.
		 */
		if (!b->len) {
			out_str(o, A_DIM " " "          " A_OFF);
		} else {
			/*
			 * THE OFFSET LIGHTS THE BLOCK: pressing it does what pressing the hash does for now (hit_plg_light) - the block's bytes in the hex
			 * pane take the block's colour and the pane scrolls to them, a second press puts them out. The cell takes the block's colour
			 * while lit, as the hash does. (On a function row the NAME opens its CFG instead.)
			 */
			out_str(o, " ");
			c0 = 1 + (int)o->col_hint;
			if (b->lit)
				out_str(o, mtn_colour[b->colour % MTN_COLOURS]);
			else
				out_str(o, A_DIM);
			out_fmt(o, "0x%08llx" A_OFF, (unsigned long long)b->off);
			hit_add(v, y, c0, (int)o->col_hint, hit_plg_light, i);
		}
		/*
		 * THE HASH, right after the offset, so the two columns that find a
		 * block are side by side, in its own colour
		 * while lit and plain otherwise - which is the whole feedback
		 * loop: the table says which colour in the hex pane is this
		 * block, and it says it by BEING that colour.
		 *
		 * The gap comes FIRST and uncoloured: opening the colour before
		 * the separating space painted that space too, and the highlight
		 * is the value.
		 */
		out_str(o, "  ");
		c0 = 1 + (int)o->col_hint;
		if (b->lit)
			out_str(o, mtn_colour[b->colour % MTN_COLOURS]);
		/* A function unit has no signature (mtn_block.nosig): a dash, never a zero that reads as a hash. */
		if (b->nosig)
			out_str(o, "-       ");
		else
			out_fmt(o, "%08x", b->id);
		if (b->lit)
			out_str(o, A_OFF);
		hit_add(v, y, c0, (int)o->col_hint, hit_plg_light, i);
		/*
		 * THE NAME, when the block is functions the object names; blank
		 * for data and for anything else. Display only: it is not part of
		 * what the rule matches.
		 */
		/*
		 * THE NAME OF A FUNCTION IS A CONTROL: pressing it asks the engine for that function's CFG and shows it in the CFG dialog (hit_plg_cfg). Only the text of the
		 * name is the target - not the padding after it - and only on a function row (a unit cut from a function; a data row has no name to press).
		 * It looks like every other name: plain. A press there did nothing before.
		 */
		{
			const int fn_row = b->fn_len != 0;
			const int nlen = (int)strnlen(b->sym, MTN_SYM_COL);

			out_str(o, "  ");
			c0 = 1 + (int)o->col_hint;
			out_fmt(o, A_DIM "%-*.*s" A_OFF, (int)MTN_SYM_COL, (int)MTN_SYM_COL, b->sym);
			if (fn_row && nlen)
				hit_add(v, y, c0, c0 + nlen - 1, hit_plg_cfg, i);
		}
		/*
		 * AND ITS SIZE IN THIS FILE, which a carried block also has
		 * none of. A dash says the same thing the blank offset beside
		 * it says; a "0" would read as a block that came out empty.
		 */
		if (!b->len)
			out_str(o, A_DIM "       -" A_OFF);
		else
			out_fmt(o, A_DIM "  %6llu" A_OFF,
				(unsigned long long)b->len);
		/* The region the block was cut from: a fact of the block, shown as it is. */
		out_fmt(o, A_DIM "  %-6.6s" A_OFF, b->rgn);
		/*
		 * HOW MUCH OF IT IS IN THE OBJECT ON SCREEN - the number the
		 * mode is for. Dim at nothing, plain otherwise: a column of
		 * zeroes down a list of blocks that do not apply to this file
		 * should not compete with the one that does.
		 */
		{
			/*
			 * A HUNDRED PER CENT ON ITS OWN SAMPLE IS NOT A
			 * MEASUREMENT, so the column is EMPTY there.
			 *
			 * Every hash of a block came out of the bytes it was
			 * carved from, so scoring it against those same bytes
			 * can only ever answer a hundred - there is no share of
			 * it that could be missing. A number appears when the
			 * block was carried here from another sample, which is
			 * what ticking one and opening the next file does, and
			 * that it is there at all is what says so.
			 */
			/*
			 * WHAT THIS BLOCK SCORED ON THE OBJECT IN FRONT OF US,
			 * and green once it clears what the rule demands.
			 *
			 * Only for a block that came from somewhere else - the
			 * rule the file matched, or a sample ticked before this
			 * one. A block carved from the object on screen scores
			 * a hundred by construction and the column stays empty
			 * for it, which is why the heading appears at all only
			 * when there is something to measure.
			 */
			/* A block a matched form decided says what the ENGINE found of it; one number, in this column. */
			{
				const struct kof_diag_part *part = kdet_block_part(dd, ndd, b->id, NULL);

				if (part)
					out_fmt(o, A_ID "  %3u%%" A_OFF, (unsigned)part->pct);
				else if (b->kept)
				out_fmt(o, "%s  %3u%%" A_OFF,
					blk_clears(&v->ed, (uint32_t)i)
					? "\033[42;30m"
					: b->score ? "" : A_DIM, b->score);
			}
			/*
			 * AND NOTHING ELSE ON THE ROW.
			 *
			 * The threshold was a control here as well, so the one
			 * number the rule decides by was on the panel twice:
			 * once in a column and once inside the condition it is
			 * part of. It lives in the condition - see
			 * draw_mutation_cond - because that is the line that
			 * becomes the rule.
			 */
		}
		if (band) {
			o->bg = NULL;
			out_str(o, A_OFF);
		}
		r++;
	}
	/* The table's own scrollbar, in the column beside the panel's, over the rows of the window (only when the window is whole on screen). */
	{
		int t, bt, full;

		if (blk_win_rows(v, &t, &bt, &full) && full)
			kv_scrollbar(o, g_cols - 1, t, bt, v->blk_off, v->blk_nshown, v->blk_nwin);
	}
	return r;
}

/*
 * WHERE THE BLOCK TABLE'S WINDOW IS ON SCREEN, when the table has more rows than the window (else it has no scroll of its own and answers 0).
 * `top` and `bot` are the screen rows of the part of the window the panel shows; `full` says the whole window is shown (the bar is drawn and
 * pressed only then, a thumb of a half window would describe the wrong span).
 */
int blk_win_rows(const struct view *v, int *top, int *bot, int *full)
{
	int t, b, pt, pb;

	if (v->ed.dr.tab != DT_BLOCKS || !g_decl_rows || v->blk_nshown <= v->blk_nwin || !v->blk_nwin)
		return 0;
	t = PR(v->blk_row0);
	b = PR(v->blk_row0 + v->blk_nwin - 1u);
	pt = decl_top() + 1;
	pb = decl_top() + g_decl_rows - 2;
	*full = t >= pt && b <= pb;
	*top = t < pt ? pt : t;
	*bot = b > pb ? pb : b;
	return *top <= *bot;
}
