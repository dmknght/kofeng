#define _GNU_SOURCE
#include "kv.h"


/* How wide the symbol column is. */
#define MTN_SYM_COL 28u

/*
 * The screen row for the next panel line, or -1 when it is scrolled out.
 *
 * `*r` counts panel rows whether or not they are drawn, so the two halves - the
 * window and the position in the list - stay one number apart and a scrolled
 * panel does not have to be laid out twice.
 */
/*
 * Where a draft row lands once the panel is scrolled, and whether it lands on
 * the screen at all.
 *
 * `r` counts rows of the draft whether or not they are visible, so one number
 * serves both the layout and the scroll position, and a draft longer than its
 * pane does not have to be laid out twice to find out what fits.
 */
#define PR(rr)     (decl_top() + 1 + (int)(rr) - (int)v->prow_off)
#define PR_VIS(rr) ((int)(rr) >= (int)v->prow_off && \
		    (int)(rr) - (int)v->prow_off < g_decl_rows - 2)

/*
 * A heading that runs the width of the screen.
 *
 * The panel is four kinds of thing stacked with nothing between them, which is
 * why it read as one long list. A bar per section costs the row the column
 * headings were already taking and gives the eye somewhere to stop.
 */
/*
 * RE-LOCATE THE STRINGS' REGIONS - a small button, in the region column's own
 * heading rather than a sentence at the end of the row.
 *
 * It reads as one of the row buttons the strings already carry ([x] and the
 * rest) because that is what it is: three characters beside the thing it acts
 * on. Spelled out at the end of the heading it was the widest thing on the row
 * and said in five words what its position says by itself.
 */
#define BTN_UPDRGN "[r]"

/*
 * "[+ str]" - DECLARE A MARKER THAT IS NOT ON THE SCREEN.
 *
 * Every other way in starts from bytes the object already has: select a run in
 * the hex pane, or pick text out of the event box. That covers the common case
 * and misses the one a researcher reaches for next - writing a marker down
 * because they know it belongs to the family, before they have a sample that
 * shows it.
 *
 * On the Strings heading, beside [r], because both are about the table under
 * them. The heading is drawn even when the table is EMPTY for this button's
 * sake: with no declarations there was no heading, so the one control that can
 * create the first declaration had nowhere to be.
 */
/*
 * THE SAME WORD THE OTHER TWO USE, ON A ROW OF ITS OWN.
 *
 * It was "[+ str]" squeezed onto the heading row beside [r], and both things
 * were wrong: the abbreviation matched nothing else in the panel, and the
 * heading is TEXT - sec_bar has already written "size  bytes" across it, so a
 * button positioned from the prefix landed on top of it and the reader saw
 * "[+ str]ytes". The add row at the foot of a table is the shape the matchers
 * and the conditions already have, it needs no column arithmetic, and there is
 * nothing on it to collide with.
 */
#define BTN_ADDSTR "[+ String]"
/* " Intron      attr       region" - the heading up to and including the
 * region title, so the button's column is measured from it rather than counted
 * by hand. "Intron" is the owner's name for the table of patterns; the word
 * marker still means a pattern that was found. */
/*
 * ONE COLUMN FOR BOTH ATTRIBUTES - see decl_attr_text in kofeditor.h.
 *
 * It was "word" and "case", nine and eleven characters wide, and twenty-one
 * columns of a row whose last field is the bytes somebody opened the file to
 * read. The cell is at most "i:pattern", so the column is nine and the table
 * gains eleven.
 */
#define STR_ATTR_W 9
#define STR_HDR_PRE " Intron      attr       region"

/*
 * A SEARCH MATCHER'S LIST ROW: the markers it is about, joined by commas, with
 * the button that adds another at the end. (A block matcher has no list: it is
 * one block, named on its first row.)
 *
 * THE SPANS ARE RECORDED AS THEY ARE DRAWN, which is what the marker row's own
 * note asked for: where an item is on the screen is a fact the drawing has, and
 * a hit test that re-derives it is a second copy of the arithmetic - which is
 * exactly how the marker row came to remove the wrong marker once an id reached
 * two digits.
 */
struct grp_list {
	struct out  *o;
	struct view *v;
	int          y;
	uint32_t     g;
	int        (*span)[2];      /* where each item landed, by slot */
	uint32_t     cap;
	uint32_t     n;             /* how many were drawn */
};


/* The row callbacks, declared here because a row registers its own and the
 * draw that does so comes before the bodies. */
static void hit_row_fmts(struct view *v, uint32_t arg);
static void hit_row_opt(struct view *v, uint32_t i);
static void hit_row_strhdr(struct view *v, uint32_t arg);
static void hit_row_str(struct view *v, uint32_t i);
static void hit_row_matcher(struct view *v, uint32_t g);
static void hit_row_markers(struct view *v, uint32_t g);
/* The shared matcher rows - see grp_list, defined with the panel below. */
static uint32_t glist_hit(const int (*span)[2], uint32_t n);
static void hit_row_addmatcher(struct view *v, uint32_t arg);

/* Names a region mask - defined with the range menu it belongs to, declared
 * here because locating a string needs it to say where the string turned up. */

/* ---- collecting the objects ------------------------------------------------ */

/* The heading row's controls. One span each, registered where each is drawn -
 * see the note above draw_decl_head on what sharing a field cost. */
static void hit_plg_tick(struct view *v, uint32_t i);
static void hit_plg_light(struct view *v, uint32_t i);
static void hit_plg_goto(struct view *v, uint32_t i);
static void hit_grp_pct(struct view *v, uint32_t i);
static void hit_grp_tag(struct view *v, uint32_t g);
static void hit_plg_rgn(struct view *v, uint32_t i);
static void hit_head_type(struct view *v, uint32_t arg);
static void hit_head_family(struct view *v, uint32_t arg);
static void hit_head_note(struct view *v, uint32_t arg);
static void hit_head_gen(struct view *v, uint32_t arg);
static void hit_head_discard(struct view *v, uint32_t arg);
static void hit_fold(struct view *v, uint32_t which);
static uint32_t mtn_n_picked(const struct view *v);
static void hit_row_ranges(struct view *v, uint32_t arg);
static void hit_optbtn(struct view *v, uint32_t arg);

/* Defined with the other field openers, far below; the matcher row's hit test
 * runs first. */
static void at_off_edit_open(struct view *v, uint32_t g);
/*
 * draw_decl_head - the row that names the rule: family, type, options, Generate, the note.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
/*
 * THE HEADING ROW'S CONTROLS, one callback each.
 *
 * This row was the last one still answering clicks by walking a chain of
 * column pairs, and it is what that chain costs: it tested o_c0/o_c1 - the
 * "[+ Options]" button, which is drawn on a DIFFERENT ROW - and those columns
 * (9..20) sit on top of "[Virus]" (7..13). Clicking the type therefore opened
 * the options list, because the options branch came first.
 *
 * Exactly the bug the comment on n_c0 already recorded, in the same chain, for
 * the same reason: a column pair that outlives the row it was measured on is
 * read by whatever else happens to be at those columns. A span registered by
 * the row that painted it cannot be read by another row at all.
 */
static void hit_head_type(struct view *v, uint32_t arg)
{
	(void)arg;
	ch_open(v, CH_TYPE, 0, g_my, g_mx);
}

static void hit_head_family(struct view *v, uint32_t arg)
{
	(void)arg;
	v->edit = 1;
}

static void hit_head_note(struct view *v, uint32_t arg)
{
	(void)arg;
	v->edit = 501;
}

/*
 * GENERATE LISTS THE OUTPUT, and writes nothing.
 *
 * The backend of a diagnose generator is not settled, so the button lists the
 * output - one entry per condition - under the tables, and pressing it again
 * takes the list away. It needs a condition to list; without one it says so
 * instead of showing an empty pane that reads as a result.
 */
static void hit_head_gen(struct view *v, uint32_t arg)
{
	(void)arg;
	if (!v->ed.dr.n_cnd) {
		say_note(&v->ed, "Add a condition first");
		return;
	}
	v->gen_preview = !v->gen_preview;
}

static void hit_head_discard(struct view *v, uint32_t arg)
{
	(void)arg;
	/* No confirmation. The panel is a draft, not a document: what it holds
	 * was typed a moment ago, and a dialog between the button and the blank
	 * sheet is a step in the way of the thing the button is for. */
	if (v->ed.dr.n_decl || v->ed.dr.family[0]) {
		draft_reset(&v->ed);
		v->gen_preview = 0;
		v->prow_home = 1;
	}
}

/*
 * The column the Generate block starts at - see the marks above.
 *
 * One function because two places need the same number: the block draws itself
 * there, and the comment box measures the gap up to it. Two copies of this
 * arithmetic is how the comment came to overlap the buttons in the first place.
 */
static int head_btn_x(const struct view *v)
{
	int x = g_cols - NEW_BTN_W - GEN_BTN_W - HEAD_RMARGIN;

	(void)v;

	return x < 2 ? 2 : x;
}

static void draw_decl_head(struct out *o, struct view *v)
{
	int top = decl_top();
	int c;

	/*
	 * TYPE FIRST, THEN FAMILY, and the order is the name a verdict is read
	 * in: "Trojan:mirai" says what KIND before it says which one. The row
	 * used to lead with the family, so the eye met a name with nothing to
	 * hang it on.
	 */
	row_start(o, top, 1);
	c = 2 + (int)o->col_hint;
	out_fmt(o, A_DIM " Type " A_OFF A_ID "[%s]" A_OFF,
		maltype_word[v->ed.dr.maltype % MALTYPE_N]);
	v->t_c0 = c; v->t_c1 = (int)o->col_hint;
	hit_add(v, top, c, (int)o->col_hint, hit_head_type, 0);

	/*
	 * THE BRACKETS HUG THE NAME; THE SPACE THEY GIVE BACK IS PADDED AFTER
	 * THEM.
	 *
	 * Two rules that look like one and are not. A family is a word -
	 * "mirai", "Meterp" - and drawn in a fixed 24 column hole it sat in
	 * eighteen columns of blank bracket, which reads as a field waiting for
	 * more rather than a field holding an answer. So the box is as wide as
	 * the name, up to FAM_W; past that the text scrolls inside it as it
	 * always has.
	 *
	 * What must NOT follow from that is the row moving. This was once
	 * FAM_W while focused and the text's length otherwise, so clicking the
	 * field widened it and shoved the comment box and the buttons
	 * sideways - a control you have to chase. The fix then was to fix the
	 * width; the fix now is narrower than that: the columns the box does
	 * not use are emitted as SPACES after its closing bracket, so the row
	 * consumes exactly FAM_W either way and everything downstream is laid
	 * out against the same mark it always was. The width also no longer
	 * depends on focus - only on the name - so pointing at it still changes
	 * nothing.
	 *
	 * One column past the text while editing, because the caret may sit one
	 * past the last character - the same allowance field_draw makes when it
	 * decides how far to scroll.
	 */
	{
		int fw = field_room(v->ed.dr.family, "?", v->edit == 1, FAM_W);

		c = 2 + (int)o->col_hint;
		out_fmt(o, A_DIM "  Family " A_OFF "%s[",
			v->edit == 1 ? A_SEL : A_ID);
		field_draw(o, v->ed.dr.family, v->caret, &v->fam_off, fw,
			   v->edit == 1, "?");
		out_str(o, "]" A_OFF);
		/*
		 * The click range is the box as DRAWN, not the space it
		 * reserves. A reader clicks what they can see; the blank
		 * columns past the bracket belong to the row.
		 */
		v->f_c0 = c; v->f_c1 = (int)o->col_hint;
		hit_add(v, top, c, (int)o->col_hint, hit_head_family, 0);
		while (fw++ < FAM_W)
			out_str(o, " ");
	}

	/* No label: the box says what it is, and the row is already a line of
	 * labels. */
	out_str(o, "  ");
	c = 1 + (int)o->col_hint;
	{
		/*
		 * As wide as the row has left, and scrolled within that.
		 *
		 * A fixed width would either waste the space on a wide terminal
		 * or cut the text short on a narrow one; what is actually
		 * available is known here and nowhere else.
		 */
		size_t len = strlen(v->ed.dr.note);
		/*
		 * IT TAKES THE GAP, and the gap has two fixed ends.
		 *
		 * This took the row minus the Discard button, and the buttons
		 * between the two were painted AFTER it from wherever it left
		 * the cursor - so the comment ate their columns and Generate
		 * was pushed off the end of the row. Now the buttons are
		 * anchored to the right edge and this is measured against where
		 * they start, so the two cannot overlap however long the note
		 * gets.
		 */
		int room = head_btn_x(v) - c - 3;
		uint32_t off;

		/*
		 * AND NO WIDER THAN A NOTE NEEDS TO BE.
		 *
		 * Filling the gap made the box as wide as the terminal - on a
		 * 140 column screen, ninety columns of empty bracket for a
		 * one-line remark. The gap is what it may not EXCEED, not what
		 * it should take: past a point a longer box stops being more
		 * room and starts being a hole in the row.
		 *
		 * The text still scrolls inside it, so a long note is not cut
		 * off, it is read by moving through it - which is what every
		 * other field on this row does.
		 */
		if (room > NOTE_W)
			room = NOTE_W;
		if (room < 8)
			room = 8;
		(void)len; (void)off;
		/*
		 * AND NO WIDER THAN WHAT IS IN IT. The gap above is the most it
		 * MAY take; this is what it needs. Nothing is padded back
		 * because what follows on this row is drawn at an absolute
		 * column - see head_btn_x - so a shorter box cannot move it.
		 */
		room = field_room(v->ed.dr.note, "Comment...",
				  v->edit == 501, room);
		out_fmt(o, "%s[", v->edit == 501 ? A_SEL : A_DIM);
		field_draw(o, v->ed.dr.note, v->caret, &v->note_off, room,
			   v->edit == 501, "Comment...");
		out_str(o, "]" A_OFF);
	}
	v->nt_c0 = c; v->nt_c1 = (int)o->col_hint;
	hit_add(v, top, c, (int)o->col_hint, hit_head_note, 0);

	{
		/*
		 * ANCHORED TO THE RIGHT EDGE, BESIDE DISCARD.
		 *
		 * Drawn with out_at rather than after whatever the comment box
		 * left behind, which is what let a long note push it off the
		 * row. Green when there is a condition to list, lit while the
		 * list is shown.
		 *
		 * What is wrong or missing with a draft is the status line's: a
		 * running commentary beside the button pushed the controls
		 * sideways as it changed length.
		 */
		c = head_btn_x(v);
		out_at(o, top, c);
		out_fmt(o, "%s[ Generate ]" A_OFF,
			v->gen_preview ? A_SEL :
			v->ed.dr.n_cnd ? "\033[42;30m" : "\033[47;90m");
		v->g_c0 = c; v->g_c1 = c + GEN_BTN_W - 1;
		hit_add(v, top, v->g_c0, v->g_c1, hit_head_gen, 0);
	}
	/*
	 * THROW THE DRAFT AWAY, at the far right of the row.
	 *
	 * A draft with markers declared on one object has no use on the next,
	 * and there is no way back to an empty panel short of leaving the
	 * program: the next thing somebody wants is a blank sheet.
	 *
	 * At the far end rather than beside Generate: green is what that button
	 * wears, this one throws the panel away, and a discard next to the
	 * button that makes something is how a misclick happens.
	 */
	out_at(o, decl_top(), g_cols - NEW_BTN_W + 1 - HEAD_RMARGIN);
	v->nw_c0 = g_cols - NEW_BTN_W + 1 - HEAD_RMARGIN;
	out_fmt(o, " %s[ Discard ]" A_OFF,
		v->ed.dr.n_decl || v->ed.dr.family[0] ? A_ID : "\033[47;90m");
	/* Where it actually ends, not where the row does - the column past it
	 * belongs to the border and a click there is not a click on this. */
	v->nw_c1 = g_cols - HEAD_RMARGIN;
	hit_add(v, decl_top(), v->nw_c0, v->nw_c1, hit_head_discard, 0);
}

/*
 * draw_decl_fmts - what object formats the rule applies to.
 *
 * Its own row above the options, because it is not optional: a module must say
 * what it applies to or ksigbuilder refuses it, and a required declaration
 * drawn among the optional ones reads as one more thing you may skip.
 *
 * Shaped like the scan ranges below it on purpose - a list of names, each one a
 * control for itself, and a button at the END of the list rather than flushed
 * right. The two rows answer the same kind of question and a reader who learns
 * one has learned the other.
 */
static int draw_decl_fmts(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		uint8_t f;
		int c;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Format " A_OFF);
		v->n_fmt_hs = 0;
		for (f = 0; f < KOF_FMT_COUNT; f++) {
			int c0;

			if (!(v->ed.dr.fmt_mask & (1u << f)))
				continue;
			out_str(o, " ");
			c0 = o->col_base + (int)o->col_hint;
			out_fmt(o, A_LOC "%s" A_OFF, kof_format_name(f));
			if (v->n_fmt_hs < KOF_FMT_COUNT) {
				v->fmt_hs[v->n_fmt_hs][0] = c0;
				v->fmt_hs[v->n_fmt_hs][1] =
					o->col_base + (int)o->col_hint - 1;
				v->n_fmt_hs++;
			}
		}
		/* WARN and not DIM: a draft with no format cannot be written,
		 * and the row that says so should not look like a row with
		 * nothing interesting on it. */
		if (!v->n_fmt_hs)
			out_str(o, A_WARN " None" A_OFF);

		out_str(o, "  ");
		c = o->col_base + (int)o->col_hint;
		/* A_ID, the same as [+ Options], [+ Matcher], [+ String] and
		 * [+ Condition]. It used to wear the menu bar's grey, which
		 * made two of the five add-buttons look like a different kind
		 * of control from the other three. */
		out_fmt(o, A_ID "[+ Formats]" A_OFF);
		v->fma_c0 = c;
		v->fma_c1 = o->col_base + (int)o->col_hint - 1;

		hit_add(v, PR(r), 0, g_cols - 1, hit_row_fmts, 0);
	}
	r++;                            /* the target format row, always */
	return r;
}

/*
 * draw_decl_opts - the optional KOF_TARGET_ declarations.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
/*
 * The button that adds an optional declaration, on a row of its own under the
 * formats.
 *
 * NOT on the Format row and not on the name row above it. It belongs to the
 * list it extends - the optional declarations drawn below - and the list has no
 * row at all until one exists, so the button has to carry the row itself.
 */
static void hit_row_opt(struct view *v, uint32_t i)
{
	if (g_mx >= g_cols - 4) {
		v->ed.dr.opt_on[i] = 0;
	} else if (g_mx >= v->opt_c0[i] && g_mx <= v->opt_c1[i]) {
		if (i == OPT_ARCH)
			ch_open(v, CH_ARCH, 0, g_my, g_mx);
		else if (i == OPT_SUBTYPE)
			ch_open(v, CH_SUBTYPE, 0, g_my, g_mx);
		else {
			/* A size is typed, so the field starts from what it
			 * says rather than empty. */
			snprintf(v->num, sizeof v->num, "%llu",
				 (unsigned long long)v->ed.dr.opt_val[i]);
			/* Opened by a click, so it starts selected: the first
			 * digit replaces rather than extends, which is what
			 * clicking a number and typing one means everywhere
			 * else. */
			v->num_fresh = 1;
			v->edit = 200 + (int)i;
		}
	}
}

static void hit_row_str(struct view *v, uint32_t i)
{
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

/* [+ Matcher] - a new matcher, whose rule is chosen before it has anything. */
static void hit_row_addmatcher(struct view *v, uint32_t arg)
{
	(void)arg;
	if (g_mx >= v->n_c0 && g_mx <= v->n_c1)
		ch_open(v, CH_RULE, MAX_GROUP, g_my, g_mx);
}

static void hit_row_matcher(struct view *v, uint32_t g)
{
	v->ed.dr.cur_grp = g;
	v->ed.dr.warn[0] = 0;
	if (v->ed.dr.grp[g].kind == GRP_KIND_SIM) {
		/*
		 * A BLOCK MATCHER'S ROW has the threshold and the comment and
		 * nothing else to press: no kind to turn it into, no [x] - the
		 * block's tick made it and the tick takes it away. The
		 * threshold registered its own span as it was drawn, so it is
		 * answered there and not here.
		 */
		if (v->grp_nt[g][0] > 0 && g_mx >= v->grp_nt[g][0] &&
		    g_mx <= v->grp_nt[g][1])
			v->edit = 300 + (int)g;
	} else if (g_mx >= g_cols - 4)
		grp_remove(&v->ed, g);
	else if (g_mx >= v->grp_rl[g][0] &&
		 g_mx <= v->grp_rl[g][1])
		ch_open(v, CH_RULE, g, g_my, g_mx);
	else if (v->grp_sg[g][0] >= 0 && g_mx >= v->grp_sg[g][0] &&
		 g_mx <= v->grp_sg[g][1]) {
		/*
		 * THE OTHER WAY, AND THE NUMBER IS NOW THE AUTHOR'S.
		 *
		 * Flipping the sign names a different byte, so whatever the
		 * engine had located is no longer what this holds - see
		 * group.at_auto, which is what stops a later anchor change
		 * from converting a step somebody chose.
		 */
		struct group *q = &v->ed.dr.grp[g];

		q->at_off = -q->at_off;
		q->at_auto = 0;
		grp_at_fix_sign(q);
	} else if (v->grp_of[g][0] >= 0 && g_mx >= v->grp_of[g][0] &&
		   g_mx <= v->grp_of[g][1]) {
		at_off_edit_open(v, g);
	} else if (g_mx >= v->grp_rg[g][0] &&
		 g_mx <= v->grp_rg[g][1])
		/* The same half of the row, asking the
		 * question that half asks for this
		 * rule: which region, or which of the
		 * marker's occurrences. */
		ch_open(v,
			grp_is_at(v->ed.dr.grp[g].rule)
			? CH_ATOFF : CH_RANGE,
			g, g_my, g_mx);
	else if (v->grp_th[g][0] > 0 &&
		 g_mx >= v->grp_th[g][0] &&
		 g_mx <= v->grp_th[g][1])
		ch_open(v, CH_THRESH, g, g_my, g_mx);
	else if (v->grp_nt[g][0] > 0 &&
		 g_mx >= v->grp_nt[g][0] &&
		 g_mx <= v->grp_nt[g][1])
		v->edit = 300 + (int)g;
	
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
	 * columns - three apiece, which assumed every id was one digit. MAX_DECL
	 * is 32, so from the first two-digit id on, every id after it drifted a
	 * column left and the click removed the wrong marker or none. The
	 * drawing records each span now - see grp_list - so there is one copy
	 * of the arithmetic and it is the one that painted the row.
	 */
	slot = glist_hit(v->grp_it[g], GRP_SIM_MAX);
	if (slot >= GRP_SIM_MAX)
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
	if (v->ed.dr.n_decl >= MAX_DECL)
		return;
	/* WHICH KIND, asked before anything is created - see CH_DECLKIND. The
	 * three are not variations on one declaration: they are compiled by
	 * different front ends and spelled in different fields. */
	ch_open(v, CH_DECLKIND, 0, g_my, g_mx);
	return;
}

/*
 * ONE SPAN PER ROW, and the row's own column tests inside it.
 *
 * The defect was never the column arithmetic - that was written beside the
 * paint and proved. It was the ROW COUNTER: click_panel_rows re-derived which
 * row is which by counting in the order the draw emits them, so a row added to
 * one and not the other shifted every click below it. Registering the row where
 * it is painted removes the counting; the tests below are the walk's, verbatim.
 */
static void hit_row_fmts(struct view *v, uint32_t arg)
{
	uint32_t h;

	(void)arg;
	for (h = 0; h < v->n_fmt_hs; h++)
		if (g_mx >= v->fmt_hs[h][0] && g_mx <= v->fmt_hs[h][1]) {
			ch_open(v, CH_FMT, h, g_my, g_mx);
			return;
		}
	if (g_mx >= v->fma_c0 && g_mx <= v->fma_c1)
		ch_open(v, CH_FMT_CAT, 0, g_my, g_mx);
}

static void hit_row_ranges(struct view *v, uint32_t arg)
{
	uint32_t h;

	(void)arg;
	/* A NAME IS THE SUBJECT. Which range was pressed is passed as the
	 * menu's argument, so every item it offers is about that one. */
	for (h = 0; h < v->n_rng_hs; h++)
		if (g_mx >= v->rng_hs[h][0] && g_mx <= v->rng_hs[h][1]) {
			ch_open(v, CH_RANGE2, h, g_my, g_mx);
			return;
		}
	if (g_mx >= v->rga_c0 && g_mx <= v->rga_c1)
		ch_open(v, CH_RANGE_ADD, 0, g_my, g_mx);
}

/* [+ Options] - the only control on its row. */
static void hit_optbtn(struct view *v, uint32_t arg)
{
	(void)arg;
	ch_open(v, CH_OPT, 0, g_my, g_mx);
}

static int draw_decl_optbtn(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		int c;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Option " A_OFF);
		c = o->col_base + (int)o->col_hint;
		out_fmt(o, " " A_ID "[+ Options]" A_OFF);
		/*
		 * ONE SPAN, ON THIS ROW, AND NOWHERE ELSE.
		 *
		 * o_c0/o_c1 used to be written here as well, because the
		 * heading row's click chain read them - and those columns land
		 * on "[Virus]" up there, so the type box opened this list
		 * instead of its own. The field is gone with that chain.
		 */
		hit_add(v, PR(r), c, o->col_base + (int)o->col_hint - 1,
			hit_optbtn, 0);
	}
	r++;                            /* the option button row, always */
	return r;
}

/*
 * THE FORMAT A SUBTYPE IS READ AGAINST - the one the DRAFT declares, not the
 * one the object under the cursor happens to be.
 *
 * The panel and the preview have to agree about which format a subtype belongs
 * to, or the panel shows one thing and the preview says another.
 *
 * It shows up first on an event record, which has no format at all - the node
 * is built straight out of the mapping and never parsed - so the row printed
 * "?" beside a platform it had already written into the draft correctly.
 */
static uint8_t draft_sub_fmt(struct view *v)
{
	uint32_t fi;

	for (fi = 0; fi < KOF_FMT_COUNT; fi++)
		if (v->ed.dr.fmt_mask & (1u << fi))
			return (uint8_t)fi;
	return cur_obj(v) ? cur_obj(v)->ctx.format : (uint8_t)KOF_FMT_UNKNOWN;
}

/*
 * WHAT AN OPTION'S VALUE IS CALLED, written once: the option rows draw it and
 * the output pane lists it, and two spellings of one value would drift.
 */
static void opt_text(struct view *v, uint32_t i, char *val, size_t cap)
{
	if (i == OPT_ARCH)
		snprintf(val, cap, "%s",
			 arch_word[v->ed.dr.opt_val[i] < ARCH_N
				   ? v->ed.dr.opt_val[i] : 0].word);
	else if (i == OPT_SUBTYPE) {
		const char *w = kof_inspect_subtype_name(
			draft_sub_fmt(v), (uint8_t)v->ed.dr.opt_val[i]);

		snprintf(val, cap, "%s", w ? w : "?");
	} else
		snprintf(val, cap, "%llu",
			 (unsigned long long)v->ed.dr.opt_val[i]);
}

static int draw_decl_opts(struct out *o, struct view *v, int r)
{
	uint32_t i;

	for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
		char val[40];
		int y;

		if (!v->ed.dr.opt_on[i])
			continue;
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		y = PR(r);
		r++;
		opt_text(v, i, val, sizeof val);
		row_start(o, y, 1);
		out_fmt(o, "   %s%-20s" A_OFF " ", A_DIM, opt_word[i]);
		v->opt_c0[i] = 1 + (int)o->col_hint;
		if (v->edit == 200 + (int)i) {
			out_str(o, A_SEL);
			field_draw(o, v->num, v->caret, &v->num_off, 18, 1, "");
			out_str(o, A_OFF);
		} else {
			out_fmt(o, "%s%s" A_OFF, A_ID, val);
		}
		v->opt_c1[i] = (int)o->col_hint;
		out_at(o, y, g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
		hit_add(v, y, 0, g_cols - 1, hit_row_opt, i);
	}

	/*
	 * What the finished source will declare, read only.
	 *
	 * A range has no existence apart from a matcher naming one, so there is
	 * nothing here to add, rename or delete - and nothing that can be left
	 * pointing at a marker that has gone. It is a summary, and its whole job
	 * is answering "which ranges is this signature going to search", which
	 * is the question that made a managed list look necessary.
	 */
	return r;
}

/*
 * draw_decl_ranges - the scan ranges the draft declares.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
static int draw_decl_ranges(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(&v->ed, rm, ru, 2u * MAX_GROUP), k;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Region " A_OFF);
		/*
		 * EACH NAME IS A CONTROL, and its own subject.
		 *
		 * The row used to end in one [Update scan range] button that
		 * acted on "a range" and then asked which one - a question the
		 * reader had already answered by looking at the row. Clicking
		 * the name opens the menu for THAT range, so extend, drop and
		 * remove all read as things done to the thing pressed.
		 *
		 * An unused range - declared, no matcher searching it - is
		 * still named and still clickable, because removing it is the
		 * one thing it needs and this is where that lives.
		 */
		v->n_rng_hs = 0;
		for (k = 0; k < nr; k++) {
			char t[40];
			int c0;

			rng_name_of(cur_obj(v)->fmt, rm[k], t, sizeof t);
			out_str(o, " ");
			c0 = o->col_base + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, ru[k] ? A_WARN : A_LOC, t);
			if (ru[k])
				out_fmt(o, A_DIM " (unused)" A_OFF);
			if (v->n_rng_hs < 2u * MAX_GROUP) {
				v->rng_hs[v->n_rng_hs][0] = c0;
				v->rng_hs[v->n_rng_hs][1] =
					o->col_base + (int)o->col_hint - 1;
				v->n_rng_hs++;
			}
		}
		if (!nr)
			out_str(o, A_DIM " None" A_OFF);
		/*
		 * And a way to declare one more, at the END of the names rather
		 * than flushed to the right edge: it belongs to the list it
		 * extends, and a control parked in the corner reads as being
		 * about the panel instead.
		 */
		{
			int c0;

			out_str(o, "  ");
			c0 = o->col_base + (int)o->col_hint;
			/* A_ID, like every other add-button - see [+ Formats]. */
			out_fmt(o, A_ID "[+ Scan region]" A_OFF);
			v->rga_c0 = c0;
			v->rga_c1 = o->col_base + (int)o->col_hint - 1;
		}
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_ranges, 0);
	}
	r++;                            /* the scan ranges row, always */
	return r;
}

/*
 * draw_decl_strings - the markers, and the column widths they decide.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
static int draw_decl_strings(struct out *o, struct view *v, int r)
{
	uint32_t i;


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
	for (i = 0; i < v->ed.dr.n_decl; i++, r++) {
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
		 * not step sideways when the list reaches ten. Two digits is
		 * the whole range: MAX_DECL is 32. */
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
			char both[40];

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
			out_fmt(o, A_DIM "%5.5s" A_OFF, cnt);
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
static void draw_grp_note(struct out *o, struct view *v, uint32_t g)
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
 * A TAG CELL: the name of the tag, and - only when another tag has the same
 * name - what tells them apart (tag_label); "none" while nothing is chosen. A
 * cell that names a tag the sources no longer have says so in red, because the
 * diagnose it would write has nothing to say.
 */
static void draw_tag_cell(struct out *o, struct view *v, uint64_t tag)
{
	char lab[160];

	if (!tag) {
		out_str(o, A_DIM "none" A_OFF);
		return;
	}
	tag_label(&v->ed, tag, lab, sizeof lab);
	if (!lab[0]) {
		out_str(o, A_BAD "tag not found" A_OFF);
		return;
	}
	if (strlen(lab) > 40u)
		memcpy(lab + 38, "~", 2);
	out_fmt(o, "%s%s" A_OFF, A_ID, lab);
}

static void glist_begin(struct grp_list *L, struct out *o, struct view *v,
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

static void glist_item(struct grp_list *L, const char *text)
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
static void glist_end(struct grp_list *L, int can_add, const char *label)
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
static void glist_gone(struct view *v, uint32_t g)
{
	uint32_t i;

	for (i = 0; i < GRP_SIM_MAX; i++)
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
static void ghead_lead(struct out *o, struct view *v, int y, uint32_t g,
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
static void grp_spans_off(struct view *v, uint32_t g)
{
	v->grp_rl[g][0] = v->grp_rl[g][1] = -1;
	v->grp_rg[g][0] = v->grp_rg[g][1] = -1;
	v->grp_sg[g][0] = v->grp_sg[g][1] = -1;
	v->grp_of[g][0] = v->grp_of[g][1] = -1;
	v->grp_th[g][0] = v->grp_th[g][1] = -1;
	v->grp_nt[g][0] = v->grp_nt[g][1] = -1;
	v->grp_tg[g][0] = v->grp_tg[g][1] = -1;
}

/*
 * A BLOCK MATCHER IS ONE ROW: the block's hash and the threshold it must reach,
 * and the comment box every matcher has.
 *
 * The hash is written the way a comment in the generated file will carry it
 * (`# hash <value>`), because it is what names the block and what a person
 * compares against the block table. The matcher holds nothing else - ticking
 * the block made it and unticking drops it, so there is no [x], no kind and no
 * list of items to add to. An older rule's matcher may name several blocks; the
 * first is shown and "+N" says how many more.
 */
static int draw_block_matcher(struct out *o, struct view *v, uint32_t g, int r)
{
	const struct group *q = &v->ed.dr.grp[g];
	uint32_t blk = q->n_sim ? q->sim[0].blk : v->ed.dr.n_blk;
	int y, c0;

	grp_spans_off(v, g);
	if (!PR_VIS(r))
		return r + 1;
	y = PR(r);
	ghead_lead(o, v, y, g, "find_sim");
	out_fmt(o, A_DIM "  # hash " A_OFF "%s%08x" A_OFF, A_ID,
		blk < v->ed.dr.n_blk ? v->ed.dr.blk[blk].id : 0u);
	if (q->n_sim > 1u)
		out_fmt(o, A_DIM " +%u" A_OFF, q->n_sim - 1u);
	out_str(o, A_DIM "   Threshold: " A_OFF);
	v->grp_th[g][0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s>= [", v->edit == ED_GRP_PCT + (int)g ? A_SEL : A_ID);
	c0 = (int)o->col_hint - 1;
	if (v->edit == ED_GRP_PCT + (int)g)
		field_draw(o, v->grp_pct_buf, v->caret, &v->grp_pct_off, 3, 1,
			   "");
	else
		out_fmt(o, "%3u", q->pct);
	out_str(o, "]" A_OFF A_DIM "%" A_OFF);
	v->grp_th[g][1] = (int)o->col_hint;
	/*
	 * A MATCHER NO CONDITION USES CARRIES ITS OWN TAG: it is a diagnose of
	 * its own. One a condition names takes the condition's, and has no cell.
	 */
	v->grp_tg[g][0] = v->grp_tg[g][1] = -1;
	if (grp_standalone(&v->ed, g)) {
		out_str(o, A_DIM "   Tag: " A_OFF);
		v->grp_tg[g][0] = 1 + (int)o->col_hint;
		draw_tag_cell(o, v, q->tag);
		v->grp_tg[g][1] = (int)o->col_hint;
	}
	draw_grp_note(o, v, g);
	/* After the row, so it wins where they overlap - see hit_at. */
	hit_add(v, y, c0, v->grp_th[g][1],   /* not past the comment box */
		hit_grp_pct, g);
	if (v->grp_tg[g][0] > 0)
		hit_add(v, y, v->grp_tg[g][0], v->grp_tg[g][1], hit_grp_tag, g);
	return r + 1;
}

/*
 * A SEARCH MATCHER: two rows - what it IS, with its range and threshold, and
 * what it is about, the markers it searches for.
 */
static int draw_str_matcher(struct out *o, struct view *v, uint32_t g, int r)
{
	const struct group *q = &v->ed.dr.grp[g];
	char rl[16];
	uint32_t i;

	/* One name for the three searches - see where the kind menu is built.
	 * What is GENERATED still follows the threshold. */
	snprintf(rl, sizeof rl, "%s",
		 !grp_is_at(q->rule) ? "find_str" : grp_rule_label(q->rule));
	grp_spans_off(v, g);
	if (PR_VIS(r)) {
		char nm[40], lead[16];

		row_start(o, PR(r), 1);
		/*
		 * AN AT MATCHER SHOWS WHERE, NOT WHICH REGION.
		 *
		 * It names no range - see group.at_off - so the field that
		 * would hold one holds the offset instead, and the preposition
		 * changes with it. The control keeps the same click span,
		 * because it is the same half of the row: the thing that says
		 * where this matcher looks.
		 */
		if (grp_is_at(q->rule))
			nm[0] = 0;      /* drawn in parts, below */
		else if (grp_has_range(&v->ed, g))
			rng_name_of(cur_obj(v)->fmt, grp_mask(&v->ed, g), nm,
				    sizeof nm);
		else
			snprintf(nm, sizeof nm, "-");
		/*
		 * Named fields, not a table: a field that does not apply is
		 * simply absent.
		 */
		snprintf(lead, sizeof lead, "  %u.", grp_loc(&v->ed, g));
		out_fmt(o, "%s%-6.6s" A_OFF,
			g == v->ed.dr.cur_grp ? A_SEL : A_DIM, lead);
		v->grp_rl[g][0] = 1 + (int)o->col_hint;
		out_fmt(o, "%s%s" A_OFF, A_WARN, rl);
		v->grp_rl[g][1] = (int)o->col_hint;
		out_str(o, grp_is_at(q->rule) ? A_DIM " at " A_OFF
					      : A_DIM " in " A_OFF);
		if (grp_is_at(q->rule)) {
			/*
			 * THE THREE PARTS, EACH ITS OWN CONTROL - see
			 * view.grp_sg. Spelled with the same helpers
			 * everywhere, so the row and the preview cannot
			 * disagree.
			 */
			char mag[24];
			int freesign = grp_at_sign_free(q->at_anchor);

			v->grp_rg[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, A_LOC,
				kof_anchor_word(q->at_anchor));
			v->grp_rg[g][1] = (int)o->col_hint;
			out_str(o, " ");
			v->grp_sg[g][0] = 1 + (int)o->col_hint;
			/* Dim where it cannot be pressed, which is what the
			 * attribute cell says with the same colour: this is
			 * fixed, not chosen. */
			out_fmt(o, "%s%c" A_OFF, freesign ? A_ID : A_DIM,
				grp_at_sign(q->at_off));
			v->grp_sg[g][1] = (int)o->col_hint;
			if (!freesign)
				v->grp_sg[g][0] = v->grp_sg[g][1] = -1;
			out_str(o, " ");
			v->grp_of[g][0] = 1 + (int)o->col_hint;
			if (v->edit == ED_AT_OFF + (int)g) {
				/*
				 * AS WIDE AS WHAT IS IN IT, and one cell more
				 * to type into: the step is four or five
				 * characters in almost every rule.
				 */
				int room = (int)strlen(v->at_buf) + 1;

				if (room < 5)
					room = 5;
				out_str(o, A_SEL);
				field_draw(o, v->at_buf, v->caret,
					   &v->at_buf_off, room, 1, "0x...");
				out_str(o, A_OFF);
			} else {
				snprintf(mag, sizeof mag, "0x%llx",
					 grp_at_mag(q->at_off));
				out_fmt(o, "%s%s" A_OFF, A_LOC, mag);
			}
			v->grp_of[g][1] = (int)o->col_hint;
		} else {
			v->grp_rg[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, A_LOC, nm);
			v->grp_rg[g][1] = (int)o->col_hint;
		}
		/*
		 * TWO THINGS, AND ONLY ONE OF THEM IS A CONTROL.
		 *
		 * ">= N" is the threshold: it is what the author sets, and
		 * clicking it opens the menu of values. "of N" is how many
		 * markers the matcher currently holds - a fact about the
		 * matcher, changed by adding or removing a marker and by
		 * nothing else, so the clickable span ends where the control
		 * does.
		 *
		 * "==" at the top and ">=" below it, which is the difference
		 * the author is choosing between: a floor a bigger set can
		 * clear, or all of them however many there are.
		 */
		if (!grp_is_at(q->rule)) {
			uint32_t n = grp_count(&v->ed, g);
			uint32_t th = grp_thresh_eff(&v->ed, g);

			out_str(o, A_DIM "   Threshold: " A_OFF);
			v->grp_th[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s %u" A_OFF, A_ID,
				(n && th >= n) ? "==" : ">=", th);
			v->grp_th[g][1] = (int)o->col_hint;
			out_fmt(o, A_DIM " of " A_OFF "%s%u" A_OFF, A_SIZE, n);
		}
		draw_grp_note(o, v, g);
		out_at(o, PR(r), g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_matcher, g);
	}
	r++;

	/* The markers are the matcher's own row, because they are what it
	 * searches for and not a separate thing that happens to be nearby. */
	if (!PR_VIS(r)) {
		glist_gone(v, g);
		return r + 1;
	}
	{
		struct grp_list L;

		glist_begin(&L, o, v, PR(r), g, "Markers", v->grp_it[g],
			    GRP_SIM_MAX);
		for (i = 0; i < v->ed.dr.n_decl; i++) {
			/* Ten digits and a terminator: what %u can actually
			 * produce, so a large index is not labelled short. */
			char num[11];

			if (!(v->ed.dr.decl[i].grp & (1u << g)))
				continue;
			snprintf(num, sizeof num, "%u", i + 1u);
			glist_item(&L, num);
		}
		glist_end(&L, decl_free(&v->ed) != 0, "String");
	}
	return r + 1;
}

/*
 * draw_decl_matchers - the matchers of the open tab, one call each.
 *
 * One section of the draft panel. `r` is the panel's running row number and it
 * is passed in and handed back rather than shared.
 *
 * THE LIST IS ONE AND EACH TAB NUMBERS ITS OWN KIND OF IT FROM 1. A condition
 * names a matcher by its number on its own tab (grp_loc), so the Blocks tab
 * opens at 1 whatever Patterns holds, and a tab switch renumbers nothing.
 * Patterns lists find_str and find_at, Blocks lists the find_sim that ticking a
 * block made.
 */
static int draw_decl_matchers(struct out *o, struct view *v, int r)
{
	uint32_t g;

	if (PR_VIS(r)) {
		sec_bar(o, v, PR(r), " Matchers");
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
	}
	r++;

	v->row_grp = PR(r);
	for (g = 0; g < v->ed.dr.n_grp; g++) {
		if (grp_tab(&v->ed, g) != v->ed.dr.tab)
			grp_spans_off(v, g);
		else if (v->ed.dr.grp[g].kind == GRP_KIND_SIM)
			r = draw_block_matcher(o, v, g, r);
		else
			r = draw_str_matcher(o, v, g, r);
	}

	/*
	 * AND THE BUTTON THAT ADDS ONE, AT THE FOOT OF THEM, on the Patterns
	 * tab only: a block matcher is made by ticking the block, so the Blocks
	 * tab has nothing to add by hand. At the foot it is beside the last
	 * thing added, which is where the reader is already looking.
	 */
	if (v->ed.dr.tab == DT_PATTERNS) {
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			v->n_c0 = 2;
			out_fmt(o, " " A_ID "[+ Matcher]" A_OFF);
			v->n_c1 = (int)o->col_hint;
			hit_add(v, PR(r), 0, g_cols - 1, hit_row_addmatcher, 0);
		}
		r++;
	}
	return r;
}

/*
 * draw_decl_conds - the open tab's conditions, each one a block of its own.
 *
 * One section of the draft panel. A condition is independent: its own matchers
 * (numbered on this tab), its own tag, one file. Nothing joins one condition to
 * the next - several files are the "or" between them. `r` is the panel's
 * running row number and it is passed in and handed back rather than shared.
 */
static int draw_decl_conds(struct out *o, struct view *v, int r)
{
	uint32_t g;

	/* ---- the conditions: what it means ---- */
	if (PR_VIS(r)) {
		sec_bar(o, v, PR(r), " Conditions");
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
	}
	r++;
	v->row_cnd = PR(r);
	for (g = 0; g < v->n_cseq; g++) {
		uint32_t ci = v->cseq_idx[g];
		const struct cond *c2 = &v->ed.dr.cnd[ci];

		if (!PR_VIS(r)) {
			if (v->cseq_kind[g] == CS_COND) {
				v->cnd_tg[ci][0] = v->cnd_tg[ci][1] = -1;
				v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
			} else if (v->cseq_kind[g] == CS_MATCH) {
				v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			}
			r++;
			continue;
		}
		row_start(o, PR(r), 1);
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_cond, g);

		if (v->cseq_kind[g] == CS_COND) {
			/* Under the label of the block's first row. */
			out_fmt(o, "%7s", "");

			out_str(o, A_DIM "Tag: " A_OFF);
			v->cnd_tg[ci][0] = 1 + (int)o->col_hint;
			/*
			 * THE TAG, chosen from the table of tags and never
			 * typed, so nothing here can be misspelt. Not chosen
			 * yet is plain "none".
			 */
			draw_tag_cell(o, v, c2->tag);
			v->cnd_tg[ci][1] = (int)o->col_hint;
			r++;
			continue;
		}

		if (v->cseq_kind[g] == CS_MATCH) {
			uint32_t m2;

			/*
			 * THE BLOCK'S NAME GOES ON ITS FIRST ROW, which this
			 * now is. A label on the last line names a thing the
			 * reader has already read past; on the first it says
			 * what they are about to read, and it is the mark that
			 * shows which condition the cursor is on.
			 *
			 * Same width as the rail it replaces - indent plus six
			 * columns - so the rows under it still line up.
			 */
			{
				char lab2[16];

				cnd_label(&v->ed, ci, lab2, sizeof lab2);
				out_fmt(o, "%*s", 1, "");
				out_fmt(o, "%s%-6.6s" A_OFF,
					ci == v->ed.dr.cur_cnd ? A_SEL : A_DIM,
					lab2);
			}
			out_str(o, A_DIM "Matchers: " A_OFF);
			for (m2 = 0; m2 < MAX_GROUP; m2++)
				v->cnd_ids[ci][m2][0] =
					v->cnd_ids[ci][m2][1] = -1;
			v->cnd_op[ci][0] = v->cnd_op[ci][1] = -1;
			v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
			{
				char canon[64];

				cnd_canon(&v->ed, ci, canon, sizeof canon);
				if (c2->expr[0] &&
				    strcmp(c2->expr, canon) != 0) {
					/* Typed, and not a list. Shown as
					 * written, because rendering it as a
					 * list would show a different
					 * condition from the generated one -
					 * and no id is drawn, so none of them
					 * is clickable. */
					v->cnd_ex[ci][0] = 1 +
							   (int)o->col_hint;
					out_str(o, v->edit == 103 + (int)ci
						   ? A_SEL : A_WARN);
					field_draw(o, c2->expr, v->caret,
						   &v->cnd_eoff[ci],
						   v->edit == 103 + (int)ci
						   ? 24
						   : (int)strlen(c2->expr),
						   v->edit == 103 + (int)ci,
						   "");
					out_str(o, A_OFF);
					v->cnd_ex[ci][1] = (int)o->col_hint;
					goto ids_done;
				}
			}
			if (grp_tab_count(&v->ed, v->ed.dr.tab)) {
				uint32_t m;
				int first2 = 1;

				for (m = 0; m < v->ed.dr.n_grp; m++) {
					if (!cnd_uses(&v->ed, c2, m))
						continue;
					if (!first2) {
						if (v->cnd_op[ci][0] < 0)
							v->cnd_op[ci][0] = 2 +
							  (int)o->col_hint;
						out_fmt(o, "%s %s " A_OFF,
							c2->op ? A_OR : A_AND,
							c2->op ? "or" : "and");
						v->cnd_op[ci][1] =
							(int)o->col_hint - 1;
					}
					v->cnd_ids[ci][m][0] = 1 +
							       (int)o->col_hint;
					/* The "!" is not the id's colour: it
					 * says the opposite of what the id
					 * says, and reading past it is reading
					 * the condition backwards. It is inside
					 * the click window, because it is what
					 * the author is pointing at when they
					 * want it gone. */
					if (cnd_neg(&v->ed, c2, m))
						out_str(o, A_WARN "!" A_OFF);
					out_fmt(o, "%s%u" A_OFF, A_ID,
						grp_loc(&v->ed, m));
					v->cnd_ids[ci][m][1] = (int)o->col_hint;
					first2 = 0;
				}
				if (first2)
					out_str(o, A_DIM "None" A_OFF);
			} else {
				out_str(o, A_DIM "None" A_OFF);
			}
ids_done:
			v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			if (grp_tab_count(&v->ed, v->ed.dr.tab)) {
				v->cnd_mt[ci][0] = 1 + (int)o->col_hint;
				out_fmt(o, "   " A_ID "[+ Matcher]" A_OFF);
				v->cnd_mt[ci][1] = (int)o->col_hint;
			}
			/*
			 * No comment box here.
			 *
			 * A note written above a branch in the source is about
			 * the search the branch makes - "matcher 1: Hooks" -
			 * and the search belongs to the matcher. Two places to
			 * put one remark meant the loader had to guess which,
			 * and it guessed the condition.
			 */
			/*
			 * REMOVING THE BLOCK BELONGS BESIDE ITS NAME.
			 *
			 * It was drawn on the verdict row, which carried the
			 * label until the label moved to the top of the block;
			 * afterwards the button sat two rows below the thing it
			 * names, beside a verdict it has nothing to do with,
			 * and the row a reader aims at - the one that says
			 * which condition this is - threw the click away. It is
			 * on the first row now, from the column every matcher's
			 * is drawn at.
			 */
			out_at(o, PR(r), g_cols - 4);
			out_str(o, A_BAD "[x]" A_OFF);
			r++;
			continue;
		}
	}

	/*
	 * AND THE BUTTON THAT ADDS A CONDITION, at the foot of them all - the
	 * same move the matchers just made, and for the same reason. It makes
	 * an independent block on this tab.
	 */
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->a_c0 = 2;
		out_fmt(o, " %s[+ Condition]" A_OFF,
			grp_tab_count(&v->ed, v->ed.dr.tab) ? A_ID : A_DIM);
		v->a_c1 = (int)o->col_hint;
		v->b_c0 = v->b_c1 = -1;
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_addcond, 0);
	}
	r++;
	return r;
}



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
/*
 * The fold handle, on the column row of each table. `which` is 0 for the block
 * table and 2 for the diagnoses - one control, because they fold for the same
 * reason and a reader should not learn two gestures. (1 was the similarity table,
 * which went with the measure it listed.)
 */
static void hit_fold(struct view *v, uint32_t which)
{
	if (which == 2u)
		v->diag_fold = !v->diag_fold;
	else
		v->blk_fold = !v->blk_fold;
}

/*
 * IS THIS RULE ABOUT SOME OTHER OBJECT?
 *
 * Every block it carries scores zero here, so none of them was cut from what
 * is on screen - and the panel refuses to CHANGE it for that reason:
 * a block's row shows an offset, a region and a length belonging to the file
 * it came from, and editing those against this object edits a rule about two
 * files at once.
 *
 * The rule is still SHOWN, and still scored, because that is what opening one
 * on a different sample is for.
 */
static int mtn_foreign(const struct view *v)
{
	uint32_t i, carried = 0, scored = 0;

	for (i = 0; i < v->ed.dr.n_blk; i++) {
		if (!v->ed.dr.blk[i].kept)
			continue;
		carried++;
		if (v->ed.dr.blk[i].score)
			scored++;
	}
	return carried && carried == v->ed.dr.n_blk && !scored;
}

static void hit_plg_tick(struct view *v, uint32_t i)
{
	if (mtn_foreign(v)) {
		say_err(&v->ed, "These blocks are not in this object");
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
 * GO TO THE BLOCK WITHOUT MARKING IT.
 *
 * The offset is a PLACE, so pointing at it means "show me there" and nothing
 * more. The colour belongs to the hash beside it - that cell is the block's
 * name and lighting it is what ties the name to the bytes - so a jump that also
 * lit would take the one gesture that says "mark this" and give it to the one
 * that says "look at this".
 */
static void hit_plg_goto(struct view *v, uint32_t i)
{
	if (i >= v->ed.dr.n_blk || !v->ed.dr.blk[i].len)
		return;
	view_show_in(v, v->node[v->sel_node].obj, v->node[v->sel_node].sym,
		     v->ed.dr.blk[i].off, 0);
}

/*
 * GO TO THE DIAGNOSE'S HEAD. Only a match has a place: a diagnose that was seen
 * and did not match found no node to point at, and a jump to 0 would be a lie.
 */
static void hit_diag_goto(struct view *v, uint32_t i)
{
	struct object *ob = cur_obj(v);

	if (!ob || i >= ob->n_diag || ob->diag[i].state != KOF_DIAG_ST_MATCH ||
	    !ob->diag[i].n_bound)
		return;
	view_show_in(v, v->node[v->sel_node].obj, v->node[v->sel_node].sym,
		     ob->diag[i].at[0], 0);
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


/* A percentage is digits and nothing else - the box refuses the rest rather
 * than accepting what it will then have to ignore. */
int mtn_digit(int c)
{
	return c >= '0' && c <= '9';
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
static void at_off_edit_open(struct view *v, uint32_t g)
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

/* The Tag cell of a standalone block matcher opens the table of tags. */
static void hit_grp_tag(struct view *v, uint32_t g)
{
	if (g >= v->ed.dr.n_grp)
		return;
	v->ed.dr.cur_grp = g;
	syn_pick_tag(v, PK_TAG_GRP, g);
}

/* Clicking the threshold puts the caret in it - see the note where it is
 * drawn. */
static void hit_grp_pct(struct view *v, uint32_t g)
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
 * And the region cell turns the anchor off and on.
 *
 * Nothing is re-hashed: the block's hashes are the same bytes either way, and
 * only the question of WHERE they must be found changes - so this costs a
 * rescore and not a re-carve.
 */
static void hit_plg_rgn(struct view *v, uint32_t i)
{
	if (mtn_foreign(v)) {
		say_err(&v->ed, "These blocks are not in this object");
		return;
	}
	if (i >= v->ed.dr.n_blk)
		return;
	v->ed.dr.blk[i].anywhere = (uint8_t)!v->ed.dr.blk[i].anywhere;
	v->mtn_scored = 0;
}

/*
 * THE LIST READS IN FILE ORDER.
 *
 * A rule loaded for an infected file puts its blocks in first and the carve
 * appends the rest, so the block the rule fired on sat at the top of the table
 * whatever its offset - on a Gafgyt sample at 0xf9ce, above five blocks that
 * come before it in the file. The table is about an object, and an object is
 * read from its start.
 *
 * A block with no place in THIS object - a declared block the carve did not
 * reproduce - has no offset to sort by and goes last, which is also where a
 * reader looking for it in the hex pane will not be sent hunting.
 *
 * Insertion sort: sixty-four rows at most, once per object.
 */
static void mtn_order(struct view *v)
{
	static struct mtn_block tmp[MTN_MAX_BLOCK];
	uint32_t ord[MTN_MAX_BLOCK];
	uint32_t i, j, n = v->ed.dr.n_blk;

	/*
	 * SORTED AS A PERMUTATION, so what names a block can follow it.
	 *
	 * Moving the records directly leaves nothing to say where each one went
	 * - see mtn_moved - and a matcher holds an index. The order is worked
	 * out first, then applied, then the matchers are told.
	 */
	for (i = 0; i < n; i++)
		ord[i] = i;
	for (i = 1; i < n; i++) {
		uint32_t t = ord[i];

		for (j = i; j; j--) {
			const struct mtn_block *a = &v->ed.dr.blk[ord[j - 1u]];
			const struct mtn_block *b = &v->ed.dr.blk[t];
			int after = !a->len ? (b->len != 0)
				  : (b->len && b->off < a->off);

			if (!after)
				break;
			ord[j] = ord[j - 1u];
		}
		ord[j] = t;
	}
	for (i = 0; i < n; i++)
		tmp[i] = v->ed.dr.blk[ord[i]];
	{
		/* Where each block went, handed over whole: see blk_permute. */
		static uint32_t to[MTN_MAX_BLOCK];

		for (i = 0; i < n; i++) {
			v->ed.dr.blk[i] = tmp[i];
			to[ord[i]] = i;
		}
		blk_permute(&v->ed, to, n);
	}
	/* Cycled by POSITION, so neighbours never share - which is a property
	 * of the order and has to be redone when the order changes. */
	for (i = 0; i < v->ed.dr.n_blk; i++)
		v->ed.dr.blk[i].colour = (uint8_t)(i % MTN_COLOURS);
}

/*
 * CARVED AND SCORED BEFORE THE PANEL IS LAID OUT, not while it is drawn.
 *
 * The layout decides how tall the panel is from how many blocks there are, so
 * the carve has to have happened by then. Done inside the drawing it was a
 * frame late: the first frame sized the panel for no blocks at all and the row
 * count went from zero to sixty-four, which the draft's "it just grew, show me
 * its end" rule read as new rows arriving at the bottom - so the table opened
 * scrolled to its last six blocks and the wheel was already at the stop.
 *
 * Carved on arrival at an object, because a list left over from the previous
 * file would be a list of blocks that are not in this one. Scored separately:
 * the score also moves when a block's normalizer is changed by hand, which is
 * not a re-carve.
 */
void mtn_sync(struct view *v)
{
	if (!v->mtn_segged || v->mtn_seg_obj != v->node[v->sel_node].obj) {
		mtn_segment(v);
		mtn_order(v);
		v->mtn_segged = 1;
		v->mtn_seg_obj = v->node[v->sel_node].obj;
		/* The rows just moved; a box open on one of them is open on a
		 * different block now. */
		if (v->edit >= ED_GRP_PCT &&
		    v->edit < ED_GRP_PCT + (int)MAX_GROUP)
			v->edit = 0;
		/*
		 * A NEW LIST STARTS AT ITS TOP, and says so the way every
		 * other caller does.
		 *
		 * It set prow_seen to the number of BLOCKS. prow_seen is
		 * compared against the number of PANEL ROWS, and the panel is
		 * the head, the block table, the matchers and the conditions -
		 * always more rows than there are blocks. So the very next
		 * frame read "the draft just grew" and jumped the panel to its
		 * end: opening any object with more blocks than fit showed the
		 * block table already scrolled, its heading and the Format,
		 * Region and Option rows above the window.
		 *
		 * The row count is not known here - prow_build has not run yet
		 * - and it does not need to be: prow_home is the flag that
		 * means this, and the frame records prow_seen from the count it
		 * has just built.
		 */
		v->prow_off = 0;
		v->prow_home = 1;
	}
	/*
	 * AND THE RULE TARGETS THE FORMAT OF THE FILE IN FRONT OF IT.
	 *
	 * The draft seeds this when the first marker is taken; mutation mode
	 * takes no markers, so nothing seeded it and the Format row read "None"
	 * on an ELF that was plainly an ELF. Same call, same rule: only when
	 * nothing has been chosen yet, so a format the author set by hand
	 * stands.
	 */
	draft_seed_target(v);
	if (!v->mtn_scored || v->mtn_scored_n != v->ed.dr.n_blk ||
	    v->mtn_scored_obj != v->node[v->sel_node].obj) {
		/* Unless they arrived with the blocks - see mtn_scores_known. */
		if (!v->mtn_scores_known)
			mtn_rescore(v);
		v->mtn_scores_known = 0;
		v->mtn_scored = 1;
		v->mtn_scored_n = v->ed.dr.n_blk;
		v->mtn_scored_obj = v->node[v->sel_node].obj;
	}
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





/*
 * HOW MANY DIAGNOSES MATCHED THIS FILE - the rows of the table, and nothing
 * else is one. What the engine says about the diagnoses that did not match is
 * shown where it belongs; here a row is a diagnose the file carries.
 */
uint32_t diag_shown_n(struct view *v)
{
	struct object *ob = cur_obj(v);
	uint32_t i, n = 0;

	if (ob)
		for (i = 0; i < ob->n_diag; i++)
			n += ob->diag[i].state == KOF_DIAG_ST_MATCH;
	return n;
}

/*
 * LINEAGE - the diagnoses this file matches, on the Graphs tab. Each row says
 * how many of its nodes were found and where its head is - clicking goes there.
 * All of it is the engine's answer, read from the scan that produced the
 * verdict: nothing here analyses the object again.
 *
 * THE TAB IS ON HOLD, and so is what the table is for: generating a graph
 * diagnose is not built, so the table is drawn - it is what the tab is made of
 * - and says so in its title and in its empty state, rather than offering a
 * control that leads nowhere.
 */
static int draw_decl_diag(struct out *o, struct view *v, int r)
{
	struct object *ob = cur_obj(v);
	uint32_t i, n = diag_shown_n(v);
	char sum[64];

	snprintf(sum, sizeof sum, " %u matched", n);
	r = decl_table_head(o, v, r, " Lineage (on hold)", v->diag_fold, 2u,
			    "         diagnose                  nodes  head",
			    sum);
	if (v->diag_fold)
		return r;
	if (!n) {
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			out_str(o, A_DIM "      none - graph diagnoses are on "
				"hold" A_OFF);
		}
		return r + 1;
	}
	for (i = 0; i < ob->n_diag; i++) {
		const struct kof_diag_report *d = &ob->diag[i];
		int y, c0;

		if (d->state != KOF_DIAG_ST_MATCH)
			continue;
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		y = PR(r);
		row_start(o, y, 1);
		/* Past the fold gutter - see decl_table_head. */
		out_str(o, "    ");
		c0 = 2 + (int)o->col_hint;
		out_fmt(o, " %s%-28.28s" A_OFF, A_HIT1,
			d->name ? d->name : "?");
		out_fmt(o, A_DIM " %2u/%-2u " A_OFF, d->n_bound, d->n_node);
		out_fmt(o, "%s0x%llx" A_OFF, A_WARN,
			(unsigned long long)d->at[0]);
		hit_add(v, y, c0, (int)o->col_hint, hit_diag_goto, i);   /* the whole row */
		r++;
	}
	return r;
}

/* The Graphs tab's Conditions: a heading and the reason there is nothing under
 * it. A condition over graph diagnoses cannot be written until they can. */
static int draw_decl_conds_hold(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		sec_bar(o, v, PR(r), " Conditions (on hold)");
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
	}
	r++;
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		out_str(o, A_DIM "      none - nothing to combine until graph "
			"diagnoses can be generated" A_OFF);
	}
	return r + 1;
}

static int draw_decl_blocks(struct out *o, struct view *v, int r)
{
	uint32_t i;
	char hdr[96];

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
		char cols[112], sum[48];

		snprintf(cols, sizeof cols,
			 " use  %-10s  %-8s  %-*s  %6s  %-6s%s",
			 "offset", "hash", (int)MTN_SYM_COL, "name", "size", "region",
			 mtn_kept_any(v) ? "  score" : "");
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
		if (!blk_row_shown(v, i))
			continue;
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		y = PR(r);
		row_start(o, y, 1);
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
			 * AND THE OFFSET GOES THERE TOO.
			 *
			 * It is the one cell on the row that IS a place, so it
			 * is the one a reader points at to be taken there -
			 * lighting the block on the way, because a jump that
			 * left the bytes unmarked would put the pane somewhere
			 * without saying what at.
			 */
			c0 = 1 + (int)o->col_hint;
			out_fmt(o, A_DIM " 0x%08llx" A_OFF,
				(unsigned long long)b->off);
			hit_add(v, y, c0, (int)o->col_hint, hit_plg_goto, i);
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
		out_fmt(o, "%08x", b->id);
		if (b->lit)
			out_str(o, A_OFF);
		hit_add(v, y, c0, (int)o->col_hint, hit_plg_light, i);
		/*
		 * THE NAME, when the block is functions the object names; blank
		 * for data and for anything else. Display only: it is not part of
		 * what the rule matches.
		 */
		out_fmt(o, A_DIM "  %-*.*s" A_OFF, (int)MTN_SYM_COL, (int)MTN_SYM_COL,
			b->sym);
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
		/*
		 * WHERE IT IS LOOKED FOR, and it is a control because that is a
		 * choice - see mtn_block.anywhere. "any" is the whole file;
		 * anything else is the region the block was cut from, which is
		 * the anchor and the default.
		 */
		{
			int rc = 2 + (int)o->col_hint;

			out_fmt(o, "%s  %-6.6s" A_OFF,
				b->anywhere ? A_ID : A_DIM,
				b->anywhere ? "any" : b->rgn);
			hit_add(v, y, rc, (int)o->col_hint, hit_plg_rgn, i);
		}
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
			if (b->kept)
				out_fmt(o, "%s  %3u%%" A_OFF,
					blk_clears(&v->ed, (uint32_t)i)
					? "\033[42;30m"
					: b->score ? "" : A_DIM, b->score);
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
		r++;
	}
	return r;
}

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

/* ---- the output pane ------------------------------------------------ */

/*
 * THE OUTPUT, listed and not written: one entry per condition,
 * because a diagnose file is one condition.
 *
 *     Output - PREVIEW, nothing is written
 *       Shared   type Botnet  family mirai  format ELF  arch x86_64
 *       1. botnet_mirai_network-flood_01.c
 *            if 1&2
 *            tag network-flood
 *            1  find_str >= 2 of 7  markers 1, 2, 3
 *            2  find_sim  # hash 3a7f21c9  threshold 60
 *
 * The name, the id and the tag come from the editor (cnd_file_name, tag_name)
 * and the rest from the draft as the tables hold it. The Graphs tab has no
 * condition to list while it is on hold.
 *
 * ROWS ARE COUNTED BY ONE FUNCTION and drawn from the same loop shape: the row
 * model has to know how tall this pane is before it is drawn, and a count kept
 * apart from the drawing is how the panel's rows once came out one off.
 */
static uint32_t cnd_matchers(const struct view *v, uint32_t ci)
{
	uint32_t g, n = 0;

	for (g = 0; g < v->ed.dr.n_grp; g++)
		n += cnd_uses(&v->ed, &v->ed.dr.cnd[ci], g) != 0;
	return n;
}

uint32_t preview_rows(const struct view *v)
{
	uint32_t ci, g, n = 2;

	if (!v->gen_preview)
		return 0;
	for (ci = 0; ci < v->ed.dr.n_cnd; ci++)
		if (v->ed.dr.cnd[ci].tab != DT_GRAPHS)
			n += 3u + cnd_matchers(v, ci);
	/* A block matcher no condition uses: its file, its tag, itself. */
	for (g = 0; g < v->ed.dr.n_grp; g++)
		n += 3u * (grp_standalone(&v->ed, g) != 0);
	return n;
}

/* The tag as the output lists it: the cell's own words. */
static void preview_tag(const struct view *v, uint64_t tag, char *out,
			size_t cap)
{
	if (!tag) {
		snprintf(out, cap, "none");
		return;
	}
	tag_label(&v->ed, tag, out, cap);
	if (!out[0])
		snprintf(out, cap, "not found");
}

/* One matcher as the output lists it. */
static void preview_matcher(struct view *v, uint32_t g, char *out, size_t cap)
{
	const struct group *q = &v->ed.dr.grp[g];
	uint32_t i, n = 0;
	size_t at;

	if (q->kind == GRP_KIND_SIM) {
		uint32_t b = q->n_sim ? q->sim[0].blk : v->ed.dr.n_blk;

		snprintf(out, cap, "%u  find_sim  # hash %08x  threshold %u",
			 grp_loc(&v->ed, g),
			 b < v->ed.dr.n_blk ? v->ed.dr.blk[b].id : 0u, q->pct);
		return;
	}
	at = (size_t)snprintf(out, cap, "%u  %s", grp_loc(&v->ed, g),
			      grp_is_at(q->rule) ? "find_at" : "find_str");
	if (!grp_is_at(q->rule) && at < cap)
		at += (size_t)snprintf(out + at, cap - at, " >= %u of %u",
				       grp_thresh_eff(&v->ed, g),
				       grp_count(&v->ed, g));
	if (at < cap)
		at += (size_t)snprintf(out + at, cap - at, "  markers");
	for (i = 0; i < v->ed.dr.n_decl && at < cap; i++)
		if (v->ed.dr.decl[i].grp & (1u << g))
			at += (size_t)snprintf(out + at, cap - at, "%s %u",
					       n++ ? "," : "", i + 1u);
}

/* The shared declaration, once: what every file below it carries. */
static void preview_head(struct view *v, char *out, size_t cap)
{
	size_t at;
	uint32_t i, f;

	at = (size_t)snprintf(out, cap, "type %s  family %s",
			      maltype_word[v->ed.dr.maltype % MALTYPE_N],
			      v->ed.dr.family[0] ? v->ed.dr.family : "?");
	for (f = 0; f < KOF_FMT_COUNT && at < cap; f++)
		if (v->ed.dr.fmt_mask & (1u << f))
			at += (size_t)snprintf(out + at, cap - at,
					       "  format %s",
					       kof_format_name((uint8_t)f));
	for (i = 0; i < (uint32_t)OPT_COUNT && at < cap; i++) {
		char val[40];

		if (!v->ed.dr.opt_on[i])
			continue;
		opt_text(v, i, val, sizeof val);
		at += (size_t)snprintf(out + at, cap - at, "  %s %s",
				       opt_word[i], val);
	}
}

static int draw_decl_preview(struct out *o, struct view *v, int r)
{
	uint32_t ci, g, listed = 0;
	/* How much of a row a field may take: negative would be "no limit"
	 * to the %.*s below, so a narrow terminal gets a floor. */
	int w = g_cols - 8;

	if (!v->gen_preview)
		return r;
	if (w < 20)
		w = 20;
	if (PR_VIS(r)) {
		sec_bar(o, v, PR(r), " Output - PREVIEW, nothing is written");
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
	}
	r++;
	if (PR_VIS(r)) {
		char hd[200];

		preview_head(v, hd, sizeof hd);
		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM "  Shared   " A_OFF "%.*s", w, hd);
	}
	r++;
	for (ci = 0; ci < v->ed.dr.n_cnd; ci++) {
		const struct cond *c = &v->ed.dr.cnd[ci];
		char fn[200], ln[160];

		if (c->tab == DT_GRAPHS)
			continue;
		cnd_file_name(&v->ed, ci, fn, sizeof fn);
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			out_fmt(o, "  %s%2u." A_OFF " %s%.*s" A_OFF, A_DIM,
				listed + 1u, c->tag ? A_ID : A_WARN, w - 6, fn);
		}
		listed++;
		r++;
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			out_fmt(o, A_DIM "        if " A_OFF "%s%.*s" A_OFF
				"%s", A_WARN, w - 40,
				c->expr[0] ? c->expr : "-",
				cnd_foreign(&v->ed, c)
				? A_BAD "  REFUSED: names a matcher not on "
				  "this tab" A_OFF : "");
		}
		r++;
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			preview_tag(v, c->tag, ln, sizeof ln);
			out_fmt(o, A_DIM "        tag " A_OFF "%s%.*s" A_OFF,
				c->tag ? A_ID : A_DIM, w, ln);
		}
		r++;
		for (g = 0; g < v->ed.dr.n_grp; g++) {
			if (!cnd_uses(&v->ed, c, g))
				continue;
			if (PR_VIS(r)) {
				preview_matcher(v, g, ln, sizeof ln);
				row_start(o, PR(r), 1);
				out_fmt(o, "        %.*s", w, ln);
			}
			r++;
		}
	}
	/* One diagnose for each block matcher that no condition uses. */
	for (g = 0; g < v->ed.dr.n_grp; g++) {
		const struct group *q = &v->ed.dr.grp[g];
		char fn[200], ln[160];

		if (!grp_standalone(&v->ed, g))
			continue;
		grp_file_name(&v->ed, g, fn, sizeof fn);
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			out_fmt(o, "  %s%2u." A_OFF " %s%.*s" A_OFF, A_DIM,
				listed + 1u, q->tag ? A_ID : A_WARN, w - 6, fn);
		}
		listed++;
		r++;
		if (PR_VIS(r)) {
			row_start(o, PR(r), 1);
			preview_tag(v, q->tag, ln, sizeof ln);
			out_fmt(o, A_DIM "        tag " A_OFF "%s%.*s" A_OFF,
				q->tag ? A_ID : A_DIM, w, ln);
		}
		r++;
		if (PR_VIS(r)) {
			preview_matcher(v, g, ln, sizeof ln);
			row_start(o, PR(r), 1);
			out_fmt(o, "        %.*s", w, ln);
		}
		r++;
	}
	return r;
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
	r = draw_decl_fmts(o, v, r);
	r = draw_decl_ranges(o, v, r);
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
		r = draw_decl_matchers(o, v, r);
		r = draw_decl_conds(o, v, r);
		break;
	case DT_GRAPHS:
		r = draw_decl_diag(o, v, r);
		r = draw_decl_conds_hold(o, v, r);
		break;
	default:
		r = draw_decl_strings(o, v, r);
		r = draw_decl_matchers(o, v, r);
		r = draw_decl_conds(o, v, r);
		break;
	}
	r = draw_decl_preview(o, v, r);

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
