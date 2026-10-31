#define _GNU_SOURCE
#include "kv.h"
#include "kv_tags.h"
#include "../libkofeng/databases/diagsrc.h"


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
static void hit_plg_cfg(struct view *v, uint32_t i);
static void hit_grp_pct(struct view *v, uint32_t i);
static void hit_unit_tag(struct view *v, uint32_t unit);
static void hit_unit_type(struct view *v, uint32_t unit);
static void hit_head_family(struct view *v, uint32_t arg);
static void hit_head_variant(struct view *v, uint32_t arg);
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
/* The family and the variant are CHOSEN from the Pathogens catalog, never typed. */
static void hit_head_family(struct view *v, uint32_t arg)
{
	(void)arg;
	ch_open(v, CH_HFAM, 0, g_my, g_mx);
}

/* Greyed (no span is registered) until a family is chosen; the list holds only that family's variants. */
static void hit_head_variant(struct view *v, uint32_t arg)
{
	(void)arg;
	ch_open(v, CH_HVAR, 0, g_my, g_mx);
}

/*
 * THE TYPES A UNIT MAY HAVE are the types of the header's variant: its bit mask over enum kof_maltype, 0 while no variant is
 * chosen (or the catalog no longer has it). One function for the unit's list, its cell and the sync below.
 */
uint32_t decl_var_types(const struct view *v)
{
	int32_t i;

	if (!v->fam || !v->ed.dr.variant[0])
		return 0;
	i = kv_fam_find_variant(&v->fam->cat, v->ed.dr.variant);
	return i < 0 ? 0u : v->fam->cat.var[i].types;
}

/* The header names a variant the catalog does not have (renamed or deleted in Manage > Pathogens, or no catalog to ask). The draft keeps
 * NAMES, so this is a draft whose variant went away: its units keep their types until another variant is chosen, and the header shows
 * the name in red. */
static int decl_var_gone(const struct view *v)
{
	return v->ed.dr.variant[0] &&
	       (!v->fam || kv_fam_find_variant(&v->fam->cat, v->ed.dr.variant) < 0);
}

/* One unit's type against the variant's types: a variant with exactly one type fills it in, one the variant lacks goes back to `?`. */
static void unit_type_fix(uint8_t *ut, uint32_t mask)
{
	uint32_t t, n = 0, one = 0;

	for (t = 0; t < 32u; t++)
		if (mask & (1u << t)) {
			n++;
			one = t;
		}
	if (n == 1u)
		*ut = (uint8_t)(one + 1u);
	else if (*ut && (*ut - 1u >= 32u || !(mask & (1u << (*ut - 1u)))))
		*ut = 0;
}

/* Every unit's type, after the header's variant changed (and each frame: a unit made later gets a one-type variant's type too). */
void decl_types_sync(struct view *v)
{
	uint32_t mask = decl_var_types(v), i;

	if (decl_var_gone(v))
		return;             /* not "a variant with no types": the units' types are not ours to reset */
	for (i = 0; i < v->ed.dr.n_cnd; i++)
		unit_type_fix(&v->ed.dr.cnd[i].utype, mask);
	for (i = 0; i < v->ed.dr.n_grp; i++)
		unit_type_fix(&v->ed.dr.grp[i].utype, mask);
}

/* A family was chosen: another one clears the variant, a family with exactly one variant selects it. */
/* The variant's own comment is the head's comment, unless the author already wrote one. */
static void note_from_variant(struct view *v, uint32_t var)
{
	if (v->fam && var < v->fam->cat.n_var && !v->ed.dr.note[0])
		snprintf(v->ed.dr.note, sizeof v->ed.dr.note, "%s", v->fam->cat.var[var].comment);
}

void decl_pick_family(struct view *v, uint32_t fam)
{
	int created;
	struct kv_fam_ui *u = fam_ensure(v, &created);
	uint32_t i, n = 0, one = 0;

	if (!u || fam >= u->cat.n_fam)
		return;
	if (strcmp(v->ed.dr.family, u->cat.fam[fam].name)) {
		snprintf(v->ed.dr.family, sizeof v->ed.dr.family, "%s", u->cat.fam[fam].name);
		v->ed.dr.variant[0] = 0;
	}
	for (i = 0; i < u->cat.n_var; i++)
		if (u->cat.var[i].family == fam) {
			n++;
			one = i;
		}
	if (n == 1u) {
		snprintf(v->ed.dr.variant, sizeof v->ed.dr.variant, "%s", u->cat.var[one].name);
		note_from_variant(v, one);
	}
	decl_types_sync(v);
}

void decl_pick_variant(struct view *v, uint32_t var)
{
	if (!v->fam || var >= v->fam->cat.n_var)
		return;
	snprintf(v->ed.dr.variant, sizeof v->ed.dr.variant, "%s", v->fam->cat.var[var].name);
	note_from_variant(v, var);
	decl_types_sync(v);
}

/* The variant as the header shows it: its letters ("A"), or the whole name when the catalog no longer has it. */
static void head_variant_text(const struct view *v, char *out, size_t cap)
{
	int32_t i = v->fam ? kv_fam_find_variant(&v->fam->cat, v->ed.dr.variant) : -1;

	if (i >= 0 && kof_famcat_letter_text(v->fam->cat.var[i].letter, out, (uint32_t)cap))
		return;
	snprintf(out, cap, "%s", v->ed.dr.variant);
}

static void hit_head_note(struct view *v, uint32_t arg)
{
	(void)arg;
	v->edit = 501;
}

/*
 * GENERATE WRITES THE OUTPUT: one diagnose source per unit into <bases>/diagnoses
 * (draft_generate, which owns every rule: the header's family and variant, a type and a
 * tag on every unit, no file replaced). The outcome - "Wrote N file(s)" or the reason it
 * refused - is the note. The button asks nothing of its own: no unit is draft_generate's to answer.
 */

static void hit_head_gen(struct view *v, uint32_t arg)
{
	char dir[300], msg[400];
	int rc;

	(void)arg;
	snprintf(dir, sizeof dir, "%s/diagnoses", v->basedir[0] ? v->basedir : "bases");
	draft_set_tree_dir(&v->ed, dir);
	rc = draft_generate(&v->ed, dir, msg, sizeof msg);
	if (rc < 0) {
		say_err(&v->ed, "%s", msg);
		return;
	}
	draft_mark_saved(&v->ed);
	say_note(&v->ed, "%s", msg);
}

static void hit_head_discard(struct view *v, uint32_t arg)
{
	(void)arg;
	/* No confirmation. The panel is a draft, not a document: what it holds
	 * was typed a moment ago, and a dialog between the button and the blank
	 * sheet is a step in the way of the thing the button is for. */
	if (v->ed.dr.n_decl || v->ed.dr.family[0]) {
		draft_reset(&v->ed);
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
	 * FAMILY AND VARIANT, chosen from the Pathogens catalog. They are what every
	 * diagnose of the rule shares; the TYPE is each unit's own (see
	 * draw_unit_cells). The variant is greyed until a family is chosen and then
	 * lists only that family's variants.
	 */
	row_start(o, top, 1);
	c = 2 + (int)o->col_hint;
	out_fmt(o, A_DIM " Family " A_OFF "%s[ %s ]" A_OFF, A_ID,
		v->ed.dr.family[0] ? v->ed.dr.family : "?");
	hit_add(v, top, c, (int)o->col_hint, hit_head_family, 0);
	{
		char lt[KOF_NAME_MAX + 1];

		head_variant_text(v, lt, sizeof lt);
		out_str(o, "  ");
		c = 2 + (int)o->col_hint - 1;
		if (v->ed.dr.family[0]) {
			out_fmt(o, A_DIM "Variant " A_OFF "%s[ %s ]" A_OFF,
				decl_var_gone(v) ? A_BAD : A_ID, lt[0] ? lt : "?");
			hit_add(v, top, c, (int)o->col_hint, hit_head_variant, 0);
		} else {
			out_fmt(o, "\033[90mVariant [ ? ]" A_OFF);
		}
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
		 * row. Always the colour of an enabled button, lit while the
		 * list is shown.
		 *
		 * What is wrong or missing with a draft is the status line's: a
		 * running commentary beside the button pushed the controls
		 * sideways as it changed length.
		 */
		c = head_btn_x(v);
		out_at(o, top, c);
		out_fmt(o, "%s[ Save ]" A_OFF, "\033[42;30m");
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
static void unit_cells(struct out *o, struct view *v, int y, int is_grp, uint32_t idx)
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
}

/*
 * A BLOCK MATCHER IS TWO ROWS: the block's function's name and hash, and the
 * threshold it must reach, with the comment box every matcher has; and the
 * unit's Type and Tag on a row of their own under it.
 *
 * The hash is bare, what a person compares against the block table; the name is
 * the block's own `sym`, the field the blocks table prints (the engine's
 * kof_func_name). The matcher holds nothing else - ticking
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
		goto unit_row;
	y = PR(r);
	/* No word: find_sim is the only kind of the Blocks tab. Name first, then the hash. */
	ghead_lead(o, v, y, g, "");
	if (blk < v->ed.dr.n_blk && v->ed.dr.blk[blk].sym[0])
		out_fmt(o, A_DIM "%.*s: " A_OFF, (int)MTN_SYM_COL,
			v->ed.dr.blk[blk].sym);
	out_fmt(o, "%s%08x" A_OFF, A_ID,
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
	draw_grp_note(o, v, g);
	/* After the row, so it wins where they overlap - see hit_at. */
	hit_add(v, y, c0, v->grp_th[g][1],   /* not past the comment box */
		hit_grp_pct, g);
unit_row:
	/* A block matcher IS a diagnose unit (the Blocks tab has no conditions): its own Type and Tag, under the row. */
	r++;
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		/* Not hit_row_matcher: its comment-box span is a column range of the first row. */
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_none, 0);
		out_fmt(o, "%7s", "");
		unit_cells(o, v, PR(r), 1, g);
	}
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
 * THE LIST IS ONE AND EACH TAB NUMBERS ITS OWN KIND OF IT FROM 1 (grp_loc), so
 * the Blocks tab opens at 1 whatever Patterns holds, and a tab switch renumbers
 * nothing. Patterns lists find_str and find_at, which its conditions name;
 * Blocks lists the find_sim that ticking a block made, and each IS a unit.
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
 * draw_decl_conds - the Patterns tab's conditions (the Blocks tab has none), each one a block of its own.
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
			if (v->cseq_kind[g] == CS_COND)
				v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
			else if (v->cseq_kind[g] == CS_MATCH)
				v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			r++;
			continue;
		}
		row_start(o, PR(r), 1);
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_cond, g);

		if (v->cseq_kind[g] == CS_COND) {
			/* Under the label of the block's first row. */
			out_fmt(o, "%7s", "");

			/* THE TYPE AND THE TAG, each chosen from a list and never typed
			 * (the same cells as a block matcher's row). */
			unit_cells(o, v, PR(r), 0, ci);
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
			if (grp_tab_count(&v->ed, DT_PATTERNS)) {
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
			if (grp_tab_count(&v->ed, DT_PATTERNS)) {
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
			grp_tab_count(&v->ed, DT_PATTERNS) ? A_ID : A_DIM);
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
/* The fold handle, on the column row of the block table. */
static void hit_fold(struct view *v, uint32_t which)
{
	(void)which;
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

/* The Tag cell of a unit (a condition, or a block matcher with CH_UNIT_GRP) opens the list of the Syndromes catalog's tags. */
static void hit_unit_tag(struct view *v, uint32_t unit)
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
static void hit_unit_type(struct view *v, uint32_t unit)
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
/*
 * ON ARRIVAL AT AN OBJECT THE ENGINE SAYS MATCHED: its blocks that decided a matched form are ticked, the way a reader would tick them (so
 * they become matchers), and the header's Family and Variant take the catalog's names of the diagnose (only while the header holds none).
 * What matched is the engine's report (decided_diags); nothing is worked out here.
 */
static void mtn_from_match(struct view *v)
{
	struct object *ob = cur_obj(v);
	uint32_t n = 0, i;
	const struct kof_diag_report *dd = decided_diags(v, ob, &n);
	const struct kof_diag_report *first = NULL;

	struct { uint32_t g; uint32_t id; char name[KDET_TEXT_MAX]; } made[MAX_GROUP];
	uint32_t n_made = 0;

	/* What was loaded for the previous object is not this object's: links and the loaded list start empty on every arrival. */
	draft_links_reset(&v->ed);
	if (!dd || mtn_foreign(v))
		return;
	for (i = 0; i < v->ed.dr.n_blk; i++) {
		const struct kof_diag_report *d = NULL;
		const struct kof_diag_part *part = kdet_block_part(dd, n, v->ed.dr.blk[i].id, &d);

		if (part) {
			struct kdet_diag kd = { 0 };
			uint32_t g;

			if (!first)
				first = d;
			blk_set_picked(&v->ed, i, 1);
			/* The matcher that ticking made takes the catalog's tag of the diagnose that decided the block. */
			g = grp_of_block(&v->ed, i);
			if (g < MAX_GROUP && kdet_diag_of(v->eng, d->id, &kd) && kd.has_catalog) {
				snprintf(v->ed.dr.grp[g].tag, sizeof v->ed.dr.grp[g].tag, "%.*s", KOF_NAME_MAX, kd.tag);
				/* And its type, which the diagnose declares: a unit that is to be recognised as that diagnose has to say the same. */
				if (kd.type >= 0)
					v->ed.dr.grp[g].utype = (uint8_t)(kd.type + 1);
			}
			/* The link is the diagnose's id value; the name is what the engine turns that id into (the file stem). */
			if (g < MAX_GROUP && n_made < MAX_GROUP && d->id && kd.name) {
				made[n_made].g = g;
				made[n_made].id = d->id;
				snprintf(made[n_made++].name, sizeof made[0].name, "%s", kd.name);
			}
			/* And the threshold the diagnose demands of that block, not the editor's default. */
			if (g < MAX_GROUP && kdet_part_need(d, part))
				v->ed.dr.grp[g].pct = (uint8_t)kdet_part_need(d, part);
		}
	}
	if (first && !v->ed.dr.family[0]) {
		struct kdet_diag kd;
		int created;
		struct kv_fam_ui *u = fam_ensure(v, &created);
		int32_t f;

		if (u && kdet_diag_of(v->eng, first->id, &kd) && kd.has_catalog) {
			/* By the ids the diagnose carries: the engine's text of a variant ("Mirai.A") is not the catalog's name ("Mirai_A"). */
			f = kv_fam_find_family_id(&u->cat, kdb_diagnose_family(v->eng, first->id));
			if (f >= 0) {
				int32_t w;

				decl_pick_family(v, (uint32_t)f);
				w = kv_fam_find_variant_id(&u->cat, kdb_diagnose_variant(v->eng, first->id));
				if (w >= 0)
					decl_pick_variant(v, (uint32_t)w);
			}
		}
	}
	/*
	 * THE LINKS, last: a matcher is linked to the diagnose it was made from only when the draft - family, variant, format, type, tag,
	 * block, threshold - regenerates exactly what that file says (draft_link_unit decides; nothing is compared here). The format the
	 * rule targets is seeded on arrival as well (draft_seed_target, idempotent), because it is part of what the file says.
	 */
	if (n_made) {
		char dir[300];

		draft_seed_target(v);
		snprintf(dir, sizeof dir, "%s/diagnoses", v->basedir[0] ? v->basedir : "bases");
		for (i = 0; i < n_made; i++)
			(void)draft_link_unit(&v->ed, 1, made[i].g, dir, made[i].id, made[i].name);
	}
}

void mtn_sync(struct view *v)
{
	if (!v->mtn_segged || v->mtn_seg_obj != v->node[v->sel_node].obj) {
		/*
		 * WHAT THE ENGINE OFFERS ON ARRIVAL IS NOT THE READER'S EDIT (DR-2).
		 *
		 * mtn_from_match writes the header's family, variant and note, ticks blocks and sets their tag and
		 * threshold, all of which the draft hash mixes, so an untouched draft read as edited at once and
		 * every guard that asks draft_edited (next/previous file, unpack, dump, rebuild) refused with
		 * "Finish or undo the draft first". A draft that was not edited BEFORE the arrival takes the
		 * seeded state as its baseline; one the reader had edited keeps its baseline, so the seeding is
		 * added to a real edit and cannot hide it. Chosen over a flag per field (the opt_auto shape):
		 * the seeding writes six kinds of field, each also written by a reader's click, and a flag would
		 * have to be cleared in every one of those writers.
		 */
		int was_edited = draft_edited(&v->ed);

		mtn_segment(v);
		mtn_order(v);
		v->mtn_segged = 1;
		v->mtn_seg_obj = v->node[v->sel_node].obj;
		mtn_from_match(v);
		if (!was_edited)
			draft_mark_saved(&v->ed);
		/* The rows just moved; a box open on one of them is open on a
		 * different block now. */
		if (v->edit >= ED_GRP_PCT &&
		    v->edit < ED_GRP_PCT + (int)MAX_GROUP)
			v->edit = 0;
		/* A NEW LIST STARTS AT ITS TOP: prow_home says so (the row count is not
		 * known here, prow_build has not run yet, and the scroll does not need it). */
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

static int draw_decl_blocks(struct out *o, struct view *v, int r)
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
		uint32_t band;
		if (!blk_row_shown(v, i))
			continue;
		band = (nshown++ / 2u) & 1u;
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
