#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The header row of the draft panel: the family and variant pick, the types a unit takes from the variant, and the row's controls. */

/* Defined below; a row registers its own callback before the callback is written. */
static void hit_head_family(struct view *v, uint32_t arg);
static void hit_head_variant(struct view *v, uint32_t arg);
static int decl_var_gone(const struct view *v);
static void unit_type_fix(uint8_t *ut, uint32_t mask);
static void note_from_variant(struct view *v, uint32_t var);
static void head_variant_text(const struct view *v, char *out, size_t cap);
static void hit_head_note(struct view *v, uint32_t arg);
static void hit_head_gen(struct view *v, uint32_t arg);
static void hit_head_discard(struct view *v, uint32_t arg);
static int head_btn_x(const struct view *v);

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

void draw_decl_head(struct out *o, struct view *v)
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
