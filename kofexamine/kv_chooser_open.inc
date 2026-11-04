/* kv_chooser_open.inc - the opening half of each chooser kind; included by kv_chooser.c (one translation unit, so the kind table names static functions). */

/*
 * OPENING A CHOOSER: one function per kind, found by `what`.
 *
 * ch_open_in was one function of 664 lines, a chain of `if (what == CH_...)`.
 * Each kind is now a static function that fills the (zeroed) chooser's rows and
 * answers 1 to go on and place the list, or 0 when there is nothing to show -
 * the list then stays closed, exactly as the old early `return` left it. A
 * kind that has no row here (CH_NONE, CH_RANGE4) answers 0 by having no entry.
 * The taking half is in kv_chooser_take.inc; kv_chooser.c joins both in one table (struct ch_kind).
 */

/* THE ANCHORS, one row each. */
static int ch_open_atoff(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)v; (void)arg;

	/*
	 * THE ANCHORS, AND NOTHING ELSE - see enum kof_anchor.
	 *
	 * THIS LIST USED TO ANSWER TWO QUESTIONS AT ONCE. Above the
	 * anchors it carried every occurrence of the matcher's marker
	 * twice - as the offset it sits at, and as a step from the
	 * entry point - so the same list held "0x4d78", "entry +
	 * 0x3ee8" and "entry", which are two spellings of one place
	 * followed by an anchor. WHICH OCCURRENCE and HOW TO EXPRESS
	 * IT are different questions, and a control that asks both
	 * has to be read twice to be understood.
	 *
	 * It made sense while the place was ONE span: the list was
	 * the only way to change any part of it. The row now draws
	 * three controls - the anchor, the sign, the step - and this
	 * one is behind the anchor. So it offers anchors.
	 *
	 * The step is typed, and changing the anchor converts a step
	 * the engine put there rather than keeping it - see
	 * group.at_auto - which is what the entry-relative rows were
	 * really for.
	 *
	 * NO GUARD ON THE MARKER. The old list was built out of a
	 * marker's occurrences and had to return when there were
	 * none; an anchor does not depend on the bytes being found,
	 * so there is always something here to choose.
	 */
	for (i = 0; i < KOF_ANCHOR_COUNT; i++)
		ch_add(c, kof_anchor_word((int)i));
	return 1;
}

/* find_str or find_at. */
static int ch_open_rule(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)v; (void)arg;

	/*
	 * ONE ROW FOR THE THREE SEARCHES, because they are one question
	 * asked with three thresholds.
	 *
	 * find_all is "every one of them", find_any is "at least one"
	 * and find_multi is "at least N" - the same fold over the same
	 * markers in the same range, differing only in the number. Three
	 * rows made the reader choose a SPELLING before choosing the
	 * number, and then offered the number separately with 1 and the
	 * maximum missing from it, because those two had rows of their
	 * own. So the kind is one row and the number is the whole
	 * choice.
	 *
	 * WHAT IS GENERATED DOES NOT CHANGE - see grp_rule_of_thresh:
	 * the number picks the call back, so a rule still comes out as
	 * kof_find_str_all, _any or _multi, an old rule still reads
	 * back, and the short-circuit that && and || give is still
	 * there where it applies.
	 *
	 * THESE TWO ARE THE STRING MATCHERS. A similarity matcher is
	 * not a kind to choose here: ticking a block makes its find_sim
	 * and unticking drops it - see blk_set_picked.
	 */
	ch_add(c, "find_str");
	/* Last, because it is the one that is not a search: it compares
	 * at one offset, and it is the only rule that constrains the
	 * matcher to a single marker. */
	ch_add(c, "find_at (offset)");
	return 1;
}

/* Which defined range a matcher searches. */
static int ch_open_range(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/*
	 * WHICH DEFINED RANGE THIS MATCHER SEARCHES.
	 *
	 * Every range the draft has, plus WHOLE-FILE - not a set worked
	 * out from the markers the matcher happens to hold. That was
	 * the old rule and it is what made a matcher on CODE&DATA
	 * refuse a DATA marker: the range was DERIVED from the first
	 * marker, so taking one from CODE narrowed the matcher to CODE
	 * and locked the other region out, even though the draft had
	 * declared CODE&DATA and the row displayed it.
	 *
	 * Picking here PINS grp[g].mask to the chosen range, so the
	 * eligibility test - rng_holds, an overlap - then admits a
	 * marker from any region the range covers. That is the whole
	 * fix: the range says what may go in, rather than the first
	 * thing that went in saying what the range is.
	 */
	uint32_t rm[2 * MAX_GROUP];
	int ru[2 * MAX_GROUP];
	uint32_t nr = rng_all(&v->ed, rm, ru, 2u * MAX_GROUP), k;
	char t[CH_W];

	for (k = 0; k < nr; k++) {
		rng_name_of(cur_obj(v)->fmt, rm[k], t, sizeof t);
		ch_add(c, t);
	}
	ch_add(c, "WHOLE-FILE");
	return 1;
}

/* The menu for one scan range. */
static int ch_open_range2(struct view *v, struct chooser *c, uint32_t arg)
{
	/*
	 * THE MENU FOR ONE RANGE, the one whose name was clicked.
	 *
	 * `arg` is its index in rng_all's order - the same order the row
	 * drew the names in - so the subject is settled before a single
	 * item is offered, and every item names it.
	 *
	 * Three things can be done to a range and they are different
	 * questions: make it cover MORE (extend), make it cover LESS
	 * (drop one region), or make it not exist (remove). Drop and
	 * remove are deliberately not the same item: on CODE&DATA&NOLOAD
	 * "remove" takes the whole range away, while "drop" takes one
	 * region off and leaves a narrower range behind.
	 */
	uint32_t rm[2 * MAX_GROUP];
	int ru[2 * MAX_GROUP];
	uint32_t nr = rng_all(&v->ed, rm, ru, 2u * MAX_GROUP);
	uint32_t cur, have, rest, bits = 0, b;
	char nm[40], t[CH_W];

	if (arg >= nr)
		return 0;
	cur  = rm[arg];
	have = ch_rng_regions(v);
	rest = have & ~cur;               /* regions it does not cover */
	for (b = 0; b < 32u; b++)
		bits += (cur >> b) & 1u;
	rng_name_of(cur_obj(v)->fmt, cur, nm, sizeof nm);
	c->arg2 = cur;

	/* Extend: one region left is named outright, several ask. */
	if (rest && !(cur & KOF_SCAN_ALL)) {
		uint32_t rb = 0;

		for (b = 0; b < 32u; b++)
			rb += (rest >> b) & 1u;
		if (rb == 1u) {
			char on[40];

			rng_name_of(cur_obj(v)->fmt, rest, on, sizeof on);
			snprintf(t, sizeof t, "Extend with %.20s", on);
			ch_add_verb(c, t, 0);
		} else {
			ch_add_verb_sub(c, "Extend with a region", 0);
		}
	}
	/*
	 * Drop one region, only while there is more than one to drop
	 * FROM: a range of a single region has nothing to narrow to,
	 * and taking its last region away is what Remove means.
	 */
	if (bits > 1u)
		ch_add_verb_sub(c, "Drop a region from this range", 1);
	snprintf(t, sizeof t, "Remove scan range %.15s", nm);
	ch_add_verb(c, t, 2);
	if (!c->n)
		return 0;
	return 1;
}

/* A new range over one region. */
static int ch_open_range_add(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/*
	 * A NEW RANGE, over any single region the object has, and
	 * WHOLE-FILE last.
	 *
	 * Every region is offered, not only those no range covers yet.
	 * A narrow range and a wider one containing it are different
	 * questions - "this marker must be in CODE" beside "any of
	 * these, wherever the compiler put them" - and offering only
	 * the uncovered ones made the narrow one unreachable the moment
	 * the wide one existed, with no way back. An exactly duplicate
	 * mask is still refused where the range is created; the packer
	 * merges identical masks anyway.
	 */
	uint32_t have = ch_rng_regions(v), b;
	char t[CH_W];

	for (b = 0; b < 32u; b++) {
		if (!(have & (1u << b)))
			continue;
		rng_name_of(cur_obj(v)->fmt, 1u << b, t, sizeof t);
		ch_add(c, t);
	}
	ch_add(c, "WHOLE-FILE");
	return 1;
}

/* Which region to add to, or take off, the subject range (CH_RANGE_EXT and CH_RANGE_DROP). */
static int ch_open_range_pick(struct view *v, struct chooser *c, uint32_t arg)
{
	/*
	 * Which region to add to, or take off, the subject range. The
	 * subject came down in arg2 from the menu that raised this one.
	 */
	/*
	 * THE SUBJECT COMES THROUGH `arg`, not arg2.
	 *
	 * ch_open memsets the chooser and then builds the items, so
	 * anything the caller writes into arg2 AFTERWARDS is not there
	 * while this list is being made. It was read from arg2 and the
	 * effects were both bugs: Drop saw 0, produced no items and so
	 * never opened at all, and Extend saw "every region" while the
	 * taker later saw "every region except this range's" - two
	 * different lists, so row N chose a different region from the
	 * one printed on it.
	 */
	uint32_t set = c->what == CH_RANGE_EXT
		     ? (ch_rng_regions(v) & ~arg) : arg;
	char t[CH_W];
	uint32_t b;

	for (b = 0; b < 32u; b++) {
		if (!(set & (1u << b)))
			continue;
		rng_name_of(cur_obj(v)->fmt, 1u << b, t, sizeof t);
		ch_add(c, t);
	}
	if (!c->n)
		return 0;
	return 1;
}

/* The header's family. */
static int ch_open_hfam(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)arg;

	int created;
	struct kv_fam_ui *u = fam_ensure(v, &created);

	if (!u || !u->cat.n_fam) {
		say_note(&v->ed, "no pathogens: add one in Manage > Pathogens");
		return 0;
	}
	for (i = 0; i < u->cat.n_fam; i++)
		ch_add(c, u->cat.fam[i].name);
	return 1;
}

/* The header's variant. */
static int ch_open_hvar(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)arg;

	/* Only the chosen family's variants; each row is the name the catalog composed (the types are the unit's to choose, not shown here). */
	int created;
	struct kv_fam_ui *u = fam_ensure(v, &created);
	int32_t f = u ? kv_fam_find_family(&u->cat, v->ed.dr.family) : -1;

	if (f < 0)
		return 0;
	for (i = 0; i < u->cat.n_var; i++) {
		struct kv_fam_row r = { KV_FAM_VARIANT, (uint32_t)f, (int32_t)i };
		char nm[KOF_FAMCAT_NAME_MAX + 8], ty[128], cm[KOF_FAMCAT_COMMENT_MAX + 1];

		if (u->cat.var[i].family != (uint32_t)f)
			continue;
		kv_fam_cells(&u->cat, &r, nm, sizeof nm, ty, sizeof ty, cm, sizeof cm);
		ch_add_verb(c, nm + KV_FAM_INDENT, i);
	}
	if (!c->n)
		return 0;
	return 1;
}

/* A unit's type. */
static int ch_open_utype(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)arg;

	uint32_t mask = decl_var_types(v);

	for (i = 0; i < kof_famcat_type_count(); i++)
		if (mask & (1u << kof_famcat_type_value(i)))
			ch_add_verb(c, kof_famcat_type_name(i), kof_famcat_type_value(i));
	if (!c->n)
		return 0;
	return 1;
}

/* A unit's tag. */
static int ch_open_utag(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)arg;

	struct kv_tag_ui *u = tags_ensure(v);

	if (!u || !u->cat.n) {
		say_note(&v->ed, "no syndromes: add one in Manage > Syndromes");
		return 0;
	}
	/* The name alone: a tag's activities and objects are the Syndromes dialog's to show. */
	ch_add_verb(c, "(none)", 0);
	for (i = 0; i < u->cat.n; i++)
		ch_add_verb(c, u->cat.tag[i].name, i + 1u);
	return 1;
}

/* An unused marker for a matcher. */
static int ch_open_marker(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	/*
	 * Only the markers this condition could actually search for:
	 * unused, and inside the range it names. Offering the rest and
	 * refusing afterwards would be a list that lies about itself.
	 */
	char t[CH_W];
	for (i = 0; i < v->ed.dr.n_decl; i++) {
		/* Already in THIS matcher is what disqualifies it -
		 * being in another one does not. A marker two matchers
		 * ask about is the whole point of the shape. */
		if (v->ed.dr.decl[i].grp & (1u << arg))
			continue;
		if (!rng_holds(grp_mask(&v->ed, arg), v->ed.dr.decl[i].mask))
			continue;
		snprintf(t, sizeof t, "%u  %s  %s", i + 1u,
			 v->ed.dr.decl[i].hex ? "hex" : "str",
			 v->ed.dr.decl[i].rgn);
		ch_add(c, t);
	}
	if (!c->n)
		return 0;
	return 1;
}

/* A matcher for a condition. */
static int ch_open_cmatch(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	/*
	 * The matchers this condition does not already name.
	 *
	 * Same shape as picking a marker for a matcher, one level up:
	 * a condition is written over matchers the way a matcher is
	 * written over markers, and offering one that is already in
	 * the expression would produce "1&1".
	 */
	char t[CH_W];

	for (i = 0; i < v->ed.dr.n_grp; i++) {
		if (!cmatch_ok(v, arg, i))
			continue;
		grp_label(&v->ed, i, t, sizeof t);
		ch_add(c, t);
	}
	if (!c->n)
		return 0;
	return 1;
}

/* What to do to one matcher a condition names. */
static int ch_open_cmatch2(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	/*
	 * One matcher on a condition's row, and the three things that
	 * can be done to it.
	 *
	 * Clicking it used to remove it outright. That is the right
	 * thing to be able to do and the wrong thing for a click to
	 * mean on its own: it is the only one of the three that loses
	 * work, and it happened with nothing on screen to undo it.
	 */
	uint32_t ci = CH_PAIR_C(arg), m = CH_PAIR_M(arg);
	struct cond *cc;
	char t[CH_W];

	if (ci >= v->ed.dr.n_cnd || m >= v->ed.dr.n_grp)
		return 0;
	cc = &v->ed.dr.cnd[ci];
	if (!cnd_uses(&v->ed, cc, m))
		return 0;
	/*
	 * ONE VERB FOR BOTH DIRECTIONS, in the notation the row is
	 * already showing.
	 *
	 * Inverting is its own inverse, so the item never needs an
	 * "un-" form - and naming the two ends says which way this
	 * particular row goes without the reader having to work out
	 * which state they are in. Spelling the same fact out in words
	 * instead - "must be absent" - makes them translate between two
	 * vocabularies for it, and the "!" is the one on screen.
	 */
	snprintf(t, sizeof t, cnd_neg(&v->ed, cc, m)
		 ? "Invert !%u to %u"
		 : "Invert %u to !%u", grp_loc(&v->ed, m),
		 grp_loc(&v->ed, m));
	ch_add_verb(c, t, 0);
	/*
	 * Only while there is another matcher to switch TO. A row that
	 * opens an empty list is a row that appears to do nothing, and
	 * the same predicate answers here and where the pick is carried
	 * out - see ch_opt_offerable for why that matters.
	 */
	for (i = 0; i < v->ed.dr.n_grp; i++)
		if (cmatch_ok(v, ci, i))
			break;
	if (i < v->ed.dr.n_grp)
		ch_add_verb_sub(c, "Switch to another matcher", 1);
	snprintf(t, sizeof t, "Remove matcher %u", grp_loc(&v->ed, m));
	ch_add_verb(c, t, 2);
	return 1;
}

/* Which matcher takes the place of one. */
static int ch_open_cswap(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	/*
	 * The matchers this condition could hold instead - which is
	 * the same list CH_CMATCH offers, for the same reason: one
	 * already in the expression would produce "1&1", and one the
	 * gate above already tested has been decided before control
	 * gets here.
	 *
	 * The one being replaced is in the expression, so it excludes
	 * itself and no extra rule is needed to keep it off its own
	 * list.
	 */
	uint32_t ci = CH_PAIR_C(arg);
	char t[CH_W];

	if (ci >= v->ed.dr.n_cnd)
		return 0;
	for (i = 0; i < v->ed.dr.n_grp; i++) {
		if (!cmatch_ok(v, ci, i))
			continue;
		grp_label(&v->ed, i, t, sizeof t);
		ch_add(c, t);
	}
	if (!c->n)
		return 0;
	return 1;
}

/* One target format's own menu. */
static int ch_open_fmt(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/*
	 * ONE FORMAT'S OWN MENU: swap it for another, or drop it.
	 *
	 * `arg` is which of the set was clicked, counted in format
	 * order - the same walk that drew the names, so the row pressed
	 * and the row acted on cannot drift apart.
	 *
	 * Every other format is offered as a SWITCH rather than as an
	 * add, because that is what clicking a name means: this one,
	 * changed. Adding is the button at the end of the row.
	 */
	/*
	 * BY KIND, THE SAME SHAPE AS "+ Formats", because it is the
	 * same question asked about the same eighteen names.
	 *
	 * This was one flat list of "Switch to <name>" - seventeen rows
	 * in whatever order the enum happens to be in, which is the
	 * list fmt_cat exists to avoid presenting. The ACT is still a
	 * swap and not an add; only the way the choice is laid out
	 * changed, so a reader who has learnt one of these two menus
	 * has learnt both.
	 *
	 * THE FORMAT IN USE CANNOT BE OFFERED, and not by a test: every
	 * pool below is masked with ~fmt_mask, so the row being
	 * switched FROM is absent by construction.
	 */
	uint32_t ci;

	for (ci = 0; ci <= FMT_CAT_N; ci++)
		if (ch_fmt_cat_langs(ci) ||
		    (ch_fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
			ch_add_verb_sub(c, ch_fmt_cat_name(ci), 0);
	/* Last, and the one row that acts rather than opening a list. */
	ch_add(c, "Remove this format");
	return 1;
}

/* One kind's formats to switch to. */
static int ch_open_fmt_sw(struct view *v, struct chooser *c, uint32_t arg)
{
	/* One kind's formats, minus what the draft already targets. */
	uint8_t f;
	uint32_t have = ch_fmt_cat_mask(FMT_SW_CAT(arg)) &
			~v->ed.dr.fmt_mask;

	for (f = 0; f < KOF_FMT_COUNT; f++)
		if (have & (1u << f))
			ch_add(c, kof_format_name(f));
	return 1;
}

/* Languages to switch to. */
static int ch_open_fmt_sw_lang(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/*
	 * AND FOR SCRIPTS THE CHOICE IS A LANGUAGE, so what the switch
	 * list leaves out is the LANGUAGE in use, not the format.
	 * Masking with ~fmt_mask would hide the whole Scripts row the
	 * moment a draft targeted a script - which is exactly when the
	 * reader wants to change which script it is.
	 */
	uint32_t k, skip = ch_fmt_lang_skip(v);

	for (k = 0; k < script_sub_n; k++) {
		if (k == skip)
			continue;
		ch_add(c, k == 0 ? "Any language" : script_sub[k]);
	}
	return 1;
}

/* The kinds of format. */
static int ch_open_fmt_cat(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/* Only the kinds that still have something to offer - a row
	 * that opens an empty submenu is a row that wastes a click. */
	uint32_t ci;

	for (ci = 0; ci <= FMT_CAT_N; ci++)
		/*
		 * A row is offered while it has a format left to add -
		 * AND the languages row is offered always, because what
		 * it sets is the subtype as much as the format. With
		 * the format already in the set it is still the way to
		 * say which language, and hiding it there left the
		 * reader with the menu they wanted gone from the menu
		 * bar.
		 */
		if (ch_fmt_cat_langs(ci) ||
		    (ch_fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
			/* Each opens a list rather than acting, so
			 * each carries the menu bar's ">" - see
			 * chooser.sub. */
			ch_add_verb_sub(c, ch_fmt_cat_name(ci), 0);
	return 1;
}

/* The scripting languages. */
static int ch_open_fmt_lang(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)v; (void)arg;

	/*
	 * THE LANGUAGES, and picking one states TWO things: the format
	 * is a script and the subtype is that language.
	 *
	 * They belong together because a rule that says "script" and
	 * nothing else is offered every script on the machine - every
	 * .sh, every .py - which is the cost the subtype axis exists to
	 * avoid. The menu that sets the format is the place to avoid
	 * it, rather than a second row the reader has to know to go and
	 * find afterwards.
	 *
	 * Row 0 is KOF_SCRIPT_ANY, which is a real answer and not a
	 * blank: "a script, whichever language". It is spelled so
	 * rather than left as the enum's word, and it CLEARS the
	 * subtype instead of setting it to zero - a declared subtype of
	 * ANY and no declared subtype are the same filter, and only one
	 * of them is honest about what was chosen.
	 */
	uint32_t k;

	for (k = 0; k < script_sub_n; k++)
		ch_add(c, k == 0 ? "Any language" : script_sub[k]);
	return 1;
}

/* One kind's formats to add. */
static int ch_open_fmt_add(struct view *v, struct chooser *c, uint32_t arg)
{
	/* One kind's formats, and only what is not already there: a
	 * list that offers what it will refuse lies about itself. */
	uint32_t have = ch_fmt_cat_mask(arg) & ~v->ed.dr.fmt_mask;
	uint8_t f;

	for (f = 0; f < KOF_FMT_COUNT; f++)
		if (have & (1u << f))
			ch_add(c, kof_format_name(f));
	return 1;
}

/* The codings of the decoder. */
static int ch_open_enc_type(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/*
	 * A LIST, NOT A CYCLE. Stepping a control through seven values
	 * to reach the one you want is a control that has to be poked
	 * six times and watched while you do it. The chooser is already
	 * here, every other multi-valued field in this file uses it,
	 * and it shows all seven at once with the current one marked.
	 */
	uint32_t t;

	for (t = 0; t < (uint32_t)KOF_CODEC_COUNT; t++)
		ch_add(c, kof_codec_name(t));
	c->sel = (int)v->enc_type;
	return 1;
}

/* Which optional declaration to add. */
static int ch_open_opt(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)arg;

	/* Only the ones this object can answer for, and only the ones
	 * not already there: a list that offers what it will refuse is
	 * a list that lies about itself. */
	if (ch_opt_offerable(v, OPT_SIZE_MIN))
		ch_add(c, opt_word[OPT_SIZE_MIN]);
	if (ch_opt_offerable(v, OPT_SIZE_MAX))
		ch_add(c, opt_word[OPT_SIZE_MAX]);
	/* Which of these two the object can answer for is decided in
	 * ch_opt_offerable, for this list and for the taker both. */
	if (ch_opt_offerable(v, OPT_ARCH))
		ch_add(c, opt_word[OPT_ARCH]);
	if (ch_opt_offerable(v, OPT_SUBTYPE))
		ch_add(c, opt_word[OPT_SUBTYPE]);
	if (!c->n)
		return 0;
	return 1;
}

/* Every architecture. */
static int ch_open_arch(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)v; (void)arg;

	for (i = 0; i < ARCH_N; i++)
		ch_add(c, arch_word[i].word);
	return 1;
}

/* The format's subtypes. */
static int ch_open_subtype(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	(void)arg;

	uint8_t fmt = cur_obj(v)->ctx.format;

	if (fmt == KOF_FMT_ELF)
		for (i = 0; i < elf_sub_n; i++)
			ch_add(c, elf_sub[i]);
	else if (fmt == KOF_FMT_PE)
		for (i = 0; i < pe_sub_n; i++)
			ch_add(c, pe_sub[i]);
	if (!c->n)
		return 0;
	return 1;
}

/* What [+ String] adds. */
static int ch_open_declkind(struct view *v, struct chooser *c, uint32_t arg)
{
	(void)v; (void)arg;

	/*
	 * WHAT THE ROW AT THE FOOT OF THE STRINGS TABLE ADDS.
	 *
	 * Plain text first because it is what a reader reaches for
	 * most, then the two that are written as a pattern.
	 */
	ch_add(c, "String");
	ch_add(c, "Hex");
	ch_add(c, "Regex");
	return 1;
}

/* The attributes of one marker. */
static int ch_open_attr(struct view *v, struct chooser *c, uint32_t arg)
{
	/* Seeded from the declaration, which is the last thing that
	 * wrote it - so a list reopened after an Apply comes up on
	 * what was applied. */
	const struct decl *d = arg < v->ed.dr.n_decl
			     ? &v->ed.dr.decl[arg] : NULL;

	c->pend_icase = d ? d->icase != 0 : 0;
	c->pend_word = d ? d->fullword : KOF_WORD_SUBSTRING;
	ch_attr_items(c);
	return 1;
}

/* How many markers must be present. */
static int ch_open_thresh(struct view *v, struct chooser *c, uint32_t arg)
{
	uint32_t i;

	char t[CH_W];
	uint32_t n = arg < v->ed.dr.n_grp ? grp_count(&v->ed, arg) : 0;

	/*
	 * WHERE THE LIST STARTS DEPENDS ON WHETHER THE CALL IS SHARED.
	 *
	 * On its own, ">= 1" is find_any spelled the long way and n is
	 * find_all - both already have their own entry in the rule
	 * list, so offering them here would be two ways to say one
	 * thing.
	 *
	 * Sharing a call changes that. "at least three, otherwise at
	 * least one" is a real pair of thresholds over ONE scan, and
	 * writing the weaker half as a second find_any matcher would
	 * scan the same markers in the same region again - the cost
	 * this shape exists to remove. So when another matcher asks the
	 * same thing, 1 becomes a threshold like any other.
	 */
	/*
	 * EVERY NUMBER, INCLUDING 1 AND THE MAXIMUM.
	 *
	 * They used to be left out because find_any and find_all had
	 * rows of their own in the kind menu, and offering them here as
	 * well would have been two ways to say one thing. The kind menu
	 * is one row now - see where it is built - so this list is the
	 * whole choice, and the two ends of it are the two spellings
	 * that were taken away.
	 *
	 * THE TOP READS "==" BECAUSE IT MEANS SOMETHING ELSE. Every
	 * other row is a floor that a bigger file can clear with room
	 * to spare; the top one is "all of them", and it FOLLOWS the
	 * marker list - add another marker and it still means all of
	 * them, where ">= 4" would have been left behind. Writing it as
	 * a number would hide that difference behind a value that
	 * happens to be equal today.
	 */
	/* Up to AND INCLUDING n: the old bound stopped one short
	 * because the top value was find_all's row, and that row is
	 * gone. Left as it was, the list could never offer "all of
	 * them" - and for a matcher with one marker it offered
	 * nothing at all. */
	for (i = 1u; i <= n; i++) {
		if (i == n)
			snprintf(t, sizeof t, "== %u", i);
		else
			snprintf(t, sizeof t, ">= %u", i);
		ch_add(c, t);
	}
	if (!c->n)
		return 0;
	return 1;
}
