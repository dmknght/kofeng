#define _GNU_SOURCE
#include "kv.h"


/*
 * THE ATTRIBUTE FORM'S ROWS, BY NAME.
 *
 * Fixed, because every row is always offered: unlike the range list, nothing
 * here is ever declined, so the index IS the row and there is no verb to
 * carry. The two rules and the Apply row are part of the numbering - a list
 * that renumbered when a separator moved would be the same drift chooser.verb
 * exists to prevent.
 */
enum {
	CH_ATTR_ICASE = 0,
	CH_ATTR_SEP1,
	CH_ATTR_TOKEN,
	CH_ATTR_FULLWORD,
	CH_ATTR_PATTERN,
	CH_ATTR_SEP2,
	CH_ATTR_APPLY,
	CH_ATTR_ROWS
};

#define FMT_CAT_N (sizeof g_fmt_cat / sizeof g_fmt_cat[0])

/*
 * TWO NUMBERS IN ONE `arg`, because a switch submenu needs both and the
 * chooser carries one.
 *
 * The low byte is WHICH of the draft's formats was clicked - the row being
 * switched away from - and the high byte is which CATEGORY the reader then
 * opened. Packed rather than stashed in `struct view`: the chooser already
 * carries its own argument down to the taker, and a second copy living beside
 * it is a second thing to keep in step. Both fit easily - there are eighteen
 * formats and seven categories.
 */
#define FMT_SW_PACK(cat, which) (((cat) << 8) | ((which) & 0xffu))
#define FMT_SW_CAT(a)           ((a) >> 8)
#define FMT_SW_WHICH(a)         ((a) & 0xffu)

/*
 * WHAT AN ANCHOR IS WORTH IN THIS OBJECT, or that it is worth nothing.
 *
 * bof is zero by definition, eof is the object's size, and entry is whatever
 * the parser resolved - which may be nothing at all, KGENOME_NA for a format with
 * no such notion and KGENOME_BROKEN when it could not be worked out. Converting a
 * place between anchors is arithmetic on these, so the absent case has to be
 * an answer rather than a number: AT_NO_ANCHOR is returned and the caller
 * refuses the move.
 */
#define AT_NO_ANCHOR INT64_MIN



/*
 * The draft, laid out the way the source it becomes is laid out.
 *
 * Two areas. Above: what the module DECLARES - its name, its type, its ranges,
 * its strings, each with the id the conditions below will refer to. Below: the
 * conditions, which name ids rather than repeating bytes.
 *
 * That split is not decoration. A string declared once and used by a condition
 * is exactly the shape of the file being written, and a panel that printed the
 * bytes again under each condition would be describing a different file - and
 * would make a string used twice look like two strings.
 */
static void ch_add(struct chooser *c, const char *t)
{
	if (c->n < CH_ITEMS)
		snprintf(c->item[c->n++], CH_W, "%s", t);
}

/* The same, for a list whose rows are not all always there. */
static void ch_add_verb(struct chooser *c, const char *t, unsigned verb)
{
	if (c->n < CH_ITEMS)
		c->verb[c->n] = (uint8_t)verb;
	ch_add(c, t);
}

/* A rule between two halves of one list - see chooser.sep. The text is never
 * drawn, so it only has to be something. */
static void ch_add_sep(struct chooser *c)
{
	if (c->n < CH_ITEMS)
		c->sep[c->n] = 1;
	ch_add(c, "");
}

/* The same, for a row that OPENS A LIST rather than acting - drawn with the
 * menu bar's ">" marker. See chooser.sub. */
static void ch_add_verb_sub(struct chooser *c, const char *t, unsigned verb)
{
	if (c->n < CH_ITEMS)
		c->sub[c->n] = 1;
	ch_add_verb(c, t, verb);
}

/*
 * Built from the PENDING edit and not from the declaration, which is what
 * makes the tick and the dot move while the draft stays as it was.
 *
 * Rebuilt in place rather than reopened: the row, the column and the width
 * are already right and every state of this list is the same width, so
 * reopening would recompute the same placement and lose the cursor.
 */
static void ch_attr_items(struct chooser *c)
{
	char t[CH_W];

	c->n = 0;
	memset(c->sep, 0, sizeof c->sep);
	memset(c->sub, 0, sizeof c->sub);
	snprintf(t, sizeof t, "[%c] ignore case", c->pend_icase ? 'x' : ' ');
	ch_add(c, t);
	ch_add_sep(c);
	/*
	 * MOST SPECIFIC FIRST, and the order is not the enum's - a marker is
	 * a whole token far more often than it is a fragment of one, and the
	 * top row is where the eye starts. The row is named rather than
	 * counted, so the order here and the meaning in ch_take cannot drift
	 * the way a position table let them.
	 */
	{
		/* The three, spelled by decl_word_word so this list and the
		 * cell it edits cannot call the same value two things. The
		 * order is this array and not the enum's. */
		static const int word_of_row[] = {
			KOF_WORD_TOKEN, KOF_WORD_FULLWORD, KOF_WORD_SUBSTRING
		};
		unsigned k;

		for (k = 0; k < sizeof word_of_row / sizeof word_of_row[0];
		     k++) {
			snprintf(t, sizeof t, "(%c) %s",
				 c->pend_word == word_of_row[k] ? 'o' : ' ',
				 decl_word_word(word_of_row[k]));
			ch_add(c, t);
		}
	}
	ch_add_sep(c);
	/*
	 * APPLY IS THE ONLY WAY IN, and leaving is therefore the way out.
	 *
	 * The rows above move an edit that nothing has been told about yet,
	 * so a list dismissed - Escape, q, a click anywhere else - leaves the
	 * declaration exactly as it was. That is what lets somebody try two
	 * combinations before choosing one, and it is why this row exists at
	 * all rather than the list writing as it goes.
	 */
	ch_add(c, "Apply");
}


/*
 * THE ROWS ARE THE ENGINE'S GROUPS, not a list kept here.
 *
 * They were a table of masks written out format by format, and the failure was
 * the one every hand copy has: a format added to the engine was not in it, so
 * bzip2 was missing from Archives and reachable only through Other - a menu
 * quietly narrower than the engine it describes.
 *
 * kof_format_group answers which row a format belongs in and
 * kof_format_group_name gives the word, so this array is now only what is
 * PECULIAR TO THIS PANEL: which rows to show, in which order, and which one
 * opens languages instead of formats.
 *
 * TEXT IS NOT A SCRIPT, it is the absence of one - which is why it is not a row
 * here even though the engine has a group for it. KOF_FMT_SCRIPT says "these
 * bytes are meant to be run"; KOF_FMT_TEXT says only "these bytes are
 * readable" - a log, a config, a README. Grouping them put every text file one
 * click away from a menu of interpreters, which reads as a claim about it. It
 * falls into Other by subtraction, along with Raw and the event targets, which
 * are not file formats a draft can name.
 */
static const struct fmt_cat g_fmt_cat[] = {
	{ KOF_FGRP_EXEC,    0 },
	/*
	 * THIS ROW OPENS LANGUAGES - see the langs field. It is the one row
	 * whose submenu is not a list of formats.
	 */
	{ KOF_FGRP_SCRIPT,  1 },
	{ KOF_FGRP_DOC,     0 },
	{ KOF_FGRP_ARCHIVE, 0 },
	{ KOF_FGRP_MEDIA,   0 }
};

/* Every format the engine puts in this group, as the mask this panel works in.
 * Built from the engine each time rather than stored: it is a handful of
 * comparisons on a menu click, and a stored copy is the thing that went
 * stale. */
static uint32_t fmt_cat_of_group(enum kof_format_group g)
{
	uint32_t mask = 0, f;

	for (f = 0; f < KOF_FMT_COUNT; f++)
		if (kof_format_group((uint8_t)f) == g)
			mask |= 1u << f;
	return mask;
}

/* Everything the rows above do not name, so nothing can be unreachable. */
static uint32_t fmt_cat_other(void)
{
	uint32_t all = (uint32_t)((1u << KOF_FMT_COUNT) - 1u), i;

	for (i = 0; i < FMT_CAT_N; i++)
		all &= ~fmt_cat_of_group(g_fmt_cat[i].group);
	return all;
}

/* The mask of category `i`, with the catch-all last. */
static uint32_t fmt_cat_mask(uint32_t i)
{
	return i < FMT_CAT_N ? fmt_cat_of_group(g_fmt_cat[i].group)
			     : fmt_cat_other();
}

static const char *fmt_cat_name(uint32_t i)
{
	/* Plural like every row above it - the catch-all is a GROUP of formats
	 * and was the one row that read as a single thing. */
	return i < FMT_CAT_N ? kof_format_group_name(g_fmt_cat[i].group)
			     : "Others";
}

/* Does this row open a list of languages rather than of formats? */
static int fmt_cat_langs(uint32_t i)
{
	return i < FMT_CAT_N && g_fmt_cat[i].langs;
}

/*
 * The language a switch list must leave out: the one already in use.
 *
 * script_sub_n when there is none to leave out, which is a draft that does not
 * target a script yet - there every language is a real choice. A draft that
 * does target one but declared no subtype is using KOF_SCRIPT_ANY, which is
 * row 0.
 */
static uint32_t fmt_lang_skip(const struct view *v)
{
	if (!(v->ed.dr.fmt_mask & (1u << KOF_FMT_SCRIPT)))
		return script_sub_n;
	/* opt_val is 64 bit because a size bound lives in the same array; a
	 * subtype is one of sixteen. */
	return v->ed.dr.opt_on[OPT_SUBTYPE]
	       ? (uint32_t)v->ed.dr.opt_val[OPT_SUBTYPE] : 0u;
}

/* Put one format in place of another, and say nothing when either is absent. */
static void fmt_swap(struct view *v, uint32_t which, uint8_t pick)
{
	uint8_t f, n = 0, cur = KOF_FMT_COUNT;

	for (f = 0; f < KOF_FMT_COUNT; f++)
		if (v->ed.dr.fmt_mask & (1u << f)) {
			if (n == which)
				cur = f;
			n++;
		}
	if (cur >= KOF_FMT_COUNT)
		return;
	v->ed.dr.fmt_mask &= ~(1u << cur);
	if (pick < KOF_FMT_COUNT)
		v->ed.dr.fmt_mask |= 1u << pick;
	/*
	 * A SWAP KEEPS THE COUNT, so the ambiguity warning that an add needs is
	 * not needed here - see the note where CH_FMT_ADD raises it. Removing
	 * is allowed to empty the set: the panel says "Format None" in words,
	 * which beats a control that will not respond.
	 */
}
/* The removable scan ranges, listed the same way where the menu is built and
 * where a pick is carried out. Defined beside rng_apply, used here first. */
/* Every range the draft has, in one order, and which regions the object has -
 * both defined beside rng_apply and used by the menus above it. */
static uint32_t rng_object_regions(struct view *v);


/*
 * Is this optional declaration worth offering on THIS object.
 *
 * One function because two places need the answer - the list that offers them
 * and the taker that walks the same list to find which row was picked - and a
 * predicate written twice is a menu that offers what it will refuse.
 *
 * Architecture belongs to executables and to nothing else: a zip has no
 * machine. Subtype belongs to whatever format HAS one - see the branch that
 * answers it. Asked of the object in hand rather than from a fixed list, so the
 * menu answers for the file being looked at.
 */
static int opt_offerable(struct view *v, int k)
{
	uint8_t fm = cur_obj(v)->ctx.format;
	int exe = fm == KOF_FMT_ELF || fm == KOF_FMT_PE || fm == KOF_FMT_MACHO;

	if (k < 0 || k >= OPT_COUNT || v->ed.dr.opt_on[k])
		return 0;

	/*
	 * AN EVENT HAS NONE OF THESE.
	 *
	 * All four are questions about a FILE. Architecture and subtype are
	 * properties of an executable, and a record is not one. The two sizes
	 * are worse than merely inapplicable: an event's object size is the
	 * record, which is a fixed head plus however much of a script the
	 * collector managed to carry - so "size >= 400" is a statement about
	 * the transport, not about the sample, and it would drift the day the
	 * head or the arena changes size.
	 *
	 * Offered anyway, they would be four rows a researcher has to know to
	 * leave alone, and one of them would silently narrow a rule to
	 * submissions of a particular length for reasons having nothing to do
	 * with what the rule is about.
	 *
	 * What WOULD be meaningful here is a bound on the CONTENT - "a script
	 * block at least this long" is a real claim about a sample. There is no
	 * precondition for it yet, and inventing one the host does not check
	 * would be worse than not having it.
	 *
	 * THE TEST IS THE OBJECT, NOT THE FILE - the same correction bar_shown
	 * needed. A PE carried inside a submission is an executable: it has an
	 * architecture, a subtype and a size that all mean what they say, and
	 * refusing them because of the container it arrived in leaves the one
	 * object a reader most wants to write a rule about as the one they
	 * cannot state anything about.
	 */
	if (v->log && !v->pe_of[v->node[v->sel_node].obj])
		return 0;
	if (k == OPT_ARCH)
		return exe && cur_obj(v)->ctx.arch != 0;
	/*
	 * SUBTYPE IS NOT AN EXECUTABLE'S ALONE, and gating it on `exe` was a
	 * rule written when it was: a script's kind - PHP, ASP, JSP - is a
	 * subtype the engine parses, prefilters on and the generator writes, so
	 * the one format whose rules most need it was the one that could not
	 * add it. Rules written from this panel went out targeting every
	 * script there is, and the subtype had to be typed into the file by
	 * hand afterwards.
	 *
	 * The test that was already here answers it for any format: a name
	 * exists exactly when this object's subtype is one the vocabulary
	 * knows, which is what "can this rule say it" means.
	 */
	if (k == OPT_SUBTYPE)
		return kof_inspect_subtype_name(fm,
						cur_obj(v)->ctx.subtype) != NULL;
	return 1;                       /* the two sizes always apply */
}

/*
 * `row` IS THE CONTROL'S OWN ROW - g_my, and nothing arithmetic on it.
 *
 * The list is placed at row + 1, under the control, for the reasons written
 * where that is done. It did not always open downwards, and while it opened
 * UPWARDS five callers subtracted 2 or 3 to push it clear of the rows above
 * them. Those subtractions outlived the change and then pointed the wrong way:
 * a similarity matcher is two rows, so [+ Similarity] on its second row opened
 * its list at g_my - 2, one row ABOVE the matcher's own heading - the list was
 * drawn over the title of the thing it was adding to.
 *
 * Twenty-two callers pass g_my and five did not, two of them beside a sibling
 * in the same function that does. So the rule is here, in one place: hand this
 * the row that was clicked, and let it decide where the list goes.
 */
void ch_open(struct view *v, int what, uint32_t arg, int row, int col)
{
	struct chooser *c = &v->ch;
	uint32_t i;

	memset(c, 0, sizeof *c);
	c->what = what;
	c->arg = arg;

	if (what == CH_ATOFF) {
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
	} else if (what == CH_RULE) {
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
	} else if (what == CH_RANGE) {
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
	} else if (what == CH_RANGE2) {
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
			return;
		cur  = rm[arg];
		have = rng_object_regions(v);
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
			return;
	} else if (what == CH_RANGE_ADD) {
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
		uint32_t have = rng_object_regions(v), b;
		char t[CH_W];

		for (b = 0; b < 32u; b++) {
			if (!(have & (1u << b)))
				continue;
			rng_name_of(cur_obj(v)->fmt, 1u << b, t, sizeof t);
			ch_add(c, t);
		}
		ch_add(c, "WHOLE-FILE");
	} else if (what == CH_RANGE_EXT || what == CH_RANGE_DROP) {
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
		uint32_t set = what == CH_RANGE_EXT
			     ? (rng_object_regions(v) & ~arg) : arg;
		char t[CH_W];
		uint32_t b;

		for (b = 0; b < 32u; b++) {
			if (!(set & (1u << b)))
				continue;
			rng_name_of(cur_obj(v)->fmt, 1u << b, t, sizeof t);
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else if (what == CH_TYPE) {
		for (i = 0; i < MALTYPE_N; i++)
			ch_add(c, maltype_word[i]);
	} else if (what == CH_MARKER) {
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
			return;
	} else if (what == CH_CMATCH) {
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
			return;
	} else if (what == CH_CMATCH2) {
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
			return;
		cc = &v->ed.dr.cnd[ci];
		if (!cnd_uses(&v->ed, cc, m))
			return;
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
		 * out - see opt_offerable for why that matters.
		 */
		for (i = 0; i < v->ed.dr.n_grp; i++)
			if (cmatch_ok(v, ci, i))
				break;
		if (i < v->ed.dr.n_grp)
			ch_add_verb_sub(c, "Switch to another matcher", 1);
		snprintf(t, sizeof t, "Remove matcher %u", grp_loc(&v->ed, m));
		ch_add_verb(c, t, 2);
	} else if (what == CH_CSWAP) {
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
			return;
		for (i = 0; i < v->ed.dr.n_grp; i++) {
			if (!cmatch_ok(v, ci, i))
				continue;
			grp_label(&v->ed, i, t, sizeof t);
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else if (what == CH_FMT) {
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
			if (fmt_cat_langs(ci) ||
			    (fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
				ch_add_verb_sub(c, fmt_cat_name(ci), 0);
		/* Last, and the one row that acts rather than opening a list. */
		ch_add(c, "Remove this format");
	} else if (what == CH_FMT_SW) {
		/* One kind's formats, minus what the draft already targets. */
		uint8_t f;
		uint32_t have = fmt_cat_mask(FMT_SW_CAT(arg)) &
				~v->ed.dr.fmt_mask;

		for (f = 0; f < KOF_FMT_COUNT; f++)
			if (have & (1u << f))
				ch_add(c, kof_format_name(f));
	} else if (what == CH_FMT_SW_LANG) {
		/*
		 * AND FOR SCRIPTS THE CHOICE IS A LANGUAGE, so what the switch
		 * list leaves out is the LANGUAGE in use, not the format.
		 * Masking with ~fmt_mask would hide the whole Scripts row the
		 * moment a draft targeted a script - which is exactly when the
		 * reader wants to change which script it is.
		 */
		uint32_t k, skip = fmt_lang_skip(v);

		for (k = 0; k < script_sub_n; k++) {
			if (k == skip)
				continue;
			ch_add(c, k == 0 ? "Any language" : script_sub[k]);
		}
	} else if (what == CH_FMT_CAT) {
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
			if (fmt_cat_langs(ci) ||
			    (fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
				/* Each opens a list rather than acting, so
				 * each carries the menu bar's ">" - see
				 * chooser.sub. */
				ch_add_verb_sub(c, fmt_cat_name(ci), 0);
	} else if (what == CH_FMT_LANG) {
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
	} else if (what == CH_FMT_ADD) {
		/* One kind's formats, and only what is not already there: a
		 * list that offers what it will refuse lies about itself. */
		uint32_t have = fmt_cat_mask(arg) & ~v->ed.dr.fmt_mask;
		uint8_t f;

		for (f = 0; f < KOF_FMT_COUNT; f++)
			if (have & (1u << f))
				ch_add(c, kof_format_name(f));
	} else if (what == CH_ENC_TYPE) {
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
	} else if (what == CH_OPT) {
		/* Only the ones this object can answer for, and only the ones
		 * not already there: a list that offers what it will refuse is
		 * a list that lies about itself. */
		if (opt_offerable(v, OPT_SIZE_MIN))
			ch_add(c, opt_word[OPT_SIZE_MIN]);
		if (opt_offerable(v, OPT_SIZE_MAX))
			ch_add(c, opt_word[OPT_SIZE_MAX]);
		/* Which of these two the object can answer for is decided in
		 * opt_offerable, for this list and for the taker both. */
		if (opt_offerable(v, OPT_ARCH))
			ch_add(c, opt_word[OPT_ARCH]);
		if (opt_offerable(v, OPT_SUBTYPE))
			ch_add(c, opt_word[OPT_SUBTYPE]);
		if (!c->n)
			return;
	} else if (what == CH_ARCH) {
		for (i = 0; i < ARCH_N; i++)
			ch_add(c, arch_word[i].word);
	} else if (what == CH_SUBTYPE) {
		uint8_t fmt = cur_obj(v)->ctx.format;

		if (fmt == KOF_FMT_ELF)
			for (i = 0; i < elf_sub_n; i++)
				ch_add(c, elf_sub[i]);
		else if (fmt == KOF_FMT_PE)
			for (i = 0; i < pe_sub_n; i++)
				ch_add(c, pe_sub[i]);
		if (!c->n)
			return;
	} else if (what == CH_DECLKIND) {
		/*
		 * WHAT THE ROW AT THE FOOT OF THE STRINGS TABLE ADDS.
		 *
		 * Plain text first because it is what a reader reaches for
		 * most, then the two that are written as a pattern.
		 */
		ch_add(c, "String");
		ch_add(c, "Hex");
		ch_add(c, "Regex");
	} else if (what == CH_ATTR) {
		/* Seeded from the declaration, which is the last thing that
		 * wrote it - so a list reopened after an Apply comes up on
		 * what was applied. */
		const struct decl *d = arg < v->ed.dr.n_decl
				     ? &v->ed.dr.decl[arg] : NULL;

		c->pend_icase = d ? d->icase != 0 : 0;
		c->pend_word = d ? d->fullword : KOF_WORD_SUBSTRING;
		ch_attr_items(c);
	} else if (what == CH_THRESH) {
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
			return;
	} else {
		return;
	}

	/*
	 * BESIDE WHAT WAS CLICKED, never on top of it, and BELOW IT FIRST.
	 *
	 * A list that covers its own control hides the thing being changed, and
	 * the click that would dismiss it lands on the list instead - so the
	 * next click goes into closing rather than doing, and the control below
	 * looks broken. That much has always been the rule; the direction was
	 * up, and up is where a panel keeps the heading that says what section
	 * the control belongs to. Opening [+ Matcher] painted the list straight
	 * over "Matchers" and the rows under it - the reader lost sight of what
	 * they were adding to at the moment of adding to it.
	 *
	 * So: the row under the control, which is where a list belongs and
	 * where the eye already is. Above only when the list does not fit
	 * below, which is the case the screen bottom forces.
	 */
	c->open = 1;
	c->row = row + 1;
	if (c->row + c->n - 1 > g_rows - 1)
		c->row = row - c->n;
	if (c->row + c->n - 1 > g_rows - 1)
		c->row = g_rows - c->n;
	if (c->row < 1)
		c->row = 1;
	/*
	 * Wide enough for the longest row and no wider. A row is drawn as a
	 * leading space, the text, then either two columns of padding or one
	 * plus the submenu ">" - so the text field is w - 2, or w - 3 when
	 * any row in the list opens another.
	 */
	{
		int wi, longest = 0, any_sub = 0;

		for (wi = 0; wi < c->n; wi++) {
			int l = (int)strlen(c->item[wi]);

			if (l > longest)
				longest = l;
			if (c->sub[wi])
				any_sub = 1;
		}
		c->w = longest + (any_sub ? 4 : 3);
		if (c->w < CH_W_MIN)
			c->w = CH_W_MIN;
		if (c->w > CH_W)
			c->w = CH_W;
		if (c->w > g_cols - 2)
			c->w = g_cols - 2;
	}

	c->col = col;
	if (c->col + c->w > g_cols)
		c->col = g_cols - c->w;
	if (c->col < 1)
		c->col = 1;

	/*
	 * NO ROW IS THE CURSOR YET, and that is the whole of it.
	 *
	 * The list opened on row zero highlighted, which claims something the
	 * reader has not done: they pressed a control to SEE the choices, not
	 * to hover the first one. Worse on a submenu - the highlight jumped off
	 * the category they had just clicked and onto a row of the list it
	 * opened, so the thing they chose stopped looking chosen.
	 *
	 * -1 is "the keyboard is not here". An arrow key brings it to row zero;
	 * a click names its own row and never consults this.
	 */
	c->sel = -1;
}




/*
 * AN OFFSET IS A FACT ABOUT ONE LAYOUT, so say so when the draft has two.
 *
 * kof_find_str_at names a raw file offset and consults no region - see
 * c_find_str_at, which reaches straight for the object's bytes. That is exactly
 * right for "the stub at the entry point of an ELF" and meaningless the moment
 * the same rule also targets a bash script: byte 0x400 of a script is wherever
 * the author happened to stop typing.
 *
 * A NOTE AND NOT A REFUSAL. There are rules where it is deliberate - two
 * formats that genuinely share a header - and deciding which is which is the
 * researcher's job, not this panel's. What the panel owes them is that the
 * question was asked.
 *
 * Said when the situation is CREATED - a second format added, or a matcher
 * switched to at - because that is the moment the author can still mean
 * something else by it.
 */
/* Does this format define every region bit in the mask - see the note below on
 * why "no" and "called something else" are different answers. The symbol halves
 * belong to no format and are always known; see rng_name_of. */
static int rgn_bits_known(const struct kof_parser *p, uint32_t mask)
{
	uint32_t b, k;

	mask &= ~(uint32_t)KOF_SCAN_SYM;
	for (b = 0; b < 30u; b++) {
		int found = 0;

		if (!(mask & (1u << b)))
			continue;
		if (p)
			for (k = 0; k < p->n_regions; k++)
				found |= p->regions[k] == (1u << b);
		if (!found)
			return 0;
	}
	return 1;
}

static void at_warn_if_multi(struct view *v)
{
	uint32_t m = v->ed.dr.fmt_mask, g;
	int n_fmt = 0;

	for (; m; m >>= 1)
		n_fmt += (int)(m & 1u);
	if (n_fmt < 2)
		return;

	/*
	 * DO THE REGIONS STILL MEAN THE SAME THING - the louder of the two.
	 *
	 * The region axis is ONE bit space shared by every format, and that is
	 * what makes a signature over PE and ELF work at all: bit 1 is HEADERS
	 * in both, bit 2 CODE, bit 3 DATA, each format resolving it to its own
	 * extents. A rule about a cross-platform build is written once against
	 * those bits and is right in both.
	 *
	 * The correspondence STOPS AFTER BIT 3, and it stops silently. Bit 5 is
	 * UNCLAIMED in an ELF and OVERLAY in a PE; bit 4 is NOLOAD, SIGNATURE,
	 * PACKED or CONTENT depending on who is asked. Such a matcher does not
	 * fail to fire - it searches a DIFFERENT REAL REGION, which is the one
	 * answer worth interrupting for. So the names are compared rather than
	 * the bits, because the name is the thing the author meant.
	 */
	for (g = 0; g < v->ed.dr.n_grp; g++) {
		char first[64] = "", other[64];
		uint32_t want = grp_mask(&v->ed, g);
		uint8_t ff = 0, f;

		if (!grp_has_range(&v->ed, g) || (want & KOF_SCAN_ALL))
			continue;
		for (f = 0; f < KOF_FMT_COUNT; f++) {
			if (!(v->ed.dr.fmt_mask & (1u << f)))
				continue;
			/*
			 * ABSENT IS NOT THE SAME AS NAMED DIFFERENTLY, and
			 * rng_name_of cannot tell them apart: a bit the format
			 * does not define is skipped, and a mask that named
			 * nothing falls out of it as "WHOLE-FILE". Reported
			 * from that string alone this would have said a
			 * matcher searches the whole file where it in fact
			 * searches NOTHING - kof_scan_resolve_range returns no
			 * extents - which is the opposite mistake.
			 */
			if (!rgn_bits_known(kof_parser_of(f), want)) {
				say_err(&v->ed,
					"matcher %u searches nothing in %s - "
					"that format has no such region",
					grp_loc(&v->ed, g), kof_format_name(f));
				return;
			}
			rng_name_of(kof_parser_of(f), want, other,
				    sizeof other);
			if (!first[0]) {
				snprintf(first, sizeof first, "%s", other);
				ff = f;
				continue;
			}
			if (strcmp(first, other)) {
				say_err(&v->ed,
					"matcher %u: that region is %s in %s "
					"and %s in %s", grp_loc(&v->ed, g),
					first,
					kof_format_name(ff), other,
					kof_format_name(f));
				return;
			}
		}
	}

	for (g = 0; g < v->ed.dr.n_grp; g++)
		if (grp_is_at(v->ed.dr.grp[g].rule)) {
			say_note(&v->ed,
				 "find_at is one offset - it means a "
				 "different place in each of %d formats",
				 n_fmt);
			return;
		}
}

/* Which regions the object HAS, as a mask - what a range may be built from. */
static uint32_t rng_object_regions(struct view *v)
{
	uint32_t m = 0, k;

	for (k = 0; k < v->n_node; k++)
		if (v->node[k].obj == v->node[v->sel_node].obj && v->node[k].mask)
			m |= v->node[k].mask;
	return m;
}




/* What picking the highlighted item does. */
/*
 * WHICH RULE A ROW OF THE KIND MENU MEANS.
 *
 * The menu used to be the rule list itself - row 0 was find_all, row 1
 * find_any, row 2 find_multi - so the row index WAS the value and two places
 * wrote `q->rule = c->sel`. The three searches are one row now, and the number
 * chooses between them afterwards, so the two are no longer the same thing and
 * the mapping is stated once.
 *
 * A new find_str starts as "every one of them": it is the strictest reading,
 * it is what a matcher with one marker in it means either way, and it FOLLOWS
 * the markers - adding another tightens the rule rather than leaving a number
 * behind. See grp_thresh_eff, which answers `count` for it.
 */
static int ch_rule_of_row(int row)
{
	return row == 1 ? 3 : 0;        /* find_at, else find_str */
}

static int64_t at_anchor_val(uint8_t anchor, uint64_t entry, uint64_t size)
{
	if (anchor == KOF_ANCHOR_ENTRY)
		return (entry == KGENOME_NA || entry == KGENOME_BROKEN)
		     ? AT_NO_ANCHOR : (int64_t)entry;
	if (anchor == KOF_ANCHOR_EOF)
		return (int64_t)size;
	return 0;                       /* bof */
}

/*
 * Keep the highlighted row inside the visible window.
 *
 * Called wherever `sel` moves. Without it an arrow key walks the cursor off
 * the end of the drawn rows and the list stops responding to the eye - the
 * same failure as a pane whose cursor scrolls and whose view does not.
 */
void ch_follow(struct chooser *c)
{
	int vis = ch_vis(c);

	if (c->sel < 0 || c->n <= vis) {
		c->off = 0;
		return;
	}
	if (c->sel < c->off)
		c->off = c->sel;
	else if (c->sel >= c->off + vis)
		c->off = c->sel - vis + 1;
	if (c->off > c->n - vis)
		c->off = c->n - vis;
	if (c->off < 0)
		c->off = 0;
}

void ch_take(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q;

	c->open = 0;
	v->ch_up.open = 0;
	if (c->what == CH_TYPE) {
		v->ed.dr.maltype = (uint32_t)c->sel;
		return;
	}
	if (c->what == CH_FMT_CAT) {
		/* The nth kind that still has something to offer - the same
		 * walk that built the list. Picking one opens its formats
		 * beside it, the way every other two-level menu here does. */
		uint32_t ci, n = 0;
		struct chooser up = *c;

		for (ci = 0; ci <= FMT_CAT_N; ci++) {
			if (!fmt_cat_langs(ci) &&
			    !(fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
				continue;
			if ((int)n == c->sel) {
				up.open = 1;
				ch_open(v, fmt_cat_langs(ci) ? CH_FMT_LANG
							     : CH_FMT_ADD, ci,
					up.row + up.sel + 1, up.col + up.w);
				v->ch_up = up;
				return;
			}
			n++;
		}
		return;
	}
	if (c->what == CH_FMT_LANG) {
		/*
		 * The format and the language in one act - see the note where
		 * the list is built.
		 */
		if (c->sel >= 0 && (uint32_t)c->sel < script_sub_n) {
			v->ed.dr.fmt_mask |= 1u << KOF_FMT_SCRIPT;
			if (c->sel == 0) {
				v->ed.dr.opt_on[OPT_SUBTYPE] = 0;
				v->ed.dr.opt_val[OPT_SUBTYPE] = 0;
			} else {
				v->ed.dr.opt_on[OPT_SUBTYPE] = 1;
				v->ed.dr.opt_val[OPT_SUBTYPE] =
					(uint32_t)c->sel;
			}
			/* Same reason as the format taker below: adding one
			 * can make the target set ambiguous for an offset. */
			at_warn_if_multi(v);
		}
		return;
	}
	if (c->what == CH_FMT) {
		/*
		 * The nth kind the list offered, walked again rather than
		 * remembered so the two cannot disagree - and past them, the
		 * Remove row.
		 */
		uint32_t ci, n = 0;
		struct chooser up = *c;

		for (ci = 0; ci <= FMT_CAT_N; ci++) {
			if (!fmt_cat_langs(ci) &&
			    !(fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
				continue;
			if ((int)n == c->sel) {
				up.open = 1;
				ch_open(v, fmt_cat_langs(ci) ? CH_FMT_SW_LANG
							     : CH_FMT_SW,
					FMT_SW_PACK(ci, c->arg),
					up.row + up.sel + 1, up.col + up.w);
				v->ch_up = up;
				return;
			}
			n++;
		}
		/*
		 * Past every kind is the Remove row, and it is TESTED for
		 * rather than fallen into: a row added after it some day would
		 * otherwise quietly start removing the format instead.
		 */
		if (c->sel == c->n - 1) {
			uint64_t fm = v->ed.dr.fmt_mask;

			if (fm && !(fm & (fm - 1u)))
				say_note(&v->ed, "A rule needs at least one format");
			else
				fmt_swap(v, c->arg, KOF_FMT_COUNT);
		}
		return;
	}
	if (c->what == CH_FMT_SW) {
		uint8_t f, n = 0, pick = KOF_FMT_COUNT;
		uint32_t pool = fmt_cat_mask(FMT_SW_CAT(c->arg)) &
				~v->ed.dr.fmt_mask;

		for (f = 0; f < KOF_FMT_COUNT; f++)
			if (pool & (1u << f)) {
				if ((int)n == c->sel)
					pick = f;
				n++;
			}
		if (pick < KOF_FMT_COUNT)
			fmt_swap(v, FMT_SW_WHICH(c->arg), pick);
		return;
	}
	if (c->what == CH_FMT_SW_LANG) {
		/*
		 * A SCRIPT AND ITS LANGUAGE, in place of whatever was clicked.
		 * The same walk the list was built with, minus the language
		 * already in use - see fmt_lang_skip.
		 */
		uint32_t k, n = 0, skip = fmt_lang_skip(v), pick = script_sub_n;

		for (k = 0; k < script_sub_n; k++) {
			if (k == skip)
				continue;
			if ((int)n == c->sel) {
				pick = k;
				break;
			}
			n++;
		}
		if (pick >= script_sub_n)
			return;
		fmt_swap(v, FMT_SW_WHICH(c->arg), KOF_FMT_SCRIPT);
		if (pick == 0) {
			v->ed.dr.opt_on[OPT_SUBTYPE] = 0;
			v->ed.dr.opt_val[OPT_SUBTYPE] = 0;
		} else {
			v->ed.dr.opt_on[OPT_SUBTYPE] = 1;
			v->ed.dr.opt_val[OPT_SUBTYPE] = pick;
		}
		return;
	}
	if (c->what == CH_FMT_ADD) {
		uint8_t f, n = 0, pick = KOF_FMT_COUNT;
		uint32_t pool = fmt_cat_mask(c->arg) & ~v->ed.dr.fmt_mask;

		/* The nth format the list offered, walked again rather than
		 * remembered so the two cannot disagree. */
		for (f = 0; f < KOF_FMT_COUNT; f++)
			if (pool & (1u << f)) {
				if ((int)n == c->sel)
					pick = f;
				n++;
			}
		if (pick < KOF_FMT_COUNT)
			v->ed.dr.fmt_mask |= 1u << pick;
		/* Only here: a SWITCH leaves the count alone, and the count is
		 * what makes an offset ambiguous. */
		at_warn_if_multi(v);
		return;
	}
	if (c->what == CH_ENC_TYPE) {
		if (c->sel >= 0 && c->sel < KOF_CODEC_COUNT)
			v->enc_type = (uint32_t)c->sel;
		/* The result belonged to the coding that produced it. */
		v->enc_res_n = 0;
		v->enc_done = 0;
		/*
		 * AND THE CARET GOES WHERE THE READER WILL TYPE NEXT.
		 *
		 * Picking from the chooser goes through the general click path,
		 * which clears the focus on the way past - "any click leaves
		 * whatever was being typed". So after choosing a coding there
		 * was no field with the caret at all, and the next Tab moved to
		 * the input rather than to the key: choosing caesar and typing
		 * the shift put the shift into the encoded text.
		 *
		 * A coding with a key wants the key next; one without wants the
		 * text. Saying so here is also the answer to "what did picking
		 * this actually do", which a blank caret does not give.
		 */
		if (kof_codec_keyed(v->enc_type)) {
			v->edit = ED_ENC_KEY;
			v->caret = (uint32_t)strlen(v->enc_key);
		} else {
			v->edit = ED_ENC_IN;
			v->caret = (uint32_t)strlen(v->enc_in);
		}
		return;
	}
	if (c->what == CH_ARCH) {
		v->ed.dr.opt_val[OPT_ARCH] = arch_word[(size_t)c->sel % ARCH_N].val;
		return;
	}
	if (c->what == CH_SUBTYPE) {
		v->ed.dr.opt_val[OPT_SUBTYPE] = (uint32_t)c->sel;
		return;
	}
	if (c->what == CH_OPT) {
		struct object *ob = cur_obj(v);
		int seen = 0, k;

		for (k = 0; k < OPT_COUNT; k++) {
			/*
			 * THE SAME QUESTION THE LIST ASKED - see opt_offerable.
			 *
			 * These skips used to be written out again here, and the
			 * two spellings disagreed on the commonest object there
			 * is: the list offers "File subtype" when the format has
			 * a NAME for the object's subtype, and KGENOME_PE_EXE is
			 * zero with the name "EXE", while this loop skipped any
			 * subtype that was zero. So on an ordinary PE the row
			 * was offered, picked, and silently did nothing.
			 */
			if (!opt_offerable(v, k))
				continue;
			if (seen++ != c->sel)
				continue;
			v->ed.dr.opt_on[k] = 1;
			/* Chosen from the menu, so it is the draft's from
			 * here on - see kof_draft.opt_auto. */
			v->ed.dr.opt_auto[k] = 0;
			v->ed.dr.opt_val[k] = k == OPT_SIZE_MIN ? ob->buf.n :
					k == OPT_SIZE_MAX ? ob->buf.n * 2u :
					k == OPT_ARCH ? ob->ctx.arch
						      : ob->ctx.subtype;
			break;
		}
		return;
	}
	if (c->what == CH_DECLKIND) {
		struct decl *d;

		if (v->ed.dr.n_decl >= MAX_DECL)
			return;
		/*
		 * NOT WIRED YET, AND SAID RATHER THAN DONE QUIETLY - see
		 * DECL_RX. The row is offered because it is the menu this panel
		 * is meant to have; what is behind it is written later.
		 */
		if (c->sel == 2) {
			say_note(&v->ed, "Regex is not wired yet");
			return;
		}
		/*
		 * `at` is KGENOME_BROKEN - the bytes are not in this object and may
		 * never be. That is a state struct decl already has, for a
		 * marker carried from another sample, and the table draws it as
		 * "not here" rather than as an error.
		 */
		d = &v->ed.dr.decl[v->ed.dr.n_decl];
		memset(d, 0, sizeof *d);
		d->obj = v->ed.cur;
		d->at = KGENOME_BROKEN;
		d->fullword = KOF_WORD_SUBSTRING;
		d->hex = c->sel == 1 ? DECL_HEX : DECL_STR;
		snprintf(d->rgn, sizeof d->rgn, "-");
		v->ed.dr.sel_decl = v->ed.dr.n_decl;
		v->ed.dr.n_decl++;
		decl_edit_open(v, v->ed.dr.n_decl - 1u);
		return;
	}
	if (c->what == CH_ATTR) {
		struct decl *d = c->arg < v->ed.dr.n_decl
			       ? &v->ed.dr.decl[c->arg] : NULL;

		if (!d)
			return;
		if (c->sel == CH_ATTR_APPLY) {
			/* The one row that writes, and the list is already
			 * closed - ch_take shut it on the way in. */
			d->icase = c->pend_icase;
			d->fullword = c->pend_word;
			decl_locate(&v->ed, d);   /* the hit list depends on both */
			return;
		}
		switch (c->sel) {
		case CH_ATTR_ICASE:    c->pend_icase = !c->pend_icase; break;
		case CH_ATTR_TOKEN:    c->pend_word = KOF_WORD_TOKEN; break;
		case CH_ATTR_FULLWORD: c->pend_word = KOF_WORD_FULLWORD; break;
		case CH_ATTR_PATTERN:  c->pend_word = KOF_WORD_SUBSTRING; break;
		default:               return;   /* a rule, or nothing */
		}
		/*
		 * STILL OPEN, and on the row that was just pressed.
		 *
		 * The cell holds two independent facts, so one visit has to be
		 * able to set both - a list that closed on the first press
		 * would let a visit change half the cell, which is what the
		 * two separate columns already did. ch_take closed it at the
		 * top; this is the row saying it is not finished.
		 */
		ch_attr_items(c);
		c->open = 1;
		return;
	}
	if (c->what == CH_RULE && c->arg == MAX_GROUP) {
		/* A new condition: the rule is chosen before there is anything
		 * in it, which is the order somebody thinks in. */
		grp_add(&v->ed);
		if (!v->ed.dr.n_grp)
			return;
		q = &v->ed.dr.grp[v->ed.dr.n_grp - 1u];
		/* Through ch_rule_of_row rather than writing c->sel into
		 * `rule`: this used to do that, and the row number is not the
		 * rule. */
		q->rule = ch_rule_of_row(c->sel);
		/* Nothing in it yet, so there is no marker to seed from - the
		 * offset arrives with the first one. See grp_seed_at. */
		return;
	}
	if (c->what == CH_RANGE2) {
		/*
		 * One range is the subject, and c->arg2 holds its mask - put
		 * there when the menu was built, so the taker cannot disagree
		 * with the row about which range was pressed even if the draft
		 * changed shape in between.
		 */
		uint32_t cur = c->arg2, rest = rng_object_regions(v) & ~cur;
		int verb = (c->sel >= 0 && c->sel < c->n)
			 ? (int)c->verb[c->sel] : 2;
		uint32_t b, rb = 0;

		for (b = 0; b < 32u; b++)
			rb += (rest >> b) & 1u;

		if (verb == 0) {                /* extend */
			if (rb == 1u) {
				rng_retarget(&v->ed, cur, cur | rest);
				say_note(&v->ed, "%s", "Scan range extended");
			} else if (rb > 1u) {
				struct chooser up = *c;

				up.open = 1;
				ch_open(v, CH_RANGE_EXT, cur,
					up.row + up.sel + 1, up.col + up.w);
				v->ch_up = up;
			}
			return;
		}
		if (verb == 1) {                /* drop one region */
			struct chooser up = *c;

			up.open = 1;
			ch_open(v, CH_RANGE_DROP, cur,
				up.row + up.sel + 1, up.col + up.w);
			v->ch_up = up;
			return;
		}
		/* verb 2: remove the whole range, matcher and all. */
		{
			uint32_t dm[2u * MAX_GROUP];
			int du[2u * MAX_GROUP];
			uint32_t dn = rng_removable(&v->ed, dm, du, 2u * MAX_GROUP), i;

			for (i = 0; i < dn; i++)
				if (dm[i] == cur) {
					rng_delete(&v->ed, cur, du[i]);
					return;
				}
			/* Not in the removable list means a matcher searches it
			 * and rng_delete's own walk will take that matcher; ask
			 * it directly rather than refusing. */
			rng_delete(&v->ed, cur, 0);
		}
		return;
	}
	if (c->what == CH_RANGE_ADD) {
		uint32_t have = rng_object_regions(v), b, n = 0, pick = 0;

		for (b = 0; b < 32u; b++) {
			if (!(have & (1u << b)))
				continue;
			if ((int)n++ == c->sel) {
				pick = 1u << b;
				break;
			}
		}
		/* Past the last region is the WHOLE-FILE row. */
		rng_apply(&v->ed, 2, 0, pick ? pick : KOF_SCAN_ALL);
		return;
	}
	if (c->what == CH_RANGE_EXT || c->what == CH_RANGE_DROP) {
		uint32_t cur = c->arg;          /* the same field the build read */
		uint32_t set = c->what == CH_RANGE_EXT
			     ? (rng_object_regions(v) & ~cur) : cur;
		uint32_t b, n = 0, pick = 0;

		for (b = 0; b < 32u; b++) {
			if (!(set & (1u << b)))
				continue;
			if ((int)n++ == c->sel) {
				pick = 1u << b;
				break;
			}
		}
		if (!pick)
			return;
		if (c->what == CH_RANGE_EXT) {
			rng_retarget(&v->ed, cur, cur | pick);
			say_note(&v->ed, "%s", "Scan range extended");
		} else {
			/*
			 * Narrowed, not removed: the range keeps every region
			 * but this one. Taking the LAST region away would leave
			 * a matcher searching nothing, which is what Remove is
			 * for - so it is refused here rather than silently
			 * producing one.
			 */
			if ((cur & ~pick) == 0) {
				say_err(&v->ed, "%s", "That is the range's only "
					"region - remove the range instead");
				return;
			}
			rng_retarget(&v->ed, cur, cur & ~pick);
			say_note(&v->ed, "%s", "Region dropped from the scan range");
		}
		return;
	}
	if (c->what == CH_CMATCH) {
		struct cond *cc;
		uint32_t i, n = 0;

		if (c->arg >= v->ed.dr.n_cnd)
			return;
		cc = &v->ed.dr.cnd[c->arg];
		for (i = 0; i < v->ed.dr.n_grp; i++) {
			size_t l;

			if (!cmatch_ok(v, c->arg, i))
				continue;
			if ((int)n++ != c->sel)
				continue;
			/*
			 * Appended with & rather than replacing the text: the
			 * expression is the author's, and a second matcher
			 * usually narrows a condition. Anything else - an |, a
			 * parenthesis - is still typed into the box, which is
			 * why the box stays.
			 */
			l = strlen(cc->expr);
			snprintf(cc->expr + l, sizeof cc->expr - l, "%s%u",
				 l ? (cc->op ? "|" : "&") : "",
				 grp_loc(&v->ed, i));
			break;
		}
		return;
	}
	if (c->what == CH_CMATCH2) {
		uint32_t ci = CH_PAIR_C(c->arg), m = CH_PAIR_M(c->arg);
		/*
		 * The verb is carried on the row, not read off c->sel: "Switch"
		 * is offered only while there is somewhere to switch to, so a
		 * fixed row number would carry out Remove whenever it was not.
		 */
		int verb = (c->sel >= 0 && c->sel < c->n)
			 ? (int)c->verb[c->sel] : 2;

		if (ci >= v->ed.dr.n_cnd || m >= v->ed.dr.n_grp)
			return;
		if (verb == 0) {
			cnd_negate_matcher(&v->ed, &v->ed.dr.cnd[ci], m);
			return;
		}
		if (verb == 1) {
			struct chooser up = *c;

			up.open = 1;
			ch_open(v, CH_CSWAP, c->arg,
				up.row + up.sel + 1, up.col + up.w);
			v->ch_up = up;
			return;
		}
		cnd_drop_matcher(&v->ed, &v->ed.dr.cnd[ci], m);
		return;
	}
	if (c->what == CH_CSWAP) {
		uint32_t ci = CH_PAIR_C(c->arg), m = CH_PAIR_M(c->arg);
		uint32_t i, n = 0;

		if (ci >= v->ed.dr.n_cnd || m >= v->ed.dr.n_grp)
			return;
		/* The same walk the list was built from, so row N names the
		 * matcher printed on row N even if the draft changed shape
		 * while the menu was open. */
		for (i = 0; i < v->ed.dr.n_grp; i++) {
			if (!cmatch_ok(v, ci, i))
				continue;
			if ((int)n++ != c->sel)
				continue;
			cnd_swap_matcher(&v->ed, ci, m, i);
			break;
		}
		return;
	}
	if (c->arg >= v->ed.dr.n_grp)
		return;
	q = &v->ed.dr.grp[c->arg];

	if (c->what == CH_MARKER) {
		uint32_t i, n = 0;

		for (i = 0; i < v->ed.dr.n_decl; i++) {
			if (v->ed.dr.decl[i].grp & (1u << c->arg))
				continue;
			if (!rng_holds(grp_mask(&v->ed, c->arg), v->ed.dr.decl[i].mask))
				continue;
			if ((int)n++ != c->sel)
				continue;
			v->ed.dr.decl[i].grp |= 1u << c->arg;
			/* An AT matcher built rule-first has no offset until it
			 * has a marker; this is when it gets one. */
			if (grp_is_at(v->ed.dr.grp[c->arg].rule))
				grp_seed_at(&v->ed, c->arg);
			break;
		}
	} else if (c->what == CH_THRESH) {
		/* The list starts at 1 - see CH_THRESH where it is built. */
		uint32_t want = (uint32_t)c->sel + 1u;
		uint32_t n = grp_count(&v->ed, c->arg);

		/*
		 * THE NUMBER CHOOSES THE CALL BACK.
		 *
		 * This is the whole of the merge: one row in the kind menu, and
		 * the threshold decides which of the three the generator writes
		 * - so a rule still comes out as kof_find_str_all, _any or
		 * _multi, an old rule still reads back unchanged, and the
		 * short-circuit && and || give is kept exactly where it applies.
		 *
		 * `all` is a SENTINEL and not the number n: it follows the
		 * markers, so adding one keeps the rule meaning all of them.
		 */
		/*
		 * ONE MARKER IS "any", NOT "all", AND THE ORDER SAYS SO.
		 *
		 * With one marker the two calls test the same thing, so the
		 * choice is about what the generated source READS as -
		 * `kof_find_str_all(rng, s0)` is a plural about a single thing.
		 * The threshold menu offers exactly one row in that case, so
		 * nothing is being taken away from the author either: there is
		 * no second answer for this test to be overriding.
		 *
		 * It costs the sentinel in that one case. `all` follows the
		 * markers - adding one keeps the rule meaning all of them -
		 * and a group that went from one marker to two now reads ">=
		 * 1" instead of "all 2". That is the right way round: the
		 * author who adds a second marker is deciding something, and
		 * the panel shows them what the rule currently says rather
		 * than changing it under them.
		 */
		if (want <= 1u)
			q->rule = 1;            /* >= 1  -> find_any */
		else if (n && want >= n)
			q->rule = 0;            /* == n  -> find_all */
		else {
			q->rule = 2;            /* >= N  -> find_multi */
			q->thresh = want;
		}
	} else if (c->what == CH_ATOFF) {
		/*
		 * ONE ROW PER ANCHOR, so the row IS the anchor - see where
		 * the list is built. It used to walk the occurrence rows
		 * first to work out how many of them there were, which is
		 * what a list answering two questions costs its reader.
		 */
		uint64_t entry = cur_obj(v) ? cur_obj(v)->ctx.entry_off
					    : KGENOME_NA;
		uint64_t size = cur_obj(v) ? cur_obj(v)->ctx.obj_size : 0;
		int64_t base_old, base_new;

		if (c->sel < 0 || c->sel >= KOF_ANCHOR_COUNT)
			return;
		base_old = at_anchor_val(q->at_anchor, entry, size);
		base_new = at_anchor_val((uint8_t)c->sel, entry, size);
		/*
		 * AN ANCHOR THIS OBJECT DOES NOT HAVE CANNOT EXPRESS THE
		 * PLACE, so the move is refused rather than carried out
		 * against a sentinel. ctx->entry_off is KGENOME_NA for a format
		 * with no entry point and KGENOME_BROKEN when it could not be
		 * resolved.
		 */
		if (base_old == AT_NO_ANCHOR || base_new == AT_NO_ANCHOR) {
			say_note(&v->ed,
				 "This object has no %s to count from",
				 kof_anchor_word(c->sel));
			return;
		}
		/*
		 * THE PLACE IS PRESERVED AND THE STEP FOLLOWS IT - but only
		 * for a step the ENGINE put there. A number somebody typed is
		 * a step from the anchor it was typed against, and converting
		 * it would overrule what they wrote. See group.at_auto.
		 */
		if (q->at_auto)
			q->at_off = base_old + q->at_off - base_new;
		q->at_anchor = (uint8_t)c->sel;
		/* And the sign belongs to the new anchor - see
		 * grp_at_fix_sign. A no-op on the converted path; the
		 * correction that matters on the other one. */
		grp_at_fix_sign(q);
	} else if (c->what == CH_RULE) {
		q->rule = ch_rule_of_row(c->sel);
		/* Chosen now, from whatever marker the matcher already holds -
		 * see grp_seed_at. Switching away and back does not lose it,
		 * because it is only ever written here and by the offset menu. */
		if (grp_is_at(c->sel)) {
			grp_seed_at(&v->ed, c->arg);
			at_warn_if_multi(v);
		}
	} else if (c->what == CH_RANGE) {
		/*
		 * The same list the menu was built from, walked in the same
		 * order - see the note there. Past the last defined range is
		 * the WHOLE-FILE row.
		 */
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(&v->ed, rm, ru, 2u * MAX_GROUP);

		q->mask = (c->sel >= 0 && (uint32_t)c->sel < nr)
			? rm[c->sel] : KOF_SCAN_ALL;
		/* Choosing the region is the other moment the correspondence
		 * can break - see at_warn_if_multi. */
		at_warn_if_multi(v);
	}
}

/* How many rows of this list the screen has room for, from where it opened. */
int ch_vis(const struct chooser *c)
{
	int room = g_rows - c->row;     /* the status line stays uncovered */

	if (room < 1)
		room = 1;
	return room < c->n ? room : c->n;
}

static void draw_one_chooser(struct out *o, const struct chooser *c, int live)
{
	struct out_clip cl;
	int i, vis = ch_vis(c), off = c->off;

	/* Its own box: c->w columns from where it opened, and one row per
	 * VISIBLE item. Stated once here so the rows cannot be wrong about it
	 * one at a time. */
	if (off > c->n - vis)
		off = c->n - vis;
	if (off < 0)
		off = 0;
	cl = out_clip_set(o, c->row, c->col, c->row + vis - 1,
			  c->col + c->w - 1);

	for (i = off; i < off + vis; i++) {
		int y = c->row + i - off;

		out_at(o, y, c->col);
		/*
		 * SOMETHING ABOVE, SOMETHING BELOW - said on the row itself
		 * rather than in a scrollbar, because the list is three
		 * characters wider than its longest item and a bar would come
		 * out of the text. A reader who cannot see the end of a list
		 * has to be told there is one.
		 */
		if ((i == off && off > 0) ||
		    (i == off + vis - 1 && off + vis < c->n)) {
			out_str(o, BAR_ON);
			out_fmt(o, " %-*.*s", c->w - 3, c->w - 3, "...");
			out_str(o, i == c->sel ? BAR_CUR : BAR_ON);
			out_str(o, i == off ? "^" : "v");
			out_str(o, A_OFF);
			continue;
		}
		/*
		 * The parent keeps the cursor on the row whose list is open -
		 * the same thing the menu bar does with sel2, and the reason is
		 * the same: the row that was chosen has to go on looking
		 * chosen while its children are being read.
		 *
		 * A chooser with sel == -1 highlights nothing. See ch_open.
		 */
		(void)live;
		/*
		 * A separator is painted in the list's own colour and never
		 * in the cursor's, whatever c->sel happens to be: it is not a
		 * row anything can be on. The dashes stop one short of each
		 * edge so the rule reads as inside the box.
		 */
		if (c->sep[i]) {
			int k, w = c->w - 2;

			out_str(o, BAR_ON);
			out_str(o, " ");
			for (k = 0; k < w; k++)
				out_str(o, "-");
			out_str(o, " " A_OFF);
			continue;
		}
		out_str(o, i == c->sel ? BAR_CUR : BAR_ON);
		/* The ">" sits at the far edge, as the menu bar draws it. */
		if (c->sub[i])
			out_fmt(o, " %-*.*s>", c->w - 3, c->w - 3, c->item[i]);
		else
			out_fmt(o, " %-*.*s", c->w - 2, c->w - 2, c->item[i]);
		out_str(o, A_OFF);
	}
	out_clip_restore(o, cl);
}

void draw_chooser(struct out *o, struct view *v)
{
	if (!v->ch.open)
		return;
	if (v->ch_up.open)
		draw_one_chooser(o, &v->ch_up, 0);
	draw_one_chooser(o, &v->ch, 1);
}
