#define _GNU_SOURCE
#include "kv.h"
#include "kv_tags.h"
#include "kv_chooser_private.h"

/* The rows a chooser is made of, and the questions several kinds of list ask alike. */


_Static_assert(CH_ITEMS >= KV_FAM_MAX_VARIANT && CH_ITEMS >= KV_FAM_MAX_FAMILY &&
	       CH_ITEMS >= KV_TAG_MAX,
	       "a catalog outgrew the chooser: raise CH_ITEMS");
/* A chooser is shown as a pop-up whose rows are its items one for one (ch_popup): kv_popup_add refuses past KV_POP_MAX, so the list must fit. */
_Static_assert(CH_ITEMS <= KV_POP_MAX, "a chooser can hold more rows than a pop-up: raise KV_POP_MAX");

/* A row past CH_ITEMS is counted, not dropped unseen: ch_open names the number on the last row. */
void ch_add(struct chooser *c, const char *t)
{
	if (c->n < CH_ITEMS)
		snprintf(c->item[c->n++], CH_W, "%.*s", CH_W - 1, t);
	else
		c->more++;
}

/* The same, for a list whose rows are not all always there. */
void ch_add_verb(struct chooser *c, const char *t, unsigned verb)
{
	if (c->n < CH_ITEMS)
		c->verb[c->n] = (uint8_t)verb;
	ch_add(c, t);
}

/* A rule between two halves of one list - see chooser.sep. The text is never
 * drawn, so it only has to be something. */
void ch_add_sep(struct chooser *c)
{
	if (c->n < CH_ITEMS)
		c->sep[c->n] = 1;
	ch_add(c, "");
}

/* The same, for a row that OPENS A LIST rather than acting - drawn with the
 * menu bar's ">" marker. See chooser.sub. */
void ch_add_verb_sub(struct chooser *c, const char *t, unsigned verb)
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
void ch_attr_items(struct chooser *c)
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
uint32_t ch_fmt_cat_mask(uint32_t i)
{
	return i < FMT_CAT_N ? fmt_cat_of_group(g_fmt_cat[i].group)
			     : fmt_cat_other();
}

const char *ch_fmt_cat_name(uint32_t i)
{
	/* Plural like every row above it - the catch-all is a GROUP of formats
	 * and was the one row that read as a single thing. */
	return i < FMT_CAT_N ? kof_format_group_name(g_fmt_cat[i].group)
			     : "Others";
}

/* Does this row open a list of languages rather than of formats? */
int ch_fmt_cat_langs(uint32_t i)
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
uint32_t ch_fmt_lang_skip(const struct view *v)
{
	if (!(v->ed.dr.fmt_mask & (1u << KOF_FMT_SCRIPT)))
		return script_sub_n;
	/* opt_val is 64 bit because a size bound lives in the same array; a
	 * subtype is one of sixteen. */
	return v->ed.dr.opt_on[OPT_SUBTYPE]
	       ? (uint32_t)v->ed.dr.opt_val[OPT_SUBTYPE] : 0u;
}

/* Put one format in place of another, and say nothing when either is absent. */
void ch_fmt_swap(struct view *v, uint32_t which, uint8_t pick)
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

const uint32_t ch_fmt_cat_n = sizeof g_fmt_cat / sizeof g_fmt_cat[0];


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
int ch_opt_offerable(struct view *v, int k)
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

/* Which regions the object HAS, as a mask - what a range may be built from. */
uint32_t ch_rng_regions(struct view *v)
{
	uint32_t m = 0, k;

	for (k = 0; k < v->n_node; k++)
		if (v->node[k].obj == v->node[v->sel_node].obj && v->node[k].mask)
			m |= v->node[k].mask;
	return m;
}
