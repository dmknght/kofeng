/*
 * cond_expr - what a condition's matcher list means, read and rewritten.
 *
 * The property under test: the readers of a condition's expression agree about
 * it. The panel asks which matchers a condition names and which of them are
 * negated; the buttons rewrite the list; the canonical form decides whether the
 * row is drawn as a list at all. They are separate walks over one string, and
 * nothing at run time compares them.
 *
 * It matters because the failure is SILENT: a "!" dropped by one of them leaves
 * a panel showing "!1" over a draft that tests for 1, or the other way about.
 *
 * The rest is the draft model of the diagnose panel: tabs, tags, names and the
 * per-tab numbering of matchers and conditions.
 *
 * Nothing here writes a file or needs the engine, so it runs anywhere: the tag
 * sources the names are made from are built in memory.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "../../kofexamine/kofeditor.h"
#include "../../kofexamine/kofinspect.h"
#include <kofmod/pe.h>
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define EQ(a, b) do { \
	if (strcmp((a), (b))) { \
		printf("  FAIL %s:%d\n    got  \"%s\"\n    want \"%s\"\n", \
		       __FILE__, __LINE__, (a), (b)); \
		fails++; \
	} \
} while (0)

static struct kof_editor E;

static void reading(void)
{
	struct cond c;

	memset(&E.dr, 0, sizeof E.dr);
	/* All Patterns: number == place. The editor holds MAX_GROUP matchers and the group table has that
	 * many rows: this said 14, and grp_tab indexed the ninth row and the rest (UBSAN: index 12 out of
	 * bounds for type 'group [8]') - the test was building a state the editor cannot be in. The
	 * multi-digit id is still in the expression: 13 names no matcher of eight. */
	E.dr.n_grp = MAX_GROUP;
	memset(&c, 0, sizeof c);
	snprintf(c.expr, sizeof c.expr, "%s", "!1&2&!13");
	CK(cnd_uses(&E, &c, 0) && cnd_uses(&E, &c, 1));
	/* 1 and 13 share a digit, and 3 is a substring of 13: an id is a
	 * NUMBER here, not a character somewhere in the text. */
	CK(!cnd_uses(&E, &c, 2));
	CK(!cnd_uses(&E, &c, 7));
	CK(!cnd_uses(&E, &c, 12));      /* past the table: no matcher, not a read of the ninth row */
	CK(cnd_neg(&E, &c, 0) == 1);
	CK(cnd_neg(&E, &c, 1) == 0);
	/* A matcher the condition does not name is not negated either. */
	CK(cnd_neg(&E, &c, 2) == 0);

	/* P-4: every "!" negates (the file is written with all of them), so "!!1" is two negations and "!!!1" is one. */
	snprintf(c.expr, sizeof c.expr, "%s", "!!1");
	CK(cnd_uses(&E, &c, 0) && cnd_neg(&E, &c, 0) == 0);
	snprintf(c.expr, sizeof c.expr, "%s", "!!!1");
	CK(cnd_uses(&E, &c, 0) && cnd_neg(&E, &c, 0) == 1);

	/* "!(" negates a GROUP the author typed. The list does not own it, so
	 * no id inside it reads as negated. */
	snprintf(c.expr, sizeof c.expr, "%s", "!(1&2)");
	CK(cnd_uses(&E, &c, 0) && cnd_neg(&E, &c, 0) == 0);
}

static void rewriting(void)
{
	struct cond c;

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_grp = 5;
	memset(&c, 0, sizeof c);
	snprintf(c.expr, sizeof c.expr, "%s", "!1&2&3");
	cnd_drop_matcher(&E, &c, 1);
	EQ(c.expr, "!1&3");
	cnd_negate_matcher(&E, &c, 2);
	EQ(c.expr, "!1&!3");
	/* Negating twice leaves the expression as it was found. */
	cnd_negate_matcher(&E, &c, 0);
	EQ(c.expr, "1&!3");
	cnd_drop_matcher(&E, &c, 0);
	EQ(c.expr, "!3");
	cnd_drop_matcher(&E, &c, 2);
	EQ(c.expr, "");
	/* Dropping something that is not there changes nothing. */
	cnd_drop_matcher(&E, &c, 4);
	EQ(c.expr, "");

	/* P-1: only the id acted on changes; the join that was typed stays (a list whose op differs is not rewritten to it). */
	memset(&c, 0, sizeof c);
	c.op = 1;
	snprintf(c.expr, sizeof c.expr, "%s", "1&!2&3");
	cnd_drop_matcher(&E, &c, 2);
	EQ(c.expr, "1&!2");
}

static void switching(void)
{
	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_cnd = 1;
	E.dr.n_grp = 7;

	/*
	 * A switch keeps the NEGATION with the id - a remove followed by an
	 * append would leave it behind - and puts the list back in the order
	 * the row draws it in, which is by number. A list that stopped being
	 * ordered would stop being drawn as a list, and the author who clicked
	 * a matcher would get a text box back.
	 */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!1&2&3");
	cnd_swap_matcher(&E, 0, 0, 6);
	EQ(E.dr.cnd[0].expr, "2&3&!7");

	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&!2&5");
	cnd_swap_matcher(&E, 0, 1, 3);
	EQ(E.dr.cnd[0].expr, "1&!4&5");

	/* A matcher that does not exist is not somewhere to switch to. */
	cnd_swap_matcher(&E, 0, 0, 99);
	EQ(E.dr.cnd[0].expr, "1&!4&5");
	cnd_swap_matcher(&E, 99, 0, 2);
	EQ(E.dr.cnd[0].expr, "1&!4&5");
}

static void canon(void)
{
	char out[64];

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_cnd = 1;
	E.dr.n_grp = 3;

	/*
	 * The canonical form carries the "!". Without it every negated
	 * condition would differ from its own canonical form, and the row falls
	 * back to a text box the moment those two disagree - so negating a
	 * matcher would have taken the id list away.
	 */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!1&3");
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "!1&3");

	E.dr.cnd[0].op = 1;
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "!1|3");
}


/*
 * A ZEROED VIEW MEANS FILE LAYOUT, AND A MAPPED ONE SURVIVES THE PARSE.
 *
 * THIS IS THE CONTRACT EVERY CALLER RELIES ON, and it is worth pinning because
 * it is the opposite of what a parser normally does. pe_parse memsets its view
 * like the others - and then puts `layout` BACK, because that field is an INPUT
 * the caller owns and clearing it would make every declared mapped image parse
 * as a file and resolve its regions to the wrong bytes.
 *
 * The consequence is that whatever was in the allocation IS the answer, so
 * every caller must hand over a view it has cleared. Three did not, at
 * different times:
 *
 *   scan.c's SNIFF path reused one persistent view per format without clearing
 *   it. That bug was ACTIVE and was seen: scanning a manually-mapped image left
 *   MAPPED in the view, and the very next PE the scanner sniffed - a file, off
 *   a disk - was parsed as an image. Measured as a heuristic firing twice on
 *   one module, once on bytes that could not possibly be mapped.
 *
 *   kofinspect's two entry points malloc'd a view and parsed straight into it.
 *   That one is LATENT rather than active: the view is 7.6KB, and on the
 *   allocator here a block of that size comes back zeroed, so the wrong answer
 *   happens to be the right one. It is still undefined behaviour and still
 *   wrong under any allocator that fills freed memory - a debug CRT writes
 *   0xCD - so it is fixed, but honesty requires saying it was never observed
 *   failing.
 *
 * WHAT THIS TEST DOES AND DOES NOT COVER. It pins the parser's half
 * deterministically: cleared means FILE, set means MAPPED. It does NOT catch a
 * caller that forgets to clear, because that needs the allocator to hand back
 * dirty memory on demand and it will not - the first version of this case tried
 * exactly that, poisoned a block, freed it, and got a fresh zeroed one back. A
 * probabilistic test that usually fails to reproduce the defect is worse than
 * none, so it was replaced with this.
 *
 * Here rather than in a file of its own because this is the one test that
 * already links kofinspect.
 */
static void view_inputs(void)
{
	static const unsigned char pe[] = {
		/* Enough of a PE for the sniff to accept: MZ, e_lfanew at 0x3c
		 * pointing at "PE" and two NULs, one section, a PE32 optional header. */
		0x4d,0x5a,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0x40,0,0,0,
		0x50,0x45,0,0,
		0x4c,0x01, 0x01,0x00,
		0,0,0,0, 0,0,0,0, 0,0,0,0,
		0xe0,0x00, 0x02,0x01,
		0x0b,0x01
	};
	struct kgenome_pe_info info;
	struct kof_obj_ctx ctx;

	/*
	 * CLEARED MEANS FILE. This is what every caller buys by zeroing the
	 * view before handing it over, and what the three that did not were
	 * accidentally relying on the allocator for.
	 */
	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(kof_buf_make(pe, sizeof pe), &info, &ctx)) {
		printf("  note: the minimal PE did not parse; the view input "
		       "case did not run\n");
		return;
	}
	CK(info.layout == KGENOME_PE_LAYOUT_FILE);

	/*
	 * AND SET MEANS SET. The parse memsets its view and must put this one
	 * field back - a version that cleared it would make every declared
	 * mapped image resolve its regions at file offsets, silently.
	 */
	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	info.layout = KGENOME_PE_LAYOUT_MAPPED;
	if (kof_pe_parse(kof_buf_make(pe, sizeof pe), &info, &ctx))
		CK(info.layout == KGENOME_PE_LAYOUT_MAPPED);

	/*
	 * mem_origin RIDES WITH IT, and is cleared when the layout is not
	 * mapped - an origin on bytes that came off a disk would be a claim
	 * about where they were read from, which nobody made.
	 */
	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	info.mem_origin = KGENOME_PE_ORIGIN_MANUAL;
	if (kof_pe_parse(kof_buf_make(pe, sizeof pe), &info, &ctx))
		CK(info.mem_origin == KGENOME_PE_ORIGIN_NONE);
}

/*
 * THE WORD BETWEEN THE IDS, AND THE EXPRESSION UNDER IT.
 *
 * The row draws a list of ids only while the expression IS the canonical
 * spelling of that list - see canon() above. `op` decides what the canonical
 * spelling is, so flipping it without rewriting the expression makes the two
 * disagree, and the row silently becomes a text box with the old spelling in
 * it. An author who asked for "or" got a caret.
 *
 * The bug reached a person: a condition over two matchers, one click to turn
 * "and" into "or", and the next click landed in an editor.
 */
static void operator_word(void)
{
	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_cnd = 1;
	E.dr.n_grp = 3;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2");

	cnd_set_op(&E, 0, 1);
	CK(E.dr.cnd[0].op == 1);
	EQ(E.dr.cnd[0].expr, "1|2");
	cnd_set_op(&E, 0, 0);
	CK(E.dr.cnd[0].op == 0);
	EQ(E.dr.cnd[0].expr, "1&2");

	/* The negation rides along, because canon writes it. */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "!1&2");
	cnd_set_op(&E, 0, 1);
	EQ(E.dr.cnd[0].expr, "!1|2");

	/*
	 * AN EXPRESSION SOMEBODY TYPED IS THEIRS.
	 *
	 * The word is not drawn for one, so it cannot be clicked - and a call
	 * that arrived anyway must not rewrite what was typed into a list that
	 * says something else.
	 */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&(2|3)");
	cnd_set_op(&E, 0, 1);
	EQ(E.dr.cnd[0].expr, "1&(2|3)");
}

/*
 * A MATCHER HOLDS A BLOCK BY ITS INDEX, and the list of blocks is rebuilt
 * whenever the object under the panel changes - dropped, compacted, sorted into
 * file order. Every one of those moves a block to a different index.
 *
 * The bug this guards: a rule loaded over the sample it was cut from lost track
 * of its own block. The row showed no offset, the block could not be lit, and
 * the draft reported a ticked block that no matcher named - which is the one
 * thing that stops it being written.
 */
static void block_indices(void)
{
	static struct mtn_block blk[4];

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.blk = blk;
	E.dr.n_blk = 3;
	E.dr.n_grp = 2;
	blk[0].picked = blk[1].picked = blk[2].picked = 1;
	blk[0].n_hash = blk[1].n_hash = blk[2].n_hash =
		KGENOME_MUTATION_MIN_HASH;
	E.dr.grp[0].kind = (uint8_t)GRP_KIND_SIM;
	E.dr.grp[1].kind = (uint8_t)GRP_KIND_SIM;
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 2));
	CK(grp_sim_add(&E, 1, SIM_IT_BLOCK, 0));

	CK(grp_of_block(&E, 2) == 0);
	CK(grp_of_block(&E, 0) == 1);
	CK(grp_of_block(&E, 1) == MAX_GROUP);

	blk_moved(&E, 2, 1);
	CK(E.dr.grp[0].sim[0].blk == 1);
	CK(E.dr.grp[1].sim[0].blk == 0);
	blk_moved(&E, 0, 2);
	CK(E.dr.grp[1].sim[0].blk == 2);
	/* A move to where it already is changes nothing. */
	blk_moved(&E, 1, 1);
	CK(E.dr.grp[0].sim[0].blk == 1);

	/*
	 * A REORDERING IS ONE MOVE OF EVERY BLOCK, not a series of single ones: a
	 * series moves an item that was just moved a second time. Here 0 goes to 2,
	 * 1 to 0 and 2 to 1 - the matchers naming 2 and 0 must end up naming 1 and 2,
	 * whereas blk_moved(0,2) then blk_moved(2,1) would leave both at 1.
	 */
	{
		static const uint32_t to[3] = { 2, 0, 1 };

		E.dr.grp[0].sim[0].blk = 2;
		E.dr.grp[1].sim[0].blk = 0;
		blk_permute(&E, to, 3);
		CK(E.dr.grp[0].sim[0].blk == 1);
		CK(E.dr.grp[1].sim[0].blk == 2);
		/* An index past the list is left alone, not read out of the table. */
		E.dr.grp[0].sim[0].blk = 7;
		blk_permute(&E, to, 3);
		CK(E.dr.grp[0].sim[0].blk == 7);
		E.dr.grp[0].sim[0].blk = 1;
		E.dr.grp[1].sim[0].blk = 2;
	}

	/*
	 * A MEASURE IS IDENTIFIED BY WHICH BLOCK IT IS - so the same block twice is
	 * one item and two different blocks are two.
	 */
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 1) && E.dr.grp[0].n_sim == 1);
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 0) && E.dr.grp[0].n_sim == 2);
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 0) && E.dr.grp[0].n_sim == 2);
	/* 1 and 2 were the shape and the string set, 3 the block vector: gaps,
	 * nothing holds them. */
	CK(grp_sim_of(&E, 1u, 0) == MAX_GROUP);
	CK(grp_sim_of(&E, 3u, 0) == MAX_GROUP);
	/* Taking one out closes the gap rather than leaving a hole for the
	 * list row to draw. */
	grp_sim_del(&E, 0, 0);
	CK(E.dr.grp[0].n_sim == 1 && E.dr.grp[0].sim[0].what == SIM_IT_BLOCK &&
	   E.dr.grp[0].sim[0].blk == 0);
	CK(grp_of_block(&E, 2) == 1);
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 1) && E.dr.grp[0].n_sim == 2);

}

/*
 * THE DIAGNOSE PANEL'S MODEL: a tick makes the block's matcher and unticking
 * drops it. The tags a diagnose is labelled with, and the names built from
 * them, are checked in names_and_tags.
 */
static void tabs_tags_names(void)
{
	static struct mtn_block blk[3];

	/* Ticking a block makes its find_similar matcher; unticking drops it
	 * and renumbers the condition that named it. */
	memset(&E.dr, 0, sizeof E.dr);
	E.dr.blk = blk;
	E.dr.n_blk = 3;
	blk[0].n_hash = blk[1].n_hash = blk[2].n_hash =
		KGENOME_MUTATION_MIN_HASH;
	blk[0].id = 0x11u; blk[1].id = 0x22u; blk[2].id = 0x33u;
	E.dr.tab = DT_BLOCKS;
	blk_set_picked(&E, 1, 1);
	blk_set_picked(&E, 2, 1);
	CK(E.dr.n_grp == 2);
	CK(E.dr.grp[0].kind == GRP_KIND_SIM && E.dr.grp[0].n_sim == 1 &&
	   E.dr.grp[0].sim[0].blk == 1 && E.dr.grp[0].pct == GRP_PCT_DEFAULT);
	CK(grp_of_block(&E, 2) == 1);
	/* Ticking it again does not make a second one. */
	blk_set_picked(&E, 2, 1);
	CK(E.dr.n_grp == 2);
	CK(grp_tab(&E, 0) == DT_BLOCKS && grp_tab_count(&E, DT_BLOCKS) == 2u);
	CK(grp_tab_count(&E, DT_PATTERNS) == 0u);
	/* Each block matcher is a unit with its OWN type and tag: unticking one
	 * keeps the other's, and no condition exists on this tab. */
	E.dr.grp[0].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	snprintf(E.dr.grp[0].tag, sizeof E.dr.grp[0].tag, "%s", "flood");
	E.dr.grp[1].utype = (uint8_t)(KOF_MALTYPE_TROJAN + 1);
	snprintf(E.dr.grp[1].tag, sizeof E.dr.grp[1].tag, "%s", "c2");
	CK(E.dr.n_cnd == 0);
	blk_set_picked(&E, 1, 0);
	CK(E.dr.n_grp == 1 && grp_of_block(&E, 1) == MAX_GROUP &&
	   grp_of_block(&E, 2) == 0);
	CK(E.dr.grp[0].utype == (uint8_t)(KOF_MALTYPE_TROJAN + 1) &&
	   !strcmp(E.dr.grp[0].tag, "c2"));
	blk_set_picked(&E, 2, 0);
	CK(E.dr.n_grp == 0);
}

/* ---- tags, built in memory ------------------------------------------------- */

static void set_tag(char *dst, size_t cap, const char *name)
{
	snprintf(dst, cap, "%s", name);
}

/*
 * EVERY WORD OF A UNIT'S FILE NAME IS THE UNIT'S OWN OR THE HEADER'S:
 * `<type>_<family>_<tag>_<id>.c`, the type the unit's (utype is a kof_maltype
 * value plus one, 0 is not chosen), the family the header's, the tag the
 * unit's. A type or tag not chosen is written `<type>` / `<tag>`, no family
 * leaves no doubled underscore, and the id runs per prefix over the conditions
 * and then the block matchers.
 */
static void names_and_tags(void)
{
	char fn[160];

	memset(&E.dr, 0, sizeof E.dr);
	snprintf(E.dr.family, sizeof E.dr.family, "%s", "Gafgyt");
	E.dr.n_cnd = 4;
	E.dr.cnd[0].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	set_tag(E.dr.cnd[0].tag, sizeof E.dr.cnd[0].tag, "flood");
	E.dr.cnd[1].utype = (uint8_t)(KOF_MALTYPE_TROJAN + 1);
	set_tag(E.dr.cnd[1].tag, sizeof E.dr.cnd[1].tag, "c2");
	E.dr.cnd[2].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	set_tag(E.dr.cnd[2].tag, sizeof E.dr.cnd[2].tag, "flood");
	E.dr.cnd[3].utype = 0;
	set_tag(E.dr.cnd[3].tag, sizeof E.dr.cnd[3].tag, "bare");
	cnd_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "botnet_gafgyt_flood_01.c");
	cnd_file_name(&E, 1, fn, sizeof fn);
	EQ(fn, "trojan_gafgyt_c2_01.c");
	cnd_file_name(&E, 2, fn, sizeof fn);
	EQ(fn, "botnet_gafgyt_flood_02.c");   /* running per prefix */
	cnd_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "<type>_gafgyt_bare_01.c");    /* type not chosen */
	/* No family: nothing is left in its place and no underscore doubles. */
	E.dr.family[0] = 0;
	cnd_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "botnet_flood_01.c");
	CK(strstr(fn, "__") == NULL);
	E.dr.cnd[3].tag[0] = 0;
	E.dr.cnd[3].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	cnd_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "botnet_<tag>_01.c");         /* tag not chosen */
	cnd_file_name(&E, 7, fn, sizeof fn);
	EQ(fn, "");
}

/*
 * THE UNIT RULE: a PATTERNS CONDITION is a unit and a BLOCKS MATCHER is a unit; nothing else is (a string
 * matcher is part of the conditions that name it). The list (draft_units) is the one the draw, the hit zones,
 * the file names, the preview and the writer read. Why the old tests missed the Blocks-condition shape (a
 * block matcher a condition named lost its cells, and a Graphs condition took an id and was never written):
 * (b) no test mixed a Blocks condition or a Graphs one with a written one of the same prefix.
 */
static int has_unit(const struct draft_unit *u, uint32_t n, int is_grp, uint32_t idx)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (!u[i].is_grp == !is_grp && u[i].idx == idx)
			return 1;
	return 0;
}

static void unit_list(void)
{
	struct draft_unit u[DRAFT_UNIT_MAX];
	char fn[160];
	uint32_t n;

	/* One string matcher, two block matchers, no condition: the two block matchers are the units. */
	memset(&E.dr, 0, sizeof E.dr);
	snprintf(E.dr.family, sizeof E.dr.family, "%s", "Mirai");
	E.dr.n_grp = 3;
	E.dr.grp[0].kind = (uint8_t)GRP_KIND_STR;
	E.dr.grp[1].kind = E.dr.grp[2].kind = (uint8_t)GRP_KIND_SIM;
	E.dr.grp[1].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	set_tag(E.dr.grp[1].tag, sizeof E.dr.grp[1].tag, "flood");
	E.dr.grp[2].utype = (uint8_t)(KOF_MALTYPE_TROJAN + 1);
	set_tag(E.dr.grp[2].tag, sizeof E.dr.grp[2].tag, "c2");
	n = draft_units(&E, u, DRAFT_UNIT_MAX);
	CK(n == 2u && u[0].is_grp && u[0].idx == 1 && u[1].is_grp && u[1].idx == 2);
	CK(u[0].utype == (uint8_t)(KOF_MALTYPE_BOTNET + 1) && !strcmp(u[0].tag, "flood"));
	CK(draft_unit_count(&E) == 2u);
	CK(draft_units_on_tab(&E, DT_BLOCKS, u, DRAFT_UNIT_MAX) == 2u);
	CK(draft_units_on_tab(&E, DT_PATTERNS, u, DRAFT_UNIT_MAX) == 0u);
	CK(draft_units_on_tab(&E, DT_GRAPHS, u, DRAFT_UNIT_MAX) == 0u);
	CK(draft_unit_find(&E, 1, 0) == -1);                 /* a string matcher is no unit */
	CK(draft_unit_find(&E, 1, 1) == 0 && draft_unit_find(&E, 1, 2) == 1);
	grp_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "");
	grp_file_name(&E, 1, fn, sizeof fn);
	EQ(fn, "botnet_mirai_flood_01.c");
	grp_file_name(&E, 2, fn, sizeof fn);
	EQ(fn, "trojan_mirai_c2_01.c");

	/* A condition over the string matcher: the output order is the condition, then the block matchers, and the
	 * running id counts over both within one prefix. */
	cnd_add(&E);
	E.dr.cnd[0].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	set_tag(E.dr.cnd[0].tag, sizeof E.dr.cnd[0].tag, "flood");
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1");
	n = draft_units(&E, u, DRAFT_UNIT_MAX);
	CK(n == 3u && !u[0].is_grp && u[0].idx == 0 && u[1].idx == 1 && u[2].idx == 2);
	CK(draft_units_on_tab(&E, DT_PATTERNS, u, DRAFT_UNIT_MAX) == 1u && !u[0].is_grp);
	CK(draft_units_on_tab(&E, DT_BLOCKS, u, DRAFT_UNIT_MAX) == 2u && u[0].is_grp);
	cnd_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "botnet_mirai_flood_01.c");
	grp_file_name(&E, 1, fn, sizeof fn);
	EQ(fn, "botnet_mirai_flood_02.c");
	/* A block matcher is never part of a condition: naming it is refused, and no edit brings it in. */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2");
	CK(cnd_foreign(&E, &E.dr.cnd[0]) == 3ul);
	CK(!cnd_uses(&E, &E.dr.cnd[0], 1) && !cnd_uses(&E, &E.dr.cnd[0], 2));
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1");
	cnd_drop_matcher(&E, &E.dr.cnd[0], 1);
	cnd_negate_matcher(&E, &E.dr.cnd[0], 1);
	EQ(E.dr.cnd[0].expr, "1");
	cnd_swap_matcher(&E, 0, 0, 1);
	EQ(E.dr.cnd[0].expr, "1");
	cnd_swap_matcher(&E, 0, 1, 0);
	EQ(E.dr.cnd[0].expr, "1");
	/* Both blocks stay units whatever the condition says: the matcher's pair is its own and never hidden. */
	CK(has_unit(u, draft_units(&E, u, DRAFT_UNIT_MAX), 1, 1) && has_unit(u, 3u, 1, 2));
}

/* Removing a block matcher renumbers nothing in a condition and every other matcher keeps its own type and tag;
 * removing a string matcher renumbers the conditions that name the matchers above it. */
static void matcher_removal(void)
{
	struct draft_unit u[DRAFT_UNIT_MAX];
	char fn[160];

	memset(&E.dr, 0, sizeof E.dr);
	snprintf(E.dr.family, sizeof E.dr.family, "%s", "Mirai");
	E.dr.n_grp = 4;
	E.dr.grp[0].kind = E.dr.grp[1].kind = (uint8_t)GRP_KIND_STR;
	E.dr.grp[2].kind = E.dr.grp[3].kind = (uint8_t)GRP_KIND_SIM;
	E.dr.grp[2].utype = (uint8_t)(KOF_MALTYPE_BOTNET + 1);
	set_tag(E.dr.grp[2].tag, sizeof E.dr.grp[2].tag, "flood");
	E.dr.grp[3].utype = (uint8_t)(KOF_MALTYPE_TROJAN + 1);
	set_tag(E.dr.grp[3].tag, sizeof E.dr.grp[3].tag, "c2");
	cnd_add(&E);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2");
	grp_remove(&E, 2);                                   /* a block matcher: the condition is untouched */
	EQ(E.dr.cnd[0].expr, "1&2");
	CK(E.dr.n_grp == 3 && draft_units(&E, u, DRAFT_UNIT_MAX) == 2u && u[1].is_grp && u[1].idx == 2);
	EQ(E.dr.grp[2].tag, "c2");
	CK(E.dr.grp[2].utype == (uint8_t)(KOF_MALTYPE_TROJAN + 1));
	grp_file_name(&E, 2, fn, sizeof fn);
	EQ(fn, "trojan_mirai_c2_01.c");
	grp_remove(&E, 0);                                   /* a string matcher: "1&2" loses 1 and 2 becomes 1 */
	EQ(E.dr.cnd[0].expr, "1");
	CK(E.dr.n_grp == 2 && E.dr.grp[1].utype == (uint8_t)(KOF_MALTYPE_TROJAN + 1) && !strcmp(E.dr.grp[1].tag, "c2"));
	/* Conditions are numbered by position. */
	cnd_add(&E);
	cnd_add(&E);
	cnd_label(&E, 2, fn, sizeof fn);
	EQ(fn, "3.");
	cnd_label(&E, 0, fn, sizeof fn);
	EQ(fn, "1.");
}

/* EACH TAB NUMBERS ITS OWN MATCHERS FROM 1, and a condition names the Patterns ones only. */
static void tab_numbers(void)
{
	static struct mtn_block blk[2];
	char out[64];

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.blk = blk;
	E.dr.n_blk = 2;
	E.dr.n_grp = 4;
	E.dr.grp[2].kind = E.dr.grp[3].kind = (uint8_t)GRP_KIND_SIM;
	CK(grp_loc(&E, 0) == 1 && grp_loc(&E, 1) == 2);
	CK(grp_loc(&E, 2) == 1 && grp_loc(&E, 3) == 2);
	CK(grp_loc(&E, 9) == 0);
	E.dr.tab = DT_BLOCKS;                                /* which tab is open renumbers nothing */
	CK(grp_loc(&E, 2) == 1);
	E.dr.tab = DT_PATTERNS;
	CK(grp_loc(&E, 2) == 1);
	CK(grp_tab_count(&E, DT_PATTERNS) == 2u && grp_tab_count(&E, DT_BLOCKS) == 2u);

	E.dr.n_cnd = 1;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&!2");
	CK(cnd_uses(&E, &E.dr.cnd[0], 0) && cnd_uses(&E, &E.dr.cnd[0], 1));
	CK(!cnd_uses(&E, &E.dr.cnd[0], 2) && !cnd_uses(&E, &E.dr.cnd[0], 3));
	CK(cnd_neg(&E, &E.dr.cnd[0], 1) == 1 && cnd_neg(&E, &E.dr.cnd[0], 0) == 0);
	CK(cnd_foreign(&E, &E.dr.cnd[0]) == 0);
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "1&!2");
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&3");
	CK(cnd_foreign(&E, &E.dr.cnd[0]) == 4ul);            /* only two string matchers exist */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "0");
	CK(cnd_foreign(&E, &E.dr.cnd[0]) != 0);
}

int main(void)
{
	reading();
	rewriting();
	switching();
	canon();
	view_inputs();
	operator_word();
	block_indices();
	tabs_tags_names();
	names_and_tags();
	tab_numbers();
	unit_list();
	matcher_removal();

	printf("condition expressions: read, rewrite, switch, canon, "
	       "view inputs, the operator word, block indices, tabs, "
	       "tags, names and per-tab numbers%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
