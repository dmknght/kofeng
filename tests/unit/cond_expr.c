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

	/* A run of "!" is one negation. */
	snprintf(c.expr, sizeof c.expr, "%s", "!!1");
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

	/* The join is the condition's own operator, not whatever was typed. */
	memset(&c, 0, sizeof c);
	c.op = 1;
	snprintf(c.expr, sizeof c.expr, "%s", "1&!2&3");
	cnd_drop_matcher(&E, &c, 2);
	EQ(c.expr, "1|!2");
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
	cnd_add(&E);
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2");
	CK(E.dr.cnd[0].tab == DT_BLOCKS);
	blk_set_picked(&E, 1, 0);
	CK(E.dr.n_grp == 1 && grp_of_block(&E, 1) == MAX_GROUP &&
	   grp_of_block(&E, 2) == 0);
	EQ(E.dr.cnd[0].expr, "1");
	blk_set_picked(&E, 2, 0);
	CK(E.dr.n_grp == 0);
	EQ(E.dr.cnd[0].expr, "");
}

/* ---- tags, built in memory ------------------------------------------------- */

static struct kof_tagset TS;

/* An entity of the set; its id is the one the set generated. */
static uint64_t make(uint8_t kind, const char *name, const uint64_t *typ,
		     uint32_t n_typ, uint64_t fam)
{
	struct kof_tagent p;
	const struct kof_tagent *e;
	const char *why = NULL;
	uint32_t i;

	memset(&p, 0, sizeof p);
	p.kind = kind;
	snprintf(p.name, sizeof p.name, "%s", name);
	for (i = 0; i < n_typ; i++)
		p.typ[p.n_typ++] = typ[i];
	if (fam) {
		p.has_fam = 1;
		p.fam = fam;
	}
	e = kof_tagset_add(&TS, &p, NULL, NULL, &why);
	CK(e != NULL);
	return e ? e->id : 0;
}

/* Two types, a family and four tags - two of them named alike - and the editor
 * pointed at them. */
static uint64_t t_botnet, t_trojan, t_rootkit, f_mirai;
static uint64_t g_flood, g_c2, g_flood2, g_bare;

static void tags_build(void)
{
	uint64_t a[2];

	kof_tagset_free(&TS);
	kof_tagset_init(&TS);
	snprintf(TS.dir, sizeof TS.dir, "build/kof_cond_expr_unused");
	t_botnet = make(KOF_TAGSRC_K_TYPE, "botnet", NULL, 0, 0);
	t_trojan = make(KOF_TAGSRC_K_TYPE, "trojan", NULL, 0, 0);
	t_rootkit = make(KOF_TAGSRC_K_TYPE, "rootkit", NULL, 0, 0);
	f_mirai = make(KOF_TAGSRC_K_FAMILY, "mirai", NULL, 0, 0);
	a[0] = t_botnet;
	g_flood = make(KOF_TAGSRC_K_TAG, "flood", a, 1, 0);
	a[0] = t_trojan;
	a[1] = t_botnet;
	g_c2 = make(KOF_TAGSRC_K_TAG, "c2", a, 2, f_mirai);
	a[0] = t_rootkit;
	g_flood2 = make(KOF_TAGSRC_K_TAG, "flood", a, 1, 0);
	g_bare = make(KOF_TAGSRC_K_TAG, "bare", NULL, 0, 0);
	E.tags = &TS;
}

/*
 * THE TAG IS THE DIAGNOSE'S OWN, AND SO IS EVERY WORD OF ITS FILE NAME:
 * `<first type>_<family>_<tag>_<id>.c`, the type the first the tag declares,
 * the family the tag's, nothing from the draft's shared Type or Family. A part
 * a tag has not got is left out without a doubled underscore, an untagged
 * diagnose has `<tag>` in its place, and the id runs per prefix over the
 * conditions and then the block matchers no condition uses.
 */
static void names_and_tags(void)
{
	char fn[160], lab[160];

	tags_build();
	memset(&E.dr, 0, sizeof E.dr);
	E.tags = &TS;
	E.dr.maltype = KOF_MALTYPE_ROOTKIT;             /* shared: no effect */
	snprintf(E.dr.family, sizeof E.dr.family, "%s", "gafgyt");
	E.dr.n_cnd = 4;
	E.dr.cnd[0].tag = g_flood;
	E.dr.cnd[1].tag = g_c2;
	E.dr.cnd[2].tag = g_flood;
	E.dr.cnd[3].tag = g_bare;
	cnd_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "botnet_flood_01.c");
	cnd_file_name(&E, 1, fn, sizeof fn);
	EQ(fn, "trojan_mirai_c2_01.c");
	cnd_file_name(&E, 2, fn, sizeof fn);
	EQ(fn, "botnet_flood_02.c");          /* running per prefix */
	cnd_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "bare_01.c");                  /* no type and no family */
	CK(strstr(fn, "__") == NULL);
	E.dr.maltype = KOF_MALTYPE_BOTNET;
	E.dr.family[0] = 0;
	cnd_file_name(&E, 1, fn, sizeof fn);
	EQ(fn, "trojan_mirai_c2_01.c");       /* the shared Type and Family */
	E.dr.cnd[3].tag = 0;
	cnd_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "<tag>_01.c");
	E.dr.cnd[3].tag = 0x7777;             /* a tag that is not there */
	cnd_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "<tag>_01.c");
	cnd_file_name(&E, 7, fn, sizeof fn);
	EQ(fn, "");

	/* The Tag cell: the name, and what tells two tags of one name apart. */
	tag_label(&E, g_c2, lab, sizeof lab);
	EQ(lab, "c2");
	tag_label(&E, g_flood, lab, sizeof lab);
	EQ(lab, "flood (types botnet)");
	tag_label(&E, g_flood2, lab, sizeof lab);
	EQ(lab, "flood (types rootkit)");
	tag_label(&E, 0, lab, sizeof lab);
	EQ(lab, "");
	EQ(tag_name(&E, g_c2), "c2");
	EQ(tag_name(&E, 0x7777), "");
	E.tags = NULL;
	EQ(tag_name(&E, g_c2), "");
	cnd_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "<tag>_01.c");
	E.tags = &TS;
}

/*
 * A BLOCK MATCHER NO CONDITION USES IS A DIAGNOSE OF ITS OWN, with its own tag,
 * and its file name runs on from the conditions'. One a condition names takes
 * the condition's tag and is not standalone.
 */
static void standalone_matchers(void)
{
	char fn[160];

	tags_build();
	memset(&E.dr, 0, sizeof E.dr);
	E.tags = &TS;
	E.dr.n_grp = 4;
	E.dr.grp[0].kind = (uint8_t)GRP_KIND_STR;       /* a string matcher */
	E.dr.grp[1].kind = E.dr.grp[2].kind = E.dr.grp[3].kind =
		(uint8_t)GRP_KIND_SIM;
	CK(!grp_standalone(&E, 0));           /* only a block matcher is */
	CK(grp_standalone(&E, 1) && grp_standalone(&E, 2) &&
	   grp_standalone(&E, 3));
	CK(!grp_standalone(&E, 9));
	/* A condition over the Blocks tab's matcher 1 (grp 1) takes it. */
	E.dr.n_cnd = 1;
	E.dr.cnd[0].tab = DT_BLOCKS;
	E.dr.cnd[0].tag = g_flood;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1");
	CK(!grp_standalone(&E, 1) && grp_standalone(&E, 2));
	/* Two standalone ones: the first shares the condition's prefix. */
	E.dr.grp[2].tag = g_flood;
	E.dr.grp[3].tag = g_flood;
	cnd_file_name(&E, 0, fn, sizeof fn);
	EQ(fn, "botnet_flood_01.c");
	grp_file_name(&E, 2, fn, sizeof fn);
	EQ(fn, "botnet_flood_02.c");
	grp_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "botnet_flood_03.c");
	grp_file_name(&E, 1, fn, sizeof fn);
	EQ(fn, "");                           /* not standalone: no name */
	E.dr.grp[3].tag = 0;
	grp_file_name(&E, 3, fn, sizeof fn);
	EQ(fn, "<tag>_01.c");
	/* A tag change is a change of the draft. */
	E.dr.saved_hash = draft_hash(&E);
	E.dr.grp[3].tag = g_c2;
	CK(draft_hash(&E) != E.dr.saved_hash);
}

/*
 * EACH TAB NUMBERS ITS OWN MATCHERS FROM 1, AND A CONDITION NAMES ONLY ITS
 * OWN TAB'S. Two Patterns matchers then two Blocks ones: the first Blocks
 * matcher is 1, a number past the end of a tab is refused, and removing a
 * matcher renumbers its own tab and no other.
 */
static void tab_numbers(void)
{
	static struct mtn_block blk[2];
	char fn[160], out[64];
	struct cond c;

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.blk = blk;
	E.dr.n_blk = 2;
	E.dr.n_grp = 4;
	E.dr.grp[2].kind = E.dr.grp[3].kind = (uint8_t)GRP_KIND_SIM;
	CK(grp_loc(&E, 0) == 1 && grp_loc(&E, 1) == 2);
	CK(grp_loc(&E, 2) == 1 && grp_loc(&E, 3) == 2);
	CK(grp_loc(&E, 9) == 0);
	/* Which tab is open renumbers nothing. */
	E.dr.tab = DT_BLOCKS;
	CK(grp_loc(&E, 2) == 1);
	E.dr.tab = DT_PATTERNS;
	CK(grp_loc(&E, 2) == 1);

	/* A Blocks condition's "1" is the first Blocks matcher (2 in the
	 * list), and it does not name the Patterns matcher that is first in
	 * the list. */
	memset(&c, 0, sizeof c);
	c.tab = DT_BLOCKS;
	snprintf(c.expr, sizeof c.expr, "%s", "1&!2");
	CK(cnd_uses(&E, &c, 2) && cnd_uses(&E, &c, 3));
	CK(!cnd_uses(&E, &c, 0) && !cnd_uses(&E, &c, 1));
	CK(cnd_neg(&E, &c, 3) == 1 && cnd_neg(&E, &c, 2) == 0);
	CK(cnd_foreign(&E, &c) == 0);
	E.dr.cnd[0] = c;
	E.dr.n_cnd = 1;
	cnd_canon(&E, 0, out, sizeof out);
	EQ(out, "1&!2");

	/* A reference past the tab's own list is refused: matcher 3 exists in
	 * the list but is not on the Blocks tab. */
	snprintf(c.expr, sizeof c.expr, "%s", "1&3");
	CK(cnd_foreign(&E, &c) == 4ul);
	CK(!cnd_uses(&E, &c, 0) && !cnd_uses(&E, &c, 1));
	snprintf(c.expr, sizeof c.expr, "%s", "0");
	CK(cnd_foreign(&E, &c) != 0);
	/* And no edit can bring another tab's matcher in. */
	snprintf(c.expr, sizeof c.expr, "%s", "1");
	cnd_drop_matcher(&E, &c, 0);
	EQ(c.expr, "1");
	cnd_negate_matcher(&E, &c, 1);
	EQ(c.expr, "1");
	E.dr.cnd[0] = c;
	cnd_swap_matcher(&E, 0, 2, 0);
	EQ(E.dr.cnd[0].expr, "1");
	cnd_swap_matcher(&E, 0, 0, 2);
	EQ(E.dr.cnd[0].expr, "1");
	cnd_swap_matcher(&E, 0, 2, 3);
	EQ(E.dr.cnd[0].expr, "2");

	E.dr.n_decl = 0;

	/* Removing the first Patterns matcher renumbers Patterns conditions
	 * and leaves a Blocks condition's numbers alone. */
	memset(&E.dr.cnd, 0, sizeof E.dr.cnd);
	E.dr.n_cnd = 2;
	E.dr.cnd[0].tab = DT_PATTERNS;
	E.dr.cnd[1].tab = DT_BLOCKS;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1&2");
	snprintf(E.dr.cnd[1].expr, sizeof E.dr.cnd[1].expr, "%s", "1&2");
	grp_remove(&E, 0);
	EQ(E.dr.cnd[0].expr, "1");
	EQ(E.dr.cnd[1].expr, "1&2");
	CK(E.dr.n_grp == 3 && grp_loc(&E, 0) == 1 && grp_loc(&E, 1) == 1);


	/* Conditions are numbered within their own tab. */
	memset(&E.dr, 0, sizeof E.dr);
	E.dr.n_cnd = 3;
	E.dr.cnd[1].tab = DT_BLOCKS;
	cnd_label(&E, 2, fn, sizeof fn);
	EQ(fn, "2.");
	cnd_label(&E, 1, fn, sizeof fn);
	EQ(fn, "1.");
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
	standalone_matchers();
	tab_numbers();

	kof_tagset_free(&TS);
	printf("condition expressions: read, rewrite, switch, canon, "
	       "view inputs, the operator word, block indices, tabs, "
	       "tags, names and per-tab numbers%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
