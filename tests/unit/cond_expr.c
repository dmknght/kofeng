/*
 * cond_expr - what a condition's matcher list means, read and written.
 *
 * The property under test: the four readers of a condition's expression agree
 * about it. The panel asks which matchers a condition names and which of them
 * are negated; the buttons rewrite the list; the canonical form decides whether
 * the row is drawn as a list at all; and the emitter turns it into C. They are
 * separate walks over one string, and nothing at run time compares them.
 *
 * It matters because the failure is SILENT and it INVERTS A SIGNATURE. A "!"
 * dropped by one of the four leaves a panel showing "!1" over a file that tests
 * for 1, or the other way about - and the rule still compiles, still loads, and
 * still reports findings, just the wrong ones. No corpus run catches that,
 * because a corpus cannot say what the author meant.
 *
 * The brackets around a negated matcher get their own cases for the same
 * reason: a threshold matcher emits "m1 >= 3", and "!m1 >= 3" is "(!m1) >= 3",
 * which compiles, is always false, and reads exactly like what was asked for.
 *
 * Nothing here touches the filesystem or the engine, so it runs anywhere.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../kofexamine/kofeditor.h"
#include "../../kofexamine/kofinspect.h"
#include <kofmod/pe.h>
#include "../../libkofeng/kofparsers/binaries/pe_parse.h"

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

/* emit_expr's output, as a string. */
static const char *emit(const char *expr)
{
	static char buf[512];
	FILE *f;
	long n;

	memset(buf, 0, sizeof buf);
	f = tmpfile();
	if (!f)
		return "";
	emit_expr(f, &E, expr);
	n = ftell(f);
	if (n < 0 || (size_t)n >= sizeof buf)
		n = 0;
	rewind(f);
	if (fread(buf, 1u, (size_t)n, f) != (size_t)n)
		n = 0;
	buf[n] = 0;
	fclose(f);
	return buf;
}

static void reading(void)
{
	struct cond c;

	memset(&c, 0, sizeof c);
	snprintf(c.expr, sizeof c.expr, "%s", "!1&2&!13");
	CK(cnd_uses(&c, 0) && cnd_uses(&c, 1) && cnd_uses(&c, 12));
	/* 1 and 13 share a digit, and 3 is a substring of 13: an id is a
	 * NUMBER here, not a character somewhere in the text. */
	CK(!cnd_uses(&c, 2));
	CK(cnd_neg(&c, 0) == 1);
	CK(cnd_neg(&c, 1) == 0);
	CK(cnd_neg(&c, 12) == 1);
	/* A matcher the condition does not name is not negated either. */
	CK(cnd_neg(&c, 2) == 0);

	/* A run of "!" is one negation - the same reading the emitter gives
	 * it, which is the point rather than the value. */
	snprintf(c.expr, sizeof c.expr, "%s", "!!1");
	CK(cnd_uses(&c, 0) && cnd_neg(&c, 0) == 1);
	EQ(emit("!!1"), emit("!1"));

	/* "!(" negates a GROUP the author typed. The list does not own it, so
	 * no id inside it reads as negated - and the emitter passes it
	 * through, so the two still agree. */
	snprintf(c.expr, sizeof c.expr, "%s", "!(1&2)");
	CK(cnd_uses(&c, 0) && cnd_neg(&c, 0) == 0);
}

static void rewriting(void)
{
	struct cond c;

	memset(&c, 0, sizeof c);
	snprintf(c.expr, sizeof c.expr, "%s", "!1&2&3");
	cnd_drop_matcher(&c, 1);
	EQ(c.expr, "!1&3");
	cnd_negate_matcher(&c, 2);
	EQ(c.expr, "!1&!3");
	/* Negating twice leaves the expression as it was found. */
	cnd_negate_matcher(&c, 0);
	EQ(c.expr, "1&!3");
	cnd_drop_matcher(&c, 0);
	EQ(c.expr, "!3");
	cnd_drop_matcher(&c, 2);
	EQ(c.expr, "");
	/* Dropping something that is not there changes nothing. */
	cnd_drop_matcher(&c, 4);
	EQ(c.expr, "");

	/* The join is the condition's own operator, not whatever was typed. */
	memset(&c, 0, sizeof c);
	c.op = 1;
	snprintf(c.expr, sizeof c.expr, "%s", "1&!2&3");
	cnd_drop_matcher(&c, 2);
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

static void emitting(void)
{
	static struct object obs[2];

	memset(&E, 0, sizeof E);
	memset(obs, 0, sizeof obs);
	/* The editor points at the host's object array, and emit_call asks one
	 * of them what its regions are called. A WHOLE-FILE mask never reaches
	 * the format, so a zeroed object is all this needs. */
	E.obj = obs;

	E.dr.n_grp = 2;
	E.dr.n_decl = 2;
	E.dr.decl[0].grp = 1u;                  /* s0 is matcher 1's */
	E.dr.decl[1].grp = 2u;                  /* s1 is matcher 2's */
	E.dr.grp[0].mask = KOF_SCAN_ALL;
	E.dr.grp[1].mask = KOF_SCAN_ALL;
	E.dr.grp[0].rule = 1;                   /* find_any */
	E.dr.grp[1].rule = 2;                   /* find_multi, >= 2 */
	E.dr.grp[1].thresh = 2;

	EQ(emit("1"), "kof_find_str_any(scan_range_whole_file, s0)");
	EQ(emit("!1"), "!(kof_find_str_any(scan_range_whole_file, s0))");
	/* THE CASE THE BRACKETS EXIST FOR. */
	EQ(emit("2"), "kof_find_str_multi(scan_range_whole_file, s1) >= 2");
	EQ(emit("!2"),
	   "!(kof_find_str_multi(scan_range_whole_file, s1) >= 2)");
	EQ(emit("1&!2"),
	   "kof_find_str_any(scan_range_whole_file, s0) && "
	   "!(kof_find_str_multi(scan_range_whole_file, s1) >= 2)");
	EQ(emit("!(1|2)"),
	   "!(kof_find_str_any(scan_range_whole_file, s0) || "
	   "kof_find_str_multi(scan_range_whole_file, s1) >= 2)");
	/* An id past the end of the draft is a 0, not a call. */
	EQ(emit("!9"), "!(0)");
	/* An empty expression tests nothing, and says so. */
	EQ(emit(""), "1");
	/* Nothing that is not code survives - a "!" that negates nothing
	 * included. */
	EQ(emit("1;drop"), "kof_find_str_any(scan_range_whole_file, s0)");
	EQ(emit("!;1"), "kof_find_str_any(scan_range_whole_file, s0)");
}

/*
 * HOW TWO BLOCKS JOIN, AND THE ONE THAT IS NOT AN OR.
 *
 * The panel drew "logic [and]" between two conditions and the generator wrote
 * two separate ifs - which is two detections, either of which fires on its own.
 * The word said the opposite of the file, and nothing compares the two.
 *
 * So the property here is the conjunction itself: one if, both terms, one
 * verdict, and the OTHER two words still producing what they always did.
 */
static const char *emit_block(void)
{
	static char buf[1024];
	FILE *f;
	long n;
	uint32_t k;

	memset(buf, 0, sizeof buf);
	f = tmpfile();
	if (!f)
		return "";
	for (k = 0; k < E.dr.n_cnd; k++) {
		if (E.dr.cnd[k].parent >= 0)
			continue;
		k = emit_cond(f, &E, k, 0);
	}
	n = ftell(f);
	if (n < 0 || (size_t)n >= sizeof buf)
		n = 0;
	rewind(f);
	if (fread(buf, 1u, (size_t)n, f) != (size_t)n)
		n = 0;
	buf[n] = 0;
	fclose(f);
	return buf;
}

static void joining(void)
{
	/* emitting() left two matchers declared; two leaf conditions over
	 * them, each concluding, is the shape that was generated wrong. */
	E.dr.n_cnd = 2;
	memset(E.dr.cnd, 0, sizeof E.dr.cnd[0] * 2u);
	E.dr.cnd[0].parent = E.dr.cnd[1].parent = -1;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1");
	snprintf(E.dr.cnd[1].expr, sizeof E.dr.cnd[1].expr, "%s", "2");
	E.dr.cnd[0].level = E.dr.cnd[1].level = LV_INFECT;

	/* ONE if, BOTH terms, ONE verdict. */
	E.dr.cnd[0].join = JN_AND;
	EQ(emit_block(),
	   "if (kof_find_str_any(scan_range_whole_file, s0) && "
	   "kof_find_str_multi(scan_range_whole_file, s1) >= 2)\n"
	   "\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n");

	/*
	 * AND "or" IS TWO BRANCHES, WITH NO "else" IN IT.
	 *
	 * A verdict returns, so the second if is reached exactly when the first
	 * declined - which is what an else would have said, less directly and
	 * wrongly for a gate. There is no third join value to test because
	 * there is nothing a third one could mean.
	 */
	E.dr.cnd[0].join = JN_OR;
	EQ(emit_block(),
	   "if (kof_find_str_any(scan_range_whole_file, s0))\n"
	   "\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
	   "if (kof_find_str_multi(scan_range_whole_file, s1) >= 2)\n"
	   "\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n");
	CK(strstr(emit_block(), "else") == NULL);

	/* A TERM HOLDING AN "or" IS BRACKETED: "&&" binds tighter than "||",
	 * so without them the second block would swallow half the first. */
	E.dr.cnd[0].join = JN_AND;
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1|2");
	EQ(emit_block(),
	   "if ((kof_find_str_any(scan_range_whole_file, s0) || "
	   "kof_find_str_multi(scan_range_whole_file, s1) >= 2) && "
	   "kof_find_str_multi(scan_range_whole_file, s1) >= 2)\n"
	   "\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n");

	/* THE RUN'S VERDICT IS ITS LAST MEMBER'S - the one reached when the
	 * whole conjunction holds. */
	snprintf(E.dr.cnd[0].expr, sizeof E.dr.cnd[0].expr, "%s", "1");
	E.dr.cnd[1].level = LV_SUSPECT;
	CK(strstr(emit_block(), "KOF_SCAN_SUSPECT(KOF_MALVAR_AUTO);") != NULL);
	CK(strstr(emit_block(), "KOF_SCAN_INFECT") == NULL);

	/* AND A GATE IS NOT A TERM. cnd[1] gains a child, so it is a brace
	 * around branches rather than a value to "&&" - the run ends at
	 * cnd[0] and both are emitted as themselves. */
	E.dr.cnd[1].level = LV_INFECT;
	E.dr.n_cnd = 3;
	memset(&E.dr.cnd[2], 0, sizeof E.dr.cnd[2]);
	E.dr.cnd[2].parent = 1;
	E.dr.cnd[2].level = LV_INFECT;
	snprintf(E.dr.cnd[2].expr, sizeof E.dr.cnd[2].expr, "%s", "2");
	CK(cnd_and_run(&E, 0) == 0);
	CK(strstr(emit_block(), " && ") == NULL);
	E.dr.n_cnd = 0;
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
	struct kof_pe_info info;
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
	CK(info.layout == KOF_PE_LAYOUT_FILE);

	/*
	 * AND SET MEANS SET. The parse memsets its view and must put this one
	 * field back - a version that cleared it would make every declared
	 * mapped image resolve its regions at file offsets, silently.
	 */
	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	info.layout = KOF_PE_LAYOUT_MAPPED;
	if (kof_pe_parse(kof_buf_make(pe, sizeof pe), &info, &ctx))
		CK(info.layout == KOF_PE_LAYOUT_MAPPED);

	/*
	 * mem_origin RIDES WITH IT, and is cleared when the layout is not
	 * mapped - an origin on bytes that came off a disk would be a claim
	 * about where they were read from, which nobody made.
	 */
	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	info.mem_origin = KOF_PE_ORIGIN_MANUAL;
	if (kof_pe_parse(kof_buf_make(pe, sizeof pe), &info, &ctx))
		CK(info.mem_origin == KOF_PE_ORIGIN_NONE);
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
	static struct plg_block blk[4];

	memset(&E.dr, 0, sizeof E.dr);
	E.dr.blk = blk;
	E.dr.n_blk = 3;
	E.dr.n_grp = 2;
	blk[0].picked = blk[1].picked = blk[2].picked = 1;
	blk[0].n_hash = blk[1].n_hash = blk[2].n_hash = KOF_PLAGUE_MIN_HASH;
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
	 * A MEASURE IS IDENTIFIED BY WHAT IT IS AND, FOR A BLOCK, BY WHICH -
	 * so the same block twice is one item, two different blocks are two,
	 * and a whole-object measure is one per matcher whatever `blk` says.
	 */
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 1) && E.dr.grp[0].n_sim == 1);
	CK(grp_sim_add(&E, 0, SIM_IT_SHAPE, 0) && E.dr.grp[0].n_sim == 2);
	CK(grp_sim_add(&E, 0, SIM_IT_SHAPE, 7) && E.dr.grp[0].n_sim == 2);
	CK(grp_sim_of(&E, SIM_IT_SHAPE, 0) == 0);
	CK(grp_sim_of(&E, SIM_IT_STRSET, 0) == MAX_GROUP);
	CK(draft_uses_sim(&E, SIM_IT_SHAPE));
	CK(!draft_uses_sim(&E, SIM_IT_BLKSET));
	/* Taking one out closes the gap rather than leaving a hole for the
	 * list row to draw. */
	grp_sim_del(&E, 0, 0);
	CK(E.dr.grp[0].n_sim == 1 && E.dr.grp[0].sim[0].what == SIM_IT_SHAPE);
	CK(!draft_uses_sim(&E, SIM_IT_BLOCK) || grp_of_block(&E, 2) == 1);
	CK(grp_sim_add(&E, 0, SIM_IT_BLOCK, 1) && E.dr.grp[0].n_sim == 2);

	/* A block is usable when it was TICKED and can be scored - both, and
	 * the four menus that offer blocks ask this one question. */
	CK(blk_usable(&E, 0) && blk_usable(&E, 1));
	blk[1].picked = 0;
	CK(!blk_usable(&E, 1));
	blk[1].picked = 1;
	blk[1].n_hash = KOF_PLAGUE_MIN_HASH - 1u;
	CK(!blk_usable(&E, 1));
	CK(!blk_usable(&E, 99));

	/* And a draft uses blocks when a MATCHER names one - a ticked block
	 * nobody named is not use, which is what draft_missing_of refuses. */
	CK(draft_uses_blocks(&E));
	E.dr.n_grp = 0;
	CK(!draft_uses_blocks(&E));
}

int main(void)
{
	reading();
	rewriting();
	switching();
	canon();
	emitting();
	joining();
	view_inputs();
	operator_word();
	block_indices();

	printf("condition expressions: read, rewrite, switch, canon, emit, "
	       "joins, view inputs, the operator word, block indices%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
