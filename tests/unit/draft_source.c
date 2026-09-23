/*
 * draft_source - a signature source read back into the draft it came from.
 *
 * The property under test: what generate() can WRITE, draft_from_source can
 * READ. The two are separate walks over one file format and nothing at run time
 * compares them, so a shape the writer learned and the reader did not is a rule
 * that opens as less than itself - and then Save writes that less back over the
 * whole.
 *
 * That happened: the panel can put two matchers in one condition, the writer
 * emits them as "if (A && B)" on one line, and the reader took only the first
 * call on a line. A four-marker webshell rule opened with one matcher, its
 * other three markers attached to nothing, and the "&" gone from the condition.
 *
 * The editor borrows its tables from the host - see struct kof_editor - so a
 * test over it has to lend it some. They are the smallest that let the reader
 * run; nothing here reads them back.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

#include "../../kofexamine/kofeditor.h"
#include "../../kofexamine/kofinspect.h"

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

/* The host's side of the editor, lent to it for the duration. */
static struct object   g_obj[2];
static uint32_t        g_n_obj = 1;
static uint32_t        g_foreign;
static uint32_t        g_foreign_w;
static char            g_sample[8][128];
static uint32_t        g_n_sample;
static char            g_who[8][48];
static uint32_t        g_n_who;
static char            g_made[2][24];
static struct kof_range g_scratch[KOF_SCAN_MAX_EXTENTS];

static void lend(struct kof_editor *e)
{
	memset(e, 0, sizeof *e);
	memset(g_obj, 0, sizeof g_obj);
	g_n_obj = 1;
	g_n_sample = g_n_who = 0;
	e->obj       = g_obj;
	e->n_obj     = &g_n_obj;
	e->foreign   = &g_foreign;
	e->foreign_w = &g_foreign_w;
	e->basedir   = "bases";
	e->path      = "sample";
	e->sample    = g_sample;
	e->n_sample  = &g_n_sample;
	e->who       = g_who;
	e->n_who     = &g_n_who;
	e->made      = g_made;
	e->scratch   = g_scratch;
}

static const char *write_tmp(const char *body)
{
	static char path[64];
	FILE *f;

	snprintf(path, sizeof path, "/tmp/kof_draft_src_%d.c", (int)getpid());
	f = fopen(path, "w");
	if (!f)
		return NULL;
	fputs(body, f);
	fclose(f);
	return path;
}

/*
 * TWO CALLS ON ONE LINE ARE TWO MATCHERS, and the condition names both.
 *
 * The shape generate() writes for one condition over two matchers. Read as one
 * matcher it is a different rule: the markers of the second are declared and
 * used by nothing, which is also what the panel shows as a marker with no
 * region.
 */
static void two_calls_one_line(void)
{
	static const char src[] =
		"#include <kofmod/kofsig.h>\n"
		"KOF_TARGET_FORMAT(KOF_FMT_SCRIPT);\n"
		"KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, \"Twoline\");\n"
		"KOF_TARGET_RANGE(scan_range_whole_file, KOF_SCAN_ALL);\n"
		"KOF_DEFINE_STR(s0, \"alpha\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"KOF_DEFINE_STR(s1, \"bravo\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"KOF_DEFINE_STR(s2, \"delta\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"void kof_scan(const struct kof_obj_ctx *ctx)\n"
		"{\n"
		"\tif (kof_find_str_any(scan_range_whole_file, s0) && "
		"kof_find_str_any(scan_range_whole_file, s1, s2))\n"
		"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
		"}\n";
	struct kof_editor e;
	const char *path = write_tmp(src);

	if (!path) {
		printf("  (no temporary file - nothing tested)\n");
		return;
	}
	lend(&e);
	CK(draft_from_source(&e, path) != 0);
	CK(e.dr.n_decl == 3);
	CK(e.dr.n_grp == 2);
	CK(e.dr.n_cnd == 1);
	if (e.dr.n_cnd)
		EQ(e.dr.cnd[0].expr, "1&2");
	/* Every marker belongs to a matcher - one with none is a marker the
	 * panel can show no region for. */
	if (e.dr.n_decl == 3) {
		CK(e.dr.decl[0].grp == 1u);
		CK(e.dr.decl[1].grp == 2u);
		CK(e.dr.decl[2].grp == 2u);
	}
	/*
	 * draft_clear, NOT just unlink. A draft's literals are heap buffers and
	 * the editor frees them exactly here; a test that skipped it leaked one
	 * per KOF_DEFINE_STR it parsed and `make unit-asan` said so - 30 bytes
	 * across the three functions that do this.
	 */
	draft_clear(&e);
	unlink(path);
}

/* And the same shape with "or" between them, which is the other operator the
 * row can be switched to and the writer can emit. */
static void two_calls_or(void)
{
	static const char src[] =
		"#include <kofmod/kofsig.h>\n"
		"KOF_TARGET_FORMAT(KOF_FMT_SCRIPT);\n"
		"KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, \"Orline\");\n"
		"KOF_TARGET_RANGE(scan_range_whole_file, KOF_SCAN_ALL);\n"
		"KOF_DEFINE_STR(s0, \"alpha\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"KOF_DEFINE_STR(s1, \"bravo\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"void kof_scan(const struct kof_obj_ctx *ctx)\n"
		"{\n"
		"\tif (kof_find_str_any(scan_range_whole_file, s0) || "
		"kof_find_str_any(scan_range_whole_file, s1))\n"
		"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
		"}\n";
	struct kof_editor e;
	const char *path = write_tmp(src);

	if (!path)
		return;
	lend(&e);
	CK(draft_from_source(&e, path) != 0);
	CK(e.dr.n_grp == 2);
	if (e.dr.n_cnd) {
		CK(e.dr.cnd[0].op == 1);
		EQ(e.dr.cnd[0].expr, "1|2");
	}
	/*
	 * draft_clear, NOT just unlink. A draft's literals are heap buffers and
	 * the editor frees them exactly here; a test that skipped it leaked one
	 * per KOF_DEFINE_STR it parsed and `make unit-asan` said so - 30 bytes
	 * across the three functions that do this.
	 */
	draft_clear(&e);
	unlink(path);
}

/*
 * A RULE MADE OF BLOCKS IS STILL A RULE THE INDEX HAS TO SEE.
 *
 * src_read read KOF_DEFINE_STR and nothing else, so a plague rule - which
 * declares no strings at all - was indexed as a file with zero patterns, and
 * draft_dup, which skipped any source with zero patterns, could not tell two
 * of them apart. Generating the same block twice raised no duplicate warning.
 */
static void src_sees_blocks(void)
{
	static const char src[] =
		"#include <kofmod/kofsig.h>\n"
		"#include <kofmod/kofplague.h>\n"
		"KOF_TARGET_FORMAT(KOF_FMT_ELF);\n"
		"KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, \"Blockly\");\n"
		"KOF_PLAGUE_BLOCK(blk_dded9322, KOF_SCAN_CODE, "
			"KOF_PLAGUE_RAW,\n"
		"\t0x00001000u, 0x00001111u, 0x00001222u, 0x00001333u, 0x00001444u, 0x00001555u, 0x00001666u, 0x00001777u, 0x00001888u, 0x00001999u, 0x00001aaau, 0x00001bbbu, 0x00001cccu, 0x00001dddu, 0x00001eeeu, 0x00001fffu);\n"
		"KOF_PLAGUE_BLOCK(blk_6fad1193, KOF_SCAN_CODE, "
			"KOF_PLAGUE_RAW,\n"
		"\t0x3333u, 0x4444u);\n"
		"void kof_scan(const struct kof_obj_ctx *ctx)\n"
		"{\n"
		"\tif (kof_plague_score(blk_dded9322) >= 60u)\n"
		"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
		"}\n";
	struct src_ent ent;
	const char *path = write_tmp(src);

	if (!path)
		return;
	memset(&ent, 0, sizeof ent);
	CK(src_read(path, &ent) != 0);
	CK(ent.n_blk == 2);
	/* The sum, so the order the two are declared in cannot change it. */
	CK(ent.blk == 0xdded9322u + 0x6fad1193u);
	/* And no pattern was invented out of a rule that declares none. */
	CK(ent.n_pat == 0);
	unlink(path);
}

/*
 * A RULE THAT DOES BOTH. The reader must not lose the half it was not looking
 * for: a string rule that also scores a block is one rule, and opening it has
 * to bring back the strings AND the blocks.
 */
static void mixed_rule(void)
{
	static const char src[] =
		"#include <kofmod/kofsig.h>\n"
		"#include <kofmod/kofplague.h>\n"
		"KOF_TARGET_FORMAT(KOF_FMT_ELF);\n"
		"KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, \"Mixy\");\n"
		"KOF_TARGET_RANGE(scan_range_whole_file, KOF_SCAN_ALL);\n"
		"KOF_DEFINE_STR(s0, \"alpha\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"KOF_PLAGUE_BLOCK(blk_dded9322, KOF_SCAN_CODE, "
			"KOF_PLAGUE_RAW,\n"
		"\t0x00001000u, 0x00001111u, 0x00001222u, 0x00001333u, 0x00001444u, 0x00001555u, 0x00001666u, 0x00001777u, 0x00001888u, 0x00001999u, 0x00001aaau, 0x00001bbbu, 0x00001cccu, 0x00001dddu, 0x00001eeeu, 0x00001fffu);\n"
		"void kof_scan(const struct kof_obj_ctx *ctx)\n"
		"{\n"
		"\tif (kof_find_str_any(scan_range_whole_file, s0) && "
		"kof_plague_score(blk_dded9322) >= 70u)\n"
		"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
		"}\n";
	struct kof_editor e;
	struct kof_plague_decl d[4];
	struct kof_verdict_decl verdict;
	static uint32_t pool[4 * KOF_PLAGUE_MAX_HASH];
	/* The three whole-object measures the same reader recovers. This rule
	 * names none of them, so they come back zero - which is the answer
	 * that says "the file did not ask for it". */
	uint8_t shp_pct = 0, str_pct = 0, blkv_pct = 0;
	int shp_lv = 0, str_lv = 0, blkv_lv = 0;
	uint32_t n = 0;
	uint8_t chain_pct = 0;
	int chain_lv = 0;
	const char *path = write_tmp(src);

	if (!path)
		return;
	lend(&e);
	/* The string half. */
	CK(draft_from_source(&e, path) != 0);
	CK(e.dr.n_decl == 1);
	CK(e.dr.n_grp == 1);
	EQ(e.dr.family, "Mixy");
	/* And the block half, off the same file. */
	CK(plague_from_source(&e, path, d, 4, &n, pool,
			      (uint32_t)(sizeof pool / sizeof pool[0]),
			      &verdict, &shp_pct, &shp_lv, &str_pct, &str_lv,
			      &blkv_pct, &blkv_lv, &chain_pct,
			      &chain_lv) != 0);
	CK(n == 1);
	if (n) {
		CK(d[0].id == 0xdded9322u);
		CK(d[0].n_hash == 16);
		CK(d[0].thr == 70);
	}
	CK(!shp_pct && !str_pct && !blkv_pct);
	/*
	 * draft_clear, NOT just unlink. A draft's literals are heap buffers and
	 * the editor frees them exactly here; a test that skipped it leaked one
	 * per KOF_DEFINE_STR it parsed and `make unit-asan` said so - 30 bytes
	 * across the three functions that do this.
	 */
	draft_clear(&e);
	unlink(path);
}

/*
 * WHERE AN AT MATCHER LOOKS, WHICH THE READER USED TO THROW AWAY.
 *
 * kof_find_str_at takes a place, and both AT rules in bases/ name it from the
 * entry point rather than as a file offset - an infector's stub is a fixed
 * step from the entry and is at a different offset in every build. The reader
 * ran strtoull over "ctx->entry_off + 236u", which has no leading digits, so
 * it produced 0 and reported nothing. The rule opened as "compare at offset
 * 0" and Save wrote that back: a different rule, silently.
 *
 * Both halves are checked here, because either one alone still loses it - a
 * reader that understands the text and a writer that cannot put it back is the
 * same corruption one step later.
 */
static void at_place_is_kept(void)
{
	static const char src[] =
		"#include <kofmod/kofsig.h>\n"
		"KOF_TARGET_FORMAT(KOF_FMT_ELF);\n"
		"KOF_TARGET_NAME(KOF_MALTYPE_VIRUS, \"Atplace\");\n"
		"KOF_TARGET_RANGE(scan_range_whole_file, KOF_SCAN_ALL);\n"
		"KOF_DEFINE_STR(s0, \"alpha\", KOF_CASE_EXACT, "
			"KOF_WORD_SUBSTRING);\n"
		"void kof_scan(const struct kof_obj_ctx *ctx)\n"
		"{\n"
		"\tif (kof_find_str_at(ctx->entry_off + 236u, s0))\n"
		"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
		"}\n";
	struct kof_editor e;
	const char *path = write_tmp(src);
	char txt[64];

	if (!path)
		return;
	lend(&e);
	CK(draft_from_source(&e, path) != 0);
	CK(e.dr.n_grp == 1);
	if (e.dr.n_grp) {
		CK(e.dr.grp[0].rule == 3);
		CK(e.dr.grp[0].at_base == GRP_AT_ENTRY);
		CK(e.dr.grp[0].at_off == 236);
		/* And back out as C, which is what Save writes. */
		grp_at_text(e.dr.grp[0].at_base, e.dr.grp[0].at_off,
			    txt, sizeof txt, 1);
		EQ(txt, "ctx->entry_off + 0xecu");
		/* And as the panel shows it, which has to be short and must
		 * not be a file offset the author would read as one. */
		grp_at_text(e.dr.grp[0].at_base, e.dr.grp[0].at_off,
			    txt, sizeof txt, 0);
		EQ(txt, "entry + 0xec");
	}
	draft_clear(&e);
	unlink(path);
}

/*
 * The three other shapes the first argument can take, read directly - a bare
 * base, a literal, and a step backwards. The parser is what the importer uses
 * and is the only thing that decides whether a shipped rule survives being
 * opened, so each form is pinned rather than assumed from the one above.
 */
static void at_place_forms(void)
{
	int b;
	int64_t off;
	char txt[64];

	/* A base on its own - rst_00.c, and the commonest form there is. */
	grp_at_parse("ctx->entry_off, s0", &b, &off);
	CK(b == GRP_AT_ENTRY);
	CK(off == 0);
	grp_at_text(b, off, txt, sizeof txt, 1);
	EQ(txt, "ctx->entry_off");          /* not "+ 0x0" */

	/* A plain number, which is what this field held before and still the
	 * default: an occurrence picked off the marker is an offset. */
	grp_at_parse("0x400, s0", &b, &off);
	CK(b == GRP_AT_ABS);
	CK(off == 0x400);

	/* Decimal too, because somebody typing one is not an error - the old
	 * reader took base 0 for this reason and that part was right. */
	grp_at_parse("1024, s0", &b, &off);
	CK(b == GRP_AT_ABS);
	CK(off == 1024);

	/* Backwards. The bytes before an entry are as much a marker as the
	 * bytes at it, and an unsigned field could not say so. */
	grp_at_parse("ctx->entry_off - 8u, s0", &b, &off);
	CK(b == GRP_AT_ENTRY);
	CK(off == -8);
	grp_at_text(b, off, txt, sizeof txt, 0);
	EQ(txt, "entry - 0x8");

	/* Written without the context name, which a hand-edited rule may be.
	 * Reading it as 0 is the fault being fixed, so it is tested. */
	grp_at_parse("entry_off + 2, s0", &b, &off);
	CK(b == GRP_AT_ENTRY);
	CK(off == 2);
}

/*
 * EVERY SHIPPED RULE, READ BACK, AND NONE OF THEM "CUSTOM LOGIC".
 *
 * The editor refuses Save on a rule whose body it could not model - it says
 * "Custom logic - Save As to derive a new rule from it" - and that refusal is
 * right when a rule really does carry hand-written code. It is a lie when the
 * reader merely failed to recognise something it was supposed to.
 *
 * The difference is invisible from inside: a line the reader did not model is
 * counted, not reported, so a reader that regressed looks exactly like a rule
 * that got cleverer. The invariant that separates them is WHICH rules may be
 * refused - a rule carrying kof_cure has a repair function written by hand, and
 * the panel has no cure section to hold it, so that one is refused honestly.
 * Every other rule in bases/ is written from the panel and must not be.
 *
 * It caught one: mirai_00.c is one kof_find_str_any and one verdict, and it was
 * refused because the paragraph break in its explanatory comment - an asterisk
 * with nothing after it - fell through the comment skip and was counted as
 * logic. See comment_blank in kofeditor.c.
 */
/* Does the source contain this text - used to ask whether a rule writes its own
 * repair, which is the one thing in bases/ the panel cannot hold. */
static int src_has(const char *path, const char *what)
{
	char line[1024];
	FILE *f = fopen(path, "r");
	int hit = 0;

	if (!f)
		return 0;
	while (!hit && fgets(line, sizeof line, f))
		hit = strstr(line, what) != NULL;
	fclose(f);
	return hit;
}

static void shipped_rules_are_all_modelled(void)
{
	static const char *dirs[] = { "bases/signatures", "bases/heur" };
	unsigned d;
	int read = 0, foreign = 0, cured = 0;

	for (d = 0; d < sizeof dirs / sizeof dirs[0]; d++) {
		DIR *dp = opendir(dirs[d]);
		struct dirent *de;

		if (!dp)
			continue;       /* run from elsewhere - nothing to say */
		while ((de = readdir(dp))) {
			char path[512];
			size_t n = strlen(de->d_name);
			struct kof_editor e;

			if (n < 3u || strcmp(de->d_name + n - 2u, ".c"))
				continue;
			snprintf(path, sizeof path, "%s/%s", dirs[d],
				 de->d_name);
			g_foreign = g_foreign_w = 0;
			lend(&e);
			if (draft_from_source(&e, path)) {
				int cures = src_has(path, "void kof_cure");

				read++;
				if (g_foreign_w && !cures) {
					printf("  FAIL %s - %u unmodelled "
					       "line(s), and it has no cure "
					       "to explain them\n",
					       path, g_foreign_w);
					foreign++;
				}
				if (cures)
					cured++;
			}
			draft_clear(&e);
		}
		closedir(dp);
	}
	if (!read) {
		printf("  (bases/ not beside the test - nothing read)\n");
		return;
	}
	CK(foreign == 0);
	printf("  %d shipped rule(s) read, %d carry a hand-written cure, "
	       "%d refused without one\n", read, cured, foreign);
}

/*
 * A HEX MARKER'S OPTIONS SURVIVE BEING OPENED.
 *
 * They are newer than the reader: a hex pattern could not carry a case or a
 * word option when draft_from_source was written, so the reader took them on
 * the literal branch and nowhere else. A rule declaring an ICASE hex marker
 * therefore opened as an exact-case one, and Generate wrote that back - the
 * option survives a build and does not survive being looked at, which loses it
 * silently and in the one direction nobody checks.
 *
 * Both spellings are read here, because the short form is what almost every
 * hex marker in bases/ uses and it has to keep meaning exactly what it meant.
 */
static void hex_options_survive(void)
{
	static const char src[] =
		"#include <kofmod/kofsig.h>\n"
		"KOF_TARGET_FORMAT(KOF_FMT_ELF);\n"
		"KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, \"Hexopt\");\n"
		"KOF_TARGET_RANGE(scan_range_whole_file, KOF_SCAN_ALL);\n"
		"KOF_DEFINE_HEXSTR(s0, \"63 6D 64\");\n"
		"KOF_DEFINE_HEXSTR(s1, \"63 6D 64\", KOF_CASE_ICASE, "
			"KOF_WORD_FULLWORD);\n"
		"void kof_scan(const struct kof_obj_ctx *ctx)\n"
		"{\n"
		"\tif (kof_find_str_any(scan_range_whole_file, s0, s1))\n"
		"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
		"}\n";
	struct kof_editor e;
	const char *path = write_tmp(src);

	if (!path)
		return;
	lend(&e);
	CK(draft_from_source(&e, path) != 0);
	CK(e.dr.n_decl == 2);
	if (e.dr.n_decl == 2) {
		/* The short form is exact case, matching anywhere - and that
		 * must not drift, because it is what bases/ is written in. */
		CK(e.dr.decl[0].hex == 1);
		CK(e.dr.decl[0].icase == 0);
		CK(e.dr.decl[0].fullword == KOF_WORD_SUBSTRING);
		/* And the long form keeps what it said. */
		CK(e.dr.decl[1].hex == 1);
		CK(e.dr.decl[1].icase == 1);
		CK(e.dr.decl[1].fullword == KOF_WORD_FULLWORD);
		/* The PATTERN text is kept verbatim either way: converting it
		 * the way a literal is converted turns "??" into a zero byte,
		 * which is a different pattern. */
		EQ(e.dr.decl[1].hexs, "63 6D 64");
	}
	draft_clear(&e);
	unlink(path);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	two_calls_one_line();
	two_calls_or();
	src_sees_blocks();
	mixed_rule();
	at_place_is_kept();
	at_place_forms();
	hex_options_survive();
	shipped_rules_are_all_modelled();

	if (fails) {
		printf("draft source: %d check(s) failed\n", fails);
		return 1;
	}
	printf("draft source: two calls on one line, or, block index, "
	       "mixed rule, at place, shipped rules - ok\n");
	return 0;
}
