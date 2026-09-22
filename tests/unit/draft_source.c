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
	unlink(path);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	two_calls_one_line();
	two_calls_or();
	src_sees_blocks();
	mixed_rule();

	if (fails) {
		printf("draft source: %d check(s) failed\n", fails);
		return 1;
	}
	printf("draft source: two calls on one line, or, block index, mixed rule - ok\n");
	return 0;
}
