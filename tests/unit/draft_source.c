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

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	two_calls_one_line();
	two_calls_or();

	if (fails) {
		printf("draft source: %d check(s) failed\n", fails);
		return 1;
	}
	printf("draft source: two calls on one line, and or - ok\n");
	return 0;
}
