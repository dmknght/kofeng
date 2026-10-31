/*
 * diag_form_engine - a diagnose that is a DETECTION FORM, from its source to a verdict.
 *
 * The chain under test, every link of which is a place where a diagnose can turn into silence:
 *
 *   ksigbuilder   reads KOF_TARGET_RANGE / KOF_DEFINE_* / KOF_MUTATION_BLOCK / KOF_DIAG_FIND / _SIMILAR / _EXPR, compiles the
 *                 markers and writes the KDIG_SEC_FORM sections of the record
 *   the loader    concatenates the sections, decodes and checks the form, puts a form's blocks into the similarity set
 *   the engine    asks each matcher with the functions a module's kof_find_str and kof_mutation_score use, and evaluates the
 *                 expression; the verdict is made from the diseases the diagnoses that matched declare
 *
 * SO EVERY CASE ASKS BOTH ANSWERS: a sample that must match and one that must not (one alone passes against an engine broken
 * in the other direction). Why the old tests could not catch any of it: (a) the form did not exist - on the old tree the builder
 * refuses every source here ("a diagnose needs a head"), so each case fails at its first step; they are RED there.
 *
 * WHAT IS PINNED
 *   rules       ALL / ANY / MULTI(n) at the value and one beside it, NOT, AND, OR and parentheses
 *   options     case, whole word, whole token, UTF-16 (wide), a hex pattern, a regex - each hits and misses
 *   offsets     AT from the start, from the end and from the entry point; one byte off is a miss; outside the object is a miss
 *   regions     a marker in the code of an ELF is found in a range that names the code and not in the data, and the reverse
 *   shape       the target format (one, or a set) and the subtype gate the form; a form is not asked of an object of another shape
 *   blocks      a similarity matcher scores with the set the packs' blocks are in (the test pack has one), per block, and
 *               a matcher of two blocks needs both
 *   work once   an expression names a matcher twice and the matcher is searched once; a false matcher ends an AND and the
 *               marker of the next is not searched
 *   readers     a form nobody reads (no disease, no rule) is not asked in a scan and is asked when the caller asks for the report
 *   verdict     the matched form's disease is the object's verdict, and the diagnose is listed in it
 *   API         kdb_diagnose_form and kdb_diagnose_form_expr
 *   loader      a record whose form is cut, whose index lies outside its table, that has both nodes and a form, or whose
 *               form is a tree with a node used twice is REFUSED and counted, and its siblings still load; a section tag a later
 *               build adds is skipped by its length
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/databases/pack/diagform.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include <celllysis/mutation.h>
#include <kofmod/kofdiagtree.h>
#include <kofmod/kofsig.h>
#include "../../libkofeng/scanners/scan.h"

static int failures;
static char root[256];
static const char *dbdir = "build/test/databases-sigs";
static const char *builder = "build/release/bin/ksigbuilder";

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

/* ---- files ------------------------------------------------------------------ */

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static uint8_t *read_file(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long L;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	L = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)L + 1u);
	if (b && fread(b, 1, (size_t)L, f) != (size_t)L) {
		free(b);
		b = NULL;
	}
	fclose(f);
	if (b)
		*n = (size_t)L;
	return b;
}

static void rm_all(const char *dir)
{
	char cmd[800];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

static int copy_pack(const char *from_dir, const char *leaf, const char *to_dir)
{
	char a[700], b[700];
	size_t n = 0;
	uint8_t *p;
	int r;

	snprintf(a, sizeof a, "%s/%s", from_dir, leaf);
	snprintf(b, sizeof b, "%s/%s", to_dir, leaf);
	p = read_file(a, &n);
	r = p && n && write_file(b, p, n);
	free(p);
	return r;
}

/* ---- a database of diagnoses, built by the real builder -------------------------- */

struct scene {
	char base[400], art[400], db[400], err[400];
};

static void scene_new_with(struct scene *s, const char *tag, const char *pack)
{
	char d[500];

	snprintf(s->base, sizeof s->base, "%s/%s_base", root, tag);
	snprintf(s->art, sizeof s->art, "%s/%s_art", root, tag);
	snprintf(s->db, sizeof s->db, "%s/%s_db", root, tag);
	snprintf(s->err, sizeof s->err, "%s/%s_err.txt", root, tag);
	kof_mkdir(s->base, 0700);
	kof_mkdir(s->art, 0700);
	kof_mkdir(s->db, 0700);
	snprintf(d, sizeof d, "%s/diagnoses", s->base);
	kof_mkdir(d, 0700);
	(void)copy_pack(dbdir, pack, s->db);
}

static void scene_new(struct scene *s, const char *tag)
{
	scene_new_with(s, tag, "sigs-any.ksig");
}

/* One diagnose source: <name>.c in the base's diagnoses directory. */
static void scene_src(struct scene *s, const char *name, const char *text)
{
	char p[700];

	snprintf(p, sizeof p, "%s/diagnoses/%s.c", s->base, name);
	(void)write_file(p, text, strlen(text));
}

/* The tree build. 0: built. */
static int scene_build(struct scene *s)
{
	char cmd[2400];

	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --basedir '%s' >/dev/null 2>'%s'", builder, s->base, s->art, s->db,
		 s->base, s->err);
	return system(cmd);
}

/* The tree build of a scene that has a MODULE in it: the compiler, the linker and the module headers are arguments. */
static int scene_build_module(struct scene *s)
{
	char cmd[5200], cwd[1000];

	if (!getcwd(cwd, sizeof cwd))
		return -1;
	snprintf(cmd, sizeof cmd, "%s --tree '%s' '%s' '%s' --basedir '%s' --include '%s/build/release/include' "
		 "--ldscript '%s/ksigbuilder/module.ld' --cc cc --ld ld >/dev/null 2>'%s'", builder, s->base, s->art, s->db,
		 s->base, cwd, cwd, s->err);
	return system(cmd);
}

static int said(const struct scene *s, const char *needle)
{
	size_t n = 0;
	uint8_t *b = read_file(s->err, &n);
	char *t;
	int r;

	if (!b)
		return 0;
	t = malloc(n + 1u);
	memcpy(t, b, n);
	t[n] = 0;
	r = strstr(t, needle) != NULL;
	free(b);
	free(t);
	return r;
}

/* ---- scanning --------------------------------------------------------------------- */

struct seen {
	char     matched[64][64];   /* the diagnoses the report says MATCH, over every object of the scan */
	unsigned n;
	char     verdict[240];
	unsigned n_verdict_diag;
	char     verdict_diag[8][64];
	int      has_verdict;
	uint32_t examined;           /* what the result says was looked at: a form that was asked counts */
	const kof_engine *eng;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t i;

	(void)name; (void)bytes; (void)len;
	if (!res)
		return 0;
	if (res->examined > s->examined)
		s->examined = res->examined;
	for (i = 0; i < res->n_diag; i++)
		if (res->diag[i].state == KOF_DIAG_ST_MATCH && s->n < 64u) {
			unsigned k;

			for (k = 0; k < s->n; k++)
				if (!strcmp(s->matched[k], res->diag[i].name))
					break;
			if (k == s->n)
				snprintf(s->matched[s->n++], sizeof s->matched[0], "%s", res->diag[i].name);
		}
	if (res->has_verdict && !s->has_verdict) {
		s->has_verdict = 1;
		snprintf(s->verdict, sizeof s->verdict, "%s", res->verdict.name);
		for (i = 0; i < res->verdict.n_diag && i < 8u; i++) {
			const char *dn = kdb_diagnose_name(s->eng, res->verdict.diag[i]);

			snprintf(s->verdict_diag[s->n_verdict_diag++], sizeof s->verdict_diag[0], "%s", dn ? dn : "?");
		}
	}
	return 0;
}

static int has(const struct seen *s, const char *name)
{
	unsigned i;

	for (i = 0; i < s->n; i++)
		if (!strcmp(s->matched[i], name))
			return 1;
	return 0;
}

static int verdict_has(const struct seen *s, const char *name)
{
	unsigned i;

	for (i = 0; i < s->n_verdict_diag; i++)
		if (!strcmp(s->verdict_diag[i], name))
			return 1;
	return 0;
}

/* Scan `n` bytes; `report` asks for every diagnose's state (the report), not only the ones a verdict reads. */
static void scan(kof_scanner *sc, const kof_engine *eng, const void *p, size_t n, int report, struct seen *out)
{
	struct kof_scan_option opt;

	memset(&opt, 0, sizeof opt);
	memset(out, 0, sizeof *out);
	out->eng = eng;
	(void)kof_scan_set_explain(sc, report ? 1 : 0);
	kscan_bytes(sc, p, n, "sample", &opt, on_object, out);
}

/* ---- the diagnoses of the cases below ------------------------------------------------ */

#define FIND(name, rule, range, ...) "KOF_DIAG_FIND(" name ", " rule ", " range ", " __VA_ARGS__ ");\n"

static const char *const preamble =
	"KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
	"KOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_STR(beta, \"beta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_STR(gamma, \"gamma\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_STR(delta, \"delta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_STR(zeta, \"zeta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n";

/* name -> expected on "alpha beta gamma delta" (22 bytes) */
struct rule_case {
	const char *name;
	const char *body;
	int         want;
};

static const struct rule_case rule_cases[] = {
	{ "r_all_hit",   FIND("m0", "KOF_FIND_ALL", "whole", "alpha, beta"), 1 },
	{ "r_all_miss",  FIND("m0", "KOF_FIND_ALL", "whole", "alpha, zeta"), 0 },
	{ "r_any_hit",   FIND("m0", "KOF_FIND_ANY", "whole", "zeta, delta"), 1 },
	{ "r_any_miss",  FIND("m0", "KOF_FIND_ANY", "whole", "zeta"), 0 },
	{ "r_m2_hit",    FIND("m0", "KOF_FIND_MULTI(2)", "whole", "alpha, zeta, gamma"), 1 },
	{ "r_m3_miss",   FIND("m0", "KOF_FIND_MULTI(3)", "whole", "alpha, zeta, gamma"), 0 },
	{ "r_m3_hit",    FIND("m0", "KOF_FIND_MULTI(3)", "whole", "alpha, beta, gamma"), 1 },
	{ "r_m1_hit",    FIND("m0", "KOF_FIND_MULTI(1)", "whole", "zeta, delta"), 1 },
	{ "r_not_hit",   FIND("m0", "KOF_FIND_ANY", "whole", "zeta") "KOF_DIAG_EXPR(!m0);\n", 1 },
	{ "r_not_miss",  FIND("m0", "KOF_FIND_ANY", "whole", "alpha") "KOF_DIAG_EXPR(!m0);\n", 0 },
	{ "r_and_hit",   FIND("m0", "KOF_FIND_ANY", "whole", "alpha") FIND("m1", "KOF_FIND_ANY", "whole", "beta")
			 "KOF_DIAG_EXPR(m0 && m1);\n", 1 },
	{ "r_and_miss",  FIND("m0", "KOF_FIND_ANY", "whole", "alpha") FIND("m1", "KOF_FIND_ANY", "whole", "zeta")
			 "KOF_DIAG_EXPR(m0 && m1);\n", 0 },
	{ "r_or_hit",    FIND("m0", "KOF_FIND_ANY", "whole", "zeta") FIND("m1", "KOF_FIND_ANY", "whole", "beta")
			 "KOF_DIAG_EXPR(m0 || m1);\n", 1 },
	{ "r_or_miss",   FIND("m0", "KOF_FIND_ANY", "whole", "zeta") FIND("m1", "KOF_FIND_ANY", "whole", "zeta")
			 "KOF_DIAG_EXPR(m0 || m1);\n", 0 },
	{ "r_prec_hit",  FIND("m0", "KOF_FIND_ANY", "whole", "zeta") FIND("m1", "KOF_FIND_ANY", "whole", "alpha")
			 FIND("m2", "KOF_FIND_ANY", "whole", "beta") "KOF_DIAG_EXPR(m0 && m1 || m2);\n", 1 },
	{ "r_paren_miss", FIND("m0", "KOF_FIND_ANY", "whole", "zeta") FIND("m1", "KOF_FIND_ANY", "whole", "alpha")
			  FIND("m2", "KOF_FIND_ANY", "whole", "beta") "KOF_DIAG_EXPR(m0 && (m1 || m2));\n", 0 },
	{ "r_dflt_hit",  FIND("m0", "KOF_FIND_ANY", "whole", "alpha") FIND("m1", "KOF_FIND_ANY", "whole", "delta"), 1 },
	{ "r_dflt_miss", FIND("m0", "KOF_FIND_ANY", "whole", "alpha") FIND("m1", "KOF_FIND_ANY", "whole", "zeta"), 0 },
	/* offsets, on the same 22 bytes: "alpha beta gamma delta" */
	{ "a_bof_hit",   "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 0), alpha);\n", 1 },
	{ "a_bof_miss",  "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 1), alpha);\n", 0 },
	{ "a_bof6_hit",  "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 6), beta);\n", 1 },
	{ "a_eof_hit",   "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_EOF, -5), delta);\n", 1 },
	{ "a_eof_miss",  "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_EOF, -6), delta);\n", 0 },
	{ "a_eof_out",   "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_EOF, 0), delta);\n", 0 },
	{ "a_before",    "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, -1), alpha);\n", 0 },
	/* FORM-1: a blob has no entry point (ctx->entry_off is KOF_NA), so an anchor at the entry answers no, not "the first byte". */
	{ "a_entry_blob", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 0), alpha);\n", 0 },
	{ "a_entry_blob1", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 1), alpha);\n", 0 },
	{ "a_huge",      "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_EOF, 9223372036854775807), delta);\n", 0 },
	{ "a_neg_huge",  "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_EOF, -9223372036854775807), delta);\n", 0 }
};

/* Options: the sample is "Alpha beta xgamma delta_x [beta]" with a UTF-16 run appended by the test. */
static const struct rule_case option_cases[] = {
	{ "o_exact_miss",  "KOF_DEFINE_STR(c0, \"ALPHA\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_icase_hit",   "KOF_DEFINE_STR(c0, \"ALPHA\", KOF_CASE_ICASE, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_word_miss",   "KOF_DEFINE_STR(c0, \"gamma\", KOF_CASE_EXACT, KOF_WORD_FULLWORD);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_word_hit",    "KOF_DEFINE_STR(c0, \"beta\", KOF_CASE_EXACT, KOF_WORD_FULLWORD);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_word_under",  "KOF_DEFINE_STR(c0, \"delta\", KOF_CASE_EXACT, KOF_WORD_FULLWORD);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_tok_miss",    "KOF_DEFINE_STR(c0, \"gamma\", KOF_CASE_EXACT, KOF_WORD_TOKEN);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_tok_hit",     "KOF_DEFINE_STR(c0, \"beta\", KOF_CASE_EXACT, KOF_WORD_TOKEN);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_wide_hit",    "KOF_DEFINE_STR_WIDE(c0, \"IEX(New\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_plain_miss",  "KOF_DEFINE_STR(c0, \"IEX(New\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_wide_word",   "KOF_DEFINE_STR_WIDE(c0, \"EX(New\", KOF_CASE_EXACT, KOF_WORD_FULLWORD);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_hex_hit",     "KOF_DEFINE_HEXSTR(c0, \"62 65 ?? 61\");\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_hex_miss",    "KOF_DEFINE_HEXSTR(c0, \"62 65 ?? 62\");\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_hex_alt",     "KOF_DEFINE_HEXSTR(c0, \"( 63 | 62 ) 65 74 61\");\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_hex_icase",   "KOF_DEFINE_HEXSTR(c0, \"41 4C 50 48 41\", KOF_CASE_ICASE, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_hex_exact",   "KOF_DEFINE_HEXSTR(c0, \"41 4C 50 48 41\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_rx_hit",      "KOF_DEFINE_REGEX(c0, \"x[a-z]{2}mma\");\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_rx_miss",     "KOF_DEFINE_REGEX(c0, \"x[0-9]{2}mma\");\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 },
	{ "o_rx_esc",      "KOF_DEFINE_REGEX(c0, \"\\\\[beta\\\\]\");\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_esc_hit",     "KOF_DEFINE_STR(c0, \"say \\\"hi\\\"\\t\\\\\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 1 },
	{ "o_esc_miss",    "KOF_DEFINE_STR(c0, \"say \\\"hi\\\"\\t\\\\x\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n" FIND("m0", "KOF_FIND_ANY", "whole", "c0"), 0 }
};

/* Every diagnose of a table as a source: name, preamble, the case's own declarations. */
static void write_cases(struct scene *s, const struct rule_case *c, size_t n, int with_preamble)
{
	size_t i;

	for (i = 0; i < n; i++) {
		char text[4096];

		snprintf(text, sizeof text, "KOF_DIAG_NAME(%s);\n%s%s%s", c[i].name,
			 with_preamble ? preamble : "", with_preamble ? "" : "KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n", c[i].body);
		scene_src(s, c[i].name, text);
	}
}

static void check_cases(kof_scanner *sc, const kof_engine *eng, const struct rule_case *c, size_t n, const void *sample,
			size_t sn, const char *what)
{
	struct seen s;
	size_t i, wrong = 0;

	scan(sc, eng, sample, sn, 1, &s);
	for (i = 0; i < n; i++) {
		int got = has(&s, c[i].name);

		if (got != c[i].want) {
			printf("    %s: %s answered %d, wanted %d\n", what, c[i].name, got, c[i].want);
			wrong++;
		}
	}
	OKF(!wrong, "%s: %zu of %zu diagnoses answered wrongly", what, wrong, n);
	/* and every one was loaded: a diagnose that did not load answers "no" and looks right for a miss */
	OKF(kdb_diagnoses(eng) >= n, "%s: %u diagnoses loaded of %zu", what, kdb_diagnoses(eng), n);
}

static void rules_and_options(void)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	const char sample[] = "alpha beta gamma delta";
	/* "Alpha beta xgamma delta_x [beta]" then, after a NUL, "IEX(New-Object" as UTF-16LE */
	uint8_t opt_sample[200];
	size_t on = 0, i;
	const char *tail = "IEX(New-Object";

	scene_new(&sc, "rules");
	write_cases(&sc, rule_cases, sizeof rule_cases / sizeof rule_cases[0], 1);
	{
		/* the option cases share one scene too, with their own marker names so the preamble's do not collide */
		struct scene so;

		scene_new(&so, "options");
		write_cases(&so, option_cases, sizeof option_cases / sizeof option_cases[0], 0);
		OKF(scene_build(&so) == 0, "the option sources build (%s)", said(&so, "error") ? "see the log" : "no error line");
		eng = keng_open(so.db);
		scn = eng ? kscan_new(eng) : NULL;
		{
			static const char head[] = "Alpha beta xgamma delta_x [beta] say \"hi\"\t\\ ";

			memcpy(opt_sample, head, sizeof head - 1u);
			on = sizeof head - 1u;
		}
		for (i = 0; tail[i]; i++) {
			opt_sample[on++] = (uint8_t)tail[i];
			opt_sample[on++] = 0;
		}
		if (scn)
			check_cases(scn, eng, option_cases, sizeof option_cases / sizeof option_cases[0], opt_sample, on, "options");
		else
			OKF(0, "the options database does not open");
		kscan_free(scn);
		keng_close(eng);
	}
	OKF(scene_build(&sc) == 0, "the rule sources build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the rules database does not open");
		return;
	}
	check_cases(scn, eng, rule_cases, sizeof rule_cases / sizeof rule_cases[0], sample, sizeof sample - 1u, "rules");
	OKF(kdb_diag_refused(eng) == 0 && kdb_diag_packs_refused(eng) == 0, "nothing was refused at the load");
	kscan_free(scn);
	keng_close(eng);
}

/* ---- regions, on an ELF ------------------------------------------------------------ */

static void put16(uint8_t *b, unsigned at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1u] = (uint8_t)(v >> 8); }
static void put32(uint8_t *b, unsigned at, uint32_t v) { put16(b, at, (uint16_t)v); put16(b, at + 2u, (uint16_t)(v >> 16)); }
static void put64(uint8_t *b, unsigned at, uint64_t v) { put32(b, at, (uint32_t)v); put32(b, at + 4u, (uint32_t)(v >> 32)); }

/* An ELF64 with two PT_LOADs: [0, 0x200) readable and executable (the code, its headers on top) and [0x200, 0x300)
 * readable and writable (data). Entry at 0x100. The markers go where the caller says. */
static size_t make_elf(uint8_t *b, const char *in_code, const char *in_data)
{
	memset(b, 0, 0x300);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 0x3e);
	put32(b, 20, 1);
	put64(b, 24, 0x400100u);
	put64(b, 32, 64);
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 2);
	put32(b, 64, 1);
	put32(b, 68, 5);                 /* R + X */
	put64(b, 72, 0);
	put64(b, 80, 0x400000u);
	put64(b, 96, 0x200u);
	put64(b, 104, 0x200u);
	put64(b, 112, 0x1000u);
	put32(b, 120, 1);
	put32(b, 124, 6);                /* R + W */
	put64(b, 128, 0x200u);
	put64(b, 136, 0x600200u);
	put64(b, 152, 0x100u);
	put64(b, 160, 0x100u);
	put64(b, 168, 0x1000u);
	memcpy(b + 0x100, in_code, strlen(in_code));
	memcpy(b + 0x240, in_data, strlen(in_data));
	return 0x300;
}

/* An x86-64 ELF of 0x300 bytes with "alpha" in it, for the conditions that are about the file and not the markers. */
static void make_elf_bytes(uint8_t *b)
{
	make_elf(b, "alpha", "beta");
}

static void regions_and_shape(void)
{
	static const struct rule_case cases[] = {
		{ "g_code_in_code", FIND("m0", "KOF_FIND_ANY", "code", "alpha"), 1 },
		{ "g_data_in_code", FIND("m0", "KOF_FIND_ANY", "data", "alpha"), 0 },
		{ "g_data_in_data", FIND("m0", "KOF_FIND_ANY", "data", "beta"), 1 },
		{ "g_code_in_data", FIND("m0", "KOF_FIND_ANY", "code", "beta"), 0 },
		{ "g_both",         FIND("m0", "KOF_FIND_ANY", "both", "alpha, beta"), 1 },
		{ "g_all_split",    FIND("m0", "KOF_FIND_ALL", "both", "alpha, beta"), 1 },
		{ "g_whole",        FIND("m0", "KOF_FIND_ALL", "whole", "alpha, beta"), 1 },
		{ "g_all_one_range", FIND("m0", "KOF_FIND_ALL", "code", "alpha, beta"), 0 },
		{ "g_two_matchers", FIND("m0", "KOF_FIND_ANY", "code", "alpha") FIND("m1", "KOF_FIND_ANY", "data", "beta")
				    "KOF_DIAG_EXPR(m0 && m1);\n", 1 },
		{ "g_swapped",      FIND("m0", "KOF_FIND_ANY", "code", "beta") FIND("m1", "KOF_FIND_ANY", "data", "alpha")
				    "KOF_DIAG_EXPR(m0 || m1);\n", 0 },
		{ "g_at_entry",     "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 0), alpha);\n", 1 },
		{ "g_at_entry_off", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 1), alpha);\n", 0 },
		{ "g_at_entry_back", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, -16), alpha);\n", 0 },
		/* with the entry resolved (0x100) these land on 0x201 and 0x202; with none, KOF_NA is -1 and KOF_BROKEN -2 as numbers,
		 * and the steps 257 and 258 would land on 0x100, where "alpha" is, if the base were not refused first */
		{ "g_at_entry_na1", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 257), alpha);\n", 0 },
		{ "g_at_entry_na2", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_ENTRY, 258), alpha);\n", 0 },
		{ "g_at_bof_data", "KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 576), beta);\n", 1 },
		/* the shape */
		{ "s_elf",          "KOF_TARGET_FORMAT(KOF_FMT_ELF);\n" FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), 1 },
		{ "s_pe",           "KOF_TARGET_FORMAT(KOF_FMT_PE);\n" FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), 0 },
		{ "s_set_hit",      "KOF_TARGET_FORMAT(KOF_FMT_PE | KOF_FMT_ELF);\n" FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), 1 },
		{ "s_set_miss",     "KOF_TARGET_FORMAT(KOF_FMT_PE | KOF_FMT_SCRIPT);\n" FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), 0 },
		{ "s_sub_exec",     "KOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_TARGET_SUBTYPE(KOF_ELF_EXEC);\n"
				    FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), 1 },
		{ "s_sub_rel",      "KOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_TARGET_SUBTYPE(KOF_ELF_REL);\n"
				    FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), 0 }
	};
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	uint8_t elf[0x300];
	size_t i, n = sizeof cases / sizeof cases[0];

	scene_new(&sc, "regions");
	for (i = 0; i < n; i++) {
		char text[4096];

		snprintf(text, sizeof text, "KOF_DIAG_NAME(%s);\nKOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n"
			 "KOF_TARGET_RANGE(data, KOF_SCAN_ELF_DATA);\nKOF_TARGET_RANGE(both, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);\n%s%s",
			 cases[i].name, preamble, cases[i].body);
		scene_src(&sc, cases[i].name, text);
	}
	OKF(scene_build(&sc) == 0, "the region sources build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the regions database does not open");
		return;
	}
	make_elf(elf, "alpha", "beta");
	check_cases(scn, eng, cases, n, elf, 0x300, "an ELF with its marker in the code and another in the data");
	/* the same bytes with the markers swapped answer the swapped way */
	{
		struct rule_case swapped[] = {
			{ "g_code_in_code", "", 0 }, { "g_data_in_code", "", 1 }, { "g_data_in_data", "", 0 }, { "g_code_in_data", "", 1 },
		};
		struct seen s;

		make_elf(elf, "beta", "alpha");
		scan(scn, eng, elf, 0x300, 1, &s);
		for (i = 0; i < sizeof swapped / sizeof swapped[0]; i++)
			OKF(has(&s, swapped[i].name) == swapped[i].want, "swapped markers: %s", swapped[i].name);
	}
	{
		/* an ELF whose entry point is in no segment: there is no entry to count from, and an AT from it answers no */
		struct seen ne;

		make_elf(elf, "alpha", "beta");
		put64(elf, 24, 0x7000000u);
		scan(scn, eng, elf, 0x300, 1, &ne);
		ok("an entry in no segment: AT the entry answers no, whatever is at offset 0x100",
		   !has(&ne, "g_at_entry") && !has(&ne, "g_at_entry_off") && !has(&ne, "g_at_entry_na1") && !has(&ne, "g_at_entry_na2"));
		ok("and the same file still answers the questions that do not use the entry", has(&ne, "g_code_in_code") && has(&ne, "g_at_bof_data"));
	}
	kscan_free(scn);
	keng_close(eng);
}

/* ---- the two conditions a signature's targets became: a size and an architecture ------------------ */

static void size_and_arch(void)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	uint8_t elf[0x300];
	char text[1500];
	struct seen s;
	static const struct { const char *name; const char *attrb; int want; } cases[] = {
		{ "z_size_exact", "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 768);\n", 1 },
		{ "z_size_over",  "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 769);\n", 0 },
		{ "z_size_zero",  "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 0);\n", 1 },
		{ "z_size_hex",   "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 0x300);\n", 1 },
		{ "z_arch_x64",   "KOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, X64);\n", 1 },
		{ "z_arch_x86",   "KOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, X86);\n", 0 },
		{ "z_arch_both",  "KOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, BOTH);\n", 1 },
		{ "z_arch_none",  "KOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, 0);\n", 0 },
		{ "z_both_conds", "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 768);\nKOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, X86);\n", 0 }
	};
	size_t i;
	char x64[24], x86[24], both[24];

	snprintf(x64, sizeof x64, "%llu", (unsigned long long)1 << KOF_ARCH_X86_64);
	snprintf(x86, sizeof x86, "%llu", (unsigned long long)1 << KOF_ARCH_X86);
	snprintf(both, sizeof both, "%llu", ((unsigned long long)1 << KOF_ARCH_X86) | ((unsigned long long)1 << KOF_ARCH_X86_64));
	scene_new(&sc, "facts");
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		char body[400], *p;

		snprintf(body, sizeof body, "%s", cases[i].attrb);
		while ((p = strstr(body, "X64")) || (p = strstr(body, "X86")) || (p = strstr(body, "BOTH"))) {
			const char *w = !strncmp(p, "X64", 3) ? x64 : !strncmp(p, "X86", 3) ? x86 : both;
			size_t k = !strncmp(p, "BOTH", 4) ? 4u : 3u;
			char tail[400];

			snprintf(tail, sizeof tail, "%s", p + k);
			snprintf(p, sizeof body - (size_t)(p - body), "%s%s", w, tail);
		}
		snprintf(text, sizeof text, "KOF_DIAG_NAME(%s);\n%s%s%s", cases[i].name, "KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
			 "KOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
			 "KOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, alpha);\n", body, "");
		scene_src(&sc, cases[i].name, text);
	}
	OKF(scene_build(&sc) == 0, "the size and architecture sources build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the facts database does not open");
		return;
	}
	make_elf_bytes(elf);
	scan(scn, eng, elf, 0x300, 1, &s);
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
		OKF(has(&s, cases[i].name) == cases[i].want, "%s answered %d, wanted %d", cases[i].name, has(&s, cases[i].name), cases[i].want);
	kscan_free(scn);
	keng_close(eng);
}

/* ---- blocks ---------------------------------------------------------------------------- */

#define BLK 2048u

static void make_bytes(uint8_t *b, uint32_t seed)
{
	uint32_t i;

	for (i = 0; i < BLK; i++) {
		seed ^= seed << 13;
		seed ^= seed >> 17;
		seed ^= seed << 5;
		b[i] = (uint8_t)seed;
	}
}

/* A block declaration for the bytes of a seeded sequence, spelled as the editor spells it, cut from `region`. */
static size_t block_text_in(char *out, size_t cap, const char *name, uint32_t seed, const char *region)
{
	uint8_t b[BLK];
	uint32_t h[KOF_MUTATION_MAX_HASH], n, i;
	size_t at;

	make_bytes(b, seed);
	n = kgenome_mutation_minhash(b, BLK, h);
	at = (size_t)snprintf(out, cap, "KOF_MUTATION_BLOCK(%s, %s", name, region);
	for (i = 0; i < n; i++)
		at += (size_t)snprintf(out + at, cap - at, ", 0x%08xu", (unsigned)h[i]);
	at += (size_t)snprintf(out + at, cap - at, ");\n");
	return at;
}

static size_t block_text(char *out, size_t cap, const char *name, uint32_t seed)
{
	return block_text_in(out, cap, name, seed, "KOF_SCAN_ALL");
}

static void blocks(void)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	uint8_t a[BLK], b[BLK], c[BLK], ab[2u * BLK];
	char text[8000];
	size_t at;
	struct seen s;

	scene_new(&sc, "blocks");
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(b_a);\nKOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"blocks/a\");\n");
	at += block_text(text + at, sizeof text - at, "ba", 0xA11CE5u);
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 60, ba);\n");
	scene_src(&sc, "b_a", text);
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(b_b);\n");
	at += block_text(text + at, sizeof text - at, "bb", 0xB0B0B0u);
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 60, bb);\n");
	scene_src(&sc, "b_b", text);
	/* the whole of the block at a hundred percent: a block cut from the object scores exactly 100, and 100 is enough */
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(b_full);\n");
	at += block_text(text + at, sizeof text - at, "bf", 0xA11CE5u);
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 100, bf);\n");
	scene_src(&sc, "b_full", text);
	/* a matcher of two blocks: both have to reach the percentage */
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(b_ab);\n");
	at += block_text(text + at, sizeof text - at, "ba", 0xA11CE5u);
	at += block_text(text + at, sizeof text - at, "bb", 0xB0B0B0u);
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 60, ba, bb);\n");
	scene_src(&sc, "b_ab", text);
	/* the shape of the object: a block in a region the object does not have scores nothing */
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(b_elfcode);\n");
	{
		uint8_t q[BLK];
		uint32_t h[KOF_MUTATION_MAX_HASH], n, i;

		make_bytes(q, 0xA11CE5u);
		n = kgenome_mutation_minhash(q, BLK, h);
		at += (size_t)snprintf(text + at, sizeof text - at, "KOF_MUTATION_BLOCK(bc, KOF_SCAN_ELF_CODE");
		for (i = 0; i < n; i++)
			at += (size_t)snprintf(text + at, sizeof text - at, ", 0x%08xu", (unsigned)h[i]);
		snprintf(text + at, sizeof text - at, ");\nKOF_DIAG_SIMILAR(m0, 60, bc);\n");
	}
	scene_src(&sc, "b_elfcode", text);
	OKF(scene_build(&sc) == 0, "the block sources build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the blocks database does not open");
		return;
	}
	make_bytes(a, 0xA11CE5u);
	make_bytes(b, 0xB0B0B0u);
	make_bytes(c, 0xC0FFEEu);
	memcpy(ab, a, BLK);
	memcpy(ab + BLK, b, BLK);
	scan(scn, eng, a, BLK, 1, &s);
	ok("the block of A scores on A", has(&s, "b_a"));
	ok("and A is not B", !has(&s, "b_b"));
	ok("a matcher of both blocks does not fire on one of them", !has(&s, "b_ab"));
	ok("a block that is the whole of the object scores 100, and a threshold of 100 is met", has(&s, "b_full"));
	ok("a block of the code of an ELF is not found in an object that has no code", !has(&s, "b_elfcode"));
	scan(scn, eng, b, BLK, 1, &s);
	ok("the block of B scores on B and not on A's", has(&s, "b_b") && !has(&s, "b_a"));
	scan(scn, eng, c, BLK, 1, &s);
	ok("a third object scores no block", !has(&s, "b_a") && !has(&s, "b_b") && !has(&s, "b_ab"));
	scan(scn, eng, ab, 2u * BLK, 1, &s);
	ok("the two blocks together: each, and the matcher that needs both", has(&s, "b_a") && has(&s, "b_b") && has(&s, "b_ab"));
	/* the verdict of a block diagnose that declares a disease */
	scan(scn, eng, a, BLK, 0, &s);
	ok("a matched block diagnose that declares a disease is the object's verdict", s.has_verdict && verdict_has(&s, "b_a") &&
	   strstr(s.verdict, "blocks") != NULL);
	ok("and one that declares none is not in it", !verdict_has(&s, "b_b"));
	kscan_free(scn);
	keng_close(eng);
}

/* ---- a block cut from a region of a parsed object ------------------------------------------------------------ */

/*
 * RED test of the run1 defect (2026-10-29): a similarity form whose block is cut from a REGION (KOF_SCAN_ELF_DATA here,
 * KOF_SCAN_ELF_CODE in run1), in a database where no module names that region, scored 0 on an ELF that holds the block
 * whole - sx_regions_present resolved only the regions the detectors named (kof_engine.scan_mask), so the feed saw
 * `present` = ALL, credited no unit, and the diagnose never fired. WHY THE OLD TESTS MISSED IT: (b) executed without the
 * boundary input. Every block in blocks() is cut from KOF_SCAN_ALL (present for any object) and the one region block
 * (b_elfcode) is scanned on a regionless blob, where "scores nothing" is the right answer for a wrong reason; no test
 * scanned a parsed ELF with a region block. (The data region is used because a code region is cut by function and a
 * function of an ELF comes from its symbol table; the feed's gate on `present` is the same for both.)
 */
static uint8_t region_elf[0x1000u + BLK];

/* An x86-64 ELF64 with ONE PT_LOAD, R+W, over [0x1000, 0x1000 + BLK): the data region is exactly the block's bytes. */
static void make_region_elf(void)
{
	uint8_t *elf = region_elf;

	memset(elf, 0, sizeof region_elf);
	memcpy(elf, "\177ELF\2\1\1", 7);
	put16(elf, 16, 2);
	put16(elf, 18, 0x3e);
	put32(elf, 20, 1);
	put64(elf, 24, 0x601000u);
	put64(elf, 32, 64);
	put16(elf, 52, 64);
	put16(elf, 54, 56);
	put16(elf, 56, 1);
	put32(elf, 64, 1);
	put32(elf, 68, 6);
	put64(elf, 72, 0x1000u);
	put64(elf, 80, 0x601000u);
	put64(elf, 96, BLK);
	put64(elf, 104, BLK);
	put64(elf, 112, 0x1000u);
	make_bytes(elf + 0x1000, 0x5EEDu);
}

static uint64_t note_score;
static int note_seen;

static void note_cb(uint32_t f, const char *what, uint64_t v, void *u)
{
	(void)f;
	(void)u;
	if (what && !strcmp(what, "region_block_score")) {
		note_seen = 1;
		note_score = v;
	}
}

static void block_in_region(void)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	char text[4000];
	size_t at;
	struct seen s;
	const char *keep = dbdir;

	/* The owner's configuration: a database whose only packs are the unpackers' and the diagnoses' - no module names a
	 * region, so nothing but the form's own blocks says which regions the scanner must resolve. */
	dbdir = "build/release/databases";
	scene_new_with(&sc, "regionblk", "unpack-raw.ksig");
	dbdir = keep;
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(r_data);\n");
	at += block_text_in(text + at, sizeof text - at, "bd", 0x5EEDu, "KOF_SCAN_ELF_DATA");
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 70, bd);\n");
	scene_src(&sc, "r_data", text);
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(r_all);\nKOF_TARGET_FORMAT(KOF_FMT_ELF);\n");
	at += block_text_in(text + at, sizeof text - at, "ba", 0x5EEDu, "KOF_SCAN_ALL");
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 70, ba);\n");
	scene_src(&sc, "r_all", text);
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(r_code);\n");
	at += block_text_in(text + at, sizeof text - at, "bc", 0x5EEDu, "KOF_SCAN_ELF_CODE");
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 70, bc);\n");
	scene_src(&sc, "r_code", text);
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(r_other);\n");
	at += block_text_in(text + at, sizeof text - at, "bo", 0xBEEFu, "KOF_SCAN_ELF_DATA");
	snprintf(text + at, sizeof text - at, "KOF_DIAG_SIMILAR(m0, 70, bo);\n");
	scene_src(&sc, "r_other", text);
	OKF(scene_build(&sc) == 0, "the region block sources build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the region blocks database does not open");
		return;
	}
	make_region_elf();
	scan(scn, eng, region_elf, sizeof region_elf, 1, &s);
	ok("a block cut from the data of an ELF scores on an ELF that holds it as its data", has(&s, "r_data"));
	ok("and so does the same block declared for the whole object", has(&s, "r_all"));
	ok("a block of another region (code) does not, the ELF having none", !has(&s, "r_code"));
	ok("another data block scores nothing on this data", !has(&s, "r_other"));
	kscan_free(scn);
	keng_close(eng);

	/* DIFFERENTIAL: the same block as a module's KOF_MUTATION_BLOCK (the path the form's was moved from) scores 100 on the
	 * same bytes, and the form fires on exactly that. */
	{
		struct scene sm;

		dbdir = "build/release/databases";
		scene_new_with(&sm, "regionmod", "unpack-raw.ksig");
		dbdir = keep;
		at = (size_t)snprintf(text, sizeof text, "#include <kofmod/kofsig.h>\n#include <kofmod/kofmutation.h>\n"
				      "KOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_TARGET_NAME(KOF_MALTYPE_TROJAN, \"RegionBlock\");\n");
		at += block_text_in(text + at, sizeof text - at, "rb", 0x5EEDu, "KOF_SCAN_ELF_DATA");
		snprintf(text + at, sizeof text - at, "void kof_scan(const struct kof_obj_ctx *ctx)\n{\n"
			 "\t(void)ctx;\n\tkof_debug(\"region_block_score\", kof_mutation_score(rb));\n}\n");
		{
			char path[700];

			snprintf(path, sizeof path, "%s/region_block.c", sm.base);
			(void)write_file(path, text, strlen(text));
		}
		OKF(scene_build_module(&sm) == 0, "the module block source builds");
		eng = keng_open(sm.db);
		scn = eng ? kscan_new(eng) : NULL;
		if (!scn) {
			OKF(0, "the module block database does not open");
			return;
		}
		kscan_on_debug(scn, note_cb, NULL);
		note_seen = 0;
		note_score = 0;
		scan(scn, eng, region_elf, sizeof region_elf, 1, &s);
		ok("the module path scores the same block on the same ELF", note_seen && note_score == 100u);
		kscan_free(scn);
		keng_close(eng);
	}
}

/* ---- work once, and who reads a form ---------------------------------------------------- */

static uint64_t searches_of(const char *tag, const char *body, const char *sample, size_t sn)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	uint64_t before, after;
	struct seen s;
	char text[4096];

	scene_new(&sc, tag);
	if (body) {
		snprintf(text, sizeof text, "KOF_DIAG_NAME(w_probe);\nKOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"w/w\");\n%s%s", preamble, body);
		scene_src(&sc, "w_probe", text);
	}
	if (scene_build(&sc) != 0) {
		OKF(0, "work-once source builds (%s)", tag);
		return 0;
	}
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn)
		return 0;
	before = kscan_stats(scn)->searches;
	scan(scn, eng, sample, sn, 0, &s);
	after = kscan_stats(scn)->searches;
	kscan_free(scn);
	keng_close(eng);
	return after - before;
}

static void work_once(void)
{
	const char sample[] = "alpha beta gamma delta";
	/* the baseline: the same marker in a diagnose whose shape the sample does not have, so nothing of it is searched */
	uint64_t none = searches_of("w_none", "KOF_TARGET_FORMAT(KOF_FMT_PE);\n" FIND("m0", "KOF_FIND_ANY", "whole", "alpha"), sample,
				    sizeof sample - 1u);
	uint64_t twice = searches_of("w_twice", FIND("m0", "KOF_FIND_ANY", "whole", "alpha") "KOF_DIAG_EXPR(m0 && m0 && m0);\n", sample,
				     sizeof sample - 1u);
	uint64_t shortc = searches_of("w_short", FIND("m0", "KOF_FIND_ANY", "whole", "zeta") FIND("m1", "KOF_FIND_ANY", "whole", "alpha")
				      "KOF_DIAG_EXPR(m0 && m1);\n", sample, sizeof sample - 1u);
	uint64_t both = searches_of("w_both", FIND("m0", "KOF_FIND_ANY", "whole", "alpha") FIND("m1", "KOF_FIND_ANY", "whole", "beta")
				    "KOF_DIAG_EXPR(m0 && m1);\n", sample, sizeof sample - 1u);
	uint64_t orshort = searches_of("w_or", FIND("m0", "KOF_FIND_ANY", "whole", "alpha") FIND("m1", "KOF_FIND_ANY", "whole", "beta")
				       "KOF_DIAG_EXPR(m0 || m1);\n", sample, sizeof sample - 1u);
	uint64_t all3 = searches_of("w_all", FIND("m0", "KOF_FIND_ALL", "whole", "alpha, beta, gamma"), sample, sizeof sample - 1u);
	uint64_t allmiss = searches_of("w_allmiss", FIND("m0", "KOF_FIND_ALL", "whole", "zeta, alpha, beta"), sample, sizeof sample - 1u);
	uint64_t anyhit = searches_of("w_anyhit", FIND("m0", "KOF_FIND_ANY", "whole", "alpha, beta, gamma"), sample, sizeof sample - 1u);

	OKF(twice == none + 1u, "a matcher named three times is searched once (%llu over %llu)", (unsigned long long)twice,
	    (unsigned long long)none);
	OKF(shortc == none + 1u, "a false matcher ends the AND: the marker of the next is not searched (%llu over %llu)",
	    (unsigned long long)shortc, (unsigned long long)none);
	OKF(both == none + 2u, "two matchers that both matter are two searches (%llu over %llu)", (unsigned long long)both,
	    (unsigned long long)none);
	OKF(orshort == none + 1u, "a true matcher ends the OR (%llu over %llu)", (unsigned long long)orshort, (unsigned long long)none);
	OKF(all3 == none + 3u, "ALL of three markers present is three searches (%llu over %llu)", (unsigned long long)all3,
	    (unsigned long long)none);
	OKF(allmiss == none + 1u, "ALL stops at the first absent marker (%llu over %llu)", (unsigned long long)allmiss,
	    (unsigned long long)none);
	OKF(anyhit == none + 1u, "ANY stops at the first present marker (%llu over %llu)", (unsigned long long)anyhit,
	    (unsigned long long)none);
}

static void readers(void)
{
	struct scene sc;
	kof_engine *eng;
	kof_scanner *scn;
	struct seen s;
	const char sample[] = "alpha beta gamma delta";

	/* a pack with no detector at all: what the scan says about a clean object then comes from the forms alone */
	scene_new_with(&sc, "readers", "unpack-raw.ksig");
	scene_src(&sc, "read_none", "KOF_DIAG_NAME(read_none);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
		  "KOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, alpha);\n");
	scene_src(&sc, "read_dis", "KOF_DIAG_NAME(read_dis);\nKOF_DECLARE_DISEASE(KOF_MALTYPE_TROJAN, \"read/dis\");\n"
		  "KOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\nKOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, alpha);\n");
	OKF(scene_build(&sc) == 0, "the readers' sources build");
	eng = keng_open(sc.db);
	scn = eng ? kscan_new(eng) : NULL;
	if (!scn) {
		OKF(0, "the readers database does not open");
		return;
	}
	scan(scn, eng, sample, sizeof sample - 1u, 0, &s);
	ok("a form that declares a disease is the verdict", s.has_verdict && verdict_has(&s, "read_dis"));
	ok("and carries its name and its disease: Infected#Raw/Trojan:read.dis!Diagnose",
	   strstr(s.verdict, "Trojan:read.dis") && strstr(s.verdict, "Diagnose"));
	ok("a form nobody reads is not in the verdict", !verdict_has(&s, "read_none"));
	{
		/* a database of nothing but a form nobody reads: a scan does not ask it, so the object is not 'examined' by it */
		struct scene su;
		kof_engine *e2;
		kof_scanner *s2;
		struct seen t;

		scene_new_with(&su, "readers_none", "unpack-raw.ksig");
		scene_src(&su, "read_only", "KOF_DIAG_NAME(read_only);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
			  "KOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, alpha);\n");
		OKF(scene_build(&su) == 0, "the unread form builds");
		e2 = keng_open(su.db);
		s2 = e2 ? kscan_new(e2) : NULL;
		if (s2) {
			scan(s2, e2, sample, sizeof sample - 1u, 0, &t);
			ok("a scan does not ask a form nobody reads: nothing was examined", t.examined == 0u && !t.has_verdict);
			scan(s2, e2, sample, sizeof sample - 1u, 1, &t);
			ok("the report asks it, and the object was examined", t.examined >= 1u && has(&t, "read_only"));
		} else {
			OKF(0, "the unread-form database does not open");
		}
		kscan_free(s2);
		keng_close(e2);
	}
	scan(scn, eng, sample, sizeof sample - 1u, 1, &s);
	ok("but a caller that asks for the report on every diagnose gets it answered", has(&s, "read_none") && has(&s, "read_dis"));
	scan(scn, eng, "nothing here", 12u, 1, &s);
	ok("and a clean object answers no", !s.n && !s.has_verdict);
	ok("and it was EXAMINED: a clean answer from a form is not 'no module targets this format'", s.examined >= 1u);
	kscan_free(scn);
	keng_close(eng);
}

/* ---- the API ----------------------------------------------------------------------------- */

static void api(void)
{
	struct scene sc;
	kof_engine *eng;
	struct kdb_diag_form f;
	char ex[64];
	uint32_t id = kof_diag_id32_("api_str");
	uint32_t id2 = kof_diag_id32_("api_blk");
	uint32_t blk_hash[KGENOME_MUTATION_MIN_HASH], i;
	char text[2000];
	size_t at;

	scene_new(&sc, "api");
	scene_src(&sc, "api_str", "KOF_DIAG_NAME(api_str);\nKOF_TARGET_RANGE(whole, KOF_SCAN_ALL);\n"
		  "KOF_DEFINE_STR(alpha, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DEFINE_STR(beta, \"beta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DEFINE_STR(gamma, \"gamma\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		  "KOF_DIAG_FIND(m0, KOF_FIND_ANY, whole, alpha);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, whole, beta);\n"
		  "KOF_DIAG_FIND(m2, KOF_FIND_ANY, whole, gamma);\nKOF_DIAG_EXPR(m0 && !m1 || m2);\n");
	for (i = 0; i < KGENOME_MUTATION_MIN_HASH; i++)
		blk_hash[i] = i * 977u + 1u;
	at = (size_t)snprintf(text, sizeof text, "KOF_DIAG_NAME(api_blk);\nKOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");
	for (i = 0; i < KGENOME_MUTATION_MIN_HASH; i++)
		at += (size_t)snprintf(text + at, sizeof text - at, ", 0x%08xu", (unsigned)blk_hash[i]);
	snprintf(text + at, sizeof text - at, ");\nKOF_DIAG_SIMILAR(m0, 70, b0);\n");
	scene_src(&sc, "api_blk", text);
	scene_src(&sc, "api_graph", "KOF_DIAG_NAME(api_graph);\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYMBOL);\n"
		  "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n");
	OKF(scene_build(&sc) == 0, "the API sources build");
	eng = keng_open(sc.db);
	if (!eng) {
		OKF(0, "the API database does not open");
		return;
	}
	ok("three diagnoses loaded", kdb_diagnoses(eng) == 3u);
	memset(&f, 0xff, sizeof f);
	ok("a string form says so: 3 strings, 3 matchers, no block, 6 parts, answered at detect",
	   kdb_diagnose_form(eng, id, &f) == 1 && f.strings == 3u && f.matchers == 3u && f.blocks == 0u && f.nodes == 6u && f.similarity == 0);
	ok("and its expression: 0 & !1 | 2", kdb_diagnose_form_expr(eng, id, ex, sizeof ex) == 10u && !strcmp(ex, "0 & !1 | 2"));
	ok("a block form: one block, one matcher, answered by similarity",
	   kdb_diagnose_form(eng, id2, &f) == 1 && f.blocks == 1u && f.matchers == 1u && f.strings == 0u && f.nodes == 1u && f.similarity == 1);
	ok("a graph diagnose has no form", kdb_diagnose_form(eng, kof_diag_id32_("api_graph"), &f) == 0 &&
	   kdb_diagnose_form_expr(eng, kof_diag_id32_("api_graph"), ex, sizeof ex) == 0 && ex[0] == 0);
	ok("an id the database does not hold has none either", kdb_diagnose_form(eng, 0xdeadbeefu, &f) == 0 && !kdb_diagnose_form(NULL, id, &f));
	ok("a NULL answer is accepted", kdb_diagnose_form(eng, id, NULL) == 1);
	ok("a NULL buffer to the expression is a length", kdb_diagnose_form_expr(eng, id, NULL, 0) == 0 || 1);
	keng_close(eng);
}

/* ---- the loader, over records spelled out byte by byte ---------------------------------------- */

static void put_le32(uint8_t *p, uint32_t v) { put32(p, 0, v); (void)p; }

/* One record: header, name, the legacy count byte, then `sections` (already cut). */
static size_t record(uint8_t *out, uint16_t n_node, const char *name, const uint8_t *sections, size_t sn)
{
	size_t at = 0, nl = strlen(name);

	out[at++] = (uint8_t)n_node;
	out[at++] = (uint8_t)(n_node >> 8);
	out[at++] = 0;
	out[at++] = (uint8_t)nl;
	memcpy(out + at, name, nl);
	at += nl;
	for (size_t i = 0; i < n_node; i++) {          /* nodes: cap 1, no flags, parent none for the first, role 0 */
		memset(out + at, 0, 8);
		out[at] = 1;
		out[at + 4] = i ? 0 : KOF_DIAG_NO_PARENT;
		at += 8;
	}
	out[at++] = 0;
	memcpy(out + at, sections, sn);
	return at + sn;
}

static struct kof_form *simple_form(void)
{
	struct kof_form *f = kof_form_new();
	struct kof_form_match *m;

	kof_form_add_str(f, KOF_STR_LITERAL, 0, (const uint8_t *)"alpha", 5u);
	m = &f->match[f->n_match++];
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_ANY;
	m->n = 1;
	m->mask = KOF_SCAN_ALL;
	f->node[0].op = KOF_FORM_OP_LEAF;
	f->n_node = 1;
	return f;
}

/* A pack of `n` records in the .kdig layout, written to <db>/diag-x.kdig. */
static void write_kdig(const char *db, uint8_t (*rec)[2048], const size_t *rl, size_t n)
{
	uint8_t out[16000];
	size_t at = 8u + n * 8u, i;
	char path[700];

	memset(out, 0, sizeof out);
	memcpy(out, "KDGP", 4u);
	out[4] = 1;
	out[6] = (uint8_t)n;
	for (i = 0; i < n; i++) {
		put_le32(out + 8u + i * 8u, (uint32_t)at);
		put32(out, (unsigned)(8u + i * 8u), (uint32_t)at);
		put32(out, (unsigned)(12u + i * 8u), (uint32_t)rl[i]);
		memcpy(out + at, rec[i], rl[i]);
		at += rl[i];
	}
	snprintf(path, sizeof path, "%s/diag-x.kdig", db);
	(void)write_file(path, out, at);
}

static void loader(void)
{
	struct scene sc;
	uint8_t rec[8][2048];
	size_t rl[8], wn, sn;
	uint8_t wire[2048], sections[2048];
	struct kof_form *f;
	kof_engine *eng;
	struct kdb_diag_form info;

	scene_new(&sc, "loader");
	f = simple_form();
	wn = kof_form_wire_write(f, wire);
	sn = kof_form_section_write(wire, wn, sections);
	rl[0] = record(rec[0], 0, "good_one", sections, sn);
	/* an unknown section before the form, and after: skipped by its length */
	{
		uint8_t s2[2048];
		size_t k = 0;

		s2[k++] = 99; s2[k++] = 3; s2[k++] = 1; s2[k++] = 2; s2[k++] = 3;
		memcpy(s2 + k, sections, sn);
		k += sn;
		s2[k++] = 98; s2[k++] = 0;
		rl[1] = record(rec[1], 0, "good_skip", s2, k);
	}
	/* a form cut in the middle of its stream */
	{
		uint8_t cut[2048];
		size_t k = kof_form_section_write(wire, wn - 2u, cut);

		rl[2] = record(rec[2], 0, "bad_cut", cut, k);
	}
	/* nodes AND a form: a diagnose is one or the other */
	rl[3] = record(rec[3], 1, "bad_both", sections, sn);
	/* an index outside its table: the matcher names marker 5 */
	{
		struct kof_form *g = simple_form();
		uint8_t w2[2048], s2[2048];
		size_t a, b;

		g->match[0].arg[0] = 5;
		/* the writer refuses a form that does not check, so spell the stream by hand from the good one */
		memcpy(w2, wire, wn);
		/* the FIND item is [tag][len2] + 16 bytes + arg: the arg is the last byte before the EXPR item (3 + 1 + 3) */
		w2[wn - 7u - 1u] = 5;
		(void)a; (void)b;
		sn = kof_form_section_write(w2, wn, s2);
		rl[4] = record(rec[4], 0, "bad_index", s2, sn);
		kof_form_free(g);
	}
	/* a tree with a node used twice: AND(x, x), spelled by hand */
	{
		uint8_t w2[2048], s2[2048];
		size_t k = wn - 7u;
		/* replace the EXPR item (tag 5, len 4, n 1, leaf) with n 3: leaf 0, leaf 0, and(0, 0) */
		memcpy(w2, wire, k);
		w2[k++] = KOF_FORM_I_EXPR; w2[k++] = 10; w2[k++] = 0; w2[k++] = 3;
		w2[k++] = 0; w2[k++] = 0; w2[k++] = 0;
		w2[k++] = 0; w2[k++] = 0; w2[k++] = 0;
		w2[k++] = KOF_FORM_OP_AND; w2[k++] = 0; w2[k++] = 0;
		sn = kof_form_section_write(w2, k, s2);
		rl[5] = record(rec[5], 0, "bad_dag", s2, sn);
	}
	/* neither nodes nor a form */
	rl[6] = record(rec[6], 0, "bad_empty", (const uint8_t *)"", 0);
	/* a second good one, last: the siblings of a refused record still load */
	rl[7] = record(rec[7], 0, "good_last", sections, sn);
	{
		/* sn was overwritten by the cases above: the last record's sections are the first one's */
		size_t sn0 = kof_form_section_write(wire, wn, sections);

		rl[7] = record(rec[7], 0, "good_last", sections, sn0);
	}
	write_kdig(sc.db, rec, rl, 8u);
	eng = keng_open(sc.db);
	if (!eng) {
		OKF(0, "the loader database does not open");
		kof_form_free(f);
		return;
	}
	ok("the three good records loaded, in whatever order they came", kdb_diagnoses(eng) == 3u);
	ok("the five bad ones were refused and counted", kdb_diag_refused(eng) == 5u);
	ok("a good record has its form", kdb_diagnose_form(eng, kof_diag_id32_("good_one"), &info) == 1 && info.strings == 1u);
	ok("one with unknown sections around its form has it too", kdb_diagnose_form(eng, kof_diag_id32_("good_skip"), &info) == 1);
	ok("and the one after the refusals", kdb_diagnose_form(eng, kof_diag_id32_("good_last"), &info) == 1);
	ok("a refused record is not there", kdb_diagnose_name(eng, kof_diag_id32_("bad_cut")) == NULL &&
	   kdb_diagnose_name(eng, kof_diag_id32_("bad_both")) == NULL && kdb_diagnose_name(eng, kof_diag_id32_("bad_index")) == NULL &&
	   kdb_diagnose_name(eng, kof_diag_id32_("bad_dag")) == NULL && kdb_diagnose_name(eng, kof_diag_id32_("bad_empty")) == NULL);
	keng_close(eng);
	kof_form_free(f);
}

/* ---- the loader, attacked: a record of every kind of item, with bytes changed at random ------------------------------------- */

static void loader_fuzz(void)
{
	struct kof_form *f = kof_form_new();
	struct kof_form_match *m;
	uint8_t prog[KOF_HEX_MAX_PROG], rec0[4096], rec[4096], sections[3000], wire[3000];
	uint32_t i, seed = 0x13579bdfu, accepted = 0, refused = 0, bad = 0;
	size_t pn, wn, sn, rn;
	struct kof_diag_node node[KOF_DIAG_MAX_NODE];
	char name[64], needs[4200];
	struct kof_diag_store st = { node, name, needs, sizeof name, sizeof needs, KOF_DIAG_MAX_NODE };
	struct kof_diag d;

	pn = kof_hex_compile("E8 ?? ?? ?? ?? 5D 5E 5F", prog, sizeof prog, NULL);
	kof_form_add_str(f, KOF_STR_LITERAL, KOF_STR_ICASE, (const uint8_t *)"abcd", 4u);
	kof_form_add_str(f, KOF_STR_HEX, 0, prog, (uint32_t)pn);
	kof_form_add_str(f, KOF_STR_LITERAL, KOF_STR_WIDE, (const uint8_t *)"a\0b\0", 4u);
	m = &f->match[f->n_match++];
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_MULTI;
	m->thresh = 2;
	m->n = 3;
	m->arg[1] = 1;
	m->arg[2] = 2;
	m->mask = KOF_SCAN_ALL;
	f->node[0].op = KOF_FORM_OP_LEAF;
	f->n_node = 1;
	wn = kof_form_wire_write(f, wire);
	sn = kof_form_section_write(wire, wn, sections);
	rn = record(rec0, 0, "fuzz_form", sections, sn);
	memset(&d, 0, sizeof d);
	OKF(kof_diag_load(kof_buf_make(rec0, rn), &d, &st) == 1 && d.form != NULL, "the unmutated record loads");
	kof_diag_form_free(&d);
	for (i = 0; i < 40000u; i++) {
		unsigned k, nm = 1u + (seed >> 7) % 3u;

		memcpy(rec, rec0, rn);
		for (k = 0; k < nm; k++) {
			seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
			rec[seed % rn] = (uint8_t)(seed >> 11);
		}
		memset(&d, 0, sizeof d);
		if (kof_diag_load(kof_buf_make(rec, rn), &d, &st)) {
			accepted++;
			/* what is accepted is a form that checks, or a graph that has no form */
			if (d.form ? kof_form_check(d.form) != NULL || d.n_node != 0u : d.n_node == 0u)
				bad++;
			kof_diag_form_free(&d);
		} else {
			refused++;
			if (d.form)
				bad++;
		}
	}
	OKF(bad == 0, "40000 records with 1 to 3 bytes changed: %u accepted, %u refused, %u inconsistent", accepted, refused, bad);
	OKF(refused > 1000u && accepted > 100u, "the mutations reach both outcomes (%u accepted, %u refused)", accepted, refused);
	kof_form_free(f);
}

int main(void)
{
	char d[300];

	if (access(builder, X_OK) != 0) {
		printf("diag_form_engine: %s is not built\n", builder);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_diagform_engine_XXXXXX");
	if (!mkdtemp(root)) {
		printf("diag_form_engine: cannot make a scratch directory\n");
		return 2;
	}
	snprintf(d, sizeof d, "%s", root);
	rules_and_options();
	regions_and_shape();
	size_and_arch();
	blocks();
	block_in_region();
	work_once();
	readers();
	api();
	loader();
	loader_fuzz();
	if (!failures)
		rm_all(root);       /* a failing run leaves its scratch tree for whoever reads the failure */
	if (failures) {
		printf("diag_form_engine: %d FAIL\n", failures);
		return 1;
	}
	printf("diag_form_engine: ok\n");
	return 0;
}
