/*
 * diagsrc - a diagnose's source read, shown and written back.
 *
 * What is pinned here is the property the editor depends on and nothing else
 * checks: a file is patched, never regenerated. Every shipped diagnose is read
 * and written back unchanged and must come out byte for byte, and an edit
 * changes exactly the declaration lines it names - the comments around them,
 * which carry the evidence for the rule, are never touched. The printer is
 * pinned by reading back what it wrote.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/analyzers/nucleo/nucleo.h"

static int fails;

#define CHECK(c, ...) do { \
	if (!(c)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static char *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	char *b;
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
	if (b) {
		b[L] = 0;
		*n = (size_t)L;
	}
	return b;
}

static int lines_of(const char *t)
{
	int n = 0;

	for (; *t; t++)
		if (*t == '\n')
			n++;
	return n;
}

/* The lines of `t` that are not declarations, joined: what must survive. */
static char *prose(const char *t, size_t n)
{
	struct kof_dsrc *d = calloc(1, sizeof *d);
	char *out = calloc(n + 1u, 1);
	size_t at = 0, o = 0;
	unsigned line = 0, q;

	kof_dsrc_parse(t, n, d, NULL);
	while (at < n) {
		size_t e = at;
		int decl = 0;

		while (e < n && t[e] != '\n')
			e++;
		line++;
		for (q = 0; q < d->n; q++)
			if (d->item[q].line == line)
				decl = 1;
		if (!decl) {
			memcpy(out + o, t + at, e - at + (e < n ? 1u : 0u));
			o += e - at + (e < n ? 1u : 0u);
		}
		at = e < n ? e + 1u : e;
	}
	free(d);
	return out;
}

static void one_file(const char *path)
{
	size_t n = 0, pn = 0;
	char *t = slurp(path, &n), *p;
	struct kof_dsrc *d = calloc(1, sizeof *d);
	struct kof_dsrc_view v;
	uint32_t q;

	if (!t) {
		CHECK(0, "cannot read %s", path);
		free(d);
		return;
	}
	CHECK(kof_dsrc_parse(t, n, d, NULL) == 0, "%s does not parse", path);
	CHECK(kof_dsrc_resolve(d, &v, NULL) == 0, "%s does not resolve", path);

	/* Unchanged, written back: the same bytes. */
	p = kof_dsrc_patch(t, n, d, &pn);
	CHECK(p && pn == n && !memcmp(p, t, n), "%s changed by a no-op patch",
	      path);
	free(p);

	/* What the printer writes reads back as the same declaration. */
	for (q = 0; q < d->n; q++) {
		char line[512];
		struct kof_dsrc *r = calloc(1, sizeof *r);
		size_t L = kof_dsrc_print(&d->item[q], line, sizeof line);

		CHECK(L > 0, "%s item %u cannot be printed", path, q);
		if (L) {
			line[L++] = '\n';
			kof_dsrc_parse(line, L, r, NULL);
			CHECK(r->n == 1 && kof_dsrc_same(&r->item[0], &d->item[q]),
			      "%s item %u: \"%.*s\" did not read back", path, q,
			      (int)L - 1, line);
		}
		free(r);
	}
	free(d);
	free(t);
}

/* A small source with prose around its declarations. */
static const char src[] =
	"#include <kofmod/kofpathogen.h>\n"
	"\n"
	"/* WHY: measured on 900 clean modules, none do this. */\n"
	"KOF_DIAG_NAME(DIAG_T);\n"
	"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
	"\n"
	"/* the root is rare */\n"
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
	"/* and it is read from */\n"
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);\n"
	"/* KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_OPEN); mentioned, not declared */\n";

static void edits(void)
{
	size_t n = strlen(src), pn = 0, an = 0, bn;
	struct kof_dsrc *d = calloc(1, sizeof *d), *e = calloc(1, sizeof *e);
	struct kof_dsrc_view v;
	char *p, *pr0, *pr1;
	uint32_t i;

	CHECK(kof_dsrc_parse(src, n, d, NULL) == 0, "fixture does not parse");
	CHECK(d->n == 5, "fixture has %u declarations, want 5", d->n);
	CHECK(kof_dsrc_resolve(d, &v, NULL) == 0 && v.n_nd == 3 &&
	      v.nd[0].flags == KOF_FLOWF_WX, "fixture tree is wrong");
	pr0 = prose(src, n);

	/* Remove the second tail. Only its line goes. */
	*e = *d;
	for (i = 0; i < e->n; i++)
		if (e->item[i].kind == KDS_TAIL &&
		    e->item[i].a == KOF_NUCLEO_EXEC_REG) {
			memmove(&e->item[i], &e->item[i + 1u],
				(e->n - i - 1u) * sizeof e->item[0]);
			e->n--;
			break;
		}
	p = kof_dsrc_patch(src, n, e, &pn);
	CHECK(p && lines_of(p) == lines_of(src) - 1, "removal: %d lines, want %d",
	      p ? lines_of(p) : -1, lines_of(src) - 1);
	CHECK(p && !strstr(p, "KOF_NUCLEO_EXEC_REG);\n/*") &&
	      !strstr(p, "DECLARE_TAIL(KOF_NUCLEO_EXEC_REG)"),
	      "removal: the tail is still there");
	pr1 = p ? prose(p, pn) : NULL;
	CHECK(pr1 && !strcmp(pr0, pr1), "removal changed the prose");
	free(pr1);
	free(p);

	/* Add a tail with a kind: one new line, after the last tail. */
	*e = *d;
	memset(&e->item[e->n], 0, sizeof e->item[0]);
	e->item[e->n].kind = KDS_TAIL;
	e->item[e->n].a = KOF_NUCLEO_NET_OPEN;
	e->item[e->n].b = KOF_DIAG_B_PRODUCED;
	e->n++;
	p = kof_dsrc_patch(src, n, e, &pn);
	CHECK(p && lines_of(p) == lines_of(src) + 1, "addition: %d lines, want %d",
	      p ? lines_of(p) : -1, lines_of(src) + 1);
	CHECK(p && strstr(p, "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_OPEN, "
			     "KOF_DIAG_B_PRODUCED);\n"), "addition: not written");
	pr1 = p ? prose(p, pn) : NULL;
	CHECK(pr1 && !strcmp(pr0, pr1), "addition changed the prose");
	free(pr1);
	/* and it reads back into the tree */
	if (p) {
		struct kof_dsrc *r = calloc(1, sizeof *r);

		kof_dsrc_parse(p, pn, r, NULL);
		CHECK(kof_dsrc_resolve(r, &v, NULL) == 0 && v.n_nd == 4 &&
		      v.nd[3].cap == KOF_NUCLEO_NET_OPEN &&
		      (v.nd[3].bits & KOF_DIAG_B_PRODUCED),
		      "addition: tree after the edit is wrong");
		free(r);
	}
	free(p);

	/* Change the head's flags: that one line is replaced, in place. */
	*e = *d;
	for (i = 0; i < e->n; i++)
		if (e->item[i].kind == KDS_HEAD)
			e->item[i].b = 0;
	p = kof_dsrc_patch(src, n, e, &pn);
	CHECK(p && lines_of(p) == lines_of(src), "replacement moved lines");
	CHECK(p && strstr(p, "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, 0);\n"
			     "/* and it is read from */"),
	      "replacement: not in place");
	pr1 = p ? prose(p, pn) : NULL;
	CHECK(pr1 && !strcmp(pr0, pr1), "replacement changed the prose");
	free(pr1);
	free(p);

	/* A second patch of the patched text is the identity. */
	*e = *d;
	p = kof_dsrc_patch(src, n, e, &pn);
	{
		struct kof_dsrc *r = calloc(1, sizeof *r);
		char *q;

		kof_dsrc_parse(p, pn, r, NULL);
		q = kof_dsrc_patch(p, pn, r, &bn);
		CHECK(q && bn == pn && !memcmp(p, q, pn), "patch is not stable");
		free(q);
		free(r);
	}
	(void)an;
	free(p);
	free(pr0);
	free(d);
	free(e);
}

static void mentions(void)
{
	static const char t[] =
		"/*\n"
		" * KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0) is what a\n"
		" * different diagnose would say.\n"
		" */\n"
		"KOF_DIAG_NAME(DIAG_T); // KOF_DIAG_USE_EMU()\n"
		"KOF_DIAG_DECLARE_SYMBOL(m, \"a/*b\");\n";
	struct kof_dsrc *d = calloc(1, sizeof *d);

	kof_dsrc_parse(t, strlen(t), d, NULL);
	CHECK(d->n == 2, "a macro in a comment was read: %u declarations", d->n);
	CHECK(d->n == 2 && d->item[1].kind == KDS_SYMBOL &&
	      !strcmp(d->item[1].s2, "a/*b"), "a comment opener in a string "
	      "swallowed the rest of the file");
	free(d);
}

/* ---- a verdict that reads diagnoses ------------------------------------------- */

static const char vsrc[] =
	"#include <kofmod/kofsig.h>\n"
	"\n"
	"/* WHY: both, because one alone is a packer. kof_diag(NOT_A_TERM) */\n"
	"KOF_TARGET_FORMAT(KOF_FMT_ELF);\n"
	"KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, \"Meterp\");\n"
	"\n"
	"void kof_scan(const struct kof_obj_ctx *ctx)\n"
	"{\n"
	"\tif (kof_diag(DIAG_MEM_EXECSYSCALL) &&\n"
	"\t    kof_diag(DIAG_NET_RECVSYSCALL) &&\n"
	"\t    kof_diag_share(KOF_NUCLEO_MEM_READ, DIAG_MEM_EXECSYSCALL,\n"
	"\t\t\t   DIAG_NET_RECVSYSCALL))\n"
	"\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n"
	"}\n";

static void verdict_file(const char *path)
{
	size_t n = 0, pn = 0;
	char *t = slurp(path, &n), *p;
	struct kof_dsrc *d = calloc(1, sizeof *d);

	if (!t || !d) {
		CHECK(0, "cannot read %s", path);
		free(t);
		free(d);
		return;
	}
	CHECK(kof_dsrc_parse(t, n, d, NULL) == 0 && d->has_cond,
	      "%s: not read as a verdict", path);
	CHECK(kof_dsrc_verdict_check(d, NULL) == 0, "%s: fails its own check", path);
	p = kof_dsrc_patch(t, n, d, &pn);
	CHECK(p && pn == n && !memcmp(p, t, n), "%s changed by a no-op patch", path);
	free(p);
	free(d);
	free(t);
}

static void verdicts(void)
{
	size_t n = strlen(vsrc), pn = 0, gn = 0;
	struct kof_dsrc *d = calloc(1, sizeof *d), *e = calloc(1, sizeof *e);
	struct kof_dsrc *r = calloc(1, sizeof *r);
	char *p, *g;
	uint32_t i;
	static const char *const bad[] = {
		"void kof_scan(const struct kof_obj_ctx *c)\n{\n\tif (kof_diag(A) || kof_diag(B))\n\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n}\n",
		"void kof_scan(const struct kof_obj_ctx *c)\n{\n\tint n = 0;\n\tif (kof_diag(A))\n\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n}\n",
		"void kof_scan(const struct kof_obj_ctx *c)\n{\n\tif (kof_diag(A) && x)\n\t\tKOF_SCAN_INFECT(KOF_MALVAR_AUTO);\n}\n"
	};
	unsigned k;

	CHECK(kof_dsrc_parse(vsrc, n, d, NULL) == 0 && d->has_cond, "fixture not read");
	CHECK(d->cond.n == 3 && d->cond.t[0].kind == KVT_DIAG &&
	      !strcmp(d->cond.t[0].a, "DIAG_MEM_EXECSYSCALL") && d->cond.t[2].kind == KVT_SHARE &&
	      d->cond.t[2].cap == KOF_NUCLEO_MEM_READ &&
	      !strcmp(d->cond.t[2].b, "DIAG_NET_RECVSYSCALL"),
	      "terms: %u, a wrapped kof_diag_share was misread", d->cond.n);
	/* the comment named kof_diag(NOT_A_TERM) and it is not a term */
	for (i = 0; i < d->cond.n; i++)
		CHECK(strcmp(d->cond.t[i].a, "NOT_A_TERM"), "a comment was read");
	CHECK(kof_dsrc_verdict_check(d, NULL) == 0, "fixture fails its own check");

	/* Add a term: only the condition's bytes change. */
	*e = *d;
	strcpy(e->cond.t[e->cond.n].a, "DIAG_EXTRA");
	e->cond.t[e->cond.n].kind = KVT_DIAG;
	e->cond.t[e->cond.n].n_str = 0;
	e->cond.t[e->cond.n].cap = 0;
	e->cond.t[e->cond.n].b[0] = 0;
	e->cond.n++;
	p = kof_dsrc_patch(vsrc, n, e, &pn);
	CHECK(p != NULL, "patch with a new term failed");
	if (p) {
		CHECK(!memcmp(p, vsrc, d->cond.at) &&
		      !memcmp(p + pn - (n - d->cond.end), vsrc + d->cond.end,
			      n - d->cond.end),
		      "adding a term touched what is around the condition");
		CHECK(kof_dsrc_parse(p, pn, r, NULL) == 0 && r->cond.n == 4 &&
		      !strcmp(r->cond.t[3].a, "DIAG_EXTRA"), "the new term did not read back");
		free(p);
	}

	/* Remove the join. */
	*e = *d;
	e->cond.n = 2;
	p = kof_dsrc_patch(vsrc, n, e, &pn);
	CHECK(p && strstr(p, "kof_diag(DIAG_NET_RECVSYSCALL))") &&
	      !strstr(p, "kof_diag_share"), "removing the join: %s", p ? p : "(null)");
	free(p);

	/* Change the format: one declaration line, in place. */
	*e = *d;
	for (i = 0; i < e->n; i++)
		if (e->item[i].kind == KDS_FORMAT)
			e->item[i].v = KOF_FMT_PE;
	p = kof_dsrc_patch(vsrc, n, e, &pn);
	CHECK(p && strstr(p, "KOF_TARGET_FORMAT(KOF_FMT_PE);\n"), "format not changed");
	CHECK(p && strstr(p, "WHY: both, because one alone is a packer"), "prose lost");
	free(p);

	/* A string term is read, kept, and written the way it was. */
	{
		static const char sv[] =
			"KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_UNKNOWN);\n"
			"KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, \"LKM\");\n"
			"void kof_scan(const struct kof_obj_ctx *ctx)\n{\n"
			"\tif (kof_diag(DIAG_A) &&\n"
			"\t    kof_diag_str_any(DIAG_B, \"sys_call_table\",\n"
			"\t\t\t     \"x64_sys_call\"))\n"
			"\t\tKOF_SCAN_INFECT(KOF_MALVAR_GENERIC);\n}\n";
		size_t sn = strlen(sv), qn = 0;
		char *q;

		memset(r, 0, sizeof *r);
		CHECK(kof_dsrc_parse(sv, sn, r, NULL) == 0 && r->has_cond &&
		      r->cond.n == 2 && r->cond.t[1].kind == KVT_STR_ANY &&
		      r->cond.t[1].n_str == 2 &&
		      !strcmp(r->cond.t[1].str[1], "x64_sys_call") &&
		      !strcmp(r->cond.infect, "KOF_MALVAR_GENERIC"),
		      "a string term was misread");
		/* the set of formats is kept as written, though a number cannot say it */
		q = kof_dsrc_patch(sv, sn, r, &qn);
		CHECK(q && qn == sn && !memcmp(q, sv, sn), "no-op patch of a string verdict");
		free(q);
		r->cond.t[1].n_str = 1;
		q = kof_dsrc_patch(sv, sn, r, &qn);
		CHECK(q && strstr(q, "kof_diag_str_any(DIAG_B, \"sys_call_table\"))") &&
		      strstr(q, "KOF_FMT_ELF | KOF_FMT_UNKNOWN"),
		      "dropping a string: %s", q ? q : "(null)");
		free(q);
	}

	/* A verdict written from nothing reads back as what was written. */
	g = kof_dsrc_verdict_new(d, &gn);
	CHECK(g != NULL, "no new verdict");
	if (g) {
		memset(r, 0, sizeof *r);
		CHECK(kof_dsrc_parse(g, gn, r, NULL) == 0 && r->has_cond &&
		      kof_dsrc_cond_same(&r->cond, &d->cond) &&
		      kof_dsrc_verdict_check(r, NULL) == 0,
		      "a generated verdict does not read back the same");
		free(g);
	}

	/* What is not this shape is refused, not guessed at. */
	for (k = 0; k < sizeof bad / sizeof bad[0]; k++) {
		memset(r, 0, sizeof *r);
		CHECK(kof_dsrc_parse(bad[k], strlen(bad[k]), r, NULL) > 0 && !r->has_cond,
		      "verdict %u was accepted", k);
	}
	free(d);
	free(e);
	free(r);
}

static void tables(void)
{
	size_t i;
	uint16_t c;
	const char *w;

	CHECK(kof_dsrc_cap_table_check(), "the capability table is incomplete");
	for (i = 0; (w = kof_dsrc_cap_at(i, &c)) != NULL; i++) {
		uint16_t back = 0;

		CHECK(kof_dsrc_cap_of(w, &back) && back == c,
		      "%s does not round-trip", w);
		CHECK(kof_dsrc_cap_word(c) != NULL, "%s has no word", w);
	}
}

int main(void)
{
	static const char *const dirs[] = { "bases/diagnoses", "tests/sigs/diagnoses" };
	unsigned k, files = 0;

	tables();
	mentions();
	edits();
	verdicts();
	for (k = 0; k < sizeof dirs / sizeof dirs[0]; k++) {
		DIR *dir = opendir(dirs[k]);
		struct dirent *de;

		if (!dir) {
			CHECK(0, "cannot open %s", dirs[k]);
			continue;
		}
		while ((de = readdir(dir)) != NULL) {
			size_t L = strlen(de->d_name);
			char path[512];

			if (L < 3u || strcmp(de->d_name + L - 2u, ".c"))
				continue;
			snprintf(path, sizeof path, "%s/%s", dirs[k], de->d_name);
			one_file(path);
			files++;
		}
		closedir(dir);
	}
	CHECK(files >= 11u, "only %u diagnose sources found", files);
	{
		static const char *const vdirs[] = { "bases/signatures", "tests/sigs" };
		unsigned vf = 0;

		for (k = 0; k < sizeof vdirs / sizeof vdirs[0]; k++) {
			DIR *dir = opendir(vdirs[k]);
			struct dirent *de;

			if (!dir)
				continue;
			while ((de = readdir(dir)) != NULL) {
				size_t L = strlen(de->d_name), tn = 0;
				char path[512], *t;

				if (L < 3u || strcmp(de->d_name + L - 2u, ".c"))
					continue;
				snprintf(path, sizeof path, "%s/%s", vdirs[k], de->d_name);
				t = slurp(path, &tn);
				if (t && (strstr(t, "kof_diag(") || strstr(t, "kof_diag_share(") ||
					  strstr(t, "kof_diag_str_"))) {
					verdict_file(path);
					vf++;
				}
				free(t);
			}
			closedir(dir);
		}
		CHECK(vf >= 5u, "only %u verdicts that read diagnoses found", vf);
		files += vf;
	}
	if (fails) {
		printf("diagsrc: %d failure(s)\n", fails);
		return 1;
	}
	printf("diagsrc: %u shipped sources read, written back and printed, "
	       "verdicts read and patched, edits touch only their own lines, comments are not read - ok\n",
	       files);
	return 0;
}
