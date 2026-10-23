/*
 * diagsrc - a diagnose's source read, shown and written back.
 *
 * What is pinned here is the property the editor depends on and nothing else
 * checks: a file is patched, never regenerated. Every diagnose source of the corpus (the
 * ones switched off in docs/disabled/ and the fixtures of tests/sigs/) is read
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
#include <kofmod/kofsig.h>   /* KOF_FMT_*, KOF_MALTYPE_* - no longer reached through the genome headers */
#include <celllysis/nucleo.h>

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
	"#include <kofmod/kofdiagtree.h>\n"
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
	      v.nd[0].flags == KGENOME_NUCLEO_F_WX, "fixture tree is wrong");
	pr0 = prose(src, n);

	/* Remove the second tail. Only its line goes. */
	*e = *d;
	for (i = 0; i < e->n; i++)
		if (e->item[i].kind == KDS_TAIL &&
		    e->item[i].a == KGENOME_NUCLEO_EXEC_REG) {
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
	e->item[e->n].a = KGENOME_NUCLEO_NET_OPEN;
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
		      v.nd[3].cap == KGENOME_NUCLEO_NET_OPEN &&
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

/* A declaration after column 2047 of its line is read, and the newlines the condition
 * parse needs are still there afterwards. The reader copied each line into 2048 bytes. */
static void long_line(void)
{
	static const char decl[] = "KOF_DIAG_NAME(DIAG_T);\nKOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\n";
	size_t pad = 70000, n = pad + sizeof decl - 1u;
	char *t = malloc(pad + sizeof decl);
	struct kof_dsrc *d = calloc(1, sizeof *d);

	CHECK(t && d, "out of memory");
	if (t && d) {
		memset(t, ' ', pad);
		memcpy(t + pad, decl, sizeof decl - 1u);
		/* the name declaration itself starts at column 70000 */
		CHECK(kof_dsrc_parse(t, n, d, NULL) == 0 && d->n == 2, "declarations after 70000 blanks: %u read", d->n);
	}
	free(t);
	free(d);
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

/*
 * The disease: one per diagnose, a lower-case path, read and printed back,
 * and a patch that adds one touches its own line only.
 */
static void disease(void)
{
	static const char good[] =
		"/* what it means */\n"
		"KOF_DIAG_NAME(DIAG_A);\n"
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"cnc/recv-syscall\");\n"
		"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
		"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
		"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n";
	static const char *const bad[] = {
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"Cnc/Recv\");\n",             /* upper case        */
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"cnc recv\");\n",             /* a space           */
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"/recv\");\n",                /* an empty part     */
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"recv/\");\n",
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"cnc//recv\");\n",
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, cnc/recv);\n",   /* not quoted        */
		"KOF_DECLARE_DISEASE(\"cnc/recv\");\n",                 /* no type           */
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_NOPE, \"cnc/recv\");\n",  /* not a maltype     */
		"KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"a\");\nKOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"b\");\n", /* two */
	};
	static struct kof_dsrc d;
	struct kof_dsrc_view v;
	struct kof_dsrc_report rep = { NULL, NULL, NULL };
	char line[128];
	unsigned k;

	CHECK(kof_dsrc_parse(good, sizeof good - 1u, &d, &rep) == 0, "a good source parses");
	CHECK(kof_dsrc_resolve(&d, &v, &rep) == 0, "and resolves");
	CHECK(!strcmp(v.disease, "cnc/recv-syscall") && v.disease_type == KOF_MALTYPE_BOTNET,
	      "the disease and its type reach the view: %s", v.disease);
	for (k = 0; k < d.n; k++)
		if (d.item[k].kind == KDS_DISEASE) {
			CHECK(kof_dsrc_print(&d.item[k], line, sizeof line) > 0 &&
			      !strcmp(line, "KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, \"cnc/recv-syscall\");"),
			      "printed as written: %s", line);
		}
	for (k = 0; k < sizeof bad / sizeof bad[0]; k++) {
		static char text[512];
		int errs;

		snprintf(text, sizeof text,
			 "KOF_DIAG_NAME(DIAG_B);\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
			 "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
			 "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n%s", bad[k]);
		errs = kof_dsrc_parse(text, strlen(text), &d, &rep);
		if (!errs)
			errs = kof_dsrc_resolve(&d, &v, &rep);
		CHECK(errs > 0, "refused: %s", bad[k]);
	}
}

int main(void)
{
	static const char *const dirs[] = { "docs/disabled/diagnoses", "tests/sigs/diagnoses" };
	unsigned k, files = 0;

	tables();
	disease();
	mentions();
	long_line();
	edits();
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
	if (fails) {
		printf("diagsrc: %d failure(s)\n", fails);
		return 1;
	}
	printf("diagsrc: %u diagnose sources read, written back and printed, "
	       "edits touch only their own lines, comments are not read - ok\n",
	       files);
	return 0;
}
