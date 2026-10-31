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

/*
 * THE CATALOG DECLARATIONS - KOF_DIAG_FAMILY / _VARIANT / _TYPE / _TAG: read, shown, patched, and
 * an unknown KOF_ line is said and not dropped. A source without them reads and prints exactly as
 * before (the corpus loop of main pins that), so what is pinned here is the new lines only.
 */
static unsigned warns;
static char last_warn[200];

static char last_err[200];

static void on_err(void *ud, int line, const char *m)
{
	(void)ud;
	(void)line;
	snprintf(last_err, sizeof last_err, "%s", m);
}

static void on_warn(void *ud, const char *m)
{
	(void)ud;
	warns++;
	snprintf(last_warn, sizeof last_warn, "%s", m);
}

static const char meta_src[] =
	"/* the evidence for the rule: MEASURED on 0 of 900 clean modules */\n"
	"KOF_DIAG_NAME(botnet_mirai_flood_01);\n"
	"KOF_DIAG_FAMILY(\"Mirai\");\n"
	"/* the variant is the catalog's own name */\n"
	"KOF_DIAG_VARIANT(\"A\");\n"
	"KOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\n"
	"KOF_DIAG_TAG(\"flood\");\n"
	"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n";

static const char plain_src[] =
	"/* the evidence for the rule: MEASURED on 0 of 900 clean modules */\n"
	"KOF_DIAG_NAME(botnet_mirai_flood_01);\n"
	"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n";

static struct kof_dsrc_item *item_of(struct kof_dsrc *d, unsigned kind)
{
	uint32_t q;

	for (q = 0; q < d->n; q++)
		if (d->item[q].kind == kind)
			return &d->item[q];
	return NULL;
}

static void catalog(void)
{
	static struct kof_dsrc d, e2, back;
	struct kof_dsrc_view v;
	struct kof_dsrc_report rep = { NULL, on_warn, NULL };
	size_t n = sizeof meta_src - 1u, pn = 0, k;
	char line[128];
	char *p, *pr0, *pr1;
	struct kof_dsrc_item *it;
	unsigned c;

	warns = 0;
	CHECK(kof_dsrc_parse(meta_src, n, &d, &rep) == 0 && warns == 0, "the source parses without a word said");
	CHECK(d.n == 8u, "eight declarations, got %u", d.n);
	CHECK(kof_dsrc_resolve(&d, &v, &rep) == 0, "and resolves");
	CHECK(!strcmp(v.family, "Mirai") && !strcmp(v.variant, "A") && !strcmp(v.tag, "flood") &&
	      v.type == KOF_MALTYPE_BOTNET && v.meta == KOF_DSRC_META_ALL, "the view carries the four");
	{
		static const struct { unsigned kind; const char *text; } want[] = {
			{ KDS_FAMILY,  "KOF_DIAG_FAMILY(\"Mirai\");" },
			{ KDS_VARIANT, "KOF_DIAG_VARIANT(\"A\");" },
			{ KDS_TYPE,    "KOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);" },
			{ KDS_TAG,     "KOF_DIAG_TAG(\"flood\");" },
		};

		for (k = 0; k < 4u; k++) {
			it = item_of(&d, want[k].kind);
			CHECK(it && kof_dsrc_print(it, line, sizeof line) > 0 && !strcmp(line, want[k].text),
			      "printed as written: %s", it ? line : "(missing)");
		}
	}
	/* No-op patch: byte for byte. */
	p = kof_dsrc_patch(meta_src, n, &d, &pn);
	CHECK(p && pn == n && !memcmp(p, meta_src, n), "a no-op patch changed the source");
	free(p);

	/* Replace the tag: one line changes, the comments around it do not. */
	memcpy(&e2, &d, sizeof e2);
	it = item_of(&e2, KDS_TAG);
	snprintf(it->s1, sizeof it->s1, "%s", "c2");
	p = kof_dsrc_patch(meta_src, n, &e2, &pn);
	CHECK(p && strstr(p, "KOF_DIAG_TAG(\"c2\");\n") && !strstr(p, "\"flood\"") &&
	      lines_of(p) == lines_of(meta_src), "the tag line is replaced in place");
	pr0 = prose(meta_src, n);
	pr1 = p ? prose(p, pn) : NULL;
	CHECK(pr1 && !strcmp(pr0, pr1), "replacing the tag changed the prose");
	CHECK(p && kof_dsrc_parse(p, pn, &back, &rep) == 0 &&
	      kof_dsrc_resolve(&back, &v, &rep) == 0 && !strcmp(v.tag, "c2"), "and it reads back");
	free(p); free(pr0); free(pr1);

	/* Remove the family line: one line fewer, and the four are no longer all there. */
	memcpy(&e2, &d, sizeof e2);
	for (c = 0; c < e2.n; c++)
		if (e2.item[c].kind == KDS_FAMILY) {
			memmove(&e2.item[c], &e2.item[c + 1u], (e2.n - c - 1u) * sizeof e2.item[0]);
			e2.n--;
			break;
		}
	p = kof_dsrc_patch(meta_src, n, &e2, &pn);
	CHECK(p && lines_of(p) == lines_of(meta_src) - 1 && !strstr(p, "KOF_DIAG_FAMILY"), "the family line is removed");
	CHECK(p && strstr(p, "/* the variant is the catalog's own name */"), "its neighbour's comment stays");
	CHECK(p && kof_dsrc_parse(p, pn, &back, &rep) == 0 && kof_dsrc_resolve(&back, &v, NULL) > 0,
	      "three of the four is an error: they go together");
	free(p);

	/* Add the four to a source without them: only new lines appear. */
	pn = sizeof plain_src - 1u;
	CHECK(kof_dsrc_parse(plain_src, pn, &d, &rep) == 0, "the plain source parses");
	memcpy(&e2, &d, sizeof e2);
	{
		static const unsigned kinds[4] = { KDS_FAMILY, KDS_VARIANT, KDS_TYPE, KDS_TAG };

		for (c = 0; c < 4u; c++) {
			it = &e2.item[e2.n++];
			memset(it, 0, sizeof *it);
			it->kind = (uint8_t)kinds[c];
			if (kinds[c] == KDS_FAMILY)
				snprintf(it->s1, sizeof it->s1, "Mirai");
			else if (kinds[c] == KDS_VARIANT)
				snprintf(it->s1, sizeof it->s1, "A");
			else if (kinds[c] == KDS_TAG)
				snprintf(it->s1, sizeof it->s1, "flood");
			else
				it->a = KOF_MALTYPE_BOTNET;
		}
	}
	p = kof_dsrc_patch(plain_src, pn, &e2, &pn);
	CHECK(p && lines_of(p) == lines_of(plain_src) + 4, "four lines are added, nothing else");
	pr0 = prose(plain_src, sizeof plain_src - 1u);
	pr1 = p ? prose(p, pn) : NULL;
	CHECK(pr1 && !strcmp(pr0, pr1), "adding them changed the prose");
	CHECK(p && kof_dsrc_parse(p, pn, &back, &rep) == 0 && kof_dsrc_resolve(&back, &v, &rep) == 0 &&
	      !strcmp(v.family, "Mirai") && !strcmp(v.variant, "A") && !strcmp(v.tag, "flood") &&
	      v.type == KOF_MALTYPE_BOTNET, "and they read back");
	{
		size_t qn = 0;
		char *q = p ? kof_dsrc_patch(p, pn, &back, &qn) : NULL;

		CHECK(q && qn == pn && !memcmp(p, q, pn), "the patched text is stable under another patch");
		free(q);
	}
	free(p); free(pr0); free(pr1);

	/* An unknown macro line is said, with its line, and is not an error, and the patcher keeps it. */
	{
		static const char unk[] =
			"KOF_DIAG_NAME(a);\n"
			"KOF_DIAG_FUTURE(1);\n"
			"/* KOF_IN_A_COMMENT(1); is only a mention */\n"
			"KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n";
		size_t un = sizeof unk - 1u, qn = 0;

		warns = 0;
		last_warn[0] = 0;
		CHECK(kof_dsrc_parse(unk, un, &d, &rep) == 0, "an unknown macro is not an error");
		CHECK(warns == 1 && strstr(last_warn, "line 2") && strstr(last_warn, "KOF_DIAG_FUTURE"),
		      "it is said once, with its line: '%s'", last_warn);
		CHECK(d.n == 2u, "and is not a declaration: %u", d.n);
		p = kof_dsrc_patch(unk, un, &d, &qn);
		CHECK(p && qn == un && !memcmp(p, unk, un), "the patcher leaves the line where it was");
		free(p);
	}

	/* What a line may not say. */
	{
		static const char *const bad[] = {
			"KOF_DIAG_FAMILY(Mirai);\n",                 /* not quoted         */
			"KOF_DIAG_FAMILY(\"\");\n",                  /* empty              */
			"KOF_DIAG_FAMILY(\"a b\");\n",               /* a space            */
			"KOF_DIAG_FAMILY(\"a,b\");\n",               /* splits the line    */
			"KOF_DIAG_FAMILY(\"a/b\");\n",
			"KOF_DIAG_FAMILY();\n",
			"KOF_DIAG_VARIANT(\"Mirai_A\");\n",              /* the family is not part of it */
			"KOF_DIAG_VARIANT(\"a\");\n",                   /* lower case          */
			"KOF_DIAG_VARIANT(\"A1\");\n",
			"KOF_DIAG_VARIANT(\"ABCDEFGHI\");\n",            /* nine letters        */
			"KOF_DIAG_VARIANT(\"\");\n",
			"KOF_DIAG_TYPE(KOF_MALTYPE_NOPE);\n",
			"KOF_DIAG_TYPE(Botnet);\n",
			"KOF_DIAG_TYPE();\n",
		};

		for (c = 0; c < sizeof bad / sizeof bad[0]; c++) {
			static char text[256];
			int errs;

			snprintf(text, sizeof text, "KOF_DIAG_NAME(b);\n%s", bad[c]);
			errs = kof_dsrc_parse(text, strlen(text), &d, &rep);
			CHECK(errs > 0, "refused: %s", bad[c]);
		}
		{
			static const char old_form[] = "KOF_DIAG_NAME(b);\nKOF_DIAG_VARIANT(\"Mirai_A\");\n";
			struct kof_dsrc_report er = { on_err, NULL, NULL };

			last_err[0] = 0;
			CHECK(kof_dsrc_parse(old_form, sizeof old_form - 1u, &d, &er) == 1 &&
			      strstr(last_err, "letters only") != NULL,
			      "Mirai_A is refused with a clear message: '%s'", last_err);
		}
		/* A name over the bound, and the declaration twice. */
		{
			static char text[512];
			char long_name[80];

			memset(long_name, 'a', sizeof long_name - 1u);
			long_name[sizeof long_name - 1u] = 0;
			snprintf(text, sizeof text, "KOF_DIAG_TAG(\"%s\");\n", long_name);
			CHECK(kof_dsrc_parse(text, strlen(text), &d, &rep) > 0, "a name of 79 characters is refused");
			snprintf(text, sizeof text, "KOF_DIAG_NAME(b);\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n"
				 "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n"
				 "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
				 "KOF_DIAG_FAMILY(\"A\");\nKOF_DIAG_FAMILY(\"B\");\nKOF_DIAG_VARIANT(\"A\");\n"
				 "KOF_DIAG_TYPE(KOF_MALTYPE_BOTNET);\nKOF_DIAG_TAG(\"t\");\n");
			CHECK(kof_dsrc_parse(text, strlen(text), &d, &rep) == 0, "twice parses ...");
			CHECK(kof_dsrc_resolve(&d, &v, &rep) > 0, "... and resolve refuses it");
		}
	}

	/* A call that is never closed is refused: an error, and no item (WD-1). */
	{
		static const char open_call[] = "KOF_DIAG_TAG(\"flood\"\n";

		CHECK(kof_dsrc_parse(open_call, sizeof open_call - 1u, &d, &rep) > 0 && d.n == 0u,
		      "an unclosed KOF_DIAG_TAG( is refused (WD-1)");
	}

	/* Every byte in a name, exhaustively: a name the printer writes is a name the reader reads. */
	{
		unsigned b, accepted = 0;

		for (b = 1; b < 256u; b++) {
			char w[4], text[64];
			int errs;

			w[0] = 'a'; w[1] = (char)b; w[2] = 'c'; w[3] = 0;
			if (b == '\n')
				continue;
			snprintf(text, sizeof text, "KOF_DIAG_TAG(\"%s\");\n", w);
			errs = kof_dsrc_parse(text, strlen(text), &d, &rep);
			CHECK((errs == 0) == (kof_dsrc_catalog_word_ok(w) != 0),
			      "byte 0x%02x: reader and word rule disagree", b);
			if (errs == 0) {
				accepted++;
				char want[80];

				snprintf(want, sizeof want, "KOF_DIAG_TAG(\"%s\");", w);
				CHECK(d.n == 1u && !strcmp(d.item[0].s1, w) &&
				      kof_dsrc_print(&d.item[0], line, sizeof line) > 0 &&
				      !strcmp(line, want),
				      "byte 0x%02x does not round trip", b);
			}
		}
		/* letters, digits, '_' and '-' */
		CHECK(accepted == 26u + 26u + 10u + 2u, "%u bytes accepted, want 64", accepted);
	}
	/* The printer refuses what the reader would. */
	{
		struct kof_dsrc_item bad_it;

		memset(&bad_it, 0, sizeof bad_it);
		bad_it.kind = KDS_TAG;
		snprintf(bad_it.s1, sizeof bad_it.s1, "a b");
		CHECK(kof_dsrc_print(&bad_it, line, sizeof line) == 0, "the printer refuses a bad name");
		bad_it.kind = KDS_TYPE;
		bad_it.a = (uint16_t)KOF_MALTYPE_COUNT;
		CHECK(kof_dsrc_print(&bad_it, line, sizeof line) == 0, "and a type that is no maltype");
	}
}

int main(void)
{
	static const char *const dirs[] = { "docs/disabled/diagnoses", "tests/sigs/diagnoses" };
	unsigned k, files = 0;

	tables();
	disease();
	catalog();
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
