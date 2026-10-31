/*
 * diagsrc_form - the detection form of a diagnose SOURCE: read, written back, patched and resolved.
 *
 * The declarations are the ones a signature made (KOF_TARGET_RANGE, KOF_DEFINE_STR / _STR_WIDE / _HEXSTR / _REGEX,
 * KOF_MUTATION_BLOCK[_LIB]) plus KOF_DIAG_FIND, KOF_DIAG_SIMILAR and KOF_DIAG_EXPR, which stand for what a module wrote in
 * its kof_scan. What is pinned, and (c) the way the old tests could not have: before this the reader warned "unknown
 * declaration" and went on, so the first assertion of every case here fails on the old tree.
 *
 *   ROUND TRIP    every string over a small alphabet of the characters that break a reader (quote, backslash, the
 *                 question mark C reads as a trigraph, comma, parentheses, semicolon, a comment opener, the three
 *                 whitespace escapes) written and read back: 14^4 literals, 15^4 regex texts, the bytes a literal cannot
 *                 spell are REFUSED by the printer, never written as other bytes; a hash list of any length 16..128.
 *   PATCH         an edit changes the lines of the declarations it names and nothing else; the comment lines around a
 *                 form, its blank lines and every declaration that did not change survive byte for byte.
 *   RESOLVE       the rules, one source each, with the line the error names: a name taken twice, an unknown name, a
 *                 threshold that cannot be reached, an AT matcher with two markers or a range, an unknown region, an escape
 *                 the language does not have, a regex with `*`, a hex pattern with no concrete byte, 15 and 129 hashes,
 *                 strings and blocks in one form, a graph and a form in one diagnose, a bad expression (open parenthesis,
 *                 unknown matcher, trailing junk, nested past the bound).
 *   CAPS          each bound at the value and one past it, a hard error and never a cut.
 *   EXPRESSION    2000 random expressions with parentheses over five matchers, the resolved tree evaluated on all 32
 *                 assignments against an independent evaluator of the text (precedence ! over && over ||).
 *   FORMAT        several formats are a SET fact (the old reader ORed their numbers into a number that names none).
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/databases/diagsrc.h"
#include <kofmod/kofsig.h>
#include <celllysis/nucleo.h>
#include <celllysis/mutation_window.h>
#include "../../libkofeng/analyzers/parsers/kofformat.h"

static int failures;

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define OKF(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

struct said {
	int  n_err, n_warn, line;
	char first[200];
	char warns[2000];
};

static void on_err(void *ud, int line, const char *m)
{
	struct said *s = ud;

	if (!s->n_err++) {
		s->line = line;
		snprintf(s->first, sizeof s->first, "%s", m);
	}
}

static void on_warn(void *ud, const char *m)
{
	struct said *s = ud;

	s->n_warn++;
	if (strlen(s->warns) + strlen(m) + 2u < sizeof s->warns) {
		strcat(s->warns, m);
		strcat(s->warns, "\n");
	}
}

static struct kof_dsrc *D;

/* Parse and resolve `text`; the errors come back in `s`. `v` must be freed by the caller when it holds a form. */
static int load(const char *text, struct kof_dsrc_view *v, struct said *s)
{
	struct kof_dsrc_report rep = { on_err, on_warn, s };
	int e;

	memset(s, 0, sizeof *s);
	memset(v, 0, sizeof *v);
	e = kof_dsrc_parse(text, strlen(text), D, &rep);
	if (!e)
		e = kof_dsrc_resolve(D, v, &rep);
	return e;
}

/* The header every case shares: a name, and (so that a form needs nothing else) nothing more. */
#define HEAD "KOF_DIAG_NAME(t);\n"

static int resolves(const char *body)
{
	char *t = malloc(strlen(body) + sizeof HEAD + 1u);
	struct kof_dsrc_view v;
	struct said s;
	int e;

	sprintf(t, "%s%s", HEAD, body);
	e = load(t, &v, &s);
	if (e)
		printf("    unexpected: %s (line %d)\n", s.first, s.line);
	kof_dsrc_view_free(&v);
	free(t);
	return e == 0;
}

/* The source is refused with `why` in the first message, on `line` (0: any line). */
static int refused(const char *body, const char *why, int line)
{
	char *t = malloc(strlen(body) + sizeof HEAD + 1u);
	struct kof_dsrc_view v;
	struct said s;
	int e, good;

	sprintf(t, "%s%s", HEAD, body);
	e = load(t, &v, &s);
	good = e > 0 && strstr(s.first, why) != NULL && (!line || s.line == line + 1);
	if (!good)
		printf("    wanted \"%s\" on line %d, got %d error(s): \"%s\" on line %d\n", why, line, e, s.first, s.line);
	kof_dsrc_view_free(&v);
	free(t);
	return good;
}

/* ---- a full source: every declaration, printed and read back ------------------------- */

static const char *const FULL =
	"/* a form with every declaration */\n"
	"KOF_DIAG_NAME(full);\n"
	"KOF_TARGET_FORMAT(KOF_FMT_ELF);\n"
	"KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);\n"
	"KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);\n"
	"// the markers\n"
	"KOF_DEFINE_STR(s0, \"/bin/sh\", KOF_CASE_EXACT, KOF_WORD_FULLWORD);\n"
	"KOF_DEFINE_STR(s1, \"say \\\"hi\\\" \\\\ ok\\?\\t\\n\", KOF_CASE_ICASE, KOF_WORD_TOKEN);\n"
	"KOF_DEFINE_STR_WIDE(s2, \"IEX(New-Object\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_HEXSTR(s3, \"E8 ?? ?? ?? ?? 5D 5E 5F 90 C3\");\n"
	"KOF_DEFINE_HEXSTR(s4, \"( E8 | E9 ) ?? ?? ?? ?? 5D 5E 5F 90\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
	"KOF_DEFINE_REGEX(s5, \"GET /[a-z]{4}\\\\.php\");\n"
	"KOF_DEFINE_REGEX(s6, \"POST /[a-z]{2}\", KOF_CASE_ICASE, KOF_WORD_SUBSTRING);\n"
	"KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0, s1);\n"
	"KOF_DIAG_FIND(m1, KOF_FIND_ANY, everything, s2, s3, s4);\n"
	"KOF_DIAG_FIND(m2, KOF_FIND_MULTI(2), code, s5, s6, s0);\n"
	"KOF_DIAG_FIND(m3, KOF_FIND_AT(KOF_ANCHOR_ENTRY, -8), s3);\n"
	"KOF_DIAG_EXPR(m0 && (m1 || !m2) || m3);\n";

static void read_print_back(void)
{
	struct kof_dsrc_view v;
	struct said s;
	uint32_t q, found = 0, same = 0;
	struct kof_dsrc *r = calloc(1, sizeof *r);
	char line[8192];
	static const unsigned want[] = { KDS_NAME, KDS_FORMAT, KDS_RANGE, KDS_RANGE, KDS_STR, KDS_STR, KDS_STR, KDS_STR,
					 KDS_STR, KDS_STR, KDS_STR, KDS_FIND, KDS_FIND, KDS_FIND, KDS_FIND, KDS_EXPR };

	{
		int e = load(FULL, &v, &s);

		if (e || s.n_warn)
			printf("    full source: %d error(s), first \"%s\" line %d; %d warning(s): %s\n", e, s.first, s.line,
			       s.n_warn, s.warns);
		ok("the full source reads and resolves", e == 0 && s.n_warn == 0);
	}
	ok("it has the declarations it was written with, in order", D->n == sizeof want / sizeof want[0]);
	for (q = 0; q < D->n && q < sizeof want / sizeof want[0]; q++)
		found += D->item[q].kind == want[q];
	ok("of the kinds it was written with", found == D->n);
	ok("the resolved form has 7 strings, 4 matchers and no block", v.form && v.form->n_str == 7u &&
	   v.form->n_match == 4u && v.form->n_block == 0u && !v.form->n_sim);
	/* the strings as the engine will search for them: flags and bytes */
	if (v.form) {
		const struct kof_form_str *s0 = &v.form->str[0], *s1 = &v.form->str[1], *s2 = &v.form->str[2];

		ok("s0 is the literal /bin/sh, a whole word",
		   s0->kind == 0 && s0->len == 7u && !memcmp(v.form->pool + s0->off, "/bin/sh", 7u) &&
		   (s0->flags & 3u) == 2u);
		ok("s1 had its escapes undone: say \"hi\" \\ ok?<tab><newline>, case folded, a whole token",
		   s1->len == 16u && !memcmp(v.form->pool + s1->off, "say \"hi\" \\ ok?\t\n", 16u) && (s1->flags & 1u) &&
		   (s1->flags & 8u));
		ok("s2 is widened: one byte and a zero for each", s2->len == 28u && v.form->pool[s2->off] == 'I' &&
		   v.form->pool[s2->off + 1u] == 0 && (s2->flags & 4u));
		ok("s3 and s4 are compiled programs, s5 and s6 too", v.form->str[3].kind == 1 && v.form->str[4].kind == 1 &&
		   v.form->str[5].kind == 1 && v.form->str[6].kind == 1);
		ok("m3 is AT the entry point, 8 before it, one marker",
		   v.form->match[3].rule == KOF_FORM_R_AT && v.form->match[3].anchor == KOF_FORM_ANCHOR_ENTRY &&
		   v.form->match[3].at == -8 && v.form->match[3].n == 1u && v.form->match[3].mask == 0u);
		ok("m2 wants 2 of its 3", v.form->match[2].rule == KOF_FORM_R_MULTI && v.form->match[2].thresh == 2u &&
		   v.form->match[2].n == 3u);
	}
	/* every declaration prints, and what it prints reads back as the same declaration */
	for (q = 0; q < D->n; q++) {
		size_t n = kof_dsrc_print(&D->item[q], line, sizeof line);
		int e;

		if (!n) {
			OKF(0, "item %u (kind %u) does not print", q, D->item[q].kind);
			continue;
		}
		e = kof_dsrc_parse(line, n, r, NULL);
		if (e || r->n != 1u || !kof_dsrc_same(&D->item[q], &r->item[0])) {
			OKF(0, "item %u reads back as another declaration: %s", q, line);
			continue;
		}
		same++;
	}
	ok("all sixteen print and read back as themselves", same == D->n);
	/* and the unchanged source patched with its own declarations is the same bytes */
	{
		size_t pn = 0;
		char *p = kof_dsrc_patch(FULL, strlen(FULL), D, &pn);

		ok("a no-op patch of the whole form gives back the same bytes", p && pn == strlen(FULL) && !memcmp(p, FULL, pn));
		free(p);
	}
	kof_dsrc_view_free(&v);
	free(r);
}

/* ---- exhaustive: what a literal and a regex text are made of ------------------------- */

static void lit_round_trip(void)
{
	static const char alpha[] = { 'a', '"', '\\', '?', ',', '(', ')', ';', '/', '*', ' ', '\t', '\n', '\r' };
	const uint32_t A = sizeof alpha;
	struct kof_dsrc *w = calloc(1, sizeof *w), *r = calloc(1, sizeof *r);
	uint32_t total = 0, good = 0, L, idx, k;
	char line[8192];

	for (L = 1; L <= 4u; L++) {
		uint32_t count = 1;

		for (k = 0; k < L; k++)
			count *= A;
		for (idx = 0; idx < count; idx++) {
			uint8_t b[4];
			uint32_t t = idx;
			struct kof_dsrc_item *it = &w->item[0];
			size_t n;

			for (k = 0; k < L; k++) {
				b[k] = (uint8_t)alpha[t % A];
				t /= A;
			}
			memset(w, 0, sizeof *w);
			memset(it, 0, sizeof *it);
			it->kind = KDS_STR;
			it->a = KDS_STR_PLAIN;
			it->b = KDS_OPT_GIVEN;
			snprintf(it->s1, sizeof it->s1, "s0");
			it->t1 = kof_dsrc_text(w, (const char *)b, L);
			it->n1 = L;
			total++;
			n = kof_dsrc_print(it, line, sizeof line);
			if (n && kof_dsrc_parse(line, n, r, NULL) == 0 && r->n == 1u && r->item[0].n1 == L &&
			    !memcmp(r->item[0].t1, b, L))
				good++;
		}
	}
	OKF(good == total, "%u of %u literals over the hostile alphabet came back as the bytes written", good, total);
	/* the bytes with no spelling are refused, not written as other bytes */
	{
		static const uint8_t bad[] = { 0x00, 0x01, 0x1f, 0x7f, 0x80, 0xff };
		uint32_t refused_n = 0;

		for (k = 0; k < sizeof bad; k++) {
			uint8_t b[3] = { 'a', bad[k], 'b' };
			struct kof_dsrc_item *it = &w->item[0];

			memset(w, 0, sizeof *w);
			it->kind = KDS_STR;
			it->a = KDS_STR_PLAIN;
			it->b = KDS_OPT_GIVEN;
			snprintf(it->s1, sizeof it->s1, "s0");
			it->t1 = kof_dsrc_text(w, (const char *)b, 3u);
			it->n1 = 3u;
			refused_n += kof_dsrc_print(it, line, sizeof line) == 0;
			OKF(kof_dsrc_lit_escape(b, 3u, line, sizeof line) == 0, "byte %02x got a spelling", (unsigned)bad[k]);
		}
		ok("a byte with no spelling is refused by the printer", refused_n == sizeof bad);
	}
	free(w);
	free(r);
}

static void regex_round_trip(void)
{
	static const char alpha[] = { 'a', '\\', '"', '.', '[', ']', '(', ')', '{', '}', '1', ',', ';', '|', ' ' };
	const uint32_t A = sizeof alpha;
	struct kof_dsrc *w = calloc(1, sizeof *w), *r = calloc(1, sizeof *r);
	uint32_t total = 0, good = 0, L, idx, k;
	char line[8192];

	for (L = 1; L <= 4u; L++) {
		uint32_t count = 1;

		for (k = 0; k < L; k++)
			count *= A;
		for (idx = 0; idx < count; idx++) {
			char b[5];
			uint32_t t = idx;
			struct kof_dsrc_item *it = &w->item[0];
			size_t n;

			for (k = 0; k < L; k++) {
				b[k] = alpha[t % A];
				t /= A;
			}
			memset(w, 0, sizeof *w);
			it->kind = KDS_STR;
			it->a = KDS_STR_REGEX;
			snprintf(it->s1, sizeof it->s1, "s0");
			it->t1 = kof_dsrc_text(w, b, L);
			it->n1 = L;
			total++;
			n = kof_dsrc_print(it, line, sizeof line);
			if (n && kof_dsrc_parse(line, n, r, NULL) == 0 && r->n == 1u && r->item[0].n1 == L &&
			    !memcmp(r->item[0].t1, b, L))
				good++;
		}
	}
	OKF(good == total, "%u of %u regex texts over the hostile alphabet came back as written", good, total);
	free(w);
	free(r);
}

static void hash_round_trip(void)
{
	struct kof_dsrc *w = calloc(1, sizeof *w), *r = calloc(1, sizeof *r);
	uint32_t n, k, good = 0, total = 0, seed = 12345u;
	char line[8192];

	for (n = 1; n <= 130u; n++) {
		uint32_t h[130];
		struct kof_dsrc_item *it = &w->item[0];
		size_t len;

		for (k = 0; k < n; k++) {
			seed = seed * 1664525u + 1013904223u;
			h[k] = seed;
		}
		memset(w, 0, sizeof *w);
		it->kind = KDS_BLOCK;
		it->b = n & 1u;
		it->v = KOF_SCAN_ALL;
		snprintf(it->s1, sizeof it->s1, "b0");
		it->t1 = kof_dsrc_text(w, "KOF_SCAN_ALL", 12u);
		it->n1 = 12u;
		it->t2 = kof_dsrc_text(w, (const char *)h, (size_t)n * 4u);
		it->n2 = n * 4u;
		len = kof_dsrc_print(it, line, sizeof line);
		total++;
		if (len && kof_dsrc_parse(line, len, r, NULL) == 0 && r->n == 1u && kof_dsrc_same(it, &r->item[0]) &&
		    r->item[0].n2 == n * 4u)
			good++;
	}
	/* 1..128 hashes round-trip through the reader; 129 and 130 are refused AT THE READER (a block holds 128) */
	OKF(good == 128u && total == 130u, "hash lists of 1..128 read back (%u of 130)", good);
	free(w);
	free(r);
}

/* ---- patching: an edit changes the lines it names and nothing else ------------------------ */

static void patch_keeps_prose(void)
{
	static const char *const src =
		"/* evidence: seen in 12 of 400 samples */\n"
		"KOF_DIAG_NAME(p);\n"
		"\n"
		"// the range\n"
		"KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n"
		"KOF_DEFINE_STR(s0, \"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);   /* trailing words */\n"
		"KOF_DEFINE_STR(s1, \"beta\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		"KOF_DEFINE_STR(s2, \"gamma\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		"/* the matcher: at least two of three */\n"
		"KOF_DIAG_FIND(m0, KOF_FIND_MULTI(2), code, s0, s1, s2);\n"
		"KOF_DIAG_EXPR(m0);\n"
		"// end\n";
	struct kof_dsrc *e = calloc(1, sizeof *e);
	struct kof_dsrc_report rep = { NULL, NULL, NULL };
	size_t n = strlen(src), pn = 0;
	char *p;
	uint32_t q;

	kof_dsrc_parse(src, n, D, &rep);
	memcpy(e, D, sizeof *e);
	/* the pointers of the copy still point into D's pool, which is alive: that is what an editor's copy of the list does */
	for (q = 0; q < e->n; q++)
		if (e->item[q].kind == KDS_FIND)
			e->item[q].b = 3;               /* MULTI(3) */
	p = kof_dsrc_patch(src, n, e, &pn);
	ok("an edit of the threshold gives a text", p != NULL);
	if (p) {
		ok("MULTI(2) became MULTI(3)", strstr(p, "KOF_FIND_MULTI(3)") && !strstr(p, "KOF_FIND_MULTI(2)"));
		ok("the comment before the first declaration survived", !strncmp(p, "/* evidence: seen in 12 of 400 samples */\n", 42u));
		ok("the blank line and the comment of the range survived", strstr(p, "KOF_DIAG_NAME(p);\n\n// the range\n") != NULL);
		ok("a line with words after its declaration is kept whole (its declaration did not change)",
		   strstr(p, "\"alpha\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);   /* trailing words */\n") != NULL);
		ok("the comment above the matcher and the closing comment survived",
		   strstr(p, "/* the matcher: at least two of three */\nKOF_DIAG_FIND(m0, KOF_FIND_MULTI(3)") != NULL &&
		   strstr(p, "// end\n") != NULL);
		free(p);
	}
	/* remove a string and a new matcher at the end */
	{
		uint32_t keep = 0;

		memcpy(e, D, sizeof *e);
		for (q = 0; q < e->n; q++)
			if (!(e->item[q].kind == KDS_STR && !strcmp(e->item[q].s1, "s1")))
				e->item[keep++] = e->item[q];
		e->n = keep;
		e->item[e->n].kind = KDS_FIND;
		e->item[e->n].line = 0;
		snprintf(e->item[e->n].s1, sizeof e->item[e->n].s1, "m1");
		snprintf(e->item[e->n].s2, sizeof e->item[e->n].s2, "code");
		e->item[e->n].a = KOF_FORM_R_ANY;
		e->item[e->n].t1 = kof_dsrc_text(e, "s0", 2u);
		e->item[e->n].n1 = 2u;
		e->n++;
		p = kof_dsrc_patch(src, n, e, &pn);
		ok("a removed declaration loses its line and nothing else", p && !strstr(p, "\"beta\"") && strstr(p, "\"alpha\"") &&
		   strstr(p, "\"gamma\"") && strstr(p, "// the range\n") && strstr(p, "// end\n"));
		ok("a new declaration is written as a line", p && strstr(p, "KOF_DIAG_FIND(m1, KOF_FIND_ANY, code, s0);\n") != NULL);
		free(p);
	}
	free(e);
}

/* ---- the rules, one source each ------------------------------------------------------------ */

static void rules(void)
{
	static const char *const base =
		"KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n"
		"KOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		"KOF_DEFINE_STR(s1, \"def\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n";
	char b[4096];

/* `line` counts the lines of the TAIL, the first being 1; the three declarations of `base` come before it. */
#define CASE_REFUSED(tail, why, line) do { snprintf(b, sizeof b, "%s%s", base, tail); \
		OKF(refused(b, why, (line) ? (line) + 3 : 0), "%s", why); } while (0)
#define CASE_OK(tail) do { snprintf(b, sizeof b, "%s%s", base, tail); OKF(resolves(b), "should resolve: %s", tail); } while (0)

	CASE_OK("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0, s1);\n");
	CASE_OK("KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m1, KOF_FIND_ALL, code, s1);\nKOF_DIAG_EXPR(m0 && m1);\n");
	CASE_OK("KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 0), s0);\n");
	CASE_OK("KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_EOF, -16), s0);\n");
	CASE_OK("KOF_DIAG_FIND(m0, KOF_FIND_MULTI(2), code, s0, s1);\n");

	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s1);\n",
		     "matcher with this name is already declared", 2);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s9);\n", "names a string that is not declared", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, nowhere, s0);\n", "names a range that is not declared", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_MULTI(3), code, s0, s1);\n", "cannot ask for more markers", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_MULTI(0), code, s0, s1);\n", "KOF_FIND_MULTI(n)", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 0), s0, s1);\n", "ONE marker", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_MID, 0), s0);\n", "anchor is KOF_ANCHOR_BOF", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0, s0);\n", "listed twice", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_SOME, code, s0);\n", "the rule is KOF_FIND_ALL", 1);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0\n", "not closed on its line", 1);
	CASE_REFUSED("KOF_DEFINE_STR(s0, \"again\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\n",
		     "string with this name is already declared", 1);
	CASE_REFUSED("KOF_TARGET_RANGE(bad, KOF_SCAN_NOT_A_REGION);\n", "unknown region", 1);
	CASE_REFUSED("KOF_TARGET_RANGE(code, KOF_SCAN_ELF_DATA);\n", "range with this name is already declared", 1);
	CASE_REFUSED("KOF_DEFINE_STR(x, \"a\\x41b\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", "only \\\\", 1);
	CASE_REFUSED("KOF_DEFINE_STR(x, \"\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", "empty pattern", 1);
	CASE_REFUSED("KOF_DEFINE_STR(x, \"ab\", KOF_CASE_EXACT);\n", "wants a plain name, a literal and both options", 1);
	CASE_REFUSED("KOF_DEFINE_STR(x, \"ab\", KOF_CASE_LOOSE, KOF_WORD_SUBSTRING);\n", "the case option", 1);
	CASE_REFUSED("KOF_DEFINE_STR(x, \"ab\", KOF_CASE_EXACT, KOF_WORD_WHOLE);\n", "the word option", 1);
	CASE_REFUSED("KOF_DEFINE_STR(x, \"abc, KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", "not closed on its line", 1);
	CASE_REFUSED("KOF_DEFINE_STR_WIDE(x, \"caf\xc3\xa9\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, x);\n",
		     "a wide pattern must be ASCII", 1);
	CASE_REFUSED("KOF_DEFINE_REGEX(x, \"a*\");\nKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, x);\n", "", 0);
	CASE_REFUSED("KOF_DEFINE_HEXSTR(x, \"?? ?? ??\");\nKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, x);\n", "", 0);
	CASE_REFUSED("KOF_DEFINE_HEXSTR(x, \"E8 ZZ\");\nKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, x);\n", "", 0);

	/* blocks */
	{
		char blk[2600];
		uint32_t k, n;

		for (n = 14; n <= 16u; n++) {
			size_t at = (size_t)snprintf(blk, sizeof blk, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");

			for (k = 0; k < n; k++)
				at += (size_t)snprintf(blk + at, sizeof blk - at, ", 0x%08xu", k * 977u + 5u);
			snprintf(blk + at, sizeof blk - at, ");\nKOF_DIAG_SIMILAR(m0, 60, b0);\n");
			if (n < 16u)
				OKF(refused(blk, "too few hashes", 1), "%u hashes do not score a block", n);
			else
				OKF(resolves(blk), "16 hashes are the least a block scores with");
		}
		{
			size_t at = (size_t)snprintf(blk, sizeof blk, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");

			for (k = 0; k < 129u; k++)
				at += (size_t)snprintf(blk + at, sizeof blk - at, ", 0x%08xu", k * 977u + 5u);
			snprintf(blk + at, sizeof blk - at, ");\nKOF_DIAG_SIMILAR(m0, 60, b0);\n");
			OKF(refused(blk, "more hashes than a block may carry", 1), "129 hashes are over a block's bound");
		}
		{
			size_t at = (size_t)snprintf(blk, sizeof blk, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");

			for (k = 0; k < 128u; k++)
				at += (size_t)snprintf(blk + at, sizeof blk - at, ", %uu", k * 977u + 5u);
			{
				size_t short_at = (size_t)snprintf(blk, sizeof blk, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");

				for (k = 0; k < 16u; k++)
					short_at += (size_t)snprintf(blk + short_at, sizeof blk - short_at, ", %uu", k * 977u + 5u);
				snprintf(blk + short_at, sizeof blk - short_at, ", 4294967296u);\nKOF_DIAG_SIMILAR(m0, 50, b0);\n");
				OKF(refused(blk, "a hash that is not a number", 1), "a hash wider than 32 bits");
				at = (size_t)snprintf(blk, sizeof blk, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");
				for (k = 0; k < 128u; k++)
					at += (size_t)snprintf(blk + at, sizeof blk - at, ", %uu", k * 977u + 5u);
			}
			snprintf(blk + at, sizeof blk - at, ");\nKOF_DIAG_SIMILAR(m0, 100, b0);\n");
			OKF(resolves(blk), "128 hashes, written in decimal, and a threshold of 100");
			snprintf(blk + at, sizeof blk - at, ");\nKOF_DIAG_SIMILAR(m0, 101, b0);\n");
			OKF(refused(blk, "a percentage from 1 to 100", 2), "101 percent");
			snprintf(blk + at, sizeof blk - at, ");\nKOF_DIAG_SIMILAR(m0, 0, b0);\n");
			OKF(refused(blk, "a percentage from 1 to 100", 2), "0 percent");
			snprintf(blk + at, sizeof blk - at, ");\nKOF_DIAG_SIMILAR(m0, 50, b7);\n");
			OKF(refused(blk, "block that is not declared", 2), "an undeclared block");
			snprintf(blk + at, sizeof blk - at, ");\nKOF_MUTATION_BLOCK_LIB(b0, KOF_SCAN_ALL, 1u);\n");
			OKF(refused(blk, "block with this name is already declared", 2), "a block name taken twice");
		}
		/* THE THIRD ARGUMENT IS GONE (2026-10-31). The old three-argument form is not accepted beside the new one: its normalizer word
		 * stands where a hash is read and is refused as one - RAW, the removed XOR and SUB, and any other word, in both macros. */
		CASE_REFUSED("KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL, KOF_MUTATION_RAW, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL, KOF_MUTATION_XOR, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL, KOF_MUTATION_SUB, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL, KOF_MUTATION_ROT13, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK_LIB(b0, KOF_SCAN_ALL, KOF_MUTATION_RAW, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK_LIB(b0, KOF_SCAN_ALL, KOF_MUTATION_XOR, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK_LIB(b0, KOF_SCAN_ALL, KOF_MUTATION_SUB, 1u, 2u);\n", "a hash that is not a number", 1);
		CASE_REFUSED("KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL);\n", "KOF_MUTATION_BLOCK(name, regions, hashes...)", 1);
	}

	/* stages and kinds of diagnose */
	{
		char two[4096];
		uint32_t k;
		size_t at = (size_t)snprintf(two, sizeof two, "%sKOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL", base);

		for (k = 0; k < 16u; k++)
			at += (size_t)snprintf(two + at, sizeof two - at, ", 0x%08xu", k * 31u + 1u);
		snprintf(two + at, sizeof two - at, ");\nKOF_DIAG_SIMILAR(m1, 60, b0);\nKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\n");
		OKF(refused(two, "mixes string matchers and similarity matchers", 0), "strings and blocks in one form");
	}
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\n",
		     "a graph or a form", 0);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYMBOL);\n",
		     "a graph or a form", 0);
	CASE_REFUSED("", "a form needs a matcher", 0);

	/* the expression */
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR((m0);\n", "parenthesis", 2);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0 && m9);\n", "matcher that is not declared", 2);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0 &&);\n", "wants a matcher name", 2);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0 m0);\n", "something after its end", 2);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0 & m0);\n", "something after its end", 2);
	/* P-7: a surplus ")" past the closing parenthesis is not read as m0 */
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0));\n", "closing parenthesis", 2);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0);\nKOF_DIAG_EXPR(m0);\n", "has one KOF_DIAG_EXPR", 3);
	CASE_REFUSED("KOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(m0, m0);\n", "KOF_DIAG_EXPR(expression)", 2);
	{
		char deep[600];
		size_t at = (size_t)snprintf(deep, sizeof deep, "%sKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(", base);
		int i;

		for (i = 0; i < 60; i++)
			deep[at++] = '(';
		deep[at++] = 'm'; deep[at++] = '0';
		for (i = 0; i < 60; i++)
			deep[at++] = ')';
		snprintf(deep + at, sizeof deep - at, ");\n");
		OKF(refused(deep, "nested too deep", 5), "60 nested parentheses");
		at = (size_t)snprintf(deep, sizeof deep, "%sKOF_DIAG_FIND(m0, KOF_FIND_ALL, code, s0);\nKOF_DIAG_EXPR(", base);
		for (i = 0; i < 30; i++)
			deep[at++] = '(';
		deep[at++] = 'm'; deep[at++] = '0';
		for (i = 0; i < 30; i++)
			deep[at++] = ')';
		snprintf(deep + at, sizeof deep - at, ");\n");
		OKF(resolves(deep), "30 nested parentheses are within the bound");
	}
}

/* ---- the caps: each at the value and one past it --------------------------------------------- */

static void caps(void)
{
	static char big[80000];
	size_t at;
	uint32_t i;

	/* 64 strings, 65 */
	for (i = 64; i <= 65u; i++) {
		uint32_t k;

		at = (size_t)snprintf(big, sizeof big, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n");
		for (k = 0; k < i; k++)
			at += (size_t)snprintf(big + at, sizeof big - at,
					       "KOF_DEFINE_STR(s%u, \"marker%03u\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", k, k);
		for (k = 0; k < i; k += 8u)
			at += (size_t)snprintf(big + at, sizeof big - at,
					       "KOF_DIAG_FIND(m%u, KOF_FIND_ANY, code, s%u, s%u, s%u, s%u, s%u, s%u, s%u, s%u);\n", k / 8u,
					       k, k + 1u < i ? k + 1u : k, k + 2u < i ? k + 2u : k, k + 3u < i ? k + 3u : k,
					       k + 4u < i ? k + 4u : k, k + 5u < i ? k + 5u : k, k + 6u < i ? k + 6u : k,
					       k + 7u < i ? k + 7u : k);
		(void)at;
		if (i == 64u)
			OKF(0 || 1, "64 strings: matcher lists repeat a name, so only the bound on strings is measured below");
	}
	/* the matcher lists above repeat names, which is an error of its own; measure the bound with one matcher each */
	for (i = 64; i <= 65u; i++) {
		uint32_t k;

		at = (size_t)snprintf(big, sizeof big, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n");
		for (k = 0; k < i; k++)
			at += (size_t)snprintf(big + at, sizeof big - at,
					       "KOF_DEFINE_STR(s%u, \"marker%03u\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", k, k);
		at += (size_t)snprintf(big + at, sizeof big - at, "KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\n");
		if (i == 64u)
			OKF(resolves(big), "64 strings are within a diagnose's bound (63 of them unused: said as warnings, not refused)");
		else
			OKF(refused(big, "more declared strings than a diagnose may have", 0), "the 65th string is refused");
	}
	/* 16 names in a matcher, 17 */
	for (i = 16; i <= 17u; i++) {
		uint32_t k;

		at = (size_t)snprintf(big, sizeof big, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n");
		for (k = 0; k < i; k++)
			at += (size_t)snprintf(big + at, sizeof big - at,
					       "KOF_DEFINE_STR(s%u, \"marker%03u\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", k, k);
		at += (size_t)snprintf(big + at, sizeof big - at, "KOF_DIAG_FIND(m0, KOF_FIND_ANY, code");
		for (k = 0; k < i; k++)
			at += (size_t)snprintf(big + at, sizeof big - at, ", s%u", k);
		snprintf(big + at, sizeof big - at, ");\n");
		if (i == 16u)
			OKF(resolves(big), "16 markers in one matcher");
		else
			OKF(refused(big, "from one to sixteen markers", 0), "17 markers in one matcher");
	}
	/* literal 512, 513 */
	for (i = 512; i <= 513u; i++) {
		at = (size_t)snprintf(big, sizeof big, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\nKOF_DEFINE_STR(s0, \"");
		memset(big + at, 'q', i);
		at += i;
		snprintf(big + at, sizeof big - at, "\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\n");
		if (i == 512u)
			OKF(resolves(big), "a 512 byte literal");
		else
			OKF(refused(big, "pattern literal too long", 0), "a 513 byte literal");
	}
	/* a hex text of 511 characters, 512 */
	for (i = 511; i <= 512u; i++) {
		uint32_t k;

		at = (size_t)snprintf(big, sizeof big, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\nKOF_DEFINE_HEXSTR(s0, \"41");
		for (k = 2; k + 3u <= i; k += 3u)
			at += (size_t)snprintf(big + at, sizeof big - at, " 41");
		while (k < i) {
			big[at++] = ' ';
			k++;
		}
		snprintf(big + at, sizeof big - at, "\");\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\n");
		if (i == 511u)
			OKF(resolves(big), "a 511 character hex text");
		else
			OKF(refused(big, "hex pattern too long", 0), "a 512 character hex text");
	}
	/* the text pool: kof_dsrc_text fills and then refuses; it never cuts */
	{
		struct kof_dsrc *d = calloc(1, sizeof *d);
		uint32_t got = 0;
		const char *p;
		char chunk[1000];

		memset(chunk, 'z', sizeof chunk);
		while ((p = kof_dsrc_text(d, chunk, sizeof chunk)) != NULL)
			got++;
		OKF(got >= 120u && d->pool_n + sizeof chunk + 1u > KOF_DSRC_POOL, "the pool filled to its bound (%u pieces)", got);
		OKF(!kof_dsrc_text(d, chunk, sizeof chunk) && !kof_dsrc_text(d, NULL, 1u) && !kof_dsrc_text(NULL, chunk, 1u),
		    "a full pool, a NULL text and a NULL pool are refused");
		OKF(kof_dsrc_text(d, "", 0) == NULL || d->pool_n < KOF_DSRC_POOL, "an empty text takes a byte, so a pool with none left refuses it");
		free(d);
	}
}

/* ---- the expression, against an independent evaluator of the text -------------------------------- */

/* A different algorithm from the resolver's: shunting-yard over the tokens, evaluated at once for one assignment. */
static int eval_text(const char *t, uint32_t assign)
{
	int vals[64], vn = 0;
	char ops[64];
	int on = 0;
	const char *p = t;

#define POP_OP() do { char po = ops[--on]; \
		if (po == '!') { vals[vn - 1] = !vals[vn - 1]; } \
		else { int pb = vals[--vn], pa = vals[--vn]; vals[vn++] = po == '&' ? (pa && pb) : (pa || pb); } } while (0)
	while (*p) {
		if (*p == ' ') {
			p++;
		} else if (*p == 'm') {
			vals[vn++] = (int)((assign >> (p[1] - '0')) & 1u);
			p += 2;
		} else if (*p == '!') {
			ops[on++] = '!';
			p++;
		} else if (*p == '(') {
			ops[on++] = '(';
			p++;
		} else if (*p == ')') {
			while (on && ops[on - 1] != '(')
				POP_OP();
			on--;
			while (on && ops[on - 1] == '!')
				POP_OP();
			p++;
		} else {
			char o = *p == '&' ? '&' : '|';
			int prec = o == '&' ? 2 : 1;

			p += 2;
			while (on && ops[on - 1] != '(' &&
			       (ops[on - 1] == '!' || (ops[on - 1] == '&' ? 2 : 1) >= prec))
				POP_OP();
			ops[on++] = o;
		}
		/* a value has been read: a pending not binds to it now */
		if (p > t && (p[-1] != ' ') && (p[-1] != '!') && (p[-1] != '(') && p[-1] != '&' && p[-1] != '|')
			while (on && ops[on - 1] == '!')
				POP_OP();
	}
	while (on)
		POP_OP();
#undef POP_OP
	return vals[0];
}

static int eval_tree(const struct kof_form *f, uint32_t i, uint32_t assign)
{
	const struct kof_form_node *n = &f->node[i];

	switch (n->op) {
	case KOF_FORM_OP_LEAF: return (int)((assign >> n->a) & 1u);
	case KOF_FORM_OP_NOT: return !eval_tree(f, n->a, assign);
	case KOF_FORM_OP_AND: return eval_tree(f, n->a, assign) && eval_tree(f, n->b, assign);
	default: return eval_tree(f, n->a, assign) || eval_tree(f, n->b, assign);
	}
}

static uint32_t xs = 0x1234567u;

static uint32_t xr(void)
{
	xs ^= xs << 13;
	xs ^= xs >> 17;
	xs ^= xs << 5;
	return xs;
}

/* A random expression text over m0..m4: atoms, !, && and ||, parentheses where the depth allows. */
static size_t gen_expr(char *out, size_t at, int depth)
{
	uint32_t pick = xr() % 7u;

	if (depth <= 0 || pick < 2u) {
		out[at++] = 'm';
		out[at++] = (char)('0' + xr() % 5u);
		return at;
	}
	if (pick == 2u) {
		out[at++] = '!';
		return gen_expr(out, at, depth - 1);
	}
	if (pick == 3u) {
		out[at++] = '(';
		at = gen_expr(out, at, depth - 1);
		out[at++] = ')';
		return at;
	}
	at = gen_expr(out, at, depth - 1);
	memcpy(out + at, (xr() & 1u) ? " && " : " || ", 4u);
	at += 4u;
	return gen_expr(out, at, depth - 1);
}

static void expressions(void)
{
	static const char *const decl =
		HEAD "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n"
		"KOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		"KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, code, s0);\n"
		"KOF_DIAG_FIND(m2, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m3, KOF_FIND_ANY, code, s0);\n"
		"KOF_DIAG_FIND(m4, KOF_FIND_ANY, code, s0);\n";
	uint32_t n, agree = 0, total = 0, speltok = 0;

	for (n = 0; n < 2000u; n++) {
		char expr[400], src[1000];
		size_t at = gen_expr(expr, 0, 5);
		struct kof_dsrc_view v;
		struct said s;
		uint32_t a;
		int good = 1;

		expr[at] = 0;
		snprintf(src, sizeof src, "%sKOF_DIAG_EXPR(%s);\n", decl, expr);
		if (load(src, &v, &s) != 0 || !v.form) {
			OKF(0, "an expression that must read does not: %s (%s)", expr, s.first);
			kof_dsrc_view_free(&v);
			continue;
		}
		for (a = 0; a < 32u; a++)
			good = good && eval_tree(v.form, (uint32_t)v.form->n_node - 1u, a) == eval_text(expr, a);
		total++;
		agree += (uint32_t)good;
		/* and the spelling the API prints, read back as an expression over the same names, means the same */
		{
			char sp[400], re[1500], named[800];
			size_t o = 0, k;
			struct kof_dsrc_view v2;
			struct said s2;

			kof_form_expr_text(v.form, sp, sizeof sp);
			for (k = 0; sp[k]; k++) {
				if (sp[k] >= '0' && sp[k] <= '9')
					o += (size_t)snprintf(named + o, sizeof named - o, "m%c", sp[k]);
				else if (sp[k] == '&' || sp[k] == '|')
					o += (size_t)snprintf(named + o, sizeof named - o, "%c%c", sp[k], sp[k]);
				else
					named[o++] = sp[k];
			}
			named[o] = 0;
			snprintf(re, sizeof re, "%sKOF_DIAG_EXPR(%s);\n", decl, named);
			if (load(re, &v2, &s2) == 0 && v2.form) {
				int same = 1;

				for (a = 0; a < 32u; a++)
					same = same && eval_tree(v.form, (uint32_t)v.form->n_node - 1u, a) ==
						       eval_tree(v2.form, (uint32_t)v2.form->n_node - 1u, a);
				speltok += (uint32_t)same;
			}
			kof_dsrc_view_free(&v2);
		}
		kof_dsrc_view_free(&v);
	}
	OKF(agree == total && total == 2000u, "%u of %u random expressions mean what an independent evaluator says", agree, total);
	OKF(speltok == total, "%u of %u expression spellings (kof_form_expr_text) read back as the same function", speltok, total);
	/* no expression: every matcher, anded */
	{
		struct kof_dsrc_view v;
		struct said s;

		ok("without an expression every matcher is anded", load(HEAD "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n"
			"KOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
			"KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, code, s0);\n"
			"KOF_DIAG_FIND(m2, KOF_FIND_ANY, code, s0);\n", &v, &s) == 0 && v.form && v.form->n_node == 5u &&
		   eval_tree(v.form, 4u, 7u) == 1 && eval_tree(v.form, 4u, 3u) == 0 && eval_tree(v.form, 4u, 6u) == 0);
		kof_dsrc_view_free(&v);
	}
}

/* ---- the formats, the warnings ----------------------------------------------------------------- */

static void facts(void)
{
	struct kof_dsrc_view v;
	struct said s;
	static const char *const m = "KOF_TARGET_RANGE(code, KOF_SCAN_ALL);\nKOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
				     "KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\n";
	char t[1200];

	snprintf(t, sizeof t, HEAD "KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_SCRIPT);\n%s", m);
	ok("two formats resolve", load(t, &v, &s) == 0 && v.n_when == 1);
	ok("to the SET fact: a bit for each", v.n_when == 1 && v.when[0].fact == KOF_FACT_FORMAT_SET &&
	   v.when[0].val == (((uint64_t)1 << KOF_FMT_ELF) | ((uint64_t)1 << KOF_FMT_SCRIPT)));
	kof_dsrc_view_free(&v);
	snprintf(t, sizeof t, HEAD "KOF_TARGET_FORMAT(KOF_FMT_ELF);\n%s", m);
	ok("one format keeps the equality fact, bit for bit", load(t, &v, &s) == 0 && v.n_when == 1 &&
	   v.when[0].fact == KOF_FACT_FORMAT && v.when[0].val == KOF_FMT_ELF);
	kof_dsrc_view_free(&v);
	snprintf(t, sizeof t, HEAD "KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_ELF);\n%s", m);
	ok("the same format twice is one format", load(t, &v, &s) == 0 && v.n_when == 1 && v.when[0].fact == KOF_FACT_FORMAT);
	kof_dsrc_view_free(&v);
	snprintf(t, sizeof t, HEAD "KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_PE);\nKOF_TARGET_FORMAT(KOF_FMT_SCRIPT);\n%s", m);
	ok("a second target format line is refused", load(t, &v, &s) > 0 && strstr(s.first, "declared twice"));
	kof_dsrc_view_free(&v);
	snprintf(t, sizeof t, HEAD "KOF_TARGET_FORMAT(KOF_FMT_ELF);\nKOF_TARGET_SUBTYPE(KOF_ELF_REL);\n%s", m);
	ok("a format and a subtype are two conditions", load(t, &v, &s) == 0 && v.n_when == 2);
	kof_dsrc_view_free(&v);

	/* the two conditions a signature's targets became: they read, print and read back as themselves */
	snprintf(t, sizeof t, HEAD "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 4096);\nKOF_DIAG_HAS_ATTRB(KOF_FACT_ARCH_SET, 0x6);\n%s", m);
	ok("a size and an architecture resolve to two conditions", load(t, &v, &s) == 0 && v.n_when == 2 &&
	   v.when[0].fact == KOF_FACT_SIZE_MIN && v.when[0].val == 4096u && v.when[1].fact == KOF_FACT_ARCH_SET && v.when[1].val == 6u);
	kof_dsrc_view_free(&v);
	{
		char ln[200];
		struct kof_dsrc *r = calloc(1, sizeof *r);
		uint32_t q, back = 0;

		for (q = 0; q < D->n; q++)
			if (D->item[q].kind == KDS_ATTRB && kof_dsrc_print(&D->item[q], ln, sizeof ln) &&
			    kof_dsrc_parse(ln, strlen(ln), r, NULL) == 0 && r->n == 1u && kof_dsrc_same(&D->item[q], &r->item[0]))
				back++;
		ok("and both print and read back as themselves", back == 2u);
		free(r);
	}
	snprintf(t, sizeof t, HEAD "KOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 4096);\nKOF_DIAG_HAS_ATTRB(KOF_FACT_SIZE_MIN, 8192);\n%s", m);
	ok("two conditions of one fact are both kept (they are ANDed)", load(t, &v, &s) == 0 && v.n_when == 2);
	kof_dsrc_view_free(&v);

	/* unused names are said, none refused */
	snprintf(t, sizeof t, HEAD "KOF_TARGET_RANGE(code, KOF_SCAN_ALL);\nKOF_TARGET_RANGE(spare, KOF_SCAN_ELF_DATA);\n"
		 "KOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\nKOF_DEFINE_STR(s1, \"xyz\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
		 "KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, code, s0);\nKOF_DIAG_EXPR(m0);\n");
	ok("unused names resolve", load(t, &v, &s) == 0 && v.form);
	ok("a range, a string and a matcher nothing uses are each said", s.n_warn == 3 && strstr(s.warns, "range spare") &&
	   strstr(s.warns, "string s1") && strstr(s.warns, "matcher m1"));
	kof_dsrc_view_free(&v);
	/* a short hex anchor is said */
	snprintf(t, sizeof t, HEAD "KOF_TARGET_RANGE(code, KOF_SCAN_ALL);\nKOF_DEFINE_HEXSTR(s0, \"DE ?? AD\");\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\n");
	ok("a hex marker whose longest run is under four bytes is said", load(t, &v, &s) == 0 && s.n_warn == 1 &&
	   strstr(s.warns, "anchor under four bytes"));
	kof_dsrc_view_free(&v);
}

/* ---- the words ------------------------------------------------------------------------------------ */

static void words(void)
{
	uint32_t bit = 0, m = 0, n = 0;
	char why[100];
	const char *w;

	ok("one region reads", kof_dsrc_mask_of("KOF_SCAN_ELF_CODE", &m, why, sizeof why) && m != 0);
	ok("two regions or together", kof_dsrc_mask_of("KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA", &bit, why, sizeof why) &&
	   bit == (m | (m << 1)) );
	ok("spacing is free", kof_dsrc_mask_of("  KOF_SCAN_ELF_CODE|KOF_SCAN_ELF_DATA ", &m, why, sizeof why) && m == bit);
	ok("an empty term is refused", !kof_dsrc_mask_of("KOF_SCAN_ELF_CODE |", &m, why, sizeof why) && strstr(why, "empty term"));
	ok("an unknown region is named", !kof_dsrc_mask_of("KOF_SCAN_ELF_CODEX", &m, why, sizeof why) && strstr(why, "KOF_SCAN_ELF_CODEX"));
	ok("and leaves the mask zero", m == 0);
	for (n = 0; (w = kof_dsrc_region_at(n, &bit)) != NULL; n++) {
		uint32_t back = 0;

		if (!kof_dsrc_mask_of(w, &back, why, sizeof why) || back != bit) {
			OKF(0, "region %s does not read back as its own bit", w);
			break;
		}
	}
	ok("every region of the table reads as itself", n > 40u && !kof_dsrc_region_at(n, NULL));
	{
		/* and the other way, which is what the editor relies on to spell a mask: every region of every format reads back, in the
		 * words the table has for that format, as that region's bit - a region of any format a signature could not name is
		 * what this found (seven families were missing from the builder's table) */
		uint32_t f, k, regions = 0, bad = 0;

		for (f = 0; f < KOF_FMT_COUNT; f++) {
			const struct kof_parser *fp = kof_parser_of((uint8_t)f);

			if (!fp)
				continue;
			for (k = 0; k < fp->n_regions; k++) {
				const char *nm = kof_dsrc_region_word((uint8_t)f, fp->regions[k]);
				uint32_t back = 0;

				regions++;
				if (!nm || !kof_dsrc_mask_of(nm, &back, why, sizeof why) || back != fp->regions[k]) {
					printf("    format %u region bit %08x: %s\n", f, (unsigned)fp->regions[k], nm ? nm : "(no word)");
					bad++;
				}
			}
		}
		OKF(regions > 30u && !bad, "%u regions of every format read back as their own bit (%u did not)", regions, bad);
	}
	{
		const char *whyp = NULL;
		uint8_t out[8];
		long got = kof_dsrc_lit_unescape("a\\\\b\\\"c\\?\\t", 11u, out, sizeof out, &whyp);

		ok("the escapes of a literal", got == 7 && !memcmp(out, "a\\b\"c?\t", 7u));
		ok("an unknown escape is refused with the list of the six", kof_dsrc_lit_unescape("\\x41", 4u, out, sizeof out, &whyp) < 0 &&
		   strstr(whyp, "only"));
		ok("and so is one that ends the text", kof_dsrc_lit_unescape("ab\\", 3u, out, sizeof out, &whyp) < 0);
		ok("and a literal that does not fit the room it is given", kof_dsrc_lit_unescape("123456789", 9u, out, 8u, &whyp) < 0);
		{
			uint8_t wide[8];

			ok("widening: a byte and a zero each", kof_dsrc_widen((const uint8_t *)"ab", 2u, wide, sizeof wide, &whyp) == 4 &&
			   !memcmp(wide, "a\0b\0", 4u));
			ok("a byte above 0x7F is refused, not encoded wrong", kof_dsrc_widen((const uint8_t *)"a\x80", 2u, wide, sizeof wide, &whyp) < 0);
			ok("and a widened text that does not fit", kof_dsrc_widen((const uint8_t *)"abcde", 5u, wide, sizeof wide, &whyp) < 0);
		}
	}
}

/* ---- the edges the first version of these tests let a mutant through --------------------------------------------- */

static char *big_text;

static void edges(void)
{
	static const char *const base =
		"KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\n"
		"KOF_DEFINE_STR(s0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n";
	char b[4096], t[6200];
	size_t at, i;
	struct kof_dsrc_view v;
	struct said sd;

	/* a line of more than 160 arguments is not read at all (and says so), one of 20 names is refused by the rule on names */
	at = (size_t)snprintf(big_text, 60000, "%s KOF_DIAG_FIND(m0, KOF_FIND_ANY, code", base);
	for (i = 0; i < 161u; i++)
		at += (size_t)snprintf(big_text + at, 60000 - at, ", s0");
	snprintf(big_text + at, 60000 - at, ");\n");
	OKF(refused(big_text, "not closed on its line", 3), "a call of 164 arguments is refused by the splitter, not cut");

	/* names: underscore and digits are in, a hyphen is out; 63 characters are in, 64 are out */
	{
		char nm[80];

		snprintf(b, sizeof b, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\nKOF_DEFINE_STR(s_0_x9, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
			 "KOF_DIAG_FIND(m_0, KOF_FIND_ANY, code, s_0_x9);\n");
		OKF(resolves(b), "a name with underscores and digits");
		snprintf(b, sizeof b, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\nKOF_DEFINE_STR(s-0, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n");
		OKF(refused(b, "wants a plain name", 2), "a hyphen is not in a name");
		memset(nm, 'n', 63);
		nm[63] = 0;
		snprintf(b, sizeof b, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\nKOF_DEFINE_STR(%s, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
			 "KOF_DIAG_FIND(m0, KOF_FIND_ANY, code, %s);\n", nm, nm);
		OKF(resolves(b), "a name of 63 characters");
		memset(nm, 'n', 64);
		nm[64] = 0;
		snprintf(b, sizeof b, "KOF_TARGET_RANGE(code, KOF_SCAN_ELF_CODE);\nKOF_DEFINE_STR(%s, \"abc\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n", nm);
		OKF(refused(b, "wants a plain name", 2), "a name of 64 characters");
	}
	/* a regex text of 511 characters, 512 */
	for (i = 511; i <= 512u; i++) {
		at = (size_t)snprintf(big_text, 60000, "%sKOF_DEFINE_REGEX(r0, \"", base);
		memset(big_text + at, 'a', i);
		at += i;
		snprintf(big_text + at, 60000 - at, "\");\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, r0);\n");
		if (i == 511u)
			OKF(resolves(big_text), "a regex text of 511 characters");
		else
			OKF(refused(big_text, "the pattern is too long", 3), "a regex text of 512 characters");
	}
	/* hash suffixes: u, U, l, L, ul are suffixes; anything else after the digits is not a number */
	for (i = 0; i < 6u; i++) {
		static const char *const suf[6] = { "u", "U", "l", "L", "ul", "z" };
		char blk[1800];
		uint32_t k;
		size_t o = (size_t)snprintf(blk, sizeof blk, "KOF_MUTATION_BLOCK(b0, KOF_SCAN_ALL");

		for (k = 0; k < 16u; k++)
			o += (size_t)snprintf(blk + o, sizeof blk - o, ", %u%s", k * 7u + 1u, k == 0 ? suf[i] : "u");
		snprintf(blk + o, sizeof blk - o, ");\nKOF_DIAG_SIMILAR(m0, 50, b0);\n");
		if (i < 5u)
			OKF(resolves(blk), "the hash suffix %s", suf[i]);
		else
			OKF(refused(blk, "a hash that is not a number", 1), "the hash suffix %s", suf[i]);
	}
	/* MULTI: 0 and 256 are not a count (the reader says so), 255 is one the reader reads and the rule then refuses */
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_MULTI(0), code, s0);\n", base);
	OKF(refused(b, "whole number from 1 to 255", 3), "MULTI(0) is not a number of markers");
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_MULTI(256), code, s0);\n", base);
	OKF(refused(b, "whole number from 1 to 255", 3), "MULTI(256) is not a number of markers");
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_MULTI(255), code, s0);\n", base);
	OKF(refused(b, "cannot ask for more markers", 3), "MULTI(255) over one marker: read, then refused by the rule");
	/* an AT with something after its closing parenthesis, and a matcher of no marker */
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_AT(KOF_ANCHOR_BOF, 0)(1), s0);\n", base);
	OKF(refused(b, "KOF_FIND_AT(anchor, step)", 3), "KOF_FIND_AT followed by more parentheses");
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_ALL, code);\n", base);
	OKF(refused(b, "from one to sixteen markers", 3), "a matcher with a range and no marker");
	snprintf(b, sizeof b, "%sKOF_DIAG_SIMILAR(m0, 50);\n", base);
	OKF(refused(b, "a percentage from 1 to 100", 3), "a similarity matcher with no block");
	/* an expression of 255 characters is read, 256 is not */
	for (i = 255; i <= 256u; i++) {
		at = (size_t)snprintf(big_text, 60000, "%sKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_EXPR(m0", base);
		memset(big_text + at, ' ', i - 8u);
		at += i - 8u;
		snprintf(big_text + at, 60000 - at, " || m0);\n");
		if (i == 255u)
			OKF(resolves(big_text), "an expression of 255 characters");
		else
			OKF(refused(big_text, "under 256 characters", 4), "an expression of 256 characters");
	}
	/* the operators are two characters: a single | or & is not one */
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, code, s0);\nKOF_DIAG_EXPR(m0 | m1);\n", base);
	OKF(refused(b, "something after its end", 5), "a single | is not an or");
	snprintf(b, sizeof b, "%sKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, s0);\nKOF_DIAG_FIND(m1, KOF_FIND_ANY, code, s0);\nKOF_DIAG_EXPR(m0 || m1 | m0);\n", base);
	OKF(refused(b, "something after its end", 5), "a single | after an or is not one either");
	/* a hex marker's longest concrete run: three bytes is said, four is not */
	snprintf(b, sizeof b, "KOF_TARGET_RANGE(code, KOF_SCAN_ALL);\nKOF_DEFINE_HEXSTR(h0, \"DE AD BE ?? 00 ?? 01\");\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, h0);\n");
	{
		snprintf(t, sizeof t, "%s%s", HEAD, b);
		OKF(load(t, &v, &sd) == 0 && sd.n_warn == 1, "a run of three bytes is said");
		kof_dsrc_view_free(&v);
		snprintf(b, sizeof b, "KOF_TARGET_RANGE(code, KOF_SCAN_ALL);\nKOF_DEFINE_HEXSTR(h0, \"DE AD BE EF ?? 00\");\nKOF_DIAG_FIND(m0, KOF_FIND_ANY, code, h0);\n");
		snprintf(t, sizeof t, "%s%s", HEAD, b);
		OKF(load(t, &v, &sd) == 0 && sd.n_warn == 0, "a run of four bytes is not");
		kof_dsrc_view_free(&v);
	}
	/* what the reader cannot be given but an editor can: items built by hand are checked by the same rules */
	{
		struct kof_dsrc *w = calloc(1, sizeof *w);
		struct kof_dsrc_item *it;
		uint32_t h[16], k;
		struct said s2;
		struct kof_dsrc_report rep = { on_err, on_warn, &s2 };

		for (k = 0; k < 16u; k++)
			h[k] = k + 1u;
		memset(&s2, 0, sizeof s2);
		it = &w->item[w->n++];
		it->kind = KDS_NAME;
		snprintf(it->s1, sizeof it->s1, "t");
		it = &w->item[w->n++];
		it->kind = KDS_BLOCK;
		snprintf(it->s1, sizeof it->s1, "b0");
		it->a = 0;
		it->v = 0;                                       /* no region */
		it->t1 = kof_dsrc_text(w, "KOF_SCAN_ALL", 12u);
		it->n1 = 12u;
		it->t2 = kof_dsrc_text(w, (const char *)h, sizeof h);
		it->n2 = sizeof h;
		it = &w->item[w->n++];
		it->kind = KDS_SIMILAR;
		snprintf(it->s1, sizeof it->s1, "m0");
		it->a = 50;
		it->t1 = kof_dsrc_text(w, "b0", 2u);
		it->n1 = 2u;
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s2.first, "names no region"), "a block of no region: %s", s2.first);
		kof_dsrc_view_free(&v);
		/* the same block twice in one matcher */
		w->item[1].v = KOF_SCAN_ALL;
		w->item[2].t1 = kof_dsrc_text(w, "b0, b0", 6u);
		w->item[2].n1 = 6u;
		memset(&s2, 0, sizeof s2);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s2.first, "listed twice"), "a block listed twice: %s", s2.first);
		kof_dsrc_view_free(&v);
		w->item[2].t1 = kof_dsrc_text(w, "b0", 2u);
		w->item[2].n1 = 2u;
		memset(&s2, 0, sizeof s2);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) == 0 && v.form, "and the same items with a region and one name resolve");
		kof_dsrc_view_free(&v);
		/* an AT matcher that was given a range */
		memset(w, 0, sizeof *w);
		it = &w->item[w->n++];
		it->kind = KDS_NAME;
		snprintf(it->s1, sizeof it->s1, "t");
		it = &w->item[w->n++];
		it->kind = KDS_STR;
		it->a = KDS_STR_PLAIN;
		it->b = KDS_OPT_GIVEN;
		snprintf(it->s1, sizeof it->s1, "s0");
		it->t1 = kof_dsrc_text(w, "abc", 3u);
		it->n1 = 3u;
		it = &w->item[w->n++];
		it->kind = KDS_RANGE;
		snprintf(it->s1, sizeof it->s1, "code");
		it->v = KOF_SCAN_ALL;
		it->t1 = kof_dsrc_text(w, "KOF_SCAN_ALL", 12u);
		it->n1 = 12u;
		it = &w->item[w->n++];
		it->kind = KDS_FIND;
		snprintf(it->s1, sizeof it->s1, "m0");
		snprintf(it->s2, sizeof it->s2, "code");
		it->a = KOF_FORM_R_AT;
		it->b = KOF_FORM_ANCHOR_BOF;
		it->t1 = kof_dsrc_text(w, "s0", 2u);
		it->n1 = 2u;
		memset(&s2, 0, sizeof s2);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s2.first, "names no range"), "an AT matcher with a range: %s", s2.first);
		kof_dsrc_view_free(&v);
		free(w);
	}
	/* more parts than an expression holds: 70 operands are 139 nodes, and the bound is 128 (one-letter names keep it under 256 characters) */
	{
		size_t o = (size_t)snprintf(big_text, 60000, "%sKOF_DIAG_FIND(a, KOF_FIND_ANY, code, s0);\nKOF_DIAG_EXPR(a", base);

		for (i = 1; i < 70u; i++)
			o += (size_t)snprintf(big_text + o, 60000 - o, "&&a");
		snprintf(big_text + o, 60000 - o, ");\n");
		OKF(refused(big_text, "over the bound on its parts", 4), "an expression of 139 parts");
		o = (size_t)snprintf(big_text, 60000, "%sKOF_DIAG_FIND(a, KOF_FIND_ANY, code, s0);\nKOF_DIAG_EXPR(a", base);
		for (i = 1; i < 64u; i++)
			o += (size_t)snprintf(big_text + o, 60000 - o, "&&a");
		snprintf(big_text + o, 60000 - o, ");\n");
		OKF(resolves(big_text), "an expression of 127 parts (64 operands and 63 ands) is within it");
	}
	/* the bounds an editor's hand-built items can reach and a reader's line cannot: one text pool, no escape to parse */
	{
		struct kof_dsrc *w = calloc(1, sizeof *w);
		struct kof_dsrc_item *it;
		struct said s3;
		struct kof_dsrc_report rep = { on_err, on_warn, &s3 };
		char names[400];
		uint32_t k;

		it = &w->item[w->n++];
		it->kind = KDS_NAME;
		snprintf(it->s1, sizeof it->s1, "t");
		it = &w->item[w->n++];
		it->kind = KDS_RANGE;
		snprintf(it->s1, sizeof it->s1, "code");
		it->v = KOF_SCAN_ALL;
		it->t1 = kof_dsrc_text(w, "KOF_SCAN_ALL", 12u);
		it->n1 = 12u;
		for (k = 0; k < 17u; k++) {
			it = &w->item[w->n++];
			it->kind = KDS_STR;
			it->a = KDS_STR_PLAIN;
			it->b = KDS_OPT_GIVEN;
			snprintf(it->s1, sizeof it->s1, "s%u", k);
			it->t1 = kof_dsrc_text(w, "abc", 3u);
			it->n1 = 3u;
		}
		{
			size_t o = 0;

			for (k = 0; k < 17u; k++)
				o += (size_t)snprintf(names + o, sizeof names - o, "%ss%u", k ? ", " : "", k);
		}
		it = &w->item[w->n++];
		it->kind = KDS_FIND;
		snprintf(it->s1, sizeof it->s1, "m0");
		snprintf(it->s2, sizeof it->s2, "code");
		it->a = KOF_FORM_R_ANY;
		it->t1 = kof_dsrc_text(w, names, strlen(names));
		it->n1 = (uint32_t)strlen(names);
		memset(&s3, 0, sizeof s3);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s3.first, "from one to sixteen markers"), "a hand-built matcher of 17 markers: %s", s3.first);
		kof_dsrc_view_free(&v);
		/* a literal of no bytes, and one of 513 */
		w->n = 2;
		it = &w->item[w->n++];
		it->kind = KDS_STR;
		it->a = KDS_STR_PLAIN;
		it->b = KDS_OPT_GIVEN;
		snprintf(it->s1, sizeof it->s1, "s0");
		it->t1 = kof_dsrc_text(w, "", 0u);
		it->n1 = 0;
		it = &w->item[w->n++];
		it->kind = KDS_FIND;
		snprintf(it->s1, sizeof it->s1, "m0");
		snprintf(it->s2, sizeof it->s2, "code");
		it->a = KOF_FORM_R_ANY;
		it->t1 = kof_dsrc_text(w, "s0", 2u);
		it->n1 = 2u;
		memset(&s3, 0, sizeof s3);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s3.first, "from one to 512 bytes"), "a literal of no bytes: %s", s3.first);
		kof_dsrc_view_free(&v);
		memset(names, 'q', 400u);
		w->item[2].t1 = kof_dsrc_text(w, names, 400u);
		w->item[2].n1 = 513u;                  /* longer than the bytes it holds: only the count is under test */
		memset(&s3, 0, sizeof s3);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s3.first, "from one to 512 bytes"), "a literal of 513 bytes: %s", s3.first);
		kof_dsrc_view_free(&v);
		/* an expression with an open parenthesis (a reader's line cannot carry one: its splitter counts them) */
		w->n = 2;
		it = &w->item[w->n++];
		it->kind = KDS_STR;
		it->a = KDS_STR_PLAIN;
		it->b = KDS_OPT_GIVEN;
		snprintf(it->s1, sizeof it->s1, "s0");
		it->t1 = kof_dsrc_text(w, "abc", 3u);
		it->n1 = 3u;
		it = &w->item[w->n++];
		it->kind = KDS_FIND;
		snprintf(it->s1, sizeof it->s1, "m0");
		snprintf(it->s2, sizeof it->s2, "code");
		it->a = KOF_FORM_R_ANY;
		it->t1 = kof_dsrc_text(w, "s0", 2u);
		it->n1 = 2u;
		it = &w->item[w->n++];
		it->kind = KDS_EXPR;
		it->t1 = kof_dsrc_text(w, "(m0 && m0", 9u);
		it->n1 = 9u;
		memset(&s3, 0, sizeof s3);
		memset(&v, 0, sizeof v);
		OKF(kof_dsrc_resolve(w, &v, &rep) > 0 && strstr(s3.first, "parenthesis"), "an open parenthesis: %s", s3.first);
		kof_dsrc_view_free(&v);
		free(w);
	}
	/* printing: a '?' is escaped (a trigraph in C), an hex text with a quote and a hash list that is not whole words are refused */
	{
		struct kof_dsrc *w = calloc(1, sizeof *w);
		struct kof_dsrc_item *it = &w->item[0];
		char line[512];

		it->kind = KDS_STR;
		it->a = KDS_STR_PLAIN;
		it->b = KDS_OPT_GIVEN;
		snprintf(it->s1, sizeof it->s1, "s0");
		it->t1 = kof_dsrc_text(w, "a?b", 3u);
		it->n1 = 3u;
		OKF(kof_dsrc_print(it, line, sizeof line) && strstr(line, "\"a\\?b\""), "a question mark is written escaped: %s", line);
		it->a = KDS_STR_HEX;
		it->t1 = kof_dsrc_text(w, "41 \" 42", 7u);
		it->n1 = 7u;
		OKF(kof_dsrc_print(it, line, sizeof line) == 0, "a hex text with a quote has no spelling");
		it->kind = KDS_BLOCK;
		it->a = 0;
		it->b = 0;
		it->t1 = kof_dsrc_text(w, "KOF_SCAN_ALL", 12u);
		it->n1 = 12u;
		it->t2 = kof_dsrc_text(w, "abcdefghi", 9u);
		it->n2 = 9u;
		OKF(kof_dsrc_print(it, line, sizeof line) == 0, "a hash list of nine bytes is not whole words");
		it->n2 = 8u;
		OKF(kof_dsrc_print(it, line, sizeof line) > 0, "and of eight is two hashes");
		/* two blocks that differ only in the length of their hash lists are not the same declaration */
		{
			struct kof_dsrc_item a2 = *it, b2 = *it;

			a2.n2 = 8u;
			b2.n2 = 4u;
			OKF(!kof_dsrc_same(&a2, &b2), "items that differ only in the length of their second text are different");
			b2 = a2;
			OKF(kof_dsrc_same(&a2, &b2), "and equal items are the same");
		}
		free(w);
	}
	/* printing an AT matcher: every anchor, and a negative step */
	{
		static const char *const anchors[3] = { "KOF_ANCHOR_BOF", "KOF_ANCHOR_ENTRY", "KOF_ANCHOR_EOF" };
		struct kof_dsrc *w = calloc(1, sizeof *w), *r = calloc(1, sizeof *r);
		char line[300];
		unsigned a;

		for (a = 0; a < 3u; a++) {
			struct kof_dsrc_item *it = &w->item[0];

			memset(w, 0, sizeof *w);
			it->kind = KDS_FIND;
			it->a = KOF_FORM_R_AT;
			it->b = (uint16_t)a;
			it->v = (uint64_t)(int64_t)-12;
			snprintf(it->s1, sizeof it->s1, "m0");
			it->t1 = kof_dsrc_text(w, "s0", 2u);
			it->n1 = 2u;
			OKF(kof_dsrc_print(it, line, sizeof line) && strstr(line, anchors[a]) && strstr(line, ", -12)") &&
			    kof_dsrc_parse(line, strlen(line), r, NULL) == 0 && r->n == 1u && kof_dsrc_same(it, &r->item[0]),
			    "AT %s, -12 prints and reads back", anchors[a]);
		}
		free(w);
		free(r);
	}
}

int main(void)
{
	D = calloc(1, sizeof *D);
	big_text = malloc(60000);
	if (!D || !big_text)
		return 2;
	read_print_back();
	lit_round_trip();
	regex_round_trip();
	hash_round_trip();
	patch_keeps_prose();
	rules();
	caps();
	expressions();
	facts();
	words();
	edges();
	free(big_text);
	free(D);
	if (failures) {
		printf("diagsrc_form: %d FAIL\n", failures);
		return 1;
	}
	printf("diagsrc_form: ok\n");
	return 0;
}
