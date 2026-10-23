/*
 * genome / diag_text_work - the hostile shapes of the TEXT route, read in work that is linear in the text, COUNTED and not timed.
 *
 * These were two wall-clock checks (hostile_one in diag_text_testlib.h: `clock() < 3 s`, used by diag_text_langs.c and diag_text_stmt.c). A clock is what a loaded machine,
 * a coverage build (-O0 --coverage) and a sanitised build change, and both tests failed under -O0 --coverage on a machine that was busy: a test that fails for the load
 * says nothing about the code. Here every shape is built at about n and at 4n bytes and the route's executed basic blocks are counted (tests/lib/work_count.h: gcc's
 * trace-pc instrumentation of the route's own translation units - the Makefile compiles libgenome/phenotype/diag_text*.c into this one test, ahead of the archive, with the
 * flag): a linear reader's count grows by about 4, a quadratic one's by about 16, and `work_grows_linearly` asks for at most 6 and for at most PER_BYTE blocks a byte. The count
 * does not depend on the load, the compiler, or the optimisation level.
 *
 * Each shape is one of the ones the audit found quadratic in some pass of the route (names after one `global`, a chain of calls, arrow functions each running to the end of the
 * text, a name of a megabyte, brackets and substitutions that never close ...); the text is `head`, a unit repeated with its index, and `tail`. In the unit `%d` is the index,
 * `%D` the one before it (0 for the first) and `%I` as many spaces as the index.
 *
 * Why the old checks missed what they were for: (c) a wall clock cannot tell a slow machine from a quadratic loop at the sizes that fit a unit test, so the bound had to be
 * generous (3 s) - and was still crossed by a loaded machine while a loop quadratic only in a small constant stayed under it.
 *
 * usage: diag_text_work
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <phenotype/diag_scan.h>
#include <textual/textual.h>

#include "../work_count.h"

#define PER_BYTE 12000u        /* blocks a byte at the larger size: the measured worst shape is far below it (the table prints them with -v) */

static int fails;

#define PHP  KGENOME_TEXTUAL_LANG_PHP
#define SH   KGENOME_TEXTUAL_LANG_SH
#define JS   KGENOME_TEXTUAL_LANG_JS
#define VB   KGENOME_TEXTUAL_LANG_VBS
#define ASP  KGENOME_TEXTUAL_LANG_ASP
#define CF   KGENOME_TEXTUAL_LANG_CFM
#define PY   KGENOME_TEXTUAL_LANG_PY
#define PL   KGENOME_TEXTUAL_LANG_PERL
#define RB   KGENOME_TEXTUAL_LANG_RUBY
#define TCL  KGENOME_TEXTUAL_LANG_TCL
#define BAT  KGENOME_TEXTUAL_LANG_BAT
#define PS   KGENOME_TEXTUAL_LANG_PSH

struct shape {
	uint32_t    lang;
	const char *what, *head, *unit, *tail;
};

static const struct shape S[] = {
	{ PY, "nested defs, each indented one more", "", "%Idef f%d():\n", "x = 1\n" },
	{ PY, "names after one global", "def f():\n    global ", "v%d,", "" },
	{ JS, "a chain of calls", "a", ".b(x)", "" },
	{ JS, "arrow functions", "", "(a)=>", "1" },
	{ RB, "def without an end", "", "def a\n", "" },
	{ SH, "a name of any length as a command word", "", "a", " | sh\n" },
	{ SH, "a name of any length as an assignment", "x=", "a", " | sh\n" },
	{ VB, "a name of any length as a variable", "Set ", "a", " = CreateObject(\"WScript.Shell\")\n" },
	{ CF, "a tag name that never closes", "<cf", "a", "" },
	{ ASP, "an island that never closes (bytes)", "<% ", "a", "" },
	{ SH, "nested $(", "", "$(", "" },
	{ SH, "backticks", "", "`", "" },
	{ BAT, "open brackets in a batch file", "", "(", "" },
	{ PS, "open brackets in powershell", "", "(", "" },
	{ SH, "pipes", "", "a | ", "" },
	{ PS, "pipes in powershell", "", "a | ", "" },
	{ SH, "assignments, each of the one before", "", "x%d=$x%D\n", "" },
	{ SH, "strings that open a substitution", "", "\"$(\"", "" },
	{ RB, "backticks that open an expression", "", "`ls #{", "" },
	{ PL, "backticks that open a subscript", "", "`ls $x{", "" },
	{ CF, "tags that open an expression and never close", "", "<cfexecute name=\"#", "" },
	{ ASP, "islands that never close", "", "<% x\n", "" },
	{ VB, "one line ifs", "", "if x then o.Run y : ", "" },
	{ VB, "a member chain", "", "o.", "" },
	{ BAT, "conditions that never end in a command", "", "if a==b ", "" },
	{ TCL, "ensemble commands", "", "file ", "" },
	{ TCL, "open tcl brackets", "", "[", "" },
	{ PS, "type literals", "", "[T]::", "" },
	{ PS, "a chain of constructed objects", "", "(New-Object X).", "" },
	{ PHP, "names assigned from the one before", "<?php ", "$v%d = $v%D . 'x'; ", "system($v0);" },
	{ PHP, "a call nested in the call before", "<?php ", "f(", "1" },
	{ SH, "heredocs that never close", "", "cat <<E%d\n", "" },
	/* the jump tables of the ident pass: a node with no statement stop after it, its arguments and its redirections (each walked to the end of the text before they were tables) */
	{ PL, "backticks with a redirect that open a subscript", "", "`ls $x>f{", "" },
	{ SH, "substitutions with a redirect that never close", "", "$(a > b ", "" },
	{ SH, "backticks with a redirect", "", "`a > b ", "" },
	{ VB, "statement calls with arguments and no line break", "", "o.Run a, b ", "" },
	{ PHP, "statement calls with arguments", "<?php ", "include $a, $b ", "" },
	{ PS, "calls with a redirect and no stop", "", "(New-Object X) > f ", "" },
	{ JS, "calls with a comma list and no stop", "", "a(b, c), ", "" },
	/* a value flowing out through brackets that are calls of a function the text defines, and plain groupings that never close: each walked the frames below it */
	{ PY, "calls of a defined function that never close", "def f(a):\n    return a\n", "f(", "system(x)" },
	{ JS, "calls of a defined function that never close", "function f(a) { return a }\n", "f(", "eval(x)" },
	{ PHP, "calls of a defined function that never close", "<?php function f($a) { return $a; } ", "f(", "system($x)" },
	{ PHP, "groupings that never close, with a node in each", "<?php ", "(system($x), ", "" },
	{ PY, "defined calls that never close, a node between", "def f(a):\n    return a\n", "f(chr(1), ", "system(x)" },
	{ PY, "functions that share a parameter name", "", "def f%d(a, b):\n    return a\n", "" },
	{ PY, "functions that share a global name", "", "def f%d():\n    global g\n    return g\n", "" },
};

/* the text: head, unit written until `bytes` are reached, tail; *len is its length */
static uint8_t *build(const struct shape *s, uint32_t bytes, uint32_t *len)
{
	size_t cap = (size_t)bytes + 4096u + strlen(s->head) + strlen(s->tail), w = 0;
	uint8_t *b = malloc(cap);
	uint32_t i = 0;

	if (!b)
		abort();
	memcpy(b, s->head, strlen(s->head));
	w = strlen(s->head);
	while (w < bytes) {
		const char *u;

		for (u = s->unit; *u; u++) {
			if (u[0] == '%' && u[1] == 'd') {
				w += (size_t)sprintf((char *)b + w, "%u", i);
				u++;
			} else if (u[0] == '%' && u[1] == 'D') {
				w += (size_t)sprintf((char *)b + w, "%u", i ? i - 1u : 0u);
				u++;
			} else if (u[0] == '%' && u[1] == 'I') {
				memset(b + w, ' ', i);
				w += i;
				u++;
			} else {
				b[w++] = (uint8_t)*u;
			}
		}
		i++;
	}
	memcpy(b + w, s->tail, strlen(s->tail));
	w += strlen(s->tail);
	*len = (uint32_t)w;
	return b;
}

/* the blocks the scan executes (in the route's own, instrumented translation units); the scan is made and given back */
static uint64_t scan_work(uint32_t lang, const uint8_t *in, uint32_t n, struct kgenome_diag_text_work *ww, int *made)
{
	struct kgenome_diag_text_req rq = { .base = in, .size = n, .lang = lang, .work = ww };
	struct kgenome_diag_scan *sc;
	uint64_t w;

	WORK_BEGIN();
	sc = kgenome_diag_scan_text(&rq);
	w = work_end();
	*made = sc != NULL;
	if (sc)
		kgenome_diag_scan_free(sc);
	return w;
}

int main(int argc, char **argv)
{
	size_t k;
	int verbose = argc > 1 && argv[1][0] == '-';       /* -v: the table of counts */

	if (!work_selfcheck())
		return 1;
	for (k = 0; k < sizeof S / sizeof S[0]; k++) {
		uint32_t l1, l2;
		struct kgenome_diag_text_work c1 = { 0 }, c2 = { 0 };
		int m1, m2;
		uint8_t *a = build(&S[k], 32u << 10, &l1), *b = build(&S[k], 128u << 10, &l2);
		uint64_t w1 = scan_work(S[k].lang, a, l1, &c1, &m1), w2 = scan_work(S[k].lang, b, l2, &c2, &m2);

		if (verbose)
			printf("  %-52s %8u B %10llu blocks | %8u B %10llu blocks  x%.1f  (%.0f a byte; probes %llu edges %llu steps %llu listed %llu)\n", S[k].what, l1, (unsigned long long)w1, l2,
			       (unsigned long long)w2, (double)w2 / (double)(w1 ? w1 : 1u), (double)w2 / (double)l2, (unsigned long long)c2.probes, (unsigned long long)c2.edges,
			       (unsigned long long)c2.steps, (unsigned long long)c2.listed);
		if (!m1 || !m2) {
			printf("  FAIL %s: no scan\n", S[k].what);
			fails++;
		}
		if (!work_grows_linearly(S[k].what, w1, l1, w2, l2, PER_BYTE))
			fails++;
		/* the route's own counters are linear too: a table whose names share a hash is quadratic in a count and not in a basic block of the caller */
		if (c2.probes > 64ull * l2 + 4096u || c2.edges > 64ull * l2 + 4096u || c2.steps > 64ull * l2 + 4096u || c2.listed > 64ull * l2 + 4096u) {
			printf("  FAIL %s: probes %llu edges %llu steps %llu listed %llu at %u bytes\n", S[k].what, (unsigned long long)c2.probes, (unsigned long long)c2.edges,
			       (unsigned long long)c2.steps, (unsigned long long)c2.listed, l2);
			fails++;
		}
		free(a);
		free(b);
	}
	printf("diag text work: %zu shapes at 32 KiB and 128 KiB - %s\n", sizeof S / sizeof S[0], fails ? "FAILED" : "ok");
	return fails != 0;
}
