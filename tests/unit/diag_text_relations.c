/*
 * diag_text_relations - the EXPECTED RELATIONS of real script samples, and whether the TEXT route found them.
 *
 * tests/data/diag_text_expect.tsv holds, per sample, the relations a person reading the file sees: (from line, from capability, to line, to capability, strength, why). They were written by
 * READING the samples (php, asp, aspx, jsp, cfm, python, perl, cgi, the hoho/haha loaders, sh and powershell and batch and vbscript droppers) and not from any output of the route:
 * strength `must` is a value that reaches an argument in one function, `may` goes through a function the file defines or an object's field, `shared` is two nodes that name one constant
 * path, `none` says the sample has no relation to find. The samples are not in the tree (they are malware and tools kept under the corpora): a row whose file is not there is
 * counted as not scanned, and a run without the table does nothing.
 *
 * WHAT IS REPORTED, and it is not a detection rate: for each strength, how many expected relations were found as a link between a node of the first capability on the first line and a node
 * of the second on the second line (`direct`), reached through a chain of links (`path`: a decode's result reaches the eval through the decode that came between), or not found (listed with
 * the reason the reader wrote). A relation the route does not make is a gap in the analysis, said here, and not a failure: the test fails only for a table it cannot read.
 *
 * usage: diag_text_relations [table.tsv] [-v]     (default: tests/data/diag_text_expect.tsv)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

#include "../../libkofeng/analyzers/parsers/scripts/script_apply.h"

#define MAXROWS 4096
#define MAXNODE 70000

struct row {
	char path[1100], from_cap[32], to_cap[32], why[200], strength[8];
	int  from_line, to_line;
};

static struct row R[MAXROWS];
static int nrows;

static uint32_t lang_of(const char *p)
{
	const char *e = strrchr(p, '.');

	if (strstr(p, "/sc_fam/f"))
		return KGENOME_TEXTUAL_LANG_SH;
	if (!e)
		return 0;
	if (!strcmp(e, ".php"))
		return KGENOME_TEXTUAL_LANG_PHP;
	if (!strcmp(e, ".asp"))
		return KGENOME_TEXTUAL_LANG_ASP;
	if (!strcmp(e, ".aspx"))
		return KGENOME_TEXTUAL_LANG_ASPX;
	if (!strcmp(e, ".jsp"))
		return KGENOME_TEXTUAL_LANG_JSP;
	if (!strcmp(e, ".cfm") || !strcmp(e, ".cfc"))
		return KGENOME_TEXTUAL_LANG_CFM;
	if (!strcmp(e, ".py"))
		return KGENOME_TEXTUAL_LANG_PY;
	if (!strcmp(e, ".pl") || !strcmp(e, ".cgi"))
		return KGENOME_TEXTUAL_LANG_PERL;
	if (!strcmp(e, ".sh"))
		return KGENOME_TEXTUAL_LANG_SH;
	if (!strcmp(e, ".ps1"))
		return KGENOME_TEXTUAL_LANG_PSH;
	if (!strcmp(e, ".bat") || !strcmp(e, ".cmd"))
		return KGENOME_TEXTUAL_LANG_BAT;
	if (!strcmp(e, ".vbs"))
		return KGENOME_TEXTUAL_LANG_VBS;
	return 0;
}

static int load(const char *fn)
{
	FILE *f = fopen(fn, "r");
	char line[1024];

	if (!f)
		return 0;
	while (fgets(line, sizeof line, f) && nrows < MAXROWS) {
		char *c[8];
		int n = 0;
		char *p = line;

		line[strcspn(line, "\r\n")] = 0;
		if (!line[0])
			continue;
		c[n++] = p;
		while (*p && n < 8) {
			if (*p == '\t') {
				*p = 0;
				c[n++] = p + 1;
			}
			p++;
		}
		if (n < 6)
			return -1;
		snprintf(R[nrows].path, sizeof R[0].path, "%s", c[0]);
		R[nrows].from_line = atoi(c[1]);
		snprintf(R[nrows].from_cap, sizeof R[0].from_cap, "%s", c[2]);
		R[nrows].to_line = atoi(c[3]);
		snprintf(R[nrows].to_cap, sizeof R[0].to_cap, "%s", c[4]);
		snprintf(R[nrows].strength, sizeof R[0].strength, "%s", c[5]);
		snprintf(R[nrows].why, sizeof R[0].why, "%s", n > 6 ? c[6] : "");
		nrows++;
	}
	fclose(f);
	return 1;
}

static int line_of(const uint8_t *b, uint64_t off)
{
	int ln = 1;
	uint64_t i;

	for (i = 0; i < off && b[i]; i++)
		ln += b[i] == '\n';
	return ln;
}

/* Is there a chain of links, the first node to the second: `direct` when it is one link of the kind asked. */
static int reach(const struct kgenome_diag_scan *s, uint32_t from, uint32_t to, int shared, int *direct)
{
	static uint32_t stk[MAXNODE];
	static uint8_t seen[MAXNODE];
	uint32_t n = kgenome_diag_scan_count(s), sp = 0, i;
	uint8_t k;

	memset(seen, 0, n < MAXNODE ? n : MAXNODE);
	{
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, to);

		for (k = 0; k < h->n_in; k++)
			if (h->in[k].from == from && (h->in[k].kind == KGENOME_DIAG_KIND_SHARED) == (shared != 0)) {
				*direct = 1;
				return 1;
			}
	}
	*direct = 0;
	if (n >= MAXNODE)
		return 0;
	stk[sp++] = to;
	seen[to] = 1;
	while (sp) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, stk[--sp]);

		for (k = 0; k < h->n_in; k++) {
			uint32_t f = h->in[k].from;

			if (f == from && f != to)
				return 1;
			if (f < n && !seen[f] && (h->in[k].kind == KGENOME_DIAG_KIND_SHARED) == (shared != 0)) {
				seen[f] = 1;
				stk[sp++] = f;
			}
		}
	}
	(void)i;
	return 0;
}

int main(int argc, char **argv)
{
	/* KNOWN DEFECT S2-TSV (2026-10-24, M) [sev L]: rows of tests/data/diag_text_expect.tsv state relations the engine does not or should not produce, so the gate counts them as "not found".
	 * Trigger: the first 100 rows (all php): STALE capability names rows 0,3,9,15,16,17,39; WRONG rows 47,48,49 (eval inside a single-quoted string) and 84 (shared belongs to L664, not L665); SHAPE rows 37,38.
	 * Effect: 24 of 100 rows read as misses (75 found directly), so the found/missing numbers this test prints are not a coverage measure. Reproducer: /mnt/games/normtest/fix_script2/red_report.md section 9.
	 * Fix: correct the rows (the engine's spelling, the real sample line) and keep the real gaps as rows; the table is data, so the comment is here, where it is read. */
	const char *table = "tests/data/diag_text_expect.tsv";
	int verbose = 0, a, i;
	int found_direct[4] = { 0 }, found_path[4] = { 0 }, missing[4] = { 0 }, nones = 0, none_with_links = 0, absent = 0, unread = 0, samples = 0;
	static const char *const SN[4] = { "must", "may", "shared", "none" };
	char cur[1100] = "";
	uint8_t *buf = NULL;
	struct kgenome_diag_scan *s = NULL;
	long sz = 0;

	for (a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "-v"))
			verbose = 1;
		else
			table = argv[a];
	}
	{
		int r = load(table);

		if (r == 0) {
			printf("diag_text_relations: no table at %s, nothing to check\n", table);
			return 0;
		}
		if (r < 0) {
			printf("FAIL: the table has a row with fewer than six columns\n");
			return 1;
		}
	}
	for (i = 0; i < nrows; i++) {
		struct row *r = &R[i];
		int st = !strcmp(r->strength, "must") ? 0 : !strcmp(r->strength, "may") ? 1 : !strcmp(r->strength, "shared") ? 2 : 3;
		uint32_t n, x, y;
		int ok = 0, direct = 0, tried = 0;

		if (strcmp(r->path, cur)) {
			FILE *f;
			uint32_t lang = lang_of(r->path);
			struct kgenome_diag_text_req rq;

			kgenome_diag_scan_free(s);
			s = NULL;
			free(buf);
			buf = NULL;
			snprintf(cur, sizeof cur, "%s", r->path);
			/* KNOWN DEFECT REV-D12 (2026-10-24, M) [sev L]: the table names its samples by absolute path (1035 rows start with /mnt/games/normtest/s3/), and a sample that is not there is only counted in `absent`.
			 * Trigger: any checkout without the corpus at that path (CI, another machine). Effect: every row of the missing files is skipped, the test exits 0 and checks nothing.
			 * Reproducer: tests/data/diag_text_expect.tsv. Fix: store paths relative to a corpus root given as an argument, and fail (or report loudly) when a named file is absent. */
			f = fopen(r->path, "rb");
			if (!f) {
				absent++;
				continue;
			}
			fseek(f, 0, SEEK_END);
			sz = ftell(f);
			fseek(f, 0, SEEK_SET);
			buf = malloc((size_t)sz + 1u);
			if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
				fclose(f);
				unread++;
				free(buf);
				buf = NULL;
				continue;
			}
			buf[sz] = 0;
			fclose(f);
			samples++;
			if (!lang) {
				unread++;
				free(buf);
				buf = NULL;
				continue;
			}
			memset(&rq, 0, sizeof rq);
			rq.base = buf;
			rq.size = (uint64_t)sz;
			rq.lang = lang;
			rq.apply = kof_script_apply;
			s = kgenome_diag_scan_text(&rq);
		}
		if (!buf || !s)
			continue;
		n = kgenome_diag_scan_count(s);
		if (st == 3) {
			uint32_t links = 0;

			nones++;
			for (x = 0; x < n; x++)
				links += kgenome_diag_scan_at(s, x)->n_in;
			none_with_links += links != 0;
			if (links && verbose)
				printf("  expects none, route made %u links: %s   [%s]\n", links, strrchr(r->path, '/') + 1, r->why);
			continue;
		}
		for (x = 0; x < n && !ok; x++) {
			const struct kgenome_diag_hit *hx = kgenome_diag_scan_at(s, x);

			if (strcmp(kgenome_nucleo_cap_name(hx->cap), r->from_cap) || line_of(buf, hx->at) != r->from_line)
				continue;
			for (y = 0; y < n && !ok; y++) {
				const struct kgenome_diag_hit *hy = kgenome_diag_scan_at(s, y);

				if (strcmp(kgenome_nucleo_cap_name(hy->cap), r->to_cap) || line_of(buf, hy->at) != r->to_line)
					continue;
				tried++;
				ok = reach(s, x, y, st == 2, &direct);
			}
		}
		if (ok)
			(direct ? found_direct : found_path)[st]++;
		else {
			missing[st]++;
			if (verbose)
				printf("  not found (%s): %s  L%d %s -> L%d %s   [%s]%s\n", r->strength, strchr(r->path + 1, '/') ? strrchr(r->path, '/') + 1 : r->path, r->from_line, r->from_cap,
				       r->to_line, r->to_cap, r->why, tried ? "" : "  (no such node pair)");
		}
	}
	kgenome_diag_scan_free(s);
	free(buf);
	printf("diag_text_relations: %d rows, %d samples scanned (%d not present, %d not scanned)\n", nrows, samples, absent, unread);
	for (a = 0; a < 3; a++)
		printf("  %-6s expected %4d: found as a link %4d, through a chain %4d, not found %4d\n", SN[a], found_direct[a] + found_path[a] + missing[a], found_direct[a], found_path[a], missing[a]);
	printf("  none   %d samples that expect no relation; the route made links in %d of them\n", nones, none_with_links);
	return 0;
}
