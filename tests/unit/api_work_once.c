/*
 * api_work_once - the engine builds each product ONCE per object, asserted as an EQUALITY on kof_stats.work_* through every way a host scans (owner 2026-10-29).
 *
 * mem_diag_forms asked for "<=" (at most one per object); a counter that never moved would pass, and so would a product built twice for half the objects. Here the
 * database is made so that the number is KNOWN, and the counters must equal it:
 *
 *   FORMS   12 similarity diagnoses of 1 to 3 blocks (24 matchers). Every object scanned: feeds 1, form asks 12, matchers 24, verdicts 1, catalogs 0 (no catalog facts).
 *           The whole of a form is evaluated for each object: today no matcher is skipped (an optimisation lowers the asks and flips this row on purpose).
 *   ROUTES  kscan_bytes, kscan_path over a directory of 3 files, kscan_path_mt (2 scanners, summed), kscan_explain (report on): n objects cost exactly n times the
 *           per-object figure, in every route - the walk, the thread split and the report build nothing a second time.
 *   REPEAT  the same object scanned again on the same scanner costs the same again (no figure shrinks: nothing is cached across scans, nothing is built twice
 *           inside one), and a second scanner of the engine counts from zero (the counters belong to the scanner).
 *   CATALOG diagnoses that carry catalog facts (tests/agree/alt_a, the sample run1 when it exists): work_catalogs == the objects whose verdict was made from
 *           them (1: the normalised view), work_verdicts == the objects that reached the verdict stage.
 *
 * usage: api_work_once
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "form_pack.h"
#include "../../libkofeng/kofeng.h"

static int failures;
#define CK(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static char root[256];

static int cb(const char *n, const void *b, uint64_t l, const struct kof_result *r, void *u)
{
	(void)n; (void)b; (void)l; (void)r;
	if (u)
		(*(unsigned *)u)++;
	return 0;
}

struct w {
	uint64_t objects, feeds, asks, matchers, verdicts, catalogs;
};

static struct w take(const kof_scanner *sc)
{
	const struct kof_stats *s = kscan_stats(sc);
	struct w w = { s->objects, s->work_feeds, s->work_form_asks, s->work_form_matchers, s->work_verdicts, s->work_catalogs };

	return w;
}

static struct w add(struct w a, struct w b)
{
	a.objects += b.objects; a.feeds += b.feeds; a.asks += b.asks; a.matchers += b.matchers; a.verdicts += b.verdicts; a.catalogs += b.catalogs;
	return a;
}

#define NF 12u
#define MATCHERS 24u            /* sum over k < 12 of 1 + k % 3 */

static void expect_forms(const char *what, struct w w, uint64_t objects)
{
	CK(w.objects == objects, "%s: %llu objects scanned, %llu expected", what, (unsigned long long)w.objects, (unsigned long long)objects);
	CK(w.feeds == objects, "%s: the similarity feed was built %llu times for %llu objects", what, (unsigned long long)w.feeds, (unsigned long long)objects);
	CK(w.asks == NF * objects, "%s: %llu form expressions for %u forms and %llu objects", what, (unsigned long long)w.asks, NF, (unsigned long long)objects);
	CK(w.matchers == MATCHERS * objects, "%s: %llu matchers for %u matchers and %llu objects", what, (unsigned long long)w.matchers, MATCHERS, (unsigned long long)objects);
	CK(w.verdicts == objects, "%s: the verdict was built %llu times for %llu objects", what, (unsigned long long)w.verdicts, (unsigned long long)objects);
	CK(w.catalogs == 0u, "%s: a catalog verdict was built (%llu) for diagnoses that carry no catalog facts", what, (unsigned long long)w.catalogs);
}

static void forms(void)
{
	char db[400], dir[400], path[500];
	uint8_t *rec[NF], a[BLK], b[BLK];
	size_t rl[NF], k;
	kof_engine *e;
	kof_scanner *sc, *s2, *mt[2];
	struct kof_scan_option o;
	unsigned seen = 0;
	kdet_run *run;
	struct w w0, w1, w2;

	snprintf(db, sizeof db, "%s/db", root);
	kof_mkdir(db, 0700);
	(void)copy_pack("build/test/databases-sigs", "sigs-any.ksig", db);
	(void)copy_pack("build/release/databases", "names.kdig", db);
	for (k = 0; k < NF; k++) {
		char nm[16];

		rec[k] = malloc(70000);
		snprintf(nm, sizeof nm, "f%zu", k);
		rl[k] = form_record(rec[k], nm, (uint32_t)k, 1u + (uint32_t)k % 3u);
	}
	write_kdig(db, "diag-a.kdig", rec, rl, NF);
	for (k = 0; k < NF; k++)
		free(rec[k]);
	make_bytes(a, seed_of(3u, 0u));
	make_bytes(b, seed_of(900u, 0u));
	snprintf(dir, sizeof dir, "%s/files", root);
	kof_mkdir(dir, 0700);
	snprintf(path, sizeof path, "%s/a.bin", dir);
	write_file(path, a, BLK);
	snprintf(path, sizeof path, "%s/b.bin", dir);
	write_file(path, b, BLK);
	snprintf(path, sizeof path, "%s/c.bin", dir);
	write_file(path, a, BLK);
	e = keng_open(db);
	CK(e && kdb_diagnoses(e) == NF, "the form database does not open with %u diagnoses", NF);
	if (!e)
		return;
	memset(&o, 0, sizeof o);
	sc = kscan_new(e);
	CK(take(sc).objects == 0u && take(sc).feeds == 0u, "a new scanner does not start from zero");
	/* bytes: three objects, one of them matching a form */
	(void)kscan_bytes(sc, a, BLK, "a", &o, cb, &seen);
	(void)kscan_bytes(sc, b, BLK, "b", &o, cb, &seen);
	(void)kscan_bytes(sc, a, BLK, "a2", &o, cb, &seen);
	expect_forms("kscan_bytes x3 (repeat of one object included)", take(sc), 3u);
	w0 = take(sc);
	/* a second scanner of the same engine counts from zero */
	s2 = kscan_new(e);
	CK(take(s2).objects == 0u, "a second scanner does not start from zero");
	(void)kscan_bytes(s2, b, BLK, "b", &o, cb, &seen);
	expect_forms("second scanner", take(s2), 1u);
	CK(take(sc).objects == w0.objects, "scanning on the second scanner moved the first one's counters");
	kscan_free(s2);
	/* the report is built by the same pipeline: no second pass of anything */
	run = kscan_explain(sc, a, BLK, "e", NULL);
	w1 = take(sc);
	CK(run && kdet_run_count(run) == 1u, "explain: one object");
	CK(w1.objects == w0.objects + 1u && w1.feeds == w0.feeds + 1u && w1.asks == w0.asks + NF && w1.matchers == w0.matchers + MATCHERS && w1.verdicts == w0.verdicts + 1u,
	   "kscan_explain built something twice or not at all (objects +%llu feeds +%llu asks +%llu matchers +%llu verdicts +%llu)",
	   (unsigned long long)(w1.objects - w0.objects), (unsigned long long)(w1.feeds - w0.feeds), (unsigned long long)(w1.asks - w0.asks),
	   (unsigned long long)(w1.matchers - w0.matchers), (unsigned long long)(w1.verdicts - w0.verdicts));
	kdet_run_free(run);
	/* a walk over a directory of three files */
	kscan_free(sc);
	sc = kscan_new(e);
	seen = 0;
	(void)kscan_path(sc, dir, &(struct kof_scan_option){ .recurse_dirs = 1 }, cb, &seen);
	CK(seen == 3u, "the walk delivered %u objects, not 3", seen);
	expect_forms("kscan_path over 3 files", take(sc), 3u);
	kscan_free(sc);
	/* the same walk split over two scanners and two threads: the sum is the same, nothing is built twice for the split */
	mt[0] = kscan_new(e);
	mt[1] = kscan_new(e);
	seen = 0;
	(void)kscan_path_mt(mt, 2u, dir, &(struct kof_scan_option){ .recurse_dirs = 1 }, cb, &seen);
	w2 = add(take(mt[0]), take(mt[1]));
	CK(seen == 3u, "the parallel walk delivered %u objects, not 3", seen);
	expect_forms("kscan_path_mt over 3 files (2 scanners summed)", w2, 3u);
	kscan_free(mt[0]);
	kscan_free(mt[1]);
	keng_close(e);
}

static void catalog_facts(void)
{
	static const char *const unp[] = { "unpack-archive.ksig", "unpack-doc.ksig", "unpack-elf.ksig", "unpack-pe.ksig", "unpack-raw.ksig", "unpack-raw-x7.ksig" };
	/* KNOWN DEFECT DEF-F (2026-10-30, R) [sev L]: catalog_facts reads its sample from the owner's scratch (a hard-coded absolute path) and, when it is absent, prints a note and returns: the row is silently not run elsewhere.
	  * Trigger: any machine or CI without /mnt/games/normtest/scan_run1. Effect: the test passes without checking the catalog facts.
	  * Reproducer: run the test where that path is missing (the "is not there" note).
	  * Fix: build the sample at run time from the scene (as the det_acc2_fmt tests generate their fixtures) and fail, not skip, when it cannot. */
	const char *run1 = "/mnt/games/normtest/scan_run1/run1";
	char db[400], p[400];
	unsigned i, seen = 0, with = 0;
	kof_engine *e;
	kof_scanner *sc;
	struct w w;

	if (access(run1, R_OK) || access("build/test/databases-alt_a/names.kdig", R_OK)) {
		printf("  note: %s or the alt_a database is not there: the catalog row is not run\n", run1);
		return;
	}
	snprintf(db, sizeof db, "%s/dbc", root);
	kof_mkdir(db, 0700);
	for (i = 0; i < sizeof unp / sizeof unp[0]; i++)
		CK(copy_pack("build/release/databases", unp[i], db), "copy %s", unp[i]);
	CK(copy_pack("build/test/databases-alt_a", "diag-trojan.kdig", db) && copy_pack("build/test/databases-alt_a", "names.kdig", db), "copy the alt_a packs");
	snprintf(p, sizeof p, "%s/run1.copy", root);
	{
		char cmd[900];

		snprintf(cmd, sizeof cmd, "cp %s %s && chmod a-w %s", run1, p, p);
		CK(system(cmd) == 0, "copy run1");
	}
	e = keng_open(db);
	/* Seven: the six whose blocks are cut from functions (not scored: function units carry no similarity signature, prototype 2026-10-30) and
	 * one whose block is data (trojan_zorg_zorg-wave_07), the only one that matches. */
	CK(e && kdb_diagnoses(e) == 7u, "alt_a database");
	if (!e)
		return;
	sc = kscan_new(e);
	(void)kscan_path(sc, p, &(struct kof_scan_option){ .recurse_dirs = 1 }, cb, &seen);
	w = take(sc);
	with = 1;                       /* the normalised view: the one object whose verdict is made of the diagnoses that match (the data one) */
	CK(w.objects == 2u, "run1 is %llu objects (the file and its view)", (unsigned long long)w.objects);
	CK(w.catalogs == with, "work_catalogs %llu, %u object(s) have a verdict made from catalog facts", (unsigned long long)w.catalogs, with);
	CK(w.verdicts == w.objects, "work_verdicts %llu for %llu objects", (unsigned long long)w.verdicts, (unsigned long long)w.objects);
	CK(w.feeds <= w.objects && w.feeds >= 1u, "feeds %llu", (unsigned long long)w.feeds);
	printf("  run1 over alt_a: objects %llu feeds %llu asks %llu matchers %llu verdicts %llu catalogs %llu\n", (unsigned long long)w.objects, (unsigned long long)w.feeds,
	       (unsigned long long)w.asks, (unsigned long long)w.matchers, (unsigned long long)w.verdicts, (unsigned long long)w.catalogs);
	kscan_free(sc);
	keng_close(e);
}

int main(void)
{
	if (access("build/test/databases-sigs", X_OK) != 0) {
		printf("api_work_once: build/test/databases-sigs is not built\n");
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_workonce_XXXXXX");
	if (!mkdtemp(root)) {
		printf("api_work_once: no scratch directory\n");
		return 2;
	}
	forms();
	catalog_facts();
	if (!failures)
		rm_all(root);
	if (failures) {
		printf("api_work_once: %d FAIL\n", failures);
		return 1;
	}
	printf("api_work_once: ok\n");
	return 0;
}
