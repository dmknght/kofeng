/*
 * mem_oom_open - an allocation that fails while the engine is OPENED, its catalog loaded, an object scanned and everything closed must leave nothing behind
 * (audit_mem MEM-7).
 *
 * silent_oom_sweep refuses every allocation of a SCAN and asks whether the answer changed in silence; it never refuses one of the load. The load is where the
 * pack's tables, the similarity set and the catalog are made, each with several blocks and a free on every exit, and a free missing on one of them is a block held
 * and never used (kof_mutation_build_req, when the table of parts is refused, left the filter bank it had just made: 232 bytes, found by refusing the 47th
 * allocation of a load under LeakSanitizer and pinned here without it).
 *
 * HOW. A phase is: open a database of 12 similarity diagnoses, load the catalog, make a scanner, scan two objects (one matches), free the scanner, load the
 * catalog again, close. It is run once to settle what libc keeps, once to count its allocations, then once for every n with the n-th allocation refused. After
 * each, every block the engine allocated must have been freed: a phase that ends with more than it began with held something. What the phase answers when memory is
 * refused is not asserted (silent_oom_sweep does that for a scan); that it does not crash and gives everything back is.
 *
 * The tracker and the sweep are oom_harness.h's (shared with mem_oom_api and mem_flat_api); this file is the phase of the open/catalog/scan/close path.
 *
 * usage: mem_oom_open
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oom_harness.h"
#include "form_pack.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/scanners/scan.h"

static char root[256];
static char db[400];
static const char *dbdir = "build/test/databases-sigs";

#define OKF OHK

static int hits;

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)user;
	if (res)
		for (uint32_t i = 0; i < res->n_diag; i++)
			hits += res->diag[i].state == KOF_DIAG_ST_MATCH;
	return 0;
}

static uint8_t obj_a[BLK], obj_b[BLK];

static int phase(void *ctx)
{
	(void)ctx;
	kof_engine *eng = keng_open(db);
	kof_scanner *sc;
	struct kof_scan_option opt;

	if (!eng)
		return -1;
	(void)keng_catalog_load(eng, "bases/pathogens", "bases/syndromes");
	sc = kscan_new(eng);
	if (sc) {
		memset(&opt, 0, sizeof opt);
		(void)kof_scan_set_explain(sc, 1);
		(void)kscan_bytes(sc, obj_a, BLK, "a", &opt, on_object, NULL);
		(void)kscan_bytes(sc, obj_b, BLK, "b", &opt, on_object, NULL);
		kscan_free(sc);
	}
	(void)keng_catalog_load(eng, "bases/pathogens", "bases/syndromes");
	keng_close(eng);
	return 0;
}

int main(void)
{
	uint8_t *rec[12];
	size_t rl[12];
	uint32_t k;

	if (access(dbdir, X_OK) != 0) {
		printf("mem_oom_open: %s is not built\n", dbdir);
		return 2;
	}
	snprintf(root, sizeof root, "build/kof_memoom_XXXXXX");
	if (!mkdtemp(root)) {
		printf("mem_oom_open: cannot make a scratch directory\n");
		return 2;
	}
	snprintf(db, sizeof db, "%s/db", root);
	kof_mkdir(db, 0700);
	(void)copy_pack(dbdir, "sigs-any.ksig", db);
	(void)copy_pack("build/release/databases", "names.kdig", db);       /* the names table of the ids is read at the open too (MERGED 61) */
	for (k = 0; k < 12u; k++) {
		char name[16];

		rec[k] = malloc(70000);
		snprintf(name, sizeof name, "f%u", k);
		rl[k] = form_record(rec[k], name, k, 1u + k % 3u);
	}
	write_kdig(db, "diag-a.kdig", rec, rl, 12u);
	for (k = 0; k < 12u; k++)
		free(rec[k]);
	make_bytes(obj_a, seed_of(3u, 0u));
	make_bytes(obj_b, seed_of(900u, 0u));

	{
		struct oh_sweep_res r;

		hits = 0;
		r = oh_sweep("open/catalog/scan/close", phase, NULL, NULL, 100u);
		OKF(hits >= 1, "the clean phase did not match the diagnose of its object (%d)", hits);
		printf("  %lu allocations refused in turn, %lu left blocks behind\n", r.allocs, r.leaked);
	}
	if (!oh_failures)
		rm_all(root);
	if (oh_failures) {
		printf("mem_oom_open: %d FAIL\n", oh_failures);
		return 1;
	}
	printf("mem_oom_open: ok\n");
	return 0;
}
