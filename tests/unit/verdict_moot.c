/*
 * verdict_moot - an analysis that ran out of budget on an object that OPENED is not a
 * cut object.
 *
 * The emulate route of the diagnose scan spends its instruction budget on a packer's
 * stub; the unpacker has meanwhile produced the child that holds the program, and the
 * child is the subject. The wrapper came back "Limit reached" over a child scanned in
 * full. sx_verdict_gap is the one place an unfinished analysis becomes
 * KOF_BROKEN_LIMIT, and it is driven here on a hand-built scanner state:
 *
 *   no child (the cut was the ONLY analysis)  -> LIMIT, as before
 *   a normalised view only, or a carve only   -> LIMIT (neither is the subject)
 *   an unpacked / container child             -> not broken, analysis_moot set,
 *                                                kof_stats.analysis_moot counted
 *   a verdict already made                    -> not asked: sx_verdict_make calls the gap only without one
 *   an earlier reason (DAMAGED)               -> kept
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/scanners/scan_int.h"

static int fails;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		fails++;
}

static struct kof_result res;

static void run(kof_scanner *sc, uint32_t kids, uint32_t views, uint32_t carved,
		uint32_t broken)
{
	memset(&res, 0, sizeof res);
	res.broken = broken;
	sc->child.n = kids;
	sc->child.n_views = views;
	sc->child.n_carved = carved;
	sx_verdict_gap(sc, NULL, &res, 1);    /* the analysis was cut, nothing matched */
}

int main(int argc, char **argv)
{
	kof_engine *e = keng_open(argc > 1 ? argv[1] : "build/test/databases-sigs");
	kof_scanner *sc;
	uint64_t m0;

	if (!e) {
		printf("verdict moot: cannot open the database\n");
		return 2;
	}
	sc = kscan_new(e);
	if (!sc)
		return 2;
	m0 = sc->st.analysis_moot;

	run(sc, 0, 0, 0, 0);
	ok("no child: the cut is the only analysis, LIMIT", res.broken == KOF_BROKEN_LIMIT && !res.analysis_moot);
	run(sc, 1, 1, 0, 0);
	ok("a normalised view is not the subject: LIMIT", res.broken == KOF_BROKEN_LIMIT);
	run(sc, 1, 0, 1, 0);
	ok("a carve is not the subject: LIMIT", res.broken == KOF_BROKEN_LIMIT);
	ok("and none of these was counted moot", sc->st.analysis_moot == m0);
	run(sc, 1, 0, 0, 0);
	ok("an unpacked child carries the evidence: not broken", res.broken == KOF_BROKEN_NONE);
	ok("it says so, for -v and an examiner", res.analysis_moot == 1);
	ok("and it is counted", sc->st.analysis_moot == m0 + 1);
	run(sc, 3, 1, 0, 0);
	ok("a view beside a real child: still moot", res.broken == KOF_BROKEN_NONE && res.analysis_moot);
	run(sc, 1, 0, 0, KOF_BROKEN_DAMAGED);
	ok("an earlier reason is kept", res.broken == KOF_BROKEN_DAMAGED && !res.analysis_moot);

	/* the fake children are not a list the scanner owns */
	sc->child.n = sc->child.n_views = sc->child.n_carved = 0;
	kscan_free(sc);
	keng_close(e);
	printf("verdict moot: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
