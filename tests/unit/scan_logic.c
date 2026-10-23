/*
 * scan_logic - what the scan does when it is told to stop. Each case is a way to LOSE
 * a detection or to keep a thing nobody should keep. A file is DETECTED when it has a
 * verdict, and the one that has here is a kernel module that imports the two credential
 * functions (the fixture diagnose tests/sigs/diagnoses/kmod_give_root.c declares the
 * disease; caps_fix.h builds the image).
 *
 *   1. (that two detectors may both match one object, and that nothing one of them says
 *      ends the scan, is match_all.c's.)
 *   2. a host asks to stop in the middle of an object. The object was not fully
 *      examined, so it must not be handed to the cache as clean: a cache that
 *      remembers it skips the file for ever, and the detection that would have
 *      been found is gone.
 *   3. the same without a stop, as the control: a clean file IS remembered and a
 *      detected one is not.
 *   4. told to stop with the children of a container still waiting.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caps_fix.h"
#include "../../libkofeng/kofeng.h"

static int fails;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		fails++;
}

static int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	fwrite(p, 1, n, f);
	fclose(f);
	return 1;
}

static int n_obj;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)user; (void)res;
	n_obj++;
	return 0;
}

static int abort_at = -1;

/* Counts objects and asks the walk to stop when the abort_at-th one is reported
 * (0 is the file itself, 1.. its children), -1 never. */
static int on_object_abort(const char *name, const void *bytes, uint64_t len,
			   const struct kof_result *res, void *user)
{
	int idx = n_obj;

	(void)name; (void)bytes; (void)len; (void)res; (void)user;
	n_obj++;
	return idx == abort_at;
}

/* ---- the cache and stop hooks ----------------------------------------- */

static char kept[8][256], dropped[8][256];
static int n_kept, n_dropped, stop_calls, stop_after;

static int cb_seen(void *u, const char *path) { (void)u; (void)path; return 0; }
static void cb_keep(void *u, const char *p)
{
	(void)u;
	if (n_kept < 8) snprintf(kept[n_kept++], 256, "%s", p);
}
static void cb_drop(void *u, const char *p)
{
	(void)u;
	if (n_dropped < 8) snprintf(dropped[n_dropped++], 256, "%s", p);
}
/* Says go until `stop_after` questions have been asked, then stop - so the
 * question that gets the answer is the one the test chose. */
static int cb_stop(void *u)
{
	(void)u;
	return ++stop_calls > stop_after;
}

static int in(char list[][256], int n, const char *needle)
{
	int i;

	for (i = 0; i < n; i++)
		if (strstr(list[i], needle))
			return 1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	char dir[] = "build/test/scanlogic_XXXXXX";
	char pa[256], pb[256];
	static uint8_t kmod[4096];
	uint64_t kmod_n;
	uint8_t marker[48];
	kof_engine *e;
	kof_scanner *sc;
	struct kof_scan_option opt;
	unsigned i;

	printf("scan_logic:\n");
	if (!mkdtemp(dir)) {
		printf("scan_logic: cannot make a work directory\n");
		return 1;
	}
	snprintf(pa, sizeof pa, "%s/a_detected.bin", dir);
	snprintf(pb, sizeof pb, "%s/b_clean.bin", dir);

	kmod_n = cf_kmod(kmod, sizeof kmod, 4, 0);
	write_file(pa, kmod, (size_t)kmod_n);
	for (i = 0; i < sizeof marker; i++)
		marker[i] = (uint8_t)(0x90u + i);     /* nothing matches this */
	write_file(pb, marker, sizeof marker);

	e = keng_open(db);
	if (!e) {
		printf("scan_logic: cannot open %s - run `make databases "
		       "BASEDIR=tests/sigs` first\n", db);
		return 1;
	}
	sc = kscan_new(e);
	if (!sc) {
		keng_close(e);
		return 1;
	}

	/* ---- 4. the control: no stop -------------------------------------- */
	memset(&opt, 0, sizeof opt);
	opt.recurse_dirs = 1;
	opt.cache_seen = cb_seen; opt.cache_keep = cb_keep; opt.cache_drop = cb_drop;
	n_kept = n_dropped = 0;
	n_obj = 0;
	(void)kscan_path(sc, dir, &opt, on_object, NULL);
	ok("a clean file is remembered", in(kept, n_kept, "b_clean"));
	ok("a detected file is not", !in(kept, n_kept, "a_detected"));
	ok("and the cache is told about the detection",
	   in(dropped, n_dropped, "a_detected"));

	/* ---- 3. stopped inside an object ---------------------------------- */
	memset(&opt, 0, sizeof opt);
	opt.recurse_dirs = 1;
	opt.cache_seen = cb_seen; opt.cache_keep = cb_keep; opt.cache_drop = cb_drop;
	opt.should_stop = cb_stop;
	n_kept = n_dropped = 0;
	stop_calls = 0;
	stop_after = 1;             /* the walk's own check passes; the next is mid-object */
	n_obj = 0;
	(void)kscan_path(sc, pa, &opt, on_object, NULL);
	ok("the stop was asked for while the object was being examined",
	   stop_calls >= 2);
	ok("an object cut short is NOT handed to the cache as clean",
	   !in(kept, n_kept, "a_detected"));


	/* ---- 5. told to stop with children still waiting ------------------ */
	{
		char pm[256];
		static uint8_t multi[40 + 4096];

		snprintf(pm, sizeof pm, "%s/m_multi.bin", dir);
		memset(multi, 0x70, 40);
		memcpy(multi, "KOFMULTI", 8);
		/* The LAST child is the one with something in it: it runs to the end. */
		memcpy(multi + 40, kmod, (size_t)kmod_n);
		write_file(pm, multi, 40u + (size_t)kmod_n);

		memset(&opt, 0, sizeof opt);
		opt.cache_seen = cb_seen; opt.cache_keep = cb_keep;
		opt.cache_drop = cb_drop;

		/* the control: every object is scanned, the detection is found */
		n_kept = n_dropped = 0; n_obj = 0; abort_at = -1;
		(void)kscan_path(sc, pm, &opt, on_object_abort, NULL);
		ok("the container yields its three children and itself",
		   n_obj == 4);
		ok("the payload in the last one is found, so the file is not kept",
		   !in(kept, n_kept, "m_multi") && in(dropped, n_dropped, "m_multi"));

		/* the host says abandon at the FIRST object: children are waiting */
		n_kept = n_dropped = 0; n_obj = 0; abort_at = 0;
		(void)kscan_path(sc, pm, &opt, on_object_abort, NULL);
		ok("the walk stopped with children unexamined", n_obj < 4);
		ok("a file with children nobody looked at is NOT remembered as clean",
		   !in(kept, n_kept, "m_multi"));

		/* the host says abandon at the LAST object: nothing was left over */
		n_kept = n_dropped = 0; n_obj = 0; abort_at = 3;
		(void)kscan_path(sc, pm, &opt, on_object_abort, NULL);
		ok("abandoning at the last object leaves nothing unexamined",
		   n_obj == 4);
		ok("and that outcome is the control's: the finding still reaches the cache",
		   in(dropped, n_dropped, "m_multi"));
	}

	kscan_free(sc);
	keng_close(e);
	printf("scan_logic: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
