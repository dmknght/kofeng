/*
 * verdict_delivery - the verdict a scan REPORTS and the verdict the summary COUNTS are
 * one thing.
 *
 * A host learns of a verdict from two places: the on_event_detected callback (what a
 * tool prints) and the file roll-up kverdict_filemap_fold (what a tool counts:
 * "infected N file(s)"). Both read kof_result.verdict, and an object's verdict is made
 * of its diseases: a detector's note is no verdict and leaves neither a verdict nor a
 * count.
 *
 * THE INVARIANT, asserted here for every top-level file given: the file has a roll-up
 * verdict (it is counted infected) if and only if the scan delivered at least one
 * verdict event for an object of that file, and the event is the roll-up's.
 *
 * With no path argument the test builds its own objects (one that a fixture diagnose
 * names, one only a detector matched, a clean one) from the sigs database. With paths (a file, or a directory
 * whose files are scanned one by one) it is a corpus check and lists every mismatch:
 *
 *     unit_verdict_delivery <db> <path>...
 *
 * THE SCANNER REPAIRS IN PLACE: pass copies, `chmod a-w`.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "caps_fix.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofobjname.h"
#include "../../libkofeng/verdictor/verdict.h"

static int fails;
static unsigned n_files, n_counted, n_mismatch;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		fails++;
}

struct run {
	kverdict_filemap *map;
	unsigned events;           /* verdict events for this file */
	char first[256];           /* the first one's text */
	char path[4096];
};

static void on_event(const char *object, const char *verdict,
		     const struct kof_finding *f, void *u)
{
	struct run *r = u;

	(void)object;
	(void)f;
	if (!r->events)
		snprintf(r->first, sizeof r->first, "%s", verdict);
	r->events++;
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *u)
{
	struct run *r = u;

	(void)bytes;
	(void)len;
	kverdict_filemap_fold(r->map, name, res, 1);
	return 0;
}

/* One top-level file: scan it, and say whether the two sources agree. */
static int check_file(kof_scanner *sc, const char *path, int quiet)
{
	struct run r;
	struct kof_scan_option o;
	const struct kverdict_file *e;
	int counted, agree;

	memset(&r, 0, sizeof r);
	snprintf(r.path, sizeof r.path, "%s", path);
	r.map = kverdict_filemap_new();
	memset(&o, 0, sizeof o);
	o.on_event_detected = on_event;
	o.event_user = &r;
	(void)kscan_path(sc, path, &o, on_object, &r);
	e = kverdict_filemap_find(r.map, path, strlen(path));
	counted = e && e->has_verdict;
	agree = counted == (r.events > 0);
	n_files++;
	n_counted += (unsigned)counted;
	if (!agree) {
		n_mismatch++;
		if (!quiet)
			printf("  MISMATCH %s: roll-up %s (%s), events %u\n", path,
			       counted ? "counts it" : "does not count it",
			       counted ? e->name : "-", r.events);
	}
	kverdict_filemap_free(r.map);
	return agree;
}

static void check_path(kof_scanner *sc, const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return;
	if (S_ISDIR(st.st_mode)) {
		DIR *d = opendir(path);
		struct dirent *de;

		if (!d)
			return;
		while ((de = readdir(d)) != NULL) {
			char sub[4096];

			if (de->d_name[0] == '.')
				continue;
			snprintf(sub, sizeof sub, "%s/%s", path, de->d_name);
			check_path(sc, sub);
		}
		closedir(d);
		return;
	}
	(void)check_file(sc, path, 0);
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

/* An object the fixture diagnose kmod_give_root names (a kernel module that imports the two
 * credential functions), one only a detector matched (sig_anyfmt: "GCC: (GNU)") and a clean
 * object. */
static void synthetic(kof_engine *e)
{
	const char *hit = "build/test/verdict_delivery_hit.tmp";
	const char *evid = "build/test/verdict_delivery_evid.tmp";
	const char *clean = "build/test/verdict_delivery_clean.tmp";
	uint8_t buf[256];
	static uint8_t kmod[4096];
	uint64_t kmod_n = cf_kmod(kmod, sizeof kmod, 0, 0);
	kof_scanner *sc = kscan_new(e);
	struct run r;
	struct kof_scan_option o;
	const struct kverdict_file *f;

	memset(buf, 'A', sizeof buf);
	if (!sc || !write_file(clean, buf, sizeof buf)) {
		printf("verdict delivery: cannot set up\n");
		fails++;
		return;
	}
	write_file(hit, kmod, (size_t)kmod_n);
	memset(buf, 'A', sizeof buf);
	memcpy(buf + 40, "GCC: (GNU)", 10);
	write_file(evid, buf, sizeof buf);

	memset(&r, 0, sizeof r);
	r.map = kverdict_filemap_new();
	memset(&o, 0, sizeof o);
	o.on_event_detected = on_event;
	o.event_user = &r;
	(void)kscan_path(sc, hit, &o, on_object, &r);
	f = kverdict_filemap_find(r.map, hit, strlen(hit));
	ok("the roll-up counts the object that has a disease", f && f->has_verdict);
	ok("and an event delivers its verdict, named from the disease", r.events >= 1 &&
	   strstr(r.first, "Rootkit:kernel.giveroot") != NULL);
	ok("the delivered name is the roll-up's name", f && r.events >= 1 &&
	   strstr(r.first, f->name) != NULL);
	kverdict_filemap_free(r.map);
	ok("the file is in agreement", check_file(sc, hit, 0));
	ok("a detector's note leaves no verdict, no event, no count",
	   check_file(sc, evid, 0) && n_counted == 1u);
	ok("a clean file is counted by neither", check_file(sc, clean, 0));
	kscan_free(sc);
	remove(hit);
	remove(evid);
	remove(clean);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine *e = keng_open(db);
	int i;

	if (!e) {
		printf("verdict delivery: cannot open %s\n", db);
		return 2;
	}
	if (argc <= 2) {
		n_files = n_counted = n_mismatch = 0;
		synthetic(e);
	} else {
		kof_scanner *sc = kscan_new(e);

		if (!sc)
			return 2;
		n_files = n_counted = n_mismatch = 0;
		for (i = 2; i < argc; i++)
			check_path(sc, argv[i]);
		printf("%u file(s), %u counted by the roll-up, %u mismatch(es)\n",
		       n_files, n_counted, n_mismatch);
		ok("every counted file has a delivered verdict and no other has", n_mismatch == 0);
		kscan_free(sc);
	}
	keng_close(e);
	printf("verdict delivery: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
