/*
 * verdict_delivery - the verdict a scan REPORTS and the verdict the summary COUNTS are
 * one thing.
 *
 * A host learns of a verdict from two places: the on_event_detected callback (what a
 * tool prints, finding by finding) and the file roll-up kverdict_filemap_fold (what a
 * tool counts: "infected N file(s)"). They had two sources. The roll-up counted the
 * worst finding of any object; the callback delivered only the findings that took the
 * file's verdict slot (is_verdict), and a detector that declares no disease cannot be
 * read by a syndrome, so its finding never took it. A packed miner came back
 * "infected 1 file(s)" with no line above it.
 *
 * THE INVARIANT, asserted here for every top-level file given: the file has a roll-up
 * level (it is counted infected, suspected or heuristic) if and only if the scan
 * delivered at least one verdict event for an object of that file. Both directions,
 * with --all-matches off and on.
 *
 * With no path argument the test builds its own objects (a detector with no disease,
 * a clean one) from the sigs database. With paths (a file, or a directory whose files
 * are scanned one by one) it is a corpus check and lists every mismatch:
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
static int check_file(kof_scanner *sc, const char *path, int all_matches, int quiet)
{
	struct run r;
	struct kof_scan_option o;
	const struct kverdict_file *e;
	int counted, agree;

	memset(&r, 0, sizeof r);
	snprintf(r.path, sizeof r.path, "%s", path);
	r.map = kverdict_filemap_new();
	memset(&o, 0, sizeof o);
	o.all_matches = (uint8_t)all_matches;
	o.on_event_detected = on_event;
	o.event_user = &r;
	(void)kscan_path(sc, path, &o, on_object, &r);
	e = kverdict_filemap_find(r.map, path, strlen(path));
	counted = e && e->level >= 0;
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

static void check_path(kof_scanner *sc, const char *path, int all_matches)
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
			check_path(sc, sub, all_matches);
		}
		closedir(d);
		return;
	}
	(void)check_file(sc, path, all_matches, 0);
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

/* A detector with NO disease (sig_anyfmt: the marker "GCC: (GNU)") and a clean object. */
static void synthetic(kof_engine *e)
{
	const char *hit = "build/test/verdict_delivery_hit.tmp";
	const char *clean = "build/test/verdict_delivery_clean.tmp";
	uint8_t buf[256];
	int am;

	memset(buf, 'A', sizeof buf);
	if (!write_file(clean, buf, sizeof buf)) {
		printf("verdict delivery: cannot set up\n");
		fails++;
		return;
	}
	memcpy(buf + 40, "GCC: (GNU)", 10);
	write_file(hit, buf, sizeof buf);
	for (am = 0; am < 2; am++) {
		kof_scanner *sc = kscan_new(e);
		struct run r;
		struct kof_scan_option o;
		const struct kverdict_file *f;

		if (!sc) {
			ok("scanner", 0);
			continue;
		}
		memset(&r, 0, sizeof r);
		r.map = kverdict_filemap_new();
		memset(&o, 0, sizeof o);
		o.all_matches = (uint8_t)am;
		o.on_event_detected = on_event;
		o.event_user = &r;
		(void)kscan_path(sc, hit, &o, on_object, &r);
		f = kverdict_filemap_find(r.map, hit, strlen(hit));
		printf(" all_matches=%d\n", am);
		ok("the roll-up counts the detector's finding", f && f->level >= 0);
		ok("and an event delivers it, named", r.events >= 1 &&
		   strstr(r.first, "GccComment") != NULL);
		ok("the delivered name is the roll-up's name", f && r.events >= 1 &&
		   strstr(r.first, f->name) != NULL);
		kverdict_filemap_free(r.map);
		ok("the file is in agreement", check_file(sc, hit, am, 0));
		ok("a clean file is counted by neither", check_file(sc, clean, am, 0));
		kscan_free(sc);
	}
	remove(hit);
	remove(clean);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine *e = keng_open(db);
	int i, am;

	if (!e) {
		printf("verdict delivery: cannot open %s\n", db);
		return 2;
	}
	if (argc <= 2) {
		synthetic(e);
	} else {
		for (am = 0; am < 2; am++) {
			kof_scanner *sc = kscan_new(e);

			if (!sc)
				return 2;
			n_files = n_counted = n_mismatch = 0;
			for (i = 2; i < argc; i++)
				check_path(sc, argv[i], am);
			printf("all_matches=%d: %u file(s), %u counted by the roll-up, %u mismatch(es)\n",
			       am, n_files, n_counted, n_mismatch);
			ok("every counted file has a delivered verdict and no other has", n_mismatch == 0);
			kscan_free(sc);
		}
	}
	keng_close(e);
	printf("verdict delivery: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
