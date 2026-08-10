/*
 * kofscanner - the scanner.
 *
 *   kofscanner --db <dir-or-blob> --scan-files <path>
 *
 * Built on nothing but libkofeng/kofeng.h. That constraint is the point: if this needs
 * something the public header does not offer, the header is wrong and gets fixed, and
 * anyone else embedding the engine gets the fix too. kofexamine is the opposite - a
 * diagnostic that reaches into the internal collectors on purpose - and the two exist
 * separately so neither has to compromise for the other.
 *
 * There is no directory walk here. A directory yielding files and an archive yielding
 * members are the same shape, so the walk belongs to the engine; doing one of them out
 * here would mean writing that loop twice. What is left for a CLI is what a CLI is
 * for: read the arguments, set the policy, print what comes back.
 */

/* Before any include, not after: clock_gettime is POSIX, and a feature test macro
 * placed after the first include has no effect at all. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../libkofeng/kofeng.h"

struct run {
	/* No object counter: the engine already keeps one, and a second copy is a
	 * second thing that can disagree with it. */
	uint64_t infected, suspect, dropped, incomplete;
	int verbose;
	int stats;
};

static const char *level_str(uint32_t level)
{
	return level == KOF_LEVEL_INFECT ? "INFECTED" : "SUSPECT";
}

/*
 * Called once per object the engine scanned, findings or not.
 *
 * Returning zero always: this scanner reports everything and stops for nothing. A
 * different caller - an on-access hook that only needs to know whether to block -
 * returns non-zero at the first finding and the engine abandons the rest of the tree.
 */
static int on_object(const char *name, const struct kof_result *res, void *user)
{
	struct run *r = user;
	uint32_t i;
	int worst = -1;

	/*
	 * An object the engine could not finish with is not clean, and is not a
	 * finding either. Reported separately, because the two lead to different
	 * decisions and collapsing them is how a decompression bomb stops being
	 * scanned and starts being trusted.
	 */
	if (res->incomplete) {
		r->incomplete++;
		printf("%-10s %s: limit reached; the object was not fully examined\n",
		       "PARTIAL", name);
	}
	if (res->n == 0) {
		if (r->verbose && !res->incomplete)
			printf("%-10s %s\n", "OK", name);
		return 0;
	}
	for (i = 0; i < res->n; i++) {
		printf("%-10s %s: %s\n", level_str(res->v[i].level), name,
		       res->v[i].name);
		if ((int)res->v[i].level > worst)
			worst = (int)res->v[i].level;
	}
	/*
	 * One object, one count, at its highest level.
	 *
	 * Two modules may both name an object, one certain and one not; counting each
	 * finding would report more infected objects than there are objects, and
	 * counting the object in both columns would report it twice. Neither is a
	 * number anyone can act on.
	 *
	 * There is no third number for findings. Once an object is reported at its
	 * level, the count of how many modules agreed is about the database rather
	 * than about the disk, and it reads as a severity by anyone scanning the
	 * summary - an object named by four modules is not worse than one named by
	 * one. Every finding is printed above; the summary counts objects.
	 */
	if (worst == KOF_LEVEL_INFECT)
		r->infected++;
	else if (worst == KOF_LEVEL_SUSPECT)
		r->suspect++;
	if (res->dropped) {
		printf("%-10s %s: %u further finding(s) not reported\n", "NOTE",
		       name, res->dropped);
		r->dropped += res->dropped;
	}
	return 0;
}

/*
 * What the filtering earned.
 *
 * Behind a flag rather than always printed, and printed at all rather than merely
 * collected: the engine counts every one of these on every module of every object,
 * and a counter nothing can read is a counter nobody keeps honest. The whole design
 * rests on ruling a module out being much cheaper than running it, and these are the
 * numbers that say whether it does.
 *
 * `considered` must equal `ran` plus the four rejections - the prefilter has no
 * other exit - so the two columns are also a check on each other.
 */
static void print_stats(const struct kof_stats *st)
{
	uint64_t skipped = st->by_target + st->by_size + st->by_arch + st->by_region;

	printf("\n--- filtering ---\n");
	printf("considered %llu module evaluation(s)\n",
	       (unsigned long long)st->considered);
	printf("  ran      %llu\n", (unsigned long long)st->ran);
	printf("  target   %llu\n", (unsigned long long)st->by_target);
	printf("  size     %llu\n", (unsigned long long)st->by_size);
	printf("  arch     %llu\n", (unsigned long long)st->by_arch);
	printf("  region   %llu\n", (unsigned long long)st->by_region);
	if (st->ran + skipped != st->considered)
		printf("  NOTE: ran + skipped is %llu, not %llu\n",
		       (unsigned long long)(st->ran + skipped),
		       (unsigned long long)st->considered);

	printf("searches   %llu, %.2f MB read\n",
	       (unsigned long long)st->searches,
	       (double)st->bytes_searched / 1048576.0);
	printf("  answered without scanning %llu\n",
	       (unsigned long long)st->gram_answers);
	printf("presence   %.2f MB indexed\n",
	       (double)st->gram_bytes / 1048576.0);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s --db <dir-or-blob> --scan-files <path> [options]\n"
		"\n"
		"  --db            module database: a directory of them, or one blob\n"
		"  --scan-files    file to scan, or directory to scan recursively\n"
		"  --max-depth N   directory depth limit\n"
		"  --follow-links  follow symbolic links (off by default: a link into\n"
		"                  an ancestor turns a walk into a loop)\n"
		"  --all-matches   keep scanning an object after the first finding\n"
		"  --stats         report what the prefilter and the presence set earned\n"
		"  --max-produced N  bytes an object may yield before the scan gives up\n"
		"  -v              also report objects that came back clean\n"
		"\n"
		"exit: 0 nothing found, 1 something found, 2 could not scan\n",
		argv0);
}

int main(int argc, char **argv)
{
	const char *db = NULL, *target = NULL;
	kof_engine *eng;
	kof_scanner *sc;
	struct kof_scan_option opt;
	struct run r;
	const struct kof_stats *st;
	struct timespec t0, t1;
	double secs, mb;
	uint64_t unreadable = 0;
	int i, rc;

	memset(&r, 0, sizeof r);
	memset(&opt, 0, sizeof opt);
	/* Scanning a named directory means scanning what is in it. The engine defaults
	 * to not recursing so that a caller who says nothing gets less rather than a
	 * surprise; a scanner is the caller that does want it. */
	opt.recurse_dirs = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
			db = argv[++i];
		else if (strcmp(argv[i], "--scan-files") == 0 && i + 1 < argc)
			target = argv[++i];
		else if (strcmp(argv[i], "--max-depth") == 0 && i + 1 < argc)
			opt.max_depth = (uint32_t)strtoul(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--follow-links") == 0)
			opt.follow_symlinks = 1;
		else if (strcmp(argv[i], "--all-matches") == 0)
			opt.all_matches = 1;
		else if (strcmp(argv[i], "--max-produced") == 0 && i + 1 < argc)
			opt.max_produced_bytes = strtoull(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--stats") == 0)
			r.stats = 1;
		else if (strcmp(argv[i], "-v") == 0)
			r.verbose = 1;
		else {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		}
	}
	if (!db || !target) {
		usage(argv[0]);
		return 2;
	}

	eng = kof_engine_open(db);
	if (!eng) {
		fprintf(stderr, "%s: cannot load a database from %s\n", argv[0], db);
		return 2;
	}
	printf("database: version %u, %u record(s)\n",
	       kof_engine_db_version(eng), kof_engine_records(eng));

	sc = kof_scanner_new(eng);
	if (!sc) {
		fprintf(stderr, "%s: out of memory\n", argv[0]);
		kof_engine_close(eng);
		return 2;
	}

	/*
	 * Wall clock, not CPU time, and around the scan alone.
	 *
	 * A scanner spends much of its time waiting for a disk, and CPU time hides
	 * exactly that - it would report a cold scan as fast as a warm one. Wall clock
	 * is also what the throughput below has to be derived from for the number to
	 * mean anything.
	 *
	 * Loading the database is outside it: it happens once whatever is scanned, so
	 * folding it in makes a scan of one file look slow and a scan of a filesystem
	 * look faster than it is.
	 */
	clock_gettime(CLOCK_MONOTONIC, &t0);
	rc = kof_scan_path(sc, target, &opt, on_object, &r);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	if (rc < 0)
		fprintf(stderr, "%s: cannot scan %s\n", argv[0], target);

	secs = (double)(t1.tv_sec - t0.tv_sec) +
	       (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	st = kof_scanner_stats(sc);
	mb = st ? (double)st->object_bytes / 1048576.0 : 0.0;

	printf("\n--- scan complete ---\n");
	printf("scanned   %llu object(s), %.2f MB\n",
	       st ? (unsigned long long)st->objects : 0ull, mb);
	printf("infected  %llu object(s)\n", (unsigned long long)r.infected);
	printf("suspected %llu object(s)\n", (unsigned long long)r.suspect);
	if (r.incomplete)
		printf("partial   %llu object(s) the engine could not finish\n",
		       (unsigned long long)r.incomplete);
	/* Throughput beside the time it came from: on its own, a duration says nothing
	 * without the size of what was scanned, and both are already here. Guarded
	 * because a scan can finish inside the clock's resolution. */
	if (secs > 0.0005)
		printf("time      %.2f s (%.0f MB/s)\n", secs, mb / secs);
	else
		printf("time      %.3f s\n", secs);
	/* Copied out while the scanner is alive. kof_scanner_stats hands back a
	 * pointer INTO the scanner, and the exit decision below runs after the
	 * scanner has been freed - reading it there was a use-after-free, reached
	 * on exactly the scans that found nothing, which is why every run that
	 * detected something hid it. */
	if (st)
		unreadable = st->unreadable;
	if (unreadable)
		printf("skipped   %llu object(s) that could not be read\n",
		       (unsigned long long)unreadable);
	if (r.dropped)
		printf("note      %llu finding(s) over the per-object cap\n",
		       (unsigned long long)r.dropped);
	if (r.stats && st)
		print_stats(st);

	kof_scanner_free(sc);
	kof_engine_close(eng);

	/*
	 * Three outcomes, not two, because "found nothing" and "could not look" are
	 * different answers and a shell has to be able to tell them apart. Reporting
	 * both as 0 meant a scan of a path that does not exist, or of files that could
	 * not be opened, came back looking exactly like a clean scan.
	 *
	 *   0  scanned, nothing found
	 *   1  something found
	 *   2  could not scan, or could not scan all of it
	 *
	 * A detection outranks an error: if something was found, that is the answer,
	 * whatever else was skipped alongside it.
	 */
	if (r.infected || r.suspect)
		return 1;
	/* "Could not finish" belongs with "could not look", not with "found
	 * nothing": a caller that treats an exhausted budget as a clean scan has
	 * been evaded rather than reassured. */
	if (rc < 0 || unreadable || r.incomplete)
		return 2;
	return 0;
}