/*
 * kofscanner - the scanner.
 *
 *   kofscanner --db <dir-or-blob> --scan-files <path>
 *
 * Built on nothing but libkofeng/kofeng.h. That constraint is the point: if this needs
 * something the public header does not offer, the header is wrong and gets fixed, and
 * anyone else embedding the engine gets the fix too. tools/kofrun is the opposite - a
 * test harness that reaches into internal headers on purpose - and the two exist
 * separately so neither has to compromise for the other.
 *
 * There is no directory walk here. A directory yielding files and an archive yielding
 * members are the same shape, so the walk belongs to the engine; doing one of them out
 * here would mean writing that loop twice. What is left for a CLI is what a CLI is
 * for: read the arguments, set the policy, print what comes back.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libkofeng/kofeng.h"

struct run {
	/* No object counter: the engine already keeps one, and a second copy is a
	 * second thing that can disagree with it. */
	uint64_t infected, findings, dropped;
	int verbose;
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
	int counted = 0;

	if (res->n == 0) {
		if (r->verbose)
			printf("%-10s %s\n", "OK", name);
		return 0;
	}
	for (i = 0; i < res->n; i++) {
		printf("%-10s %s: %s\n", level_str(res->v[i].level), name,
		       res->v[i].name);
		r->findings++;
		/* An object is infected or it is not, however many modules named it. */
		if (res->v[i].level == KOF_LEVEL_INFECT && !counted) {
			r->infected++;
			counted = 1;
		}
	}
	if (res->dropped) {
		printf("%-10s %s: %u further finding(s) not reported\n", "NOTE",
		       name, res->dropped);
		r->dropped += res->dropped;
	}
	return 0;
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
		"  -v              also report objects that came back clean\n",
		argv0);
}

int main(int argc, char **argv)
{
	const char *db = NULL, *target = NULL;
	kof_engine *eng;
	kof_scanner *sc;
	struct kof_policy pol;
	struct run r;
	const struct kof_stats *st;
	int i, rc;

	memset(&r, 0, sizeof r);
	memset(&pol, 0, sizeof pol);
	/* Scanning a named directory means scanning what is in it. The engine defaults
	 * to not recursing so that a caller who says nothing gets less rather than a
	 * surprise; a scanner is the caller that does want it. */
	pol.recurse_dirs = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
			db = argv[++i];
		else if (strcmp(argv[i], "--scan-files") == 0 && i + 1 < argc)
			target = argv[++i];
		else if (strcmp(argv[i], "--max-depth") == 0 && i + 1 < argc)
			pol.max_depth = (uint32_t)strtoul(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--follow-links") == 0)
			pol.follow_symlinks = 1;
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
	printf("database: %u module(s), %u string(s)\n",
	       kof_engine_modules(eng), kof_engine_strings(eng));

	sc = kof_scanner_new(eng);
	if (!sc) {
		fprintf(stderr, "%s: out of memory\n", argv[0]);
		kof_engine_close(eng);
		return 2;
	}

	rc = kof_scan_path(sc, target, &pol, on_object, &r);
	if (rc < 0)
		fprintf(stderr, "%s: cannot scan %s\n", argv[0], target);

	st = kof_scanner_stats(sc);

	printf("\n--- scan complete ---\n");
	printf("scanned  %llu object(s), %.2f MB\n",
	       st ? (unsigned long long)st->objects : 0ull,
	       st ? (double)st->object_bytes / 1048576.0 : 0.0);
	printf("infected %llu object(s), %llu finding(s)\n",
	       (unsigned long long)r.infected, (unsigned long long)r.findings);
	if (st && st->unreadable)
		printf("skipped  %llu object(s) that could not be read\n",
		       (unsigned long long)st->unreadable);
	if (r.dropped)
		printf("note     %llu finding(s) over the per-object cap\n",
		       (unsigned long long)r.dropped);

	kof_scanner_free(sc);
	kof_engine_close(eng);
	/* Non-zero when something was found, so a shell can act on it. */
	return r.infected ? 1 : 0;
}