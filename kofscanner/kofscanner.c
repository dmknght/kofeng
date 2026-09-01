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
#include <unistd.h>
#include <time.h>

#include "../libkofeng/kofeng.h"

struct run {
	/* No object counter: the engine already keeps one, and a second copy is a
	 * second thing that can disagree with it. */
	uint64_t infected, suspect, heur, dropped, incomplete;
	uint64_t by_reason[KOF_BROKEN_COUNT];
	int verbose;
	int stats;

	/* Where produced objects are written, or NULL. See dump_object. */
	const char *dump_dir;
	uint64_t    dumped;
	FILE       *manifest;

	/*
	 * The progress line: how many objects have gone by, when it was last
	 * drawn, and whether to draw it at all.
	 *
	 * A count kept here rather than read from the engine's stats, which is
	 * the one place this file otherwise refuses to keep its own: the stats
	 * belong to a scanner, and with several scanners there is no single one
	 * to ask while the walk is still running. This counts callbacks, which is
	 * the same thing seen from where it can actually be seen.
	 */
	int      progress;
	uint64_t seen;
	double   drawn_at;
	int      drawn;          /* something is on the line, and must be erased */
};

/*
 * Write a produced object out, numbered.
 *
 * Named by a counter rather than by what the object is called, and that is the
 * simplification rather than a compromise. A name out of an archive exists to be
 * read in the report; turning one into a filename means answering what to do about
 * separators, "..", duplicates and length, and every one of those answers is a way
 * to write a file somewhere it was not meant to go. A number has none of those
 * questions.
 *
 * The mapping is not lost, it is written down: MANIFEST holds the number against
 * the full name the report printed, so the two are joined by looking rather than by
 * guessing which mangled filename came from which line.
 *
 * The engine itself never creates a file from a name - the objects it produces have
 * no filename at all, by construction (see objsrc.h). This is a debugging
 * convenience, and it keeps that property.
 */
static void dump_object(struct run *r, const char *name, const void *bytes,
			uint64_t len)
{
	char path[1024];
	FILE *f;

	if (!r->dump_dir || !bytes || !len)
		return;
	/* Only what the engine PRODUCED. A top level object is already a file on
	 * disk and copying it would say nothing. */
	if (!strstr(name, "//"))
		return;

	r->dumped++;
	if ((size_t)snprintf(path, sizeof path, "%s/%06llu.raw", r->dump_dir,
			     (unsigned long long)r->dumped) >= sizeof path) {
		fprintf(stderr, "kofscanner: dump path too long, skipped\n");
		return;
	}
	f = fopen(path, "wb");
	if (!f) {
		fprintf(stderr, "kofscanner: cannot write %s\n", path);
		return;
	}
	if (fwrite(bytes, 1, (size_t)len, f) != (size_t)len)
		fprintf(stderr, "kofscanner: short write to %s\n", path);
	fclose(f);

	if (!r->manifest) {
		char mf[1024];

		snprintf(mf, sizeof mf, "%s/MANIFEST", r->dump_dir);
		r->manifest = fopen(mf, "w");
		if (r->manifest)
			fprintf(r->manifest, "# file          bytes  object\n");
	}
	if (r->manifest)
		fprintf(r->manifest, "%06llu.raw  %10llu  %s\n",
			(unsigned long long)r->dumped, (unsigned long long)len,
			name);
}

static const char *level_str(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return "INFECTED";
	return level == KOF_LEVEL_HEUR ? "HEURISTIC" : "SUSPECT";
}

/* How loudly a level speaks, which is not the order the constants were given.
 * -1 for "nothing reported yet", so an object with no findings ranks below all. */
static int rank_of(int level)
{
	switch (level) {
	case KOF_LEVEL_INFECT:  return 3;
	case KOF_LEVEL_SUSPECT: return 2;
	case KOF_LEVEL_HEUR:    return 1;
	default:                return 0;
	}
}

/*
 * Called once per object the engine scanned, findings or not.
 *
 * Returning zero always: this scanner reports everything and stops for nothing. A
 * different caller - an on-access hook that only needs to know whether to block -
 * returns non-zero at the first finding and the engine abandons the rest of the tree.
 */
/*
 * WHERE THE TIME GOES WHEN NOTHING IS FOUND.
 *
 * A scan prints a line per finding, so a subtree with no findings prints
 * nothing at all - and a person watching cannot tell that from a scan that has
 * stopped. Measured on this collection: 1 282 files across five directories
 * yield no finding between them, which is four seconds of silence in the middle
 * of a run, and every report of "it hangs at file X" has been that silence
 * ending at X rather than anything about X.
 *
 * On stderr and only when stderr is a terminal, so a redirect, a pipe or a log
 * gets exactly the bytes it always did. Rate limited to ten a second, because
 * the point is to show that time is passing and not to spend it: at 60 000
 * objects an unlimited version would draw more often than a terminal can scroll.
 */
#define PROGRESS_HZ 10.0

static double now_s(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void progress_draw(struct run *r, const char *name)
{
	double now;
	const char *tail;
	size_t n;

	if (!r->progress)
		return;
	r->seen++;
	now = now_s();
	if (r->drawn && now - r->drawn_at < 1.0 / PROGRESS_HZ)
		return;
	r->drawn_at = now;

	/* The last two path components: a full path wraps and a bare basename
	 * does not say which subtree the scan is in, which is the one thing
	 * somebody watching wants to know. */
	tail = name;
	{
		const char *p1 = NULL, *p2 = NULL, *c;

		for (c = name; *c; c++)
			if (*c == '/') { p2 = p1; p1 = c; }
		if (p2)
			tail = p2 + 1;
		else if (p1)
			tail = p1 + 1;
	}
	n = strlen(tail);
	if (n > 48)
		tail += n - 48;
	fprintf(stderr, "\r\033[K  %llu object(s)  %s",
		(unsigned long long)r->seen, tail);
	fflush(stderr);
	r->drawn = 1;
}

/* Take the line back before anything else writes, so a finding is never printed
 * onto a half-erased progress line. */
static void progress_clear(struct run *r)
{
	if (r->progress && r->drawn) {
		fprintf(stderr, "\r\033[K");
		fflush(stderr);
		r->drawn = 0;
	}
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct run *r = user;
	uint32_t i;
	int worst = -1;

	progress_draw(r, name);
	if (res->broken || res->n || r->verbose)
		progress_clear(r);

	dump_object(r, name, bytes, len);

	/*
	 * An object the engine could not finish with is not clean, and is not a
	 * finding either. Reported separately, because the two lead to different
	 * decisions and collapsing them is how a decompression bomb stops being
	 * scanned and starts being trusted.
	 */
	if (res->broken) {
		r->incomplete++;
		if (res->broken < KOF_BROKEN_COUNT)
			r->by_reason[res->broken]++;
		printf("%-10s %s: %s\n", "BROKEN", name,
		       kof_broken_name(res->broken));
	}
	if (res->n == 0) {
		if (r->verbose && !res->broken)
			printf("%-10s %s\n", "OK", name);
		return 0;
	}
	for (i = 0; i < res->n; i++) {
		printf("%-10s %s: %s\n", level_str(res->v[i].level), name,
		       res->v[i].name);
		/*
		 * Ranked, not compared as numbers.
		 *
		 * KOF_LEVEL_HEUR is 2 and INFECT is 1, so ">" made a heuristic
		 * outrank a named detection - the weakest answer presented as
		 * the strongest. The values are identifiers; the order they are
		 * reported in is a separate fact and belongs here.
		 */
		if (rank_of((int)res->v[i].level) > rank_of(worst))
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
	else if (worst == KOF_LEVEL_HEUR)
		r->heur++;
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
	uint64_t skipped = st->by_target + st->by_size + st->by_arch +
			  st->by_subtype + st->by_region;

	printf("\n--- filtering ---\n");
	printf("considered %llu module evaluation(s)\n",
	       (unsigned long long)st->considered);
	printf("  ran      %llu\n", (unsigned long long)st->ran);
	printf("  target   %llu\n", (unsigned long long)st->by_target);
	printf("  size     %llu\n", (unsigned long long)st->by_size);
	printf("  arch     %llu\n", (unsigned long long)st->by_arch);
	printf("  subtype  %llu\n", (unsigned long long)st->by_subtype);
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
	/*
	 * Printed even at zero, because zero is the answer a reader wants on a
	 * clean tree: it says the rules that can turn the emulator on did not.
	 */
	printf("heur emu   %llu object(s) interpreted at a rule's request\n",
	       (unsigned long long)st->heur_emu);
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
		"  --heur N        1 (default) scores what the format parse found\n"
		"                  wrong with the object and what the unpackers made\n"
		"                  of it; 0 gathers and scores nothing. Neither costs\n"
		"                  an extra pass. 2 additionally RUNS an object that\n"
		"                  no unpacker could open and that looks packed or\n"
		"                  damaged, and scans what it writes - which is the\n"
		"                  one level here that costs real time. It reports a\n"
		"                  level of its own and never a family\n"
		"  --dump DIR      write every object the engine PRODUCED into DIR:\n"
		"                  what came out of an unpacker, not what went in\n"
		"  --jobs N        scan on N threads (default 1). The objects come\n"
	    "                  back in whatever order the workers finish them,\n"
	    "                  which is the one thing this changes besides speed\n"
		"  --stats         report what the prefilter and the presence set earned\n"
		"  --emu MODE      overrides what --heur chose: never interprets\n"
	    "                  nothing, auto is what --heur 2 turns on, only\n"
	    "                  interprets instead of the packer modules, ungated\n"
	    "  --max-produced N  bytes an object may yield before the scan gives up\n"
		"  --max-resident N  bytes of produced data that may be alive at once\n"
		"  --max-object N    bytes any one produced object may reach\n"
		"  -v              also report objects that came back clean\n"
		"\n"
		"exit: 0 nothing found, 1 something found, 2 could not scan\n",
		argv0);
}

/*
 * --heur, which is on or off and used to be a ladder.
 *
 * The second rung was marker evidence and was never built: nothing gathered
 * those facts, so asking for it changed no verdict and cost nothing, which is
 * the worst kind of option - one that answers yes and does nothing. The engine
 * still keeps "should this run" as its own field rather than as the zero of a
 * number, because a zeroed kof_scan_option has to mean the heuristic RUNS.
 *
 * Written as a number rather than as --no-heur so that the command lines and
 * scripts that already say --heur 0 or --heur 1 keep working.
 */
static int heur_arg(const char *v, struct kof_scan_option *opt)
{
	char *end;
	unsigned long n;

	if (!*v)
		return 0;
	n = strtoul(v, &end, 10);
	if (*end)
		return 0;               /* trailing junk: not a level */
	/*
	 * A LADDER OF TWO DECISIONS, not one setting with three values.
	 *
	 * 0 and 1 are the old pair: gather and score what the parse and the
	 * unpackers already produced, or do not. 2 adds the one thing that is
	 * not free - running an object no unpacker could open. It belongs on
	 * this flag rather than on its own because it is the same question
	 * asked harder: how much is this scan willing to spend to say something
	 * about a file nothing recognised.
	 */
	switch (n) {
	case 0: opt->heur_off = 1; opt->emu_use = KOF_EMU_NEVER; return 1;
	case 1: opt->heur_off = 0; opt->emu_use = KOF_EMU_NEVER; return 1;
	case 2: opt->heur_off = 0; opt->emu_use = KOF_EMU_AUTO;  return 1;
	default: return 0;
	}
}

/* Refused rather than clamped. A level this build does not have is a request
 * that was not carried out, and a scan that quietly did less than it was told
 * to is the one result worth never producing. */
static int heur_bad(const char *argv0, const char *v)
{
	fprintf(stderr, "%s: --heur takes 0, 1 or 2, not '%s'\n", argv0, v);
	return 2;
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
	/*
	 * What --emu asked for, held back until every argument has been read.
	 *
	 * --heur sets emu_use too, because the level is what turns interpreting
	 * on. Applying either one where it is parsed makes the pair
	 * order-dependent: `--emu only --heur 2` and `--heur 2 --emu only` are
	 * the same request and used to mean different things, the first one
	 * silently downgraded to auto. --emu is documented as the override, so
	 * it is applied last rather than in place.
	 */
	int emu_want = -1;
	/*
	 * How many scanners the walk runs on. One by default and not the core
	 * count, because more than one changes something a caller can see: the
	 * ORDER objects are reported in. A scan that prints its findings as it
	 * goes is read by a person, and the same directory scanned twice should
	 * read the same way both times. Speed is asked for, not assumed.
	 */
	unsigned jobs = 1;
	kof_scanner **scs = NULL;
	unsigned made = 0;

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
		/*
		 * One number, because the three settings are a ladder and an
		 * operator picking a rung should not have to work out which of
		 * two switches to reach for. It is 1 unless said otherwise - the
		 * facts level 1 scores are produced by the parse and the
		 * unpackers whether anybody asks or not, so refusing to score
		 * them saved nothing.
		 *
		 * Both spellings, because the rest of this parser takes its
		 * values as a separate word and the request that produced this
		 * wrote --heur=N. Neither is worth being wrong about at a
		 * prompt.
		 */
		else if (strncmp(argv[i], "--heur=", 7) == 0) {
			if (!heur_arg(argv[i] + 7, &opt))
				return heur_bad(argv[0], argv[i] + 7);
		} else if (strcmp(argv[i], "--heur") == 0 && i + 1 < argc) {
			if (!heur_arg(argv[++i], &opt))
				return heur_bad(argv[0], argv[i]);
		}
		else if (strcmp(argv[i], "--emu") == 0 && i + 1 < argc) {
			const char *w = argv[++i];

			/* Words rather than numbers: "--emu 2" says nothing
			 * about what it does, and the three settings are not
			 * points on a scale - "only" is not more of "auto". */
			if (strcmp(w, "auto") == 0)
				emu_want = KOF_EMU_AUTO;
			else if (strcmp(w, "never") == 0)
				emu_want = KOF_EMU_NEVER;
			else if (strcmp(w, "only") == 0)
				emu_want = KOF_EMU_ONLY;
			else {
				fprintf(stderr, "%s: --emu takes auto, never "
					"or only, not '%s'\n", argv[0], w);
				return 2;
			}
		}
		else if (strcmp(argv[i], "--max-produced") == 0 && i + 1 < argc)
			opt.max_produced_bytes = strtoull(argv[++i], NULL, 10);
		/* The memory ceiling, exposed because it is the limit that decides
		 * how much of a container is examined and because a decoder that
		 * cannot stream is sized from what is left under it - neither is
		 * reachable from outside without being able to set it. */
		else if (strcmp(argv[i], "--max-resident") == 0 && i + 1 < argc)
			opt.max_resident_bytes = strtoull(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--max-object") == 0 && i + 1 < argc)
			opt.max_object_bytes = strtoull(argv[++i], NULL, 10);
		else if (strcmp(argv[i], "--dump") == 0 && i + 1 < argc)
			r.dump_dir = argv[++i];
		else if (strcmp(argv[i], "--jobs") == 0 && i + 1 < argc) {
			unsigned long v = strtoul(argv[++i], NULL, 10);

			/* Refused rather than clamped, for the reason --heur
			 * gives: a scan that quietly did something other than
			 * what it was told to is the one result worth never
			 * producing. */
			if (v < 1 || v > 256) {
				fprintf(stderr, "%s: --jobs takes 1 to 256, "
					"not '%s'\n", argv[0], argv[i]);
				return 2;
			}
			jobs = (unsigned)v;
		}
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
	if (emu_want >= 0) {
		opt.emu_use = (enum kof_emu_use)emu_want;
		/*
		 * SAID EXPLICITLY, so a heuristic rule may not ask past it.
		 *
		 * --heur 1 also leaves emu_use at NEVER, and there it means
		 * "not on by default" - which is exactly the case a rule's ask
		 * is meant to turn into emulation. Only a --emu never typed on
		 * the command line means never.
		 */
		if (emu_want == KOF_EMU_NEVER)
			opt.emu_forbidden = 1;
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
	printf("database: version %u, %u record(s), %u unpacker(s), "
	       "%u heur rule(s)\n",
	       kof_engine_db_version(eng), kof_engine_records(eng),
	       kof_engine_unpackers(eng), kof_engine_heur_rules(eng));

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
	/*
	 * The extra scanners, and the budgets divided among them.
	 *
	 * max_resident_bytes is a per-scanner ceiling, so N workers left at the
	 * default would be allowed N times the memory one was - which is not
	 * what "the same scan, faster" should mean. Dividing it keeps the whole
	 * run inside the bound the caller asked for. The other two ceilings are
	 * per object and per tree and need no division.
	 */
	if (jobs > 1) {
		unsigned k;

		if (opt.max_resident_bytes)
			opt.max_resident_bytes /= jobs;
		scs = calloc(jobs, sizeof *scs);
		if (scs) {
			scs[0] = sc;
			for (k = 1; k < jobs; k++) {
				scs[k] = kof_scanner_new(eng);
				if (!scs[k])
					break;
			}
			made = k;
		}
		if (!scs || made < 2) {
			/* Fewer scanners than asked for is a scan that did not
			 * do what it was told; say so rather than run slower
			 * and let the number be a mystery. */
			fprintf(stderr, "%s: could not create %u scanners\n",
				argv[0], jobs);
			jobs = made > 1 ? made : 1;
		} else {
			jobs = made;
		}
	}

	/*
	 * Progress is on when stderr is a terminal and off otherwise, with no
	 * flag to set. A person watching a scan wants it; a pipe, a log or a
	 * script must get the bytes it always got, and isatty is the question
	 * that separates those two without anybody having to answer it.
	 */
	r.progress = isatty(2) ? 1 : 0;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (jobs > 1)
		rc = kof_scan_path_mt(scs, jobs, target, &opt, on_object, &r);
	else
		rc = kof_scan_path(sc, target, &opt, on_object, &r);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	progress_clear(&r);
	if (rc < 0)
		fprintf(stderr, "%s: cannot scan %s\n", argv[0], target);

	secs = (double)(t1.tv_sec - t0.tv_sec) +
	       (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	if (r.manifest)
		fclose(r.manifest);
	/*
	 * The totals, summed over every scanner that ran.
	 *
	 * Reading one scanner's stats after a parallel walk would report a
	 * fraction of the scan as the whole of it, and the fraction is whatever
	 * share of the files that worker happened to take - a number that
	 * changes run to run. Summed here rather than in the engine because the
	 * engine never owned the array.
	 */
	{
		static struct kof_stats sum;
		const struct kof_stats *one;
		unsigned k;

		if (jobs > 1 && scs) {
			for (k = 0; k < jobs; k++) {
				one = scs[k] ? kof_scanner_stats(scs[k]) : NULL;
				if (!one)
					continue;
				sum.objects        += one->objects;
				sum.object_bytes   += one->object_bytes;
				sum.unreadable     += one->unreadable;
				sum.considered     += one->considered;
				sum.ran            += one->ran;
				sum.by_target      += one->by_target;
				sum.by_size        += one->by_size;
				sum.by_arch        += one->by_arch;
				sum.by_subtype     += one->by_subtype;
				sum.by_region      += one->by_region;
				sum.gram_bytes     += one->gram_bytes;
				sum.gram_answers   += one->gram_answers;
				sum.searches       += one->searches;
				sum.heur_emu       += one->heur_emu;
				sum.bytes_searched += one->bytes_searched;
				if (one->peak_resident > sum.peak_resident)
					sum.peak_resident = one->peak_resident;
			}
			st = &sum;
		} else {
			st = kof_scanner_stats(sc);
		}
	}
	mb = st ? (double)st->object_bytes / 1048576.0 : 0.0;

	printf("\n--- scan complete ---\n");
	printf("scanned   %llu object(s), %.2f MB\n",
	       st ? (unsigned long long)st->objects : 0ull, mb);
	printf("infected  %llu object(s)\n", (unsigned long long)r.infected);
	printf("suspected %llu object(s)\n", (unsigned long long)r.suspect);
	/*
	 * Its own line, and printed even at zero when the heuristic ran.
	 *
	 * A number that appears only when it is non-zero cannot be read as "the
	 * heuristic found nothing" - it reads as "the heuristic was off", and the
	 * two are the difference between a quiet scan and a scan that did not
	 * look.
	 */
	/*
	 * "broken structure", not "by structure, no family named".
	 *
	 * The old wording said what the line was NOT - it named no family -
	 * which reads as an apology for a weaker verdict. What the number
	 * actually counts is objects whose STRUCTURE scored past the bar:
	 * truncated, stripped, segments that overlap, an entry point that is
	 * not executable. There is no vector here for which family an object
	 * belongs to and there never was, so the line now says the thing it can
	 * support rather than the thing it cannot.
	 */
	if (!opt.heur_off)
		printf("heuristic %llu object(s) with broken structure\n",
		       (unsigned long long)r.heur);
	/*
	 * Broken objects, split by reason. The three call for different actions -
	 * raise a limit, report a gap in this build, or accept that the file is
	 * damaged - so one total would say the least useful thing the numbers can
	 * say.
	 */
	if (r.incomplete) {
		uint32_t k;

		printf("broken    %llu object(s) the engine could not finish\n",
		       (unsigned long long)r.incomplete);
		for (k = 1; k < KOF_BROKEN_COUNT; k++)
			if (r.by_reason[k])
				printf("            %-28s %llu\n",
				       kof_broken_name(k),
				       (unsigned long long)r.by_reason[k]);
	}
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

	if (scs) {
		unsigned k;

		/* scs[0] is sc, freed below like it always was. */
		for (k = 1; k < made; k++)
			kof_scanner_free(scs[k]);
		free(scs);
	}
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