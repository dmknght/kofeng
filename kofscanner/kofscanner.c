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

/*
 * Before any include, not after: a feature test macro placed after the first
 * system header has no effect at all.
 *
 * _GNU_SOURCE and not _POSIX_C_SOURCE, because this file includes
 * kofplatform.h and that header calls memmem and realpath - neither of which
 * POSIX 2008 declares on glibc. The header says so where it defines the
 * wrapper, and deliberately does not define the macro itself: a feature test
 * macro belongs to the translation unit, not to a header included partway
 * through one. This is that translation unit saying it.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "kofscanner_int.h"

/*
 * ONE LINE A FLAG.
 *
 * This was ninety-eight lines: every flag carried the argument for its own
 * default - why the cache outlives the run, what a cached file's identity is
 * made of and when that is sound, what level 2 of --scan-procs compares and
 * why nothing else can see it. All of it true and none of it what a reader
 * reaching for --help wants, which is the name of the flag that does the thing
 * they are trying to do.
 *
 * The reasoning is not lost and was never only here: every one of those
 * paragraphs is a comment beside the code it is about, where somebody changing
 * the behaviour will read it. A terminal is the wrong place to keep it, and a
 * usage block nobody finishes reading is a usage block nobody reads.
 */
static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s --db <dir-or-blob> --scan-files <path> [options]\n"
		"       %s --db <dir-or-blob> --scan-procs [options]\n"
		"\n"
		"  --db D            module database: a directory or one blob\n"
		"  --scan-files P    a file, or a directory scanned recursively\n"
		"  --scan-procs      scan what is RUNNING, not what is on disk\n"
		"  --pid N           only this process; repeatable, up to 64\n"
		"\n"
		"  --heur N          0 gather nothing  1 score and descend (default)\n"
		"                    2 also interpret what no unpacker opened\n"
		"  --emu MODE        never | auto | only; overrides what --heur chose\n"
		"  --all-matches     keep scanning an object after the first finding\n"
		"  --max-depth N     directory depth limit\n"
		"  --object-depth N  how deep to descend INSIDE a file\n"
		"  --follow-links    follow symbolic links (off by default)\n"
		"\n"
		"  --cache-file F    keep the verdict cache in F\n"
		"  --no-cache        trust nothing carried between runs\n"
		"  --jobs N          scan on N threads (default 1; disables caching)\n"
		"  --max-produced N  bytes an object may yield before giving up\n"
		"  --max-resident N  bytes of produced data alive at once, for the whole run\n"
		"                    (shared among --jobs threads, 32 MiB at least each)\n"
		"  --scratch-dir D   where an object too big for memory is spilled (default: the\n"
		"                    platform's temp directory; a RAM one is not used)\n"
		"  --max-object N    bytes any one produced object may reach\n"
		"\n"
		"  --stats           report what the prefilter earned\n"
		"  -v                also report objects that came back clean\n"
		"\n"
		"An infected file is repaired where a rule knows how; there is no\n"
		"flag for it and no backup is taken.\n"
		"\n"
		"exit: 0 nothing found, 1 something found, 2 could not scan\n",
		argv0, argv0);
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
 * scripts that already ksn_say --heur 0 or --heur 1 keep working.
 */
/*
 * A NUMBER, OR THE RUN DOES NOT START.
 *
 * `strtoul` answers 0 for a string it could not read at all, and every limit
 * this tool takes reads 0 as "no limit" or "the default" - so a mistyped
 * `--max-depth 1O` (letter O) does not narrow the scan, it REMOVES the bound
 * the operator just asked for, and nothing is printed. The mistake is
 * invisible at the one moment it matters.
 *
 * `--heur` and `--jobs` already refuse rather than clamp, for the reason
 * written beside them. This is the same rule for the rest of them, in one
 * place: the whole argument must be digits, it must be inside the range, and
 * anything else stops the run.
 */
static int num_arg(const char *argv0, const char *opt, const char *v,
		   unsigned long long lo, unsigned long long hi,
		   unsigned long long *out)
{
	char *end;
	unsigned long long n;

	if (!v || !*v) {
		fprintf(stderr, "%s: %s needs a number\n", argv0, opt);
		return 0;
	}
	errno = 0;
	n = strtoull(v, &end, 10);
	if (*end || errno == ERANGE || n < lo || n > hi) {
		fprintf(stderr, "%s: %s takes %llu to %llu, not '%s'\n",
			argv0, opt, lo, hi, v);
		return 0;
	}
	*out = n;
	return 1;
}

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
	 * asked harder: how much is this scan willing to spend to ksn_say something
	 * about a file nothing recognised.
	 */
	switch (n) {
	case 0: opt->heur_off = 1; opt->heur_level = 0;
		opt->emu_use = KOF_EMU_NEVER; return 1;
	case 1: opt->heur_off = 0; opt->heur_level = 1;
		opt->emu_use = KOF_EMU_NEVER; return 1;
	case 2: opt->heur_off = 0; opt->heur_level = 2;
		opt->emu_use = KOF_EMU_AUTO;  return 1;
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



/*
 * EVERYTHING ONE RUN OF THE TOOL IS MADE OF, which main used to hold as forty locals.
 * Filled by cli_parse, used by the steps that follow it in main, in order: open the
 * database, make the scanners, scan, total the stats, report, close, exit.
 */
struct cli {
	const char *argv0;
	const char *db, *target;
	struct kof_scan_option opt;
	struct run  r;
	/*
	 * How many scanners the walk runs on. One by default and not the core
	 * count, because more than one changes something a caller can see: the
	 * ORDER objects are reported in. A scan that prints its findings as it
	 * goes is read by a person, and the same directory scanned twice should
	 * read the same way both times. Speed is asked for, not assumed.
	 */
	unsigned    jobs;
	int         want_procs;
	/*
	 * WHERE THE VERDICT CACHE IS KEPT BETWEEN RUNS.
	 *
	 * On by default at a per-user path - see koffridge_default_path, which
	 * is also where the reason the DEFAULT is safe is written down. It used
	 * to be off unless a path was given, and that made a five-fold
	 * difference in sweep time depend on somebody knowing to ask.
	 *
	 * --cache-file overrides the path; --no-cache turns it off, for a run
	 * that must answer from nothing but this database and these bytes.
	 *
	 * CACHING ITSELF IS NOT OPTIONAL AND HAS NO FLAG. A process sweep
	 * meets the same file many times - measured, 5795 mappings behind 335
	 * distinct files, with libc mapped a hundred times - so scanning each
	 * mapping would scan libc a hundred times for one answer. The
	 * in-memory cache is what makes the sweep finish and it is always on.
	 *
	 * This names a FILE to carry that across runs, and it is off by
	 * default for a reason that is about trust rather than speed: whoever
	 * can write the file decides what this scanner calls clean, and a
	 * served hit looks exactly like a file that was examined. The operator
	 * says where it lives, which is the moment they decide who can write
	 * it. See koffridge.h.
	 */
	const char *cache_path;
	char        cache_buf[1024];
	int         no_cache;
	uint32_t    pids[64];
	uint32_t    n_pids;
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
	int         emu_want;

	kof_engine   *eng;
	kof_scanner  *sc;
	kof_scanner **scs;
	unsigned      made;

	int           rc;                /* the scan's own answer: 0, or a KOF_ERR_* */
	double        secs, mb;
	struct kof_stats        sum;     /* the totals over every scanner of a parallel walk */
	const struct kof_stats *st;
	uint64_t      unreadable;
	/* The file-level tallies, computed from the per-file map for the summary and read
	 * again by the exit code after the map is gone. */
	uint64_t      inf_f, sus_f, broken_objs;
	struct timespec t0, t1;
};

/*
 * THE ARGUMENTS: the policy of the scan, the target, and what to print. Returns -1 to
 * go on, else the exit code - 0 for --help, 2 for anything that cannot run.
 */
static int cli_parse(struct cli *c, int argc, char **argv)
{
	int i;

	/* Where the engine sends a verdict - see kof_on_event_detected. This tool
	 * registers it and prints; it decides nothing. */
	c->opt.on_event_detected = ksn_on_event_detected;
	c->opt.event_user        = &c->r;
	/* Set once, for every scan this run makes - the file sweep and the
	 * process sweep both. See ksn_scan_should_stop. */
	c->opt.should_stop = ksn_scan_should_stop;
	/* Scanning a named directory means scanning what is in it. The engine defaults
	 * to not recursing so that a caller who says nothing gets less rather than a
	 * surprise; a scanner is the caller that does want it. */
	c->opt.recurse_dirs = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
			c->db = argv[++i];
		else if (strcmp(argv[i], "--scan-files") == 0 && i + 1 < argc)
			c->target = argv[++i];
		else if (strcmp(argv[i], "--max-depth") == 0 && i + 1 < argc) {
			unsigned long long v;

			if (!num_arg(argv[0], "--max-depth", argv[++i],
				     1, 0xffffffffull, &v))
				return 2;
			c->opt.max_depth = (uint32_t)v;
		}
		else if (strcmp(argv[i], "--object-depth") == 0 && i + 1 < argc) {
			unsigned long long v;

			if (!num_arg(argv[0], "--object-depth", argv[++i],
				     1, 0xffffffffull, &v))
				return 2;
			c->opt.max_object_depth = (uint32_t)v;
		}
		else if (strcmp(argv[i], "--follow-links") == 0)
			c->opt.follow_symlinks = 1;
		else if (strcmp(argv[i], "--all-matches") == 0)
			c->opt.all_matches = 1;

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
			if (!heur_arg(argv[i] + 7, &c->opt))
				return heur_bad(argv[0], argv[i] + 7);
		} else if (strcmp(argv[i], "--heur") == 0 && i + 1 < argc) {
			if (!heur_arg(argv[++i], &c->opt))
				return heur_bad(argv[0], argv[i]);
		}
		else if (strcmp(argv[i], "--emu") == 0 && i + 1 < argc) {
			const char *w = argv[++i];

			/* Words rather than numbers: "--emu 2" says nothing
			 * about what it does, and the three settings are not
			 * points on a scale - "only" is not more of "auto". */
			if (strcmp(w, "auto") == 0)
				c->emu_want = KOF_EMU_AUTO;
			else if (strcmp(w, "never") == 0)
				c->emu_want = KOF_EMU_NEVER;
			else if (strcmp(w, "only") == 0)
				c->emu_want = KOF_EMU_ONLY;
			else {
				fprintf(stderr, "%s: --emu takes auto, never "
					"or only, not '%s'\n", argv[0], w);
				return 2;
			}
		}
		else if (strcmp(argv[i], "--max-produced") == 0 && i + 1 < argc) {
			unsigned long long v;

			if (!num_arg(argv[0], "--max-produced", argv[++i],
				     1, ~0ull, &v))
				return 2;
			c->opt.max_produced_bytes = v;
		}
		/* The memory ceiling, exposed because it is the limit that decides
		 * how much of a container is examined and because a decoder that
		 * cannot stream is sized from what is left under it - neither is
		 * reachable from outside without being able to set it. */
		else if (strcmp(argv[i], "--scratch-dir") == 0 && i + 1 < argc) {
			c->opt.scratch_dir = argv[++i];
		}
		else if (strcmp(argv[i], "--max-resident") == 0 && i + 1 < argc) {
			unsigned long long v;

			if (!num_arg(argv[0], "--max-resident", argv[++i],
				     1, ~0ull, &v))
				return 2;
			c->opt.max_resident_bytes = v;
		}
		else if (strcmp(argv[i], "--max-object") == 0 && i + 1 < argc) {
			unsigned long long v;

			if (!num_arg(argv[0], "--max-object", argv[++i],
				     1, ~0ull, &v))
				return 2;
			c->opt.max_object_bytes = v;
		}
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
			c->jobs = (unsigned)v;
		}
		else if (strcmp(argv[i], "--scan-procs") == 0)
			c->want_procs = 1;

		else if (strcmp(argv[i], "--cache-file") == 0 && i + 1 < argc)
			c->cache_path = argv[++i];
		else if (strcmp(argv[i], "--no-cache") == 0)
			c->no_cache = 1;
		/*
		 * ONE PROCESS, OR A FEW. Naming them is not a filter over the
		 * whole table - the walk opens only what was named, which is
		 * the whole point when something else has already decided a
		 * process is interesting. See kof_walk_option.
		 */
		else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
			unsigned long long v;

			/*
			 * REFUSED, NOT DROPPED. The 65th --pid used to be
			 * consumed and thrown away: a caller that named a
			 * process got a run which never opened it and said
			 * nothing, which is the failure this tool counts
			 * `cached` and `unreadable` to avoid everywhere else.
			 */
			if (c->n_pids >= (uint32_t)(sizeof c->pids / sizeof c->pids[0])) {
				fprintf(stderr, "%s: --pid may be given at "
					"most %u times\n", argv[0],
					(unsigned)(sizeof c->pids / sizeof c->pids[0]));
				return 2;
			}
			if (!num_arg(argv[0], "--pid", argv[++i],
				     1, 0xffffffffull, &v))
				return 2;
			c->pids[c->n_pids++] = (uint32_t)v;
			c->want_procs = 1;
		}
		else if (strcmp(argv[i], "--stats") == 0)
			c->r.stats = 1;
		else if (strcmp(argv[i], "-v") == 0)
			c->r.verbose = 1;
		/* Asked for by name rather than reached by getting something
		 * wrong: --help printed "unrecognised argument" first, which
		 * is the tool telling a reader they made a mistake for using
		 * the flag every other tool has. */
		else if (strcmp(argv[i], "--help") == 0 ||
			 strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		}
		else {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		}
	}
	if (c->emu_want >= 0) {
		c->opt.emu_use = (enum kof_emu_use)c->emu_want;
		/*
		 * SAID EXPLICITLY, so a heuristic rule may not ask past it.
		 *
		 * --heur 1 also leaves emu_use at NEVER, and there it means
		 * "not on by default" - which is exactly the case a rule's ask
		 * is meant to turn into emulation. Only a --emu never typed on
		 * the command line means never.
		 */
		if (c->emu_want == KOF_EMU_NEVER)
			c->opt.emu_forbidden = 1;
	}

	/* --scan-procs names its own target: what is running. */
	if (!c->db || (!c->target && !c->want_procs)) {
		usage(argv[0]);
		return 2;
	}
	return -1;
}

/* The database, and what a reader should know about it before anything is reported.
 * Returns -1 to go on, else the exit code. */
static int cli_open(struct cli *c)
{
	KOF_TIME_BEGIN(KOF_T_DB_LOAD);
	c->eng = keng_open(c->db);
	KOF_TIME_END(KOF_T_DB_LOAD);
	if (!c->eng) {
		fprintf(stderr, "%s: cannot load a database from %s\n", c->argv0, c->db);
		return 2;
	}
	{
		/*
		 * The OLDEST pack's version, which is what the engine reports:
		 * a database directory is only as fresh as its stalest file.
		 */
		struct kof_db_version dv;

		uint64_t mmb = 0;
		uint32_t mmc = 0;

		kdb_version(c->eng, &dv);
		printf("database: format %u.%u build %u, %u record(s), "
		       "%u unpacker(s), %u heur rule(s)\n",
		       (unsigned)dv.major, (unsigned)dv.minor, dv.build,
		       kdb_records(c->eng), kdb_unpackers(c->eng),
		       kmatch_rules(c->eng));
		/* The matcher's footprint is a design claim - bucket counts are
		 * derived from the marker count and bounded - so it is printed
		 * where a reader will see it rather than left to be inferred. */
		if (kmatch_tables(c->eng, &mmb, &mmc) == 0 && mmb)
			printf("          multi-pattern tables %.2f MB, "
			       "worst bucket %u marker(s)\n",
			       (double)mmb / 1048576.0, mmc);
		/* A database that did not load whole says so, where a reader of the
		 * scan will see it: a diagnose that is absent reads, from every rule
		 * naming it, as an object that does not do the thing. Silent at zero. */
		if (kdb_diag_refused(c->eng) || kdb_diag_packs_refused(c->eng) ||
		    kdb_diag_full(c->eng) || kdb_diag_collisions(c->eng))
			fprintf(stderr, "%s: warning: the database did not load whole: "
				"%u diagnose(s) refused, %u file(s) refused, %u collision(s)%s\n",
				c->argv0, kdb_diag_refused(c->eng),
				kdb_diag_packs_refused(c->eng), kdb_diag_collisions(c->eng),
				kdb_diag_full(c->eng) ? ", the diagnose table is full" : "");
	}
	return -1;
}

/* The scanner, and the extra ones a parallel walk asks for with the budgets divided
 * among them. Returns -1 to go on, else the exit code. */
static int cli_scanners(struct cli *c)
{
	int why = KSCAN_NEW_OK;

	/*
	 * -v reports each file as it finishes, and that is only sound on one
	 * thread - see run.cur_file.
	 */
	c->r.stream_v = (c->jobs == 1);

	c->sc = kscan_new_ex(c->eng, &why);
	c->r.files = kverdict_filemap_new();
	if (!c->sc || !c->r.files) {
		fprintf(stderr, "%s: out of memory%s%s\n", c->argv0,
			c->sc ? "" : ": ", c->sc ? "" : kscan_new_why_str(why));
		kverdict_filemap_free(c->r.files);
		kscan_free(c->sc);
		keng_close(c->eng);
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
	if (c->jobs > 1) {
		unsigned k;
		c->scs = calloc(c->jobs, sizeof *c->scs);
		if (c->scs) {
			c->scs[0] = c->sc;
			for (k = 1; k < c->jobs; k++) {
				c->scs[k] = kscan_new_ex(c->eng, &why);
				if (!c->scs[k])
					break;
			}
			c->made = k;
		}
		if (!c->scs || c->made < 2) {
			/* Fewer scanners than asked for is a scan that did not
			 * do what it was told; ksn_say so rather than run slower
			 * and let the number be a mystery. */
			fprintf(stderr, "%s: could not create %u scanners%s%s\n",
				c->argv0, c->jobs, c->made < c->jobs && why ? ": " : "",
				c->made < c->jobs && why ? kscan_new_why_str(why) : "");
			c->jobs = c->made > 1 ? c->made : 1;
		} else {
			c->jobs = c->made;
		}
		/*
		 * THE RESIDENT ALLOWANCE IS SHARED OUT BY THE ENGINE (kscan_path_mt divides
		 * it among the scanners that are running, floored at KOF_SHARE_MIN - see
		 * kof_scan_option.resident_per_scanner), over the threads there ARE and not
		 * the ones that were asked for. The tool used to divide an explicit
		 * --max-resident itself and left the built-in default undivided.
		 */
	}
	return -1;
}

/*
 * THE FILE SWEEP, with the between-run cache when it applies. Sets c->rc.
 */
static void scan_files(struct cli *c)
{
	/*
	 * THE SAME CACHE THE PROCESS SWEEP HAS, on the path that meets
	 * far more files.
	 *
	 * It was only ever wired into --scan-procs, and the help text
	 * describes it as a property of the scanner - so a directory
	 * sweep re-read the whole database against every unchanged file
	 * on every run, while the help said it would not.
	 *
	 * ONE JOB ONLY, FOR NOW. The set is not written for concurrent
	 * add, and a cache that loses entries under --jobs would be a
	 * cache that is slower the more workers it is given - the exact
	 * opposite of what asking for workers means. Making it
	 * thread-safe is a measurement, not a guess: it needs to be
	 * shown that the contention costs less than the sweep it saves.
	 */
	struct kof_fidset *fs = NULL;
	/* Outlives the scan below, because opt.cache_user points at it. */
	struct cache_hook hook = { NULL, NULL };
	/*
	 * AND IT SAYS SO, because the alternative is a silent one.
	 *
	 * --jobs turns the persistent cache off for the reason above,
	 * and without a word a reader sees a second run take as long
	 * as the first and has nothing to connect it to. The sweep
	 * already prints exactly this sentence when --jobs meets
	 * --scan-procs; a flag that quietly disables another flag is
	 * the kind of thing this cache has been burned by before.
	 */
	if (!c->no_cache && c->jobs > 1)
		fprintf(stderr, "%s: --jobs turns the between-run "
			"cache off; it is not written for concurrent "
			"add\n", c->argv0);
	if (c->jobs <= 1) {
		if (!c->cache_path &&
		    koffridge_default_path(c->cache_buf, sizeof c->cache_buf))
			c->cache_path = c->cache_buf;
		if (c->cache_path) {
			/* The DATABASE, not the date on it - see
			 * kdb_stamp for what a build number
			 * failed to notice. */
			fs = kof_fidset_open(kdb_stamp(c->eng),
					       ksn_engine_stamp());
			if (fs) {
				struct kof_fidset_stat fst;
				char when[64];

				(void)kof_fidset_load(fs, c->cache_path);
				/*
				 * SAID ON THE WAY IN, because a sweep
				 * that reuses answers should ksn_say whose
				 * and how old before it reports
				 * anything. An empty set says nothing:
				 * a first run has no news.
				 */
				kof_fidset_stats(fs, &fst);
				if (fst.mapped) {
					ksn_cache_age(fst.made, when,
						  sizeof when);
					fprintf(stderr,
						"cache: %llu entr%s "
						"loaded%s\n",
						(unsigned long long)
						fst.mapped,
						fst.mapped == 1u
						? "y" : "ies", when);
				}
				/*
				 * --no-cache takes the two that
				 * BELIEVE the set and leaves the one
				 * that corrects it - see ksn_fid_drop.
				 */
				if (!c->no_cache) {
					c->opt.cache_seen = ksn_fid_seen;
					c->opt.cache_keep = ksn_fid_keep;
				}
				c->opt.cache_drop = ksn_fid_drop;
				hook.fs = fs;
				hook.r  = &c->r;
				c->opt.cache_user = &hook;
			}
		}
	}
	if (c->jobs > 1)
		c->rc = kscan_path_mt(c->scs, c->jobs, c->target, &c->opt,
				      ksn_on_object, &c->r);
	else
		c->rc = kscan_path(c->sc, c->target, &c->opt, ksn_on_object, &c->r);
	if (fs) {
		struct kof_fidset_stat fst;

		kof_fidset_stats(fs, &fst);
		/* A run that was told to trust nothing writes the set
		 * back only when it has something to TAKE OUT of it. */
		if ((!c->no_cache || fst.dropped) &&
		    !kof_fidset_save(fs, c->cache_path))
			fprintf(stderr,
				"cache: could not be written to %s\n",
				c->cache_path);
		if (fst.dropped)
			fprintf(stderr, "cache: %llu entr%s dropped - "
				"found something in a file the cache "
				"called clean\n",
				(unsigned long long)fst.dropped,
				fst.dropped == 1u ? "y" : "ies");
		/* Before the free, and for the same reason ksn_scan_procs
		 * does it: `opt` lives past this block. */
		c->opt.cache_seen = NULL;
		c->opt.cache_keep = NULL;
		c->opt.cache_drop = NULL;
		c->opt.cache_user = NULL;
		kof_fidset_close(fs);
	}
}

/* The scan itself, in wall clock: what is running, or what is on the disk. */
static void cli_scan(struct cli *c)
{
	/*
	 * Progress is on when stderr is a terminal and off otherwise, with no
	 * flag to set. A person watching a scan wants it; a pipe, a log or a
	 * script must get the bytes it always got, and isatty is the question
	 * that separates those two without anybody having to answer it.
	 */
	c->r.progress = isatty(2) ? 1 : 0;
	/*
	 * INSTALLED BEFORE ANY WORK, and deliberately not with sigaction's
	 * SA_RESTART left to chance: the handler sets a flag and returns, and
	 * whether a read is restarted or fails with EINTR is not this tool's
	 * business - the walk finds out through the callback on the next
	 * object either way.
	 */
	signal(SIGINT, ksn_on_interrupt);
#ifdef SIGTERM
	/* A sweep is the kind of thing a service manager stops. Same answer:
	 * report what was scanned rather than vanish. */
	signal(SIGTERM, ksn_on_interrupt);
#endif
	/* Colour follows the same rule, asked of stdout because that is where the
	 * findings go: a redirect or a pipe gets plain text, a terminal gets the
	 * highlight. */
	c->r.color = isatty(1) ? 1 : 0;
	c->r.eng = c->eng;
	clock_gettime(CLOCK_MONOTONIC, &c->t0);
	/*
	 * WHAT IS RUNNING, rather than what is on the disk. A different
	 * source of bytes and the same scan - see ksn_scan_procs.
	 */
	if (c->want_procs) {
		struct kof_db_version dv;

		memset(&dv, 0, sizeof dv);
		(void)kdb_version(c->eng, &dv);
		/* The cache is only true of one database - see koffridge.h. */
		/*
		 * THE COMPARISON IS WHAT --heur 2 MEANS HERE.
		 *
		 * Level 2 is already the rung that says "do the expensive thing
		 * that finds what the cheap things cannot" - it is where the
		 * interpreter runs. Comparing a written-to module against its
		 * file is exactly that shape: it is the only way to see an
		 * inline hook, and it costs reads no sweep should pay by
		 * default. A separate flag would have been a second dial
		 * meaning the same thing.
		 */
		/*
		 * --jobs DOES NOTHING HERE, AND SAYS SO.
		 *
		 * The process walk is sequential: one collector handle, one
		 * fridge, one address space open at a time. A flag that is
		 * accepted and ignored is worse than one that is refused -
		 * somebody sets it, measures no change, and concludes the
		 * machine is the limit. Measured, the thing it WOULD help is
		 * real: of a 5.2s sweep, 4.2s is scanning the distinct module
		 * files, and those are independent of each other.
		 */
		if (c->jobs > 1)
			fprintf(stderr, "%s: --jobs is ignored with "
				"--scan-procs; the process walk is "
				"sequential\n", c->argv0);
		/*
		 * The default path is worked out here rather than inside
		 * ksn_scan_procs, so that "no cache" and "a cache nobody could
		 * find a home for" are one state at the call rather than two
		 * behaviours inside it.
		 */
		if (!c->cache_path &&
		    koffridge_default_path(c->cache_buf, sizeof c->cache_buf))
			c->cache_path = c->cache_buf;

		/* --no-cache does not mean "there is no cache file": it means
		 * this run answers from these bytes alone. The set is still
		 * where it was, and a finding here has to reach it. */
		{
			const struct ksn_procs_req rq = {
				.r = &c->r, .sc = c->sc, .opt = &c->opt,
				.cache = { kdb_stamp(c->eng), c->cache_path, !c->no_cache },
				.pick = { c->pids, c->n_pids,
					  !c->opt.heur_off && c->opt.heur_level >= 2 },
			};

			c->rc = ksn_scan_procs(&rq);
		}
	} else {
		scan_files(c);
	}
	clock_gettime(CLOCK_MONOTONIC, &c->t1);
	ksn_progress_clear(&c->r);
	if (c->rc < 0)
		fprintf(stderr, "%s: cannot scan %s\n", c->argv0, c->target);
}

/* The scan's time, and the totals summed over every scanner that ran. */
static void cli_stats(struct cli *c)
{
	c->secs = (double)(c->t1.tv_sec - c->t0.tv_sec) +
	       (double)(c->t1.tv_nsec - c->t0.tv_nsec) / 1e9;
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
		const struct kof_stats *one;
		unsigned k;

		if (c->jobs > 1 && c->scs) {
			for (k = 0; k < c->jobs; k++) {
				one = c->scs[k] ? kscan_stats(c->scs[k]) : NULL;
				if (!one)
					continue;
				c->sum.objects        += one->objects;
				c->sum.object_bytes   += one->object_bytes;
				c->sum.unreadable     += one->unreadable;
				c->sum.cached         += one->cached;
				c->sum.considered     += one->considered;
				c->sum.ran            += one->ran;
				c->sum.by_target      += one->by_target;
				c->sum.by_size        += one->by_size;
				c->sum.by_arch        += one->by_arch;
				c->sum.by_subtype     += one->by_subtype;
				c->sum.by_region      += one->by_region;
				c->sum.gram_bytes     += one->gram_bytes;
				c->sum.gram_answers   += one->gram_answers;
				c->sum.searches       += one->searches;
				c->sum.multi_passes   += one->multi_passes;
				c->sum.multi_degraded += one->multi_degraded;
				c->sum.multi_reads    += one->multi_reads;
				c->sum.multi_bytes    += one->multi_bytes;
				c->sum.multi_answers    += one->multi_answers;
				c->sum.heur_emu       += one->heur_emu;
				c->sum.emu_insn       += one->emu_insn;
				c->sum.emu_budget_denied += one->emu_budget_denied;
				c->sum.limit_hits     += one->limit_hits;
				c->sum.verdict_lost   += one->verdict_lost;
				c->sum.bytes_searched += one->bytes_searched;
				if (one->peak_resident > c->sum.peak_resident)
					c->sum.peak_resident = one->peak_resident;
			}
			c->st = &c->sum;
		} else {
			c->st = kscan_stats(c->sc);
		}
	}
	c->mb = c->st ? (double)c->st->object_bytes / 1048576.0 : 0.0;
}

/* Under -v, the files that came back clean, and the ones nothing examined. */
static void report_files(struct cli *c)
{
	/*
	 * Under -v, the files that came back clean, at the file level.
	 *
	 * The findings above already named every infected, suspected, heuristic or
	 * broken file where it was found, so only the clean ones are left to
	 * mention - and a scanner that says nothing about a file a person asked it
	 * to look at reads as a scanner that skipped it. One line per file, not per
	 * object, so a container and the layers it unpacked to are one "OK".
	 */
	if (c->r.verbose) {
		size_t fi;

		/* The file the walk ended on has no successor to trigger it. */
		if (c->r.stream_v && c->r.cur_len)
			ksn_v_say_file(&c->r, c->r.cur_file, c->r.cur_len);

		/*
		 * Whatever streaming did not reach: every file under --jobs
		 * above 1, and any file the walk revisited. `said` is what
		 * keeps the two from printing the same line twice.
		 */
		for (fi = 0; fi < kverdict_filemap_count(c->r.files); fi++) {
			struct kverdict_file *e = kverdict_filemap_at(c->r.files, fi);

			if (e->host)
				continue;
			if (e->level < 0 && !e->broken && e->examined) {
				e->host = 1;
				ksn_say(&c->r, C_GRN, "OK", e->file);
			}
		}
		/*
		 * The unexamined ones, and NOT under -v only.
		 *
		 * "OK" is a claim, and this is the one case where the scan
		 * cannot make it: no module was eligible, so nothing looked.
		 * Saying so unconditionally is the point - a caller who only
		 * reads the default output would otherwise be told a file is
		 * clean when the honest answer is that it was not examined.
		 */
		/*
		 * The unexamined ones, beside the clean ones and behind the
		 * same -v.
		 *
		 * It printed unconditionally at first, on the argument that a
		 * caller must not be told "clean" when nothing looked. That
		 * argument is right and the SUMMARY is where it is answered -
		 * there is a `skipped` count now, and it is not folded into
		 * clean.
		 *
		 * WHY THIS DIFFERS FROM BROKEN, which prints its verdict
		 * unconditionally by the rule above it: FREQUENCY. A broken
		 * file is rare - a limit ran out, a codec is missing, the file
		 * is damaged - so a line each is information. Skipped is
		 * ordinary: 190 of the 954 files in /usr/bin are shell and
		 * Perl scripts that no module targets, and a line each buried
		 * everything else the scan had to ksn_say. Same kind of verdict,
		 * two orders of magnitude apart in how often it happens, so
		 * the count carries it and the per-file line is detail.
		 */
		for (fi = 0; fi < kverdict_filemap_count(c->r.files); fi++) {
			const struct kverdict_file *e = kverdict_filemap_at(c->r.files, fi);

			if (e->level < 0 && !e->broken && !e->examined)
				ksn_say(&c->r, C_DIM, "No module targets this format",
				    e->file);
		}
	}
}

/*
 * THE SUMMARY: counts per file, read off the engine's per-file verdicts, then the time.
 */
static void report_summary(struct cli *c)
{
	printf("\n--- scan complete ---\n");

	/*
	 * COUNTS ARE PER FILE, rolled up from the objects inside it.
	 *
	 * A packed file scanned as three objects, one of them the malware, is one
	 * infected file - not two clean objects plus one infected. So the summary
	 * reads the verdict this run kept for each top-level file rather than
	 * counting objects, which would call one file both clean and infected on
	 * two different lines. -v listed every clean OBJECT, so a container whose
	 * child was the malware printed "OK <file>" above the child's finding; the
	 * roll-up is what stops that.
	 */
	{
		/* Heuristic files broken down by the WORD each finding carries, so
		 * the summary can ksn_say "Shellcode" and "Truncated" apart rather than
		 * calling a well-formed shellcode shape "broken structure". */
		struct { char kind[48]; uint64_t n; } hk[16];
		int n_hk = 0, j;
		uint64_t heur_f = 0, broken_f = 0, clean_f;
		uint64_t skip_f = 0;
		uint64_t rf[KOF_BROKEN_COUNT];   /* broken FILES, by their reason */
		size_t fi;
		uint32_t k;

		memset(rf, 0, sizeof rf);
		for (fi = 0; fi < kverdict_filemap_count(c->r.files); fi++) {
			const struct kverdict_file *e = kverdict_filemap_at(c->r.files, fi);

			if (e->level == KOF_LEVEL_INFECT) {
				c->inf_f++;
			} else if (e->level == KOF_LEVEL_SUSPECT) {
				c->sus_f++;
			} else if (e->level == KOF_LEVEL_HEUR) {
				const char *kd = e->kind[0] ? e->kind : NULL;

				heur_f++;
				if (kd) {
					for (j = 0; j < n_hk; j++)
						if (!strcmp(hk[j].kind, kd))
							break;
					if (j == n_hk &&
					    n_hk < (int)(sizeof hk / sizeof hk[0])) {
						snprintf(hk[n_hk].kind,
							 sizeof hk[n_hk].kind, "%s", kd);
						hk[n_hk].n = 0;
						n_hk++;
					}
					if (j < n_hk)
						hk[j].n++;
				}
			} else if (e->broken) {
				broken_f++;
				if (e->broken < KOF_BROKEN_COUNT)
					rf[e->broken]++;
			} else if (!e->examined) {
				/* Counted apart from clean, and BEFORE the
				 * subtraction below, or the file would be
				 * counted as clean by omission - which is the
				 * whole thing this is here to stop. */
				skip_f++;
			}
		}
		/* Per OBJECT, for the exit code only: any object a limit or a gap
		 * stopped means the scan did not see all of the tree, whatever the
		 * file it was in rolled up to. */
		for (k = 1; k < KOF_BROKEN_COUNT; k++)
			c->broken_objs += c->r.by_reason[k];
		/*
		 * Clean is the files nothing was said about, and it is a SUBTRACTION
		 * clamped so it cannot wrap. It cannot go negative under any normal
		 * path - every file has one root object, counted once - but a target
		 * whose own name contains "//" (the separator the engine puts between
		 * a parent and its children) would miscount the root, and an unsigned
		 * underflow there would print a clean count in the billions.
		 */
		{
			uint64_t nonclean = c->inf_f + c->sus_f + heur_f + broken_f +
					    skip_f;

			clean_f = kverdict_filemap_files(c->r.files) > nonclean
				  ? kverdict_filemap_files(c->r.files) - nonclean : 0;
		}

		printf("scanned   %llu object(s) in %s%llu%s file(s), %.2f MB\n",
		       c->st ? (unsigned long long)c->st->objects : 0ull,
		       ksn_col(&c->r, C_BLD), (unsigned long long)kverdict_filemap_files(c->r.files),
		       ksn_col(&c->r, C_RST), c->mb);
		printf("infected  %s%llu%s file(s)\n",
		       c->inf_f ? ksn_col(&c->r, C_RED) : "", (unsigned long long)c->inf_f,
		       c->inf_f ? ksn_col(&c->r, C_RST) : "");
		printf("suspected %s%llu%s file(s)\n",
		       c->sus_f ? ksn_col(&c->r, C_YEL) : "", (unsigned long long)c->sus_f,
		       c->sus_f ? ksn_col(&c->r, C_RST) : "");
		/*
		 * REPAIRED, AND ONLY WHEN SOMETHING WAS.
		 *
		 * A scan that cured nothing is almost every scan, and a line
		 * reading "repaired 0" on all of them is the kind of noise that
		 * trains a reader to stop looking at this block. When it is not
		 * zero it is the one line here that says the scanner CHANGED the
		 * disk, so it appears directly under the verdict counts rather
		 * than at the end, and in the same green the per-file line used.
		 *
		 * It is NOT subtracted from `infected`. A repaired file was
		 * infected and is still reported as such - the verdict says what
		 * was found, this says what was done about it.
		 */
		if (c->r.repaired)
			printf("repaired  %s%llu%s file(s)\n",
			       ksn_col(&c->r, C_GRN), (unsigned long long)c->r.repaired,
			       ksn_col(&c->r, C_RST));
		/*
		 * HEURISTIC, split by KIND. Printed even at zero when the heuristic
		 * ran, so a reader can tell "found nothing" from "was switched off".
		 * The old single line said "with broken structure", which is true of
		 * the scored model - truncated, overlapping, an entry that is not
		 * executable - and wrong about a rule that recognised a shellcode
		 * SHAPE in a perfectly well-formed file. Each kind now speaks for
		 * itself.
		 */
		if (!c->opt.heur_off) {
			printf("heuristic %s%llu%s file(s)\n",
			       heur_f ? ksn_col(&c->r, C_MAG) : "",
			       (unsigned long long)heur_f,
			       heur_f ? ksn_col(&c->r, C_RST) : "");
		/*
		 * Only when there are any. A line reading "skipped 0" on every
		 * scan is noise; the interesting case is the one where it is
		 * not zero, and then it has to be impossible to miss.
		 */
			/* Each kind on its own line, read the same way as the
			 * totals above it: the count right after the label and
			 * then "file(s)", not pushed out to a far column, and
			 * indented so it sits under the heuristic total. */
			for (j = 0; j < n_hk; j++)
				printf("  %-8s %s%llu%s file(s)\n", hk[j].kind,
				       ksn_col(&c->r, C_MAG),
				       (unsigned long long)hk[j].n, ksn_col(&c->r, C_RST));
		}
		/*
		 * Broken files, split by reason. The reasons are counted per object
		 * because that is where they happen - one file may hold several - and
		 * the three call for different actions: raise a limit, report a gap in
		 * this build, or accept that the file is damaged.
		 */
		if (skip_f) {
			printf("skipped   %s%llu%s file(s)  "
			       "(no module targets the format)\n",
			       ksn_col(&c->r, C_DIM), (unsigned long long)skip_f,
			       ksn_col(&c->r, C_RST));
		}
		if (broken_f) {
			printf("broken    %s%llu%s file(s) the engine could not finish\n",
			       ksn_col(&c->r, C_CYN), (unsigned long long)broken_f,
			       ksn_col(&c->r, C_RST));
			for (k = 1; k < KOF_BROKEN_COUNT; k++)
				if (rf[k])
					printf("            %-28s %llu\n",
					       kverdict_broken_name(k),
					       (unsigned long long)rf[k]);
		}
		printf("clean     %s%llu%s file(s)\n",
		       clean_f ? ksn_col(&c->r, C_GRN) : "", (unsigned long long)clean_f,
		       clean_f ? ksn_col(&c->r, C_RST) : "");
	}
	/* Throughput beside the time it came from: on its own, a duration says nothing
	 * without the size of what was scanned, and both are already here. Guarded
	 * because a scan can finish inside the clock's resolution. */
	if (c->secs > 0.0005)
		printf("time      %.2f s (%.0f MB/s)\n", c->secs, c->mb / c->secs);
	else
		printf("time      %.3f s\n", c->secs);
	/* Copied out while the scanner is alive. kscan_stats hands back a
	 * pointer INTO the scanner, and the exit decision below runs after the
	 * scanner has been freed - reading it there was a use-after-free, reached
	 * on exactly the scans that found nothing, which is why every run that
	 * detected something hid it. */
}

/* What else the run has to ksn_say: the objects it could not read, the cache, the cap. */
static void report_notes(struct cli *c)
{
	if (c->st)
		c->unreadable = c->st->unreadable;
	if (c->unreadable)
		printf("skipped   %llu object(s) that could not be read\n",
		       (unsigned long long)c->unreadable);
	/*
	 * SAID OUT LOUD, because a sweep that opened a tenth of what it was
	 * pointed at and printed nothing about the rest reads as a sweep of a
	 * tree with nothing in it. It is also the number that says whether the
	 * cache is earning anything.
	 */
	if (c->st && c->st->cached)
		printf("cached    %llu file(s) unchanged since the last scan\n",
		       (unsigned long long)c->st->cached);
	/* The engine's own check (kof_stats.verdict_lost): a file counted above with no
	 * verdict line is a defect, and it is said as one - never summarised away. */
	if (c->st && c->st->verdict_lost)
		printf("ERROR     %llu file(s) counted without a verdict delivered (engine defect)\n",
		       (unsigned long long)c->st->verdict_lost);
	if (c->r.dropped)
		printf("note      %llu finding(s) over the per-object cap\n",
		       (unsigned long long)c->r.dropped);
	if (c->r.stats && c->st)
		ksn_print_stats(c->st);
}

/* The scanners, the engine and the per-file map. */
static void cli_close(struct cli *c)
{
	if (c->scs) {
		unsigned k;

		/* scs[0] is sc, freed below like it always was. */
		for (k = 1; k < c->made; k++)
			kscan_free(c->scs[k]);
		free(c->scs);
	}
	kscan_free(c->sc);
	keng_close(c->eng);
	kverdict_filemap_free(c->r.files);
}

/*
 * THE EXIT CODE - see the three outcomes below. Also where the time report is printed,
 * because every path out of the tool passes here.
 */
static int cli_exit(const struct cli *c)
{
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
	/*
	 * AND WHERE THE TIME WENT, in a debug build only - printed before the
	 * exit code is decided, because every one of those paths leaves main.
	 * The tool asks for it; the engine never decides to print, see
	 */
	fflush(stdout);
	KOF_TIME_REPORT();

	if (c->inf_f || c->sus_f)
		return 1;
	/* "Could not finish" belongs with "could not look", not with "found
	 * nothing": a caller that treats an exhausted budget as a clean scan has
	 * been evaded rather than reassured. broken_objs counts the objects a limit
	 * or a gap stopped, which is the per-object fact the exit turns on. */
	if (c->rc < 0 || c->unreadable || c->broken_objs)
		return 2;
	/*
	 * AND AN INTERRUPTED SWEEP IS THE SAME KIND OF ANSWER.
	 *
	 * The summary above is honest about what was looked at, but the exit
	 * code is what a script reads, and 0 there means "clean". A run that
	 * stopped at file 649 of 1056 has not established that the other 407
	 * are anything - by the paragraph above, that is "could not finish"
	 * and not "found nothing".
	 *
	 * Below the detection check on purpose: if the interrupted part had
	 * already found something, the finding is still the answer.
	 */
	if (ksn_interrupted)
		return 2;
	return 0;
}

int main(int argc, char **argv)
{
	struct cli c;
	int rc;

	/*
	 * BEFORE A BYTE OF argv IS READ OR A PATH IS OPENED.
	 *
	 * On Windows argv has already lost every character outside the machine's
	 * ANSI codepage by the time main is entered, and the narrow path
	 * functions would not find the file even if it had not. A scanner that
	 * cannot open a file is not a scanner that found it clean - see
	 * kof_utf8_init. No-op on POSIX, where a path is just bytes.
	 */
	kof_utf8_init(&argc, &argv);

	memset(&c, 0, sizeof c);
	c.argv0 = argv[0];
	c.jobs = 1;
	c.emu_want = -1;
	if ((rc = cli_parse(&c, argc, argv)) >= 0 ||
	    (rc = cli_open(&c)) >= 0 ||
	    (rc = cli_scanners(&c)) >= 0)
		return rc;
	cli_scan(&c);
	cli_stats(&c);
	report_files(&c);
	report_summary(&c);
	report_notes(&c);
	cli_close(&c);
	return cli_exit(&c);
}
