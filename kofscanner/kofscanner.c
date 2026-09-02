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

/*
 * COLOUR, and only when the output is a terminal.
 *
 * A pipe, a log or a grep must get the bytes it always did, so every escape goes
 * through col(): it returns the sequence when stdout is a tty and an empty string
 * otherwise, which is the same rule progress already applies to stderr. The codes
 * are chosen so the verdict reads at a glance - red is the one that stops a
 * release, green the one that does not.
 */
#define C_RED "\033[1;31m"      /* INFECTED  */
#define C_YEL "\033[1;33m"      /* SUSPECT   */
#define C_MAG "\033[1;35m"      /* HEURISTIC */
#define C_CYN "\033[36m"        /* BROKEN    */
#define C_GRN "\033[32m"        /* OK        */
#define C_DIM "\033[2m"         /* secondary context */
#define C_RST "\033[0m"

/*
 * ONE VERDICT PER TOP-LEVEL FILE, rolled up from every object inside it.
 *
 * A packed or carrying file is scanned as a tree - the file, then whatever the
 * unpackers made of it - and the malware is usually in a child, not the root. So
 * the root on its own comes back clean, and reporting THAT as the file's verdict
 * calls an infected file clean. The fix is to key a verdict by the top-level file
 * (the name up to the first "//") and keep the WORST thing found anywhere in its
 * tree; the child's finding still prints in full, but the file it came in is what
 * is counted.
 *
 * A small open-addressed map, because the callback is serialised (even under
 * --jobs) and the objects of one file need not arrive together, so a running
 * "current file" cannot be trusted - two files' objects interleave. Keyed by the
 * file name, valued by the worst level seen (-1 for none), the broken reason, and
 * the finding text to show.
 */
struct fent {
	char    *file;
	int      level;          /* worst KOF_LEVEL_*, or -1 */
	uint32_t broken;         /* worst kof_broken reason, or 0 */
	char     name[224];      /* the worst finding's composed name */
};

struct fmap {
	struct fent *arr;        /* entries in first-seen order, for -v listing */
	size_t       n, cap;
	uint32_t    *idx;        /* open-addressed: (arr index + 1), 0 = empty */
	size_t       icap;       /* a power of two */
};

struct run {
	/* No object counter: the engine already keeps one, and a second copy is a
	 * second thing that can disagree with it. */
	uint64_t dropped;
	uint64_t by_reason[KOF_BROKEN_COUNT];
	int verbose;
	int stats;
	int color;               /* stdout is a terminal */

	/* Every top-level file's rolled-up verdict, and how many files there were.
	 * The counts printed at the end are derived from these, so a file with an
	 * infected child is one infected file and not one clean plus one infected. */
	struct fmap files;
	uint64_t    files_total;

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

/* The escape when stdout is a terminal, nothing otherwise. */
static const char *col(const struct run *r, const char *c)
{
	return r->color ? c : "";
}

static const char *level_str(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return "INFECTED";
	return level == KOF_LEVEL_HEUR ? "HEURISTIC" : "SUSPECT";
}

/* The colour a level speaks in. */
static const char *level_col(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return C_RED;
	return level == KOF_LEVEL_HEUR ? C_MAG : C_YEL;
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
 * The word a heuristic finding carries between "Heur:" and the "#", which is what
 * KIND of heuristic it was: "Shellcode" for a rule that recognised a shape,
 * "Truncated" and the like for the scored model that weighs a damaged structure.
 * The summary breaks its count down by this, because "broken structure" is true of
 * the second and wrong about the first.
 */
static const char *heur_kind(const char *name, char *buf, size_t cap)
{
	const char *p = strstr(name, "/Heur:");
	size_t i = 0;

	if (!p)
		return NULL;
	p += 6;                          /* past "/Heur:" */
	while (p[i] && p[i] != '#' && p[i] != '?' && i + 1 < cap) {
		buf[i] = p[i];
		i++;
	}
	buf[i] = 0;
	return i ? buf : NULL;
}

/* ---- the per-file verdict map --------------------------------------------- */

static uint32_t fnv_n(const char *s, size_t n)
{
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ (uint8_t)s[i]) * 16777619u;
	return h;
}

/* Find the top-level file's entry, creating it if new. `file` is a substring of a
 * longer name and is `flen` bytes, not NUL-terminated. NULL only on OOM. */
static struct fent *fmap_get(struct fmap *m, const char *file, size_t flen)
{
	uint32_t h, slot;

	/* Grow the index when it is half full, so probe chains stay short. */
	if (m->n * 2u >= m->icap) {
		size_t nc = m->icap ? m->icap * 2u : 256u;
		uint32_t *ni = calloc(nc, sizeof *ni);
		size_t i;

		if (!ni)
			return NULL;
		for (i = 0; i < m->n; i++) {
			uint32_t s = fnv_n(m->arr[i].file,
					   strlen(m->arr[i].file)) &
				     (uint32_t)(nc - 1u);

			while (ni[s])
				s = (s + 1u) & (uint32_t)(nc - 1u);
			ni[s] = (uint32_t)(i + 1u);
		}
		free(m->idx);
		m->idx = ni;
		m->icap = nc;
	}

	h = fnv_n(file, flen) & (uint32_t)(m->icap - 1u);
	for (slot = h; m->idx[slot]; slot = (slot + 1u) & (uint32_t)(m->icap - 1u)) {
		struct fent *e = &m->arr[m->idx[slot] - 1u];

		if (strlen(e->file) == flen && !memcmp(e->file, file, flen))
			return e;
	}

	/* New file: append an entry and point the slot at it. */
	if (m->n == m->cap) {
		size_t nc = m->cap ? m->cap * 2u : 128u;
		struct fent *na = realloc(m->arr, nc * sizeof *na);

		if (!na)
			return NULL;
		m->arr = na;
		m->cap = nc;
	}
	{
		struct fent *e = &m->arr[m->n];

		e->file = malloc(flen + 1u);
		if (!e->file)
			return NULL;
		memcpy(e->file, file, flen);
		e->file[flen] = 0;
		e->level = -1;
		e->broken = 0;
		e->name[0] = 0;
		m->idx[slot] = (uint32_t)(m->n + 1u);
		m->n++;
		return e;
	}
}

static void fmap_free(struct fmap *m)
{
	size_t i;

	for (i = 0; i < m->n; i++)
		free(m->arr[i].file);
	free(m->arr);
	free(m->idx);
}

/* The top-level file a name belongs to: everything up to the first "//". */
static size_t toplevel_len(const char *name)
{
	const char *p = strstr(name, "//");

	return p ? (size_t)(p - name) : strlen(name);
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
	const char *worst_name = NULL;
	size_t flen = toplevel_len(name);

	(void)bytes;
	(void)len;

	progress_draw(r, name);
	/*
	 * Take the progress line back only when a finding is about to land on it.
	 * A clean object prints nothing during the scan now - its "OK" waits for
	 * the per-file pass at the end - so clearing for it under -v would just
	 * flicker the line the rate limit exists to keep still.
	 */
	if (res->n || (res->broken && (res->n == 0 || r->verbose)) || res->dropped)
		progress_clear(r);

	/* Each top-level FILE counted once, and a root object is the one whose
	 * name carries no "//" - the separator the engine puts between a parent
	 * and the objects it produced. */
	if (flen == strlen(name))
		r->files_total++;

	/*
	 * The findings, in full, at the object that carries them - a child three
	 * layers down still prints with its own "//"-joined name, so a reader sees
	 * exactly where in the file it is. The worst of them is what the file rolls
	 * up to.
	 */
	for (i = 0; i < res->n; i++) {
		uint32_t lv = res->v[i].level;

		printf("%s%-10s%s %s: %s\n", col(r, level_col(lv)),
		       level_str(lv), col(r, C_RST), name, res->v[i].name);
		/*
		 * Ranked, not compared as numbers: KOF_LEVEL_HEUR is 2 and INFECT
		 * is 1, so ">" on the values alone would let a heuristic outrank a
		 * named detection. The order a level speaks in is its own fact.
		 */
		if (rank_of((int)lv) > rank_of(worst)) {
			worst = (int)lv;
			worst_name = res->v[i].name;
		}
	}

	/*
	 * BROKEN is secondary to a finding, not a second verdict beside it.
	 *
	 * A context-keyed encoder comes back both as a rule's Heur:Shellcode and,
	 * from the unpacker that could not read its key, as "the content is
	 * encrypted". Those are one thing said twice: the finding is the answer,
	 * the encryption is only why nothing further could be read - so with a
	 * finding present it is shown under -v and nowhere else. With no finding it
	 * IS the verdict and always prints. The reason is still tallied either way.
	 */
	if (res->broken) {
		if (res->broken < KOF_BROKEN_COUNT)
			r->by_reason[res->broken]++;
		if (res->n == 0 || r->verbose)
			printf("%s%-10s%s %s: %s\n", col(r, C_CYN), "BROKEN",
			       col(r, C_RST), name, kof_broken_name(res->broken));
	}

	/*
	 * Roll this object's verdict up into its top-level file. Non-clean objects
	 * always get an entry so the file is counted; a clean object touches one
	 * only under -v, where every file is listed at the end whatever it turned
	 * out to be.
	 */
	if (res->n || res->broken || r->verbose) {
		struct fent *e = fmap_get(&r->files, name, flen);

		if (e) {
			if (worst >= 0 && rank_of(worst) > rank_of(e->level)) {
				e->level = worst;
				snprintf(e->name, sizeof e->name, "%s",
					 worst_name ? worst_name : "");
			}
			if (res->broken && !e->broken)
				e->broken = res->broken;
		}
	}

	if (res->dropped) {
		printf("%s%-10s%s %s: %u further finding(s) not reported\n",
		       col(r, C_DIM), "NOTE", col(r, C_RST), name, res->dropped);
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
	/* The file-level tallies, computed from the per-file map for the summary
	 * and read again by the exit code after the map is gone. */
	uint64_t inf_f = 0, sus_f = 0, broken_objs = 0;
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
	/* Colour follows the same rule, asked of stdout because that is where the
	 * findings go: a redirect or a pipe gets plain text, a terminal gets the
	 * highlight. */
	r.color = isatty(1) ? 1 : 0;

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

	/*
	 * Under -v, the files that came back clean, at the file level.
	 *
	 * The findings above already named every infected, suspected, heuristic or
	 * broken file where it was found, so only the clean ones are left to
	 * mention - and a scanner that says nothing about a file a person asked it
	 * to look at reads as a scanner that skipped it. One line per file, not per
	 * object, so a container and the layers it unpacked to are one "OK".
	 */
	if (r.verbose) {
		size_t fi;

		for (fi = 0; fi < r.files.n; fi++) {
			const struct fent *e = &r.files.arr[fi];

			if (e->level < 0 && !e->broken)
				printf("%s%-10s%s %s\n", col(&r, C_GRN), "OK",
				       col(&r, C_RST), e->file);
		}
	}

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
		 * the summary can say "Shellcode" and "Truncated" apart rather than
		 * calling a well-formed shellcode shape "broken structure". */
		struct { char kind[48]; uint64_t n; } hk[16];
		int n_hk = 0, j;
		uint64_t heur_f = 0, broken_f = 0, clean_f;
		uint64_t rf[KOF_BROKEN_COUNT];   /* broken FILES, by their reason */
		size_t fi;
		uint32_t k;

		memset(rf, 0, sizeof rf);
		for (fi = 0; fi < r.files.n; fi++) {
			const struct fent *e = &r.files.arr[fi];

			if (e->level == KOF_LEVEL_INFECT) {
				inf_f++;
			} else if (e->level == KOF_LEVEL_SUSPECT) {
				sus_f++;
			} else if (e->level == KOF_LEVEL_HEUR) {
				char kb[48];
				const char *kd = heur_kind(e->name, kb, sizeof kb);

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
			}
		}
		/* Per OBJECT, for the exit code only: any object a limit or a gap
		 * stopped means the scan did not see all of the tree, whatever the
		 * file it was in rolled up to. */
		for (k = 1; k < KOF_BROKEN_COUNT; k++)
			broken_objs += r.by_reason[k];
		/*
		 * Clean is the files nothing was said about, and it is a SUBTRACTION
		 * clamped so it cannot wrap. It cannot go negative under any normal
		 * path - every file has one root object, counted once - but a target
		 * whose own name contains "//" (the separator the engine puts between
		 * a parent and its children) would miscount the root, and an unsigned
		 * underflow there would print a clean count in the billions.
		 */
		{
			uint64_t nonclean = inf_f + sus_f + heur_f + broken_f;

			clean_f = r.files_total > nonclean
				  ? r.files_total - nonclean : 0;
		}

		printf("scanned   %llu object(s) in %llu file(s), %.2f MB\n",
		       st ? (unsigned long long)st->objects : 0ull,
		       (unsigned long long)r.files_total, mb);
		printf("infected  %s%llu%s file(s)\n",
		       inf_f ? col(&r, C_RED) : "", (unsigned long long)inf_f,
		       inf_f ? col(&r, C_RST) : "");
		printf("suspected %s%llu%s file(s)\n",
		       sus_f ? col(&r, C_YEL) : "", (unsigned long long)sus_f,
		       sus_f ? col(&r, C_RST) : "");
		/*
		 * HEURISTIC, split by KIND. Printed even at zero when the heuristic
		 * ran, so a reader can tell "found nothing" from "was switched off".
		 * The old single line said "with broken structure", which is true of
		 * the scored model - truncated, overlapping, an entry that is not
		 * executable - and wrong about a rule that recognised a shellcode
		 * SHAPE in a perfectly well-formed file. Each kind now speaks for
		 * itself.
		 */
		if (!opt.heur_off) {
			printf("heuristic %s%llu%s file(s)\n",
			       heur_f ? col(&r, C_MAG) : "",
			       (unsigned long long)heur_f,
			       heur_f ? col(&r, C_RST) : "");
			for (j = 0; j < n_hk; j++)
				printf("            %-20s %llu\n", hk[j].kind,
				       (unsigned long long)hk[j].n);
		}
		/*
		 * Broken files, split by reason. The reasons are counted per object
		 * because that is where they happen - one file may hold several - and
		 * the three call for different actions: raise a limit, report a gap in
		 * this build, or accept that the file is damaged.
		 */
		if (broken_f) {
			printf("broken    %s%llu%s file(s) the engine could not finish\n",
			       col(&r, C_CYN), (unsigned long long)broken_f,
			       col(&r, C_RST));
			for (k = 1; k < KOF_BROKEN_COUNT; k++)
				if (rf[k])
					printf("            %-28s %llu\n",
					       kof_broken_name(k),
					       (unsigned long long)rf[k]);
		}
		printf("clean     %s%llu%s file(s)\n",
		       clean_f ? col(&r, C_GRN) : "", (unsigned long long)clean_f,
		       clean_f ? col(&r, C_RST) : "");
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
	fmap_free(&r.files);

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
	if (inf_f || sus_f)
		return 1;
	/* "Could not finish" belongs with "could not look", not with "found
	 * nothing": a caller that treats an exhausted budget as a clean scan has
	 * been evaded rather than reassured. broken_objs counts the objects a limit
	 * or a gap stopped, which is the per-object fact the exit turns on. */
	if (rc < 0 || unreadable || broken_objs)
		return 2;
	return 0;
}