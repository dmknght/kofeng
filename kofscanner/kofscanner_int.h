/*
 * kofscanner_int.h - what the units of kofscanner share: the run state, the colour codes
 * and what one unit offers another (ksn_ prefix). Private to kofscanner/.
 */

#ifndef KOFSCANNER_INT_H
#define KOFSCANNER_INT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <kofeng.h>
#include <kofdebug.h>
#include <kofplatform.h>
/* kof_hash_bytes - the engine's one FNV, see kofcore.h. */
#include <kofcore.h>
/*
 * SCANNING WHAT IS RUNNING, on the platform that has a collector for it.
 *
 * libkoforbit/antarc is the Linux collector and builds only there, the way
 * libkoforbit/grille builds only for Windows. The scan itself is the same scan - see
 * scan_procs below - so what is guarded is the collector, not the idea.
 */
/*
 * THE PROCESS WALK IS A CONTRACT, NOT A PLATFORM. kof_walk_open is declared
 * once and defined by whichever collector this host links - libkoforbit/antarc on
 * Linux, libkoforbit/grille on Windows. Nothing in this file is #ifdef'd for it.
 */
#include "kofwalk.h"
#include "kofproc.h"
#include "koffridge.h"
#include "fidset.h"
#include <kofmod/proc.h>

/*
 * COLOUR, and only when the output is a terminal.
 *
 * A pipe, a log or a grep must get the bytes it always did, so every escape goes
 * through ksn_col(): it returns the sequence when stdout is a tty and an empty string
 * otherwise, which is the same rule progress already applies to stderr. The codes
 * are chosen so the verdict reads at a glance - red is the one that stops a
 * release, green the one that does not.
 */
#define C_RED "\033[1;31m"      /* INFECTED  */
#define C_CYN "\033[36m"        /* BROKEN    */
#define C_GRN "\033[32m"        /* OK        */
#define C_DIM "\033[2m"         /* secondary context */
#define C_BLD "\033[1m"         /* a neutral number worth the eye */
#define C_RST "\033[0m"

/*
 * ONE VERDICT PER TOP-LEVEL FILE, rolled up from every object inside it - by the
 * engine, not here: see kverdict_filemap in verdictor/verdict.h. The callback folds
 * each object into the map and the counts printed at the end are read off it, so a
 * file with an infected child is one infected file and not one clean plus one
 * infected. What this tool keeps beside an entry is `host`, the one flag it needs
 * (whether -v has already printed that file's line).
 */

struct run {
	/* No object counter: the engine already keeps one, and a second copy is a
	 * second thing that can disagree with it. */
	uint64_t by_reason[KOF_BROKEN_COUNT];
	/* Files the clean set answered for, counted where the skip happens
	 * so the progress line can ksn_say so. kof_stats counts them too, but
	 * that arrives at the END of the scan and this is needed during
	 * it. */
	uint64_t cached_seen;
	/* The tail of the path currently on the progress line. Kept so the
	 * line can be painted again after a finding was printed over it -
	 * see progress_restore. */
	char     last[64];
	int verbose;
	int stats;
	int color;               /* stdout is a terminal */

	/* Every top-level file's rolled-up verdict, and how many files there were. The
	 * counts printed at the end are derived from this, so a file with an infected
	 * child is one infected file and not one clean plus one infected. An entry's
	 * `host` is set once -v has printed that file's line: the verdict is streamed as
	 * each file finishes, so the flag is what stops the sweep at exit from saying it
	 * twice - and what lets that sweep still catch anything streaming did not reach. */
	kverdict_filemap *files;

	/*
	 * THE FILE -v IS STILL WAITING ON, so a clean one is reported when it
	 * finishes instead of when the whole scan does.
	 *
	 * Findings print the moment they are found; clean files used to be
	 * listed only at exit. On a tree where most files are clean that is a
	 * long silence between the last finding and the summary - on 4698
	 * files here, twenty seconds of a scanner that looks stopped. It is
	 * also the wrong shape for a pipe, where a reader wants the answer for
	 * a file when that file is done.
	 *
	 * WHY A SINGLE NAME IS ENOUGH, AND ONLY AT --jobs 1. The callback is
	 * serialised, and with one thread the walk finishes a file's whole
	 * object tree before it starts the next - so a name different from
	 * this one means the previous file is complete. With more threads the
	 * objects of two files interleave (see kverdict_filemap) and a name
	 * change proves nothing, so streaming is off and the sweep at exit
	 * does the work it always did.
	 */
	char        cur_file[512];
	size_t      cur_len;
	int         stream_v;        /* -v may report as it goes */

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

	/*
	 * THE ENGINE, held only to turn a diagnose id back into its name.
	 *
	 * A verdict carries ids, because an id is what travels; the name exists for a person to
	 * read and lives in the database. Keeping a copy of the table here
	 * would be a second carrier for one fact, and it would be the one that
	 * is stale after a database reload - so the engine is asked.
	 */
	const kof_engine *eng;
};

/*
 * WHAT THE CACHE HOOKS ARE GIVEN.
 *
 * The set, and the run - and the run is here for one reason: a file the set
 * answers for never reaches ksn_on_object, so it never reaches ksn_progress_draw
 * either. Measured on 300 files from /usr/bin: a cold scan drew the progress
 * line six times and the second scan, with every file cached, drew it ZERO
 * times. The scanner did its work and said nothing at all while doing it,
 * which on a large tree is indistinguishable from being stuck.
 */
struct cache_hook {
	struct kof_fidset *fs;
	struct run        *r;
};

/* Set by the signal handler, read wherever the scan unwinds. */
extern volatile sig_atomic_t ksn_interrupted;

const char *ksn_col(const struct run *r, const char *c);
void ksn_on_interrupt(int sig);
int ksn_scan_should_stop(void *user);
void ksn_progress_draw(struct run *r, const char *name);
void ksn_progress_clear(struct run *r);
void ksn_say(struct run *r, const char *colour, const char *tag,
		const char *name);
void ksn_on_event_detected(const char *object, const char *verdict,
		       const struct kof_finding *f, void *user);
void ksn_v_say_file(struct run *r, const char *file, size_t flen);
int ksn_on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user);
void ksn_print_stats(const struct kof_stats *st);
int ksn_fid_seen(void *user, const char *path);
void ksn_fid_keep(void *user, const char *path);
void ksn_cache_age(uint64_t made, char *out, size_t cap);
uint64_t ksn_engine_stamp(void);
void ksn_fid_drop(void *user, const char *path);
/*
 * One process sweep, as one request: who scans (run, scanner, option), what the
 * file cache is (a stamp, where it lives, whether its word is believed) and which
 * processes are walked. `cache.path` NULL means no cache; `cache.trust` 0 means
 * the set is loaded and findings are dropped from it, but nothing is skipped.
 * `opt` is the caller's and is edited: the cache hooks are written into it.
 */
struct ksn_procs_cache {
	uint64_t    db_stamp;
	const char *path;
	int         trust;
};

struct ksn_procs_pick {
	const uint32_t *pids;           /* NULL for every process */
	uint32_t        n_pids;
	int             compare_modules;
};

struct ksn_procs_req {
	struct run              *r;
	kof_scanner             *sc;
	struct kof_scan_option  *opt;
	struct ksn_procs_cache   cache;
	struct ksn_procs_pick    pick;
};

int ksn_scan_procs(const struct ksn_procs_req *rq);

#endif /* KOFSCANNER_INT_H */
