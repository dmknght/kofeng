/*
 * kofmontrace_int.h - what the units of kofmontrace share: the includes, the collector
 * constants, the spiller and the tracer records and what one unit offers another
 * (kmt_ prefix). Private to kofwatcher/.
 */

#ifndef KOFMONTRACE_INT_H
#define KOFMONTRACE_INT_H


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ONE TRACER, TWO PLATFORMS, AND ONE PLACE THAT KNOWS WHICH.
 *
 * Everything below the adapter is the same code on both: the same options,
 * the same drain loop, the same report. What differs is the collector and how
 * a subject is started, scoped and contained - and it differs HERE rather
 * than at the forty-odd call sites it used to.
 */
#ifdef _WIN32
#include <windows.h>

#include "kofgrille.h"
#else
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "kofantarc.h"
#include "afan.h"
/* Both Linux collectors behind one api - see amon.h on why the merge and the
 * exec de-duplication live in antarc and not in here. */
#include "amon.h"
#endif

/*
 * THE COLLECTOR'S OWN VERSION, recorded in a log header so a reader can tell
 * which producer wrote it. Two collectors, two numbers, one name here.
 */
#ifdef _WIN32
#define TRACER_MAJOR KOFW_MAJOR
#define TRACER_MINOR KOFW_MINOR
#else
#define TRACER_MAJOR KOFA_MAJOR
#define TRACER_MINOR KOFA_MINOR
#endif

/*
 * WHAT WAS ASKED FOR, in one vocabulary, because the FLAGS ARE THE SAME ON
 * BOTH PLATFORMS and a flag that exists on one host only is a flag somebody
 * has to remember the host for. On Windows each of these is a distinct ETW
 * subscription. On Linux fanotify answers the file ones and nothing answers
 * the rest - the banner still prints what was asked, and the health line at
 * the end is where a run learns that it got less than it asked for.
 */
#ifdef _WIN32
#define TRACER_SUB_PROCESS    KOFW_SUB_PROCESS
#define TRACER_SUB_IMAGE      KOFW_SUB_IMAGE
#define TRACER_SUB_FILE       KOFW_SUB_FILE
#define TRACER_SUB_FILE_WRITE KOFW_SUB_FILE_WRITE
#define TRACER_SUB_FILE_OPEN  KOFW_SUB_FILE_OPEN
#define TRACER_SUB_NET        KOFW_SUB_NET
#define TRACER_SUB_REGISTRY   KOFW_SUB_REGISTRY
#define TRACER_SUB_AMSI       KOFW_SUB_AMSI
#define TRACER_SUB_DNS        KOFW_SUB_DNS
#define TRACER_SUB_THREAD     KOFW_SUB_THREAD
#else
#define TRACER_SUB_PROCESS    (1u << 0)
#define TRACER_SUB_IMAGE      (1u << 1)
#define TRACER_SUB_FILE       (1u << 2)
#define TRACER_SUB_FILE_WRITE (1u << 3)
#define TRACER_SUB_FILE_OPEN  (1u << 4)
#define TRACER_SUB_NET        (1u << 5)
#define TRACER_SUB_REGISTRY   (1u << 6)
#define TRACER_SUB_AMSI       (1u << 7)
#define TRACER_SUB_DNS        (1u << 8)
#define TRACER_SUB_THREAD     (1u << 9)
#endif
#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofevtlog.h"

/*
 * AND THE ENGINE, WHICH THIS TOOL DID NOT USED TO LINK.
 *
 * It links it for the report: a trace says which files the program created and
 * which strings it used, and only the bytes say what those files ARE and
 * whether those strings are in the sample at all. Hashing an artefact, naming
 * the packer that produced it and checking a candidate string against the
 * subject's bytes are all engine work, and doing them anywhere else would mean
 * a second opinion on questions the engine already answers.
 *
 * The cost is in the Makefile and is written down there: this stopped
 * cross-building, because $(LIB) is built for the host. kofwatchtower stays in
 * the cross block and keeps libkoforbit/grille type-checked on a machine with no ETW.
 */
#include "kofeng.h"
#include "kofcore/kofcore.h"
#include "kofcore/kofplatform.h"
#include "kofreport.h"

/* ------------------------------------------------------------- the spiller */

/*
 * COPY A CREATED FILE WHILE IT STILL EXISTS.
 *
 * THE PROBLEM THIS SOLVES, precisely. Collection happens after the traced tree
 * is dead - kofrepart.c opens with why, and the reasons are right: a file read
 * while its writer runs hashes to something that was never on the disk, and
 * unbounded I/O on the drain path costs a full ring rather than a queue. But a
 * dropper that writes its second stage and deletes it has nothing left to
 * collect by then, and that is not an unusual sample, it is the common one.
 * Every metasploit payload that stages through a file cleans up after itself.
 *
 * So the copy happens HERE, on the event, and it stays a FALLBACK: the report
 * still reads the disk at the end and only reaches for this when the original
 * is gone. See kof_report_spill.
 *
 * AND IT IS BOUNDED, because the objection in kofrepart.c does not stop being
 * true just because the copy is useful:
 *
 *   - one copy per path, not per event: a build tool writing a file in a loop
 *     costs one copy, not a thousand
 *   - a per-file ceiling and a total budget, both small by default
 *   - a fixed table, so a sample that touches ten thousand paths runs out of
 *     slots rather than out of disk
 *   - NOTHING UNDER THE REPORT DIRECTORY is ever copied. The copies live
 *     there, and copying them would raise events that produce more copies -
 *     a loop that fills a disk at the speed of the ring.
 */
#define SPILL_MAX_FILES  256u
#define SPILL_MAX_ONE    (16u * 1024u * 1024u)
#define SPILL_MAX_TOTAL  (256u * 1024u * 1024u)

struct spiller {
	char     dir[512];      /* <report>/spill */
	char     guard[512];    /* the report root: never copy from under it */
	size_t   guard_len;
	uint32_t n;
	uint64_t bytes, skipped_big, skipped_full, failed;
	int      ready;
	/* Paths already copied. Hashes only - the strings live in the report's
	 * arena and this table exists to answer "again?" in one compare. */
	uint64_t seen[SPILL_MAX_FILES * 2u];
};

/* ------------------------------------------------------------ the subject */

/*
 * WHAT A TRACER NEEDS: a collector scoped to one program, and a way to start,
 * hold and end that program. The two platforms answer both differently and
 * nothing below this block says so.
 *
 * SCOPING IS THE INTERESTING HALF. Windows is told about every process start
 * and keeps a tracked set - see kofw_mon_track. Linux has no such stream
 * without the netlink connector, which needs CAP_NET_ADMIN and drops records
 * under load, so the scope is a PROCESS GROUP: the child gets its own with
 * setpgid, every descendant inherits it, and an event is in scope exactly when
 * getpgid(pid) returns it. One syscall per event, nothing to build, nothing to
 * poll, and the kernel is not going to forget which group a process is in.
 *
 * WHAT ESCAPES THAT, plainly: a process that calls setsid() leaves the group
 * and stops being reported. That is the hole a daemonising payload walks
 * through, and it is why the Windows side tracks instead of grouping. The
 * honest position is that this scopes a well-behaved subject.
 *
 * AND WITHOUT PRIVILEGE THERE IS NOTHING TO SCOPE BY: an unprivileged fanotify
 * listener is handed pid 0 for every event it did not cause itself. A degraded
 * run reports what it can see and attributes none of it - see afan.h.
 */
struct tracer {
#ifdef _WIN32
	struct kofw_mon    *mon;
	struct kofw_evt     raw;
	STARTUPINFOA        si;
	PROCESS_INFORMATION pi;
	HANDLE              job;
	char                cmd[8192];
#else
	struct kofa_mon          *mon_l;
	const struct kof_mon_api *api;
	pid_t                     kid, group;
	uint32_t                  asked, granted;
	uint64_t                  out_of_scope, unattributed;
	int                       running;
	int                       unscoped;

	/*
	 * WHAT WE LEARNED WHILE THE ANSWER STILL EXISTED.
	 *
	 * getpgid() on a process that has exited returns -1, and an event
	 * arrives AFTER the thing that caused it - so a program that writes a
	 * file and exits inside one poll interval can no longer be asked which
	 * group it was in. That is not an edge case, it is the shape of a
	 * dropper: the trace was losing exactly the events it exists to catch.
	 *
	 * So every resolution is remembered. A pid seen once while it lived is
	 * still answerable after it dies, which covers everything that raised
	 * more than one event or lived longer than one drain.
	 *
	 * Open addressing, fixed size, no allocation on the event path. A full
	 * table is not an error: an entry is overwritten and the pid becomes
	 * unknown again, which falls back to the rule below rather than to a
	 * wrong answer.
	 */
	struct { uint32_t pid; uint8_t known, in; } seen[512];
#endif
	uint32_t root_pid;
};

/* The files --watch named (the tracer reads them once, at open). */
extern const char *kmt_watch[32];
extern unsigned    kmt_n_watch;

int kmt_tracer_open(struct tracer *t, unsigned providers, uint32_t ring);
int kmt_tracer_start(struct tracer *t, char **argv, const char *cmdline);
int kmt_tracer_track(struct tracer *t, const char *leaf);
int kmt_tracer_contain(struct tracer *t);
void kmt_tracer_resume(struct tracer *t);
int kmt_tracer_next(struct tracer *t, struct kof_evt *out, uint32_t wait_ms,
		       int all);
const char *kmt_tracer_name_of(struct tracer *t);
int kmt_tracer_alive(struct tracer *t);
void kmt_tracer_health(struct tracer *t, struct kof_evt_health *nh);
void kmt_tracer_extra(struct tracer *t, FILE *out);
void kmt_tracer_subs(struct tracer *t, uint32_t *asked, uint32_t *enabled);
const char *kmt_tracer_sub_name(uint32_t bit);
void kmt_tracer_filter(struct tracer *t, uint32_t root_pid, int no_scope,
			  int show_all_img, int show_raw, int amsi_anywhere);
int kmt_tracer_resolve(const char *name, char *out, size_t cap);
void kmt_tracer_report_unattributed(struct tracer *t, FILE *out);
uint64_t kmt_tracer_filtered_scope(struct tracer *t);
int kmt_tracer_describe(struct tracer *t, char *buf, size_t cap);
const char *kmt_tracer_tracked_nth(struct tracer *t, uint32_t k,
				      uint32_t *pid);
void kmt_tracer_stop(struct tracer *t);
void kmt_tracer_close(struct tracer *t);
int kmt_rep_ask(void *user, const char *path, struct kof_fp_verdict *v);
void kmt_spill_init(struct spiller *sp, const char *rep_dir);
void kmt_spill_take(struct spiller *sp, struct kof_report *rep,
		       const struct kof_evt *e);
void kmt_spill_report(const struct spiller *sp, FILE *out);

#endif /* KOFMONTRACE_INT_H */
