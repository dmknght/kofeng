/*
 * kofdebug.c - the timing table behind kofdebug.h. Nothing here exists in a
 * release build; see the header for why that is a build decision and not a
 * flag.
 *
 * clock_gettime is POSIX 2001 and this tree builds as -std=c11, which hides
 * it; the same declaration objsrc.c makes, for the same reason.
 */
#define _POSIX_C_SOURCE 200809L

#include "kofdebug.h"

#if KOF_DEBUG

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static const char *const slot_name[KOF_T_COUNT] = {
	"db load", "parse", "unpack", "heur", "emulate", "match",
	"diag syscall", "diag symbol", "diag emulate", "diag apihash",
	"diag text", "diag lineage", "diag match"
};

/*
 * THE TABLE IS TOUCHED AT SCAN TIME, from every scan thread (the scanner's
 * --jobs): KOF_TIME_BEGIN/END sit in the unpack, heuristic, emulation, diag and
 * match stages, which run per object. It only exists in a DEBUG build, but a
 * measurement taken with several jobs must not be a data race.
 *
 * So the table is split by who may write it. What is a total over the whole run
 * (nanoseconds, entries) is atomic and shared. What belongs to ONE thread's
 * nesting - the depth and the start of the outermost entry - is thread-local:
 * a second thread entering the same stage is its own outermost entry and starts
 * its own clock, instead of seeing the first thread's depth and never timing
 * anything. A row is therefore the SUM of the time every thread spent in the
 * stage, which is thread-seconds and not wall time with more than one job.
 */
struct slot {
	_Atomic uint64_t total;         /* nanoseconds, outermost spans only */
	_Atomic uint64_t calls;         /* entries, including re-entries     */
};

struct slot_nest {
	uint64_t started;
	unsigned depth;
};

static struct slot g_slot[KOF_T_COUNT];
static _Thread_local struct slot_nest t_nest[KOF_T_COUNT];

static uint64_t now_ns(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
		return 0;
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

void kof_time_begin(enum kof_time_slot s)
{
	if ((unsigned)s >= (unsigned)KOF_T_COUNT)
		return;
	atomic_fetch_add_explicit(&g_slot[s].calls, 1, memory_order_relaxed);
	/* Only the outermost entry starts the clock - see the note on nesting
	 * in the header. */
	if (!t_nest[s].depth++)
		t_nest[s].started = now_ns();
}

void kof_time_end(enum kof_time_slot s)
{
	if ((unsigned)s >= (unsigned)KOF_T_COUNT || !t_nest[s].depth)
		return;
	if (!--t_nest[s].depth && t_nest[s].started)
		atomic_fetch_add_explicit(&g_slot[s].total,
					  now_ns() - t_nest[s].started,
					  memory_order_relaxed);
}

void kof_time_report(void)
{
	unsigned order[KOF_T_COUNT], i, j, n = 0;
	uint64_t sum = 0;

	for (i = 0; i < (unsigned)KOF_T_COUNT; i++)
		if (g_slot[i].calls) {
			order[n++] = i;
			sum += g_slot[i].total;
		}
	if (!n)
		return;
	/* slowest first: the row a reader wants is the top one */
	for (i = 0; i + 1u < n; i++)
		for (j = i + 1u; j < n; j++)
			if (g_slot[order[j]].total > g_slot[order[i]].total) {
				unsigned t = order[i];

				order[i] = order[j];
				order[j] = t;
			}
	fprintf(stderr, "\n--- where the time went ---\n");
	for (i = 0; i < n; i++) {
		const struct slot *p = &g_slot[order[i]];
		double ms = (double)p->total / 1000000.0;

		fprintf(stderr, "  %-14s %9.3f ms  %6.1f%%  %8llu call(s)"
			"  %8.1f us each\n",
			slot_name[order[i]], ms,
			sum ? 100.0 * (double)p->total / (double)sum : 0.0,
			(unsigned long long)p->calls,
			p->calls ? (double)p->total / 1000.0 /
				   (double)p->calls : 0.0);
	}
	/*
	 * THE TOTAL IS OF THE ROWS AND NOT OF THE RUN. Stages nest - a match
	 * inside an unpacked child is inside that unpack - so these do not add
	 * up to wall time and saying they did would be the lie.
	 */
	fprintf(stderr, "  %-14s %9.3f ms  (rows only; stages nest)\n",
		"sum", (double)sum / 1000000.0);
	for (i = 0; i < (unsigned)KOF_T_COUNT; i++) {
		atomic_store(&g_slot[i].total, 0);
		atomic_store(&g_slot[i].calls, 0);
		t_nest[i].depth = 0;     /* the reporting thread's own nesting */
	}
}

#endif /* KOF_DEBUG */
