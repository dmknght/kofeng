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

#include <stdint.h>
#include <stdio.h>
#include <time.h>

static const char *const slot_name[KOF_T_COUNT] = {
	"db load", "parse", "unpack", "heur", "emulate", "match",
	"diag syscall", "diag symbol", "diag emulate", "diag apihash",
	"diag match"
};

struct slot {
	uint64_t total;         /* nanoseconds, outermost spans only */
	uint64_t started;
	uint64_t calls;         /* entries, including re-entries     */
	unsigned depth;
};

static struct slot g_slot[KOF_T_COUNT];

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
	g_slot[s].calls++;
	/* Only the outermost entry starts the clock - see the note on nesting
	 * in the header. */
	if (!g_slot[s].depth++)
		g_slot[s].started = now_ns();
}

void kof_time_end(enum kof_time_slot s)
{
	if ((unsigned)s >= (unsigned)KOF_T_COUNT || !g_slot[s].depth)
		return;
	if (!--g_slot[s].depth && g_slot[s].started)
		g_slot[s].total += now_ns() - g_slot[s].started;
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
		g_slot[i].total = 0;
		g_slot[i].calls = 0;
		g_slot[i].depth = 0;
	}
}

#endif /* KOF_DEBUG */
