/*
 * oom_harness.h - the one harness of the memory tests: allocation-failure injection and a flat-heap check, for every public API to reuse.
 *
 * WHY IT IS ONE HEADER. audit_mem found leaks on error paths (MEM-7: a filter bank left when the table of parts was refused) that no answer-checking test
 * could see, and mem_oom_open pinned it with a private copy of an allocation tracker. Each API that owns memory (open/close, catalog, scanner, explain,
 * filemap, path walk) needs the same two questions asked of it, so the tracker lives here and a test supplies only a PHASE: a function that opens, uses and
 * closes, and gives back whatever it was given.
 *
 *   oh_sweep   refuse the n-th allocation of the phase, for every n, and ask that (1) the phase returns (no crash, no hang), (2) every block the engine
 *              allocated has been freed when it ends, (3) an optional judge accepts the status it returned (the status is a value, not "whatever").
 *   oh_flat    run the phase again and again: the blocks and bytes the engine holds, the open descriptors and the resident set do not grow.
 *
 * LINKING. The allocator is WRAPPED, not interposed: the test is linked with `$(OOM_WRAP)` (mk/tests.mk: UNIT_LIBS_<name> := $(OOM_WRAP)), the linker
 * routes malloc/calloc/realloc/free of the engine and of the test through the functions below, so the same test runs under a sanitizer, and what is counted
 * is what the engine allocated, not what libc keeps for itself (a stdio buffer, an open directory). Include this header in ONE translation unit of the test.
 * A block allocated by libc (strdup, getline) and freed by the engine is not in the table and its free is ignored.
 *
 * WHAT A PHASE MUST DO. Be deterministic in the number of allocations it makes (no threads that race for the order, no time), and end with everything it
 * made freed: it is run once to settle what libc and the engine keep for good (a first stdio buffer, a lazily built static table), once to count, then once
 * per refused allocation. A phase that has not settled is reported by the clean run itself ("a clean phase keeps N blocks").
 *
 * NOTHING HERE TOUCHES THE ENGINE: no engine header is included.
 */

#ifndef KOFENG_TESTS_OOM_HARNESS_H
#define KOFENG_TESTS_OOM_HARNESS_H

#define _GNU_SOURCE

#include <dirent.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
void __wrap_free(void *p);

#define OH_UNUSED __attribute__((unused))
#define OH_TAB_SIZE (1u << 18)
#define OH_FRAMES 6

struct oh_live {
	void *p;
	size_t size;
	unsigned long serial;
	void *frame[OH_FRAMES];
	int nframe;
};

static struct oh_live oh_tab[OH_TAB_SIZE];
static unsigned long oh_serial, oh_seen, oh_fail_at;
static long oh_n_live;
static size_t oh_bytes_live;
static int oh_armed;
static int oh_failures;

#define OHK(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); oh_failures++; } } while (0)

static size_t oh_slot_of(const void *p)
{
	return (size_t)(((uintptr_t)p >> 4) * 0x9E3779B1u) & (OH_TAB_SIZE - 1u);
}

static void oh_track_add(void *p, size_t size)
{
	size_t i;

	if (!p)
		return;
	for (i = oh_slot_of(p); oh_tab[i].p; i = (i + 1u) & (OH_TAB_SIZE - 1u))
		;
	oh_tab[i].p = p;
	oh_tab[i].size = size;
	oh_tab[i].serial = ++oh_serial;
	oh_tab[i].nframe = backtrace(oh_tab[i].frame, OH_FRAMES);
	oh_n_live++;
	oh_bytes_live += size;
}

static void oh_track_del(void *p)
{
	size_t i, j, k;

	if (!p)
		return;
	for (i = oh_slot_of(p); oh_tab[i].p; i = (i + 1u) & (OH_TAB_SIZE - 1u))
		if (oh_tab[i].p == p)
			break;
	if (!oh_tab[i].p)
		return;                         /* not ours: libc allocated it and the engine freed it */
	oh_n_live--;
	oh_bytes_live -= oh_tab[i].size;
	for (j = i, k = (i + 1u) & (OH_TAB_SIZE - 1u); oh_tab[k].p; k = (k + 1u) & (OH_TAB_SIZE - 1u)) {   /* backward shift: no tombstones */
		size_t h = oh_slot_of(oh_tab[k].p);

		if (((k - h) & (OH_TAB_SIZE - 1u)) >= ((k - j) & (OH_TAB_SIZE - 1u))) {
			oh_tab[j] = oh_tab[k];
			j = k;
		}
	}
	memset(&oh_tab[j], 0, sizeof oh_tab[j]);
}

/*
 * THREAD SAFE, because kscan_path_mt allocates from several threads: one mutex around the table and the counters, and a per-thread flag so that an allocation made
 * by the tracker itself (backtrace, the first time) is passed through untracked instead of taking the mutex it already holds. With more than one thread the ORDER of
 * allocations is not fixed, so oh_sweep (which refuses "the n-th") is for single-threaded phases; oh_flat is for any.
 */
static pthread_mutex_t oh_mu = PTHREAD_MUTEX_INITIALIZER;
static __thread int oh_in;

static void *oh_site[8];
static int oh_site_n;

/* The frames above the refused allocation are kept: a judge that rejects the status of a refusal prints where the engine was asked for the block. */
static int oh_refuse(void)
{
	if (oh_armed && ++oh_seen == oh_fail_at) {
		oh_site_n = backtrace(oh_site, 8);
		return 1;
	}
	return 0;
}

void *__wrap_malloc(size_t n)
{
	void *p;

	if (oh_in)
		return __real_malloc(n);
	pthread_mutex_lock(&oh_mu);
	oh_in = 1;
	p = oh_refuse() ? NULL : __real_malloc(n);
	oh_track_add(p, n);
	oh_in = 0;
	pthread_mutex_unlock(&oh_mu);
	return p;
}

void *__wrap_calloc(size_t a, size_t b)
{
	void *p;

	if (oh_in)
		return __real_calloc(a, b);
	pthread_mutex_lock(&oh_mu);
	oh_in = 1;
	p = oh_refuse() ? NULL : __real_calloc(a, b);
	oh_track_add(p, a * b);
	oh_in = 0;
	pthread_mutex_unlock(&oh_mu);
	return p;
}

void *__wrap_realloc(void *p, size_t n)
{
	void *q;

	if (oh_in)
		return __real_realloc(p, n);
	pthread_mutex_lock(&oh_mu);
	oh_in = 1;
	if (n && oh_refuse()) {
		oh_in = 0;
		pthread_mutex_unlock(&oh_mu);
		return NULL;
	}
	q = __real_realloc(p, n);
	if (q != p || n) {
		oh_track_del(p);
		oh_track_add(q, n);
	}
	oh_in = 0;
	pthread_mutex_unlock(&oh_mu);
	return q;
}

void __wrap_free(void *p)
{
	if (oh_in) {
		__real_free(p);
		return;
	}
	pthread_mutex_lock(&oh_mu);
	oh_in = 1;
	oh_track_del(p);
	oh_in = 0;
	pthread_mutex_unlock(&oh_mu);
	__real_free(p);
}

/* ---- the numbers a phase is judged by ---------------------------------------------------------------- */

static OH_UNUSED long oh_live_blocks(void) { return oh_n_live; }
static OH_UNUSED size_t oh_live_bytes(void) { return oh_bytes_live; }

/* The allocations made while armed, since the last arm. */
static OH_UNUSED unsigned long oh_allocs(void) { return oh_seen; }

static OH_UNUSED unsigned oh_open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	unsigned n = 0;

	if (!d)
		return 0;
	while (readdir(d))
		n++;
	closedir(d);
	return n;
}

static OH_UNUSED long oh_rss_kb(void)
{
	FILE *f = fopen("/proc/self/statm", "r");
	long pages = 0, rss = 0;

	if (!f)
		return 0;
	if (fscanf(f, "%ld %ld", &pages, &rss) != 2)
		rss = 0;
	fclose(f);
	return rss * (sysconf(_SC_PAGESIZE) / 1024);
}

/* libgcc is loaded now, not inside a refusal (backtrace allocates the first time). */
static OH_UNUSED void oh_init(void)
{
	void *warm[2];

	(void)backtrace(warm, 2);
}

/* ---- a phase, and the sweep over it ------------------------------------------------------------------- */

/* A phase does one complete use of an API and gives everything back. It answers a status (any int) so a judge can ask what it said. */
typedef int (*oh_phase)(void *ctx);

/*
 * A judge sees the status of a phase run with the n-th allocation refused (`n`; 0 = the clean run) beside the status of the clean run.
 * It returns 0 when that is an acceptable answer. NULL: any status is accepted.
 */
typedef int (*oh_judge)(void *ctx, unsigned long n, int rc, int clean_rc);

struct oh_sweep_res {
	unsigned long allocs;           /* what the clean phase allocated */
	unsigned long refused;          /* refusals that were reached */
	unsigned long leaked;           /* refusals after which a block stayed */
	unsigned long judged_bad;       /* refusals whose status the judge rejected */
	int clean_rc;
};

static OH_UNUSED void oh_print_leak_site(unsigned long mark)
{
	size_t i;

	for (i = 0; i < OH_TAB_SIZE; i++)
		if (oh_tab[i].p && oh_tab[i].serial > mark) {
			fflush(stdout);
			backtrace_symbols_fd(oh_tab[i].frame + 1, oh_tab[i].nframe - 1, 1);
			break;
		}
}

/*
 * Settle, count, then refuse every allocation in turn. `min_allocs` is the floor under which the sweep would prove nothing (a phase that allocates ten
 * times is not an open/scan/close). A leak is reported once and then forgotten, so the next refusal is judged on its own.
 */
static OH_UNUSED struct oh_sweep_res oh_sweep(const char *what, oh_phase fn, void *ctx, oh_judge judge, unsigned long min_allocs)
{
	struct oh_sweep_res r;
	unsigned long n, mark;
	long before;
	int rc;

	memset(&r, 0, sizeof r);
	oh_init();
	(void)fn(ctx);                          /* settle: what a clean phase leaves in the process for good */
	before = oh_n_live;
	oh_armed = 1;
	oh_seen = 0;
	oh_fail_at = 0;                         /* count only */
	r.clean_rc = fn(ctx);
	oh_armed = 0;
	r.allocs = oh_seen;
	OHK(oh_n_live == before, "%s: a clean phase keeps %ld blocks", what, oh_n_live - before);
	OHK(r.allocs >= min_allocs, "%s: a phase makes only %lu allocations (floor %lu): the sweep would prove nothing", what, r.allocs, min_allocs);
	if (judge)
		OHK(judge(ctx, 0, r.clean_rc, r.clean_rc) == 0, "%s: the judge rejects the clean answer %d", what, r.clean_rc);
	before = oh_n_live;
	for (n = 1; n <= r.allocs + 2u; n++) {
		size_t i;

		mark = oh_serial;
		oh_seen = 0;
		oh_fail_at = n;
		oh_armed = 1;
		rc = fn(ctx);
		oh_armed = 0;
		if (oh_seen >= n)
			r.refused++;
		if (judge && judge(ctx, n, rc, r.clean_rc) != 0) {
			if (r.judged_bad++ < 4u) {
				printf("  FAIL %s: refusing allocation %lu gave status %d (clean %d), rejected by the judge; the refused block was asked for from:\n", what, n, rc, r.clean_rc);
				fflush(stdout);
				backtrace_symbols_fd(oh_site + 1, oh_site_n > 1 ? oh_site_n - 1 : 0, 1);
			}
		}
		if (oh_n_live == before)
			continue;
		if (r.leaked++ < 4u) {
			printf("  FAIL %s: refusing allocation %lu left %ld block(s) behind, asked for from:\n", what, n, oh_n_live - before);
			oh_print_leak_site(mark);
		}
		for (i = 0; i < OH_TAB_SIZE; i++)
			if (oh_tab[i].p && oh_tab[i].serial > mark)
				oh_tab[i].serial = 0;
		before = oh_n_live;
	}
	OHK(r.leaked == 0u, "%s: %lu of %lu refused allocations left blocks behind (the first frames above)", what, r.leaked, r.allocs);
	OHK(r.judged_bad == 0u, "%s: %lu refused allocations gave a status the judge rejected", what, r.judged_bad);
	OHK(r.refused + 2u >= r.allocs, "%s: only %lu of %lu refusals were reached (the phase is not deterministic)", what, r.refused, r.allocs);
	printf("  %s: %lu allocations refused in turn, %lu leaked, %lu statuses rejected\n", what, r.allocs, r.leaked, r.judged_bad);
	return r;
}

/*
 * Flat heap: `rounds` runs after two to settle. Blocks and bytes the engine holds must be EQUAL at the end (the table counts only what the engine
 * allocated, so an exact figure is fair: "within 5 percent" lets a leak of a byte per object through), the descriptors the same, and the resident set
 * may grow by at most `rss_slack_kb` (memory the table cannot see: a mapping, a spill). Returns the number of failed assertions.
 */
static OH_UNUSED int oh_flat(const char *what, oh_phase fn, void *ctx, unsigned rounds, long rss_slack_kb)
{
	unsigned i, fds0, fds1;
	long b0, b1, rss0, rss1;
	size_t y0, y1;
	int bad = oh_failures;

	oh_init();
	(void)fn(ctx);
	(void)fn(ctx);
	b0 = oh_n_live;
	y0 = oh_bytes_live;
	fds0 = oh_open_fds();
	rss0 = oh_rss_kb();
	for (i = 0; i < rounds; i++)
		(void)fn(ctx);
	b1 = oh_n_live;
	y1 = oh_bytes_live;
	fds1 = oh_open_fds();
	rss1 = oh_rss_kb();
	OHK(b1 == b0, "%s: %u rounds grew the heap by %ld blocks", what, rounds, b1 - b0);
	OHK(y1 == y0, "%s: %u rounds grew the heap by %ld bytes", what, rounds, (long)y1 - (long)y0);
	OHK(fds1 == fds0, "%s: %u rounds changed the open descriptors %u -> %u", what, rounds, fds0, fds1);
	OHK(rss1 - rss0 <= rss_slack_kb, "%s: %u rounds grew the resident set by %ld KiB (allowed %ld)", what, rounds, rss1 - rss0, rss_slack_kb);
	printf("  %s: flat over %u rounds (blocks %ld, bytes %lu, fds %u, rss +%ld KiB)\n", what, rounds, b1, (unsigned long)y1, fds1, rss1 - rss0);
	return oh_failures - bad;
}

#endif /* KOFENG_TESTS_OOM_HARNESS_H */
