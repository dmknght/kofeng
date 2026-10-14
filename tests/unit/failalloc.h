/*
 * failalloc.h - an allocator that can be told to refuse, for the tests that ask
 * "what does the engine SAY when memory is refused".
 *
 * malloc, calloc and realloc are interposed in the test program (the same way
 * funcs_status.c has always done for realloc): a call is numbered from the moment the test
 * arms the counter, and the one with the chosen number returns NULL. Two shapes:
 *
 *   fa_arm_nth(n)       the n-th allocation after the arm fails, once. n = 1 is the next.
 *   fa_arm_size(sz, k)  the k-th allocation of exactly `sz` bytes after the arm fails, once.
 *   fa_arm_min(sz, k)   the k-th allocation of AT LEAST `sz` bytes after the arm fails, once -
 *                       for a sweep over the allocations that are tables (a few dozen, the
 *                       big ones) and not over the thousands of small records around them.
 *
 *   fa_count()          allocations seen since the arm - run once unarmed (fa_arm_nth(0)) to
 *                       learn how many there are, then sweep 1..count.
 *   fa_hit()            whether the armed allocation was reached.
 *   fa_site()           the first frames above the allocator, as addresses of the caller
 *                       that was refused; fa_print_site() prints them. Addresses, not names:
 *                       the engine is not linked with -rdynamic, and a name resolved here
 *                       would be a second table to keep (resolve with addr2line).
 *
 * A SANITIZER OWNS malloc: under one none of this exists (FA_AVAILABLE is 0) and a test
 * reports its failing-allocation cases as skipped, the way funcs_status.c does. The cases that
 * do not need the hook (a memory ceiling set with keng_set_memory_cap, a table filled to its
 * limit) run in every build.
 *
 * Needs <execinfo.h> (glibc). The first backtrace() call may itself allocate, so it is made
 * once, disarmed, before any test asks.
 */

#ifndef KOFENG_TESTS_FAILALLOC_H
#define KOFENG_TESTS_FAILALLOC_H

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define FA_AVAILABLE 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define FA_AVAILABLE 0
#endif
#endif
#ifndef FA_AVAILABLE
#define FA_AVAILABLE 1
#endif

#if FA_AVAILABLE
#include <execinfo.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

#define FA_FRAMES 8

static volatile int  fa_on;                /* counting at all                    */
static volatile long fa_seen;              /* allocations since the arm          */
static volatile long fa_fail_nth;          /* the one to refuse, 0 = none        */
static volatile size_t fa_fail_size;       /* with fa_fail_nth: only this size   */
static volatile size_t fa_fail_min;        /* with fa_fail_nth: only this size and up */
static volatile long fa_size_seen;
static volatile int  fa_was_hit;
static void *fa_frames[FA_FRAMES];
static int   fa_nframes;

static int fa_refuse(size_t n)
{
	if (!fa_on)
		return 0;
	if (fa_fail_min && n < fa_fail_min)
		return 0;
	fa_seen++;
	if (!fa_fail_nth)
		return 0;
	if (fa_fail_size) {
		if (n != fa_fail_size || ++fa_size_seen != fa_fail_nth)
			return 0;
	} else if (fa_seen != fa_fail_nth) {
		return 0;
	}
	fa_on = 0;                              /* backtrace may allocate */
	fa_nframes = backtrace(fa_frames, FA_FRAMES);
	fa_was_hit = 1;
	fa_fail_nth = 0;
	fa_on = 1;
	errno = ENOMEM;
	return 1;
}

void *malloc(size_t n)
{
	return fa_refuse(n) ? NULL : __libc_malloc(n);
}

void *calloc(size_t a, size_t b)
{
	return fa_refuse(a * b) ? NULL : __libc_calloc(a, b);
}

void *realloc(void *p, size_t n)
{
	if (n && fa_refuse(n))
		return NULL;
	return __libc_realloc(p, n);
}

static __attribute__((unused)) void fa_init(void)
{
	void *f[2];

	(void)backtrace(f, 2);                  /* load libgcc now, not inside a refusal */
}

static __attribute__((unused)) void fa_arm_nth(long n)
{
	fa_seen = 0;
	fa_size_seen = 0;
	fa_fail_nth = n;
	fa_fail_size = 0;
	fa_fail_min = 0;
	fa_was_hit = 0;
	fa_nframes = 0;
	fa_on = 1;
}

static __attribute__((unused)) void fa_arm_size(size_t size, long k)
{
	fa_arm_nth(k);
	fa_fail_size = size;
}

static __attribute__((unused)) void fa_arm_min(size_t size, long k)
{
	fa_arm_nth(k);
	fa_fail_min = size;
}

static __attribute__((unused)) long fa_count(void)
{
	return fa_seen;
}

static __attribute__((unused)) int fa_disarm_hit(void)
{
	int h = fa_was_hit;

	fa_on = 0;
	fa_fail_nth = 0;
	return h;
}

static __attribute__((unused)) void fa_print_site(void)
{
	int i;

	for (i = 2; i < fa_nframes; i++)
		printf(" %p", fa_frames[i]);
}
#else
static __attribute__((unused)) void fa_init(void) {}
static __attribute__((unused)) void fa_arm_nth(long n) { (void)n; }
static __attribute__((unused)) void fa_arm_size(size_t s, long k) { (void)s; (void)k; }
static __attribute__((unused)) void fa_arm_min(size_t s, long k) { (void)s; (void)k; }
static __attribute__((unused)) long fa_count(void) { return 0; }
static __attribute__((unused)) int fa_disarm_hit(void) { return 0; }
static __attribute__((unused)) void fa_print_site(void) {}
#endif

#endif /* KOFENG_TESTS_FAILALLOC_H */
