/*
 * known_miss.h - a check that records a MISS the engine has today, and goes
 * red the day the engine stops having it.
 *
 *   KM_CHECK(correct, "what", "CAP_NAME")
 *
 * `correct` is the condition that is TRUE when the engine does the right
 * thing: the diagnose matches, the flag is raised, the symbol is kept. Written
 * as the expectation, never as the bug.
 *
 *   engine wrong today   correct == 0   prints `KNOWN-MISS <what> (cap: <name>)`
 *                                       and counts as a pass, so the suite is
 *                                       green while the cap is there.
 *   engine right         correct != 0   prints `FIXED-UNEXPECTEDLY ...` and
 *                                       FAILS, because a marker that no longer
 *                                       describes the engine is a lie the next
 *                                       reader will believe. The fix is to
 *                                       change the KM_CHECK to a CK.
 *
 * A test that returns km_failed() from main is red exactly when a cap is
 * fixed, which is the moment the marker has to come out.
 *
 * NOT A SKIP. A skipped check proves nothing; this one is evaluated every run
 * and fails if the miss disappears.
 *
 *   KM_WARN(correct, "what: numbers", ...)
 *
 * The third state, for a SHORTFALL that has no single cap to name and no
 * condition that should go red the day it is fixed: the engine opens fewer
 * children than a container holds, a limit is lower than a real file needs. It
 * prints `WARN <what>` and is counted; it never fails the run and never goes red
 * when the shortfall disappears (a warning that stops printing needs no edit).
 * `what` is printf-style so the line carries the NUMBERS (entries, children,
 * the broken reason) a reader needs to see how far the engine is from correct.
 * A test that uses it ends with km_summary(), which prints one line,
 * `warnings: N`, so `make unit 2>&1 | grep -E '^(WARN|warnings: [1-9])'` finds
 * every one. Use KM_CHECK instead when one named cap explains the miss and
 * turning it into a CK is the fix.
 */

#ifndef KOFENG_TESTS_KNOWN_MISS_H
#define KOFENG_TESTS_KNOWN_MISS_H

#include <stdio.h>

static unsigned km_known_n, km_fixed_n, km_warn_n;

#define KM_CHECK(correct, what, cap) do { \
	if ((correct)) { \
		printf("  FIXED-UNEXPECTEDLY %s (cap: %s) - the engine is right now: " \
		       "turn this KM_CHECK into a normal check (%s:%d)\n", \
		       (what), (cap), __FILE__, __LINE__); \
		km_fixed_n++; \
	} else { \
		printf("  KNOWN-MISS %s (cap: %s)\n", (what), (cap)); \
		km_known_n++; \
	} \
} while (0)

#define KM_WARN(correct, ...) do { \
	if (!(correct)) { \
		printf("WARN "); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		km_warn_n++; \
	} \
} while (0)

/* Non-zero when a marker is stale. A test returns `fails != 0 || km_failed()`. */
static inline int km_failed(void)
{
	return km_fixed_n != 0;
}

static inline unsigned km_known(void)
{
	return km_known_n;
}

static inline unsigned km_warned(void)
{
	return km_warn_n;
}

/* The one line a run ends with when it uses KM_WARN. */
static inline void km_summary(void)
{
	printf("warnings: %u\n", km_warn_n);
}

#endif /* KOFENG_TESTS_KNOWN_MISS_H */
