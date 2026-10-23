#ifndef KOF_TEST_WORK_COUNT_H
#define KOF_TEST_WORK_COUNT_H

/*
 * work_count.h - how much WORK a routine does, counted, for the tests that assert a bound and not a time (tests/lib/genome/textual_work.h adds the lexer's driver).
 *
 * A quadratic loop is a loop over the input inside a loop over the input; its time depends on the machine, its count of executed basic blocks does not. The test
 * is compiled with gcc's `-fsanitize-coverage=trace-pc` (added to it by UNIT_LIBS_<name> in mk/tests.mk), which calls __sanitizer_cov_trace_pc at the start of every
 * basic block of the translation unit; this header defines that call as a counter. The code under test is #included into the test (white box, like the tests that
 * include a private header), so its blocks are counted, and the archive's copy of it is not linked: every symbol it exports is defined by the test. Production code
 * carries no counter and no hook.
 *
 * ASSERTIONS: the same input shape at n and at 4n bytes. A linear reader's work grows by about 4, a quadratic one's by about 16: `work_grows_linearly` asks for at
 * most 6, and for at most `per_byte` blocks a byte at the larger size, which is the absolute bound. The numbers the test prints are counts of blocks.
 *
 * work_selfcheck() fails the test when the instrumentation is not there (a build that lost the flag would count 0 and pass everything).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* volatile: the instrumentation calls are added after the optimiser has run, so it does not know the callback reads and writes these, and would drop the stores around a measured call */
static volatile uint64_t work_n;
static volatile int work_on;

#if defined(__clang__)
#define WORK_NO_COV __attribute__((no_sanitize("coverage")))
#else
#define WORK_NO_COV __attribute__((no_sanitize_coverage))
#endif

void __sanitizer_cov_trace_pc(void);
WORK_NO_COV void __sanitizer_cov_trace_pc(void)
{
	if (work_on)
		work_n++;
}

#define WORK_BEGIN() do { work_n = 0; work_on = 1; } while (0)

static inline uint64_t work_end(void)
{
	work_on = 0;
	return (uint64_t)work_n;
}

static volatile uint32_t work_sink;

static inline int work_selfcheck(void)
{
	uint32_t i;
	uint64_t w;

	WORK_BEGIN();
	for (i = 0; i < 1000u; i++)
		work_sink += i;
	w = work_end();
	if (w < 1000u) {
		printf("  FAIL the work counter counted %llu blocks for a loop of 1000: the test was not built with -fsanitize-coverage=trace-pc (UNIT_LIBS_<name>)\n",
		       (unsigned long long)w);
		return 0;
	}
	return 1;
}

/* Work `w2` at `n2` bytes against `w1` at `n1` (n2 = 4 n1): linear growth, and at most `per_byte` blocks a byte. 1 when it holds. */
static inline int work_grows_linearly(const char *what, uint64_t w1, uint64_t n1, uint64_t w2, uint64_t n2, uint64_t per_byte)
{
	int ok = w2 <= 6u * w1 + 64u && w2 <= per_byte * n2;

	if (!ok)
		printf("  FAIL %s: %llu blocks at %llu bytes, %llu at %llu (x%.1f; linear is x4, quadratic x16; bound %llu a byte)\n", what, (unsigned long long)w1,
		       (unsigned long long)n1, (unsigned long long)w2, (unsigned long long)n2, (double)w2 / (double)(w1 ? w1 : 1u), (unsigned long long)per_byte);
	return ok;
}

#endif /* KOF_TEST_WORK_COUNT_H */
