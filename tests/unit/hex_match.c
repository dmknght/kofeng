/*
 * hex_match - compile a hex pattern and match it, in one process.
 *
 * The compiler and the matcher are two halves of one encoding, and testing them
 * apart is how both halves pass while the pair is wrong: a compiler that writes a
 * gap one too wide and a matcher that reads it one too narrow agree with each other
 * and with nothing else. So every case here goes through kof_hex_compile and then
 * through the same kof_match_* the scanner calls.
 *
 * Three groups, and the third is the one that matters most:
 *
 *   matching     does the pattern mean what the syntax says
 *   refusing     does the compiler reject what it promised to reject
 *   bounds       does a compare near or past the end of the object stay inside it
 *
 * The bounds group exists because kof_find_str_at takes an offset a module worked
 * out from the file. That is the one number in the whole engine that is attacker
 * influenced and not bounded by construction, so the check that it is inside the
 * object is load bearing, and a test that only fed it sensible offsets would not
 * touch it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofmatchers/kofmatch.h"
#include "../../libkofeng/kofdb/kofpack.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* "4a1b" -> bytes. Returns the length, or -1. */
static int unhex(const char *t, uint8_t *out, size_t cap)
{
	size_t n = 0;

	while (*t) {
		unsigned v;

		if (*t == ' ') {
			t++;
			continue;
		}
		if (n >= cap || sscanf(t, "%2x", &v) != 1)
			return -1;
		out[n++] = (uint8_t)v;
		t += 2;
	}
	return (int)n;
}

/* ---- matching --------------------------------------------------------------- */

/*
 * `hay` is the object, `pat` the hex syntax, `want` the offset a match should be
 * found at or -1 for no match.
 *
 * Searched over the whole object with kof_match_in, then - when a match was
 * expected - compared at exactly that offset with kof_match_at, so the two entry
 * points are checked against each other rather than only against the test's
 * expectation.
 */
static void check(const char *tag, const char *pat, const char *hay, int want)
{
	uint8_t prog[KOF_HEX_MAX_PROG], data[512];
	struct kof_match_ctx m;
	struct kof_hex_stat st;
	uint32_t plen;
	int dlen, got;

	dlen = unhex(hay, data, sizeof data);
	if (dlen < 0) {
		fail(tag, "the test's own haystack is malformed");
		return;
	}

	plen = kof_hex_compile(pat, prog, sizeof prog, &st);
	if (plen == 0) {
		fail(tag, kof_hex_error());
		return;
	}

	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0)) {
		fail(tag, "out of memory");
		return;
	}
	kof_match_begin(&m, kof_buf_make(data, (uint64_t)dlen));

	got = kof_match_in(&m, 0, (uint64_t)dlen, prog, (uint16_t)plen,
			   KOF_STR_HEX, 0);
	if (got != (want >= 0))
		fail(tag, want >= 0 ? "searched and did not find it"
				    : "found something that is not there");

	if (want >= 0) {
		if (!kof_match_at(&m, (uint64_t)want, prog, (uint16_t)plen,
				  KOF_STR_HEX, 0))
			fail(tag, "does not compare equal at the offset it was "
				  "expected at");
		/* One byte off must not match, or the pattern is anchored on
		 * nothing and the search result above was luck. */
		if (want > 0 &&
		    kof_match_at(&m, (uint64_t)want - 1, prog, (uint16_t)plen,
				 KOF_STR_HEX, 0) &&
		    kof_match_at(&m, (uint64_t)want + 1, prog, (uint16_t)plen,
				 KOF_STR_HEX, 0))
			fail(tag, "matches at every neighbouring offset too");
	}
	kof_match_state_free(&m);
}

/* ---- refusing ---------------------------------------------------------------- */

static void refuse(const char *tag, const char *pat)
{
	uint8_t prog[KOF_HEX_MAX_PROG];

	if (kof_hex_compile(pat, prog, sizeof prog, NULL) != 0)
		fail(tag, "compiled a pattern that should have been refused");
}

/* ---- bounds ------------------------------------------------------------------ */

/*
 * A compare at every offset from inside the object to well past its end.
 *
 * Nothing is asserted about the answers except that they are answers: the point is
 * that the run completes without reading outside the mapping, which is what a
 * sanitizer build turns into a failure. The buffer is heap allocated for exactly
 * that reason - a static array has neighbours, and reading into them is not a
 * fault, so the bug would not show.
 */
static void bounds(const char *tag, const char *pat)
{
	uint8_t prog[KOF_HEX_MAX_PROG];
	struct kof_match_ctx m;
	uint8_t *data;
	uint32_t plen;
	uint64_t off;
	const uint64_t n = 64;

	plen = kof_hex_compile(pat, prog, sizeof prog, NULL);
	if (plen == 0) {
		fail(tag, kof_hex_error());
		return;
	}
	data = malloc((size_t)n);
	if (!data) {
		fail(tag, "out of memory");
		return;
	}
	memset(data, 0xe8, (size_t)n);

	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0)) {
		free(data);
		fail(tag, "out of memory");
		return;
	}
	kof_match_begin(&m, kof_buf_make(data, n));

	for (off = 0; off < n + 16; off++)
		(void)kof_match_at(&m, off, prog, (uint16_t)plen, KOF_STR_HEX, 0);

	/* The offsets a module could compute from a hostile file: enormous, and
	 * one that would wrap if the bound were written as off + len. */
	(void)kof_match_at(&m, UINT64_MAX, prog, (uint16_t)plen, KOF_STR_HEX, 0);
	(void)kof_match_at(&m, UINT64_MAX - 4, prog, (uint16_t)plen, KOF_STR_HEX, 0);
	(void)kof_match_in(&m, UINT64_MAX - 4, 64, prog, (uint16_t)plen,
			   KOF_STR_HEX, 0);
	(void)kof_match_in(&m, n - 1, UINT64_MAX, prog, (uint16_t)plen,
			   KOF_STR_HEX, 0);

	kof_match_state_free(&m);
	free(data);
}

int main(void)
{
	/*                                 0  1  2  3  4  5  6  7  8  9 */
	static const char hay[] = "90 90 e8 11 22 33 44 5d c3 90";

	/* --- the plain forms --- */
	check("literal",     "e8 11 22 33 44",       hay, 2);
	check("absent",      "e8 11 22 33 45",       hay, -1);
	check("wildcard",    "e8 ?? ?? ?? ?? 5d",    hay, 2);
	check("wild-first",  "?? ?? e8",             hay, 0);
	check("nibble-lo",   "e8 1?",                hay, 2);
	check("nibble-hi",   "e8 ?1",                hay, 2);
	check("nibble-miss", "e8 2?",                hay, -1);

	/* --- gaps --- */
	check("gap-exact",   "e8 [3] 44",            hay, 2);
	check("gap-range",   "e8 [2-4] 44",          hay, 2);
	check("gap-too-far", "e8 [4-6] 44",          hay, -1);
	check("gap-open",    "90 90 [-] c3",         hay, 0);
	check("gap-from",    "e8 [3-] 5d",           hay, 2);
	check("two-gaps",    "e8 [1-2] 22 [1-3] 5d", hay, 2);

	/* --- alternatives --- */
	check("alt-first",   "( e8 | e9 ) 11",       hay, 2);
	check("alt-second",  "( e7 | e8 ) 11",       hay, 2);
	check("alt-none",    "( e6 | e7 ) 11",       hay, -1);
	check("alt-lengths", "( e8 11 | 90 ) 22",    hay, 2);
	check("alt-short",   "( e8 11 | 90 ) 90",    hay, 0);
	check("alt-three",   "( 01 | 02 | e8 ) 11",  hay, 2);
	check("alt-then-gap", "( e8 | e9 ) [2-3] 44", hay, 2);

	/* --- edges --- */
	check("at-start",    "90 90 e8",             hay, 0);
	check("at-end",      "5d c3 90",             hay, 7);
	check("whole",       "90 90 e8 11 22 33 44 5d c3 90", hay, 0);
	check("longer-than", "90 90 e8 11 22 33 44 5d c3 90 90", hay, -1);

	/* --- what the compiler must refuse --- */
	refuse("lead-gap",    "[2-4] e8");
	refuse("trail-gap",   "e8 [2-4]");
	refuse("double-gap",  "e8 [2-4] [1-2] 90");
	refuse("gap-in-alt",  "( e8 [2] 11 | e9 )");
	refuse("nested-alt",  "( e8 | ( 11 | 22 ) )");
	refuse("all-wild",    "?? ?? ??");
	refuse("odd-digit",   "e8 1");
	refuse("bad-digit",   "e8 zz");
	refuse("empty",       "");
	refuse("empty-alt",   "( e8 | )");
	refuse("unclosed-alt", "( e8 | e9");
	refuse("unclosed-gap", "e8 [2-4 90");
	refuse("backwards-gap", "e8 [6-2] 90");
	refuse("huge-gap",    "e8 [4000-5000] 90");

	/* --- offsets a module could compute from a hostile file --- */
	bounds("bounds-plain", "e8 11 22 33");
	bounds("bounds-gap",   "e8 [1-8] 33");
	bounds("bounds-alt",   "( e8 | e9 ) [1-4] 33 44 55");

	printf("hex: compile and match %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
