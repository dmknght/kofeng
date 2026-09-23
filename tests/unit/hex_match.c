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

#include "../../libkofeng/detector/matchers/kofmatch.h"
#include "../../libkofeng/databases/dbcore.h"

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

/* ---- the case and word options ------------------------------------------- */

/*
 * A HEX PATTERN'S OPTIONS, THROUGH THE SAME DOOR THE SCANNER USES.
 *
 * These arrived late: the declaration took them, the build printed them, and
 * four separate gates each had to be taught what they mean -
 *
 *     find_lit       the anchor search, which produces the candidates
 *     hex_walk       the byte comparison, and the boundary at the match's end
 *     gram_admits    the presence index, which rules an object out
 *     kofmultimatch  the memo table, whose answer is final
 *
 * Every one of them answered "no match" on its own, so a test that exercised
 * three of them would have passed while the pattern found nothing. This goes
 * through kof_match_in, which is what a module's kof_find_str_any reaches, so
 * all four are on the path.
 */
static void opt(const char *tag, const char *pat, const char *hay,
		uint8_t flags, int want)
{
	uint8_t prog[KOF_HEX_MAX_PROG], data[512];
	struct kof_match_ctx m;
	struct kof_hex_stat st;
	uint32_t plen;
	int dlen, got;

	dlen = unhex(hay, data, sizeof data);
	plen = kof_hex_compile(pat, prog, sizeof prog, &st);
	if (dlen < 0 || plen == 0) {
		fail(tag, "the test's own fixture is malformed");
		return;
	}
	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0)) {
		fail(tag, "out of memory");
		return;
	}
	kof_match_begin(&m, kof_buf_make(data, (uint64_t)dlen));
	got = kof_match_in(&m, 0, (uint64_t)dlen, prog, (uint16_t)plen,
			   KOF_STR_HEX, flags);
	if (got != want)
		fail(tag, want ? "the option refused a match it should allow"
			       : "the option allowed a match it should refuse");
	kof_match_state_free(&m);
}

static void hex_options(void)
{
	/* "cmd.exe" as bytes, and the four haystacks that tell the two options
	 * apart: same case or not, standing alone or not. */
	static const char *P = "63 6D 64 2E 65 78 65";
	/* " cmd.exe " / " CMD.EXE " / "xcmd.exey" / " CMD.EXEy" */
	static const char *lo_free  = "20 63 6D 64 2E 65 78 65 20";
	static const char *up_free  = "20 43 4D 44 2E 45 58 45 20";
	static const char *lo_bound = "78 63 6D 64 2E 65 78 65 79";
	static const char *up_bound = "20 43 4D 44 2E 45 58 45 79";

	/* No options: the bytes as written, anywhere. */
	opt("hex plain finds its own case", P, lo_free, 0, 1);
	opt("hex plain refuses another case", P, up_free, 0, 0);
	opt("hex plain matches inside a word", P, lo_bound, 0, 1);

	/* ICASE: letters fold, and only letters - "." is 0x2E either way. */
	opt("hex icase finds the other case", P, up_free, KOF_STR_ICASE, 1);
	opt("hex icase still finds its own", P, lo_free, KOF_STR_ICASE, 1);

	/* FULLWORD: the neighbours decide, and for hex the far one is only
	 * known once the walk has run. */
	opt("hex fullword alone", P, lo_free, KOF_STR_FULLWORD, 1);
	opt("hex fullword inside a word", P, lo_bound, KOF_STR_FULLWORD, 0);

	/* Both together, which is the pair a real marker uses. */
	opt("hex icase+fullword alone", P, up_free,
	    KOF_STR_ICASE | KOF_STR_FULLWORD, 1);
	opt("hex icase+fullword in a word", P, up_bound,
	    KOF_STR_ICASE | KOF_STR_FULLWORD, 0);

	/*
	 * A NEGATED BYTE IS NOT FOLDED, and this is the case that can tell.
	 *
	 * "!63" is any byte but 'c'. 'C' is not 'c', so it matches - and it has
	 * to keep matching under ICASE, because "anything but this letter"
	 * folded would quietly become "anything but either case", which is a
	 * broader claim than what was written and would refuse this.
	 *
	 * The masked case cannot be tested this way and does not need to be: a
	 * nibble mask zeroes the nibble it covers, so the stored byte is never
	 * a letter and the fold could not apply to it however it were written.
	 * The explicit test for a whole-byte mask in alt_at makes that true by
	 * construction rather than by how the compiler happens to store it.
	 */
	opt("hex icase does not fold a negated byte", "20 !63 20",
	    "20 43 20", KOF_STR_ICASE, 1);
}

/* ---- regex: the same program, a second syntax ---------------------------- */

/*
 * WHAT IS BEING TESTED IS THE REFUSALS AS MUCH AS THE MATCHES.
 *
 * The point of compiling a regex to the hex program is that the dangerous
 * constructs are not slow here, they are unrepresentable - so each one has to
 * come back as a build error naming what to write instead, rather than as a
 * pattern that quietly means something narrower.
 */
static void rx(const char *tag, const char *pat, const char *hay, int want)
{
	uint8_t prog[KOF_HEX_MAX_PROG], data[512];
	struct kof_match_ctx m;
	struct kof_hex_stat st;
	uint32_t plen;
	int dlen, got;

	dlen = (int)strlen(hay);
	if (dlen > (int)sizeof data)
		dlen = (int)sizeof data;
	memcpy(data, hay, (size_t)dlen);

	plen = kof_regex_compile(pat, prog, sizeof prog, &st);
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
	if (got != want)
		fail(tag, want ? "searched and did not find it"
			       : "found something that is not there");
	kof_match_state_free(&m);
}

static void rx_no(const char *tag, const char *pat)
{
	uint8_t prog[KOF_HEX_MAX_PROG];

	if (kof_regex_compile(pat, prog, sizeof prog, NULL) != 0)
		fail(tag, "compiled something that cannot be walked forward");
}

static void regex_forms(void)
{
	/* Literals coalesce into one run. */
	rx("regex literal", "GET /index.php", "xx GET /index.php yy", 1);
	rx("regex literal refuses another", "GET /index.php",
	   "xx GET /index.asp yy", 0);

	/* "." is any byte and joins the run it is in. */
	rx("regex dot", "GET /inde..php", "xx GET /index.php yy", 1);

	/* A class is its own step and a 256-bit set. */
	rx("regex class", "GET /[a-z]ndex", "xx GET /index.php", 1);
	rx("regex class refuses outside the set", "GET /[0-9]ndex",
	   "xx GET /index.php", 0);
	rx("regex negated class", "GET /[^0-9]ndex", "xx GET /index.php", 1);

	/* An exact count repeats; the copies are the same set. */
	rx("regex counted class", "/[a-z]{5}\\.php", "xx /index.php yy", 1);
	rx("regex counted class is exact", "/[a-z]{4}\\.php",
	   "xx /index.php yy", 0);

	/* A variable count of "." is the program's gap. */
	rx("regex gap", "GET .{1,8}\\.php", "xx GET /index.php yy", 1);
	rx("regex gap too short", "GET .{1,2}\\.php", "xx GET /index.php yy", 0);

	/* A group is one step with alternatives. */
	rx("regex group first", "/(index|home)\\.php", "xx /index.php", 1);
	rx("regex group second", "/(index|home)\\.php", "xx /home.php", 1);
	rx("regex group neither", "/(index|home)\\.php", "xx /admin.php", 0);

	/* Escapes, so a pattern can name the syntax's own characters. */
	rx("regex escaped dot", "index\\.php", "xx index.php", 1);
	rx("regex escaped dot is literal", "index\\.php", "xx indexAphp", 0);
	rx("regex hex escape", "A\\x42C", "xx ABC yy", 1);

	/*
	 * THE REFUSALS. Each of these is a construct that would need either
	 * backtracking or optionality, and neither exists in the program.
	 */
	rx_no("regex refuses *", "abc*");
	rx_no("regex refuses +", "abc+");
	rx_no("regex refuses ?", "abc?");
	rx_no("regex refuses an open count", "a{2,}");
	rx_no("regex refuses a variable count on a class", "[a-z]{2,4}");
	rx_no("regex refuses a counted group", "(ab|cd){2}");
	rx_no("regex refuses a nested group", "(a(b|c))");
	rx_no("regex refuses a class in an alternative", "(a|[b-d])");
	rx_no("regex refuses an empty class", "a[]b");
	rx_no("regex refuses an unclosed class", "a[b-d");
	rx_no("regex refuses an unclosed group", "a(b|c");
	rx_no("regex refuses a backwards range", "[z-a]");
	rx_no("regex refuses a count with nothing before it", "{2}");
	rx_no("regex refuses an empty pattern", "");
	rx_no("regex refuses a trailing gap", "abcd.{1,4}");

	/*
	 * AND THE ANCHOR, which is not a rule this front end applies - a class
	 * contributes no concrete byte, so a pattern made of classes has no run
	 * for the prefilter to key on and the shared back end refuses it. That
	 * is the whole of "a regex must have an anchor".
	 */
	rx_no("regex refuses a pattern with no anchor", "[a-z][0-9][a-z]");
}

int main(void)
{
	hex_options();
	regex_forms();
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

	/*
	 * --- a group is a CHOICE AT THIS POSITION, not a jump ---
	 *
	 * YARA's own examples, because that is the syntax this claims to be:
	 * "F4 23 ( 62 B4 | 56 ) 45" matches F42362B445 and F4235645. The third
	 * case is the one that says it is not a gap - a byte BETWEEN the group
	 * and what follows it must not match.
	 */
	check("yara-alt-long",  "f4 23 ( 62 b4 | 56 ) 45",
	      "00 f4 23 62 b4 45", 1);
	check("yara-alt-short", "f4 23 ( 62 b4 | 56 ) 45",
	      "00 f4 23 56 45", 1);
	check("alt-is-not-gap", "f4 23 ( 62 b4 | 56 ) 45",
	      "00 f4 23 56 99 45", -1);
	check("yara-alt-wild",  "f4 23 ( 62 b4 | 56 | 45 ?? 67 ) 45",
	      "00 f4 23 45 99 67 45", 1);

	/*
	 * --- "!" is a byte that is anything BUT this ---
	 *
	 * YARA 4.3 spells it "~" and both are read. The nibble form is the one
	 * worth pinning: "!?0" excludes only the low nibble, so a byte that
	 * differs in the HIGH nibble and still ends in 0 must not match.
	 */
	check("not-byte",      "f4 23 !00 62 b4", "f4 23 01 62 b4", 0);
	check("not-byte-miss", "f4 23 !00 62 b4", "f4 23 00 62 b4", -1);
	check("not-tilde",     "f4 23 ~00 62 b4", "f4 23 ff 62 b4", 0);
	check("not-nibble",    "f4 23 !?0 62 b4", "f4 23 11 62 b4", 0);
	check("not-nibble-lo", "f4 23 !?0 62 b4", "f4 23 10 62 b4", -1);
	check("not-nibble-hi", "f4 23 !?0 62 b4", "f4 23 a0 62 b4", -1);
	check("not-in-alt",    "41 ( !42 | 43 ) 44", "41 43 44", 0);
	check("not-in-alt-no", "41 ( !42 42 | 43 43 ) 44", "41 42 42 44", -1);

	/*
	 * A NEGATED BYTE IS NOT A CONCRETE ONE. It names every value but one,
	 * so counting it into the anchor would have the matcher search for a
	 * byte the pattern forbids - and then find the pattern nowhere. The run
	 * here is "62 b4", after the exclusion, not "f4 23 !00 62 b4".
	 */
	{
		uint8_t prog[KOF_HEX_MAX_PROG];
		struct kof_hex_stat st;

		memset(&st, 0, sizeof st);
		if (!kof_hex_compile("f4 !00 62 b4 c1", prog, sizeof prog, &st))
			fail("not-anchor", kof_hex_error());
		else if (st.anchor_len != 3u)
			fail("not-anchor",
			     "the anchor run counted a negated byte");
	}

	/*
	 * --- a word folded per character, which is what the cap is for ---
	 *
	 * "cmd.exe" in quotes is nine parts. At a cap of eight the first thing
	 * anybody writes was refused; see KOF_HEX_MAX_STEPS for why raising it
	 * costs almost nothing.
	 */
	check("icase-word",
	      "22(63|43)(6d|4d)(64|44)2e(65|45)(78|58)(65|45)22",
	      "00 22 63 6d 64 2e 65 78 65 22", 1);
	check("icase-word-mixed",
	      "22(63|43)(6d|4d)(64|44)2e(65|45)(78|58)(65|45)22",
	      "00 22 43 6d 44 2e 45 78 65 22", 1);
	check("icase-word-miss",
	      "22(63|43)(6d|4d)(64|44)2e(65|45)(78|58)(65|45)22",
	      "00 22 63 6d 64 78 65 78 65 22", -1);

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
	/* "not any byte" is satisfied by no byte at all. */
	refuse("not-any",     "e8 !?? 90");
	/* And the cap is still a cap: one part per group, past the limit. */
	refuse("too-many-parts",
	       "(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)"
	       "(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)"
	       "(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)(41|42)"
	       "(41|42)");

	/* --- offsets a module could compute from a hostile file --- */
	bounds("bounds-plain", "e8 11 22 33");
	bounds("bounds-gap",   "e8 [1-8] 33");
	bounds("bounds-alt",   "( e8 | e9 ) [1-4] 33 44 55");
	/* The negation array is a third read per byte - the one place a
	 * malformed program could send the walk past the mapping. */
	bounds("bounds-not",   "e8 !00 !?0 33 44 55");

	printf("hex: compile and match %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
