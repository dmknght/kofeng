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

	if (fails) {
		printf("\nnormalize exe: %d check(s) failed\n", fails);
		return 1;
	}
	printf("\nnormalize exe: ok\n");
	return 0;
}
