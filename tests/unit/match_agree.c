/*
 * match_agree - the three matcher entry points must answer the same question.
 *
 * kof_match_in says whether a pattern is in a range, kof_match_where says where,
 * and kof_match_at says whether it is at one offset. They are three doors into one
 * search and nothing checked that they agree: hex_match.c compares `in` against
 * `at` on hand written cases, and `where` - which the panel now uses to place
 * every marker it draws - had no test at all.
 *
 * Disagreement between them is not a cosmetic fault. "Present but nowhere" and
 * "here, but not when asked directly" are both reachable from one off by one in a
 * bound, and both look like a working search until somebody reads the offset.
 *
 * The invariants, checked on random haystacks with random literal and hex
 * patterns:
 *
 *   1  where != BROKEN  <->  in is true
 *   2  where lands inside the range it was given
 *   3  at(where) is true
 *   4  where is the FIRST one: at(p) is false for every p before it
 *   5  restarting past a hit makes progress - strictly greater, or BROKEN
 *
 * Five is what a walk over every occurrence depends on, and the one whose failure
 * is an infinite loop rather than a wrong answer.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../libkofeng/core/kofcore.h"
#include "../../libkofeng/kofmatchers/kofmatch.h"
#include "../../libkofeng/kofmatchers/hexprog.h"
#include "../../libkofeng/kofdb/kofpack.h"

static int failures;
static const char *g_case = "?";
static uint8_t g_flags;
static const uint8_t *g_hay, *g_pat;
static uint32_t g_hn, g_plen, g_span;
static uint64_t g_off, g_len;

static void fail(const char *why)
{
	uint32_t i;

	if (failures < 3) {
		printf("  FAIL %s: %s\n", g_case, why);
		printf("       flags=%s%s  off=%llu len=%llu span=%u\n",
		       (g_flags & KOF_STR_ICASE) ? "ICASE " : "",
		       (g_flags & KOF_STR_FULLWORD) ? "FULLWORD" : "",
		       (unsigned long long)g_off, (unsigned long long)g_len,
		       g_span);
		printf("       pat ="); for (i=0;i<g_plen;i++) printf(" %02X", g_pat[i]);
		printf("\n       hay ="); for (i=0;i<g_hn && i<64;i++) printf(" %02X", g_hay[i]);
		printf("%s\n", g_hn>64?" ...":"");
	}
	failures++;
}

/* splitmix64, so a failure is reproducible from the seed printed below. */
static uint64_t rs;
static uint64_t rnd(void)
{
	uint64_t z = (rs += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}
static uint32_t rnd_n(uint32_t n) { return n ? (uint32_t)(rnd() % n) : 0; }

#define HAY_MAX 512u

/*
 * A haystack with a small alphabet.
 *
 * Random bytes make a pattern of more than two bytes essentially unique, so every
 * search finds nothing and the interesting invariants - first match, progress over
 * repeats - are never exercised. Four symbols make repeats the normal case.
 */
static uint32_t make_hay(uint8_t *h)
{
	static const uint8_t sym[] = { 'A', 'B', 0x00, 0xff };
	uint32_t n = 8u + rnd_n(HAY_MAX - 8u), i;

	for (i = 0; i < n; i++)
		h[i] = sym[rnd_n(4)];
	return n;
}

/*
 * THE WORD RULE AS A RANGE SEARCH APPLIES IT.
 *
 * kof_match_at is given an offset and no window, so its boundary is the object.
 * match_one is given a range - the region a module asked about - and its
 * boundary is that range's edge. The two agree everywhere except at the edge,
 * and that difference is the contract, not a fault: so the brute force below
 * has to apply the range rule when it is checking a range search.
 */
static int word_ok_in_range(const uint8_t *h, uint64_t p, uint32_t span,
			    uint64_t off, uint64_t len)
{
	int lok = (p == off) || !(h[p - 1] == 'A' || h[p - 1] == 'B');
	int rok = (p + span >= off + len) ||
		  !(h[p + span] == 'A' || h[p + span] == 'B');

	return lok && rok;
}

/* All the offsets the pattern matches at, found the slow way. */
static uint32_t brute(struct kof_match_ctx *m, uint64_t n, const uint8_t *pat,
		      uint16_t plen, uint8_t kind, uint8_t flags,
		      uint64_t *out, uint32_t cap)
{
	uint64_t i;
	uint32_t k = 0;

	for (i = 0; i < n && k < cap; i++)
		if (kof_match_at(m, i, pat, plen, kind, flags))
			out[k++] = i;
	return k;
}

static void one_round(void)
{
	uint8_t hay[HAY_MAX], pat[64], prog[KOF_HEX_MAX_PROG];
	uint8_t kind = KOF_STR_LITERAL, flags = 0;
	const uint8_t *use = pat;
	uint32_t hn = make_hay(hay), plen, span;
	uint64_t brute_at[HAY_MAX];
	uint32_t n_brute, i;
	uint64_t off, len, at, prev;
	struct kof_match_ctx m;

	/* --- the pattern: a slice of the haystack, or noise --- */
	plen = 1u + rnd_n(6u);
	if (rnd_n(4)) {
		uint32_t from = rnd_n(hn > plen ? hn - plen : 1u);

		memcpy(pat, hay + from, plen);
	} else {
		for (i = 0; i < plen; i++)
			pat[i] = (uint8_t)rnd_n(256);
	}

	if (rnd_n(2)) {
		/* Hex, sometimes with a wildcard or a gap. */
		char t[256];
		size_t w = 0;
		struct kof_hex_stat st;

		for (i = 0; i < plen; i++) {
			if (i && rnd_n(6) == 0 && i + 1u < plen)
				w += (size_t)snprintf(t + w, sizeof t - w,
						      "[%u] ", 1u + rnd_n(2));
			if (rnd_n(8) == 0)
				w += (size_t)snprintf(t + w, sizeof t - w, "?? ");
			else
				w += (size_t)snprintf(t + w, sizeof t - w,
						      "%02X ", pat[i]);
		}
		t[w] = 0;
		plen = kof_hex_compile(t, prog, sizeof prog, &st);
		if (!plen)
			return;         /* refused; refusal is hex_match.c's job */
		span = st.min_span;
		use = prog;
		kind = KOF_STR_HEX;
		g_case = "hex";
	} else {
		span = plen;
		if (rnd_n(2)) flags |= KOF_STR_ICASE;
		if (rnd_n(3) == 0) flags |= KOF_STR_FULLWORD;
		g_case = "literal";
	}

	g_flags = flags; g_hay = hay; g_pat = pat; g_hn = hn;
	g_plen = (kind == KOF_STR_HEX) ? 0u : plen; g_span = span;
	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0))
		return;
	kof_match_begin(&m, kof_buf_make(hay, hn));

	/*
	 * Brute forced WITHOUT the word rule, so the rule can be applied below
	 * with the boundary the call being checked actually uses. Asking
	 * kof_match_at with the flag would apply the object rule and then the
	 * comparison would be against the wrong contract.
	 */
	n_brute = brute(&m, hn, use, (uint16_t)plen, kind,
			(uint8_t)(flags & ~(unsigned)KOF_STR_FULLWORD),
			brute_at, HAY_MAX);

	/* --- a random sub range, because a module names its own --- */
	off = rnd_n(hn);
	len = rnd_n((uint32_t)(hn - off) + 1u);
	g_off = off; g_len = len;

	at = kof_match_where(&m, off, len, use, (uint16_t)plen, kind, flags);
	{
		int in = kof_match_in(&m, off, len, use, (uint16_t)plen, kind,
				      flags);

		if (in != (at != KOF_BROKEN))
			fail("kof_match_in and kof_match_where disagree on "
			     "whether the pattern is in the range");
	}
	if (at != KOF_BROKEN) {
		if (at < off || at >= off + len)
			fail("kof_match_where returned an offset outside the "
			     "range it was given");
		/*
		 * Checked without the word flag plus the range rule, for the
		 * reason above: at the edge of the range the two boundaries
		 * differ by contract.
		 */
		if (!kof_match_at(&m, at, use, (uint16_t)plen, kind,
				  (uint8_t)(flags & ~(unsigned)KOF_STR_FULLWORD)))
			fail("kof_match_at says no at the offset "
			     "kof_match_where returned");
		if ((flags & KOF_STR_FULLWORD) &&
		    !word_ok_in_range(hay, at, span, off, len))
			fail("kof_match_where returned a hit the word rule "
			     "should have refused");
		for (i = 0; i < n_brute; i++) {
			if (brute_at[i] >= at)
				break;
			/*
			 * Only a match that FITS is one a range search can
			 * report: starting inside the range and running past
			 * its end is not in the range.
			 */
			if (brute_at[i] >= off &&
			    brute_at[i] + span <= off + len &&
			    (!(flags & KOF_STR_FULLWORD) ||
			     word_ok_in_range(hay, brute_at[i], span, off,
					      len)))
				fail("kof_match_where skipped an earlier "
				     "match inside the range");
		}
		/* 5: progress. */
		prev = at;
		at = kof_match_where(&m, prev + 1u,
				     off + len > prev + 1u
				     ? off + len - (prev + 1u) : 0,
				     use, (uint16_t)plen, kind, flags);
		if (at != KOF_BROKEN && at <= prev)
			fail("restarting past a hit did not move forward");
	} else {
		for (i = 0; i < n_brute; i++)
			if (brute_at[i] >= off &&
			    brute_at[i] + span <= off + len &&
			    (!(flags & KOF_STR_FULLWORD) ||
			     word_ok_in_range(hay, brute_at[i], span, off,
					      len)))
				fail("kof_match_where found nothing where "
				     "kof_match_at finds a match");
	}
	kof_match_state_free(&m);
}

int main(int argc, char **argv)
{
	uint32_t rounds = 20000, i;

	rs = argc > 1 ? strtoull(argv[1], NULL, 0) : 0x5eedu;
	if (argc > 2)
		rounds = (uint32_t)strtoul(argv[2], NULL, 0);
	for (i = 0; i < rounds; i++)
		one_round();
	printf("match agree: %u round(s), seed 0x%llx %s\n", rounds,
	       (unsigned long long)(argc > 1 ? strtoull(argv[1], NULL, 0)
					      : 0x5eedu),
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
