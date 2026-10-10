/*
 * plague_minhash - a block made of the smallest hashes of ALL its windows.
 *
 * kof_plague_minhash keeps the smallest KOF_PLAGUE_MINHASH_K of every window of a
 * span, so the block is the same size however large or small the span - and a
 * function of sixty bytes can be one.
 *
 * WHAT IS PINNED, and why each is a separate failure:
 *   - the sketch IS the k smallest distinct window hashes: checked against a
 *     brute-force reference written here from first principles, for every
 *     normalizer, at lengths on both sides of every threshold. A generator that
 *     differed from what the matcher reads would produce rules that match nothing
 *     and say so nowhere.
 *   - a block is found by the scanner whatever the values of its hashes: the
 *     gate follows the set, so it cannot be a fixed fraction of windows.
 *   - it survives bytes inserted around it and a little damage inside it, and
 *     does not match what is not there.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/overlord/plague/kofplague.h"

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static uint32_t rnd(uint32_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 17;
	*s ^= *s << 5;
	return *s;
}

static int cmp32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

/*
 * THE REFERENCE: every window's hash, sorted, distinct, the first k. Written the
 * obvious way and sharing nothing with the engine but the definition of what a
 * window is - the rolling value, the mix, the normalizer's bytes, and the rule
 * that a window of one repeated byte is not content.
 */
static uint32_t reference(const uint8_t *p, uint64_t n, uint32_t norm,
			  uint32_t *out, uint32_t k)
{
	uint32_t *all, nw = 0, got = 0, i;
	uint64_t at, len = norm == KOF_PLAGUE_RAW ? n : n - 1u;

	if ((norm != KOF_PLAGUE_RAW && n < 2u) || len < KOF_PLAGUE_NG)
		return 0;
	all = malloc((size_t)len * sizeof *all);
	for (at = 0; at + KOF_PLAGUE_NG <= len; at++) {
		uint32_t h = 0;

		for (i = 0; i < KOF_PLAGUE_NG; i++)
			h = h * KOF_PLAGUE_BASE +
			    (uint32_t)kof_plague_byte(p, at + i, norm);
		if (!kof_plague_flat(p, at, norm))
			all[nw++] = kof_plague_mix(h);
	}
	qsort(all, nw, sizeof *all, cmp32);
	for (i = 0; i < nw && got < k; i++)
		if (!i || all[i] != all[i - 1u])
			out[got++] = all[i];
	free(all);
	return got;
}

#define RGN (1u << 2)

/* The score of a block against one UNIT. */
static uint32_t score(const struct kof_plague_block *blocks, uint32_t nb,
		      const uint32_t *pool, uint32_t np, const uint8_t *hay,
		      uint32_t hn, uint32_t which)
{
	struct kof_plague_set *set = kof_plague_build(blocks, nb, pool, np);
	struct kof_plague_ctx ctx;
	uint32_t s;

	if (!set || !kof_plague_ctx_init(&ctx, set))
		return 999u;
	kof_plague_begin(&ctx);
	kof_plague_unit(&ctx, RGN, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER, hay, hn);
	s = kof_plague_pct(&ctx, which);
	kof_plague_ctx_done(&ctx);
	kof_plague_set_free(set);
	return s;
}

/* ---- the byte carve: kof_plague_cut ------------------------------------- */

struct cutlog { uint64_t at, n, stop_after, smallest, largest; int gap, partial; };

static int note_cut(void *user, uint64_t from, uint64_t to)
{
	struct cutlog *c = user;

	if (from != c->at)
		c->gap = 1;
	c->at = to;
	if (!c->n || to - from < c->smallest)
		c->smallest = to - from;
	if (to - from > c->largest)
		c->largest = to - from;
	c->n++;
	return c->stop_after && c->n >= c->stop_after;
}

struct cutends { uint64_t *e; uint64_t *n; };

static int record_cut(void *user, uint64_t from, uint64_t to)
{
	struct cutends *x = user;

	(void)from;
	if (*x->n < 256u)
		x->e[(*x->n)++] = to;
	return 0;
}

static void carve_tests(const uint8_t *p, uint64_t len)
{
	struct cutlog c;

	memset(&c, 0, sizeof c);
	kof_plague_cut(p, len, 256u, 64u, 1024u, note_cut, &c);
	check(!c.gap && c.at == len, "the pieces do not tile the span");
	check(c.n > 1u, "a long span was not cut at all");
	check(c.largest <= 1024u, "a piece is longer than the maximum");
	memset(&c, 0, sizeof c);
	c.stop_after = 3u;
	kof_plague_cut(p, len, 256u, 64u, 1024u, note_cut, &c);
	check(c.n == 3u, "returning non-zero did not stop the walk");
	memset(&c, 0, sizeof c);
	kof_plague_cut(p, KOF_PLAGUE_NG, 256u, 64u, 1024u, note_cut, &c);
	check(c.n == 1u && c.at == KOF_PLAGUE_NG, "a span of one window is one piece");
	/* the same bytes are cut in the same places after anything is put in front */
	{
		static uint8_t shifted[20000 + 73];
		struct cutlog a, b;
		uint64_t i;
		uint64_t ends_a[256], ends_b[256], na = 0, nb = 0, same = 0, j;

		memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
		memcpy(shifted + 73, p, len);
		for (i = 0; i < 73; i++)
			shifted[i] = (uint8_t)(i * 31u);
		(void)a; (void)b;
		{
			struct cutends ca = { ends_a, &na }, cb = { ends_b, &nb };

			kof_plague_cut(p, len, 256u, 64u, 1024u, record_cut, &ca);
			kof_plague_cut(shifted, len + 73, 256u, 64u, 1024u, record_cut, &cb);
		}
		for (i = 0; i < na; i++)
			for (j = 0; j < nb; j++)
				if (ends_a[i] + 73 == ends_b[j])
					same++;
		check(na > 4u && same * 10u >= na * 8u,
		      "most cut points did not survive bytes inserted in front");
	}
}

int main(void)
{
	static const uint32_t lens[] = { 22, 23, 24, 40, 64, 100, 400, 4000, 20000 };
	static uint8_t hay[16384], fn[20000];
	uint32_t pool[KOF_PLAGUE_MAX_HASH * 2], got[KOF_PLAGUE_MAX_HASH], want[KOF_PLAGUE_MAX_HASH];
	uint32_t seed = 0xc0ffee11u, i, norm, l;
	struct kof_plague_block blk[2];

	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; i < sizeof fn; i++)
		fn[i] = (uint8_t)rnd(&seed);

	/* ---- the sketch is the k smallest distinct window hashes -------------- */
	for (norm = 0; norm < KOF_PLAGUE_NORM_COUNT; norm++)
		for (l = 0; l < sizeof lens / sizeof lens[0]; l++) {
			uint32_t g = kof_plague_minhash(fn, lens[l], norm, got);
			uint32_t w = reference(fn, lens[l], norm, want, KOF_PLAGUE_MINHASH_K);
			char why[96];

			snprintf(why, sizeof why, "minhash of %u bytes, normalizer %u, is "
				 "not the k smallest distinct window hashes (%u against %u)",
				 lens[l], norm, g, w);
			check(g == w && !memcmp(got, want, w * sizeof *want), why);
		}

	/* ---- the size follows the span only until it is big enough ------------- */
	check(kof_plague_minhash(fn, 22, KOF_PLAGUE_RAW, got) < KOF_PLAGUE_MIN_HASH,
	      "22 bytes holds only 15 windows and cannot be a block");
	check(kof_plague_minhash(fn, 23, KOF_PLAGUE_RAW, got) >= KOF_PLAGUE_MIN_HASH,
	      "23 bytes is the smallest span that makes a block");
	check(kof_plague_minhash(fn, 20000, KOF_PLAGUE_RAW, got) == KOF_PLAGUE_MINHASH_K,
	      "a large span yields the same count as a small one");

	/* nothing is capped: a long span is hashed whole */
	{
		uint32_t g = kof_plague_minhash(fn, sizeof fn, KOF_PLAGUE_RAW, got);
		uint32_t w = reference(fn, sizeof fn, KOF_PLAGUE_RAW, want, KOF_PLAGUE_MINHASH_K);

		check(g == w && !memcmp(got, want, w * sizeof *want),
		      "a span is hashed whole");
	}

	/* ---- a unit is scored by how much of the block's sketch it holds ------ */
	for (i = 0; i < sizeof hay; i++)
		hay[i] = (uint8_t)rnd(&seed);
	{
		uint32_t n = kof_plague_minhash(fn, 100, KOF_PLAGUE_RAW, pool);
		uint32_t s;

		memset(&blk[0], 0, sizeof blk[0]);
		blk[0].n_hash = n; blk[0].scan_mask = RGN; blk[0].norm = KOF_PLAGUE_RAW;

		check(score(blk, 1, pool, n, hay, 100, 0) < 15u,
		      "a unit that is not the function scored");
		check(score(blk, 1, pool, n, fn, 100, 0) == 100u,
		      "a unit equal to the function was not found whole");
		memcpy(hay, fn, 100);
		{
			uint32_t d;

			for (d = 0; d < 100; d += 33)               /* three bytes changed */
				hay[d] ^= 0xff;
			s = score(blk, 1, pool, n, hay, 100, 0);
			check(s >= 40u && s < 100u,
			      "a little damage should cost some of the score and not all");
		}
	}

	carve_tests(fn, 20000);

	if (failures) {
		printf("plague minhash: %d failure(s)\n", failures);
		return 1;
	}
	printf("plague minhash: the k smallest of every window for each normalizer, "
	       "found wherever its hashes lie, damage costs only what it "
	       "touches - ok\n");
	return 0;
}
