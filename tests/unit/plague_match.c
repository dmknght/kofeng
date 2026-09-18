/*
 * plague_match - the similarity matcher, against inputs built here.
 *
 * WHAT NEEDS PROVING, and each of these is a way the matcher could be wrong
 * while still looking like it works:
 *
 *   - a block found whole scores 100, and one that is absent scores nothing.
 *   - THE SCORE MOVES WITH THE DAMAGE. A block with a quarter of it overwritten
 *     must score near seventy-five, not "matched" or "not matched" - the
 *     percentage is the finding, so a matcher that only had two answers would
 *     pass every yes/no test and be useless.
 *   - REORDERING THE RECORDS COSTS ONLY THE SEAMS. Set containment is why a
 *     credential table shuffled between builds still matches; the shortfall is
 *     the windows that spanned a record boundary, and it is arithmetic rather
 *     than noise - see the note where it is checked.
 *   - INSERTION DOES NOT SHIFT IT. Bytes added before the block must not move
 *     the score, because nothing here is measured from an offset.
 *   - THE NORMALIZER ERASES A CONSTANT KEY. A block XORed with any single byte
 *     must score the same under KOF_PLAGUE_XOR, and must NOT under RAW.
 *   - THE REGION IS PART OF THE MATCH. The same bytes fed as another region
 *     score zero, which is what a rule's anchoring rests on.
 *   - BLOCKS ARE INDEPENDENT. Two blocks fed in one pass each report their own
 *     percentage; combining them is the rule's business and not the matcher's,
 *     so what is tested here is that neither disturbs the other.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofmatchers/kofplague.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

static void ok_(int cond, const char *what)
{
	if (!cond)
		fail(what, "the answer was the wrong one");
}

/* ---- material ---------------------------------------------------------- */

#define BLK   4096u
#define RGN_A (1u << 2)
#define RGN_B (1u << 3)

static uint32_t rnd(uint32_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
	return *s;
}

/* A block of records, so the reorder case has records to reorder. */
#define REC  64u
#define NREC (BLK / REC)

static void make_block(uint8_t *b, uint32_t seed)
{
	uint32_t s = seed, i;

	for (i = 0; i < BLK; i++)
		b[i] = (uint8_t)rnd(&s);
}

/* Every hash a buffer yields under one normalizer, in ascending order, cut to
 * what a rule may carry - the same k-smallest cut the authoring side makes. */
static uint32_t harvest(const uint8_t *p, uint32_t n, uint32_t norm,
			uint32_t *out, uint32_t max_out)
{
	uint32_t h = 0, drop = kof_plague_drop_weight(), i, got = 0, at;
	uint32_t tmp[8192];
	uint32_t nt = 0;

	if (norm != KOF_PLAGUE_RAW) {
		if (n < 2u) return 0;
		n -= 1u;
	}
	if (n < KOF_PLAGUE_NG)
		return 0;
#define BY(k) ((uint32_t)(norm == KOF_PLAGUE_RAW ? p[(k)]                     \
	       : norm == KOF_PLAGUE_XOR ? (uint8_t)(p[(k)] ^ p[(k) + 1u])     \
	       : (uint8_t)(p[(k) + 1u] - p[(k)])))
	for (i = 0; i < KOF_PLAGUE_NG; i++)
		h = h * KOF_PLAGUE_BASE + BY(i);
	for (at = 0;; at++) {
		uint32_t m = kof_plague_mix(h);

		if (kof_plague_selects(m) && nt < 8192u)
			tmp[nt++] = m;
		if (at + KOF_PLAGUE_NG >= n)
			break;
		h -= BY(at) * drop;
		h = h * KOF_PLAGUE_BASE + BY(at + KOF_PLAGUE_NG);
	}
#undef BY
	/* sort + dedupe, then take the smallest max_out */
	for (i = 1; i < nt; i++) {
		uint32_t v = tmp[i], j = i;

		while (j && tmp[j - 1u] > v) { tmp[j] = tmp[j - 1u]; j--; }
		tmp[j] = v;
	}
	for (i = 0; i < nt && got < max_out; i++)
		if (!i || tmp[i] != tmp[i - 1u])
			out[got++] = tmp[i];
	return got;
}

/* Feed a buffer, then read one block's percentage. */
static uint32_t score_of(struct kof_plague_ctx *c, uint32_t rgn,
			 const uint8_t *p, uint32_t n, uint32_t norms,
			 uint32_t block)
{
	uint32_t k;

	kof_plague_begin(c);
	for (k = 0; k < KOF_PLAGUE_NORM_COUNT; k++)
		if (norms & (1u << k))
			kof_plague_feed(c, rgn, k, p, n);
	return kof_plague_pct(c, block);
}

int main(void)
{
	static uint8_t blk[BLK], hay[BLK * 4], anchor[BLK];
	uint32_t pool[KOF_PLAGUE_MAX_HASH * 4];
	struct kof_plague_block blocks[2];
	struct kof_plague_set *set;
	struct kof_plague_ctx ctx;
	uint32_t n0, n1, norms, s;

	setvbuf(stdout, NULL, _IONBF, 0);
	make_block(blk, 0x1234u);
	make_block(anchor, 0x9999u);

	n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool, KOF_PLAGUE_MAX_HASH);
	if (n0 < KOF_PLAGUE_MIN_HASH) {
		printf("plague match: block yielded %u hashes, too few to test\n", n0);
		return 1;
	}
	blocks[0].first_hash = 0; blocks[0].n_hash = n0;
	blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
	memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

	set = kof_plague_build(blocks, 1, pool, n0);
	if (!set || !kof_plague_ctx_init(&ctx, set)) {
		printf("plague match: could not build the set\n");
		return 1;
	}
	norms = kof_plague_set_norms(set, RGN_A);
	ok_(norms == (1u << KOF_PLAGUE_RAW), "the set reports the one normalizer it uses");

	/* whole, absent, and the region */
	memset(hay, 0xA5, sizeof hay);
	memcpy(hay + BLK, blk, BLK);
	ok_(score_of(&ctx, RGN_A, hay, sizeof hay, norms, 0u) == 100u,
	    "a block present whole scores 100");
	ok_(score_of(&ctx, RGN_B, hay, sizeof hay, norms, 0u) == 0u,
	    "the same bytes in another region score nothing");
	memset(hay, 0x5A, sizeof hay);
	ok_(score_of(&ctx, RGN_A, hay, sizeof hay, norms, 0u) == 0u,
	    "a block that is not there scores nothing");

	/* insertion in front must not move it */
	memset(hay, 0xA5, sizeof hay);
	memcpy(hay + BLK + 37u, blk, BLK);
	ok_(score_of(&ctx, RGN_A, hay, sizeof hay, norms, 0u) == 100u,
	    "bytes inserted before the block do not move the score");

	/* damage: overwrite a quarter of it */
	memset(hay, 0xA5, sizeof hay);
	memcpy(hay + BLK, blk, BLK);
	memset(hay + BLK, 0x00, BLK / 4u);
	s = score_of(&ctx, RGN_A, hay, sizeof hay, norms, 0u);
	if (s < 60u || s > 90u) {
		char why[96];

		snprintf(why, sizeof why, "a quarter overwritten scored %u, "
			 "expected the 60-90 band", s);
		fail("the score moves with the damage", why);
	}

	/* records reordered */
	{
		uint8_t shuf[BLK];
		uint32_t i;

		for (i = 0; i < NREC; i++)
			memcpy(shuf + i * REC, blk + (NREC - 1u - i) * REC, REC);
		memset(hay, 0xA5, sizeof hay);
		memcpy(hay + BLK, shuf, BLK);
		/*
		 * NOT 100, AND THE SHORTFALL IS ARITHMETIC. Every window inside
		 * a record survives the shuffle; every window spanning a seam
		 * does not. 63 seams * 7 windows / 4089 windows is 11%, so the
		 * right answer here is about 89 - see the note in kofplague.h.
		 * A test demanding 100 would be demanding something the coding
		 * cannot give, and one accepting 50 would not notice a matcher
		 * that had lost set semantics entirely.
		 */
		s = score_of(&ctx, RGN_A, hay, sizeof hay, norms, 0u);
		if (s < 85u || s > 95u) {
			char why[112];

			snprintf(why, sizeof why, "reordered records scored %u, "
				 "the seam arithmetic says about 89", s);
			fail("reordering the records costs only the seams", why);
		}
	}
	kof_plague_ctx_done(&ctx);
	kof_plague_set_free(set);

	/* ---- the normalizer erases a constant key ----------------------- */
	{
		uint8_t keyed[BLK];
		uint32_t i, raw_s, xor_s;

		n1 = harvest(blk, BLK, KOF_PLAGUE_XOR, pool, KOF_PLAGUE_MAX_HASH);
		blocks[0].n_hash = n1; blocks[0].norm = KOF_PLAGUE_XOR;
		set = kof_plague_build(blocks, 1, pool, n1);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;
		for (i = 0; i < BLK; i++)
			keyed[i] = (uint8_t)(blk[i] ^ 0x3Bu);
		memset(hay, 0xA5, sizeof hay);
		memcpy(hay + BLK, keyed, BLK);
		xor_s = score_of(&ctx, RGN_A, hay, sizeof hay,
				 1u << KOF_PLAGUE_XOR, 0u);
		ok_(xor_s == 100u, "a constant XOR key vanishes under XOR");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);

		blocks[0].n_hash = n0; blocks[0].norm = KOF_PLAGUE_RAW;
		set = kof_plague_build(blocks, 1, pool, n0);
		if (set) {
			uint32_t m = harvest(blk, BLK, KOF_PLAGUE_RAW, pool,
					     KOF_PLAGUE_MAX_HASH);
			(void)m;
			kof_plague_set_free(set);
		}
		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool, KOF_PLAGUE_MAX_HASH);
		blocks[0].n_hash = n0;
		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;
		raw_s = score_of(&ctx, RGN_A, hay, sizeof hay,
				 1u << KOF_PLAGUE_RAW, 0u);
		ok_(raw_s == 0u, "and does not vanish under RAW");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	/* ---- the first block scores, the anchor only gates --------------- */
	{
		uint32_t na;

		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool, KOF_PLAGUE_MAX_HASH);
		na = harvest(anchor, BLK, KOF_PLAGUE_RAW, pool + n0,
			     KOF_PLAGUE_MAX_HASH);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		blocks[1].first_hash = n0; blocks[1].n_hash = na;
		blocks[1].scan_mask = RGN_A; blocks[1].norm = KOF_PLAGUE_RAW;
		memset(blocks[1].reserved, 0, sizeof blocks[1].reserved);

		set = kof_plague_build(blocks, 2, pool, n0 + na);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		/*
		 * Both blocks present, one whole and one a third: each must
		 * report its own number. A matcher that mixed them would show
		 * one value for two different facts.
		 */
		memset(hay, 0xA5, sizeof hay);
		memcpy(hay + BLK, blk, BLK);
		memcpy(hay + BLK * 2u, anchor, BLK / 3u);
		kof_plague_begin(&ctx);
		kof_plague_feed(&ctx, RGN_A, KOF_PLAGUE_RAW, hay, sizeof hay);
		ok_(kof_plague_pct(&ctx, 0u) == 100u,
		    "the block that is whole reports 100");
		s = kof_plague_pct(&ctx, 1u);
		if (s == 0u || s > 60u) {
			char why[112];

			snprintf(why, sizeof why, "the partial block reported "
				 "%u, expected a third of it", s);
			fail("blocks do not disturb each other", why);
		}

		/* and one absent reports nothing while the other still does */
		memset(hay, 0xA5, sizeof hay);
		memcpy(hay + BLK, blk, BLK);
		kof_plague_begin(&ctx);
		kof_plague_feed(&ctx, RGN_A, KOF_PLAGUE_RAW, hay, sizeof hay);
		ok_(kof_plague_pct(&ctx, 0u) == 100u &&
		    kof_plague_pct(&ctx, 1u) == 0u,
		    "an absent block reports nothing and the other is unaffected");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	/* ---- a repeated fragment is not the whole block ------------------ */
	/*
	 * THE ONE CASE A COUNTER OF ARRIVALS GETS WRONG.
	 *
	 * A file that carries a SMALL PART of the block, over and over, must
	 * report that small part - the score is how much of the block is here,
	 * not how often something of it turned up. Counting arrivals and
	 * bounding the count by the block's size reads as a hundred per cent
	 * for a file holding a twentieth of it, which is a rule firing on a
	 * sample it has almost nothing in common with. Every other case in this
	 * file passed with that bug in place, which is why this one is here.
	 */
	{
		size_t at;

		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool,
			     KOF_PLAGUE_MAX_HASH);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		memset(hay, 0xA5, sizeof hay);
		for (at = 0; at + BLK / 16u < sizeof hay; at += BLK / 16u)
			memcpy(hay + at, blk, BLK / 16u);
		kof_plague_begin(&ctx);
		kof_plague_feed(&ctx, RGN_A, KOF_PLAGUE_RAW, hay, sizeof hay);
		s = kof_plague_pct(&ctx, 0u);
		if (s > 25u) {
			char why[128];

			snprintf(why, sizeof why, "a sixteenth of the block "
				 "repeated across the object reported %u", s);
			fail("a repeated fragment scores as the fragment", why);
		}
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	/* ---- padding is not content -------------------------------------- */
	/*
	 * A BLOCK CUT FROM A SPAN WITH PADDING IN IT MUST NOT MATCH PADDING.
	 *
	 * The all-zero window hashes to zero, zero passes the selection test
	 * whatever the rate, and zero is the smallest value a window can have -
	 * so k-min keeps it first and every object with an alignment gap
	 * matched it. Measured on a shipped rule it carried 297 of 429
	 * detections, all of them landing on exactly the threshold the rule
	 * demanded. Both sides skip a window of one repeated byte now; this is
	 * what says they still agree.
	 */
	{
		/* Half content, half padding - the shape every real block cut
		 * from a region with an alignment gap in it has. */
		make_block(blk, 0x5150u);
		memset(blk + BLK / 2u, 0, BLK / 2u);
		memset(hay, 0, sizeof hay);

		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool,
			     KOF_PLAGUE_MAX_HASH);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;
		kof_plague_begin(&ctx);
		kof_plague_feed(&ctx, RGN_A, KOF_PLAGUE_RAW, hay, sizeof hay);
		ok_(kof_plague_pct(&ctx, 0u) == 0u,
		    "an object of pure padding matches nothing");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	/* ---- the region anchor, and dropping it -------------------------- */
	/*
	 * What an unpacker produced has whatever regions the rebuild gave it,
	 * which are not the ones the block was cut from - see
	 * kof_plague_any_region. Anchored the block scores nothing there;
	 * unanchored it scores what it actually shares.
	 */
	{
		make_block(blk, 0x1234u);
		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool,
			     KOF_PLAGUE_MAX_HASH);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		memset(hay, 0xA5, sizeof hay);
		memcpy(hay + BLK, blk, BLK);

		kof_plague_begin(&ctx);
		kof_plague_feed(&ctx, RGN_B, KOF_PLAGUE_RAW, hay, sizeof hay);
		ok_(kof_plague_pct(&ctx, 0u) == 0u,
		    "the wrong region scores nothing");

		kof_plague_begin(&ctx);
		kof_plague_any_region(&ctx, 1);
		kof_plague_feed(&ctx, RGN_B, KOF_PLAGUE_RAW, hay, sizeof hay);
		ok_(kof_plague_pct(&ctx, 0u) == 100u,
		    "without the anchor the same bytes score whole");

		/* And the next object starts anchored again. */
		kof_plague_begin(&ctx);
		kof_plague_feed(&ctx, RGN_B, KOF_PLAGUE_RAW, hay, sizeof hay);
		ok_(kof_plague_pct(&ctx, 0u) == 0u,
		    "begin puts the anchor back");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	if (failures) {
		printf("plague match: %d check(s) failed\n", failures);
		return 1;
	}
	printf("plague match: whole, absent, region, insertion, damage, "
	       "reordering (seams only), a constant key, a repeated fragment, "
	       "padding, the region anchor and dropping it, "
	       "and two blocks that do not disturb "
	       "each other - ok\n");
	return 0;
}
