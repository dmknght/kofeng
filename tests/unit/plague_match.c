/*
 * plague_match - the similarity matcher, against inputs built here.
 *
 * The scanner walks the windows of UNITS of an object - kof_plague_unit - and a
 * block's score is how many of its hashes the best single unit contains. What
 * needs proving,
 * each a way the matcher could be wrong while still looking like it works:
 *
 *   - a unit equal to the block scores 100, and an absent one scores nothing.
 *   - THE SCORE MOVES WITH THE DAMAGE. A unit with a quarter overwritten must
 *     score between the extremes: the percentage is the finding, so a matcher
 *     that only had two answers would pass every yes/no test and be useless.
 *   - REORDERING THE RECORDS COSTS ONLY THE SEAMS.
 *   - THE NORMALIZER ERASES A CONSTANT KEY: a unit XORed with any single byte
 *     scores the same under KOF_PLAGUE_XOR, and does not under RAW.
 *   - THE REGION AND THE SIDE ARE PART OF THE MATCH.
 *   - THE BEST UNIT, NOT THE SUM: two units that each hold half of a block do not
 *     add up to the whole of it.
 *   - BLOCKS ARE INDEPENDENT, and padding is not content.
 *   - A BLOCK INSIDE A LARGER UNIT STILL SCORES 100: containment, not the overlap
 *     of two sketches, which falls to a fraction once the unit holds more than
 *     the block did.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/overlord/plague/kofplague.h"

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

/* The sketch a buffer yields under one normalizer, in ascending order. The
 * engine's own generator: this file carried a copy of it once, and a copy is
 * exactly what lets the authoring side and the matcher drift apart with
 * nothing reporting it. */
static uint32_t harvest(const uint8_t *p, uint32_t n, uint32_t norm,
			uint32_t *out)
{
	return kof_plague_minhash(p, n, norm, out);
}

/* Feed a buffer as ONE unit, then read one block's percentage. */
static uint32_t score_of(struct kof_plague_ctx *c, uint32_t rgn,
			 const uint8_t *p, uint32_t n, uint32_t norms,
			 uint32_t block)
{
	uint32_t k;

	kof_plague_begin(c);
	for (k = 0; k < KOF_PLAGUE_NORM_COUNT; k++)
		if (norms & (1u << k))
			kof_plague_unit(c, rgn, k, KOF_PLAGUE_SIDE_USER, p, n);
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

	n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
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
	ok_(score_of(&ctx, RGN_A, blk, BLK, norms, 0u) == 100u,
	    "a unit equal to the block scores 100");
	ok_(score_of(&ctx, RGN_B, blk, BLK, norms, 0u) == 0u,
	    "the same bytes in another region score nothing");
	memset(hay, 0x5A, sizeof hay);
	ok_(score_of(&ctx, RGN_A, hay, BLK, norms, 0u) == 0u,
	    "a unit that is not the block scores nothing");

	/* damage: overwrite a quarter of it */
	memcpy(hay, blk, BLK);
	memset(hay, 0x00, BLK / 4u);
	s = score_of(&ctx, RGN_A, hay, BLK, norms, 0u);
	if (s < 45u || s > 90u) {
		char why[96];

		snprintf(why, sizeof why, "a quarter overwritten scored %u, "
			 "expected the 45-90 band", s);
		fail("the score moves with the damage", why);
	}

	/* records reordered */
	{
		uint8_t shuf[BLK];
		uint32_t i;

		for (i = 0; i < NREC; i++)
			memcpy(shuf + i * REC, blk + (NREC - 1u - i) * REC, REC);
		/*
		 * NOT 100, AND THE SHORTFALL IS ARITHMETIC. Every window inside
		 * a record survives the shuffle; every window spanning a seam
		 * does not. 63 seams * 7 windows / 4089 windows is 11%, so the
		 * right answer here is about 89 - see the note in kofplague.h.
		 * A test demanding 100 would be demanding something the coding
		 * cannot give, and one accepting 50 would not notice a matcher
		 * that had lost set semantics entirely.
		 */
		s = score_of(&ctx, RGN_A, shuf, BLK, norms, 0u);
		if (s < 70u || s > 98u) {
			char why[112];

			snprintf(why, sizeof why, "reordered records scored %u, "
				 "the seam arithmetic says most survives", s);
			fail("reordering the records costs only the seams", why);
		}
	}
	kof_plague_ctx_done(&ctx);
	kof_plague_set_free(set);

	/* ---- the normalizer erases a constant key ----------------------- */
	{
		uint8_t keyed[BLK];
		uint32_t i, raw_s, xor_s;

		n1 = harvest(blk, BLK, KOF_PLAGUE_XOR, pool);
		blocks[0].n_hash = n1; blocks[0].norm = KOF_PLAGUE_XOR;
		set = kof_plague_build(blocks, 1, pool, n1);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;
		for (i = 0; i < BLK; i++)
			keyed[i] = (uint8_t)(blk[i] ^ 0x3Bu);
		xor_s = score_of(&ctx, RGN_A, keyed, BLK,
				 1u << KOF_PLAGUE_XOR, 0u);
		ok_(xor_s == 100u, "a constant XOR key vanishes under XOR");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);

		blocks[0].n_hash = n0; blocks[0].norm = KOF_PLAGUE_RAW;
		set = kof_plague_build(blocks, 1, pool, n0);
		if (set) {
			uint32_t m = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
			(void)m;
			kof_plague_set_free(set);
		}
		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		blocks[0].n_hash = n0;
		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;
		raw_s = score_of(&ctx, RGN_A, keyed, BLK,
				 1u << KOF_PLAGUE_RAW, 0u);
		ok_(raw_s == 0u, "and does not vanish under RAW");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	/* ---- the first block scores, the anchor only gates --------------- */
	{
		uint32_t na;

		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		na = harvest(anchor, BLK, KOF_PLAGUE_RAW, pool + n0);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		blocks[1].first_hash = n0; blocks[1].n_hash = na;
		blocks[1].scan_mask = RGN_A; blocks[1].norm = KOF_PLAGUE_RAW;
		memset(blocks[1].reserved, 0, sizeof blocks[1].reserved);

		set = kof_plague_build(blocks, 2, pool, n0 + na);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		/*
		 * Two units, one the first block whole and one a third of the
		 * second: each block reports its own number.
		 */
		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				anchor, BLK / 3u);
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
		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 100u &&
		    kof_plague_pct(&ctx, 1u) == 0u,
		    "an absent block reports nothing and the other is unaffected");

		/* THE UNION OVER UNITS, NOT THE BEST ONE: each half of the first block
		 * in a unit of its own holds about half of it, and the two together
		 * are the block - less the few windows that straddle the cut, which
		 * belong to neither half. Whether a gap fell in the middle of the data
		 * is the scanner's cut and not a fact about the object, so it must
		 * not change the score. */
		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK / 2u);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk + BLK / 2u, BLK / 2u);
		s = kof_plague_pct(&ctx, 0u);
		if (s < 80u) {
			char why[112];

			snprintf(why, sizeof why, "two halves scored %u; the "
				 "union is the block less the straddling windows", s);
			fail("units add up", why);
		}
		/* And a hash seen again in a later unit is still one hash. */
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 100u,
		    "the same block seen in three units reads 100, not 300");
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

		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		for (at = 0; at + BLK / 16u <= sizeof hay; at += BLK / 16u)
			memcpy(hay + at, blk, BLK / 16u);
		s = score_of(&ctx, RGN_A, hay, sizeof hay, 1u << KOF_PLAGUE_RAW, 0u);
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

		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;
		ok_(score_of(&ctx, RGN_A, hay, sizeof hay, 1u << KOF_PLAGUE_RAW, 0u) == 0u,
		    "a unit of pure padding matches nothing");
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
		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_B, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 0u,
		    "the wrong region scores nothing");

		kof_plague_begin(&ctx);
		kof_plague_any_region(&ctx, 1);
		kof_plague_unit(&ctx, RGN_B, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 100u,
		    "without the anchor the same bytes score whole");

		/* And the next object starts anchored again. */
		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_B, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 0u,
		    "begin puts the anchor back");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	/* ---- the side is part of the match ------------------------------- */
	/*
	 * A block cut from the static library and one cut from the author's own
	 * code answer different questions, and one must not score the other - see
	 * enum kof_plague_side. A block of one side scores only from units of that
	 * side.
	 */
	{
		make_block(blk, 0x77aau);
		n0 = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		blocks[0].first_hash = 0; blocks[0].n_hash = n0;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		memset(blocks[0].reserved, 0, sizeof blocks[0].reserved);
		blocks[0].side = KOF_PLAGUE_SIDE_LIB;

		set = kof_plague_build(blocks, 1, pool, n0);
		if (!set || !kof_plague_ctx_init(&ctx, set)) return 1;

		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 0u,
		    "a library block is not scored by the author's code");
		kof_plague_begin(&ctx);
		kof_plague_unit(&ctx, RGN_A, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_LIB,
				blk, BLK);
		ok_(kof_plague_pct(&ctx, 0u) == 100u,
		    "and is scored by the library's");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
		blocks[0].side = KOF_PLAGUE_SIDE_USER;
	}

	/*
	 * THE NAME OF A SET OF BLOCKS.
	 *
	 * A rule whose condition is "block A and block B" is named after both.
	 * The order the two are asked in is the order a C expression evaluates
	 * them, which is not part of the rule - so the name must not depend on
	 * it. And a rule with one block keeps that block's own name: every
	 * verdict already written says so.
	 */
	{
		const uint32_t ab[2] = { 0xdded9322u, 0x6fad1193u };
		const uint32_t ba[2] = { 0x6fad1193u, 0xdded9322u };
		const uint32_t ac[2] = { 0xdded9322u, 0x00000001u };
		const uint32_t one[1] = { 0xdded9322u };

		ok_(kof_plague_name_of(one, 1u) == 0xdded9322u,
		    "one block is named after itself");
		ok_(kof_plague_name_of(ab, 2u) == kof_plague_name_of(ba, 2u),
		    "the set's name does not depend on the order asked");
		ok_(kof_plague_name_of(ab, 2u) != kof_plague_name_of(ac, 2u),
		    "a different set is a different name");
		ok_(kof_plague_name_of(ab, 2u) != 0xdded9322u &&
		    kof_plague_name_of(ab, 2u) != 0x6fad1193u,
		    "a pair is not named after either half");
		ok_(kof_plague_name_of(NULL, 0u) == 0u,
		    "no blocks, no name");
	}

	/*
	 * THE BLOCK INSIDE MORE. The block's 32 hashes are the smallest of its own
	 * span; a unit four times as long carries the whole span and three others,
	 * and its own 32 smallest are mostly not the block's. Compared as sketches
	 * that unit scored about a quarter; every hash of the block is in its bytes,
	 * so asked by containment it scores all of them.
	 */
	{
		uint32_t n = harvest(blk, BLK, KOF_PLAGUE_RAW, pool);
		uint32_t seed;

		for (seed = 0; seed < 4u; seed++)
			make_block(hay + seed * BLK, 0x7000u + seed);
		memcpy(hay + 2u * BLK, blk, BLK);
		blocks[0].first_hash = 0; blocks[0].n_hash = n;
		blocks[0].scan_mask = RGN_A; blocks[0].norm = KOF_PLAGUE_RAW;
		set = kof_plague_build(blocks, 1, pool, n);
		if (!set || !kof_plague_ctx_init(&ctx, set))
			return 1;
		s = score_of(&ctx, RGN_A, hay, BLK * 4u, 1u << KOF_PLAGUE_RAW, 0u);
		ok_(s == 100u, "a block inside a unit four times its size scores all of it");
		make_block(hay + 2u * BLK, 0x7002u);
		s = score_of(&ctx, RGN_A, hay, BLK * 4u, 1u << KOF_PLAGUE_RAW, 0u);
		ok_(s == 0u, "and the same unit without the block scores nothing");
		kof_plague_ctx_done(&ctx);
		kof_plague_set_free(set);
	}

	if (failures) {
		printf("plague match: %d check(s) failed\n", failures);
		return 1;
	}
	printf("plague match: whole, absent, region, damage, "
	       "reordering (seams only), a constant key, a repeated fragment, "
	       "padding, the region anchor and dropping it, "
	       "two blocks that do not disturb "
	       "each other, and the name of a set of blocks - ok\n");
	return 0;
}
