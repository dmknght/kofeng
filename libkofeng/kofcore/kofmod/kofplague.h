/*
 * kofplague.h - similarity matching over a BLOCK a researcher chose.
 *
 * WHY THIS EXISTS BESIDE THE PATTERN MATCHER, rather than as another kind of
 * signature inside it. A pattern rule answers "are these exact bytes present".
 * This answers "how much of this block is present", as a percentage, and the
 * percentage is the finding. The two need different storage, a different index
 * and a different report, so they are different machinery.
 *
 * WHAT IT IS FOR, stated narrowly because the measurements that produced this
 * file also ruled several things out. It finds VARIANTS OF A CODEBASE: the same
 * family rebuilt, reconfigured, or cross compiled. Measured on real IoT botnet
 * families, one block taken from ONE sample reached every other sample of its
 * family across seven and eight architectures - which byte-level similarity
 * over a whole region could not do at all.
 *
 * WHAT IT IS NOT FOR: finding malware nobody has seen. A block comes from a
 * sample somebody already analysed. This is a similarity tool, not a discovery
 * tool, and every number it produces is relative to a block a human picked.
 *
 *
 * THE SHAPE, and each piece is here because leaving it out was measured to fail:
 *
 *   A BLOCK, CHOSEN BY A PERSON. Automatic block discovery was tried three
 *   times and failed three times in the same way - it selects whatever is
 *   locally rare, which on a mixed corpus is the C runtime, the packer's
 *   scrambled alphabet, or a bundled licence text. None of those belong to a
 *   family, and all of them look distinctive. A researcher looking at the bytes
 *   rejects them instantly. So the block is an input, not a computation.
 *
 *   CONTENT DEFINED SAMPLING, so the two sides agree without knowing each
 *   other's layout. Every 8 byte window is hashed and kept when the hash lands
 *   in one slice of the value space. A target file is chunked by the same rule,
 *   so a block that moved, or that had entries inserted before it, still
 *   produces the same hashes. Nothing here depends on an offset.
 *
 *   A SET, NOT A SEQUENCE. Matching is set containment, so reordering the
 *   records inside a block - a credential table shuffled, a config rewritten in
 *   another order - changes nothing.
 *
 *   A NORMALIZER, DECLARED PER RULE. Measured: hashing the byte-to-byte
 *   difference instead of the bytes makes a single byte XOR key vanish, and
 *   tripled what one block reached on a family that re-keys per campaign. On
 *   two other families it left recall unchanged and multiplied collisions with
 *   unrelated families sevenfold. It is a property of the family, so it is a
 *   property of the rule.
 *
 *   A PERCENTAGE AND TWO THRESHOLDS. Measured over one rule against 1300
 *   objects: every clean file scored under 10%, unrelated malware scored under
 *   10%, samples of the rule's own family scored 70-79%, and fifty-three
 *   samples of OTHER families spread across 10-99% - forks sharing part of the
 *   block. That middle is real and is the whole reason the score is reported
 *   rather than a yes or no.
 */

#ifndef KOFENG_KOFPLAGUE_H
#define KOFENG_KOFPLAGUE_H

#include <stdint.h>

/*
 * THE WINDOW, AND THE SAMPLING RATE - shared by everything that produces or
 * consumes these hashes, because a disagreement about either produces two sets
 * that never intersect and no error anywhere.
 *
 * Eight bytes is wide enough that a window is not a coincidence and narrow
 * enough that an edit only disturbs the eight windows that cover it.
 *
 * One in thirty-two is what makes the scan affordable: a 150KB region has about
 * 150000 windows and yields about 4700 hashes to look up. Lower and a small
 * block stops producing enough hashes to score with; higher and the lookup
 * count grows without buying accuracy.
 */
#define KOF_PLAGUE_NG        8u
#define KOF_PLAGUE_SEL_BITS  5u     /* keep 1 window in 2^SEL_BITS */

/* Below this many hashes a block cannot be scored: the percentage would move in
 * steps too coarse to mean anything, and a handful of common windows would
 * reach any threshold. A block that produces fewer is one the author must
 * widen. */
#define KOF_PLAGUE_MIN_HASH  16u

/* And the ceiling on what one rule stores. Measured: a rule cut to 128 hashes
 * reached exactly what the full block reached in eleven of twelve comparisons,
 * so carrying more is storage spent for nothing. The cut is by value - the
 * smallest hashes - so both sides of a comparison keep the same subset. */
#define KOF_PLAGUE_MAX_HASH  128u

/*
 * What a rule hashes: the bytes, or a difference between neighbours.
 *
 * The difference forms exist to make a constant key disappear. If a block is
 * obfuscated with one byte XORed over it, (b[i]^k) ^ (b[i+1]^k) is b[i]^b[i+1]
 * whatever k was - so the same block re-keyed produces the same hashes. SUB
 * does the same for a key that was added rather than XORed.
 *
 * They cost one operation per byte and they LOSE INFORMATION - the absolute
 * value of each byte - which is why they are not the default. See the note on
 * normalizers above.
 */
enum kof_plague_norm {
	KOF_PLAGUE_RAW = 0,   /* the bytes themselves */
	KOF_PLAGUE_XOR = 1,   /* b[i] ^ b[i+1]  - a constant XOR key vanishes */
	KOF_PLAGUE_SUB = 2,   /* b[i+1] - b[i]  - a constant additive key vanishes */
	KOF_PLAGUE_NORM_COUNT
};

/*
 * THE HASH, WRITTEN ONCE AND INCLUDED EVERYWHERE.
 *
 * A rolling polynomial over the window, then one multiply to mix. Both halves
 * matter: the polynomial is what makes the per byte cost a constant instead of
 * eight, and the multiply is what makes the top bits usable for selection -
 * a plain polynomial's low bits are nearly the last byte, so selecting on them
 * would sample by content in the worst possible way.
 *
 * Inline in the header rather than in a library, because ksigbuilder, the
 * engine and the viewer must all produce identical values and the only way to
 * be sure of that is for them to compile the same lines.
 */
#define KOF_PLAGUE_BASE 16777619u          /* the FNV prime, as a radix */
#define KOF_PLAGUE_MIX  2654435761u        /* 2^32 / golden ratio */

/* BASE^(NG-1), the weight of the byte leaving the window. Computed rather than
 * written out so the two constants above stay the only numbers to change. */
static inline uint32_t kof_plague_drop_weight(void)
{
	uint32_t w = 1u, i;

	for (i = 1u; i < KOF_PLAGUE_NG; i++)
		w *= KOF_PLAGUE_BASE;
	return w;
}

/* Mix a window value into the form that is stored and selected on. */
static inline uint32_t kof_plague_mix(uint32_t h)
{
	h *= KOF_PLAGUE_MIX;
	h ^= h >> 15;
	return h;
}

/* Is this window one of the ones kept? Tested on the MIXED value, for the
 * reason the note above gives. */
static inline int kof_plague_selects(uint32_t mixed)
{
	return (mixed >> (32u - KOF_PLAGUE_SEL_BITS)) == 0u;
}

/*
 * A WINDOW OF ONE REPEATED BYTE IS NOT CONTENT, AND IS NEVER KEPT.
 *
 * The all-zero window is the case that shows why. Its rolling value is zero,
 * kof_plague_mix leaves it zero, and zero passes kof_plague_selects for any
 * number of bits - so it is selected in every object that has eight zero bytes
 * anywhere, which is every object with an alignment gap. Worse, zero is the
 * SMALLEST value a window can have, so the k smallest are guaranteed to keep
 * it: every block cut from a span containing padding carries it, and every file
 * containing padding matches it. A hash that everything has and everything
 * matches is a free point towards every threshold.
 *
 * Measured on a shipped rule: 27 hashes, of which one was this, and files
 * matching 19 of them scored exactly the 70 the rule demanded. Without it the
 * same files score 18 of 26, which is 69.
 *
 * Every other constant run has the same shape - it is one window value however
 * long the run is, and it says nothing about the object beyond "there is
 * padding here" - so the test is on the bytes and not on the value.
 *
 * Tested AFTER selection on both sides, because a window that was not selected
 * costs nothing to skip and this costs eight comparisons.
 */
/* One byte of the stream a normalizer presents: the byte itself, or the
 * difference between it and its neighbour. */
static inline uint8_t kof_plague_byte(const uint8_t *p, uint64_t k,
				      uint32_t norm)
{
	return norm == KOF_PLAGUE_RAW ? p[k]
	     : norm == KOF_PLAGUE_XOR ? (uint8_t)(p[k] ^ p[k + 1u])
	     : (uint8_t)(p[k + 1u] - p[k]);
}

/*
 * THE NAME A BLOCK CARRIES, folded from its hashes.
 *
 * Written into a rule as blk_<this>, read back out of the source by its name
 * alone, and shown in the panel as the value a reader clicks. It is a NAME and
 * not a checksum: short enough to read off a row, stable enough that the same
 * block is always called the same thing, and derived from the content so that
 * nobody has to invent one.
 *
 * Here rather than in whoever happens to need it because the generator, the
 * reader and the panel must all arrive at the same spelling; two of them
 * agreeing and one of them not is a rule whose name does not match its own
 * blocks.
 */
static inline uint32_t kof_plague_fold(const uint32_t *h, uint32_t n)
{
	uint32_t i, f = 2166136261u;

	for (i = 0; i < n; i++)
		f = kof_plague_mix(f ^ h[i]);
	return f;
}

/*
 * THE NAME OF A SET OF BLOCKS - what a rule that uses several is called.
 *
 * A condition may be "block A and block B", and then neither block is the
 * verdict: what matched is the pair. Naming the verdict after one of them - the
 * strongest, as it happened - said something true about a part and nothing
 * about the whole, and two rules of one family that shared their strongest
 * block reported the same name.
 *
 * SORTED FIRST, because the fold is order-dependent and the order blocks are
 * asked in is the order a C expression happens to evaluate them: the same set
 * reached by "A && B" and by "B && A" is the same rule and must be called the
 * same thing.
 *
 * ONE BLOCK KEEPS ITS OWN NAME. A rule with a single block is the ordinary case
 * and its verdict already names that block; folding a one-element set would
 * rename every such rule for nothing.
 */
#define KOF_PLAGUE_NAME_MAX 16u

static inline uint32_t kof_plague_name_of(const uint32_t *id, uint32_t n)
{
	uint32_t srt[KOF_PLAGUE_NAME_MAX], i, j;

	if (!id || !n)
		return 0u;
	if (n == 1u)
		return id[0];
	if (n > KOF_PLAGUE_NAME_MAX)
		n = KOF_PLAGUE_NAME_MAX;
	/* Insertion sort: n is a handful - see KOF_PLAGUE_NAME_MAX - and a
	 * small fixed copy is cheaper to read than a call to qsort. */
	for (i = 0; i < n; i++) {
		uint32_t v = id[i];

		for (j = i; j && srt[j - 1u] > v; j--)
			srt[j] = srt[j - 1u];
		srt[j] = v;
	}
	return kof_plague_fold(srt, n);
}

/*
 * ARE THESE TWO HASH SETS THE SAME BLOCK.
 *
 * Not "is this the same list" - that is what comparing the fold answers, and it
 * answers it too strictly. The fold covers the WHOLE list, so one hash more or
 * less names a different block: a rule written before a window rule changed, or
 * a span whose edge moved by a byte, stops being recognisable as the thing it
 * plainly is. A rule loaded over the sample it was cut from then failed to find
 * itself there - no offset, no highlight, and a second row for the same bytes.
 *
 * Overlap is what this format measures everywhere else, so it is what sameness
 * means here too: more than half of the smaller set in the larger. Half is a
 * wide line and it can afford to be, because the spans being compared do not
 * overlap each other - a carve does not cut the same bytes twice.
 *
 * Both lists must be ASCENDING, which is how a block's hashes are always kept:
 * the k smallest, in order.
 */
static inline int kof_plague_same_block(const uint32_t *a, uint32_t na,
					const uint32_t *b, uint32_t nb)
{
	uint32_t i = 0, j = 0, both = 0, need;

	if (!a || !b || !na || !nb)
		return 0;
	while (i < na && j < nb) {
		if (a[i] < b[j])
			i++;
		else if (a[i] > b[j])
			j++;
		else {
			both++;
			i++;
			j++;
		}
	}
	need = (na < nb ? na : nb) / 2u;
	return both > need;
}

/*
 * REGIONS A SIMILARITY BLOCK IS NEVER CUT FROM, BY THEIR KOF_SCAN_* SPELLING.
 *
 * A header describes the object rather than being part of what it does: its
 * bytes are offsets, sizes and flags that a rebuild rewrites and a compiler
 * changes between two builds of one source, so a block cut from one measures
 * the toolchain. The symbol regions are not bytes of the file at all - the host
 * BUILDS those records while parsing - so a block cut from them has no offsets
 * in any file and could not be looked for.
 *
 * Asked in two places that must agree: the carve, which must not offer such a
 * block, and the whole-object pass, which must not feed such a region to a
 * block that named no region. They were two tests on two different strings -
 * one on the label a panel shows, one on the enum a rule writes - and they
 * agreed by luck. The enum spelling is the canonical one: it is what a parser
 * publishes and what a rule carries.
 *
 * A rule may still NAME one of these, and the engine will look there - see
 * plague_prepass. This is about what is offered and what is swept, not about
 * what an author is allowed to ask for.
 */
static inline int kof_plague_region_excluded(const char *enum_name)
{
	const char *p;

	if (!enum_name)
		return 1;
	for (p = enum_name; *p; p++) {
		if (p[0] == '_' && p[1] == 'H' && p[2] == 'E' && p[3] == 'A' &&
		    p[4] == 'D')
			return 1;
		if (p[0] == '_' && p[1] == 'S' && p[2] == 'Y' && p[3] == 'M')
			return 1;
	}
	return 0;
}

static inline int kof_plague_flat(const uint8_t *p, uint64_t at, uint32_t norm)
{
	uint8_t b0 = kof_plague_byte(p, at, norm);
	uint32_t i;

	for (i = 1u; i < KOF_PLAGUE_NG; i++)
		if (kof_plague_byte(p, at + i, norm) != b0)
			return 0;
	return 1;
}

/*
 * ONE BLOCK: a slice of the pack's hash pool, plus where it came from and how
 * it was hashed.
 *
 * The pool is shared by every block in a pack - the same arrangement the
 * pattern packs use for their strings, and for the same reason: one
 * allocation, and a record small enough to walk through.
 *
 * Each block carries its OWN region and normalizer. A rule may want a config
 * table out of the data region hashed raw and a decryptor out of the code
 * region hashed as differences; those are two questions about two places and
 * nothing is served by forcing them to agree.
 */
struct kof_plague_block {
	uint32_t first_hash;      /* into the pack's hash pool */
	uint32_t n_hash;
	uint32_t scan_mask;       /* which region this block was taken from */
	uint8_t  norm;            /* enum kof_plague_norm */
	uint8_t  reserved[3];
};

#endif /* KOFENG_KOFPLAGUE_H */
