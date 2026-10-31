/*
 * mutation_window.h - what a WINDOW of bytes is, and how it is hashed.
 *
 * DEFINED BY libgenome: cutting an object into units and hashing a window is the
 * genotyping of bytes (see mutation.h, which includes this). The engine's
 * <celllysis/mutation_window.h> re-exports it and adds the part that is the detector's
 * and the module ABI's own: the block record, the block's name, and the
 * ceiling on what one rule stores.
 */
#ifndef KGENOME_MUTATION_WINDOW_H
#define KGENOME_MUTATION_WINDOW_H

#include <stdint.h>

/*
 * THE WINDOW - shared by everything that produces or
 * consumes these hashes, because a disagreement about either produces two sets
 * that never intersect and no error anywhere.
 *
 * Eight bytes is wide enough that a window is not a coincidence and narrow
 * enough that an edit only disturbs the eight windows that cover it.
 *
 * A block keeps the smallest KGENOME_MUTATION_MINHASH_K of ALL its windows - see
 * kofmutation.h in the mutation engine.
 */
#define KGENOME_MUTATION_NG        8u

/* Below this many hashes a block cannot be scored: the percentage would move in
 * steps too coarse to mean anything, and a handful of common windows would
 * reach any threshold. A block that produces fewer is one the author must
 * widen. */
#define KGENOME_MUTATION_MIN_HASH  16u

/*
 * What a rule hashes: the bytes. There is no other form.
 *
 * A form that hashed the difference between neighbouring bytes (so that a constant XOR or
 * additive key vanishes), and the normalizer argument that chose it, were removed 2026-10-31
 * by the owner: nothing in the tool decides which form a block needs, and an encoding that
 * is detected is decoded by the NORMALISE stage (the normalised view), not by the matcher.
 * The pack's block record keeps a byte where the normalizer was (the layout is the owner's to
 * change); it is written 0 and a loader refuses any other value.
 */

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
#define KGENOME_MUTATION_BASE 16777619u          /* the FNV prime, as a radix (KOF_HASH_PRIME; not
                                                  * included here: this header is freestanding) */
#define KGENOME_MUTATION_MIX  2654435761u        /* 2^32 / golden ratio */

/* BASE^(NG-1), the weight of the byte leaving the window. Computed rather than
 * written out so the two constants above stay the only numbers to change. */
static inline uint32_t kgenome_mutation_drop_weight(void)
{
	uint32_t w = 1u, i;

	for (i = 1u; i < KGENOME_MUTATION_NG; i++)
		w *= KGENOME_MUTATION_BASE;
	return w;
}

/* Mix a window value into the form that is stored: `h *= MIX; h ^= h >> 15`. */
static inline uint32_t kgenome_mutation_mix(uint32_t h)
{
	h *= KGENOME_MUTATION_MIX;
	return h ^ (h >> 15);
}

/*
 * A WINDOW OF ONE REPEATED BYTE IS NOT CONTENT, AND IS NEVER KEPT.
 *
 * The all-zero window is the case that shows why. Its rolling value is zero,
 * kgenome_mutation_mix leaves it zero, and so it is a window of every object that has eight zero bytes anywhere, which is
 * every object with an alignment gap. Worse, zero is the
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
 * Tested after the cheaper comparison on both sides, because a window that
 * would not have been kept costs nothing to skip and this costs eight.
 */
static inline int kgenome_mutation_flat(const uint8_t *p, uint64_t at)
{
	uint8_t b0 = p[at];
	uint32_t i;

	for (i = 1u; i < KGENOME_MUTATION_NG; i++)
		if (p[at + i] != b0)
			return 0;
	return 1;
}

/*
 * WHICH HALF OF THE OBJECT A BLOCK WAS CUT FROM, and why that is part of the
 * match rather than a note about it.
 *
 * A statically linked binary is two things in one file: what the author wrote,
 * and what the linker pulled in. Measured in koflib.h, two CLEAN binaries reach
 * a median string-set Jaccard of 0.25 and a 90th percentile of 0.99 purely
 * through the second - so a similarity number that does not know which half it
 * is measuring is measuring the toolchain and calling it identity.
 *
 * The first answer to that was to refuse the library outright: the matcher
 * skipped every window inside a library span, so a block cut from libc could
 * never be credited. That keeps the contamination out and throws away a real
 * question with it - "do these two samples carry the SAME statically linked
 * runtime" is a fact about a build, and for a family that ships one vendored
 * copy of one library it is a strong one.
 *
 * So the two are counted separately instead. A block remembers which side it
 * came from, a window knows which side it is in, and a block is credited only
 * by windows from its own side. Neither number can contaminate the other,
 * because they are never added together.
 *
 * USER IS ZERO ON PURPOSE. It is what the reserved bytes of every pack built
 * before this held, and it is also what every object with no library at all
 * resolves to - so nothing already written changes meaning, and a database
 * that predates this reads exactly as it did.
 */
enum kgenome_mutation_side {
	KGENOME_MUTATION_SIDE_USER = 0,   /* everything the static library is not */
	KGENOME_MUTATION_SIDE_LIB         /* inside a span kgenome_true_find named */
};

#endif /* KGENOME_MUTATION_WINDOW_H */
