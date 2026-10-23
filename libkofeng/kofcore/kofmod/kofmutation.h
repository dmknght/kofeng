/*
 * kofmutation.h - similarity matching over a BLOCK a researcher chose.
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

#ifndef KOFENG_KOFMUTATION_H
#define KOFENG_KOFMUTATION_H

#include <stdint.h>
#include <celllysis/mutation_window.h>

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define KOF_MUTATION_RAW                   KGENOME_MUTATION_RAW
#define kof_mutation_mix                   kgenome_mutation_mix
#define kof_mutation_norm                  kgenome_mutation_norm
#define kof_mutation_side                  kgenome_mutation_side



/* And the ceiling on what one rule stores. Measured: a rule cut to 128 hashes
 * reached exactly what the full block reached in eleven of twelve comparisons,
 * so carrying more is storage spent for nothing. The cut is by value - the
 * smallest hashes - so both sides of a comparison keep the same subset. */
#define KOF_MUTATION_MAX_HASH  128u



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
static inline uint32_t kof_mutation_fold(const uint32_t *h, uint32_t n)
{
	uint32_t i, f = 2166136261u;

	for (i = 0; i < n; i++)
		f = kof_mutation_mix(f ^ h[i]);
	return f;
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
static inline int kof_mutation_same_block(const uint32_t *a, uint32_t na,
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

struct kof_mutation_block {
	uint32_t first_hash;      /* into the pack's hash pool */
	uint32_t n_hash;
	uint32_t scan_mask;       /* which region this block was taken from */
	uint8_t  norm;            /* enum kof_mutation_norm */
	uint8_t  side;            /* enum kof_mutation_side */
	uint8_t  reserved[2];
};

#endif /* KOFENG_KOFMUTATION_H */
