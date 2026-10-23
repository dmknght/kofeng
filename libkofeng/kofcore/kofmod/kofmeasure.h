/*
 * kofmeasure.h - the similarity measures and which question each answers;
 * kof_mutation_score.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFMEASURE_H
#define KOFENG_KOFMEASURE_H

#include <stdint.h>
#include "kofctx.h"

/*
 * ============================================================================
 * THE SIMILARITY MEASURES, AND WHICH ONE ANSWERS WHICH QUESTION.
 * ============================================================================
 *
 * They are not spellings of one idea and they do not fail together. Each
 * is listed below with the DATA it needs - which is what decides when a rule
 * may ask it - and what it measured on the cases that break the others.
 *
 *   kof_mutation_score BLOCK. Selected rolling-hash windows of ONE declared run,
 *                    anchored to the region it was cut from.
 *
 *   kof_mutation_blocks   BLOCK SET. The same windows over the WHOLE object against
 *                    a reference's whole set, anchored to nothing.
 *
 *   (the behaviour track is unplugged - see "THE BEHAVIOUR MACROS ARE GONE")
 *
 *
 * WHAT EACH SURVIVES, MEASURED. One object against transformations of itself,
 * and against a program with nothing in common:
 *
 *                              structure  blocks
 *   whole code rebuilt              -       2%      <- the recompile
 *   +20% padding, any kind        83%      98%      <- the padder
 *   UNRELATED, same size         100%      99%      <- the control
 *
 * Read the last row first. NEITHER OF THESE IDENTIFIES ON ITS OWN: an
 * unrelated program of the same size answers 100% and 99%. Structure is a
 * filter, and a rule that rests a verdict on it alone has written a rule about
 * file size. The block set is what carries identity, and a chain is what
 * survives the recompile that takes the blocks away.
 *
 *
 * WHEN A RULE MAY ASK, WHICH IS A CONSEQUENCE OF THE ABOVE AND NOT A POLICY:
 *
 *   BEFORE the normaliser - structure, and both block measures. Structure needs
 *   only the header. The block measures ride on CODE, which the normaliser does
 *   not rewrite, so they answer the same before and after. Measured on 747 real
 *   Mirai samples, structure asked before the normaliser still separates -
 *   15.9% of same-family pairs against 4.4% of cross-family - though it is
 *   about 1.7x weaker on the 693 of them whose content is obscured than on the
 *   54 whose content is not.
 *
 *   AFTER the normaliser - anything whose reference was cut from a normalised
 *   view. The transform rewrites bytes inside the code regions too, through
 *   the library cut and the zero-run collapse, so a block set built on one
 *   form is not the set built on the other: measured over 693 real parent and
 *   view pairs, 71.1% of a parent's blocks survive into its own view on
 *   malware and 93.4% on clean objects. Ask a measure on the form its
 *   reference was written from.
 *
 * A MEASURE IS FOR A KIND OF DATA, NOT FOR EVERY OBJECT.
 *
 * The string set that used to sit here was removed for exactly this reason. It
 * hashed printable runs by their bytes, so any encoding of the strings answered
 * zero; and on a large statically linked binary most of what it collected was
 * not strings at all but printable byte sequences inside machine code, which
 * unrelated programs share. Measured at a threshold of 80, cross-family pairs
 * reached it in 12.11% of Go ELF samples and 7.70% of C++ ones against 2.36%
 * of plain C. A rule written on it measured the toolchain.
 *
 * ============================================================================
 */

/*
 * How much of a declared block is here, nought to a hundred.
 *
 * An ordinary expression, so it composes with everything else a rule can say:
 *
 *     if (kof_find_str(rng, cmd_exe) && kof_mutation_score(cfg) >= 50)
 *
 * which is the case that decided the design - a common string as an anchor
 * beside a block as the measurement. No combining logic lives in the matcher
 * because this is enough to write it here.
 */
#define kof_mutation_score(blk)                                              \
	((ctx)->content->mutation_score((ctx), KOF_PASTE(kof_blockid_, blk)))

/*
 * HOW MUCH OF A REFERENCE'S BLOCK SET THIS OBJECT HAS.
 *
 *     static const uint32_t ref_blocks[] = { 0x..., 0x..., };
 *
 *     if (kof_mutation_blocks(ref_blocks) >= 60u)
 *             kof_debug("reference", 0);
 *
 * The hashes are the selected windows of the reference's loadable regions after
 * its static library was subtracted - the same windows mutation selects, over the
 * whole object rather than carved into named runs.
 *
 * NOT A SUM OF MUTATION SCORES. A rule could add up kof_mutation_score over several
 * declared blocks and divide, and that would be a different measurement: each
 * of those is anchored to the region its block came from and each can fire on
 * its own. This is one set, one containment, one threshold.
 */
/*
 * THE BLOCK VECTOR IS GONE, and the vtable slot behind it (reserved_0) stays NULL.
 *
 * It asked how alike an object was across a reference's WHOLE set of selected
 * windows rather than how much of one named run it carried. The measurement
 * was sound and the gate it needed was not: containment over a whole set is
 * strict enough that it answered on very few objects, and the ones it did
 * answer on were ones a named block already had. Carrying a second set-shaped
 * measure for that is cost without reach.
 *
 * The slot is left where it is so that no entry after it moves and a module
 * built against an older header cannot call the wrong one.
 */

#endif /* KOFENG_KOFMEASURE_H */
