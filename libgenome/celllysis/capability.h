/*
 * celllysis/capability.h - THE CAPABILITY VOCABULARY, and the shapes made of it.
 *
 * WHY IT IS A MODULE HEADER AND NOT AN ENGINE ONE.
 *
 * A rule used to reach this vocabulary only through a reference chain the
 * generator wrote for it - the words were the engine's and a rule carried
 * numbers. The words are a rule's own now, so they have to be where a
 * researcher's file can see them.
 *
 * NO RULE NAMES ONE YET. The macros that spent them - kof_pth_has and
 * kof_pth_feeds - went with the chain matcher, because a sequence with
 * distances could not hold the shapes they were asked about. The vocabulary
 * is what was kept; what reads it is being built again.
 *
 * It is the gene vocabulary: the features a
 * sample is reduced to before anything is compared. What a profile made of
 * them looks like is the scanner's business; what they MEAN is here.
 *
 * NOTHING IN THIS FILE READS AN OBJECT. It is names and widths only, so it
 * costs a rule nothing to include and carries no dependency but <stdint.h>.
 */
#ifndef KGENOME_CAPABILITY_H
#define KGENOME_CAPABILITY_H

/* The vocabulary is three headers, one purpose each; this is the one a caller includes. */
#include "capability_word.h"    /* the shape of the word: context, group, action, the macros */
#include "capability_ids.h"     /* the words: enum kgenome_nucleo_cap */
#include "capability_flags.h"   /* KGENOME_NUCLEO_F_*: what a node carries besides it */

/*
 * THE RULE SHAPE STOOD HERE - kof_pth_step and kof_pth_symptom, a sequence
 * of steps with a distance back to the one that fed each.
 *
 * It is gone with the chain. Three things it could not hold and each is the
 * ordinary case: one producer with several consumers is a TREE and not a
 * list; a step joined to another by CONTROL rather than by a value has no
 * row in a sequence at all, which is how `vfork` then `execl("/bin/sh")`
 * came off a page that had already found both; and a DISTANCE in a sequence
 * is changed by inserting one step between two, which makes it the one part
 * of a rule an author can break on purpose.
 *
 * What replaces it is a set of relations between nodes - a producer named by
 * its ROLE in the rule and not by how far back it sits - which is both
 * insertion-proof and canonicalisable, and therefore hashable.
 *
 * What stays is the VOCABULARY, in the three headers above: the capability words
 * and the three tables that answer for them. Those are the unit a gene is built
 * from and they did not depend on the chain.
 */

#endif /* KGENOME_CAPABILITY_H */
