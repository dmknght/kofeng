/*
 * ovlflow.h - comparing two capability sequences, which is overlord's job.
 *
 * WHERE THE SPLIT IS. kofdisasm/flow.c reads code and produces nodes; it holds
 * no opinion about whether two programs are alike. Deciding that is similarity,
 * and similarity lives here beside the string and block dimensions - one place
 * that already knows how to compare, and already refuses to answer with a
 * single number.
 *
 *
 * WHY LOCAL ALIGNMENT AND NOT A PATTERN.
 *
 * A stager IS its sequence. A trojan that also has a loader carries that
 * sequence as ONE SEGMENT among many, and a miner's interesting part is twenty
 * nodes among two thousand. Matching the whole of one against the whole of the
 * other answers the wrong question for both.
 *
 * Local alignment answers "is there a segment of A that lines up with a segment
 * of B", which is exactly the shape of the problem, and it was invented for it.
 * It also gets the three things a variant does for free:
 *
 *     junk inserted   -> a gap, priced by the gap penalty
 *     a step dropped  -> a deletion, costing points rather than the match
 *     re-encoding     -> already gone, one layer down in flow.c
 *
 * IT IS CHEAP HERE AND NOWHERE ELSE. The table is nodes by nodes, and a region
 * holds a handful: measured on /usr/bin, 79% of the regions that hold anything
 * hold one or two, and 0.78% of all regions hold three or more. Alignment over
 * bytes is not affordable; alignment over this is a few dozen cells.
 *
 *
 * THE ANSWER IS NOT A SCORE.
 *
 * kofoverlord.h states why and this keeps to it: the internal dynamic program
 * has to add numbers up, and none of them leaves this file. What comes back is
 * WHAT LINED UP - how many nodes, how many of them rare, how many gaps, how
 * long - and a rule is a conjunction over those. A caller that wants one number
 * is asking for the projection that throws away what separates two shapes.
 */
#ifndef KOFENG_OVLFLOW_H
#define KOFENG_OVLFLOW_H

#include <stdint.h>

#include "../kofdisasm/flow.h"

/*
 * HOW MUCH A CAPABILITY IS WORTH, and every one of these is MEASURED.
 *
 * Share of the regions that hold any node at all, over 846 x86-64 binaries in
 * /usr/bin - 76510 regions, 2894 of them with nodes:
 *
 *     file-open   66.62%      alloc         5.29%
 *     read        14.89%      net-open      3.52%
 *     write       12.61%      ptrace        2.38%
 *     exec-image   8.36%      net-connect   1.76%
 *     sleep        6.74%      net-accept    1.07%
 *     spawn        6.19%      memfd         0.07%
 *                             alloc-exec    0.10%
 *
 * A ladder and not the raw number: the shares come from ONE corpus on ONE
 * machine, so the ORDER is evidence and the third decimal is not. Four bands,
 * each an order of magnitude, so a rule does not move when the corpus does.
 *
 * "file-open in both" is worth almost nothing and the weight says so. That is
 * the whole point of measuring rather than assigning - it would have been easy
 * to give reading a file the same standing as mapping executable memory.
 */
#define KOF_OVLF_W_COMMON  1u   /* over 50%   */
#define KOF_OVLF_W_ORDINARY 2u  /* 10 - 50%   */
#define KOF_OVLF_W_NOTABLE 4u   /* 1 - 10%    */
#define KOF_OVLF_W_RARE    8u   /* under 1%   */

uint8_t kof_ovlf_weight(uint8_t cap);

/*
 * IS THIS SEQUENCE WORTH COMPARING AT ALL - the gate, and it is most of the
 * cost saving.
 *
 * Two nodes of "read then write" is every program ever written, and aligning
 * it against anything produces a match that means nothing. So a sequence has
 * to be long enough to say something AND hold something that is not everywhere.
 * On /usr/bin that leaves well under one percent of regions as candidates
 * before a single cell of the table is filled.
 */
#define KOF_OVLF_MIN_NODES 2u
/*
 * AND THE BAR IS THE SUM OF THE WEIGHTS, not the presence of a rare one.
 *
 * "Contains something rare" was the first rule here and MEASUREMENT REFUSED
 * IT. It passed zero of 76510 clean regions, which read as a triumph until the
 * same gate was run against the things it is for: the meterpreter x64 stager
 * holds connect and sleep - 1.76% and 6.74%, neither of them rare - and was
 * rejected too. A gate that turns away every sample it exists to catch is not
 * selective, it is broken.
 *
 * Twelve, which is three NOTABLE capabilities, or one RARE beside one NOTABLE.
 * It says the same thing the first rule meant - "this region claims more than
 * every program claims" - without making it hang on one band.
 */
#define KOF_OVLF_MIN_WEIGHT 12u
int kof_ovlf_worth(const struct kof_flow_node *v, uint32_t n);

/*
 * WHAT LINED UP. Every field is a count, and a rule reads them together.
 */
struct kof_ovlf_hit {
	uint8_t  matched;    /* nodes aligned as the same capability      */
	uint8_t  related;    /* aligned within one family - see families  */
	uint8_t  mismatch;   /* aligned against something else            */
	uint8_t  gaps;       /* how many runs of insertion or deletion    */
	uint8_t  gap_len;    /* how long they are in total                */
	uint8_t  rare;       /* how many of the matches were rare         */
	uint8_t  chained;    /* matched nodes carrying `from` or EXECUTED */
	uint8_t  a_first, a_last;   /* the segment of A that lined up     */
	uint8_t  b_first, b_last;
};

/*
 * Align two sequences and report what lined up. Returns 0 - and leaves the hit
 * zeroed - when either side fails the gate or nothing aligned.
 *
 * Symmetric in the sense that matters: neither argument is the rule and
 * neither is the sample. Comparing two unknown samples to cluster variants is
 * the same call as comparing one to a reference, which is the property
 * kof_ovl_compare already has and the reason this is shaped the same way.
 */
int kof_ovlf_align(const struct kof_flow_node *a, uint32_t na,
		   const struct kof_flow_node *b, uint32_t nb,
		   struct kof_ovlf_hit *out);

#endif /* KOFENG_OVLFLOW_H */
