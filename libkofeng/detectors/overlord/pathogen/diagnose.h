/*
 * diagnose.h - comparing two capability sequences, which is overlord's job.
 *
 * WHERE THE SPLIT IS. analyzers/parsers/binaries/disasm/flow.c reads code and produces nodes; it holds
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
#ifndef KOFENG_DIAGNOSE_H
#define KOFENG_DIAGNOSE_H

#include <stdint.h>

#include <kofmod/kofoverlord.h>
#include "../../../analyzers/parsers/binaries/disasm/flow.h"

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
#define KOF_DIAG_MIN_STEPS 2u
/*
 * AND THERE IS NO WEIGHT BAR ANY MORE.
 *
 * There was one: every capability carried a weight from a four-band ladder
 * measured over one corpus, a chain's weights were summed, and anything
 * under twelve was thrown away before a reader or a rule ever saw it.
 *
 * MEASURED, IT DELETED THE EVIDENCE IT WAS MEANT TO RANK. The sum is taken
 * over a chain's STEPS, and adjacent identical steps merge into one with a
 * count - so a function that resolves forty-six symbols in a row collapses
 * to a single `lib-resolve`, scores four, and the whole chain is dropped.
 * Forty-six nodes of a loader's import stub cost the node budget and
 * produced nothing. The bar could not see the difference between a program
 * doing one thing once and a program doing it forty-six times, because
 * merging had already thrown that away before the sum was taken.
 *
 * A BAR BELONGS WHERE THE CLAIM IS MADE, NOT WHERE THE EVIDENCE IS BUILT. A
 * rule that wants three notable capabilities can say so; the analyser's job
 * is to report what is there. So every chain the sweep builds is kept, and
 * what to do with it is the reader's decision.
 */

/*
 * WHAT LINED UP. Every field is a count, and a rule reads them together.
 */
struct kof_diag_hit {
	uint8_t  matched;    /* nodes aligned as the same capability      */
	uint8_t  related;    /* aligned within one family - see families  */
	uint8_t  mismatch;   /* aligned against something else            */
	uint8_t  gaps;       /* how many runs of insertion or deletion    */
	uint8_t  gap_len;    /* how long they are in total                */
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
int kof_diag_align(const struct kof_flow_node *a, uint32_t na,
		   const struct kof_flow_node *b, uint32_t nb,
		   struct kof_diag_hit *out);

/*
 * THE STORED CHAIN - struct kof_pth_symptom - LIVES IN kofmod/kofoverlord.h,
 * beside kof_plague_shape and for the same reason: a rule carries one, and a rule
 * is compiled against the kofmod headers and nothing else.
 */

/*
 * WHICH FLAGS ARE ABOUT THE PROGRAM, and which are about how well it was read.
 *
 * LOW8 says the selector resolved only in its low byte - that is a fact about
 * the sweep's confidence, it moves when the code is re-encoded, and a rule
 * that carried it would be a rule about the decoder. It is dropped. The rest
 * are claims about what the code does and are kept.
 */
/* And BY_NAME with them: a stored symptom should remember whether its steps
 * were the avoidable kind, so a rule written from one can say so. */
#define KOF_PTH_FLAG_KEEP ((uint8_t)(KOF_FLOWF_LOOP | KOF_FLOWF_EXECUTED | \
				      KOF_FLOWF_VIA_REG | KOF_FLOWF_WX | \
				      KOF_FLOWF_DGRAM | KOF_FLOWF_LOCAL | \
				      KOF_FLOWF_BY_NAME))

/*
 * Pack a swept region into one. Returns 0 - and leaves the chain empty - when
 * the region does not clear the same gate kof_diag_align uses, so a draft
 * never stores a shape too thin to have meant anything.
 */
int kof_diag_of(const struct kof_flow_node *v, uint32_t n,
		      struct kof_pth_symptom *out);

/*
 * DO THESE CAPABILITIES STAND TOGETHER, within `window` steps of each other?
 *
 * LOCALITY IS MOST OF THE SIGNAL, and that is the measurement this exists
 * for. Over 2416 botnet objects against 1260 Linux binaries from this
 * machine:
 *
 *     the best SET of capabilities, anywhere in the object   1.5x
 *     net-connect, write, read, sleep ANYWHERE               1.5x
 *     the same four WITHIN FOUR STEPS of one chain          43x
 *
 * A program that opens a socket somewhere and sleeps somewhere else is every
 * program. One that connects, writes, reads and sleeps inside four steps is
 * doing one thing, and that one thing is what a rule is about.
 *
 * NO NAMES, AND THAT IS DELIBERATE. This was a table of labelled behaviours
 * for one revision - "beacon", "download", "serve" - and a label is a second
 * vocabulary to keep: every family that does something new needs a new one,
 * and the ones already there drift. Worse, it HIDES the thing it names. A
 * researcher reading "beacon" has lost the sequence that produced it, and
 * the sequence is what they came for.
 *
 * So the engine answers the question and the researcher asks it. What counts
 * as a behaviour is a rule's claim, stated in the rule, where it can be read
 * and argued with - and every row of that claim can be counted on clean
 * software, which a label cannot.
 */
int kof_diag_near(const struct kof_flow_node *v, uint32_t n,
		  const uint8_t *cap, uint32_t n_cap, uint32_t window);

/* The capability set, for the prefilter that decides whether a candidate is
 * worth aligning at all. A candidate missing any of these bits cannot align
 * against this chain, whatever else it has. */
uint64_t kof_diag_mask(const struct kof_pth_symptom *c);

/*
 * HOW MUCH OF A STORED CHAIN THIS REGION CARRIES, as a percentage of the
 * stored chain's length - the same shape of answer kof_plague_shape_pct and
 * kof_plague_blocks_pct gives, so the table can put it in the same column.
 *
 * A HUNDRED MEANS EVERY STEP LINED UP, not that the two are the same program.
 * What else lined up, and at what cost, is kof_diag_align's answer, and a
 * rule that wants those reads them there.
 */
uint32_t kof_diag_pct(const struct kof_pth_symptom *ref,
			    const struct kof_flow_node *v, uint32_t n);

/* The stored chain as nodes again, so it can be aligned against a sample.
 * Writes at most KOF_PTH_SYMPTOM_MAX and returns how many. */
uint32_t kof_diag_nodes(const struct kof_pth_symptom *c,
			      struct kof_flow_node *out);

#endif /* KOFENG_DIAGNOSE_H */
