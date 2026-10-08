/* arm64_int.h - the layout of the AArch64 decode tables. Shared by arm64.c and
 * arm64_tab.c, and by nobody else. */
#ifndef KOF_GENOTYPE_ARM64_INT_H
#define KOF_GENOTYPE_ARM64_INT_H

#include <stdint.h>

/*
 * A ROW is "a word matches when (word & mask) == val". A list of rows is tried in
 * order and its LAST row has mask 0, so something always matches: priority is the
 * order, which is how "this pattern, except that one" is said without a second
 * mask. The identity of a row is either an instruction (id < GT_ARM64_NODE0) or
 * the number of a node to continue in.
 */
struct gt_arm64_row {
	uint32_t mask, val;
	uint16_t id;
	uint16_t fl;                    /* GT_ARM64_RF_* */
};

/* The one check a row can ask for that a mask cannot say: the N:imms pair of a logical immediate names a bitmask. */
#define GT_ARM64_RF_BITMASK 0x0001u

/*
 * A NODE is an index. The key is two bit-fields of the word, the second placed
 * above the first - ((w >> sh0) & m0) | (((w >> sh1) & m1) << n0), with n0 the
 * width of the first - and it selects a row list. A field the node does not need
 * has mask 0, and a node with both has one list.
 */
struct gt_arm64_node {
	uint8_t sh0, m0, sh1, m1, n0;
	const struct gt_arm64_row *const *b;
};

#define GT_ARM64_NODE0 0x400u

extern const struct gt_arm64_node gt_arm64_top;
extern const struct gt_arm64_node *const gt_arm64_nodes[];
/* name and attributes, one per identity */
extern const char *const gt_arm64_names[];
extern const uint8_t gt_arm64_lsk[];
extern const uint8_t gt_arm64_am[];

#endif /* KOF_GENOTYPE_ARM64_INT_H */
