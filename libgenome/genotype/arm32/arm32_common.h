/*
 * arm32_common.h - bit helpers the ARM state and Thumb state field accessors
 * share. Pure functions of an integer; nothing about an instruction.
 */
#ifndef KOF_GENOTYPE_ARM32_COMMON_H
#define KOF_GENOTYPE_ARM32_COMMON_H

#include <stdint.h>

/* Bit n (0 = least significant) of v. */
static inline uint32_t gt_arm_bit(uint32_t v, unsigned n)
{
	return (v >> n) & 1u;
}

/* Bits hi..lo of v. */
static inline uint32_t gt_arm_bits(uint32_t v, unsigned hi, unsigned lo)
{
	return (v >> lo) & ((2u << (hi - lo)) - 1u);
}

/* Rotate right; the count is taken modulo 32. */
static inline uint32_t gt_arm_ror(uint32_t v, uint32_t n)
{
	n &= 31u;
	return n ? (v >> n) | (v << (32u - n)) : v;
}

/* Sign-extend the low `bits` of v. */
static inline int32_t gt_arm_sext(uint32_t v, unsigned bits)
{
	uint32_t m = 1u << (bits - 1u);

	v &= (bits >= 32u) ? 0xffffffffu : ((1u << bits) - 1u);
	return (int32_t)(v ^ m) - (int32_t)m;
}

#endif /* KOF_GENOTYPE_ARM32_COMMON_H */
