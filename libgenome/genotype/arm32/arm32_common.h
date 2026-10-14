/*
 * arm32_common.h - bit helpers the ARM state and Thumb state field accessors
 * share. Pure functions of an integer; nothing about an instruction.
 */
#ifndef KGENOME_GENOTYPE_ARM32_COMMON_H
#define KGENOME_GENOTYPE_ARM32_COMMON_H

#include <stdint.h>

/* Bit n (0 = least significant) of v. */
static inline uint32_t kgenome_arm_bit(uint32_t v, unsigned n)
{
	return (v >> n) & 1u;
}

/* Rotate right; the count is taken modulo 32. */
static inline uint32_t kgenome_arm_ror(uint32_t v, uint32_t n)
{
	n &= 31u;
	return n ? (v >> n) | (v << (32u - n)) : v;
}

/* Sign-extend the low `bits` of v. */
static inline int32_t kgenome_arm_sext(uint32_t v, unsigned bits)
{
	uint32_t m;

	if (!bits)
		return 0;                       /* no bits, no value (and no shift by -1) */
	if (bits >= 32u)
		return (int32_t)v;              /* all of it: already the value */
	m = 1u << (bits - 1u);
	v &= (1u << bits) - 1u;
	return (int32_t)((v ^ m) - m);          /* unsigned: no signed overflow at the top bit */
}

#endif /* KGENOME_GENOTYPE_ARM32_COMMON_H */
