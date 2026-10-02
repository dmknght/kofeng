/*
 * gpr.h - the general-purpose register a decoded operand names.
 *
 * Two sweeps read the same operands for different reasons - flow.c follows
 * what the code DOES and xref.c follows where its addresses COME FROM - and
 * both begin by asking this one question of an operand. They asked it with
 * their own copy of the same five lines and their own #define of the same
 * sixteen, which is two places for a decoder upgrade that renames a register
 * class to be applied once and forgotten once.
 *
 * NGPR IS THE "NOT A REGISTER" ANSWER AS WELL AS THE COUNT, which is why it is
 * here rather than in either sweep: both use it to index a per-register array
 * and both use it to mean "this operand names none", so the two meanings have
 * to be the same number.
 */

#ifndef KOFENG_DISASM_GPR_H
#define KOFENG_DISASM_GPR_H

#include <stdint.h>

#include "bddisasm.h"

/* x86-64 has sixteen, and the sixteenth index is the sentinel - see above. */
#define NGPR 16u

static inline uint32_t gpr_of(const ND_OPERAND *op)
{
	if (op->Type != ND_OP_REG || op->Info.Register.Type != ND_REG_GPR)
		return NGPR;
	return op->Info.Register.Reg < NGPR ? op->Info.Register.Reg : NGPR;
}

#endif /* KOFENG_DISASM_GPR_H */
