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

#include <x86/x86.h>

/* x86-64 has sixteen, and the sixteenth index is the sentinel - see above. */
#define NGPR 16u

/*
 * AH, CH, DH AND BH FOLD ONTO rax, rcx, rdx AND rbx.
 *
 * the decoder numbers the legacy byte registers by their ENCODING, so those
 * four come back as 4, 5, 6 and 7 - the slots that at every other width
 * mean rsp, rbp, rsi and rdi. Returning that number does not lose
 * information, it INVENTS it: `mov dh, 0x10` reads as a write to rsi, and a
 * caller tracking rsi across it is handed a value the program never put
 * there.
 *
 * MEASURED: msfvenom's x86-64 stager builds its mmap length with
 * `cdq; mov dh,0x10`. The constant map had rdx untouched and rsi clobbered,
 * so the length came back unknown and the register that would hold the
 * mapped address came back zero.
 *
 * The CALLER still has to know it was a partial write - the operand's
 * `size` says so, and writing one byte over an unknown register leaves it
 * unknown. This answers only WHICH register, which is the question here.
 */
static inline uint32_t gpr_of(const struct gt_x86_op *op)
{
	uint32_t r;

	if (op->type != GT_X86_OP_REG || op->rtype != GT_X86_REG_GPR)
		return NGPR;
	r = op->reg;
	if (op->high8 && r >= 4u && r < 8u)
		r -= 4u;
	return r < NGPR ? r : NGPR;
}

#endif /* KOFENG_DISASM_GPR_H */
