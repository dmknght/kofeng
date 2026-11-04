/*
 * genotype/ppc - a PowerPC (Power ISA, 32-bit and 64-bit) instruction decoder.
 *
 * WHAT IT IS. PowerPC instructions are one 32-bit word (the byte order of the object decides how the
 * four bytes make it: big-endian for PowerPC 32 and ppc64 BE, little-endian for ppc64le). So there is
 * no length to find and no prefix: decoding is "which instruction is this word". ppc_tab.c holds that
 * as DATA - a 64-entry table on the six-bit primary opcode that names the identity, hands the word to
 * a short row list, or indexes the ten-bit extended opcode of primary opcode 31 - and ppc.c only
 * walks it. Nothing in the code knows an encoding but the 32/64-bit mode check.
 *
 * TWO STEPS, AS genotype/arm64. kgenome_ppc_decode finds the identity (KGENOME_PPC_I_*, ppc_ids.h)
 * and keeps the word; registers, immediates and the branch displacement are read out of the word by
 * the accessors below. The engine's classes, operand forms and written-register masks are
 * celllysis's (celllysis/decode_ppc.c).
 *
 * THE MODE. `wide` says the object is the 64-bit architecture. A 64-bit-only instruction (ld, std,
 * rld*, mulld, extsw, ...) is INVALID in 32-bit mode: a PowerPC 32 core takes an illegal-instruction
 * exception on it, so the answer is exact for the object, not a guess.
 *
 * WHAT IS DECIDED. Fixed bits are compared exactly. A field the architecture says "should be zero"
 * (the reserved bit 31 of an X-form load, the BO "z" bits, the L bit of a 32-bit compare) is NOT
 * checked: the processor ignores it, and rejecting the word would lose a real instruction (the same
 * decision as arm64.h). The exceptions are forms the architecture itself calls invalid, each a fixed
 * rule and not a guess: stwcx. and stdcx. with Rc = 0; a compare with L = 1 in 32-bit mode (cmpd is a
 * 64-bit instruction, like every identity marked P64); bcctr whose BO asks to decrement CTR.
 *
 * WHAT IS NOT TABLED, and what each answers (never a guessed instruction):
 *   UNSUPPORTED (status KGENOME_UNSUPPORTED, length four): primary opcode 4 (AltiVec, SPE), opcodes
 *       56, 57, 60, 61 (quad, pair, VSX), and the AltiVec/VSX loads and stores of opcode 31 that
 *       write no general register.
 *   INVALID: everything else not listed in ppc_ids.h - which includes embedded and Book E
 *       instructions (rfci, wrtee, tlbwe, ...), the SLB instructions, the ISA 2.06+ extensions of
 *       opcode 31 (popcnt, prtyw, cmpb, ldbrx, vsx moves, ...) and the ISA 3.1 prefixed (8-byte)
 *       instructions of primary opcode 1. INVALID here means "not in the tabled set", not "never
 *       allocated". Next step for each: a row per family, with its adapter handler.
 */
#ifndef KGENOME_GENOTYPE_PPC_H
#define KGENOME_GENOTYPE_PPC_H

#include <stddef.h>
#include <stdint.h>

#include "ppc_ids.h"
#include "../genotype.h"

/* A decoded instruction: its identity and the word it came from. */
struct kgenome_ppc_insn {
	uint32_t word;
	uint16_t id;                    /* enum kgenome_ppc_id */
};

/*
 * Decode one word (already assembled in host order from the four instruction bytes). Always fills
 * `out`. The status is KGENOME_OK for an instruction, KGENOME_UNSUPPORTED for the identity
 * UNSUPPORTED, KGENOME_INVALID for INVALID.
 */
enum kgenome_status kgenome_ppc_decode(struct kgenome_ppc_insn *out, uint32_t word, int wide);

/* The identity's name, for a tool or a test; "?" past the end. */
const char *kgenome_ppc_name(unsigned id);

/* ---- fields every format shares (the manuals' bit numbers are big-endian: bit 0 is the MSB) ----- */

static inline unsigned kgenome_ppc_bits(const struct kgenome_ppc_insn *in, unsigned lo, unsigned n)
{
	return (in->word >> lo) & ((1u << n) - 1u);
}
/* RT / RS / FRT / FRS / BO / TO / BF:  bits 6..10 */
static inline unsigned kgenome_ppc_rt(const struct kgenome_ppc_insn *in) { return (in->word >> 21) & 31u; }
static inline unsigned kgenome_ppc_rs(const struct kgenome_ppc_insn *in) { return (in->word >> 21) & 31u; }
static inline unsigned kgenome_ppc_bo(const struct kgenome_ppc_insn *in) { return (in->word >> 21) & 31u; }
/* RA / BI / BFA: bits 11..15 */
static inline unsigned kgenome_ppc_ra(const struct kgenome_ppc_insn *in) { return (in->word >> 16) & 31u; }
static inline unsigned kgenome_ppc_bi(const struct kgenome_ppc_insn *in) { return (in->word >> 16) & 31u; }
/* RB / SH (32-bit forms) / NB: bits 16..20 */
static inline unsigned kgenome_ppc_rb(const struct kgenome_ppc_insn *in) { return (in->word >> 11) & 31u; }
/* Rc (bit 31) and LK (bit 31), AA (bit 30), OE (bit 21) */
static inline unsigned kgenome_ppc_rc(const struct kgenome_ppc_insn *in) { return in->word & 1u; }
static inline unsigned kgenome_ppc_lk(const struct kgenome_ppc_insn *in) { return in->word & 1u; }
static inline unsigned kgenome_ppc_aa(const struct kgenome_ppc_insn *in) { return (in->word >> 1) & 1u; }
static inline unsigned kgenome_ppc_oe(const struct kgenome_ppc_insn *in) { return (in->word >> 10) & 1u; }
/* the L bit of a compare (bit 10) */
static inline unsigned kgenome_ppc_cmp_l(const struct kgenome_ppc_insn *in) { return (in->word >> 21) & 1u; }
/* the condition-register field a compare or crop writes: BF (bits 6..8), BFA (bits 11..13) */
static inline unsigned kgenome_ppc_bf(const struct kgenome_ppc_insn *in) { return (in->word >> 23) & 7u; }

/* ---- immediates ------------------------------------------------------------------------------- */

/* the signed 16-bit immediate of a D-form */
static inline int64_t kgenome_ppc_simm(const struct kgenome_ppc_insn *in)
{
	return (int64_t)(int16_t)(in->word & 0xffffu);
}
static inline unsigned kgenome_ppc_uimm(const struct kgenome_ppc_insn *in) { return in->word & 0xffffu; }

/* the rotate fields of the M-form (rlwinm, rlwimi, rlwnm): SH (or RB) bits 16..20, MB 21..25, ME 26..30 */
static inline unsigned kgenome_ppc_sh(const struct kgenome_ppc_insn *in) { return (in->word >> 11) & 31u; }
static inline unsigned kgenome_ppc_mb(const struct kgenome_ppc_insn *in) { return (in->word >> 6) & 31u; }
static inline unsigned kgenome_ppc_me(const struct kgenome_ppc_insn *in) { return (in->word >> 1) & 31u; }

/* the 10-bit special-purpose register number of mfspr / mtspr (its two halves are swapped in the word) */
static inline unsigned kgenome_ppc_spr(const struct kgenome_ppc_insn *in)
{
	return ((in->word >> 16) & 31u) | (((in->word >> 11) & 31u) << 5);
}

/* the DS-form displacement of ld, ldu, lwa, std, stdu: bits 16..29 times four, signed */
static inline int64_t kgenome_ppc_ds(const struct kgenome_ppc_insn *in)
{
	return (int64_t)(int16_t)(in->word & 0xfffcu);
}

/*
 * The signed byte displacement of B (LI, 24 bits times four: +-32 MB) and of BC (BD, 14 bits times
 * four: +-32 KB), read from the word. For AA=0 it is relative to the address of the instruction
 * ITSELF (PowerPC has no "+ length"); for AA=1 it IS the target (sign-extended). 0 for any other
 * identity.
 */
int64_t kgenome_ppc_branch_off(const struct kgenome_ppc_insn *in);

/*
 * The branch target in the address space the object runs in: the displacement against `pc`, or
 * the absolute value for AA, wrapped to 32 bits when !wide. Only B and BC have one; for any other
 * identity this returns 0 and `*has` is 0.
 */
uint64_t kgenome_ppc_branch_target(const struct kgenome_ppc_insn *in, uint64_t pc, int wide, int *has);

#endif /* KGENOME_GENOTYPE_PPC_H */
