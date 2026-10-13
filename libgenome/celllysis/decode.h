/*
 * decode.h - one decoded instruction, in the one form the engine reads.
 *
 * WHY THIS EXISTS.
 *
 * The sweep used to read whatever the decoder in front of it produced:
 * the decoder's INSTRUX on x86, hand-written bit tests for ARM, two more for
 * Thumb and the half-word encodings. So the same question - does this write
 * a register, where does this branch go, is this a call - was answered four
 * times in four spellings, and every one of them had to be kept correct
 * against the same corpus. A fifth architecture meant a fifth copy of the
 * sweep, not a fifth decoder.
 *
 * The form itself is kofmod/cell.h's, which a signature module already
 * reads. One form, not two: a rule and the engine see the same instruction
 * the same way, and nothing has to be translated between them.
 *
 * NOT TEXT. There is no mnemonic string anywhere in it. A consumer that
 * wanted to know whether something was a call compared a number, and a
 * consumer that wanted the operand read a field; neither parsed anything.
 * Text belongs to whatever draws a screen, and drawing is not what this
 * layer is for.
 *
 * WHAT A DECODER PROMISES. `op` is never left at KGENOME_CELL_OTHER when the class
 * is one the vocabulary has, `len` is the real length, `wmask` names EVERY
 * register the instruction writes including the ones it does not spell, and
 * an operand that is absent is KGENOME_CELL_O_NONE rather than zeroed. A decoder
 * that cannot answer says so by returning 0 - it does not guess a length.
 */
#ifndef KGENOME_DISASM_DECODE_H
#define KGENOME_DISASM_DECODE_H

#include <stddef.h>
#include <stdint.h>

#include <celllysis/cell.h>

/*
 * REGISTERS ARE AN INDEX AND THE ARCHITECTURE SAYS WHAT IT MEANS.
 *
 * x86-64 uses 0..15 in the decoder's own order, which is how the sweeps size
 * their per-register arrays. ARM uses r0..r15, MIPS
 * $0..$31. The number is only ever used to index those arrays and to
 * compare two operands, so what matters is that one decoder is consistent
 * with itself, not that two architectures agree.
 */
#define KGENOME_CELL_NREG 32u

/* Which special register a KGENOME_CELL_MOV_SPECIAL touches, carried in `cond`. */
#define KGENOME_CELL_SR_CR 0u
#define KGENOME_CELL_SR_DR 1u
#define KGENOME_CELL_SR_TR 2u

/*
 * ONE INSTRUCTION, DECODED - or 0 when these bytes are not one.
 *
 * `va` is the address the instruction would run at, which the decoder needs
 * for a relative branch and for rip-relative addressing.
 */
uint32_t kgenome_cell_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			unsigned bits, struct kgenome_cell_insn *out);

/*
 * THE ONE WAY IN: the decoder for `arch` (KOF_ARCH_*), chosen here and nowhere
 * else. `be` is big-endian code and `va` the address the instruction runs at.
 * 0 when the bytes are not an instruction or `n` is too short.
 */
uint32_t kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n,
		     uint64_t va, struct kgenome_cell_insn *out);

/* The decoders themselves, for a caller that already knows which it wants
 * (tests, tools, and the ISA a cursor cannot tell: Thumb). */
/* `be` is big-endian; MIPS ships both ways and bots use both. */
uint32_t kgenome_cell_decode_mips(const uint8_t *p, uint32_t n, uint64_t va,
			 int be, struct kgenome_cell_insn *out);

/*
 * ARM. Registers are r0..r15 as 0..15 (sp 13, lr 14, pc 15) in wmask.
 *
 * `be` is big-endian: ARM-BE bots exist. kgenome_cell_decode_arm32 reads one 4-byte ARM state
 * word; kgenome_cell_decode_thumb reads Thumb state and returns 2 or 4, the real length of the
 * instruction at p (the caller knows from the ELF mapping symbols or the
 * low bit of a branch target that the code is Thumb).
 */
uint32_t kgenome_cell_decode_arm32(const uint8_t *p, uint32_t n, uint64_t va,
			int be, struct kgenome_cell_insn *out);
uint32_t kgenome_cell_decode_thumb(const uint8_t *p, uint32_t n, uint64_t va,
			int be, struct kgenome_cell_insn *out);

/* AArch64: x0..x30 as 0..30, sp as 31 (wmask bit 31). Always little-endian. */
uint32_t kgenome_cell_decode_arm64(const uint8_t *p, uint32_t n, uint64_t va,
			struct kgenome_cell_insn *out);

#endif /* KGENOME_DISASM_DECODE_H */
