/*
 * genotype/arm32 - the 32-bit ARM architecture's decoders: ARM state here
 * (arm32.h), Thumb state in thumb.h. This file is the ARM state one (the
 * architecture's A32 instruction set: fixed 32-bit words, a condition on
 * nearly everything).
 *
 * WHAT IT IS. A decode TABLE and nothing else. The knowledge of what an
 * encoding is lives in data - arm32_rows.c, written by hand, one row per
 * encoding with its bit pattern beside it - and the code here only indexes it, matches a row and keeps the word. It knows nothing of what an
 * analysis wants to ask: which instructions are branches, which registers a
 * load writes, how an operand is spelled are celllysis's to say from the
 * instruction's NAME and its fields (libgenome/celllysis/decode_arm32.c).
 *
 * THE SAME TWO STEPS AS genotype/x86. gt_arm32_decode finds the instruction:
 * its name (an enum at the granularity of an ENCODING - ADD_IMM, ADD_REG and
 * ADD_RSR are three), its condition, its length, and keeps the raw word.
 * Everything else - register numbers, the rotated immediate, the register list,
 * the addressing-mode bits, the branch offset - is read out of the word by the
 * accessors below, when somebody asks. Building operands is not part of
 * decoding: on x86 that was 15 of the 41 ns, and here too most callers want one
 * or two fields of an instruction or none.
 *
 * THE ROW LOOKUP. The rows are in priority order, the first whose mask matches
 * the word winning. A first-level index on bits 27..20 and 7..4 selects, for each
 * key, the short list of rows that can match it; it is DERIVED from the rows by
 * code (arm32_index.c) the first time a decode needs it - thread-safe, no
 * allocation - and costs a decode one load and one predictable branch.
 * Condition 15 (the unconditional space) is its own table. No row needs a
 * check a mask cannot say: every UNDEFINED and every "valid, not modelled"
 * decision of the decoder this replaced is a bit pattern, so there is no
 * per-row flag.
 *
 * WHAT IT SAYS ABOUT AN ENCODING IT DOES NOT MODEL. The integer space - data
 * processing, multiplies, loads and stores, media instructions, branches, the
 * miscellaneous group - is validity-checked: an encoding the ARM ARM (ARMv7-A
 * with the ARMv8 AArch32 additions it carries: crc32, acquire/release, the
 * unprivileged-free ldrd/strd rule) leaves unallocated decodes as
 * GT_ARM32_I_INVALID with status GT_INVALID, length 4. The coprocessor, VFP and
 * Advanced SIMD spaces are NOT checked: they decode as the one name of their
 * group (CDP, MCR, MRC, LDC, STC, MCRR, MRRC, VLDST, ASIMD_DP) whatever the
 * rest of the word says. Instructions the architecture defines to fault
 * (UDF) decode as GT_ARM32_I_UDF with status GT_OK: they are instructions.
 */
#ifndef KOF_GENOTYPE_ARM32_H
#define KOF_GENOTYPE_ARM32_H

#include <stddef.h>
#include <stdint.h>

#include "arm32_ids.h"
#include "arm32_common.h"
#include "arm32_int.h"
#include "../genotype.h"

struct gt_arm32_insn {
	uint16_t id;            /* enum gt_arm32_id                               */
	uint8_t  cond;          /* the condition field as encoded, 0..15; 15 is   */
	                        /* the unconditional instruction space            */
	uint8_t  len;           /* always 4                                       */
	uint32_t w;             /* the word, for the accessors                    */
};

/*
 * Decode one instruction word. GT_OK, or GT_INVALID with id GT_ARM32_I_INVALID.
 *
 * INLINE, because it is a table index and a short loop and the call was a
 * larger cost than the lookup: out of line, the caller's struct has to live in
 * memory across the call. MEASURED with callgrind over the .text of the 21 Mirai
 * ARM binaries (632,171 instructions), genotype decode plus the celllysis
 * adapter: 120.9 M instructions out of line, 112.0 M inline. The instruction is
 * also handed to the adapter's builders BY VALUE - it is 8 bytes, one register -
 * and its accessors take it so: 109.5 M. ns per instruction: arm32_equiv bench.
 */
static inline enum gt_status gt_arm32_decode(struct gt_arm32_insn *out, uint32_t w)
{
	const struct gt_arm32_row *r;

	gt_arm32_ensure();
	r = &gt_arm32_lists[gt_arm32_idx[gt_arm32_key(w)]];

	/* the last row of every list matches whatever is left */
	while ((w & r->mask) != r->value)
		r++;
	out->id = r->id;
	out->cond = (uint8_t)(w >> 28);
	out->len = 4u;
	out->w = w;
	return r->id == GT_ARM32_I_INVALID ? GT_INVALID : GT_OK;
}

/*
 * ---- FIELD ACCESSORS ------------------------------------------------------
 *
 * POSITIONAL, because the ARM ARM names a register by what it does in each
 * encoding and the same bits are Rn in one, Rd in another and RdHi in a third.
 * r16 is bits 19:16 (Rn; Rd/RdHi of a multiply), r12 bits 15:12 (Rd, Rt; Ra or
 * RdLo of a multiply), r8 bits 11:8 (Rs, Rm of a multiply), r0 bits 3:0 (Rm).
 */
static inline uint32_t gt_arm32_r16(struct gt_arm32_insn in) { return (in.w >> 16) & 15u; }
static inline uint32_t gt_arm32_r12(struct gt_arm32_insn in) { return (in.w >> 12) & 15u; }
static inline uint32_t gt_arm32_r8(struct gt_arm32_insn in)  { return (in.w >> 8) & 15u; }
static inline uint32_t gt_arm32_r0(struct gt_arm32_insn in)  { return in.w & 15u; }

/* Bit n of the word. */
static inline uint32_t gt_arm32_bit(struct gt_arm32_insn in, unsigned n)
{
	return gt_arm_bit(in.w, n);
}

/*
 * The addressing-mode and flag bits, named for the load/store and
 * load/store-multiple encodings: P (bit 24, pre-indexed), U (23, add), B (22,
 * byte; the immediate form of the halfword transfers; the S of an LDM), W (21,
 * write back), and bit 20, which is S in data processing and L (load) in a
 * transfer.
 */
static inline uint32_t gt_arm32_p(struct gt_arm32_insn in) { return gt_arm_bit(in.w, 24); }
static inline uint32_t gt_arm32_u(struct gt_arm32_insn in) { return gt_arm_bit(in.w, 23); }
static inline uint32_t gt_arm32_b(struct gt_arm32_insn in) { return gt_arm_bit(in.w, 22); }
static inline uint32_t gt_arm32_wb(struct gt_arm32_insn in) { return gt_arm_bit(in.w, 21); }
static inline uint32_t gt_arm32_s(struct gt_arm32_insn in) { return gt_arm_bit(in.w, 20); }

/* The rotated immediate of data processing: imm8 rotated right by 2 * rot. */
static inline uint32_t gt_arm32_modimm(struct gt_arm32_insn in)
{
	return gt_arm_ror(in.w & 255u, ((in.w >> 8) & 15u) * 2u);
}

/* The 12-bit offset of a load or store. */
static inline uint32_t gt_arm32_imm12(struct gt_arm32_insn in) { return in.w & 0xfffu; }

/* The 8-bit offset of a halfword or doubleword transfer, split across 11:8 and 3:0. */
static inline uint32_t gt_arm32_imm8_split(struct gt_arm32_insn in)
{
	return ((in.w >> 4) & 0xf0u) | (in.w & 15u);
}

/* movw and movt: imm4:imm12 */
static inline uint32_t gt_arm32_imm16(struct gt_arm32_insn in)
{
	return ((in.w >> 4) & 0xf000u) | (in.w & 0xfffu);
}

/* The 16 bits of a register list. */
static inline uint32_t gt_arm32_list(struct gt_arm32_insn in) { return in.w & 0xffffu; }

/* svc: the 24-bit immediate. bkpt, hvc, smc: the 16 bits split across 19:8 and 3:0. */
static inline uint32_t gt_arm32_imm24(struct gt_arm32_insn in) { return in.w & 0xffffffu; }
static inline uint32_t gt_arm32_imm16_split(struct gt_arm32_insn in)
{
	return ((in.w >> 4) & 0xfff0u) | (in.w & 15u);
}

/*
 * A branch's offset: the signed 24-bit field times four, relative to the
 * instruction's address plus 8. blx (immediate) adds the H bit as a halfword.
 */
static inline int32_t gt_arm32_branch_off(struct gt_arm32_insn in)
{
	return gt_arm_sext(in.w, 24) * 4;
}
static inline uint32_t gt_arm32_h(struct gt_arm32_insn in) { return gt_arm_bit(in.w, 24); }

/* The shift of a register operand: type 0..3 (lsl lsr asr ror), amount 0..31
 * (0 means 32 for lsr and asr, and ror #0 is rrx), or the register holding it. */
static inline uint32_t gt_arm32_shift_type(struct gt_arm32_insn in) { return (in.w >> 5) & 3u; }
static inline uint32_t gt_arm32_shift_imm(struct gt_arm32_insn in) { return (in.w >> 7) & 31u; }

/* sxt, uxt: the rotation, in bytes 0..3 (bits 11:10). */
static inline uint32_t gt_arm32_rot(struct gt_arm32_insn in) { return (in.w >> 10) & 3u; }

#endif /* KOF_GENOTYPE_ARM32_H */
