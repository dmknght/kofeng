/*
 * genotype/arm32, Thumb state: the 16-bit and 32-bit Thumb instruction sets of
 * the 32-bit ARM architecture (Thumb-1, and Thumb-2's wide encodings). ARM
 * state is arm32.h; the two share nothing but the table shape and the bit
 * helpers (arm32_int.h, arm32_common.h). Read arm32.h first: what it says about
 * a decode being a table, about accessors, and about validity applies here.
 *
 * THE LENGTH comes from the first halfword alone: 11101, 11110 and 11111 in its
 * top five bits open a 32-bit instruction, anything else is 16 bits. A caller
 * with a buffer asks gt_thumb_len(hw0) before it reads the second halfword, so
 * a decoder never needs bytes it was not given.
 *
 * `hw0` and `hw1` ARE HALFWORD VALUES, not bytes: byte order is the caller's.
 * For a 16-bit instruction `hw1` is ignored and kept as 0. The instruction keeps
 * them as one word, first halfword in the high half, which is also the form the
 * 32-bit encodings' fields sit in at the same positions as in ARM state.
 *
 * WHAT IS NOT IN IT: the IT block. `it` decodes as GT_THUMB_I_IT and the up to
 * four instructions it governs are decoded as if unconditional; the condition
 * of an instruction inside the block is the caller's to carry. The accessors
 * that name a condition (gt_thumb_n_cond, the b<cond> forms) read the one the
 * encoding itself holds.
 *
 * The coprocessor, VFP and Advanced SIMD spaces are not validity-checked, as
 * in ARM state (see arm32.h).
 */
#ifndef KOF_GENOTYPE_THUMB_H
#define KOF_GENOTYPE_THUMB_H

#include <stddef.h>
#include <stdint.h>

#include "thumb_ids.h"
#include "arm32_common.h"
#include "arm32_int.h"
#include "../genotype.h"

struct gt_thumb_insn {
	uint32_t w;             /* first halfword << 16 | second; the second is 0 */
	                        /* when len is 2                                  */
	uint16_t id;            /* enum gt_thumb_id                               */
	uint8_t  len;           /* 2 or 4                                         */
	uint8_t  _pad;
};

/* 2 or 4: how long the instruction that starts with `hw0` is. */
static inline unsigned gt_thumb_len(uint32_t hw0)
{
	return (hw0 >> 11) >= 0x1du ? 4u : 2u;
}

/*
 * Decode one instruction. GT_OK, or GT_INVALID with id GT_THUMB_I_INVALID; the
 * length is set either way. Inline for the reason gt_arm32_decode is (arm32.h);
 * here the same measurement was 214.8 M instructions out of line and 195.2 M
 * inline, 186.0 M once the halfwords are kept as the one word they are.
 *
 * gt_thumb_decode_narrow and gt_thumb_decode_wide are the two halves, for a
 * caller that has already asked gt_thumb_len and would otherwise have it asked
 * again.
 */
static inline enum gt_status gt_thumb_decode_narrow(struct gt_thumb_insn *out, uint32_t hw0)
{
	unsigned e, id;

	gt_thumb_ensure();
	hw0 &= 0xffffu;
	e = gt_thumb_idx_narrow[gt_thumb_narrow_key(hw0)];
	if (e & GT_ARM32_DIRECT) {
		id = e & ~GT_ARM32_DIRECT;
	} else {
		const struct gt_arm32_row *r = &gt_thumb_lists[e];

		/* the last row of every list matches whatever is left */
		while ((hw0 & r->mask) != r->value)
			r++;
		id = r->id;
	}
	out->w = hw0 << 16;
	out->id = (uint16_t)id;
	out->len = 2u;
	out->_pad = 0;
	return id == GT_THUMB_I_INVALID ? GT_INVALID : GT_OK;
}

static inline enum gt_status gt_thumb_decode_wide(struct gt_thumb_insn *out, uint32_t hw0,
						  uint32_t hw1)
{
	uint32_t w = (hw0 & 0xffffu) << 16 | (hw1 & 0xffffu);
	unsigned e, id;

	gt_thumb_ensure();
	e = gt_thumb_idx_wide[gt_thumb_wide_key(w)];

	if (e & GT_ARM32_DIRECT) {
		id = e & ~GT_ARM32_DIRECT;
	} else {
		const struct gt_arm32_row *r = &gt_thumb_lists[e];

		while ((w & r->mask) != r->value)
			r++;
		id = r->id;
	}
	out->w = w;
	out->id = (uint16_t)id;
	out->len = 4u;
	out->_pad = 0;
	return id == GT_THUMB_I_INVALID ? GT_INVALID : GT_OK;
}

static inline enum gt_status gt_thumb_decode(struct gt_thumb_insn *out, uint32_t hw0,
					     uint32_t hw1)
{
	return gt_thumb_len(hw0) == 2u ? gt_thumb_decode_narrow(out, hw0)
				       : gt_thumb_decode_wide(out, hw0, hw1);
}

/*
 * ---- FIELD ACCESSORS: 16-bit forms (read hw0) ------------------------------
 *
 * Positional, named for the bit they start at: r0 is bits 2:0, r3 bits 5:3, r6
 * bits 8:6, r8 bits 10:8.
 */
static inline uint32_t gt_thumb_n_r0(struct gt_thumb_insn in) { return (in.w >> 16) & 7u; }
static inline uint32_t gt_thumb_n_r3(struct gt_thumb_insn in) { return ((in.w >> 16) >> 3) & 7u; }
static inline uint32_t gt_thumb_n_r6(struct gt_thumb_insn in) { return ((in.w >> 16) >> 6) & 7u; }
static inline uint32_t gt_thumb_n_r8(struct gt_thumb_insn in) { return ((in.w >> 16) >> 8) & 7u; }
/* The high-register forms: rd is bit 7 : bits 2:0, rm is bits 6:3. */
static inline uint32_t gt_thumb_n_hi_rd(struct gt_thumb_insn in)
{
	return ((in.w >> 16) & 7u) | (((in.w >> 16) >> 4) & 8u);
}
static inline uint32_t gt_thumb_n_hi_rm(struct gt_thumb_insn in) { return ((in.w >> 16) >> 3) & 15u; }
static inline uint32_t gt_thumb_n_bit(struct gt_thumb_insn in, unsigned n)
{
	return gt_arm_bit((in.w >> 16), n);
}
static inline uint32_t gt_thumb_n_imm3(struct gt_thumb_insn in) { return ((in.w >> 16) >> 6) & 7u; }
static inline uint32_t gt_thumb_n_imm5(struct gt_thumb_insn in) { return ((in.w >> 16) >> 6) & 31u; }
static inline uint32_t gt_thumb_n_imm7(struct gt_thumb_insn in) { return (in.w >> 16) & 127u; }
static inline uint32_t gt_thumb_n_imm8(struct gt_thumb_insn in) { return (in.w >> 16) & 255u; }
/* The register list of push, pop, ldm and stm: bits 7:0. */
static inline uint32_t gt_thumb_n_list(struct gt_thumb_insn in) { return (in.w >> 16) & 255u; }
/* Bits 12:11 of the shift-by-immediate forms: 0 lsl, 1 lsr, 2 asr. */
static inline uint32_t gt_thumb_n_shift_type(struct gt_thumb_insn in) { return ((in.w >> 16) >> 11) & 3u; }
/* b<cond>: the condition (bits 11:8), the offset in bytes, signed. */
static inline uint32_t gt_thumb_n_cond(struct gt_thumb_insn in) { return ((in.w >> 16) >> 8) & 15u; }
static inline int32_t gt_thumb_n_bcond_off(struct gt_thumb_insn in)
{
	return gt_arm_sext((in.w >> 16), 8) * 2;
}
/* b: the 11-bit offset in bytes, signed. */
static inline int32_t gt_thumb_n_b_off(struct gt_thumb_insn in)
{
	return gt_arm_sext((in.w >> 16), 11) * 2;
}
/* cbz, cbnz: i : imm5 : 0, forward only. */
static inline uint32_t gt_thumb_n_cbz_off(struct gt_thumb_insn in)
{
	return (((in.w >> 16) >> 3) & 0x40u) | (((in.w >> 16) >> 2) & 0x3eu);
}

/*
 * ---- FIELD ACCESSORS: 32-bit forms ----------------------------------------
 *
 * Positional again. rn is the first halfword's bits 3:0; the second halfword
 * holds rt (15:12), rd or rt2 (11:8) and rm (3:0).
 */
static inline uint32_t gt_thumb_w_rn(struct gt_thumb_insn in) { return (in.w >> 16) & 15u; }
static inline uint32_t gt_thumb_w_rt(struct gt_thumb_insn in) { return (in.w & 0xffffu) >> 12; }
static inline uint32_t gt_thumb_w_rd(struct gt_thumb_insn in) { return ((in.w & 0xffffu) >> 8) & 15u; }
static inline uint32_t gt_thumb_w_rm(struct gt_thumb_insn in) { return (in.w & 0xffffu) & 15u; }
static inline uint32_t gt_thumb_w_bit0(struct gt_thumb_insn in, unsigned n)
{
	return gt_arm_bit((in.w >> 16), n);
}
static inline uint32_t gt_thumb_w_bit1(struct gt_thumb_insn in, unsigned n)
{
	return gt_arm_bit((in.w & 0xffffu), n);
}
/* Data processing: the S bit (hw0 bit 4), and the operation field (hw0 bits 8:5). */
static inline uint32_t gt_thumb_w_s(struct gt_thumb_insn in) { return ((in.w >> 16) >> 4) & 1u; }
/* i : imm3 : imm8, the 12 bits of the plain and modified immediates. */
static inline uint32_t gt_thumb_w_imm12(struct gt_thumb_insn in)
{
	return (((in.w >> 16) >> 10) & 1u) << 11 | (((in.w & 0xffffu) >> 12) & 7u) << 8 | ((in.w & 0xffffu) & 255u);
}
/* The modified immediate of ThumbExpandImm, from those 12 bits. */
static inline uint32_t gt_thumb_w_modimm(struct gt_thumb_insn in)
{
	uint32_t imm12 = gt_thumb_w_imm12(in), b = imm12 & 255u;

	if (!(imm12 & 0xc00u)) {
		switch ((imm12 >> 8) & 3u) {
		case 0:
			return b;
		case 1:
			return b << 16 | b;
		case 2:
			return b << 24 | b << 8;
		default:
			return b * 0x01010101u;
		}
	}
	return gt_arm_ror(0x80u | (b & 0x7fu), (imm12 >> 7) & 31u);
}
/* movw and movt: imm4 : i : imm3 : imm8. */
static inline uint32_t gt_thumb_w_imm16(struct gt_thumb_insn in)
{
	return (gt_thumb_w_rn(in) << 12) | gt_thumb_w_imm12(in);
}
/* A load or store's 12-bit and 8-bit offsets, and ldrd/strd's 8-bit word offset. */
static inline uint32_t gt_thumb_w_ls_imm12(struct gt_thumb_insn in) { return (in.w & 0xffffu) & 0xfffu; }
static inline uint32_t gt_thumb_w_ls_imm8(struct gt_thumb_insn in) { return (in.w & 0xffffu) & 255u; }
/* The shifted register: type 0..3 (lsl lsr asr ror), amount imm3 : imm2. */
static inline uint32_t gt_thumb_w_shift_type(struct gt_thumb_insn in) { return ((in.w & 0xffffu) >> 4) & 3u; }
static inline uint32_t gt_thumb_w_shift_imm(struct gt_thumb_insn in)
{
	return (((in.w & 0xffffu) >> 12) & 7u) << 2 | (((in.w & 0xffffu) >> 6) & 3u);
}
/* Register offset: the shift left of the index, 0..3 (imm2). */
static inline uint32_t gt_thumb_w_index_shift(struct gt_thumb_insn in) { return ((in.w & 0xffffu) >> 4) & 3u; }
/* The register list of ldm, stm, push, pop: the second halfword. */
static inline uint32_t gt_thumb_w_list(struct gt_thumb_insn in) { return (in.w & 0xffffu); }
/* The sxt/uxt rotation in bits (0, 8, 16, 24): hw1 bits 5:4 times 8. */
static inline uint32_t gt_thumb_w_rot(struct gt_thumb_insn in) { return (((in.w & 0xffffu) >> 4) & 3u) * 8u; }
/* The condition of b<cond>.W: hw0 bits 9:6. */
static inline uint32_t gt_thumb_w_cond(struct gt_thumb_insn in) { return ((in.w >> 16) >> 6) & 15u; }

/* Branch offsets in bytes, signed: b<cond>.W (21 bits), and b.W and bl (25 bits
 * with I1 and I2 reconstructed from J1, J2 and S). blx (immediate)'s differs
 * in having bit 1 from the low field and being measured from the aligned pc. */
static inline int32_t gt_thumb_w_bcond_off(struct gt_thumb_insn in)
{
	uint32_t s = ((in.w >> 16) >> 10) & 1u, j1 = ((in.w & 0xffffu) >> 13) & 1u, j2 = ((in.w & 0xffffu) >> 11) & 1u;
	uint32_t imm = s << 20 | j2 << 19 | j1 << 18 | ((in.w >> 16) & 0x3fu) << 12 |
		       ((in.w & 0xffffu) & 0x7ffu) << 1;

	return gt_arm_sext(imm, 21);
}
static inline uint32_t gt_thumb_w_branch_imm(struct gt_thumb_insn in)
{
	uint32_t s = ((in.w >> 16) >> 10) & 1u, j1 = ((in.w & 0xffffu) >> 13) & 1u, j2 = ((in.w & 0xffffu) >> 11) & 1u;
	uint32_t i1 = !(j1 ^ s), i2 = !(j2 ^ s);

	return s << 24 | i1 << 23 | i2 << 22 | ((in.w >> 16) & 0x3ffu) << 12;
}
static inline int32_t gt_thumb_w_b_off(struct gt_thumb_insn in)
{
	return gt_arm_sext(gt_thumb_w_branch_imm(in) | ((in.w & 0xffffu) & 0x7ffu) << 1, 25);
}
static inline int32_t gt_thumb_w_blx_off(struct gt_thumb_insn in)
{
	return gt_arm_sext(gt_thumb_w_branch_imm(in) | (((in.w & 0xffffu) >> 1) & 0x3ffu) << 2, 25);
}

#endif /* KOF_GENOTYPE_THUMB_H */
