/*
 * api_decoders - the field accessors and shared helpers of the ARM, Thumb and A64
 * decoders, and the x86 attribute readers, each against an encoding whose answer
 * is written in the architecture manual (the field diagram is beside every word).
 *
 * decode_arm32/decode_arm64/genotype_* already pin which INSTRUCTION a word is;
 * what none of them named is the small functions every consumer calls to take a
 * field out of one - a register number, a rotated immediate, a branch offset
 * with its sign - and the helpers the celllysis adapters build operands with.
 * A wrong shift in one of them is a wrong register in every decode downstream, so
 * each is checked on a word where the answer is not a coincidence, then on the
 * boundary words (all ones, all zeros) where a sign or a width goes wrong.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>
#include <genotype/arm32/arm32.h>
#include <genotype/arm32/thumb.h>
#include <genotype/arm64/arm64.h>
#include <celllysis/decode_arm32.h>

#include "hk.h"

static struct kgenome_arm32_insn a32(uint32_t w)
{
	struct kgenome_arm32_insn in;
	kgenome_arm32_decode(&in, w);
	return in;
}

/* ---- A32 -------------------------------------------------------------------------------------- */

static void t_arm32_fields(void)
{
	struct kgenome_arm32_insn in;

	/* e2810004  add r0, r1, #4   cond=AL Rn=1 Rd=0 imm12=4 */
	CK(kgenome_arm32_decode(&in, 0xe2810004u) == KGENOME_OK);
	CK(in.id == KGENOME_ARM32_I_ADD_IMM && in.cond == 0xe);
	CK(kgenome_arm32_r16(in) == 1 && kgenome_arm32_r12(in) == 0 && kgenome_arm32_r8(in) == 0 &&
	   kgenome_arm32_r0(in) == 4);
	CK(kgenome_arm32_imm12(in) == 4 && kgenome_arm32_modimm(in) == 4);
	CK(kgenome_arm32_s(in) == 0);
	/* 0xe28104ff: imm8 = 0xff rotated right by 2*4 -> 0xff000000 */
	kgenome_arm32_decode(&in, 0xe28104ffu);
	CK(kgenome_arm32_modimm(in) == 0xff000000u);
	/* 0xe2810f01: imm8 = 1, rot field 0xf -> ror(1, 30) = 4 */
	kgenome_arm32_decode(&in, 0xe2810f01u);
	CK(kgenome_arm32_modimm(in) == 4u);
	/* rot field 0 and the all-ones immediate */
	kgenome_arm32_decode(&in, 0xe28100ffu);
	CK(kgenome_arm32_modimm(in) == 0xffu);
	/* e2910004  adds r0, r1, #4 */
	kgenome_arm32_decode(&in, 0xe2910004u);
	CK(kgenome_arm32_s(in) == 1);

	/* e5910004  ldr r0, [r1, #4]   P=1 U=1 B=0 W=0 */
	kgenome_arm32_decode(&in, 0xe5910004u);
	CK(in.id == KGENOME_ARM32_I_LDR_IMM);
	CK(kgenome_arm32_p(in) == 1 && kgenome_arm32_u(in) == 1 && kgenome_arm32_b(in) == 0 &&
	   kgenome_arm32_wb(in) == 0);
	CK(kgenome_arm32_imm12(in) == 4);
	/* e5f12004  ldrb r2, [r1, #4]!  B=1 W=1 */
	kgenome_arm32_decode(&in, 0xe5f12004u);
	CK(kgenome_arm32_b(in) == 1 && kgenome_arm32_wb(in) == 1 && kgenome_arm32_r12(in) == 2);
	/* e5110004  ldr r0, [r1, #-4]  U=0 */
	kgenome_arm32_decode(&in, 0xe5110004u);
	CK(kgenome_arm32_u(in) == 0);

	/* ea000002  b +8 (+8 for the pipeline is the caller's)  imm24 = 2 -> offset 8 */
	kgenome_arm32_decode(&in, 0xea000002u);
	CK(in.id == KGENOME_ARM32_I_B);
	CK(kgenome_arm32_imm24(in) == 2 && kgenome_arm32_branch_off(in) == 8);
	/* eafffffe  b .  imm24 = 0xfffffe -> -2 words */
	kgenome_arm32_decode(&in, 0xeafffffeu);
	CK(kgenome_arm32_imm24(in) == 0xfffffeu && kgenome_arm32_branch_off(in) == -8);
	/* ea7fffff: the largest positive offset; ea800000: the most negative */
	kgenome_arm32_decode(&in, 0xea7fffffu);
	CK(kgenome_arm32_branch_off(in) == 0x1fffffc);
	kgenome_arm32_decode(&in, 0xea800000u);
	CK(kgenome_arm32_branch_off(in) == -0x2000000);
	/* eb000002  bl */
	kgenome_arm32_decode(&in, 0xeb000002u);
	CK(in.id == KGENOME_ARM32_I_BL && kgenome_arm32_h(in) == 1);      /* bit 24: L for bl, H for blx */
	CK(kgenome_arm32_h(a32(0xea000002u)) == 0);
	/* fb000002  blx (the H bit) */
	kgenome_arm32_decode(&in, 0xfb000002u);
	CK(kgenome_arm32_h(in) == 1);

	/* e92d4010  push {r4, lr} */
	kgenome_arm32_decode(&in, 0xe92d4010u);
	CK(kgenome_arm32_list(in) == 0x4010u);
	/* e1a00181  mov r0, r1, lsl #3 ; e1a00141  mov r0, r1, asr #2 ; e1a00461 ror #8 */
	kgenome_arm32_decode(&in, 0xe1a00181u);
	CK(kgenome_arm32_shift_type(in) == 0 && kgenome_arm32_shift_imm(in) == 3);
	kgenome_arm32_decode(&in, 0xe1a00141u);
	CK(kgenome_arm32_shift_type(in) == 2 && kgenome_arm32_shift_imm(in) == 2);
	kgenome_arm32_decode(&in, 0xe1a00461u);
	CK(kgenome_arm32_shift_type(in) == 3);
	/* e3010234  movw r0, #0x1234 : imm4:imm12 */
	kgenome_arm32_decode(&in, 0xe3010234u);
	CK(kgenome_arm32_imm16(in) == 0x1234);
	/* e18000d1 ldrd r0,[r0,r1]: the split 8-bit immediate (imm4H:imm4L) of the halfword forms */
	kgenome_arm32_decode(&in, 0xe1c200d4u);
	CK(kgenome_arm32_imm8_split(in) == 4u);
	kgenome_arm32_decode(&in, 0xe1c20fffu);
	CK(kgenome_arm32_imm8_split(in) == 0xffu);
	CK(kgenome_arm32_imm16_split(in) == ((0xe1c20fffu >> 4 & 0xfff0u) | (0xe1c20fffu & 15u)));
	CK(kgenome_arm32_imm16_split(in) == 0x20ffu);
	/* ror: a rotate by 0 is the identity (and must not shift by 32) */
	kgenome_arm32_decode(&in, 0xe6ef0071u);        /* uxtb r0, r1 */
	CK(kgenome_arm32_rot(in) == 0);
	kgenome_arm32_decode(&in, 0xe6ef0c71u);        /* uxtb r0, r1, ror #24 */
	CK(kgenome_arm32_rot(in) == 3);

	/* the shared bit helpers */
	CK(kgenome_arm_bit(0x80000000u, 31) == 1 && kgenome_arm_bit(0x80000000u, 30) == 0);
	CK(kgenome_arm_ror(0x12345678u, 0) == 0x12345678u);
	CK(kgenome_arm_ror(0x1u, 1) == 0x80000000u);
	CK(kgenome_arm_ror(0x80000000u, 31) == 1u);
	CK(kgenome_arm_ror(0xffu, 8) == 0xff000000u);
	CK(kgenome_arm_sext(0xffu, 8) == -1);
	CK(kgenome_arm_sext(0x7fu, 8) == 127);
	CK(kgenome_arm_sext(0x80u, 8) == -128);
	CK(kgenome_arm_sext(0x1u, 1) == -1);
	CK(kgenome_arm_sext(0x7fffffffu, 31) == -1);                  /* bits == 32 is signed overflow in the helper: not called */
	CK(kgenome_arm_sext(0x3fffffffu, 31) == 0x3fffffff);
	CK(kgenome_arm_sext(0x800000u, 24) == -0x800000);

	/* the table's index: lookups are by bit pattern; every key is inside the arrays */
	{
		uint32_t w;
		struct hk_rng r = { 0x2545f4914f6cdd1dull };
		unsigned i;
		CK(kgenome_arm32_key(0) < KGENOME_ARM32_KEYS * 2u);
		CK(kgenome_arm32_key(0xffffffffu) < KGENOME_ARM32_KEYS * 2u);
		CK(kgenome_arm32_key(0xf0000000u) >= KGENOME_ARM32_KEYS);   /* condition 15 has its own table */
		CK(kgenome_arm32_key(0xe0000000u) < KGENOME_ARM32_KEYS);
		CK(kgenome_arm32_key12(0xffffffffu) == 0xfffu);
		CK(kgenome_thumb_narrow_key(0xffffu) < KGENOME_THUMB_NARROW_KEYS);
		CK(kgenome_thumb_wide_key(0xffffffffu) < KGENOME_THUMB_WIDE_KEYS);
		for (i = 0; i < 100000; i++) {
			w = (uint32_t)hk_next(&r);
			CK(kgenome_arm32_key(w) < KGENOME_ARM32_KEYS * 2u);
			CK(kgenome_arm32_key12(w) < KGENOME_ARM32_KEYS);
			CK(kgenome_thumb_narrow_key(w) < KGENOME_THUMB_NARROW_KEYS);
			CK(kgenome_thumb_wide_key(w) < KGENOME_THUMB_WIDE_KEYS);
		}
	}
	/* the lazy tables: ensure() is idempotent and leaves state 2; build() may be re-entered */
	kgenome_arm32_ensure();
	kgenome_arm32_ensure();
	kgenome_thumb_ensure();
	kgenome_thumb_ensure();
	kgenome_arm32_build();
	kgenome_thumb_build();
	CK(kgenome_arm32_decode(&in, 0xe2810004u) == KGENOME_OK && in.id == KGENOME_ARM32_I_ADD_IMM);
	/* every row list ends in a row that matches: scan the first rows of each key for a mask-0 end */
	{
		unsigned k, bad_lists = 0;
		for (k = 0; k < 2u * KGENOME_ARM32_KEYS; k++) {
			unsigned e = kgenome_arm32_idx[k];
			const struct kgenome_arm32_row *r = &kgenome_arm32_lists[e];
			unsigned guard = 0;
			while (r->mask != 0 && guard++ < 100000u)
				r++;
			if (guard >= 100000u)
				bad_lists++;
		}
		CK(bad_lists == 0);      /* no list runs on without a catch-all row */
	}
}

static struct kgenome_thumb_insn a_thumb_wide(uint32_t h0, uint32_t h1)
{
	struct kgenome_thumb_insn in;
	kgenome_thumb_decode_wide(&in, h0, h1);
	return in;
}

/* ---- Thumb --------------------------------------------------------------------------------------- */

static void t_thumb_fields(void)
{
	struct kgenome_thumb_insn in;

	CK(kgenome_thumb_len(0x4770) == 2);
	CK(kgenome_thumb_len(0xe7fe) == 2);
	CK(kgenome_thumb_len(0xe7ffu) == 2);
	CK(kgenome_thumb_len(0xe800) == 4 && kgenome_thumb_len(0xf000) == 4 && kgenome_thumb_len(0xffffu) == 4);
	CK(kgenome_thumb_len(0) == 2);

	/* 4770 bx lr: Rm = bits 6:3 = 14 */
	CK(kgenome_thumb_decode_narrow(&in, 0x4770) == KGENOME_OK);
	CK(in.id == KGENOME_THUMB_I_BX && in.len == 2 && (in.w & 0xffffu) == 0);
	CK(kgenome_thumb_n_hi_rm(in) == 14);
	/* 2105 movs r1, #5 : Rd = bits 10:8, imm8 */
	kgenome_thumb_decode_narrow(&in, 0x2105);
	CK(kgenome_thumb_n_r8(in) == 1 && kgenome_thumb_n_imm8(in) == 5);
	/* 1cc8 adds r0, r1, #3 : Rd 2:0, Rn 5:3, imm3 8:6 */
	kgenome_thumb_decode_narrow(&in, 0x1cc8);
	CK(kgenome_thumb_n_r0(in) == 0 && kgenome_thumb_n_r3(in) == 1 && kgenome_thumb_n_imm3(in) == 3);
	/* 1853 adds r3, r2, r1 : Rm 8:6 */
	kgenome_thumb_decode_narrow(&in, 0x1853);
	CK(kgenome_thumb_n_r0(in) == 3 && kgenome_thumb_n_r3(in) == 2 && kgenome_thumb_n_r6(in) == 1);
	/* 00ca lsls r2, r1, #3 : imm5 10:6 */
	kgenome_thumb_decode_narrow(&in, 0x00ca);
	CK(kgenome_thumb_n_imm5(in) == 3 && kgenome_thumb_n_shift_type(in) == 0);
	/* 0ccb lsrs r3, r1, #3 : the shift type is 11:11 .. 12 */
	kgenome_thumb_decode_narrow(&in, 0x08ca);
	CK(kgenome_thumb_n_shift_type(in) == 1);
	/* e7fe b . : imm11 = 0x7fe -> -2 halfwords -> -4 bytes */
	kgenome_thumb_decode_narrow(&in, 0xe7fe);
	CK(in.id == KGENOME_THUMB_I_B && kgenome_thumb_n_b_off(in) == -4);
	kgenome_thumb_decode_narrow(&in, 0xe3ff);
	CK(kgenome_thumb_n_b_off(in) == 0x7fe);           /* largest positive: imm11 = 0x3ff */
	kgenome_thumb_decode_narrow(&in, 0xe400);
	CK(kgenome_thumb_n_b_off(in) == -0x800);          /* most negative */
	/* d0fe beq . : cond 11:8 = 0, imm8 = 0xfe -> -4 */
	kgenome_thumb_decode_narrow(&in, 0xd0fe);
	CK(kgenome_thumb_n_cond(in) == 0 && kgenome_thumb_n_bcond_off(in) == -4);
	kgenome_thumb_decode_narrow(&in, 0xd17f);
	CK(kgenome_thumb_n_cond(in) == 1 && kgenome_thumb_n_bcond_off(in) == 254);
	/* b108 cbz r0, +? : i:imm5 -> offset */
	kgenome_thumb_decode_narrow(&in, 0xb108);
	CK(kgenome_thumb_n_cbz_off(in) == 2);
	kgenome_thumb_decode_narrow(&in, 0xb3f8);         /* i=1 imm5=31 */
	CK(kgenome_thumb_n_cbz_off(in) == 0x7e);
	/* 4601 mov r1, r0 (hi-register form): Rd = {bit7, 2:0} */
	kgenome_thumb_decode_narrow(&in, 0x4681);         /* mov r9, r0 */
	CK(kgenome_thumb_n_hi_rd(in) == 9 && kgenome_thumb_n_hi_rm(in) == 0);
	/* b5f0 push {r4-r7, lr} : list 7:0 */
	kgenome_thumb_decode_narrow(&in, 0xb5f0);
	CK(kgenome_thumb_n_list(in) == 0xf0);
	/* b00a add sp, #40 : imm7 */
	kgenome_thumb_decode_narrow(&in, 0xb00a);
	CK(kgenome_thumb_n_imm7(in) == 10);
	/* n_bit reads a bit of the halfword */
	kgenome_thumb_decode_narrow(&in, 0x8000);
	CK(kgenome_thumb_n_bit(in, 15) == 1 && kgenome_thumb_n_bit(in, 14) == 0);

	/* the wide forms: f000 f800 is bl +0 (S=0 J1=J2=1 imm10=0 imm11=0) */
	CK(kgenome_thumb_decode_wide(&in, 0xf000, 0xf800) == KGENOME_OK);
	CK(in.id == KGENOME_THUMB_I_BL && in.len == 4);
	CK(kgenome_thumb_decode(&in, 0xf000, 0xf800) == KGENOME_OK && in.id == KGENOME_THUMB_I_BL);
	/* f7ff fffe : bl . (S=1 imm10=0x3ff imm11=0x7fe, J1=J2=1) */
	kgenome_thumb_decode_wide(&in, 0xf7ff, 0xfffe);
	CK(in.id == KGENOME_THUMB_I_BL && kgenome_thumb_w_s(in) == 1);
	CK(kgenome_thumb_w_b_off(in) == -4);
	/* the upper bits of the offset (S, I1, I2, imm10), before the low field is added */
	CK(kgenome_thumb_w_branch_imm(in) == (1u << 24 | 1u << 23 | 1u << 22 | 0x3ffu << 12));
	CK(kgenome_thumb_w_branch_imm(a_thumb_wide(0xf000, 0xf800)) == 0);                  /* S=0, J1=J2=1: I1=I2=0 */
	/* f000 e800 blx +0 */
	kgenome_thumb_decode_wide(&in, 0xf000, 0xe800);
	CK(in.id == KGENOME_THUMB_I_BLX_IMM);
	CK(kgenome_thumb_w_blx_off(in) == 0);
	/* f8d1 0004 ldr.w r0, [r1, #4] : Rn 3:0 of hw0, Rt 15:12 of hw1, imm12 */
	kgenome_thumb_decode_wide(&in, 0xf8d1, 0x0004);
	CK(kgenome_thumb_w_rn(in) == 1 && kgenome_thumb_w_rt(in) == 0 && kgenome_thumb_w_ls_imm12(in) == 4);
	/* f851 0c04 ldr r0, [r1, #-4] : the imm8 form */
	kgenome_thumb_decode_wide(&in, 0xf851, 0x0c04);
	CK(kgenome_thumb_w_ls_imm8(in) == 4);
	/* f04f 0a05 mov.w r10, #5 : Rd 11:8 of hw1, modified immediate */
	kgenome_thumb_decode_wide(&in, 0xf04f, 0x0a05);
	CK(in.id == KGENOME_THUMB_I_MOV_IMM_W);
	CK(kgenome_thumb_w_rd(in) == 10 && kgenome_thumb_w_modimm(in) == 5 && kgenome_thumb_w_imm12(in) == 5);
	/* the modified-immediate forms: byte repeated four ways, then the rotated 8-bit */
	kgenome_thumb_decode_wide(&in, 0xf04f, 0x01ab);   /* imm12 = 0x0ab: 000 -> 0x000000ab */
	CK(kgenome_thumb_w_modimm(in) == 0xabu);
	kgenome_thumb_decode_wide(&in, 0xf04f, 0x11ab);   /* imm12 = 0x1ab: 0x00ab00ab */
	CK(kgenome_thumb_w_modimm(in) == 0x00ab00abu);
	kgenome_thumb_decode_wide(&in, 0xf04f, 0x21ab);   /* 0xab00ab00 */
	CK(kgenome_thumb_w_modimm(in) == 0xab00ab00u);
	kgenome_thumb_decode_wide(&in, 0xf04f, 0x31ab);   /* 0xabababab */
	CK(kgenome_thumb_w_modimm(in) == 0xababababu);
	kgenome_thumb_decode_wide(&in, 0xf44f, 0x4180);   /* i=1 imm3=4 imm8=0x80: ror(0x80, 9) */
	CK(kgenome_thumb_w_modimm(in) == 0x4000u);
	/* movw: imm16 = imm4:i:imm3:imm8 */
	kgenome_thumb_decode_wide(&in, 0xf241, 0x2034);   /* movw r0, #0x1234 */
	CK(kgenome_thumb_w_imm16(in) == 0x1234u);
	/* the bit readers of each half */
	kgenome_thumb_decode_wide(&in, 0xf000, 0x8001);
	CK(kgenome_thumb_w_bit0(in, 15) == 1 && kgenome_thumb_w_bit0(in, 14) == 1 && kgenome_thumb_w_bit1(in, 15) == 1 &&
	   kgenome_thumb_w_bit1(in, 0) == 1 && kgenome_thumb_w_bit1(in, 1) == 0);
	/* the conditional branch: f0c0 8000 b<c>.w with cond 11:8 of hw0's low part */
	kgenome_thumb_decode_wide(&in, 0xf0c0, 0x8000);
	(void)kgenome_thumb_w_cond(in);
	(void)kgenome_thumb_w_bcond_off(in);
	(void)kgenome_thumb_w_index_shift(in);
	(void)kgenome_thumb_w_rot(in);
	(void)kgenome_thumb_w_rm(in);
	(void)kgenome_thumb_w_s(in);
	CK(kgenome_thumb_w_cond(in) == ((0xf0c0u >> 6) & 15u));
	/* thumb 16-bit decode ignores hw1 entirely */
	CK(kgenome_thumb_decode(&in, 0x4770, 0xffff) == KGENOME_OK && (in.w & 0xffffu) == 0);
}

/* ---- A64 ------------------------------------------------------------------------------------------ */

static struct kgenome_arm64_insn a64(uint32_t w)
{
	struct kgenome_arm64_insn in;
	kgenome_arm64_decode(&in, w);
	return in;
}

static void t_arm64_fields(void)
{
	struct kgenome_arm64_insn in;

	/* 91000420  add x0, x1, #1 : sf=1 Rd=0 Rn=1 imm12=1 */
	in = a64(0x91000420u);
	CK(kgenome_arm64_sf(&in) == 1 && kgenome_arm64_rd(&in) == 0 && kgenome_arm64_rn(&in) == 1);
	CK(kgenome_arm64_addsub_imm(&in) == 1);
	/* 91400420  add x0, x1, #1, lsl #12 */
	in = a64(0x91400420u);
	CK(kgenome_arm64_addsub_imm(&in) == 0x1000);
	/* 11000420  add w0, w1, #1 : sf=0 */
	in = a64(0x11000420u);
	CK(kgenome_arm64_sf(&in) == 0);
	/* d2800020  movz x0, #1 ; d2a00020 movz x0, #1, lsl #16 ; d2e00020 lsl #48 */
	in = a64(0xd2800020u);
	CK(kgenome_arm64_movw_imm(&in) == 1 && kgenome_arm64_movw_shift(&in) == 0 && kgenome_arm64_imm16(&in) == 1);
	in = a64(0xd2a00020u);
	CK(kgenome_arm64_movw_shift(&in) == 16 && kgenome_arm64_movw_imm(&in) == 0x10000u);
	in = a64(0xd2ffffe0u);
	CK(kgenome_arm64_movw_shift(&in) == 48 && kgenome_arm64_movw_imm(&in) == 0xffffull << 48);
	in = a64(0xd2e00020u);
	CK(kgenome_arm64_movw_imm(&in) == (1ull << 48));
	/* 14000002 b +8 ; 17fffffe b -8 ; 94000001 bl +4 */
	in = a64(0x14000002u);
	CK(kgenome_arm64_branch_off(&in) == 8);
	in = a64(0x17fffffeu);
	CK(kgenome_arm64_branch_off(&in) == -8);
	in = a64(0x94000001u);
	CK(kgenome_arm64_branch_off(&in) == 4);
	/* the widest forward and backward displacement of B: imm26 = 0x1ffffff / 0x2000000 */
	in = a64(0x15ffffffu);
	CK(kgenome_arm64_branch_off(&in) == 0x7fffffc);
	in = a64(0x16000000u);
	CK(kgenome_arm64_branch_off(&in) == -0x8000000);
	/* b4000040 cbz x0, +8 ; 54000040 b.eq +8 ; 54fffff1 b.ne -4 (cond 1) */
	in = a64(0xb4000040u);
	CK(kgenome_arm64_branch_off(&in) == 8);
	in = a64(0x54000040u);
	CK(kgenome_arm64_branch_off(&in) == 8 && kgenome_arm64_cond_branch(&in) == 0);
	in = a64(0x54ffffe1u);
	CK(kgenome_arm64_branch_off(&in) == -4 && kgenome_arm64_cond_branch(&in) == 1);
	/* 36000040 tbz w0, #0, +8 ; b6f80040 tbz x0, #63, +8 */
	in = a64(0x36000040u);
	CK(kgenome_arm64_tbz_bit(&in) == 0 && kgenome_arm64_branch_off(&in) == 8);
	in = a64(0xb6f80040u);
	CK(kgenome_arm64_tbz_bit(&in) == 63);
	/* 10000020 adr x0, +4 ; f0000000 adrp: immlo 30:29 immhi 23:5 */
	in = a64(0x10000020u);
	CK(kgenome_arm64_adr_imm(&in) == 4);
	in = a64(0x70000000u);                    /* adr x0, with immlo=3 */
	CK(kgenome_arm64_adr_imm(&in) == 3);
	in = a64(0x10ffffe0u);                    /* immhi all ones: -4 */
	CK(kgenome_arm64_adr_imm(&in) == -4);
	/* f9400020 ldr x0, [x1] ; f9400420 ldr x0, [x1, #8] ; b9400020 ldr w0, [x1] ; 39400020 ldrb */
	in = a64(0xf9400020u);
	CK(kgenome_arm64_rt(&in) == 0 && kgenome_arm64_rn(&in) == 1 && kgenome_arm64_ldst_bytes(&in) == 8 &&
	   kgenome_arm64_ldst_off(&in) == 0 && kgenome_arm64_size(&in) == 3);
	CK(kgenome_arm64_lskind(&in) == KGENOME_ARM64_K_LOAD && kgenome_arm64_amode(&in) == KGENOME_ARM64_AM_OFFSET);
	in = a64(0xf9400420u);
	CK(kgenome_arm64_ldst_off(&in) == 8);
	in = a64(0xb9400020u);
	CK(kgenome_arm64_ldst_bytes(&in) == 4 && kgenome_arm64_size(&in) == 2);
	in = a64(0x39400020u);
	CK(kgenome_arm64_ldst_bytes(&in) == 1 && kgenome_arm64_size(&in) == 0);
	/* f81f8020 stur x0, [x1, #-8] : the unscaled signed offset */
	in = a64(0xf81f8020u);
	CK(kgenome_arm64_ldst_off(&in) == -8 && kgenome_arm64_amode(&in) == KGENOME_ARM64_AM_UNSCALED &&
	   kgenome_arm64_lskind(&in) == KGENOME_ARM64_K_STORE);
	/* a9bf7bfd stp x29, x30, [sp, #-16]! : Rt2 and the pre-index writeback */
	in = a64(0xa9bf7bfdu);
	CK(kgenome_arm64_rt(&in) == 29 && kgenome_arm64_rt2(&in) == 30 && kgenome_arm64_rn(&in) == 31);
	CK(kgenome_arm64_ldst_off(&in) == -16 && kgenome_arm64_amode(&in) == KGENOME_ARM64_AM_PRE);
	/* 9b037c41 mul x1, x2, x3 = madd x1, x2, x3, xzr : Rm, Ra, Rn, Rd */
	in = a64(0x9b037c41u);
	CK(kgenome_arm64_rd(&in) == 1 && kgenome_arm64_rn(&in) == 2 && kgenome_arm64_rm(&in) == 3 &&
	   kgenome_arm64_ra(&in) == 31 && kgenome_arm64_rs(&in) == 3);
	/* 9a8203e0 csel x0, xzr, x2, eq family: cond 15:12 */
	in = a64(0x9a821020u);
	CK(kgenome_arm64_cond_select(&in) == 1);
	/* 92401c20  and x0, x1, #0xff : N=1 immr=0 imms=7 */
	in = a64(0x92401c20u);
	CK(kgenome_arm64_immr(&in) == 0 && kgenome_arm64_imms(&in) == 7);
	CK(kgenome_arm64_logical_imm(&in) == 0xff);
	/* 9240 0020 and x0, x1, #1 ; 9240f820 and x0, x1, #0xfffffffffffffffe? (imms=62) */
	in = a64(0x92400020u);
	CK(kgenome_arm64_logical_imm(&in) == 1);
	in = a64(0x92400fe0u);                    /* N=1 immr=0 imms=3 -> 0xf; Rn=31 */
	CK(kgenome_arm64_logical_imm(&in) == 0xf);
	/* d503201f nop : hint 0 ; d503203f yield : hint 1 ; d5033fdf isb : not a hint */
	in = a64(0xd503201fu);
	CK(kgenome_arm64_hint(&in) == 0);
	in = a64(0xd503203fu);
	CK(kgenome_arm64_hint(&in) == 1);
	/* d4000001 svc #0 ; d4001001 svc #0x80 : imm16 */
	in = a64(0xd4001001u);
	CK(kgenome_arm64_imm16(&in) == 0x80);
	/* d53bd040 mrs x0, tpidr_el0 : the system register field */
	in = a64(0xd53bd040u);
	CK(kgenome_arm64_sysreg(&in) == ((0xd53bd040u >> 5) & 0x7fffu));
	/* bits */
	in = a64(0xffffffffu);
	CK(kgenome_arm64_bits(&in, 0, 32 - 1) == 0x7fffffffu);
	CK(kgenome_arm64_bits(&in, 31, 1) == 1);
	CK(kgenome_arm64_bits(&in, 0, 1) == 1);
	/* the names */
	CK(kgenome_arm64_name(a64(0xd503201fu).id) != NULL && kgenome_arm64_name(a64(0xd503201fu).id)[0]);
	CK(!strcmp(kgenome_arm64_name(~0u), "?") && !strcmp(kgenome_arm64_name(0xfffffu), "?"));
	/* the all-ones/all-zeros words decode (to something or to INVALID) and say which */
	{
		struct kgenome_arm64_insn z, o;
		enum kgenome_status sz = kgenome_arm64_decode(&z, 0), so = kgenome_arm64_decode(&o, 0xffffffffu);
		CK(sz == KGENOME_INVALID || sz == KGENOME_OK);
		CK(so == KGENOME_INVALID || so == KGENOME_OK);
		CK((sz == KGENOME_INVALID) == (z.id == KGENOME_ARM64_I_INVALID));
		CK((so == KGENOME_INVALID) == (o.id == KGENOME_ARM64_I_INVALID));
	}
}

/* ---- the identity lists: one X-macro, three tables ------------------------------------------------------------- */

static void t_arm64_id_tables(void)
{
	unsigned i, j, listed = 0;
	struct kgenome_arm64_insn in;

#define COUNT(n, k, a) listed++;
	KGENOME_ARM64_ID_LIST(COUNT)
#undef COUNT
	CK(listed == KGENOME_ARM64_I_COUNT);
	CK(KGENOME_ARM64_I_INVALID == 0 && KGENOME_ARM64_I_UDF == 1);
	CK(KGENOME_ARM64_I_B < KGENOME_ARM64_I_BL && KGENOME_ARM64_I_BL < KGENOME_ARM64_I_BCOND &&
	   KGENOME_ARM64_I_BCOND < KGENOME_ARM64_I_TBNZ);              /* branch_off reads the width from this order */
	CK(KGENOME_ARM64_I_COUNT < 0x400u);                  /* identities are below the node numbers the tree uses */
	for (i = 0; i < KGENOME_ARM64_I_COUNT; i++) {
		const char *nm = kgenome_arm64_name(i);

		CK(nm && nm[0] && strcmp(nm, "?") != 0);
		for (j = i + 1u; j < KGENOME_ARM64_I_COUNT; j++)
			CK(strcmp(nm, kgenome_arm64_name(j)) != 0);
		memset(&in, 0, sizeof in);
		in.id = (uint16_t)i;
		CK(kgenome_arm64_lskind(&in) <= KGENOME_ARM64_K_LOAD_FP);
		CK(kgenome_arm64_amode(&in) <= KGENOME_ARM64_AM_NOALLOC);
	}
	CK(!strcmp(kgenome_arm64_name(KGENOME_ARM64_I_COUNT), "?"));
	CK(KGENOME_ARM32_I_COUNT > 100 && KGENOME_THUMB_I_COUNT > 100);
}

/* ---- the celllysis ARM helpers ------------------------------------------------------------------- */

static void t_arm_helpers(void)
{
	static const uint8_t b[4] = { 0x12, 0x34, 0x56, 0x78 };
	struct kgenome_cell_insn o;
	struct kgenome_cell_operand d;
	uint64_t m;

	CK(kgenome_arm_h(b, 0) == 0x3412u && kgenome_arm_h(b, 1) == 0x1234u);
	CK(kgenome_arm_w(b, 0) == 0x78563412u && kgenome_arm_w(b, 1) == 0x12345678u);
	CK(kgenome_arm_popcount16(0) == 0 && kgenome_arm_popcount16(0xffffu) == 16 &&
	   kgenome_arm_popcount16(0xffff0001u) == 1 && kgenome_arm_popcount16(0x8000u) == 1);
	CK(kgenome_arm_lowest(1) == 0 && kgenome_arm_lowest(0x8000u) == 15 && kgenome_arm_lowest(0x4010u) == 4);

	memset(&o, 0xaa, sizeof o);
	kgenome_arm_begin(&o, 0x1000, 4);
	CK(o.op == KGENOME_CELL_OTHER && o.len == 4 && o.n_op == 0 && o.cond == 0xe && o.flags == 0);
	CK(o.at == 0x1000 && o.at_va == 0x1000 && o.target == KGENOME_BROKEN && o.target_va == KGENOME_BROKEN);
	CK(o.wmask == 0);
	{
		unsigned i;
		for (i = 0; i < 3; i++)
			CK(o.o[i].kind == KGENOME_CELL_O_NONE && o.o[i].reg == KGENOME_CELL_REG_NONE &&
			   o.o[i].index == KGENOME_CELL_REG_NONE && o.o[i].seg == KGENOME_CELL_REG_NONE &&
			   o.o[i].imm == 0 && o.o[i].disp == 0 && o.o[i].size == 0);
	}
	kgenome_arm_begin(&o, UINT64_MAX - 3u, 2);
	CK(o.len == 2 && o.at == UINT64_MAX - 3u);
	kgenome_arm_begin(&o, 0, 0x1ffu);           /* len is a byte: the caller's width is cut, not widened */
	CK(o.len == 0xff);

	memset(&d, 0, sizeof d);
	kgenome_arm_reg(&d, 9, KGENOME_CELL_OF_WRITE);
	CK(d.kind == KGENOME_CELL_O_REG && d.reg == 9 && d.size == 4 && d.flags == KGENOME_CELL_OF_WRITE);
	kgenome_arm_imm(&d, 0x1234);
	CK(d.kind == KGENOME_CELL_O_IMM && d.imm == 0x1234);
	kgenome_arm_mem(&d, 5, -12, 8, KGENOME_CELL_OF_READ);
	CK(d.kind == KGENOME_CELL_O_MEM && d.reg == 5 && d.disp == -12 && d.size == 8 && d.index == KGENOME_CELL_REG_NONE &&
	   d.scale == 1 && d.flags == KGENOME_CELL_OF_READ);
	kgenome_arm_op_reg(&d, 3, KGENOME_CELL_OF_READ);
	CK(d.kind == KGENOME_CELL_O_REG && d.reg == 3 && d.size == 4 && d.scale == 0);
	kgenome_arm_op_imm(&d, 77);
	CK(d.kind == KGENOME_CELL_O_IMM && d.imm == 77);
	/* a shift: kind in scale, amount in disp, the shift register in index when there is one */
	memset(&d, 0, sizeof d);
	d.index = KGENOME_CELL_REG_NONE;
	kgenome_arm_shift(&d, KGENOME_ARM_SH_LSL, 3, 0xff);
	CK(d.scale == KGENOME_ARM_SH_LSL && d.disp == 3 && d.index == KGENOME_CELL_REG_NONE);
	kgenome_arm_shift(&d, KGENOME_ARM_SH_ASR, 31, 4);
	CK(d.scale == KGENOME_ARM_SH_ASR && d.index == 4);
	d.index = KGENOME_CELL_REG_NONE;
	kgenome_arm_shift(&d, KGENOME_ARM_SH_NONE, 0, 4);
	CK(d.index == KGENOME_CELL_REG_NONE);       /* no shift: no shift register */

	/* push / pop of a list */
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_pushpop(&o, 0, 0x4010);          /* push {r4, lr} */
	CK(o.op == KGENOME_CELL_PUSH && o.wmask == KGENOME_ARM_R(KGENOME_ARM_SP));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_pushpop(&o, 1, 0x0010);          /* pop {r4}: one register -> an operand */
	CK(o.op == KGENOME_CELL_POP && o.n_op == 1 && o.o[0].reg == 4 &&
	   (o.wmask & KGENOME_ARM_R(4)) && (o.wmask & KGENOME_ARM_R(KGENOME_ARM_SP)));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_pushpop(&o, 1, 0x8010);          /* pop {r4, pc} is a return */
	CK(o.op == KGENOME_CELL_RET && (o.flags & KGENOME_CELL_F_INDIRECT) && o.n_op == 0);
	CK(o.wmask & KGENOME_ARM_R(KGENOME_ARM_PC));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_pushpop(&o, 1, 0x8000);          /* pop {pc} */
	CK(o.op == KGENOME_CELL_RET);
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_pushpop(&o, 0, 0);               /* an empty list is not an infinite loop */
	CK(o.op == KGENOME_CELL_PUSH);

	/* the write-mask recipes */
	m = kgenome_arm_wm(KGENOME_ARM_WM_F0 | KGENOME_ARM_WM_F12, 0x00009005u);
	CK(m == (KGENOME_ARM_R(5) | KGENOME_ARM_R(9)));
	CK(kgenome_arm_wm(KGENOME_ARM_WM_F8, 0x00000f00u) == KGENOME_ARM_R(15));
	CK(kgenome_arm_wm(KGENOME_ARM_WM_F16, 0x000d0000u) == KGENOME_ARM_R(13));
	CK(kgenome_arm_wm(KGENOME_ARM_WM_F12N, 0x0000f000u) == KGENOME_ARM_R(0));      /* the one after r15 wraps to r0 */
	CK(kgenome_arm_wm(KGENOME_ARM_WM_F12N, 0x00002000u) == KGENOME_ARM_R(3));
	CK(kgenome_arm_wm(KGENOME_ARM_WM_PC, 0) == KGENOME_ARM_R(KGENOME_ARM_PC));
	CK(kgenome_arm_wm(0, 0xffffffffu) == 0);
	CK(kgenome_arm_wm(0x3f, 0xffffffffu) == (KGENOME_ARM_R(15) | KGENOME_ARM_R(0)));

	/* clr / ud / other / dp / imm_insn / wmask_if / rfe */
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_clr(&o);
	CK(o.len == 4);
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_ud(&o);
	CK(o.op == KGENOME_CELL_UD);
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_other(&o, KGENOME_ARM_R(3) | KGENOME_ARM_R(4));
	CK(o.op == KGENOME_CELL_OTHER && o.wmask == (KGENOME_ARM_R(3) | KGENOME_ARM_R(4)));
	/* the general form: the second operand is a register with a shift (the three-operand add) */
	{
		struct kgenome_cell_operand src;
		memset(&src, 0, sizeof src);
		kgenome_arm_op_reg(&src, 2, KGENOME_CELL_OF_READ);
		kgenome_arm_begin(&o, 0x100, 4);
		kgenome_arm_dp(&o, 4 /* ADD */, 0, 1, 0, &src, 8);
		CK(o.op == KGENOME_CELL_ADD && o.n_op == 3 && o.o[0].reg == 0 && o.o[1].reg == 1 && o.o[2].reg == 2);
		CK(o.wmask & KGENOME_ARM_R(0));
		/* rn = pc reads pc + pc_off */
		kgenome_arm_begin(&o, 0x100, 4);
		kgenome_arm_dp(&o, 4, 0, KGENOME_ARM_PC, 0, &src, 8);
		CK(o.n_op >= 2);
	}
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_dp_imm(&o, 4 /* ADD */, 0, 1, 0, 8, 0);
	CK(o.op == KGENOME_CELL_ADD && o.n_op >= 2);
	CK(o.wmask & KGENOME_ARM_R(0));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_dp_imm(&o, 13 /* MOV */, 0, 0, 2, 5, 0);
	CK(o.op == KGENOME_CELL_MOV && (o.wmask & KGENOME_ARM_R(2)));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_dp_imm(&o, 10 /* CMP */, 1, 1, 0, 5, 0);
	CK(o.op == KGENOME_CELL_CMP && !(o.wmask & KGENOME_ARM_R(1)));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_dp_imm(&o, 15, 1, 15, 15, UINT64_MAX, INT64_MIN);      /* every field at its largest */
	CK(o.len == 4);
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_imm_insn(&o, KGENOME_CELL_INT, 0x80);
	CK(o.op == KGENOME_CELL_INT && o.n_op == 1 && o.o[0].imm == 0x80);
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_wmask_if(&o, KGENOME_CELL_MOV, 1, 7);
	CK(o.op == KGENOME_CELL_MOV && o.wmask == KGENOME_ARM_R(7));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_wmask_if(&o, KGENOME_CELL_MOV, 0, 7);
	CK(o.wmask == 0);
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_rfe(&o, KGENOME_CELL_IRET, 1, 5);
	CK(o.op == KGENOME_CELL_IRET && o.wmask == (KGENOME_ARM_R(KGENOME_ARM_PC) | KGENOME_ARM_R(5)));
	kgenome_arm_begin(&o, 0, 4);
	kgenome_arm_rfe(&o, KGENOME_CELL_IRET, 0, 5);
	CK(o.wmask == KGENOME_ARM_R(KGENOME_ARM_PC));
}

/* ---- the x86 attribute readers on known instructions --------------------------------------------- */

static struct kgenome_x86_insn x86(const char *hex, int mode)
{
	uint8_t b[16];
	unsigned n = 0;
	struct kgenome_x86_insn in;

	memset(&in, 0, sizeof in);
	while (hex[0] && hex[1] && n < 16) {
		unsigned v;
		sscanf(hex, "%2x", &v);
		b[n++] = (uint8_t)v;
		hex += 2;
	}
	kgenome_x86_decode(&in, b, n, mode);
	return in;
}

static void t_x86_attrs(void)
{
	struct kgenome_x86_insn in;
	struct kgenome_x86_op ops[KGENOME_X86_MAX_OPS];
	char text[KGENOME_X86_TEXT];
	size_t n;

	/* 48 89 e5  mov rbp, rsp */
	in = x86("4889e5", 64);
	CK(in.len == 3 && kgenome_x86_nops(&in) >= 2 && kgenome_x86_nexp(&in) == 2 && kgenome_x86_nform(&in) >= 2);
	kgenome_x86_operands(&in, ops);
	CK(ops[0].type == KGENOME_X86_OP_REG && ops[0].rtype == KGENOME_X86_REG_GPR && ops[0].reg == 5);
	CK(ops[1].type == KGENOME_X86_OP_REG && ops[1].reg == 4);
	CK(kgenome_x86_gpr_of(&ops[0]) == 5 && kgenome_x86_gpr_of(&ops[1]) == 4);
	CK(kgenome_x86_asz(&in) == 8);
	CK(kgenome_x86_repeated(&in) == 0);
	n = kgenome_x86_format(&in, 0x1000, text, sizeof text);
	CK(n > 0 && n < sizeof text && !strncmp(text, "MOV", 3) && strstr(text, "rbp") && strstr(text, "rsp"));
	CK(strlen(text) == n);
	/* the operand reader and the array reader agree, one operand at a time */
	{
		struct kgenome_x86_op one;
		unsigned k;
		for (k = 0; k < kgenome_x86_nops(&in); k++) {
			kgenome_x86_operand(&in, k, &one);
			CK(one.type == ops[k].type && one.reg == ops[k].reg && one.size == ops[k].size);
		}
	}
	/* 67 8b 00  mov eax, [eax]  : a 67 prefix in 64-bit mode makes the address 4 bytes */
	in = x86("678b00", 64);
	CK(kgenome_x86_asz(&in) == 4);
	in = x86("8b00", 32);
	CK(kgenome_x86_asz(&in) == 4);
	in = x86("678b00", 32);
	CK(kgenome_x86_asz(&in) == 2);
	/* f3 a4  rep movsb : repeated ; a4 alone : not */
	in = x86("f3a4", 64);
	CK(kgenome_x86_repeated(&in) == 1);
	in = x86("a4", 64);
	CK(kgenome_x86_repeated(&in) == 0);
	/* f3 90 pause is REP-prefixed but not a string instruction */
	in = x86("f390", 64);
	CK(kgenome_x86_repeated(&in) == 0);
	/* 6c insb: the definition counts [rdi] and dx though neither is written */
	in = x86("6c", 64);
	CK(kgenome_x86_nform(&in) > kgenome_x86_nexp(&in));
	/* the high-byte registers fold onto rax..rbx: 88 e0 = mov al, ah ; 88 f2 : mov dl, dh */
	in = x86("88e0", 32);
	kgenome_x86_operands(&in, ops);
	CK(ops[1].high8 == 1 && kgenome_x86_gpr_of(&ops[1]) == 0);
	in = x86("88f2", 64);
	kgenome_x86_operands(&in, ops);
	CK(ops[1].high8 == 1 && kgenome_x86_gpr_of(&ops[1]) == 2);
	{
		/* a non-register and a non-GPR register are "none" */
		struct kgenome_x86_op mem;
		memset(&mem, 0, sizeof mem);
		mem.type = KGENOME_X86_OP_MEM;
		CK(kgenome_x86_gpr_of(&mem) == KGENOME_X86_NGPR);
		mem.type = KGENOME_X86_OP_REG;
		mem.rtype = KGENOME_X86_REG_SSE;
		CK(kgenome_x86_gpr_of(&mem) == KGENOME_X86_NGPR);
		mem.rtype = KGENOME_X86_REG_GPR;
		mem.reg = 31;
		CK(kgenome_x86_gpr_of(&mem) == KGENOME_X86_NGPR);
		mem.reg = 15;
		CK(kgenome_x86_gpr_of(&mem) == 15);
		mem.reg = 6;
		mem.high8 = 1;
		CK(kgenome_x86_gpr_of(&mem) == 2);
		mem.reg = 8;
		CK(kgenome_x86_gpr_of(&mem) == 8);      /* r8b is not a high-byte register */
	}
	/* wgpr: the implicit writes of cdq (edx) and mul (rax, rdx) */
	in = x86("99", 64);
	CK(kgenome_x86_wgpr(&in) & (1u << 2));
	in = x86("48f7e3", 64);
	CK((kgenome_x86_wgpr(&in) & 5u) == 5u);
	/* a call and a conditional jump have a category and a condition */
	in = x86("e800000000", 64);
	CK(kgenome_x86_cat(&in) != 0);
	in = x86("7400", 64);
	{
		struct kgenome_x86_insn je = x86("7400", 64), jne = x86("7500", 64);
		CK(kgenome_x86_cond(&je) != kgenome_x86_cond(&jne));
	}

	/* the text for hostile instruction pointers and buffers */
	in = x86("e8fbffffff", 64);                  /* call .  */
	n = kgenome_x86_format(&in, 0x400000, text, sizeof text);
	CK(n > 0 && strstr(text, "0x400000"));
	n = kgenome_x86_format(&in, UINT64_MAX - 1u, text, sizeof text);
	CK(n > 0);                                   /* wraps, still prints */
	CK(kgenome_x86_format(&in, 0, text, 0) == 0);
	CK(kgenome_x86_format(&in, 0, text, 1) == 0);
	CK(kgenome_x86_format(&in, 0, text, 2) <= 1);
	CK(kgenome_x86_format(&in, 0, text, 5) <= 4);

	/* sweep: the same instruction, the explicit operands narrowed to what is kept */
	{
		struct kgenome_x86_sweep sw;
		const uint8_t mov[] = { 0x48, 0x8b, 0x45, 0xf8 };       /* mov rax, [rbp-8] */
		CK(kgenome_x86_sweep(&sw, mov, sizeof mov, 64) == KGENOME_OK);
		CK(sw.len == 4 && sw.n == 2);
		CK(sw.op[0].kind == KGENOME_X86_SK_REG && sw.op[0].reg == 0 && (sw.op[0].flags & KGENOME_X86_SF_WRITE));
		CK(sw.op[1].kind == KGENOME_X86_SK_MEM && sw.op[1].reg == 5 && sw.op[1].disp == -8 &&
		   sw.op[1].index == KGENOME_X86_SREG_NONE && (sw.op[1].flags & KGENOME_X86_SF_READ));
		CK(sw.wmask & 1u);
		CK(sw.op[2].kind == KGENOME_X86_SK_NONE);
	}
	{
		struct kgenome_x86_sweep sw;
		const uint8_t jmp[] = { 0xeb, 0xfe };
		CK(kgenome_x86_sweep(&sw, jmp, sizeof jmp, 64) == KGENOME_OK);
		CK(sw.n == 1 && sw.op[0].kind == KGENOME_X86_SK_REL && (int64_t)sw.op[0].imm == -2);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	t_arm32_fields();
	t_thumb_fields();
	t_arm64_fields();
	t_arm64_id_tables();
	t_arm_helpers();
	t_x86_attrs();
	printf("api_decoders: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
