/*
 * thumb_rows.c - the Thumb state instruction encodings, 16-bit and 32-bit: THE
 * CANONICAL TABLE.
 *
 * Hand-maintained data, in the form arm32_rows.c explains: {mask, value, name},
 * the ARM ARM-style pattern in the comment on the same line, rows in PRIORITY
 * ORDER with the first match winning. The index the decoder runs on is DERIVED
 * from these rows by code (arm32_index.c) the first time a decode needs it;
 * tests/unit/genotype_arm32.c fails if a row is shadowed by an earlier one.
 *
 * THE 16-BIT TABLE (Thumb-1, and the 16-bit forms Thumb-2 added). Names keep the
 * architecture's own spelling; the 16-bit forms that set the flags outside an IT
 * block carry the S the assembler prints (ADDS_REG). The length is not in this
 * file: the first halfword's top five bits being 11101, 11110 or 11111 make an
 * instruction 32 bits, and those never reach the 16-bit table.
 *
 * THE 32-BIT TABLE (Thumb-2). A suffix _W is the architecture's .W: the wide form
 * of an instruction that also has a 16-bit one, named so that one enum can hold
 * both.
 */
#include "thumb_ids.h"
#include "arm32_int.h"

/* 16 bits: the first halfword. */
const struct gt_arm32_row gt_thumb_src_narrow[] = {
	/* ---- shift by immediate, add/subtract, move/compare/add/subtract 8-bit ---- */
	/* 0000 0000 00xx xxxx */ { 0xffc0u, 0x0000u, GT_THUMB_I_MOVS_REG },
	/* 0000 0xxx xxxx xxxx */ { 0xf800u, 0x0000u, GT_THUMB_I_LSL_IMM },
	/* 0000 1xxx xxxx xxxx */ { 0xf800u, 0x0800u, GT_THUMB_I_LSR_IMM },
	/* 0001 0xxx xxxx xxxx */ { 0xf800u, 0x1000u, GT_THUMB_I_ASR_IMM },
	/* 0001 100x xxxx xxxx */ { 0xfe00u, 0x1800u, GT_THUMB_I_ADDS_REG },
	/* 0001 101x xxxx xxxx */ { 0xfe00u, 0x1a00u, GT_THUMB_I_SUBS_REG },
	/* 0001 110x xxxx xxxx */ { 0xfe00u, 0x1c00u, GT_THUMB_I_ADDS_IMM3 },
	/* 0001 111x xxxx xxxx */ { 0xfe00u, 0x1e00u, GT_THUMB_I_SUBS_IMM3 },
	/* 0010 0xxx xxxx xxxx */ { 0xf800u, 0x2000u, GT_THUMB_I_MOVS_IMM8 },
	/* 0010 1xxx xxxx xxxx */ { 0xf800u, 0x2800u, GT_THUMB_I_CMP_IMM8 },
	/* 0011 0xxx xxxx xxxx */ { 0xf800u, 0x3000u, GT_THUMB_I_ADDS_IMM8 },
	/* 0011 1xxx xxxx xxxx */ { 0xf800u, 0x3800u, GT_THUMB_I_SUBS_IMM8 },

	/* ---- data processing, register: 010000 op(4) rm rdn ---- */
	/* 0100 0000 00xx xxxx */ { 0xffc0u, 0x4000u, GT_THUMB_I_ANDS_REG },
	/* 0100 0000 01xx xxxx */ { 0xffc0u, 0x4040u, GT_THUMB_I_EORS_REG },
	/* 0100 0000 10xx xxxx */ { 0xffc0u, 0x4080u, GT_THUMB_I_LSLS_REG },
	/* 0100 0000 11xx xxxx */ { 0xffc0u, 0x40c0u, GT_THUMB_I_LSRS_REG },
	/* 0100 0001 00xx xxxx */ { 0xffc0u, 0x4100u, GT_THUMB_I_ASRS_REG },
	/* 0100 0001 01xx xxxx */ { 0xffc0u, 0x4140u, GT_THUMB_I_ADCS_REG },
	/* 0100 0001 10xx xxxx */ { 0xffc0u, 0x4180u, GT_THUMB_I_SBCS_REG },
	/* 0100 0001 11xx xxxx */ { 0xffc0u, 0x41c0u, GT_THUMB_I_RORS_REG },
	/* 0100 0010 00xx xxxx */ { 0xffc0u, 0x4200u, GT_THUMB_I_TST_REG },
	/* 0100 0010 01xx xxxx */ { 0xffc0u, 0x4240u, GT_THUMB_I_RSBS_IMM0 },
	/* 0100 0010 10xx xxxx */ { 0xffc0u, 0x4280u, GT_THUMB_I_CMP_REG },
	/* 0100 0010 11xx xxxx */ { 0xffc0u, 0x42c0u, GT_THUMB_I_CMN_REG },
	/* 0100 0011 00xx xxxx */ { 0xffc0u, 0x4300u, GT_THUMB_I_ORRS_REG },
	/* 0100 0011 01xx xxxx */ { 0xffc0u, 0x4340u, GT_THUMB_I_MULS },
	/* 0100 0011 10xx xxxx */ { 0xffc0u, 0x4380u, GT_THUMB_I_BICS_REG },
	/* 0100 0011 11xx xxxx */ { 0xffc0u, 0x43c0u, GT_THUMB_I_MVNS_REG },

	/* ---- special data processing and branch exchange ---- */
	/* 0100 0100 xxxx xxxx */ { 0xff00u, 0x4400u, GT_THUMB_I_ADD_REG_HI },
	/* 0100 0101 xxxx xxxx */ { 0xff00u, 0x4500u, GT_THUMB_I_CMP_REG_HI },
	/* 0100 0110 xxxx xxxx */ { 0xff00u, 0x4600u, GT_THUMB_I_MOV_REG_HI },
	/* 0100 0111 0xxx xxxx */ { 0xff80u, 0x4700u, GT_THUMB_I_BX },
	/* 0100 0111 1xxx xxxx */ { 0xff80u, 0x4780u, GT_THUMB_I_BLX_REG },

	/* ---- load and store ---- */
	/* 0100 1xxx xxxx xxxx */ { 0xf800u, 0x4800u, GT_THUMB_I_LDR_LIT },
	/* 0101 000x xxxx xxxx */ { 0xfe00u, 0x5000u, GT_THUMB_I_STR_REG },
	/* 0101 001x xxxx xxxx */ { 0xfe00u, 0x5200u, GT_THUMB_I_STRH_REG },
	/* 0101 010x xxxx xxxx */ { 0xfe00u, 0x5400u, GT_THUMB_I_STRB_REG },
	/* 0101 011x xxxx xxxx */ { 0xfe00u, 0x5600u, GT_THUMB_I_LDRSB_REG },
	/* 0101 100x xxxx xxxx */ { 0xfe00u, 0x5800u, GT_THUMB_I_LDR_REG },
	/* 0101 101x xxxx xxxx */ { 0xfe00u, 0x5a00u, GT_THUMB_I_LDRH_REG },
	/* 0101 110x xxxx xxxx */ { 0xfe00u, 0x5c00u, GT_THUMB_I_LDRB_REG },
	/* 0101 111x xxxx xxxx */ { 0xfe00u, 0x5e00u, GT_THUMB_I_LDRSH_REG },
	/* 0110 0xxx xxxx xxxx */ { 0xf800u, 0x6000u, GT_THUMB_I_STR_IMM5 },
	/* 0110 1xxx xxxx xxxx */ { 0xf800u, 0x6800u, GT_THUMB_I_LDR_IMM5 },
	/* 0111 0xxx xxxx xxxx */ { 0xf800u, 0x7000u, GT_THUMB_I_STRB_IMM5 },
	/* 0111 1xxx xxxx xxxx */ { 0xf800u, 0x7800u, GT_THUMB_I_LDRB_IMM5 },
	/* 1000 0xxx xxxx xxxx */ { 0xf800u, 0x8000u, GT_THUMB_I_STRH_IMM5 },
	/* 1000 1xxx xxxx xxxx */ { 0xf800u, 0x8800u, GT_THUMB_I_LDRH_IMM5 },
	/* 1001 0xxx xxxx xxxx */ { 0xf800u, 0x9000u, GT_THUMB_I_STR_SP },
	/* 1001 1xxx xxxx xxxx */ { 0xf800u, 0x9800u, GT_THUMB_I_LDR_SP },
	/* 1010 0xxx xxxx xxxx */ { 0xf800u, 0xa000u, GT_THUMB_I_ADR },
	/* 1010 1xxx xxxx xxxx */ { 0xf800u, 0xa800u, GT_THUMB_I_ADD_SP_IMM8 },

	/* ---- miscellaneous: 1011 ---- */
	/* 1011 0000 0xxx xxxx */ { 0xff80u, 0xb000u, GT_THUMB_I_ADD_SP_IMM7 },
	/* 1011 0000 1xxx xxxx */ { 0xff80u, 0xb080u, GT_THUMB_I_SUB_SP_IMM7 },
	/* 1011 00x1 xxxx xxxx */ { 0xfd00u, 0xb100u, GT_THUMB_I_CBZ },
	/* 1011 10x1 xxxx xxxx */ { 0xfd00u, 0xb900u, GT_THUMB_I_CBNZ },
	/* 1011 0010 00xx xxxx */ { 0xffc0u, 0xb200u, GT_THUMB_I_SXTH },
	/* 1011 0010 01xx xxxx */ { 0xffc0u, 0xb240u, GT_THUMB_I_SXTB },
	/* 1011 0010 10xx xxxx */ { 0xffc0u, 0xb280u, GT_THUMB_I_UXTH },
	/* 1011 0010 11xx xxxx */ { 0xffc0u, 0xb2c0u, GT_THUMB_I_UXTB },
	/* 1011 010x xxxx xxxx */ { 0xfe00u, 0xb400u, GT_THUMB_I_PUSH },
	/* 1011 110x xxxx xxxx */ { 0xfe00u, 0xbc00u, GT_THUMB_I_POP },
	/* 1011 0110 011x xxxx */ { 0xffe0u, 0xb660u, GT_THUMB_I_CPS },
	/* 1011 0110 0101 xxxx */ { 0xfff0u, 0xb650u, GT_THUMB_I_SETEND },
	/* 1011 0110 xxxx xxxx */ { 0xff00u, 0xb600u, GT_THUMB_I_INVALID },
	/* 1011 1010 00xx xxxx */ { 0xffc0u, 0xba00u, GT_THUMB_I_REV },
	/* 1011 1010 01xx xxxx */ { 0xffc0u, 0xba40u, GT_THUMB_I_REV16 },
	/* 1011 1010 10xx xxxx */ { 0xffc0u, 0xba80u, GT_THUMB_I_INVALID },
	/* 1011 1010 11xx xxxx */ { 0xffc0u, 0xbac0u, GT_THUMB_I_REVSH },
	/* 1011 1110 xxxx xxxx */ { 0xff00u, 0xbe00u, GT_THUMB_I_BKPT },
	/* hints (NOP, YIELD, WFE, WFI, SEV) have a zero low nibble; any other is IT */
	/* 1011 1111 xxxx 0000 */ { 0xff0fu, 0xbf00u, GT_THUMB_I_HINT },
	/* 1011 1111 xxxx xxxx */ { 0xff00u, 0xbf00u, GT_THUMB_I_IT },
	/* 1011 xxxx xxxx xxxx */ { 0xf000u, 0xb000u, GT_THUMB_I_INVALID },

	/* ---- load/store multiple, conditional branch, supervisor call, branch ---- */
	/* 1100 0xxx xxxx xxxx */ { 0xf800u, 0xc000u, GT_THUMB_I_STM },
	/* 1100 1xxx xxxx xxxx */ { 0xf800u, 0xc800u, GT_THUMB_I_LDM },
	/* 1101 1110 xxxx xxxx */ { 0xff00u, 0xde00u, GT_THUMB_I_UDF },
	/* 1101 1111 xxxx xxxx */ { 0xff00u, 0xdf00u, GT_THUMB_I_SVC },
	/* 1101 xxxx xxxx xxxx */ { 0xf000u, 0xd000u, GT_THUMB_I_BCOND },
	/* 1110 0xxx xxxx xxxx */ { 0xf800u, 0xe000u, GT_THUMB_I_B },
};
const unsigned gt_thumb_src_narrow_n = sizeof gt_thumb_src_narrow / sizeof gt_thumb_src_narrow[0];

/* 32 bits: the first halfword in the high half, then the second. */
const struct gt_arm32_row gt_thumb_src_wide[] = {
	/* ======================= first halfword 11101: 1110 1xxx ================= */

	/* ---- coprocessor: first halfword 111x 11xx (also the 11111 group) ---- */
	/* the cp13 slot of ldc2/stc2 is ARMv8.2's VSDOT/VUDOT (vector) */
	/* 1111 1100 0x10 xxxx xxxx 1101 xxxx xxxx */ { 0xffb00f00u, 0xfc200d00u, GT_THUMB_I_VDOT },
	/* 111x 1100 000x xxxx xxxx xxxx xxxx xxxx */ { 0xefe00000u, 0xec000000u, GT_THUMB_I_INVALID },
	/* 111x 1100 0100 xxxx xxxx xxxx xxxx xxxx */ { 0xeff00000u, 0xec400000u, GT_THUMB_I_MCRR },
	/* 111x 1100 0101 xxxx xxxx xxxx xxxx xxxx */ { 0xeff00000u, 0xec500000u, GT_THUMB_I_MRRC },
	/* 111x 110x xxx0 xxxx xxxx xxxx xxxx xxxx */ { 0xee100000u, 0xec000000u, GT_THUMB_I_STC },
	/* 111x 110x xxx1 xxxx xxxx xxxx xxxx xxxx */ { 0xee100000u, 0xec100000u, GT_THUMB_I_LDC },
	/* 111x 1110 xxxx xxxx xxxx xxxx xxx0 xxxx */ { 0xef000010u, 0xee000000u, GT_THUMB_I_CDP },
	/* 111x 1110 xxx0 xxxx xxxx xxxx xxx1 xxxx */ { 0xef100010u, 0xee000010u, GT_THUMB_I_MCR },
	/* 111x 1110 xxx1 xxxx xxxx xxxx xxx1 xxxx */ { 0xef100010u, 0xee100010u, GT_THUMB_I_MRC },
	/* 111x 1111 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xef000000u, 0xef000000u, GT_THUMB_I_ASIMD_DP },

	/* ---- data processing, shifted register: 1110 101x ---- */
	/* 1110 1010 110x xxxx xxxx xxxx xx0x xxxx */ { 0xffe00020u, 0xeac00000u, GT_THUMB_I_PKHBT },
	/* 1110 1010 110x xxxx xxxx xxxx xx1x xxxx */ { 0xffe00020u, 0xeac00020u, GT_THUMB_I_PKHTB },
	/* 1110 1010 0001 xxxx xxxx 1111 xxxx xxxx */ { 0xfff00f00u, 0xea100f00u, GT_THUMB_I_TST_REG_W },
	/* 1110 1010 000x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xea000000u, GT_THUMB_I_AND_REG_W },
	/* 1110 1010 001x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xea200000u, GT_THUMB_I_BIC_REG_W },
	/* 1110 1010 010x 1111 xxxx xxxx xxxx xxxx */ { 0xffef0000u, 0xea4f0000u, GT_THUMB_I_MOV_REG_W },
	/* 1110 1010 010x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xea400000u, GT_THUMB_I_ORR_REG_W },
	/* 1110 1010 011x 1111 xxxx xxxx xxxx xxxx */ { 0xffef0000u, 0xea6f0000u, GT_THUMB_I_MVN_REG_W },
	/* 1110 1010 011x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xea600000u, GT_THUMB_I_ORN_REG_W },
	/* 1110 1010 1001 xxxx xxxx 1111 xxxx xxxx */ { 0xfff00f00u, 0xea900f00u, GT_THUMB_I_TEQ_REG_W },
	/* 1110 1010 100x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xea800000u, GT_THUMB_I_EOR_REG_W },
	/* 1110 1010 101x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeaa00000u, GT_THUMB_I_INVALID },
	/* 1110 1010 111x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeae00000u, GT_THUMB_I_INVALID },
	/* 1110 1011 0001 xxxx xxxx 1111 xxxx xxxx */ { 0xfff00f00u, 0xeb100f00u, GT_THUMB_I_CMN_REG_W },
	/* 1110 1011 000x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeb000000u, GT_THUMB_I_ADD_REG_W },
	/* 1110 1011 001x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeb200000u, GT_THUMB_I_INVALID },
	/* 1110 1011 010x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeb400000u, GT_THUMB_I_ADC_REG_W },
	/* 1110 1011 011x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeb600000u, GT_THUMB_I_SBC_REG_W },
	/* 1110 1011 100x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeb800000u, GT_THUMB_I_INVALID },
	/* 1110 1011 1011 xxxx xxxx 1111 xxxx xxxx */ { 0xfff00f00u, 0xebb00f00u, GT_THUMB_I_CMP_REG_W },
	/* 1110 1011 101x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xeba00000u, GT_THUMB_I_SUB_REG_W },
	/* 1110 1011 110x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xebc00000u, GT_THUMB_I_RSB_REG_W },
	/* 1110 1011 111x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xebe00000u, GT_THUMB_I_INVALID },

	/* ---- load/store dual, exclusive, table branch: 1110 100x x1xx ---- */
	/* P = 0, W = 0: exclusive and acquire/release, table branch */
	/* 1110 1000 0100 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xe8400000u, GT_THUMB_I_STREX },
	/* 1110 1000 0101 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xe8500000u, GT_THUMB_I_LDREX },
	/* 1110 1000 1101 xxxx xxxx xxxx 1011 xxxx */ { 0xfff000f0u, 0xe8d000b0u, GT_THUMB_I_INVALID },
	/* 1110 1000 1100 xxxx xxxx xxxx 1011 xxxx */ { 0xfff000f0u, 0xe8c000b0u, GT_THUMB_I_INVALID },
	/* 1110 1000 1101 xxxx xxxx xxxx 1000 xxxx */ { 0xfff000f0u, 0xe8d00080u, GT_THUMB_I_LDAB },
	/* 1110 1000 1101 xxxx xxxx xxxx 1001 xxxx */ { 0xfff000f0u, 0xe8d00090u, GT_THUMB_I_LDAH },
	/* 1110 1000 1101 xxxx xxxx xxxx 1010 xxxx */ { 0xfff000f0u, 0xe8d000a0u, GT_THUMB_I_LDA },
	/* 1110 1000 1101 xxxx xxxx xxxx 1100 xxxx */ { 0xfff000f0u, 0xe8d000c0u, GT_THUMB_I_LDAEXB },
	/* 1110 1000 1101 xxxx xxxx xxxx 1101 xxxx */ { 0xfff000f0u, 0xe8d000d0u, GT_THUMB_I_LDAEXH },
	/* 1110 1000 1101 xxxx xxxx xxxx 1110 xxxx */ { 0xfff000f0u, 0xe8d000e0u, GT_THUMB_I_LDAEX },
	/* 1110 1000 1101 xxxx xxxx xxxx 1111 xxxx */ { 0xfff000f0u, 0xe8d000f0u, GT_THUMB_I_LDAEXD },
	/* 1110 1000 1100 xxxx xxxx xxxx 1000 xxxx */ { 0xfff000f0u, 0xe8c00080u, GT_THUMB_I_STLB },
	/* 1110 1000 1100 xxxx xxxx xxxx 1001 xxxx */ { 0xfff000f0u, 0xe8c00090u, GT_THUMB_I_STLH },
	/* 1110 1000 1100 xxxx xxxx xxxx 1010 xxxx */ { 0xfff000f0u, 0xe8c000a0u, GT_THUMB_I_STL },
	/* 1110 1000 1100 xxxx xxxx xxxx 1100 xxxx */ { 0xfff000f0u, 0xe8c000c0u, GT_THUMB_I_STLEXB },
	/* 1110 1000 1100 xxxx xxxx xxxx 1101 xxxx */ { 0xfff000f0u, 0xe8c000d0u, GT_THUMB_I_STLEXH },
	/* 1110 1000 1100 xxxx xxxx xxxx 1110 xxxx */ { 0xfff000f0u, 0xe8c000e0u, GT_THUMB_I_STLEX },
	/* 1110 1000 1100 xxxx xxxx xxxx 1111 xxxx */ { 0xfff000f0u, 0xe8c000f0u, GT_THUMB_I_STLEXD },
	/* 1110 1000 1101 xxxx xxxx xxxx 0000 xxxx */ { 0xfff000f0u, 0xe8d00000u, GT_THUMB_I_TBB },
	/* 1110 1000 1101 xxxx xxxx xxxx 0001 xxxx */ { 0xfff000f0u, 0xe8d00010u, GT_THUMB_I_TBH },
	/* 1110 1000 1101 xxxx xxxx xxxx 0100 xxxx */ { 0xfff000f0u, 0xe8d00040u, GT_THUMB_I_LDREXB },
	/* 1110 1000 1101 xxxx xxxx xxxx 0101 xxxx */ { 0xfff000f0u, 0xe8d00050u, GT_THUMB_I_LDREXH },
	/* 1110 1000 1101 xxxx xxxx xxxx 0111 xxxx */ { 0xfff000f0u, 0xe8d00070u, GT_THUMB_I_LDREXD },
	/* 1110 1000 1100 xxxx xxxx xxxx 0100 xxxx */ { 0xfff000f0u, 0xe8c00040u, GT_THUMB_I_STREXB },
	/* 1110 1000 1100 xxxx xxxx xxxx 0101 xxxx */ { 0xfff000f0u, 0xe8c00050u, GT_THUMB_I_STREXH },
	/* 1110 1000 1100 xxxx xxxx xxxx 0111 xxxx */ { 0xfff000f0u, 0xe8c00070u, GT_THUMB_I_STREXD },
	/* 1110 1000 x10x xxxx xxxx xxxx xxxx xxxx */ { 0xff600000u, 0xe8400000u, GT_THUMB_I_INVALID },
	/* P = 1 or W = 1: ldrd, strd */
	/* 1110 100x x1x0 xxxx xxxx xxxx xxxx xxxx */ { 0xfe500000u, 0xe8400000u, GT_THUMB_I_STRD_IMM },
	/* 1110 100x x1x1 xxxx xxxx xxxx xxxx xxxx */ { 0xfe500000u, 0xe8500000u, GT_THUMB_I_LDRD_IMM },

	/* ---- load/store multiple: 1110 100x x0xx ---- */
	/* 1110 1000 00x0 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe8000000u, GT_THUMB_I_SRS },
	/* 1110 1000 00x1 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe8100000u, GT_THUMB_I_RFE },
	/* 1110 1001 10x0 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe9800000u, GT_THUMB_I_SRS },
	/* 1110 1001 10x1 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe9900000u, GT_THUMB_I_RFE },
	/* 1110 1000 1011 1101 xxxx xxxx xxxx xxxx */ { 0xffff0000u, 0xe8bd0000u, GT_THUMB_I_POP_W },
	/* 1110 1000 10x0 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe8800000u, GT_THUMB_I_STM_W },
	/* 1110 1000 10x1 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe8900000u, GT_THUMB_I_LDM_W },
	/* 1110 1001 0010 1101 xxxx xxxx xxxx xxxx */ { 0xffff0000u, 0xe92d0000u, GT_THUMB_I_PUSH_W },
	/* 1110 1001 00x0 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe9000000u, GT_THUMB_I_STMDB_W },
	/* 1110 1001 00x1 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xe9100000u, GT_THUMB_I_LDMDB_W },

	/* ======================= first halfword 11110: 1111 0xxx ================= */

	/* ---- branches and miscellaneous control: second halfword bit 15 = 1 ---- */
	/* bits 14 and 12 of the second halfword: 00 conditional branch or control, 01 b.w, */
	/* 11 bl, 10 blx */
	/* 1111 0011 100x xxxx 10x0 xxxx xxxx xxxx */ { 0xffe0d000u, 0xf3808000u, GT_THUMB_I_MSR },
	/* 1111 0011 1010 xxxx 10x0 x000 xxxx xxxx */ { 0xfff0d700u, 0xf3a08000u, GT_THUMB_I_HINT_W },
	/* 1111 0011 1010 xxxx 10x0 xxxx xxxx xxxx */ { 0xfff0d000u, 0xf3a08000u, GT_THUMB_I_CPS_W },
	/* 1111 0011 1011 xxxx 10x0 xxxx 0010 xxxx */ { 0xfff0d0f0u, 0xf3b08020u, GT_THUMB_I_CLREX },
	/* 1111 0011 1011 xxxx 10x0 xxxx 0100 xxxx */ { 0xfff0d0f0u, 0xf3b08040u, GT_THUMB_I_DSB },
	/* 1111 0011 1011 xxxx 10x0 xxxx 0101 xxxx */ { 0xfff0d0f0u, 0xf3b08050u, GT_THUMB_I_DMB },
	/* 1111 0011 1011 xxxx 10x0 xxxx 0110 xxxx */ { 0xfff0d0f0u, 0xf3b08060u, GT_THUMB_I_ISB },
	/* 1111 0011 1011 xxxx 10x0 xxxx xxxx xxxx */ { 0xfff0d000u, 0xf3b08000u, GT_THUMB_I_INVALID },
	/* 1111 0011 1100 xxxx 10x0 xxxx xxxx xxxx */ { 0xfff0d000u, 0xf3c08000u, GT_THUMB_I_BXJ },
	/* 1111 0011 1101 xxxx 10x0 xxxx xxxx xxxx */ { 0xfff0d000u, 0xf3d08000u, GT_THUMB_I_SUBS_PC_LR },
	/* 1111 0011 111x xxxx 10x0 xxxx xxxx xxxx */ { 0xffe0d000u, 0xf3e08000u, GT_THUMB_I_MRS },
	/* 1111 0111 1110 xxxx 1000 xxxx xxxx xxxx */ { 0xfff0f000u, 0xf7e08000u, GT_THUMB_I_HVC },
	/* 1111 0111 1111 xxxx 1000 xxxx xxxx xxxx */ { 0xfff0f000u, 0xf7f08000u, GT_THUMB_I_SMC },
	/* 1111 0111 1111 xxxx 1010 xxxx xxxx xxxx */ { 0xfff0f000u, 0xf7f0a000u, GT_THUMB_I_UDF_W },
	/* 1111 0x11 1xxx xxxx 10x0 xxxx xxxx xxxx */ { 0xfb80d000u, 0xf3808000u, GT_THUMB_I_INVALID },
	/* 1111 0xxx xxxx xxxx 10x0 xxxx xxxx xxxx */ { 0xf800d000u, 0xf0008000u, GT_THUMB_I_BCOND_W },
	/* 1111 0xxx xxxx xxxx 10x1 xxxx xxxx xxxx */ { 0xf800d000u, 0xf0009000u, GT_THUMB_I_B_W },
	/* 1111 0xxx xxxx xxxx 11x1 xxxx xxxx xxxx */ { 0xf800d000u, 0xf000d000u, GT_THUMB_I_BL },
	/* 1111 0xxx xxxx xxxx 11x0 xxxx xxxx xxx0 */ { 0xf800d001u, 0xf000c000u, GT_THUMB_I_BLX_IMM },
	/* 1111 0xxx xxxx xxxx 11x0 xxxx xxxx xxx1 */ { 0xf800d001u, 0xf000c001u, GT_THUMB_I_INVALID },

	/* ---- data processing, plain binary immediate: 1111 0x1x, bit 15 = 0 ---- */
	/* 1111 0x10 0000 1111 0xxx xxxx xxxx xxxx */ { 0xfbff8000u, 0xf20f0000u, GT_THUMB_I_ADR_ADD },
	/* 1111 0x10 0000 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf2000000u, GT_THUMB_I_ADDW },
	/* 1111 0x10 1010 1111 0xxx xxxx xxxx xxxx */ { 0xfbff8000u, 0xf2af0000u, GT_THUMB_I_ADR_SUB },
	/* 1111 0x10 1010 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf2a00000u, GT_THUMB_I_SUBW },
	/* 1111 0x10 0100 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf2400000u, GT_THUMB_I_MOVW },
	/* 1111 0x10 1100 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf2c00000u, GT_THUMB_I_MOVT },
	/* 1111 0x11 0000 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3000000u, GT_THUMB_I_SSAT },
	/* 1111 0x11 0010 xxxx 0000 xxxx 00xx xxxx */ { 0xfbf0f0c0u, 0xf3200000u, GT_THUMB_I_SSAT16 },
	/* 1111 0x11 0010 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3200000u, GT_THUMB_I_SSAT },
	/* 1111 0x11 0100 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3400000u, GT_THUMB_I_SBFX },
	/* 1111 0x11 0110 1111 0xxx xxxx xxxx xxxx */ { 0xfbff8000u, 0xf36f0000u, GT_THUMB_I_BFC },
	/* 1111 0x11 0110 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3600000u, GT_THUMB_I_BFI },
	/* 1111 0x11 1000 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3800000u, GT_THUMB_I_USAT },
	/* 1111 0x11 1010 xxxx 0000 xxxx 00xx xxxx */ { 0xfbf0f0c0u, 0xf3a00000u, GT_THUMB_I_USAT16 },
	/* 1111 0x11 1010 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3a00000u, GT_THUMB_I_USAT },
	/* 1111 0x11 1100 xxxx 0xxx xxxx xxxx xxxx */ { 0xfbf08000u, 0xf3c00000u, GT_THUMB_I_UBFX },
	/* 1111 0x1x xxxx xxxx 0xxx xxxx xxxx xxxx */ { 0xfa008000u, 0xf2000000u, GT_THUMB_I_INVALID },

	/* ---- data processing, modified immediate: 1111 0x0x, bit 15 = 0 ---- */
	/* 1111 0x00 0001 xxxx 0xxx 1111 xxxx xxxx */ { 0xfbf08f00u, 0xf0100f00u, GT_THUMB_I_TST_IMM_W },
	/* 1111 0x00 000x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf0000000u, GT_THUMB_I_AND_IMM_W },
	/* 1111 0x00 001x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf0200000u, GT_THUMB_I_BIC_IMM_W },
	/* 1111 0x00 010x 1111 0xxx xxxx xxxx xxxx */ { 0xfbef8000u, 0xf04f0000u, GT_THUMB_I_MOV_IMM_W },
	/* 1111 0x00 010x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf0400000u, GT_THUMB_I_ORR_IMM_W },
	/* 1111 0x00 011x 1111 0xxx xxxx xxxx xxxx */ { 0xfbef8000u, 0xf06f0000u, GT_THUMB_I_MVN_IMM_W },
	/* 1111 0x00 011x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf0600000u, GT_THUMB_I_ORN_IMM_W },
	/* 1111 0x00 1001 xxxx 0xxx 1111 xxxx xxxx */ { 0xfbf08f00u, 0xf0900f00u, GT_THUMB_I_TEQ_IMM_W },
	/* 1111 0x00 100x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf0800000u, GT_THUMB_I_EOR_IMM_W },
	/* 1111 0x00 101x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf0a00000u, GT_THUMB_I_INVALID },
	/* 1111 0x00 11xx xxxx 0xxx xxxx xxxx xxxx */ { 0xfbc08000u, 0xf0c00000u, GT_THUMB_I_INVALID },
	/* 1111 0x01 0001 xxxx 0xxx 1111 xxxx xxxx */ { 0xfbf08f00u, 0xf1100f00u, GT_THUMB_I_CMN_IMM_W },
	/* 1111 0x01 000x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1000000u, GT_THUMB_I_ADD_IMM_W },
	/* 1111 0x01 001x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1200000u, GT_THUMB_I_INVALID },
	/* 1111 0x01 010x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1400000u, GT_THUMB_I_ADC_IMM_W },
	/* 1111 0x01 011x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1600000u, GT_THUMB_I_SBC_IMM_W },
	/* 1111 0x01 100x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1800000u, GT_THUMB_I_INVALID },
	/* 1111 0x01 1011 xxxx 0xxx 1111 xxxx xxxx */ { 0xfbf08f00u, 0xf1b00f00u, GT_THUMB_I_CMP_IMM_W },
	/* 1111 0x01 101x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1a00000u, GT_THUMB_I_SUB_IMM_W },
	/* 1111 0x01 110x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1c00000u, GT_THUMB_I_RSB_IMM_W },
	/* 1111 0x01 111x xxxx 0xxx xxxx xxxx xxxx */ { 0xfbe08000u, 0xf1e00000u, GT_THUMB_I_INVALID },

	/* ======================= first halfword 11111: 1111 1xxx ================= */

	/* ---- Advanced SIMD element and structure load/store ---- */
	/* 1111 1001 xxx0 xxxx xxxx xxxx xxxx xxxx */ { 0xff100000u, 0xf9000000u, GT_THUMB_I_VLDST },

	/* ---- store single: 1111 1000 kkk0, k = size/form ---- */
	/* 1111 1000 xxx0 1111 xxxx xxxx xxxx xxxx */ { 0xff1f0000u, 0xf80f0000u, GT_THUMB_I_INVALID },
	/* 1111 1000 x110 xxxx xxxx xxxx xxxx xxxx */ { 0xff700000u, 0xf8600000u, GT_THUMB_I_INVALID },
	/* 1111 1000 1000 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8800000u, GT_THUMB_I_STRB_IMM12_W },
	/* 1111 1000 1010 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8a00000u, GT_THUMB_I_STRH_IMM12_W },
	/* 1111 1000 1100 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8c00000u, GT_THUMB_I_STR_IMM12_W },
	/* 1111 1000 0100 1101 xxxx 1101 0000 0100 */ { 0xffff0fffu, 0xf84d0d04u, GT_THUMB_I_PUSH_REG_W },
	/* 1111 1000 0xx0 xxxx xxxx 10x0 xxxx xxxx */ { 0xff900d00u, 0xf8000800u, GT_THUMB_I_INVALID },
	/* 1111 1000 0000 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf8000800u, GT_THUMB_I_STRB_IMM8_W },
	/* 1111 1000 0010 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf8200800u, GT_THUMB_I_STRH_IMM8_W },
	/* 1111 1000 0100 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf8400800u, GT_THUMB_I_STR_IMM8_W },
	/* 1111 1000 0000 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf8000000u, GT_THUMB_I_STRB_REG_W },
	/* 1111 1000 0010 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf8200000u, GT_THUMB_I_STRH_REG_W },
	/* 1111 1000 0100 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf8400000u, GT_THUMB_I_STR_REG_W },
	/* 1111 1000 xxx0 xxxx xxxx xxxx xxxx xxxx */ { 0xff100000u, 0xf8000000u, GT_THUMB_I_INVALID },

	/* ---- load single: 1111 100s uzz1; s = signed, zz = size ---- */
	/* size 3, and a signed word, are unallocated */
	/* 1111 100x x111 xxxx xxxx xxxx xxxx xxxx */ { 0xfe700000u, 0xf8700000u, GT_THUMB_I_INVALID },
	/* 1111 1001 x101 xxxx xxxx xxxx xxxx xxxx */ { 0xff700000u, 0xf9500000u, GT_THUMB_I_INVALID },
	/* ldrb */
	/* 1111 1000 x001 1111 xxxx xxxx xxxx xxxx */ { 0xff7f0000u, 0xf81f0000u, GT_THUMB_I_LDRB_LIT_W },
	/* 1111 1000 1001 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8900000u, GT_THUMB_I_LDRB_IMM12_W },
	/* 1111 1000 0001 xxxx xxxx 10x0 xxxx xxxx */ { 0xfff00d00u, 0xf8100800u, GT_THUMB_I_INVALID },
	/* 1111 1000 0001 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf8100800u, GT_THUMB_I_LDRB_IMM8_W },
	/* 1111 1000 0001 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf8100000u, GT_THUMB_I_LDRB_REG_W },
	/* 1111 1000 0001 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8100000u, GT_THUMB_I_INVALID },
	/* ldrsb */
	/* 1111 1001 x001 1111 xxxx xxxx xxxx xxxx */ { 0xff7f0000u, 0xf91f0000u, GT_THUMB_I_LDRSB_LIT_W },
	/* 1111 1001 1001 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf9900000u, GT_THUMB_I_LDRSB_IMM12_W },
	/* 1111 1001 0001 xxxx xxxx 10x0 xxxx xxxx */ { 0xfff00d00u, 0xf9100800u, GT_THUMB_I_INVALID },
	/* 1111 1001 0001 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf9100800u, GT_THUMB_I_LDRSB_IMM8_W },
	/* 1111 1001 0001 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf9100000u, GT_THUMB_I_LDRSB_REG_W },
	/* 1111 1001 0001 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf9100000u, GT_THUMB_I_INVALID },
	/* ldrh */
	/* 1111 1000 x011 1111 xxxx xxxx xxxx xxxx */ { 0xff7f0000u, 0xf83f0000u, GT_THUMB_I_LDRH_LIT_W },
	/* 1111 1000 1011 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8b00000u, GT_THUMB_I_LDRH_IMM12_W },
	/* 1111 1000 0011 xxxx xxxx 10x0 xxxx xxxx */ { 0xfff00d00u, 0xf8300800u, GT_THUMB_I_INVALID },
	/* 1111 1000 0011 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf8300800u, GT_THUMB_I_LDRH_IMM8_W },
	/* 1111 1000 0011 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf8300000u, GT_THUMB_I_LDRH_REG_W },
	/* 1111 1000 0011 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8300000u, GT_THUMB_I_INVALID },
	/* ldrsh */
	/* 1111 1001 x011 1111 xxxx xxxx xxxx xxxx */ { 0xff7f0000u, 0xf93f0000u, GT_THUMB_I_LDRSH_LIT_W },
	/* 1111 1001 1011 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf9b00000u, GT_THUMB_I_LDRSH_IMM12_W },
	/* 1111 1001 0011 xxxx xxxx 10x0 xxxx xxxx */ { 0xfff00d00u, 0xf9300800u, GT_THUMB_I_INVALID },
	/* 1111 1001 0011 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf9300800u, GT_THUMB_I_LDRSH_IMM8_W },
	/* 1111 1001 0011 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf9300000u, GT_THUMB_I_LDRSH_REG_W },
	/* 1111 1001 0011 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf9300000u, GT_THUMB_I_INVALID },
	/* ldr */
	/* 1111 1000 x101 1111 xxxx xxxx xxxx xxxx */ { 0xff7f0000u, 0xf85f0000u, GT_THUMB_I_LDR_LIT_W },
	/* 1111 1000 1101 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8d00000u, GT_THUMB_I_LDR_IMM12_W },
	/* 1111 1000 0101 1101 xxxx 1011 0000 0100 */ { 0xffff0fffu, 0xf85d0b04u, GT_THUMB_I_POP_REG_W },
	/* 1111 1000 0101 xxxx xxxx 10x0 xxxx xxxx */ { 0xfff00d00u, 0xf8500800u, GT_THUMB_I_INVALID },
	/* 1111 1000 0101 xxxx xxxx 1xxx xxxx xxxx */ { 0xfff00800u, 0xf8500800u, GT_THUMB_I_LDR_IMM8_W },
	/* 1111 1000 0101 xxxx xxxx 0000 00xx xxxx */ { 0xfff00fc0u, 0xf8500000u, GT_THUMB_I_LDR_REG_W },
	/* 1111 1000 0101 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf8500000u, GT_THUMB_I_INVALID },

	/* ---- data processing, register: 1111 1010 ---- */
	/* second halfword 1111 dddd oooo mmmm; anything else is unallocated */
	/* 1111 1010 000x xxxx 1111 xxxx 0000 xxxx */ { 0xffe0f0f0u, 0xfa00f000u, GT_THUMB_I_LSL_REG_W },
	/* 1111 1010 001x xxxx 1111 xxxx 0000 xxxx */ { 0xffe0f0f0u, 0xfa20f000u, GT_THUMB_I_LSR_REG_W },
	/* 1111 1010 010x xxxx 1111 xxxx 0000 xxxx */ { 0xffe0f0f0u, 0xfa40f000u, GT_THUMB_I_ASR_REG_W },
	/* 1111 1010 011x xxxx 1111 xxxx 0000 xxxx */ { 0xffe0f0f0u, 0xfa60f000u, GT_THUMB_I_ROR_REG_W },
	/* 1111 1010 0000 1111 1111 xxxx 1xxx xxxx */ { 0xfffff080u, 0xfa0ff080u, GT_THUMB_I_SXTH_W },
	/* 1111 1010 0000 xxxx 1111 xxxx 1xxx xxxx */ { 0xfff0f080u, 0xfa00f080u, GT_THUMB_I_SXTAH },
	/* 1111 1010 0001 1111 1111 xxxx 1xxx xxxx */ { 0xfffff080u, 0xfa1ff080u, GT_THUMB_I_UXTH_W },
	/* 1111 1010 0001 xxxx 1111 xxxx 1xxx xxxx */ { 0xfff0f080u, 0xfa10f080u, GT_THUMB_I_UXTAH },
	/* 1111 1010 0010 1111 1111 xxxx 1xxx xxxx */ { 0xfffff080u, 0xfa2ff080u, GT_THUMB_I_SXTB16 },
	/* 1111 1010 0010 xxxx 1111 xxxx 1xxx xxxx */ { 0xfff0f080u, 0xfa20f080u, GT_THUMB_I_SXTAB16 },
	/* 1111 1010 0011 1111 1111 xxxx 1xxx xxxx */ { 0xfffff080u, 0xfa3ff080u, GT_THUMB_I_UXTB16 },
	/* 1111 1010 0011 xxxx 1111 xxxx 1xxx xxxx */ { 0xfff0f080u, 0xfa30f080u, GT_THUMB_I_UXTAB16 },
	/* 1111 1010 0100 1111 1111 xxxx 1xxx xxxx */ { 0xfffff080u, 0xfa4ff080u, GT_THUMB_I_SXTB_W },
	/* 1111 1010 0100 xxxx 1111 xxxx 1xxx xxxx */ { 0xfff0f080u, 0xfa40f080u, GT_THUMB_I_SXTAB },
	/* 1111 1010 0101 1111 1111 xxxx 1xxx xxxx */ { 0xfffff080u, 0xfa5ff080u, GT_THUMB_I_UXTB_W },
	/* 1111 1010 0101 xxxx 1111 xxxx 1xxx xxxx */ { 0xfff0f080u, 0xfa50f080u, GT_THUMB_I_UXTAB },
	/* 1111 1010 0xxx xxxx xxxx xxxx xxxx xxxx */ { 0xff800000u, 0xfa000000u, GT_THUMB_I_INVALID },
	/* parallel add and subtract: op1 sub-opcodes 3 and 7, and prefix 3, are unallocated */
	/* 1111 1010 1x11 xxxx 1111 xxxx 0xxx xxxx */ { 0xffb0f080u, 0xfab0f000u, GT_THUMB_I_INVALID },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0x11 xxxx */ { 0xff80f0b0u, 0xfa80f030u, GT_THUMB_I_INVALID },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0000 xxxx */ { 0xff80f0f0u, 0xfa80f000u, GT_THUMB_I_PAS_S },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0001 xxxx */ { 0xff80f0f0u, 0xfa80f010u, GT_THUMB_I_PAS_Q },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0010 xxxx */ { 0xff80f0f0u, 0xfa80f020u, GT_THUMB_I_PAS_SH },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0100 xxxx */ { 0xff80f0f0u, 0xfa80f040u, GT_THUMB_I_PAS_U },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0101 xxxx */ { 0xff80f0f0u, 0xfa80f050u, GT_THUMB_I_PAS_UQ },
	/* 1111 1010 1xxx xxxx 1111 xxxx 0110 xxxx */ { 0xff80f0f0u, 0xfa80f060u, GT_THUMB_I_PAS_UH },
	/* miscellaneous operations */
	/* 1111 1010 1000 xxxx 1111 xxxx 1000 xxxx */ { 0xfff0f0f0u, 0xfa80f080u, GT_THUMB_I_QADD },
	/* 1111 1010 1000 xxxx 1111 xxxx 1001 xxxx */ { 0xfff0f0f0u, 0xfa80f090u, GT_THUMB_I_QDADD },
	/* 1111 1010 1000 xxxx 1111 xxxx 1010 xxxx */ { 0xfff0f0f0u, 0xfa80f0a0u, GT_THUMB_I_QSUB },
	/* 1111 1010 1000 xxxx 1111 xxxx 1011 xxxx */ { 0xfff0f0f0u, 0xfa80f0b0u, GT_THUMB_I_QDSUB },
	/* 1111 1010 1001 xxxx 1111 xxxx 1000 xxxx */ { 0xfff0f0f0u, 0xfa90f080u, GT_THUMB_I_REV_W },
	/* 1111 1010 1001 xxxx 1111 xxxx 1001 xxxx */ { 0xfff0f0f0u, 0xfa90f090u, GT_THUMB_I_REV16_W },
	/* 1111 1010 1001 xxxx 1111 xxxx 1010 xxxx */ { 0xfff0f0f0u, 0xfa90f0a0u, GT_THUMB_I_RBIT },
	/* 1111 1010 1001 xxxx 1111 xxxx 1011 xxxx */ { 0xfff0f0f0u, 0xfa90f0b0u, GT_THUMB_I_REVSH_W },
	/* 1111 1010 1010 xxxx 1111 xxxx 1000 xxxx */ { 0xfff0f0f0u, 0xfaa0f080u, GT_THUMB_I_SEL },
	/* 1111 1010 1011 xxxx 1111 xxxx 1000 xxxx */ { 0xfff0f0f0u, 0xfab0f080u, GT_THUMB_I_CLZ },
	/* 1111 1010 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xff000000u, 0xfa000000u, GT_THUMB_I_INVALID },

	/* ---- multiplies: 1111 1011 0 ---- */
	/* 1111 1011 0000 xxxx 1111 xxxx xx00 xxxx */ { 0xfff0f030u, 0xfb00f000u, GT_THUMB_I_MUL_W },
	/* 1111 1011 0000 xxxx xxxx xxxx xx00 xxxx */ { 0xfff00030u, 0xfb000000u, GT_THUMB_I_MLA },
	/* 1111 1011 0000 xxxx xxxx xxxx xx01 xxxx */ { 0xfff00030u, 0xfb000010u, GT_THUMB_I_MLS },
	/* 1111 1011 0000 xxxx xxxx xxxx xx1x xxxx */ { 0xfff00020u, 0xfb000020u, GT_THUMB_I_INVALID },
	/* 1111 1011 0001 xxxx 1111 xxxx xxxx xxxx */ { 0xfff0f000u, 0xfb10f000u, GT_THUMB_I_SMULXY },
	/* 1111 1011 0001 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xfb100000u, GT_THUMB_I_SMLAXY },
	/* 1111 1011 0010 xxxx 1111 xxxx xx0x xxxx */ { 0xfff0f020u, 0xfb20f000u, GT_THUMB_I_SMUAD },
	/* 1111 1011 0010 xxxx xxxx xxxx xx0x xxxx */ { 0xfff00020u, 0xfb200000u, GT_THUMB_I_SMLAD },
	/* 1111 1011 0011 xxxx 1111 xxxx xx0x xxxx */ { 0xfff0f020u, 0xfb30f000u, GT_THUMB_I_SMULWY },
	/* 1111 1011 0011 xxxx xxxx xxxx xx0x xxxx */ { 0xfff00020u, 0xfb300000u, GT_THUMB_I_SMLAWY },
	/* 1111 1011 0100 xxxx 1111 xxxx xx0x xxxx */ { 0xfff0f020u, 0xfb40f000u, GT_THUMB_I_SMUSD },
	/* 1111 1011 0100 xxxx xxxx xxxx xx0x xxxx */ { 0xfff00020u, 0xfb400000u, GT_THUMB_I_SMLSD },
	/* 1111 1011 0101 xxxx 1111 xxxx xx0x xxxx */ { 0xfff0f020u, 0xfb50f000u, GT_THUMB_I_SMMUL },
	/* 1111 1011 0101 xxxx xxxx xxxx xx0x xxxx */ { 0xfff00020u, 0xfb500000u, GT_THUMB_I_SMMLA },
	/* 1111 1011 0110 xxxx xxxx xxxx xx0x xxxx */ { 0xfff00020u, 0xfb600000u, GT_THUMB_I_SMMLS },
	/* 1111 1011 0111 xxxx 1111 xxxx xx00 xxxx */ { 0xfff0f030u, 0xfb70f000u, GT_THUMB_I_USAD8 },
	/* 1111 1011 0111 xxxx xxxx xxxx xx00 xxxx */ { 0xfff00030u, 0xfb700000u, GT_THUMB_I_USADA8 },
	/* 1111 1011 0xxx xxxx xxxx xxxx xxxx xxxx */ { 0xff800000u, 0xfb000000u, GT_THUMB_I_INVALID },

	/* ---- long multiplies and divide: 1111 1011 1 ---- */
	/* 1111 1011 1001 xxxx 1111 xxxx 1111 xxxx */ { 0xfff0f0f0u, 0xfb90f0f0u, GT_THUMB_I_SDIV },
	/* 1111 1011 1011 xxxx 1111 xxxx 1111 xxxx */ { 0xfff0f0f0u, 0xfbb0f0f0u, GT_THUMB_I_UDIV },
	/* 1111 1011 10x1 xxxx xxxx xxxx xxxx xxxx */ { 0xffd00000u, 0xfb900000u, GT_THUMB_I_INVALID },
	/* 1111 1011 1000 xxxx xxxx xxxx 0000 xxxx */ { 0xfff000f0u, 0xfb800000u, GT_THUMB_I_SMULL },
	/* 1111 1011 1010 xxxx xxxx xxxx 0000 xxxx */ { 0xfff000f0u, 0xfba00000u, GT_THUMB_I_UMULL },
	/* 1111 1011 1100 xxxx xxxx xxxx 0000 xxxx */ { 0xfff000f0u, 0xfbc00000u, GT_THUMB_I_SMLAL },
	/* 1111 1011 1100 xxxx xxxx xxxx 10xx xxxx */ { 0xfff000c0u, 0xfbc00080u, GT_THUMB_I_SMLALXY },
	/* 1111 1011 1100 xxxx xxxx xxxx 110x xxxx */ { 0xfff000e0u, 0xfbc000c0u, GT_THUMB_I_SMLALD },
	/* 1111 1011 1101 xxxx xxxx xxxx 110x xxxx */ { 0xfff000e0u, 0xfbd000c0u, GT_THUMB_I_SMLSLD },
	/* 1111 1011 1110 xxxx xxxx xxxx 0000 xxxx */ { 0xfff000f0u, 0xfbe00000u, GT_THUMB_I_UMLAL },
	/* 1111 1011 1110 xxxx xxxx xxxx 0110 xxxx */ { 0xfff000f0u, 0xfbe00060u, GT_THUMB_I_UMAAL },
	/* 1111 1011 1xxx xxxx xxxx xxxx xxxx xxxx */ { 0xff800000u, 0xfb800000u, GT_THUMB_I_INVALID },
};
const unsigned gt_thumb_src_wide_n = sizeof gt_thumb_src_wide / sizeof gt_thumb_src_wide[0];
