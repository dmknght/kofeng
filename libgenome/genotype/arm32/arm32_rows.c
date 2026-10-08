/*
 * arm32_rows.c - the ARM state (A32) instruction encodings: THE CANONICAL TABLE.
 *
 * Hand-maintained data. Each row is {mask, value, name}; the pattern it was
 * written from is the comment on the same line, in the ARM ARM's style: bits
 * 31..0 in groups of four, 0 and 1 fixed, any other character a field that the
 * row says nothing about. ROWS ARE IN PRIORITY ORDER - the first one that
 * matches wins - so a specific encoding goes before the general one it is cut
 * out of. Condition 15 (cccc = 1111 in the patterns) is the unconditional space
 * and its rows are their own table.
 *
 * The first-level index and the per-key row lists the decoder runs on are
 * DERIVED from these rows by code (arm32_index.c), the first time a decode needs
 * them; nothing else is to be kept in step. tests/unit/genotype_arm32.c fails if
 * a row is shadowed by an earlier one, which is the mistake a priority list makes
 * silently.
 *
 * WHAT A NAME MEANS. An instruction as the architecture names it, at the
 * granularity of an ENCODING: ADD_IMM, ADD_REG and ADD_RSR (register-shifted
 * register) are three names because their operands are built three ways. Where
 * the architecture gives one mnemonic several encodings that differ only in a
 * field (LDM with P and U; the parallel add/subtract family's op field) the
 * field is read from the word. INVALID is an unallocated encoding of the space
 * whose validity this decoder checks (the integer space); the coprocessor, VFP
 * and Advanced SIMD spaces are NOT validity-checked and come out as the one
 * name of the group (CDP MCR MRC LDC STC MCRR MRRC VLDST ASIMD_DP).
 *
 * THE DECISIONS HERE ARE THOSE OF THE DECODER THIS REPLACED: every UNDEFINED and
 * every valid-but-unmodelled answer is what libgenome/celllysis/decode_arm32.c
 * said before the split (frozen as the equivalence reference).
 */
#include "arm32_ids.h"
#include "arm32_int.h"

const struct gt_arm32_row gt_arm32_src_cond[] = {
	/* ======================= conditional space: bits 27..25 = 000 ============= */

	/* ---- multiplies: bits 7..4 = 1001, bit 24 = 0 ---- */
	/* cccc 0000 000x xxxx xxxx xxxx 1001 xxxx */ { 0x0fe000f0u, 0x00000090u, GT_ARM32_I_MUL },
	/* cccc 0000 001x xxxx xxxx xxxx 1001 xxxx */ { 0x0fe000f0u, 0x00200090u, GT_ARM32_I_MLA },
	/* cccc 0000 0100 xxxx xxxx xxxx 1001 xxxx */ { 0x0ff000f0u, 0x00400090u, GT_ARM32_I_UMAAL },
	/* cccc 0000 0101 xxxx xxxx xxxx 1001 xxxx */ { 0x0ff000f0u, 0x00500090u, GT_ARM32_I_INVALID },
	/* cccc 0000 0110 xxxx xxxx xxxx 1001 xxxx */ { 0x0ff000f0u, 0x00600090u, GT_ARM32_I_MLS },
	/* cccc 0000 0111 xxxx xxxx xxxx 1001 xxxx */ { 0x0ff000f0u, 0x00700090u, GT_ARM32_I_INVALID },
	/* cccc 0000 100x xxxx xxxx xxxx 1001 xxxx */ { 0x0fe000f0u, 0x00800090u, GT_ARM32_I_UMULL },
	/* cccc 0000 101x xxxx xxxx xxxx 1001 xxxx */ { 0x0fe000f0u, 0x00a00090u, GT_ARM32_I_UMLAL },
	/* cccc 0000 110x xxxx xxxx xxxx 1001 xxxx */ { 0x0fe000f0u, 0x00c00090u, GT_ARM32_I_SMULL },
	/* cccc 0000 111x xxxx xxxx xxxx 1001 xxxx */ { 0x0fe000f0u, 0x00e00090u, GT_ARM32_I_SMLAL },

	/* ---- swap, exclusive and acquire/release: bits 7..4 = 1001, bit 24 = 1 ---- */
	/* cccc 0001 0000 xxxx xxxx xxxx 1001 xxxx */ { 0x0ff000f0u, 0x01000090u, GT_ARM32_I_SWP },
	/* cccc 0001 0100 xxxx xxxx xxxx 1001 xxxx */ { 0x0ff000f0u, 0x01400090u, GT_ARM32_I_SWPB },
	/* cccc 0001 0xxx xxxx xxxx xxxx 1001 xxxx */ { 0x0f8000f0u, 0x01000090u, GT_ARM32_I_INVALID },
	/* cccc 0001 1000 xxxx xxxx 1100 1001 xxxx */ { 0x0ff00ff0u, 0x01800c90u, GT_ARM32_I_STL },
	/* cccc 0001 1001 xxxx xxxx 1100 1001 xxxx */ { 0x0ff00ff0u, 0x01900c90u, GT_ARM32_I_LDA },
	/* cccc 0001 1100 xxxx xxxx 1100 1001 xxxx */ { 0x0ff00ff0u, 0x01c00c90u, GT_ARM32_I_STLB },
	/* cccc 0001 1101 xxxx xxxx 1100 1001 xxxx */ { 0x0ff00ff0u, 0x01d00c90u, GT_ARM32_I_LDAB },
	/* cccc 0001 1110 xxxx xxxx 1100 1001 xxxx */ { 0x0ff00ff0u, 0x01e00c90u, GT_ARM32_I_STLH },
	/* cccc 0001 1111 xxxx xxxx 1100 1001 xxxx */ { 0x0ff00ff0u, 0x01f00c90u, GT_ARM32_I_LDAH },
	/* cccc 0001 1000 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01800f90u, GT_ARM32_I_STREX },
	/* cccc 0001 1001 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01900f90u, GT_ARM32_I_LDREX },
	/* cccc 0001 1010 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01a00f90u, GT_ARM32_I_STREXD },
	/* cccc 0001 1011 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01b00f90u, GT_ARM32_I_LDREXD },
	/* cccc 0001 1100 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01c00f90u, GT_ARM32_I_STREXB },
	/* cccc 0001 1101 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01d00f90u, GT_ARM32_I_LDREXB },
	/* cccc 0001 1110 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01e00f90u, GT_ARM32_I_STREXH },
	/* cccc 0001 1111 xxxx xxxx 1111 1001 xxxx */ { 0x0ff00ff0u, 0x01f00f90u, GT_ARM32_I_LDREXH },
	/* cccc 0001 1000 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01800e90u, GT_ARM32_I_STLEX },
	/* cccc 0001 1001 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01900e90u, GT_ARM32_I_LDAEX },
	/* cccc 0001 1010 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01a00e90u, GT_ARM32_I_STLEXD },
	/* cccc 0001 1011 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01b00e90u, GT_ARM32_I_LDAEXD },
	/* cccc 0001 1100 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01c00e90u, GT_ARM32_I_STLEXB },
	/* cccc 0001 1101 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01d00e90u, GT_ARM32_I_LDAEXB },
	/* cccc 0001 1110 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01e00e90u, GT_ARM32_I_STLEXH },
	/* cccc 0001 1111 xxxx xxxx 1110 1001 xxxx */ { 0x0ff00ff0u, 0x01f00e90u, GT_ARM32_I_LDAEXH },
	/* cccc 0001 1xxx xxxx xxxx xxxx 1001 xxxx */ { 0x0f8000f0u, 0x01800090u, GT_ARM32_I_INVALID },

	/* ---- halfword and doubleword transfers: bits 7..4 = 1011, 1101, 1111 ---- */
	/* LDRD and STRD have no unprivileged form (P = 0, W = 1). */
	/* cccc 0000 xx10 xxxx xxxx xxxx 11x1 xxxx */ { 0x0f3000d0u, 0x002000d0u, GT_ARM32_I_INVALID },
	/* cccc 000x x1x0 xxxx xxxx xxxx 1011 xxxx */ { 0x0e5000f0u, 0x004000b0u, GT_ARM32_I_STRH_IMM },
	/* cccc 000x x0x0 xxxx xxxx xxxx 1011 xxxx */ { 0x0e5000f0u, 0x000000b0u, GT_ARM32_I_STRH_REG },
	/* cccc 000x x1x1 xxxx xxxx xxxx 1011 xxxx */ { 0x0e5000f0u, 0x005000b0u, GT_ARM32_I_LDRH_IMM },
	/* cccc 000x x0x1 xxxx xxxx xxxx 1011 xxxx */ { 0x0e5000f0u, 0x001000b0u, GT_ARM32_I_LDRH_REG },
	/* cccc 000x x1x0 xxxx xxxx xxxx 1101 xxxx */ { 0x0e5000f0u, 0x004000d0u, GT_ARM32_I_LDRD_IMM },
	/* cccc 000x x0x0 xxxx xxxx xxxx 1101 xxxx */ { 0x0e5000f0u, 0x000000d0u, GT_ARM32_I_LDRD_REG },
	/* cccc 000x x1x0 xxxx xxxx xxxx 1111 xxxx */ { 0x0e5000f0u, 0x004000f0u, GT_ARM32_I_STRD_IMM },
	/* cccc 000x x0x0 xxxx xxxx xxxx 1111 xxxx */ { 0x0e5000f0u, 0x000000f0u, GT_ARM32_I_STRD_REG },
	/* cccc 000x x1x1 xxxx xxxx xxxx 1101 xxxx */ { 0x0e5000f0u, 0x005000d0u, GT_ARM32_I_LDRSB_IMM },
	/* cccc 000x x0x1 xxxx xxxx xxxx 1101 xxxx */ { 0x0e5000f0u, 0x001000d0u, GT_ARM32_I_LDRSB_REG },
	/* cccc 000x x1x1 xxxx xxxx xxxx 1111 xxxx */ { 0x0e5000f0u, 0x005000f0u, GT_ARM32_I_LDRSH_IMM },
	/* cccc 000x x0x1 xxxx xxxx xxxx 1111 xxxx */ { 0x0e5000f0u, 0x001000f0u, GT_ARM32_I_LDRSH_REG },

	/* ---- the miscellaneous space: bit 24 = 1, bit 23 = 0, bit 20 = 0 ---- */
	/* halfword multiplies (bit 7 = 1, bit 4 = 0) */
	/* cccc 0001 0000 xxxx xxxx xxxx 1xx0 xxxx */ { 0x0ff00090u, 0x01000080u, GT_ARM32_I_SMLAXY },
	/* cccc 0001 0010 xxxx xxxx xxxx 1x00 xxxx */ { 0x0ff000b0u, 0x01200080u, GT_ARM32_I_SMLAWY },
	/* cccc 0001 0010 xxxx xxxx xxxx 1x10 xxxx */ { 0x0ff000b0u, 0x012000a0u, GT_ARM32_I_SMULWY },
	/* cccc 0001 0100 xxxx xxxx xxxx 1xx0 xxxx */ { 0x0ff00090u, 0x01400080u, GT_ARM32_I_SMLALXY },
	/* cccc 0001 0110 xxxx xxxx xxxx 1xx0 xxxx */ { 0x0ff00090u, 0x01600080u, GT_ARM32_I_SMULXY },
	/* bit 7 = 0: bits 22..21 are `op`, bits 6..4 `op2` */
	/* cccc 0001 0x00 xxxx xxxx xxxx 0000 xxxx */ { 0x0fb000f0u, 0x01000000u, GT_ARM32_I_MRS },
	/* cccc 0001 0x10 xxxx xxxx xxxx 0000 xxxx */ { 0x0fb000f0u, 0x01200000u, GT_ARM32_I_MSR_REG },
	/* cccc 0001 0010 xxxx xxxx xxxx 0001 xxxx */ { 0x0ff000f0u, 0x01200010u, GT_ARM32_I_BX },
	/* cccc 0001 0110 xxxx xxxx xxxx 0001 xxxx */ { 0x0ff000f0u, 0x01600010u, GT_ARM32_I_CLZ },
	/* cccc 0001 0xx0 xxxx xxxx xxxx 0001 xxxx */ { 0x0f9000f0u, 0x01000010u, GT_ARM32_I_INVALID },
	/* cccc 0001 0010 xxxx xxxx xxxx 0010 xxxx */ { 0x0ff000f0u, 0x01200020u, GT_ARM32_I_BXJ },
	/* cccc 0001 0xx0 xxxx xxxx xxxx 0010 xxxx */ { 0x0f9000f0u, 0x01000020u, GT_ARM32_I_INVALID },
	/* cccc 0001 0010 xxxx xxxx xxxx 0011 xxxx */ { 0x0ff000f0u, 0x01200030u, GT_ARM32_I_BLX_REG },
	/* cccc 0001 0xx0 xxxx xxxx xxxx 0011 xxxx */ { 0x0f9000f0u, 0x01000030u, GT_ARM32_I_INVALID },
	/* crc32 is ARMv8's optional CRC extension; bits 11, 10 and 8 are zero in it */
	/* cccc 0001 0110 xxxx xxxx xxxx 0100 xxxx */ { 0x0ff000f0u, 0x01600040u, GT_ARM32_I_INVALID },
	/* cccc 0001 0xx0 xxxx xxxx 0000 0100 xxxx */ { 0x0f900ff0u, 0x01000040u, GT_ARM32_I_CRC32 },
	/* cccc 0001 0xx0 xxxx xxxx 0010 0100 xxxx */ { 0x0f900ff0u, 0x01000240u, GT_ARM32_I_CRC32C },
	/* cccc 0001 0xx0 xxxx xxxx xxxx 0100 xxxx */ { 0x0f9000f0u, 0x01000040u, GT_ARM32_I_INVALID },
	/* cccc 0001 0000 xxxx xxxx xxxx 0101 xxxx */ { 0x0ff000f0u, 0x01000050u, GT_ARM32_I_QADD },
	/* cccc 0001 0010 xxxx xxxx xxxx 0101 xxxx */ { 0x0ff000f0u, 0x01200050u, GT_ARM32_I_QSUB },
	/* cccc 0001 0100 xxxx xxxx xxxx 0101 xxxx */ { 0x0ff000f0u, 0x01400050u, GT_ARM32_I_QDADD },
	/* cccc 0001 0110 xxxx xxxx xxxx 0101 xxxx */ { 0x0ff000f0u, 0x01600050u, GT_ARM32_I_QDSUB },
	/* cccc 0001 0110 xxxx xxxx xxxx 0110 xxxx */ { 0x0ff000f0u, 0x01600060u, GT_ARM32_I_ERET },
	/* cccc 0001 0xx0 xxxx xxxx xxxx 0110 xxxx */ { 0x0f9000f0u, 0x01000060u, GT_ARM32_I_INVALID },
	/* cccc 0001 0000 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x01000070u, GT_ARM32_I_INVALID },
	/* cccc 0001 0010 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x01200070u, GT_ARM32_I_BKPT },
	/* cccc 0001 0100 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x01400070u, GT_ARM32_I_HVC },
	/* cccc 0001 0110 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x01600070u, GT_ARM32_I_SMC },

	/* ---- data processing, register and register-shifted register ---- */
	/* cccc 0000 000x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00000000u, GT_ARM32_I_AND_REG },
	/* cccc 0000 000x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00000010u, GT_ARM32_I_AND_RSR },
	/* cccc 0000 001x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00200000u, GT_ARM32_I_EOR_REG },
	/* cccc 0000 001x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00200010u, GT_ARM32_I_EOR_RSR },
	/* cccc 0000 010x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00400000u, GT_ARM32_I_SUB_REG },
	/* cccc 0000 010x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00400010u, GT_ARM32_I_SUB_RSR },
	/* cccc 0000 011x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00600000u, GT_ARM32_I_RSB_REG },
	/* cccc 0000 011x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00600010u, GT_ARM32_I_RSB_RSR },
	/* cccc 0000 100x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00800000u, GT_ARM32_I_ADD_REG },
	/* cccc 0000 100x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00800010u, GT_ARM32_I_ADD_RSR },
	/* cccc 0000 101x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00a00000u, GT_ARM32_I_ADC_REG },
	/* cccc 0000 101x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00a00010u, GT_ARM32_I_ADC_RSR },
	/* cccc 0000 110x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00c00000u, GT_ARM32_I_SBC_REG },
	/* cccc 0000 110x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00c00010u, GT_ARM32_I_SBC_RSR },
	/* cccc 0000 111x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x00e00000u, GT_ARM32_I_RSC_REG },
	/* cccc 0000 111x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x00e00010u, GT_ARM32_I_RSC_RSR },
	/* cccc 0001 000x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01000000u, GT_ARM32_I_TST_REG },
	/* cccc 0001 000x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01000010u, GT_ARM32_I_TST_RSR },
	/* cccc 0001 001x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01200000u, GT_ARM32_I_TEQ_REG },
	/* cccc 0001 001x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01200010u, GT_ARM32_I_TEQ_RSR },
	/* cccc 0001 010x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01400000u, GT_ARM32_I_CMP_REG },
	/* cccc 0001 010x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01400010u, GT_ARM32_I_CMP_RSR },
	/* cccc 0001 011x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01600000u, GT_ARM32_I_CMN_REG },
	/* cccc 0001 011x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01600010u, GT_ARM32_I_CMN_RSR },
	/* cccc 0001 100x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01800000u, GT_ARM32_I_ORR_REG },
	/* cccc 0001 100x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01800010u, GT_ARM32_I_ORR_RSR },
	/* cccc 0001 101x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01a00000u, GT_ARM32_I_MOV_REG },
	/* cccc 0001 101x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01a00010u, GT_ARM32_I_MOV_RSR },
	/* cccc 0001 110x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01c00000u, GT_ARM32_I_BIC_REG },
	/* cccc 0001 110x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01c00010u, GT_ARM32_I_BIC_RSR },
	/* cccc 0001 111x xxxx xxxx xxxx xxx0 xxxx */ { 0x0fe00010u, 0x01e00000u, GT_ARM32_I_MVN_REG },
	/* cccc 0001 111x xxxx xxxx xxxx 0xx1 xxxx */ { 0x0fe00090u, 0x01e00010u, GT_ARM32_I_MVN_RSR },

	/* ======================= conditional space: bits 27..25 = 001 ============= */

	/* cccc 0011 0000 xxxx xxxx xxxx xxxx xxxx */ { 0x0ff00000u, 0x03000000u, GT_ARM32_I_MOVW },
	/* cccc 0011 0100 xxxx xxxx xxxx xxxx xxxx */ { 0x0ff00000u, 0x03400000u, GT_ARM32_I_MOVT },
	/* hints; the unallocated ones execute as nop */
	/* cccc 0011 0010 0000 xxxx xxxx xxxx xxxx */ { 0x0fff0000u, 0x03200000u, GT_ARM32_I_HINT },
	/* cccc 0011 0x10 xxxx xxxx xxxx xxxx xxxx */ { 0x0fb00000u, 0x03200000u, GT_ARM32_I_MSR_IMM },
	/* cccc 0010 000x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02000000u, GT_ARM32_I_AND_IMM },
	/* cccc 0010 001x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02200000u, GT_ARM32_I_EOR_IMM },
	/* cccc 0010 010x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02400000u, GT_ARM32_I_SUB_IMM },
	/* cccc 0010 011x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02600000u, GT_ARM32_I_RSB_IMM },
	/* cccc 0010 100x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02800000u, GT_ARM32_I_ADD_IMM },
	/* cccc 0010 101x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02a00000u, GT_ARM32_I_ADC_IMM },
	/* cccc 0010 110x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02c00000u, GT_ARM32_I_SBC_IMM },
	/* cccc 0010 111x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x02e00000u, GT_ARM32_I_RSC_IMM },
	/* cccc 0011 000x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03000000u, GT_ARM32_I_TST_IMM },
	/* cccc 0011 001x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03200000u, GT_ARM32_I_TEQ_IMM },
	/* cccc 0011 010x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03400000u, GT_ARM32_I_CMP_IMM },
	/* cccc 0011 011x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03600000u, GT_ARM32_I_CMN_IMM },
	/* cccc 0011 100x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03800000u, GT_ARM32_I_ORR_IMM },
	/* cccc 0011 101x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03a00000u, GT_ARM32_I_MOV_IMM },
	/* cccc 0011 110x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03c00000u, GT_ARM32_I_BIC_IMM },
	/* cccc 0011 111x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x03e00000u, GT_ARM32_I_MVN_IMM },

	/* ======================= conditional space: bits 27..25 = 010 ============= */

	/* str rt,[sp,#-4]! and ldr rt,[sp],#4: what the architecture names PUSH and POP */
	/* cccc 0101 0010 1101 xxxx 0000 0000 0100 */ { 0x0fff0fffu, 0x052d0004u, GT_ARM32_I_PUSH_1 },
	/* cccc 0100 1001 1101 xxxx 0000 0000 0100 */ { 0x0fff0fffu, 0x049d0004u, GT_ARM32_I_POP_1 },
	/* cccc 010x x0x0 xxxx xxxx xxxx xxxx xxxx */ { 0x0e500000u, 0x04000000u, GT_ARM32_I_STR_IMM },
	/* cccc 010x x0x1 xxxx xxxx xxxx xxxx xxxx */ { 0x0e500000u, 0x04100000u, GT_ARM32_I_LDR_IMM },
	/* cccc 010x x1x0 xxxx xxxx xxxx xxxx xxxx */ { 0x0e500000u, 0x04400000u, GT_ARM32_I_STRB_IMM },
	/* cccc 010x x1x1 xxxx xxxx xxxx xxxx xxxx */ { 0x0e500000u, 0x04500000u, GT_ARM32_I_LDRB_IMM },

	/* ======================= conditional space: bits 27..25 = 011 ============= */

	/* ---- media instructions (bit 4 = 1). bits 24..23 select a group, 22..20 are op1, 7..5 op2 ---- */
	/* parallel add and subtract */
	/* cccc 0110 0000 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06000010u, GT_ARM32_I_INVALID },
	/* cccc 0110 0100 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06400010u, GT_ARM32_I_INVALID },
	/* cccc 0110 0xxx xxxx xxxx xxxx 1011 xxxx */ { 0x0f8000f0u, 0x060000b0u, GT_ARM32_I_INVALID },
	/* cccc 0110 0xxx xxxx xxxx xxxx 1101 xxxx */ { 0x0f8000f0u, 0x060000d0u, GT_ARM32_I_INVALID },
	/* cccc 0110 0001 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06100010u, GT_ARM32_I_PAS_S },
	/* cccc 0110 0010 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06200010u, GT_ARM32_I_PAS_Q },
	/* cccc 0110 0011 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06300010u, GT_ARM32_I_PAS_SH },
	/* cccc 0110 0101 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06500010u, GT_ARM32_I_PAS_U },
	/* cccc 0110 0110 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06600010u, GT_ARM32_I_PAS_UQ },
	/* cccc 0110 0111 xxxx xxxx xxxx xxx1 xxxx */ { 0x0ff00010u, 0x06700010u, GT_ARM32_I_PAS_UH },
	/* pack, saturate, extend, select, reverse */
	/* cccc 0110 1000 xxxx xxxx xxxx x001 xxxx */ { 0x0ff00070u, 0x06800010u, GT_ARM32_I_PKHBT },
	/* cccc 0110 1000 xxxx xxxx xxxx x101 xxxx */ { 0x0ff00070u, 0x06800050u, GT_ARM32_I_PKHTB },
	/* cccc 0110 101x xxxx xxxx xxxx xx01 xxxx */ { 0x0fe00030u, 0x06a00010u, GT_ARM32_I_SSAT },
	/* cccc 0110 111x xxxx xxxx xxxx xx01 xxxx */ { 0x0fe00030u, 0x06e00010u, GT_ARM32_I_USAT },
	/* cccc 0110 1010 xxxx xxxx xxxx 0011 xxxx */ { 0x0ff000f0u, 0x06a00030u, GT_ARM32_I_SSAT16 },
	/* cccc 0110 1110 xxxx xxxx xxxx 0011 xxxx */ { 0x0ff000f0u, 0x06e00030u, GT_ARM32_I_USAT16 },
	/* cccc 0110 1000 xxxx xxxx xxxx 1011 xxxx */ { 0x0ff000f0u, 0x068000b0u, GT_ARM32_I_SEL },
	/* cccc 0110 1000 1111 xxxx xxxx 0111 xxxx */ { 0x0fff00f0u, 0x068f0070u, GT_ARM32_I_SXTB16 },
	/* cccc 0110 1000 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x06800070u, GT_ARM32_I_SXTAB16 },
	/* cccc 0110 1010 1111 xxxx xxxx 0111 xxxx */ { 0x0fff00f0u, 0x06af0070u, GT_ARM32_I_SXTB },
	/* cccc 0110 1010 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x06a00070u, GT_ARM32_I_SXTAB },
	/* cccc 0110 1011 1111 xxxx xxxx 0111 xxxx */ { 0x0fff00f0u, 0x06bf0070u, GT_ARM32_I_SXTH },
	/* cccc 0110 1011 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x06b00070u, GT_ARM32_I_SXTAH },
	/* cccc 0110 1100 1111 xxxx xxxx 0111 xxxx */ { 0x0fff00f0u, 0x06cf0070u, GT_ARM32_I_UXTB16 },
	/* cccc 0110 1100 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x06c00070u, GT_ARM32_I_UXTAB16 },
	/* cccc 0110 1110 1111 xxxx xxxx 0111 xxxx */ { 0x0fff00f0u, 0x06ef0070u, GT_ARM32_I_UXTB },
	/* cccc 0110 1110 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x06e00070u, GT_ARM32_I_UXTAB },
	/* cccc 0110 1111 1111 xxxx xxxx 0111 xxxx */ { 0x0fff00f0u, 0x06ff0070u, GT_ARM32_I_UXTH },
	/* cccc 0110 1111 xxxx xxxx xxxx 0111 xxxx */ { 0x0ff000f0u, 0x06f00070u, GT_ARM32_I_UXTAH },
	/* cccc 0110 1011 xxxx xxxx xxxx 0011 xxxx */ { 0x0ff000f0u, 0x06b00030u, GT_ARM32_I_REV },
	/* cccc 0110 1011 xxxx xxxx xxxx 1011 xxxx */ { 0x0ff000f0u, 0x06b000b0u, GT_ARM32_I_REV16 },
	/* cccc 0110 1111 xxxx xxxx xxxx 0011 xxxx */ { 0x0ff000f0u, 0x06f00030u, GT_ARM32_I_RBIT },
	/* cccc 0110 1111 xxxx xxxx xxxx 1011 xxxx */ { 0x0ff000f0u, 0x06f000b0u, GT_ARM32_I_REVSH },
	/* cccc 0110 1xxx xxxx xxxx xxxx xxx1 xxxx */ { 0x0f800010u, 0x06800010u, GT_ARM32_I_INVALID },
	/* divide, dual multiplies, most-significant-word multiplies */
	/* cccc 0111 0001 xxxx xxxx xxxx 0001 xxxx */ { 0x0ff000f0u, 0x07100010u, GT_ARM32_I_SDIV },
	/* cccc 0111 0011 xxxx xxxx xxxx 0001 xxxx */ { 0x0ff000f0u, 0x07300010u, GT_ARM32_I_UDIV },
	/* cccc 0111 00x1 xxxx xxxx xxxx xxx1 xxxx */ { 0x0fd00010u, 0x07100010u, GT_ARM32_I_INVALID },
	/* cccc 0111 0000 xxxx 1111 xxxx 00x1 xxxx */ { 0x0ff0f0d0u, 0x0700f010u, GT_ARM32_I_SMUAD },
	/* cccc 0111 0000 xxxx xxxx xxxx 00x1 xxxx */ { 0x0ff000d0u, 0x07000010u, GT_ARM32_I_SMLAD },
	/* cccc 0111 0000 xxxx 1111 xxxx 01x1 xxxx */ { 0x0ff0f0d0u, 0x0700f050u, GT_ARM32_I_SMUSD },
	/* cccc 0111 0000 xxxx xxxx xxxx 01x1 xxxx */ { 0x0ff000d0u, 0x07000050u, GT_ARM32_I_SMLSD },
	/* cccc 0111 0100 xxxx xxxx xxxx 00x1 xxxx */ { 0x0ff000d0u, 0x07400010u, GT_ARM32_I_SMLALD },
	/* cccc 0111 0100 xxxx xxxx xxxx 01x1 xxxx */ { 0x0ff000d0u, 0x07400050u, GT_ARM32_I_SMLSLD },
	/* cccc 0111 0101 xxxx 1111 xxxx 00x1 xxxx */ { 0x0ff0f0d0u, 0x0750f010u, GT_ARM32_I_SMMUL },
	/* cccc 0111 0101 xxxx xxxx xxxx 00x1 xxxx */ { 0x0ff000d0u, 0x07500010u, GT_ARM32_I_SMMLA },
	/* cccc 0111 0101 xxxx xxxx xxxx 11x1 xxxx */ { 0x0ff000d0u, 0x075000d0u, GT_ARM32_I_SMMLS },
	/* cccc 0111 0xxx xxxx xxxx xxxx xxx1 xxxx */ { 0x0f800010u, 0x07000010u, GT_ARM32_I_INVALID },
	/* sum of absolute differences, bit field */
	/* cccc 0111 1111 xxxx xxxx xxxx 1111 xxxx */ { 0x0ff000f0u, 0x07f000f0u, GT_ARM32_I_UDF },
	/* cccc 0111 1000 xxxx 1111 xxxx 0001 xxxx */ { 0x0ff0f0f0u, 0x0780f010u, GT_ARM32_I_USAD8 },
	/* cccc 0111 1000 xxxx xxxx xxxx 0001 xxxx */ { 0x0ff000f0u, 0x07800010u, GT_ARM32_I_USADA8 },
	/* cccc 0111 101x xxxx xxxx xxxx x101 xxxx */ { 0x0fe00070u, 0x07a00050u, GT_ARM32_I_SBFX },
	/* cccc 0111 110x 1111 xxxx xxxx x001 xxxx */ { 0x0fef0070u, 0x07cf0010u, GT_ARM32_I_BFC },
	/* cccc 0111 110x xxxx xxxx xxxx x001 xxxx */ { 0x0fe00070u, 0x07c00010u, GT_ARM32_I_BFI },
	/* cccc 0111 111x xxxx xxxx xxxx x101 xxxx */ { 0x0fe00070u, 0x07e00050u, GT_ARM32_I_UBFX },
	/* cccc 0111 1xxx xxxx xxxx xxxx xxx1 xxxx */ { 0x0f800010u, 0x07800010u, GT_ARM32_I_INVALID },

	/* ---- load and store, register offset (bit 4 = 0) ---- */
	/* cccc 011x x0x0 xxxx xxxx xxxx xxx0 xxxx */ { 0x0e500010u, 0x06000000u, GT_ARM32_I_STR_REG },
	/* cccc 011x x0x1 xxxx xxxx xxxx xxx0 xxxx */ { 0x0e500010u, 0x06100000u, GT_ARM32_I_LDR_REG },
	/* cccc 011x x1x0 xxxx xxxx xxxx xxx0 xxxx */ { 0x0e500010u, 0x06400000u, GT_ARM32_I_STRB_REG },
	/* cccc 011x x1x1 xxxx xxxx xxxx xxx0 xxxx */ { 0x0e500010u, 0x06500000u, GT_ARM32_I_LDRB_REG },

	/* ======================= conditional space: bits 27..25 = 100 ============= */

	/* stmdb sp!, {..} and ldmia sp!, {..} (no S bit): PUSH and POP */
	/* cccc 1001 0010 1101 xxxx xxxx xxxx xxxx */ { 0x0fff0000u, 0x092d0000u, GT_ARM32_I_PUSH },
	/* cccc 1000 1011 1101 xxxx xxxx xxxx xxxx */ { 0x0fff0000u, 0x08bd0000u, GT_ARM32_I_POP },
	/* cccc 1000 0xx0 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x08000000u, GT_ARM32_I_STMDA },
	/* cccc 1000 1xx0 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x08800000u, GT_ARM32_I_STM },
	/* cccc 1001 0xx0 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x09000000u, GT_ARM32_I_STMDB },
	/* cccc 1001 1xx0 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x09800000u, GT_ARM32_I_STMIB },
	/* cccc 1000 0xx1 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x08100000u, GT_ARM32_I_LDMDA },
	/* cccc 1000 1xx1 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x08900000u, GT_ARM32_I_LDM },
	/* cccc 1001 0xx1 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x09100000u, GT_ARM32_I_LDMDB },
	/* cccc 1001 1xx1 xxxx xxxx xxxx xxxx xxxx */ { 0x0f900000u, 0x09900000u, GT_ARM32_I_LDMIB },

	/* ======================= bits 27..25 = 101, 110, 111 ====================== */

	/* cccc 1010 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0x0f000000u, 0x0a000000u, GT_ARM32_I_B },
	/* cccc 1011 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0x0f000000u, 0x0b000000u, GT_ARM32_I_BL },
	/* coprocessor load and store, and the two-register moves; bits 24..21 = 0000 is unallocated */
	/* cccc 1100 000x xxxx xxxx xxxx xxxx xxxx */ { 0x0fe00000u, 0x0c000000u, GT_ARM32_I_INVALID },
	/* cccc 1100 0100 xxxx xxxx xxxx xxxx xxxx */ { 0x0ff00000u, 0x0c400000u, GT_ARM32_I_MCRR },
	/* cccc 1100 0101 xxxx xxxx xxxx xxxx xxxx */ { 0x0ff00000u, 0x0c500000u, GT_ARM32_I_MRRC },
	/* cccc 110x xxx0 xxxx xxxx xxxx xxxx xxxx */ { 0x0e100000u, 0x0c000000u, GT_ARM32_I_STC },
	/* cccc 110x xxx1 xxxx xxxx xxxx xxxx xxxx */ { 0x0e100000u, 0x0c100000u, GT_ARM32_I_LDC },
	/* cccc 1111 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0x0f000000u, 0x0f000000u, GT_ARM32_I_SVC },
	/* cccc 1110 xxxx xxxx xxxx xxxx xxx0 xxxx */ { 0x0f000010u, 0x0e000000u, GT_ARM32_I_CDP },
	/* cccc 1110 xxx0 xxxx xxxx xxxx xxx1 xxxx */ { 0x0f100010u, 0x0e000010u, GT_ARM32_I_MCR },
	/* cccc 1110 xxx1 xxxx xxxx xxxx xxx1 xxxx */ { 0x0f100010u, 0x0e100010u, GT_ARM32_I_MRC },
};
const unsigned gt_arm32_src_cond_n = sizeof gt_arm32_src_cond / sizeof gt_arm32_src_cond[0];

const struct gt_arm32_row gt_arm32_src_unc[] = {
	/* ======================= the unconditional space: condition 1111 =========== */

	/* 1111 0001 0000 xxx1 xxxx xxxx xxxx xxxx */ { 0xfff10000u, 0xf1010000u, GT_ARM32_I_SETEND },
	/* 1111 0001 0000 xxx0 xxxx xxxx xxxx xxxx */ { 0xfff10000u, 0xf1000000u, GT_ARM32_I_CPS },
	/* 1111 000x xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xfe000000u, 0xf0000000u, GT_ARM32_I_INVALID },
	/* Advanced SIMD data processing: not validity-checked */
	/* 1111 001x xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xfe000000u, 0xf2000000u, GT_ARM32_I_ASIMD_DP },
	/* Advanced SIMD element and structure load/store; pli immediate */
	/* 1111 0100 xxx0 xxxx xxxx xxxx xxxx xxxx */ { 0xff100000u, 0xf4000000u, GT_ARM32_I_VLDST },
	/* 1111 0100 x101 xxxx xxxx xxxx xxxx xxxx */ { 0xff700000u, 0xf4500000u, GT_ARM32_I_PLI_IMM },
	/* 1111 0100 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xff000000u, 0xf4000000u, GT_ARM32_I_INVALID },
	/* 1111 0101 xx01 xxxx xxxx xxxx xxxx xxxx */ { 0xff300000u, 0xf5100000u, GT_ARM32_I_PLD_IMM },
	/* 1111 0101 0111 xxxx xxxx xxxx 0001 xxxx */ { 0xfff000f0u, 0xf5700010u, GT_ARM32_I_CLREX },
	/* 1111 0101 0111 xxxx xxxx xxxx 0100 xxxx */ { 0xfff000f0u, 0xf5700040u, GT_ARM32_I_DSB },
	/* 1111 0101 0111 xxxx xxxx xxxx 0101 xxxx */ { 0xfff000f0u, 0xf5700050u, GT_ARM32_I_DMB },
	/* 1111 0101 0111 xxxx xxxx xxxx 0110 xxxx */ { 0xfff000f0u, 0xf5700060u, GT_ARM32_I_ISB },
	/* 1111 0101 0111 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xf5700000u, GT_ARM32_I_BARRIER },
	/* 1111 0101 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xff000000u, 0xf5000000u, GT_ARM32_I_INVALID },
	/* 1111 0110 x101 xxxx xxxx xxxx xxx0 xxxx */ { 0xff700010u, 0xf6500000u, GT_ARM32_I_PLI_REG },
	/* 1111 0111 xx01 xxxx xxxx xxxx xxx0 xxxx */ { 0xff300010u, 0xf7100000u, GT_ARM32_I_PLD_REG },
	/* 1111 011x xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xfe000000u, 0xf6000000u, GT_ARM32_I_INVALID },
	/* 1111 100x x0x1 xxxx xxxx xxxx xxxx xxxx */ { 0xfe500000u, 0xf8100000u, GT_ARM32_I_RFE },
	/* 1111 100x x1x0 xxxx xxxx xxxx xxxx xxxx */ { 0xfe500000u, 0xf8400000u, GT_ARM32_I_SRS },
	/* 1111 100x xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xfe000000u, 0xf8000000u, GT_ARM32_I_INVALID },
	/* 1111 101x xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xfe000000u, 0xfa000000u, GT_ARM32_I_BLX_IMM },
	/* the cp13 slot of ldc2/stc2 is ARMv8.2's VSDOT/VUDOT (vector) */
	/* 1111 1100 0x10 xxxx xxxx 1101 xxxx xxxx */ { 0xffb00f00u, 0xfc200d00u, GT_ARM32_I_VDOT },
	/* 1111 1100 000x xxxx xxxx xxxx xxxx xxxx */ { 0xffe00000u, 0xfc000000u, GT_ARM32_I_INVALID },
	/* 1111 1100 0100 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xfc400000u, GT_ARM32_I_MCRR },
	/* 1111 1100 0101 xxxx xxxx xxxx xxxx xxxx */ { 0xfff00000u, 0xfc500000u, GT_ARM32_I_MRRC },
	/* 1111 110x xxx0 xxxx xxxx xxxx xxxx xxxx */ { 0xfe100000u, 0xfc000000u, GT_ARM32_I_STC },
	/* 1111 110x xxx1 xxxx xxxx xxxx xxxx xxxx */ { 0xfe100000u, 0xfc100000u, GT_ARM32_I_LDC },
	/* 1111 1111 xxxx xxxx xxxx xxxx xxxx xxxx */ { 0xff000000u, 0xff000000u, GT_ARM32_I_INVALID },
	/* 1111 1110 xxxx xxxx xxxx xxxx xxx0 xxxx */ { 0xff000010u, 0xfe000000u, GT_ARM32_I_CDP },
	/* 1111 1110 xxx0 xxxx xxxx xxxx xxx1 xxxx */ { 0xff100010u, 0xfe000010u, GT_ARM32_I_MCR },
	/* 1111 1110 xxx1 xxxx xxxx xxxx xxx1 xxxx */ { 0xff100010u, 0xfe100010u, GT_ARM32_I_MRC },
};
const unsigned gt_arm32_src_unc_n = sizeof gt_arm32_src_unc / sizeof gt_arm32_src_unc[0];
