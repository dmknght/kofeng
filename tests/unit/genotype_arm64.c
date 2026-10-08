/*
 * genotype_arm64 - the AArch64 decode table, against what the instruction set
 * says.
 *
 * Every encoding below was assembled by hand from the A64 encoding diagrams or
 * is the well-known compiler output for that instruction, and says what it IS.
 * Nothing is a transcript of another decoder's answer, and nothing but this tree
 * is needed. The second check - every one of the 2^32 words, field for field,
 * against the decoder this table replaced - is tools/celllysis/arm64_equiv.c and
 * needs that decoder; the check against an independent decoder is
 * tools/celllysis/arm64_diff.c and needs Capstone.
 *
 * What is asserted for each word: the identity, and for the ones with fields
 * worth reading a few of the accessors (a branch offset, the access size and
 * offset of a load, a logical-immediate bitmask, the registers).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../libgenome/genotype/arm64/arm64.h"

static int failures;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

static struct gt_arm64_insn dec(uint32_t w)
{
	struct gt_arm64_insn in;

	(void)gt_arm64_decode(&in, w);
	return in;
}

struct curated {
	const char *what;
	uint32_t w;
	unsigned id;
};

#define C(w, id, what) { what, w, GT_ARM64_I_##id }

static const struct curated T[] = {
	/* what an undecodable word is */
	C(0x00001234u, UDF, "udf #0x1234 (top sixteen bits zero)"),
	C(0x00000000u, UDF, "udf #0"),
	C(0x20000000u, INVALID, "reserved group, upper half non-zero, bit 31 clear"),
	C(0x80000000u, SME, "SME space (bit 31 set in the reserved group)"),
	C(0x02000000u, INVALID, "bits 28:25 = 0001 holds no instruction"),
	/* data processing, immediate */
	C(0xd28018c8u, MOVZ, "movz x8,#198"),
	C(0x52800020u, MOVZ, "movz w0,#1"),
	C(0x92800000u, MOVN, "movn x0,#0"),
	C(0xf2a24680u, MOVK, "movk x0,#0x1234,lsl #16"),
	C(0x72a00000u, MOVK, "movk w0,#0,lsl #16"),
	C(0x12c00000u, INVALID, "movn w0,#0,lsl #32: hw >= 2 in the 32-bit form"),
	C(0xd0000080u, ADRP, "adrp x0,+0x12 pages"),
	C(0x10000081u, ADR, "adr x1,.+0x10"),
	C(0x911ea000u, ADD_IMM, "add x0,x0,#0x7a8"),
	C(0xd10083ffu, SUB_IMM, "sub sp,sp,#32"),
	C(0xf100141fu, SUBS_IMM, "cmp x0,#5 (subs xzr,x0,#5)"),
	C(0xb1000400u, ADDS_IMM, "adds x0,x0,#1"),
	C(0xf240003fu, ANDS_IMM, "tst x1,#1"),
	C(0x320003e0u, ORR_IMM, "orr w0,wzr,#1"),
	C(0xb200c3e0u, ORR_IMM, "orr x0,xzr,#0x0101010101010101"),
	C(0xd2400000u, EOR_IMM, "eor x0,x0,#1"),
	C(0x9240fc00u, INVALID, "and x0,x0,#imm with N:imms an all-ones run"),
	C(0x12000000u, AND_IMM, "and w0,w0,#1"),
	C(0x12400000u, INVALID, "and w0,w0,#1 with N set: the 32-bit form has no N"),
	C(0x1200fc00u, INVALID, "and w0,w0,#imm with N 0 and imms 63: no element"),
	C(0xd37cec20u, UBFM, "lsl x0,x1,#4 (ubfm #60,#59)"),
	C(0x131f7c00u, SBFM, "asr w0,w0,#31 (sbfm #31,#31)"),
	C(0xb3400000u, BFM, "bfxil x0,x0,#0,#1 (bfm)"),
	C(0xd3400000u, UBFM, "ubfx x0,x0,#0,#1"),
	C(0x93c10c20u, EXTR, "extr x0,x1,x1,#3 (ror x0,x1,#3)"),
	C(0xf3400000u, INVALID, "bitfield opc 3"),
	/* branches */
	C(0x94000010u, BL, "bl .+0x40"),
	C(0x17fffffeu, B, "b .-8"),
	C(0x54000041u, BCOND, "b.ne .+8"),
	C(0xb4000080u, CBZ, "cbz x0,.+0x10"),
	C(0x35ffffe1u, CBNZ, "cbnz w1,.-4"),
	C(0xb6180103u, TBZ, "tbz x3,#35,.+0x20"),
	C(0xb7180103u, TBNZ, "tbnz x3,#35,.+0x20"),
	C(0xd65f03c0u, RET, "ret"),
	C(0xd63f0060u, BLR, "blr x3"),
	C(0xd61f0200u, BR, "br x16"),
	C(0xd69f03e0u, ERET, "eret"),
	C(0xd6bf03e0u, DRPS, "drps"),
	C(0xd65f0bffu, RETAA, "retaa"),
	C(0xd65f0fffu, RETAB, "retab"),
	C(0xd61f081fu, BRAAZ, "braaz x0"),
	C(0xd63f0c1fu, BLRABZ, "blrabz x0"),
	C(0xd71f0800u, BRAA, "braa x0,x0"),
	C(0xd65f0000u, RET, "ret x0"),
	C(0xd65f0001u, INVALID, "ret with op4 non-zero"),
	C(0xd4000001u, SVC, "svc #0"),
	C(0xd4000002u, HVC, "hvc #0"),
	C(0xd4000003u, SMC, "smc #0"),
	C(0xd4207d00u, BRK, "brk #0x3e8"),
	C(0xd4400000u, HLT, "hlt #0"),
	C(0xd4a00001u, DCPS1, "dcps1"),
	C(0xd4000005u, INVALID, "exception generation with op2 non-zero"),
	/* system */
	C(0xd503201fu, HINT, "nop"),
	C(0xd503203fu, HINT, "yield"),
	C(0xd503233fu, HINT_PAC_LR, "paciasp"),
	C(0xd50323bfu, HINT_PAC_LR, "autiasp"),
	C(0xd50323ffu, HINT_PAC_LR, "autibsp"),
	C(0xd503211fu, HINT_PAC_X17, "pacia1716"),
	C(0xd50320ffu, XPACLRI, "xpaclri"),
	C(0xd5033bbfu, DMB, "dmb ish"),
	C(0xd5033fdfu, ISB, "isb"),
	C(0xd5033f9fu, DSB, "dsb sy"),
	C(0xd5033f5fu, CLREX, "clrex"),
	C(0xd50b7420u, SYS, "dc zva,x0 (sys #3,c7,c4,#1)"),
	C(0xd53bd040u, MRS, "mrs x0,tpidr_el0"),
	C(0xd51bd040u, MSR, "msr tpidr_el0,x0"),
	C(0xd500401fu, MSR_PSTATE, "cfinv (msr pstate field)"),
	/* loads and stores: one register */
	C(0xf9400420u, LDR_UOFF, "ldr x0,[x1,#8]"),
	C(0x39400420u, LDR_UOFF, "ldrb w0,[x1,#1]"),
	C(0xf90007e0u, STR_UOFF, "str x0,[sp,#8]"),
	C(0xb9800020u, LDRS64_UOFF, "ldrsw x0,[x1]"),
	C(0x39c00020u, LDRS32_UOFF, "ldrsb w0,[x1]"),
	C(0xf9800020u, PRFM_UOFF, "prfm pldl1keep,[x1]"),
	C(0xbd400020u, LDR_FP_UOFF, "ldr s0,[x1]"),
	C(0x3dc00020u, LDR_FP_UOFF, "ldr q0,[x1]"),
	C(0x3d800020u, STR_FP_UOFF, "str q0,[x1]"),
	C(0xf8408420u, LDR_POST, "ldr x0,[x1],#8"),
	C(0xf8408c20u, LDR_PRE, "ldr x0,[x1,#8]!"),
	C(0xf85f8020u, LDUR, "ldur x0,[x1,#-8]"),
	C(0xf8000020u, STUR, "stur x0,[x1]"),
	C(0xb8627820u, LDR_REG, "ldr w0,[x1,x2,lsl #2]"),
	C(0xf8a27820u, PRFM_REG, "prfm [x1,x2,lsl #3]: size 3 opc 2 is the prefetch"),
	C(0xf8400820u, LDTR, "ldtr x0,[x1]"),
	C(0xf85f9820u, LDTR, "ldtr x0,[x1,#-7]"),
	C(0x58000100u, LDR_LIT_X, "ldr x0,[pc,#0x20]"),
	C(0x18ffffe1u, LDR_LIT_W, "ldr w1,.-4"),
	C(0x98000040u, LDRSW_LIT, "ldrsw x0,.+8"),
	C(0xd8000000u, PRFM_LIT, "prfm pldl1keep,.+0"),
	C(0x1c000000u, LDR_LIT_FP, "ldr s0,.+0"),
	C(0xdc000000u, INVALID, "ldr literal for a vector register with opc 3"),
	C(0x38400c00u, LDR_PRE, "ldrb w0,[x0,#0]!"),
	C(0xf8400c00u, LDR_PRE, "ldr x0,[x0,#0]!"),
	C(0xb8e00c00u, INVALID, "size 2 opc 3 of the general register forms is not allocated"),
	/* loads and stores: pairs */
	C(0xa9bf7bfdu, STP_PRE, "stp x29,x30,[sp,#-16]!"),
	C(0xa8c17bfdu, LDP_POST, "ldp x29,x30,[sp],#16"),
	C(0xa9410440u, LDP_OFF, "ldp x0,x1,[x2,#16]"),
	C(0xa8810440u, STP_POST, "stp x0,x1,[x2],#16"),
	C(0xa8400440u, LDNP, "ldnp x0,x1,[x2]"),
	C(0x6d400400u, LDP_FP_OFF, "ldp d0,d1,[x0]"),
	C(0x69400400u, LDPSW_OFF, "ldpsw x0,x1,[x0]"),
	C(0x68400400u, INVALID, "ldpsw with the no-allocate form"),
	C(0xe9000000u, INVALID, "pair opc 3"),
	/* loads and stores: exclusive, ordered, atomic */
	C(0xc85f7c20u, LDXR, "ldxr x0,[x1]"),
	C(0xc8027c20u, STXR, "stxr w2,x0,[x1]"),
	C(0xc8dffc20u, LDAR, "ldar x0,[x1]"),
	C(0xc89ffc20u, STLR, "stlr x0,[x1]"),
	C(0xc87f0840u, LDXP, "ldxp x0,x0,[x2]"),
	C(0xc8a07c41u, CAS, "cas x0,x1,[x2]"),
	C(0x08207c40u, CASP, "casp w0,w1,w0,w1,[x2]"),
	C(0x08217c40u, INVALID, "casp with an odd Rs"),
	C(0x08207c41u, INVALID, "casp with an odd Rt"),
	C(0xf8210062u, LDADD, "ldadd x1,x2,[x3]"),
	C(0xf8218062u, SWP, "swp x1,x2,[x3]"),
	C(0xf8a0c041u, LDAPR, "ldapr x1,[x2]: A 1 R 0"),
	C(0xf8e0c041u, INVALID, "ldapr with R set"),
	C(0xf83f9040u, ST64B, "st64b x0,[x2]"),
	C(0xf83fd040u, LD64B, "ld64b x0,[x2]"),
	C(0xf83f9041u, INVALID, "st64b with an odd Rt"),
	C(0xf8200420u, LDRAA, "ldraa x0,[x1]"),
	C(0xf8a00420u, LDRAB, "ldrab x0,[x1]"),
	C(0xf8200c20u, LDRAA_PRE, "ldraa x0,[x1]!"),
	C(0xf8a00c20u, LDRAB_PRE, "ldrab x0,[x1]!"),
	C(0xb8200420u, INVALID, "ldraa with size 2"),
	/* tags, MOPS, structures */
	C(0xd9200820u, STG_OFF, "stg x0,[x1]"),
	C(0xd9200420u, STG_POST, "stg x0,[x1],#0"),
	C(0xd9600020u, LDG, "ldg x0,[x1]"),
	C(0x19040440u, MOPS_CPY, "cpyfp [x2]!,[x0]!,x4! (FEAT_MOPS)"),
	C(0x0c407000u, SIMD_STRUCT_MULT, "ld1 {v0.16b},[x0]"),
	C(0x0cc07000u, SIMD_STRUCT_MULT_POST, "ld1 {v0.16b},[x0],x0"),
	C(0x0c417000u, INVALID, "ld1 with Rm set and no post-index"),
	/* data processing, register */
	C(0x8b020020u, ADD_REG, "add x0,x1,x2"),
	C(0x8b224020u, ADD_EXT, "add x0,x1,w2,uxtw"),
	C(0xeb02003fu, SUBS_REG, "cmp x1,x2"),
	C(0xca010000u, EOR_REG, "eor x0,x0,x1"),
	C(0xaa0103e0u, ORR_REG, "mov x0,x1 (orr x0,xzr,x1)"),
	C(0x8a220020u, BIC_REG, "bic x0,x1,x2"),
	C(0xea01001fu, ANDS_REG, "tst x0,x1"),
	C(0x8bc20020u, INVALID, "add (shifted register) with shift 3"),
	C(0x0b020420u, ADD_REG, "add w0,w1,w2,lsl #1"),
	C(0x0b028420u, INVALID, "add w0,w1,w2,lsl #33: imm6 bit 5 in the 32-bit form"),
	C(0x9b027c20u, MADD, "mul x0,x1,x2 (madd with Ra xzr)"),
	C(0x9b028020u, MSUB, "msub x0,x1,x2,x0"),
	C(0x9bc27c20u, UMULH, "umulh x0,x1,x2"),
	C(0x9ac20820u, UDIV, "udiv x0,x1,x2"),
	C(0x9ac22020u, LSLV, "lsl x0,x1,x2"),
	C(0xdac01020u, CLZ, "clz x0,x1"),
	C(0xdac00020u, RBIT, "rbit x0,x1"),
	C(0xdac123e0u, PACIZA, "paciza x0 (Rn must be 31)"),
	C(0xdac143e0u, XPACI, "xpaci x0"),
	C(0xdac12000u, INVALID, "paciza with Rn 0"),
	C(0x9a020020u, ADC, "adc x0,x1,x2"),
	C(0xfa020020u, SBCS, "sbcs x0,x1,x2"),
	C(0x9a820020u, CSEL, "csel x0,x1,x2,eq"),
	C(0x9a820420u, CSINC, "csinc x0,x1,x2,eq"),
	C(0xfa410000u, CCMP_REG, "ccmp x0,x1,#0,eq"),
	C(0x1ac24820u, CRC32W, "crc32w w0,w1,w2"),
	C(0x9ac24c20u, CRC32X, "crc32x w0,w1,x2"),
	C(0x1ac24c20u, INVALID, "crc32x with sf 0"),
	/* scalar floating point, Advanced SIMD, SVE: what writes a general register */
	C(0x9e660000u, FMOV_FP_TO_GP, "fmov x0,d0"),
	C(0x9e670000u, FMOV_GP_TO_FP, "fmov d0,x0"),
	C(0x9e780000u, FCVTS_GP, "fcvtzs x0,d0"),
	C(0x1e780000u, FCVTS_GP, "fcvtzs w0,d0"),
	C(0x0e013c00u, UMOV, "umov w0,v0.b[0]"),
	C(0x0e012c00u, SMOV, "smov w0,v0.b[0]"),
	C(0x0e002c00u, INVALID, "smov with imm5 0"),
	C(0x4e208400u, FPSIMD, "add v0.16b,v0.16b,v0.16b"),
	C(0x1e202800u, FPSIMD, "fadd s0,s0,s0"),
	C(0x0420e3e0u, CNTELEM, "cntb x0"),
	C(0x0420501fu, ADDVL, "addvl sp,xzr,#0"),
	C(0x04bf5020u, RDVL, "rdvl x0,#1"),
	C(0x04200000u, SVE, "an SVE word that writes no general register"),
};

static void table(void)
{
	size_t i;
	unsigned n = 0, bad = 0;

	printf("identities:\n");
	for (i = 0; i < sizeof T / sizeof *T; i++) {
		struct gt_arm64_insn in = dec(T[i].w);
		char what[256];
		int good = in.id == T[i].id && in.word == T[i].w;

		n++;
		snprintf(what, sizeof what, "%08x %s -> %s", T[i].w, T[i].what,
			 gt_arm64_name(T[i].id));
		ok(what, good);
		if (!good) {
			bad++;
			printf("       got %s\n", gt_arm64_name(in.id));
		}
	}
	printf("  %u checked, %u wrong\n", n, bad);
}

static void status(void)
{
	struct gt_arm64_insn in;

	printf("status:\n");
	ok("an unallocated word is GT_INVALID", gt_arm64_decode(&in, 0x20000000u) == GT_INVALID &&
	   in.id == GT_ARM64_I_INVALID);
	ok("udf is a defined instruction: GT_OK", gt_arm64_decode(&in, 0x00001234u) == GT_OK &&
	   in.id == GT_ARM64_I_UDF);
	ok("an ordinary instruction is GT_OK", gt_arm64_decode(&in, 0xd65f03c0u) == GT_OK);
}

static void fields(void)
{
	struct gt_arm64_insn in;

	printf("accessors:\n");
	in = dec(0xd28018c8u);
	ok("movz x8,#198: sf 1, Rd 8, imm 198, shift 0",
	   gt_arm64_sf(&in) == 1 && gt_arm64_rd(&in) == 8 && gt_arm64_movw_imm(&in) == 198 &&
	   gt_arm64_movw_shift(&in) == 0);
	in = dec(0xd2a00020u);
	ok("movz x0,#1,lsl #16: the immediate is shifted into place", gt_arm64_movw_imm(&in) == 0x10000);
	in = dec(0xd0000080u);
	ok("adrp: the immediate is 0x12 pages", gt_arm64_adr_imm(&in) == 0x12);
	in = dec(0xf0ffffe0u);
	ok("adrp backwards: the immediate is -1", gt_arm64_adr_imm(&in) == -1);
	in = dec(0x911ea000u);
	ok("add x0,x0,#0x7a8", gt_arm64_addsub_imm(&in) == 0x7a8 && gt_arm64_rn(&in) == 0);
	in = dec(0x91400400u);
	ok("add x0,x0,#1,lsl #12: sh scales the immediate", gt_arm64_addsub_imm(&in) == 0x1000);
	in = dec(0x8b020020u);
	ok("add x0,x1,x2: Rd 0 Rn 1 Rm 2", gt_arm64_rd(&in) == 0 && gt_arm64_rn(&in) == 1 &&
	   gt_arm64_rm(&in) == 2);
	in = dec(0xf240003fu);
	ok("tst x1,#1: the bitmask is 1", gt_arm64_logical_imm(&in) == 1);
	in = dec(0xb200c3e0u);
	ok("orr x0,xzr,#0x0101..01: the bitmask replicates an 8-bit element",
	   gt_arm64_logical_imm(&in) == 0x0101010101010101ull);
	in = dec(0x320003e0u);
	ok("orr w0,wzr,#1: the 32-bit bitmask", gt_arm64_logical_imm(&in) == 1);
	in = dec(0xb2400fe0u);
	ok("orr x0,xzr,#0xf: a run of four", gt_arm64_logical_imm(&in) == 0xf);
	in = dec(0xb2440fe0u);
	ok("orr x0,xzr,#0xf000...0: a run of four rotated to the top",
	   gt_arm64_logical_imm(&in) == 0xf000000000000000ull);
	in = dec(0x94000010u);
	ok("bl: +0x40", gt_arm64_branch_off(&in) == 0x40);
	in = dec(0x17fffffeu);
	ok("b: -8", gt_arm64_branch_off(&in) == -8);
	in = dec(0x54000041u);
	ok("b.ne: +8, condition 1", gt_arm64_branch_off(&in) == 8 && gt_arm64_cond_branch(&in) == 1);
	in = dec(0xb4000080u);
	ok("cbz x0: +0x10", gt_arm64_branch_off(&in) == 0x10 && gt_arm64_rt(&in) == 0);
	in = dec(0x35ffffe1u);
	ok("cbnz w1: -4, sf 0", gt_arm64_branch_off(&in) == -4 && gt_arm64_sf(&in) == 0);
	in = dec(0xb6180103u);
	ok("tbz x3,#35: +0x20, bit 35", gt_arm64_branch_off(&in) == 0x20 && gt_arm64_tbz_bit(&in) == 35 &&
	   gt_arm64_rt(&in) == 3);
	in = dec(0xd4001c01u);
	ok("svc #0xe0: imm16", gt_arm64_imm16(&in) == 0xe0);
	in = dec(0xd53bd040u);
	ok("mrs x0,tpidr_el0: Rt 0, the system register field", gt_arm64_rt(&in) == 0 &&
	   gt_arm64_sysreg(&in) == ((0xd53bd040u >> 5) & 0x7fffu));
	in = dec(0xd50323bfu);
	ok("hint number of autiasp is 29", gt_arm64_hint(&in) == 29);

	in = dec(0xf9400c20u);
	ok("ldr x0,[x1,#24]: 8 bytes, scaled offset 24, a load, an offset address",
	   gt_arm64_ldst_bytes(&in) == 8 && gt_arm64_ldst_off(&in) == 24 &&
	   gt_arm64_lskind(&in) == GT_ARM64_K_LOAD && gt_arm64_amode(&in) == GT_ARM64_AM_OFFSET);
	in = dec(0x39400420u);
	ok("ldrb w0,[x1,#1]: one byte, offset 1", gt_arm64_ldst_bytes(&in) == 1 && gt_arm64_ldst_off(&in) == 1);
	in = dec(0x3dc00420u);
	ok("ldr q0,[x1,#16]: the Q register moves 16 bytes and scales the offset by 16",
	   gt_arm64_ldst_bytes(&in) == 16 && gt_arm64_ldst_off(&in) == 16 &&
	   gt_arm64_lskind(&in) == GT_ARM64_K_LOAD_FP);
	in = dec(0xb9800020u);
	ok("ldrsw: a sign-extending load into X, four bytes",
	   gt_arm64_lskind(&in) == GT_ARM64_K_LOAD_S64 && gt_arm64_ldst_bytes(&in) == 4);
	in = dec(0x39c00020u);
	ok("ldrsb w0: a sign-extending load into W", gt_arm64_lskind(&in) == GT_ARM64_K_LOAD_S32);
	in = dec(0xf90007e0u);
	ok("str x0,[sp,#8]: a store, Rn 31", gt_arm64_lskind(&in) == GT_ARM64_K_STORE && gt_arm64_rn(&in) == 31 &&
	   gt_arm64_ldst_off(&in) == 8);
	in = dec(0xf8408420u);
	ok("ldr x0,[x1],#8: post-index, the increment is 8",
	   gt_arm64_amode(&in) == GT_ARM64_AM_POST && gt_arm64_ldst_off(&in) == 8);
	in = dec(0xf8408c20u);
	ok("ldr x0,[x1,#8]!: pre-index", gt_arm64_amode(&in) == GT_ARM64_AM_PRE && gt_arm64_ldst_off(&in) == 8);
	in = dec(0xf85f8020u);
	ok("ldur x0,[x1,#-8]: unscaled, -8", gt_arm64_amode(&in) == GT_ARM64_AM_UNSCALED &&
	   gt_arm64_ldst_off(&in) == -8);
	in = dec(0xb8627820u);
	ok("ldr w0,[x1,x2,lsl #2]: register offset, Rm 2, S set",
	   gt_arm64_amode(&in) == GT_ARM64_AM_REG && gt_arm64_rm(&in) == 2 && gt_arm64_bits(&in, 12, 1) == 1);
	in = dec(0x58000100u);
	ok("ldr x0,[pc,#0x20]: literal, 8 bytes, +0x20", gt_arm64_amode(&in) == GT_ARM64_AM_LIT &&
	   gt_arm64_ldst_bytes(&in) == 8 && gt_arm64_ldst_off(&in) == 0x20);
	in = dec(0x18ffffe1u);
	ok("ldr w1,.-4: literal, 4 bytes, -4", gt_arm64_ldst_bytes(&in) == 4 && gt_arm64_ldst_off(&in) == -4);
	in = dec(0xa9bf7bfdu);
	ok("stp x29,x30,[sp,#-16]!: 8 bytes a register, -16, pre-index, Rt2 30",
	   gt_arm64_ldst_bytes(&in) == 8 && gt_arm64_ldst_off(&in) == -16 &&
	   gt_arm64_amode(&in) == GT_ARM64_AM_PRE && gt_arm64_rt2(&in) == 30 && gt_arm64_rt(&in) == 29);
	in = dec(0x6d400400u);
	ok("ldp d0,d1,[x0]: 8 bytes a register, a floating point load",
	   gt_arm64_ldst_bytes(&in) == 8 && gt_arm64_lskind(&in) == GT_ARM64_K_LOAD_FP);
	in = dec(0x69400800u);
	ok("ldpsw x0,x2,[x0]: 4 bytes a register, offset scaled by 4", gt_arm64_ldst_bytes(&in) == 4 &&
	   gt_arm64_lskind(&in) == GT_ARM64_K_LOAD_S64);
	in = dec(0xf8200420u);
	ok("ldraa x0,[x1]: the offset is a signed multiple of 8, here 0", gt_arm64_ldst_off(&in) == 0);
	in = dec(0xf8a00c20u);
	ok("ldrab x0,[x1]!: pre-index", gt_arm64_ldst_off(&in) == 0 && gt_arm64_rn(&in) == 1);
}

/*
 * THE LOOKUP IN FRONT OF THE TREE IS BUILT BY CODE FROM IT, so what is checked is
 * that the code is sound: a word under every one of the 2048 top-bit keys, the
 * lowest and the highest and a pseudo-random sample, and then a stride through
 * the whole space, must decode the same through gt_arm64_decode and through the
 * tree alone.
 */
static void lookup_agrees(void)
{
	uint64_t w, n = 0, bad = 0;
	uint32_t s = 0x9e3779b9u;
	unsigned k;

	printf("lookup in front of the tree:\n");
	for (k = 0; k < 2048u; k++) {
		unsigned i;

		for (i = 0; i < 64; i++) {
			uint32_t v, low;
			struct gt_arm64_insn a, b;

			s = s * 1664525u + 1013904223u;
			low = i == 0 ? 0 : i == 1 ? (1u << 21) - 1u : (s >> 3) & ((1u << 21) - 1u);
			v = (k << 21) | low;
			n++;
			if (gt_arm64_decode(&a, v) != gt_arm64_decode_tree(&b, v) || a.id != b.id)
				bad++;
		}
	}
	for (w = 0; w < 0x100000000ull; w += 251) {
		struct gt_arm64_insn a, b;

		n++;
		if (gt_arm64_decode(&a, (uint32_t)w) != gt_arm64_decode_tree(&b, (uint32_t)w) || a.id != b.id)
			bad++;
	}
	ok("decode answers what the tree does, under every top-bit key and on a stride of the space", bad == 0);
	printf("  %llu words compared, %llu differ\n", (unsigned long long)n, (unsigned long long)bad);
}

static void names(void)
{
	unsigned i, dup = 0, missing = 0;

	printf("names:\n");
	for (i = 0; i < GT_ARM64_I_COUNT; i++) {
		unsigned j;

		if (!gt_arm64_name(i) || !strcmp(gt_arm64_name(i), "?"))
			missing++;
		for (j = 0; j < i; j++)
			if (!strcmp(gt_arm64_name(i), gt_arm64_name(j)))
				dup++;
	}
	ok("every identity has a name", missing == 0);
	ok("no two identities share a name", dup == 0);
	ok("a number past the end is named \"?\"", !strcmp(gt_arm64_name(GT_ARM64_I_COUNT), "?"));
}

int main(void)
{
	printf("genotype arm64:\n");
	table();
	status();
	fields();
	lookup_agrees();
	names();
	printf("genotype arm64: %s\n", failures ? "FAILED" : "ok");
	return failures ? 1 : 0;
}
