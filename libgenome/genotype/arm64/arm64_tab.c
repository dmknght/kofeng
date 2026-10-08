/*
 * arm64_tab.c - the AArch64 decode table. DATA: every fact about which word is
 * which instruction is a row here, and arm64.c is only the walk over them.
 *
 * HOW IT IS ORGANISED. The first index is bits 29..25 of the word. The
 * architecture's own top level is bits 28..25 (sixteen groups: data processing,
 * branches, loads and stores, the vector spaces ...); bit 29 is added because it
 * is the one that splits the load/store groups into pairs and the rest, and for
 * every other group both halves are the same entry. Each group is then a NODE:
 * an index on the two or three bit-fields the architecture reference splits that
 * group on, selecting a short list of rows. A row is {mask, value, identity}; the
 * list is tried in order and ends in a row that always matches, so the order IS
 * the priority ("the pattern, except this one" is the exception first). A row
 * whose identity is a node number continues there.
 *
 * IN FRONT OF THIS TREE sits a lookup on the top 11 bits of the word that
 * arm64.c builds from these rows on first use: where those bits already decide
 * the instruction the tree is not walked at all. This file is the only carrier
 * of what a word is; the lookup never says anything it does not.
 *
 * READING A ROW. FLD(hi, lo, v) is bits hi..lo equal to v; B(n, v) is one bit;
 * fields are joined with |. ROW(identity, flags, fields) is the row they build.
 * Because the validity of a word is part of what a row says, an unallocated
 * encoding is a row to INVALID and not a missing one: that is what makes this
 * checkable word for word against the decoder it replaced (tools/celllysis/
 * arm64_equiv.c - all 2^32 words, no differences).
 *
 * THE FIELD NAMES in the comments are the architecture reference's: sf is bit
 * 31, opc, S, N, imms, immr, o0 ... as the encoding diagram of each format spells
 * them. Where a condition is "the field is not zero" it is written the way the
 * list can say it: the zero case first, then everything else is the exception.
 */
#include <stddef.h>
#include <stdint.h>

#include "arm64.h"
#include "arm64_int.h"

#define FLD(hi, lo, v) \
	((((uint64_t)((1ull << ((hi) - (lo) + 1u)) - 1u) << (lo)) << 32) | ((uint64_t)(v) << (lo)))
#define B(n, v) FLD(n, n, v)
#define ROW(id, fl, e) { (uint32_t)((uint64_t)(e) >> 32), (uint32_t)(e), (uint16_t)(id), (uint16_t)(fl) }
#define I(n) GT_ARM64_I_##n
#define LAST(n) ROW(I(n), 0, 0)
#define ONE(id) ((const struct gt_arm64_row[]){ ROW(id, 0, 0) })
#define ONEI(n) ONE(I(n))

/* the node numbers: one per index below, in the order of gt_arm64_nodes */
#define GT_ARM64_NODE_LIST(X) \
	X(SVE) X(FP7) X(FPF) X(SIMDCOPY) X(FPINT) X(FIXED) X(DPIMM) X(BR_A) X(BR_B) \
	X(EXC) X(SYS) X(BREG) X(DPREG5) X(DPREGD) X(DP12) X(EXCL) X(SIMDSTRUCT) \
	X(LIT0) X(LIT1) X(TAGS) X(RCPC) X(LS3_0) X(LS3_1) X(LSREG_0) X(LSREG_1) \
	X(UOFF_0) X(UOFF_1) X(UNSC_0) X(UNSC_1) X(POST_0) X(POST_1) X(PRE_0) X(PRE_1) \
	X(UNPRIV_0) X(REG_0) X(REG_1) X(ATOMIC) X(PAIR0) X(PAIR1)

enum {
#define X(n) NODE_##n,
	NODE_FIRST_ = GT_ARM64_NODE0 - 1,
	GT_ARM64_NODE_LIST(X)
#undef X
	NODE_END_
};
/* NODE_FIRST_ + 1 == GT_ARM64_NODE0: the first node is number 0 */

#define GO(n) ONE(NODE_##n)

/* shared lists */
static const struct gt_arm64_row rw_inv[] = { LAST(INVALID) };
static const struct gt_arm64_row rw_fpsimd[] = { LAST(FPSIMD) };
static const struct gt_arm64_row rw_sve[] = { LAST(SVE) };

/* ---- bits 28..25 = 0000: reserved, udf, SME ---------------------------------- */

static const struct gt_arm64_row rw_res[] = {
	ROW(I(UDF), 0, FLD(31, 16, 0)),         /* udf #imm16 */
	ROW(I(SME), 0, B(31, 1)),               /* SME: valid, no general register written */
	LAST(INVALID)
};

/* ---- SVE: the words that write a general register -------------------------------
 *
 * One row per family, Rd/Rdn in bits 4:0 for all of them. The masks were found by
 * enumerating the whole 2^28-word space against a reference decoder (every word
 * whose first operand is a general register, minus ctermeq/ctermne, which only
 * read it) and written as families: the element-size field is free, the rest of
 * each pattern fixed. The streaming-mode forms addsvl/addspl/rdsvl (FEAT_SME) are
 * the same patterns with bit 11 set; the reference does not decode them and the
 * architecture does, so bit 11 is left free in those three rows. Nothing here
 * decides whether a word in the rest of the space is allocated.
 *
 * The index is bits 31:29 and 24: every row starts with 0x04, 0x05 or 0x25 in
 * bits 31:24, so a word outside those three prefixes is one lookup.
 */
static const struct gt_arm64_row rw_sve04[] = {
	{ 0xffe0f000u, 0x04205000u, I(ADDVL), 0 },      /* addvl, addsvl */
	{ 0xffe0f000u, 0x04605000u, I(ADDPL), 0 },      /* addpl, addspl */
	{ 0xfffff000u, 0x04bf5000u, I(RDVL), 0 },       /* rdvl, rdsvl */
	{ 0xff30fc00u, 0x0420e000u, I(CNTELEM), 0 },    /* cntb cnth cntw cntd */
	{ 0xff30f800u, 0x0430e000u, I(INCDECELEM), 0 }, /* incb..incd, decb..decd */
	{ 0xff20f000u, 0x0420f000u, I(SQINCDECELEM), 0 }, /* sq/uq inc/dec b..d, scalar */
	LAST(SVE)
};
static const struct gt_arm64_row rw_sve05[] = {
	{ 0xff3ee000u, 0x0520a000u, I(LASTAB), 0 },     /* lasta, lastb */
	{ 0xff3ee000u, 0x0530a000u, I(CLASTAB), 0 },    /* clasta, clastb */
	LAST(SVE)
};
static const struct gt_arm64_row rw_sve25[] = {
	{ 0xff3fc200u, 0x25208000u, I(CNTP), 0 },       /* cntp */
	{ 0xff3efe00u, 0x252c8800u, I(INCDECP), 0 },    /* incp, decp, scalar */
	{ 0xff3cfa00u, 0x25288800u, I(SQINCDECP), 0 },  /* sq/uq inc/dec p, scalar */
	LAST(SVE)
};
static const struct gt_arm64_row *const bk_SVE[16] = {
	rw_sve04, rw_sve, rw_sve, rw_sve, rw_sve, rw_sve, rw_sve, rw_sve,
	rw_sve05, rw_sve25, rw_sve, rw_sve, rw_sve, rw_sve, rw_sve, rw_sve
};
static const struct gt_arm64_node n_SVE = { 29, 7, 24, 1, 3, bk_SVE };

/* ---- scalar floating point and Advanced SIMD ------------------------------------
 *
 * Bits 28..25 = 0111 (Advanced SIMD) and 1111 (scalar floating point). Only the
 * families that write a general register are told apart, and each carries the
 * allocation checks that keep a word that merely resembles it from claiming one.
 */

/* Advanced SIMD copy (bit 31 0, bit 29 0, bits 28:24 01110, 23:21 000, bit 15 0, bit 10 1): smov and umov */
static const struct gt_arm64_row rw_fp7[] = {
	{ 0xbfe08400u, 0x0e000400u, NODE_SIMDCOPY, 0 },
	LAST(FPSIMD)
};

/* by imm4. imm5 (bits 20:16) names the element size by its lowest set bit; Q is bit 30. */
static const struct gt_arm64_row rw_smov[] = {
	ROW(I(SMOV), 0, B(16, 1)),                      /* byte */
	ROW(I(SMOV), 0, FLD(17, 16, 2)),                /* halfword */
	ROW(I(SMOV), 0, B(30, 1) | FLD(18, 16, 4)),     /* word, only into an X register */
	LAST(INVALID)
};
static const struct gt_arm64_row rw_umov[] = {
	ROW(I(UMOV), 0, B(30, 1) | FLD(19, 16, 8)),     /* doubleword, only into an X register */
	ROW(I(INVALID), 0, B(30, 1)),
	ROW(I(UMOV), 0, B(16, 1)),
	ROW(I(UMOV), 0, FLD(17, 16, 2)),
	ROW(I(UMOV), 0, FLD(18, 16, 4)),
	LAST(INVALID)
};
#define FP rw_fpsimd
static const struct gt_arm64_row *const bk_SIMDCOPY[16] = {
	FP, FP, FP, FP, FP, rw_smov, FP, rw_umov, FP, FP, FP, FP, FP, FP, FP, FP
};
#undef FP
static const struct gt_arm64_node n_SIMDCOPY = { 11, 15, 0, 0, 0, bk_SIMDCOPY };

static const struct gt_arm64_row rw_fpf[] = {
	{ 0x7f20fc00u, 0x1e200000u, NODE_FPINT, 0 },    /* floating point <-> integer */
	{ 0x7f200000u, 0x1e000000u, NODE_FIXED, 0 },    /* floating point <-> fixed point */
	LAST(FPSIMD)
};

/*
 * Floating point <-> integer, by opc (bits 18:16). type is bits 23:22, rmode 20:19.
 * type 2 is the top half of a 128-bit register, which only fmov (opc 6, 7) of an X
 * register with rmode 1 uses.
 */
#define T2 FLD(23, 22, 2)
#define RM(v) FLD(20, 19, v)
static const struct gt_arm64_row rw_fi01[] = { ROW(I(INVALID), 0, T2), LAST(FCVTS_GP) };
static const struct gt_arm64_row rw_fi01u[] = { ROW(I(INVALID), 0, T2), LAST(FCVTU_GP) };
static const struct gt_arm64_row rw_fi2[] = {
	ROW(I(INVALID), 0, T2), ROW(I(SCVTF_GP), 0, RM(0)), LAST(INVALID)
};
static const struct gt_arm64_row rw_fi3[] = {
	ROW(I(INVALID), 0, T2), ROW(I(UCVTF_GP), 0, RM(0)), LAST(INVALID)
};
static const struct gt_arm64_row rw_fi4[] = {
	ROW(I(INVALID), 0, T2), ROW(I(FCVTAS_GP), 0, RM(0)), LAST(INVALID)
};
static const struct gt_arm64_row rw_fi5[] = {
	ROW(I(INVALID), 0, T2), ROW(I(FCVTAU_GP), 0, RM(0)), LAST(INVALID)
};
static const struct gt_arm64_row rw_fi6[] = {
	ROW(I(FMOV_TOP_TO_GP), 0, B(31, 1) | T2 | RM(1)),
	ROW(I(INVALID), 0, T2),
	ROW(I(FMOV_FP_TO_GP), 0, RM(0) | B(31, 0) | FLD(23, 22, 0)),   /* w, s */
	ROW(I(FMOV_FP_TO_GP), 0, RM(0) | B(31, 1) | FLD(23, 22, 1)),   /* x, d */
	ROW(I(FMOV_FP_TO_GP), 0, RM(0) | FLD(23, 22, 3)),              /* half precision */
	ROW(I(FJCVTZS), 0, RM(3) | B(31, 0) | FLD(23, 22, 1)),
	LAST(INVALID)
};
static const struct gt_arm64_row rw_fi7[] = {
	ROW(I(FMOV_TOP_FROM_GP), 0, B(31, 1) | T2 | RM(1)),
	ROW(I(INVALID), 0, T2),
	ROW(I(FMOV_GP_TO_FP), 0, RM(0) | B(31, 0) | FLD(23, 22, 0)),
	ROW(I(FMOV_GP_TO_FP), 0, RM(0) | B(31, 1) | FLD(23, 22, 1)),
	ROW(I(FMOV_GP_TO_FP), 0, RM(0) | FLD(23, 22, 3)),
	LAST(INVALID)
};
static const struct gt_arm64_row *const bk_FPINT[8] = {
	rw_fi01, rw_fi01u, rw_fi2, rw_fi3, rw_fi4, rw_fi5, rw_fi6, rw_fi7
};
static const struct gt_arm64_node n_FPINT = { 16, 7, 0, 0, 0, bk_FPINT };

/* fixed-point: fcvtzs / fcvtzu to a general register, scvtf / ucvtf from one. scale's top bit (15) must be 1 in the 32-bit form. */
static const struct gt_arm64_row rw_fixed[] = {
	ROW(I(INVALID), 0, T2),
	ROW(I(INVALID), 0, B(31, 0) | B(15, 0)),
	ROW(I(FCVTZS_FIXED), 0, RM(3) | FLD(18, 16, 0)),
	ROW(I(FCVTZU_FIXED), 0, RM(3) | FLD(18, 16, 1)),
	ROW(I(SCVTF_FIXED), 0, RM(0) | FLD(18, 16, 2)),
	ROW(I(UCVTF_FIXED), 0, RM(0) | FLD(18, 16, 3)),
	LAST(INVALID)
};
static const struct gt_arm64_row *const bk_FIXED[1] = { rw_fixed };
static const struct gt_arm64_node n_FIXED = { 0, 0, 0, 0, 0, bk_FIXED };
#undef T2
#undef RM

/* ---- data processing, immediate (bits 28..26 = 100), by bits 25:23 --------------- */

static const struct gt_arm64_row rw_adr[] = { ROW(I(ADR), 0, B(31, 0)), LAST(ADRP) };
static const struct gt_arm64_row rw_addsubi[] = {
	ROW(I(ADD_IMM), 0, FLD(30, 29, 0)), ROW(I(ADDS_IMM), 0, FLD(30, 29, 1)),
	ROW(I(SUB_IMM), 0, FLD(30, 29, 2)), LAST(SUBS_IMM)
};
/* bit 22 set: smax, umax, smin, umin (FEAT_CSSC), sf op S = x 0 0 and opc below 4. bit 22 clear: addg, subg (FEAT_MTE), sf 1, S 0, bits 15:14 zero. */
static const struct gt_arm64_row rw_minmaxi[] = {
	ROW(I(SMAX_IMM), 0, B(22, 1) | FLD(30, 29, 0) | FLD(21, 18, 0)),
	ROW(I(UMAX_IMM), 0, B(22, 1) | FLD(30, 29, 0) | FLD(21, 18, 1)),
	ROW(I(SMIN_IMM), 0, B(22, 1) | FLD(30, 29, 0) | FLD(21, 18, 2)),
	ROW(I(UMIN_IMM), 0, B(22, 1) | FLD(30, 29, 0) | FLD(21, 18, 3)),
	ROW(I(INVALID), 0, B(22, 1)),
	ROW(I(ADDG), 0, B(31, 1) | B(30, 0) | B(29, 0) | FLD(15, 14, 0)),
	ROW(I(SUBG), 0, B(31, 1) | B(30, 1) | B(29, 0) | FLD(15, 14, 0)),
	LAST(INVALID)
};
/* logical immediate: the 32-bit form has no N; N:imms must name a bitmask (the one check a mask cannot say) */
static const struct gt_arm64_row rw_logi[] = {
	ROW(I(INVALID), 0, B(31, 0) | B(22, 1)),
	ROW(I(AND_IMM), GT_ARM64_RF_BITMASK, FLD(30, 29, 0)),
	ROW(I(ORR_IMM), GT_ARM64_RF_BITMASK, FLD(30, 29, 1)),
	ROW(I(EOR_IMM), GT_ARM64_RF_BITMASK, FLD(30, 29, 2)),
	ROW(I(ANDS_IMM), GT_ARM64_RF_BITMASK, 0)
};
/* move wide: opc 1 is unallocated, and so is hw >= 2 in the 32-bit form */
static const struct gt_arm64_row rw_movw[] = {
	ROW(I(INVALID), 0, FLD(30, 29, 1)),
	ROW(I(INVALID), 0, B(31, 0) | B(22, 1)),
	ROW(I(MOVN), 0, FLD(30, 29, 0)), ROW(I(MOVZ), 0, FLD(30, 29, 2)), LAST(MOVK)
};
/* bitfield: opc 3 is unallocated, N must equal sf, and the 32-bit form has immr, imms below 32 */
static const struct gt_arm64_row rw_bitf[] = {
	ROW(I(INVALID), 0, FLD(30, 29, 3)),
	ROW(I(INVALID), 0, B(31, 1) | B(22, 0)),
	ROW(I(INVALID), 0, B(31, 0) | B(22, 1)),
	ROW(I(INVALID), 0, B(31, 0) | B(21, 1)),
	ROW(I(INVALID), 0, B(31, 0) | B(15, 1)),
	ROW(I(SBFM), 0, FLD(30, 29, 0)), ROW(I(BFM), 0, FLD(30, 29, 1)), LAST(UBFM)
};
/* extract: op21 (30:29) and o0 (21) must be 0, N equal to sf, imms below 32 in the 32-bit form */
static const struct gt_arm64_row rw_extr[] = {
	ROW(I(INVALID), 0, B(30, 1)),
	ROW(I(INVALID), 0, B(29, 1)),
	ROW(I(INVALID), 0, B(21, 1)),
	ROW(I(INVALID), 0, B(31, 1) | B(22, 0)),
	ROW(I(INVALID), 0, B(31, 0) | B(22, 1)),
	ROW(I(INVALID), 0, B(31, 0) | B(15, 1)),
	LAST(EXTR)
};
static const struct gt_arm64_row *const bk_DPIMM[8] = {
	rw_adr, rw_adr, rw_addsubi, rw_minmaxi, rw_logi, rw_movw, rw_bitf, rw_extr
};
static const struct gt_arm64_node n_DPIMM = { 23, 7, 0, 0, 0, bk_DPIMM };

/* ---- branches, exception generation, system ------------------------------------ */

/*
 * Bits 28..25 = 1010 and 1011. The index is bits 31:29 and bit 24, which is
 * everything the architecture splits these two groups on before it reads a field.
 */
#define BIDX(f0, b24) ((f0) | ((b24) << 3))
static const struct gt_arm64_row *const bk_BR_A[16] = {
	[BIDX(0, 0)] = ONEI(B),    [BIDX(0, 1)] = ONEI(B),
	[BIDX(4, 0)] = ONEI(BL),   [BIDX(4, 1)] = ONEI(BL),
	[BIDX(1, 0)] = ONEI(CBZ),  [BIDX(5, 0)] = ONEI(CBZ),
	[BIDX(1, 1)] = ONEI(CBNZ), [BIDX(5, 1)] = ONEI(CBNZ),
	[BIDX(2, 0)] = ONEI(BCOND),
	[BIDX(6, 0)] = GO(EXC),    [BIDX(6, 1)] = GO(SYS),
	[BIDX(3, 0)] = rw_inv, [BIDX(7, 0)] = rw_inv, [BIDX(3, 1)] = rw_inv,
	[BIDX(7, 1)] = rw_inv, [BIDX(2, 1)] = rw_inv
};
static const struct gt_arm64_node n_BR_A = { 29, 7, 24, 1, 3, bk_BR_A };

static const struct gt_arm64_row *const bk_BR_B[16] = {
	[BIDX(0, 0)] = ONEI(B),    [BIDX(0, 1)] = ONEI(B),
	[BIDX(4, 0)] = ONEI(BL),   [BIDX(4, 1)] = ONEI(BL),
	[BIDX(1, 0)] = ONEI(TBZ),  [BIDX(5, 0)] = ONEI(TBZ),
	[BIDX(1, 1)] = ONEI(TBNZ), [BIDX(5, 1)] = ONEI(TBNZ),
	[BIDX(6, 0)] = GO(BREG),   [BIDX(6, 1)] = GO(BREG),
	[BIDX(3, 0)] = rw_inv, [BIDX(7, 0)] = rw_inv, [BIDX(2, 0)] = rw_inv,
	[BIDX(3, 1)] = rw_inv, [BIDX(7, 1)] = rw_inv, [BIDX(2, 1)] = rw_inv
};
static const struct gt_arm64_node n_BR_B = { 29, 7, 24, 1, 3, bk_BR_B };
#undef BIDX

/* Exception generation (bits 31:24 = 0xd4): opc (23:21) and LL (1:0) name it, op2 (4:2) must be 0 */
#define EOPC(o, ll) (FLD(23, 21, o) | FLD(1, 0, ll))
static const struct gt_arm64_row rw_exc[] = {
	ROW(I(INVALID), 0, B(4, 1)), ROW(I(INVALID), 0, B(3, 1)), ROW(I(INVALID), 0, B(2, 1)),
	ROW(I(SVC), 0, EOPC(0, 1)), ROW(I(HVC), 0, EOPC(0, 2)), ROW(I(SMC), 0, EOPC(0, 3)),
	ROW(I(BRK), 0, EOPC(1, 0)), ROW(I(HLT), 0, EOPC(2, 0)),
	ROW(I(DCPS1), 0, EOPC(5, 1)), ROW(I(DCPS2), 0, EOPC(5, 2)), ROW(I(DCPS3), 0, EOPC(5, 3)),
	ROW(I(TCANCEL), 0, EOPC(3, 0)),     /* FEAT_TME */
	LAST(INVALID)
};
#undef EOPC
static const struct gt_arm64_row *const bk_EXC[1] = { rw_exc };
static const struct gt_arm64_node n_EXC = { 0, 0, 0, 0, 0, bk_EXC };

/*
 * System (bits 31:24 = 0xd5, bits 23:22 must be 0): L is bit 21, op0 20:19, op1
 * 18:16, CRn 15:12, CRm 11:8, op2 7:5, Rt 4:0. A word that is none of these is
 * unallocated, and the order below is the old decoder's.
 */
#define SYSH (FLD(15, 12, 2) | FLD(18, 16, 3) | FLD(4, 0, 31))          /* hint #crm:op2 */
#define SYSB (FLD(15, 12, 3) | FLD(4, 0, 31))                           /* barriers */
#define SYSTM(crm) (B(21, 1) | FLD(20, 19, 0) | FLD(18, 16, 3) | FLD(15, 12, 3) | FLD(11, 8, crm) | FLD(7, 5, 3))
static const struct gt_arm64_row rw_sys[] = {
	ROW(I(INVALID), 0, B(23, 1)), ROW(I(INVALID), 0, B(22, 1)),
	ROW(I(MRS), 0, B(21, 1) | B(20, 1)), ROW(I(MSR), 0, B(21, 0) | B(20, 1)),
	ROW(I(SYSL), 0, B(21, 1) | FLD(20, 19, 1)), ROW(I(SYS), 0, B(21, 0) | FLD(20, 19, 1)),
	ROW(I(TSTART), 0, SYSTM(0)), ROW(I(TTEST), 0, SYSTM(1)),        /* FEAT_TME */
	ROW(I(INVALID), 0, B(21, 1)),
	ROW(I(TCOMMIT), 0, FLD(15, 12, 3) | FLD(18, 16, 3) | FLD(7, 5, 3) | FLD(11, 8, 0) | FLD(4, 0, 31)),
	ROW(I(XPACLRI), 0, SYSH | FLD(11, 8, 0) | FLD(7, 5, 7)),
	ROW(I(HINT_PAC_LR), 0, SYSH | FLD(11, 8, 3)),                   /* paciaz .. autibsp */
	ROW(I(HINT_PAC_X17), 0, SYSH | FLD(11, 8, 1) | B(5, 0)),       /* pacia1716 .. autib1716 */
	ROW(I(CHKFEAT), 0, SYSH | FLD(11, 8, 5) | FLD(7, 5, 0)),
	ROW(I(HINT), 0, SYSH),
	ROW(I(CLREX), 0, SYSB | FLD(7, 5, 2)), ROW(I(DSB), 0, SYSB | FLD(7, 5, 4)),
	ROW(I(DMB), 0, SYSB | FLD(7, 5, 5)), ROW(I(ISB), 0, SYSB | FLD(7, 5, 6)),
	ROW(I(SB), 0, SYSB | FLD(7, 5, 7)),
	ROW(I(DSB_NXS), 0, SYSB | FLD(7, 5, 1) | FLD(9, 8, 2)),        /* FEAT_XS: op2 1, CRm 2 mod 4 */
	ROW(I(MSR_PSTATE), 0, FLD(15, 12, 4) | FLD(4, 0, 31)),
	ROW(I(WFET), 0, FLD(15, 12, 1) | FLD(11, 8, 0) | FLD(18, 16, 3) | FLD(7, 5, 0)),
	ROW(I(WFIT), 0, FLD(15, 12, 1) | FLD(11, 8, 0) | FLD(18, 16, 3) | FLD(7, 5, 1)),
	LAST(INVALID)
};
#undef SYSH
#undef SYSB
#undef SYSTM
static const struct gt_arm64_row *const bk_SYS[1] = { rw_sys };
static const struct gt_arm64_node n_SYS = { 0, 0, 0, 0, 0, bk_SYS };

/* Unconditional branch (register), bits 31:25 = 1101011: opc 24:21, op2 20:16 = 31, op3 15:10, Rn, op4 4:0 */
#define BR(opc, op3, op4) (FLD(24, 21, opc) | FLD(20, 16, 31) | FLD(15, 10, op3) | FLD(4, 0, op4))
#define RN31 FLD(9, 5, 31)
static const struct gt_arm64_row rw_breg[] = {
	ROW(I(BR), 0, BR(0, 0, 0)), ROW(I(BLR), 0, BR(1, 0, 0)), ROW(I(RET), 0, BR(2, 0, 0)),
	ROW(I(ERET), 0, BR(4, 0, 0) | RN31), ROW(I(DRPS), 0, BR(5, 0, 0) | RN31),
	/* FEAT_PAuth: op3 2 is key A, 3 is key B */
	ROW(I(BRAAZ), 0, BR(0, 2, 31)), ROW(I(BRABZ), 0, BR(0, 3, 31)),
	ROW(I(BLRAAZ), 0, BR(1, 2, 31)), ROW(I(BLRABZ), 0, BR(1, 3, 31)),
	ROW(I(BRAA), 0, FLD(24, 21, 8) | FLD(20, 16, 31) | FLD(15, 10, 2)),
	ROW(I(BRAB), 0, FLD(24, 21, 8) | FLD(20, 16, 31) | FLD(15, 10, 3)),
	ROW(I(BLRAA), 0, FLD(24, 21, 9) | FLD(20, 16, 31) | FLD(15, 10, 2)),
	ROW(I(BLRAB), 0, FLD(24, 21, 9) | FLD(20, 16, 31) | FLD(15, 10, 3)),
	ROW(I(RETAA), 0, BR(2, 2, 31) | RN31), ROW(I(RETAB), 0, BR(2, 3, 31) | RN31),
	ROW(I(ERETAA), 0, BR(4, 2, 31) | RN31), ROW(I(ERETAB), 0, BR(4, 3, 31) | RN31),
	LAST(INVALID)
};
#undef BR
#undef RN31
static const struct gt_arm64_row *const bk_BREG[1] = { rw_breg };
static const struct gt_arm64_node n_BREG = { 0, 0, 0, 0, 0, bk_BREG };

/* ---- data processing, register -------------------------------------------------- */

/*
 * Bits 28..25 = 0101 (bit 28 clear): logical and add/subtract, shifted or extended
 * register, indexed by bit 24 (add/sub) and bit 21 (N of a logical; extended of an
 * add/sub). The 32-bit forms have no shift amount of 32 or more (imm6 bit 5 =
 * bit 15).
 */
#define LOGROWS(a, b, c, d) \
	ROW(I(INVALID), 0, B(31, 0) | B(15, 1)), \
	ROW(I(a), 0, FLD(30, 29, 0)), ROW(I(b), 0, FLD(30, 29, 1)), \
	ROW(I(c), 0, FLD(30, 29, 2)), LAST(d)
static const struct gt_arm64_row rw_logic0[] = { LOGROWS(AND_REG, ORR_REG, EOR_REG, ANDS_REG) };
static const struct gt_arm64_row rw_logic1[] = { LOGROWS(BIC_REG, ORN_REG, EON_REG, BICS_REG) };
/* shifted add/sub: shift 3 is unallocated */
static const struct gt_arm64_row rw_addsub_sh[] = {
	ROW(I(INVALID), 0, FLD(23, 22, 3)),
	ROW(I(INVALID), 0, B(31, 0) | B(15, 1)),
	ROW(I(ADD_REG), 0, FLD(30, 29, 0)), ROW(I(ADDS_REG), 0, FLD(30, 29, 1)),
	ROW(I(SUB_REG), 0, FLD(30, 29, 2)), LAST(SUBS_REG)
};
/* extended add/sub: bits 23:22 must be 0 and the left shift imm3 (12:10) at most 4 */
static const struct gt_arm64_row rw_addsub_ext[] = {
	ROW(I(INVALID), 0, B(23, 1)), ROW(I(INVALID), 0, B(22, 1)),
	ROW(I(INVALID), 0, B(12, 1) | B(11, 1)), ROW(I(INVALID), 0, B(12, 1) | B(10, 1)),
	ROW(I(ADD_EXT), 0, FLD(30, 29, 0)), ROW(I(ADDS_EXT), 0, FLD(30, 29, 1)),
	ROW(I(SUB_EXT), 0, FLD(30, 29, 2)), LAST(SUBS_EXT)
};
static const struct gt_arm64_row *const bk_DPREG5[4] = {
	rw_logic0, rw_addsub_sh, rw_logic1, rw_addsub_ext
};
static const struct gt_arm64_node n_DPREG5 = { 24, 1, 21, 1, 1, bk_DPREG5 };

/*
 * Bits 28..25 = 1101 (bit 28 set), indexed by bit 24 and bits 23:21. With bit 24
 * set it is the three-source group: op54 (30:29) must be 0; the 32-bit form has
 * only madd and msub; op31 3, 4 and 7 are unallocated; smulh and umulh have o0 0.
 */
#define MUL3(a, b, wide) \
	ROW(I(INVALID), 0, B(30, 1)), ROW(I(INVALID), 0, B(29, 1)), \
	wide ROW(I(a), 0, B(15, 0)), LAST(b)
#define W64 ROW(I(INVALID), 0, B(31, 0)),
static const struct gt_arm64_row rw_mul0[] = { MUL3(MADD, MSUB, ) };
static const struct gt_arm64_row rw_mul1[] = { MUL3(SMADDL, SMSUBL, W64) };
static const struct gt_arm64_row rw_mul5[] = { MUL3(UMADDL, UMSUBL, W64) };
static const struct gt_arm64_row rw_mul2[] = {
	ROW(I(INVALID), 0, B(30, 1)), ROW(I(INVALID), 0, B(29, 1)), W64
	ROW(I(INVALID), 0, B(15, 1)), LAST(SMULH)
};
static const struct gt_arm64_row rw_mul6[] = {
	ROW(I(INVALID), 0, B(30, 1)), ROW(I(INVALID), 0, B(29, 1)), W64
	ROW(I(INVALID), 0, B(15, 1)), LAST(UMULH)
};
#undef MUL3
#undef W64

/*
 * Bit 24 clear, bits 23:21 = 000: add/subtract with carry, and the flag
 * manipulation setf8, setf16 (FEAT_FlagM) and rmif that share its space with
 * S = 1 and a non-zero imm6; 010: conditional compare; 100: conditional select.
 */
static const struct gt_arm64_row rw_adc[] = {
	{ 0xfffffc1fu, 0x3a00080du, I(SETF8), 0 },
	{ 0xfffffc1fu, 0x3a00480du, I(SETF16), 0 },
	{ 0xffe07c10u, 0xba000400u, I(RMIF), 0 },
	ROW(I(ADC), 0, FLD(15, 10, 0) | FLD(30, 29, 0)), ROW(I(ADCS), 0, FLD(15, 10, 0) | FLD(30, 29, 1)),
	ROW(I(SBC), 0, FLD(15, 10, 0) | FLD(30, 29, 2)), ROW(I(SBCS), 0, FLD(15, 10, 0) | FLD(30, 29, 3)),
	LAST(INVALID)
};
/* S must be 1, and bits 10 and 4 are o2 and o3 = 0; bit 11 selects the immediate form */
#define CCM(id, op, imm) ROW(I(id), 0, B(29, 1) | B(10, 0) | B(4, 0) | B(30, op) | B(11, imm))
static const struct gt_arm64_row rw_ccmp[] = {
	CCM(CCMN_REG, 0, 0), CCM(CCMN_IMM, 0, 1), CCM(CCMP_REG, 1, 0), CCM(CCMP_IMM, 1, 1),
	LAST(INVALID)
};
#undef CCM
/* S must be 0 and op2 (11:10) at most 1 */
#define CSL(id, op, o2) ROW(I(id), 0, B(29, 0) | B(11, 0) | B(30, op) | B(10, o2))
static const struct gt_arm64_row rw_csel[] = {
	CSL(CSEL, 0, 0), CSL(CSINC, 0, 1), CSL(CSINV, 1, 0), CSL(CSNEG, 1, 1), LAST(INVALID)
};
#undef CSL

/* bits 23:21 = 110: one source (bit 30 set) and two source. Registers named by opcode (15:10), opcode2 (20:16). */
#define O2(v) FLD(20, 16, v)
#define OPC(v) FLD(15, 10, v)
#define PAC1(id, v) ROW(I(id), 0, O2(1) | B(31, 1) | OPC(v))
#define PACZ(id, v) ROW(I(id), 0, O2(1) | B(31, 1) | OPC(v) | FLD(9, 5, 31))
static const struct gt_arm64_row rw_dp1[] = {
	ROW(I(INVALID), 0, B(29, 1)),
	ROW(I(CLZ), 0, O2(0) | OPC(4)), ROW(I(REV), 0, O2(0) | OPC(2)),
	ROW(I(RBIT), 0, O2(0) | OPC(0)), ROW(I(REV16), 0, O2(0) | OPC(1)),
	ROW(I(REV64), 0, O2(0) | OPC(3) | B(31, 1)), ROW(I(CLS), 0, O2(0) | OPC(5)),
	PAC1(PACIA, 0), PAC1(PACIB, 1), PAC1(PACDA, 2), PAC1(PACDB, 3),
	PAC1(AUTIA, 4), PAC1(AUTIB, 5), PAC1(AUTDA, 6), PAC1(AUTDB, 7),
	PACZ(PACIZA, 8), PACZ(PACIZB, 9), PACZ(PACDZA, 10), PACZ(PACDZB, 11),
	PACZ(AUTIZA, 12), PACZ(AUTIZB, 13), PACZ(AUTDZA, 14), PACZ(AUTDZB, 15),
	PACZ(XPACI, 16), PACZ(XPACD, 17),
	LAST(INVALID)
};
#undef PAC1
#undef PACZ
#undef O2
/* S set is subps only; the shifts and divides first, being the common ones */
static const struct gt_arm64_row rw_dp2[] = {
	ROW(I(SUBPS), 0, B(29, 1) | B(31, 1) | OPC(0)),
	ROW(I(INVALID), 0, B(29, 1)),
	ROW(I(LSLV), 0, OPC(8)), ROW(I(LSRV), 0, OPC(9)), ROW(I(ASRV), 0, OPC(10)),
	ROW(I(RORV), 0, OPC(11)), ROW(I(UDIV), 0, OPC(2)), ROW(I(SDIV), 0, OPC(3)),
	ROW(I(SUBP), 0, B(31, 1) | OPC(0)), ROW(I(IRG), 0, B(31, 1) | OPC(4)),
	ROW(I(GMI), 0, B(31, 1) | OPC(5)), ROW(I(PACGA), 0, B(31, 1) | OPC(12)),
	/* crc32: the X form (sf 1) is the one with sz 3, the others are the 32-bit form */
	ROW(I(CRC32X), 0, B(31, 1) | OPC(19)), ROW(I(CRC32CX), 0, B(31, 1) | OPC(23)),
	ROW(I(CRC32B), 0, B(31, 0) | OPC(16)), ROW(I(CRC32H), 0, B(31, 0) | OPC(17)),
	ROW(I(CRC32W), 0, B(31, 0) | OPC(18)), ROW(I(CRC32CB), 0, B(31, 0) | OPC(20)),
	ROW(I(CRC32CH), 0, B(31, 0) | OPC(21)), ROW(I(CRC32CW), 0, B(31, 0) | OPC(22)),
	LAST(INVALID)
};
#undef OPC
static const struct gt_arm64_row *const bk_DP12[2] = { rw_dp2, rw_dp1 };
static const struct gt_arm64_node n_DP12 = { 30, 1, 0, 0, 0, bk_DP12 };

/* key: bit 24, then bits 23:21 above it */
static const struct gt_arm64_row *const bk_DPREGD[16] = {
	[0] = rw_adc, [4] = rw_ccmp, [8] = rw_csel, [12] = ONE(NODE_DP12),
	[2] = rw_inv, [6] = rw_inv, [10] = rw_inv, [14] = rw_inv,
	[1] = rw_mul0, [3] = rw_mul1, [5] = rw_mul2, [7] = rw_inv,
	[9] = rw_inv, [11] = rw_mul5, [13] = rw_mul6, [15] = rw_inv
};
static const struct gt_arm64_node n_DPREGD = { 24, 1, 21, 7, 1, bk_DPREGD };

/* ---- loads and stores ----------------------------------------------------------- */

/*
 * EXCLUSIVE, ORDERED, COMPARE-AND-SWAP (bits 28..24 = 01000 with V 0, bit 29 0),
 * indexed by bits 23:21 = o2 L o1. size is bits 31:30; with o2 0 and o1 1 a size
 * of 2 or 3 is the pair exclusive, a smaller one is casp, which takes even Rs and Rt.
 */
static const struct gt_arm64_row rw_stxp[] = {
	ROW(I(STXP), 0, B(31, 1)), ROW(I(INVALID), 0, B(16, 1)), ROW(I(INVALID), 0, B(0, 1)), LAST(CASP)
};
static const struct gt_arm64_row rw_ldxp[] = {
	ROW(I(LDXP), 0, B(31, 1)), ROW(I(INVALID), 0, B(16, 1)), ROW(I(INVALID), 0, B(0, 1)), LAST(CASP)
};
static const struct gt_arm64_row *const bk_EXCL[16] = {
	ONEI(STXR), rw_stxp, ONEI(LDXR), rw_ldxp, ONEI(STLR), ONEI(CAS), ONEI(LDAR), ONEI(CAS),
	rw_inv, rw_inv, rw_inv, rw_inv, rw_inv, rw_inv, rw_inv, rw_inv
};
static const struct gt_arm64_node n_EXCL = { 21, 7, 24, 1, 3, bk_EXCL };

/*
 * ADVANCED SIMD LOAD/STORE STRUCTURES (V 1, bits 29:28 00), indexed by bit 24
 * (single structure) and, for multiple structures, opcode (15:12): 0 2 4 6 7 8
 * 10 are allocated. Bit 31 must be 0, bit 21 clear for multiple structures, and
 * Rm (20:16) zero unless bit 23 makes it the post-index form.
 */
static const struct gt_arm64_row rw_sm[] = {
	ROW(I(INVALID), 0, B(31, 1)), ROW(I(INVALID), 0, B(21, 1)),
	ROW(I(SIMD_STRUCT_MULT), 0, B(23, 0) | FLD(20, 16, 0)),
	ROW(I(INVALID), 0, B(23, 0)), LAST(SIMD_STRUCT_MULT_POST)
};
static const struct gt_arm64_row rw_ss[] = {
	ROW(I(INVALID), 0, B(31, 1)),
	ROW(I(SIMD_STRUCT_SINGLE), 0, B(23, 0) | FLD(20, 16, 0)),
	ROW(I(INVALID), 0, B(23, 0)), LAST(SIMD_STRUCT_SINGLE_POST)
};
static const struct gt_arm64_row *const bk_SIMDSTRUCT[32] = {
	[0] = rw_sm, [4] = rw_sm, [8] = rw_sm, [12] = rw_sm, [14] = rw_sm, [16] = rw_sm, [20] = rw_sm,
	[2] = rw_inv, [6] = rw_inv, [10] = rw_inv, [18] = rw_inv, [22] = rw_inv, [24] = rw_inv,
	[26] = rw_inv, [28] = rw_inv, [30] = rw_inv,
	[1] = rw_ss, [3] = rw_ss, [5] = rw_ss, [7] = rw_ss, [9] = rw_ss, [11] = rw_ss, [13] = rw_ss,
	[15] = rw_ss, [17] = rw_ss, [19] = rw_ss, [21] = rw_ss, [23] = rw_ss, [25] = rw_ss,
	[27] = rw_ss, [29] = rw_ss, [31] = rw_ss
};
static const struct gt_arm64_node n_SIMDSTRUCT = { 24, 1, 12, 15, 1, bk_SIMDSTRUCT };

/*
 * LITERAL AND THE UNSCALED-LIKE FORMS OF THE 011 GROUP (bits 29:28 01), by bit 24.
 * Bit 24 clear is a literal load, opc (31:30) selecting it. Bit 24 set holds
 * FEAT_MOPS (size 0, bit 21 clear, bits 11:10 01: copy, or set with op1 3 whose
 * option nibble stops at 11), the memory-tag instructions (top byte 0xd9, bit 21
 * set; general registers only) and the unscaled RCPC forms stlur and ldapur
 * (bit 21 clear, bits 11:10 00; general registers only).
 */
#define MOPSM (FLD(31, 30, 0) | B(21, 0) | FLD(11, 10, 1))
#define MOPSROWS \
	ROW(I(INVALID), 0, MOPSM | FLD(23, 22, 3) | FLD(15, 14, 3)), \
	ROW(I(MOPS_SET), 0, MOPSM | FLD(23, 22, 3)), ROW(I(MOPS_CPY), 0, MOPSM)
static const struct gt_arm64_row rw_lit_g[] = {
	ROW(I(LDR_LIT_W), 0, FLD(31, 30, 0)), ROW(I(LDR_LIT_X), 0, FLD(31, 30, 1)),
	ROW(I(LDRSW_LIT), 0, FLD(31, 30, 2)), LAST(PRFM_LIT)
};
static const struct gt_arm64_row rw_lit_f[] = {
	ROW(I(INVALID), 0, FLD(31, 30, 3)), LAST(LDR_LIT_FP)
};
static const struct gt_arm64_row rw_lit0_hi[] = {
	MOPSROWS,
	ROW(NODE_TAGS, 0, FLD(31, 24, 0xd9) | B(21, 1)),
	ROW(NODE_RCPC, 0, B(21, 0) | FLD(11, 10, 0)),
	LAST(INVALID)
};
static const struct gt_arm64_row rw_lit1_hi[] = { MOPSROWS, LAST(INVALID) };
#undef MOPSROWS
#undef MOPSM
static const struct gt_arm64_row *const bk_LIT0[2] = { rw_lit_g, rw_lit0_hi };
static const struct gt_arm64_node n_LIT0 = { 24, 1, 0, 0, 0, bk_LIT0 };
static const struct gt_arm64_row *const bk_LIT1[2] = { rw_lit_f, rw_lit1_hi };
static const struct gt_arm64_node n_LIT1 = { 24, 1, 0, 0, 0, bk_LIT1 };

/* Memory tags (FEAT_MTE): op2 (11:10) 0 is the register-offset-free family, 1 post, 2 offset, 3 pre */
#define TG(op2, opc) FLD(11, 10, op2) | FLD(23, 22, opc)
static const struct gt_arm64_row rw_tags[] = {
	ROW(I(LDG), 0, TG(0, 1)),
	ROW(I(STZGM), 0, TG(0, 0) | FLD(20, 12, 0)), ROW(I(STGM), 0, TG(0, 2) | FLD(20, 12, 0)),
	ROW(I(LDGM), 0, TG(0, 3) | FLD(20, 12, 0)),
	ROW(I(INVALID), 0, FLD(11, 10, 0)),
	ROW(I(STG_POST), 0, TG(1, 0)), ROW(I(STG_OFF), 0, TG(2, 0)), ROW(I(STG_PRE), 0, TG(3, 0)),
	ROW(I(STZG_POST), 0, TG(1, 1)), ROW(I(STZG_OFF), 0, TG(2, 1)), ROW(I(STZG_PRE), 0, TG(3, 1)),
	ROW(I(ST2G_POST), 0, TG(1, 2)), ROW(I(ST2G_OFF), 0, TG(2, 2)), ROW(I(ST2G_PRE), 0, TG(3, 2)),
	ROW(I(STZ2G_POST), 0, TG(1, 3)), ROW(I(STZ2G_OFF), 0, TG(2, 3)), LAST(STZ2G_PRE)
};
#undef TG
static const struct gt_arm64_row *const bk_TAGS[1] = { rw_tags };
static const struct gt_arm64_node n_TAGS = { 0, 0, 0, 0, 0, bk_TAGS };

/*
 * THE SINGLE-REGISTER LOAD/STORE KINDS. What (size, opc, V) name is the same
 * table in every address form; the forms differ in which of the seven results
 * exist (prfm needs an unsigned, unscaled or register offset; floating point
 * and prfm have no unprivileged or acquire-release form). Key: opc (23:22) with
 * size (31:30) above it. For V 0: opc 0 store, 1 load, 2 sign-extending load
 * into X (size 0..2) or prfm (size 3), 3 sign-extending load into W (size 0..1).
 * For V 1: opc 0 and 1 store and load of a B, H, S or D register; opc 2 and 3
 * with size 0 are the Q register.
 */
#define LSG(st, ld, s64, s32, pf) \
	ONEI(st), ONEI(ld), ONEI(s64), ONEI(s32), \
	ONEI(st), ONEI(ld), ONEI(s64), ONEI(s32), \
	ONEI(st), ONEI(ld), ONEI(s64), rw_inv, \
	ONEI(st), ONEI(ld), ONEI(pf), rw_inv
#define LSF(st, ld) \
	ONEI(st), ONEI(ld), ONEI(st), ONEI(ld), \
	ONEI(st), ONEI(ld), rw_inv, rw_inv, \
	ONEI(st), ONEI(ld), rw_inv, rw_inv, \
	ONEI(st), ONEI(ld), rw_inv, rw_inv
static const struct gt_arm64_row *const bk_UOFF_0[16] = { LSG(STR_UOFF, LDR_UOFF, LDRS64_UOFF, LDRS32_UOFF, PRFM_UOFF) };
static const struct gt_arm64_row *const bk_UOFF_1[16] = { LSF(STR_FP_UOFF, LDR_FP_UOFF) };
static const struct gt_arm64_row *const bk_UNSC_0[16] = { LSG(STUR, LDUR, LDURS64, LDURS32, PRFUM) };
static const struct gt_arm64_row *const bk_UNSC_1[16] = { LSF(STUR_FP, LDUR_FP) };
static const struct gt_arm64_row *const bk_POST_0[16] = { LSG(STR_POST, LDR_POST, LDRS64_POST, LDRS32_POST, INVALID) };
static const struct gt_arm64_row *const bk_POST_1[16] = { LSF(STR_FP_POST, LDR_FP_POST) };
static const struct gt_arm64_row *const bk_PRE_0[16] = { LSG(STR_PRE, LDR_PRE, LDRS64_PRE, LDRS32_PRE, INVALID) };
static const struct gt_arm64_row *const bk_PRE_1[16] = { LSF(STR_FP_PRE, LDR_FP_PRE) };
static const struct gt_arm64_row *const bk_UNPRIV_0[16] = { LSG(STTR, LDTR, LDTRS64, LDTRS32, INVALID) };
static const struct gt_arm64_row *const bk_REG_0[16] = { LSG(STR_REG, LDR_REG, LDRS64_REG, LDRS32_REG, PRFM_REG) };
static const struct gt_arm64_row *const bk_REG_1[16] = { LSF(STR_FP_REG, LDR_FP_REG) };
#define KEY_SO 22, 3, 30, 3, 2
static const struct gt_arm64_node n_UOFF_0 = { KEY_SO, bk_UOFF_0 };
static const struct gt_arm64_node n_UOFF_1 = { KEY_SO, bk_UOFF_1 };
static const struct gt_arm64_node n_UNSC_0 = { KEY_SO, bk_UNSC_0 };
static const struct gt_arm64_node n_UNSC_1 = { KEY_SO, bk_UNSC_1 };
static const struct gt_arm64_node n_POST_0 = { KEY_SO, bk_POST_0 };
static const struct gt_arm64_node n_POST_1 = { KEY_SO, bk_POST_1 };
static const struct gt_arm64_node n_PRE_0 = { KEY_SO, bk_PRE_0 };
static const struct gt_arm64_node n_PRE_1 = { KEY_SO, bk_PRE_1 };
static const struct gt_arm64_node n_UNPRIV_0 = { KEY_SO, bk_UNPRIV_0 };
static const struct gt_arm64_node n_REG_0 = { KEY_SO, bk_REG_0 };
static const struct gt_arm64_node n_REG_1 = { KEY_SO, bk_REG_1 };
/* stlur, ldapur: no prfm, no floating point */
static const struct gt_arm64_row *const bk_RCPC[16] = {
	ONEI(STLUR), ONEI(LDAPUR), ONEI(LDAPURS64), ONEI(LDAPURS32),
	ONEI(STLUR), ONEI(LDAPUR), ONEI(LDAPURS64), ONEI(LDAPURS32),
	ONEI(STLUR), ONEI(LDAPUR), ONEI(LDAPURS64), rw_inv,
	ONEI(STLUR), ONEI(LDAPUR), rw_inv, rw_inv
};
static const struct gt_arm64_node n_RCPC = { KEY_SO, bk_RCPC };
#undef KEY_SO
#undef LSG
#undef LSF

/* ldraa, ldrab (FEAT_PAuth): size 3 and V 0; bit 23 is the key, bit 11 the writeback */
static const struct gt_arm64_row rw_ldra[] = {
	ROW(I(INVALID), 0, B(31, 0)), ROW(I(INVALID), 0, B(30, 0)),
	ROW(I(LDRAA), 0, B(23, 0)), LAST(LDRAB)
};
static const struct gt_arm64_row rw_ldra_pre[] = {
	ROW(I(INVALID), 0, B(31, 0)), ROW(I(INVALID), 0, B(30, 0)),
	ROW(I(LDRAA_PRE), 0, B(23, 0)), LAST(LDRAB_PRE)
};

/*
 * Atomic memory operations (bit 21 set, bits 11:10 00, V 0), by o3 (bit 15) and
 * op (14:12): o3 0 is the eight ldadd.. forms, o3 1 swp, ldapr, and FEAT_LS64
 * ld64b, st64b, st64bv0, st64bv. LS64 needs size 3, A and R clear, and the
 * data registers an even run ending at or before x29 (Rt even and at most 22,
 * which is what a reference decoder was seen to accept).
 */
#define LS64(id) \
	ROW(I(INVALID), 0, B(31, 0)), ROW(I(INVALID), 0, B(30, 0)), \
	ROW(I(INVALID), 0, B(23, 1)), ROW(I(INVALID), 0, B(22, 1)), \
	ROW(I(INVALID), 0, B(0, 1)), ROW(I(INVALID), 0, B(4, 1) | B(3, 1)), LAST(id)
static const struct gt_arm64_row rw_st64b[] = { LS64(ST64B) };
static const struct gt_arm64_row rw_st64bv0[] = { LS64(ST64BV0) };
static const struct gt_arm64_row rw_st64bv[] = { LS64(ST64BV) };
static const struct gt_arm64_row rw_ld64b[] = { LS64(LD64B) };
#undef LS64
static const struct gt_arm64_row rw_ldapr[] = { ROW(I(LDAPR), 0, B(23, 1) | B(22, 0)), LAST(INVALID) };
static const struct gt_arm64_row *const bk_ATOMIC[16] = {
	ONEI(LDADD), ONEI(SWP), ONEI(LDCLR), rw_st64b, ONEI(LDEOR), rw_st64bv0,
	ONEI(LDSET), rw_st64bv, ONEI(LDSMAX), rw_ldapr, ONEI(LDSMIN), rw_ld64b,
	ONEI(LDUMAX), rw_inv, ONEI(LDUMIN), rw_inv
};
static const struct gt_arm64_node n_ATOMIC = { 15, 1, 12, 7, 1, bk_ATOMIC };

/*
 * The 111 group with bit 24 clear, by bit 21 and bits 11:10:
 *   bit 21 0: the unscaled, post-index, unprivileged and pre-index forms (11:10 = 00, 01, 10, 11)
 *   bit 21 1: 00 atomics, 01 and 11 ldraa/ldrab, 10 register offset (option bit 1, bit 14, must be set)
 */
static const struct gt_arm64_row rw_regoff_0[] = { ROW(I(INVALID), 0, B(14, 0)), ROW(NODE_REG_0, 0, 0) };
static const struct gt_arm64_row rw_regoff_1[] = { ROW(I(INVALID), 0, B(14, 0)), ROW(NODE_REG_1, 0, 0) };
static const struct gt_arm64_row *const bk_LSREG_0[8] = {
	GO(UNSC_0), GO(ATOMIC), GO(POST_0), rw_ldra, GO(UNPRIV_0), rw_regoff_0, GO(PRE_0), rw_ldra_pre
};
static const struct gt_arm64_node n_LSREG_0 = { 21, 1, 10, 3, 1, bk_LSREG_0 };
static const struct gt_arm64_row *const bk_LSREG_1[8] = {
	GO(UNSC_1), rw_inv, GO(POST_1), rw_inv, rw_inv, rw_regoff_1, GO(PRE_1), rw_inv
};
static const struct gt_arm64_node n_LSREG_1 = { 21, 1, 10, 3, 1, bk_LSREG_1 };
/* the 111 group (bits 29:28 11): bit 24 set is the unsigned offset, clear the forms above */
static const struct gt_arm64_row *const bk_LS3_0[2] = { ONE(NODE_LSREG_0), ONE(NODE_UOFF_0) };
static const struct gt_arm64_node n_LS3_0 = { 24, 1, 0, 0, 0, bk_LS3_0 };
static const struct gt_arm64_row *const bk_LS3_1[2] = { ONE(NODE_LSREG_1), ONE(NODE_UOFF_1) };
static const struct gt_arm64_node n_LS3_1 = { 24, 1, 0, 0, 0, bk_LS3_1 };

/*
 * PAIRS (bits 29:28 10): opc (31:30), then bits 24:22 = the form (0 no-allocate,
 * 1 post-index, 2 offset, 3 pre-index) and L. opc 3 is unallocated; for V 0, opc
 * 1 is stgp and ldpsw (FEAT_MTE for stgp), which have no no-allocate form; for
 * V 1 opc 0..2 is the S, D and Q register.
 */
#define P8(a, b, c, d, e, f, g, h) ONEI(a), ONEI(b), ONEI(c), ONEI(d), ONEI(e), ONEI(f), ONEI(g), ONEI(h)
#define PINV rw_inv, rw_inv, rw_inv, rw_inv, rw_inv, rw_inv, rw_inv, rw_inv
static const struct gt_arm64_row *const bk_PAIR0[32] = {
	P8(STNP, LDNP, STP_POST, LDP_POST, STP_OFF, LDP_OFF, STP_PRE, LDP_PRE),
	rw_inv, rw_inv, ONEI(STGP_POST), ONEI(LDPSW_POST), ONEI(STGP_OFF), ONEI(LDPSW_OFF),
	ONEI(STGP_PRE), ONEI(LDPSW_PRE),
	P8(STNP, LDNP, STP_POST, LDP_POST, STP_OFF, LDP_OFF, STP_PRE, LDP_PRE),
	PINV
};
static const struct gt_arm64_row *const bk_PAIR1[32] = {
	P8(STNP_FP, LDNP_FP, STP_FP_POST, LDP_FP_POST, STP_FP_OFF, LDP_FP_OFF, STP_FP_PRE, LDP_FP_PRE),
	P8(STNP_FP, LDNP_FP, STP_FP_POST, LDP_FP_POST, STP_FP_OFF, LDP_FP_OFF, STP_FP_PRE, LDP_FP_PRE),
	P8(STNP_FP, LDNP_FP, STP_FP_POST, LDP_FP_POST, STP_FP_OFF, LDP_FP_OFF, STP_FP_PRE, LDP_FP_PRE),
	PINV
};
#undef P8
#undef PINV
static const struct gt_arm64_node n_PAIR0 = { 22, 7, 30, 3, 3, bk_PAIR0 };
static const struct gt_arm64_node n_PAIR1 = { 22, 7, 30, 3, 3, bk_PAIR1 };

/* ---- the first index and the node list --------------------------------------------- */

#define BOTH(g, p) [g] = (p), [(g) + 16] = (p)
static const struct gt_arm64_row *const bk_top[32] = {
	BOTH(0x0, rw_res), BOTH(0x1, rw_inv), BOTH(0x3, rw_inv),
	BOTH(0x2, GO(SVE)),
	[0x4] = GO(EXCL), [0x14] = GO(PAIR0),
	BOTH(0x5, GO(DPREG5)),
	[0x6] = GO(SIMDSTRUCT), [0x16] = GO(PAIR1),
	BOTH(0x7, ONE(NODE_FP7)),
	BOTH(0x8, GO(DPIMM)), BOTH(0x9, GO(DPIMM)),
	BOTH(0xa, GO(BR_A)), BOTH(0xb, GO(BR_B)),
	[0xc] = GO(LIT0), [0x1c] = GO(LS3_0),
	BOTH(0xd, GO(DPREGD)),
	[0xe] = GO(LIT1), [0x1e] = GO(LS3_1),
	BOTH(0xf, GO(FPF))
};
#undef BOTH
const struct gt_arm64_node gt_arm64_top = { 25, 31, 0, 0, 0, bk_top };

/* group 7 and f lists are plain rows, wrapped as nodes so the walk has one shape */
static const struct gt_arm64_row *const bk_FP7[1] = { rw_fp7 };
static const struct gt_arm64_node n_FP7 = { 0, 0, 0, 0, 0, bk_FP7 };
static const struct gt_arm64_row *const bk_FPF[1] = { rw_fpf };
static const struct gt_arm64_node n_FPF = { 0, 0, 0, 0, 0, bk_FPF };

const struct gt_arm64_node *const gt_arm64_nodes[] = {
#define X(n) &n_##n,
	GT_ARM64_NODE_LIST(X)
#undef X
};

/* ---- names and attributes, from the identity list ---------------------------------- */

const char *const gt_arm64_names[GT_ARM64_I_COUNT] = {
#define X(n, k, a) #n,
	GT_ARM64_ID_LIST(X)
#undef X
};

const uint8_t gt_arm64_lsk[GT_ARM64_I_COUNT] = {
#define X(n, k, a) GT_ARM64_K_##k,
	GT_ARM64_ID_LIST(X)
#undef X
};

const uint8_t gt_arm64_am[GT_ARM64_I_COUNT] = {
#define X(n, k, a) GT_ARM64_AM_##a,
	GT_ARM64_ID_LIST(X)
#undef X
};
