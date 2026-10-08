/*
 * arm64_ids.h - the instruction identities the AArch64 (A64 instruction set,
 * Armv8-A and the extensions up to Armv9.x that the decoder knows) table can
 * answer with.
 *
 * ONE LIST, THREE USES. GT_ARM64_ID_LIST names every identity once, with the two
 * attributes a consumer needs from the identity alone - what a load or store
 * does with its data register (`kind`) and how it forms its address (`amode`).
 * The enum below, the attribute table in arm64_tab.c and the names the unit
 * test prints are all expanded from it, so an identity cannot be added to one
 * and forgotten in another.
 *
 * GRANULARITY. An identity is a MNEMONIC IN ONE ENCODING FORM where the two
 * differ in what they do to registers or memory: `LDR` with an unsigned offset,
 * with a post-index, with a register offset are different identities, because
 * they are different rows of the table and write different registers. Where
 * the architecture separates mnemonics by a field that nothing reads (ldxr and
 * ldaxr differ in bit 15, ldadd and ldadda in bit 23) they are ONE identity and
 * the field is read from the word. The same for the width: `ldr w0` and
 * `ldr x0` are the identity LDR_* and `size` says which. Scalar floating point,
 * Advanced SIMD, SVE and SME are NOT decomposed to mnemonics: they are the
 * identity FPSIMD, SVE or SME, plus the few rows that write a general register
 * (see arm64.h, THE VECTOR SPACES).
 *
 * The ORDER matters in two places and the comments say where: the branches,
 * whose offset width is read from the identity's range, and the first two
 * (INVALID, UDF), which are what "not an instruction" looks like.
 */
#ifndef KOF_GENOTYPE_ARM64_IDS_H
#define KOF_GENOTYPE_ARM64_IDS_H

/* What a load or store does with its data register. */
enum gt_arm64_lskind {
	GT_ARM64_K_NONE,
	GT_ARM64_K_STORE,       /* store Xt/Wt                                     */
	GT_ARM64_K_LOAD,        /* load Xt/Wt of the access size (4 or 8 bytes in the register) */
	GT_ARM64_K_LOAD_S64,    /* load a byte, halfword or word, sign-extended into Xt */
	GT_ARM64_K_LOAD_S32,    /* load a byte or halfword, sign-extended into Wt */
	GT_ARM64_K_PREFETCH,    /* prfm: reads memory's address, writes nothing     */
	GT_ARM64_K_STORE_FP,    /* store a scalar floating point / SIMD register    */
	GT_ARM64_K_LOAD_FP
};

/* How a load or store forms its address. */
enum gt_arm64_amode {
	GT_ARM64_AM_NONE,       /* [Xn]                                            */
	GT_ARM64_AM_OFFSET,     /* [Xn, #imm]: unsigned scaled, or signed for a pair or a tag */
	GT_ARM64_AM_UNSCALED,   /* [Xn, #simm9]                                    */
	GT_ARM64_AM_POST,       /* [Xn], #imm - Xn is written                      */
	GT_ARM64_AM_PRE,        /* [Xn, #imm]! - Xn is written                     */
	GT_ARM64_AM_UNPRIV,     /* ldtr/sttr: unscaled, as if at EL0               */
	GT_ARM64_AM_REG,        /* [Xn, Xm{, extend {#amount}}]                    */
	GT_ARM64_AM_LIT,        /* PC-relative literal                             */
	GT_ARM64_AM_NOALLOC     /* ldnp/stnp: signed scaled offset, non-temporal   */
};

#define GT_ARM64_ID_LIST(X) \
	/* what an undecodable word is: INVALID is unallocated, UDF is the permanently undefined udf #imm16 */ \
	X(INVALID, NONE, NONE) X(UDF, NONE, NONE) \
	/* SME (bit 31 set in the 0000 group): valid, writes no general register */ \
	X(SME, NONE, NONE) \
	/* SVE: SVE is every word of its space that no row below names; the rest write a general register */ \
	X(SVE, NONE, NONE) X(ADDVL, NONE, NONE) X(ADDPL, NONE, NONE) X(RDVL, NONE, NONE) \
	X(CNTELEM, NONE, NONE) X(INCDECELEM, NONE, NONE) X(SQINCDECELEM, NONE, NONE) \
	X(CNTP, NONE, NONE) X(INCDECP, NONE, NONE) X(SQINCDECP, NONE, NONE) \
	X(LASTAB, NONE, NONE) X(CLASTAB, NONE, NONE) \
	/* scalar floating point and Advanced SIMD */ \
	X(FPSIMD, NONE, NONE) \
	X(FCVTS_GP, NONE, NONE) X(FCVTU_GP, NONE, NONE) X(SCVTF_GP, NONE, NONE) \
	X(UCVTF_GP, NONE, NONE) X(FCVTAS_GP, NONE, NONE) X(FCVTAU_GP, NONE, NONE) \
	X(FMOV_FP_TO_GP, NONE, NONE) X(FMOV_GP_TO_FP, NONE, NONE) X(FJCVTZS, NONE, NONE) \
	X(FMOV_TOP_TO_GP, NONE, NONE) X(FMOV_TOP_FROM_GP, NONE, NONE) \
	X(FCVTZS_FIXED, NONE, NONE) X(FCVTZU_FIXED, NONE, NONE) \
	X(SCVTF_FIXED, NONE, NONE) X(UCVTF_FIXED, NONE, NONE) \
	X(SMOV, NONE, NONE) X(UMOV, NONE, NONE) \
	/* data processing, immediate */ \
	X(ADR, NONE, NONE) X(ADRP, NONE, NONE) \
	X(ADD_IMM, NONE, NONE) X(ADDS_IMM, NONE, NONE) X(SUB_IMM, NONE, NONE) X(SUBS_IMM, NONE, NONE) \
	X(SMAX_IMM, NONE, NONE) X(UMAX_IMM, NONE, NONE) X(SMIN_IMM, NONE, NONE) X(UMIN_IMM, NONE, NONE) \
	X(ADDG, NONE, NONE) X(SUBG, NONE, NONE) \
	X(AND_IMM, NONE, NONE) X(ORR_IMM, NONE, NONE) X(EOR_IMM, NONE, NONE) X(ANDS_IMM, NONE, NONE) \
	X(MOVN, NONE, NONE) X(MOVZ, NONE, NONE) X(MOVK, NONE, NONE) \
	X(SBFM, NONE, NONE) X(BFM, NONE, NONE) X(UBFM, NONE, NONE) X(EXTR, NONE, NONE) \
	/* branches. B and BL carry an imm26, CBZ CBNZ BCOND an imm19, TBZ and TBNZ an imm14: */ \
	/* gt_arm64_branch_off reads the width from this ORDER */ \
	X(B, NONE, NONE) X(BL, NONE, NONE) \
	X(CBZ, NONE, NONE) X(CBNZ, NONE, NONE) X(BCOND, NONE, NONE) \
	X(TBZ, NONE, NONE) X(TBNZ, NONE, NONE) \
	X(SVC, NONE, NONE) X(HVC, NONE, NONE) X(SMC, NONE, NONE) X(BRK, NONE, NONE) X(HLT, NONE, NONE) \
	X(DCPS1, NONE, NONE) X(DCPS2, NONE, NONE) X(DCPS3, NONE, NONE) X(TCANCEL, NONE, NONE) \
	X(BR, NONE, NONE) X(BLR, NONE, NONE) X(RET, NONE, NONE) X(ERET, NONE, NONE) X(DRPS, NONE, NONE) \
	X(BRAAZ, NONE, NONE) X(BRABZ, NONE, NONE) X(BLRAAZ, NONE, NONE) X(BLRABZ, NONE, NONE) \
	X(BRAA, NONE, NONE) X(BRAB, NONE, NONE) X(BLRAA, NONE, NONE) X(BLRAB, NONE, NONE) \
	X(RETAA, NONE, NONE) X(RETAB, NONE, NONE) X(ERETAA, NONE, NONE) X(ERETAB, NONE, NONE) \
	/* system */ \
	X(MRS, NONE, NONE) X(MSR, NONE, NONE) X(SYS, NONE, NONE) X(SYSL, NONE, NONE) \
	X(TSTART, NONE, NONE) X(TTEST, NONE, NONE) X(TCOMMIT, NONE, NONE) \
	X(HINT, NONE, NONE) X(XPACLRI, NONE, NONE) X(HINT_PAC_LR, NONE, NONE) \
	X(HINT_PAC_X17, NONE, NONE) X(CHKFEAT, NONE, NONE) \
	X(CLREX, NONE, NONE) X(DSB, NONE, NONE) X(DSB_NXS, NONE, NONE) X(DMB, NONE, NONE) \
	X(ISB, NONE, NONE) X(SB, NONE, NONE) X(MSR_PSTATE, NONE, NONE) X(WFET, NONE, NONE) X(WFIT, NONE, NONE) \
	/* load/store: exclusive, ordered, compare-and-swap, atomics, pointer-authenticated, 64-byte */ \
	X(STXR, NONE, NONE) X(LDXR, NONE, NONE) X(STXP, NONE, NONE) X(LDXP, NONE, NONE) \
	X(CASP, NONE, NONE) X(STLR, NONE, NONE) X(LDAR, NONE, NONE) X(CAS, NONE, NONE) \
	X(LDADD, NONE, NONE) X(LDCLR, NONE, NONE) X(LDEOR, NONE, NONE) X(LDSET, NONE, NONE) \
	X(LDSMAX, NONE, NONE) X(LDSMIN, NONE, NONE) X(LDUMAX, NONE, NONE) X(LDUMIN, NONE, NONE) \
	X(SWP, NONE, NONE) X(LDAPR, NONE, NONE) \
	X(ST64B, NONE, NONE) X(ST64BV0, NONE, NONE) X(ST64BV, NONE, NONE) X(LD64B, NONE, NONE) \
	X(LDRAA, NONE, NONE) X(LDRAB, NONE, NONE) X(LDRAA_PRE, NONE, NONE) X(LDRAB_PRE, NONE, NONE) \
	/* load/store: Advanced SIMD structures (multiple, single; with and without a post-index) */ \
	X(SIMD_STRUCT_MULT, NONE, NONE) X(SIMD_STRUCT_MULT_POST, NONE, NONE) \
	X(SIMD_STRUCT_SINGLE, NONE, NONE) X(SIMD_STRUCT_SINGLE_POST, NONE, NONE) \
	/* load/store: FEAT_MOPS copy and set, and the memory-tag instructions (FEAT_MTE) */ \
	X(MOPS_CPY, NONE, NONE) X(MOPS_SET, NONE, NONE) \
	X(LDG, NONE, NONE) X(STGM, NONE, NONE) X(STZGM, NONE, NONE) X(LDGM, NONE, NONE) \
	X(STG_POST, NONE, POST) X(STG_OFF, NONE, OFFSET) X(STG_PRE, NONE, PRE) \
	X(STZG_POST, NONE, POST) X(STZG_OFF, NONE, OFFSET) X(STZG_PRE, NONE, PRE) \
	X(ST2G_POST, NONE, POST) X(ST2G_OFF, NONE, OFFSET) X(ST2G_PRE, NONE, PRE) \
	X(STZ2G_POST, NONE, POST) X(STZ2G_OFF, NONE, OFFSET) X(STZ2G_PRE, NONE, PRE) \
	/* load/store: literal */ \
	X(LDR_LIT_W, LOAD, LIT) X(LDR_LIT_X, LOAD, LIT) X(LDRSW_LIT, LOAD_S64, LIT) \
	X(PRFM_LIT, PREFETCH, LIT) X(LDR_LIT_FP, LOAD_FP, LIT) \
	/* load/store: one register, by address form */ \
	X(STR_UOFF, STORE, OFFSET) X(LDR_UOFF, LOAD, OFFSET) X(LDRS64_UOFF, LOAD_S64, OFFSET) \
	X(LDRS32_UOFF, LOAD_S32, OFFSET) X(PRFM_UOFF, PREFETCH, OFFSET) \
	X(STR_FP_UOFF, STORE_FP, OFFSET) X(LDR_FP_UOFF, LOAD_FP, OFFSET) \
	X(STUR, STORE, UNSCALED) X(LDUR, LOAD, UNSCALED) X(LDURS64, LOAD_S64, UNSCALED) \
	X(LDURS32, LOAD_S32, UNSCALED) X(PRFUM, PREFETCH, UNSCALED) \
	X(STUR_FP, STORE_FP, UNSCALED) X(LDUR_FP, LOAD_FP, UNSCALED) \
	X(STR_POST, STORE, POST) X(LDR_POST, LOAD, POST) X(LDRS64_POST, LOAD_S64, POST) \
	X(LDRS32_POST, LOAD_S32, POST) X(STR_FP_POST, STORE_FP, POST) X(LDR_FP_POST, LOAD_FP, POST) \
	X(STR_PRE, STORE, PRE) X(LDR_PRE, LOAD, PRE) X(LDRS64_PRE, LOAD_S64, PRE) \
	X(LDRS32_PRE, LOAD_S32, PRE) X(STR_FP_PRE, STORE_FP, PRE) X(LDR_FP_PRE, LOAD_FP, PRE) \
	X(STTR, STORE, UNPRIV) X(LDTR, LOAD, UNPRIV) X(LDTRS64, LOAD_S64, UNPRIV) X(LDTRS32, LOAD_S32, UNPRIV) \
	X(STR_REG, STORE, REG) X(LDR_REG, LOAD, REG) X(LDRS64_REG, LOAD_S64, REG) \
	X(LDRS32_REG, LOAD_S32, REG) X(PRFM_REG, PREFETCH, REG) \
	X(STR_FP_REG, STORE_FP, REG) X(LDR_FP_REG, LOAD_FP, REG) \
	X(STLUR, STORE, UNSCALED) X(LDAPUR, LOAD, UNSCALED) X(LDAPURS64, LOAD_S64, UNSCALED) \
	X(LDAPURS32, LOAD_S32, UNSCALED) \
	/* load/store: pairs. STGP and LDPSW exist only in the post, offset and pre forms */ \
	X(STNP, STORE, NOALLOC) X(LDNP, LOAD, NOALLOC) X(STNP_FP, STORE_FP, NOALLOC) X(LDNP_FP, LOAD_FP, NOALLOC) \
	X(STP_POST, STORE, POST) X(STP_OFF, STORE, OFFSET) X(STP_PRE, STORE, PRE) \
	X(LDP_POST, LOAD, POST) X(LDP_OFF, LOAD, OFFSET) X(LDP_PRE, LOAD, PRE) \
	X(STGP_POST, STORE, POST) X(STGP_OFF, STORE, OFFSET) X(STGP_PRE, STORE, PRE) \
	X(LDPSW_POST, LOAD_S64, POST) X(LDPSW_OFF, LOAD_S64, OFFSET) X(LDPSW_PRE, LOAD_S64, PRE) \
	X(STP_FP_POST, STORE_FP, POST) X(STP_FP_OFF, STORE_FP, OFFSET) X(STP_FP_PRE, STORE_FP, PRE) \
	X(LDP_FP_POST, LOAD_FP, POST) X(LDP_FP_OFF, LOAD_FP, OFFSET) X(LDP_FP_PRE, LOAD_FP, PRE) \
	/* data processing, register: logical (shifted) */ \
	X(AND_REG, NONE, NONE) X(BIC_REG, NONE, NONE) X(ORR_REG, NONE, NONE) X(ORN_REG, NONE, NONE) \
	X(EOR_REG, NONE, NONE) X(EON_REG, NONE, NONE) X(ANDS_REG, NONE, NONE) X(BICS_REG, NONE, NONE) \
	/* add/subtract, shifted register and extended register */ \
	X(ADD_REG, NONE, NONE) X(ADDS_REG, NONE, NONE) X(SUB_REG, NONE, NONE) X(SUBS_REG, NONE, NONE) \
	X(ADD_EXT, NONE, NONE) X(ADDS_EXT, NONE, NONE) X(SUB_EXT, NONE, NONE) X(SUBS_EXT, NONE, NONE) \
	/* three source */ \
	X(MADD, NONE, NONE) X(MSUB, NONE, NONE) X(SMADDL, NONE, NONE) X(SMSUBL, NONE, NONE) \
	X(SMULH, NONE, NONE) X(UMADDL, NONE, NONE) X(UMSUBL, NONE, NONE) X(UMULH, NONE, NONE) \
	/* add/subtract with carry, flag manipulation, conditional compare and select */ \
	X(ADC, NONE, NONE) X(ADCS, NONE, NONE) X(SBC, NONE, NONE) X(SBCS, NONE, NONE) \
	X(SETF8, NONE, NONE) X(SETF16, NONE, NONE) X(RMIF, NONE, NONE) \
	X(CCMN_REG, NONE, NONE) X(CCMN_IMM, NONE, NONE) X(CCMP_REG, NONE, NONE) X(CCMP_IMM, NONE, NONE) \
	X(CSEL, NONE, NONE) X(CSINC, NONE, NONE) X(CSINV, NONE, NONE) X(CSNEG, NONE, NONE) \
	/* one source (REV is rev w / rev32; REV64 is rev x) and pointer authentication */ \
	X(RBIT, NONE, NONE) X(REV16, NONE, NONE) X(REV, NONE, NONE) X(REV64, NONE, NONE) \
	X(CLZ, NONE, NONE) X(CLS, NONE, NONE) \
	X(PACIA, NONE, NONE) X(PACIB, NONE, NONE) X(PACDA, NONE, NONE) X(PACDB, NONE, NONE) \
	X(AUTIA, NONE, NONE) X(AUTIB, NONE, NONE) X(AUTDA, NONE, NONE) X(AUTDB, NONE, NONE) \
	X(PACIZA, NONE, NONE) X(PACIZB, NONE, NONE) X(PACDZA, NONE, NONE) X(PACDZB, NONE, NONE) \
	X(AUTIZA, NONE, NONE) X(AUTIZB, NONE, NONE) X(AUTDZA, NONE, NONE) X(AUTDZB, NONE, NONE) \
	X(XPACI, NONE, NONE) X(XPACD, NONE, NONE) \
	/* two source */ \
	X(UDIV, NONE, NONE) X(SDIV, NONE, NONE) X(LSLV, NONE, NONE) X(LSRV, NONE, NONE) \
	X(ASRV, NONE, NONE) X(RORV, NONE, NONE) \
	X(SUBP, NONE, NONE) X(SUBPS, NONE, NONE) X(IRG, NONE, NONE) X(GMI, NONE, NONE) X(PACGA, NONE, NONE) \
	X(CRC32B, NONE, NONE) X(CRC32H, NONE, NONE) X(CRC32W, NONE, NONE) X(CRC32X, NONE, NONE) \
	X(CRC32CB, NONE, NONE) X(CRC32CH, NONE, NONE) X(CRC32CW, NONE, NONE) X(CRC32CX, NONE, NONE)

enum gt_arm64_id {
#define X(n, k, a) GT_ARM64_I_##n,
	GT_ARM64_ID_LIST(X)
#undef X
	GT_ARM64_I_COUNT
};

#endif /* KOF_GENOTYPE_ARM64_IDS_H */
