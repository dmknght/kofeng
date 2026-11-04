/*
 * ppc_ids.h - the instruction identities the PowerPC table can answer with.
 *
 * ONE LIST, THREE USES (as arm64_ids.h): KGENOME_PPC_ID_LIST names every identity once with
 * its attribute bits; the enum below, the attribute table and the names a test prints are all
 * expanded from it.
 *
 * GRANULARITY. An identity is a MNEMONIC FAMILY. The bits that make a family's variants are read
 * from the word: Rc (record, bit 0), OE (overflow enable, XO-form bit 21), LK (link), AA
 * (absolute), the L of a compare, the BO/BI of a branch. `lwz` and `lwzu` are two identities
 * because they write different registers; `add`, `add.`, `addo` and `addo.` are one.
 *
 * ATTRIBUTES. P64: the instruction exists only in the 64-bit architecture; in 32-bit mode its
 * word is INVALID. L64: a compare whose L bit (the word's 0x00200000) is set is the 64-bit compare
 * (cmpd): in 32-bit mode that word is INVALID. RC1: bit 0 must be 1 (stwcx., stdcx.: the word with bit 0 clear is not an
 * instruction).
 *
 * THE FIRST TWO are what "not an instruction" looks like. INVALID: the word is not an
 * instruction of the set this table covers (PowerPC user ISA, the virtual environment, the basic
 * supervisor instructions, the 64-bit forms, scalar floating point). UNSUPPORTED: the word lies
 * in a space the architecture allocates and this table does not spell (AltiVec and SPE in
 * primary opcode 4, the VSX/quad/pair loads, the vector loads of primary opcode 31); its length
 * is four bytes and nothing else is claimed.
 */
#ifndef KGENOME_GENOTYPE_PPC_IDS_H
#define KGENOME_GENOTYPE_PPC_IDS_H

#define KGENOME_PPC_A_NONE   0x00u
#define KGENOME_PPC_A_P64    0x01u
#define KGENOME_PPC_A_RC1    0x02u
#define KGENOME_PPC_A_P64_RC1 0x03u
#define KGENOME_PPC_A_L64    0x04u

#define KGENOME_PPC_ID_LIST(X) \
	X(INVALID, NONE) X(UNSUPPORTED, NONE) \
	/* D-form arithmetic and compare, logical immediates */ \
	X(TDI, P64) X(TWI, NONE) X(MULLI, NONE) X(SUBFIC, NONE) X(CMPLI, L64) X(CMPI, L64) X(ADDIC, NONE) X(ADDIC_, NONE) \
	X(ADDI, NONE) X(ADDIS, NONE) X(ORI, NONE) X(ORIS, NONE) X(XORI, NONE) X(XORIS, NONE) X(ANDI_, NONE) X(ANDIS_, NONE) \
	/* branches and system call */ \
	X(BC, NONE) X(SC, NONE) X(B, NONE) \
	/* rotates (M-form), and the 64-bit rotates (MD and MDS forms) */ \
	X(RLWIMI, NONE) X(RLWINM, NONE) X(RLWNM, NONE) \
	X(RLDICL, P64) X(RLDICR, P64) X(RLDIC, P64) X(RLDIMI, P64) X(RLDCL, P64) X(RLDCR, P64) \
	/* loads and stores, D-form and DS-form */ \
	X(LWZ, NONE) X(LWZU, NONE) X(LBZ, NONE) X(LBZU, NONE) X(STW, NONE) X(STWU, NONE) X(STB, NONE) X(STBU, NONE) \
	X(LHZ, NONE) X(LHZU, NONE) X(LHA, NONE) X(LHAU, NONE) X(STH, NONE) X(STHU, NONE) X(LMW, NONE) X(STMW, NONE) \
	X(LFS, NONE) X(LFSU, NONE) X(LFD, NONE) X(LFDU, NONE) X(STFS, NONE) X(STFSU, NONE) X(STFD, NONE) X(STFDU, NONE) \
	X(LD, P64) X(LDU, P64) X(LWA, P64) X(STD, P64) X(STDU, P64) \
	/* primary opcode 19: condition register, branch to LR / CTR, rfi, isync */ \
	X(MCRF, NONE) X(BCLR, NONE) X(RFI, NONE) X(RFID, P64) X(ISYNC, NONE) X(CRNOR, NONE) X(CRANDC, NONE) X(CRXOR, NONE) \
	X(CRNAND, NONE) X(CRAND, NONE) X(CREQV, NONE) X(CRORC, NONE) X(CROR, NONE) X(BCCTR, NONE) \
	/* primary opcode 31, XO-form arithmetic (the OE bit is read from the word) */ \
	X(ADD, NONE) X(ADDC, NONE) X(ADDE, NONE) X(ADDME, NONE) X(ADDZE, NONE) X(DIVW, NONE) X(DIVWU, NONE) X(MULHW, NONE) \
	X(MULHWU, NONE) X(MULLW, NONE) X(NEG, NONE) X(SUBF, NONE) X(SUBFC, NONE) X(SUBFE, NONE) X(SUBFME, NONE) X(SUBFZE, NONE) \
	X(DIVD, P64) X(DIVDU, P64) X(MULHD, P64) X(MULHDU, P64) X(MULLD, P64) \
	/* primary opcode 31, X-form and XFX-form */ \
	X(CMP, L64) X(TW, NONE) X(LWARX, NONE) X(LWZX, NONE) X(SLW, NONE) X(CNTLZW, NONE) X(AND, NONE) X(CMPL, L64) \
	X(LWZUX, NONE) X(ANDC, NONE) X(MFMSR, NONE) X(LBZX, NONE) X(LBZUX, NONE) X(NOR, NONE) X(MTMSR, NONE) X(STWCX_, RC1) \
	X(STWX, NONE) X(STWUX, NONE) X(MTSR, NONE) X(STBX, NONE) X(STBUX, NONE) X(MTSRIN, NONE) X(MFSR, NONE) X(MFSRIN, NONE) \
	X(TLBIE, NONE) X(TLBSYNC, NONE) X(DCBF, NONE) X(DCBST, NONE) X(DCBT, NONE) X(DCBTST, NONE) X(DCBI, NONE) X(DCBZ, NONE) \
	X(DCBA, NONE) X(ICBI, NONE) X(ECIWX, NONE) X(ECOWX, NONE) X(EIEIO, NONE) X(SYNC, NONE) X(LHZX, NONE) X(LHZUX, NONE) \
	X(LHAX, NONE) X(LHAUX, NONE) X(LHBRX, NONE) X(STHBRX, NONE) X(LWBRX, NONE) X(STWBRX, NONE) X(STHX, NONE) X(STHUX, NONE) \
	X(LSWI, NONE) X(LSWX, NONE) X(STSWI, NONE) X(STSWX, NONE) \
	X(LFSX, NONE) X(LFSUX, NONE) X(LFDX, NONE) X(LFDUX, NONE) X(STFSX, NONE) X(STFSUX, NONE) X(STFDX, NONE) X(STFDUX, NONE) \
	X(STFIWX, NONE) X(XOR, NONE) X(OR, NONE) X(ORC, NONE) X(NAND, NONE) X(EQV, NONE) X(SRW, NONE) X(SRAW, NONE) X(SRAWI, NONE) \
	X(EXTSB, NONE) X(EXTSH, NONE) X(MFCR, NONE) X(MTCRF, NONE) X(MFSPR, NONE) X(MTSPR, NONE) X(MFTB, NONE) X(MCRXR, NONE) \
	X(TLBIA, NONE) X(ISEL, NONE) \
	X(LDX, P64) X(LDUX, P64) X(STDX, P64) X(STDUX, P64) X(LWAX, P64) X(LWAUX, P64) X(SLD, P64) \
	X(SRD, P64) X(SRAD, P64) X(SRADI, P64) X(CNTLZD, P64) X(EXTSW, P64) X(LDARX, P64) \
	X(STDCX_, P64_RC1) X(TD, P64) \
	/* scalar floating point: primary opcodes 59 (single) and 63 (double and the status register) */ \
	X(FDIVS, NONE) X(FSUBS, NONE) X(FADDS, NONE) X(FSQRTS, NONE) X(FRES, NONE) X(FMULS, NONE) X(FRSQRTES, NONE) \
	X(FMSUBS, NONE) X(FMADDS, NONE) X(FNMSUBS, NONE) X(FNMADDS, NONE) \
	X(FDIV, NONE) X(FSUB, NONE) X(FADD, NONE) X(FSQRT, NONE) X(FSEL, NONE) X(FMUL, NONE) X(FRSQRTE, NONE) X(FMSUB, NONE) \
	X(FMADD, NONE) X(FNMSUB, NONE) X(FNMADD, NONE) X(FCMPU, NONE) X(FRSP, NONE) X(FCTIW, NONE) X(FCTIWZ, NONE) \
	X(FCMPO, NONE) X(MTFSB1, NONE) X(FNEG, NONE) X(MCRFS, NONE) X(MTFSB0, NONE) X(FMR, NONE) X(MTFSFI, NONE) \
	X(FNABS, NONE) X(FABS, NONE) X(MFFS, NONE) X(MTFSF, NONE) X(FCTID, P64) X(FCTIDZ, P64) X(FCFID, P64)

enum kgenome_ppc_id {
#define X(n, a) KGENOME_PPC_I_##n,
	KGENOME_PPC_ID_LIST(X)
#undef X
	KGENOME_PPC_I_COUNT
};

#endif /* KGENOME_GENOTYPE_PPC_IDS_H */
