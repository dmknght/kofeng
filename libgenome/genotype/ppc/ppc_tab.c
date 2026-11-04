/*
 * ppc_tab.c - the PowerPC decode tables: DATA only. See ppc.h for what each answer means and
 * ppc_private.h for the layout. Every number below is a primary opcode, an extended opcode or a
 * mask written from the Power ISA instruction-form diagrams (the field's bit positions are the
 * manual's, bit 0 the most significant); tests/lib/genome/genotype_ppc.c holds the same facts as
 * hand-assembled words and checks them from the other side.
 */
#include "ppc.h"
#include "ppc_private.h"

#define I(n) KGENOME_PPC_I_##n

/* XO-form: nine-bit extended opcode (bits 22..30) and the OE bit (bit 21) in front of it. */
#define XO9(x, n) [x] = I(n), [(x) + 512] = I(n)

/*
 * PRIMARY OPCODE 31: the index is the ten-bit extended opcode, bits 21..30 = (word >> 1) & 1023.
 * A zero entry is INVALID. isel (a five-bit extended opcode, bits 26..30 = 15) is not here: it is
 * the one form with a different width and is tested for in ppc.c before this table. sradi is the
 * XS-form (nine-bit extended opcode, bit 30 is a shift bit), so it fills two entries.
 */
const uint16_t kgenome_ppc_x31[1024] = {
	[0] = I(CMP), [4] = I(TW), [20] = I(LWARX), [21] = I(LDX), [23] = I(LWZX), [24] = I(SLW),
	[26] = I(CNTLZW), [27] = I(SLD), [28] = I(AND), [32] = I(CMPL), [53] = I(LDUX), [54] = I(DCBST), [55] = I(LWZUX),
	[58] = I(CNTLZD), [60] = I(ANDC), [68] = I(TD), [83] = I(MFMSR), [84] = I(LDARX), [86] = I(DCBF),
	[87] = I(LBZX), [119] = I(LBZUX), [124] = I(NOR), [144] = I(MTCRF), [146] = I(MTMSR),
	[149] = I(STDX), [150] = I(STWCX_), [151] = I(STWX), [181] = I(STDUX), [183] = I(STWUX),
	[210] = I(MTSR), [214] = I(STDCX_), [215] = I(STBX), [242] = I(MTSRIN), [246] = I(DCBTST),
	[247] = I(STBUX), [278] = I(DCBT), [279] = I(LHZX), [284] = I(EQV), [306] = I(TLBIE),
	[310] = I(ECIWX), [311] = I(LHZUX), [316] = I(XOR), [339] = I(MFSPR), [341] = I(LWAX),
	[343] = I(LHAX), [370] = I(TLBIA), [371] = I(MFTB), [373] = I(LWAUX), [375] = I(LHAUX),
	[407] = I(STHX), [412] = I(ORC), [826] = I(SRADI), [827] = I(SRADI), [438] = I(ECOWX),
	[439] = I(STHUX), [444] = I(OR), [467] = I(MTSPR), [470] = I(DCBI), [476] = I(NAND),
	[19] = I(MFCR), [512] = I(MCRXR), [533] = I(LSWX), [534] = I(LWBRX), [535] = I(LFSX),
	[536] = I(SRW), [539] = I(SRD), [566] = I(TLBSYNC), [567] = I(LFSUX), [595] = I(MFSR),
	[597] = I(LSWI), [598] = I(SYNC), [599] = I(LFDX), [631] = I(LFDUX), [659] = I(MFSRIN),
	[661] = I(STSWX), [662] = I(STWBRX), [663] = I(STFSX), [695] = I(STFSUX), [725] = I(STSWI),
	[727] = I(STFDX), [758] = I(DCBA), [759] = I(STFDUX), [790] = I(LHBRX), [792] = I(SRAW),
	[794] = I(SRAD), [824] = I(SRAWI), [854] = I(EIEIO), [918] = I(STHBRX), [922] = I(EXTSH),
	[954] = I(EXTSB), [982] = I(ICBI), [983] = I(STFIWX), [986] = I(EXTSW), [1014] = I(DCBZ),
	/* XO-form arithmetic, with and without OE */
	XO9(8, SUBFC), XO9(9, MULHDU), XO9(10, ADDC), XO9(11, MULHWU), XO9(40, SUBF), XO9(73, MULHD),
	XO9(75, MULHW), XO9(104, NEG), XO9(136, SUBFE), XO9(138, ADDE), XO9(200, SUBFZE),
	XO9(202, ADDZE), XO9(232, SUBFME), XO9(233, MULLD), XO9(234, ADDME), XO9(235, MULLW),
	XO9(266, ADD), XO9(457, DIVDU), XO9(459, DIVWU), XO9(489, DIVD), XO9(491, DIVW),
	/* AltiVec and VSX loads and stores that write no general register: known, not spelled */
	[6] = I(UNSUPPORTED), [7] = I(UNSUPPORTED), [12] = I(UNSUPPORTED), [38] = I(UNSUPPORTED),
	[39] = I(UNSUPPORTED), [71] = I(UNSUPPORTED), [76] = I(UNSUPPORTED), [103] = I(UNSUPPORTED),
	[135] = I(UNSUPPORTED), [140] = I(UNSUPPORTED), [167] = I(UNSUPPORTED), [199] = I(UNSUPPORTED),
	[231] = I(UNSUPPORTED), [332] = I(UNSUPPORTED), [342] = I(UNSUPPORTED), [359] = I(UNSUPPORTED),
	[374] = I(UNSUPPORTED), [487] = I(UNSUPPORTED), [524] = I(UNSUPPORTED), [588] = I(UNSUPPORTED),
	[652] = I(UNSUPPORTED), [716] = I(UNSUPPORTED), [780] = I(UNSUPPORTED), [822] = I(UNSUPPORTED),
	[844] = I(UNSUPPORTED), [908] = I(UNSUPPORTED), [972] = I(UNSUPPORTED),
};

/* PRIMARY OPCODE 19, XL-form: mask 0xFC0007FE (Rc/LK, bit 0, is a field of the word). */
#define M19 0xFC0007FEu
#define R19(x, n) { M19, 0x4C000000u | ((uint32_t)(x) << 1), I(n) }
static const struct kgenome_ppc_row rows19[] = {
	R19(0, MCRF), R19(16, BCLR), R19(18, RFID), R19(33, CRNOR), R19(50, RFI), R19(129, CRANDC),
	R19(150, ISYNC), R19(193, CRXOR), R19(225, CRNAND), R19(257, CRAND), R19(289, CREQV),
	R19(417, CRORC), R19(449, CROR), R19(528, BCCTR),
	{ 0, 0, I(INVALID) }
};

/* sc: 0x44000002 with the LEV field (bits 20..26) free; bit 31 set would be scv, which is not tabled. */
static const struct kgenome_ppc_row rows17[] = {
	{ 0xFC000003u, 0x44000002u, I(SC) },
	{ 0, 0, I(INVALID) }
};

/* PRIMARY OPCODE 30: MD-form (three-bit extended opcode, bits 27..29) and MDS-form (four bits, 27..30). */
static const struct kgenome_ppc_row rows30[] = {
	{ 0xFC00001Cu, 0x78000000u, I(RLDICL) }, { 0xFC00001Cu, 0x78000004u, I(RLDICR) },
	{ 0xFC00001Cu, 0x78000008u, I(RLDIC) },  { 0xFC00001Cu, 0x7800000Cu, I(RLDIMI) },
	{ 0xFC00001Eu, 0x78000010u, I(RLDCL) },  { 0xFC00001Eu, 0x78000012u, I(RLDCR) },
	{ 0, 0, I(INVALID) }
};

/* PRIMARY OPCODE 59 (single precision, A-form: five-bit extended opcode, bits 26..30). */
#define M59 0xFC00003Eu
#define A59(x, n) { M59, 0xEC000000u | ((uint32_t)(x) << 1), I(n) }
static const struct kgenome_ppc_row rows59[] = {
	A59(18, FDIVS), A59(20, FSUBS), A59(21, FADDS), A59(22, FSQRTS), A59(24, FRES), A59(25, FMULS),
	A59(26, FRSQRTES), A59(28, FMSUBS), A59(29, FMADDS), A59(30, FNMSUBS), A59(31, FNMADDS),
	{ 0, 0, I(INVALID) }
};

/* PRIMARY OPCODE 63: A-form (five-bit extended opcode) first, then X-form (ten bits). The two sets share no low five bits. */
#define A63(x, n) { 0xFC00003Eu, 0xFC000000u | ((uint32_t)(x) << 1), I(n) }
#define X63(x, n) { 0xFC0007FEu, 0xFC000000u | ((uint32_t)(x) << 1), I(n) }
static const struct kgenome_ppc_row rows63[] = {
	A63(18, FDIV), A63(20, FSUB), A63(21, FADD), A63(22, FSQRT), A63(23, FSEL), A63(25, FMUL),
	A63(26, FRSQRTE), A63(28, FMSUB), A63(29, FMADD), A63(30, FNMSUB), A63(31, FNMADD),
	X63(0, FCMPU), X63(12, FRSP), X63(14, FCTIW), X63(15, FCTIWZ), X63(32, FCMPO), X63(38, MTFSB1),
	X63(40, FNEG), X63(64, MCRFS), X63(70, MTFSB0), X63(72, FMR), X63(134, MTFSFI), X63(136, FNABS),
	X63(264, FABS), X63(583, MFFS), X63(711, MTFSF), X63(814, FCTID), X63(815, FCTIDZ), X63(846, FCFID),
	{ 0, 0, I(INVALID) }
};

/* DS-form loads and stores: the low two bits pick the instruction (ld, ldu, lwa / std, stdu). */
static const struct kgenome_ppc_row rows58[] = {
	{ 0x3u, 0u, I(LD) }, { 0x3u, 1u, I(LDU) }, { 0x3u, 2u, I(LWA) }, { 0, 0, I(INVALID) }
};
static const struct kgenome_ppc_row rows62[] = {
	{ 0x3u, 0u, I(STD) }, { 0x3u, 1u, I(STDU) }, { 0, 0, I(INVALID) }
};

#define ID(n) { KGENOME_PPC_PK_ID, I(n), 0 }
#define ROWS(r) { KGENOME_PPC_PK_ROWS, 0, r }

/* The six-bit primary opcode. An entry that is not written is INVALID (id 0, kind ID). */
const struct kgenome_ppc_prim kgenome_ppc_prim[64] = {
	[2] = ID(TDI), [3] = ID(TWI), [4] = ID(UNSUPPORTED), [7] = ID(MULLI), [8] = ID(SUBFIC),
	[10] = ID(CMPLI), [11] = ID(CMPI), [12] = ID(ADDIC), [13] = ID(ADDIC_), [14] = ID(ADDI),
	[15] = ID(ADDIS), [16] = ID(BC), [17] = ROWS(rows17), [18] = ID(B), [19] = ROWS(rows19),
	[20] = ID(RLWIMI), [21] = ID(RLWINM), [23] = ID(RLWNM), [24] = ID(ORI), [25] = ID(ORIS),
	[26] = ID(XORI), [27] = ID(XORIS), [28] = ID(ANDI_), [29] = ID(ANDIS_), [30] = ROWS(rows30),
	[31] = { KGENOME_PPC_PK_X31, 0, 0 },
	[32] = ID(LWZ), [33] = ID(LWZU), [34] = ID(LBZ), [35] = ID(LBZU), [36] = ID(STW), [37] = ID(STWU),
	[38] = ID(STB), [39] = ID(STBU), [40] = ID(LHZ), [41] = ID(LHZU), [42] = ID(LHA), [43] = ID(LHAU),
	[44] = ID(STH), [45] = ID(STHU), [46] = ID(LMW), [47] = ID(STMW), [48] = ID(LFS), [49] = ID(LFSU),
	[50] = ID(LFD), [51] = ID(LFDU), [52] = ID(STFS), [53] = ID(STFSU), [54] = ID(STFD), [55] = ID(STFDU),
	[56] = ID(UNSUPPORTED), [57] = ID(UNSUPPORTED), [58] = ROWS(rows58), [59] = ROWS(rows59),
	[60] = ID(UNSUPPORTED), [61] = ID(UNSUPPORTED), [62] = ROWS(rows62), [63] = ROWS(rows63),
};

const char *const kgenome_ppc_names[] = {
#define X(n, a) #n,
	KGENOME_PPC_ID_LIST(X)
#undef X
};

const uint8_t kgenome_ppc_attr[] = {
#define X(n, a) KGENOME_PPC_A_##a,
	KGENOME_PPC_ID_LIST(X)
#undef X
};
