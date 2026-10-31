/*
 * arm64_fmt.c - an AArch64 instruction as text.
 *
 * WHAT THE TEXT IS. The spelling of the GNU assembler's disassembler: lower-case
 * registers (x0, w0, sp, xzr), the preferred alias where the architecture defines
 * one (mov, cmp, tst, cset, lsl, ubfx, ret ...), immediates in hex except the offset
 * of a load or store, which is decimal. The mnemonic is put in capitals and padded
 * to one column (gt_fmt_private.h) like the x86 text. The tests compare it with that
 * disassembler's output after two normalisations: case, and runs of white space
 * folded to one; what the oracle adds after the operands (a symbol in <>, a "//"
 * comment) is not compared.
 *
 * WHAT IS SPELLED. Every identity the decoder gives a mnemonic: the base integer
 * set, the branches, the system and barrier instructions, the loads and stores
 * (single, pair, exclusive, atomic, literal, scalar floating point and vector
 * registers as DATA registers), the memory-tag stores. What is NOT: scalar floating
 * point arithmetic, Advanced SIMD, SVE and SME, which the decoder does not take
 * apart (genotype/arm64/arm64.h, THE VECTOR SPACES), and the pointer-authentication
 * and memory-tag families a corpus never held. Those words come back with status
 * KGENOME_UNSUPPORTED and the text ".inst 0x........": the length is right, the
 * mnemonic is not claimed.
 *
 * ONE WALK, NO TABLE OF TEXT: the identity chooses the branch of the switch below
 * and the fields come from the accessors in arm64.h; nothing is decoded a second
 * time except the few fields (shift type, extend option, condition) the accessors
 * do not name.
 */
#include <stdio.h>
#include <string.h>

#include "arm64.h"
#include "../gt_fmt_private.h"

static const char *const g_cc[16] = {
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
};
static const char *const g_shift[4] = { "lsl", "lsr", "asr", "ror" };
static const char *const g_ext[8] = { "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx" };

struct a64 {
	struct kgenome_gt_fmt f;
	const struct kgenome_arm64_insn *in;
	uint32_t w;
	uint64_t pc;
	uint8_t flow;
	uint8_t has_target;
	uint64_t target;
	int unsupported;
};

/* x or w register; 31 is the zero register, or sp when `sp` */
static const char *rg(char *b, unsigned r, unsigned sf, unsigned sp)
{
	if (r == 31u)
		return sp ? (sf ? "sp" : "wsp") : (sf ? "xzr" : "wzr");
	snprintf(b, 8, "%c%u", sf ? 'x' : 'w', r);
	return b;
}

/* a scalar floating point / vector data register of 1, 2, 4, 8 or 16 bytes */
static const char *fr(char *b, unsigned r, unsigned bytes)
{
	static const char p[17] = { 0, 'b', 'h', 0, 's', 0, 0, 0, 'd', 0, 0, 0, 0, 0, 0, 0, 'q' };

	snprintf(b, 8, "%c%u", bytes <= 16u && p[bytes] ? p[bytes] : '?', r);
	return b;
}

static const char *cond_inv(unsigned c)
{
	return g_cc[c ^ 1u];
}

static void branch_to(struct a64 *a, uint8_t flow, int64_t off)
{
	a->flow = flow;
	a->has_target = 1;
	a->target = a->pc + (uint64_t)off;
}

#define MN(...) kgenome_gt_fmt_mn(&a->f, __VA_ARGS__)
#define OP(...) kgenome_gt_fmt_op(&a->f, __VA_ARGS__)

/* a bitmask can be made by one MOVZ or MOVN: then the assembler writes that, and an ORR of it is not shown as MOV */
static int wide_constant(uint64_t v, unsigned sf)
{
	unsigned i, z = 0, o = 0, n = sf ? 4u : 2u;

	for (i = 0; i < n; i++) {
		uint64_t h = (v >> (16u * i)) & 0xffffu;

		if (h != 0)
			z++;
		if (h != 0xffffu)
			o++;
	}
	return z <= 1u || o <= 1u;
}

static void fmt_logic_imm(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u;
	uint64_t imm = kgenome_arm64_logical_imm(a->in);
	char x[8], y[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_ORR_IMM:
		if (rn == 31u && !wide_constant(imm, sf)) {
			MN("mov");
			OP("%s, #0x%llx", rg(x, rd, sf, 1), (unsigned long long)imm);
			return;
		}
		MN("orr");
		break;
	case KGENOME_ARM64_I_AND_IMM:
		MN("and");
		break;
	case KGENOME_ARM64_I_EOR_IMM:
		MN("eor");
		break;
	default:                                                /* ANDS */
		if (rd == 31u) {
			MN("tst");
			OP("%s, #0x%llx", rg(x, rn, sf, 0), (unsigned long long)imm);
			return;
		}
		MN("ands");
		OP("%s, %s, #0x%llx", rg(x, rd, sf, 0), rg(y, rn, sf, 0), (unsigned long long)imm);
		return;
	}
	OP("%s, %s, #0x%llx", rg(x, rd, sf, 1), rg(y, rn, sf, 0), (unsigned long long)imm);
}

static void fmt_movw(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, hw = (a->w >> 21) & 3u;
	unsigned imm16 = (a->w >> 5) & 0xffffu;
	uint64_t v = (uint64_t)imm16 << (16u * hw);
	char x[8];

	if (!sf && hw > 1u) {                                   /* not an instruction on w registers */
		a->unsupported = 1;
		return;
	}
	switch (a->in->id) {
	case KGENOME_ARM64_I_MOVK:
		MN("movk");
		if (hw)
			OP("%s, #0x%x, lsl #%u", rg(x, rd, sf, 0), imm16, 16u * hw);
		else
			OP("%s, #0x%x", rg(x, rd, sf, 0), imm16);
		return;
	case KGENOME_ARM64_I_MOVZ:
		if (imm16 == 0 && hw != 0)
			break;
		MN("mov");
		OP("%s, #0x%llx", rg(x, rd, sf, 0), (unsigned long long)v);
		return;
	default:                                                /* MOVN */
		if ((imm16 == 0 && hw != 0) || (!sf && imm16 == 0xffffu))
			break;
		v = ~v;
		if (!sf)
			v &= 0xffffffffull;
		MN("mov");
		OP("%s, #0x%llx", rg(x, rd, sf, 0), (unsigned long long)v);
		return;
	}
	MN(a->in->id == KGENOME_ARM64_I_MOVZ ? "movz" : "movn");
	if (hw)
		OP("%s, #0x%x, lsl #%u", rg(x, rd, sf, 0), imm16, 16u * hw);
	else
		OP("%s, #0x%x", rg(x, rd, sf, 0), imm16);
}

static void fmt_bitfield(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u;
	unsigned immr = kgenome_arm64_immr(a->in), imms = kgenome_arm64_imms(a->in);
	unsigned bits = sf ? 64u : 32u, top = bits - 1u;
	char x[8], y[8];

	if (!sf && (((a->w >> 22) & 1u) || immr > 31u || imms > 31u)) {
		a->unsupported = 1;
		return;
	}
	switch (a->in->id) {
	case KGENOME_ARM64_I_SBFM:
		if (imms == top) {
			MN("asr");
			OP("%s, %s, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), immr);
		} else if (immr == 0 && (imms == 7u || imms == 15u || (sf && imms == 31u))) {
			MN(imms == 7u ? "sxtb" : imms == 15u ? "sxth" : "sxtw");
			OP("%s, %s", rg(x, rd, sf, 0), rg(y, rn, 0, 0));
		} else if (imms < immr) {
			MN("sbfiz");
			OP("%s, %s, #%u, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), (bits - immr) & top, imms + 1u);
		} else {
			MN("sbfx");
			OP("%s, %s, #%u, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), immr, imms - immr + 1u);
		}
		return;
	case KGENOME_ARM64_I_UBFM:
		if (!sf && immr == 0 && (imms == 7u || imms == 15u)) {
			MN(imms == 7u ? "uxtb" : "uxth");
			OP("%s, %s", rg(x, rd, 0, 0), rg(y, rn, 0, 0));
		} else if (imms == top) {
			MN("lsr");
			OP("%s, %s, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), immr);
		} else if (imms + 1u == immr) {
			MN("lsl");
			OP("%s, %s, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), top - imms);
		} else if (imms < immr) {
			MN("ubfiz");
			OP("%s, %s, #%u, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), (bits - immr) & top, imms + 1u);
		} else {
			MN("ubfx");
			OP("%s, %s, #%u, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), immr, imms - immr + 1u);
		}
		return;
	default:                                                /* BFM */
		if (imms < immr) {
			if (rn == 31u) {
				MN("bfc");
				OP("%s, #%u, #%u", rg(x, rd, sf, 0), (bits - immr) & top, imms + 1u);
			} else {
				MN("bfi");
				OP("%s, %s, #%u, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), (bits - immr) & top, imms + 1u);
			}
		} else {
			MN("bfxil");
			OP("%s, %s, #%u, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), immr, imms - immr + 1u);
		}
		return;
	}
}

static void fmt_branch(struct a64 *a)
{
	unsigned sf = a->w >> 31, rt = a->w & 31u;
	int64_t off = kgenome_arm64_branch_off(a->in);
	char x[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_B:
		MN("b");
		branch_to(a, KGENOME_GT_FLOW_JUMP, off);
		OP("0x%llx", (unsigned long long)a->target);
		break;
	case KGENOME_ARM64_I_BL:
		MN("bl");
		branch_to(a, KGENOME_GT_FLOW_CALL, off);
		OP("0x%llx", (unsigned long long)a->target);
		break;
	case KGENOME_ARM64_I_BCOND:
		MN("%s.%s", (a->w & 16u) ? "bc" : "b", g_cc[a->w & 15u]);   /* bit 4 set is BC.cond (FEAT_HBC) */
		branch_to(a, KGENOME_GT_FLOW_COND, off);
		OP("0x%llx", (unsigned long long)a->target);
		break;
	case KGENOME_ARM64_I_CBZ:
	case KGENOME_ARM64_I_CBNZ:
		MN(a->in->id == KGENOME_ARM64_I_CBZ ? "cbz" : "cbnz");
		branch_to(a, KGENOME_GT_FLOW_COND, off);
		OP("%s, 0x%llx", rg(x, rt, sf, 0), (unsigned long long)a->target);
		break;
	default: {                                              /* TBZ, TBNZ */
		unsigned bit = kgenome_arm64_tbz_bit(a->in);

		MN(a->in->id == KGENOME_ARM64_I_TBZ ? "tbz" : "tbnz");
		branch_to(a, KGENOME_GT_FLOW_COND, off);
		OP("%s, #%u, 0x%llx", rg(x, rt, bit >= 32u, 0), bit, (unsigned long long)a->target);
		break;
	}
	}
}

/* a system register: its name when it has one that is spelled here, else the generic sN_n_cN_cN_n */
#define SR(o0, o1, crn, crm, o2) \
	((uint16_t)((((o0) & 1u) << 14) | ((o1) << 11) | ((crn) << 7) | ((crm) << 3) | (o2)))

static void sysreg_name(char *b, size_t cap, unsigned key)
{
	static const struct { uint16_t key; const char *name; } t[] = {
		{ SR(3, 3, 4, 2, 0), "nzcv" }, { SR(3, 3, 4, 2, 1), "daif" }, { SR(3, 0, 4, 2, 2), "currentel" },
		{ SR(3, 3, 4, 4, 0), "fpcr" }, { SR(3, 3, 4, 4, 1), "fpsr" },
		{ SR(3, 3, 13, 0, 2), "tpidr_el0" }, { SR(3, 3, 13, 0, 3), "tpidrro_el0" }, { SR(3, 0, 13, 0, 4), "tpidr_el1" },
		{ SR(3, 3, 14, 0, 2), "cntvct_el0" }, { SR(3, 3, 14, 0, 0), "cntfrq_el0" }, { SR(3, 3, 14, 0, 1), "cntpct_el0" },
		{ SR(3, 0, 0, 0, 0), "midr_el1" }, { SR(3, 0, 0, 0, 5), "mpidr_el1" },
		{ SR(3, 3, 0, 0, 1), "ctr_el0" }, { SR(3, 3, 0, 0, 7), "dczid_el0" },
		{ SR(3, 0, 4, 2, 0), "spsel" }, { SR(3, 0, 4, 1, 0), "sp_el0" }, { SR(3, 3, 4, 2, 5), "dit" }, { SR(3, 3, 13, 0, 5), "tpidr2_el0" },
	};
	unsigned i, op0 = 2u + ((key >> 14) & 1u), op1 = (key >> 11) & 7u, crn = (key >> 7) & 15u, crm = (key >> 3) & 15u, op2 = key & 7u;

	for (i = 0; i < sizeof t / sizeof t[0]; i++)
		if (t[i].key == key) {
			snprintf(b, cap, "%s", t[i].name);
			return;
		}
	snprintf(b, cap, "s%u_%u_c%u_c%u_%u", op0, op1, crn, crm, op2);
}

static const char *barrier_opt(char *b, unsigned crm)
{
	static const char *const n[16] = {
		NULL, "oshld", "oshst", "osh", NULL, "nshld", "nshst", "nsh",
		NULL, "ishld", "ishst", "ish", NULL, "ld", "st", "sy"
	};

	if (n[crm])
		return n[crm];
	snprintf(b, 8, "#0x%x", crm);
	return b;
}

static void fmt_hint(struct a64 *a)
{
	static const struct { uint8_t n; const char *name; } t[] = {
		{ 0, "nop" }, { 1, "yield" }, { 2, "wfe" }, { 3, "wfi" }, { 4, "sev" }, { 5, "sevl" }, { 6, "dgh" },
		{ 7, "xpaclri" }, { 8, "pacia1716" }, { 10, "pacib1716" }, { 12, "autia1716" }, { 14, "autib1716" },
		{ 16, "esb" }, { 20, "csdb" }, { 24, "paciaz" }, { 25, "paciasp" }, { 26, "pacibz" }, { 27, "pacibsp" },
		{ 28, "autiaz" }, { 29, "autiasp" }, { 30, "autibz" }, { 31, "autibsp" },
	};
	unsigned h = kgenome_arm64_hint(a->in), i;

	for (i = 0; i < sizeof t / sizeof t[0]; i++)
		if (t[i].n == h) {
			MN("%s", t[i].name);
			return;
		}
	if (h == 17u || h == 18u) {
		MN(h == 17u ? "psb" : "tsb");
		OP("csync");
	} else if (h == 32u || h == 34u || h == 36u || h == 38u) {
		MN("bti");
		if (h != 32u)
			OP("%s", h == 34u ? "c" : h == 36u ? "j" : "jc");
	} else {
		MN("hint");
		OP("#0x%x", h);
	}
}

static void fmt_system(struct a64 *a)
{
	unsigned rt = a->w & 31u, crm = (a->w >> 8) & 15u;
	char x[8], nm[40], o[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_MRS:
		MN("mrs");
		sysreg_name(nm, sizeof nm, (a->w >> 5) & 0x7fffu);
		OP("%s, %s", rg(x, rt, 1, 0), nm);
		break;
	case KGENOME_ARM64_I_MSR:
		MN("msr");
		sysreg_name(nm, sizeof nm, (a->w >> 5) & 0x7fffu);
		OP("%s, %s", nm, rg(x, rt, 1, 0));
		break;
	case KGENOME_ARM64_I_MSR_PSTATE: {
		unsigned op1 = (a->w >> 16) & 7u, op2 = (a->w >> 5) & 7u;
		const char *f = op1 == 3u && op2 == 6u ? "daifset" : op1 == 3u && op2 == 7u ? "daifclr" :
				op1 == 0u && op2 == 5u ? "spsel" : op1 == 0u && op2 == 4u ? "pan" :
				op1 == 0u && op2 == 3u ? "uao" : op1 == 3u && op2 == 2u ? "dit" :
				op1 == 3u && op2 == 1u ? "ssbs" : op1 == 3u && op2 == 4u ? "tco" : NULL;

		if (!f) {                       /* SME's SMSTART/SMSTOP and what the table does not know are not claimed */
			a->unsupported = 1;
			break;
		}
		MN("msr");
		OP("%s, #0x%x", f, crm);
		break;
	}
	case KGENOME_ARM64_I_HINT:
	case KGENOME_ARM64_I_XPACLRI:
	case KGENOME_ARM64_I_HINT_PAC_LR:
	case KGENOME_ARM64_I_HINT_PAC_X17:
		fmt_hint(a);
		break;
	case KGENOME_ARM64_I_DSB:
	case KGENOME_ARM64_I_DMB:
		if (a->in->id == KGENOME_ARM64_I_DSB && crm == 0u) {
			MN("ssbb");
			break;
		}
		if (a->in->id == KGENOME_ARM64_I_DSB && crm == 4u) {
			MN("pssbb");
			break;
		}
		MN(a->in->id == KGENOME_ARM64_I_DSB ? "dsb" : "dmb");
		OP("%s", barrier_opt(o, crm));
		break;
	case KGENOME_ARM64_I_ISB:
		MN("isb");
		if (crm != 15u)
			OP("#0x%x", crm);
		break;
	case KGENOME_ARM64_I_CLREX:
		MN("clrex");
		if (crm != 15u)
			OP("#0x%x", crm);
		break;
	case KGENOME_ARM64_I_SB:
		MN("sb");
		break;
	case KGENOME_ARM64_I_SYS: {
		unsigned op1 = (a->w >> 16) & 7u, crn = (a->w >> 12) & 15u, op2 = (a->w >> 5) & 7u;
		const char *dc = NULL, *ic = NULL;

		if (crn == 7u && op1 == 3u && crm == 4u && op2 == 1u)
			dc = "zva";
		else if (crn == 7u && op1 == 3u && crm == 10u && op2 == 1u)
			dc = "cvac";
		else if (crn == 7u && op1 == 3u && crm == 11u && op2 == 1u)
			dc = "cvau";
		else if (crn == 7u && op1 == 3u && crm == 14u && op2 == 1u)
			dc = "civac";
		else if (crn == 7u && op1 == 3u && crm == 4u && op2 == 3u)
			dc = "gva";
		else if (crn == 7u && op1 == 3u && crm == 4u && op2 == 4u)
			dc = "gzva";
		else if (crn == 7u && op1 == 0u && crm == 6u && op2 == 1u)
			dc = "ivac";
		else if (crn == 7u && op1 == 0u && crm == 6u && op2 == 2u)
			dc = "isw";
		else if (crn == 7u && op1 == 0u && crm == 10u && op2 == 2u)
			dc = "csw";
		else if (crn == 7u && op1 == 0u && crm == 14u && op2 == 2u)
			dc = "cisw";
		else if (crn == 7u && op1 == 0u && crm == 5u && op2 == 0u)
			ic = "iallu";
		else if (crn == 7u && op1 == 0u && crm == 1u && op2 == 0u)
			ic = "ialluis";
		else if (crn == 7u && op1 == 3u && crm == 5u && op2 == 1u)
			ic = "ivau";
		if (dc || ic) {
			MN(dc ? "dc" : "ic");
			if (ic && op2 == 0u)
				OP("%s", ic);
			else
				OP("%s, %s", dc ? dc : ic, rg(x, rt, 1, 0));
		} else if (crn == 7u || crn == 8u) {
			a->unsupported = 1;     /* the cache, address-translation and TLB operations have names in the assembler (dc, ic, at, tlbi ...) that this table has only in part */
		} else {
			MN("sys");
			OP("#%u, c%u, c%u, #%u", op1, crn, crm, op2);
			if (rt != 31u)
				OP(", %s", rg(x, rt, 1, 0));
		}
		break;
	}
	default:
		a->unsupported = 1;
		break;
	}
}

static void fmt_branch_reg(struct a64 *a)
{
	unsigned rn = (a->w >> 5) & 31u;
	char x[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_BR:
		MN("br");
		a->flow = KGENOME_GT_FLOW_JUMP;
		OP("%s", rg(x, rn, 1, 0));
		break;
	case KGENOME_ARM64_I_BLR:
		MN("blr");
		a->flow = KGENOME_GT_FLOW_CALL;
		OP("%s", rg(x, rn, 1, 0));
		break;
	case KGENOME_ARM64_I_RET:
		MN("ret");
		a->flow = KGENOME_GT_FLOW_RET;
		if (rn != 30u)
			OP("%s", rg(x, rn, 1, 0));
		break;
	case KGENOME_ARM64_I_ERET:
		MN("eret");
		a->flow = KGENOME_GT_FLOW_RET;
		break;
	case KGENOME_ARM64_I_DRPS:
		MN("drps");
		a->flow = KGENOME_GT_FLOW_RET;
		break;
	default:
		a->unsupported = 1;
		break;
	}
}

static void fmt_exception(struct a64 *a)
{
	const char *m;

	switch (a->in->id) {
	case KGENOME_ARM64_I_SVC: m = "svc"; break;
	case KGENOME_ARM64_I_HVC: m = "hvc"; break;
	case KGENOME_ARM64_I_SMC: m = "smc"; break;
	case KGENOME_ARM64_I_BRK: m = "brk"; break;
	case KGENOME_ARM64_I_HLT: m = "hlt"; break;
	case KGENOME_ARM64_I_DCPS1: m = "dcps1"; break;
	case KGENOME_ARM64_I_DCPS2: m = "dcps2"; break;
	case KGENOME_ARM64_I_DCPS3: m = "dcps3"; break;
	default:
		m = "udf";
		break;
	}
	MN("%s", m);
	if (a->in->id == KGENOME_ARM64_I_UDF) {
		OP("#%u", a->w & 0xffffu);                 /* the one immediate this assembler writes in decimal */
	} else if (a->in->id == KGENOME_ARM64_I_DCPS1 || a->in->id == KGENOME_ARM64_I_DCPS2 || a->in->id == KGENOME_ARM64_I_DCPS3) {
		if (kgenome_arm64_imm16(a->in))
			OP("#0x%x", kgenome_arm64_imm16(a->in));
	} else {
		OP("#0x%x", kgenome_arm64_imm16(a->in));
	}
	a->flow = KGENOME_GT_FLOW_TRAP;
}

/* ---- loads and stores ----------------------------------------------------- */

/* the base register of an address, sp for 31 */
static const char *base(char *b, unsigned rn)
{
	return rg(b, rn, 1, 1);
}

static void put_address(struct a64 *a, unsigned am, unsigned rn, int64_t off)
{
	char b[8];

	switch (am) {
	case KGENOME_ARM64_AM_POST:
		OP("[%s], #%lld", base(b, rn), (long long)off);
		break;
	case KGENOME_ARM64_AM_PRE:
		OP("[%s, #%lld]!", base(b, rn), (long long)off);
		break;
	default:
		if (off)
			OP("[%s, #%lld]", base(b, rn), (long long)off);
		else
			OP("[%s]", base(b, rn));
		break;
	}
}

static void put_reg_offset(struct a64 *a, unsigned rn, unsigned shift_bytes)
{
	unsigned opt = (a->w >> 13) & 7u, s = (a->w >> 12) & 1u, rm = (a->w >> 16) & 31u;
	char b[8], m[8];

	if (opt == 3u) {
		if (s)
			OP("[%s, %s, lsl #%u]", base(b, rn), rg(m, rm, 1, 0), shift_bytes);
		else
			OP("[%s, %s]", base(b, rn), rg(m, rm, 1, 0));
		return;
	}
	if (s)
		OP("[%s, %s, %s #%u]", base(b, rn), rg(m, rm, opt & 1u, 0), g_ext[opt], shift_bytes);
	else
		OP("[%s, %s, %s]", base(b, rn), rg(m, rm, opt & 1u, 0), g_ext[opt]);
}

static const char *const g_prfop[32] = {
	"pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm", "pldl3keep", "pldl3strm", "pldslckeep", "pldslcstrm",
	"plil1keep", "plil1strm", "plil2keep", "plil2strm", "plil3keep", "plil3strm", "plislckeep", "plislcstrm",
	"pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm", "pstl3keep", "pstl3strm", "pstslckeep", "pstslcstrm",
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static const char *prf_op(char *b, unsigned n)
{
	if (n < 24u && g_prfop[n])
		return g_prfop[n];
	snprintf(b, 8, "#0x%x", n);
	return b;
}

/* STR/LDR of one register, in every address form */
static void fmt_ldst_single(struct a64 *a)
{
	unsigned k = kgenome_arm64_lskind(a->in), am = kgenome_arm64_amode(a->in);
	unsigned size = a->w >> 30, opc = (a->w >> 22) & 3u, rt = a->w & 31u, rn = (a->w >> 5) & 31u;
	int unscaled = am == KGENOME_ARM64_AM_UNSCALED || am == KGENOME_ARM64_AM_UNPRIV;
	int fp = k == KGENOME_ARM64_K_STORE_FP || k == KGENOME_ARM64_K_LOAD_FP;
	int64_t off = kgenome_arm64_ldst_off(a->in);
	const char *sfx, *base_m;
	char x[8], pf[8];
	unsigned sf = size == 3u, shift;

	switch (k) {
	case KGENOME_ARM64_K_STORE:
	case KGENOME_ARM64_K_STORE_FP:
		base_m = "str";
		break;
	case KGENOME_ARM64_K_PREFETCH:
		base_m = "prfm";
		break;
	default:
		base_m = "ldr";
		break;
	}
	if (k == KGENOME_ARM64_K_PREFETCH) {
		if (rt >= 24u) {                /* prefetch types this table does not know (named by newer extensions) */
			a->unsupported = 1;
			return;
		}
		MN(unscaled ? "prfum" : "prfm");
		OP("%s, ", prf_op(pf, rt));
		if (am == KGENOME_ARM64_AM_REG)
			put_reg_offset(a, rn, 3u);
		else
			put_address(a, am, rn, off);
		return;
	}
	if (fp) {
		unsigned bytes = size == 0u && opc >= 2u ? 16u : 1u << size;

		MN("%s", unscaled ? (k == KGENOME_ARM64_K_STORE_FP ? "stur" : "ldur") : base_m);
		OP("%s, ", fr(x, rt, bytes));
		shift = bytes == 16u ? 4u : size;
	} else {
		sfx = size == 0u ? "b" : size == 1u ? "h" : "";
		if (k == KGENOME_ARM64_K_LOAD_S64 || k == KGENOME_ARM64_K_LOAD_S32) {
			sfx = size == 0u ? "sb" : size == 1u ? "sh" : "sw";
			sf = k == KGENOME_ARM64_K_LOAD_S64;
		} else if (size == 3u || size == 2u) {
			sfx = "";
		}
		if (unscaled && am == KGENOME_ARM64_AM_UNPRIV)
			MN("%s%s", k == KGENOME_ARM64_K_STORE ? "sttr" : "ldtr", sfx);
		else if (unscaled)
			MN("%s%s", k == KGENOME_ARM64_K_STORE ? "stur" : "ldur", sfx);
		else
			MN("%s%s", base_m, sfx);
		OP("%s, ", rg(x, rt, sf, 0));
		shift = size;
	}
	if (am == KGENOME_ARM64_AM_REG)
		put_reg_offset(a, rn, shift);
	else
		put_address(a, am, rn, off);
}

static void fmt_ldst_lit(struct a64 *a)
{
	unsigned rt = a->w & 31u, opc = a->w >> 30;
	int64_t off = kgenome_arm64_ldst_off(a->in);
	char x[8], pf[8];
	uint64_t t = a->pc + (uint64_t)off;

	switch (a->in->id) {
	case KGENOME_ARM64_I_LDR_LIT_W:
		MN("ldr");
		OP("%s, 0x%llx", rg(x, rt, 0, 0), (unsigned long long)t);
		break;
	case KGENOME_ARM64_I_LDR_LIT_X:
		MN("ldr");
		OP("%s, 0x%llx", rg(x, rt, 1, 0), (unsigned long long)t);
		break;
	case KGENOME_ARM64_I_LDRSW_LIT:
		MN("ldrsw");
		OP("%s, 0x%llx", rg(x, rt, 1, 0), (unsigned long long)t);
		break;
	case KGENOME_ARM64_I_PRFM_LIT:
		MN("prfm");
		OP("%s, 0x%llx", prf_op(pf, rt), (unsigned long long)t);
		break;
	default:
		MN("ldr");
		OP("%s, 0x%llx", fr(x, rt, 4u << opc), (unsigned long long)t);
		break;
	}
	a->has_target = 1;
	a->target = t;
}

static void fmt_ldst_pair(struct a64 *a)
{
	unsigned k = kgenome_arm64_lskind(a->in), am = kgenome_arm64_amode(a->in);
	unsigned opc = a->w >> 30, rt = a->w & 31u, rt2 = (a->w >> 10) & 31u, rn = (a->w >> 5) & 31u;
	int fp = k == KGENOME_ARM64_K_STORE_FP || k == KGENOME_ARM64_K_LOAD_FP;
	int64_t off = kgenome_arm64_ldst_off(a->in);
	int store = k == KGENOME_ARM64_K_STORE || k == KGENOME_ARM64_K_STORE_FP;
	char x[8], y[8];
	const char *m;

	/* a written-back base that is also a transferred register: the oracle calls the word undefined, so it is not claimed */
	if ((am == KGENOME_ARM64_AM_POST || am == KGENOME_ARM64_AM_PRE) && rn != 31u && (rt == rn || rt2 == rn)) {
		a->unsupported = 1;
		return;
	}
	if (!store && rt == rt2) {              /* a load of two registers into one */
		a->unsupported = 1;
		return;
	}
	switch (a->in->id) {
	case KGENOME_ARM64_I_STNP: case KGENOME_ARM64_I_LDNP: case KGENOME_ARM64_I_STNP_FP: case KGENOME_ARM64_I_LDNP_FP:
		m = store ? "stnp" : "ldnp";
		break;
	case KGENOME_ARM64_I_STGP_POST: case KGENOME_ARM64_I_STGP_OFF: case KGENOME_ARM64_I_STGP_PRE:
		m = "stgp";
		break;
	case KGENOME_ARM64_I_LDPSW_POST: case KGENOME_ARM64_I_LDPSW_OFF: case KGENOME_ARM64_I_LDPSW_PRE:
		m = "ldpsw";
		break;
	default:
		m = store ? "stp" : "ldp";
		break;
	}
	MN("%s", m);
	if (fp) {
		unsigned bytes = 4u << opc;

		OP("%s, %s, ", fr(x, rt, bytes), fr(y, rt2, bytes));
	} else if (a->in->id >= KGENOME_ARM64_I_STGP_POST && a->in->id <= KGENOME_ARM64_I_STGP_PRE) {
		OP("%s, %s, ", rg(x, rt, 1, 0), rg(y, rt2, 1, 0));
	} else {
		unsigned sf = opc != 0u;

		OP("%s, %s, ", rg(x, rt, sf, 0), rg(y, rt2, sf, 0));
	}
	put_address(a, am, rn, off);
}

/* exclusive, ordered and compare-and-swap forms, and the atomics: size and the acquire/release bits come from the word */
static void fmt_ldst_excl(struct a64 *a)
{
	unsigned size = a->w >> 30, rt = a->w & 31u, rn = (a->w >> 5) & 31u, rt2 = (a->w >> 10) & 31u, rs = (a->w >> 16) & 31u;
	unsigned o0 = (a->w >> 15) & 1u, l = (a->w >> 22) & 1u, ar = (a->w >> 23) & 1u;
	const char *sfx = size == 0u ? "b" : size == 1u ? "h" : "";
	unsigned sf = size == 3u;
	char x[8], y[8], z[8], b[8];

	/* should-be-one fields: Rt2 (14:10) of the single-register forms and Rs (20:16) of the loads and releases; the oracle calls a word without them undefined */
	switch (a->in->id) {
	case KGENOME_ARM64_I_STXR: case KGENOME_ARM64_I_LDXR: case KGENOME_ARM64_I_STLR:
	case KGENOME_ARM64_I_LDAR: case KGENOME_ARM64_I_CAS:
		if (rt2 != 31u) {
			a->unsupported = 1;
			return;
		}
		break;
	default:
		break;
	}
	if ((a->in->id == KGENOME_ARM64_I_LDXR || a->in->id == KGENOME_ARM64_I_STLR || a->in->id == KGENOME_ARM64_I_LDAR) && rs != 31u) {
		a->unsupported = 1;
		return;
	}
	if (a->in->id == KGENOME_ARM64_I_LDXP && rs != 31u) {
		a->unsupported = 1;
		return;
	}
	if (a->in->id == KGENOME_ARM64_I_CASP && rt2 != 31u) {
		a->unsupported = 1;
		return;
	}

	switch (a->in->id) {
	case KGENOME_ARM64_I_STXR:
		MN("st%sxr%s", o0 ? "l" : "", sfx);
		OP("%s, %s, [%s]", rg(x, rs, 0, 0), rg(y, rt, sf, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_LDXR:
		MN("ld%sxr%s", o0 ? "a" : "", sfx);
		OP("%s, [%s]", rg(x, rt, sf, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_STXP:
		MN("st%sxp", o0 ? "l" : "");
		OP("%s, %s, %s, [%s]", rg(x, rs, 0, 0), rg(y, rt, size == 3u, 0), rg(z, rt2, size == 3u, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_LDXP:
		MN("ld%sxp", o0 ? "a" : "");
		OP("%s, %s, [%s]", rg(x, rt, size == 3u, 0), rg(y, rt2, size == 3u, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_STLR:
		MN("%s%s", o0 ? "stlr" : "stllr", sfx);
		OP("%s, [%s]", rg(x, rt, sf, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_LDAR:
		MN("%s%s", o0 ? "ldar" : "ldlar", sfx);
		OP("%s, [%s]", rg(x, rt, sf, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_CAS:
		MN("cas%s%s%s", l ? "a" : "", o0 ? "l" : "", sfx);
		OP("%s, %s, [%s]", rg(x, rs, sf, 0), rg(y, rt, sf, 0), base(b, rn));
		break;
	case KGENOME_ARM64_I_CASP:
		MN("casp%s%s", l ? "a" : "", o0 ? "l" : "");
		OP("%s, %s, %s, %s, [%s]", rg(x, rs, size == 3u, 0), rg(y, rs + 1u, size == 3u, 0),
		   rg(z, rt, size == 3u, 0), rg(b, rt + 1u, size == 3u, 0), base(x, rn));
		break;
	default:
		a->unsupported = 1;
		break;
	}
	(void)ar;
}

static void fmt_atomic(struct a64 *a)
{
	static const char *const op[8] = { "add", "clr", "eor", "set", "smax", "smin", "umax", "umin" };
	unsigned size = a->w >> 30, rt = a->w & 31u, rn = (a->w >> 5) & 31u, rs = (a->w >> 16) & 31u;
	unsigned acq = (a->w >> 23) & 1u, rel = (a->w >> 22) & 1u, o = (a->w >> 12) & 7u;
	const char *sfx = size == 0u ? "b" : size == 1u ? "h" : "";
	unsigned sf = size == 3u;
	char x[8], y[8], b[8];

	if (a->in->id == KGENOME_ARM64_I_LDAPR && rs != 31u) {         /* Rs should be one */
		a->unsupported = 1;
		return;
	}
	switch (a->in->id) {
	case KGENOME_ARM64_I_SWP:
		MN("swp%s%s%s", acq ? "a" : "", rel ? "l" : "", sfx);
		OP("%s, %s, [%s]", rg(x, rs, sf, 0), rg(y, rt, sf, 0), base(b, rn));
		return;
	case KGENOME_ARM64_I_LDAPR:
		MN("ldapr%s", sfx);
		OP("%s, [%s]", rg(x, rt, sf, 0), base(b, rn));
		return;
	default:
		break;
	}
	if (rt == 31u && !acq) {
		MN("st%s%s%s", op[o], rel ? "l" : "", sfx);
		OP("%s, [%s]", rg(x, rs, sf, 0), base(b, rn));
		return;
	}
	MN("ld%s%s%s%s", op[o], acq ? "a" : "", rel ? "l" : "", sfx);
	OP("%s, %s, [%s]", rg(x, rs, sf, 0), rg(y, rt, sf, 0), base(b, rn));
}

/* ---- data processing, register ---------------------------------------------- */

static void shifted(struct a64 *a, unsigned type, unsigned amount)
{
	if (amount || type != 0u)
		OP(", %s #%u", g_shift[type], amount);
}

static void fmt_logic_reg(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u;
	unsigned type = (a->w >> 22) & 3u, amt = (a->w >> 10) & 63u;
	char x[8], y[8], z[8];
	const char *m;

	if (!sf && amt > 31u) {
		a->unsupported = 1;
		return;
	}
	switch (a->in->id) {
	case KGENOME_ARM64_I_AND_REG: m = "and"; break;
	case KGENOME_ARM64_I_BIC_REG: m = "bic"; break;
	case KGENOME_ARM64_I_ORR_REG:
		if (rn == 31u && amt == 0u && type == 0u) {
			MN("mov");
			OP("%s, %s", rg(x, rd, sf, 0), rg(y, rm, sf, 0));
			return;
		}
		m = "orr";
		break;
	case KGENOME_ARM64_I_ORN_REG:
		if (rn == 31u) {
			MN("mvn");
			OP("%s, %s", rg(x, rd, sf, 0), rg(y, rm, sf, 0));
			shifted(a, type, amt);
			return;
		}
		m = "orn";
		break;
	case KGENOME_ARM64_I_EOR_REG: m = "eor"; break;
	case KGENOME_ARM64_I_EON_REG: m = "eon"; break;
	case KGENOME_ARM64_I_ANDS_REG:
		if (rd == 31u) {
			MN("tst");
			OP("%s, %s", rg(x, rn, sf, 0), rg(y, rm, sf, 0));
			shifted(a, type, amt);
			return;
		}
		m = "ands";
		break;
	default: m = "bics"; break;
	}
	MN("%s", m);
	OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0));
	shifted(a, type, amt);
}

static void fmt_addsub_reg(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u;
	unsigned type = (a->w >> 22) & 3u, amt = (a->w >> 10) & 63u;
	char x[8], y[8], z[8];
	int sub = a->in->id == KGENOME_ARM64_I_SUB_REG || a->in->id == KGENOME_ARM64_I_SUBS_REG;
	int flags = a->in->id == KGENOME_ARM64_I_ADDS_REG || a->in->id == KGENOME_ARM64_I_SUBS_REG;

	if ((!sf && amt > 31u) || type == 3u) {
		a->unsupported = 1;
		return;
	}
	if (flags && rd == 31u) {
		MN(sub ? "cmp" : "cmn");
		OP("%s, %s", rg(x, rn, sf, 0), rg(y, rm, sf, 0));
		shifted(a, type, amt);
		return;
	}
	if (sub && rn == 31u) {
		MN(flags ? "negs" : "neg");
		OP("%s, %s", rg(x, rd, sf, 0), rg(y, rm, sf, 0));
		shifted(a, type, amt);
		return;
	}
	MN("%s%s", sub ? "sub" : "add", flags ? "s" : "");
	OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0));
	shifted(a, type, amt);
}

static void fmt_addsub_ext(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u;
	unsigned opt = (a->w >> 13) & 7u, amt = (a->w >> 10) & 7u;
	int sub = a->in->id == KGENOME_ARM64_I_SUB_EXT || a->in->id == KGENOME_ARM64_I_SUBS_EXT;
	int flags = a->in->id == KGENOME_ARM64_I_ADDS_EXT || a->in->id == KGENOME_ARM64_I_SUBS_EXT;
	char x[8], y[8], z[8];
	/* the extended register is x only for UXTX/SXTX */
	unsigned msf = sf && (opt & 3u) == 3u;      /* a 32-bit instruction names a w register even for UXTX */
	int lsl = (sf ? opt == 3u : opt == 2u) && (flags ? rn == 31u : (rd == 31u || rn == 31u));

	if (amt > 4u) {
		a->unsupported = 1;
		return;
	}
	if (flags && rd == 31u) {
		MN(sub ? "cmp" : "cmn");
		OP("%s, %s", rg(x, rn, sf, 1), rg(y, rm, msf, 0));
	} else {
		MN("%s%s", sub ? "sub" : "add", flags ? "s" : "");
		OP("%s, %s, %s", rg(x, rd, sf, flags ? 0 : 1), rg(y, rn, sf, 1), rg(z, rm, msf, 0));
	}
	if (lsl) {
		if (amt)
			OP(", lsl #%u", amt);
	} else if (amt) {
		OP(", %s #%u", g_ext[opt], amt);
	} else {
		OP(", %s", g_ext[opt]);
	}
}

static void fmt_addsub_imm(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, sh = (a->w >> 22) & 1u;
	uint64_t imm12 = (a->w >> 10) & 0xfffu;
	int sub = a->in->id == KGENOME_ARM64_I_SUB_IMM || a->in->id == KGENOME_ARM64_I_SUBS_IMM;
	int flags = a->in->id == KGENOME_ARM64_I_ADDS_IMM || a->in->id == KGENOME_ARM64_I_SUBS_IMM;
	char x[8], y[8];

	if ((a->w >> 23) & 1u) {
		a->unsupported = 1;
		return;
	}
	if (!flags && !sub && imm12 == 0 && !sh && (rd == 31u || rn == 31u)) {
		MN("mov");
		OP("%s, %s", rg(x, rd, sf, 1), rg(y, rn, sf, 1));
		return;
	}
	if (flags && rd == 31u) {
		MN(sub ? "cmp" : "cmn");
		OP("%s, #0x%llx", rg(x, rn, sf, 1), (unsigned long long)imm12);
	} else {
		MN("%s%s", sub ? "sub" : "add", flags ? "s" : "");
		OP("%s, %s, #0x%llx", rg(x, rd, sf, flags ? 0 : 1), rg(y, rn, sf, 1), (unsigned long long)imm12);
	}
	if (sh)
		OP(", lsl #12");
}

static void fmt_pcrel(struct a64 *a)
{
	char x[8];
	int64_t imm = kgenome_arm64_adr_imm(a->in);
	uint64_t t = a->in->id == KGENOME_ARM64_I_ADRP ? (a->pc & ~0xfffull) + (uint64_t)(imm * 4096)
						       : a->pc + (uint64_t)imm;

	MN(a->in->id == KGENOME_ARM64_I_ADRP ? "adrp" : "adr");
	OP("%s, 0x%llx", rg(x, a->w & 31u, 1, 0), (unsigned long long)t);
	a->has_target = 1;
	a->target = t;
}

static void fmt_three_src(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u, ra = (a->w >> 10) & 31u;
	char x[8], y[8], z[8], t[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_MADD:
	case KGENOME_ARM64_I_MSUB: {
		int sub = a->in->id == KGENOME_ARM64_I_MSUB;

		if (ra == 31u) {
			MN(sub ? "mneg" : "mul");
			OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0));
		} else {
			MN(sub ? "msub" : "madd");
			OP("%s, %s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0), rg(t, ra, sf, 0));
		}
		return;
	}
	case KGENOME_ARM64_I_SMADDL: case KGENOME_ARM64_I_SMSUBL:
	case KGENOME_ARM64_I_UMADDL: case KGENOME_ARM64_I_UMSUBL: {
		int sub = a->in->id == KGENOME_ARM64_I_SMSUBL || a->in->id == KGENOME_ARM64_I_UMSUBL;
		const char *u = a->in->id == KGENOME_ARM64_I_UMADDL || a->in->id == KGENOME_ARM64_I_UMSUBL ? "u" : "s";

		if (ra == 31u) {
			MN("%s%sl", u, sub ? "mneg" : "mul");
			OP("%s, %s, %s", rg(x, rd, 1, 0), rg(y, rn, 0, 0), rg(z, rm, 0, 0));
		} else {
			MN("%s%sl", u, sub ? "msub" : "madd");
			OP("%s, %s, %s, %s", rg(x, rd, 1, 0), rg(y, rn, 0, 0), rg(z, rm, 0, 0), rg(t, ra, 1, 0));
		}
		return;
	}
	default:                                                /* SMULH, UMULH */
		MN(a->in->id == KGENOME_ARM64_I_SMULH ? "smulh" : "umulh");
		OP("%s, %s, %s", rg(x, rd, 1, 0), rg(y, rn, 1, 0), rg(z, rm, 1, 0));
		return;
	}
}

static void fmt_carry_cond(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u;
	unsigned c = kgenome_arm64_cond_select(a->in), nzcv = a->w & 15u, imm5 = (a->w >> 16) & 31u;
	char x[8], y[8], z[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_ADC: case KGENOME_ARM64_I_ADCS:
		MN(a->in->id == KGENOME_ARM64_I_ADC ? "adc" : "adcs");
		OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0));
		return;
	case KGENOME_ARM64_I_SBC: case KGENOME_ARM64_I_SBCS: {
		int fl = a->in->id == KGENOME_ARM64_I_SBCS;

		if (rn == 31u) {
			MN(fl ? "ngcs" : "ngc");
			OP("%s, %s", rg(x, rd, sf, 0), rg(z, rm, sf, 0));
		} else {
			MN(fl ? "sbcs" : "sbc");
			OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0));
		}
		return;
	}
	case KGENOME_ARM64_I_CCMN_REG: case KGENOME_ARM64_I_CCMP_REG:
		MN(a->in->id == KGENOME_ARM64_I_CCMN_REG ? "ccmn" : "ccmp");
		OP("%s, %s, #0x%x, %s", rg(x, rn, sf, 0), rg(y, rm, sf, 0), nzcv, g_cc[c]);
		return;
	case KGENOME_ARM64_I_CCMN_IMM: case KGENOME_ARM64_I_CCMP_IMM:
		MN(a->in->id == KGENOME_ARM64_I_CCMN_IMM ? "ccmn" : "ccmp");
		OP("%s, #0x%x, #0x%x, %s", rg(x, rn, sf, 0), imm5, nzcv, g_cc[c]);
		return;
	case KGENOME_ARM64_I_CSEL:
		MN("csel");
		break;
	case KGENOME_ARM64_I_CSINC:
		if (rm == 31u && rn == 31u && (c >> 1) != 7u) {
			MN("cset");
			OP("%s, %s", rg(x, rd, sf, 0), cond_inv(c));
			return;
		}
		if (rm != 31u && rn != 31u && rn == rm && (c >> 1) != 7u) {
			MN("cinc");
			OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), cond_inv(c));
			return;
		}
		MN("csinc");
		break;
	case KGENOME_ARM64_I_CSINV:
		if (rm == 31u && rn == 31u && (c >> 1) != 7u) {
			MN("csetm");
			OP("%s, %s", rg(x, rd, sf, 0), cond_inv(c));
			return;
		}
		if (rm != 31u && rn != 31u && rn == rm && (c >> 1) != 7u) {
			MN("cinv");
			OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), cond_inv(c));
			return;
		}
		MN("csinv");
		break;
	default:                                                /* CSNEG */
		if (rn == rm && (c >> 1) != 7u) {
			MN("cneg");
			OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), cond_inv(c));
			return;
		}
		MN("csneg");
		break;
	}
	OP("%s, %s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0), g_cc[c]);
}

static void fmt_dp_reg(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u;
	char x[8], y[8], z[8];
	const char *m = NULL;

	switch (a->in->id) {
	case KGENOME_ARM64_I_RBIT: m = "rbit"; break;
	case KGENOME_ARM64_I_REV16: m = "rev16"; break;
	case KGENOME_ARM64_I_REV: m = sf ? "rev32" : "rev"; break;
	case KGENOME_ARM64_I_REV64: m = "rev"; break;
	case KGENOME_ARM64_I_CLZ: m = "clz"; break;
	case KGENOME_ARM64_I_CLS: m = "cls"; break;
	default: break;
	}
	if (m) {
		MN("%s", m);
		OP("%s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0));
		return;
	}
	switch (a->in->id) {
	case KGENOME_ARM64_I_UDIV: m = "udiv"; break;
	case KGENOME_ARM64_I_SDIV: m = "sdiv"; break;
	case KGENOME_ARM64_I_LSLV: m = "lsl"; break;
	case KGENOME_ARM64_I_LSRV: m = "lsr"; break;
	case KGENOME_ARM64_I_ASRV: m = "asr"; break;
	case KGENOME_ARM64_I_RORV: m = "ror"; break;
	default: break;
	}
	if (m) {
		MN("%s", m);
		OP("%s, %s, %s", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0));
		return;
	}
	if (a->in->id >= KGENOME_ARM64_I_CRC32B && a->in->id <= KGENOME_ARM64_I_CRC32CX) {
		unsigned i = a->in->id - KGENOME_ARM64_I_CRC32B, c = i >> 2, sz = i & 3u;

		MN("crc32%s%c", c ? "c" : "", "bhwx"[sz]);
		OP("%s, %s, %s", rg(x, rd, 0, 0), rg(y, rn, 0, 0), rg(z, rm, sz == 3u, 0));
		return;
	}
	a->unsupported = 1;
}

static void fmt_extr(struct a64 *a)
{
	unsigned sf = a->w >> 31, rd = a->w & 31u, rn = (a->w >> 5) & 31u, rm = (a->w >> 16) & 31u, lsb = (a->w >> 10) & 63u;
	char x[8], y[8], z[8];

	if (!sf && lsb > 31u) {
		a->unsupported = 1;
		return;
	}
	if (rn == rm) {
		MN("ror");
		OP("%s, %s, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), lsb);
	} else {
		MN("extr");
		OP("%s, %s, %s, #%u", rg(x, rd, sf, 0), rg(y, rn, sf, 0), rg(z, rm, sf, 0), lsb);
	}
}

static void fmt_flagmanip(struct a64 *a)
{
	unsigned rn = (a->w >> 5) & 31u;
	char x[8];

	switch (a->in->id) {
	case KGENOME_ARM64_I_SETF8:
		MN("setf8");
		OP("%s", rg(x, rn, 0, 0));
		break;
	case KGENOME_ARM64_I_SETF16:
		MN("setf16");
		OP("%s", rg(x, rn, 0, 0));
		break;
	default:
		MN("rmif");
		OP("%s, #%u, #%u", rg(x, rn, 1, 0), (a->w >> 15) & 63u, a->w & 15u);
		break;
	}
}

static void spell(struct a64 *a)
{
	unsigned id = a->in->id;

	if (id >= KGENOME_ARM64_I_LDR_LIT_W && id <= KGENOME_ARM64_I_LDR_LIT_FP) {
		if (id == KGENOME_ARM64_I_LDR_LIT_FP && ((a->w >> 30) & 3u) == 3u) {
			a->unsupported = 1;
			return;
		}
		fmt_ldst_lit(a);
		return;
	}
	if (id >= KGENOME_ARM64_I_STNP && id <= KGENOME_ARM64_I_LDP_FP_PRE) {
		if ((((a->w >> 30) & 3u) == 3u) && (kgenome_arm64_lskind(a->in) == KGENOME_ARM64_K_STORE_FP ||
						     kgenome_arm64_lskind(a->in) == KGENOME_ARM64_K_LOAD_FP)) {
			a->unsupported = 1;
			return;
		}
		fmt_ldst_pair(a);
		return;
	}
	if (id >= KGENOME_ARM64_I_STR_UOFF && id <= KGENOME_ARM64_I_LDAPURS32) {
		/* STLUR, LDAPUR*: the release/acquire forms of the unscaled access, not spelled */
		if (id >= KGENOME_ARM64_I_STLUR) {
			a->unsupported = 1;
			return;
		}
		fmt_ldst_single(a);
		return;
	}
	switch (id) {
	case KGENOME_ARM64_I_ADR: case KGENOME_ARM64_I_ADRP:
		fmt_pcrel(a);
		return;
	case KGENOME_ARM64_I_ADD_IMM: case KGENOME_ARM64_I_ADDS_IMM:
	case KGENOME_ARM64_I_SUB_IMM: case KGENOME_ARM64_I_SUBS_IMM:
		fmt_addsub_imm(a);
		return;
	case KGENOME_ARM64_I_AND_IMM: case KGENOME_ARM64_I_ORR_IMM:
	case KGENOME_ARM64_I_EOR_IMM: case KGENOME_ARM64_I_ANDS_IMM:
		fmt_logic_imm(a);
		return;
	case KGENOME_ARM64_I_MOVN: case KGENOME_ARM64_I_MOVZ: case KGENOME_ARM64_I_MOVK:
		fmt_movw(a);
		return;
	case KGENOME_ARM64_I_SBFM: case KGENOME_ARM64_I_BFM: case KGENOME_ARM64_I_UBFM:
		fmt_bitfield(a);
		return;
	case KGENOME_ARM64_I_EXTR:
		fmt_extr(a);
		return;
	case KGENOME_ARM64_I_B: case KGENOME_ARM64_I_BL: case KGENOME_ARM64_I_CBZ:
	case KGENOME_ARM64_I_CBNZ: case KGENOME_ARM64_I_BCOND: case KGENOME_ARM64_I_TBZ:
	case KGENOME_ARM64_I_TBNZ:
		fmt_branch(a);
		return;
	case KGENOME_ARM64_I_SVC: case KGENOME_ARM64_I_HVC: case KGENOME_ARM64_I_SMC:
	case KGENOME_ARM64_I_BRK: case KGENOME_ARM64_I_HLT: case KGENOME_ARM64_I_UDF:
	case KGENOME_ARM64_I_DCPS1: case KGENOME_ARM64_I_DCPS2: case KGENOME_ARM64_I_DCPS3:
		fmt_exception(a);
		return;
	case KGENOME_ARM64_I_BR: case KGENOME_ARM64_I_BLR: case KGENOME_ARM64_I_RET:
	case KGENOME_ARM64_I_ERET: case KGENOME_ARM64_I_DRPS:
		fmt_branch_reg(a);
		return;
	case KGENOME_ARM64_I_MRS: case KGENOME_ARM64_I_MSR: case KGENOME_ARM64_I_SYS:
	case KGENOME_ARM64_I_HINT: case KGENOME_ARM64_I_XPACLRI:
	case KGENOME_ARM64_I_HINT_PAC_LR: case KGENOME_ARM64_I_HINT_PAC_X17:
	case KGENOME_ARM64_I_CLREX: case KGENOME_ARM64_I_DSB: case KGENOME_ARM64_I_DMB:
	case KGENOME_ARM64_I_ISB: case KGENOME_ARM64_I_SB: case KGENOME_ARM64_I_MSR_PSTATE:
		fmt_system(a);
		return;
	case KGENOME_ARM64_I_STXR: case KGENOME_ARM64_I_LDXR: case KGENOME_ARM64_I_STXP:
	case KGENOME_ARM64_I_LDXP: case KGENOME_ARM64_I_CASP: case KGENOME_ARM64_I_STLR:
	case KGENOME_ARM64_I_LDAR: case KGENOME_ARM64_I_CAS:
		fmt_ldst_excl(a);
		return;
	case KGENOME_ARM64_I_LDADD: case KGENOME_ARM64_I_LDCLR: case KGENOME_ARM64_I_LDEOR:
	case KGENOME_ARM64_I_LDSET: case KGENOME_ARM64_I_LDSMAX: case KGENOME_ARM64_I_LDSMIN:
	case KGENOME_ARM64_I_LDUMAX: case KGENOME_ARM64_I_LDUMIN: case KGENOME_ARM64_I_SWP:
	case KGENOME_ARM64_I_LDAPR:
		fmt_atomic(a);
		return;
	case KGENOME_ARM64_I_AND_REG: case KGENOME_ARM64_I_BIC_REG: case KGENOME_ARM64_I_ORR_REG:
	case KGENOME_ARM64_I_ORN_REG: case KGENOME_ARM64_I_EOR_REG: case KGENOME_ARM64_I_EON_REG:
	case KGENOME_ARM64_I_ANDS_REG: case KGENOME_ARM64_I_BICS_REG:
		fmt_logic_reg(a);
		return;
	case KGENOME_ARM64_I_ADD_REG: case KGENOME_ARM64_I_ADDS_REG:
	case KGENOME_ARM64_I_SUB_REG: case KGENOME_ARM64_I_SUBS_REG:
		fmt_addsub_reg(a);
		return;
	case KGENOME_ARM64_I_ADD_EXT: case KGENOME_ARM64_I_ADDS_EXT:
	case KGENOME_ARM64_I_SUB_EXT: case KGENOME_ARM64_I_SUBS_EXT:
		fmt_addsub_ext(a);
		return;
	case KGENOME_ARM64_I_MADD: case KGENOME_ARM64_I_MSUB: case KGENOME_ARM64_I_SMADDL:
	case KGENOME_ARM64_I_SMSUBL: case KGENOME_ARM64_I_SMULH: case KGENOME_ARM64_I_UMADDL:
	case KGENOME_ARM64_I_UMSUBL: case KGENOME_ARM64_I_UMULH:
		fmt_three_src(a);
		return;
	case KGENOME_ARM64_I_ADC: case KGENOME_ARM64_I_ADCS: case KGENOME_ARM64_I_SBC:
	case KGENOME_ARM64_I_SBCS: case KGENOME_ARM64_I_CCMN_REG: case KGENOME_ARM64_I_CCMN_IMM:
	case KGENOME_ARM64_I_CCMP_REG: case KGENOME_ARM64_I_CCMP_IMM: case KGENOME_ARM64_I_CSEL:
	case KGENOME_ARM64_I_CSINC: case KGENOME_ARM64_I_CSINV: case KGENOME_ARM64_I_CSNEG:
		fmt_carry_cond(a);
		return;
	case KGENOME_ARM64_I_SETF8: case KGENOME_ARM64_I_SETF16: case KGENOME_ARM64_I_RMIF:
		fmt_flagmanip(a);
		return;
	default:
		fmt_dp_reg(a);
		return;
	}
}

void kgenome_arm64_format(const struct kgenome_arm64_fmt_req *req, struct kgenome_gt_fmt_res *res)
{
	struct a64 a;
	const struct kgenome_arm64_insn *in = req->in;

	memset(&a, 0, sizeof a);
	kgenome_gt_fmt_init(&a.f);
	a.in = in;
	a.w = in->word;
	a.pc = req->pc;
	memset(res, 0, sizeof *res);
	if (in->id == KGENOME_ARM64_I_INVALID) {
		res->status = KGENOME_BAD_INPUT;
		res->flow = KGENOME_GT_FLOW_TRAP;
		kgenome_gt_fmt_mn(&a.f, ".inst");
		kgenome_gt_fmt_op(&a.f, "0x%08x ; undefined", in->word);
		(void)kgenome_gt_fmt_done(&a.f, req->buf, req->cap, &res->len);
		return;
	}
	spell(&a);
	if (a.unsupported || a.f.mn_n == 0) {
		kgenome_gt_fmt_init(&a.f);
		kgenome_gt_fmt_mn(&a.f, ".inst");
		kgenome_gt_fmt_op(&a.f, "0x%08x", in->word);
		res->status = KGENOME_UNSUPPORTED;
		(void)kgenome_gt_fmt_done(&a.f, req->buf, req->cap, &res->len);
		return;
	}
	res->flow = a.flow;
	res->has_target = a.has_target;
	res->target = a.target;
	res->status = kgenome_gt_fmt_done(&a.f, req->buf, req->cap, &res->len);
}
