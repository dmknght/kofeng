/*
 * arm32_fmt.c - an ARM state (A32) instruction as text.
 *
 * WHAT THE TEXT IS. The spelling of the GNU assembler's disassembler in unified
 * syntax: lower-case registers (r0 to r12, sp, lr, pc: r11 and r12 are not fp and ip), the
 * condition after the mnemonic and after the S (addseq), the preferred alias
 * (push, pop, nop, lsl for a shifted MOV), immediates in decimal as that
 * disassembler writes them, hex only where it does (svc, bkpt). The mnemonic is
 * put in capitals and padded to one column (gt_fmt_private.h) like the x86 text.
 * The tests compare it with that disassembler's output after two normalisations:
 * case, and runs of white space folded to one; what the oracle adds after the
 * operands (a "@" comment, a symbol in <>) is not compared.
 *
 * WHAT IS SPELLED. The integer instruction set in ARM state: data processing,
 * multiplies, loads and stores (single, halfword, doubleword, multiple, exclusive),
 * branches, the media instructions, barriers. What is NOT: the coprocessor, VFP
 * and Advanced SIMD spaces (the decoder gives them one name each and does not take
 * them apart), the saturating and parallel arithmetic, Thumb state (a caller
 * needs the instruction-set mode, which a file's bytes do not carry). Those words
 * come back with status KGENOME_UNSUPPORTED and the text ".inst 0x........": the
 * length is right and no mnemonic is claimed.
 */
#include <stdio.h>
#include <string.h>

#include "arm32.h"
#include "../gt_fmt_private.h"

static const char *const g_cond[16] = {
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", ""
};
static const char *const g_reg[16] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
};
static const char *const g_shift[4] = { "lsl", "lsr", "asr", "ror" };

struct a32 {
	struct kgenome_gt_fmt f;
	struct kgenome_arm32_insn in;
	uint32_t w;
	uint64_t pc;
	uint8_t flow;
	uint8_t has_target;
	uint64_t target;
	int unsupported;
};

#define MN(...) kgenome_gt_fmt_mn(&a->f, __VA_ARGS__)
#define OP(...) kgenome_gt_fmt_op(&a->f, __VA_ARGS__)
#define R(n) g_reg[(n) & 15u]

static const char *cc(const struct a32 *a)
{
	return g_cond[a->in.cond];
}

/* the mnemonic with its optional S and its condition: "add" "s" "eq" -> addseq */
static void mn_cc(struct a32 *a, const char *m, const char *s)
{
	MN("%s%s%s", m, s, cc(a));
}

/* the shifted-register operand: ", lsl #2", ", rrx", or nothing for lsl #0 */
static void put_shift_imm(struct a32 *a)
{
	unsigned type = kgenome_arm32_shift_type(a->in), n = kgenome_arm32_shift_imm(a->in);

	if (type == 0u && n == 0u)
		return;
	if (type == 3u && n == 0u) {
		OP(", rrx");
		return;
	}
	if ((type == 1u || type == 2u) && n == 0u)
		n = 32u;
	OP(", %s #%u", g_shift[type], n);
}

static void put_shift_reg(struct a32 *a)
{
	OP(", %s %s", g_shift[kgenome_arm32_shift_type(a->in)], R(kgenome_arm32_r8(a->in)));
}

static void branch_to(struct a32 *a, uint8_t flow, int64_t t)
{
	a->flow = flow;
	a->has_target = 1;
	a->target = (uint64_t)t & 0xffffffffu;      /* a 32-bit address space: a branch wraps */
}

/* the register list of LDM, STM, PUSH, POP: every register named, as that assembler lists them */
static void put_list(struct a32 *a, uint32_t list)
{
	unsigned i, first = 1;

	OP("{");
	for (i = 0; i < 16u; i++)
		if (list & (1u << i)) {
			OP("%s%s", first ? "" : ", ", R(i));
			first = 0;
		}
	OP("}");
}

/* ---- data processing -------------------------------------------------------- */

/*
 * The rotated immediate. The value is written as a signed decimal; when a smaller rotation
 * would have given the same value the pair is written instead, "#imm8, rot" (an encoding that is
 * not the one an assembler would choose).
 */
static void put_modimm(struct a32 *a)
{
	uint32_t v = kgenome_arm32_modimm(a->in), imm8 = a->w & 0xffu, rot = ((a->w >> 8) & 15u) * 2u, i;

	for (i = 0; i < 32u; i += 2u)
		if (((v << i) | (i ? v >> (32u - i) : 0u)) <= 0xffu)
			break;
	if (i != rot)
		OP("#%u, %u", imm8, rot);
	else
		OP("#%d", (int32_t)v);
}

enum { DP_AND, DP_EOR, DP_SUB, DP_RSB, DP_ADD, DP_ADC, DP_SBC, DP_RSC, DP_TST, DP_TEQ, DP_CMP, DP_CMN, DP_ORR, DP_MOV, DP_BIC, DP_MVN };
static const char *const g_dp[16] = {
	"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"
};

static void fmt_dp(struct a32 *a, unsigned form)       /* form 0 reg, 1 rsr, 2 imm */
{
	unsigned op = (a->w >> 21) & 15u, rd = kgenome_arm32_r12(a->in), rn = kgenome_arm32_r16(a->in);
	unsigned rm = kgenome_arm32_r0(a->in), s = (unsigned)kgenome_arm32_s(a->in);
	int test = op >= DP_TST && op <= DP_CMN, mov = op == DP_MOV || op == DP_MVN;

	if (mov && rn != 0u) {                  /* Rn is should-be-zero: the oracle calls such a word undefined */
		a->unsupported = 1;
		return;
	}

	if (op == DP_MOV && form == 0u && rd == 0u && rm == 0u && !s && !(a->w & 0xfe0u) && a->in.cond == 14u) {
		MN("nop");
		return;
	}
	if (op == DP_MOV && form != 2u && (((a->w >> 4) & 0xffu) != 0u)) {
		/* a shifted MOV is written as the shift: lsl rd, rm, #n / lsl rd, rm, rs / rrx rd, rm */
		unsigned type = kgenome_arm32_shift_type(a->in), n = kgenome_arm32_shift_imm(a->in);

		if (form == 0u && type == 3u && n == 0u) {
			mn_cc(a, "rrx", s ? "s" : "");
			OP("%s, %s", R(rd), R(rm));
			return;
		}
		mn_cc(a, g_shift[type], s ? "s" : "");
		OP("%s, %s", R(rd), R(rm));
		if (form == 1u)
			OP(", %s", R(kgenome_arm32_r8(a->in)));
		else
			OP(", #%u", (type == 1u || type == 2u) && n == 0u ? 32u : n);
		return;
	}
	if (test && rd == 15u)                  /* the old 26-bit-mode form, which that disassembler marks with a P */
		MN("%sp%s", g_dp[op], cc(a));
	else
		mn_cc(a, g_dp[op], (s && !test) ? "s" : "");
	if (test)
		OP("%s, ", R(rn));
	else if (mov)
		OP("%s, ", R(rd));
	else
		OP("%s, %s, ", R(rd), R(rn));
	if (form == 2u) {
		put_modimm(a);
		return;
	}
	OP("%s", R(rm));
	if (form == 1u)
		put_shift_reg(a);
	else
		put_shift_imm(a);
}

/* ---- loads and stores ---------------------------------------------------- */

/* the "!" of a pre-indexed halfword address with an IMMEDIATE offset: not written for a pc base (the oracle leaves it out there, and keeps it for word transfers and for register offsets) */
static const char *wb_mark(unsigned wb, unsigned rn)
{
	return wb && rn != 15u ? "!" : "";
}

/* the address of a word or byte transfer, immediate or register offset */
static void put_addr_word(struct a32 *a, int reg_off)
{
	unsigned rn = kgenome_arm32_r16(a->in), p = (unsigned)kgenome_arm32_p(a->in), u = (unsigned)kgenome_arm32_u(a->in);
	unsigned wb = (unsigned)kgenome_arm32_wb(a->in);

	if (!reg_off) {
		uint32_t imm = kgenome_arm32_imm12(a->in);

		if (!p) {
			OP("[%s], #%s%u", R(rn), u ? "" : "-", imm);
		} else {
			if (rn == 15u && !wb) {
				a->has_target = 1;
				a->target = a->pc + 8u + (u ? imm : (uint64_t)0 - imm);
			}
			if (imm == 0u && u && !wb)
				OP("[%s]", R(rn));
			else
				OP("[%s, #%s%u]%s", R(rn), u ? "" : "-", imm, wb ? "!" : "");
		}
		return;
	}
	if (!p) {
		OP("[%s], %s%s", R(rn), u ? "" : "-", R(kgenome_arm32_r0(a->in)));
	} else {
		OP("[%s, %s%s", R(rn), u ? "" : "-", R(kgenome_arm32_r0(a->in)));
		put_shift_imm(a);
		OP("]%s", wb ? "!" : "");
	}
	if (!p)
		put_shift_imm(a);
}

static void fmt_ldst_word(struct a32 *a, int load, int byte, int reg_off)
{
	unsigned rt = kgenome_arm32_r12(a->in);
	unsigned p = (unsigned)kgenome_arm32_p(a->in), wb = (unsigned)kgenome_arm32_wb(a->in);

	MN("%s%s%s%s", load ? "ldr" : "str", byte ? "b" : "", (!p && wb) ? "t" : "", cc(a));
	if (rt == 15u && load && !byte)
		a->flow = KGENOME_GT_FLOW_JUMP;
	OP("%s, ", R(rt));
	put_addr_word(a, reg_off);
}

static void fmt_ldst_half(struct a32 *a, const char *base, int imm_form)
{
	unsigned rt = kgenome_arm32_r12(a->in), rn = kgenome_arm32_r16(a->in);
	unsigned p = (unsigned)kgenome_arm32_p(a->in), u = (unsigned)kgenome_arm32_u(a->in), wb = (unsigned)kgenome_arm32_wb(a->in);

	/* the register-offset forms of the halfword and signed transfers have bits 11:8 should-be-zero; the oracle spells such a word as another instruction or as undefined, so it is not claimed here */
	if (!imm_form && (a->w & 0xf00u) && strcmp(base, "ldrd") && strcmp(base, "strd")) {
		a->unsupported = 1;
		return;
	}
	MN("%s%s%s", base, (!p && wb) ? "t" : "", cc(a));
	OP("%s, ", R(rt));                      /* LDRD and STRD name the first register only, as that disassembler does */
	if (imm_form) {
		uint32_t imm = kgenome_arm32_imm8_split(a->in);

		if (!p) {
			OP("[%s], #%s%u", R(rn), u ? "" : "-", imm);
		} else {
			if (rn == 15u && !wb) {
				a->has_target = 1;
				a->target = a->pc + 8u + (u ? imm : (uint64_t)0 - imm);
			}
			if (imm == 0u && u && !wb)
				OP("[%s]", R(rn));
			else
				OP("[%s, #%s%u]%s", R(rn), u ? "" : "-", imm, wb_mark(wb, rn));
		}
	} else {
		if (!p)
			OP("[%s], %s%s", R(rn), u ? "" : "-", R(kgenome_arm32_r0(a->in)));
		else
			OP("[%s, %s%s]%s", R(rn), u ? "" : "-", R(kgenome_arm32_r0(a->in)), wb ? "!" : "");
	}
}

static void fmt_ldst_multi(struct a32 *a, const char *base)
{
	unsigned rn = kgenome_arm32_r16(a->in), wb = (unsigned)kgenome_arm32_wb(a->in);
	uint32_t list = kgenome_arm32_list(a->in);

	/* STM carries "ia" when the base is written back or the list ends in ^; LDM never does (measured against the oracle) */
	MN("%s%s%s", base, (wb || kgenome_arm32_b(a->in)) && a->in.id == KGENOME_ARM32_I_STM ? "ia" : "", cc(a));
	OP("%s%s, ", R(rn), wb ? "!" : "");
	put_list(a, list);
	if (kgenome_arm32_b(a->in))
		OP("^");
	if ((list & 0x8000u) && (a->w & (1u << 20)))
		a->flow = KGENOME_GT_FLOW_RET;
}

/* ---- the rest ---------------------------------------------------------------- */

static void fmt_mul(struct a32 *a, const char *m, int acc, int wide)
{
	unsigned s = (unsigned)kgenome_arm32_s(a->in);

	mn_cc(a, m, s ? "s" : "");
	if (wide)
		OP("%s, %s, %s, %s", R(kgenome_arm32_r12(a->in)), R(kgenome_arm32_r16(a->in)), R(kgenome_arm32_r0(a->in)), R(kgenome_arm32_r8(a->in)));
	else if (acc)
		OP("%s, %s, %s, %s", R(kgenome_arm32_r16(a->in)), R(kgenome_arm32_r0(a->in)), R(kgenome_arm32_r8(a->in)), R(kgenome_arm32_r12(a->in)));
	else
		OP("%s, %s, %s", R(kgenome_arm32_r16(a->in)), R(kgenome_arm32_r0(a->in)), R(kgenome_arm32_r8(a->in)));
}

static const char *barrier_opt(char *b, unsigned o)
{
	switch (o) {
	case 15: return "sy";
	case 14: return "st";
	case 11: return "ish";
	case 10: return "ishst";
	case 7: return "nsh";
	case 6: return "nshst";
	case 3: return "osh";
	case 2: return "oshst";
	default:
		snprintf(b, 8, "#%u", o);
		return b;
	}
}

static void fmt_ext(struct a32 *a, const char *m, int add)
{
	unsigned rot = kgenome_arm32_rot(a->in);

	if (a->w & 0x300u) {                    /* bits 9:8 are should-be-zero */
		a->unsupported = 1;
		return;
	}
	mn_cc(a, m, "");
	if (add)
		OP("%s, %s, %s", R(kgenome_arm32_r12(a->in)), R(kgenome_arm32_r16(a->in)), R(kgenome_arm32_r0(a->in)));
	else
		OP("%s, %s", R(kgenome_arm32_r12(a->in)), R(kgenome_arm32_r0(a->in)));
	if (rot)
		OP(", ror #%u", rot * 8u);
}

static void fmt_two(struct a32 *a, const char *m)
{
	if ((a->w & 0xf0f00u) != 0xf0f00u) {    /* should-be-one fields of REV, REV16, RBIT, REVSH, CLZ: the oracle calls such a word undefined */
		a->unsupported = 1;
		return;
	}
	mn_cc(a, m, "");
	OP("%s, %s", R(kgenome_arm32_r12(a->in)), R(kgenome_arm32_r0(a->in)));
}

static void fmt_three(struct a32 *a, const char *m)
{
	if ((a->w & 0xf000u) != 0xf000u) {      /* SDIV and UDIV: bits 15:12 are should-be-one */
		a->unsupported = 1;
		return;
	}
	mn_cc(a, m, "");
	OP("%s, %s, %s", R(kgenome_arm32_r16(a->in)), R(kgenome_arm32_r0(a->in)), R(kgenome_arm32_r8(a->in)));
}

/* the register a LOAD-exclusive writes is numbered, not named (r14 where every other instruction says lr): the oracle's spelling */
static const char *rnum(char *b, unsigned r)
{
	snprintf(b, 8, "r%u", r & 15u);
	return b;
}

static void fmt_excl(struct a32 *a, const char *m, int store, int dbl)
{
	char x[8];

	/* should-be-one bits: 11:8 always, and 3:0 of the loads; the oracle calls a word without them undefined */
	if ((a->w & 0xf00u) != 0xf00u || (!store && (a->w & 15u) != 15u)) {
		a->unsupported = 1;
		return;
	}
	unsigned rt = store ? (a->w & 15u) : kgenome_arm32_r12(a->in);

	mn_cc(a, m, "");
	/* the doubleword forms name the first register of the pair only, as LDRD and STRD do */
	if (store)
		OP("%s, %s, ", R(kgenome_arm32_r12(a->in)), R(rt));
	else
		OP("%s, ", rnum(x, rt));
	(void)dbl;
	OP("[%s]", R(kgenome_arm32_r16(a->in)));
}

static void fmt_branch(struct a32 *a)
{
	int64_t t = (int64_t)a->pc + 8 + kgenome_arm32_branch_off(a->in);

	switch (a->in.id) {
	case KGENOME_ARM32_I_BL:
		MN("bl%s", cc(a));
		branch_to(a, KGENOME_GT_FLOW_CALL, t);
		break;
	case KGENOME_ARM32_I_BLX_IMM:
		MN("blx");
		t += kgenome_arm32_h(a->in) ? 2 : 0;
		branch_to(a, KGENOME_GT_FLOW_CALL, t);
		break;
	default:
		MN("b%s", cc(a));
		branch_to(a, a->in.cond == 14u ? KGENOME_GT_FLOW_JUMP : KGENOME_GT_FLOW_COND, t);
		break;
	}
	OP("0x%llx", (unsigned long long)a->target);
}

static void spell(struct a32 *a)
{
	struct kgenome_arm32_insn in = a->in;
	char b[8];

	switch (in.id) {
	case KGENOME_ARM32_I_AND_REG: case KGENOME_ARM32_I_EOR_REG: case KGENOME_ARM32_I_SUB_REG: case KGENOME_ARM32_I_RSB_REG:
	case KGENOME_ARM32_I_ADD_REG: case KGENOME_ARM32_I_ADC_REG: case KGENOME_ARM32_I_SBC_REG: case KGENOME_ARM32_I_RSC_REG:
	case KGENOME_ARM32_I_TST_REG: case KGENOME_ARM32_I_TEQ_REG: case KGENOME_ARM32_I_CMP_REG: case KGENOME_ARM32_I_CMN_REG:
	case KGENOME_ARM32_I_ORR_REG: case KGENOME_ARM32_I_MOV_REG: case KGENOME_ARM32_I_BIC_REG: case KGENOME_ARM32_I_MVN_REG:
		fmt_dp(a, 0);
		if ((a->w >> 21 & 15u) == DP_MOV && kgenome_arm32_r12(in) == 15u)
			a->flow = KGENOME_GT_FLOW_JUMP;
		return;
	case KGENOME_ARM32_I_AND_RSR: case KGENOME_ARM32_I_EOR_RSR: case KGENOME_ARM32_I_SUB_RSR: case KGENOME_ARM32_I_RSB_RSR:
	case KGENOME_ARM32_I_ADD_RSR: case KGENOME_ARM32_I_ADC_RSR: case KGENOME_ARM32_I_SBC_RSR: case KGENOME_ARM32_I_RSC_RSR:
	case KGENOME_ARM32_I_TST_RSR: case KGENOME_ARM32_I_TEQ_RSR: case KGENOME_ARM32_I_CMP_RSR: case KGENOME_ARM32_I_CMN_RSR:
	case KGENOME_ARM32_I_ORR_RSR: case KGENOME_ARM32_I_MOV_RSR: case KGENOME_ARM32_I_BIC_RSR: case KGENOME_ARM32_I_MVN_RSR:
		fmt_dp(a, 1);
		return;
	case KGENOME_ARM32_I_AND_IMM: case KGENOME_ARM32_I_EOR_IMM: case KGENOME_ARM32_I_SUB_IMM: case KGENOME_ARM32_I_RSB_IMM:
	case KGENOME_ARM32_I_ADD_IMM: case KGENOME_ARM32_I_ADC_IMM: case KGENOME_ARM32_I_SBC_IMM: case KGENOME_ARM32_I_RSC_IMM:
	case KGENOME_ARM32_I_TST_IMM: case KGENOME_ARM32_I_TEQ_IMM: case KGENOME_ARM32_I_CMP_IMM: case KGENOME_ARM32_I_CMN_IMM:
	case KGENOME_ARM32_I_ORR_IMM: case KGENOME_ARM32_I_MOV_IMM: case KGENOME_ARM32_I_BIC_IMM: case KGENOME_ARM32_I_MVN_IMM:
		fmt_dp(a, 2);
		return;
	case KGENOME_ARM32_I_MOVW: case KGENOME_ARM32_I_MOVT:
		mn_cc(a, in.id == KGENOME_ARM32_I_MOVW ? "movw" : "movt", "");
		OP("%s, #%u", R(kgenome_arm32_r12(in)), kgenome_arm32_imm16(in));
		return;
	case KGENOME_ARM32_I_MUL: fmt_mul(a, "mul", 0, 0); return;
	case KGENOME_ARM32_I_MLA: fmt_mul(a, "mla", 1, 0); return;
	case KGENOME_ARM32_I_MLS: fmt_mul(a, "mls", 1, 0); return;
	case KGENOME_ARM32_I_UMAAL: fmt_mul(a, "umaal", 0, 1); return;
	case KGENOME_ARM32_I_UMULL: fmt_mul(a, "umull", 0, 1); return;
	case KGENOME_ARM32_I_UMLAL: fmt_mul(a, "umlal", 0, 1); return;
	case KGENOME_ARM32_I_SMULL: fmt_mul(a, "smull", 0, 1); return;
	case KGENOME_ARM32_I_SMLAL: fmt_mul(a, "smlal", 0, 1); return;
	case KGENOME_ARM32_I_STR_IMM: fmt_ldst_word(a, 0, 0, 0); return;
	case KGENOME_ARM32_I_LDR_IMM: fmt_ldst_word(a, 1, 0, 0); return;
	case KGENOME_ARM32_I_STRB_IMM: fmt_ldst_word(a, 0, 1, 0); return;
	case KGENOME_ARM32_I_LDRB_IMM: fmt_ldst_word(a, 1, 1, 0); return;
	case KGENOME_ARM32_I_STR_REG: fmt_ldst_word(a, 0, 0, 1); return;
	case KGENOME_ARM32_I_LDR_REG: fmt_ldst_word(a, 1, 0, 1); return;
	case KGENOME_ARM32_I_STRB_REG: fmt_ldst_word(a, 0, 1, 1); return;
	case KGENOME_ARM32_I_LDRB_REG: fmt_ldst_word(a, 1, 1, 1); return;
	case KGENOME_ARM32_I_PUSH_1:
		MN("push%s", cc(a));
		OP("{%s}", R(kgenome_arm32_r12(in)));
		return;
	case KGENOME_ARM32_I_POP_1:
		MN("pop%s", cc(a));
		OP("{%s}", R(kgenome_arm32_r12(in)));
		if (kgenome_arm32_r12(in) == 15u)
			a->flow = KGENOME_GT_FLOW_RET;
		return;
	case KGENOME_ARM32_I_PUSH:
		if (__builtin_popcount(kgenome_arm32_list(in)) == 1) {      /* one register: written as the multiple store */
			MN("stmfd%s", cc(a));
			OP("sp!, ");
		} else {
			MN("push%s", cc(a));
		}
		put_list(a, kgenome_arm32_list(in));
		return;
	case KGENOME_ARM32_I_POP:
		if (__builtin_popcount(kgenome_arm32_list(in)) == 1) {
			MN("ldmfd%s", cc(a));
			OP("sp!, ");
		} else {
			MN("pop%s", cc(a));
		}
		put_list(a, kgenome_arm32_list(in));
		if (kgenome_arm32_list(in) & 0x8000u)
			a->flow = KGENOME_GT_FLOW_RET;
		return;
	case KGENOME_ARM32_I_STMDA: fmt_ldst_multi(a, "stmda"); return;
	case KGENOME_ARM32_I_STM: fmt_ldst_multi(a, "stm"); return;
	case KGENOME_ARM32_I_STMDB: fmt_ldst_multi(a, "stmdb"); return;
	case KGENOME_ARM32_I_STMIB: fmt_ldst_multi(a, "stmib"); return;
	case KGENOME_ARM32_I_LDMDA: fmt_ldst_multi(a, "ldmda"); return;
	case KGENOME_ARM32_I_LDM: fmt_ldst_multi(a, "ldm"); return;
	case KGENOME_ARM32_I_LDMDB: fmt_ldst_multi(a, "ldmdb"); return;
	case KGENOME_ARM32_I_LDMIB: fmt_ldst_multi(a, "ldmib"); return;
	case KGENOME_ARM32_I_STRH_IMM: fmt_ldst_half(a, "strh", 1); return;
	case KGENOME_ARM32_I_STRH_REG: fmt_ldst_half(a, "strh", 0); return;
	case KGENOME_ARM32_I_LDRH_IMM: fmt_ldst_half(a, "ldrh", 1); return;
	case KGENOME_ARM32_I_LDRH_REG: fmt_ldst_half(a, "ldrh", 0); return;
	case KGENOME_ARM32_I_LDRSB_IMM: fmt_ldst_half(a, "ldrsb", 1); return;
	case KGENOME_ARM32_I_LDRSB_REG: fmt_ldst_half(a, "ldrsb", 0); return;
	case KGENOME_ARM32_I_LDRSH_IMM: fmt_ldst_half(a, "ldrsh", 1); return;
	case KGENOME_ARM32_I_LDRSH_REG: fmt_ldst_half(a, "ldrsh", 0); return;
	case KGENOME_ARM32_I_LDRD_IMM: fmt_ldst_half(a, "ldrd", 1); return;
	case KGENOME_ARM32_I_LDRD_REG: fmt_ldst_half(a, "ldrd", 0); return;
	case KGENOME_ARM32_I_STRD_IMM: fmt_ldst_half(a, "strd", 1); return;
	case KGENOME_ARM32_I_STRD_REG: fmt_ldst_half(a, "strd", 0); return;
	case KGENOME_ARM32_I_B: case KGENOME_ARM32_I_BL: case KGENOME_ARM32_I_BLX_IMM:
		fmt_branch(a);
		return;
	case KGENOME_ARM32_I_BX:
		if ((a->w & 0xfff00u) != 0xfff00u) {
			a->unsupported = 1;
			return;
		}
		MN("bx%s", cc(a));
		OP("%s", R(kgenome_arm32_r0(in)));
		a->flow = kgenome_arm32_r0(in) == 14u ? KGENOME_GT_FLOW_RET : KGENOME_GT_FLOW_JUMP;
		return;
	case KGENOME_ARM32_I_BLX_REG:
		if ((a->w & 0xfff00u) != 0xfff00u) {
			a->unsupported = 1;
			return;
		}
		MN("blx%s", cc(a));
		OP("%s", R(kgenome_arm32_r0(in)));
		a->flow = KGENOME_GT_FLOW_CALL;
		return;
	case KGENOME_ARM32_I_BXJ:
		if ((a->w & 0xfff00u) != 0xfff00u) {
			a->unsupported = 1;
			return;
		}
		MN("bxj%s", cc(a));
		OP("%s", R(kgenome_arm32_r0(in)));
		a->flow = KGENOME_GT_FLOW_JUMP;
		return;
	case KGENOME_ARM32_I_SVC:
		MN("svc%s", cc(a));
		OP("0x%08x", kgenome_arm32_imm24(in));
		a->flow = KGENOME_GT_FLOW_TRAP;
		return;
	case KGENOME_ARM32_I_BKPT:
		if (in.cond != 14u) {                   /* the oracle spells BKPT only unconditionally */
			a->unsupported = 1;
			return;
		}
		MN("bkpt");
		OP("0x%04x", kgenome_arm32_imm16_split(in));
		a->flow = KGENOME_GT_FLOW_TRAP;
		return;
	case KGENOME_ARM32_I_UDF:
		if (in.cond != 14u) {
			a->unsupported = 1;
			return;
		}
		MN("udf");
		OP("#%u", kgenome_arm32_imm16_split(in));
		a->flow = KGENOME_GT_FLOW_TRAP;
		return;
	case KGENOME_ARM32_I_CLZ: fmt_two(a, "clz"); return;
	case KGENOME_ARM32_I_REV: fmt_two(a, "rev"); return;
	case KGENOME_ARM32_I_REV16: fmt_two(a, "rev16"); return;
	case KGENOME_ARM32_I_RBIT: fmt_two(a, "rbit"); return;
	case KGENOME_ARM32_I_REVSH: fmt_two(a, "revsh"); return;
	case KGENOME_ARM32_I_SXTB: fmt_ext(a, "sxtb", 0); return;
	case KGENOME_ARM32_I_SXTH: fmt_ext(a, "sxth", 0); return;
	case KGENOME_ARM32_I_UXTB: fmt_ext(a, "uxtb", 0); return;
	case KGENOME_ARM32_I_UXTH: fmt_ext(a, "uxth", 0); return;
	case KGENOME_ARM32_I_SXTAB: fmt_ext(a, "sxtab", 1); return;
	case KGENOME_ARM32_I_SXTAH: fmt_ext(a, "sxtah", 1); return;
	case KGENOME_ARM32_I_UXTAB: fmt_ext(a, "uxtab", 1); return;
	case KGENOME_ARM32_I_UXTAH: fmt_ext(a, "uxtah", 1); return;
	case KGENOME_ARM32_I_SDIV: fmt_three(a, "sdiv"); return;
	case KGENOME_ARM32_I_UDIV: fmt_three(a, "udiv"); return;
	case KGENOME_ARM32_I_UBFX: case KGENOME_ARM32_I_SBFX: {
		unsigned lsb = (a->w >> 7) & 31u, w = ((a->w >> 16) & 31u) + 1u;

		mn_cc(a, in.id == KGENOME_ARM32_I_UBFX ? "ubfx" : "sbfx", "");
		OP("%s, %s, #%u, #%u", R(kgenome_arm32_r12(in)), R(kgenome_arm32_r0(in)), lsb, w);
		return;
	}
	case KGENOME_ARM32_I_BFC: case KGENOME_ARM32_I_BFI: {
		unsigned lsb = (a->w >> 7) & 31u, msb = (a->w >> 16) & 31u;

		if (msb < lsb) {
			a->unsupported = 1;
			return;
		}
		/* BFC is BFI with Rn = 1111; the decoder's row keys on bits 19:16 instead (see the note above kgenome_arm32_src_cond in arm32_rows.c) */
		if ((a->w & 15u) == 15u) {
			mn_cc(a, "bfc", "");
			OP("%s, #%u, #%u", R(kgenome_arm32_r12(in)), lsb, msb - lsb + 1u);
		} else {
			mn_cc(a, "bfi", "");
			OP("%s, %s, #%u, #%u", R(kgenome_arm32_r12(in)), R(kgenome_arm32_r0(in)), lsb, msb - lsb + 1u);
		}
		return;
	}
	case KGENOME_ARM32_I_SWP: case KGENOME_ARM32_I_SWPB:
		if (a->w & 0xf00u) {
			a->unsupported = 1;
			return;
		}
		mn_cc(a, in.id == KGENOME_ARM32_I_SWP ? "swp" : "swpb", "");
		OP("%s, %s, [%s]", R(kgenome_arm32_r12(in)), R(kgenome_arm32_r0(in)), R(kgenome_arm32_r16(in)));
		return;
	case KGENOME_ARM32_I_LDREX: fmt_excl(a, "ldrex", 0, 0); return;
	case KGENOME_ARM32_I_LDREXB: fmt_excl(a, "ldrexb", 0, 0); return;
	case KGENOME_ARM32_I_LDREXH: fmt_excl(a, "ldrexh", 0, 0); return;
	case KGENOME_ARM32_I_LDREXD: fmt_excl(a, "ldrexd", 0, 1); return;
	case KGENOME_ARM32_I_STREX: fmt_excl(a, "strex", 1, 0); return;
	case KGENOME_ARM32_I_STREXB: fmt_excl(a, "strexb", 1, 0); return;
	case KGENOME_ARM32_I_STREXH: fmt_excl(a, "strexh", 1, 0); return;
	case KGENOME_ARM32_I_STREXD: fmt_excl(a, "strexd", 1, 1); return;
	case KGENOME_ARM32_I_CLREX:
		MN("clrex");
		return;
	case KGENOME_ARM32_I_DSB: case KGENOME_ARM32_I_DMB: case KGENOME_ARM32_I_ISB:
		if ((a->w & 0xfff00u) != 0xff000u) {    /* bits 19:8 are fixed */
			a->unsupported = 1;
			return;
		}
		MN("%s", in.id == KGENOME_ARM32_I_DSB ? "dsb" : in.id == KGENOME_ARM32_I_DMB ? "dmb" : "isb");
		OP("%s", barrier_opt(b, a->w & 15u));
		return;
	case KGENOME_ARM32_I_HINT: {
		static const char *const h[5] = { "nop", "yield", "wfe", "wfi", "sev" };
		unsigned n = a->w & 0xffu;

		if (n == 0u) {
			MN("nop%s", cc(a));
			OP("{0}");
		} else if (n < 5u) {
			MN("%s%s", h[n], cc(a));
		} else if (n >= 0xf0u) {
			MN("dbg%s", cc(a));
			OP("#%u", n & 15u);
		} else {
			a->unsupported = 1;             /* an unallocated hint: the oracle calls it undefined */
		}
		return;
	}
	case KGENOME_ARM32_I_MRS:
		if ((a->w & 0xf0fffu) != 0xf0000u) {      /* should-be-one and should-be-zero bits the decoder's row does not check */
			a->unsupported = 1;
			return;
		}
		MN("mrs%s", cc(a));
		OP("%s, %s", R(kgenome_arm32_r12(in)), (a->w >> 22) & 1u ? "SPSR" : "CPSR");
		return;
	default:
		a->unsupported = 1;
		return;
	}
}

void kgenome_arm32_format(const struct kgenome_arm32_fmt_req *req, struct kgenome_gt_fmt_res *res)
{
	struct a32 a;

	memset(&a, 0, sizeof a);
	kgenome_gt_fmt_init(&a.f);
	a.in = *req->in;
	a.w = req->in->w;
	a.pc = req->pc;
	memset(res, 0, sizeof *res);
	if (a.in.id == KGENOME_ARM32_I_INVALID) {
		res->status = KGENOME_BAD_INPUT;
		res->flow = KGENOME_GT_FLOW_TRAP;
		kgenome_gt_fmt_mn(&a.f, ".word");
		kgenome_gt_fmt_op(&a.f, "0x%08x", a.w);
		(void)kgenome_gt_fmt_done(&a.f, req->buf, req->cap, &res->len);
		return;
	}
	spell(&a);
	if (a.unsupported || a.f.mn_n == 0) {
		kgenome_gt_fmt_init(&a.f);
		kgenome_gt_fmt_mn(&a.f, ".inst");
		kgenome_gt_fmt_op(&a.f, "0x%08x", a.w);
		res->status = KGENOME_UNSUPPORTED;
		(void)kgenome_gt_fmt_done(&a.f, req->buf, req->cap, &res->len);
		return;
	}
	res->flow = a.flow;
	res->has_target = a.has_target;
	res->target = a.target;
	res->status = kgenome_gt_fmt_done(&a.f, req->buf, req->cap, &res->len);
}
