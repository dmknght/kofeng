/*
 * decode_arm32.c - ARM state into the engine's one instruction form.
 *
 * AN ADAPTER. Which instruction a word is - and whether it is one - is
 * genotype's (libgenome/genotype/arm32, gt_arm32_decode): a table lookup that
 * answers with the instruction's NAME and keeps the word. This turns that into
 * struct cell_insn, and the conventions it spells operands in are
 * decode_arm32.h's, which a consumer needs.
 *
 * THE NAME IS INDEXED, NOT SWITCHED ON. g_info holds, per name, the builder that
 * spells its operands, the class the engine files it under, one small argument
 * for that builder (the data-processing opcode, the access width) and the
 * recipe of registers it writes without spelling them. A builder reads fields
 * through genotype's accessors and decides nothing about what the word IS. The
 * decisions that remain here are about the engine's form: that `ldr pc,[..]` is
 * an indirect jump, that `bx lr` is a return, that `add r0,r0,#4` is spelled
 * with two operands.
 *
 * WHAT IT SAYS ABOUT AN ENCODING IT DOES NOT MODEL: see arm32.h. A name genotype
 * calls INVALID or UDF is CELL_UD, length 4; the coprocessor, VFP and Advanced
 * SIMD spaces are CELL_OTHER with the core registers they write.
 */
#include <arm32/arm32.h>

#include "decode_arm32.h"


struct a_info;
typedef void (*a_fn)(struct gt_arm32_insn in, const struct a_info *e,
		     struct cell_insn *o);

struct a_info {
	a_fn    fn;             /* the builder that spells this name's operands */
	uint8_t cls;            /* CELL_* the name is filed under */
	uint8_t aux;            /* the builder's argument, see each */
	uint8_t wm;             /* ARM_WM_*: registers written without being spelled */
};

#define L1 0x10u                /* aux of a transfer: it loads */

/* aux of a load or store: bit 0 loads, bit 1 is a byte */
#define XF(l, b) ((l) | ((b) << 1))
/* aux of a halfword or doubleword transfer: the width, and L1 when it loads */
#define XX(size, l) ((size) | (l))

#define I(id, c, f, a, w) [GT_ARM32_I_##id] = { (f), (c), (a), (w) }

/* ---- the second operand of data processing ------------------------------- */

/*
 * A register with its shift, as a source operand: an immediate amount, where an
 * amount of 0 means no shift for lsl, 32 for lsr and asr, and rrx for ror.
 */
static void op2_reg(struct gt_arm32_insn in, struct cell_operand *t)
{
	uint32_t type = gt_arm32_shift_type(in), amt = gt_arm32_shift_imm(in);

	arm_op_reg(t, gt_arm32_r0(in), CELL_OF_READ);
	if (!amt) {
		if (type == 3u)
			arm_shift(t, ARM_SH_RRX, 1u, 0xffu);
		else if (type)
			arm_shift(t, type + 1u, 32u, 0xffu);
		/* lsl #0 is the register itself */
		return;
	}
	arm_shift(t, type + 1u, amt, 0xffu);
}

/* ... or by a register: the amount is in the register. */
static void op2_rsr(struct gt_arm32_insn in, struct cell_operand *t)
{
	arm_op_reg(t, gt_arm32_r0(in), CELL_OF_READ);
	arm_shift(t, gt_arm32_shift_type(in) + 1u, 0, gt_arm32_r8(in));
}

static void f_dp_imm(struct gt_arm32_insn in, const struct a_info *e,
		     struct cell_insn *o)
{
	struct cell_operand t;

	arm_op_imm(&t, gt_arm32_modimm(in));
	kof_arm_dp(o, e->aux, gt_arm32_s(in), gt_arm32_r16(in), gt_arm32_r12(in), &t, 8);
}

static void f_dp_reg(struct gt_arm32_insn in, const struct a_info *e,
		     struct cell_insn *o)
{
	struct cell_operand t;

	op2_reg(in, &t);
	kof_arm_dp(o, e->aux, gt_arm32_s(in), gt_arm32_r16(in), gt_arm32_r12(in), &t, 8);
}

static void f_dp_rsr(struct gt_arm32_insn in, const struct a_info *e,
		     struct cell_insn *o)
{
	struct cell_operand t;

	op2_rsr(in, &t);
	kof_arm_dp(o, e->aux, gt_arm32_s(in), gt_arm32_r16(in), gt_arm32_r12(in), &t, 8);
}

/* ---- small forms --------------------------------------------------------- */

static void f_ud(struct gt_arm32_insn in, const struct a_info *e,
		 struct cell_insn *o)
{
	(void)in;
	(void)e;
	kof_arm_ud(o);
}

static void f_other(struct gt_arm32_insn in, const struct a_info *e,
		    struct cell_insn *o)
{
	kof_arm_other(o, arm_wm(e->wm, in.w));
}

static void f_priv(struct gt_arm32_insn in, const struct a_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = arm_wm(e->wm, in.w);
}

/* A hint: the unallocated ones execute as nop. */
static void f_nop(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	(void)in;
	o->op = e->cls;
}

static void f_movw(struct gt_arm32_insn in, const struct a_info *e,
		   struct cell_insn *o)
{
	o->n_op = 2;
	arm_reg(&o->o[0], gt_arm32_r12(in), CELL_OF_WRITE);
	o->wmask = arm_wm(e->wm, in.w);
	o->op = e->cls;
	arm_imm(&o->o[1], gt_arm32_imm16(in));
}

/* movt: rd = rd & 0xffff | v << 16, which is an OR of the high half. */
static void f_movt(struct gt_arm32_insn in, const struct a_info *e,
		   struct cell_insn *o)
{
	o->n_op = 2;
	arm_reg(&o->o[0], gt_arm32_r12(in), CELL_OF_WRITE);
	o->wmask = arm_wm(e->wm, in.w);
	o->op = e->cls;
	arm_imm(&o->o[1], (uint64_t)gt_arm32_imm16(in) << 16);
}

static void f_mrs(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = ARM_R(gt_arm32_r12(in));
	o->n_op = 1;
	arm_reg(&o->o[0], gt_arm32_r12(in), CELL_OF_WRITE);
}

static void f_bx(struct gt_arm32_insn in, const struct a_info *e,
		 struct cell_insn *o)
{
	uint32_t rm = gt_arm32_r0(in);

	(void)e;
	o->wmask = ARM_R(ARM_PC);
	o->flags |= CELL_F_INDIRECT;
	o->op = rm == ARM_LR ? CELL_RET : CELL_JMP;
	o->n_op = 1;
	arm_reg(&o->o[0], rm, CELL_OF_READ);
}

/* bxj: bx on a core without Jazelle. */
static void f_bxj(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	o->wmask = ARM_R(ARM_PC);
	o->flags |= CELL_F_INDIRECT;
	o->op = e->cls;
	o->n_op = 1;
	arm_reg(&o->o[0], gt_arm32_r0(in), CELL_OF_READ);
}

static void f_blx_reg(struct gt_arm32_insn in, const struct a_info *e,
		      struct cell_insn *o)
{
	o->flags |= CELL_F_INDIRECT;
	o->op = e->cls;
	o->wmask = ARM_R(ARM_LR) | ARM_R(ARM_PC);
	o->n_op = 1;
	arm_reg(&o->o[0], gt_arm32_r0(in), CELL_OF_READ);
}

static void f_clz(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	kof_arm_other(o, arm_wm(e->wm, in.w));
	o->n_op = 2;
	arm_reg(&o->o[0], gt_arm32_r12(in), CELL_OF_WRITE);
	arm_reg(&o->o[1], gt_arm32_r0(in), CELL_OF_READ);
}

/* bkpt, hvc, smc: the immediate. */
static void f_imm16(struct gt_arm32_insn in, const struct a_info *e,
		    struct cell_insn *o)
{
	o->op = e->cls;
	o->n_op = 1;
	arm_imm(&o->o[0], gt_arm32_imm16_split(in));
}

static void f_mul(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = arm_wm(e->wm, in.w);
	o->n_op = 3;
	arm_reg(&o->o[0], gt_arm32_r16(in), CELL_OF_WRITE);
	arm_reg(&o->o[1], gt_arm32_r0(in), CELL_OF_READ);
	arm_reg(&o->o[2], gt_arm32_r8(in), CELL_OF_READ);
}

/* sdiv and udiv are spelled as mul is: destination, then the two sources. */
static void f_div(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	f_mul(in, e, o);
}

/* sxtb sxth uxtb uxth: a move that widens, with the rotation of the source. */
static void f_ext(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	uint32_t rot = gt_arm32_rot(in);

	kof_arm_other(o, arm_wm(e->wm, in.w));
	o->op = e->cls;
	o->n_op = 2;
	arm_reg(&o->o[0], gt_arm32_r12(in), CELL_OF_WRITE);
	arm_reg(&o->o[1], gt_arm32_r0(in), CELL_OF_READ);
	o->o[1].size = e->aux;
	if (rot)
		arm_shift(&o->o[1], ARM_SH_ROR, rot * 8u, 0xffu);
}

/* ---- loads and stores ---------------------------------------------------- */

static void f_xfer_imm(struct gt_arm32_insn in, const struct a_info *e,
		       struct cell_insn *o)
{
	uint32_t p = gt_arm32_p(in), u = gt_arm32_u(in), w = gt_arm32_wb(in);
	uint32_t rn = gt_arm32_r16(in), rt = gt_arm32_r12(in);
	int l = e->aux & 1u;
	unsigned size = (e->aux & 2u) ? 1u : 4u;
	struct cell_operand *m = l ? &o->o[1] : &o->o[0];
	int64_t off = (int64_t)gt_arm32_imm12(in);
	uint64_t wm = 0;

	o->op = e->cls;
	if (l) {
		wm = ARM_R(rt);
		arm_reg(&o->o[0], rt, CELL_OF_WRITE);
	} else {
		arm_reg(&o->o[1], rt, CELL_OF_READ);
	}
	o->n_op = 2;
	if (!u)
		off = -off;
	if (rn == ARM_PC && p && !w)
		arm_mem(m, rn, 8 + off, size,
			(l ? CELL_OF_READ : CELL_OF_WRITE) | CELL_OF_RIPREL);
	else
		arm_mem(m, rn, p ? off : 0, size, l ? CELL_OF_READ : CELL_OF_WRITE);
	if (!p) {
		o->n_op = 3;
		arm_imm(&o->o[2], (uint64_t)off);
	}
	if (!p || w)
		wm |= ARM_R(rn);
	o->wmask = wm;

	if (l && !(e->aux & 2u) && rt == ARM_PC) {
		/* ldr pc, [...] - an indirect jump, through memory */
		struct cell_operand mem = *m;

		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		kof_arm_clr(o);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

static void f_xfer_reg(struct gt_arm32_insn in, const struct a_info *e,
		       struct cell_insn *o)
{
	uint32_t p = gt_arm32_p(in), u = gt_arm32_u(in), w = gt_arm32_wb(in);
	uint32_t rn = gt_arm32_r16(in), rt = gt_arm32_r12(in);
	int l = e->aux & 1u;
	unsigned size = (e->aux & 2u) ? 1u : 4u;
	struct cell_operand *m = l ? &o->o[1] : &o->o[0];
	struct cell_operand t;
	uint64_t wm = 0;

	o->op = e->cls;
	if (l) {
		wm = ARM_R(rt);
		arm_reg(&o->o[0], rt, CELL_OF_WRITE);
	} else {
		arm_reg(&o->o[1], rt, CELL_OF_READ);
	}
	o->n_op = 2;
	op2_reg(in, &t);
	arm_mem(m, rn, 0, size, l ? CELL_OF_READ : CELL_OF_WRITE);
	if (!p) {
		/* post-indexed: the access is at the base, and the register that
		 * moves it is the third operand */
		o->n_op = 3;
		o->o[2] = t;
		o->o[2].imm = u ? 0u : 1u;
	} else {
		m->index = (uint8_t)gt_arm32_r0(in);
		m->imm = u ? 0u : 1u;
		if (t.scale == ARM_SH_NONE) {
			m->scale = 1u;
		} else if (t.scale == ARM_SH_LSL && t.disp <= 7) {
			m->scale = (uint8_t)(1u << t.disp);
		} else {
			m->scale = 0;
			m->imm |= (uint64_t)t.scale << 8;
		}
	}
	if (!p || w)
		wm |= ARM_R(rn);
	o->wmask = wm;

	if (l && !(e->aux & 2u) && rt == ARM_PC) {
		struct cell_operand mem = *m;

		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		kof_arm_clr(o);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

/* halfword, signed byte and doubleword transfers, immediate offset */
static void f_xferx_imm(struct gt_arm32_insn in, const struct a_info *e,
			struct cell_insn *o)
{
	uint32_t p = gt_arm32_p(in), u = gt_arm32_u(in), w = gt_arm32_wb(in);
	uint32_t rn = gt_arm32_r16(in), rt = gt_arm32_r12(in);
	int load = (e->aux & L1) != 0;
	unsigned size = e->aux & 15u;
	struct cell_operand *m = load ? &o->o[1] : &o->o[0];
	int64_t off = (int64_t)gt_arm32_imm8_split(in);
	uint64_t wm = 0;

	o->op = e->cls;
	if (load) {
		wm = ARM_R(rt);
		if (size == 8u)
			wm |= ARM_R((rt + 1u) & 15u);
		arm_reg(&o->o[0], rt, CELL_OF_WRITE);
	} else {
		arm_reg(&o->o[1], rt, CELL_OF_READ);
	}
	o->n_op = 2;
	if (!u)
		off = -off;
	if (rn == ARM_PC && p && !w)
		arm_mem(m, rn, 8 + off, size,
			(load ? CELL_OF_READ : CELL_OF_WRITE) | CELL_OF_RIPREL);
	else
		arm_mem(m, rn, p ? off : 0, size,
			load ? CELL_OF_READ : CELL_OF_WRITE);
	if (!p) {
		o->n_op = 3;
		arm_imm(&o->o[2], (uint64_t)off);
	}
	if (!p || w)
		wm |= ARM_R(rn);
	o->wmask = wm;
}

/* ... and register offset */
static void f_xferx_reg(struct gt_arm32_insn in, const struct a_info *e,
			struct cell_insn *o)
{
	uint32_t p = gt_arm32_p(in), u = gt_arm32_u(in), w = gt_arm32_wb(in);
	uint32_t rn = gt_arm32_r16(in), rt = gt_arm32_r12(in);
	int load = (e->aux & L1) != 0;
	unsigned size = e->aux & 15u;
	struct cell_operand *m = load ? &o->o[1] : &o->o[0];
	uint64_t wm = 0;

	o->op = e->cls;
	if (load) {
		wm = ARM_R(rt);
		if (size == 8u)
			wm |= ARM_R((rt + 1u) & 15u);
		arm_reg(&o->o[0], rt, CELL_OF_WRITE);
	} else {
		arm_reg(&o->o[1], rt, CELL_OF_READ);
	}
	o->n_op = 2;
	arm_mem(m, rn, 0, size, load ? CELL_OF_READ : CELL_OF_WRITE);
	if (p) {
		m->index = (uint8_t)gt_arm32_r0(in);
		m->imm = u ? 0u : 1u;
	} else {
		o->n_op = 3;
		arm_reg(&o->o[2], gt_arm32_r0(in), CELL_OF_READ);
		o->o[2].imm = u ? 0u : 1u;
	}
	if (!p || w)
		wm |= ARM_R(rn);
	o->wmask = wm;
}

/* str rt,[sp,#-4]! and ldr rt,[sp],#4: the architecture's PUSH and POP */
static void f_push1(struct gt_arm32_insn in, const struct a_info *e,
		    struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 0, ARM_R(gt_arm32_r12(in)));
}

static void f_pop1(struct gt_arm32_insn in, const struct a_info *e,
		   struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 1, ARM_R(gt_arm32_r12(in)));
}

static void f_push(struct gt_arm32_insn in, const struct a_info *e,
		   struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 0, gt_arm32_list(in));
}

static void f_pop(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 1, gt_arm32_list(in));
}

/* ldm and stm, every addressing mode; aux is 1 for a load */
static void f_ldm(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	uint32_t rn = gt_arm32_r16(in), list = gt_arm32_list(in);
	uint32_t s = gt_arm32_b(in), w = gt_arm32_wb(in);
	int l = e->aux & 1u;

	o->op = e->cls;
	if (l)
		o->wmask |= list;
	if (w)
		o->wmask |= ARM_R(rn);
	if (l && (list & ARM_R(ARM_PC))) {
		/* ldm ..., {..., pc}: a branch (an exception return with ^) */
		o->op = s ? CELL_PRIV : CELL_JMP;
		if (!s)
			o->flags |= CELL_F_INDIRECT;
		o->o[0].imm = list;
		return;
	}
	o->n_op = 2;
	arm_reg(&o->o[0], rn, w ? CELL_OF_WRITE | CELL_OF_READ : CELL_OF_READ);
	arm_imm(&o->o[1], list);
}

/* ---- branches ------------------------------------------------------------ */

static void f_b(struct gt_arm32_insn in, const struct a_info *e,
		struct cell_insn *o)
{
	/* a 32-bit address space: a branch past either end wraps */
	uint64_t t = (o->at_va + 8u + (uint64_t)(int64_t)gt_arm32_branch_off(in)) &
		     0xffffffffu;

	o->n_op = 1;
	o->o[0].kind = CELL_O_REL;
	o->target_va = t;
	o->target = t;
	o->wmask = ARM_R(ARM_PC);
	o->op = in.cond == 0xEu ? CELL_JMP : CELL_JCC;
	if (o->op == CELL_JCC)
		o->cond = in.cond;
	(void)e;
}

static void f_bl(struct gt_arm32_insn in, const struct a_info *e,
		 struct cell_insn *o)
{
	uint64_t t = (o->at_va + 8u + (uint64_t)(int64_t)gt_arm32_branch_off(in)) &
		     0xffffffffu;

	o->n_op = 1;
	o->o[0].kind = CELL_O_REL;
	o->target_va = t;
	o->target = t;
	o->wmask = ARM_R(ARM_PC) | ARM_R(ARM_LR);
	o->op = e->cls;
}

/* blx (immediate): always to Thumb state, and the H bit is the halfword. */
static void f_blx_imm(struct gt_arm32_insn in, const struct a_info *e,
		      struct cell_insn *o)
{
	uint64_t t = (o->at_va + 8u + (uint64_t)(int64_t)gt_arm32_branch_off(in) +
		      (gt_arm32_h(in) ? 2u : 0u)) & 0xffffffffu;

	o->op = e->cls;
	o->wmask = ARM_R(ARM_LR) | ARM_R(ARM_PC);
	o->n_op = 1;
	o->o[0].kind = CELL_O_REL;
	o->target_va = t & ~(uint64_t)1;
	o->target = o->target_va;
}

static void f_svc(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	o->op = e->cls;
	o->n_op = 1;
	arm_imm(&o->o[0], gt_arm32_imm24(in));
}

/* ---- the coprocessor space ----------------------------------------------- */

/* ldc, stc: the base register is written back with W. */
static void f_cop_wb(struct gt_arm32_insn in, const struct a_info *e,
		     struct cell_insn *o)
{
	o->op = e->cls;
	if (gt_arm32_wb(in))
		o->wmask = ARM_R(gt_arm32_r16(in));
}

/* mrc, vmov to core, vmrs: Rt is written, unless it is pc (apsr_nzcv). */
static void f_mrc(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	o->op = e->cls;
	if (gt_arm32_r12(in) != ARM_PC)
		o->wmask = ARM_R(gt_arm32_r12(in));
}

/* Advanced SIMD structure load/store: the base is written back when Rm is not pc. */
static void f_vldst(struct gt_arm32_insn in, const struct a_info *e,
		    struct cell_insn *o)
{
	o->op = e->cls;
	if (gt_arm32_r0(in) != 15u)
		o->wmask = ARM_R(gt_arm32_r16(in));
}

/* rfe: returns, and writes the base back with W. */
static void f_rfe(struct gt_arm32_insn in, const struct a_info *e,
		  struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = ARM_R(ARM_PC);
	if (gt_arm32_wb(in))
		o->wmask |= ARM_R(gt_arm32_r16(in));
}

static const struct a_info g_info[GT_ARM32_I_COUNT] = {
	/* what the architecture leaves unallocated, and what it defines to fault */
	I(INVALID, CELL_UD, f_ud, 0, 0),
	I(UDF, CELL_UD, f_ud, 0, 0),

	/* multiplies. The two- and three-register forms the engine reads are MUL */
	I(MUL, CELL_MUL, f_mul, 0, ARM_WM_F16),
	I(MLA, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(MLS, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(UMAAL, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(UMULL, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(UMLAL, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(SMULL, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(SMLAL, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(SMLAXY, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMLAWY, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMULWY, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMLALXY, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(SMULXY, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMUAD, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMLAD, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMUSD, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMLSD, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMLALD, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(SMLSLD, CELL_OTHER, f_other, 0, ARM_WM_F16 | ARM_WM_F12),
	I(SMMUL, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMMLA, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SMMLS, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(USAD8, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(USADA8, CELL_OTHER, f_other, 0, ARM_WM_F16),
	I(SDIV, CELL_IDIV, f_div, 0, ARM_WM_F16),
	I(UDIV, CELL_DIV, f_div, 0, ARM_WM_F16),

	/* swap, exclusive, acquire/release */
	I(SWP, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SWPB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STL, CELL_OTHER, f_other, 0, 0),
	I(STLB, CELL_OTHER, f_other, 0, 0),
	I(STLH, CELL_OTHER, f_other, 0, 0),
	I(LDA, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STREX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDREX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STREXD, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDREXD, CELL_OTHER, f_other, 0, ARM_WM_F12 | ARM_WM_F12N),
	I(STREXB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDREXB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STREXH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDREXH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STLEX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STLEXD, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEXD, CELL_OTHER, f_other, 0, ARM_WM_F12 | ARM_WM_F12N),
	I(STLEXB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEXB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(STLEXH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEXH, CELL_OTHER, f_other, 0, ARM_WM_F12),

	/* halfword, signed byte and doubleword transfers */
	I(STRH_IMM, CELL_MOV, f_xferx_imm, XX(2, 0), 0),
	I(STRH_REG, CELL_MOV, f_xferx_reg, XX(2, 0), 0),
	I(LDRH_IMM, CELL_MOVZX, f_xferx_imm, XX(2, L1), 0),
	I(LDRH_REG, CELL_MOVZX, f_xferx_reg, XX(2, L1), 0),
	I(LDRD_IMM, CELL_MOV, f_xferx_imm, XX(8, L1), 0),
	I(LDRD_REG, CELL_MOV, f_xferx_reg, XX(8, L1), 0),
	I(STRD_IMM, CELL_MOV, f_xferx_imm, XX(8, 0), 0),
	I(STRD_REG, CELL_MOV, f_xferx_reg, XX(8, 0), 0),
	I(LDRSB_IMM, CELL_MOVSX, f_xferx_imm, XX(1, L1), 0),
	I(LDRSB_REG, CELL_MOVSX, f_xferx_reg, XX(1, L1), 0),
	I(LDRSH_IMM, CELL_MOVSX, f_xferx_imm, XX(2, L1), 0),
	I(LDRSH_REG, CELL_MOVSX, f_xferx_reg, XX(2, L1), 0),

	/* the miscellaneous space */
	I(MRS, CELL_PRIV, f_mrs, 0, 0),
	I(MSR_REG, CELL_PRIV, f_priv, 0, 0),
	I(BX, CELL_JMP, f_bx, 0, 0),
	I(BXJ, CELL_JMP, f_bxj, 0, 0),
	I(BLX_REG, CELL_CALL, f_blx_reg, 0, 0),
	I(CLZ, CELL_OTHER, f_clz, 0, ARM_WM_F12),
	I(CRC32, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(CRC32C, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(QADD, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(QSUB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(QDADD, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(QDSUB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(ERET, CELL_PRIV, f_priv, 0, ARM_WM_PC),
	I(BKPT, CELL_INT, f_imm16, 0, 0),
	I(HVC, CELL_PRIV, f_imm16, 0, 0),
	I(SMC, CELL_PRIV, f_imm16, 0, 0),
	I(HINT, CELL_NOP, f_nop, 0, 0),
	I(MSR_IMM, CELL_PRIV, f_priv, 0, 0),
	I(SETEND, CELL_PRIV, f_priv, 0, 0),
	I(CPS, CELL_PRIV, f_priv, 0, 0),

	/* data processing: the opcode is the aux */
#define DP(n, opc) \
	I(n##_REG, CELL_OTHER, f_dp_reg, opc, 0), \
	I(n##_RSR, CELL_OTHER, f_dp_rsr, opc, 0), \
	I(n##_IMM, CELL_OTHER, f_dp_imm, opc, 0)
	DP(AND, 0), DP(EOR, 1), DP(SUB, 2), DP(RSB, 3), DP(ADD, 4), DP(ADC, 5),
	DP(SBC, 6), DP(RSC, 7), DP(TST, 8), DP(TEQ, 9), DP(CMP, 10), DP(CMN, 11),
	DP(ORR, 12), DP(MOV, 13), DP(BIC, 14), DP(MVN, 15),
#undef DP
	I(MOVW, CELL_MOV, f_movw, 0, ARM_WM_F12),
	I(MOVT, CELL_OR, f_movt, 0, ARM_WM_F12),

	/* loads and stores */
	I(PUSH_1, CELL_PUSH, f_push1, 0, 0),
	I(POP_1, CELL_POP, f_pop1, 0, 0),
	I(STR_IMM, CELL_MOV, f_xfer_imm, XF(0, 0), 0),
	I(LDR_IMM, CELL_MOV, f_xfer_imm, XF(1, 0), 0),
	I(STRB_IMM, CELL_MOV, f_xfer_imm, XF(0, 1), 0),
	I(LDRB_IMM, CELL_MOVZX, f_xfer_imm, XF(1, 1), 0),
	I(STR_REG, CELL_MOV, f_xfer_reg, XF(0, 0), 0),
	I(LDR_REG, CELL_MOV, f_xfer_reg, XF(1, 0), 0),
	I(STRB_REG, CELL_MOV, f_xfer_reg, XF(0, 1), 0),
	I(LDRB_REG, CELL_MOVZX, f_xfer_reg, XF(1, 1), 0),
	I(PUSH, CELL_PUSH, f_push, 0, 0),
	I(POP, CELL_POP, f_pop, 0, 0),
	I(STMDA, CELL_OTHER, f_ldm, 0, 0),
	I(STM, CELL_OTHER, f_ldm, 0, 0),
	I(STMDB, CELL_OTHER, f_ldm, 0, 0),
	I(STMIB, CELL_OTHER, f_ldm, 0, 0),
	I(LDMDA, CELL_OTHER, f_ldm, 1, 0),
	I(LDM, CELL_OTHER, f_ldm, 1, 0),
	I(LDMDB, CELL_OTHER, f_ldm, 1, 0),
	I(LDMIB, CELL_OTHER, f_ldm, 1, 0),

	/* media: saturate, pack, select, reverse, extend, bit field */
	I(PAS_S, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PAS_Q, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PAS_SH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PAS_U, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PAS_UQ, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PAS_UH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PKHBT, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(PKHTB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SSAT, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(USAT, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SSAT16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(USAT16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SEL, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SXTB16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SXTAB16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SXTAB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SXTAH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(UXTB16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(UXTAB16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(UXTAB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(UXTAH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SXTB, CELL_MOVSX, f_ext, 1, ARM_WM_F12),
	I(SXTH, CELL_MOVSX, f_ext, 2, ARM_WM_F12),
	I(UXTB, CELL_MOVZX, f_ext, 1, ARM_WM_F12),
	I(UXTH, CELL_MOVZX, f_ext, 2, ARM_WM_F12),
	I(REV, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(REV16, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(RBIT, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(REVSH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(SBFX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(BFC, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(BFI, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(UBFX, CELL_OTHER, f_other, 0, ARM_WM_F12),

	/* branches and system calls */
	I(B, CELL_JMP, f_b, 0, 0),
	I(BL, CELL_CALL, f_bl, 0, 0),
	I(BLX_IMM, CELL_CALL, f_blx_imm, 0, 0),
	I(SVC, CELL_SYSCALL, f_svc, 0, 0),

	/* coprocessor, VFP, Advanced SIMD: not validity-checked */
	I(CDP, CELL_OTHER, f_other, 0, 0),
	I(MCR, CELL_OTHER, f_other, 0, 0),
	I(MRC, CELL_OTHER, f_mrc, 0, 0),
	I(MCRR, CELL_OTHER, f_other, 0, 0),
	I(MRRC, CELL_OTHER, f_other, 0, ARM_WM_F12 | ARM_WM_F16),
	I(STC, CELL_OTHER, f_cop_wb, 0, 0),
	I(LDC, CELL_OTHER, f_cop_wb, 0, 0),
	I(ASIMD_DP, CELL_OTHER, f_other, 0, 0),
	I(VLDST, CELL_OTHER, f_vldst, 0, 0),
	I(VDOT, CELL_OTHER, f_other, 0, 0),
	I(PLI_IMM, CELL_OTHER, f_other, 0, 0),
	I(PLD_IMM, CELL_OTHER, f_other, 0, 0),
	I(PLI_REG, CELL_OTHER, f_other, 0, 0),
	I(PLD_REG, CELL_OTHER, f_other, 0, 0),
	I(CLREX, CELL_OTHER, f_other, 0, 0),
	I(DSB, CELL_OTHER, f_other, 0, 0),
	I(DMB, CELL_OTHER, f_other, 0, 0),
	I(ISB, CELL_OTHER, f_other, 0, 0),
	I(BARRIER, CELL_OTHER, f_other, 0, 0),
	I(RFE, CELL_PRIV, f_rfe, 0, 0),
	I(SRS, CELL_PRIV, f_priv, 0, 0),
};



/* ---- entry --------------------------------------------------------------- */

uint32_t cell_decode_arm32(const uint8_t *p, uint32_t n, uint64_t va,
			   int be, struct cell_insn *out)
{
	struct gt_arm32_insn in;
	const struct a_info *e;

	if (!p || n < 4u || !out)
		return 0;
	(void)gt_arm32_decode(&in, arm_w(p, be));
	arm_begin(out, va, 4u);
	/* the unconditional space (15) reports "always", as a Thumb instruction does */
	if (in.cond != 15u)
		out->cond = in.cond;
	e = &g_info[in.id];
	e->fn(in, e, out);
	return 4u;
}
