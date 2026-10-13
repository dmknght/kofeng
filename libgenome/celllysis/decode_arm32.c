/*
 * decode_arm32.c - ARM state into the engine's one instruction form.
 *
 * AN ADAPTER. Which instruction a word is - and whether it is one - is
 * genotype's (libgenome/genotype/arm32, kgenome_arm32_decode): a table lookup that
 * answers with the instruction's NAME and keeps the word. This turns that into
 * struct kgenome_cell_insn, and the conventions it spells operands in are
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
 * calls INVALID or UDF is KGENOME_CELL_UD, length 4; the coprocessor, VFP and Advanced
 * SIMD spaces are KGENOME_CELL_OTHER with the core registers they write.
 */
#include <arm32/arm32.h>

#include "decode_arm32.h"


struct a_info;
typedef void (*a_fn)(struct kgenome_arm32_insn in, const struct a_info *e,
		     struct kgenome_cell_insn *o);

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

#define I(id, c, f, a, w) [KGENOME_ARM32_I_##id] = { (f), (c), (a), (w) }

/* ---- the second operand of data processing ------------------------------- */

/*
 * A register with its shift, as a source operand: an immediate amount, where an
 * amount of 0 means no shift for lsl, 32 for lsr and asr, and rrx for ror.
 */
static void op2_reg(struct kgenome_arm32_insn in, struct kgenome_cell_operand *t)
{
	uint32_t type = kgenome_arm32_shift_type(in), amt = kgenome_arm32_shift_imm(in);

	kgenome_arm_op_reg(t, kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
	if (!amt) {
		if (type == 3u)
			kgenome_arm_shift(t, KGENOME_ARM_SH_RRX, 1u, 0xffu);
		else if (type)
			kgenome_arm_shift(t, type + 1u, 32u, 0xffu);
		/* lsl #0 is the register itself */
		return;
	}
	kgenome_arm_shift(t, type + 1u, amt, 0xffu);
}

/* ... or by a register: the amount is in the register. */
static void op2_rsr(struct kgenome_arm32_insn in, struct kgenome_cell_operand *t)
{
	kgenome_arm_op_reg(t, kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
	kgenome_arm_shift(t, kgenome_arm32_shift_type(in) + 1u, 0, kgenome_arm32_r8(in));
}

static void f_dp_imm(struct kgenome_arm32_insn in, const struct a_info *e,
		     struct kgenome_cell_insn *o)
{
	kgenome_arm_dp_imm(o, e->aux, kgenome_arm32_s(in), kgenome_arm32_r16(in),
			   kgenome_arm32_r12(in), kgenome_arm32_modimm(in), 8);
}

static void f_dp_reg(struct kgenome_arm32_insn in, const struct a_info *e,
		     struct kgenome_cell_insn *o)
{
	struct kgenome_cell_operand t;

	op2_reg(in, &t);
	kgenome_arm_dp(o, e->aux, kgenome_arm32_s(in), kgenome_arm32_r16(in), kgenome_arm32_r12(in), &t, 8);
}

static void f_dp_rsr(struct kgenome_arm32_insn in, const struct a_info *e,
		     struct kgenome_cell_insn *o)
{
	struct kgenome_cell_operand t;

	op2_rsr(in, &t);
	kgenome_arm_dp(o, e->aux, kgenome_arm32_s(in), kgenome_arm32_r16(in), kgenome_arm32_r12(in), &t, 8);
}

/* ---- small forms --------------------------------------------------------- */

static void f_ud(struct kgenome_arm32_insn in, const struct a_info *e,
		 struct kgenome_cell_insn *o)
{
	(void)in;
	(void)e;
	kgenome_arm_ud(o);
}

static void f_other(struct kgenome_arm32_insn in, const struct a_info *e,
		    struct kgenome_cell_insn *o)
{
	kgenome_arm_other(o, kgenome_arm_wm(e->wm, in.w));
}

static void f_priv(struct kgenome_arm32_insn in, const struct a_info *e,
		   struct kgenome_cell_insn *o)
{
	o->op = e->cls;
	o->wmask = kgenome_arm_wm(e->wm, in.w);
}

/* A hint: the unallocated ones execute as nop. */
static void f_nop(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	(void)in;
	o->op = e->cls;
}

static void f_movw(struct kgenome_arm32_insn in, const struct a_info *e,
		   struct kgenome_cell_insn *o)
{
	o->n_op = 2;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r12(in), KGENOME_CELL_OF_WRITE);
	o->wmask = kgenome_arm_wm(e->wm, in.w);
	o->op = e->cls;
	kgenome_arm_imm(&o->o[1], kgenome_arm32_imm16(in));
}

/* movt: rd = rd & 0xffff | v << 16, which is an OR of the high half. */
static void f_movt(struct kgenome_arm32_insn in, const struct a_info *e,
		   struct kgenome_cell_insn *o)
{
	o->n_op = 2;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r12(in), KGENOME_CELL_OF_WRITE);
	o->wmask = kgenome_arm_wm(e->wm, in.w);
	o->op = e->cls;
	kgenome_arm_imm(&o->o[1], (uint64_t)kgenome_arm32_imm16(in) << 16);
}

static void f_mrs(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	o->op = e->cls;
	o->wmask = KGENOME_ARM_R(kgenome_arm32_r12(in));
	o->n_op = 1;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r12(in), KGENOME_CELL_OF_WRITE);
}

static void f_bx(struct kgenome_arm32_insn in, const struct a_info *e,
		 struct kgenome_cell_insn *o)
{
	uint32_t rm = kgenome_arm32_r0(in);

	(void)e;
	o->wmask = KGENOME_ARM_R(KGENOME_ARM_PC);
	o->flags |= KGENOME_CELL_F_INDIRECT;
	o->op = rm == KGENOME_ARM_LR ? KGENOME_CELL_RET : KGENOME_CELL_JMP;
	o->n_op = 1;
	kgenome_arm_reg(&o->o[0], rm, KGENOME_CELL_OF_READ);
}

/* bxj: bx on a core without Jazelle. */
static void f_bxj(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	o->wmask = KGENOME_ARM_R(KGENOME_ARM_PC);
	o->flags |= KGENOME_CELL_F_INDIRECT;
	o->op = e->cls;
	o->n_op = 1;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
}

static void f_blx_reg(struct kgenome_arm32_insn in, const struct a_info *e,
		      struct kgenome_cell_insn *o)
{
	o->flags |= KGENOME_CELL_F_INDIRECT;
	o->op = e->cls;
	o->wmask = KGENOME_ARM_R(KGENOME_ARM_LR) | KGENOME_ARM_R(KGENOME_ARM_PC);
	o->n_op = 1;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
}

static void f_clz(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	kgenome_arm_other(o, kgenome_arm_wm(e->wm, in.w));
	o->n_op = 2;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r12(in), KGENOME_CELL_OF_WRITE);
	kgenome_arm_reg(&o->o[1], kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
}

/* bkpt, hvc, smc: the immediate. */
static void f_imm16(struct kgenome_arm32_insn in, const struct a_info *e,
		    struct kgenome_cell_insn *o)
{
	kgenome_arm_imm_insn(o, e->cls, kgenome_arm32_imm16_split(in));
}

static void f_mul(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	o->op = e->cls;
	o->wmask = kgenome_arm_wm(e->wm, in.w);
	o->n_op = 3;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r16(in), KGENOME_CELL_OF_WRITE);
	kgenome_arm_reg(&o->o[1], kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
	kgenome_arm_reg(&o->o[2], kgenome_arm32_r8(in), KGENOME_CELL_OF_READ);
}

/* sdiv and udiv are spelled as mul is: destination, then the two sources. */
static void f_div(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	f_mul(in, e, o);
}

/* sxtb sxth uxtb uxth: a move that widens, with the rotation of the source. */
static void f_ext(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	uint32_t rot = kgenome_arm32_rot(in);

	kgenome_arm_other(o, kgenome_arm_wm(e->wm, in.w));
	o->op = e->cls;
	o->n_op = 2;
	kgenome_arm_reg(&o->o[0], kgenome_arm32_r12(in), KGENOME_CELL_OF_WRITE);
	kgenome_arm_reg(&o->o[1], kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
	o->o[1].size = e->aux;
	if (rot)
		kgenome_arm_shift(&o->o[1], KGENOME_ARM_SH_ROR, rot * 8u, 0xffu);
}

/* ---- loads and stores ---------------------------------------------------- */

static void f_xfer_imm(struct kgenome_arm32_insn in, const struct a_info *e,
		       struct kgenome_cell_insn *o)
{
	uint32_t p = kgenome_arm32_p(in), u = kgenome_arm32_u(in), w = kgenome_arm32_wb(in);
	uint32_t rn = kgenome_arm32_r16(in), rt = kgenome_arm32_r12(in);
	int l = e->aux & 1u;
	unsigned size = (e->aux & 2u) ? 1u : 4u;
	struct kgenome_cell_operand *m = l ? &o->o[1] : &o->o[0];
	int64_t off = (int64_t)kgenome_arm32_imm12(in);
	uint64_t wm = 0;

	o->op = e->cls;
	if (l) {
		wm = KGENOME_ARM_R(rt);
		kgenome_arm_reg(&o->o[0], rt, KGENOME_CELL_OF_WRITE);
	} else {
		kgenome_arm_reg(&o->o[1], rt, KGENOME_CELL_OF_READ);
	}
	o->n_op = 2;
	if (!u)
		off = -off;
	if (rn == KGENOME_ARM_PC && p && !w)
		kgenome_arm_mem(m, rn, 8 + off, size,
			(l ? KGENOME_CELL_OF_READ : KGENOME_CELL_OF_WRITE) | KGENOME_CELL_OF_RIPREL);
	else
		kgenome_arm_mem(m, rn, p ? off : 0, size, l ? KGENOME_CELL_OF_READ : KGENOME_CELL_OF_WRITE);
	if (!p) {
		o->n_op = 3;
		kgenome_arm_imm(&o->o[2], (uint64_t)off);
	}
	if (!p || w)
		wm |= KGENOME_ARM_R(rn);
	o->wmask = wm;

	if (l && !(e->aux & 2u) && rt == KGENOME_ARM_PC) {
		/* ldr pc, [...] - an indirect jump, through memory */
		struct kgenome_cell_operand mem = *m;

		o->op = KGENOME_CELL_JMP;
		o->flags |= KGENOME_CELL_F_INDIRECT;
		kgenome_arm_clr(o);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

static void f_xfer_reg(struct kgenome_arm32_insn in, const struct a_info *e,
		       struct kgenome_cell_insn *o)
{
	uint32_t p = kgenome_arm32_p(in), u = kgenome_arm32_u(in), w = kgenome_arm32_wb(in);
	uint32_t rn = kgenome_arm32_r16(in), rt = kgenome_arm32_r12(in);
	int l = e->aux & 1u;
	unsigned size = (e->aux & 2u) ? 1u : 4u;
	struct kgenome_cell_operand *m = l ? &o->o[1] : &o->o[0];
	struct kgenome_cell_operand t;
	uint64_t wm = 0;

	o->op = e->cls;
	if (l) {
		wm = KGENOME_ARM_R(rt);
		kgenome_arm_reg(&o->o[0], rt, KGENOME_CELL_OF_WRITE);
	} else {
		kgenome_arm_reg(&o->o[1], rt, KGENOME_CELL_OF_READ);
	}
	o->n_op = 2;
	op2_reg(in, &t);
	kgenome_arm_mem(m, rn, 0, size, l ? KGENOME_CELL_OF_READ : KGENOME_CELL_OF_WRITE);
	if (!p) {
		/* post-indexed: the access is at the base, and the register that
		 * moves it is the third operand */
		o->n_op = 3;
		o->o[2] = t;
		o->o[2].imm = u ? 0u : 1u;
	} else {
		m->index = (uint8_t)kgenome_arm32_r0(in);
		m->imm = u ? 0u : 1u;
		if (t.scale == KGENOME_ARM_SH_NONE) {
			m->scale = 1u;
		} else if (t.scale == KGENOME_ARM_SH_LSL && t.disp <= 7) {
			m->scale = (uint8_t)(1u << t.disp);
		} else {
			m->scale = 0;
			m->imm |= (uint64_t)t.scale << 8;
		}
	}
	if (!p || w)
		wm |= KGENOME_ARM_R(rn);
	o->wmask = wm;

	if (l && !(e->aux & 2u) && rt == KGENOME_ARM_PC) {
		struct kgenome_cell_operand mem = *m;

		o->op = KGENOME_CELL_JMP;
		o->flags |= KGENOME_CELL_F_INDIRECT;
		kgenome_arm_clr(o);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

/* halfword, signed byte and doubleword transfers, immediate offset */
static void f_xferx_imm(struct kgenome_arm32_insn in, const struct a_info *e,
			struct kgenome_cell_insn *o)
{
	uint32_t p = kgenome_arm32_p(in), u = kgenome_arm32_u(in), w = kgenome_arm32_wb(in);
	uint32_t rn = kgenome_arm32_r16(in), rt = kgenome_arm32_r12(in);
	int load = (e->aux & L1) != 0;
	unsigned size = e->aux & 15u;
	struct kgenome_cell_operand *m = load ? &o->o[1] : &o->o[0];
	int64_t off = (int64_t)kgenome_arm32_imm8_split(in);
	uint64_t wm = 0;

	o->op = e->cls;
	if (load) {
		wm = KGENOME_ARM_R(rt);
		if (size == 8u)
			wm |= KGENOME_ARM_R((rt + 1u) & 15u);
		kgenome_arm_reg(&o->o[0], rt, KGENOME_CELL_OF_WRITE);
	} else {
		kgenome_arm_reg(&o->o[1], rt, KGENOME_CELL_OF_READ);
	}
	o->n_op = 2;
	if (!u)
		off = -off;
	if (rn == KGENOME_ARM_PC && p && !w)
		kgenome_arm_mem(m, rn, 8 + off, size,
			(load ? KGENOME_CELL_OF_READ : KGENOME_CELL_OF_WRITE) | KGENOME_CELL_OF_RIPREL);
	else
		kgenome_arm_mem(m, rn, p ? off : 0, size,
			load ? KGENOME_CELL_OF_READ : KGENOME_CELL_OF_WRITE);
	if (!p) {
		o->n_op = 3;
		kgenome_arm_imm(&o->o[2], (uint64_t)off);
	}
	if (!p || w)
		wm |= KGENOME_ARM_R(rn);
	o->wmask = wm;
}

/* ... and register offset */
static void f_xferx_reg(struct kgenome_arm32_insn in, const struct a_info *e,
			struct kgenome_cell_insn *o)
{
	uint32_t p = kgenome_arm32_p(in), u = kgenome_arm32_u(in), w = kgenome_arm32_wb(in);
	uint32_t rn = kgenome_arm32_r16(in), rt = kgenome_arm32_r12(in);
	int load = (e->aux & L1) != 0;
	unsigned size = e->aux & 15u;
	struct kgenome_cell_operand *m = load ? &o->o[1] : &o->o[0];
	uint64_t wm = 0;

	o->op = e->cls;
	if (load) {
		wm = KGENOME_ARM_R(rt);
		if (size == 8u)
			wm |= KGENOME_ARM_R((rt + 1u) & 15u);
		kgenome_arm_reg(&o->o[0], rt, KGENOME_CELL_OF_WRITE);
	} else {
		kgenome_arm_reg(&o->o[1], rt, KGENOME_CELL_OF_READ);
	}
	o->n_op = 2;
	kgenome_arm_mem(m, rn, 0, size, load ? KGENOME_CELL_OF_READ : KGENOME_CELL_OF_WRITE);
	if (p) {
		m->index = (uint8_t)kgenome_arm32_r0(in);
		m->imm = u ? 0u : 1u;
	} else {
		o->n_op = 3;
		kgenome_arm_reg(&o->o[2], kgenome_arm32_r0(in), KGENOME_CELL_OF_READ);
		o->o[2].imm = u ? 0u : 1u;
	}
	if (!p || w)
		wm |= KGENOME_ARM_R(rn);
	o->wmask = wm;
}

/* str rt,[sp,#-4]! and ldr rt,[sp],#4: the architecture's PUSH and POP */
static void f_push1(struct kgenome_arm32_insn in, const struct a_info *e,
		    struct kgenome_cell_insn *o)
{
	(void)e;
	kgenome_arm_pushpop(o, 0, KGENOME_ARM_R(kgenome_arm32_r12(in)));
}

static void f_pop1(struct kgenome_arm32_insn in, const struct a_info *e,
		   struct kgenome_cell_insn *o)
{
	(void)e;
	kgenome_arm_pushpop(o, 1, KGENOME_ARM_R(kgenome_arm32_r12(in)));
}

static void f_push(struct kgenome_arm32_insn in, const struct a_info *e,
		   struct kgenome_cell_insn *o)
{
	(void)e;
	kgenome_arm_pushpop(o, 0, kgenome_arm32_list(in));
}

static void f_pop(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	(void)e;
	kgenome_arm_pushpop(o, 1, kgenome_arm32_list(in));
}

/* ldm and stm, every addressing mode; aux is 1 for a load */
static void f_ldm(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	uint32_t rn = kgenome_arm32_r16(in), list = kgenome_arm32_list(in);
	uint32_t s = kgenome_arm32_b(in), w = kgenome_arm32_wb(in);
	int l = e->aux & 1u;

	o->op = e->cls;
	if (l)
		o->wmask |= list;
	if (w)
		o->wmask |= KGENOME_ARM_R(rn);
	if (l && (list & KGENOME_ARM_R(KGENOME_ARM_PC))) {
		/* ldm ..., {..., pc}: a branch (an exception return with ^) */
		o->op = s ? KGENOME_CELL_PRIV : KGENOME_CELL_JMP;
		if (!s)
			o->flags |= KGENOME_CELL_F_INDIRECT;
		o->o[0].imm = list;
		return;
	}
	o->n_op = 2;
	kgenome_arm_reg(&o->o[0], rn, w ? KGENOME_CELL_OF_WRITE | KGENOME_CELL_OF_READ : KGENOME_CELL_OF_READ);
	kgenome_arm_imm(&o->o[1], list);
}

/* ---- branches ------------------------------------------------------------ */

static void f_b(struct kgenome_arm32_insn in, const struct a_info *e,
		struct kgenome_cell_insn *o)
{
	/* a 32-bit address space: a branch past either end wraps */
	uint64_t t = (o->at_va + 8u + (uint64_t)(int64_t)kgenome_arm32_branch_off(in)) &
		     0xffffffffu;

	o->n_op = 1;
	o->o[0].kind = KGENOME_CELL_O_REL;
	o->target_va = t;
	o->target = t;
	o->wmask = KGENOME_ARM_R(KGENOME_ARM_PC);
	o->op = in.cond == 0xEu ? KGENOME_CELL_JMP : KGENOME_CELL_JCC;
	if (o->op == KGENOME_CELL_JCC)
		o->cond = in.cond;
	(void)e;
}

static void f_bl(struct kgenome_arm32_insn in, const struct a_info *e,
		 struct kgenome_cell_insn *o)
{
	uint64_t t = (o->at_va + 8u + (uint64_t)(int64_t)kgenome_arm32_branch_off(in)) &
		     0xffffffffu;

	o->n_op = 1;
	o->o[0].kind = KGENOME_CELL_O_REL;
	o->target_va = t;
	o->target = t;
	o->wmask = KGENOME_ARM_R(KGENOME_ARM_PC) | KGENOME_ARM_R(KGENOME_ARM_LR);
	o->op = e->cls;
}

/* blx (immediate): always to Thumb state, and the H bit is the halfword. */
static void f_blx_imm(struct kgenome_arm32_insn in, const struct a_info *e,
		      struct kgenome_cell_insn *o)
{
	uint64_t t = (o->at_va + 8u + (uint64_t)(int64_t)kgenome_arm32_branch_off(in) +
		      (kgenome_arm32_h(in) ? 2u : 0u)) & 0xffffffffu;

	o->op = e->cls;
	o->wmask = KGENOME_ARM_R(KGENOME_ARM_LR) | KGENOME_ARM_R(KGENOME_ARM_PC);
	o->n_op = 1;
	o->o[0].kind = KGENOME_CELL_O_REL;
	o->target_va = t & ~(uint64_t)1;
	o->target = o->target_va;
}

static void f_svc(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	kgenome_arm_imm_insn(o, e->cls, kgenome_arm32_imm24(in));
}

/* ---- the coprocessor space ----------------------------------------------- */

/* ldc, stc: the base register is written back with W. */
static void f_cop_wb(struct kgenome_arm32_insn in, const struct a_info *e,
		     struct kgenome_cell_insn *o)
{
	kgenome_arm_wmask_if(o, e->cls, kgenome_arm32_wb(in), kgenome_arm32_r16(in));
}

/* mrc, vmov to core, vmrs: Rt is written, unless it is pc (apsr_nzcv). */
static void f_mrc(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	kgenome_arm_wmask_if(o, e->cls, kgenome_arm32_r12(in) != KGENOME_ARM_PC,
			     kgenome_arm32_r12(in));
}

/* Advanced SIMD structure load/store: the base is written back when Rm is not pc. */
static void f_vldst(struct kgenome_arm32_insn in, const struct a_info *e,
		    struct kgenome_cell_insn *o)
{
	kgenome_arm_wmask_if(o, e->cls, kgenome_arm32_r0(in) != 15u, kgenome_arm32_r16(in));
}

/* rfe: returns, and writes the base back with W. */
static void f_rfe(struct kgenome_arm32_insn in, const struct a_info *e,
		  struct kgenome_cell_insn *o)
{
	kgenome_arm_rfe(o, e->cls, kgenome_arm32_wb(in), kgenome_arm32_r16(in));
}

static const struct a_info g_info[KGENOME_ARM32_I_COUNT] = {
	/* what the architecture leaves unallocated, and what it defines to fault */
	I(INVALID, KGENOME_CELL_UD, f_ud, 0, 0),
	I(UDF, KGENOME_CELL_UD, f_ud, 0, 0),

	/* multiplies. The two- and three-register forms the engine reads are MUL */
	I(MUL, KGENOME_CELL_MUL, f_mul, 0, KGENOME_ARM_WM_F16),
	I(MLA, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(MLS, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(UMAAL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(UMULL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(UMLAL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(SMULL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(SMLAL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(SMLAXY, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMLAWY, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMULWY, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMLALXY, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(SMULXY, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMUAD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMLAD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMUSD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMLSD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMLALD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(SMLSLD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16 | KGENOME_ARM_WM_F12),
	I(SMMUL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMMLA, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SMMLS, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(USAD8, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(USADA8, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F16),
	I(SDIV, KGENOME_CELL_IDIV, f_div, 0, KGENOME_ARM_WM_F16),
	I(UDIV, KGENOME_CELL_DIV, f_div, 0, KGENOME_ARM_WM_F16),

	/* swap, exclusive, acquire/release */
	I(SWP, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SWPB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STL, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(STLB, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(STLH, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(LDA, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDAB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDAH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STREX, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDREX, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STREXD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDREXD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12 | KGENOME_ARM_WM_F12N),
	I(STREXB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDREXB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STREXH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDREXH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STLEX, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDAEX, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STLEXD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDAEXD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12 | KGENOME_ARM_WM_F12N),
	I(STLEXB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDAEXB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(STLEXH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(LDAEXH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),

	/* halfword, signed byte and doubleword transfers */
	I(STRH_IMM, KGENOME_CELL_MOV, f_xferx_imm, XX(2, 0), 0),
	I(STRH_REG, KGENOME_CELL_MOV, f_xferx_reg, XX(2, 0), 0),
	I(LDRH_IMM, KGENOME_CELL_MOVZX, f_xferx_imm, XX(2, L1), 0),
	I(LDRH_REG, KGENOME_CELL_MOVZX, f_xferx_reg, XX(2, L1), 0),
	I(LDRD_IMM, KGENOME_CELL_MOV, f_xferx_imm, XX(8, L1), 0),
	I(LDRD_REG, KGENOME_CELL_MOV, f_xferx_reg, XX(8, L1), 0),
	I(STRD_IMM, KGENOME_CELL_MOV, f_xferx_imm, XX(8, 0), 0),
	I(STRD_REG, KGENOME_CELL_MOV, f_xferx_reg, XX(8, 0), 0),
	I(LDRSB_IMM, KGENOME_CELL_MOVSX, f_xferx_imm, XX(1, L1), 0),
	I(LDRSB_REG, KGENOME_CELL_MOVSX, f_xferx_reg, XX(1, L1), 0),
	I(LDRSH_IMM, KGENOME_CELL_MOVSX, f_xferx_imm, XX(2, L1), 0),
	I(LDRSH_REG, KGENOME_CELL_MOVSX, f_xferx_reg, XX(2, L1), 0),

	/* the miscellaneous space */
	I(MRS, KGENOME_CELL_PRIV, f_mrs, 0, 0),
	I(MSR_REG, KGENOME_CELL_PRIV, f_priv, 0, 0),
	I(BX, KGENOME_CELL_JMP, f_bx, 0, 0),
	I(BXJ, KGENOME_CELL_JMP, f_bxj, 0, 0),
	I(BLX_REG, KGENOME_CELL_CALL, f_blx_reg, 0, 0),
	I(CLZ, KGENOME_CELL_OTHER, f_clz, 0, KGENOME_ARM_WM_F12),
	I(CRC32, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(CRC32C, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(QADD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(QSUB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(QDADD, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(QDSUB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(ERET, KGENOME_CELL_PRIV, f_priv, 0, KGENOME_ARM_WM_PC),
	I(BKPT, KGENOME_CELL_INT, f_imm16, 0, 0),
	I(HVC, KGENOME_CELL_PRIV, f_imm16, 0, 0),
	I(SMC, KGENOME_CELL_PRIV, f_imm16, 0, 0),
	I(HINT, KGENOME_CELL_NOP, f_nop, 0, 0),
	I(MSR_IMM, KGENOME_CELL_PRIV, f_priv, 0, 0),
	I(SETEND, KGENOME_CELL_PRIV, f_priv, 0, 0),
	I(CPS, KGENOME_CELL_PRIV, f_priv, 0, 0),

	/* data processing: the opcode is the aux */
#define DP(n, opc) \
	I(n##_REG, KGENOME_CELL_OTHER, f_dp_reg, opc, 0), \
	I(n##_RSR, KGENOME_CELL_OTHER, f_dp_rsr, opc, 0), \
	I(n##_IMM, KGENOME_CELL_OTHER, f_dp_imm, opc, 0)
	DP(AND, 0), DP(EOR, 1), DP(SUB, 2), DP(RSB, 3), DP(ADD, 4), DP(ADC, 5),
	DP(SBC, 6), DP(RSC, 7), DP(TST, 8), DP(TEQ, 9), DP(CMP, 10), DP(CMN, 11),
	DP(ORR, 12), DP(MOV, 13), DP(BIC, 14), DP(MVN, 15),
#undef DP
	I(MOVW, KGENOME_CELL_MOV, f_movw, 0, KGENOME_ARM_WM_F12),
	I(MOVT, KGENOME_CELL_OR, f_movt, 0, KGENOME_ARM_WM_F12),

	/* loads and stores */
	I(PUSH_1, KGENOME_CELL_PUSH, f_push1, 0, 0),
	I(POP_1, KGENOME_CELL_POP, f_pop1, 0, 0),
	I(STR_IMM, KGENOME_CELL_MOV, f_xfer_imm, XF(0, 0), 0),
	I(LDR_IMM, KGENOME_CELL_MOV, f_xfer_imm, XF(1, 0), 0),
	I(STRB_IMM, KGENOME_CELL_MOV, f_xfer_imm, XF(0, 1), 0),
	I(LDRB_IMM, KGENOME_CELL_MOVZX, f_xfer_imm, XF(1, 1), 0),
	I(STR_REG, KGENOME_CELL_MOV, f_xfer_reg, XF(0, 0), 0),
	I(LDR_REG, KGENOME_CELL_MOV, f_xfer_reg, XF(1, 0), 0),
	I(STRB_REG, KGENOME_CELL_MOV, f_xfer_reg, XF(0, 1), 0),
	I(LDRB_REG, KGENOME_CELL_MOVZX, f_xfer_reg, XF(1, 1), 0),
	I(PUSH, KGENOME_CELL_PUSH, f_push, 0, 0),
	I(POP, KGENOME_CELL_POP, f_pop, 0, 0),
	I(STMDA, KGENOME_CELL_OTHER, f_ldm, 0, 0),
	I(STM, KGENOME_CELL_OTHER, f_ldm, 0, 0),
	I(STMDB, KGENOME_CELL_OTHER, f_ldm, 0, 0),
	I(STMIB, KGENOME_CELL_OTHER, f_ldm, 0, 0),
	I(LDMDA, KGENOME_CELL_OTHER, f_ldm, 1, 0),
	I(LDM, KGENOME_CELL_OTHER, f_ldm, 1, 0),
	I(LDMDB, KGENOME_CELL_OTHER, f_ldm, 1, 0),
	I(LDMIB, KGENOME_CELL_OTHER, f_ldm, 1, 0),

	/* media: saturate, pack, select, reverse, extend, bit field */
	I(PAS_S, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PAS_Q, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PAS_SH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PAS_U, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PAS_UQ, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PAS_UH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PKHBT, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(PKHTB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SSAT, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(USAT, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SSAT16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(USAT16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SEL, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SXTB16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SXTAB16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SXTAB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SXTAH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(UXTB16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(UXTAB16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(UXTAB, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(UXTAH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SXTB, KGENOME_CELL_MOVSX, f_ext, 1, KGENOME_ARM_WM_F12),
	I(SXTH, KGENOME_CELL_MOVSX, f_ext, 2, KGENOME_ARM_WM_F12),
	I(UXTB, KGENOME_CELL_MOVZX, f_ext, 1, KGENOME_ARM_WM_F12),
	I(UXTH, KGENOME_CELL_MOVZX, f_ext, 2, KGENOME_ARM_WM_F12),
	I(REV, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(REV16, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(RBIT, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(REVSH, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(SBFX, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(BFC, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(BFI, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),
	I(UBFX, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12),

	/* branches and system calls */
	I(B, KGENOME_CELL_JMP, f_b, 0, 0),
	I(BL, KGENOME_CELL_CALL, f_bl, 0, 0),
	I(BLX_IMM, KGENOME_CELL_CALL, f_blx_imm, 0, 0),
	I(SVC, KGENOME_CELL_SYSCALL, f_svc, 0, 0),

	/* coprocessor, VFP, Advanced SIMD: not validity-checked */
	I(CDP, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(MCR, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(MRC, KGENOME_CELL_OTHER, f_mrc, 0, 0),
	I(MCRR, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(MRRC, KGENOME_CELL_OTHER, f_other, 0, KGENOME_ARM_WM_F12 | KGENOME_ARM_WM_F16),
	I(STC, KGENOME_CELL_OTHER, f_cop_wb, 0, 0),
	I(LDC, KGENOME_CELL_OTHER, f_cop_wb, 0, 0),
	I(ASIMD_DP, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(VLDST, KGENOME_CELL_OTHER, f_vldst, 0, 0),
	I(VDOT, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(PLI_IMM, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(PLD_IMM, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(PLI_REG, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(PLD_REG, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(CLREX, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(DSB, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(DMB, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(ISB, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(BARRIER, KGENOME_CELL_OTHER, f_other, 0, 0),
	I(RFE, KGENOME_CELL_PRIV, f_rfe, 0, 0),
	I(SRS, KGENOME_CELL_PRIV, f_priv, 0, 0),
};



/* ---- entry --------------------------------------------------------------- */

uint32_t kgenome_cell_decode_arm32(const uint8_t *p, uint32_t n, uint64_t va,
			   int be, struct kgenome_cell_insn *out)
{
	struct kgenome_arm32_insn in;
	const struct a_info *e;

	if (!p || n < 4u || !out)
		return 0;
	(void)kgenome_arm32_decode(&in, kgenome_arm_w(p, be));
	kgenome_arm_begin(out, va, 4u);
	/* the unconditional space (15) reports "always", as a Thumb instruction does */
	if (in.cond != 15u)
		out->cond = in.cond;
	e = &g_info[in.id];
	e->fn(in, e, out);
	return 4u;
}
