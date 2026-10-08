/*
 * decode_thumb.c - Thumb state (Thumb-1 and Thumb-2) into the engine's one
 * instruction form.
 *
 * AN ADAPTER, as decode_arm32.c is: which instruction these halfwords are is
 * genotype's (libgenome/genotype/arm32, gt_thumb_decode); this turns its answer
 * into struct cell_insn. The length comes from the first halfword alone - 11101,
 * 11110 and 11111 in its top five bits open a 32-bit instruction - so this
 * returns 0 only for a 32-bit instruction with two bytes left, and for no other
 * reason: a decoder that needed the second halfword to know how long the first
 * was could not step through a buffer that ends in the middle of one.
 *
 * THE NAME IS INDEXED, NOT SWITCHED ON: g_info holds, per name, the builder that
 * spells its operands, the class, that builder's argument and the recipe of
 * registers it writes without spelling them. The data-processing family is
 * decode_arm32_common.c's, shared with ARM state, so what `adds r0, r0, #4`
 * MEANS is decided in one place.
 *
 * WHAT IS NOT TRACKED, and a consumer has to know: `it`. It is CELL_OTHER,
 * length 2, and the instructions it governs report cond 0xE. The decoder is
 * stateless; an engine that wants the condition of an instruction inside the
 * block carries the IT state itself. The oracle in tools/celllysis/arm32_diff.c
 * does carry it, which is why that tool compares `cond` only on branches.
 *
 * The same validity policy as ARM state: the integer space is checked and what
 * the architecture leaves unallocated is CELL_UD with the right length; the
 * coprocessor, VFP and Advanced SIMD space is not, and is CELL_OTHER.
 */
#include <arm32/thumb.h>

#include "decode_arm32.h"


struct t_info;
typedef void (*t_fn)(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o);

struct t_info {
	t_fn    fn;             /* the builder that spells this name's operands */
	uint8_t cls;            /* CELL_* the name is filed under */
	uint8_t aux;            /* the builder's argument, see each */
	uint8_t wm;             /* ARM_WM_*, over the 32-bit word: the registers written unspelled */
};

#define L1 0x10u                /* aux of a transfer: it loads */
#define I(id, c, f, a, w) [GT_THUMB_I_##id] = { (f), (c), (a), (w) }

/* ---- helpers ------------------------------------------------------------- */

/* Where a pc-relative literal is measured from, relative to this instruction. */
static int64_t t_pcb(const struct cell_insn *o)
{
	return (int64_t)(((o->at_va + 4u) & ~(uint64_t)3) - o->at_va);
}

static void t_src_reg(struct cell_operand *t, uint32_t rm)
{
	arm_op_reg(t, rm, CELL_OF_READ);
}

static void t_src_imm(struct cell_operand *t, uint64_t v)
{
	arm_op_imm(t, v);
}

/* Register `rm` shifted by a type (0..3 = lsl lsr asr ror) and amount. */
static void t_src_shift(struct cell_operand *t, uint32_t rm, uint32_t type,
			uint32_t amt)
{
	t_src_reg(t, rm);
	if (!amt) {
		if (type == 3u)
			arm_shift(t, ARM_SH_RRX, 1u, 0xffu);
		else if (type)
			arm_shift(t, type + 1u, 32u, 0xffu);
		return;
	}
	arm_shift(t, type + 1u, amt, 0xffu);
}

/* A direct branch: where it goes, from pc = at + 4, in a 32-bit space. */
static void t_branch_to(struct cell_insn *o, uint64_t t)
{
	t &= 0xffffffffu;
	o->n_op = 1;
	o->o[0].kind = CELL_O_REL;
	o->target_va = t;
	o->target = t;
	o->wmask |= ARM_R(ARM_PC);
}

/*
 * A load or a store. `m` is the memory operand, already built; this places the
 * operands in the form ARM state uses and adds what the access writes.
 */
static void t_ls(struct cell_insn *o, int load, unsigned cls, unsigned rt,
		 const struct cell_operand *m)
{
	o->op = (uint8_t)cls;
	o->n_op = 2;
	if (load) {
		arm_reg(&o->o[0], rt, CELL_OF_WRITE);
		o->o[1] = *m;
		o->wmask |= ARM_R(rt);
	} else {
		o->o[0] = *m;
		arm_reg(&o->o[1], rt, CELL_OF_READ);
	}
}

/* The memory operand of an immediate-offset access, with the literal case. */
static void t_mem_imm(struct cell_insn *o, struct cell_operand *m, uint32_t rn,
		      int64_t off, unsigned size, int load)
{
	unsigned fl = load ? CELL_OF_READ : CELL_OF_WRITE;

	if (rn == ARM_PC)
		arm_mem(m, rn, t_pcb(o) + off, size, fl | CELL_OF_RIPREL);
	else
		arm_mem(m, rn, off, size, fl);
}

/* A register-offset memory operand: base + (index << sh). */
static void t_mem_reg(struct cell_operand *m, uint32_t rn, uint32_t rm,
		      uint32_t sh, unsigned size, int load)
{
	arm_mem(m, rn, 0, size, load ? CELL_OF_READ : CELL_OF_WRITE);
	m->index = (uint8_t)rm;
	m->scale = (uint8_t)(1u << sh);
}

static uint32_t t_word(struct gt_thumb_insn in)
{
	return in.w;
}

/* ---- the forms every size shares ----------------------------------------- */

static void f_ud(struct gt_thumb_insn in, const struct t_info *e,
		 struct cell_insn *o)
{
	(void)in;
	(void)e;
	kof_arm_ud(o);
}

static void f_other(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	kof_arm_other(o, arm_wm(e->wm, t_word(in)));
}

static void f_priv(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = arm_wm(e->wm, t_word(in));
}

static void f_nop(struct gt_thumb_insn in, const struct t_info *e,
		  struct cell_insn *o)
{
	(void)in;
	o->op = e->cls;
}

/* ---- 16-bit -------------------------------------------------------------- */

/* lsl lsr asr by an immediate: 00 op imm5 rm rd */
static void fn_shift_imm(struct gt_thumb_insn in, const struct t_info *e,
			 struct cell_insn *o)
{
	struct cell_operand t;

	(void)e;
	t_src_shift(&t, gt_thumb_n_r3(in), gt_thumb_n_shift_type(in),
		    gt_thumb_n_imm5(in));
	kof_arm_dp(o, 13u, 1u, 0, gt_thumb_n_r0(in), &t, 0);
}

/* add sub, register or 3-bit immediate */
static void fn_addsub(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	struct cell_operand t;

	if (e->aux & 2u)
		t_src_imm(&t, gt_thumb_n_imm3(in));
	else
		t_src_reg(&t, gt_thumb_n_r6(in));
	kof_arm_dp(o, (e->aux & 1u) ? 2u : 4u, 1u, gt_thumb_n_r3(in),
		   gt_thumb_n_r0(in), &t, 0);
}

/* mov cmp add sub with an 8-bit immediate: 001 op rd imm8 */
static void fn_imm8(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	struct cell_operand t;
	uint32_t rd = gt_thumb_n_r8(in);

	t_src_imm(&t, gt_thumb_n_imm8(in));
	kof_arm_dp(o, e->aux, 1u, rd, rd, &t, 0);
}

/* the data-processing register group: 010000 op rm rdn */
static void fn_dpreg(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	struct cell_operand t;
	uint32_t rd = gt_thumb_n_r0(in);

	t_src_reg(&t, gt_thumb_n_r3(in));
	kof_arm_dp(o, e->aux, 1u, rd, rd, &t, 0);
}

/* lsl lsr asr ror by register: rdn is the value, rm the amount */
static void fn_shift_reg(struct gt_thumb_insn in, const struct t_info *e,
			 struct cell_insn *o)
{
	struct cell_operand t;
	uint32_t rd = gt_thumb_n_r0(in);

	t_src_reg(&t, rd);
	arm_shift(&t, e->aux, 0, gt_thumb_n_r3(in));
	kof_arm_dp(o, 13u, 1u, 0, rd, &t, 0);
}

/* rsbs rd, rm, #0 : negs */
static void fn_rsb0(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	struct cell_operand t;

	(void)e;
	t_src_imm(&t, 0);
	kof_arm_dp(o, 3u, 1u, gt_thumb_n_r3(in), gt_thumb_n_r0(in), &t, 0);
}

/* muls rd, rm, rd */
static void fn_mul(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	uint32_t rd = gt_thumb_n_r0(in);

	o->op = e->cls;
	o->wmask = ARM_R(rd);
	o->n_op = 3;
	arm_reg(&o->o[0], rd, CELL_OF_WRITE);
	arm_reg(&o->o[1], gt_thumb_n_r3(in), CELL_OF_READ);
	arm_reg(&o->o[2], rd, CELL_OF_READ);
}

/* add cmp mov on any registers */
static void fn_hi(struct gt_thumb_insn in, const struct t_info *e,
		  struct cell_insn *o)
{
	uint32_t rm = gt_thumb_n_hi_rm(in), rd = gt_thumb_n_hi_rd(in);
	struct cell_operand t;

	t_src_reg(&t, rm);
	switch (e->aux) {
	case 4:
		kof_arm_dp(o, 4u, 0, rd, rd, &t, 0);
		return;
	case 10:
		kof_arm_dp(o, 10u, 1u, rd, rd, &t, 0);
		return;
	default:
		kof_arm_dp(o, 13u, 0, 0, rd, &t, 0);
		if (rd == rm && rd != ARM_PC)
			o->op = CELL_NOP;       /* mov r8, r8 is the Thumb-1 nop */
		return;
	}
}

/* bx, blx register */
static void fn_bx(struct gt_thumb_insn in, const struct t_info *e,
		  struct cell_insn *o)
{
	uint32_t rm = gt_thumb_n_hi_rm(in);

	kof_arm_clr(o);
	o->flags |= CELL_F_INDIRECT;
	o->wmask = ARM_R(ARM_PC);
	o->n_op = 1;
	arm_reg(&o->o[0], rm, CELL_OF_READ);
	if (e->aux) {
		o->op = e->cls;
		o->wmask |= ARM_R(ARM_LR);
	} else {
		o->op = rm == ARM_LR ? CELL_RET : e->cls;
	}
}

/* ldr rt, [pc, #imm8 * 4] */
static void fn_ldr_lit(struct gt_thumb_insn in, const struct t_info *e,
		       struct cell_insn *o)
{
	struct cell_operand m;

	t_mem_imm(o, &m, ARM_PC, (int64_t)gt_thumb_n_imm8(in) * 4, 4u, 1);
	t_ls(o, 1, e->cls, gt_thumb_n_r8(in), &m);
}

/* the eight loads and stores with a register offset */
static void fn_ls_reg(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	int load = (e->aux & L1) != 0;
	struct cell_operand m;

	t_mem_reg(&m, gt_thumb_n_r3(in), gt_thumb_n_r6(in), 0, e->aux & 15u, load);
	t_ls(o, load, e->cls, gt_thumb_n_r0(in), &m);
}

/* str ldr strb ldrb with a 5-bit offset: the offset is scaled by the width */
static void fn_ls_imm5(struct gt_thumb_insn in, const struct t_info *e,
		       struct cell_insn *o)
{
	int load = (e->aux & L1) != 0;
	unsigned size = e->aux & 15u;
	struct cell_operand m;
	uint32_t off = gt_thumb_n_imm5(in) << (size == 4u ? 2 : 0);

	t_mem_imm(o, &m, gt_thumb_n_r3(in), (int64_t)off, size, load);
	t_ls(o, load, e->cls, gt_thumb_n_r0(in), &m);
}

/* strh ldrh with a 5-bit halfword offset */
static void fn_ls_half(struct gt_thumb_insn in, const struct t_info *e,
		       struct cell_insn *o)
{
	int load = (e->aux & L1) != 0;
	struct cell_operand m;

	t_mem_imm(o, &m, gt_thumb_n_r3(in), (int64_t)(gt_thumb_n_imm5(in) << 1), 2u,
		  load);
	t_ls(o, load, e->cls, gt_thumb_n_r0(in), &m);
}

/* str ldr rt, [sp, #imm8 * 4] */
static void fn_ls_sp(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	int load = (e->aux & L1) != 0;
	struct cell_operand m;

	t_mem_imm(o, &m, ARM_SP, (int64_t)gt_thumb_n_imm8(in) * 4, 4u, load);
	t_ls(o, load, e->cls, gt_thumb_n_r8(in), &m);
}

/* adr rd, label ; add rd, sp, #imm8 * 4 */
static void fn_adr(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	struct cell_operand t;

	t_src_imm(&t, (uint64_t)gt_thumb_n_imm8(in) * 4);
	kof_arm_dp(o, 4u, 0, e->aux ? ARM_SP : ARM_PC, gt_thumb_n_r8(in), &t,
		   t_pcb(o));
}

/* add sp, #imm7*4 ; sub sp, #imm7*4 */
static void fn_sp_adjust(struct gt_thumb_insn in, const struct t_info *e,
			 struct cell_insn *o)
{
	struct cell_operand t;

	t_src_imm(&t, (uint64_t)gt_thumb_n_imm7(in) * 4);
	kof_arm_dp(o, e->aux, 0, ARM_SP, ARM_SP, &t, 0);
}

/* cbz cbnz: forward only, from pc = at + 4 */
static void fn_cbz(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	uint64_t t = o->at_va + 4u + gt_thumb_n_cbz_off(in);

	o->op = e->cls;
	o->cond = (uint8_t)e->aux;      /* ne : eq */
	t_branch_to(o, t);
	o->n_op = 2;
	arm_reg(&o->o[1], gt_thumb_n_r0(in), CELL_OF_READ);
}

/* sxth sxtb uxth uxtb */
static void fn_ext(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	struct cell_operand t;

	o->op = e->cls;
	o->n_op = 2;
	o->wmask = ARM_R(gt_thumb_n_r0(in));
	arm_reg(&o->o[0], gt_thumb_n_r0(in), CELL_OF_WRITE);
	t_src_reg(&t, gt_thumb_n_r3(in));
	o->o[1] = t;
	o->o[1].size = e->aux;
}

/* push {list, lr} */
static void fn_push(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 0, gt_thumb_n_list(in) |
			  (gt_thumb_n_bit(in, 8) ? ARM_R(ARM_LR) : 0));
}

/* pop {list, pc} */
static void fn_pop(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 1, gt_thumb_n_list(in) |
			  (gt_thumb_n_bit(in, 8) ? ARM_R(ARM_PC) : 0));
}

/* rev rev16 revsh */
static void fn_rev(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	(void)e;
	kof_arm_other(o, ARM_R(gt_thumb_n_r0(in)));
}

static void fn_bkpt(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	o->op = e->cls;
	o->n_op = 1;
	arm_imm(&o->o[0], gt_thumb_n_imm8(in));
}

/* it: see the note at the top */
static void fn_it(struct gt_thumb_insn in, const struct t_info *e,
		  struct cell_insn *o)
{
	(void)in;
	(void)e;
	kof_arm_other(o, 0);
}

/* stmia ldmia rn!, {list}: 1100 l rn list */
static void fn_ldm(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	uint32_t rn = gt_thumb_n_r8(in), list = gt_thumb_n_list(in);

	o->op = e->cls;
	if (e->aux) {
		o->wmask = list;
		if (!(list & ARM_R(rn)))
			o->wmask |= ARM_R(rn);
	} else {
		o->wmask = ARM_R(rn);
	}
	o->n_op = 2;
	arm_reg(&o->o[0], rn, CELL_OF_READ | CELL_OF_WRITE);
	arm_imm(&o->o[1], list);
}

static void fn_bcond(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	o->op = e->cls;
	o->cond = (uint8_t)gt_thumb_n_cond(in);
	t_branch_to(o, o->at_va + 4u + (uint64_t)(int64_t)gt_thumb_n_bcond_off(in));
}

static void fn_svc(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->n_op = 1;
	arm_imm(&o->o[0], gt_thumb_n_imm8(in));
}

static void fn_b(struct gt_thumb_insn in, const struct t_info *e,
		 struct cell_insn *o)
{
	o->op = e->cls;
	t_branch_to(o, o->at_va + 4u + (uint64_t)(int64_t)gt_thumb_n_b_off(in));
}

/* ---- 32-bit -------------------------------------------------------------- */

/* The modified-immediate and shifted-register data-processing forms. */
static void fw_dp_imm(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	struct cell_operand t;

	t_src_imm(&t, gt_thumb_w_modimm(in));
	kof_arm_dp(o, e->aux, gt_thumb_w_s(in), gt_thumb_w_rn(in), gt_thumb_w_rd(in),
		   &t, 0);
}

static void fw_dp_reg(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	struct cell_operand t;

	t_src_shift(&t, gt_thumb_w_rm(in), gt_thumb_w_shift_type(in),
		    gt_thumb_w_shift_imm(in));
	kof_arm_dp(o, e->aux, gt_thumb_w_s(in), gt_thumb_w_rn(in), gt_thumb_w_rd(in),
		   &t, 0);
}

/* addw subw, adr: the plain 12-bit immediate; pc as the base is the address */
static void fw_plain(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	struct cell_operand t;

	t_src_imm(&t, gt_thumb_w_imm12(in));
	kof_arm_dp(o, e->aux, 0, gt_thumb_w_rn(in), gt_thumb_w_rd(in), &t, t_pcb(o));
}

static void fw_movw(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	o->n_op = 2;
	o->wmask = ARM_R(gt_thumb_w_rd(in));
	arm_reg(&o->o[0], gt_thumb_w_rd(in), CELL_OF_WRITE);
	o->op = e->cls;
	arm_imm(&o->o[1], gt_thumb_w_imm16(in));
}

static void fw_movt(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	o->n_op = 2;
	o->wmask = ARM_R(gt_thumb_w_rd(in));
	arm_reg(&o->o[0], gt_thumb_w_rd(in), CELL_OF_WRITE);
	o->op = e->cls;
	arm_imm(&o->o[1], (uint64_t)gt_thumb_w_imm16(in) << 16);
}

static void fw_bxj(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->flags |= CELL_F_INDIRECT;
	o->wmask = ARM_R(ARM_PC);
	o->n_op = 1;
	arm_reg(&o->o[0], gt_thumb_w_rn(in), CELL_OF_READ);
}

/* tbb tbh: an indirect jump through a table of bytes or halfwords */
static void fw_tb(struct gt_thumb_insn in, const struct t_info *e,
		  struct cell_insn *o)
{
	struct cell_operand *m = &o->o[0];

	o->op = e->cls;
	o->flags |= CELL_F_INDIRECT;
	o->wmask = ARM_R(ARM_PC);
	o->n_op = 1;
	arm_mem(m, gt_thumb_w_rn(in), 0, e->aux, CELL_OF_READ);
	m->index = (uint8_t)gt_thumb_w_rm(in);
	m->scale = e->aux;
}

/* ldrd strd, immediate */
static void fw_ldrd(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	uint32_t p = gt_thumb_w_bit0(in, 8), u = gt_thumb_w_bit0(in, 7);
	uint32_t w = gt_thumb_w_bit0(in, 5), rn = gt_thumb_w_rn(in);
	int l = e->aux & 1u;
	struct cell_operand m;
	int64_t off = (int64_t)gt_thumb_w_ls_imm8(in) * 4;

	if (!u)
		off = -off;
	/* the offset form with pc as the base is pc-relative, load or store; a
	 * written-back pc base is UNPREDICTABLE and is not */
	if (rn == ARM_PC && !(p && !w))
		arm_mem(&m, rn, p ? off : 0, 8u, l ? CELL_OF_READ : CELL_OF_WRITE);
	else
		t_mem_imm(o, &m, rn, p ? off : 0, 8u, l);
	t_ls(o, l, e->cls, gt_thumb_w_rt(in), &m);
	if (l)
		o->wmask |= ARM_R(gt_thumb_w_rd(in));
	if (!p) {
		o->n_op = 3;
		arm_imm(&o->o[2], (uint64_t)off);
	}
	if (w || !p)
		o->wmask |= ARM_R(rn);
}

/* ldm stm, ia and db; aux is 1 for a load */
static void fw_ldm(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	uint32_t w = gt_thumb_w_bit0(in, 5), rn = gt_thumb_w_rn(in);
	uint32_t list = gt_thumb_w_list(in);
	int l = e->aux & 1u;

	o->op = e->cls;
	if (l)
		o->wmask |= list;
	if (w)
		o->wmask |= ARM_R(rn);
	if (l && (list & ARM_R(ARM_PC))) {
		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		o->o[0].imm = list;
		return;
	}
	o->n_op = 2;
	arm_reg(&o->o[0], rn, w ? CELL_OF_READ | CELL_OF_WRITE : CELL_OF_READ);
	arm_imm(&o->o[1], list);
}

static void fw_push1(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 0, ARM_R(gt_thumb_w_rt(in)));    /* str rt, [sp, #-4]! */
}

static void fw_pop1(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 1, ARM_R(gt_thumb_w_rt(in)));    /* ldr rt, [sp], #4 */
}

static void fw_push(struct gt_thumb_insn in, const struct t_info *e,
		    struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 0, gt_thumb_w_list(in));
}

static void fw_pop(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	(void)e;
	arm_pushpop(o, 1, gt_thumb_w_list(in));
}

/* rfe: returns, and writes the base back with W */
static void fw_rfe(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = ARM_R(ARM_PC);
	if (gt_thumb_w_bit0(in, 5))
		o->wmask |= ARM_R(gt_thumb_w_rn(in));
}

static void fw_bcond(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	o->op = e->cls;
	o->cond = (uint8_t)gt_thumb_w_cond(in);
	t_branch_to(o, o->at_va + 4u + (uint64_t)(int64_t)gt_thumb_w_bcond_off(in));
}

static void fw_b(struct gt_thumb_insn in, const struct t_info *e,
		 struct cell_insn *o)
{
	o->op = e->cls;
	t_branch_to(o, o->at_va + 4u + (uint64_t)(int64_t)gt_thumb_w_b_off(in));
}

static void fw_bl(struct gt_thumb_insn in, const struct t_info *e,
		  struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = ARM_R(ARM_LR);
	t_branch_to(o, o->at_va + 4u + (uint64_t)(int64_t)gt_thumb_w_b_off(in));
}

/* blx (immediate): to ARM state, from the aligned pc */
static void fw_blx(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = ARM_R(ARM_LR);
	t_branch_to(o, (uint64_t)(int64_t)(t_pcb(o) + (int64_t)o->at_va) +
		       (uint64_t)(int64_t)gt_thumb_w_blx_off(in));
}

/* ---- 32-bit loads and stores --------------------------------------------- */

static void fw_st_imm12(struct gt_thumb_insn in, const struct t_info *e,
			struct cell_insn *o)
{
	struct cell_operand m;

	t_mem_imm(o, &m, gt_thumb_w_rn(in), (int64_t)gt_thumb_w_ls_imm12(in), e->aux, 0);
	t_ls(o, 0, e->cls, gt_thumb_w_rt(in), &m);
}

static void fw_st_imm8(struct gt_thumb_insn in, const struct t_info *e,
		       struct cell_insn *o)
{
	uint32_t p = gt_thumb_w_bit1(in, 10), u = gt_thumb_w_bit1(in, 9);
	uint32_t w = gt_thumb_w_bit1(in, 8), rn = gt_thumb_w_rn(in);
	int64_t off = (int64_t)gt_thumb_w_ls_imm8(in);
	struct cell_operand m;

	if (!u)
		off = -off;
	t_mem_imm(o, &m, rn, p ? off : 0, e->aux, 0);
	t_ls(o, 0, e->cls, gt_thumb_w_rt(in), &m);
	if (!p) {
		o->n_op = 3;
		arm_imm(&o->o[2], (uint64_t)off);
	}
	if (w || !p)
		o->wmask |= ARM_R(rn);
}

static void fw_st_reg(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	struct cell_operand m;

	t_mem_reg(&m, gt_thumb_w_rn(in), gt_thumb_w_rm(in),
		  gt_thumb_w_index_shift(in), e->aux, 0);
	t_ls(o, 0, e->cls, gt_thumb_w_rt(in), &m);
}

/*
 * What every single load does after its memory operand is built. A load whose
 * Rt is pc is a prefetch hint unless it is a word: it writes nothing but a
 * written-back base. A word load into pc is an indirect jump through memory.
 */
static void fw_load_finish(struct gt_thumb_insn in, const struct t_info *e,
			   struct cell_insn *o, const struct cell_operand *m,
			   int wb, int post, int64_t off)
{
	uint32_t rn = gt_thumb_w_rn(in), rt = gt_thumb_w_rt(in);
	int word = e->aux == 4u;

	t_ls(o, 1, e->cls, rt, m);
	if (post) {
		o->n_op = 3;
		arm_imm(&o->o[2], (uint64_t)off);
	}
	if (wb)
		o->wmask |= ARM_R(rn);
	if (!word && rt == ARM_PC) {
		o->op = CELL_OTHER;
		o->wmask = wb ? ARM_R(rn) : 0;
		return;
	}
	if (word && rt == ARM_PC) {
		struct cell_operand mem = o->o[1];

		kof_arm_clr(o);
		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		o->wmask |= ARM_R(ARM_PC);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

/* literal: u is add or subtract */
static void fw_ld_lit(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	int64_t off = (int64_t)gt_thumb_w_ls_imm12(in);
	struct cell_operand m;

	t_mem_imm(o, &m, gt_thumb_w_rn(in), gt_thumb_w_bit0(in, 7) ? off : -off, e->aux, 1);
	fw_load_finish(in, e, o, &m, 0, 0, 0);
}

static void fw_ld_imm12(struct gt_thumb_insn in, const struct t_info *e,
			struct cell_insn *o)
{
	struct cell_operand m;

	t_mem_imm(o, &m, gt_thumb_w_rn(in), (int64_t)gt_thumb_w_ls_imm12(in), e->aux, 1);
	fw_load_finish(in, e, o, &m, 0, 0, 0);
}

static void fw_ld_imm8(struct gt_thumb_insn in, const struct t_info *e,
		       struct cell_insn *o)
{
	uint32_t p = gt_thumb_w_bit1(in, 10), u = gt_thumb_w_bit1(in, 9);
	uint32_t w = gt_thumb_w_bit1(in, 8);
	int64_t off = (int64_t)gt_thumb_w_ls_imm8(in);
	struct cell_operand m;

	if (!u)
		off = -off;
	t_mem_imm(o, &m, gt_thumb_w_rn(in), p ? off : 0, e->aux, 1);
	fw_load_finish(in, e, o, &m, w || !p, !p, off);
}

static void fw_ld_reg(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	struct cell_operand m;

	t_mem_reg(&m, gt_thumb_w_rn(in), gt_thumb_w_rm(in),
		  gt_thumb_w_index_shift(in), e->aux, 1);
	fw_load_finish(in, e, o, &m, 0, 0, 0);
}

/* ---- 32-bit: the rest ---------------------------------------------------- */

/* lsl lsr asr ror by register: the S bit is the first halfword's bit 4 */
static void fw_shift_reg(struct gt_thumb_insn in, const struct t_info *e,
			 struct cell_insn *o)
{
	struct cell_operand t;

	t_src_reg(&t, gt_thumb_w_rn(in));
	arm_shift(&t, e->aux, 0, gt_thumb_w_rm(in));
	kof_arm_dp(o, 13u, gt_thumb_w_s(in), 0, gt_thumb_w_rd(in), &t, 0);
}

/* sxth sxtb uxth uxtb: a move that widens, with the rotation of the source */
static void fw_ext(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	uint32_t rot = gt_thumb_w_rot(in);

	kof_arm_other(o, arm_wm(e->wm, t_word(in)));
	o->op = e->cls;
	o->n_op = 2;
	arm_reg(&o->o[0], gt_thumb_w_rd(in), CELL_OF_WRITE);
	arm_reg(&o->o[1], gt_thumb_w_rm(in), CELL_OF_READ);
	o->o[1].size = e->aux;
	if (rot)
		arm_shift(&o->o[1], ARM_SH_ROR, rot, 0xffu);
}

static void fw_mul(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	o->wmask = ARM_R(gt_thumb_w_rd(in));
	o->n_op = 3;
	arm_reg(&o->o[0], gt_thumb_w_rd(in), CELL_OF_WRITE);
	arm_reg(&o->o[1], gt_thumb_w_rn(in), CELL_OF_READ);
	arm_reg(&o->o[2], gt_thumb_w_rm(in), CELL_OF_READ);
}

/* sdiv udiv: spelled as mul is */
static void fw_div(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	fw_mul(in, e, o);
}

/* ldc stc: the base is written back with W */
static void fw_cop_wb(struct gt_thumb_insn in, const struct t_info *e,
		      struct cell_insn *o)
{
	o->op = e->cls;
	if (gt_thumb_w_bit0(in, 5))
		o->wmask = ARM_R(gt_thumb_w_rn(in));
}

/* mrc, vmov to core, vmrs: Rt is written, unless it is pc (apsr_nzcv) */
static void fw_mrc(struct gt_thumb_insn in, const struct t_info *e,
		   struct cell_insn *o)
{
	o->op = e->cls;
	if (gt_thumb_w_rt(in) != ARM_PC)
		o->wmask = ARM_R(gt_thumb_w_rt(in));
}

/* Advanced SIMD element or structure load/store: the base is written back
 * when Rm is not pc */
static void fw_vldst(struct gt_thumb_insn in, const struct t_info *e,
		     struct cell_insn *o)
{
	o->op = e->cls;
	if (gt_thumb_w_rm(in) != 15u)
		o->wmask = ARM_R(gt_thumb_w_rn(in));
}

static const struct t_info g_info[GT_THUMB_I_COUNT] = {
	/* what the architecture leaves unallocated, and what it defines to fault */
	I(INVALID, CELL_UD, f_ud, 0, 0),
	I(UDF, CELL_UD, f_ud, 0, 0),
	I(UDF_W, CELL_UD, f_ud, 0, 0),

	/* ---- 16-bit ---- */
	I(MOVS_REG, 0, fn_shift_imm, 0, 0),
	I(LSL_IMM, 0, fn_shift_imm, 0, 0),
	I(LSR_IMM, 0, fn_shift_imm, 0, 0),
	I(ASR_IMM, 0, fn_shift_imm, 0, 0),
	/* aux: bit 0 subtract, bit 1 a 3-bit immediate rather than a register */
	I(ADDS_REG, 0, fn_addsub, 0, 0),
	I(SUBS_REG, 0, fn_addsub, 1, 0),
	I(ADDS_IMM3, 0, fn_addsub, 2, 0),
	I(SUBS_IMM3, 0, fn_addsub, 3, 0),
	/* aux: the ARM state data-processing opcode */
	I(MOVS_IMM8, 0, fn_imm8, 13, 0),
	I(CMP_IMM8, 0, fn_imm8, 10, 0),
	I(ADDS_IMM8, 0, fn_imm8, 4, 0),
	I(SUBS_IMM8, 0, fn_imm8, 2, 0),
	I(ANDS_REG, 0, fn_dpreg, 0, 0),
	I(EORS_REG, 0, fn_dpreg, 1, 0),
	I(ADCS_REG, 0, fn_dpreg, 5, 0),
	I(SBCS_REG, 0, fn_dpreg, 6, 0),
	I(TST_REG, 0, fn_dpreg, 8, 0),
	I(CMP_REG, 0, fn_dpreg, 10, 0),
	I(CMN_REG, 0, fn_dpreg, 11, 0),
	I(ORRS_REG, 0, fn_dpreg, 12, 0),
	I(BICS_REG, 0, fn_dpreg, 14, 0),
	I(MVNS_REG, 0, fn_dpreg, 15, 0),
	I(LSLS_REG, 0, fn_shift_reg, ARM_SH_LSL, 0),
	I(LSRS_REG, 0, fn_shift_reg, ARM_SH_LSR, 0),
	I(ASRS_REG, 0, fn_shift_reg, ARM_SH_ASR, 0),
	I(RORS_REG, 0, fn_shift_reg, ARM_SH_ROR, 0),
	I(RSBS_IMM0, 0, fn_rsb0, 0, 0),
	I(MULS, CELL_MUL, fn_mul, 0, 0),
	/* aux: the opcode */
	I(ADD_REG_HI, 0, fn_hi, 4, 0),
	I(CMP_REG_HI, 0, fn_hi, 10, 0),
	I(MOV_REG_HI, 0, fn_hi, 13, 0),
	I(BX, CELL_JMP, fn_bx, 0, 0),
	I(BLX_REG, CELL_CALL, fn_bx, 1, 0),
	I(LDR_LIT, CELL_MOV, fn_ldr_lit, 0, 0),
	/* aux: the access width, and L1 when it loads */
	I(STR_REG, CELL_MOV, fn_ls_reg, 4, 0),
	I(STRH_REG, CELL_MOV, fn_ls_reg, 2, 0),
	I(STRB_REG, CELL_MOV, fn_ls_reg, 1, 0),
	I(LDRSB_REG, CELL_MOVSX, fn_ls_reg, 1 | L1, 0),
	I(LDR_REG, CELL_MOV, fn_ls_reg, 4 | L1, 0),
	I(LDRH_REG, CELL_MOVZX, fn_ls_reg, 2 | L1, 0),
	I(LDRB_REG, CELL_MOVZX, fn_ls_reg, 1 | L1, 0),
	I(LDRSH_REG, CELL_MOVSX, fn_ls_reg, 2 | L1, 0),
	I(STR_IMM5, CELL_MOV, fn_ls_imm5, 4, 0),
	I(LDR_IMM5, CELL_MOV, fn_ls_imm5, 4 | L1, 0),
	I(STRB_IMM5, CELL_MOV, fn_ls_imm5, 1, 0),
	I(LDRB_IMM5, CELL_MOVZX, fn_ls_imm5, 1 | L1, 0),
	I(STRH_IMM5, CELL_MOV, fn_ls_half, 2, 0),
	I(LDRH_IMM5, CELL_MOVZX, fn_ls_half, 2 | L1, 0),
	I(STR_SP, CELL_MOV, fn_ls_sp, 4, 0),
	I(LDR_SP, CELL_MOV, fn_ls_sp, 4 | L1, 0),
	I(ADR, 0, fn_adr, 0, 0),
	I(ADD_SP_IMM8, 0, fn_adr, 1, 0),
	I(ADD_SP_IMM7, 0, fn_sp_adjust, 4, 0),
	I(SUB_SP_IMM7, 0, fn_sp_adjust, 2, 0),
	/* aux: the condition cbz branches on */
	I(CBZ, CELL_JCC, fn_cbz, 0, 0),
	I(CBNZ, CELL_JCC, fn_cbz, 1, 0),
	/* aux: the width of the source */
	I(SXTH, CELL_MOVSX, fn_ext, 2, 0),
	I(SXTB, CELL_MOVSX, fn_ext, 1, 0),
	I(UXTH, CELL_MOVZX, fn_ext, 2, 0),
	I(UXTB, CELL_MOVZX, fn_ext, 1, 0),
	I(PUSH, CELL_PUSH, fn_push, 0, 0),
	I(POP, CELL_POP, fn_pop, 0, 0),
	I(CPS, CELL_PRIV, f_priv, 0, 0),
	I(SETEND, CELL_PRIV, f_priv, 0, 0),
	I(REV, CELL_OTHER, fn_rev, 0, 0),
	I(REV16, CELL_OTHER, fn_rev, 0, 0),
	I(REVSH, CELL_OTHER, fn_rev, 0, 0),
	I(BKPT, CELL_INT, fn_bkpt, 0, 0),
	I(HINT, CELL_NOP, f_nop, 0, 0),
	I(IT, CELL_OTHER, fn_it, 0, 0),
	I(STM, CELL_OTHER, fn_ldm, 0, 0),
	I(LDM, CELL_OTHER, fn_ldm, 1, 0),
	I(BCOND, CELL_JCC, fn_bcond, 0, 0),
	I(SVC, CELL_SYSCALL, fn_svc, 0, 0),
	I(B, CELL_JMP, fn_b, 0, 0),

	/* ---- 32-bit: data processing; aux is the ARM state opcode (16 is orn) ---- */
	I(AND_IMM_W, 0, fw_dp_imm, 0, 0), I(BIC_IMM_W, 0, fw_dp_imm, 14, 0),
	I(ORR_IMM_W, 0, fw_dp_imm, 12, 0), I(MOV_IMM_W, 0, fw_dp_imm, 13, 0),
	I(ORN_IMM_W, 0, fw_dp_imm, 16, 0), I(MVN_IMM_W, 0, fw_dp_imm, 15, 0),
	I(EOR_IMM_W, 0, fw_dp_imm, 1, 0), I(ADD_IMM_W, 0, fw_dp_imm, 4, 0),
	I(ADC_IMM_W, 0, fw_dp_imm, 5, 0), I(SBC_IMM_W, 0, fw_dp_imm, 6, 0),
	I(SUB_IMM_W, 0, fw_dp_imm, 2, 0), I(RSB_IMM_W, 0, fw_dp_imm, 3, 0),
	I(TST_IMM_W, 0, fw_dp_imm, 8, 0), I(TEQ_IMM_W, 0, fw_dp_imm, 9, 0),
	I(CMN_IMM_W, 0, fw_dp_imm, 11, 0), I(CMP_IMM_W, 0, fw_dp_imm, 10, 0),
	I(AND_REG_W, 0, fw_dp_reg, 0, 0), I(BIC_REG_W, 0, fw_dp_reg, 14, 0),
	I(ORR_REG_W, 0, fw_dp_reg, 12, 0), I(MOV_REG_W, 0, fw_dp_reg, 13, 0),
	I(ORN_REG_W, 0, fw_dp_reg, 16, 0), I(MVN_REG_W, 0, fw_dp_reg, 15, 0),
	I(EOR_REG_W, 0, fw_dp_reg, 1, 0), I(ADD_REG_W, 0, fw_dp_reg, 4, 0),
	I(ADC_REG_W, 0, fw_dp_reg, 5, 0), I(SBC_REG_W, 0, fw_dp_reg, 6, 0),
	I(SUB_REG_W, 0, fw_dp_reg, 2, 0), I(RSB_REG_W, 0, fw_dp_reg, 3, 0),
	I(TST_REG_W, 0, fw_dp_reg, 8, 0), I(TEQ_REG_W, 0, fw_dp_reg, 9, 0),
	I(CMN_REG_W, 0, fw_dp_reg, 11, 0), I(CMP_REG_W, 0, fw_dp_reg, 10, 0),
	I(LSL_REG_W, 0, fw_shift_reg, ARM_SH_LSL, 0),
	I(LSR_REG_W, 0, fw_shift_reg, ARM_SH_LSR, 0),
	I(ASR_REG_W, 0, fw_shift_reg, ARM_SH_ASR, 0),
	I(ROR_REG_W, 0, fw_shift_reg, ARM_SH_ROR, 0),
	I(PKHBT, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(PKHTB, CELL_OTHER, f_other, 0, ARM_WM_F8),
	/* aux: the opcode, 2 for the subtracting forms */
	I(ADDW, 0, fw_plain, 4, 0), I(ADR_ADD, 0, fw_plain, 4, 0),
	I(SUBW, 0, fw_plain, 2, 0), I(ADR_SUB, 0, fw_plain, 2, 0),
	I(MOVW, CELL_MOV, fw_movw, 0, 0),
	I(MOVT, CELL_OR, fw_movt, 0, 0),
	I(SSAT, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SSAT16, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SBFX, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(BFC, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(BFI, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(USAT, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(USAT16, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(UBFX, CELL_OTHER, f_other, 0, ARM_WM_F8),

	/* extend, parallel arithmetic, miscellaneous operations: they write Rd */
	I(SXTAH, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(UXTAH, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SXTB16, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SXTAB16, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(UXTB16, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(UXTAB16, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SXTAB, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(UXTAB, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SXTH_W, CELL_MOVSX, fw_ext, 2, ARM_WM_F8),
	I(UXTH_W, CELL_MOVZX, fw_ext, 2, ARM_WM_F8),
	I(SXTB_W, CELL_MOVSX, fw_ext, 1, ARM_WM_F8),
	I(UXTB_W, CELL_MOVZX, fw_ext, 1, ARM_WM_F8),
	I(PAS_S, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(PAS_Q, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(PAS_SH, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(PAS_U, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(PAS_UQ, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(PAS_UH, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(QADD, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(QDADD, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(QSUB, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(QDSUB, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(REV_W, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(REV16_W, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(RBIT, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(REVSH_W, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SEL, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(CLZ, CELL_OTHER, f_other, 0, ARM_WM_F8),

	/* multiplies and divide */
	I(MUL_W, CELL_MUL, fw_mul, 0, ARM_WM_F8),
	I(MLA, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(MLS, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMULXY, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMLAXY, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMUAD, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMLAD, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMULWY, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMLAWY, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMUSD, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMLSD, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMMUL, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMMLA, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SMMLS, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(USAD8, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(USADA8, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(SDIV, CELL_IDIV, fw_div, 0, ARM_WM_F8),
	I(UDIV, CELL_DIV, fw_div, 0, ARM_WM_F8),
	I(SMULL, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(UMULL, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(SMLAL, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(SMLALXY, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(SMLALD, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(SMLSLD, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(UMLAL, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),
	I(UMAAL, CELL_OTHER, f_other, 0, ARM_WM_F8 | ARM_WM_F12),

	/* exclusive, acquire/release, table branch, doubleword */
	I(STREX, CELL_OTHER, f_other, 0, ARM_WM_F8),
	I(LDREX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDA, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEXB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEXH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEX, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDAEXD, CELL_OTHER, f_other, 0, ARM_WM_F12 | ARM_WM_F8),
	I(STLB, CELL_OTHER, f_other, 0, 0),
	I(STLH, CELL_OTHER, f_other, 0, 0),
	I(STL, CELL_OTHER, f_other, 0, 0),
	I(STLEXB, CELL_OTHER, f_other, 0, ARM_WM_F0),
	I(STLEXH, CELL_OTHER, f_other, 0, ARM_WM_F0),
	I(STLEX, CELL_OTHER, f_other, 0, ARM_WM_F0),
	I(STLEXD, CELL_OTHER, f_other, 0, ARM_WM_F0),
	I(LDREXB, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDREXH, CELL_OTHER, f_other, 0, ARM_WM_F12),
	I(LDREXD, CELL_OTHER, f_other, 0, ARM_WM_F12 | ARM_WM_F8),
	I(STREXB, CELL_OTHER, f_other, 0, ARM_WM_F0),
	I(STREXH, CELL_OTHER, f_other, 0, ARM_WM_F0),
	I(STREXD, CELL_OTHER, f_other, 0, ARM_WM_F0),
	/* aux: the width of a table entry */
	I(TBB, CELL_JMP, fw_tb, 1, 0),
	I(TBH, CELL_JMP, fw_tb, 2, 0),
	I(STRD_IMM, CELL_MOV, fw_ldrd, 0, 0),
	I(LDRD_IMM, CELL_MOV, fw_ldrd, 1, 0),

	/* load and store multiple */
	I(SRS, CELL_PRIV, f_priv, 0, 0),
	I(RFE, CELL_PRIV, fw_rfe, 0, 0),
	I(POP_W, CELL_POP, fw_pop, 0, 0),
	I(PUSH_W, CELL_PUSH, fw_push, 0, 0),
	I(STM_W, CELL_OTHER, fw_ldm, 0, 0),
	I(LDM_W, CELL_OTHER, fw_ldm, 1, 0),
	I(STMDB_W, CELL_OTHER, fw_ldm, 0, 0),
	I(LDMDB_W, CELL_OTHER, fw_ldm, 1, 0),
	I(PUSH_REG_W, CELL_PUSH, fw_push1, 0, 0),
	I(POP_REG_W, CELL_POP, fw_pop1, 0, 0),

	/* branches and miscellaneous control */
	I(MSR, CELL_PRIV, f_priv, 0, 0),
	I(HINT_W, CELL_NOP, f_nop, 0, 0),
	I(CPS_W, CELL_PRIV, f_priv, 0, 0),
	I(CLREX, CELL_OTHER, f_other, 0, 0),
	I(DSB, CELL_OTHER, f_other, 0, 0),
	I(DMB, CELL_OTHER, f_other, 0, 0),
	I(ISB, CELL_OTHER, f_other, 0, 0),
	I(BXJ, CELL_JMP, fw_bxj, 0, 0),
	I(SUBS_PC_LR, CELL_PRIV, f_priv, 0, ARM_WM_PC),
	I(MRS, CELL_PRIV, f_priv, 0, ARM_WM_F8),
	I(HVC, CELL_PRIV, f_priv, 0, 0),
	I(SMC, CELL_PRIV, f_priv, 0, 0),
	I(BCOND_W, CELL_JCC, fw_bcond, 0, 0),
	I(B_W, CELL_JMP, fw_b, 0, 0),
	I(BL, CELL_CALL, fw_bl, 0, 0),
	I(BLX_IMM, CELL_CALL, fw_blx, 0, 0),

	/* single loads and stores; aux is the width, and L1 when it loads */
	I(STRB_IMM12_W, CELL_MOV, fw_st_imm12, 1, 0),
	I(STRH_IMM12_W, CELL_MOV, fw_st_imm12, 2, 0),
	I(STR_IMM12_W, CELL_MOV, fw_st_imm12, 4, 0),
	I(STRB_IMM8_W, CELL_MOV, fw_st_imm8, 1, 0),
	I(STRH_IMM8_W, CELL_MOV, fw_st_imm8, 2, 0),
	I(STR_IMM8_W, CELL_MOV, fw_st_imm8, 4, 0),
	I(STRB_REG_W, CELL_MOV, fw_st_reg, 1, 0),
	I(STRH_REG_W, CELL_MOV, fw_st_reg, 2, 0),
	I(STR_REG_W, CELL_MOV, fw_st_reg, 4, 0),
	I(LDRB_LIT_W, CELL_MOVZX, fw_ld_lit, 1, 0),
	I(LDRB_IMM12_W, CELL_MOVZX, fw_ld_imm12, 1, 0),
	I(LDRB_IMM8_W, CELL_MOVZX, fw_ld_imm8, 1, 0),
	I(LDRB_REG_W, CELL_MOVZX, fw_ld_reg, 1, 0),
	I(LDRSB_LIT_W, CELL_MOVSX, fw_ld_lit, 1, 0),
	I(LDRSB_IMM12_W, CELL_MOVSX, fw_ld_imm12, 1, 0),
	I(LDRSB_IMM8_W, CELL_MOVSX, fw_ld_imm8, 1, 0),
	I(LDRSB_REG_W, CELL_MOVSX, fw_ld_reg, 1, 0),
	I(LDRH_LIT_W, CELL_MOVZX, fw_ld_lit, 2, 0),
	I(LDRH_IMM12_W, CELL_MOVZX, fw_ld_imm12, 2, 0),
	I(LDRH_IMM8_W, CELL_MOVZX, fw_ld_imm8, 2, 0),
	I(LDRH_REG_W, CELL_MOVZX, fw_ld_reg, 2, 0),
	I(LDRSH_LIT_W, CELL_MOVSX, fw_ld_lit, 2, 0),
	I(LDRSH_IMM12_W, CELL_MOVSX, fw_ld_imm12, 2, 0),
	I(LDRSH_IMM8_W, CELL_MOVSX, fw_ld_imm8, 2, 0),
	I(LDRSH_REG_W, CELL_MOVSX, fw_ld_reg, 2, 0),
	I(LDR_LIT_W, CELL_MOV, fw_ld_lit, 4, 0),
	I(LDR_IMM12_W, CELL_MOV, fw_ld_imm12, 4, 0),
	I(LDR_IMM8_W, CELL_MOV, fw_ld_imm8, 4, 0),
	I(LDR_REG_W, CELL_MOV, fw_ld_reg, 4, 0),

	/* coprocessor, VFP, Advanced SIMD: not validity-checked */
	I(VDOT, CELL_OTHER, f_other, 0, 0),
	I(MCRR, CELL_OTHER, f_other, 0, 0),
	I(MRRC, CELL_OTHER, f_other, 0, ARM_WM_F12 | ARM_WM_F16),
	I(STC, CELL_OTHER, fw_cop_wb, 0, 0),
	I(LDC, CELL_OTHER, fw_cop_wb, 0, 0),
	I(CDP, CELL_OTHER, f_other, 0, 0),
	I(MCR, CELL_OTHER, f_other, 0, 0),
	I(MRC, CELL_OTHER, fw_mrc, 0, 0),
	I(ASIMD_DP, CELL_OTHER, f_other, 0, 0),
	I(VLDST, CELL_OTHER, fw_vldst, 0, 0),
};



/* ---- entry --------------------------------------------------------------- */

uint32_t cell_decode_thumb(const uint8_t *p, uint32_t n, uint64_t va,
			   int be, struct cell_insn *out)
{
	struct gt_thumb_insn in;
	const struct t_info *e;
	uint32_t h1, len;

	if (!p || n < 2u || !out)
		return 0;
	h1 = arm_h(p, be);
	len = gt_thumb_len(h1);
	if (len == 4u) {
		if (n < 4u)
			return 0;
		(void)gt_thumb_decode_wide(&in, h1, arm_h(p + 2, be));
	} else {
		(void)gt_thumb_decode_narrow(&in, h1);
	}
	arm_begin(out, va, len);
	e = &g_info[in.id];
	e->fn(in, e, out);
	return len;
}
