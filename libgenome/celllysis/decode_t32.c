/*
 * t32.c - Thumb and Thumb-2 into the engine's one instruction form.
 *
 * The length is decided by the first halfword alone: 0b11101, 0b11110 and
 * 0b11111 in its top five bits open a 32-bit instruction, everything else is
 * 16 bits. A decoder that needed the second halfword to know how long the
 * first one was could not step through a buffer that ends in the middle of
 * one, and this returns 0 only for that - a 32-bit instruction with two bytes
 * left - and for no other reason.
 *
 * DISPATCH BY TABLE ON THE BIT FIELD, as a32.c and decode_mips.c do: the top
 * six bits select a 16-bit handler, the top five a group of 32-bit ones, and
 * inside a group the opcode fields index small tables. Operand conventions
 * are in decode_arm.h; the data-processing family is arm_common.c's, shared with
 * a32.c, so what `adds r0, r0, #4` MEANS is decided in one place.
 *
 * WHAT IS NOT TRACKED, and a consumer has to know: `it`. It is decoded as
 * CELL_OTHER, length 2, and the instructions it governs report cond 0xE. The
 * decoder is stateless; an engine that wants the condition of an instruction
 * inside the block carries the IT state itself. The oracle in
 * tools/celllysis/arm_diff.c does carry it, which is why that tool compares
 * `cond` only on branches.
 *
 * The same validity policy as a32.c: the integer space is checked and what
 * the architecture leaves unallocated is CELL_UD with the right length; the
 * coprocessor, VFP and Advanced SIMD space is not, and is CELL_OTHER.
 */
#include "decode_arm.h"

typedef void (*t16_fn)(uint32_t h, struct cell_insn *o);
typedef void (*t32_fn)(uint32_t h1, uint32_t h2, struct cell_insn *o);

/* ---- helpers ------------------------------------------------------------ */

/* Where a pc-relative literal is measured from, relative to this instruction. */
static int64_t t_pcb(const struct cell_insn *o)
{
	return (int64_t)(((o->at_va + 4u) & ~(uint64_t)3) - o->at_va);
}

static void t_src_reg(struct cell_operand *t, uint32_t rm)
{
	memset(t, 0, sizeof *t);
	t->reg = t->index = t->seg = CELL_REG_NONE;
	arm_reg(t, rm, CELL_OF_READ);
}

static void t_src_imm(struct cell_operand *t, uint64_t v)
{
	memset(t, 0, sizeof *t);
	t->reg = t->index = t->seg = CELL_REG_NONE;
	arm_imm(t, v);
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

static uint64_t t_wr(uint32_t v, unsigned shift)
{
	return ARM_R((v >> shift) & 15u);
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
 * operands in the form a32.c uses and adds what the access writes.
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

/* ---- the 16-bit instructions -------------------------------------------- */

/* lsl lsr asr by an immediate: 00 op imm5 rm rd */
static void s_shift_imm(uint32_t h, struct cell_insn *o)
{
	struct cell_operand t;
	uint32_t type = (h >> 11) & 3u;

	t_src_shift(&t, (h >> 3) & 7u, type, (h >> 6) & 31u);
	kof_arm_dp(o, 13u, 1u, 0, h & 7u, &t, 0);
}

/* add sub, register or 3-bit immediate: 00011 i op rm/imm3 rn rd */
static void s_addsub(uint32_t h, struct cell_insn *o)
{
	struct cell_operand t;

	if (h & 0x0400u)
		t_src_imm(&t, (h >> 6) & 7u);
	else
		t_src_reg(&t, (h >> 6) & 7u);
	kof_arm_dp(o, (h & 0x0200u) ? 2u : 4u, 1u, (h >> 3) & 7u, h & 7u, &t, 0);
}

/* mov cmp add sub with an 8-bit immediate: 001 op rd imm8 */
static void s_imm8(uint32_t h, struct cell_insn *o)
{
	static const uint8_t opc[4] = { 13u, 10u, 4u, 2u };
	struct cell_operand t;
	uint32_t rd = (h >> 8) & 7u;

	t_src_imm(&t, h & 255u);
	kof_arm_dp(o, opc[(h >> 11) & 3u], 1u, rd, rd, &t, 0);
}

/* the data-processing register group: 010000 op rm rdn */
static void s_dpreg(uint32_t h, struct cell_insn *o)
{
	uint32_t op = (h >> 6) & 15u, rm = (h >> 3) & 7u, rd = h & 7u;
	struct cell_operand t;

	switch (op) {
	case 2: case 3: case 4: case 7: {       /* lsl lsr asr ror by register */
		static const uint8_t kind[8] = { 0, 0, ARM_SH_LSL, ARM_SH_LSR,
						 ARM_SH_ASR, 0, 0, ARM_SH_ROR };

		t_src_reg(&t, rd);
		arm_shift(&t, kind[op], 0, rm);
		kof_arm_dp(o, 13u, 1u, 0, rd, &t, 0);
		return;
	}
	case 9:                                 /* rsbs rd, rm, #0 : negs */
		t_src_imm(&t, 0);
		kof_arm_dp(o, 3u, 1u, rm, rd, &t, 0);
		return;
	case 13:                                /* muls rd, rm, rd */
		o->op = CELL_MUL;
		o->wmask = ARM_R(rd);
		o->n_op = 3;
		arm_reg(&o->o[0], rd, CELL_OF_WRITE);
		arm_reg(&o->o[1], rm, CELL_OF_READ);
		arm_reg(&o->o[2], rd, CELL_OF_READ);
		return;
	default: {
		/* and eor . . adc sbc . . tst . cmp cmn orr . bic mvn */
		static const uint8_t opc[16] = { 0, 1, 0, 0, 0, 5, 6, 0,
						 8, 0, 10, 11, 12, 0, 14, 15 };

		t_src_reg(&t, rm);
		kof_arm_dp(o, opc[op], 1u, rd, rd, &t, 0);
		return;
	}
	}
}

/* add cmp mov on any registers, and bx blx: 010001 op ... */
static void s_hireg(uint32_t h, struct cell_insn *o)
{
	uint32_t op = (h >> 8) & 3u, rm = (h >> 3) & 15u;
	uint32_t rd = (h & 7u) | ((h >> 4) & 8u);
	struct cell_operand t;

	t_src_reg(&t, rm);
	switch (op) {
	case 0:
		kof_arm_dp(o, 4u, 0, rd, rd, &t, 0);
		return;
	case 1:
		kof_arm_dp(o, 10u, 1u, rd, rd, &t, 0);
		return;
	case 2:
		kof_arm_dp(o, 13u, 0, 0, rd, &t, 0);
		if (rd == rm && rd != ARM_PC)
			o->op = CELL_NOP;       /* mov r8, r8 is the Thumb-1 nop */
		return;
	default:                                /* bx, blx */
		kof_arm_clr(o);
		o->flags |= CELL_F_INDIRECT;
		o->wmask = ARM_R(ARM_PC);
		o->n_op = 1;
		arm_reg(&o->o[0], rm, CELL_OF_READ);
		if (h & 0x80u) {
			o->op = CELL_CALL;
			o->wmask |= ARM_R(ARM_LR);
		} else {
			o->op = rm == ARM_LR ? CELL_RET : CELL_JMP;
		}
		return;
	}
}

/* ldr rt, [pc, #imm8 * 4] */
static void s_ldr_lit(uint32_t h, struct cell_insn *o)
{
	struct cell_operand m;

	t_mem_imm(o, &m, ARM_PC, (int64_t)(h & 255u) * 4, 4u, 1);
	t_ls(o, 1, CELL_MOV, (h >> 8) & 7u, &m);
}

/* str strh strb ldrsb ldr ldrh ldrb ldrsh with a register offset */
static void s_ls_reg(uint32_t h, struct cell_insn *o)
{
	static const uint8_t cls[8] = { CELL_MOV, CELL_MOV, CELL_MOV,
					CELL_MOVSX, CELL_MOV, CELL_MOVZX,
					CELL_MOVZX, CELL_MOVSX };
	static const uint8_t sz[8] = { 4, 2, 1, 1, 4, 2, 1, 2 };
	uint32_t op = (h >> 9) & 7u;
	struct cell_operand m;

	t_mem_reg(&m, (h >> 3) & 7u, (h >> 6) & 7u, 0, sz[op], op >= 3u);
	t_ls(o, op >= 3u, cls[op], h & 7u, &m);
}

/* str ldr strb ldrb with a 5-bit offset: 011 b l imm5 rn rt */
static void s_ls_imm(uint32_t h, struct cell_insn *o)
{
	uint32_t b = (h >> 12) & 1u, l = (h >> 11) & 1u;
	uint32_t off = ((h >> 6) & 31u) << (b ? 0 : 2);
	struct cell_operand m;

	t_mem_imm(o, &m, (h >> 3) & 7u, (int64_t)off, b ? 1u : 4u, (int)l);
	t_ls(o, (int)l, (l && b) ? CELL_MOVZX : CELL_MOV, h & 7u, &m);
}

/* strh ldrh with a 5-bit halfword offset */
static void s_ls_half(uint32_t h, struct cell_insn *o)
{
	uint32_t l = (h >> 11) & 1u;
	struct cell_operand m;

	t_mem_imm(o, &m, (h >> 3) & 7u, (int64_t)(((h >> 6) & 31u) << 1), 2u,
		  (int)l);
	t_ls(o, (int)l, l ? CELL_MOVZX : CELL_MOV, h & 7u, &m);
}

/* str ldr rt, [sp, #imm8 * 4] */
static void s_ls_sp(uint32_t h, struct cell_insn *o)
{
	uint32_t l = (h >> 11) & 1u;
	struct cell_operand m;

	t_mem_imm(o, &m, ARM_SP, (int64_t)(h & 255u) * 4, 4u, (int)l);
	t_ls(o, (int)l, CELL_MOV, (h >> 8) & 7u, &m);
}

/* adr rd, label ; add rd, sp, #imm8 * 4 */
static void s_addr(uint32_t h, struct cell_insn *o)
{
	struct cell_operand t;

	t_src_imm(&t, (uint64_t)(h & 255u) * 4);
	kof_arm_dp(o, 4u, 0, (h & 0x0800u) ? ARM_SP : ARM_PC, (h >> 8) & 7u, &t,
		   t_pcb(o));
}

/* the miscellaneous group: 1011 */
static void s_misc(uint32_t h, struct cell_insn *o)
{
	uint32_t op = (h >> 8) & 15u;

	if (op == 0u) {                         /* add sp, #imm7*4 ; sub */
		struct cell_operand t;

		t_src_imm(&t, (uint64_t)(h & 127u) * 4);
		kof_arm_dp(o, (h & 0x80u) ? 2u : 4u, 0, ARM_SP, ARM_SP, &t, 0);
		return;
	}
	if ((h & 0x0500u) == 0x0100u) {         /* cbz cbnz */
		uint64_t t = o->at_va + 4u +
			     (((h >> 3) & 0x40u) | ((h >> 2) & 0x3eu));

		o->op = CELL_JCC;
		o->cond = (h & 0x0800u) ? 1u : 0u;      /* ne : eq */
		t_branch_to(o, t);
		o->n_op = 2;
		arm_reg(&o->o[1], h & 7u, CELL_OF_READ);
		return;
	}
	switch (op) {
	case 2: {                               /* sxth sxtb uxth uxtb */
		struct cell_operand t;
		uint32_t k = (h >> 6) & 3u;

		if (k > 3u) {
			kof_arm_ud(o);
			return;
		}
		o->op = (k & 2u) ? CELL_MOVZX : CELL_MOVSX;
		o->n_op = 2;
		o->wmask = ARM_R(h & 7u);
		arm_reg(&o->o[0], h & 7u, CELL_OF_WRITE);
		t_src_reg(&t, (h >> 3) & 7u);
		o->o[1] = t;
		o->o[1].size = (k & 1u) ? 1u : 2u;
		return;
	}
	case 4: case 5:                         /* push {list, lr} */
		arm_pushpop(o, 0, (h & 255u) | ((h & 0x100u) ? ARM_R(ARM_LR) : 0));
		return;
	case 12: case 13:                       /* pop {list, pc} */
		arm_pushpop(o, 1, (h & 255u) | ((h & 0x100u) ? ARM_R(ARM_PC) : 0));
		return;
	case 6:
		if ((h & 0xffe0u) == 0xb660u || (h & 0xfff0u) == 0xb650u)
			o->op = CELL_PRIV;      /* cps, setend */
		else
			kof_arm_ud(o);
		return;
	case 10: {                              /* rev rev16 revsh */
		uint32_t k = (h >> 6) & 3u;

		if (k == 2u) {
			kof_arm_ud(o);
			return;
		}
		kof_arm_other(o, ARM_R(h & 7u));
		return;
	}
	case 14:                                /* bkpt */
		o->op = CELL_INT;
		o->n_op = 1;
		arm_imm(&o->o[0], h & 255u);
		return;
	case 15:                                /* hints, and it */
		if (h & 15u) {
			kof_arm_other(o, 0);    /* it: see the note at the top */
		} else {
			o->op = CELL_NOP;
		}
		return;
	default:
		kof_arm_ud(o);
		return;
	}
}

/* stmia ldmia rn!, {list}: 1100 l rn list */
static void s_ldm(uint32_t h, struct cell_insn *o)
{
	uint32_t l = (h >> 11) & 1u, rn = (h >> 8) & 7u, list = h & 255u;

	o->op = CELL_OTHER;
	if (l) {
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

/* b<cond>, udf, svc: 1101 cond imm8 */
static void s_bcond(uint32_t h, struct cell_insn *o)
{
	uint32_t c = (h >> 8) & 15u;

	if (c == 14u) {
		kof_arm_ud(o);
		return;
	}
	if (c == 15u) {
		o->op = CELL_SYSCALL;
		o->n_op = 1;
		arm_imm(&o->o[0], h & 255u);
		return;
	}
	o->op = CELL_JCC;
	o->cond = (uint8_t)c;
	t_branch_to(o, o->at_va + 4u + (uint64_t)(arm_sext(h, 8) * 2));
}

/* b: 11100 imm11 */
static void s_b(uint32_t h, struct cell_insn *o)
{
	o->op = CELL_JMP;
	t_branch_to(o, o->at_va + 4u + (uint64_t)(arm_sext(h, 11) * 2));
}

/*
 * Indexed by the top six bits of the halfword. The last six entries (the
 * 32-bit prefixes) are never reached through this table.
 */
static const t16_fn g_t16[64] = {
	s_shift_imm, s_shift_imm, s_shift_imm, s_shift_imm,     /* 00 000-001 lsl lsr */
	s_shift_imm, s_shift_imm, s_addsub, s_addsub,           /* asr, add/sub */
	s_imm8, s_imm8, s_imm8, s_imm8,
	s_imm8, s_imm8, s_imm8, s_imm8,
	s_dpreg, s_hireg, s_ldr_lit, s_ldr_lit,
	s_ls_reg, s_ls_reg, s_ls_reg, s_ls_reg,
	s_ls_imm, s_ls_imm, s_ls_imm, s_ls_imm,
	s_ls_imm, s_ls_imm, s_ls_imm, s_ls_imm,
	s_ls_half, s_ls_half, s_ls_half, s_ls_half,
	s_ls_sp, s_ls_sp, s_ls_sp, s_ls_sp,
	s_addr, s_addr, s_addr, s_addr,
	s_misc, s_misc, s_misc, s_misc,
	s_ldm, s_ldm, s_ldm, s_ldm,
	s_bcond, s_bcond, s_bcond, s_bcond,
	s_b, s_b, NULL, NULL,
	NULL, NULL, NULL, NULL,
};

/* ---- 32-bit: the modified immediate ------------------------------------- */

static uint32_t t_expand_imm(uint32_t imm12)
{
	uint32_t b = imm12 & 255u;

	if (!(imm12 & 0xc00u)) {
		switch ((imm12 >> 8) & 3u) {
		case 0:
			return b;
		case 1:
			return b << 16 | b;
		case 2:
			return b << 24 | b << 8;
		default:
			return b * 0x01010101u;
		}
	}
	return arm_ror32(0x80u | (b & 0x7fu), (imm12 >> 7) & 31u);
}

/*
 * The four-bit data-processing opcode of the two Thumb-2 forms, as A32's
 * numbering. 0xff = not allocated. The compare forms are the same opcode with
 * Rd = 1111 and S = 1, and mov/mvn the same with Rn = 1111; both are folded
 * here so kof_arm_dp sees the instruction the program wrote.
 */
static const uint8_t g_t2dp[16] = {
	0, 14, 12, 16, 1, 0xff, 0xff, 0xff,     /* and bic orr orn eor . pkh . */
	4, 0xff, 5, 6, 0xff, 2, 3, 0xff,        /* add . adc sbc . sub rsb . */
};

static void t_dp_common(struct cell_insn *o, uint32_t op, uint32_t s,
			uint32_t rn, uint32_t rd, const struct cell_operand *t)
{
	unsigned opc = g_t2dp[op];

	if (opc == 0xffu) {
		kof_arm_ud(o);
		return;
	}
	if (rd == ARM_PC && s) {
		if (op == 0u)
			opc = 8u;               /* tst */
		else if (op == 4u)
			opc = 9u;               /* teq */
		else if (op == 8u)
			opc = 11u;              /* cmn */
		else if (op == 13u)
			opc = 10u;              /* cmp */
	}
	if (rn == ARM_PC) {
		if (op == 2u)
			opc = 13u;              /* mov */
		else if (op == 3u)
			opc = 15u;              /* mvn */
	}
	kof_arm_dp(o, opc, s, rn, rd, t, 0);
}

static void t_dp_modimm(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	struct cell_operand t;
	uint32_t imm12 = ((h1 >> 10) & 1u) << 11 | ((h2 >> 12) & 7u) << 8 | (h2 & 255u);

	t_src_imm(&t, t_expand_imm(imm12));
	t_dp_common(o, (h1 >> 5) & 15u, (h1 >> 4) & 1u, h1 & 15u,
		    (h2 >> 8) & 15u, &t);
}

static void t_dp_plain(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t op = (h1 >> 4) & 31u, rn = h1 & 15u, rd = (h2 >> 8) & 15u;
	uint32_t imm12 = ((h1 >> 10) & 1u) << 11 | ((h2 >> 12) & 7u) << 8 | (h2 & 255u);
	struct cell_operand t;

	switch (op) {
	case 0: case 10:                        /* addw subw, adr */
		t_src_imm(&t, imm12);
		kof_arm_dp(o, op ? 2u : 4u, 0, rn, rd, &t, t_pcb(o));
		return;
	case 4: case 12: {                      /* movw movt */
		uint32_t v = (rn << 12) | imm12;

		o->n_op = 2;
		o->wmask = ARM_R(rd);
		arm_reg(&o->o[0], rd, CELL_OF_WRITE);
		if (op == 4u) {
			o->op = CELL_MOV;
			arm_imm(&o->o[1], v);
		} else {
			o->op = CELL_OR;
			arm_imm(&o->o[1], (uint64_t)v << 16);
		}
		return;
	}
	case 16: case 18: case 20: case 22: case 24: case 26: case 28:
		/* ssat sbfx bfi usat ubfx. Bit 26 (i) is SBZ in them. */
		kof_arm_other(o, ARM_R(rd));
		return;
	default:
		kof_arm_ud(o);
		return;
	}
}

static void t_dp_shift(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	struct cell_operand t;
	uint32_t op = (h1 >> 5) & 15u, rd = (h2 >> 8) & 15u;

	/* bit 15 of the second halfword is SBZ: a set bit is UNPREDICTABLE */
	if (op == 6u) {                         /* pkhbt pkhtb */
		kof_arm_other(o, ARM_R(rd));
		return;
	}
	t_src_shift(&t, h2 & 15u, (h2 >> 4) & 3u,
		    ((h2 >> 12) & 7u) << 2 | ((h2 >> 6) & 3u));
	t_dp_common(o, op, (h1 >> 4) & 1u, h1 & 15u, rd, &t);
}

/* ---- 32-bit: branches and miscellaneous control ------------------------- */

static void t_misc_ctl(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t op = (h1 >> 4) & 0x7fu;

	switch (op) {
	case 0x38: case 0x39:                   /* msr */
		o->op = CELL_PRIV;
		return;
	case 0x3a:
		if ((h2 >> 8) & 7u)
			o->op = CELL_PRIV;      /* cps */
		else
			o->op = CELL_NOP;       /* nop yield wfe wfi sev dbg */
		return;
	case 0x3b: {                            /* clrex dsb dmb isb */
		uint32_t k = (h2 >> 4) & 15u;

		if (k == 2u || k == 4u || k == 5u || k == 6u)
			kof_arm_other(o, 0);
		else
			kof_arm_ud(o);
		return;
	}
	case 0x3c:                              /* bxj */
		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		o->wmask = ARM_R(ARM_PC);
		o->n_op = 1;
		arm_reg(&o->o[0], h1 & 15u, CELL_OF_READ);
		return;
	case 0x3d:                              /* subs pc, lr, #imm ; eret */
		o->op = CELL_PRIV;
		o->wmask = ARM_R(ARM_PC);
		return;
	case 0x3e: case 0x3f:                   /* mrs */
		o->op = CELL_PRIV;
		o->wmask = t_wr(h2, 8);
		return;
	case 0x7e:                              /* hvc */
		o->op = (h2 >> 12) == 8u ? CELL_PRIV : CELL_UD;
		if (o->op == CELL_UD)
			kof_arm_ud(o);
		return;
	case 0x7f:                              /* smc ; udf.w */
		if ((h2 >> 12) == 8u)
			o->op = CELL_PRIV;
		else
			kof_arm_ud(o);
		return;
	default:
		kof_arm_ud(o);
		return;
	}
}

static void t_branch(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t s = (h1 >> 10) & 1u, j1 = (h2 >> 13) & 1u, j2 = (h2 >> 11) & 1u;
	uint32_t i1 = !(j1 ^ s), i2 = !(j2 ^ s);
	uint32_t b14 = (h2 >> 14) & 1u, b12 = (h2 >> 12) & 1u;
	uint32_t imm;

	if (!(h2 & 0x8000u)) {
		kof_arm_ud(o);                  /* not the branch group at all */
		return;
	}
	if (!b14 && !b12) {
		if (((h1 >> 7) & 7u) == 7u) {
			t_misc_ctl(h1, h2, o);
			return;
		}
		/* b<cond>.w */
		imm = s << 20 | j2 << 19 | j1 << 18 | (h1 & 0x3fu) << 12 |
		      (h2 & 0x7ffu) << 1;
		o->op = CELL_JCC;
		o->cond = (uint8_t)((h1 >> 6) & 15u);
		t_branch_to(o, o->at_va + 4u + (uint64_t)arm_sext(imm, 21));
		return;
	}
	imm = s << 24 | i1 << 23 | i2 << 22 | (h1 & 0x3ffu) << 12;
	if (!b14) {                             /* b.w */
		imm |= (h2 & 0x7ffu) << 1;
		o->op = CELL_JMP;
		t_branch_to(o, o->at_va + 4u + (uint64_t)arm_sext(imm, 25));
		return;
	}
	if (b12) {                              /* bl */
		imm |= (h2 & 0x7ffu) << 1;
		o->op = CELL_CALL;
		o->wmask = ARM_R(ARM_LR);
		t_branch_to(o, o->at_va + 4u + (uint64_t)arm_sext(imm, 25));
		return;
	}
	if (h2 & 1u) {                          /* blx imm must have bit 0 clear */
		kof_arm_ud(o);
		return;
	}
	imm = (imm & ~0xfffu) | ((h2 >> 1) & 0x3ffu) << 2;      /* blx: to A32 */
	o->op = CELL_CALL;
	o->wmask = ARM_R(ARM_LR);
	t_branch_to(o, (uint64_t)(int64_t)(t_pcb(o) + (int64_t)o->at_va) +
			(uint64_t)arm_sext(imm, 25));
}

/* ---- 32-bit: load and store multiple, dual, exclusive, table branch ----- */

static void t_ldstm(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t opc = (h1 >> 7) & 3u, w = (h1 >> 5) & 1u, l = (h1 >> 4) & 1u;
	uint32_t rn = h1 & 15u, list = h2 & 0xffffu;

	if (opc == 0u || opc == 3u) {           /* srs, rfe */
		o->op = CELL_PRIV;
		if (l) {
			o->wmask = ARM_R(ARM_PC);
			if (w)
				o->wmask |= ARM_R(rn);
		}
		return;
	}
	if (rn == ARM_SP && w) {
		if (opc == 2u && !l) {
			arm_pushpop(o, 0, list);
			return;
		}
		if (opc == 1u && l) {
			arm_pushpop(o, 1, list);
			return;
		}
	}
	o->op = CELL_OTHER;
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

static void t_ldstd(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t p = (h1 >> 8) & 1u, u = (h1 >> 7) & 1u, w = (h1 >> 5) & 1u;
	uint32_t l = (h1 >> 4) & 1u, rn = h1 & 15u;
	uint32_t rt = h2 >> 12, rt2 = (h2 >> 8) & 15u;

	if (!p && !w) {                         /* exclusive, table branch */
		uint32_t op3 = (h2 >> 4) & 15u;

		if (!u) {
			kof_arm_other(o, l ? ARM_R(rt) : t_wr(h2, 8));
			return;
		}
		if (op3 & 8u) {                 /* ARMv8: lda stl ldaex stlex */
			uint32_t sz = op3 & 3u, ex = op3 & 4u;

			if (!ex && sz == 3u) {
				kof_arm_ud(o);
			} else if (l) {
				kof_arm_other(o, ARM_R(rt) |
					      (ex && sz == 3u ? ARM_R(rt2) : 0));
			} else {
				kof_arm_other(o, ex ? ARM_R(h2 & 15u) : 0);
			}
			return;
		}
		if (l && op3 <= 1u) {           /* tbb tbh */
			struct cell_operand *m = &o->o[0];

			o->op = CELL_JMP;
			o->flags |= CELL_F_INDIRECT;
			o->wmask = ARM_R(ARM_PC);
			o->n_op = 1;
			arm_mem(m, rn, 0, op3 ? 2u : 1u, CELL_OF_READ);
			m->index = (uint8_t)(h2 & 15u);
			m->scale = (uint8_t)(op3 ? 2u : 1u);
			return;
		}
		if (op3 == 4u || op3 == 5u || op3 == 7u) {
			if (l)
				kof_arm_other(o, ARM_R(rt) |
					      (op3 == 7u ? ARM_R(rt2) : 0));
			else
				kof_arm_other(o, ARM_R(h2 & 15u));
			return;
		}
		kof_arm_ud(o);
		return;
	}

	{                                       /* ldrd strd, immediate */
		struct cell_operand m;
		int64_t off = (int64_t)(h2 & 255u) * 4;

		if (!u)
			off = -off;
		/* the offset form with pc as the base is pc-relative, load or
		 * store; a written-back pc base is UNPREDICTABLE and is not */
		if (rn == ARM_PC && !(p && !w))
			arm_mem(&m, rn, p ? off : 0, 8u,
				l ? CELL_OF_READ : CELL_OF_WRITE);
		else
			t_mem_imm(o, &m, rn, p ? off : 0, 8u, (int)l);
		t_ls(o, (int)l, CELL_MOV, rt, &m);
		if (l)
			o->wmask |= ARM_R(rt2);
		if (!p) {
			o->n_op = 3;
			arm_imm(&o->o[2], (uint64_t)off);
		}
		if (w || !p)
			o->wmask |= ARM_R(rn);
	}
}

/* ---- 32-bit: single loads and stores ------------------------------------- */

static void t_store(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t k = (h1 >> 5) & 7u, rn = h1 & 15u, rt = h2 >> 12;
	static const uint8_t sz[8] = { 1, 2, 4, 0, 1, 2, 4, 0 };
	struct cell_operand m;

	if (!sz[k] || rn == ARM_PC) {
		kof_arm_ud(o);
		return;
	}
	if (k & 4u) {                           /* imm12 */
		t_mem_imm(o, &m, rn, (int64_t)(h2 & 0xfffu), sz[k], 0);
		t_ls(o, 0, CELL_MOV, rt, &m);
		return;
	}
	if (h2 & 0x0800u) {                     /* imm8: p u w */
		uint32_t p = (h2 >> 10) & 1u, u = (h2 >> 9) & 1u, w = (h2 >> 8) & 1u;
		int64_t off = (int64_t)(h2 & 255u);

		if (!p && !w) {
			kof_arm_ud(o);
			return;
		}
		if (!u)
			off = -off;
		if (k == 2u && rn == ARM_SP && p && !u && w && (h2 & 255u) == 4u) {
			arm_pushpop(o, 0, ARM_R(rt));   /* str rt, [sp, #-4]! */
			return;
		}
		t_mem_imm(o, &m, rn, p ? off : 0, sz[k], 0);
		t_ls(o, 0, CELL_MOV, rt, &m);
		if (!p) {
			o->n_op = 3;
			arm_imm(&o->o[2], (uint64_t)off);
		}
		if (w || !p)
			o->wmask |= ARM_R(rn);
		return;
	}
	if (h2 & 0x0fc0u) {                     /* register: 000000 imm2 rm */
		kof_arm_ud(o);
		return;
	}
	t_mem_reg(&m, rn, h2 & 15u, (h2 >> 4) & 3u, sz[k], 0);
	t_ls(o, 0, CELL_MOV, rt, &m);
}

static void t_load(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t size = (h1 >> 5) & 3u, sgn = (h1 >> 8) & 1u, u = (h1 >> 7) & 1u;
	uint32_t rn = h1 & 15u, rt = h2 >> 12;
	unsigned cls, sz;
	int hint, wb = 0;
	struct cell_operand m;

	if (size == 3u || (size == 2u && sgn)) {
		kof_arm_ud(o);
		return;
	}
	sz = size == 0u ? 1u : size == 1u ? 2u : 4u;
	cls = size == 2u ? CELL_MOV : sgn ? CELL_MOVSX : CELL_MOVZX;
	hint = size != 2u && rt == ARM_PC;      /* pld, pli, unallocated hints */

	if (rn == ARM_PC) {                     /* literal: u is add/subtract */
		int64_t off = (int64_t)(h2 & 0xfffu);

		t_mem_imm(o, &m, rn, u ? off : -off, sz, 1);
	} else if (u) {                         /* imm12 */
		t_mem_imm(o, &m, rn, (int64_t)(h2 & 0xfffu), sz, 1);
	} else if (h2 & 0x0800u) {              /* imm8: p u w */
		uint32_t p = (h2 >> 10) & 1u, uu = (h2 >> 9) & 1u, w = (h2 >> 8) & 1u;
		int64_t off = (int64_t)(h2 & 255u);

		if (!p && !w) {
			kof_arm_ud(o);
			return;
		}
		if (!uu)
			off = -off;
		if (size == 2u && rn == ARM_SP && !p && uu && w && (h2 & 255u) == 4u) {
			arm_pushpop(o, 1, ARM_R(rt));   /* ldr rt, [sp], #4 */
			return;
		}
		t_mem_imm(o, &m, rn, p ? off : 0, sz, 1);
		wb = w || !p;
		if (!p) {
			t_ls(o, 1, cls, rt, &m);
			o->n_op = 3;
			arm_imm(&o->o[2], (uint64_t)off);
			goto done;
		}
	} else {
		if (h2 & 0x0fc0u) {
			kof_arm_ud(o);
			return;
		}
		t_mem_reg(&m, rn, h2 & 15u, (h2 >> 4) & 3u, sz, 1);
	}
	t_ls(o, 1, cls, rt, &m);
done:
	if (wb)
		o->wmask |= ARM_R(rn);
	if (hint) {
		/* the load is a prefetch hint: it writes nothing */
		o->op = CELL_OTHER;
		o->wmask = wb ? ARM_R(rn) : 0;
		return;
	}
	if (size == 2u && rt == ARM_PC) {
		struct cell_operand mem = o->o[1];

		kof_arm_clr(o);
		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		o->wmask |= ARM_R(ARM_PC);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

/* ---- 32-bit: register data processing, multiplies ----------------------- */

static void t_dpreg(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t op1 = (h1 >> 4) & 15u, op2 = (h2 >> 4) & 15u;
	uint32_t rn = h1 & 15u, rd = (h2 >> 8) & 15u, rm = h2 & 15u;
	struct cell_operand t;

	if ((h2 & 0xf000u) != 0xf000u) {
		kof_arm_ud(o);
		return;
	}
	if (!(op1 & 8u)) {
		if (!op2) {                     /* lsl lsr asr ror by register */
			static const uint8_t kind[4] = { ARM_SH_LSL, ARM_SH_LSR,
							 ARM_SH_ASR, ARM_SH_ROR };

			t_src_reg(&t, rn);
			arm_shift(&t, kind[op1 >> 1], 0, rm);
			kof_arm_dp(o, 13u, op1 & 1u, 0, rd, &t, 0);
			return;
		}
		if ((op2 & 8u) && op1 <= 5u) {
			/* sxtah sxth uxtah uxth sxtab16 sxtb16 .. sxtab sxtb ..;
			 * bit 6 is SBZ */
			uint32_t rot = (op2 & 3u) * 8u, k = op1 >> 1;

			kof_arm_other(o, ARM_R(rd));
			if (rn == ARM_PC && k != 1u) {
				o->op = (op1 & 1u) ? CELL_MOVZX : CELL_MOVSX;
				o->n_op = 2;
				arm_reg(&o->o[0], rd, CELL_OF_WRITE);
				arm_reg(&o->o[1], rm, CELL_OF_READ);
				o->o[1].size = k == 0u ? 2u : 1u;
				if (rot)
					arm_shift(&o->o[1], ARM_SH_ROR, rot, 0xffu);
			}
			return;
		}
		kof_arm_ud(o);
		return;
	}
	/* op1 = 1xxx */
	if ((op2 & 8u) == 0u) {                 /* parallel add and subtract */
		uint32_t sub = op1 & 7u, pfx = op2 & 3u;

		if (sub == 3u || sub == 7u || pfx == 3u)
			kof_arm_ud(o);
		else
			kof_arm_other(o, ARM_R(rd));
		return;
	}
	if ((op2 & 0xcu) == 8u) {               /* miscellaneous operations */
		uint32_t a = op1 & 7u, b = op2 & 3u;

		if (!(op1 & 4u) && (a < 2u || b == 0u))
			kof_arm_other(o, ARM_R(rd));
		else
			kof_arm_ud(o);
		return;
	}
	kof_arm_ud(o);
}

static void t_mul(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t op1 = (h1 >> 4) & 7u, op2 = (h2 >> 4) & 3u;
	uint32_t ra = h2 >> 12, rd = (h2 >> 8) & 15u;

	if (op1 == 0u && op2 == 0u && ra == 15u) {
		o->op = CELL_MUL;
		o->wmask = ARM_R(rd);
		o->n_op = 3;
		arm_reg(&o->o[0], rd, CELL_OF_WRITE);
		arm_reg(&o->o[1], h1 & 15u, CELL_OF_READ);
		arm_reg(&o->o[2], h2 & 15u, CELL_OF_READ);
		return;
	}
	/* the allocated (op1, op2) pairs: op1 1 takes all four op2, 7 only 0 */
	if (op1 == 1u || (op1 == 7u ? op2 == 0u : op2 <= 1u))
		kof_arm_other(o, ARM_R(rd));
	else
		kof_arm_ud(o);
}

static void t_longmul(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t op1 = (h1 >> 4) & 7u, op2 = (h2 >> 4) & 15u;
	uint32_t rdlo = h2 >> 12, rdhi = (h2 >> 8) & 15u;

	switch (op1) {
	case 1: case 3:                         /* sdiv udiv */
		if (op2 != 15u || rdlo != 15u) {
			kof_arm_ud(o);
			return;
		}
		o->op = op1 == 1u ? CELL_IDIV : CELL_DIV;
		o->wmask = ARM_R(rdhi);
		o->n_op = 3;
		arm_reg(&o->o[0], rdhi, CELL_OF_WRITE);
		arm_reg(&o->o[1], h1 & 15u, CELL_OF_READ);
		arm_reg(&o->o[2], h2 & 15u, CELL_OF_READ);
		return;
	case 0: case 2:                         /* smull umull */
		if (op2) {
			kof_arm_ud(o);
			return;
		}
		break;
	case 4:                                 /* smlal smlalxy smlald */
		if (op2 && (op2 & 0xcu) != 8u && (op2 & 0xeu) != 12u) {
			kof_arm_ud(o);
			return;
		}
		break;
	case 5:                                 /* smlsld */
		if ((op2 & 0xeu) != 12u) {
			kof_arm_ud(o);
			return;
		}
		break;
	case 6:                                 /* umlal umaal */
		if (op2 && op2 != 6u) {
			kof_arm_ud(o);
			return;
		}
		break;
	default:
		kof_arm_ud(o);
		return;
	}
	kof_arm_other(o, ARM_R(rdlo) | ARM_R(rdhi));
}

/* ---- 32-bit: coprocessor, Advanced SIMD, VFP (not validity-checked) ----- */

static void t_cop(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	uint32_t rn = h1 & 15u, rt = h2 >> 12;

	o->op = CELL_OTHER;
	if (!((h1 >> 9) & 1u)) {                /* ldc stc mcrr mrrc */
		uint32_t k = (h1 >> 5) & 15u;

		/* ARMv8.2 VSDOT/VUDOT reuse the cp13 slot of ldc2/stc2 */
		if ((h1 & 0xffb0u) == 0xfc20u && ((h2 >> 8) & 15u) == 13u)
			return;

		if (k == 0u) {
			kof_arm_ud(o);
			return;
		}
		if (k == 2u) {
			if (h1 & 0x10u)
				o->wmask = ARM_R(rt) | ARM_R(rn);
			return;
		}
		if (h1 & 0x20u)
			o->wmask = ARM_R(rn);
		return;
	}
	if (!((h1 >> 8) & 1u) && (h2 & 0x10u) && (h1 & 0x10u) && rt != ARM_PC)
		o->wmask = ARM_R(rt);           /* mrc, vmov to core, vmrs */
}

/* ---- 32-bit: the three groups ------------------------------------------- */

static void t_g_e8(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	if (h1 & 0x0400u) {
		t_cop(h1, h2, o);
	} else if (h1 & 0x0200u) {
		t_dp_shift(h1, h2, o);
	} else if (h1 & 0x40u) {
		t_ldstd(h1, h2, o);
	} else {
		t_ldstm(h1, h2, o);
	}
}

static void t_g_f0(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	if (h2 & 0x8000u)
		t_branch(h1, h2, o);
	else if (h1 & 0x0200u)
		t_dp_plain(h1, h2, o);
	else
		t_dp_modimm(h1, h2, o);
}

static void t_g_f8(uint32_t h1, uint32_t h2, struct cell_insn *o)
{
	if (h1 & 0x0400u) {
		t_cop(h1, h2, o);
		return;
	}
	if (!(h1 & 0x0200u)) {
		if (h1 & 0x10u) {
			t_load(h1, h2, o);
		} else if (h1 & 0x0100u) {
			/* advanced SIMD element or structure load/store */
			o->op = CELL_OTHER;
			if ((h2 & 15u) != 15u)
				o->wmask = ARM_R(h1 & 15u);
		} else {
			t_store(h1, h2, o);
		}
		return;
	}
	if (!(h1 & 0x0100u))
		t_dpreg(h1, h2, o);
	else if (!(h1 & 0x80u))
		t_mul(h1, h2, o);
	else
		t_longmul(h1, h2, o);
}

static const t32_fn g_t32[4] = { NULL, t_g_e8, t_g_f0, t_g_f8 };

/* ---- entry -------------------------------------------------------------- */

uint32_t cell_decode_t32(const uint8_t *p, uint32_t n, uint64_t va,
			int be, struct cell_insn *out)
{
	uint32_t h1;

	if (!p || n < 2u || !out)
		return 0;
	h1 = arm_h(p, be);
	if ((h1 >> 11) >= 0x1du) {
		uint32_t h2;

		if (n < 4u)
			return 0;
		h2 = arm_h(p + 2, be);
		arm_begin(out, va, 4u);
		g_t32[(h1 >> 11) & 3u](h1, h2, out);
		return 4u;
	}
	arm_begin(out, va, 2u);
	g_t16[h1 >> 10](h1, out);
	return 2u;
}
