/*
 * a32.c - ARM (A32) into the engine's one instruction form.
 *
 * Written from the ARM ARM's encoding structure, and checked against an
 * oracle that is NOT part of this tree (tools/celllysis/arm_diff.c). The
 * operand conventions - the pc rule, the literal address, the three-operand
 * ALU form, the shift carried on a source operand - are in decode_arm.h and a
 * consumer needs them.
 *
 * DISPATCH BY TABLE ON THE BIT FIELD, as decode_mips.c does: bits 27..25
 * select one of eight handlers (a second table for the unconditional space,
 * cond = 0xF), and inside a handler the class comes from a table indexed by
 * the opcode field (g_dpcls, g_hcls). An instruction's cost does not depend on
 * where it sits in a list of cases.
 *
 * WHAT IT SAYS ABOUT AN ENCODING IT DOES NOT MODEL. The integer space -
 * data processing, multiplies, loads and stores, media instructions, branches,
 * the miscellaneous group - is validity-checked: an encoding the ARM ARM
 * leaves unallocated comes back CELL_UD, length 4. The coprocessor, VFP and
 * Advanced SIMD spaces are NOT: they come back CELL_OTHER, length 4, with the
 * core registers they write (a base register written back, the Rt of an
 * MRC/VMOV to core, the pair of an MRRC) in wmask. A decoder that told the
 * sweep an encoding was undefined when it was only a NEON form it never
 * learned would end a walk on ordinary code.
 */
#include "decode_arm.h"

typedef void (*a32_fn)(uint32_t x, struct cell_insn *o);

/* ---- helpers ------------------------------------------------------------ */

/* A written register from a field. */
static uint64_t a_wr(uint32_t x, unsigned shift)
{
	return ARM_R((x >> shift) & 15u);
}

/*
 * The second source operand of a data-processing instruction: a rotated
 * immediate or a register with its shift. Returns 1 when it is an immediate.
 */
static int a_op2(uint32_t x, int imm_form, struct cell_operand *t)
{
	uint32_t type, amt;

	t->reg = t->index = t->seg = CELL_REG_NONE;
	if (imm_form) {
		arm_imm(t, arm_ror32(x & 255u, ((x >> 8) & 15u) * 2u));
		return 1;
	}
	arm_reg(t, x & 15u, CELL_OF_READ);
	type = (x >> 5) & 3u;
	if (x & 0x10u) {
		arm_shift(t, type + 1u, 0, (x >> 8) & 15u);
		return 0;
	}
	amt = (x >> 7) & 31u;
	if (!amt) {
		if (type == 3u)
			arm_shift(t, ARM_SH_RRX, 1u, 0xffu);
		else if (type)
			arm_shift(t, type + 1u, 32u, 0xffu);
		/* lsl #0 is the register itself */
		return 0;
	}
	arm_shift(t, type + 1u, amt, 0xffu);
	return 0;
}

/* ---- data processing ---------------------------------------------------- */

static void a_dp(uint32_t x, struct cell_insn *o, int imm_form)
{
	struct cell_operand t;

	memset(&t, 0, sizeof t);
	(void)a_op2(x, imm_form, &t);
	kof_arm_dp(o, (x >> 21) & 15u, (x >> 20) & 1u, (x >> 16) & 15u,
		   (x >> 12) & 15u, &t, 8);
}

/* ---- the miscellaneous group (bits 24:23 = 10, S = 0) -------------------- */

static void a_misc(uint32_t x, struct cell_insn *o)
{
	uint32_t op = (x >> 21) & 3u, op2 = (x >> 4) & 7u, rm = x & 15u;

	switch (op2) {
	case 0:
		if (op & 1u) {                  /* msr */
			o->op = CELL_PRIV;
		} else {                        /* mrs, banked or not */
			o->op = CELL_PRIV;
			o->wmask = a_wr(x, 12);
			o->n_op = 1;
			arm_reg(&o->o[0], (x >> 12) & 15u, CELL_OF_WRITE);
		}
		return;
	case 1:
		if (op == 1u) {                 /* bx */
			o->wmask = ARM_R(ARM_PC);
			o->flags |= CELL_F_INDIRECT;
			o->op = rm == ARM_LR ? CELL_RET : CELL_JMP;
			o->n_op = 1;
			arm_reg(&o->o[0], rm, CELL_OF_READ);
		} else if (op == 3u) {          /* clz */
			kof_arm_other(o, a_wr(x, 12));
			o->n_op = 2;
			arm_reg(&o->o[0], (x >> 12) & 15u, CELL_OF_WRITE);
			arm_reg(&o->o[1], rm, CELL_OF_READ);
		} else {
			kof_arm_ud(o);
		}
		return;
	case 2:
		if (op == 1u) {                 /* bxj: bx on a core without Jazelle */
			o->wmask = ARM_R(ARM_PC);
			o->flags |= CELL_F_INDIRECT;
			o->op = CELL_JMP;
			o->n_op = 1;
			arm_reg(&o->o[0], rm, CELL_OF_READ);
		} else {
			kof_arm_ud(o);
		}
		return;
	case 3:
		if (op == 1u) {                 /* blx reg */
			o->flags |= CELL_F_INDIRECT;
			o->op = CELL_CALL;
			o->wmask = ARM_R(ARM_LR) | ARM_R(ARM_PC);
			o->n_op = 1;
			arm_reg(&o->o[0], rm, CELL_OF_READ);
		} else {
			kof_arm_ud(o);
		}
		return;
	case 4:
		/*
		 * crc32, ARMv8's optional CRC extension. Decoded; the oracle in
		 * its default (v7) mode does not, and that is the whole of the
		 * `cond=E, bits 27:20 = 0x10/0x12/0x14` rows in arm_diff's
		 * "UD in oracle" table.
		 */
		if (op != 3u && !(x & 0xd00u)) {
			kof_arm_other(o, a_wr(x, 12));
			return;
		}
		kof_arm_ud(o);
		return;
	case 5:                                 /* qadd qsub qdadd qdsub */
		kof_arm_other(o, a_wr(x, 12));
		return;
	case 6:
		if (op == 3u) {                 /* eret */
			o->op = CELL_PRIV;
			o->wmask = ARM_R(ARM_PC);
		} else {
			kof_arm_ud(o);
		}
		return;
	default:                                /* 7: bkpt hvc smc */
		if (op == 0u) {
			kof_arm_ud(o);
			return;
		}
		o->op = op == 1u ? CELL_INT : CELL_PRIV;
		o->n_op = 1;
		arm_imm(&o->o[0], ((x >> 4) & 0xfff0u) | (x & 15u));
		return;
	}
}

/* ---- multiplies, synchronisation, halfword and doubleword transfers ------ */

static void a_mul_sync(uint32_t x, struct cell_insn *o)
{
	uint32_t op = (x >> 20) & 15u;

	if (!(x & 0x01000000u)) {               /* multiplies */
		uint32_t hi = (x >> 16) & 15u, lo = (x >> 12) & 15u;

		switch (op >> 1) {
		case 0:                         /* mul */
			o->op = CELL_MUL;
			o->wmask = ARM_R(hi);
			o->n_op = 3;
			arm_reg(&o->o[0], hi, CELL_OF_WRITE);
			arm_reg(&o->o[1], x & 15u, CELL_OF_READ);
			arm_reg(&o->o[2], (x >> 8) & 15u, CELL_OF_READ);
			return;
		case 1:                         /* mla */
			kof_arm_other(o, ARM_R(hi));
			return;
		case 2:                         /* umaal, and 0101 is unallocated */
			if (op & 1u)
				kof_arm_ud(o);
			else
				kof_arm_other(o, ARM_R(hi) | ARM_R(lo));
			return;
		case 3:                         /* mls, and 0111 is unallocated */
			if (op & 1u)
				kof_arm_ud(o);
			else
				kof_arm_other(o, ARM_R(hi));
			return;
		default:                        /* umull umlal smull smlal */
			kof_arm_other(o, ARM_R(hi) | ARM_R(lo));
			return;
		}
	}

	/*
	 * swp, ldrex, strex and their sized forms; and ARMv8's acquire/release
	 * forms, which sit in the same slots with bits 11:8 = 1110 (stlex,
	 * ldaex) or 1100 (stl, lda).
	 */
	{
		uint32_t f = (x >> 8) & 15u;
		int ld = op & 1u;

		if (op == 0u || op == 4u) {             /* swp, swpb */
			kof_arm_other(o, a_wr(x, 12));
			return;
		}
		if (!(op & 8u) || (f != 15u && f != 14u && f != 12u)) {
			kof_arm_ud(o);
			return;
		}
		if (f == 12u) {
			/* stl/stlb/stlh store (8, 12, 14); lda* load (9, 13, 15) */
			if (op == 10u || op == 11u) {
				kof_arm_ud(o);
				return;
			}
			kof_arm_other(o, ld ? a_wr(x, 12) : 0);
			return;
		}
		if (op == 11u) {                        /* ldrexd, ldaexd: rt, rt+1 */
			kof_arm_other(o, a_wr(x, 12) |
				   ARM_R((((x >> 12) & 15u) + 1u) & 15u));
			return;
		}
		kof_arm_other(o, a_wr(x, 12));
	}
}

/* Class of a halfword/doubleword transfer on (L << 2 | sh). 0 = a store. */
static const uint8_t g_hcls[8] = {
	0, CELL_MOV, CELL_MOV, CELL_MOV,         /* L=0: -, strh, ldrd, strd */
	0, CELL_MOVZX, CELL_MOVSX, CELL_MOVSX,   /* L=1: -, ldrh, ldrsb, ldrsh */
};
static const uint8_t g_hsize[8] = { 0, 2, 8, 8, 0, 2, 1, 2 };

static void a_extra_ldst(uint32_t x, struct cell_insn *o)
{
	uint32_t sh = (x >> 5) & 3u, l = (x >> 20) & 1u, p = (x >> 24) & 1u;
	uint32_t u = (x >> 23) & 1u, w = (x >> 21) & 1u;
	uint32_t imm_form = (x >> 22) & 1u;
	uint32_t rn = (x >> 16) & 15u, rt = (x >> 12) & 15u;
	uint32_t k = l << 2 | sh;
	unsigned size = g_hsize[k];
	int load = (k >= 4u) || k == 2u;        /* ldrd is the load at L=0 */
	int wb = !p || w;
	struct cell_operand *m;
	struct cell_operand *v;
	uint64_t wm = 0;

	/*
	 * strd/ldrd have no unprivileged form. An odd Rt is UNPREDICTABLE in
	 * the ARM ARM (v7) and the oracle decodes it, so it is decoded.
	 */
	if (size == 8u && !p && w) {
		kof_arm_ud(o);
		return;
	}

	o->op = g_hcls[k] ? g_hcls[k] : CELL_MOV;
	if (load) {
		wm = ARM_R(rt);
		if (size == 8u)
			wm |= ARM_R((rt + 1u) & 15u);
		m = &o->o[1];
		v = &o->o[0];
		arm_reg(v, rt, CELL_OF_WRITE);
	} else {
		m = &o->o[0];
		v = &o->o[1];
		arm_reg(v, rt, CELL_OF_READ);
	}
	o->n_op = 2;

	if (imm_form) {
		int64_t off = (int64_t)(((x >> 4) & 0xf0u) | (x & 15u));

		if (!u)
			off = -off;
		if (rn == ARM_PC && p && !w)
			arm_mem(m, rn, 8 + off, size,
				(load ? CELL_OF_READ : CELL_OF_WRITE) |
				CELL_OF_RIPREL);
		else
			arm_mem(m, rn, p ? off : 0, size,
				load ? CELL_OF_READ : CELL_OF_WRITE);
		if (!p) {
			o->n_op = 3;
			arm_imm(&o->o[2], (uint64_t)off);
		}
	} else {
		arm_mem(m, rn, 0, size, load ? CELL_OF_READ : CELL_OF_WRITE);
		if (p) {
			m->index = (uint8_t)(x & 15u);
			m->imm = u ? 0u : 1u;
		} else {
			o->n_op = 3;
			arm_reg(&o->o[2], x & 15u, CELL_OF_READ);
			o->o[2].imm = u ? 0u : 1u;
		}
	}
	if (wb)
		wm |= ARM_R(rn);
	o->wmask = wm;
}

/* ---- single data transfer ----------------------------------------------- */

static void a_ldst(uint32_t x, struct cell_insn *o, int reg_form)
{
	uint32_t p = (x >> 24) & 1u, u = (x >> 23) & 1u, b = (x >> 22) & 1u;
	uint32_t w = (x >> 21) & 1u, l = (x >> 20) & 1u;
	uint32_t rn = (x >> 16) & 15u, rt = (x >> 12) & 15u;
	unsigned size = b ? 1u : 4u;
	struct cell_operand *m;
	struct cell_operand *v;
	uint64_t wm = 0;
	int wb = !p || w;

	if (!reg_form && rn == ARM_SP && !b && (x & 0xfffu) == 4u) {
		/* str rt,[sp,#-4]! is push {rt}; ldr rt,[sp],#4 is pop {rt} */
		if (!l && p && !u && w) {
			arm_pushpop(o, 0, ARM_R(rt));
			return;
		}
		if (l && !p && u && !w) {
			arm_pushpop(o, 1, ARM_R(rt));
			return;
		}
	}

	o->op = l ? (b ? CELL_MOVZX : CELL_MOV) : CELL_MOV;
	if (l) {
		wm = ARM_R(rt);
		m = &o->o[1];
		v = &o->o[0];
		arm_reg(v, rt, CELL_OF_WRITE);
	} else {
		m = &o->o[0];
		v = &o->o[1];
		arm_reg(v, rt, CELL_OF_READ);
	}
	o->n_op = 2;

	if (!reg_form) {
		int64_t off = (int64_t)(x & 0xfffu);

		if (!u)
			off = -off;
		if (rn == ARM_PC && p && !w)
			arm_mem(m, rn, 8 + off, size,
				(l ? CELL_OF_READ : CELL_OF_WRITE) |
				CELL_OF_RIPREL);
		else
			arm_mem(m, rn, p ? off : 0, size,
				l ? CELL_OF_READ : CELL_OF_WRITE);
		if (!p) {
			o->n_op = 3;
			arm_imm(&o->o[2], (uint64_t)off);
		}
	} else {
		struct cell_operand t;

		memset(&t, 0, sizeof t);
		(void)a_op2(x, 0, &t);
		arm_mem(m, rn, 0, size, l ? CELL_OF_READ : CELL_OF_WRITE);
		if (!p) {
			/* post-indexed: the access is at the base, and the
			 * register that moves it is the third operand */
			o->n_op = 3;
			o->o[2] = t;
			o->o[2].imm = u ? 0u : 1u;
		} else {
			m->index = (uint8_t)(x & 15u);
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
	}
	if (wb)
		wm |= ARM_R(rn);
	o->wmask = wm;

	if (l && !b && rt == ARM_PC) {
		/* ldr pc, [...] - an indirect jump, through memory */
		struct cell_operand mem = *m;

		o->op = CELL_JMP;
		o->flags |= CELL_F_INDIRECT;
		kof_arm_clr(o);
		o->o[0] = mem;
		o->n_op = 1;
	}
}

/* ---- media instructions (bit 25 = 1, bit 4 = 1) -------------------------- */

static void a_media(uint32_t x, struct cell_insn *o)
{
	uint32_t hi = (x >> 23) & 3u, op1 = (x >> 20) & 7u, op2 = (x >> 5) & 7u;
	uint32_t rd = (x >> 12) & 15u;

	switch (hi) {
	case 0:                                 /* parallel add and subtract */
		if (op1 == 0u || op1 == 4u || op2 == 5u || op2 == 6u)
			kof_arm_ud(o);
		else
			kof_arm_other(o, a_wr(x, 12));
		return;
	case 1:
		if (!(op2 & 1u) && (op1 == 0u || (op1 & 2u))) {
			/* pkh, ssat, usat */
			kof_arm_other(o, a_wr(x, 12));
			return;
		}
		if (op2 == 1u && (op1 == 2u || op1 == 6u)) {    /* ssat16 usat16 */
			kof_arm_other(o, a_wr(x, 12));
			return;
		}
		if (op2 == 3u && op1 != 1u && op1 != 5u) {
			/* sxt[a]b16/b/h, uxt[a]b16/b/h; rn = 15 is the plain one */
			uint32_t rot = (x >> 10) & 3u;

			kof_arm_other(o, a_wr(x, 12));
			if (((x >> 16) & 15u) == 15u && op1 != 0u && op1 != 4u) {
				o->op = (op1 & 4u) ? CELL_MOVZX : CELL_MOVSX;
				o->n_op = 2;
				arm_reg(&o->o[0], rd, CELL_OF_WRITE);
				arm_reg(&o->o[1], x & 15u, CELL_OF_READ);
				o->o[1].size = (op1 & 1u) ? 2u : 1u;
				if (rot)
					arm_shift(&o->o[1], ARM_SH_ROR,
						  rot * 8u, 0xffu);
			}
			return;
		}
		if (op1 == 0u && op2 == 5u) {   /* sel */
			kof_arm_other(o, a_wr(x, 12));
			return;
		}
		if ((op1 == 3u || op1 == 7u) && (op2 == 1u || op2 == 5u)) {
			kof_arm_other(o, a_wr(x, 12));        /* rev rev16 rbit revsh */
			return;
		}
		kof_arm_ud(o);
		return;
	case 2: {
		uint32_t d = (x >> 16) & 15u;

		if (op1 == 1u || op1 == 3u) {
			if (op2 != 0u) {
				kof_arm_ud(o);
				return;
			}
			o->op = op1 == 1u ? CELL_IDIV : CELL_DIV;
			o->wmask = ARM_R(d);
			o->n_op = 3;
			arm_reg(&o->o[0], d, CELL_OF_WRITE);
			arm_reg(&o->o[1], x & 15u, CELL_OF_READ);
			arm_reg(&o->o[2], (x >> 8) & 15u, CELL_OF_READ);
			return;
		}
		if (op1 == 0u && op2 < 4u) {            /* smlad smuad smlsd smusd */
			kof_arm_other(o, ARM_R(d));
			return;
		}
		if (op1 == 4u && op2 < 4u) {            /* smlald smlsld */
			kof_arm_other(o, ARM_R(d) | a_wr(x, 12));
			return;
		}
		if (op1 == 5u && (op2 < 2u || op2 >= 6u)) {   /* smmla smmul smmls */
			kof_arm_other(o, ARM_R(d));
			return;
		}
		kof_arm_ud(o);
		return;
	}
	default:                                /* 3 */
		if (op1 == 0u && op2 == 0u) {   /* usad8 usada8 */
			kof_arm_other(o, ARM_R((x >> 16) & 15u));
			return;
		}
		if ((op1 == 2u || op1 == 3u) && (op2 & 3u) == 2u) {
			kof_arm_other(o, a_wr(x, 12));        /* sbfx */
			return;
		}
		if ((op1 == 4u || op1 == 5u) && (op2 & 3u) == 0u) {
			kof_arm_other(o, a_wr(x, 12));        /* bfc bfi */
			return;
		}
		if ((op1 == 6u || op1 == 7u) && (op2 & 3u) == 2u) {
			kof_arm_other(o, a_wr(x, 12));        /* ubfx */
			return;
		}
		kof_arm_ud(o);                        /* includes udf: op1 7, op2 7 */
		return;
	}
}

/* ---- the groups --------------------------------------------------------- */

static void g_000(uint32_t x, struct cell_insn *o)
{
	if (!(x & 0x10u) || !(x & 0x80u)) {
		/* bit 4 = 0, or bit 4 = 1 and bit 7 = 0 */
		if ((x & 0x01900000u) == 0x01000000u) {
			/* 10xx0: misc, or halfword multiplies */
			if (!(x & 0x10u) && (x & 0x80u)) {
				uint32_t op = (x >> 21) & 3u;
				uint32_t d = (x >> 16) & 15u;

				kof_arm_other(o, op == 2u ? ARM_R(d) | a_wr(x, 12)
						    : ARM_R(d));
			} else if (!(x & 0x80u)) {
				a_misc(x, o);
			} else {
				kof_arm_ud(o);
			}
			return;
		}
		a_dp(x, o, 0);
		return;
	}
	/* bit 7 = 1 and bit 4 = 1 */
	if (!(x & 0x60u))
		a_mul_sync(x, o);
	else
		a_extra_ldst(x, o);
}

static void g_001(uint32_t x, struct cell_insn *o)
{
	uint32_t op1 = (x >> 20) & 31u;

	if ((op1 & 0x19u) == 0x10u) {
		/* 10xx0 : movw movt, msr immediate, hints */
		if (!(op1 & 2u)) {
			uint32_t v = ((x >> 4) & 0xf000u) | (x & 0xfffu);

			o->n_op = 2;
			arm_reg(&o->o[0], (x >> 12) & 15u, CELL_OF_WRITE);
			o->wmask = a_wr(x, 12);
			if (!(op1 & 4u)) {      /* movw */
				o->op = CELL_MOV;
				arm_imm(&o->o[1], v);
			} else {                /* movt: rd = rd & 0xffff | v << 16 */
				o->op = CELL_OR;
				arm_imm(&o->o[1], (uint64_t)v << 16);
			}
			return;
		}
		if (!(op1 & 4u) && !((x >> 16) & 15u)) {
			/* hints; the unallocated ones execute as nop */
			o->op = CELL_NOP;
			return;
		}
		o->op = CELL_PRIV;              /* msr immediate */
		return;
	}
	a_dp(x, o, 1);
}

static void g_010(uint32_t x, struct cell_insn *o)
{
	a_ldst(x, o, 0);
}

static void g_011(uint32_t x, struct cell_insn *o)
{
	if (x & 0x10u)
		a_media(x, o);
	else
		a_ldst(x, o, 1);
}

static void g_100(uint32_t x, struct cell_insn *o)
{
	uint32_t p = (x >> 24) & 1u, u = (x >> 23) & 1u, s = (x >> 22) & 1u;
	uint32_t w = (x >> 21) & 1u, l = (x >> 20) & 1u;
	uint32_t rn = (x >> 16) & 15u, list = x & 0xffffu;

	if (rn == ARM_SP && !s && w) {
		if (!l && p && !u) {            /* stmdb sp!, {...} */
			arm_pushpop(o, 0, list);
			return;
		}
		if (l && !p && u) {             /* ldmia sp!, {...} */
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

static void g_101(uint32_t x, struct cell_insn *o)
{
	/* a 32-bit address space: a branch past either end wraps */
	uint64_t t = (o->at_va + 8u + (uint64_t)(arm_sext(x, 24) * 4)) &
		     0xffffffffu;

	o->n_op = 1;
	o->o[0].kind = CELL_O_REL;
	o->target_va = t;
	o->target = t;
	o->wmask = ARM_R(ARM_PC);
	if (x & 0x01000000u) {
		o->op = CELL_CALL;
		o->wmask |= ARM_R(ARM_LR);
	} else if ((x >> 28) == 0xEu) {
		o->op = CELL_JMP;
	} else {
		o->op = CELL_JCC;
		o->cond = (uint8_t)(x >> 28);
	}
}

/*
 * The coprocessor space: LDC STC MCRR MRRC (bits 27:25 = 110) and CDP MCR MRC
 * (111, bit 24 = 0). VFP and Advanced SIMD share these encodings - cp10 and
 * cp11 - so one rule serves both, and it is the only part of them a consumer
 * of core registers needs: which core registers get written.
 */
static void a_cop(uint32_t x, struct cell_insn *o)
{
	uint32_t rn = (x >> 16) & 15u, rt = (x >> 12) & 15u;

	o->op = CELL_OTHER;
	if (((x >> 25) & 7u) == 6u) {
		uint32_t k = (x >> 21) & 31u;

		if (k == 0u) {
			kof_arm_ud(o);
			return;
		}
		if (k == 2u) {                  /* mcrr, mrrc */
			if (x & 0x00100000u)
				o->wmask = ARM_R(rt) | ARM_R(rn);
			return;
		}
		if (x & 0x00200000u)            /* writeback */
			o->wmask = ARM_R(rn);
		return;
	}
	if ((x & 0x10u) && (x & 0x00100000u) && rt != ARM_PC)
		o->wmask = ARM_R(rt);           /* mrc, vmov to core, vmrs */
}

static void g_110(uint32_t x, struct cell_insn *o)
{
	a_cop(x, o);
}

static void g_111(uint32_t x, struct cell_insn *o)
{
	if (x & 0x01000000u) {                  /* svc */
		o->op = CELL_SYSCALL;
		o->n_op = 1;
		arm_imm(&o->o[0], x & 0xffffffu);
		return;
	}
	a_cop(x, o);
}

static const a32_fn g_grp[8] = {
	g_000, g_001, g_010, g_011, g_100, g_101, g_110, g_111,
};

/* ---- the unconditional space (cond = 0xF) -------------------------------- */

static void u_000(uint32_t x, struct cell_insn *o)
{
	if ((x & 0x0ff00000u) == 0x01000000u) {
		o->op = CELL_PRIV;              /* cps, setend */
		return;
	}
	kof_arm_ud(o);
}

static void u_other(uint32_t x, struct cell_insn *o)
{
	(void)x;
	o->op = CELL_OTHER;                     /* Advanced SIMD data processing */
}

static void u_010(uint32_t x, struct cell_insn *o)
{
	uint32_t l = (x >> 20) & 1u, w = (x >> 21) & 1u, r = (x >> 22) & 1u;

	if (!(x & 0x01000000u)) {
		if (!l) {
			/* vld/vst: the base is written back when Rm is not pc */
			o->op = CELL_OTHER;
			if ((x & 15u) != 15u)
				o->wmask = a_wr(x, 16);
		} else if (r && !w) {
			o->op = CELL_OTHER;             /* pli, immediate */
		} else {
			kof_arm_ud(o);
		}
		return;
	}
	if (l && !w)
		o->op = CELL_OTHER;                     /* pld, pldw, immediate */
	else if (((x >> 20) & 0xffu) == 0x57u)
		o->op = CELL_OTHER;                     /* clrex dsb dmb isb */
	else
		kof_arm_ud(o);
}

static void u_011(uint32_t x, struct cell_insn *o)
{
	uint32_t l = (x >> 20) & 1u, w = (x >> 21) & 1u, r = (x >> 22) & 1u;

	if ((x & 0x10u) || !l || w || (!(x & 0x01000000u) && !r))
		kof_arm_ud(o);
	else
		o->op = CELL_OTHER;                     /* pld, pli by register */
}

static void u_100(uint32_t x, struct cell_insn *o)
{
	o->op = CELL_PRIV;
	if (!(x & 0x00400000u) && (x & 0x00100000u)) {  /* rfe */
		o->wmask = ARM_R(ARM_PC);
		if (x & 0x00200000u)
			o->wmask |= a_wr(x, 16);
	} else if (!((x & 0x00400000u) && !(x & 0x00100000u))) {
		kof_arm_ud(o);                        /* neither srs nor rfe */
	}
}

static void u_101(uint32_t x, struct cell_insn *o)
{
	/* blx imm: always Thumb, and the H bit is the halfword */
	uint64_t t = (o->at_va + 8u + (uint64_t)(arm_sext(x, 24) * 4) +
		      ((x >> 24) & 1u ? 2u : 0u)) & 0xffffffffu;

	o->op = CELL_CALL;
	o->wmask = ARM_R(ARM_LR) | ARM_R(ARM_PC);
	o->n_op = 1;
	o->o[0].kind = CELL_O_REL;
	o->target_va = t & ~(uint64_t)1;
	o->target = o->target_va;
}

/*
 * cond = 0xF and cp13 in the load/store space is not a load or store: it is
 * ARMv8.2's VSDOT/VUDOT (vector), which the old LDC2/STC2 slots were reused
 * for. The oracle reads them as such; read as LDC2 they would claim a base
 * register written back.
 */
static void u_110(uint32_t x, struct cell_insn *o)
{
	if ((x & 0x0fb00f00u) == 0x0c200d00u)
		o->op = CELL_OTHER;
	else
		a_cop(x, o);
}

static void u_111(uint32_t x, struct cell_insn *o)
{
	if (x & 0x01000000u)
		kof_arm_ud(o);
	else
		a_cop(x, o);
}

static const a32_fn g_unc[8] = {
	u_000, u_other, u_010, u_011, u_100, u_101, u_110, u_111,
};

/* ---- entry -------------------------------------------------------------- */

uint32_t cell_decode_a32(const uint8_t *p, uint32_t n, uint64_t va,
			int be, struct cell_insn *out)
{
	uint32_t x;

	if (!p || n < 4u || !out)
		return 0;
	x = arm_w(p, be);
	arm_begin(out, va, 4u);
	if ((x >> 28) == 0xFu) {
		g_unc[(x >> 25) & 7u](x, out);
		return 4u;
	}
	out->cond = (uint8_t)(x >> 28);
	g_grp[(x >> 25) & 7u](x, out);
	return 4u;
}
