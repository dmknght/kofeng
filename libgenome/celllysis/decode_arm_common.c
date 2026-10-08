/*
 * arm_common.c - what the A32 and Thumb decoders say the same way.
 *
 * The data-processing family is one instruction set with two spellings: A32
 * has the four-bit opcode in the word, Thumb-2 has it in a different place and
 * Thumb-1 has its own forms of it. What the instruction MEANS - which class, which
 * operands, which registers it writes, what it is when the destination is pc -
 * is decided once, here, from the A32 opcode numbering, and both decoders
 * call it. Two copies of this were the first thing the plan was to avoid
 * (CLAUDE.md rule 2): the next fix lands in both or in neither.
 */
#include "decode_arm.h"

void kof_arm_clr(struct cell_insn *o)
{
	unsigned i;

	o->n_op = 0;
	for (i = 0; i < 3u; i++) {
		memset(&o->o[i], 0, sizeof o->o[i]);
		o->o[i].reg = o->o[i].index = o->o[i].seg = CELL_REG_NONE;
	}
}

/* An encoding the architecture leaves unallocated. */
void kof_arm_ud(struct cell_insn *o)
{
	o->op = CELL_UD;
	o->wmask = 0;
	o->flags = 0;
	kof_arm_clr(o);
}

/* Valid, not a class the engine asks about, and writing `mask`. */
void kof_arm_other(struct cell_insn *o, uint64_t mask)
{
	o->op = CELL_OTHER;
	o->wmask = mask;
}

/* On the four-bit opcode field. OTHER where there is no class to name. */
static const uint8_t g_dpcls[17] = {
	CELL_AND, CELL_XOR, CELL_SUB, CELL_OTHER,       /* and eor sub rsb */
	CELL_ADD, CELL_ADC, CELL_SBB, CELL_OTHER,       /* add adc sbc rsc */
	CELL_TEST, CELL_TEST, CELL_CMP, CELL_OTHER,     /* tst teq cmp cmn */
	CELL_OR, CELL_MOV, CELL_OTHER, CELL_NOT,        /* orr mov bic mvn */
	CELL_OTHER,                                     /* 16: orn (Thumb-2) */
};

/* mov rd, rm, <shift> on the shift kind; ARM_SH_* - 1 indexes it. */
static const uint8_t g_shcls[5] = {
	CELL_SHL, CELL_SHR, CELL_SAR, CELL_ROR, CELL_OTHER      /* ... rrx */
};

void kof_arm_dp(struct cell_insn *o, unsigned opc, unsigned s, unsigned rn,
		unsigned rd, const struct cell_operand *srcp, int64_t pc_off)
{
	struct cell_operand t = *srcp;
	int is_imm = t.kind == CELL_O_IMM;

	o->op = g_dpcls[opc];

	if (opc >= 8u && opc <= 11u) {
		/* a comparison: reads rn, writes the flags and no register */
		o->n_op = 2;
		arm_reg(&o->o[0], rn, CELL_OF_READ);
		o->o[1] = t;
		return;
	}

	arm_reg(&o->o[0], rd, CELL_OF_WRITE);
	o->wmask = ARM_R(rd);

	if (opc == 13u) {                       /* mov, and the shifts */
		if (is_imm) {
			o->n_op = 2;
			o->o[1] = t;
		} else if (t.scale == ARM_SH_NONE) {
			o->n_op = 2;
			o->o[1] = t;
			if (!s && rd == 0 && t.reg == 0)
				o->op = CELL_NOP;       /* mov r0, r0 */
		} else if (t.scale == ARM_SH_RRX) {
			o->op = CELL_OTHER;
			o->n_op = 2;
			o->o[1] = t;
		} else {
			/* mov rd, rm, lsl #n  IS lsl rd, rm, #n */
			o->op = g_shcls[t.scale - 1u];
			o->n_op = 3;
			arm_reg(&o->o[1], t.reg, CELL_OF_READ);
			if (t.index != CELL_REG_NONE)
				arm_reg(&o->o[2], t.index, CELL_OF_READ);
			else
				arm_imm(&o->o[2], (uint64_t)t.disp);
		}
	} else if (opc == 15u) {                /* mvn */
		o->n_op = 2;
		if (is_imm) {
			o->op = CELL_MOV;
			arm_imm(&o->o[1], (~t.imm) & 0xffffffffu);
		} else {
			o->o[1] = t;
			/*
			 * NOT IS ONE-OPERAND in cell_state (`d = ~d`), so it is
			 * only that when the register is its own source and
			 * nothing is shifted; anything else is a value the map
			 * could not compute and must not be told it can.
			 */
			if (t.reg != rd || t.scale != ARM_SH_NONE)
				o->op = CELL_OTHER;
		}
	} else if (opc == 3u && is_imm && t.imm == 0) {
		/* rsb rd, rn, #0 is a negate; NEG is `d = -d` to cell_state */
		o->n_op = 2;
		arm_reg(&o->o[1], rn, CELL_OF_READ);
		o->op = rn == rd ? CELL_NEG : CELL_OTHER;
	} else if (pc_off && rn == ARM_PC && is_imm && !s &&
		   (opc == 4u || opc == 2u)) {
		/* add/sub rd, pc, #imm - the address, and `adr` is its name */
		o->op = CELL_LEA;
		o->n_op = 2;
		arm_mem(&o->o[1], ARM_PC, opc == 4u ? pc_off + (int64_t)t.imm
						    : pc_off - (int64_t)t.imm,
			0, CELL_OF_RIPREL);
	} else if (rn == rd && (is_imm || t.scale == ARM_SH_NONE) &&
		   (o->op == CELL_ADD || o->op == CELL_SUB || o->op == CELL_AND ||
		    o->op == CELL_OR || o->op == CELL_XOR || o->op == CELL_ADC ||
		    o->op == CELL_SBB)) {
		/*
		 * `add r0, r0, #4` IS `r0 += 4`, and is spelt that way: two
		 * operands, destination then source - the form cell_state's
		 * constant map computes with. Written as three it reads
		 * o[1] (r0) as the SOURCE and answers `r0 + r0`; and
		 * `sub r0, r0, #1` hits its "a register against itself is
		 * zero" arm and answers 0. Both measured, both silent.
		 */
		o->n_op = 2;
		o->o[1] = t;
	} else {
		o->n_op = 3;
		arm_reg(&o->o[1], rn, CELL_OF_READ);
		o->o[2] = t;
	}

	if (rd != ARM_PC)
		return;

	/* A write to pc is a branch. */
	o->wmask |= ARM_R(ARM_PC);
	if (s) {                                /* movs pc, lr: exception return */
		o->op = CELL_PRIV;
		return;
	}
	o->flags |= CELL_F_INDIRECT;
	if (opc == 13u && !is_imm && t.scale == ARM_SH_NONE) {
		o->op = t.reg == ARM_LR ? CELL_RET : CELL_JMP;
		kof_arm_clr(o);
		o->n_op = 1;
		arm_reg(&o->o[0], t.reg, CELL_OF_READ);
	} else {
		o->op = CELL_JMP;
		kof_arm_clr(o);
	}
}
