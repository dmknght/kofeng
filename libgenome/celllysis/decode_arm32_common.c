/*
 * decode_arm32_common.c - what the ARM state and Thumb state adapters say the same way.
 *
 * The data-processing family is one instruction set with two spellings: ARM state
 * has the four-bit opcode in the word, Thumb-2 has it in a different place and
 * Thumb-1 has its own forms of it. What the instruction MEANS - which class, which
 * operands, which registers it writes, what it is when the destination is pc -
 * is decided once, here, from the ARM state opcode numbering, and both decoders
 * call it. Two copies of this were the first thing the plan was to avoid
 * (CLAUDE.md rule 2): the next fix lands in both or in neither.
 */
#include "decode_arm32.h"

void kgenome_arm_clr(struct kgenome_cell_insn *o)
{
	unsigned i;

	o->n_op = 0;
	for (i = 0; i < 3u; i++) {
		memset(&o->o[i], 0, sizeof o->o[i]);
		o->o[i].reg = o->o[i].index = o->o[i].seg = KGENOME_CELL_REG_NONE;
	}
}

/* An encoding the architecture leaves unallocated. */
void kgenome_arm_ud(struct kgenome_cell_insn *o)
{
	o->op = KGENOME_CELL_UD;
	o->wmask = 0;
	o->flags = 0;
	kgenome_arm_clr(o);
}

/* Valid, not a class the engine asks about, and writing `mask`. */
void kgenome_arm_other(struct kgenome_cell_insn *o, uint64_t mask)
{
	o->op = KGENOME_CELL_OTHER;
	o->wmask = mask;
}

/* On the four-bit opcode field. OTHER where there is no class to name. */
static const uint8_t g_dpcls[17] = {
	KGENOME_CELL_AND, KGENOME_CELL_XOR, KGENOME_CELL_SUB, KGENOME_CELL_OTHER,       /* and eor sub rsb */
	KGENOME_CELL_ADD, KGENOME_CELL_ADC, KGENOME_CELL_SBB, KGENOME_CELL_OTHER,       /* add adc sbc rsc */
	KGENOME_CELL_TEST, KGENOME_CELL_TEST, KGENOME_CELL_CMP, KGENOME_CELL_OTHER,     /* tst teq cmp cmn */
	KGENOME_CELL_OR, KGENOME_CELL_MOV, KGENOME_CELL_OTHER, KGENOME_CELL_NOT,        /* orr mov bic mvn */
	KGENOME_CELL_OTHER,                                     /* 16: orn (Thumb-2) */
};

/* mov rd, rm, <shift> on the shift kind; ARM_SH_* - 1 indexes it. */
static const uint8_t g_shcls[5] = {
	KGENOME_CELL_SHL, KGENOME_CELL_SHR, KGENOME_CELL_SAR, KGENOME_CELL_ROR, KGENOME_CELL_OTHER      /* ... rrx */
};

void kgenome_arm_dp(struct kgenome_cell_insn *o, unsigned opc, unsigned s, unsigned rn,
		unsigned rd, const struct kgenome_cell_operand *srcp, int64_t pc_off)
{
	/* the source is only read, and never aliases `o`: no copy of it */
	const struct kgenome_cell_operand *const tp = srcp;
	int is_imm = tp->kind == KGENOME_CELL_O_IMM;

	o->op = g_dpcls[opc];

	if (opc >= 8u && opc <= 11u) {
		/* a comparison: reads rn, writes the flags and no register */
		o->n_op = 2;
		kgenome_arm_reg(&o->o[0], rn, KGENOME_CELL_OF_READ);
		o->o[1] = *tp;
		return;
	}

	kgenome_arm_reg(&o->o[0], rd, KGENOME_CELL_OF_WRITE);
	o->wmask = KGENOME_ARM_R(rd);

	if (opc == 13u) {                       /* mov, and the shifts */
		if (is_imm) {
			o->n_op = 2;
			o->o[1] = *tp;
		} else if (tp->scale == KGENOME_ARM_SH_NONE) {
			o->n_op = 2;
			o->o[1] = *tp;
			if (!s && rd == 0 && tp->reg == 0)
				o->op = KGENOME_CELL_NOP;       /* mov r0, r0 */
		} else if (tp->scale == KGENOME_ARM_SH_RRX) {
			o->op = KGENOME_CELL_OTHER;
			o->n_op = 2;
			o->o[1] = *tp;
		} else {
			/* mov rd, rm, lsl #n  IS lsl rd, rm, #n */
			o->op = g_shcls[tp->scale - 1u];
			o->n_op = 3;
			kgenome_arm_reg(&o->o[1], tp->reg, KGENOME_CELL_OF_READ);
			if (tp->index != KGENOME_CELL_REG_NONE)
				kgenome_arm_reg(&o->o[2], tp->index, KGENOME_CELL_OF_READ);
			else
				kgenome_arm_imm(&o->o[2], (uint64_t)tp->disp);
		}
	} else if (opc == 15u) {                /* mvn */
		o->n_op = 2;
		if (is_imm) {
			o->op = KGENOME_CELL_MOV;
			kgenome_arm_imm(&o->o[1], (~tp->imm) & 0xffffffffu);
		} else {
			o->o[1] = *tp;
			/*
			 * NOT IS ONE-OPERAND in kgenome_cell_state (`d = ~d`), so it is
			 * only that when the register is its own source and
			 * nothing is shifted; anything else is a value the map
			 * could not compute and must not be told it can.
			 */
			if (tp->reg != rd || tp->scale != KGENOME_ARM_SH_NONE)
				o->op = KGENOME_CELL_OTHER;
		}
	} else if (opc == 3u && is_imm && tp->imm == 0) {
		/* rsb rd, rn, #0 is a negate; NEG is `d = -d` to kgenome_cell_state */
		o->n_op = 2;
		kgenome_arm_reg(&o->o[1], rn, KGENOME_CELL_OF_READ);
		o->op = rn == rd ? KGENOME_CELL_NEG : KGENOME_CELL_OTHER;
	} else if (pc_off && rn == KGENOME_ARM_PC && is_imm && !s &&
		   (opc == 4u || opc == 2u)) {
		/* add/sub rd, pc, #imm - the address, and `adr` is its name */
		o->op = KGENOME_CELL_LEA;
		o->n_op = 2;
		kgenome_arm_mem(&o->o[1], KGENOME_ARM_PC, opc == 4u ? pc_off + (int64_t)tp->imm
						    : pc_off - (int64_t)tp->imm,
			0, KGENOME_CELL_OF_RIPREL);
	} else if (rn == rd && (is_imm || tp->scale == KGENOME_ARM_SH_NONE) &&
		   (o->op == KGENOME_CELL_ADD || o->op == KGENOME_CELL_SUB || o->op == KGENOME_CELL_AND ||
		    o->op == KGENOME_CELL_OR || o->op == KGENOME_CELL_XOR || o->op == KGENOME_CELL_ADC ||
		    o->op == KGENOME_CELL_SBB)) {
		/*
		 * `add r0, r0, #4` IS `r0 += 4`, and is spelt that way: two
		 * operands, destination then source - the form kgenome_cell_state's
		 * constant map computes with. Written as three it reads
		 * o[1] (r0) as the SOURCE and answers `r0 + r0`; and
		 * `sub r0, r0, #1` hits its "a register against itself is
		 * zero" arm and answers 0. Both measured, both silent.
		 */
		o->n_op = 2;
		o->o[1] = *tp;
	} else {
		o->n_op = 3;
		kgenome_arm_reg(&o->o[1], rn, KGENOME_CELL_OF_READ);
		o->o[2] = *tp;
	}

	if (rd != KGENOME_ARM_PC)
		return;

	/* A write to pc is a branch. */
	o->wmask |= KGENOME_ARM_R(KGENOME_ARM_PC);
	if (s) {                                /* movs pc, lr: exception return */
		o->op = KGENOME_CELL_PRIV;
		return;
	}
	o->flags |= KGENOME_CELL_F_INDIRECT;
	if (opc == 13u && !is_imm && tp->scale == KGENOME_ARM_SH_NONE) {
		o->op = tp->reg == KGENOME_ARM_LR ? KGENOME_CELL_RET : KGENOME_CELL_JMP;
		kgenome_arm_clr(o);
		o->n_op = 1;
		kgenome_arm_reg(&o->o[0], tp->reg, KGENOME_CELL_OF_READ);
	} else {
		o->op = KGENOME_CELL_JMP;
		kgenome_arm_clr(o);
	}
}
