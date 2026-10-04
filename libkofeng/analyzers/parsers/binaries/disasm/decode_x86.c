/*
 * decode_x86.c - x86 and x86-64 into the engine's one instruction form.
 *
 * The decoding itself is bddisasm's; this is the translation, and it is the
 * ONLY place in the engine that reads an INSTRUX. Everything downstream
 * reads struct kdis_insn, so a decoder upgrade that renames an instruction
 * class is applied here and nowhere else - see decode.h for why that
 * mattered enough to write this.
 */
#include <string.h>

#include "decode.h"
#include "gpr.h"

/* ---- THE CLASS ---------------------------------------------------------- */
/*
 * bddisasm names roughly sixteen hundred instructions and the sweep asks
 * about thirty-eight of them. The rest are not "unknown": they are
 * instructions whose CLASS is all anyone downstream needs, and KDIS_OTHER
 * with a correct wmask is a complete answer for them.
 */

static uint8_t class_slow(const INSTRUX *ix)
{
	switch (ix->Instruction) {
	case ND_INS_NOP:      return KDIS_NOP;
	case ND_INS_MOV:      return KDIS_MOV;
	case ND_INS_MOVZX:    return KDIS_MOVZX;
	case ND_INS_MOVSX:
	case ND_INS_MOVSXD:   return KDIS_MOVSX;
	case ND_INS_LEA:      return KDIS_LEA;
	case ND_INS_XCHG:     return KDIS_XCHG;
	case ND_INS_PUSH:     return KDIS_PUSH;
	case ND_INS_POP:      return KDIS_POP;
	case ND_INS_ADD:      return KDIS_ADD;
	case ND_INS_SUB:      return KDIS_SUB;
	case ND_INS_ADC:      return KDIS_ADC;
	case ND_INS_SBB:      return KDIS_SBB;
	case ND_INS_AND:      return KDIS_AND;
	case ND_INS_OR:       return KDIS_OR;
	case ND_INS_XOR:      return KDIS_XOR;
	case ND_INS_NOT:      return KDIS_NOT;
	case ND_INS_NEG:      return KDIS_NEG;
	case ND_INS_INC:      return KDIS_INC;
	case ND_INS_DEC:      return KDIS_DEC;
	case ND_INS_CMP:      return KDIS_CMP;
	case ND_INS_TEST:     return KDIS_TEST;
	case ND_INS_SHL:      return KDIS_SHL;
	case ND_INS_SHR:      return KDIS_SHR;
	case ND_INS_SAR:      return KDIS_SAR;
	case ND_INS_ROL:      return KDIS_ROL;
	case ND_INS_ROR:      return KDIS_ROR;
	case ND_INS_RCL:      return KDIS_RCL;
	case ND_INS_RCR:      return KDIS_RCR;
	case ND_INS_MUL:      return KDIS_MUL;
	case ND_INS_IMUL:     return KDIS_IMUL;
	case ND_INS_DIV:      return KDIS_DIV;
	case ND_INS_IDIV:     return KDIS_IDIV;
	case ND_INS_CALLNR:
	case ND_INS_CALLNI:
	case ND_INS_CALLFI:
	case ND_INS_CALLFD:   return KDIS_CALL;
	case ND_INS_JMPNR:
	case ND_INS_JMPNI:
	case ND_INS_JMPFI:
	case ND_INS_JMPFD:    return KDIS_JMP;
	case ND_INS_Jcc:      return KDIS_JCC;
	case ND_INS_LOOP:
	case ND_INS_LOOPNZ:
	case ND_INS_LOOPZ:    return KDIS_LOOP;
	case ND_INS_RETN:
	case ND_INS_RETF:     return KDIS_RET;
	case ND_INS_INT:
	case ND_INS_INT1:
	case ND_INS_INT3:
	case ND_INS_INTO:     return KDIS_INT;
	case ND_INS_SYSCALL:
	case ND_INS_SYSENTER: return KDIS_SYSCALL;
	case ND_INS_CMOVcc:   return KDIS_CMOV;
	case ND_INS_SETcc:    return KDIS_SETCC;
	case ND_INS_CBW:
	case ND_INS_CWDE:
	case ND_INS_CDQE:
	case ND_INS_CWD:
	case ND_INS_CDQ:
	case ND_INS_CQO:      return KDIS_WIDEN;
	/*
	 * WHICH special register, in `cond` - the field is the condition
	 * code of a JCC and a MOV has none, so it is free here. A module
	 * writing cr0 is a rootkit turning write protection off; one
	 * touching a debug register is doing something else entirely, and
	 * the class alone cannot tell them apart.
	 */
	case ND_INS_MOV_CR:
	case ND_INS_MOV_DR:
	case ND_INS_MOV_TR:   return KDIS_MOV_SPECIAL;
	case ND_INS_IRET:     return KDIS_IRET;
	case ND_INS_UD0:
	case ND_INS_UD1:
	case ND_INS_UD2:      return KDIS_UD;
	case ND_INS_MOVS:
	case ND_INS_STOS:
	case ND_INS_LODS:
	case ND_INS_SCAS:
	case ND_INS_CMPS:     return KDIS_STRING;
	default:              break;
	}
	return KDIS_OTHER;
}

/*
 * AND THE ANSWER IS LOOKED UP, NOT SEARCHED.
 *
 * The switch above is sixty cases over values scattered through sixteen
 * hundred, so the compiler builds a chain of comparisons and the cost of
 * recognising an instruction depends on where its case was written. That
 * is the one thing bddisasm's own decoder refuses to do - it indexes a
 * table by the opcode and walks tables from there - and on a path this
 * hot the same rule applies to us.
 *
 * Filled once, from the switch, so there is exactly one statement of
 * what each instruction is. Two threads racing here would compute the
 * same bytes.
 */
static uint8_t g_cls[ND_INS_XTEST + 1u];
static int g_cls_ready;

static uint8_t class_of(const INSTRUX *ix)
{
	if (!g_cls_ready) {
		INSTRUX t;
		uint32_t i;

		memset(&t, 0, sizeof t);
		for (i = 0; i <= (uint32_t)ND_INS_XTEST; i++) {
			t.Instruction = (ND_INS_CLASS)i;
			g_cls[i] = class_slow(&t);
		}
		g_cls_ready = 1;
	}
	if ((uint32_t)ix->Instruction > (uint32_t)ND_INS_XTEST)
		return KDIS_OTHER;
	/* The x87 test needs the category, which the table cannot hold. */
	if (g_cls[ix->Instruction] == KDIS_OTHER &&
	    ix->Category == ND_CAT_X87_ALU)
		return KDIS_FPU;
	return g_cls[ix->Instruction];
}

/*
 * IS THE BRANCH THROUGH SOMETHING RATHER THAN TO SOMEWHERE - the one
 * difference between `call printf` and `call *%eax`, and the sweep turns on
 * it everywhere.
 */
static int is_indirect(const INSTRUX *ix)
{
	switch (ix->Instruction) {
	case ND_INS_CALLNI: case ND_INS_CALLFI:
	case ND_INS_JMPNI:  case ND_INS_JMPFI:
		return 1;
	default:
		return 0;
	}
}

static int is_far(const INSTRUX *ix)
{
	switch (ix->Instruction) {
	case ND_INS_RETF: case ND_INS_JMPFI: case ND_INS_JMPFD:
	case ND_INS_CALLFI: case ND_INS_CALLFD:
		return 1;
	default:
		return 0;
	}
}

uint32_t kof_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			unsigned bits, struct kdis_insn *out)
{
	INSTRUX ix;
	uint32_t i, k = 0;

	if (!p || !n || !out)
		return 0;
	if (!ND_SUCCESS(NdDecodeEx(&ix, p, n,
				   bits == 32 ? ND_CODE_32 : ND_CODE_64,
				   bits == 32 ? ND_DATA_32 : ND_DATA_64)))
		return 0;

	/*
	 * EVERY FIELD WRITTEN, NOT ZEROED THEN WRITTEN.
	 *
	 * This cleared the whole structure first, which is a hundred and
	 * twenty bytes per instruction on a path that runs tens of
	 * millions of times - MEASURED on one 7 MB object, the
	 * translation cost 38% on top of the decode itself, and the clear
	 * was most of it. The operands are cleared one at a time as they
	 * are reached, and the ones past the end are marked absent at the
	 * foot, so nothing is written twice and nothing is left stale.
	 */
	out->op = class_of(&ix);
	out->len = (uint8_t)ix.Length;
	out->n_op = 0;
	out->flags = 0;
	out->wmask = 0;
	out->at_va = va;
	out->at = va;
	out->cond = (uint8_t)ix.Condition;
	if (out->op == KDIS_MOV_SPECIAL)
		out->cond = ix.Instruction == ND_INS_MOV_CR ? KDIS_SR_CR
			  : ix.Instruction == ND_INS_MOV_DR ? KDIS_SR_DR
							    : KDIS_SR_TR;
	out->target = (uint64_t)-1;
	out->target_va = (uint64_t)-1;
	if (is_far(&ix))
		out->flags |= KDIS_F_FAR;
	if (is_indirect(&ix))
		out->flags |= KDIS_F_INDIRECT;
	if (ix.Rep)
		out->flags |= KDIS_F_REP;

	for (i = 0; i < ix.OperandsCount; i++) {
		const ND_OPERAND *o = &ix.Operands[i];
		struct kdis_operand *d;

		/*
		 * EVERY WRITTEN REGISTER GOES IN THE MASK, named or not -
		 * see kdis_insn.wmask. This is the whole reason the mask
		 * exists: bddisasm reports the implicit ones and a
		 * hand-written decoder does not, so the consumer must not
		 * have to care which.
		 */
		if (o->Access.Write && o->Type == ND_OP_REG &&
		    o->Info.Register.Type == ND_REG_GPR &&
		    o->Info.Register.Reg < 64u)
			out->wmask |= 1ull << gpr_of(o);

		/* Only the explicit ones become operands - see kdis_insn. */
		if (o->Flags.IsDefault || k >= 3u)
			continue;
		d = &out->o[k];
		d->kind = KDIS_O_NONE;
		d->reg = KDIS_REG_NONE;
		d->index = KDIS_REG_NONE;
		d->seg = KDIS_REG_NONE;
		d->scale = 0;
		d->disp = 0;
		d->imm = 0;
		d->size = (uint8_t)o->Size;
		d->flags = (uint8_t)((o->Access.Write ? KDIS_OF_WRITE : 0u) |
				     (o->Access.Read ? KDIS_OF_READ : 0u) |
				     ((o->Type == ND_OP_REG &&
				       o->Info.Register.IsHigh8) ?
				      KDIS_OF_HIGH8 : 0u));
		switch (o->Type) {
		case ND_OP_REG:
			if (o->Info.Register.Type != ND_REG_GPR)
				continue;       /* not one the sweep tracks */
			d->kind = KDIS_O_REG;
			d->reg = (uint8_t)gpr_of(o);
			break;
		case ND_OP_IMM:
			d->kind = KDIS_O_IMM;
			d->imm = o->Info.Immediate.Imm;
			break;
		case ND_OP_OFFS:
			d->kind = KDIS_O_REL;
			d->imm = o->Info.RelativeOffset.Rel;
			out->target_va = va + ix.Length +
					 (uint64_t)(int64_t)
					 (int32_t)o->Info.RelativeOffset.Rel;
			out->target = out->target_va;
			break;
		case ND_OP_MEM:
			d->kind = KDIS_O_MEM;
			if (o->Info.Memory.HasBase)
				d->reg = (uint8_t)o->Info.Memory.Base;
			if (o->Info.Memory.HasIndex) {
				d->index = (uint8_t)o->Info.Memory.Index;
				d->scale = (uint8_t)o->Info.Memory.Scale;
			}
			if (o->Info.Memory.HasDisp)
				d->disp = (int64_t)o->Info.Memory.Disp;
			if (o->Info.Memory.IsRipRel)
				d->flags |= KDIS_OF_RIPREL;
			if (o->Info.Memory.HasSeg)
				d->seg = (uint8_t)o->Info.Memory.Seg;
			break;
		default:
			continue;
		}
		k++;
	}
	out->n_op = (uint8_t)k;
	/* And the ones this instruction does not have say so. */
	while (k < 3u) {
		out->o[k].kind = KDIS_O_NONE;
		out->o[k].reg = KDIS_REG_NONE;
		out->o[k].index = KDIS_REG_NONE;
		out->o[k].seg = KDIS_REG_NONE;
		out->o[k].flags = 0;
		out->o[k].imm = 0;
		out->o[k].disp = 0;
		k++;
	}
	return ix.Length;
}
