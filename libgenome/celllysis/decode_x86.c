/*
 * decode_x86.c - x86 and x86-64 into celllysis's one instruction form.
 *
 * The decoding itself is genotype's (libgenome/genotype/x86); this is the
 * translation, and it is the ONLY place in the engine that reads one of its
 * instructions. Everything downstream reads struct cell_insn, so a decoder
 * that renames an instruction class is applied here and nowhere else - see
 * decode.h for why that mattered enough to write this.
 *
 * ONLY WHAT THE SWEEP READS IS BUILT. genotype finds the instruction first and
 * builds operands when asked; the sweep asks for the explicit ones (at most
 * three are kept) and takes the registers an instruction writes WITHOUT naming
 * them from a mask the decoder keeps per opcode, so the stack pointer a push
 * moves or the rdx a mul fills is never built as an operand at all. MEASURED
 * over 44.7 M instructions, building every operand was 15 of the 41 ns.
 */
#include <string.h>

/* KOF_BROKEN - the sentinel cell.h names for a target there is not. */
#include "kofmod/kofsig.h"
#include "decode.h"
#include "gpr.h"
#include <x86/x86.h>

/* ---- THE CLASS ---------------------------------------------------------- */
/*
 * the decoder names roughly sixteen hundred instructions and the sweep asks
 * about thirty-eight of them. The rest are not "unknown": they are
 * instructions whose CLASS is all anyone downstream needs, and CELL_OTHER
 * with a correct wmask is a complete answer for them.
 */

static uint8_t class_slow(unsigned id)
{
	switch (id) {
	case GT_X86_I_NOP:      return CELL_NOP;
	case GT_X86_I_MOV:      return CELL_MOV;
	case GT_X86_I_MOVZX:    return CELL_MOVZX;
	case GT_X86_I_MOVSX:
	case GT_X86_I_MOVSXD:   return CELL_MOVSX;
	case GT_X86_I_LEA:      return CELL_LEA;
	case GT_X86_I_XCHG:     return CELL_XCHG;
	case GT_X86_I_PUSH:     return CELL_PUSH;
	case GT_X86_I_POP:      return CELL_POP;
	case GT_X86_I_ADD:      return CELL_ADD;
	case GT_X86_I_SUB:      return CELL_SUB;
	case GT_X86_I_ADC:      return CELL_ADC;
	case GT_X86_I_SBB:      return CELL_SBB;
	case GT_X86_I_AND:      return CELL_AND;
	case GT_X86_I_OR:       return CELL_OR;
	case GT_X86_I_XOR:      return CELL_XOR;
	case GT_X86_I_NOT:      return CELL_NOT;
	case GT_X86_I_NEG:      return CELL_NEG;
	case GT_X86_I_INC:      return CELL_INC;
	case GT_X86_I_DEC:      return CELL_DEC;
	case GT_X86_I_CMP:      return CELL_CMP;
	case GT_X86_I_TEST:     return CELL_TEST;
	case GT_X86_I_SHL:      return CELL_SHL;
	case GT_X86_I_SHR:      return CELL_SHR;
	case GT_X86_I_SAR:      return CELL_SAR;
	case GT_X86_I_ROL:      return CELL_ROL;
	case GT_X86_I_ROR:      return CELL_ROR;
	case GT_X86_I_RCL:      return CELL_RCL;
	case GT_X86_I_RCR:      return CELL_RCR;
	case GT_X86_I_MUL:      return CELL_MUL;
	case GT_X86_I_IMUL:     return CELL_IMUL;
	case GT_X86_I_DIV:      return CELL_DIV;
	case GT_X86_I_IDIV:     return CELL_IDIV;
	case GT_X86_I_CALLNR:
	case GT_X86_I_CALLNI:
	case GT_X86_I_CALLFI:
	case GT_X86_I_CALLFD:   return CELL_CALL;
	case GT_X86_I_JMPNR:
	case GT_X86_I_JMPNI:
	case GT_X86_I_JMPFI:
	case GT_X86_I_JMPFD:    return CELL_JMP;
	case GT_X86_I_Jcc:      return CELL_JCC;
	case GT_X86_I_LOOP:
	case GT_X86_I_LOOPNZ:
	case GT_X86_I_LOOPZ:    return CELL_LOOP;
	case GT_X86_I_RETN:
	case GT_X86_I_RETF:     return CELL_RET;
	case GT_X86_I_INT:
	case GT_X86_I_INT1:
	case GT_X86_I_INT3:
	case GT_X86_I_INTO:     return CELL_INT;
	case GT_X86_I_SYSCALL:
	case GT_X86_I_SYSENTER: return CELL_SYSCALL;
	case GT_X86_I_CMOVcc:   return CELL_CMOV;
	case GT_X86_I_SETcc:    return CELL_SETCC;
	case GT_X86_I_CBW:
	case GT_X86_I_CWDE:
	case GT_X86_I_CDQE:
	case GT_X86_I_CWD:
	case GT_X86_I_CDQ:
	case GT_X86_I_CQO:      return CELL_WIDEN;
	/*
	 * WHICH special register, in `cond` - the field is the condition
	 * code of a JCC and a MOV has none, so it is free here. A module
	 * writing cr0 is a rootkit turning write protection off; one
	 * touching a debug register is doing something else entirely, and
	 * the class alone cannot tell them apart.
	 */
	case GT_X86_I_MOV_CR:
	case GT_X86_I_MOV_DR:
	case GT_X86_I_MOV_TR:   return CELL_MOV_SPECIAL;
	case GT_X86_I_IRET:     return CELL_IRET;
	case GT_X86_I_UD0:
	case GT_X86_I_UD1:
	case GT_X86_I_UD2:      return CELL_UD;
	case GT_X86_I_MOVS:
	case GT_X86_I_STOS:
	case GT_X86_I_LODS:
	case GT_X86_I_SCAS:
	case GT_X86_I_CMPS:     return CELL_STRING;
	default:              break;
	}
	return CELL_OTHER;
}

/*
 * AND THE ANSWER IS LOOKED UP, NOT SEARCHED.
 *
 * The switch above is sixty cases over values scattered through sixteen
 * hundred, so the compiler builds a chain of comparisons and the cost of
 * recognising an instruction depends on where its case was written. That
 * is the one thing the decoder's own decoder refuses to do - it indexes a
 * table by the opcode and walks tables from there - and on a path this
 * hot the same rule applies to us.
 *
 * Filled once, from the switch, so there is exactly one statement of
 * what each instruction is. Two threads racing here would compute the
 * same bytes.
 */
static uint8_t g_cls[GT_X86_I__COUNT];
static int g_cls_ready;

static uint8_t class_of(unsigned id, unsigned cat)
{
	if (!g_cls_ready) {
		uint32_t i;

		for (i = 0; i < (uint32_t)GT_X86_I__COUNT; i++)
			g_cls[i] = class_slow(i);
		g_cls_ready = 1;
	}
	if (id >= (unsigned)GT_X86_I__COUNT)
		return CELL_OTHER;
	/* The x87 test needs the category, which the table cannot hold. */
	if (g_cls[id] == CELL_OTHER && cat == GT_X86_C_X87_ALU)
		return CELL_FPU;
	return g_cls[id];
}

/*
 * IS THE BRANCH THROUGH SOMETHING RATHER THAN TO SOMEWHERE - the one
 * difference between `call printf` and `call *%eax`, and the sweep turns on
 * it everywhere.
 */
static int is_indirect(unsigned id)
{
	switch (id) {
	case GT_X86_I_CALLNI: case GT_X86_I_CALLFI:
	case GT_X86_I_JMPNI:  case GT_X86_I_JMPFI:
		return 1;
	default:
		return 0;
	}
}

static int is_far(unsigned id)
{
	switch (id) {
	case GT_X86_I_RETF: case GT_X86_I_JMPFI: case GT_X86_I_JMPFD:
	case GT_X86_I_CALLFI: case GT_X86_I_CALLFD:
		return 1;
	default:
		return 0;
	}
}

uint32_t cell_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			unsigned bits, struct cell_insn *out)
{
	struct gt_x86_insn ix;
	uint32_t i, nexp, k = 0;

	if (!p || !n || !out)
		return 0;
	if (gt_x86_decode(&ix, p, n, bits == 32 ? 32 : 64) != GT_OK)
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
	out->op = class_of(ix.id, gt_x86_cat(&ix));
	out->len = ix.len;
	out->n_op = 0;
	out->flags = 0;
	out->wmask = 0;
	out->at_va = va;
	out->at = va;
	out->cond = (uint8_t)gt_x86_cond(&ix);
	if (out->op == CELL_MOV_SPECIAL)
		out->cond = ix.id == GT_X86_I_MOV_CR ? CELL_SR_CR
			  : ix.id == GT_X86_I_MOV_DR ? CELL_SR_DR
						     : CELL_SR_TR;
	/*
	 * KOF_BROKEN AND NOT (uint64_t)-1, WHICH IS A DIFFERENT NUMBER.
	 *
	 * cell.h says "no target" is KOF_BROKEN, and KOF_BROKEN is
	 * UINT64_MAX - 1. Writing UINT64_MAX here meant every reader's
	 * `target_va != KOF_BROKEN` was true for EVERY instruction, branch
	 * or not. MEASURED: kof_cell_next then called kof_pz_addr_to_off -
	 * a linear walk of the segment table - 1,327,512 times over a 12 MB
	 * subset where only 273,617 instructions have a relative target,
	 * and that one wasted call was 6.2% of the whole scan.
	 *
	 * It did not produce a wrong answer, which is why it survived: the
	 * walk found no segment holding UINT64_MAX and returned KOF_BROKEN,
	 * so `target` came out right by the long way round. `target_va` did
	 * not - it kept UINT64_MAX, and a reader testing IT against
	 * KOF_BROKEN still sees a target that is not there.
	 */
	out->target = KOF_BROKEN;
	out->target_va = KOF_BROKEN;
	if (is_far(ix.id))
		out->flags |= CELL_F_FAR;
	if (is_indirect(ix.id))
		out->flags |= CELL_F_INDIRECT;
	if (ix.rep)
		out->flags |= CELL_F_REP;
	/* The registers it writes without naming: from the opcode, not the operands. */
	out->wmask = gt_x86_wgpr(&ix);

	nexp = gt_x86_nexp(&ix);
	for (i = 0; i < nexp; i++) {
		struct gt_x86_op o;
		struct cell_operand *d;

		gt_x86_operand(&ix, i, &o);
		/*
		 * EVERY WRITTEN REGISTER GOES IN THE MASK, named or not -
		 * see cell_insn.wmask. This is the whole reason the mask
		 * exists: the decoder reports the implicit ones and a
		 * hand-written decoder does not, so the consumer must not
		 * have to care which. The implicit ones are already in
		 * (gt_x86_wgpr); these are the ones the instruction names.
		 */
		if ((o.acc & GT_X86_ACC_W) && o.type == GT_X86_OP_REG &&
		    o.rtype == GT_X86_REG_GPR && o.reg < 64u)
			out->wmask |= 1ull << gpr_of(&o);

		/* Only the first three become operands - see cell_insn. */
		if (k >= 3u)
			continue;
		d = &out->o[k];
		d->kind = CELL_O_NONE;
		d->reg = CELL_REG_NONE;
		d->index = CELL_REG_NONE;
		d->seg = CELL_REG_NONE;
		d->scale = 0;
		d->disp = 0;
		d->imm = 0;
		d->size = (uint8_t)o.size;
		d->flags = (uint8_t)(((o.acc & GT_X86_ACC_W) ? CELL_OF_WRITE : 0u) |
				     ((o.acc & GT_X86_ACC_R) ? CELL_OF_READ : 0u) |
				     ((o.type == GT_X86_OP_REG && o.high8) ?
				      CELL_OF_HIGH8 : 0u));
		switch (o.type) {
		case GT_X86_OP_REG:
			if (o.rtype != GT_X86_REG_GPR)
				continue;       /* not one the sweep tracks */
			d->kind = CELL_O_REG;
			d->reg = (uint8_t)gpr_of(&o);
			break;
		case GT_X86_OP_IMM:
			d->kind = CELL_O_IMM;
			d->imm = (uint64_t)o.v;
			break;
		case GT_X86_OP_REL:
			d->kind = CELL_O_REL;
			d->imm = (uint64_t)o.v;
			out->target_va = va + ix.len +
					 (uint64_t)(int64_t)(int32_t)o.v;
			out->target = out->target_va;
			break;
		case GT_X86_OP_MEM:
			d->kind = CELL_O_MEM;
			if (o.mf & GT_X86_M_BASE)
				d->reg = o.base;
			if (o.mf & GT_X86_M_INDEX) {
				d->index = o.index;
				d->scale = o.scale;
			}
			if (o.mf & GT_X86_M_DISP)
				d->disp = o.v;
			if (o.mf & GT_X86_M_RIPREL)
				d->flags |= CELL_OF_RIPREL;
			if (o.mf & GT_X86_M_SEG)
				d->seg = o.seg;
			break;
		default:
			continue;
		}
		k++;
	}
	out->n_op = (uint8_t)k;
	/* And the ones this instruction does not have say so. */
	while (k < 3u) {
		out->o[k].kind = CELL_O_NONE;
		out->o[k].reg = CELL_REG_NONE;
		out->o[k].index = CELL_REG_NONE;
		out->o[k].seg = CELL_REG_NONE;
		out->o[k].flags = 0;
		out->o[k].imm = 0;
		out->o[k].disp = 0;
		k++;
	}
	return ix.len;
}
