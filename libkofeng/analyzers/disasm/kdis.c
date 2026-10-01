/*
 * kdis.c - the engine half of kofmod/kdis.h: decode, translate, and keep a
 * constant map. Read that header first; it says what this is for and why.
 *
 * THREE JOBS AND THEY ARE DELIBERATELY SEPARATE.
 *
 *   DECODE is bddisasm's, and it is the only part of this file that names it.
 *   TRANSLATE turns one decoded instruction into this engine's vocabulary, so
 *     that a module never sees the decoder and does not change when it does.
 *   THE CONSTANT MAP is the "pseudo" in pseudo-emulation: what a register
 *     holds, where that is knowable by reading forwards and nothing else.
 *
 * WHAT THE MAP WILL NOT DO, which is most of what an interpreter does. It does
 * not read memory - a value loaded from anywhere becomes unknown, because the
 * bytes at that address at that moment are not a thing this can know. It does
 * not take branches. It does not model flags. Every one of those is a place
 * where guessing would produce a number that looks like an answer, and the
 * whole value of this over the interpreter is that its answers are either
 * derived or absent.
 */

#include <stdint.h>
#include <string.h>

#include "kofcore.h"
#include "kofmod/kofsig.h"
#include "kofmod/pe.h"
#include "kofmod/elf.h"
#include "kofmod/kdis.h"
#include "kdis.h"
#include "../../disinfect/pzero.h"

#include "bddisasm.h"

/* ---- translation ---------------------------------------------------------
 *
 * bddisasm's instruction id to an opcode class. Everything not named here is
 * KDIS_OTHER, which is an answer and not a failure - see the header.
 */
static uint8_t kdis_class(const INSTRUX *ix)
{
	switch (ix->Instruction) {
	case ND_INS_NOP:    return KDIS_NOP;
	case ND_INS_MOV:    return KDIS_MOV;
	case ND_INS_MOVZX:  return KDIS_MOVZX;
	case ND_INS_MOVSX: case ND_INS_MOVSXD: return KDIS_MOVSX;
	case ND_INS_LEA:    return KDIS_LEA;
	case ND_INS_XCHG:   return KDIS_XCHG;
	case ND_INS_PUSH: case ND_INS_PUSHA: case ND_INS_PUSHF:
		return KDIS_PUSH;
	case ND_INS_POP: case ND_INS_POPA: case ND_INS_POPF:
		return KDIS_POP;
	case ND_INS_ADD:    return KDIS_ADD;
	case ND_INS_SUB:    return KDIS_SUB;
	case ND_INS_ADC:    return KDIS_ADC;
	case ND_INS_SBB:    return KDIS_SBB;
	case ND_INS_AND:    return KDIS_AND;
	case ND_INS_OR:     return KDIS_OR;
	case ND_INS_XOR:    return KDIS_XOR;
	case ND_INS_NOT:    return KDIS_NOT;
	case ND_INS_NEG:    return KDIS_NEG;
	case ND_INS_INC:    return KDIS_INC;
	case ND_INS_DEC:    return KDIS_DEC;
	case ND_INS_CMP:    return KDIS_CMP;
	case ND_INS_TEST:   return KDIS_TEST;
	case ND_INS_SHL:    return KDIS_SHL;
	case ND_INS_SHR:    return KDIS_SHR;
	case ND_INS_SAR:    return KDIS_SAR;
	case ND_INS_ROL:    return KDIS_ROL;
	case ND_INS_ROR:    return KDIS_ROR;
	case ND_INS_RCL:    return KDIS_RCL;
	case ND_INS_RCR:    return KDIS_RCR;
	case ND_INS_MUL:    return KDIS_MUL;
	case ND_INS_IMUL:   return KDIS_IMUL;
	case ND_INS_DIV:    return KDIS_DIV;
	case ND_INS_IDIV:   return KDIS_IDIV;
	case ND_INS_CALLNR: case ND_INS_CALLNI:
	case ND_INS_CALLFD: case ND_INS_CALLFI:
		return KDIS_CALL;
	case ND_INS_JMPNR: case ND_INS_JMPNI:
	case ND_INS_JMPFD: case ND_INS_JMPFI:
		return KDIS_JMP;
	case ND_INS_Jcc:    return KDIS_JCC;
	case ND_INS_LOOP: case ND_INS_LOOPZ: case ND_INS_LOOPNZ:
	case ND_INS_JrCXZ:
		return KDIS_LOOP;
	case ND_INS_RETN: case ND_INS_RETF:
		return KDIS_RET;
	case ND_INS_INT: case ND_INS_INT1: case ND_INS_INT3: case ND_INS_INTO:
		return KDIS_INT;
	case ND_INS_CMOVcc: return KDIS_CMOV;
	case ND_INS_SETcc:  return KDIS_SETCC;
	default:
		break;
	}
	/*
	 * BY CATEGORY FOR THE TWO GROUPS A RULE ASKS ABOUT WHOLESALE. A junk
	 * engine emits x87 by the dozen and a rule walking through junk wants
	 * to say "any FPU instruction" rather than name forty of them; string
	 * operations are the same kind of ask.
	 */
	if (ix->Category == ND_CAT_X87_ALU)
		return KDIS_FPU;
	if (ix->Category == ND_CAT_STRINGOP)
		return KDIS_STRING;
	if (ix->Category == ND_CAT_SYSTEM || ix->Category == ND_CAT_IO)
		return KDIS_PRIV;
	return KDIS_OTHER;
}

/*
 * One operand. Answers 0 for an operand this does not describe - a vector
 * register, a segment - which the caller reports as KDIS_O_NONE rather than
 * pretending it was absent.
 */
static int kdis_operand(const ND_OPERAND *in, struct kdis_operand *out)
{
	memset(out, 0, sizeof *out);
	out->reg = KDIS_REG_NONE;
	out->index = KDIS_REG_NONE;
	out->size = (uint8_t)(in->Size > 255u ? 255u : in->Size);

	switch (in->Type) {
	case ND_OP_REG:
		if (in->Info.Register.Type != ND_REG_GPR)
			return 0;
		out->kind = KDIS_O_REG;
		out->reg = (uint8_t)in->Info.Register.Reg;
		return 1;
	case ND_OP_MEM:
		out->kind = KDIS_O_MEM;
		if (in->Info.Memory.HasBase)
			out->reg = (uint8_t)in->Info.Memory.Base;
		if (in->Info.Memory.HasIndex) {
			out->index = (uint8_t)in->Info.Memory.Index;
			out->scale = in->Info.Memory.Scale
				   ? (uint8_t)in->Info.Memory.Scale : 1u;
		}
		if (in->Info.Memory.HasDisp)
			out->disp = (int64_t)in->Info.Memory.Disp;
		return 1;
	case ND_OP_IMM:
		out->kind = KDIS_O_IMM;
		out->imm = in->Info.Immediate.Imm;
		return 1;
	case ND_OP_OFFS:
		out->kind = KDIS_O_REL;
		out->disp = (int64_t)in->Info.RelativeOffset.Rel;
		return 1;
	default:
		return 0;
	}
}

/* ---- offsets and addresses ----------------------------------------------
 *
 * The cursor is an offset; a branch is computed in addresses. Both directions
 * are needed and only one of them already existed.
 */
static uint64_t kdis_off_to_va(const struct kof_obj_ctx *ctx, uint64_t off)
{
	if (!ctx || !ctx->file_header)
		return KOF_BROKEN;
	if (ctx->format == KOF_FMT_PE) {
		const struct kof_pe_info *p = kof_pe(ctx);
		uint32_t i;

		if (!p->valid)
			return KOF_BROKEN;
		for (i = 0; i < p->sec_count; i++) {
			const struct kof_pe_sec *s = &p->sec[i];

			if (s->file_size && off >= s->file_off &&
			    off - s->file_off < s->file_size)
				return p->image_base + s->mem_rva +
				       (off - s->file_off);
		}
		/* The headers map at the image base, one to one. */
		if (p->sec_count && off < p->sec[0].file_off)
			return p->image_base + off;
		return KOF_BROKEN;
	}
	if (ctx->format == KOF_FMT_ELF) {
		const struct kof_elf_info *e = kof_elf(ctx);
		uint32_t i;

		for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
			const struct kof_elf_seg *s = &e->seg[i];

			if (s->type != 1u || !s->file_size)   /* PT_LOAD */
				continue;
			if (off >= s->file_off &&
			    off - s->file_off < s->file_size)
				return s->mem_addr + (off - s->file_off);
		}
	}
	return KOF_BROKEN;
}

/* ---- the modelled stack -------------------------------------------------
 *
 * See KDIS_STACK in kdis.h for why sixteen slots is the right size and what
 * this is for. Pushing past the end drops the oldest rather than refusing,
 * because a walk that stopped there would stop on ordinary code.
 */
static void stk_push(struct kof_kdis *k, uint64_t v, int known)
{
	unsigned i;

	if (k->stk_n >= KDIS_STACK) {
		for (i = 1; i < KDIS_STACK; i++) {
			k->stk[i - 1u] = k->stk[i];
			if (k->stk_known & (1u << i))
				k->stk_known |= (uint16_t)(1u << (i - 1u));
			else
				k->stk_known &= (uint16_t)~(1u << (i - 1u));
		}
		k->stk_n = KDIS_STACK - 1u;
	}
	k->stk[k->stk_n] = v;
	if (known)
		k->stk_known |= (uint16_t)(1u << k->stk_n);
	else
		k->stk_known &= (uint16_t)~(1u << k->stk_n);
	k->stk_n++;
}

/* The top of the modelled stack. Answers 0 when it is empty or unknown. */
static int stk_top(const struct kof_kdis *k, uint64_t *out)
{
	if (!k->stk_n || !(k->stk_known & (1u << (k->stk_n - 1u))))
		return 0;
	*out = k->stk[k->stk_n - 1u];
	return 1;
}

static int stk_pop(struct kof_kdis *k, uint64_t *out)
{
	int got;

	if (!k->stk_n)
		return 0;
	got = stk_top(k, out);
	k->stk_n--;
	return got;
}

/* ---- the constant map ----------------------------------------------------
 *
 * Updated from the instruction just decoded, and the rule is simple: a
 * destination register becomes known only when every input is known and the
 * operation is one this can compute. Anything else makes it unknown, which is
 * the answer that keeps the map honest.
 */
static void kdis_track(struct kof_kdis *k, const struct kdis_insn *in)
{
	uint8_t d;
	uint64_t a, b;
	int have_b;

	/*
	 * THE STACK FIRST, because the idiom that matters most goes through
	 * it - see KDIS_STACK. A CALL pushes the address of the instruction
	 * after it, which is exactly the cursor, so the POP that follows is
	 * the one place a static walk learns a real address.
	 */
	switch (in->op) {
	case KDIS_CALL:
		if (in->at_va != KOF_BROKEN)
			stk_push(k, in->at_va + in->len, 1);
		else
			stk_push(k, 0, 0);
		return;
	case KDIS_PUSH:
		if (in->n_op && in->o[0].kind == KDIS_O_IMM)
			stk_push(k, in->o[0].imm, 1);
		else if (in->n_op && in->o[0].kind == KDIS_O_REG &&
			 in->o[0].reg < 16u &&
			 (k->known & (1u << in->o[0].reg)))
			stk_push(k, k->reg[in->o[0].reg], 1);
		else
			stk_push(k, 0, 0);
		return;
	case KDIS_POP:
		if (in->n_op && in->o[0].kind == KDIS_O_REG &&
		    in->o[0].reg < 16u) {
			uint64_t v = 0;

			if (stk_pop(k, &v)) {
				k->reg[in->o[0].reg] = v;
				k->known |= (uint16_t)(1u << in->o[0].reg);
			} else {
				k->known &= (uint16_t)~(1u << in->o[0].reg);
			}
		} else {
			uint64_t v;

			(void)stk_pop(k, &v);
		}
		return;
	case KDIS_RET: {
		uint64_t v;

		(void)stk_pop(k, &v);
		return;
	}
	default:
		break;
	}

	if (!in->n_op || in->o[0].kind != KDIS_O_REG)
		return;
	d = in->o[0].reg;
	if (d >= 16u)
		return;

	/* One source, and only three kinds of it can be a number. */
	have_b = 0;
	b = 0;
	if (in->n_op > 1u) {
		if (in->o[1].kind == KDIS_O_IMM) {
			b = in->o[1].imm;
			have_b = 1;
		} else if (in->o[1].kind == KDIS_O_REG &&
			   in->o[1].reg < 16u &&
			   (k->known & (1u << in->o[1].reg))) {
			b = k->reg[in->o[1].reg];
			have_b = 1;
		}
	}
	a = k->reg[d];

	switch (in->op) {
	case KDIS_MOV:
		if (have_b) {
			k->reg[d] = b;
			k->known |= (uint16_t)(1u << d);
		} else {
			k->known &= (uint16_t)~(1u << d);
		}
		return;
	case KDIS_ADD: case KDIS_SUB: case KDIS_AND:
	case KDIS_OR:  case KDIS_XOR:
		if (!have_b || !(k->known & (1u << d))) {
			k->known &= (uint16_t)~(1u << d);
			return;
		}
		switch (in->op) {
		case KDIS_ADD: k->reg[d] = a + b; break;
		case KDIS_SUB: k->reg[d] = a - b; break;
		case KDIS_AND: k->reg[d] = a & b; break;
		case KDIS_OR:  k->reg[d] = a | b; break;
		default:       k->reg[d] = a ^ b; break;
		}
		return;
	case KDIS_INC: case KDIS_DEC:
		if (!(k->known & (1u << d)))
			return;
		k->reg[d] = in->op == KDIS_INC ? a + 1u : a - 1u;
		return;
	case KDIS_NOT:
		if (k->known & (1u << d))
			k->reg[d] = ~a;
		return;
	case KDIS_NEG:
		if (k->known & (1u << d))
			k->reg[d] = (uint64_t)0 - a;
		return;
	case KDIS_CMP: case KDIS_TEST: case KDIS_PUSH:
		return;                         /* no destination written */
	default:
		/*
		 * EVERYTHING ELSE CLEARS IT, including the loads. `mov eax,
		 * [esi]` is a KDIS_MOV whose source is memory and falls out of
		 * the MOV arm above with have_b clear; anything that reaches
		 * here wrote the register in a way this did not follow, and the
		 * only safe record of that is "unknown".
		 */
		k->known &= (uint16_t)~(1u << d);
		return;
	}
}

/* ---- the cursor ---------------------------------------------------------- */

int kof_kdis_seek(struct kof_kdis *k, uint64_t off, int keep)
{
	if (!k)
		return 0;
	k->at = off;
	k->open = 1;
	if (!keep) {
		memset(k->reg, 0, sizeof k->reg);
		k->known = 0;
		k->stk_n = 0;
		k->stk_known = 0;
	}
	return 1;
}

int kof_kdis_reg(const struct kof_kdis *k, uint8_t r, uint64_t *out)
{
	if (!k || !out || r >= 16u || !(k->known & (1u << r)))
		return 0;
	*out = k->reg[r];
	return 1;
}

int kof_kdis_next(struct kof_kdis *k, const struct kof_obj_ctx *ctx,
		  const uint8_t *base, uint64_t size, struct kdis_insn *out)
{
	INSTRUX ix;
	uint64_t left;
	unsigned i, n = 0;
	uint8_t code, data;

	if (!k || !k->open || !ctx || !base || !out || k->at >= size)
		return 0;
	left = size - k->at;
	if (left > 16u)
		left = 16u;             /* the longest an instruction can be */

	/*
	 * THE WIDTH IS THE OBJECT'S, not a guess. A 32-bit body decoded as
	 * 64-bit reads its REX-looking bytes as prefixes and every length
	 * after that is wrong - which is not a wrong answer, it is a wrong
	 * walk.
	 */
	if (ctx->arch == KOF_ARCH_X86_64) {
		code = ND_CODE_64;
		data = ND_DATA_64;
	} else {
		code = ND_CODE_32;
		data = ND_DATA_32;
	}
	if (!ND_SUCCESS(NdDecodeEx(&ix, (const ND_UINT8 *)(base + k->at),
				   (ND_SIZET)left, code, data)))
		return 0;

	memset(out, 0, sizeof *out);
	out->op = kdis_class(&ix);
	out->len = ix.Length;
	out->at = k->at;
	out->at_va = kdis_off_to_va(ctx, k->at);
	out->target = KOF_BROKEN;
	out->target_va = KOF_BROKEN;
	if (out->op == KDIS_JCC || out->op == KDIS_CMOV ||
	    out->op == KDIS_SETCC)
		out->cond = (uint8_t)ix.Condition;

	for (i = 0; i < ix.OperandsCount && n < 3u; i++) {
		/*
		 * THE IMPLICIT ONES ARE DROPPED. bddisasm reports the flags
		 * register, the stack pointer behind a push and the
		 * instruction pointer behind a branch; a rule that had to skip
		 * those would be written against the decoder. Flags.IsDefault
		 * is exactly the decoder saying "the encoding did not name
		 * this".
		 */
		if (ix.Operands[i].Flags.IsDefault)
			continue;
		if (!kdis_operand(&ix.Operands[i], &out->o[n]))
			out->o[n].kind = KDIS_O_NONE;
		n++;
	}
	out->n_op = (uint8_t)n;

	/*
	 * WHERE A BRANCH GOES, resolved here because it is arithmetic on an
	 * address and a module works in offsets. An indirect branch keeps
	 * KOF_BROKEN: `jmp eax` has a target, and this is not the thing that
	 * can know it.
	 */
	if ((out->op == KDIS_JMP || out->op == KDIS_CALL ||
	     out->op == KDIS_JCC || out->op == KDIS_LOOP) &&
	    n && out->o[0].kind == KDIS_O_REL &&
	    out->at_va != KOF_BROKEN) {
		out->target_va = out->at_va + out->len +
				 (uint64_t)out->o[0].disp;
		out->target = kof_pz_addr_to_off(ctx, out->target_va);
	}

	/*
	 * AND AN INDIRECT BRANCH RESOLVED FROM WHAT IS KNOWN, which is the
	 * whole difference between decoding and pseudo-emulation.
	 *
	 * `jmp eax` has no target in the encoding, and a walk that gives up
	 * there gives up on every polymorphic stub - they all end by computing
	 * an address and going to it. When the constant map holds that
	 * register, or the modelled stack holds what a `ret` will take, the
	 * target IS known and saying so is not a guess.
	 *
	 * DONE BEFORE kdis_track, because a RET's target is the value still on
	 * the stack - tracking pops it.
	 */
	if (out->target == KOF_BROKEN) {
		uint64_t v = 0;
		int have = 0;

		if (out->op == KDIS_RET)
			have = stk_top(k, &v);
		else if ((out->op == KDIS_JMP || out->op == KDIS_CALL) && n &&
			 out->o[0].kind == KDIS_O_REG && out->o[0].reg < 16u)
			have = kof_kdis_reg(k, out->o[0].reg, &v);
		if (have) {
			out->target_va = v;
			out->target = kof_pz_addr_to_off(ctx, v);
		}
	}

	kdis_track(k, out);
	k->at += out->len;
	return 1;
}
