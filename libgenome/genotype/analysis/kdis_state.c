/*
 * kdis_state.c - the constant map and the modelled stack: what the registers
 * hold, where that is knowable by reading forwards and nothing else.
 *
 * THIS IS THE "PSEUDO" IN PSEUDO-EMULATION, and it is decode-level: it reads one
 * decoded instruction (struct kdis_insn) and nothing about the object the code
 * sits in. Where the code came from, how an offset becomes an address and what
 * a number means are the engine's (libkofeng/analyzers/nucleo/kdis.c).
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

#include "kofmod/kofsig.h"
#include "kofmod/kdis.h"
#include "kdis_state.h"

/* ---- the modelled stack -------------------------------------------------
 *
 * See KDIS_STACK in kdis.h for why sixteen slots is the right size and what
 * this is for. Pushing past the end drops the oldest rather than refusing,
 * because a walk that stopped there would stop on ordinary code.
 */
static void stk_push(struct kdis_state *k, uint64_t v, int known)
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
int kdis_state_stack_top(const struct kdis_state *k, uint64_t *out)
{
	if (!k->stk_n || !(k->stk_known & (1u << (k->stk_n - 1u))))
		return 0;
	*out = k->stk[k->stk_n - 1u];
	return 1;
}

static int stk_pop(struct kdis_state *k, uint64_t *out)
{
	int got;

	if (!k->stk_n)
		return 0;
	got = kdis_state_stack_top(k, out);
	k->stk_n--;
	return got;
}

/*
 * FORGET EVERY REGISTER THIS INSTRUCTION WRITES, except the one the caller
 * has just worked out for itself.
 *
 * The decoder reports the implicit writes in `wmask` - see kdis_insn - and
 * for a while nothing read it: the map cleared the FIRST OPERAND instead.
 * That is wrong in both directions at once, and `mul ebx` shows both:
 * the operand is READ, not written, so a known ebx was thrown away, while
 * eax and edx - which the instruction really does write - kept whatever
 * they held. MEASURED: msfvenom's i386 payloads set their socketcall
 * operation with `xor ebx,ebx; mul ebx; inc ebx`, so every one of them
 * lost its whole network half.
 */
static void kdis_forget_written(struct kdis_state *k, const struct kdis_insn *in,
				int keep_reg)
{
	uint8_t r;

	for (r = 0; r < 16u; r++) {
		if (!(in->wmask & (1ull << r)) || (int)r == keep_reg)
			continue;
		k->known &= (uint16_t)~(1u << r);
	}
}

/*
 * WRITE A VALUE OF `size` BYTES INTO A REGISTER, which is not the same as
 * writing the register.
 *
 * Eight and four bytes replace it - a 32-bit write clears the top half on
 * x86-64 and there is no top half anywhere else, so one case covers both.
 * One and two bytes REPLACE A PART and leave the rest, which means the rest
 * has to be known or the answer is not. Writing the narrow value as if it
 * were the whole register is the one outcome that must not happen: it is a
 * number, it looks like an answer, and it is wrong.
 */
static void kdis_put(struct kdis_state *k, uint8_t d, const struct kdis_operand *o,
		     uint64_t v)
{
	uint64_t old;

	if (d >= 16u)
		return;
	if (o->size >= 4u || o->size == 0u) {
		k->reg[d] = v;
		k->known |= (uint16_t)(1u << d);
		return;
	}
	if (!(k->known & (1u << d))) {
		k->known &= (uint16_t)~(1u << d);
		return;
	}
	old = k->reg[d];
	if (o->size == 2u)
		k->reg[d] = (old & ~(uint64_t)0xffff) | (v & 0xffffu);
	else if (o->flags & KDIS_OF_HIGH8)
		k->reg[d] = (old & ~(uint64_t)0xff00) | ((v & 0xffu) << 8);
	else
		k->reg[d] = (old & ~(uint64_t)0xff) | (v & 0xffu);
	k->known |= (uint16_t)(1u << d);
}

/* ---- the constant map ----------------------------------------------------
 *
 * Updated from the instruction just decoded, and the rule is simple: a
 * destination register becomes known only when every input is known and the
 * operation is one this can compute. Anything else makes it unknown, which is
 * the answer that keeps the map honest.
 */
void kdis_state_track(struct kdis_state *k, const struct kdis_insn *in)
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

	/*
	 * CDQ AND CQO NAME NO OPERAND AT ALL, so they have to be answered
	 * before the test below sends everything operand-less away. They fill
	 * the second register with the sign bit of the first, which makes it
	 * exactly zero for any non-negative value - how a payload writes a
	 * zero argument without spending an instruction on it. A value with
	 * the sign bit set is left unknown rather than extended, because the
	 * width that was extended is not recorded here.
	 */
	if (in->op == KDIS_WIDEN) {
		if ((in->wmask & (1ull << KDIS_REG_DX)) &&
		    (k->known & (1u << KDIS_REG_AX)) &&
		    k->reg[KDIS_REG_AX] < 0x80000000u) {
			k->reg[KDIS_REG_DX] = 0;
			k->known |= (uint16_t)(1u << KDIS_REG_DX);
			return;
		}
		kdis_forget_written(k, in, -1);
		return;
	}

	/*
	 * AN INSTRUCTION WHOSE FIRST OPERAND IS NOT A REGISTER CAN STILL
	 * WRITE ONE - a string operation walks rsi and rdi while naming
	 * memory. Returning without forgetting those is how a stale value
	 * outlives the instruction that destroyed it.
	 */
	if (!in->n_op || in->o[0].kind != KDIS_O_REG ||
	    in->o[0].reg >= 16u) {
		kdis_forget_written(k, in, -1);
		return;
	}
	d = in->o[0].reg;

	/*
	 * EVERYTHING ELSE THIS INSTRUCTION WRITES IS NOW UNKNOWN, except the
	 * destination - the arms below are about to work that one out, and
	 * clearing it here would take away the value they read. That is not
	 * hypothetical: it cost `inc ebx` the zero that `xor ebx,ebx` had
	 * just put there.
	 */
	kdis_forget_written(k, in, (int)d);

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
		if (have_b)
			kdis_put(k, d, &in->o[0], b);
		else
			k->known &= (uint16_t)~(1u << d);
		kdis_forget_written(k, in, d);
		return;
	case KDIS_XCHG:
		/*
		 * TWO DESTINATIONS, and the old code had none: XCHG fell to
		 * the default arm, which cleared the first operand and left
		 * the second holding a value the swap had just moved away.
		 * That is a wrong number rather than an unknown one.
		 * msfvenom's x86-64 stager parks its socket descriptor with
		 * `xchg rdi, rax`.
		 */
		if (in->n_op > 1u && in->o[1].kind == KDIS_O_REG &&
		    in->o[1].reg < 16u) {
			uint8_t e = in->o[1].reg;
			uint64_t va = k->reg[d], ve = k->reg[e];
			uint16_t ka = (uint16_t)(k->known & (1u << d));
			uint16_t ke = (uint16_t)(k->known & (1u << e));

			k->reg[d] = ve; k->reg[e] = va;
			k->known = (uint16_t)(k->known & ~((1u << d) | (1u << e)));
			if (ke) k->known |= (uint16_t)(1u << d);
			if (ka) k->known |= (uint16_t)(1u << e);
		} else {
			k->known &= (uint16_t)~(1u << d);
			kdis_forget_written(k, in, -1);
		}
		return;
	case KDIS_SUB: case KDIS_XOR:
		/*
		 * A REGISTER AGAINST ITSELF IS ZERO whatever it held, and
		 * this used to answer "unknown" for it because it demanded a
		 * known input. It is the ordinary way to write a zero -
		 * msfvenom opens with `xor edi,edi` - so the map started
		 * blind at the first instruction.
		 */
		if (in->n_op > 1u && in->o[1].kind == KDIS_O_REG &&
		    in->o[1].reg == d) {
			k->reg[d] = 0;
			k->known |= (uint16_t)(1u << d);
			kdis_forget_written(k, in, d);
			return;
		}
		/* fall through */
	case KDIS_ADD: case KDIS_AND: case KDIS_OR:
		if (!have_b || !(k->known & (1u << d))) {
			k->known &= (uint16_t)~(1u << d);
			kdis_forget_written(k, in, d);
			return;
		}
		switch (in->op) {
		case KDIS_ADD: k->reg[d] = a + b; break;
		case KDIS_SUB: k->reg[d] = a - b; break;
		case KDIS_AND: k->reg[d] = a & b; break;
		case KDIS_OR:  k->reg[d] = a | b; break;
		default:       k->reg[d] = a ^ b; break;
		}
		kdis_forget_written(k, in, d);
		return;
	case KDIS_INC: case KDIS_DEC:
		if (k->known & (1u << d))
			k->reg[d] = in->op == KDIS_INC ? a + 1u : a - 1u;
		kdis_forget_written(k, in, d);
		return;
	case KDIS_NOT:
		if (k->known & (1u << d))
			k->reg[d] = ~a;
		kdis_forget_written(k, in, d);
		return;
	case KDIS_NEG:
		if (k->known & (1u << d))
			k->reg[d] = (uint64_t)0 - a;
		kdis_forget_written(k, in, d);
		return;
	case KDIS_MUL:
		/*
		 * MULTIPLYING BY A KNOWN ZERO GIVES ZERO whatever the other
		 * half held, and that is not a corner case here: `xor
		 * ebx,ebx; mul ebx` is the two-byte way to clear eax AND edx
		 * at once, which is why msfvenom's i386 payloads open with
		 * it. Answering "unknown" for both loses the syscall number
		 * that the next instruction writes a byte into.
		 */
		if (in->n_op && in->o[0].kind == KDIS_O_REG &&
		    in->o[0].reg < 16u && (k->known & (1u << in->o[0].reg)) &&
		    k->reg[in->o[0].reg] == 0) {
			k->reg[KDIS_REG_AX] = 0;
			k->reg[KDIS_REG_DX] = 0;
			k->known |= (uint16_t)((1u << KDIS_REG_AX) |
					       (1u << KDIS_REG_DX));
			return;
		}
		kdis_forget_written(k, in, -1);
		return;
	case KDIS_CMP: case KDIS_TEST: case KDIS_PUSH:
		return;                         /* no destination written */
	default:
		/*
		 * EVERYTHING ELSE FORGETS WHAT THE INSTRUCTION WROTE, which
		 * is `wmask` and not the first operand. The two differ
		 * exactly where it matters: `mul ebx` READS ebx and writes
		 * eax and edx, `cdq` names no operand at all and writes edx,
		 * and a string operation walks index registers it never
		 * mentions. Clearing the operand instead threw away a value
		 * that survived and kept two that did not.
		 */
		kdis_forget_written(k, in, -1);
		if (in->o[0].flags & KDIS_OF_WRITE)
			k->known &= (uint16_t)~(1u << d);
		return;
	}
}


void kdis_state_reset(struct kdis_state *k)
{
	memset(k, 0, sizeof *k);
}

int kdis_state_reg(const struct kdis_state *k, uint8_t r, uint64_t *out)
{
	if (!k || !out || r >= 16u || !(k->known & (1u << r)))
		return 0;
	*out = k->reg[r];
	return 1;
}
