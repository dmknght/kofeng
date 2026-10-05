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
#include "../../../../disinfect/pzero.h"

#include "bddisasm.h"
#include "decode.h"



/* ---- offsets and addresses ----------------------------------------------
 *
 * The cursor is an offset; a branch is computed in addresses. Both directions
 * are needed and only one of them already existed.
 */
static uint64_t kdis_off_to_va(struct kof_kdis *k,
			       const struct kof_obj_ctx *ctx, uint64_t off)
{
	/* Inside the window the last call established, it is one addition -
	 * see the note on map_lo in kdis.h for why that is almost always. */
	if (k->map_ok && off >= k->map_lo && off < k->map_hi)
		return (uint64_t)((int64_t)off + k->map_delta);
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
			    off - s->file_off < s->file_size) {
				k->map_lo = s->file_off;
				k->map_hi = s->file_off + s->file_size;
				k->map_delta = (int64_t)(p->image_base +
							 s->mem_rva) -
					       (int64_t)s->file_off;
				k->map_ok = 1;
				return p->image_base + s->mem_rva +
				       (off - s->file_off);
			}
		}
		/* The headers map at the image base, one to one. */
		if (p->sec_count && off < p->sec[0].file_off) {
			k->map_lo = 0;
			k->map_hi = p->sec[0].file_off;
			k->map_delta = (int64_t)p->image_base;
			k->map_ok = 1;
			return p->image_base + off;
		}
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
			    off - s->file_off < s->file_size) {
				k->map_lo = s->file_off;
				k->map_hi = s->file_off + s->file_size;
				k->map_delta = (int64_t)s->mem_addr -
					       (int64_t)s->file_off;
				k->map_ok = 1;
				return s->mem_addr + (off - s->file_off);
			}
		}
	}
	return KOF_BROKEN;
}

/*
 * AND THE WAY BACK, FOR A BRANCH THAT STAYS IN THE SAME SEGMENT.
 *
 * Which nearly every branch does: a relative displacement cannot leave the
 * image and a compiler does not emit one that leaves the section. The
 * window established above is a mapping in both directions, so the inverse
 * is the same single subtraction - and when the target IS somewhere else,
 * this falls through to the engine's one resolver rather than growing a
 * second copy of it.
 */
static uint64_t kdis_va_to_off(const struct kof_kdis *k,
			       const struct kof_obj_ctx *ctx, uint64_t va)
{
	if (k->map_ok) {
		uint64_t lo = (uint64_t)((int64_t)k->map_lo + k->map_delta);
		uint64_t hi = (uint64_t)((int64_t)k->map_hi + k->map_delta);

		if (va >= lo && va < hi)
			return (uint64_t)((int64_t)va - k->map_delta);
	}
	return kof_pz_addr_to_off(ctx, va);
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
static void kdis_forget_written(struct kof_kdis *k, const struct kdis_insn *in,
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
static void kdis_put(struct kof_kdis *k, uint8_t d, const struct kdis_operand *o,
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

/* ---- the cursor ---------------------------------------------------------- */

int kof_kdis_seek(struct kof_kdis *k, uint64_t off, int keep)
{
	if (!k)
		return 0;
	k->at = off;
	k->open = 1;
	/* A new walk may be a new object at the same context address - see
	 * the note on map_lo in kdis.h. */
	k->map_ok = 0;
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
	uint64_t left;
	uint32_t n;

	if (!k || !k->open || !ctx || !base || !out || k->at >= size)
		return 0;
	left = size - k->at;
	if (left > 16u)
		left = 16u;             /* the longest an instruction can be */

	/*
	 * THE DECODER IS kof_decode_x86 AND THERE IS NO SECOND ONE.
	 *
	 * This used to call NdDecodeEx itself, classify with a switch of its
	 * own and build its own operands - a complete copy of decode_x86.c
	 * standing beside it. The copy was written first and never caught
	 * up: when the enum gained KDIS_SYSCALL and KDIS_WIDEN and the
	 * decoder gained `wmask`, only one of the two learned them.
	 *
	 * MEASURED, and it is not a small drift: a `syscall` instruction came
	 * back as KDIS_OTHER, so nothing reading an object through this
	 * cursor could see a Linux system call AT ALL - on a static binary
	 * that is every capability the program has. `cdq` was the same, and
	 * `wmask` was zero for every instruction, which is what the constant
	 * map needs to know which registers an instruction destroys.
	 *
	 * One decoder now. Rule 10.
	 */
	n = kof_decode_x86(base + k->at, (uint32_t)left,
			   kdis_off_to_va(k, ctx, k->at),
			   ctx->arch == KOF_ARCH_X86_64 ? 64u : 32u, out);
	if (!n)
		return 0;
	out->at = k->at;
	n = out->n_op;
	if (out->target_va != KOF_BROKEN)
		out->target = kdis_va_to_off(k, ctx, out->target_va);

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
			out->target = kdis_va_to_off(k, ctx, v);
		}
	}

	kdis_track(k, out);
	k->at += out->len;
	return 1;
}
