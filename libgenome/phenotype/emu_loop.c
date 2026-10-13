/*
 * emu_loop.c - a counted delay loop is accounted by its iterations, not run.
 *
 * WHAT IT IS FOR. A program that waits before it acts - `mov ecx, N; L: dec ecx;
 * jnz L` - is the cheapest anti-analysis there is, and the run it hides is
 * decided by how many instructions the wait costs: the budget ended a 2.2M
 * instruction wait in a small object with nothing found, and the stall stop (no
 * new page for 4M instructions) ended a 5M one in a bigger object. Raising either
 * bound is paid by every object whose run spins to it - measured on Mirai samples,
 * x2.8 (see KGENOME_DIAG_EMU_STOPS in diag_emu_private.h) - because a bound cannot
 * tell a wait from a spin. The loop can: a delay has a COUNTER, and the number of
 * iterations it takes is arithmetic, not something to find out by running them.
 *
 * WHAT IT RECOGNISES, and nothing past it. The backward branch taken
 * KGENOME_EMU_DELAY_PROBE times in a row from one place; the body from its target
 * to the branch is read once and must be
 *
 *     (nop | pause)*  STEP  [cmp COUNTER, imm]  (jne | jb | jl) top
 *     (nop | pause)*  loop top
 *
 * where STEP is `inc`, `dec`, `add r, +-1` or `sub r, +-1` on one 32 or 64 bit
 * general register. A body with a load, a store, a call, a second register, a
 * second branch or any other instruction is NOT a delay and runs as it always
 * did: a spin that polls or computes between its backward jumps is the thing the
 * bounds exist for and none of it is touched here. The recogniser is a
 * statement about the SHAPE (a register-only body whose exit depends on one
 * counter moving by one), and that is what makes skipping it sound - the body
 * has no effect but the counter and the flags.
 *
 * HOW MUCH IS SKIPPED. All but the LAST iteration. The counter is set to the value
 * it has one iteration before the exit and the loop is left to finish itself, so
 * the flags, the counter and the next instruction are exactly what running every
 * iteration leaves - no flag is computed here. The skipped instructions go to
 * `ff_insn`, not to `insn`: see the note at that field.
 *
 * WHAT IT COSTS. A compare on every taken backward branch, and the decode of at
 * most KGENOME_EMU_DELAY_BODY bytes once per loop that reaches the probe count -
 * and a loop that is not a delay is not probed again until another branch has
 * been taken in between.
 */

#include "emu_private.h"

#define KGENOME_EMU_DELAY_BODY 48u

static uint64_t width_mask(unsigned bytes)
{
	return bytes >= 8u ? ~(uint64_t)0 : ((uint64_t)1 << (bytes * 8u)) - 1u;
}

/* The immediate as a signed number of the register's width. */
static int64_t imm_signed(const struct kgenome_x86_op *op, unsigned bytes)
{
	return bytes >= 8u ? (int64_t)op->v : (int64_t)(int32_t)op->v;
}

static int counter_reg(const struct kgenome_x86_op *op)
{
	return op->type == KGENOME_X86_OP_REG && op->rtype == KGENOME_X86_REG_GPR &&
	       (op->rsize == 4u || op->rsize == 8u) && !op->high8 &&
	       op->reg != KGENOME_EMU_RSP;
}

/* Skip `n - 1` of `n` remaining iterations of `per` instructions each: the counter
 * becomes `last` (its value one iteration before the exit). */
static void skip(struct kgenome_emu *e, unsigned reg, unsigned bytes, uint64_t last,
		 uint64_t n, unsigned per)
{
	uint64_t skipped = n - 1u;

	kgenome_emu_reg_wr(e, reg, bytes, 0, last);
	/* A wait of 2^64 iterations is a number and not a loop: saturate. */
	e->ff_insn = skipped > (~(uint64_t)0 - e->ff_insn) / per
		   ? ~(uint64_t)0 : e->ff_insn + skipped * per;
}

void kgenome_emu_delay_note(struct kgenome_emu *e, uint64_t top, uint64_t at, unsigned at_len)
{
	uint8_t buf[KGENOME_EMU_DELAY_BODY];
	uint64_t len = at + at_len - top;
	uint64_t pos = 0;
	unsigned ni = 0, mode = e->bits == 32 ? 32u : 64u;
	int have_step = 0, have_cmp = 0, d = 0;
	unsigned reg = 0, bytes = 0;
	uint64_t K = 0;

	if (at < top || len > sizeof buf || !kgenome_emu_mem_rd(e, top, buf, (unsigned)len))
		return;
	for (;;) {
		struct kgenome_emu_insn ix;
		unsigned id;

		if (kgenome_x86_decode(&ix.h, buf + pos, (size_t)(len - pos), (int)mode) != KGENOME_OK)
			return;
		ix.n = kgenome_x86_nops(&ix.h);
		kgenome_x86_operands(&ix.h, ix.op);
		id = ix.h.id;
		ni++;
		pos += ix.h.len;

		if (pos == len) {
			/* The branch itself, and it must go back to `top`. */
			uint64_t n, v;

			if (id == KGENOME_X86_I_LOOP) {
				if (have_step || have_cmp)
					return;
				/* The counter is RCX and the emulator counts the whole
				 * register: what is left in it now is the iterations
				 * still to run. */
				n = e->gpr[KGENOME_EMU_RCX];
				if (n >= 2u)
					skip(e, KGENOME_EMU_RCX, 8u, 1u, n, ni);
				return;
			}
			if (id != KGENOME_X86_I_Jcc || ix.n < 1u ||
			    ix.op[0].type != KGENOME_X86_OP_REL ||
			    at + at_len + (uint64_t)ix.op[0].v != top || !have_step)
				return;
			{
				unsigned cc = kgenome_x86_cond(&ix.h);
				uint64_t m = width_mask(bytes);

				v = kgenome_emu_reg_rd(e, reg, bytes, 0) & m;
				if (!have_cmp) {
					if (cc != 5u)           /* jne: the result is not zero */
						return;
					n = d < 0 ? v : (0 - v) & m;
					if (n >= 2u)
						skip(e, reg, bytes, (v + (uint64_t)(int64_t)d * (n - 1u)) & m, n, ni);
					return;
				}
				if (cc == 5u) {                 /* counter != K */
					n = d < 0 ? (v - K) & m : (K - v) & m;
				} else if (cc == 2u && d > 0 && v < K) {        /* unsigned < */
					n = K - v;
				} else if (cc == 12u && d > 0 &&
					   kgenome_emu_sext(v, bytes) < kgenome_emu_sext(K, bytes)) {
					n = (uint64_t)((int64_t)kgenome_emu_sext(K, bytes) -
						       (int64_t)kgenome_emu_sext(v, bytes));
				} else {
					return;
				}
				if (n >= 2u)
					skip(e, reg, bytes, (K - (uint64_t)(int64_t)d) & m, n, ni);
			}
			return;
		}

		if (id == KGENOME_X86_I_NOP || id == KGENOME_X86_I_PAUSE)
			continue;
		if ((id == KGENOME_X86_I_INC || id == KGENOME_X86_I_DEC) && !have_step && ix.n >= 1u &&
		    counter_reg(&ix.op[0])) {
			have_step = 1;
			reg = ix.op[0].reg;
			bytes = ix.op[0].rsize;
			d = id == KGENOME_X86_I_INC ? 1 : -1;
			continue;
		}
		if ((id == KGENOME_X86_I_ADD || id == KGENOME_X86_I_SUB) && !have_step && ix.n >= 2u &&
		    counter_reg(&ix.op[0]) && ix.op[1].type == KGENOME_X86_OP_IMM) {
			int64_t k = imm_signed(&ix.op[1], ix.op[0].rsize);

			if (k != 1 && k != -1)
				return;
			have_step = 1;
			reg = ix.op[0].reg;
			bytes = ix.op[0].rsize;
			d = (id == KGENOME_X86_I_ADD) == (k == 1) ? 1 : -1;
			continue;
		}
		if (id == KGENOME_X86_I_CMP && have_step && !have_cmp && ix.n >= 2u &&
		    counter_reg(&ix.op[0]) && ix.op[0].reg == reg && ix.op[0].rsize == bytes &&
		    ix.op[1].type == KGENOME_X86_OP_IMM) {
			have_cmp = 1;
			K = (uint64_t)imm_signed(&ix.op[1], bytes) & width_mask(bytes);
			continue;
		}
		return;
	}
}
