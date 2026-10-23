/*
 * emu_ops.c - the less common integer, string and system instructions of the interpreter.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"


/*
 * Execute the string instructions, with and without a repeat prefix.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_str(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint64_t a = 0;

	switch (ixp->h.id) {
	case KGENOME_X86_I_LODS: case KGENOME_X86_I_STOS:
	case KGENOME_X86_I_MOVS: case KGENOME_X86_I_SCAS: case KGENOME_X86_I_CMPS: {
		/* WHAT THE GUEST IS MEASURING OR COMPARING, on request.
		 * A stub that resolves its own imports runs strlen
		 * over the name it wants before it looks for it, and
		 * RDI is pointing at that name here - the one place it
		 * is nameable. Printed once per distinct string. */
		if (KOF_TRACING) {
			char nm[64];
			uint64_t c = 0;
			unsigned q;

			for (q = 0; q + 1 < sizeof nm; q++) {
				if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RDI] + q,
					    &c, 1u) || !c)
					break;
				if (c < 32u || c > 126u)
					break;
				nm[q] = (char)c;
			}
			nm[q] = 0;
			if (q >= 5u && !c)
				fprintf(stderr, "[str] %s\n", nm);
		}
		unsigned w = ixp->op[0].size ? ixp->op[0].size : 1u;
		int64_t step = (e->flags & KGENOME_EMU_FL_DF) ? -(int64_t)w : (int64_t)w;
		uint64_t iter = 1;

		if (kgenome_x86_repeated(&ixp->h)) {
			iter = e->gpr[KGENOME_EMU_RCX];
			if (!iter) break;
			if (iter > e->max_insn - e->insn)
				iter = e->max_insn - e->insn;
		}
		while (iter--) {
			uint64_t v = 0;

			switch (ixp->h.id) {
			case KGENOME_X86_I_LODS:
				if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RSI], &v, w))
					goto fault;
				kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, w, 0, v);
				e->gpr[KGENOME_EMU_RSI] += (uint64_t)step;
				break;
			case KGENOME_X86_I_STOS:
				v = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, w, 0);
				if (!kgenome_emu_mem_wr(e, e->gpr[KGENOME_EMU_RDI], &v, w))
					goto fault;
				e->gpr[KGENOME_EMU_RDI] += (uint64_t)step;
				break;
			case KGENOME_X86_I_MOVS:
				if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RSI], &v, w) ||
				    !kgenome_emu_mem_wr(e, e->gpr[KGENOME_EMU_RDI], &v, w))
					goto fault;
				e->gpr[KGENOME_EMU_RSI] += (uint64_t)step;
				e->gpr[KGENOME_EMU_RDI] += (uint64_t)step;
				break;
			case KGENOME_X86_I_CMPS: {
				uint64_t rhs;

				if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RSI], &a, w) ||
				    !kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RDI], &rhs, w))
					goto fault;
				kgenome_emu_fl_sub(e, a, rhs, 0, w);
				e->gpr[KGENOME_EMU_RSI] += (uint64_t)step;
				e->gpr[KGENOME_EMU_RDI] += (uint64_t)step;
				break;
			}
			default:
				if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RDI], &v, w))
					goto fault;
				a = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, w, 0);
				kgenome_emu_fl_sub(e, a, v, 0, w);
				e->gpr[KGENOME_EMU_RDI] += (uint64_t)step;
				break;
			}
			if (kgenome_x86_repeated(&ixp->h)) {
				e->gpr[KGENOME_EMU_RCX]--;
				e->insn++;
				/* REPZ/REPNZ on a compare stop on the flag
				 * as well as on the count; REP on a move
				 * only on the count. */
				if (ixp->h.id == KGENOME_X86_I_SCAS ||
				    ixp->h.id == KGENOME_X86_I_CMPS) {
					int z = (e->flags & KGENOME_EMU_FL_ZF) != 0;

					if (ixp->h.rep == 0xF3 ? !z : z)
						break;
				}
			}
		}
		break;
	}
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

fault:
	return KGENOME_EMU_RUN_FAULT;
}

/*
 * Execute the less common integer instructions: the clock and MXCSR reads, the atomics, MUL, DIV, bit tests and scans, POPCNT.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_misc(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint64_t a = 0;
	unsigned sz = ixp->op[0].size ? ixp->op[0].size : 8u;

	switch (ixp->h.id) {
	/*
	 * A clock that only moves forward. Real time would make a run
	 * unreproducible, and a stub that times itself is looking for a
	 * debugger - a steady tick reads as an ordinary machine.
	 */
	case KGENOME_X86_I_RDTSC: case KGENOME_X86_I_RDTSCP: {
		uint64_t now = kgenome_emu_tsc_read(e);

		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 4, 0, now & 0xffffffffu);
		kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, 4, 0, now >> 32);
		if (ixp->h.id == KGENOME_X86_I_RDTSCP)
			kgenome_emu_reg_wr(e, KGENOME_EMU_RCX, 4, 0, 0);
		break;
	}

	/*
	 * The SSE control word, read and written. Its rounding mode (bits
	 * 13-14) is acted on by every floating point instruction that
	 * rounds (emu_vec_fp.c); its exception flags and masks, DAZ and FTZ
	 * are kept and handed back as written but change nothing.
	 */
	case KGENOME_X86_I_STMXCSR:
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], e->mxcsr))
			goto unsupported;
		break;
	case KGENOME_X86_I_LDMXCSR:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			goto unsupported;
		e->mxcsr = (uint32_t)a;
		break;

	/* XCR0: x87 and SSE enabled, nothing wider - which is the truth
	 * about this machine, and keeps a runtime off the AVX paths. */
	case KGENOME_X86_I_XGETBV:
		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 4, 0, 3);
		kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, 4, 0, 0);
		break;

	/*
	 * The atomics a runtime starts on. LOCK is a no-op here - one
	 * thread, so the read-modify-write is already indivisible.
	 */
	case KGENOME_X86_I_CMPXCHG: {
		uint64_t dst, src, acc = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, sz, 0);

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &dst) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &src))
			goto unsupported;
		kgenome_emu_fl_sub(e, acc, dst, 0, sz);
		if (((acc ^ dst) & kgenome_emu_mask_of(sz)) == 0) {
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], src))
				goto unsupported;
		} else {
			kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, sz, 0, dst);
		}
		break;
	}

	case KGENOME_X86_I_XADD: {
		uint64_t dst, src;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &dst) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &src))
			goto unsupported;
		kgenome_emu_fl_add(e, dst, src, 0, sz);
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[1], dst) ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], dst + src))
			goto unsupported;
		break;
	}

	/*
	 * Unsigned multiply (and, below, both divides).
	 */
	case KGENOME_X86_I_MUL: {
		uint64_t acc = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, sz, 0), hi;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			goto unsupported;
		if (sz == 8) {
			uint64_t al = acc & 0xffffffffu, ah = acc >> 32;
			uint64_t bl = a & 0xffffffffu, bh = a >> 32;
			uint64_t m0 = al * bl, m1 = al * bh, m2 = ah * bl;
			uint64_t carry = ((m0 >> 32) + (m1 & 0xffffffffu) +
					  (m2 & 0xffffffffu)) >> 32;

			hi = ah * bh + (m1 >> 32) + (m2 >> 32) + carry;
			kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 8, 0, acc * a);
			kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, 8, 0, hi);
		} else {
			uint64_t r64 = (acc & kgenome_emu_mask_of(sz)) * (a & kgenome_emu_mask_of(sz));

			hi = (r64 >> (sz * 8u)) & kgenome_emu_mask_of(sz);
			/* 8-bit MUL lands the whole 16-bit product in AX;
			 * every wider size splits it AX/DX. */
			if (sz == 1) {
				kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 2, 0, r64);
			} else {
				kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, sz, 0, r64);
				kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, sz, 0, hi);
			}
		}
		e->flags = hi ? (e->flags | KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF)
			      : (e->flags & ~(uint64_t)(KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF));
		break;
	}

	/*
	 * DIV and IDIV (Intel SDM Vol. 2). The dividend is AX for a byte divisor (quotient AL,
	 * remainder AH), DX:AX, EDX:EAX or RDX:RAX for the wider ones (quotient in the low
	 * register, remainder in the high). The flags are undefined.
	 *
	 * A ZERO DIVISOR AND A QUOTIENT THAT DOES NOT FIT THE DESTINATION ARE #DE, A FAULT, AND NOT A
	 * STOP FOR WANT OF AN INSTRUCTION. The instruction changes nothing, the fault is raised the
	 * way a failed memory access is (kgenome_emu_fault_de: a Windows guest's handlers are run
	 * with STATUS_INTEGER_DIVIDE_BY_ZERO or STATUS_INTEGER_OVERFLOW, a guest with none - and
	 * every ELF guest, because no signal is delivered here - ends the run with a FAULT stop
	 * that names "divzero" or "divovf"). The 64-bit divide takes the full RDX:RAX dividend
	 * (kgenome_emu_div128) and does not read it as a 64-bit one. tests/lib/genome/diff_div.c
	 * runs the cases on the host CPU and compares, SIGFPE included.
	 */
	case KGENOME_X86_I_DIV: case KGENOME_X86_I_IDIV: {
		const int sgn = ixp->h.id == KGENOME_X86_I_IDIV;
		const uint64_t lo = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, sz == 1 ? 2u : sz, 0);
		const uint64_t hi = sz == 1 ? 0 : kgenome_emu_reg_rd(e, KGENOME_EMU_RDX, sz, 0);
		uint64_t q, rm;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			goto unsupported;
		a &= kgenome_emu_mask_of(sz);
		if (!a) {
			kgenome_emu_fault_de(e, 0);
			goto unsupported;
		}
		if (!kgenome_emu_div(sz, sgn, hi, lo, a, &q, &rm)) {
			kgenome_emu_fault_de(e, 1);
			goto unsupported;
		}
		if (sz == 1) {
			/* AL = quotient, AH = remainder, the rest of RAX unchanged */
			kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 1, 0, q);
			kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 1, 1, rm);
		} else {
			kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, sz, 0, q);
			kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, sz, 0, rm);
		}
		break;
	}

	/*
	 * BT, BTS, BTR, BTC (SDM Vol. 2). CF receives the bit. With an immediate offset, or with a
	 * register destination, the offset is taken modulo the operand width. With a MEMORY operand
	 * and a REGISTER offset the offset is a signed bit index into a bit string that starts at the
	 * operand's address: the operand addressed is the one `floor(offset / width)` operand-sizes
	 * away, and the bit is the offset modulo the width. OF, SF, AF and PF are undefined.
	 */
	case KGENOME_X86_I_BT: case KGENOME_X86_I_BTS: case KGENOME_X86_I_BTR: case KGENOME_X86_I_BTC: {
		uint64_t bit, val, addr = 0;
		unsigned w = sz * 8u;
		int in_mem = ixp->op[0].type == KGENOME_X86_OP_MEM &&
			     ixp->op[1].type == KGENOME_X86_OP_REG;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &bit))
			goto unsupported;
		if (in_mem) {
			int64_t soff = (int64_t)kgenome_emu_sext(bit, sz);
			unsigned lg = sz == 8 ? 6u : sz == 4 ? 5u : 4u;

			if (!kgenome_emu_ea_of(e, ixp, &ixp->op[0], &addr))
				goto unsupported;
			addr += (uint64_t)((soff >> lg) * (int64_t)sz);
			if (e->bits == 32)
				addr &= 0xffffffffu;
			val = 0;
			if (!kgenome_emu_mem_rd(e, addr, &val, sz))
				goto unsupported;
		} else if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &val)) {
			goto unsupported;
		}
		bit &= w - 1u;
		e->flags = (e->flags & ~KGENOME_EMU_FL_CF) |
			   (((val >> bit) & 1u) ? KGENOME_EMU_FL_CF : 0u);
		if (ixp->h.id == KGENOME_X86_I_BTS)      val |=  (uint64_t)1 << bit;
		else if (ixp->h.id == KGENOME_X86_I_BTR) val &= ~((uint64_t)1 << bit);
		else if (ixp->h.id == KGENOME_X86_I_BTC) val ^=  (uint64_t)1 << bit;
		if (ixp->h.id != KGENOME_X86_I_BT) {
			if (in_mem ? !kgenome_emu_mem_wr(e, addr, &val, sz)
				   : !kgenome_emu_op_wr(e, ixp, &ixp->op[0], val))
				goto unsupported;
		}
		break;
	}

	/*
	 * BSF/BSR (SDM): ZF = 1 when the source is zero (the destination is then left alone),
	 * else ZF = 0; the other flags are undefined. TZCNT/LZCNT: CF = 1 when the SOURCE is
	 * zero (the result is then the operand size), ZF = 1 when the RESULT is zero (TZCNT:
	 * bit 0 set; LZCNT: the top bit set); OF, SF, PF and AF are undefined.
	 */
	case KGENOME_X86_I_BSF: case KGENOME_X86_I_BSR:
	case KGENOME_X86_I_TZCNT: case KGENOME_X86_I_LZCNT: {
		uint64_t v, k;
		unsigned w = sz * 8u;
		int cnt = ixp->h.id == KGENOME_X86_I_TZCNT || ixp->h.id == KGENOME_X86_I_LZCNT;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &v))
			goto unsupported;
		if (!v) {
			if (!cnt) {
				e->flags |= KGENOME_EMU_FL_ZF;
				break;
			}
			e->flags = (e->flags | KGENOME_EMU_FL_CF) & ~(uint64_t)KGENOME_EMU_FL_ZF;
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], w))
				goto unsupported;
			break;
		}
		e->flags &= ~(uint64_t)(KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_CF);
		if (ixp->h.id == KGENOME_X86_I_BSF ||
		    ixp->h.id == KGENOME_X86_I_TZCNT) {
			for (k = 0; !((v >> k) & 1u); k++)
				;
		} else {
			for (k = w - 1u; !((v >> k) & 1u); k--)
				;
			if (ixp->h.id == KGENOME_X86_I_LZCNT)
				k = w - 1u - k;
		}
		if (cnt && !k)
			e->flags |= KGENOME_EMU_FL_ZF;
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], k))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_POPCNT: {
		uint64_t v, n = 0;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &v))
			goto unsupported;
		while (v) { n += v & 1u; v >>= 1; }
		e->flags = (e->flags & ~(uint64_t)(KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF |
						   KGENOME_EMU_FL_SF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_AF)) |
			   (n ? 0u : KGENOME_EMU_FL_ZF);
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], n))
			goto unsupported;
		break;
	}

	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}

/*
 * Execute the rotates through carry and the double shifts, which the plain shift arm does not carry.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_shift(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint64_t a = 0, b = 0, r = 0;
	unsigned sz = ixp->op[0].size ? ixp->op[0].size : 8u;

	switch (ixp->h.id) {
	/*
	 * RCL / RCR - THE ROTATE THAT INCLUDES CF, AND THAT IS THE
	 * WHOLE DIFFERENCE FROM THE PAIR BELOW.
	 *
	 * ROL and ROR rotate w bits; these rotate w+1, with the carry
	 * flag as the extra bit. So the count is taken modulo w+1 and
	 * not modulo w, and a protector that uses them as a checksum -
	 * which is what they are for outside of multiprecision
	 * arithmetic - gets a different answer from either mistake.
	 *
	 * Measured: two of the four protected samples stopped here,
	 * with "unsupported: RCR ax, 1", having run 25.9 and 26.7
	 * million instructions to reach it.
	 */
	case KGENOME_X86_I_RCL: case KGENOME_X86_I_RCR: {
		unsigned n, rc, w = sz * 8u, i;
		uint64_t m = kgenome_emu_mask_of(sz), cf;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			goto unsupported;
		n = (unsigned)(b & (sz == 8 ? 63u : 31u));
		/*
		 * 8- and 16-bit forms take the count modulo 9 and 17;
		 * the wider ones are already below w+1 after the mask
		 * above. The architecture says so and it is not an
		 * optimisation - a count of 9 on a byte is a full turn
		 * and leaves the operand alone.
		 */
		rc = n % (w + 1u);
		if (!rc) {                    /* nothing rotates; a 32 bit register is still written */
			kgenome_emu_op_keep(e, &ixp->op[0], a);
			break;
		}
		a &= m;
		cf = (e->flags & KGENOME_EMU_FL_CF) ? 1u : 0u;
		/*
		 * One step at a time, w+1 bits wide. A closed form
		 * needs three shifts and two conditionals per
		 * direction and is where this kind of code goes wrong;
		 * the count is at most 64 and these run once.
		 */
		for (i = 0; i < rc; i++) {
			if (ixp->h.id == KGENOME_X86_I_RCL) {
				uint64_t top = (a >> (w - 1u)) & 1u;

				a = ((a << 1) | cf) & m;
				cf = top;
			} else {
				uint64_t bot = a & 1u;

				a = ((a >> 1) | (cf << (w - 1u))) & m;
				cf = bot;
			}
		}
		r = a;
		e->flags &= ~(uint64_t)KGENOME_EMU_FL_CF;
		if (cf)
			e->flags |= KGENOME_EMU_FL_CF;
		/* OF is defined for a count of one alone, as above. */
		if (n == 1) {
			e->flags &= ~(uint64_t)KGENOME_EMU_FL_OF;
			if (ixp->h.id == KGENOME_X86_I_RCL) {
				if (((r >> (w - 1u)) & 1u) ^ (cf & 1u))
					e->flags |= KGENOME_EMU_FL_OF;
			} else {
				if (((r >> (w - 1u)) & 1u) ^
				    ((r >> (w - 2u)) & 1u))
					e->flags |= KGENOME_EMU_FL_OF;
			}
		}
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			goto unsupported;
		break;
	}

	/*
	 * SHIFTS and ROTATES are split, because they touch DIFFERENT
	 * flags: a shift sets SF/ZF/PF from its result like a logical op,
	 * a rotate leaves those four alone and moves only CF and OF. The
	 * old code ran both through fl_logic and so clobbered SF/ZF/PF on
	 * every rotate and left CF/OF wrong - a `rol; jc` read a carry
	 * that was always zero.
	 *
	 * The count is masked to five bits (six at 64) as the hardware
	 * does, and then - the second thing the old code got wrong -
	 * BOUNDED to the operand width before it reaches a C shift. A
	 * `sar al, 12` delivers a count of 12 against an 8-bit value, and
	 * `>> 12` past a byte sign-extended into 64 bits is a shift of 68:
	 * undefined in C, and on the host it wraps mod 64 to a wrong
	 * answer rather than the all-sign-bits x86 produces.
	 */
	/*
	 * SHRD AND SHLD, which an obfuscator reaches for because they
	 * are the one shift that mixes two registers - measured, a
	 * VMProtect stub reaches one 78 instructions in and nothing
	 * else in this build decoded it.
	 *
	 * The count is masked like the other shifts; a count of zero
	 * leaves the flags alone, and a count past the width is
	 * UNDEFINED on the hardware, so it is refused rather than
	 * invented.
	 */
	case KGENOME_X86_I_SHRD: case KGENOME_X86_I_SHLD: {
		unsigned n, w = sz * 8u;
		uint64_t m = kgenome_emu_mask_of(sz), src;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &src) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			goto unsupported;
		n = (unsigned)(b & (sz == 8 ? 63u : 31u));
		if (!n) {                     /* count masks to zero: flags kept, 32 bit register zero-extended */
			kgenome_emu_op_keep(e, &ixp->op[0], a);
			break;
		}
		a &= m;
		src &= m;
		/*
		 * A COUNT PAST THE OPERAND SIZE, WHICH ONLY 16 BIT
		 * OPERANDS CAN HAVE - the mask is 31, so 32 and 64 bit
		 * forms never reach it.
		 *
		 * Intel calls the result undefined here, and that is
		 * precisely why a protector uses it: the hardware still
		 * produces something, consistently, because the shift
		 * runs on a 32 bit datapath over the concatenation of
		 * the two operands. An interpreter that refuses the
		 * instruction is telling the guest it is not a CPU.
		 * Measured, a VMProtect stub reaches `shrd cx, ax, 0x51`
		 * - count 17 on a 16 bit pair - 78 instructions in.
		 *
		 * So it is computed the way the datapath does it, and
		 * the comment says that this is a choice about
		 * undefined behaviour rather than an architectural
		 * fact.
		 */
		if (n >= w) {
#ifdef KGENOME_EMU_HOST_DSHIFT
			uint64_t hf = 0;

			if (sz != 2u)
				goto unsupported;
			r = kgenome_emu_host_dshift16((uint16_t)a, (uint16_t)src,
					  (uint8_t)n,
					  ixp->h.id == KGENOME_X86_I_SHLD,
					  &hf);
			/* The host's own flags, for the bits this
			 * models - the guest reads them back with
			 * pushf and folds them in. */
			{
				uint64_t keep = KGENOME_EMU_FL_CF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_AF |
						KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_SF | KGENOME_EMU_FL_OF;

				e->flags = (e->flags & ~keep) |
					   (hf & keep);
			}
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
				goto unsupported;
			break;
#else
			goto unsupported;
#endif
		}
		if (ixp->h.id == KGENOME_X86_I_SHRD) {
			r = ((a >> n) | (src << (w - n))) & m;
			if ((a >> (n - 1u)) & 1u)
				b = 1;
			else
				b = 0;
		} else {
			r = ((a << n) | (src >> (w - n))) & m;
			b = (a >> (w - n)) & 1u;
		}
		kgenome_emu_fl_logic(e, r, sz);
		/* AF is architecturally undefined after a shift and
		 * real x86 SETS it; a protector reading the flags back
		 * notices the difference. See host_dshift16. */
		e->flags |= KGENOME_EMU_FL_AF;
		if (b)
			e->flags |= KGENOME_EMU_FL_CF;
		/* OF is defined only for a count of one, and is the
		 * sign changing - the same rule the single bit shifts
		 * above follow. */
		if (n == 1u && ((r ^ a) >> (w - 1u)) & 1u)
			e->flags |= KGENOME_EMU_FL_OF;
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			goto unsupported;
		break;
	}

	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}

/*
 * Execute the BCD adjustments (32-bit only).
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_bcd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	switch (ixp->h.id) {
	/*
	 * THE BCD ADJUSTS, and they are here because Alpha2 uses them
	 * as arithmetic rather than as decimal.
	 *
	 * An alphanumeric encoder can only emit bytes in a narrow range,
	 * so it builds its values out of whatever instructions fall in
	 * that range - and AAA, AAS and their siblings do. What the
	 * decoder needs from them is the exact register and flag result,
	 * which is why these are implemented rather than skipped: a stub
	 * computing an offset through AAA and getting the wrong AF back
	 * reads its payload from the wrong place.
	 *
	 * 32-bit only, like PUSHAD - amd64 removed them.
	 */
	case KGENOME_X86_I_AAA:
	case KGENOME_X86_I_AAS: {
		uint32_t ax = (uint32_t)(e->gpr[KGENOME_EMU_RAX] & 0xffffu);
		unsigned al = ax & 0xffu, ah = (ax >> 8) & 0xffu;
		int adj = (al & 0x0fu) > 9u || (e->flags & KGENOME_EMU_FL_AF);

		if (adj) {
			if (ixp->h.id == KGENOME_X86_I_AAA) {
				al = (al + 6u) & 0xffu;
				ah = (ah + 1u) & 0xffu;
			} else {
				al = (al - 6u) & 0xffu;
				ah = (ah - 1u) & 0xffu;
			}
			e->flags |= KGENOME_EMU_FL_AF | KGENOME_EMU_FL_CF;
		} else {
			e->flags &= ~(uint64_t)(KGENOME_EMU_FL_AF | KGENOME_EMU_FL_CF);
		}
		al &= 0x0fu;
		e->gpr[KGENOME_EMU_RAX] =
			(e->gpr[KGENOME_EMU_RAX] & ~0xffffull) |
			((uint64_t)ah << 8) | al;
		break;
	}

	case KGENOME_X86_I_DAA:
	case KGENOME_X86_I_DAS: {
		unsigned al = (unsigned)(e->gpr[KGENOME_EMU_RAX] & 0xffu);
		unsigned old = al;
		int oldcf = (e->flags & KGENOME_EMU_FL_CF) != 0;
		int sub = ixp->h.id == KGENOME_X86_I_DAS;

		e->flags &= ~(uint64_t)KGENOME_EMU_FL_CF;
		if ((al & 0x0fu) > 9u || (e->flags & KGENOME_EMU_FL_AF)) {
			al = sub ? (al - 6u) & 0xffu : (al + 6u) & 0xffu;
			if (sub && old < 6u)
				e->flags |= KGENOME_EMU_FL_CF;
			e->flags |= KGENOME_EMU_FL_AF;
		} else {
			e->flags &= ~(uint64_t)KGENOME_EMU_FL_AF;
		}
		if (old > 0x99u || oldcf) {
			al = sub ? (al - 0x60u) & 0xffu
				 : (al + 0x60u) & 0xffu;
			e->flags |= KGENOME_EMU_FL_CF;
		}
		/* SDM DAA/DAS: SF, ZF and PF follow the adjusted AL (OF is undefined) */
		e->flags &= ~(uint64_t)(KGENOME_EMU_FL_SF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF);
		if (!al)
			e->flags |= KGENOME_EMU_FL_ZF;
		if (al & 0x80u)
			e->flags |= KGENOME_EMU_FL_SF;
		if (!(__builtin_popcount(al) & 1))
			e->flags |= KGENOME_EMU_FL_PF;
		e->gpr[KGENOME_EMU_RAX] =
			(e->gpr[KGENOME_EMU_RAX] & ~0xffull) | al;
		break;
	}
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;
}

/*
 * Execute CPUID, INT and SYSCALL: the instructions that ask the environment something.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_sys(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	switch (ixp->h.id) {
	/*
	 * CPUID, answered rather than refused.
	 *
	 * A stub asks in order to pick a code path, and the safest
	 * answer is a plain old CPU: no AVX, no fancy string support,
	 * so whatever it selects is the simple path this interpreter
	 * has the best chance of carrying. Refusing instead would stop
	 * the run at the first sample that merely wanted to know.
	 */
	case KGENOME_X86_I_CPUID: {
		uint32_t leaf = (uint32_t)e->gpr[KGENOME_EMU_RAX];

		e->gpr[KGENOME_EMU_RAX] = e->gpr[KGENOME_EMU_RBX] =
		e->gpr[KGENOME_EMU_RCX] = e->gpr[KGENOME_EMU_RDX] = 0;
		if (leaf == 0) {
			e->gpr[KGENOME_EMU_RAX] = 1;          /* max leaf */
			e->gpr[KGENOME_EMU_RBX] = 0x756e6547;  /* "Genu" */
			e->gpr[KGENOME_EMU_RDX] = 0x49656e69;  /* "ineI" */
			e->gpr[KGENOME_EMU_RCX] = 0x6c65746e;  /* "ntel" */
		} else if (leaf == 1) {
			e->gpr[KGENOME_EMU_RAX] = 0x000306a9;  /* a plausible model */
			e->gpr[KGENOME_EMU_RDX] = 0x078bfbff;  /* fpu..sse2, no avx */
		}
		break;
	}

	/*
	 * `int 0x80` IS THE 32-BIT SYSCALL, and the only interrupt this
	 * runs.
	 *
	 * Every other vector is refused rather than ignored: an
	 * `int 3` is a debugger trap and an `int 0x2e` is Windows, and
	 * a stub reaching either is doing something this environment
	 * cannot answer for. Returning from them as though they had
	 * worked would let the run carry on into a state the guest
	 * never actually reached.
	 *
	 * Accepted in 64-bit mode too. Linux still honours int 0x80
	 * from a 64-bit process - with the i386 table - so a stub that
	 * uses it there is doing something real, and refusing it would
	 * be this emulator disagreeing with the kernel.
	 */
	case KGENOME_X86_I_INT: {
		int s = 0;
		uint64_t ret, at;
		unsigned was = e->bits;

		/*
		 * INT 0x29 IS __fastfail: the C runtime's last word after a failed check (a corrupt cookie, a
		 * pure-virtual call, an invalid parameter). On Windows it ends the process whatever handlers there
		 * are - STATUS_STACK_BUFFER_OVERRUN is not delivered to them - so it ends the run like ExitProcess,
		 * and does not read as an instruction this build lacks. Only for a guest that has the Windows model.
		 */
		if (ixp->op[0].type == KGENOME_X86_OP_IMM && (uint64_t)ixp->op[0].v == 0x29 && e->win_k32_base) {
			e->stop = KGENOME_EMU_STOP_EXIT;
			snprintf(e->detail, sizeof e->detail, "fast fail (int 0x29)");
			goto done;
		}
		if (ixp->op[0].type != KGENOME_X86_OP_IMM ||
		    (uint64_t)ixp->op[0].v != 0x80)
			goto unsupported;
		/* int 0x80 is the i386 convention whatever the mode. */
		e->bits = 32;
		at = e->rip;
		ret = kgenome_emu_do_syscall(e, &s);
		e->bits = was;
		if (s) { e->stop = (enum kgenome_emu_stop)(s - 1); goto done; }
		if (e->rip != at)
			return KGENOME_EMU_RUN_REDIRECT;
		e->gpr[KGENOME_EMU_RAX] = ret;
		break;
	}

	case KGENOME_X86_I_IN: case KGENOME_X86_I_OUT: case KGENOME_X86_I_CLI: case KGENOME_X86_I_STI:
		kgenome_emu_fault_priv(e);
		return KGENOME_EMU_RUN_FAULT;

	case KGENOME_X86_I_SYSCALL: {
		int s = 0;
		const uint64_t at = e->rip;
		uint64_t ret = kgenome_emu_do_syscall(e, &s);

		if (s) { e->stop = (enum kgenome_emu_stop)(s - 1); goto done; }
		/*
		 * A SYSTEM CALL THAT STARTED A GUEST HANDLER HAS MOVED rip ITSELF
		 * (RaiseException is dispatched to the vectored handlers: the machine
		 * is set to run them, with the return address that ends them in the
		 * stack). Stepping to the next instruction as every other call does
		 * walked past the handler, into the stub's own `ret`, which popped the
		 * handler's return address and reported a handler that had never run
		 * as one that declined.
		 */
		if (e->rip != at)
			return KGENOME_EMU_RUN_REDIRECT;
		e->gpr[KGENOME_EMU_RAX] = ret;
		break;
	}
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

done:
	return KGENOME_EMU_RUN_DONE;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}
