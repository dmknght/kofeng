/*
 * emu_x86.c - the x86 and x86-64 ENTRY of the emulator's dispatch table (struct kgenome_emu_arch, see
 * emu_private.h): the decode through genotype's x86 decoder, the execution of an instruction by its
 * id, the stack and the conventions; and the run loop of emu_run_private.h made for this entry. The
 * instruction groups the switch hands on to are emu_ops*.c, emu_vec*.c and emu_x87.c, their shared
 * helpers emu_state.c; emu_x86_private.h is what those files share.
 *
 *
 * HOW AN INSTRUCTION IS CARRIED OUT
 *
 * Not as one switch over several hundred mnemonics. the decoder hands back a
 * decoded operand list - for each operand: is it a register, a memory
 * reference or an immediate, how wide, and is it read, written or both. So the
 * shape here is
 *
 *      read every source operand generically
 *      switch on the mnemonic to compute a result   <- small
 *      write the destination generically
 *
 * and the switch holds arithmetic rather than addressing. Adding an
 * instruction is then usually one case, and the addressing modes it inherits
 * are the ones already tested by every other instruction.
 *
 *
 * FLAGS ARE COMPUTED EAGERLY
 *
 * A real CPU defers them and so do fast emulators. This one does not: a packer
 * stub is a few hundred thousand instructions, the budget stops it long before
 * the difference is measurable, and a lazy flag bug is the kind that shows up
 * as one wrong branch a hundred thousand instructions later. Correctness that
 * can be read beats speed that cannot.
 */

/* clock_gettime, for the wall clock bound - see kgenome_emu_set_deadline. The
 * project's other users of it reach for _GNU_SOURCE for the same reason. */
#define _POSIX_C_SOURCE 199309L

#include "emu_x86_private.h"
#include "emu_run_private.h"



static int cond_true(const struct kgenome_emu *e, unsigned cc)
{
	uint64_t f = e->flags;
	int r;

	switch (cc >> 1) {
	case 0: r = (f & KGENOME_EMU_FL_OF) != 0; break;                    /* O   */
	case 1: r = (f & KGENOME_EMU_FL_CF) != 0; break;                    /* B   */
	case 2: r = (f & KGENOME_EMU_FL_ZF) != 0; break;                    /* Z   */
	case 3: r = (f & (KGENOME_EMU_FL_CF | KGENOME_EMU_FL_ZF)) != 0; break;          /* BE  */
	case 4: r = (f & KGENOME_EMU_FL_SF) != 0; break;                    /* S   */
	case 5: r = (f & KGENOME_EMU_FL_PF) != 0; break;                    /* P   */
	case 6: r = ((f & KGENOME_EMU_FL_SF) != 0) != ((f & KGENOME_EMU_FL_OF) != 0); break;   /* L  */
	default: r = (((f & KGENOME_EMU_FL_SF) != 0) != ((f & KGENOME_EMU_FL_OF) != 0)) ||
		     (f & KGENOME_EMU_FL_ZF) != 0; break;                   /* LE  */
	}
	return (cc & 1u) ? !r : r;
}

/*
 * DOES THIS INSTRUCTION CHANGE ANYTHING AT ALL?
 *
 * ONLY THE FORMS THAT PROVABLY CANNOT, which is a short list and deliberately
 * so. `xchg eax, eax` and `mov edi, edi` write a register the value they just
 * read and touch no flag; NOP is the architecture saying the same thing. A
 * junk generator emits them by the dozen because they cost a disassembler a
 * line and cost the program nothing.
 *
 * NOT A DEAD-CODE ANALYSIS, and the difference is the whole safety of it.
 * Measured on a Sality decryption loop, these account for 8 of 256
 * instructions - about three percent. The other junk there is `imul`, `test`
 * and `lea` writing registers nothing reads again, and removing THOSE needs
 * liveness over three internal branches INCLUDING the flags; getting it wrong
 * produces a wrong answer silently, which is the one failure this interpreter
 * must not have. Three percent that is certain beats fifty that is not.
 *
 * A PREFIX DOES NOT MAKE IT ACTIVE. The same generator writes `rep` on
 * instructions that are not string operations, where the architecture ignores
 * it - eight more in the same loop. the decoder reports the instruction it
 * really is, so those arrive here already stripped.
 */
KGENOME_EMU_INLINE int nop_insn(const struct kgenome_emu_insn *ix)
{
	const struct kgenome_x86_op *a, *b;

	if (ix->h.id == KGENOME_X86_I_NOP)
		return 1;
	if (ix->h.id != KGENOME_X86_I_MOV && ix->h.id != KGENOME_X86_I_XCHG)
		return 0;
	if (ix->n < 2u)
		return 0;
	a = &ix->op[0];
	b = &ix->op[1];
	/*
	 * BOTH THE SAME GENERAL REGISTER, AT THE SAME WIDTH AND THE SAME HALF.
	 * `mov ah, al` is two different registers inside one; `mov eax, ax`
	 * is not even the same width. Neither is inert and neither is spelled
	 * differently from one that is.
	 */
	if (a->type != KGENOME_X86_OP_REG || b->type != KGENOME_X86_OP_REG)
		return 0;
	if (a->rtype != KGENOME_X86_REG_GPR ||
	    b->rtype != KGENOME_X86_REG_GPR)
		return 0;
	if (a->reg != b->reg)
		return 0;
	if (a->rsize != b->rsize)
		return 0;
	if (a->high8 != b->high8)
		return 0;
	/*
	 * AND NOT A 32-BIT WRITE IN 64-BIT MODE. `mov eax, eax` zeroes the top
	 * half of RAX on x86-64 - it is the shortest way to truncate a
	 * register, and treating it as a no-op loses half of a value.
	 */
	if (ix->h.mode == 64 && a->rsize == 4u)
		return 0;
	return 1;
}



/* ---- the stack ------------------------------------------------------------ */

/*
 * A push is one machine word, and how wide that is is the mode - see
 * kgenome_emu.bits. Getting this wrong is not a small error: every call, every
 * return address and every GetPC trick reads the stack at the width the code
 * wrote it, so a 32-bit stub on an 8-byte stack loses its own address on the
 * first `call`.
 */
static unsigned wordsz(const struct kgenome_emu *e)
{
	return e->bits == 32 ? 4u : 8u;
}

/*
 * THE STACK MOVES BY THE OPERAND SIZE, NOT BY THE WORD SIZE.
 *
 * A 16-bit PUSH or POP - `push word ptr [rsi]`, `pop ax`, `push r10w`, any of
 * them written with the 0x66 prefix - moves RSP by TWO. This used to move it
 * by eight in 64-bit mode and four in 32-bit, which is what the default
 * operand size would be, and for ordinary code that is the same number.
 *
 * It is not the same number for code that pushes a word on purpose, and an
 * obfuscator does. Measured on an MPRESS sample, its resolver read the export
 * ordinal it had just looked up and hid it behind a constant:
 *
 *      push  word ptr [rsi]          ; the ordinal, 3
 *      push  r10w
 *      mov   r10w, 0x7db2
 *      add   word ptr [rsp+2], r10w  ; hide it
 *      pop   r10w
 *      push  word ptr [rsp]
 *      pop   ax
 *      sub   ax, 0x7db2              ; and take it back
 *      shl   rax, 2
 *
 * With an eight-byte push the `[rsp+2]` in the middle addresses a slot that is
 * not the ordinal, so the value added was never taken back: `sub ax, 0x7db2`
 * ran on 3 rather than on 0x7db5 and produced 0x8251, the shift made that
 * 0x20944, and the resolver read its function table at that offset instead of
 * at 12. It got a zero, added it to the module base, and called the module's
 * MZ header. Everything after that - 310000 instructions of it - was this
 * arithmetic.
 *
 * PUSH imm8 is not a two-byte push: its operand is one byte and the value is
 * sign extended to the stack width, so only a size of exactly two is special.
 */
static int push_w(struct kgenome_emu *e, uint64_t v, unsigned w)
{
	if (w != 2u)
		w = wordsz(e);
	e->gpr[KGENOME_EMU_RSP] -= w;
	if (wordsz(e) == 4u)
		e->gpr[KGENOME_EMU_RSP] &= 0xffffffffu;
	return kgenome_emu_mem_wr(e, e->gpr[KGENOME_EMU_RSP], &v, w);
}

/* Inlined: the POP case of the switch runs it, and a call per pop measured +137M Ir on 112M instructions. */
KGENOME_EMU_INLINE int pop_w(struct kgenome_emu *e, uint64_t *v, unsigned w)
{
	uint64_t t = 0;

	if (w != 2u)
		w = wordsz(e);
	if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RSP], &t, w))
		return 0;
	e->gpr[KGENOME_EMU_RSP] += w;
	if (wordsz(e) == 4u)
		e->gpr[KGENOME_EMU_RSP] &= 0xffffffffu;
	*v = t;
	return 1;
}

int kgenome_emu_push(struct kgenome_emu *e, uint64_t v)
{
	return push_w(e, v, wordsz(e));
}

static int kgenome_emu_pop(struct kgenome_emu *e, uint64_t *v)
{
	return pop_w(e, v, wordsz(e));
}



/* ---- the loop -------------------------------------------------------------- */

/*
 * THE TEXT OF AN INSTRUCTION, for the messages that name one: a refusal and a
 * trace. genotype formats it from the decode it already holds, so there is no
 * second decode and nothing to keep in step.
 */
static int x86_text(const struct kgenome_emu_insn *ix, uint64_t rip, char *buf, size_t n)
{
	return kgenome_x86_format(&ix->h, rip, buf, n) != 0;
}


/* ---- the entry's answers to the loop (struct kgenome_emu_arch) ---------------------------------- */

KGENOME_EMU_INLINE unsigned x86_len(const struct kgenome_emu_insn *ix)
{
	return ix->h.len;
}

/* The decode, and every operand built once: see struct kgenome_emu_insn. */
KGENOME_EMU_INLINE int x86_decode(struct kgenome_emu *e, const uint8_t *code, unsigned n, struct kgenome_emu_insn *ixp)
{
	if (kgenome_x86_decode(&ixp->h, code, n, e->bits == 32 ? 32 : 64) != KGENOME_OK)
		return 0;
	ixp->n = kgenome_x86_nops(&ixp->h);
	kgenome_x86_operands(&ixp->h, ixp->op);
	/* Operands past the last one built are DEFINED, as zero: the run reads op[0] of every
	 * instruction (the operand size, for those that have none), and what a slot or the scratch
	 * held before is the previous occupant's, or uninitialised stack when the cache is off. */
	if (ixp->n < KGENOME_X86_MAX_OPS)
		memset(&ixp->op[ixp->n], 0, (KGENOME_X86_MAX_OPS - ixp->n) * sizeof ixp->op[0]);
	return 1;
}

/*
 * THE FOUR SHAPES A PACKER'S LOADER ENDS WITH, for the handover test of the loop (see
 * kgenome_emu_run_landed): jmp rel32 / call rel32, ret and ret imm16, jmp reg / call reg.
 */
KGENOME_EMU_INLINE int x86_tail(const uint8_t *at_b, unsigned at_len)
{
	int tail = 0;

	/* jmp rel32 / call rel32 */
	if (at_len == 5u &&
	    (at_b[0] == 0xe9u || at_b[0] == 0xe8u))
		tail = 1;
	/* ret, and ret imm16 */
	else if (at_len == 1u && at_b[0] == 0xc3u)
		tail = 1;
	else if (at_len == 3u && at_b[0] == 0xc2u)
		tail = 1;
	/* jmp reg / call reg */
	else if (at_len == 2u && at_b[0] == 0xffu &&
		 (at_b[1] == 0xe0u || at_b[1] == 0xd0u))
		tail = 1;
	return tail;
}

/* The return address a call left: on the stack, one machine word. */
KGENOME_EMU_INLINE int x86_ret_pop(struct kgenome_emu *e, uint64_t *ret)
{
	return kgenome_emu_pop(e, ret);
}

KGENOME_EMU_INLINE int x86_exec(struct kgenome_emu *e, const struct kgenome_emu_run_step *st, uint64_t *next, int *jumped)
{
	struct kgenome_emu_insn *ixp = st->ix;
	uint64_t a = 0, b = 0, r = 0;
	unsigned sz = ixp->op[0].size ? ixp->op[0].size : 8u;

	switch (ixp->h.id) {
	/*
	 * Nothing to do, for a reason rather than by omission. The
	 * fences order accesses between threads and there is one
	 * thread; PAUSE hints at a spin loop; the prefetches and the cache
	 * writebacks move no architectural state; ENDBR is a landing pad;
	 * SERIALIZE orders instructions on a machine that has no pipeline;
	 * FWAIT waits for an x87 exception that is never pending here.
	 */
	case KGENOME_X86_I_NOP:
	case KGENOME_X86_I_LFENCE: case KGENOME_X86_I_SFENCE: case KGENOME_X86_I_MFENCE:
	case KGENOME_X86_I_PAUSE:  case KGENOME_X86_I_ENDBR:
	case KGENOME_X86_I_PREFETCHT0: case KGENOME_X86_I_PREFETCHT1:
	case KGENOME_X86_I_PREFETCHT2: case KGENOME_X86_I_PREFETCHNTA:
	case KGENOME_X86_I_PREFETCHW:
	case KGENOME_X86_I_PREFETCH: case KGENOME_X86_I_PREFETCHE: case KGENOME_X86_I_PREFETCHM:
	case KGENOME_X86_I_PREFETCHWT1: case KGENOME_X86_I_PREFETCHIT0: case KGENOME_X86_I_PREFETCHIT1:
	case KGENOME_X86_I_CLFLUSH: case KGENOME_X86_I_CLFLUSHOPT: case KGENOME_X86_I_CLWB:
	case KGENOME_X86_I_CLDEMOTE: case KGENOME_X86_I_SERIALIZE: case KGENOME_X86_I_WAIT:
		break;





	case KGENOME_X86_I_MOV:
	case KGENOME_X86_I_MOVZX:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b) ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;

	case KGENOME_X86_I_MOVSX:
	case KGENOME_X86_I_MOVSXD: {
		unsigned sb = ixp->op[1].size ? ixp->op[1].size : 1u;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (sb < 8 && (b >> (sb * 8u - 1u)) & 1u)
			b |= ~kgenome_emu_mask_of(sb);
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;
	}

	case KGENOME_X86_I_LEA: {
		uint64_t ea;

		if (!kgenome_emu_ea_of(e, ixp, &ixp->op[1], &ea) ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], ea))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;
	}

	case KGENOME_X86_I_XCHG:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b) ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], b) ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[1], a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;

	case KGENOME_X86_I_ADD: case KGENOME_X86_I_ADC:
	case KGENOME_X86_I_SUB: case KGENOME_X86_I_SBB: case KGENOME_X86_I_CMP:
	case KGENOME_X86_I_AND: case KGENOME_X86_I_OR:  case KGENOME_X86_I_XOR:
	case KGENOME_X86_I_TEST: {
		uint64_t cin = 0;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (ixp->h.id == KGENOME_X86_I_ADC ||
		    ixp->h.id == KGENOME_X86_I_SBB)
			cin = (e->flags & KGENOME_EMU_FL_CF) ? 1u : 0u;
		switch (ixp->h.id) {
		case KGENOME_X86_I_ADD: case KGENOME_X86_I_ADC:
			r = a + b + cin; kgenome_emu_fl_add(e, a, b, cin, sz); break;
		case KGENOME_X86_I_SUB: case KGENOME_X86_I_SBB: case KGENOME_X86_I_CMP:
			r = a - b - cin; kgenome_emu_fl_sub(e, a, b, cin, sz); break;
		case KGENOME_X86_I_AND: case KGENOME_X86_I_TEST:
			r = a & b; kgenome_emu_fl_logic(e, r, sz); break;
		case KGENOME_X86_I_OR:
			r = a | b; kgenome_emu_fl_logic(e, r, sz); break;
		default:
			r = a ^ b; kgenome_emu_fl_logic(e, r, sz); break;
		}
		if (ixp->h.id != KGENOME_X86_I_CMP &&
		    ixp->h.id != KGENOME_X86_I_TEST &&
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;
	}

	case KGENOME_X86_I_INC: case KGENOME_X86_I_DEC: {
		uint64_t cf = e->flags & KGENOME_EMU_FL_CF;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (ixp->h.id == KGENOME_X86_I_INC) {
			r = a + 1u; kgenome_emu_fl_add(e, a, 1u, 0, sz);
		} else {
			r = a - 1u; kgenome_emu_fl_sub(e, a, 1u, 0, sz);
		}
		/* INC and DEC leave CF alone - the one thing that makes
		 * them different from ADD/SUB by one, and the reason a
		 * carry-chained loop written with them still works. */
		e->flags = (e->flags & ~(uint64_t)KGENOME_EMU_FL_CF) | cf;
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;
	}

	case KGENOME_X86_I_NEG:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		r = 0u - a;
		kgenome_emu_fl_sub(e, 0, a, 0, sz);
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;

	case KGENOME_X86_I_NOT:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], ~a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;


	/* SAL is SHL under another name - the encoding is the same and
	 * the decoder reports both. */
	case KGENOME_X86_I_SAL:
	case KGENOME_X86_I_SHL: case KGENOME_X86_I_SHR: case KGENOME_X86_I_SAR: {
		unsigned n, w = sz * 8u;
		uint64_t m = kgenome_emu_mask_of(sz);

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		n = (unsigned)(b & (sz == 8 ? 63u : 31u));
		if (!n) {                         /* no shift, no flags, but a 32 bit register is still written */
			kgenome_emu_op_keep(e, &ixp->op[0], a);
			break;
		}
		a &= m;
		switch (ixp->h.id) {
		case KGENOME_X86_I_SAL:
		case KGENOME_X86_I_SHL: r = n >= w ? 0 : (a << n) & m; break;
		case KGENOME_X86_I_SHR: r = n >= w ? 0 : a >> n; break;
		default: /* SAR: sign-extend, then an arithmetic right shift
			  * capped at w-1 so it saturates to all sign bits. */
			r = (uint64_t)(((int64_t)kgenome_emu_sext(a, sz)) >>
				       (n >= w ? w - 1u : n)) & m;
			break;
		}
		kgenome_emu_fl_logic(e, r, sz);
		/* AF is architecturally undefined after a shift and real
		 * x86 SETS it - see host_dshift16 on why that matters. */
		e->flags |= KGENOME_EMU_FL_AF;
		/* CF is the last bit shifted out, and zero once the count
		 * has cleared the whole width. */
		if (ixp->h.id == KGENOME_X86_I_SHL ||
		    ixp->h.id == KGENOME_X86_I_SAL) {
			if (n <= w && (a >> (w - n)) & 1u)
				e->flags |= KGENOME_EMU_FL_CF;
			/* SDM SHL: for a count of 1, OF = MSB(result) XOR CF. */
			if (n == 1 && (((r >> (w - 1u)) & 1u) != ((e->flags & KGENOME_EMU_FL_CF) ? 1u : 0u)))
				e->flags |= KGENOME_EMU_FL_OF;
		} else if (ixp->h.id == KGENOME_X86_I_SHR) {
			if (n <= w && (a >> (n - 1u)) & 1u)
				e->flags |= KGENOME_EMU_FL_CF;
			/* SDM SHR: for a count of 1, OF = MSB of the original operand.
			 * (SAR by one clears OF, which fl_logic did.) */
			if (n == 1 && ((a >> (w - 1u)) & 1u))
				e->flags |= KGENOME_EMU_FL_OF;
		} else {   /* SAR: bit n-1, or the sign once past the width */
			unsigned cb = n <= w ? n - 1u : w - 1u;

			if ((a >> cb) & 1u)
				e->flags |= KGENOME_EMU_FL_CF;
		}
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;
	}

	case KGENOME_X86_I_ROL: case KGENOME_X86_I_ROR: {
		unsigned n, rc, w = sz * 8u;
		uint64_t m = kgenome_emu_mask_of(sz);

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		n = (unsigned)(b & (sz == 8 ? 63u : 31u));
		if (!n) {                         /* masked count 0: no flags, a 32 bit register is still written */
			kgenome_emu_op_keep(e, &ixp->op[0], a);
			break;
		}
		a &= m;
		rc = n % w;                       /* a rotate is modulo width */
		if (ixp->h.id == KGENOME_X86_I_ROL)
			r = rc ? ((a << rc) | (a >> (w - rc))) & m : a;
		else
			r = rc ? ((a >> rc) | (a << (w - rc))) & m : a;
		/*
		 * ONLY CF and OF - SF/ZF/PF/AF are untouched, so fl_logic
		 * must not run here. CF takes the bit that landed in the
		 * position the rotate feeds it; OF is defined for a count
		 * of one alone and left as-is otherwise.
		 */
		e->flags &= ~(uint64_t)KGENOME_EMU_FL_CF;
		if (ixp->h.id == KGENOME_X86_I_ROL) {
			if (r & 1u)
				e->flags |= KGENOME_EMU_FL_CF;          /* LSB of result */
			if (n == 1) {
				e->flags &= ~(uint64_t)KGENOME_EMU_FL_OF;
				if (((r >> (w - 1u)) & 1u) ^ (r & 1u))
					e->flags |= KGENOME_EMU_FL_OF;
			}
		} else {
			if ((r >> (w - 1u)) & 1u)
				e->flags |= KGENOME_EMU_FL_CF;          /* MSB of result */
			if (n == 1) {
				e->flags &= ~(uint64_t)KGENOME_EMU_FL_OF;
				if (((r >> (w - 1u)) & 1u) ^
				    ((r >> (w - 2u)) & 1u))
					e->flags |= KGENOME_EMU_FL_OF;
			}
		}
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;
	}

	case KGENOME_X86_I_PUSH:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
		    !push_w(e, a, ixp->op[0].size))
			return KGENOME_EMU_RUN_FAULT;
		break;

	case KGENOME_X86_I_POP:
		if (!pop_w(e, &a, ixp->op[0].size))
			return KGENOME_EMU_RUN_FAULT;
		/*
		 * A DESTINATION THAT REFUSED IS NOT A FAULT OF THE GUEST'S. A memory one that could not be
		 * written says so in fault_kind and the loop reports the fault; a segment register (`pop fs`)
		 * is a register this build cannot load, which is UNSUPPORTED. Both answered FAULT, and the
		 * segment case was reported as "access at 0x0" (ED3, 2026-11-14, emu_dispatch.c).
		 */
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;

	/*
	 * PUSHF / POPF - THE PROTECTORS USE THEM, AND FOR THE FLAGS.
	 *
	 * Not carried until now, and what it cost was measured rather
	 * than guessed: three Themida protected PEs ran 25.5, 22.3 and
	 * 44.2 MILLION instructions each - so the loader is reachable,
	 * it computes, and none of the API refusals that emu_unpack.h
	 * warns about had stopped it - and then every one of them
	 * stopped on "unsupported: PUSHFQ". One instruction between a
	 * run that got nowhere and a run that might.
	 *
	 * A protector reaches for these because they are how you save
	 * the flags across a sequence that clobbers them; that a
	 * hardened loader also reads them for its own reasons is a
	 * separate matter and does not change what the instruction is.
	 *
	 * WHAT IS PUSHED IS WHAT THIS BUILD MODELS, plus the two bits
	 * that are not conditions. FL_* already sit at their real
	 * EFLAGS positions, so the value needs no rearranging; bit 1 is
	 * hardwired to 1 on every x86 and bit 9 (IF) is set in every
	 * user mode process, and code that pushes the flags to look at
	 * them would find a zero there suspicious in a way the hardware
	 * never produces.
	 *
	 * WHAT POPF TAKES BACK is only the modelled bits. The rest of
	 * the word is discarded rather than stored, because storing
	 * bits nothing reads would let a later PUSHF hand back a value
	 * this interpreter never reasoned about - and IOPL, NT, RF and
	 * VM are not things a user mode stub can set anyway.
	 */
#define FL_MODELLED (KGENOME_EMU_FL_CF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_AF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_SF | KGENOME_EMU_FL_DF | KGENOME_EMU_FL_OF)
#define FL_ALWAYS_1 (1u << 1)
#define FL_IF       (1u << 9)

	case KGENOME_X86_I_PUSHF:
		if (!kgenome_emu_push(e, e->flags | FL_ALWAYS_1 | FL_IF))
			return KGENOME_EMU_RUN_FAULT;
		break;

	case KGENOME_X86_I_POPF:
		if (!kgenome_emu_pop(e, &a))
			return KGENOME_EMU_RUN_FAULT;
		e->flags = (e->flags & ~(uint64_t)FL_MODELLED) |
			   (a & (uint64_t)FL_MODELLED);
		break;

	/*
	 * PUSHAD / POPAD - 32-BIT ONLY, AND THE STUBS USE THEM.
	 *
	 * amd64 dropped both, so the interpreter never needed them and
	 * did not carry them. A 32-bit encoder reaches for them the
	 * moment it wants to save state around a decode loop:
	 * single_static_bit stopped on its fifteenth instruction with
	 * "unsupported: PUSHAD".
	 *
	 * The order is the architecture's and not a choice: eax, ecx,
	 * edx, ebx, the ORIGINAL esp, ebp, esi, edi. POPAD restores
	 * them in reverse and DISCARDS the saved esp - the stack pointer
	 * is where the pops left it, not what was written.
	 */
	case KGENOME_X86_I_PUSHA:
	case KGENOME_X86_I_PUSHAD: {
		static const unsigned ord[8] = {
			KGENOME_EMU_RAX, KGENOME_EMU_RCX, KGENOME_EMU_RDX,
			KGENOME_EMU_RBX, KGENOME_EMU_RSP, KGENOME_EMU_RBP,
			KGENOME_EMU_RSI, KGENOME_EMU_RDI
		};
		uint64_t sp0 = e->gpr[KGENOME_EMU_RSP];
		unsigned k;

		for (k = 0; k < 8u; k++)
			if (!kgenome_emu_push(e, ord[k] == KGENOME_EMU_RSP
				     ? sp0 : e->gpr[ord[k]]))
				return KGENOME_EMU_RUN_FAULT;
		break;
	}

	case KGENOME_X86_I_POPA:
	case KGENOME_X86_I_POPAD: {
		static const unsigned ord[8] = {
			KGENOME_EMU_RDI, KGENOME_EMU_RSI, KGENOME_EMU_RBP,
			KGENOME_EMU_RSP, KGENOME_EMU_RBX, KGENOME_EMU_RDX,
			KGENOME_EMU_RCX, KGENOME_EMU_RAX
		};
		unsigned k;

		for (k = 0; k < 8u; k++) {
			uint64_t t;

			if (!kgenome_emu_pop(e, &t))
				return KGENOME_EMU_RUN_FAULT;
			if (ord[k] != KGENOME_EMU_RSP)
				e->gpr[ord[k]] = t;   /* esp: discarded */
		}
		break;
	}



	case KGENOME_X86_I_LEAVE:
		e->gpr[KGENOME_EMU_RSP] = e->gpr[KGENOME_EMU_RBP];
		if (!kgenome_emu_pop(e, &e->gpr[KGENOME_EMU_RBP]))
			return KGENOME_EMU_RUN_FAULT;
		break;

	case KGENOME_X86_I_CALLNR:
	case KGENOME_X86_I_CALLNI:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) || !kgenome_emu_push(e, *next))
			return KGENOME_EMU_RUN_FAULT;
		e->prev_call_at = e->last_call_at;
		e->last_call_at = e->rip;
		e->rip = a; *jumped = 1;
		break;

	case KGENOME_X86_I_RETN:
		if (!kgenome_emu_pop(e, &a))
			return KGENOME_EMU_RUN_FAULT;
		if (ixp->n > 0 &&
		    ixp->op[0].type == KGENOME_X86_OP_IMM)
			e->gpr[KGENOME_EMU_RSP] += (uint64_t)ixp->op[0].v;
		e->rip = a; *jumped = 1;
		break;

	case KGENOME_X86_I_JMPNR:
	case KGENOME_X86_I_JMPNI:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		e->rip = a; *jumped = 1;
		break;

	case KGENOME_X86_I_Jcc:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (cond_true(e, kgenome_x86_cond(&ixp->h))) { e->rip = a; *jumped = 1; }
		break;

	case KGENOME_X86_I_SETcc:
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0],
			   cond_true(e, kgenome_x86_cond(&ixp->h)) ? 1u : 0u))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;

	/* SDM CMOVcc: a 32 bit destination is zero-extended into the 64 bit register even
	 * when the condition is false and nothing moves. */
	case KGENOME_X86_I_CMOVcc:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (cond_true(e, kgenome_x86_cond(&ixp->h))) {
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], b))
				return KGENOME_EMU_RUN_UNSUPPORTED;
		} else if (kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a)) {
			kgenome_emu_op_keep(e, &ixp->op[0], a);
		}
		break;

	/* Sign of the accumulator into the whole of RDX/DX. */
	case KGENOME_X86_I_CWD:
		kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, 2, 0,
		       (int16_t)e->gpr[KGENOME_EMU_RAX] < 0 ? 0xffffu : 0u);
		break;
	case KGENOME_X86_I_CDQ: case KGENOME_X86_I_CQO:
		e->gpr[KGENOME_EMU_RDX] =
			(ixp->h.id == KGENOME_X86_I_CQO)
			? ((int64_t)e->gpr[KGENOME_EMU_RAX] < 0 ? ~(uint64_t)0 : 0)
			: (uint64_t)(uint32_t)((int32_t)e->gpr[KGENOME_EMU_RAX] >> 31);
		break;

	/* Widen the accumulator in place. */
	case KGENOME_X86_I_CBW:
		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 2, 0,
		       (uint64_t)(uint16_t)(int16_t)(int8_t)e->gpr[KGENOME_EMU_RAX]);
		break;
	case KGENOME_X86_I_CWDE:
		e->gpr[KGENOME_EMU_RAX] =
			(uint64_t)(uint32_t)(int32_t)(int16_t)e->gpr[KGENOME_EMU_RAX];
		break;
	case KGENOME_X86_I_CDQE:
		e->gpr[KGENOME_EMU_RAX] = (uint64_t)(int64_t)(int32_t)e->gpr[KGENOME_EMU_RAX];
		break;

	/*
	 * BRANCH ON THE COUNTER BEING ZERO, and it does NOT decrement.
	 *
	 * The one member of this family that reads RCX without
	 * touching it. Missing, a kkrunchy-packed binary stopped
	 * 4111 instructions in with "JECXZ" as the reason - the
	 * decompressor's inner loop is built on it - and all five
	 * samples here produced nothing at all.
	 *
	 * The operand size that matters is the ADDRESS size, not the
	 * data size: the same encoding reads CX, ECX or RCX depending
	 * on the address-size prefix and the mode, which is what
	 * the decoder reports in AddrMode.
	 */
	case KGENOME_X86_I_JrCXZ: {
		uint64_t cnt = e->gpr[KGENOME_EMU_RCX];

		if (kgenome_x86_asz(&ixp->h) == 4u)
			cnt = (uint32_t)cnt;
		else if (kgenome_x86_asz(&ixp->h) == 2u)
			cnt = (uint16_t)cnt;
		if (!cnt) {
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				return KGENOME_EMU_RUN_UNSUPPORTED;
			*next = a;
		}
		break;
	}

	/* The count-and-branch forms. RCX is the counter and is NOT a
	 * flag setter - only the branch decision reads ZF. */
	case KGENOME_X86_I_LOOP: case KGENOME_X86_I_LOOPZ: case KGENOME_X86_I_LOOPNZ: {
		uint64_t cnt = --e->gpr[KGENOME_EMU_RCX];
		int take = cnt != 0;

		if (ixp->h.id == KGENOME_X86_I_LOOPZ)
			take = take && (e->flags & KGENOME_EMU_FL_ZF);
		else if (ixp->h.id == KGENOME_X86_I_LOOPNZ)
			take = take && !(e->flags & KGENOME_EMU_FL_ZF);
		if (take) {
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				return KGENOME_EMU_RUN_UNSUPPORTED;
			/* `loop` is not `jumped` (the handover tests below are
			 * about jumps), so the delay-loop count is kept here. */
			if (a <= st->va) {
				if (st->va != e->dl_at) {
					e->dl_at = st->va;
					e->dl_n = 1;
				} else if (++e->dl_n == KGENOME_EMU_DELAY_PROBE) {
					kgenome_emu_delay_note(e, a, st->va, st->len);
				}
			}
			*next = a;
		}
		break;
	}

	case KGENOME_X86_I_BSWAP:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		r = 0;
		for (unsigned i = 0; i < sz; i++)
			r |= ((a >> (i * 8u)) & 0xffu) << ((sz - 1u - i) * 8u);
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		break;

	/*
	 * Count only the operands the encoding spells out. The full
	 * count includes the implicit RFLAGS, so a two-operand
	 * "IMUL rdx, rdi" looked like the three-operand form and read
	 * the flags register as its multiplier.
	 */
	case KGENOME_X86_I_IMUL:
		/*
		 * SDM IMUL two and three operand forms: the product is truncated to the
		 * operand size, and CF = OF = 1 when the SIGNED product does not fit it.
		 */
		if (kgenome_x86_nform(&ixp->h) >= 3 || kgenome_x86_nform(&ixp->h) == 2) {
			int three = kgenome_x86_nform(&ixp->h) >= 3;
			int64_t sx, sy, prod;
			int over;

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[three ? 1 : 0], &a) ||
			    !kgenome_emu_op_rd(e, ixp, &ixp->op[three ? 2 : 1], &b))
				return KGENOME_EMU_RUN_UNSUPPORTED;
			sx = (int64_t)kgenome_emu_sext(a, sz);
			sy = (int64_t)kgenome_emu_sext(b, sz);
			over = __builtin_mul_overflow(sx, sy, &prod);
			if (!over && sz < 8)
				over = (int64_t)kgenome_emu_sext((uint64_t)prod, sz) != prod;
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], (uint64_t)sx * (uint64_t)sy))
				return KGENOME_EMU_RUN_UNSUPPORTED;
			kgenome_emu_fl_cfof(e, over);
		} else {
			/* One operand: the widening form, into RDX:RAX. */
			uint64_t acc = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, sz, 0);
			int64_t  x, y;
			uint64_t ux, uy, hi;

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &b))
				return KGENOME_EMU_RUN_UNSUPPORTED;

			x = (int64_t)kgenome_emu_sext(acc, sz);
			y = (int64_t)kgenome_emu_sext(b, sz);
			ux = (uint64_t)x;
			uy = (uint64_t)y;
			hi = sz < 8 ? (ux * uy) >> (sz * 8u) : 0;      /* the product's upper half */
			if (sz == 8) {
				/* The high half of the signed 128-bit product: the unsigned
				 * high half, less each operand's other factor when it is negative. */
				uint64_t al = ux & 0xffffffffu, ah = ux >> 32;
				uint64_t bl = uy & 0xffffffffu, bh = uy >> 32;
				uint64_t m0 = al * bl, m1 = al * bh, m2 = ah * bl;
				uint64_t carry = ((m0 >> 32) + (m1 & 0xffffffffu) +
						  (m2 & 0xffffffffu)) >> 32;

				hi = ah * bh + (m1 >> 32) + (m2 >> 32) + carry;
				if (x < 0)
					hi -= uy;
				if (y < 0)
					hi -= ux;
			}
			/* SDM IMUL one operand: CF = OF = 1 when the product is not the sign
			 * extension of its low half (RDX:RAX, DX:AX, EDX:EAX, or AX for a byte). */
			if (sz == 8)
				kgenome_emu_fl_cfof(e, hi != ((int64_t)(ux * uy) < 0 ? ~(uint64_t)0 : 0));
			else
				kgenome_emu_fl_cfof(e, (int64_t)kgenome_emu_sext(ux * uy, sz) != (int64_t)(ux * uy));
			if (sz == 1) {
				/* 8-bit: the whole 16-bit product lands in AX (AL
				 * and AH), as MUL does - RDX is not written. It was
				 * AL and DL, which left AH stale and clobbered DL. */
				kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 2, 0, ux * uy);
			} else {
				kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, sz, 0, ux * uy);
				kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, sz, 0, hi);
			}
		}
		break;

	/*
	 * STRING OPERATIONS, ONE ITERATION AT A TIME.
	 *
	 * UPX's NRV decompressor is built out of these and a REP MOVS
	 * is how the payload actually lands, so this is not an optional
	 * corner. The repeat runs here rather than by re-entering the
	 * decoder, but every iteration still costs a unit of budget:
	 * a REP over a megabyte IS a megabyte of work and a budget that
	 * pretended otherwise would be a budget that does not bound
	 * anything.
	 */
	/* The flag instructions, which cost a line each and stop real
	 * samples when they are missing. */
	case KGENOME_X86_I_STC: e->flags |= KGENOME_EMU_FL_CF;  break;
	case KGENOME_X86_I_CLC: e->flags &= ~(uint64_t)KGENOME_EMU_FL_CF; break;
	case KGENOME_X86_I_CMC: e->flags ^= KGENOME_EMU_FL_CF;  break;
	case KGENOME_X86_I_SAHF:
		e->flags = (e->flags & ~(uint64_t)(KGENOME_EMU_FL_SF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_AF |
						   KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF)) |
			   (kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, 2, 0) >> 8 &
			    (KGENOME_EMU_FL_SF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_AF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF));
		break;
	case KGENOME_X86_I_LAHF:
		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 1, 1,
		       (e->flags & (KGENOME_EMU_FL_SF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_AF | KGENOME_EMU_FL_PF |
				    KGENOME_EMU_FL_CF)) | 2u);
		break;

	/*
	 * SALC - `AL = CF ? 0xFF : 0`, one byte, opcode D6, and not in
	 * any Intel manual. It exists because it is short and because a
	 * disassembler that does not know it stops there, which is
	 * exactly why a polymorphic generator emits it. Measured: a
	 * Sality body reaches one 186 million instructions in and the
	 * run ended on it.
	 */
	case KGENOME_X86_I_SALC:
		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 1, 0,
		       (e->flags & KGENOME_EMU_FL_CF) ? 0xffu : 0u);
		break;



	case KGENOME_X86_I_CLD: e->flags &= ~(uint64_t)KGENOME_EMU_FL_DF; break;
	case KGENOME_X86_I_STD: e->flags |=  (uint64_t)KGENOME_EMU_FL_DF; break;


	default: {
		/*
		 * THE LESS COMMON INSTRUCTIONS ARE IN THEIR OWN FUNCTIONS, one per
		 * group, and are asked in turn. Each answers NOT_MINE for an id it
		 * does not carry; when none of them does, the instruction is one this
		 * interpreter does not implement, which is what `default` always said.
		 */
		int rc = kgenome_emu_run_str(e, ixp);

		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_misc(e, ixp);
		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_shift(e, ixp);
		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_sys(e, ixp);
		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_vec(e, ixp);
		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_x87(e, ixp);
		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_bcd(e, ixp);
		if (rc == KGENOME_EMU_RUN_NOT_MINE)
			rc = kgenome_emu_run_ext(e, ixp);
		/* NOT_MINE from the last group is an instruction this entry does not carry: the loop
		 * treats it as UNSUPPORTED (see KGENOME_EMU_RUN_*). */
		return rc;
	}

	}
	return KGENOME_EMU_RUN_OK;
}

/*
 * THE STATE A FRESH x86 MACHINE IS IN, and what its loader assumes is always mapped.
 *
 * THE VSYSCALL PAGE, WHICH A REAL KERNEL ALWAYS PROVIDES.
 *
 * A runtime with no vDSO in its auxv falls back to calling the fixed
 * addresses here, and finding nothing at them looks like a wild jump to
 * 0xffffffffff600000 rather than the ordinary fallback it is. Three
 * entries at their architectural offsets, each doing the syscall it
 * stands for: mov eax, nr / syscall / ret.
 */
static void x86_init(struct kgenome_emu *e)
{
	static const uint16_t nrs[3] = { 96, 201, 309 }; /* gettimeofday,
							 * time, getcpu */
	uint8_t pg[KGENOME_EMU_PAGE];
	unsigned k;

	e->x86.mxcsr = 0x1f80u;             /* the reset value: all exceptions masked */
	e->x86.fcw = 0x037fu;               /* the x87 reset value: all exceptions masked, 64 bit precision, round to nearest */
	memset(pg, 0xcc, sizeof pg);
	for (k = 0; k < 3; k++) {
		uint8_t *p = pg + k * 0x400u;

		p[0] = 0xb8;                             /* mov eax, */
		p[1] = (uint8_t)nrs[k];
		p[2] = (uint8_t)(nrs[k] >> 8);
		p[3] = 0; p[4] = 0;
		p[5] = 0x0f; p[6] = 0x05;                /* syscall */
		p[7] = 0xc3;                             /* ret     */
	}
	kgenome_emu_map(e, KGENOME_EMU_VSYSCALL_BASE, pg, sizeof pg, sizeof pg,
		    KGENOME_EMU_R | KGENOME_EMU_X);
}

/*
 * THE GENERAL REGISTERS A LOADER POINTS AT THE ENTRY: every one but the stack and frame pointers (see
 * emu_unpack_elf.c for why the entry and not zero).
 */
static const uint8_t x86_seed[] = {
	KGENOME_EMU_RAX, KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_RBX,
	KGENOME_EMU_RSI, KGENOME_EMU_RDI
};

_Static_assert(KGENOME_X86_TEXT <= KGENOME_EMU_TEXT_MAX, "the loop's text buffer holds the x86 text");

static enum kgenome_emu_stop x86_run(struct kgenome_emu *e);

static const struct kgenome_emu_arch X86 = {
	.name = "x86",
	.run = x86_run,
	.decode = x86_decode,
	.len = x86_len,
	.inert = nop_insn,
	.exec = x86_exec,
	.text = x86_text,
	.tail = x86_tail,
	.delay = kgenome_emu_delay_note,
	.ret_pop = x86_ret_pop,
	.init = x86_init,
	.text_max = KGENOME_X86_TEXT,
	.sp = KGENOME_EMU_RSP,
	.acc = KGENOME_EMU_RAX,
	.seed = x86_seed,
	.n_seed = (uint8_t)(sizeof x86_seed / sizeof x86_seed[0]),
	/*
	 * i386 passes the number in eax and the arguments in ebx, ecx, edx, esi, edi, ebp - a different
	 * register for every one of them than amd64 uses - and numbers its calls differently (see
	 * kgenome_emu_sys_i386_nr). `int 0x80` is the i386 convention whatever the mode.
	 */
	.sys = {
		{ KGENOME_EMU_RAX, KGENOME_EMU_RAX,
		  { KGENOME_EMU_RBX, KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_RSI, KGENOME_EMU_RDI, KGENOME_EMU_RBP },
		  0xffffffffu, kgenome_emu_sys_i386_nr },
		{ KGENOME_EMU_RAX, KGENOME_EMU_RAX,
		  { KGENOME_EMU_RDI, KGENOME_EMU_RSI, KGENOME_EMU_RDX, KGENOME_EMU_R10, KGENOME_EMU_R8, KGENOME_EMU_R9 },
		  ~(uint64_t)0, NULL },
	},
};

/* The loop of emu_run_private.h, made for this entry: every question it asks of an instruction is a
 * direct call into this file. */
static enum kgenome_emu_stop x86_run(struct kgenome_emu *e)
{
	return kgenome_emu_run_core(e, &X86);
}

const struct kgenome_emu_arch *kgenome_emu_arch_x86(void)
{
	return &X86;
}
