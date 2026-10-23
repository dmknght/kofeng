/*
 * emu_interp.c - the interpreter loop. See emu.h for what it is for.
 * The other files of the emulator are emu_*.c; emu_private.h is what they share.
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

#include "emu_private.h"

/* The first instruction executed in a region nothing has run in yet. Returns
 * the region, marking it seen, or -1. */
static int hop_first(struct kgenome_emu *e, uint64_t rip)
{
	uint32_t i;

	if (!e->hop_unseen || rip < e->hop_lo || rip >= e->hop_hi)
		return -1;
	for (i = 0; i < e->n_hop; i++)
		if (!e->hop[i].seen && rip >= e->hop[i].lo &&
		    rip < e->hop[i].hi) {
			e->hop[i].seen = 1;
			kgenome_emu_hop_bounds(e);
			return (int)i;
		}
	return -1;
}

/* Does the instruction about to run begin with a pattern a module named? */
static int iwatch_hit(const struct kgenome_emu *e, const uint8_t *b, unsigned len)
{
	uint32_t i;

	if (!e->n_iw)
		return 0;
	/* The one instruction a caller asked to get PAST - see kgenome_emu_step.
	 * Without this a watched instruction can be stopped at and never
	 * executed: rip does not move at the pause, so resuming pauses on it
	 * again, forever. */
	if (e->iw_skip)
		return 0;
	if (e->iw_len && len != e->iw_len)
		return 0;
	for (i = 0; i < e->n_iw; i++)
		if (len >= e->iw[i].n &&
		    !memcmp(b, e->iw[i].b, e->iw[i].n))
			return 1;
	return 0;
}


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
static int nop_insn(const struct kgenome_emu_insn *ix)
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

static int pop_w(struct kgenome_emu *e, uint64_t *v, unsigned w)
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
static int insn_text(const struct kgenome_emu_insn *ix, uint64_t rip, char *buf, size_t n)
{
	return kgenome_x86_format(&ix->h, rip, buf, n) != 0;
}

static void fail(struct kgenome_emu *e, enum kgenome_emu_stop s, const struct kgenome_emu_insn *ix)
{
	e->stop = s;
	if (s == KGENOME_EMU_STOP_FAULT) {
		snprintf(e->detail, sizeof e->detail, "%s at %#llx from rip %#llx",
			 e->fault_kind[0] ? e->fault_kind : "access",
			 (unsigned long long)e->fault_va,
			 (unsigned long long)e->rip);
		return;
	}
	if (ix && s == KGENOME_EMU_STOP_UNSUPPORTED) {
		char t[KGENOME_X86_TEXT];

		if (insn_text(ix, e->rip, t, sizeof t)) {
			/*
			 * The WHOLE text. "MOV" is not a thing to go and
			 * implement - every build already has MOV - whereas
			 * "MOV rax, fs:[0x0]" names the actual gap.
			 */
			size_t i = 0;

			while (i + 1u < sizeof e->detail && t[i]) {
				e->detail[i] = t[i];
				i++;
			}
			while (i && e->detail[i - 1u] == ' ')
				i--;
			e->detail[i] = 0;
		}
	}
}

/*
 * THE CACHED INSTRUCTION STILL READS THE SAME BYTES. At most fifteen, compared
 * here in one or two word loads where a library call was made for each of the
 * hundreds of millions of instructions a long run executes - 4.5% of the whole
 * profile in the call alone. Same answer as memcmp(a, b, n) == 0.
 */
static inline int bytes_eq(const uint8_t *a, const uint8_t *b, unsigned n)
{
	uint64_t x, y;

	if (n >= 8u) {
		memcpy(&x, a, 8);
		memcpy(&y, b, 8);
		if (x != y)
			return 0;
		memcpy(&x, a + n - 8u, 8);
		memcpy(&y, b + n - 8u, 8);
		return x == y;
	}
	if (n >= 4u) {
		uint32_t p, q;

		memcpy(&p, a, 4);
		memcpy(&q, b, 4);
		if (p != q)
			return 0;
		memcpy(&p, a + n - 4u, 4);
		memcpy(&q, b + n - 4u, 4);
		return p == q;
	}
	while (n--)
		if (*a++ != *b++)
			return 0;
	return 1;
}


/*
 * What the loop does before it fetches. It lives here and not in the loop because it is a run of
 * checks that either let the instruction go ahead, skip it, or end the run - and the loop is long
 * enough without them.
 */
enum { GATE_GO, GATE_SKIP, GATE_STOP };

static inline int run_gate(struct kgenome_emu *e)
{
	/*
	 * AN EXCEPTION HANDLER RETURNING, recognised by the address it
	 * returns to. Checked before the fetch because the address is
	 * deliberately unmapped: reaching the fetch with it would be a
	 * fault, which is the safe way for this to fail if it is ever
	 * removed.
	 */
	/*
	 * THE HANDOFF, CHECKED BEFORE THE FETCH. See kgenome_emu_watch_exec
	 * for what the ranges are and where the idea came from. Whatever
	 * the loader has written is in memory now and the harvest is
	 * about to read it; going on would run the program itself,
	 * which is not what an unpacker is for.
	 */
	/*
	 * A STAGE THIS RUN HAS NOT BEEN IN BEFORE. Copied and left
	 * running - see kgenome_emu_hop_add.
	 */
	if (e->n_hop) {
		int h = hop_first(e, e->rip);

		if (h >= 0) {
			if (!e->hop_first_insn) {
				e->hop_first_insn = e->insn ? e->insn : 1;
				e->hop_first_rip = e->rip;
			}
			e->hop_last_rip = e->rip;
			e->hop_count++;
			kgenome_emu_snap_take(e, e->hop[h].lo,
				  e->hop[h].hi - e->hop[h].lo);
		}
	}

	if (e->n_xwatch) {
		/*
		 * THE EDGE, NOT THE ADDRESS.
		 *
		 * This was "rip is inside a watched range", which is
		 * right for a packer whose program sits where the
		 * loader never executes - MPRESS, Oreans - and wrong
		 * for one that shares a section with it. Measured on a
		 * PECompact2 sample: the entry section is the one the
		 * image decompresses into AND the one the entry point
		 * is in, so naming it ended the run at instruction 0,
		 * and naming every other section ended it six
		 * instructions later at the stub's own first jump.
		 *
		 * A handover is the loader LEAVING and the program
		 * being entered, so it is a transition. For a range the
		 * loader never runs in, every arrival is a transition
		 * and nothing changes; for one it starts in, the run
		 * has to leave before coming back can mean anything.
		 */
		/* Is rip inside a watched region? The edge is what
		 * matters - see xw_was_in. */
		int in = kgenome_emu_wrange_has(e->xwatch, e->n_xwatch, e->rip);

		if (in && e->xw_have_prev && !e->xw_was_in) {
			e->stop = KGENOME_EMU_STOP_HANDOFF;
			snprintf(e->detail, sizeof e->detail,
				 "handed over at %#llx",
				 (unsigned long long)e->rip);
			return GATE_STOP;
		}
		e->xw_was_in = in;
		e->xw_have_prev = 1;
	}

	if (e->exc_phase && e->rip == kgenome_emu_win_ret_magic(e)) {
		if (kgenome_emu_win_exc_return(e))
			return GATE_SKIP;
		fail(e, KGENOME_EMU_STOP_FAULT, NULL);
		return GATE_STOP;
	}

	/*
	 * A CALL TO ADDRESS ZERO IS AN IMPORT THIS ENVIRONMENT DOES
	 * NOT HAVE, AND IT IS NOT A CRASH.
	 *
	 * A stub that resolves its own imports walks a module's export
	 * directory, compares names, and on a match adds the function's
	 * RVA to the module base. This environment's kernel32 exports
	 * eighty-odd names against the real one's fifteen hundred, so a
	 * name it wants and this does not have comes back as a zero RVA
	 * - and the stub calls the module base, or, where it had the
	 * address in a register, calls zero.
	 *
	 * WHAT WINDOWS WOULD HAVE DONE is return from a function this
	 * file does not implement, so that is what happens here: pop
	 * the return address, put 0 in the accumulator and carry on.
	 * The stub gets a useless answer to a question this build
	 * cannot answer, which is exactly what every other unimplemented
	 * API here gives it, and keeps going.
	 *
	 * FAULTING INSTEAD THROWS THE RUN AWAY. Measured on an MPRESS
	 * sample: it resolved LoadLibraryA, loaded five libraries,
	 * resolved SetLastError and GetLastError, and then called one
	 * name too many at instruction 5662007 - and a fault at rip 0
	 * ends the run with its payload unharvested.
	 *
	 * BOUNDED, because a guest that does this forever is not
	 * unpacking. Past KGENOME_EMU_NULL_CALLS the answer is no longer
	 * plausible and the fault it would have been happens instead.
	 *
	 * Only the UNMAPPED null page. A guest that genuinely mapped
	 * page zero and put code there is executing its own code.
	 */
	if (e->rip < KGENOME_EMU_PAGE && !kgenome_emu_page_lookup(e, e->rip)) {
		uint64_t ret = 0;

		if (e->null_calls < KGENOME_EMU_NULL_CALLS &&
		    kgenome_emu_pop(e, &ret) && ret) {
			/* Freeze the instruction trace at the FIRST of
			 * these: the call that could not be resolved
			 * is upstream of every wrong value after it. */
			if (e->itr && e->itr_on_null && !e->null_calls)
				e->itr_frozen = 1;
			e->null_calls++;
			e->gpr[KGENOME_EMU_RAX] = 0;
			e->rip = ret;
			return GATE_SKIP;
		}
		e->fault_va = e->rip;
		memcpy(e->fault_kind, "call0", 6);
		fail(e, KGENOME_EMU_STOP_FAULT, NULL);
		return GATE_STOP;
	}

	/*
	 * EXECUTE PERMISSION, CHECKED ONCE PER PAGE.
	 *
	 * Not per instruction: a straight run stays on one page and the
	 * answer cannot change under it, so the page it last fetched
	 * from is remembered and only a move to another page pays for a
	 * lookup. That makes the check a compare in the common case.
	 *
	 * What it is for: a guest that walks a library's export
	 * directory for a name this environment does not list gets 0
	 * back, adds it to the module base and calls the module's own
	 * MZ header. Without this the header is executable, the zeroes
	 * decode as `add [rax],al`, and the run marches two bytes at a
	 * time until something faults far away - measured on an MPRESS
	 * sample, 310701 instructions ending at an address built out of
	 * header bytes. With it the fault is AT THE BASE, which names
	 * the module and says the miss was an export lookup.
	 */
	if ((e->rip & ~(uint64_t)(KGENOME_EMU_PAGE - 1u)) != e->fetch_page) {
		struct kgenome_emu_page *fp = kgenome_emu_page_lookup(e, e->rip);

		/*
		 * WRITTEN AND THEN EXECUTED: TAKE IT AND CARRY ON.
		 *
		 * Memory a run wrote and then ran is the definition of
		 * something it produced, and it is the only signal that
		 * works when a program decrypts a piece of ITSELF - no
		 * mprotect, no section, no packer to declare anything.
		 * stop_on_written_jump saw the same thing and STOPPED,
		 * which is why it is off by default: measured, a
		 * PECompact2 sample stopped eighteen instructions in.
		 * Snapshotting and continuing is Unipacker's lesson
		 * about section hopping applied to the same signal -
		 * see THIRD-PARTY.md.
		 *
		 * WHOLE CONTIGUOUS RUN, because a decrypted function is
		 * not one page and a snapshot per page hands back
		 * rubble. Bounded, and each page is taken once.
		 *
		 * NOT THE STACK. A return address is written and then
		 * executed at every call, and the stack is where this
		 * would otherwise fire constantly and collect nothing.
		 */
		if (fp && fp->written && !fp->snapped &&
		    (fp->prot & KGENOME_EMU_X) &&
		    !(e->rip >= e->stack_lo && e->rip < e->stack_hi)) {
			uint64_t base = e->rip &
					~(uint64_t)(KGENOME_EMU_PAGE - 1u);
			uint64_t lo = base, hi = base + KGENOME_EMU_PAGE;
			unsigned k;
			struct kgenome_emu_page *q;

			for (k = 0; k < KGENOME_EMU_WEX_SPAN_PAGES; k++) {
				if (lo < KGENOME_EMU_PAGE)
					break;
				q = kgenome_emu_page_lookup(e, lo - KGENOME_EMU_PAGE);
				if (!q || !q->written || q->snapped)
					break;
				lo -= KGENOME_EMU_PAGE;
			}
			for (k = 0; k < KGENOME_EMU_WEX_SPAN_PAGES; k++) {
				q = kgenome_emu_page_lookup(e, hi);
				if (!q || !q->written || q->snapped)
					break;
				hi += KGENOME_EMU_PAGE;
			}
			for (base = lo; base < hi;
			     base += KGENOME_EMU_PAGE) {
				q = kgenome_emu_page_lookup(e, base);
				if (q)
					q->snapped = 1;
			}
			kgenome_emu_snap_take(e, lo, hi - lo);

		}

		if (fp && !(fp->prot & KGENOME_EMU_X)) {
			e->fault_va = e->rip;
			memcpy(e->fault_kind, "exec", 5);
			fail(e, KGENOME_EMU_STOP_FAULT, NULL);
			return GATE_STOP;
		}
		if (fp)
			e->fetch_page = e->rip &
					~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	}
	return GATE_GO;
}

/*
 * THE INSTRUCTION ABOUT TO RUN, as ONE record. Everything the run decides from the instruction
 * after the decode - the watch for a byte pattern, the shape of a transfer for the handover test,
 * the address it came from - is read from here, and run_fetch fills it in one place (step_fill)
 * whether the decode came from the instruction cache or from a fresh fetch. The cache is an
 * acceleration; a stop, a watch or a handover must see exactly the bytes at the executed
 * address either way.
 *
 * WHY: these were scattered locals, and the bytes were a pointer at the 16-byte fetch buffer
 * that only a cache MISS filled. A hit left it holding (uninitialised, then stale) whatever was
 * last decoded, so a cached `syscall` was not watched, a cached non-syscall was, and a handover
 * by a cached `jmp rax` was judged by the wrong bytes.
 */
struct run_step {
	uint64_t va;                      /* where it is                                    */
	unsigned len;                     /* how long it is (== ix->h.len)                  */
	const uint8_t *b;                 /* its `len` bytes: the cache slot's or the fetch */
	struct kgenome_emu_insn *ix;      /* decoded: the cache slot itself, or the scratch */
	struct icache_ent *ent;           /* the cache slot, NULL when the cache is off      */
};

static inline void step_fill(struct run_step *st, uint64_t va, struct kgenome_emu_insn *ix,
			     struct icache_ent *ent, const uint8_t *bytes)
{
	st->va = va;
	st->len = ix->h.len;
	st->b = bytes;
	st->ix = ix;
	st->ent = ent;
}

/*
 * THE FETCH AND THE DECODE, through the instruction cache. Leaves the instruction in *st (see
 * run_step; decoded in the cache slot itself on a cache-able fetch, else in *ixbuf). Returns 1
 * when the run is to end here, 0 to execute.
 */
static inline int run_fetch(struct kgenome_emu *e, uint8_t (*cp)[16], struct kgenome_emu_insn *ixbuf,
			    struct run_step *st)
{
	uint8_t *code = *cp;
	struct kgenome_emu_insn *ixp;
	struct icache_ent *ent;
	struct kgenome_emu_page *fpg;

	/*
	 * THE CACHE FIRST - see `ic`. A hit skips both the fetch and
	 * the decode, which together are most of what an interpreted
	 * instruction costs.
	 */
	ent = NULL;
	fpg = e->ic ? kgenome_emu_page_lookup(e, e->rip) : NULL;
	if (fpg) {
		unsigned poff = (unsigned)(e->rip & (KGENOME_EMU_PAGE - 1u));

		{
			ent = &e->ic[((e->rip * 0x9e3779b97f4a7c15ull) >> 40) &
				     (KGENOME_EMU_ICACHE - 1u)];
			if (ent->valid && ent->va == e->rip &&
			    ent->pg == fpg &&
			    poff + ent->len <= KGENOME_EMU_PAGE &&
			    bytes_eq(fpg->data + poff, ent->bytes,
				     ent->len)) {
				/*
				 * POINTED AT, NOT COPIED. An struct kgenome_emu_insn is
				 * 480 bytes and this path runs tens of
				 * millions of times - measured on one
				 * Sality slice, 17.2 million hits, which
				 * is 8.3 GB of memcpy for bytes that are
				 * already in the right place.
				 */
				e->ic_hit++;
				step_fill(st, e->rip, &ent->ix, ent, ent->bytes);
				return 0;
			}
			e->ic_miss++;
			if (!ent->valid)
				e->m_empty++;
			else if (ent->va != e->rip)
				e->m_va++;
			else if (ent->pg != fpg)
				e->m_pg++;
			else
				e->m_bytes++;
			ent->valid = 0;
			ent->pg = fpg;
			ent->va = e->rip;
		}
		/*
		 * AND THE FETCH STRAIGHT OUT OF THE PAGE when the whole
		 * of it lies inside one. mem_rd walks the page table
		 * ONCE PER BYTE - sixteen lookups for every instruction
		 * decoded - and the page is already in hand here.
		 */
		if (poff + sizeof *cp <= KGENOME_EMU_PAGE) {
			memcpy(code, fpg->data + poff, sizeof *cp);
			goto fetched;
		}
	}
	e->in_fetch = 1;
	if (!kgenome_emu_mem_rd(e, e->rip, code, sizeof *cp)) {
		/* The tail of a mapping is a legitimate place to be: try
		 * the shortest fetch that can still hold an instruction
		 * before calling it a fault. */
		unsigned got = 0;

		while (got < sizeof *cp &&
		       kgenome_emu_mem_rd(e, e->rip + got, code + got, 1))
			got++;
		if (got < 1) {
			e->fault_va = e->rip;
			memcpy(e->fault_kind, "fetch", 6);
			fail(e, KGENOME_EMU_STOP_FAULT, NULL);
			return 1;
		}
		memset(code + got, 0, sizeof *cp - got);
	}
fetched:
	e->in_fetch = 0;
	/*
	 * DECODED INTO THE CACHE SLOT ITSELF, so that filling it costs
	 * nothing beyond the decode. The length is not known until
	 * afterwards, so whether it may be KEPT is decided then - an
	 * instruction straddling a page boundary depends on two pages
	 * and this checks one.
	 */
	ixp = ent ? &ent->ix : ixbuf;
	if (kgenome_x86_decode(&ixp->h, code, sizeof *cp, e->bits == 32 ? 32 : 64) != KGENOME_OK) {
		fail(e, KGENOME_EMU_STOP_DECODE, NULL);
		return 1;
	}
	ixp->n = kgenome_x86_nops(&ixp->h);
	kgenome_x86_operands(&ixp->h, ixp->op);
	/* Operands past the last one built are DEFINED, as zero: the run reads op[0] of every
	 * instruction (the operand size, for those that have none), and what a slot or the scratch
	 * held before is the previous occupant's, or uninitialised stack when the cache is off. */
	if (ixp->n < KGENOME_X86_MAX_OPS)
		memset(&ixp->op[ixp->n], 0, (KGENOME_X86_MAX_OPS - ixp->n) * sizeof ixp->op[0]);
	/* The slot now holds THIS instruction whether or not it is kept
	 * below, so what it said about the previous occupant is void. An
	 * instruction straddling a page is decoded here and not kept; its
	 * slot's inert flag would otherwise be read as its own, and a real
	 * instruction stepped over. */
	if (ent)
		ent->inert = 0;
	/* Kept only when it lies inside one page - see `ic`. */
	if (ent && ((e->rip + ixp->h.len - 1u) &
		    ~(uint64_t)(KGENOME_EMU_PAGE - 1u))
		   == (e->rip & ~(uint64_t)(KGENOME_EMU_PAGE - 1u))) {
		memcpy(ent->bytes, code, ixp->h.len);
		ent->len = ixp->h.len;
		ent->inert = (uint8_t)nop_insn(ixp);
		ent->valid = 1;
	}
	step_fill(st, e->rip, ixp, ent, code);
	return 0;
}

/*
 * What follows an instruction that ran: step to the next one, or, when the instruction transferred
 * control, record where it came from and test whether this is a handover. Returns 1 when the run
 * is to end here (e->stop says why).
 */
static inline int run_landed(struct kgenome_emu *e, int jumped, uint64_t next,
			     const struct run_step *st)
{
	const uint64_t at = st->va;
	const unsigned at_len = st->len;
	const uint8_t *at_b = st->b;

	if (!jumped)
		e->rip = next;
	else {
		e->last_branch_at = at;
		/* A backward branch taken again and again from one place is a loop:
		 * see emu_loop.c for the one kind of it that is not run. */
		if (e->rip <= at) {
			if (at != e->dl_at) {
				e->dl_at = at;
				e->dl_n = 1;
			} else if (++e->dl_n == KGENOME_EMU_DELAY_PROBE) {
				kgenome_emu_delay_note(e, e->rip, at, at_len);
			}
		}
		/*
		 * A jump into a page the run wrote LOOKS like the
		 * handoff, and often is not - see
		 * kgenome_emu_cfg.stop_on_written_jump for what UPX does to
		 * that idea. Off unless the caller asked.
		 */
		/*
		 * A WRITTEN PAGE AND OUTSIDE THE STUB. See
		 * kgenome_emu_set_stub_range: the first half alone fires on
		 * a stub unpacking into its own section, which is the
		 * commonest shape there is.
		 */
		struct kgenome_emu_page *p = e->stop_on_written_jump
				 ? kgenome_emu_page_find(e, e->rip) : NULL;

		/*
		 * NOR THE STACK. A handler that resumes through a
		 * thunk it built on the stack has written a page and
		 * jumped to it, and that is not a program starting -
		 * it is the same code carrying on. Measured on a
		 * PECompact2 sample, which does exactly this out of
		 * its own exception handler eighteen instructions in.
		 */
		if (p && p->written && e->stub_hi &&
		    e->rip >= e->stub_lo && e->rip < e->stub_hi)
			p = NULL;
		if (p && p->written && e->stack_hi &&
		    e->rip >= e->stack_lo && e->rip < e->stack_hi)
			p = NULL;

		if (p && p->written) {
			snprintf(e->detail, sizeof e->detail,
				 "written jump to %#llx",
				 (unsigned long long)e->rip);
			e->stop = KGENOME_EMU_STOP_HANDOFF;
			return 1;
		}

		/*
		 * ---- THE HANDOVER, BY THE SHAPE OF THE TRANSFER ----
		 *
		 * A stub ends by giving control to the program with
		 * the stack exactly as it found it. That last part is
		 * the whole discriminator: a stub CALLING something
		 * has pushed a return address, a stub HANDING OVER has
		 * not - it has undone every push it made. XVolkolak's
		 * XEmulUnpacker builds its per-packer OEP predicates
		 * on that one invariant, and its MPRESS, PECompact and
		 * Themida rules differ only in which tail instruction
		 * they accept. See THIRD-PARTY.md.
		 *
		 * WHAT IS REQUIRED OF THE TARGET: inside the image, and
		 * on a page this run WROTE. Together those say the
		 * destination is code the stub produced rather than
		 * code it came with, which is what an unpacker is
		 * looking for.
		 *
		 * WHAT IS REQUIRED OF THE TAIL: one of the four shapes
		 * a packer ends with. Without this the balanced-stack
		 * test alone fires on ordinary returns inside the stub.
		 */
		/*
		 * THE CANDIDATE HELD. Nothing has been handed over by
		 * a later transfer for KGENOME_EMU_OEP_QUIET instructions, so the
		 * code the candidate entered is not a stage of a loader
		 * - a stage is followed by the next stage - and it is
		 * the program.
		 */
		if (e->oep_cand &&
		    e->insn - e->oep_cand_insn > KGENOME_EMU_OEP_QUIET) {
			snprintf(e->detail, sizeof e->detail,
				 "handover to %#llx, unchallenged for "
				 "%llu instructions",
				 (unsigned long long)e->oep_cand_rip,
				 (unsigned long long)(e->insn -
						      e->oep_cand_insn));
			e->stop = KGENOME_EMU_STOP_HANDOFF;
			return 1;
		}

		if (e->oep_watch && e->sp0_set &&
		    e->gpr[KGENOME_EMU_RSP] == e->sp0 &&
		    e->img_hi > e->img_lo &&
		    e->rip >= e->img_lo && e->rip < e->img_hi &&
		    !(e->stack_hi && e->rip >= e->stack_lo &&
		      e->rip < e->stack_hi)) {
			struct kgenome_emu_page *t = kgenome_emu_page_find(e, e->rip);
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

			/*
			 * AND THE DIRECTION, WHICH IS WHAT KEEPS THIS
			 * FROM FIRING INSIDE THE STUB.
			 *
			 * A loader jumping about within itself does
			 * every other part of this test: the stack is
			 * balanced after a `popfq; ret`, the target is
			 * in the image, and the page is written
			 * because the loader expanded into it.
			 * Measured on a Themida sample, that fired
			 * 25440 instructions in on a jump DOWN from
			 * one part of the loader to another.
			 *
			 * XEmulUnpacker's rules each carry a direction
			 * - Themida wants a jump UP, PECompact one
			 * DOWN and out of a region that is not the
			 * image. Both are the same statement: the
			 * transfer leaves where the stub was working.
			 * Without a module to say which packer this
			 * is, the union of the two is what can be
			 * required, and it is still enough to drop the
			 * intra-loader case above.
			 */
			/*
			 * A CANDIDATE, NOT A VERDICT: the transfer leaves
			 * code the FILE supplied for code the RUN produced.
			 * The source page was never written by the guest, so
			 * it is the stub as shipped; the target page was.
			 * With no direction in it this is what a UPX stub
			 * does - it sits in the last section and jumps BACK
			 * to the entry point, which the direction test below
			 * reads as a loader moving within itself - and it is
			 * also what a protector does between its stages. The
			 * two differ in what comes next, so this arms a
			 * timer rather than stopping: see oep_cand.
			 *
			 * NOT INTO THE STUB'S OWN SECTION: a stub that
			 * expands inside the section it runs from, or
			 * relocates a piece of itself there, is code moving
			 * within the loader.
			 */
			struct kgenome_emu_page *sp = kgenome_emu_page_find(e, at);
			int from_file = sp && !sp->gwritten &&
					!(e->stub_hi &&
					  e->rip >= e->stub_lo &&
					  e->rip < e->stub_hi);

			if (tail && t && t->gwritten &&
			    (at < e->rip ||
			     at < e->img_lo || at >= e->img_hi)) {
				snprintf(e->detail, sizeof e->detail,
					 "handover to %#llx, stack "
					 "balanced, %u pages written",
					 (unsigned long long)e->rip,
					 kgenome_emu_written_run_pages(e, e->rip, 65536u));
				e->stop = KGENOME_EMU_STOP_HANDOFF;
				return 1;
			}
			if (tail && t && t->gwritten && from_file &&
			    kgenome_emu_written_run_pages(e, e->rip, KGENOME_EMU_OEP_MIN_PAGES) >=
				    KGENOME_EMU_OEP_MIN_PAGES) {
				e->oep_cand_insn = e->insn;
				e->oep_cand_rip = e->rip;
				e->oep_cand = 1;
				KOF_TRACE("[oep] candidate insn=%llu to=%#llx pages=%u\n",
					  (unsigned long long)e->insn,
					  (unsigned long long)e->rip,
					  kgenome_emu_written_run_pages(e, e->rip, 65536u));
			}
		}
	}
	return 0;
}

enum kgenome_emu_stop kgenome_emu_run(struct kgenome_emu *e)
{
	if (!e)
		return KGENOME_EMU_STOP_FAULT;  /* as kgenome_emu_step answers it */
	e->stop = KGENOME_EMU_STOP_BUDGET;
	e->detail[0] = 0;
	e->running = 1;

	while (e->insn < e->max_insn) {
		uint8_t code[16];
		struct kgenome_emu_insn ixbuf;
		struct run_step st;
		struct kgenome_emu_insn *ixp;

		uint64_t a = 0, b = 0, r = 0, next;
		unsigned sz;
		int jumped = 0;


		{
			int g = run_gate(e);

			if (g == GATE_STOP)
				goto done;
			if (g == GATE_SKIP)
				continue;
		}



		if (run_fetch(e, &code, &ixbuf, &st))
			break;
		/* From here on the instruction is `st`; by the handover test e->rip is the TARGET. */
		ixp = st.ix;


		if (!e->sp0_set) {
			e->sp0 = e->gpr[KGENOME_EMU_RSP];
			e->sp0_set = 1;
		}
		/*
		 * PAUSED ON WHAT IS ABOUT TO RUN, BEFORE IT RUNS.
		 *
		 * Here and not after the execute, because the point is to see
		 * the machine as the guest left it AT that instruction: for a
		 * `ret`, the address it is about to return to is still on the
		 * stack, and one instruction later it is not. See
		 * kgenome_emu_watch_insn.
		 *
		 * The run is resumable from here - rip has not moved - so the
		 * module reads what it wants and calls kgenome_emu_run again.
		 */
		if (iwatch_hit(e, st.b, st.len)) {
			snprintf(e->detail, sizeof e->detail,
				 "watched instruction at %#llx",
				 (unsigned long long)e->rip);
			e->stop = KGENOME_EMU_STOP_INSN;
			goto done;
		}
		if (e->hot) {
			uint32_t h = (uint32_t)((e->rip * 2654435761u) >> 8) &
				     e->hot_mask;
			uint32_t q;

			for (q = 0; q < 8u; q++) {
				uint32_t k = (h + q) & e->hot_mask;

				if (!e->hot[k].n || e->hot[k].va == e->rip) {
					e->hot[k].va = e->rip;
					e->hot[k].n++;
					break;
				}
			}
		}
		/*
		 * AND HAS THE DECRYPTION STOPPED - see KGENOME_EMU_QUIET. Counted
		 * per instruction here, reset by the write that completes a
		 * read-write pair, and only ever consulted once the guest has
		 * shown it decrypts at all.
		 */
		/*
		 * OFF UNTIL IT IS RIGHT - see KGENOME_EMU_QUIET.
		 *
		 * The signal is measured and real; the THRESHOLD is not settled.
		 * Measured on four Sality samples: three stop correctly and the
		 * fourth stops 11,066 instructions in, having decrypted
		 * nothing, because a handful of sequential writes before the
		 * decryption starts arm the test. A stop rule that is right
		 * three times in four is a rule that loses a detection, so it
		 * stays behind a flag until the arming condition is measured
		 * across more than one family.
		 */
		if (e->active_n)
			e->since_active++;
		if (e->quiet_on && e->active_n &&
		    e->since_active > KGENOME_EMU_QUIET) {
			snprintf(e->detail, sizeof e->detail,
				 "%llu instructions since the last decryption "
				 "write, after %llu of them",
				 (unsigned long long)e->since_active,
				 (unsigned long long)e->active_n);
			e->stop = KGENOME_EMU_STOP_QUIET;
			goto done;
		}
		e->trace[e->trace_n++ % KGENOME_EMU_TRACE] = e->rip;
		if (e->itr && !e->itr_frozen &&
		    ((e->itr_at && e->rip == e->itr_at) ||
		     (e->itr_until && e->insn >= e->itr_until))) {

			e->itr_frozen = 1;
			/* And what memory looked like AT THE FREEZE, which is
			 * the only moment a key a guest is comparing against
			 * is still where it was put. Reading it when the run
			 * stops is far too late. */
		}
		if (e->itr && !e->itr_frozen) {
			struct itrace *it = &e->itr[e->itr_n++ % e->itr_cap];
			char t[KGENOME_X86_TEXT];
			unsigned q = 0;

			it->rip = e->rip;
			memcpy(it->gpr, e->gpr, sizeof it->gpr);
			/* The registers are copied BEFORE the instruction runs,
			 * which is the point: they are its inputs. */
			if (insn_text(ixp, e->rip, t, sizeof t))
				while (q + 1u < sizeof it->txt && t[q]) {
					it->txt[q] = t[q];
					q++;
				}
			it->txt[q] = 0;
		}
		/* Cleared per instruction so the stop below can tell an operand
		 * this build cannot express from one it simply could not read.
		 * They were reported the same way, and an ordinary CMP against
		 * an unmapped address read as a missing instruction. */
		e->fault_va = 0;
		e->fault_kind[0] = 0;
		/*
		 * STOP WHEN IT STOPS PRODUCING.
		 *
		 * The instruction budget bounds a run that is working; nothing
		 * bounded one that is not. An unexpected object - junk padding,
		 * a loop waiting on something that will not happen, a decoder
		 * fed input it cannot use - would spin to the ceiling and cost
		 * a scan every second of it for nothing.
		 *
		 * Producing means touching a page for the first time, because
		 * that is what unpacking IS. Measured against the densest real
		 * work here, an interpreted LZMA decoder writing 2.7 MB over
		 * 250 million instructions: a new page every ~370 000. The
		 * ceiling below is an order of magnitude above that, so it
		 * cannot interrupt work, and it cuts an idle run to a fraction
		 * of a second whatever the budget allows.
		 */
		if (e->insn - e->last_new_page > e->idle_max)
			e->idle_max = e->insn - e->last_new_page;
		if (e->insn - e->last_new_page > e->idle) {
			fail(e, KGENOME_EMU_STOP_STALLED, NULL);
			break;
		}
		/* And the clock, when one was set - see kgenome_emu_set_deadline.
		 * Masked so the read happens once every 64K instructions. */
		if (e->deadline_ms && !(e->insn & 0xffffu) &&
		    kgenome_emu_now_ms() - e->started_ms > e->deadline_ms) {
			snprintf(e->detail, sizeof e->detail,
				 "deadline after %llu ms, %llu instructions",
				 (unsigned long long)(kgenome_emu_now_ms() - e->started_ms),
				 (unsigned long long)e->insn);
			e->stop = KGENOME_EMU_STOP_BUDGET;
			break;
		}
		next = e->rip + ixp->h.len;
		sz = ixp->op[0].size ? ixp->op[0].size : 8u;
		e->insn++;

		/*
		 * AN INSTRUCTION THAT CANNOT CHANGE ANYTHING IS STEPPED OVER -
		 * see nop_insn, which decided this once when the entry was
		 * decoded.
		 *
		 * AFTER ALL THE BOOKKEEPING AND BEFORE THE SWITCH, deliberately:
		 * the instruction still counts, still enters the trace, still
		 * satisfies a module's watch and still moves the deadline. The
		 * only thing skipped is the work of executing something whose
		 * result is the state it started from. A junk generator emits
		 * these by the dozen - measured, eight of the 256 instructions
		 * in one Sality decryption loop.
		 *
		 * ONLY FROM THE CACHE. Deciding it on a miss would cost the test
		 * on every first sight of an instruction to save the execution
		 * of a handful, and the miss path is already the expensive one.
		 */
		if (st.ent && st.ent->inert) {
			e->rip = next;
			continue;
		}

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
				goto unsupported;
			break;

		case KGENOME_X86_I_MOVSX:
		case KGENOME_X86_I_MOVSXD: {
			unsigned sb = ixp->op[1].size ? ixp->op[1].size : 1u;

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
				goto unsupported;
			if (sb < 8 && (b >> (sb * 8u - 1u)) & 1u)
				b |= ~kgenome_emu_mask_of(sb);
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], b))
				goto unsupported;
			break;
		}

		case KGENOME_X86_I_LEA: {
			uint64_t ea;

			if (!kgenome_emu_ea_of(e, ixp, &ixp->op[1], &ea) ||
			    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], ea))
				goto unsupported;
			break;
		}

		case KGENOME_X86_I_XCHG:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
			    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b) ||
			    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], b) ||
			    !kgenome_emu_op_wr(e, ixp, &ixp->op[1], a))
				goto unsupported;
			break;

		case KGENOME_X86_I_ADD: case KGENOME_X86_I_ADC:
		case KGENOME_X86_I_SUB: case KGENOME_X86_I_SBB: case KGENOME_X86_I_CMP:
		case KGENOME_X86_I_AND: case KGENOME_X86_I_OR:  case KGENOME_X86_I_XOR:
		case KGENOME_X86_I_TEST: {
			uint64_t cin = 0;

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
			    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
				goto unsupported;
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
				goto unsupported;
			break;
		}

		case KGENOME_X86_I_INC: case KGENOME_X86_I_DEC: {
			uint64_t cf = e->flags & KGENOME_EMU_FL_CF;

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				goto unsupported;
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
				goto unsupported;
			break;
		}

		case KGENOME_X86_I_NEG:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				goto unsupported;
			r = 0u - a;
			kgenome_emu_fl_sub(e, 0, a, 0, sz);
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
				goto unsupported;
			break;

		case KGENOME_X86_I_NOT:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
			    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], ~a))
				goto unsupported;
			break;


		/* SAL is SHL under another name - the encoding is the same and
		 * the decoder reports both. */
		case KGENOME_X86_I_SAL:
		case KGENOME_X86_I_SHL: case KGENOME_X86_I_SHR: case KGENOME_X86_I_SAR: {
			unsigned n, w = sz * 8u;
			uint64_t m = kgenome_emu_mask_of(sz);

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
			    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
				goto unsupported;
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
				goto unsupported;
			break;
		}

		case KGENOME_X86_I_ROL: case KGENOME_X86_I_ROR: {
			unsigned n, rc, w = sz * 8u;
			uint64_t m = kgenome_emu_mask_of(sz);

			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
			    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
				goto unsupported;
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
				goto unsupported;
			break;
		}

		case KGENOME_X86_I_PUSH:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) ||
			    !push_w(e, a, ixp->op[0].size))
				goto fault;
			break;

		case KGENOME_X86_I_POP:
			if (!pop_w(e, &a, ixp->op[0].size) ||
			    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], a))
				goto fault;
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
				goto fault;
			break;

		case KGENOME_X86_I_POPF:
			if (!kgenome_emu_pop(e, &a))
				goto fault;
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
					goto fault;
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
					goto fault;
				if (ord[k] != KGENOME_EMU_RSP)
					e->gpr[ord[k]] = t;   /* esp: discarded */
			}
			break;
		}



		case KGENOME_X86_I_LEAVE:
			e->gpr[KGENOME_EMU_RSP] = e->gpr[KGENOME_EMU_RBP];
			if (!kgenome_emu_pop(e, &e->gpr[KGENOME_EMU_RBP]))
				goto fault;
			break;

		case KGENOME_X86_I_CALLNR:
		case KGENOME_X86_I_CALLNI:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) || !kgenome_emu_push(e, next))
				goto fault;
			e->prev_call_at = e->last_call_at;
			e->last_call_at = e->rip;
			e->rip = a; jumped = 1;
			break;

		case KGENOME_X86_I_RETN:
			if (!kgenome_emu_pop(e, &a))
				goto fault;
			if (ixp->n > 0 &&
			    ixp->op[0].type == KGENOME_X86_OP_IMM)
				e->gpr[KGENOME_EMU_RSP] += (uint64_t)ixp->op[0].v;
			e->rip = a; jumped = 1;
			break;

		case KGENOME_X86_I_JMPNR:
		case KGENOME_X86_I_JMPNI:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				goto unsupported;
			e->rip = a; jumped = 1;
			break;

		case KGENOME_X86_I_Jcc:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				goto unsupported;
			if (cond_true(e, kgenome_x86_cond(&ixp->h))) { e->rip = a; jumped = 1; }
			break;

		case KGENOME_X86_I_SETcc:
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0],
				   cond_true(e, kgenome_x86_cond(&ixp->h)) ? 1u : 0u))
				goto unsupported;
			break;

		/* SDM CMOVcc: a 32 bit destination is zero-extended into the 64 bit register even
		 * when the condition is false and nothing moves. */
		case KGENOME_X86_I_CMOVcc:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
				goto unsupported;
			if (cond_true(e, kgenome_x86_cond(&ixp->h))) {
				if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], b))
					goto unsupported;
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
					goto unsupported;
				next = a;
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
					goto unsupported;
				/* `loop` is not `jumped` (the handover tests below are
				 * about jumps), so the delay-loop count is kept here. */
				if (a <= st.va) {
					if (st.va != e->dl_at) {
						e->dl_at = st.va;
						e->dl_n = 1;
					} else if (++e->dl_n == KGENOME_EMU_DELAY_PROBE) {
						kgenome_emu_delay_note(e, a, st.va, st.len);
					}
				}
				next = a;
			}
			break;
		}

		case KGENOME_X86_I_BSWAP:
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a))
				goto unsupported;
			r = 0;
			for (unsigned i = 0; i < sz; i++)
				r |= ((a >> (i * 8u)) & 0xffu) << ((sz - 1u - i) * 8u);
			if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], r))
				goto unsupported;
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
					goto unsupported;
				sx = (int64_t)kgenome_emu_sext(a, sz);
				sy = (int64_t)kgenome_emu_sext(b, sz);
				over = __builtin_mul_overflow(sx, sy, &prod);
				if (!over && sz < 8)
					over = (int64_t)kgenome_emu_sext((uint64_t)prod, sz) != prod;
				if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], (uint64_t)sx * (uint64_t)sy))
					goto unsupported;
				kgenome_emu_fl_cfof(e, over);
			} else {
				/* One operand: the widening form, into RDX:RAX. */
				uint64_t acc = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, sz, 0);
				int64_t  x, y;
				uint64_t ux, uy, hi;

				if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &b))
					goto unsupported;

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
			if (rc == KGENOME_EMU_RUN_FAULT)
				goto fault;
			if (rc == KGENOME_EMU_RUN_DONE)
				goto done;
			if (rc == KGENOME_EMU_RUN_REDIRECT)
				continue;
			if (rc != KGENOME_EMU_RUN_OK)
				goto unsupported;
			break;
		}

		}


		if (run_landed(e, jumped, next, &st))
			goto done;
		continue;


unsupported:
		/*
		 * MOST FAULTS ARRIVE HERE AND NOT AT `fault:`, which is why
		 * this test is in both places.
		 *
		 * An operand read that cannot reach its memory returns failure
		 * to the decode arm it was called from, and those arms say
		 * `goto unsupported` - the label then sorts the two apart by
		 * whether a fault was recorded. Hooking only `fault:` caught
		 * the minority: measured, three of four protected samples
		 * reported a read fault and none of them ever reached the
		 * dispatcher.
		 */
		if (e->fault_kind[0] && kgenome_emu_win_exc_begin(e))
			continue;
		fail(e, e->fault_kind[0] ? KGENOME_EMU_STOP_FAULT
					 : KGENOME_EMU_STOP_UNSUPPORTED, ixp);
		goto done;
fault:
		/*
		 * A WINDOWS GUEST MAY HAVE ASKED FOR THIS. See the exception
		 * dispatcher: a protector faults on purpose and expects to be
		 * handed the fault. Nothing changes for an ELF run, which has
		 * no win_k32_base and is refused at the first line of it.
		 */
		if (kgenome_emu_win_exc_begin(e))
			continue;
		fail(e, KGENOME_EMU_STOP_FAULT, NULL);
		goto done;
	}
done:
	/* The host prepares and harvests around the run; its stores are not the
	 * guest's - see `gwritten`. */
	e->running = 0;
	return e->stop;
}
