/*
 * diag_emu_step.c - the walk of one function: branches, field values, decoding and emulating one step.
 * Part of the emulate route; see diag_emu.c for what it is for and diag_emu_private.h for what the
 * files share.
 */
#include "diag_emu_private.h"

/*
 * A branch out of the span, a backward branch, and a call that the table did
 * not list.
 */
static enum kgenome_diag_emu_rel_act rel_branches(struct kgenome_diag_emu_rel_span *S,
				 const struct kgenome_cell_insn *ci, uint32_t clen,
				 uint64_t rip)
{
	struct kgenome_emu *em = S->em;
	uint64_t run_lo = S->run_lo;
	uint64_t run_hi = S->run_hi;


	/*
	 * AND OVER AN INDIRECT CALL. `call *(pv_ops+k)`
	 * goes through a pointer the loader fills; the
	 * symbol is undefined here so the slot is zero
	 * and stepping it calls address zero. Diamorphine
	 * reads cr0 that way, two instructions before it
	 * writes it, so the span died before reaching
	 * the thing it was opened for. The decoder says
	 * it is a call through memory; no list of
	 * encodings is involved.
	 */
	/*
	 * ---- A LOOP IS LET ROUND, NOT RUN OUT -----
	 *
	 * THE BUDGET WAS THE WRONG BOUND. A span had
	 * 4096 instructions and a loop ate all of
	 * them, so the span died INSIDE the loop and
	 * everything after it was lost - MEASURED on
	 * Diamorphine's hacked_getdents, which filters
	 * a directory listing and then copies it back:
	 * the run stopped 11 bytes short of that copy,
	 * and the hiding behaviour read as absent.
	 *
	 * WHY THE LOOP DOES NOT END BY ITSELF. It is
	 * bounded by the byte count the original
	 * syscall returned, and that call is skipped -
	 * so the count is a stated value, not a real
	 * one. No stated value is both a plausible
	 * pointer and a small number of iterations.
	 *
	 * SO BOUND THE ITERATIONS, WHICH IS THE INPUT,
	 * and let what comes after be whatever it is.
	 * A loop body is fully covered by its first
	 * pass - a node is a SITE, and a link already
	 * refuses a repeat - so a third arrival at the
	 * same backward branch has nothing left to
	 * show. Taking the fall-through there is the
	 * loop's own exit, not a path invented for it.
	 *
	 * A FORWARD branch is not touched: it is a
	 * choice between two paths, not a repetition,
	 * and forcing one would be inventing a run.
	 */
	/*
	 * ---- AND A CONDITIONAL BRANCH OUT OF THE SPAN --
	 *
	 * A span covers ONE function and asks which of its
	 * sites are linked. An arm that leaves the function
	 * cannot reach any of them, so following it answers
	 * nothing and ends the walk; the arm that stays is
	 * the only one with anything to say.
	 *
	 * THIS IS NOT A CLAIM ABOUT WHICH WAY THE PROGRAM
	 * GOES. The condition is computed from values this
	 * run STATED - a count from a skipped call, a page
	 * from an arena - so neither arm was demonstrated
	 * and choosing the one that can carry evidence
	 * asserts nothing the other way.
	 *
	 * MEASURED on diamondxe: its filtering loop ends
	 * `jbe <reloc>` into a cold block at 0xd0b, and the
	 * synthetic comparison took it - the span left the
	 * function with the copy back still ahead of it.
	 * diamorphine, built from the same source, keeps
	 * that block inline and never showed the fault.
	 */
	if (clen && (ci->op == KGENOME_CELL_JCC ||
		     ci->op == KGENOME_CELL_LOOP) &&
	    ci->target != KGENOME_BROKEN &&
	    (ci->target < run_lo ||
	     ci->target >= run_hi)) {
		kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE +
				rip + ci->len);
		return KGENOME_DIAG_EMU_REL_NEXT;
	}
	if (clen && (ci->op == KGENOME_CELL_JCC ||
		     ci->op == KGENOME_CELL_LOOP ||
		     ci->op == KGENOME_CELL_JMP) &&
	    ci->target != KGENOME_BROKEN &&
	    ci->target < rip) {
		uint32_t t;

		for (t = 0; t < S->n_latch; t++)
			if (S->latch[t].at == rip)
				break;
		if (t == S->n_latch && S->n_latch <
		    (uint32_t)(sizeof S->latch /
			       sizeof S->latch[0])) {
			S->latch[t].at = rip;
			S->latch[t].n = 0;
			S->n_latch++;
		}
		/*
		 * EVERY BACKWARD TRANSFER, not only the
		 * conditional ones: a loop whose latch
		 * is `jmp` was not counted at all and
		 * ran until something else stopped it.
		 *
		 * AND IT STALLS RATHER THAN FALLING
		 * THROUGH. Falling through is a path
		 * this run did not take; stalling hands
		 * the span to the seat logic, which
		 * moves to the next site - the same
		 * answer the routine gives for every
		 * other obstacle, and the reason the
		 * gap budget almost never has to.
		 */
		if (t < S->n_latch &&
		    ++S->latch[t].n > KGENOME_DIAG_REL_SPINS)
			return KGENOME_DIAG_EMU_REL_STALL;
	}
	/*
	 * ---- A DIRECT CALL THE TABLE DID NOT LIST ----
	 *
	 * EVERY call in a span is skipped - that is the
	 * design above - and the relocation table was only
	 * how they were FOUND. It does not list them all: a
	 * call to a static function in the same section is
	 * resolved by the assembler, so there is no
	 * relocation and nothing put it in the skip list.
	 *
	 * Such a call was therefore EXECUTED, and execution
	 * leaves the function - which ends the span, because
	 * a span is one function. MEASURED on diamondxe: its
	 * filtering loop calls a local helper and the walk
	 * left at 0xd0b, two sites short of the copy back.
	 *
	 * The result is stated the same way as any other
	 * skipped call - see the note on the arena page.
	 */
	if (clen && ci->op == KGENOME_CELL_CALL && ci->n_op &&
	    ci->o[0].kind == KGENOME_CELL_O_REL) {
		if (S->anon > S->anon_floor)
			kgenome_emu_set_reg(em, KGENOME_EMU_RAX,
				KGENOME_DIAG_TOK_BASE +
				(uint64_t)(--S->anon) *
				KGENOME_EMU_PAGE);
		kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE +
				rip + ci->len);
		return KGENOME_DIAG_EMU_REL_NEXT;
	}
	if (clen && ci->op == KGENOME_CELL_CALL && ci->n_op &&
	    ci->o[0].kind != KGENOME_CELL_O_REL) {
		/*
		 * AND IT HANDS SOMETHING BACK. Stepping
		 * over a call while leaving the result
		 * register alone states nothing - it
		 * leaves whatever happened to be there,
		 * and the program then tests THAT.
		 *
		 * MEASURED: Diamorphine's hooked
		 * getdents calls the original through
		 * the syscall table, keeps the result
		 * as a byte count and checks
		 * `count > 0x7fffffff`. A stale
		 * register held an address, the check
		 * failed, and the run took the error
		 * path - freeing the buffer and
		 * leaving - so the copy the hook
		 * exists for was never on the path at
		 * all.
		 *
		 * An arena page is the same answer the
		 * named skip gives and for the same
		 * reasons: non-zero, so a failure test
		 * goes the other way; mapped, so a
		 * dereference does not fault; below
		 * 2^31, so it is plausible where the
		 * program treats it as a size; and
		 * owned by no node, so it can never be
		 * mistaken for a link.
		 */
		if (S->anon > S->anon_floor)
			kgenome_emu_set_reg(em, KGENOME_EMU_RAX,
				KGENOME_DIAG_TOK_BASE +
				(uint64_t)(--S->anon) *
				KGENOME_EMU_PAGE);
		kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE +
				rip + ci->len);
		return KGENOME_DIAG_EMU_REL_NEXT;
	}
	return KGENOME_DIAG_EMU_REL_ON;
}

/* A global struct, reached without a base register. */
static void rel_field_global(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
			     const struct kgenome_cell_insn *ci, unsigned mi,
			     uint64_t rip)
{
	struct kgenome_diag_scan *s = R->s;

	/*
	 * ---- A GLOBAL STRUCT, REACHED WITHOUT
	 * A BASE REGISTER -------------------
	 *
	 * `kp` is a module global, so the read
	 * of kp.addr is
	 *
	 *     mov 0x0(%rip),%rbx
	 *
	 * with the displacement filled by a
	 * relocation. There is no base register
	 * at all, and the test below wanted one
	 * - so the one access that CONFIRMS a
	 * kprobe pair, the resolved symbol
	 * being collected between the register
	 * and the unregister, was invisible.
	 *
	 * The object's address is known: it is
	 * what register_kprobe was handed, and
	 * seen[] is holding it. An absolute
	 * target that lands inside that object
	 * is a field of it.
	 */
	if (ci->o[mi].kind == KGENOME_CELL_O_MEM &&
	    ci->o[mi].reg == KGENOME_CELL_REG_NONE &&
	    ci->o[mi].index == KGENOME_CELL_REG_NONE) {
		uint64_t tg = rip + ci->len +
			(uint64_t)ci->o[mi].disp +
			KGENOME_DIAG_REL_BASE;
		uint32_t z;

		for (z = 0; z < S->n_seen; z++)
			if (tg >= S->seen[z].val &&
			    tg - S->seen[z].val <
			    KGENOME_DIAG_OBJ_SPAN)
				break;
		if (z < S->n_seen) {
			struct kgenome_diag_hit *fh;
			uint32_t t2, lv =
			  kgenome_diag_scan_count(s);
			int dup2 = 0;

			for (t2 = 0; t2 < lv; t2++) {
				const struct kgenome_diag_hit *e =
				  kgenome_diag_scan_at(s, t2);
				/* ONLY ANOTHER FIELD
				 * NODE COUNTS. A node's
				 * `at` is a call's RESUME
				 * address, which is the
				 * very next instruction -
				 * and in diamorphine that
				 * instruction IS the read
				 * of kp.addr, so the two
				 * collided and the read
				 * was dropped. */
				if (e && e->at == rip &&
				    (e->cap == KGENOME_NUCLEO_ACTION_READ ||
				     e->cap == KGENOME_NUCLEO_ACTION_WRITE))
					dup2 = 1;
			}
			fh = dup2 ? NULL
			   : kgenome_diag_hit_add(s, rip,
				mi == 0u
				? KGENOME_NUCLEO_ACTION_WRITE
				: KGENOME_NUCLEO_ACTION_READ, 0);
			if (fh) {
				fh->attr = tg -
				  S->seen[z].val;
				kgenome_diag_emu_field_value(fh, ci, mi);
				kgenome_diag_note_in(s, fh,
				  S->seen[z].node,
				  mi == 0u
				  ? KGENOME_DIAG_ROLE_BUFFER
				  : KGENOME_DIAG_ROLE_SOURCE,
				  S->seen[z].produced
				  ? KGENOME_DIAG_KIND_PRODUCED
				  : KGENOME_DIAG_KIND_SHARED);
			}
		}
	}
}

/* A field of an object a node was handed. */
static void rel_field_held(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
			   const struct kgenome_cell_insn *ci, unsigned mi,
			   uint64_t rip, uint64_t b)
{
	struct kgenome_diag_scan *s = R->s;

	/*
	 * ---- A FIELD OF AN OBJECT A
	 * NODE WAS HANDED --------------
	 *
	 * A token stands for something a
	 * call RETURNED. The kprobe
	 * struct is not that: it is a
	 * module global, its address is a
	 * relocation into .bss, and it
	 * reaches register_kprobe as an
	 * argument. So the read of
	 * kp.addr between the register
	 * and the unregister - which is
	 * the whole reason the pair
	 * exists, the resolved symbol
	 * being collected - matched
	 * nothing and was invisible.
	 *
	 * ANY ADDRESS A NODE HAS BEEN
	 * SEEN HOLDING counts. That is
	 * what seen[] already is, and it
	 * is what confirms the block:
	 * register and unregister share
	 * an object, and in between
	 * something READS a field of it.
	 */
	if (b < KGENOME_DIAG_TOK_BASE ||
	    b >= KGENOME_DIAG_TOK_BASE +
		(uint64_t)KGENOME_DIAG_TOK_MAX *
		KGENOME_EMU_PAGE) {
		uint32_t z;

		for (z = 0; z < S->n_seen; z++)
			if (S->seen[z].val == b)
				break;
		if (z < S->n_seen) {
			struct kgenome_diag_hit *fh;
			uint32_t t2,
			  lv = kgenome_diag_scan_count(s);
			int dup2 = 0;

			for (t2 = 0; t2 < lv; t2++) {
				const struct kgenome_diag_hit *e =
				  kgenome_diag_scan_at(s, t2);
				if (e && e->at == rip)
					dup2 = 1;
			}
			fh = dup2 ? NULL
			   : kgenome_diag_hit_add(s, rip,
				mi == 0u
				? KGENOME_NUCLEO_ACTION_WRITE
				: KGENOME_NUCLEO_ACTION_READ,
				0);
			if (fh) {
				fh->attr = (uint64_t)
				  ci->o[mi].disp;
				kgenome_diag_emu_field_value(fh, ci, mi);
				kgenome_diag_note_in(s, fh,
				  S->seen[z].node,
				  mi == 0u
				  ? KGENOME_DIAG_ROLE_BUFFER
				  : KGENOME_DIAG_ROLE_SOURCE,
				  S->seen[z].produced
				  ? KGENOME_DIAG_KIND_PRODUCED
				  : KGENOME_DIAG_KIND_SHARED);
			}
		}
	}
}

/* A field of an object a node produced, and a load that hands the object on. */
static enum kgenome_diag_emu_rel_act rel_field_token(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
				    const struct kgenome_cell_insn *ci, unsigned mi,
				    uint64_t rip, uint64_t b)
{
	struct kgenome_diag_scan *s = R->s;
	struct kgenome_emu *em = S->em;

	if (b >= KGENOME_DIAG_TOK_BASE &&
	    b < KGENOME_DIAG_TOK_BASE +
		(uint64_t)KGENOME_DIAG_TOK_MAX *
		KGENOME_EMU_PAGE) {
		uint64_t page = b -
		  (b - KGENOME_DIAG_TOK_BASE) %
		  KGENOME_EMU_PAGE;
		uint32_t own =
		  (uint32_t)((page -
		   KGENOME_DIAG_TOK_BASE) /
		   KGENOME_EMU_PAGE);
		uint32_t t, live =
		  kgenome_diag_scan_count(s);
		int dup = 0;

		for (t = 0; t < live; t++) {
			const struct kgenome_diag_hit *e =
			  kgenome_diag_scan_at(s, t);
			if (e && e->at == rip)
				dup = 1;
		}
		if (!dup) {
			struct kgenome_diag_hit *fh =
			  kgenome_diag_hit_add(s, rip,
			    mi == 0u
			    ? KGENOME_NUCLEO_ACTION_WRITE
			    : KGENOME_NUCLEO_ACTION_READ,
			    0);
			if (fh) {
				fh->attr =
				  (uint64_t)
				  ci->o[mi].disp;
				kgenome_diag_emu_field_value(fh, ci, mi);
				if (own < live)
					kgenome_diag_note_in(s, fh,
					  (uint16_t)own,
					  mi == 0u
					  ? KGENOME_DIAG_ROLE_BUFFER
					  : KGENOME_DIAG_ROLE_SOURCE,
					  KGENOME_DIAG_KIND_PRODUCED);
			}
		}
		/* a load still hands
		 * the object on */
		if (mi == 1u &&
		    ci->o[0].kind ==
		    KGENOME_CELL_O_REG) {
			kgenome_emu_step(em);
			kgenome_emu_set_reg(em,
			  ci->o[0].reg, page);
			return KGENOME_DIAG_EMU_REL_NEXT;
		}
	}
	return KGENOME_DIAG_EMU_REL_ON;
}

/* A value read out of, or written into, an object a node produced. */
static enum kgenome_diag_emu_rel_act rel_mov_field(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
				  const struct kgenome_cell_insn *ci, uint64_t rip)
{
	struct kgenome_emu *em = S->em;

	unsigned mi = ci->o[0].kind == KGENOME_CELL_O_MEM ? 0u : 1u;

	rel_field_global(R, S, ci, mi, rip);
	if (ci->o[mi].kind == KGENOME_CELL_O_MEM &&
	    ci->o[mi].reg != KGENOME_CELL_REG_NONE &&
	    ci->o[mi].index == KGENOME_CELL_REG_NONE) {
		uint64_t b = kgenome_emu_get_reg(em,
			ci->o[mi].reg);
		rel_field_held(R, S, ci, mi, rip, b);
		return rel_field_token(R, S, ci, mi, rip, b);
	}
	return KGENOME_DIAG_EMU_REL_ON;
}

/*
 * The instruction at this address: a branch, a call, a field access or a cr0
 * move.
 */
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_decode(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
				    uint64_t rip)
{
	struct kgenome_diag_scan *s = R->s;
	const uint8_t *base = R->base;
	uint64_t size = R->size;
	struct kgenome_emu *em = S->em;

	enum kgenome_diag_emu_rel_act act;

	/*
	 * ---- A PROTECTION TURNED OFF, WHICH HAS NO NAME ---
	 *
	 * `mov cr0, reg` is how a kernel rootkit makes the
	 * kernel's own text writable before it patches a
	 * syscall table. It is INLINE ASSEMBLY: no symbol, no
	 * relocation, no call, so nothing the relocation
	 * table lists ever stops on it and the centre of the
	 * rootkit was invisible.
	 *
	 * RECOGNISED THROUGH THE ENGINE'S DECODER, not a list
	 * of bytes. kgenome_cell_decode_x86 already classifies a
	 * control-register move as KGENOME_CELL_MOV_SPECIAL with
	 * KGENOME_CELL_SR_CR; asking it is asking the one thing in
	 * the tree that knows x86 encodings. The vocabulary
	 * has had a row for this since it was written -
	 * mov_cr0 -> kmodule-cr-write - and nothing had ever
	 * reached it.
	 *
	 * ONE NODE PER SITE, as everywhere else: Diamorphine
	 * clears the bit and puts it back, and a loop that
	 * hooks and unhooks arrives at the same two
	 * instructions each time.
	 */
	if (rip < size) {
		struct kgenome_cell_insn ci;
		/*
		 * ---- DECODED FROM WHAT ACTUALLY RUNS ------
		 *
		 * The file's bytes are NOT what this run
		 * executes. A relocatable object leaves every
		 * branch displacement as a hole and
		 * kgenome_diag_emu_build_rel_image fills them IN THE
		 * EMULATOR'S MEMORY, so decoding `base + rip`
		 * reads zeros where the target is and answers
		 * "it jumps to the next instruction".
		 *
		 * MEASURED on diamondxe, and it defeated two
		 * repairs before it was found: the filtering
		 * loop ends `jbe <hole>` and the file says
		 * that branch stays in the function, while the
		 * run jumped 0xa8b bytes away into a cold
		 * block and left the span. Every test below
		 * that looks at a TARGET was being answered
		 * from the wrong bytes.
		 */
		uint8_t ib[16];
		uint32_t ilen = (uint32_t)(size - rip > 16u
					   ? 16u : size - rip);
		uint32_t clen;

		if (!kgenome_emu_read(em, KGENOME_DIAG_REL_BASE + rip,
				  ib, ilen))
			memcpy(ib, base + rip, ilen);
		clen = kgenome_cell_decode_x86(ib, ilen, rip, 64u, &ci);
		act = rel_branches(S, &ci, clen, rip);
		if (act != KGENOME_DIAG_EMU_REL_ON)
			return act;
		/*
		 * ---- A VALUE READ OUT OF AN OBJECT A NODE
		 * PRODUCED --------------------------------
		 *
		 * THE STEP THAT CARRIES THE MEANING, and the
		 * one the model had no place for. Between
		 * two calls the program does something to
		 * the object the first returned, and that
		 * something is what the pair is FOR:
		 *
		 *   kallsyms_lookup_name_ = *(kp + 0x2d)
		 *       the probe's resolved address, which
		 *       is why the probe was registered
		 *   pure_getdents = *(table + 0x270)
		 *       the syscall entry about to be hooked
		 *
		 * A load through a register holding a token
		 * yields a value that still belongs to that
		 * node - it came OUT of its object - so the
		 * destination inherits the token and a later
		 * call holding it links back.
		 *
		 * THE OFFSET IS NOT KEPT YET. 0x2d and 0x270
		 * are what name WHICH field and WHICH
		 * syscall, and they belong in the node's
		 * attribute run, which nothing writes. The
		 * link is the half that can be had now.
		 */
		/*
		 * EITHER DIRECTION: a field read out of the
		 * object, or written into it. The write is
		 * the one that matters most - it is what a
		 * rootkit does to the listing it intercepted
		 * - and it is the one a model built around
		 * calls had no way to see at all.
		 */
		if (clen && ci.op == KGENOME_CELL_MOV && ci.n_op > 1u) {
			act = rel_mov_field(R, S, &ci, rip);
			if (act != KGENOME_DIAG_EMU_REL_ON)
				return act;
		}

		/*
		 * ONE OPERAND, NOT TWO. decode_x86 keeps only
		 * the operands a sweep tracks, and a control
		 * register is not one - so `mov cr0,rax`
		 * arrives with the GPR in o[0] and nothing
		 * else. Requiring two was why this never
		 * fired although the walk reached the
		 * instruction.
		 *
		 * The GPR being READ is what makes it a write
		 * TO cr0 rather than a read of it.
		 */
		if (clen && ci.op == KGENOME_CELL_MOV_SPECIAL &&
		    ci.cond == KGENOME_CELL_SR_CR && ci.n_op &&
		    ci.o[0].kind == KGENOME_CELL_O_REG &&
		    (ci.o[0].flags & KGENOME_CELL_OF_READ)) {
			uint32_t live = kgenome_diag_scan_count(s);
			int seen_site = 0;

			/* LIVE COUNT, not the one taken
			 * before the walk: a node added by
			 * this very loop has to be visible
			 * to it, or the same site is added
			 * again on the next pass. A node is
			 * a site, however many times the
			 * walk arrives. */
			/*
			 * NO NODE FOR IT WHILE THE WORD IS
			 * OUT OF SERVICE - see the note on
			 * write_cr0 in nucleo.c. The move is
			 * still STEPPED OVER below, which is
			 * what the span needs; what is
			 * suspended is calling it a
			 * capability, because the word today
			 * means an x86 instruction rather
			 * than the behaviour.
			 */
			(void)seen_site;
			(void)live;
			/*
			 * AND STEP OVER IT. The interpreter
			 * answers UNSUPPORTED for a control
			 * register move - correctly, it does
			 * not model one - and that ends the
			 * span at the exact instruction the
			 * span was opened for. Everything
			 * after it is the hook itself: the
			 * stores into the table and the
			 * second write that puts the
			 * protection back.
			 *
			 * Skipping is sound here because
			 * nothing downstream depends on
			 * cr0's value. The guest never reads
			 * it back for anything but restoring
			 * it, and no link is ever carried
			 * through a control register.
			 */
			kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE +
					rip + ci.len);
			return KGENOME_DIAG_EMU_REL_NEXT;
		}
	}
	return KGENOME_DIAG_EMU_REL_ON;
}

/*
 * Step the machine one instruction; a fault on stated memory is stepped over.
 */
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_emulate(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
				     uint64_t rip)
{
	const uint8_t *base = R->base;
	uint64_t size = R->size;
	struct kgenome_emu *em = S->em;

	enum kgenome_emu_stop st;


	/*
	 * A SPAN THAT CANNOT BE WALKED ENDS QUIETLY. An
	 * unapplied relocation sends a load somewhere the
	 * file does not reach; the run stops and the span
	 * reports nothing, which is the honest answer rather
	 * than a wrong one.
	 */
	st = kgenome_emu_step(em);
	/*
	 * ---- A FAULT ON SYNTHETIC MEMORY IS NOT A FACT -----
	 *
	 * The data this run works on was STATED, not read: a
	 * skipped allocator hands back one arena page, and a
	 * skipped call hands back a count nobody measured. So a
	 * loop that walks "the buffer" runs off the end of the
	 * only page there is and the emulator faults - on an
	 * address the PROGRAM never computes, because in the
	 * program the buffer is as long as the count says.
	 *
	 * THAT FAULT IS ABOUT THE SYNTHESIS AND THE SPAN MUST NOT
	 * DIE OF IT. MEASURED on diamondxe: once the copies were
	 * given their true success value the run took the REAL
	 * path for the first time, walked the listing, faulted,
	 * and the copy back - the whole of the hiding - was never
	 * reached. It had only ever been reached before by taking
	 * the ERROR path, which is the right answer for the wrong
	 * reason.
	 *
	 * STEPPING OVER IT IS SOUND because what the instruction
	 * would have loaded is not known either way. The registers
	 * it writes are CLEARED rather than left: a stale value
	 * could still equal a token and would then read as a link
	 * the run never demonstrated. Zero belongs to no node and
	 * kgenome_diag_emu_worth_remembering refuses it.
	 *
	 * A DECODE OR UNSUPPORTED INSTRUCTION STILL ENDS THE SPAN:
	 * there the engine does not know what the instruction
	 * DOES, so everything after it would be a guess.
	 */
	if (st == KGENOME_EMU_STOP_FAULT &&
	    S->n_fault < KGENOME_DIAG_REL_FAULTS && rip < size) {
		struct kgenome_cell_insn fi;
		uint32_t fl = kgenome_cell_decode_x86(base + rip,
			(uint32_t)(size - rip > 16u ? 16u
				   : size - rip),
			rip, 64u, &fi);

		if (fl) {
			unsigned z;

			for (z = 0; z < fi.n_op; z++)
				if (fi.o[z].kind == KGENOME_CELL_O_REG &&
				    (fi.o[z].flags & KGENOME_CELL_OF_WRITE))
					kgenome_emu_set_reg(em,
						fi.o[z].reg, 0);
			kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE +
					rip + fl);
			S->n_fault++;
			return KGENOME_DIAG_EMU_REL_NEXT;
		}
	}
	if (st != KGENOME_EMU_STOP_FAULT &&
	    st != KGENOME_EMU_STOP_DECODE &&
	    st != KGENOME_EMU_STOP_UNSUPPORTED)
		return KGENOME_DIAG_EMU_REL_NEXT;
	return KGENOME_DIAG_EMU_REL_STALL;
}
