/*
 * emu_run_private.h - THE RUN LOOP, written once and made once per entry of the dispatch table.
 * NOT PART OF THE SURFACE.
 *
 * What the loop does is the core's and is the same for every architecture: the gate before a fetch
 * (a stage entered for the first time, the handover edge, an exception handler returning, a call
 * into the null page, execute permission and the write-then-execute snapshot, checked once per
 * page), the fetch through the instruction cache, the bookkeeping of an instruction (the watch, the
 * trace, the stall and deadline bounds, the count), the step over an inert one, and what follows an
 * instruction that ran (the delay probe, the written-jump and handover tests). What an instruction
 * IS and what it DOES are the entry's (struct kgenome_emu_arch): the decode, the execution, its text,
 * the shape of a handover, the stack and return-value roles.
 *
 * WHY A HEADER AND NOT A FILE: the loop asks the entry four questions of every instruction (decode on
 * a miss, len, inert, exec). Asked through a pointer, that is a call per instruction the compiler can
 * neither inline nor see through; made INSIDE the entry's own file (kgenome_emu_run_core with the
 * entry's table, a static const the compiler folds), every question is a direct call into the same
 * unit and the execute switch is inlined into the loop as it was when there was one architecture.
 * The one pointer followed per RUN is struct kgenome_emu_arch.run (kgenome_emu_run).
 *
 * Included by an entry's file only (emu_x86.c).
 */
#ifndef KGENOME_EMU_RUN_PRIVATE_H
#define KGENOME_EMU_RUN_PRIVATE_H

#include "emu_win_private.h"

/* The longest instruction text an entry writes, with its NUL (struct kgenome_emu_arch.text_max is no
 * more than this: emu_x86.c checks it at compile time). */
#define KGENOME_EMU_TEXT_MAX 160u

/* INLINED INTO THE ENTRY'S INSTANCE OF THE LOOP: the loop itself, and an entry's answer to a question the
 * loop asks of every instruction (decode, len, inert, exec, and the handover's tail and return address),
 * as the code was when the loop and the x86 switch were one function. The table still holds the
 * answers' addresses. */
#define KGENOME_EMU_INLINE static inline __attribute__((always_inline))

/*
 * THE INSTRUCTION ABOUT TO RUN, as ONE record. Everything the run decides from the instruction
 * after the decode - the watch for a byte pattern, the shape of a transfer for the handover test,
 * the address it came from - is read from here, and the fetch fills it in one place whether the
 * decode came from the instruction cache or from a fresh fetch. The cache is an acceleration; a
 * stop, a watch or a handover must see exactly the bytes at the executed address either way.
 *
 * WHY: these were scattered locals, and the bytes were a pointer at the 16-byte fetch buffer
 * that only a cache MISS filled. A hit left it holding (uninitialised, then stale) whatever was
 * last decoded, so a cached `syscall` was not watched, a cached non-syscall was, and a handover
 * by a cached `jmp rax` was judged by the wrong bytes.
 */
struct kgenome_emu_run_step {
	uint64_t va;                      /* where it is                                    */
	unsigned len;                     /* how long it is                                 */
	const uint8_t *b;                 /* its `len` bytes: the cache slot's or the fetch */
	struct kgenome_emu_insn *ix;      /* decoded: the cache slot itself, or the scratch */
	struct icache_ent *ent;           /* the cache slot, NULL when the cache is off      */
};

/* The first instruction executed in a region nothing has run in yet. Returns
 * the region, marking it seen, or -1. */
static inline int kgenome_emu_hop_first(struct kgenome_emu *e, uint64_t rip)
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
static inline int kgenome_emu_iwatch_hit(const struct kgenome_emu *e, const uint8_t *b, unsigned len)
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


static inline void kgenome_emu_fail(struct kgenome_emu *e, const struct kgenome_emu_arch *A,
				    enum kgenome_emu_stop s, const struct kgenome_emu_insn *ix)
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
		char t[KGENOME_EMU_TEXT_MAX];

		if (A->text(ix, e->rip, t, sizeof t)) {
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
static inline int kgenome_emu_bytes_eq(const uint8_t *a, const uint8_t *b, unsigned n)
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
enum { KGENOME_EMU_GATE_GO, KGENOME_EMU_GATE_SKIP, KGENOME_EMU_GATE_STOP };

static inline int kgenome_emu_run_gate(struct kgenome_emu *e, const struct kgenome_emu_arch *A)
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
		int h = kgenome_emu_hop_first(e, e->rip);

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
			return KGENOME_EMU_GATE_STOP;
		}
		e->xw_was_in = in;
		e->xw_have_prev = 1;
	}

	if (e->exc_phase && e->rip == kgenome_emu_win_ret_magic(e)) {
		if (kgenome_emu_win_exc_return(e))
			return KGENOME_EMU_GATE_SKIP;
		kgenome_emu_fail(e, A, KGENOME_EMU_STOP_FAULT, NULL);
		return KGENOME_EMU_GATE_STOP;
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
		    A->ret_pop(e, &ret) && ret) {
			/* Freeze the instruction trace at the FIRST of
			 * these: the call that could not be resolved
			 * is upstream of every wrong value after it. */
			if (e->itr && e->itr_on_null && !e->null_calls)
				e->itr_frozen = 1;
			e->null_calls++;
			e->gpr[A->acc] = 0;
			e->rip = ret;
			return KGENOME_EMU_GATE_SKIP;
		}
		e->fault_va = e->rip;
		memcpy(e->fault_kind, "call0", 6);
		kgenome_emu_fail(e, A, KGENOME_EMU_STOP_FAULT, NULL);
		return KGENOME_EMU_GATE_STOP;
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
			kgenome_emu_fail(e, A, KGENOME_EMU_STOP_FAULT, NULL);
			return KGENOME_EMU_GATE_STOP;
		}
		if (fp)
			e->fetch_page = e->rip &
					~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	}
	return KGENOME_EMU_GATE_GO;
}


static inline void kgenome_emu_step_fill(struct kgenome_emu_run_step *st, uint64_t va, unsigned len,
					 struct kgenome_emu_insn *ix, struct icache_ent *ent, const uint8_t *bytes)
{
	st->va = va;
	st->len = len;
	st->b = bytes;
	st->ix = ix;
	st->ent = ent;
}


/*
 * THE FETCH AND THE DECODE, through the instruction cache. Leaves the instruction in *st (see
 * struct kgenome_emu_run_step; decoded in the cache slot itself on a cache-able fetch, else in *ixbuf). Returns 1
 * when the run is to end here, 0 to execute.
 */
static inline int kgenome_emu_run_fetch(struct kgenome_emu *e, const struct kgenome_emu_arch *A, uint8_t (*cp)[16],
					struct kgenome_emu_insn *ixbuf, struct kgenome_emu_run_step *st)
{
	uint8_t *code = *cp;
	struct kgenome_emu_insn *ixp;
	struct icache_ent *ent;
	struct kgenome_emu_page *fpg;
	unsigned len;

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
			    kgenome_emu_bytes_eq(fpg->data + poff, ent->bytes,
				     ent->len)) {
				/*
				 * POINTED AT, NOT COPIED. An struct kgenome_emu_insn is
				 * 480 bytes and this path runs tens of
				 * millions of times - measured on one
				 * Sality slice, 17.2 million hits, which
				 * is 8.3 GB of memcpy for bytes that are
				 * already in the right place.
				 */
				kgenome_emu_step_fill(st, e->rip, ent->len, &ent->ix, ent, ent->bytes);
				return 0;
			}
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
			kgenome_emu_fail(e, A, KGENOME_EMU_STOP_FAULT, NULL);
			return 1;
		}
		memset(code + got, 0, sizeof *cp - got);
	}
fetched:
	/*
	 * DECODED INTO THE CACHE SLOT ITSELF, so that filling it costs
	 * nothing beyond the decode. The length is not known until
	 * afterwards, so whether it may be KEPT is decided then - an
	 * instruction straddling a page boundary depends on two pages
	 * and this checks one.
	 */
	ixp = ent ? &ent->ix : ixbuf;
	if (!A->decode(e, code, sizeof *cp, ixp)) {
		kgenome_emu_fail(e, A, KGENOME_EMU_STOP_DECODE, NULL);
		return 1;
	}
	len = A->len(ixp);
	/* The slot now holds THIS instruction whether or not it is kept
	 * below, so what it said about the previous occupant is void. An
	 * instruction straddling a page is decoded here and not kept; its
	 * slot's inert flag would otherwise be read as its own, and a real
	 * instruction stepped over. */
	if (ent)
		ent->inert = 0;
	/* Kept only when it lies inside one page - see `ic`. */
	if (ent && ((e->rip + len - 1u) &
		    ~(uint64_t)(KGENOME_EMU_PAGE - 1u))
		   == (e->rip & ~(uint64_t)(KGENOME_EMU_PAGE - 1u))) {
		memcpy(ent->bytes, code, len);
		ent->len = (uint8_t)len;
		ent->inert = (uint8_t)A->inert(ixp);
		ent->valid = 1;
	}
	kgenome_emu_step_fill(st, e->rip, len, ixp, ent, code);
	return 0;
}


/*
 * What follows an instruction that ran: step to the next one, or, when the instruction transferred
 * control, record where it came from and test whether this is a handover. Returns 1 when the run
 * is to end here (e->stop says why).
 */
static inline int kgenome_emu_run_landed(struct kgenome_emu *e, const struct kgenome_emu_arch *A, int jumped,
					 uint64_t next, const struct kgenome_emu_run_step *st)
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
				A->delay(e, e->rip, at, at_len);
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
		    e->gpr[A->sp] == e->sp0 &&
		    e->img_hi > e->img_lo &&
		    e->rip >= e->img_lo && e->rip < e->img_hi &&
		    !(e->stack_hi && e->rip >= e->stack_lo &&
		      e->rip < e->stack_hi)) {
			struct kgenome_emu_page *t = kgenome_emu_page_find(e, e->rip);
			/* The shapes a loader ends with are the entry's: see struct kgenome_emu_arch.tail. */
			int tail = A->tail(at_b, at_len);

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


KGENOME_EMU_INLINE enum kgenome_emu_stop kgenome_emu_run_core(struct kgenome_emu *e, const struct kgenome_emu_arch *A)
{
	e->stop = KGENOME_EMU_STOP_BUDGET;
	e->detail[0] = 0;
	e->running = 1;

	while (e->insn < e->max_insn) {
		uint8_t code[16];
		struct kgenome_emu_insn ixbuf;
		struct kgenome_emu_run_step st;
		struct kgenome_emu_insn *ixp;
		uint64_t next;
		int jumped = 0, rc;


		{
			int g = kgenome_emu_run_gate(e, A);

			if (g == KGENOME_EMU_GATE_STOP)
				goto done;
			if (g == KGENOME_EMU_GATE_SKIP)
				continue;
		}



		if (kgenome_emu_run_fetch(e, A, &code, &ixbuf, &st))
			break;
		/* From here on the instruction is `st`; by the handover test e->rip is the TARGET. */
		ixp = st.ix;


		if (!e->sp0_set) {
			e->sp0 = e->gpr[A->sp];
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
		if (kgenome_emu_iwatch_hit(e, st.b, st.len)) {
			snprintf(e->detail, sizeof e->detail,
				 "watched instruction at %#llx",
				 (unsigned long long)e->rip);
			e->stop = KGENOME_EMU_STOP_INSN;
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
			char t[KGENOME_EMU_TEXT_MAX];
			unsigned q = 0;

			it->rip = e->rip;
			memcpy(it->gpr, e->gpr, sizeof it->gpr);
			/* The registers are copied BEFORE the instruction runs,
			 * which is the point: they are its inputs. */
			if (A->text(ixp, e->rip, t, sizeof t))
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
			kgenome_emu_fail(e, A, KGENOME_EMU_STOP_STALLED, NULL);
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
		next = e->rip + st.len;
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



		/* THE INSTRUCTION, carried out by the entry - see struct kgenome_emu_arch.exec. */
		rc = A->exec(e, &st, &next, &jumped);
		if (rc == KGENOME_EMU_RUN_OK) {
			if (kgenome_emu_run_landed(e, A, jumped, next, &st))
				goto done;
			continue;
		}
		if (rc == KGENOME_EMU_RUN_REDIRECT)
			continue;
		if (rc == KGENOME_EMU_RUN_DONE)
			goto done;
		if (rc == KGENOME_EMU_RUN_FAULT)
			goto fault;
		/* UNSUPPORTED, and an id no group of the entry carries (NOT_MINE): */
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
		kgenome_emu_fail(e, A, e->fault_kind[0] ? KGENOME_EMU_STOP_FAULT
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
		kgenome_emu_fail(e, A, KGENOME_EMU_STOP_FAULT, NULL);
		goto done;
	}
done:
	/* The host prepares and harvests around the run; its stores are not the
	 * guest's - see `gwritten`. */
	e->running = 0;
	return e->stop;
}


#endif /* KGENOME_EMU_RUN_PRIVATE_H */
