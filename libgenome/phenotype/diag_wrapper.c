/*
 * diag_wrapper.c - THE SYSCALL IS INSIDE A LIBRARY FUNCTION, AND THE PROGRAM IS
 * THE CALLERS.
 *
 * A bot built against a static libc does not execute `mov eax,41; syscall` where
 * it opens a socket. It executes `call socket`, and one function somewhere in the
 * binary holds the only `syscall` instruction there is:
 *
 *     socket:  push rbx
 *              movslq edx,rdx ; movslq esi,rsi ; movslq edi,rdi   <- the PARAMETERS
 *              mov eax,0x29
 *              syscall
 *
 * Read at that instruction the arguments are the function's own parameters, so
 * the node said "a socket of an unknown kind", stood in one place for every
 * socket the program makes, and could carry no link to anything - the descriptor
 * it returned goes to eighty call sites, and the arguments of those are the
 * caller's too. MEASURED on 1000 Bazaar Linux bots: 122 of 146 old Mirai had a
 * network node and one of them had a node with any link.
 *
 * SO THE NODES BELONG AT THE CALL SITES, which is where the program says what
 * it is doing, and the function is a SUMMARY that says what a call to it means:
 * which system call, and which of the caller's values become which argument.
 * That is what a relocatable object's imports already are - a name at a call
 * site with a capability - and the same machinery (an origin that is carried from
 * the node that produced a value to the node that takes it) links them.
 *
 *   1. SUMMARISE. Every syscall instruction has an entry: the nearest direct-call
 *      target before it. If the straight line from the entry to the instruction
 *      reaches it without a branch, and the registers the kernel reads are the
 *      function's parameters (possibly moved or widened on the way) or constants,
 *      the function is a wrapper and the summary says which.
 *   2. WALK THE CALLERS, function by function, with a small symbolic state: which
 *      node produced the value in each register, in each stack slot of this frame,
 *      and in each global. A call to a wrapper makes a node at the call, with the
 *      arguments the summary maps from what the caller holds; what it returns is
 *      that node.
 *
 * WHAT THIS DOES NOT CLAIM. The walk is linear in address order and takes no
 * branch, so a value is "carried" when nothing overwrote the place it was kept
 * before the next use - a MAY link, as the rest of the static routes are. A write
 * through a pointer clears nothing. Calls to anything but a wrapper forget the
 * registers a callee may clobber and keep what is on the stack and in globals.
 * x86 and x86-64 only; the stack arguments of cdecl are read, regparm and
 * fastcall are not.
 */

#include "diag_wrapper_private.h"

void kgenome_diag_run_wrappers(struct kgenome_diag_scan *s,
			   const struct kgenome_obj *obj,
			   const uint8_t *base, uint64_t size)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	struct kgenome_diag_walk *wk;
	struct kgenome_diag_wrapper_ctx c;
	uint32_t i;

	if (!e || !e->valid)
		return;
	if (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64)
		return;
	wk = kgenome_diag_scan_walk(s);
	if (!wk)
		return;
	kgenome_diag_wrap_settle(s);
	memset(&c, 0, sizeof c);
	c.s = s;
	c.obj = obj;
	c.base = base;
	kgenome_cell_space_init(&c.sp, obj, base, size);
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;
	c.wk = wk;
	/* The walk is the object's, made once: it is already here when the
	 * functions were asked for first, and made here otherwise. */
	if (!kgenome_diag_walk_ensure(wk, obj, base, size, 1)) {
		kgenome_diag_note(s, KGENOME_NOMEM);     /* the decode walk could not be held */
		return;
	}
	if (!wk->n_site)
		goto opaque;
	for (i = 0; i < s->n_hit; i++)
		if (s->hit[i].cap == KGENOME_NUCLEO_NONE &&
		    (s->hit[i].bits & KGENOME_DIAG_H_OPAQUE) &&
		    !kgenome_diag_wrapper_push_u64(&c.open, &c.n_open, &c.cap_open, s->hit[i].at)) {
			kgenome_diag_note(s, KGENOME_NOMEM);
			goto out;
		}
	/* qsort's base is declared nonnull, and with no elements it is NULL. */
	if (c.n_open)
		qsort(c.open, c.n_open, sizeof *c.open, kof_cmp_u64);
	kgenome_diag_wrapper_tgt_unique(&c);
	if (!kgenome_diag_wrapper_charge(&c, (uint64_t)(wk->n_tgt ? wk->n_tgt : 1u) *
			 (sizeof *c.fret + sizeof *c.fmiss)))
		goto out;
	c.fret = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.fret);
	c.fmiss = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.fmiss);
	if (!c.fret || !c.fmiss) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	if (!kgenome_diag_wrapper_charge(&c, (uint64_t)(wk->n_tgt ? wk->n_tgt : 1u) * sizeof *c.tseen))
		goto out;
	c.tseen = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.tseen);
	if (!c.tseen) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	/*
	 * LEVEL 0: the functions that hold a syscall. THEN THE LEVELS: the functions
	 * whose straight line ends in a call to one already found, again and again
	 * until a level adds nothing (socket() around __socketcall around the
	 * syscall is three; the step budget is the bound).
	 */
	c.cap_ws = wk->n_site + 64u;
	if (!kgenome_diag_wrapper_charge(&c, (uint64_t)c.cap_ws * (sizeof *c.ws + sizeof *c.wi))) {
		c.cap_ws = 0;
		goto out;
	}
	c.ws = calloc(c.cap_ws, sizeof *c.ws);
	c.wi = calloc(c.cap_ws, sizeof *c.wi);
	if (!c.ws || !c.wi) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	for (i = 0; i < wk->n_site; i++) {
		uint64_t entry;
		struct kgenome_diag_wrapper_summary *t;
		unsigned nt, v;

		int ti;

		if (!kgenome_diag_wrapper_entry_of(&c, wk->site[i], &entry))
			continue;
		if (kgenome_diag_wrapper_summary_of(&c, entry))
			continue;
		ti = kgenome_diag_wrapper_tgt_index(&c, entry);
		/* A function with several sites is summarised once, and again only if
		 * a wrapper has appeared among what its walk met - see struct kgenome_diag_wrapper_tseen. */
		if (ti >= 0 && !kgenome_diag_wrapper_tseen_retry(&c, &c.tseen[ti]))
			continue;
		nt = kgenome_diag_wrapper_summarise(&c, entry, ti >= 0 ? &c.tseen[ti] : NULL, 1);
		t = c.var;
		/*
		 * A CAP CUT THE SUMMARY OF THE FUNCTION THAT HOLDS THIS SITE, and it cost an
		 * explanation when the sweep could not read the site either (the cap is
		 * what left it unexplained) or when the summary that WAS made is partial
		 * (a wrapper whose other arms were dropped): the scan says so.
		 *
		 * NOT FOR EVERY CUT. A function of two hundred instructions that holds a
		 * syscall deep inside is the ordinary case in a static libc, the body bound ends
		 * its walk, nothing was found and the sweep read the site directly - that
		 * loses no evidence and is not reported, or every static binary would
		 * come back "partial". (Measured on the prof set: see the report. One
		 * case this does not catch: a wrapper whose every arm is cut before
		 * it yields a summary, at a site the sweep read from the caller's stale
		 * constants - W_PENDING in tests/unit/diag_wrapper_limits.c.)
		 */
		if (c.cut && (nt > 0 || kgenome_diag_wrapper_site_open(&c, wk->site[i]) ||
			      kgenome_diag_wrapper_site_wrapped(s, wk->site[i])))
			kgenome_diag_note(s, KGENOME_TRUNCATED);
		for (v = 0; v < nt; v++)
			(void)kgenome_diag_wrapper_summary_insert(&c, &t[v]);
	}
	if (c.n_ws) {
		uint32_t added = 0;

		/* TO A FIXPOINT, bounded by the step budget: see the note on levels. */
		for (;;) {
			added = 0;
			if (s->bud.max_steps && c.steps + wk->n_tgt > s->bud.max_steps) {
				/* another pass cannot be paid for: whatever it would have added
				 * was never looked for, and the scan says so. */
				kgenome_diag_note(s, KGENOME_OVER_BUDGET);
				break;
			}
			c.steps += wk->n_tgt;
			for (i = 0; i < wk->n_tgt; i++) {
				struct kgenome_diag_wrapper_summary *t;
				unsigned nt, v;

				if (kgenome_diag_wrapper_summary_of(&c, wk->tgt[i]) || !kgenome_diag_wrapper_tseen_retry(&c, &c.tseen[i]))
					continue;
				nt = kgenome_diag_wrapper_summarise(&c, wk->tgt[i], &c.tseen[i], 0);
				t = c.var;
				for (v = 0; v < nt; v++) {
					if (!kgenome_diag_wrapper_summary_insert(&c, &t[v]))
						break;
					added++;
				}
			}
			if (!added || c.over_steps)
				break;
		}
	}
	if (!c.n_ws)
		goto opaque;
	/*
	 * TWICE, because a descriptor kept in a global is stored where the program
	 * dials out and read where it listens, and which of the two functions comes
	 * first in the file is the compiler's business. The second walk starts with
	 * every global the first one saw produced, so a read that came before the
	 * write in address order still finds it. The nodes it makes are the first
	 * walk's again, merged by site at the end of the scan, with the links the
	 * first walk could not yet have.
	 */
	{
		unsigned round;

		/*
		 * THE SECOND ROUND ONLY WHEN IT CAN DIFFER. It starts with the
		 * globals the first produced, so it changes the result exactly
		 * when some global was read before the first round had written it
		 * (need_round2) or a call asked for what a helper returns before the
		 * walk had reached the helper. Otherwise it would decode the whole image again
		 * to arrive at the same nodes: MEASURED, kgenome_diag_wrapper_pass_b is a full linear
		 * decode and this was the third of three over the same bytes.
		 */
		for (round = 0; round < 2u; round++) {
			if (round && !c.need_round2)
				break;
			for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
				uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

				if (have)
					kgenome_diag_wrapper_pass_b(&c, i, at, have);
			}
		}
	}
	/* A wrapper some caller made a node for is answered at its callers; the
	 * node the sweep made at the syscall inside it spoke for every caller at
	 * once and for none of them, and is set aside. */
	kgenome_diag_wrapper_supersede(&c);
opaque:
	/* A socketcall of an unknown kind is a different statement from no
	 * socketcall at all: a site nobody called with a value this could read
	 * says so, once, rather than saying nothing. */
	for (i = 0; i < s->n_wrap; i++) {
		if (!kgenome_diag_wrapper_site_made(&c, s->wrap[i])) {
			struct kgenome_diag_hit *h = kgenome_diag_hit_add(s, s->wrap[i],
								  KGENOME_NUCLEO_NONE, 0);

			if (h)
				h->bits |= KGENOME_DIAG_H_OPAQUE;
		}
	}
out:
	/* The trace STAYS with a walk the scanner owns, to the end of the object:
	 * the xref sweep reads the same instructions (see kgenome_diag_code_run), and
	 * the scanner frees the walk when the next object begins. A walk this scan
	 * made for itself has no other reader - nobody can hand it to the sweep - so
	 * its trace goes now, as it always did: a tool that keeps a scan alive to
	 * show it must not keep an object's worth of decode with it. */
	if (wk == s->own_walk)
		kgenome_diag_wrapper_walk_drop_trace(wk);
	free(c.open);
	free(c.pend);
	free(c.var);
	free(c.tseen);
	free(c.fret);
	free(c.fmiss);
	free(c.ws);
	free(c.wi);
	free(c.made);
	free(c.glob);
	kgenome_ledger_release(&s->led, c.charged);
}
