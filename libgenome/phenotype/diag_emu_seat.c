/*
 * diag_emu_seat.c - the walk of one function: seating a span, finishing it, and the driver over all functions.
 * Part of the emulate route; see diag_emu.c for what it is for and diag_emu_private.h for what the
 * files share.
 */
#include "diag_emu_private.h"

/*
 * On to the next site: seat the span there. Zero when there is none, and the
 * span ends.
 */
static int rel_seat_next(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S)
{
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_diag_emu_skipgather sg = R->sg;
	uint8_t *vis = R->vis;
	struct kgenome_emu *em = S->em;
	uint64_t run_lo = S->run_lo;
	uint64_t run_hi = S->run_hi;

	/*
	 * ---- ON TO THE NEXT SITE ---------------------------
	 *
	 * The run has stopped being able to walk - it left the
	 * function, it returned, or it met an instruction this
	 * build does not carry. None of that is a finding; the
	 * sites it has not reached yet are still listed in the
	 * relocation table, and the span's job is to arrive at
	 * them.
	 *
	 * STRICTLY FORWARD, so one pass cannot circle: the next
	 * seat is the lowest site above the last address the
	 * run was really at. That is also why no "already
	 * seated" flag is needed.
	 */
	uint32_t w, bq = sg.n, pv = sg.n;
	uint64_t seat;

	/*
	 * THE NEXT SITE IS THE NEXT ONE NOT YET
	 * LOOKED AT - not the next one by address.
	 *
	 * Seating strictly forwards was tried and it
	 * abandons sites silently: a branch that
	 * carries the run from 0x2d0 to 0x380 puts
	 * every site between them permanently behind
	 * it. MEASURED on diamondxe, whose
	 * copy_to_user at 0x365 was jumped over and
	 * then never seated - and a site that is
	 * never looked at reads exactly like a call
	 * with no link.
	 *
	 * vis[] is what makes this terminate: a site
	 * is marked when it is REACHED and when it is
	 * SEATED, so each one is tried at most once
	 * and the pass is still finite.
	 */
	/*
	 * FORWARD FIRST, STRAGGLERS AFTER.
	 *
	 * The next site AHEAD of where the run really
	 * got to is the one whose arguments the code
	 * just walked was setting up, so it is tried
	 * first - taking the lowest unvisited site
	 * instead put diamorphine's copy_to_user in a
	 * gap that never loaded its buffer.
	 *
	 * ONLY WHEN NOTHING IS AHEAD does the span go
	 * back for what it jumped over. Seating
	 * strictly forwards abandons those silently -
	 * MEASURED on diamondxe, whose copy_to_user at
	 * 0x365 was branched over and never seated,
	 * which reads exactly like a call with no
	 * link.
	 *
	 * vis[] is marked both when a site is REACHED
	 * and when it is SEATED, so each is tried at
	 * most once and the pass stays finite.
	 */
	/*
	 * ---- THE SEATS ARE THE NODES, NOT THE CALLS
	 *
	 * What the span is trying to do is VERIFY A
	 * NODE: a position that matched the
	 * vocabulary, whose arguments are the thing a
	 * link is made of. A call to something the
	 * dictionary has no word for is not a node,
	 * cannot carry a link, and is worth stepping
	 * over when it turns up - never worth moving
	 * the run to.
	 *
	 * THAT WAS THE HOLE. The seat list was every
	 * call site, so "where to go next" was decided
	 * by address arithmetic over a list that is
	 * mostly noise, and the order it produced was
	 * tuned by hand against one sample at a time -
	 * each adjustment resolving one Diamorphine
	 * build and breaking the other. The routine
	 * did not know which node it still had to
	 * verify.
	 */
	for (w = 0; w < sg.n; w++) {
		if (vis[w] ||
		    skips[w].cap == KGENOME_NUCLEO_NONE ||
		    skips[w].call_at <= S->last_in ||
		    skips[w].call_at < run_lo ||
		    skips[w].call_at >= run_hi)
			continue;
		if (bq == sg.n ||
		    skips[w].call_at < skips[bq].call_at)
			bq = w;
	}
	if (bq == sg.n)
		for (w = 0; w < sg.n; w++) {
			if (vis[w] ||
			    skips[w].cap ==
			    KGENOME_NUCLEO_NONE ||
			    skips[w].call_at < run_lo ||
			    skips[w].call_at >= run_hi)
				continue;
			if (bq == sg.n ||
			    skips[w].call_at <
			    skips[bq].call_at)
				bq = w;
		}
	if (bq != sg.n && S->n_seat >= KGENOME_DIAG_REL_SEATS)
		kgenome_diag_note(R->s, KGENOME_TRUNCATED);    /* a site left unvisited */
	if (bq == sg.n || S->n_seat >= KGENOME_DIAG_REL_SEATS)
		return 0;
	/*
	 * SEATED AT THE START OF THE GAP, NOT AT THE
	 * CALL.
	 *
	 * Landing on the call itself skips the very
	 * instructions that put its arguments in
	 * place - MEASURED: diamondxe's copy_to_user
	 * was reached and its kernel buffer register
	 * was empty, because `mov %r14,%rsi` is three
	 * instructions before the call and the seat
	 * jumped over it.
	 *
	 * The stretch between two sites is exactly
	 * what this routine was built to emulate, and
	 * the previous site's RESUME is a known
	 * instruction boundary - it is a return
	 * address - so no search for one is needed.
	 */
	for (w = 0; w < sg.n; w++) {
		if (skips[w].resume >= run_lo &&
		    skips[w].resume <=
		    skips[bq].call_at &&
		    (pv == sg.n ||
		     skips[w].resume >
		     skips[pv].resume))
			pv = w;
	}
	seat = pv == sg.n ? skips[bq].call_at
			  : skips[pv].resume;
	/*
	 * AND THE ARGUMENT REGISTERS ARE CLEARED.
	 *
	 * The run did not walk here; it was placed
	 * here. Whatever a volatile register held
	 * belongs to the stretch that stalled, and
	 * keeping it lets a value from one call be
	 * read as the argument of another - MEASURED:
	 * diamorphine's list_del was recorded taking
	 * the struct prepare_creds returned, which
	 * nothing in the program does.
	 *
	 * Only the volatile ones. rbx, rbp and r12-r15
	 * are where a function keeps what it carries
	 * across calls - the hooked getdents holds its
	 * buffer in r14 - and clearing those would
	 * throw away the links this span exists for.
	 */
	for (w = 0; w < 6u; w++)
		kgenome_emu_set_reg(em,
			kgenome_diag_sysv_arg[w], 0);
	kgenome_emu_set_reg(em, KGENOME_EMU_RAX, 0);
	vis[bq] = 1;
	S->n_seat++;
	S->gap_steps = 0;
	S->last_in = seat;
	kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE + seat);
	return 1;
}

/*
 * What this function handed back, and who must be walked again because of it.
 */
static void rel_span_finish(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S, uint32_t j)
{
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_func *fns = R->fns;
	const struct kgenome_func_set fg = R->fg;
	const struct kgenome_diag_emu_skipgather sg = R->sg;
	uint16_t *ret = R->ret;
	uint8_t *next_dirty = R->next_dirty;
	struct kgenome_emu *em = S->em;

	/*
	 * AND WHAT THIS FUNCTION HANDS BACK, for whoever calls it:
	 * the token left in the result register when its span ended.
	 * Recorded rather than reasoned about, and read by the next
	 * pass.
	 */
	uint64_t rv = kgenome_emu_get_reg(em, KGENOME_EMU_RAX);
	uint16_t was = ret[j];

	if (rv >= KGENOME_DIAG_TOK_BASE &&
	    rv < KGENOME_DIAG_TOK_BASE +
		 (uint64_t)KGENOME_DIAG_TOK_MAX * KGENOME_EMU_PAGE)
		ret[j] = (uint16_t)((rv - KGENOME_DIAG_TOK_BASE) /
				    KGENOME_EMU_PAGE);
	if (ret[j] != was) {
		uint32_t w;

		R->changed = 1;
		/* whoever calls this function may now see a
		 * different value come back */
		for (w = 0; w < sg.n; w++)
			if (skips[w].callee == fns[j].off) {
				uint32_t g;

				for (g = 0; g < fg.n; g++)
					if (skips[w].call_at >=
					    fns[g].off &&
					    skips[w].call_at <
					    fns[g].off +
					    fns[g].len)
						next_dirty[g] = 1;
			}
	}
	kgenome_emu_free(em);
}

/* `init` is what the caller filled: the object, the gathered sites and
 * functions, the per-function tables and the template. The rest is this walk's. */
static void run_rel_gaps_in(const struct kgenome_diag_emu_rel_walk *init)
{
	struct kgenome_diag_emu_rel_walk R = *init;
	struct kgenome_diag_scan *s = R.s;
	uint16_t *ret = R.ret;
	uint8_t *dirty = R.dirty, *next_dirty = R.next_dirty, *vis = R.vis;
	struct kgenome_diag_emu_rel_span S;
	uint32_t j, pass;

	S.seen = NULL;
	S.cap_seen = 0;
	R.n = kgenome_diag_scan_count(s);

	kgenome_diag_emu_promote_wrappers(s, R.fns, R.fg.n);
	for (j = 0; j < R.fg.n; j++)
		ret[j] = 0xffffu;

	for (j = 0; j < R.fg.n; j++)
		dirty[j] = 1;           /* the first pass walks everything */

	for (pass = 0; pass < KGENOME_DIAG_REL_PASSES; pass++) {
		R.changed = 0;

		for (j = 0; j < R.fg.n; j++) {
			uint32_t step;

			/*
			 * RESET AT EVERY FUNCTION, and this was tried the other way.
			 *
			 * An address looks like it should survive the function it was
			 * seen in - module_hide and module_show hand the same
			 * THIS_MODULE->list to list_del and list_add, and that
			 * relation is real. But each span BUILDS ITS OWN IMAGE, so a
			 * local in one function lands at the same emulated address as
			 * an unrelated local in the next. MEASURED: hacked_getdents'
			 * buffer linked to hacked_getdents64's, two different
			 * functions and two different buffers, and the spurious
			 * matches pushed the kprobe pairs out of the four slots a
			 * node has.
			 *
			 * A relation between functions is real only for an object
			 * with a fixed address, and a fixed address is a RELOCATION -
			 * known without running anything. That is where list_del and
			 * list_add belong, not here.
			 */
			/*
			 * ---- A LATER PASS WALKS ONLY WHAT COULD HAVE MOVED -------
			 *
			 * The passes exist so that a caller learns what an internal
			 * call returns, which is only known once the callee has been
			 * walked. If no callee of this function reported anything new,
			 * walking it again cannot produce anything new either.
			 *
			 * MEASURED: a second pass over EVERYTHING produced exactly the
			 * same 19327 nodes and 488 chains on 900 clean kernel modules
			 * and on both Diamorphine builds - it was a confirmation pass
			 * that cost a complete re-run.
			 */
			if (!dirty[j])
				continue;

			S.n_seen = 0;
			S.n_fd = 0;
			S.n_seat = 0;
			S.gap_steps = 0;
			S.n_latch = 0;
			S.n_fault = 0;
			S.lo = R.fns[j].off;
			if (S.lo >= R.size)
				continue;
			S.hi = S.lo + R.fns[j].len;

			if (kgenome_diag_emu_rel_span_too_sparse(&R, &S))
				continue;

			memset(vis, 0, R.sg.n);

			if (kgenome_diag_emu_rel_span_no_producer(&R, &S))
				continue;

			if (!kgenome_diag_emu_rel_span_open(&R, &S)) {
				free(S.seen);
				return;
			}
			/* Anonymous pages come from the top of the mapped arena (known now: the template
			 * that maps it exists): above the producers' pages when the arena was grown,
			 * anywhere in it - the old layout - when it was not. */
			S.anon = s->rel_tok_span - 1u;
			S.anon_floor = s->rel_tok_lim > KGENOME_DIAG_TOK_SPAN ? s->rel_tok_lim : 0u;

			for (step = 0; step < KGENOME_DIAG_REL_STEPS; step++) {
				uint64_t rip = kgenome_emu_get_rip(S.em) -
					       KGENOME_DIAG_REL_BASE;
				enum kgenome_diag_emu_rel_act act = kgenome_diag_emu_rel_step_enter(&S, rip);

				if (act == KGENOME_DIAG_EMU_REL_ON)
					act = kgenome_diag_emu_rel_step_sites(&R, &S, rip);
				if (act == KGENOME_DIAG_EMU_REL_ON)
					act = kgenome_diag_emu_rel_step_decode(&R, &S, rip);
				if (act == KGENOME_DIAG_EMU_REL_ON)
					act = kgenome_diag_emu_rel_step_emulate(&R, &S, rip);
				if (act == KGENOME_DIAG_EMU_REL_NEXT)
					continue;
				if (!rel_seat_next(&R, &S))
					break;
			}
			/* The span used every step and was still going: what it would
			 * have reached next is unseen. */
			if (step >= KGENOME_DIAG_REL_STEPS)
				kgenome_diag_note(s, KGENOME_TRUNCATED);
			rel_span_finish(&R, &S, j);
		}
		if (!R.changed)
			break;
		memcpy(dirty, next_dirty, R.fg.n);
		memset(next_dirty, 0, R.fg.n);
	}
	/* The last pass still changed what a function returns: the fixpoint was not
	 * reached, and what depends on it is a pass short. */
	if (pass >= KGENOME_DIAG_REL_PASSES)
		kgenome_diag_note(s, KGENOME_TRUNCATED);
	free(S.seen);
}

/*
 * Gathers what the body walks, SIZED BY THE OBJECT: a program with 3000 call
 * sites is walked at all 3000, where a fixed 1024 dropped the rest unseen.
 * An allocation that fails is reported as the scan being incomplete.
 */
void kgenome_diag_emu_run_rel_gaps(struct kgenome_diag_scan *s,
			 const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size)
{
	struct kgenome_diag_emu_skipgather sg;
	const struct kgenome_func_set *fgp;
	uint16_t *ret = NULL;
	uint8_t *flags = NULL;
	struct kgenome_emu *tmpl = NULL;

	if (obj->arch != KGENOME_ARCH_X86_64 || !kgenome_diag_scan_count(s))
		return;

	memset(&sg, 0, sizeof sg);
	{
		uint32_t nrc, k;
		const struct kgenome_diag_rcall *rc = kgenome_diag_relcalls(s, obj, &nrc);

		for (k = 0; k < nrc; k++)
			kgenome_diag_emu_gather_skip(&sg, &rc[k]);
	}
	fgp = kgenome_diag_funcs(s, obj);
	if (sg.n > 1u)
		qsort(sg.site, sg.n, sizeof *sg.site, kgenome_diag_emu_skip_cmp);
	if (sg.oom || fgp->status != KGENOME_OK) {
		s->halt = 1;
		kgenome_diag_note(s, KGENOME_NOMEM);
	}
	if (sg.n && fgp->n) {
		ret = malloc((size_t)fgp->n * sizeof *ret);
		flags = calloc((size_t)fgp->n * 3u + sg.n, 1);
		if (ret && flags) {
			struct kgenome_diag_emu_rel_walk R;

			memset(&R, 0, sizeof R);
			R.s = s;
			R.obj = obj;
			R.base = base;
			R.size = size;
			R.skips = sg.site;
			R.fns = fgp->v;
			R.sg = sg;
			R.fg = *fgp;
			R.ret = ret;
			R.dirty = flags;
			R.next_dirty = flags + fgp->n;
			R.vis = flags + 2u * fgp->n;
			R.tmpl = &tmpl;
			run_rel_gaps_in(&R);
		} else {
			s->halt = 1;
			kgenome_diag_note(s, KGENOME_NOMEM);
		}
	}
	kgenome_emu_free(tmpl);
	kgenome_diag_emu_pages_release(s);
	free(ret);
	free(flags);
	free(sg.site);
}
