/*
 * diag_emu_sites.c - the walk of one function: the span, and what a step does at a site.
 * Part of the emulate route; see diag_emu.c for what it is for and diag_emu_int.h for what the
 * files share.
 */
#include "diag_emu_int.h"




/* Whether a function is too sparse to be run: fewer than two nodes in it or
 * reachable from it, and no cr0 write. One means the span is not run. */
int kgenome_diag_emu_rel_span_too_sparse(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S)
{
	struct kgenome_diag_scan *s = R->s;
	const uint8_t *base = R->base;
	uint64_t size = R->size;
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_func *fns = R->fns;
	const struct kgenome_func_set fg = R->fg;
	const struct kgenome_diag_emu_skipgather sg = R->sg;
	uint32_t n = R->n;
	uint64_t lo = S->lo;
	uint64_t hi = S->hi;

	/*
	 * A FUNCTION WITH FEWER THAN TWO NODES IN IT CANNOT HOLD A
	 * LINK, so it is not run.
	 *
	 * EXACT, not a heuristic: a link relates two nodes, and both
	 * ends have to be inside the scope a register means anything
	 * in. The site table already says where every node is, so the
	 * check costs a comparison per site.
	 *
	 * AND IT IS WHAT KEEPS THIS SURVIVABLE ON A BLOATED BINARY,
	 * which is the reason it matters rather than a saving. A
	 * module written in C has tens of functions; a Go program has
	 * thousands, almost all of them runtime, and a routine that
	 * built an image and stepped a span for each would not finish.
	 * The gate is what makes the cost proportional to the number
	 * of NODES rather than to the number of functions - which is
	 * the only quantity the analysis is actually about.
	 *
	 * MEASURED: diamorphine.ko 7 of 13 functions run, diamondxe.ko
	 * 8 of 32. The rejected ones are the hooked syscall bodies and
	 * the helpers, holding one node or none.
	 */
	uint32_t in_fn = 0, t;

	for (t = 0; t < n; t++) {
		const struct kgenome_diag_hit *p =
			kgenome_diag_scan_at(s, t);

		if (p && p->at >= lo && p->at < hi)
			in_fn++;
	}
	/*
	 * AND A FUNCTION WITH ONE NODE STILL COUNTS IF IT
	 * CALLS ONE THAT HAS THEM. init_module holds few
	 * nodes of its own and calls findmyinterest, which
	 * holds the kprobe pair - the chain crosses the
	 * boundary and a check that only counted nodes
	 * inside would refuse to walk it.
	 */
	if (in_fn < 2u) {
		uint32_t w, reach = in_fn;

		for (w = 0; w < sg.n; w++) {
			if (skips[w].call_at < lo ||
			    skips[w].call_at >= hi)
				continue;
			if (skips[w].cap != KGENOME_NUCLEO_NONE ||
			    (skips[w].callee &&
			     kgenome_diag_emu_callee_node(s, fns, fg.n,
					 skips[w].callee) !=
			     0xffffu))
				reach++;
		}
		/* AND A FUNCTION THAT TOUCHES cr0 IS WALKED
		 * WHATEVER ELSE IS IN IT - see kgenome_diag_emu_has_cr_write. */
		if (reach < 2u &&
		    !(hi <= size &&
		      kgenome_diag_emu_has_cr_write(base + lo, hi - lo)))
			return 1;
	}
	return 0;
}

/* Whether a span has nothing that could carry a link (one means it is not
 * run), and otherwise the stretch it walks. */
int kgenome_diag_emu_rel_span_no_producer(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S)
{
	struct kgenome_diag_scan *s = R->s;
	const uint8_t *base = R->base;
	uint64_t size = R->size;
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_func *fns = R->fns;
	const struct kgenome_func_set fg = R->fg;
	const struct kgenome_diag_emu_skipgather sg = R->sg;
	uint64_t lo = S->lo;
	uint64_t hi = S->hi;

	/*
	 * ---- CAN THIS FUNCTION CARRY A LINK AT ALL -----------------
	 *
	 * Answered before a single instruction is stepped, from the
	 * site list the relocation table already gave us. It is a
	 * precondition, not a budget: if it holds, the WHOLE function
	 * is walked.
	 *
	 *   a site that HANDS SOMETHING ON, or
	 *   two sites that TAKE AN ARGUMENT - a shared relation has no
	 *   producer at all; both halves of a kprobe pair are merely
	 *   handed the same struct.
	 *
	 * With neither, nothing in this function can be linked to
	 * anything: a field access needs a token in a register, and a
	 * token only exists because some call produced one.
	 *
	 * AND THE STRETCH IS NOT CUT SHORT. Trimming it at the last
	 * CALL site was tried and it deleted evidence - 405 chains on
	 * 900 clean modules, nearly all of them
	 * `mem-alloc-heap -> mem-action-write`. A token can be
	 * dereferenced anywhere after it is produced, field accesses
	 * are not in the relocation table, and so there is no sound
	 * place to stop early. Cost belongs to the loop bounds below,
	 * not to a gate on how much of the function is looked at.
	 */
	uint32_t t, takers = 0;
	int producer = 0;

	for (t = 0; t < sg.n; t++) {
		uint64_t a = skips[t].call_at;
		unsigned k;

		if (a < lo || a >= hi)
			continue;
		/* The vocabulary's answer - see
		 * kgenome_flow_hands_on. No name here: this is
		 * a call the span stepped over, and what it
		 * is asking is only whether SOMETHING in the
		 * gap could have produced a value. */
		if (kgenome_flow_hands_on(skips[t].cap, NULL) ||
		    (skips[t].callee &&
		     kgenome_diag_emu_callee_node(s, fns, fg.n,
				 skips[t].callee) != 0xffffu))
			producer = 1;
		for (k = 0; k < 6u; k++)
			if (kgenome_diag_role_of_arg(skips[t].cap, k)
			    != KGENOME_DIAG_ROLE_NONE) {
				takers++;
				break;
			}
	}
	if (!producer && takers < 2u &&
	    !(hi <= size && kgenome_diag_emu_has_cr_write(base + lo, hi - lo)))
		return 1;
	S->run_lo = lo;
	S->run_hi = hi;
	return 0;
}

/* Fork the object's image for this span. Zero means the whole walk ends. */
int kgenome_diag_emu_rel_span_open(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S)
{
	struct kgenome_diag_scan *s = R->s;
	const struct kgenome_obj *obj = R->obj;
	const uint8_t *base = R->base;
	uint64_t size = R->size;
	struct kgenome_emu **tmpl = R->tmpl;
	uint64_t run_lo = S->run_lo;

	/* ONE IMAGE PER OBJECT, FORKED PER SPAN. Applying the relocation
	 * tables is the cost of an image, and it was paid again for
	 * every span: callgrind on a 3000-site module put 52% of the
	 * scan in the byte writes of that loop. */
	if (!*tmpl)
		*tmpl = kgenome_diag_emu_build_rel_image(s, obj, base, size);
	if (!*tmpl)
		return 0;
	S->em = kgenome_emu_fork(*tmpl);
	if (!S->em) {
		s->halt = 1;
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	kgenome_emu_set_rip(S->em, KGENOME_DIAG_REL_BASE + run_lo);
	S->last_in = run_lo;
	return 1;
}

/* Is this step still inside the stretch, and inside the gap budget. */
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_enter(struct kgenome_diag_emu_rel_span *S, uint64_t rip)
{
	uint64_t run_lo = S->run_lo;
	uint64_t run_hi = S->run_hi;

	if (rip < run_lo || rip >= run_hi)
		return KGENOME_DIAG_EMU_REL_STALL;   /* left the stretch */
	/*
	 * AND A GAP THAT WILL NOT FINISH IS ONE TO STEP
	 * AROUND - see KGENOME_DIAG_REL_GAP. Spinning here is not a
	 * finding, and the sites after it are still listed.
	 */
	if (S->gap_steps++ > KGENOME_DIAG_REL_GAP)
		return KGENOME_DIAG_EMU_REL_STALL;
	S->last_in = rip;
	return KGENOME_DIAG_EMU_REL_ON;
}

/* The names a call carries, kept with the node the call became. */
static void rel_site_names(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S, uint32_t q,
			   uint64_t rip, uint16_t node)
{
	struct kgenome_diag_scan *s = R->s;
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_func *fns = R->fns;
	const struct kgenome_func_set fg = R->fg;
	struct kgenome_emu *em = S->em;
	uint64_t lo = S->lo;

	if (skips[q].call_at == rip) {
		uint16_t cn = skips[q].callee
			? kgenome_diag_emu_callee_node(s, fns, fg.n,
				      skips[q].callee)
			: 0xffffu;
		struct kgenome_diag_hit *ch;
		uint64_t a0 = kgenome_emu_get_reg(em,
			kgenome_diag_sysv_arg[0]);
		char nm[KGENOME_DIAG_STR_MAX + 1u];

		/*
		 * THE NAMES THE CALL ITSELF CARRIES, by
		 * what the vocabulary says its
		 * capability is handed - a probe's
		 * object, a resolver's string.
		 */
		kgenome_diag_emu_capture_names(s, em, skips[q].cap, node);

		/*
		 * TWO PLACES THE SAME NAME CAN BE, and
		 * the two Diamorphine builds have one
		 * each.
		 *
		 * diamondxe keeps findmyinterest as a
		 * function, so the caller hands the
		 * name IN and the name belongs to the
		 * callee's node.
		 *
		 * diamorphine inlined it, so the block
		 * itself loads the name and passes it
		 * ON - here through a retpoline thunk,
		 * which is an import and names no
		 * callee at all. The name then belongs
		 * to the node promoted over THIS
		 * function.
		 *
		 * Both are the same statement: this
		 * hook-declaration block was reaching
		 * for that symbol.
		 */
		if (cn == 0xffffu)
			cn = kgenome_diag_emu_callee_node(s, fns, fg.n, lo);
		ch = cn == 0xffffu ? 0
				   : kgenome_diag_hit_of(s, cn);
		/*
		 * THE NAME AN INLINED RESOLVER WAS
		 * HANDED, kept under the node that was
		 * promoted over this block. Deduplicated
		 * with the line above, so a call that
		 * answers to both is one name.
		 */
		if (ch && kgenome_diag_emu_guest_name(em, a0, nm))
			kgenome_diag_str_add(s, ch->cap, cn, nm);
	}
}

/* Every earlier holder of an argument's value is a relation. */
static void rel_site_args(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S, uint16_t node)
{
	struct kgenome_diag_scan *s = R->s;
	uint64_t size = R->size;
	struct kgenome_emu *em = S->em;
	struct kgenome_diag_emu_seenval *seen = S->seen;

	unsigned k;

	if (node != 0xffffu) {
		struct kgenome_diag_hit *h =
			kgenome_diag_hit_of(s, node);

		for (k = 0; k < 6u && h; k++) {
			uint8_t role =
			  kgenome_diag_role_of_arg(
				h->cap, k);
			uint64_t v = kgenome_emu_get_reg(em,
			  kgenome_diag_sysv_arg[k]);
			uint32_t t;

			if (role == KGENOME_DIAG_ROLE_NONE)
				continue;
			/*
			 * EVERY EARLIER HOLDER OF THIS
			 * VALUE IS A RELATION, and each
			 * one is said in its own words:
			 * the node that RETURNED it is
			 * where it came from, a node
			 * that was merely handed it
			 * shares the object. See enum
			 * kgenome_diag_kind - collapsing
			 * the two left one argument
			 * with two parents under one
			 * role, and the engine then
			 * had to choose, which is how
			 * a receiver came to be
			 * recorded as a producer.
			 */
			for (t = 0; t < S->n_seen; t++) {
				const struct kgenome_diag_hit *o;

				if (seen[t].val != v ||
				    seen[t].node == node)
					continue;
				/*
				 * A SHARED EDGE IS
				 * RECORDED ONCE, FROM
				 * THE LATER SITE TO THE
				 * EARLIER ONE.
				 *
				 * Sharing an object is
				 * symmetric, but what
				 * carries the meaning is
				 * the ORDER - a buffer
				 * is filled and then
				 * written back out, and
				 * that is the hook.
				 * Recorded both ways it
				 * is a cycle: each
				 * kprobe call became the
				 * other's parent, no
				 * node was a root, and
				 * the pair stopped
				 * appearing as a chain
				 * at all while both
				 * links were in the
				 * data.
				 *
				 * Provenance needs no
				 * such rule: a producer
				 * is earlier by
				 * construction.
				 */
				o = kgenome_diag_scan_at(s,
					seen[t].node);
				if (!seen[t].produced &&
				    o && o->at >= h->at)
					continue;
				kgenome_diag_note_in(s,
					  h,
					  seen[t].node,
					  role,
					  seen[t].produced
					  ? KGENOME_DIAG_KIND_PRODUCED
					  : KGENOME_DIAG_KIND_SHARED);
			}
			/*
			 * AND THIS NODE NOW HOLDS IT
			 * TOO. Recorded even where a
			 * producer entry already
			 * stands for the value: that
			 * entry answers where the
			 * object came from and this
			 * one answers who has touched
			 * it, and the next holder
			 * needs both. A buffer
			 * kzalloc made, filled by
			 * copy_from_user and written
			 * back by copy_to_user is
			 * three entries and the third
			 * call links to the other two
			 * - the ordering IS the hook.
			 *
			 * One entry per (value, node),
			 * so a loop round the same
			 * call adds nothing.
			 */
			if (kgenome_diag_emu_worth_remembering(v, size)) {
				uint32_t e;

				for (e = 0; e < S->n_seen; e++)
					if (seen[e].val == v &&
					    seen[e].node == node)
						break;
				if (e == S->n_seen &&
				    S->n_seen < KGENOME_DIAG_REL_SEEN) {
					seen[e].val = v;
					seen[e].node = node;
					seen[e].produced = 0;
					S->n_seen++;
				}
			}
		}
	}
}

/* Over the call, with its result stated. */
static void rel_site_result(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
			    uint32_t q, uint16_t node)
{
	struct kgenome_diag_scan *s = R->s;
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_func *fns = R->fns;
	const struct kgenome_func_set fg = R->fg;
	uint16_t *ret = R->ret;
	struct kgenome_emu *em = S->em;
	struct kgenome_diag_emu_seenval *seen = S->seen;


	/*
	 * OVER THE CALL, NEVER THROUGH IT, and the
	 * result stated rather than computed - see
	 * the note on skipping above. A producer's
	 * token is remembered the same way an
	 * argument is, so the next site holding it
	 * links back here.
	 */
	kgenome_emu_set_rip(em, KGENOME_DIAG_REL_BASE +
			skips[q].resume);
	{
		uint16_t src = 0xffffu;

		if (node != 0xffffu &&
		    kgenome_flow_hands_on(skips[q].cap,
				      NULL))
			src = node;
		else if (skips[q].callee) {
			uint32_t t;

			/* What that function was
			 * MEASURED to return, from an
			 * earlier pass; the one-node
			 * rule only while nothing has
			 * been measured yet. */
			src = 0xffffu;
			for (t = 0; t < fg.n; t++)
				if (fns[t].off ==
				    skips[q].callee) {
					src = ret[t];
					break;
				}
			if (src == 0xffffu)
				src = kgenome_diag_emu_callee_node(s,
					fns, fg.n,
					skips[q].callee);
		}
		if (src != 0xffffu &&
		    src < KGENOME_DIAG_TOK_SPAN) {
			uint64_t tok = KGENOME_DIAG_TOK_BASE +
			  (uint64_t)src * KGENOME_EMU_PAGE;

			kgenome_emu_set_reg(em,
					KGENOME_EMU_RAX,
					tok);
			if (S->n_seen < KGENOME_DIAG_REL_SEEN) {
				seen[S->n_seen].val = tok;
				seen[S->n_seen].node = src;
				seen[S->n_seen].produced = 1;
				S->n_seen++;
			}
		} else if (kgenome_diag_emu_cap_force_kind(skips[q].cap)
			   != KGENOME_DIAG_EMU_FORCE_NONE) {
			/*
			 * WHAT THIS CALL HANDS BACK IS
			 * ALREADY WRITTEN DOWN, once,
			 * in kgenome_diag_emu_cap_force_kind - and this
			 * routine used to ignore it and
			 * give every call the same
			 * anonymous page. For a call
			 * whose success is ZERO that
			 * said the opposite of what was
			 * meant.
			 */
			uint64_t r = 0;

			switch (kgenome_diag_emu_cap_force_kind(
					skips[q].cap)) {
			case KGENOME_DIAG_EMU_FORCE_HANDLE:
				r = KGENOME_DIAG_EMU_FD0 +
				    S->n_fd++;
				break;
			case KGENOME_DIAG_EMU_FORCE_COUNT:
				r = kgenome_emu_get_reg(em,
				  kgenome_diag_sysv_arg[2]);
				break;
			default:
				r = 0;  /* KGENOME_DIAG_EMU_FORCE_ZERO */
				break;
			}
			kgenome_emu_set_reg(em,
					KGENOME_EMU_RAX, r);
		} else if (S->anon) {
			/*
			 * A CALL WHOSE RESULT NOTHING
			 * HERE EXPLAINS STILL HAS TO
			 * LOOK LIKE SUCCESS.
			 *
			 * Clearing the register leaves
			 * zero, and zero is what every
			 * caller tests for failure.
			 * MEASURED: Diamorphine's
			 * init_module calls
			 * findmyinterest, reads zero
			 * back, decides the lookup
			 * failed and jumps to its
			 * error return - nine
			 * instructions in, past
			 * nothing, 110 bytes short of
			 * the cr0 write the walk was
			 * opened for.
			 *
			 * An anonymous page from the
			 * arena is non-zero so the
			 * branch goes the other way,
			 * mapped so dereferencing it
			 * does not fault, and belongs
			 * to no node so it can never
			 * be mistaken for a link.
			 */
			kgenome_emu_set_reg(em,
				KGENOME_EMU_RAX,
				KGENOME_DIAG_TOK_BASE +
				(uint64_t)(--S->anon) *
				KGENOME_EMU_PAGE);
		}
	}
}

/* One when the call site is really a tail jump, which ends the function. */
static int rel_site_tail_jump(struct kgenome_diag_emu_rel_walk *R, uint64_t rip)
{
	const uint8_t *base = R->base;
	uint64_t size = R->size;

	/*
	 * ---- AND A TAIL JUMP IS AN EXIT ----------
	 *
	 * The relocation table lists `jmp foo` beside
	 * `call foo` and nothing in it says which. A
	 * call's `resume` is where the callee comes
	 * back to; a JUMP never comes back, so the
	 * bytes after it are not a continuation of
	 * anything - they belong to whatever block
	 * the compiler laid there next.
	 *
	 * MEASURED, and it is why Diamorphine's
	 * hacked_getdents had no link at all. The
	 * function ends
	 *
	 *     mov %rbx,%rax ; add $0x10,%rsp
	 *     pop %rbx,%rbp,%r12,%r13,%r14,%r15
	 *     jmp <reloc>            <- the exit
	 *     cmp %r13,0x12(%rbx)    <- loop body
	 *     jne  ...
	 *
	 * Resuming after the jump walked into the
	 * loop body with every callee-saved register
	 * just popped off a stack this run never
	 * built - so the kernel buffer was 0 - and
	 * the loop then ran until the step budget
	 * ended it, 11 bytes short of the
	 * copy_to_user the span was opened for.
	 *
	 * THE LINKS ARE NOTED FIRST, above. A tail
	 * call IS a call to that import and its
	 * arguments are set up in the usual way -
	 * god_mode ends `jmp commit_creds` - so the
	 * node and its links are real. Only the
	 * resumption is not.
	 *
	 * Asked of the decoder, not of a byte: an
	 * encoding list is the thing this engine
	 * does not keep twice.
	 */
	if (rip < size) {
		struct kgenome_cell_insn ji;
		uint32_t jl = kgenome_cell_decode_x86(base + rip,
			(uint32_t)(size - rip > 16u
				   ? 16u : size - rip),
			rip, 64u, &ji);

		if (jl && ji.op == KGENOME_CELL_JMP) {
			return 1;
		}
	}
	return 0;
}

/* One call site the step arrived at. One when the function returned. */
static int rel_site_call(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S, uint32_t q,
			 uint64_t rip)
{
	struct kgenome_diag_emu_skipsite *skips = R->skips;
	struct kgenome_diag_scan *s = R->s;
	uint32_t n = R->n;
	uint8_t *vis = R->vis;
	uint16_t node = 0xffffu;
	uint32_t i;

	vis[q] = 1;
	/*
	 * ---- THE NAME THIS CALL WAS GIVEN ---------
	 *
	 * Artifact rather than relation. The links
	 * already say a lookup happened and that what
	 * came back was indexed; this says WHAT was
	 * looked up, which is the difference between
	 * a tracing module and one reaching for the
	 * syscall table.
	 *
	 * ON THE CALLEE'S NODE, not the one at the
	 * return address. A hook-declaration block is
	 * promoted to a single node sitting at the
	 * function it occupies - see
	 * kgenome_diag_emu_promote_wrappers - and that is the node a
	 * caller means when it calls into it.
	 *
	 * KEPT IN THE ENGINE, READ FROM THE GUEST'S
	 * MEMORY: see kgenome_diag_emu_capture_names. The name used to
	 * be an offset into the file on the node, which
	 * cannot hold a name built or decoded at run
	 * time.
	 */
	/*
	 * THE NODE THIS CALL BECAME, found FIRST: a name
	 * is kept with the node of the call it was read
	 * at, and that is what lets a diagnose own the
	 * names of the sites its tree bound and no
	 * others. It used to be looked up after the
	 * capture, when there was nothing to attach it
	 * to.
	 */
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *p =
			kgenome_diag_scan_at(s, i);

		if (p && p->at == skips[q].resume) {
			node = (uint16_t)i;
			break;
		}
	}
	rel_site_names(R, S, q, rip, node);
	rel_site_args(R, S, node);
	rel_site_result(R, S, q, node);
	return rel_site_tail_jump(R, rip);
}

/*
 * The call site at this address, if there is one: the step is over either
 * way.
 */
enum kgenome_diag_emu_rel_act kgenome_diag_emu_rel_step_sites(struct kgenome_diag_emu_rel_walk *R, struct kgenome_diag_emu_rel_span *S,
				   uint64_t rip)
{
	const struct kgenome_diag_emu_skipsite *skips = R->skips;
	const struct kgenome_diag_emu_skipgather sg = R->sg;
	uint32_t q;

	/* A STEP IS AT ONE ADDRESS, so the sites there are found
	 * by search and not by reading all of them: the scan
	 * of every site per step was 5.1 of the 6.9 billion
	 * instructions on a module with 20000 call sites. */
	q = kgenome_diag_emu_skip_first(skips, sg.n, rip);
	if (q < sg.n && skips[q].call_at == rip) {
		if (rel_site_call(R, S, q, rip))
			return KGENOME_DIAG_EMU_REL_STALL;       /* the function returned */
		return KGENOME_DIAG_EMU_REL_NEXT;
	}
	return KGENOME_DIAG_EMU_REL_ON;
}
