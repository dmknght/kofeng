/*
 * diag_wrapper_summary.c - step 1, SUMMARISE: what a wrapper function is, found by walking its paths, and the table of them.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"

/* ---- kgenome_diag_wrapper_summarise one wrapper ------------------------------------------------- */

int kgenome_diag_wrapper_site_open(const struct kgenome_diag_wrapper_ctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->n_open;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->open[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_open && c->open[lo] == at;
}

/* Is `at` a site the i386 socketcall analysis was left holding - see s->wrap. */
int kgenome_diag_wrapper_site_wrapped(const struct kgenome_diag_scan *s, uint64_t at)
{
	uint32_t i;

	if (s->wrap_sorted) {           /* made by kgenome_diag_wrap_settle: a search, not a scan */
		uint32_t lo = 0, hi = s->n_wrap_sorted;

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (s->wrap_sorted[mid] < at)
				lo = mid + 1u;
			else
				hi = mid;
		}
		return lo < s->n_wrap_sorted && s->wrap_sorted[lo] == at;
	}
	for (i = 0; i < s->n_wrap; i++)
		if (s->wrap[i] == at)
			return 1;
	return 0;
}

/* One path through a wrapper that ended in a syscall or a call to a wrapper,
 * turned into a summary. 1 when it says something about the parameters. */
static int summarise_end(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f, uint64_t entry,
			 const struct kgenome_diag_wrapper_insn *in, struct kgenome_diag_wrapper_summary *callee,
			 struct kgenome_diag_wrapper_summary *out)
{
	static const uint8_t k64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t k32[] = { KGENOME_CELL_REG_BX, KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DI, KGENOME_CELL_REG_BP };
	const uint8_t *kr = c->wide ? k64 : k32;
	int any_param = 0;
	unsigned i;

	memset(out, 0, sizeof *out);
	out->entry = entry;
	out->site = in->at;
	if (!callee) {
		out->nr = f->reg[KGENOME_CELL_REG_AX];
		for (i = 0; i < 6; i++) {
			out->arg[i] = f->reg[kr[i]];
			if (out->arg[i].t != KGENOME_DIAG_WRAPPER_V_CONST && out->arg[i].t != KGENOME_DIAG_WRAPPER_V_PARAM &&
			    out->arg[i].t != KGENOME_DIAG_WRAPPER_V_SET)
				out->arg[i] = kgenome_diag_wrapper_unk;
			if (out->arg[i].t == KGENOME_DIAG_WRAPPER_V_PARAM)
				any_param = 1;
		}
	} else {
		struct kgenome_diag_wrapper_effect e;

		kgenome_diag_wrapper_eval_call(c, f, callee, &e);
		out->nr = e.nr;
		for (i = 0; i < 6; i++) {
			out->arg[i] = e.arg[i];
			if (out->arg[i].t != KGENOME_DIAG_WRAPPER_V_CONST && out->arg[i].t != KGENOME_DIAG_WRAPPER_V_PARAM &&
			    out->arg[i].t != KGENOME_DIAG_WRAPPER_V_SET)
				out->arg[i] = kgenome_diag_wrapper_unk;
			if (out->arg[i].t == KGENOME_DIAG_WRAPPER_V_PARAM)
				any_param = 1;
		}
		out->has_arr = e.has_arr;
		for (i = 0; i < 6 && e.has_arr; i++) {
			out->arr[i] = e.arr[i];
			if (out->arr[i].t != KGENOME_DIAG_WRAPPER_V_CONST && out->arr[i].t != KGENOME_DIAG_WRAPPER_V_PARAM)
				out->arr[i] = kgenome_diag_wrapper_unk;
			if (out->arr[i].t == KGENOME_DIAG_WRAPPER_V_PARAM)
				any_param = 1;
		}
	}
	if (out->nr.t != KGENOME_DIAG_WRAPPER_V_CONST && out->nr.t != KGENOME_DIAG_WRAPPER_V_PARAM)
		return 0;
	if (out->nr.t == KGENOME_DIAG_WRAPPER_V_PARAM)
		any_param = 1;
	/*
	 * A REGISTER PARAMETER (the number or an argument) is believed only where
	 * the sweep itself could not read the number. Held to every function, it
	 * accepted every syscall site that a mis-partitioned fragment reaches with
	 * the registers untouched, and made each call of the fragment a node:
	 * MEASURED on one x86 file, 40 -> 206 write nodes and the connect nodes
	 * gone. A real register-convention helper (musl's __vsyscall) is exactly
	 * the site the sweep reports as opaque.
	 */
	if (!callee && !kgenome_diag_wrapper_site_open(c, in->at)) {
		if (out->nr.t == KGENOME_DIAG_WRAPPER_V_PARAM && out->nr.v >= (int64_t)KGENOME_DIAG_WRAPPER_REG_PARAM)
			return 0;
		/* An argument register nobody set is not a parameter either. */
		any_param = out->nr.t == KGENOME_DIAG_WRAPPER_V_PARAM;
		for (i = 0; i < 6; i++) {
			if (out->arg[i].t == KGENOME_DIAG_WRAPPER_V_PARAM &&
			    out->arg[i].v >= (int64_t)KGENOME_DIAG_WRAPPER_REG_PARAM)
				out->arg[i] = kgenome_diag_wrapper_unk;
			if (out->arg[i].t == KGENOME_DIAG_WRAPPER_V_PARAM)
				any_param = 1;
		}
	}
	return any_param;
}

/*
 * What the function that begins at `entry` is, if it is a wrapper: a path that
 * ends in a kernel entry (a level-0 wrapper, the one that holds the syscall) or
 * in a call to a wrapper already summarised (a wrapper of a wrapper - uClibc's
 * socket() is `build the array; call __socketcall(1, array)`). Both ends are the
 * same question - what does this mean in terms of MY parameters - so both are
 * answered by evaluating the state where the path ends.
 *
 * MORE THAN ONE PATH, because a wrapper branches on what it was asked: uClibc's
 * fcntl takes fcntl64 for the three commands that need it and fcntl for the
 * rest, and both are summarised. The paths here are forward conditional jumps
 * inside the function and nothing else; each gives a variant, and a call is
 * evaluated against every variant - so a call whose command is not known makes
 * the node either path would have made, and the nodes merge when they agree.
 */
/* The span of the function at `entry`: its length to the next call target, never
 * less than KGENOME_DIAG_WRAPPER_SPAN_MIN - see the note there. */
static uint64_t span_of(const struct kgenome_diag_wrapper_ctx *c, uint64_t entry)
{
	uint32_t lo = 0, hi = c->wk->n_tgt;
	uint64_t end, span;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->wk->tgt[mid] <= entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	end = lo < c->wk->n_tgt ? c->wk->tgt[lo] : c->size;
	span = end > entry ? end - entry : 0;
	return span < KGENOME_DIAG_WRAPPER_SPAN_MIN ? KGENOME_DIAG_WRAPPER_SPAN_MIN : span;
}

/* Note a direct target that was not a wrapper. */
static void tseen_note(struct kgenome_diag_wrapper_tseen *t, uint64_t target)
{
	unsigned i;

	for (i = 0; i < t->n; i++)
		if (t->cal[i] == target)
			return;
	if (t->n < KGENOME_DIAG_WRAPPER_SEEN)
		t->cal[t->n++] = target;
	else
		t->more = 1;
}

/* Could a new attempt at this function come out differently now. */
int kgenome_diag_wrapper_tseen_retry(const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_diag_wrapper_tseen *t)
{
	unsigned i;

	if (!t->done || t->more)
		return 1;
	for (i = 0; i < t->n; i++) {
		uint32_t lo = kgenome_diag_wrapper_summary_pos(c, t->cal[i]);

		if (lo < c->n_ws && c->ws[c->wi[lo]].entry == t->cal[i])
			return 1;
	}
	return 0;
}

/* Room for one more queued path: the table doubles on demand, each growth charged
 * to the scan's ledger. 0 when it cannot (the allowance, or memory): the caller
 * treats the arm as not queued, and the status says why. */
static int pend_room(struct kgenome_diag_wrapper_ctx *c, unsigned n_pend)
{
	struct kgenome_diag_wrapper_pending *np;
	uint32_t nc;

	if (n_pend < c->cap_pend)
		return 1;
	nc = c->cap_pend ? c->cap_pend * 2u : KGENOME_DIAG_WRAPPER_PENDING_MIN * 2u;
	if (!kgenome_diag_wrapper_charge(c, (uint64_t)(nc - c->cap_pend) * sizeof *np))
		return 0;
	np = realloc(c->pend, (size_t)nc * sizeof *np);
	if (!np) {
		kgenome_ledger_release(&c->s->led, (uint64_t)(nc - c->cap_pend) * sizeof *np);
		c->charged -= (uint64_t)(nc - c->cap_pend) * sizeof *np;
		kgenome_diag_note(c->s, KGENOME_NOMEM);
		return 0;
	}
	c->pend = np;
	c->cap_pend = nc;
	return 1;
}

/* The summaries of one call, written into the walk's table (valid until the next
 * kgenome_diag_wrapper_summarise): at most `var_max` of them. */
unsigned kgenome_diag_wrapper_summarise(struct kgenome_diag_wrapper_ctx *c, uint64_t entry, struct kgenome_diag_wrapper_tseen *seen, int holds_site)
{
	static const uint8_t p64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_CX, 8u, 9u };
	static const uint8_t pr32[] = { KGENOME_CELL_REG_AX, KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX,
					KGENOME_CELL_REG_BX, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DI,
					KGENOME_CELL_REG_BP };
	struct kgenome_diag_wrapper_pending *pend;
	unsigned n_pend = 0, n_out = 0, i;
	const uint64_t span = span_of(c, entry);
	const uint64_t step_max = 8u * span > KGENOME_DIAG_WRAPPER_STEPS_MIN ? 8u * span : KGENOME_DIAG_WRAPPER_STEPS_MIN;
	/* The per-path bounds, as functions of the span - see KGENOME_DIAG_WRAPPER_BODY_MIN. */
	const unsigned body_max = holds_site && span > KGENOME_DIAG_WRAPPER_BODY_MIN
				? (unsigned)(span > 0xffffffu ? 0xffffffu : span) : KGENOME_DIAG_WRAPPER_BODY_MIN;
	const unsigned pend_max = span / 8u > KGENOME_DIAG_WRAPPER_PENDING_MIN ? (unsigned)(span / 8u > 0xffffffu
								? 0xffffffu : span / 8u)
							    : KGENOME_DIAG_WRAPPER_PENDING_MIN;
	const unsigned var_max = span / 8u < KGENOME_DIAG_WRAPPER_VARIANTS_MIN ? KGENOME_DIAG_WRAPPER_VARIANTS_MIN
			       : span / 8u > KGENOME_DIAG_WRAPPER_VARIANTS_CEIL ? KGENOME_DIAG_WRAPPER_VARIANTS_CEIL
			       : (unsigned)(span / 8u);
	struct kgenome_diag_wrapper_summary *out;
	uint64_t steps = 0;

	c->cut = 0;
	if (c->over_steps)
		return 0;
	if (!c->var) {
		if (!kgenome_diag_wrapper_charge(c, (uint64_t)KGENOME_DIAG_WRAPPER_VARIANTS_CEIL * sizeof *c->var))
			return 0;
		c->var = malloc((size_t)KGENOME_DIAG_WRAPPER_VARIANTS_CEIL * sizeof *c->var);
		if (!c->var) {
			kgenome_ledger_release(&c->s->led,
					       (uint64_t)KGENOME_DIAG_WRAPPER_VARIANTS_CEIL * sizeof *c->var);
			c->charged -= (uint64_t)KGENOME_DIAG_WRAPPER_VARIANTS_CEIL * sizeof *c->var;
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return 0;
		}
	}
	out = c->var;
	if (seen) {
		/* Attempted: a function is walked again only if this record says a
		 * wrapper has appeared among what it met. Re-noted from scratch. */
		seen->n = 0;
		seen->more = 0;
		seen->done = 1;
	}
	if (!pend_room(c, 0))
		return 0;
	pend = c->pend;
	kgenome_diag_wrapper_frame_reset(&pend[0].f);
	if (c->wide) {
		for (i = 0; i < 6; i++) {
			pend[0].f.reg[p64[i]].t = KGENOME_DIAG_WRAPPER_V_PARAM;
			pend[0].f.reg[p64[i]].v = i;
		}
	} else {
		/* cdecl: the return address is at offset 0 and the arguments above it */
		for (i = 0; i < 8; i++) {
			struct kgenome_diag_wrapper_val v = { KGENOME_DIAG_WRAPPER_V_PARAM, 0, (int64_t)i };

			kgenome_diag_wrapper_slot_put(c, &pend[0].f, (int32_t)(4u + 4u * i), v);
		}
		/*
		 * AND THE REGISTERS, because i386 has no register convention that a
		 * libc is obliged to keep: musl's __vsyscall takes the number in eax
		 * and the arguments in edx, ecx and edi, and enters the kernel from a
		 * helper it reaches with a `call` to the middle of itself. A register
		 * parameter is numbered KGENOME_DIAG_WRAPPER_REG_PARAM + register, so a call site can say
		 * which of its own registers it means. MEASURED: 31 of the 400 x86
		 * Bazaar files had no node but one opaque site, all through this helper.
		 */
		for (i = 0; i < sizeof pr32; i++) {
			pend[0].f.reg[pr32[i]].t = KGENOME_DIAG_WRAPPER_V_PARAM;
			pend[0].f.reg[pr32[i]].v = (int64_t)(KGENOME_DIAG_WRAPPER_REG_PARAM + pr32[i]);
		}
	}
	pend[0].at = entry;
	pend[0].n = 0;
	n_pend = 1;
	while (n_pend && n_out < var_max) {
		struct kgenome_diag_wrapper_pending *p;
		struct kgenome_diag_wrapper_isrc it;
		struct kgenome_diag_wrapper_insn in;
		/*
		 * A COPY, not the table's own entry. The entry that was just taken is
		 * the very slot the next forward branch queues its taken path into, so
		 * walking it in place made the queued path inherit what the fall-through
		 * had since done to the state (musl's __vsyscall: the path that enters
		 * the kernel was evaluated with the stack the other path had pushed
		 * onto, and its number came out unknown).
		 */
		struct kgenome_diag_wrapper_frame fcur;
		struct kgenome_diag_wrapper_frame *f = &fcur;
		unsigned n_insn;

		pend = c->pend;         /* it may have grown since the last path */
		p = &pend[--n_pend];
		n_insn = p->n;
		kgenome_diag_wrapper_frame_copy(&fcur, &p->f);
		kgenome_diag_wrapper_isrc_walk(&it, c, p->at);
		for (;;) {
			struct kgenome_diag_wrapper_summary *callee = NULL;
			uint32_t v;
			int ended = 0;

			if (++n_insn > body_max) {
				c->cut = 1;
				break;
			}
			/* THE TOTAL: every instruction of every path of this summary. */
			if (++steps > step_max) {
				c->cut = 1;
				kgenome_diag_note(c->s, KGENOME_TRUNCATED);
				n_pend = 0;     /* and no path is taken up after it */
				break;
			}
			/* AND THE OBJECT'S: the caller's budget for the whole walk. */
			if (c->s->bud.max_steps && ++c->steps > c->s->bud.max_steps) {
				c->over_steps = 1;
				kgenome_diag_note(c->s, KGENOME_OVER_BUDGET);
				n_pend = 0;
				break;
			}
			if (!kgenome_diag_wrapper_isrc_next(&it, &in))
				break;
			/* A direct jump to a function already summarised is a TAIL
			 * CALL: the same question as a call that is followed by ret. */
			if ((in.op == KGENOME_CELL_CALL || in.op == KGENOME_CELL_JMP) &&
			    !(in.flags & KGENOME_CELL_F_INDIRECT) && in.target != KGENOME_BROKEN) {
				callee = kgenome_diag_wrapper_summary_of(c, in.target);
				if (!callee && seen)
					tseen_note(seen, in.target);
			}
			if (kgenome_diag_wrapper_is_kernel_entry(c, &in)) {
				if (summarise_end(c, f, entry, &in, NULL, &out[n_out]))
					n_out++;
				break;
			}
			if (callee) {
				uint32_t base = kgenome_diag_wrapper_summary_pos(c, in.target);

				/* A jump leaves the return address where it was, so on a
				 * stack-passed ABI the callee's arguments are one word
				 * further up than they are for a call. */
				if (in.op == KGENOME_CELL_JMP && !c->wide)
					f->sp -= c->w;

				for (v = base; v < c->n_ws &&
					       kgenome_diag_wrapper_summary_at(c, v)->entry == in.target; v++) {
					if (n_out >= var_max) {
						c->cut = 1;     /* a variant it would have kept */
						break;
					}
					if (summarise_end(c, f, entry, &in, kgenome_diag_wrapper_summary_at(c, v),
							  &out[n_out]))
						n_out++;
				}
				ended = 1;
			}
			if (ended)
				break;
			/*
			 * A CALL TO SOMETHING THAT IS NOT A WRAPPER does not end the walk:
			 * it clobbers the caller-saved registers and leaves the frame as it
			 * was. uClibc's fcntl brackets the real call with
			 * pthread_setcancelstate(1, ..) ... (0, ..), and stopping at the
			 * first of them summarised no fcntl at all - 84 of 86 x86 Bazaar
			 * files that set O_NONBLOCK produced no node for it.
			 */
			if (in.op == KGENOME_CELL_CALL) {
				kgenome_diag_wrapper_frame_call_unknown(c, f);
				continue;
			}
			if (in.op == KGENOME_CELL_JCC && in.target != KGENOME_BROKEN &&
			    in.target > in.at && in.target - entry <= span &&
			    (n_pend >= pend_max || !pend_room(c, n_pend)))
				c->cut = 1;     /* an arm that was not queued, and the path ends */
			if (in.op == KGENOME_CELL_JCC && in.target != KGENOME_BROKEN &&
			    in.target > in.at && in.target - entry <= span &&
			    n_pend < pend_max && n_pend < c->cap_pend) {
				/* the taken path, later; this one carries on */
				pend = c->pend;
				kgenome_diag_wrapper_frame_copy(&pend[n_pend].f, f);
				pend[n_pend].at = in.target;
				pend[n_pend].n = n_insn;
				n_pend++;
				continue;
			}
			if (in.op == KGENOME_CELL_JMP && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
			    in.target != KGENOME_BROKEN && in.target > in.at &&
			    in.target - entry <= span) {
				kgenome_diag_wrapper_isrc_seek(&it, in.target);
				continue;
			}
			/* a call to something else, a return, a jump out: not this path */
			if (in.op == KGENOME_CELL_CALL || in.op == KGENOME_CELL_JMP || in.op == KGENOME_CELL_JCC ||
			    in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_LOOP)
				break;
			kgenome_diag_wrapper_frame_step(c, f, &in);
		}
	}
	/* The variants were full with paths still queued: arms never visited. */
	if (n_pend && n_out >= var_max)
		c->cut = 1;
	return n_out;
}

/* Keeps the table in entry order as it grows, so the lookup below is valid at
 * every moment - the level search consults it while it is being extended. The
 * summary goes to the end of the pool and its index into the sorted run, at the
 * first place whose entry is not below it: the same place, and so the same order
 * for the variants of one entry, as when the records themselves were moved. */
int kgenome_diag_wrapper_summary_insert(struct kgenome_diag_wrapper_ctx *c, const struct kgenome_diag_wrapper_summary *t)
{
	uint32_t lo;

	if (c->n_ws == c->cap_ws) {
		uint32_t nc = c->cap_ws ? c->cap_ws * 2u : 32u;
		struct kgenome_diag_wrapper_summary *nw;
		uint32_t *ni;

		if (!kgenome_diag_wrapper_charge(c, (uint64_t)(nc - c->cap_ws) *
				(sizeof *nw + sizeof *ni)))
			return 0;
		nw = realloc(c->ws, (size_t)nc * sizeof *nw);
		if (!nw) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return 0;
		}
		c->ws = nw;
		ni = realloc(c->wi, (size_t)nc * sizeof *ni);
		if (!ni) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return 0;
		}
		c->wi = ni;
		c->cap_ws = nc;
	}
	lo = kgenome_diag_wrapper_summary_pos(c, t->entry);
	memmove(&c->wi[lo + 1u], &c->wi[lo], (size_t)(c->n_ws - lo) * sizeof *c->wi);
	c->ws[c->n_ws] = *t;
	c->wi[lo] = c->n_ws;
	c->n_ws++;
	return 1;
}

uint32_t kgenome_diag_wrapper_summary_pos(const struct kgenome_diag_wrapper_ctx *c, uint64_t entry)
{
	uint32_t lo = 0, hi = c->n_ws;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->ws[c->wi[mid]].entry < entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo;
}

struct kgenome_diag_wrapper_summary *kgenome_diag_wrapper_summary_at(struct kgenome_diag_wrapper_ctx *c, uint32_t pos)
{
	return &c->ws[c->wi[pos]];
}

struct kgenome_diag_wrapper_summary *kgenome_diag_wrapper_summary_of(struct kgenome_diag_wrapper_ctx *c, uint64_t entry)
{
	uint32_t lo = kgenome_diag_wrapper_summary_pos(c, entry);

	return lo < c->n_ws && c->ws[c->wi[lo]].entry == entry ? &c->ws[c->wi[lo]] : NULL;
}

/* The nearest call target at or before `site`: the function the site is in. No
 * distance limit - the span a summary may cover is the function's own length
 * (span_of), and a site a long way past its entry simply is not reached by
 * the bounded walk, which is reported if it leaves the site unexplained. */
int kgenome_diag_wrapper_entry_of(const struct kgenome_diag_wrapper_ctx *c, uint64_t site, uint64_t *entry)
{
	uint32_t lo = 0, hi = c->wk->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->wk->tgt[mid] <= site)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo)
		return 0;
	*entry = c->wk->tgt[lo - 1u];
	return 1;
}

/* ---- the node a call to a wrapper makes ----------------------------------- */
