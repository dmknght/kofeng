/*
 * diag_wrapper_summary.c - step 1, SUMMARISE: what a wrapper function is, found by walking its paths, and the table of them.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"
#include "frame.h"

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
/* CONSOLIDATION FUNC-8 (2026-10-30, R): DROP -> kgenome_diag_funcs_with_walk (read the extent from the one set). It re-derives a function end as "next
 * call target" with a floor SPAN_MIN: the same rule as the entry walk's extent. Better logic here that the keeper lacks: the floor SPAN_MIN keeps a one-
 * instruction stub from getting a zero span (Inference). Prove with: a thunk-only function in tests/lib/genome diag_wrapper rows; compare the span with
 * the set. */
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

/*
 * ---- ONE JOB: DOES A FUNCTION ENTER A KERNEL ----------------------------------------------------------
 *
 * A function whose straight line ends in a call of a wrapper is a wrapper of that call only if the call is its whole job (diag_wrapper.c):
 * the functions it calls on the way there, and on the way from the call to its return, enter no kernel. A callee is asked through the
 * object's products, not read here: it is a FUNCTION of the table (kgenome_funcs_start, trust not NONE), and its FRAME (frame.h: the graph,
 * the reachable blocks, their calls and system calls, the facts of their instructions) has no reachable system call, no reachable block that
 * leaves the function (a tail jump, a branch through a register), no indirect call, and every direct call it makes is to a function that is
 * quiet itself or never comes back (kgenome_frame_returns: a path that calls __stack_chk_fail or abort ends there). The answer does not depend on the wrapper table, so a level that adds a wrapper never changes it (the levels stay a
 * fixpoint). Memoised per function of the table. A callee that is no function of the table (code no metadata or descent partitioned), a frame
 * that could not be made, a chain deeper than KGENOME_DIAG_WRAPPER_QUIET_DEPTH, or a function met again while it is being read (recursion) is
 * not shown quiet - the safe answer, which costs a wrapper and never makes a false one.
 *
 * WHY (LE-D3, 2026-11-17, M: tests/lib/genome/lineage_sites.c t_truth_wrapper_job): the summary stopped at the first call of a wrapper, and
 * the socket wrapper's summary maps r8 and r9 - which it never sets - to the kernel's arguments 4 and 5, so a function that called it with
 * constants and did more afterwards had "parameters" (its own untouched r8 and r9) and was a wrapper: lin_truth found 830 net-open nodes at
 * calls of user functions in main (144 static builds), and the socket call inside them had none. musl's cancellable wrappers call
 * __syscall_ret after the call (errno, no kernel): that is quiet, and they stay wrappers.
 */
#define KGENOME_DIAG_WRAPPER_QUIET_DEPTH 6u

/* What a callee is to ONE JOB: it comes back and enters no kernel (QUIET), it never comes back (NORET: a path that calls it ends there - the
 * stack protector's __stack_chk_fail, abort; what it does on the way out is not the caller's job), or neither shown (BUSY). */
enum { WQ_UNASKED = 0, WQ_QUIET, WQ_NORET, WQ_BUSY, WQ_READING };

static int quiet_fn(struct kgenome_diag_wrapper_ctx *c, uint64_t fn, unsigned depth);

/* The direct calls of the reachable blocks of a frame: each to a function that is quiet or never comes back. The instruction of a call is read
 * again through the walk's reader at its block (the frame keeps the graph, not the instructions). */
static int quiet_calls(struct kgenome_diag_wrapper_ctx *c, const struct kgenome_frame *fr, unsigned depth)
{
	uint32_t b, k;

	for (b = 0; b < fr->cfg.n_all; b++) {
		const struct kgenome_cfg_block *bl = &fr->cfg.b[b];
		struct kgenome_diag_wrapper_isrc it;
		struct kgenome_diag_wrapper_insn in;
		uint32_t at = 0;

		if (!bl->reach || !bl->n_call)
			continue;
		kgenome_diag_wrapper_isrc_walk(&it, c, fr->off + bl->at);
		for (k = bl->call_first; k < bl->call_first + bl->n_call; k++) {
			const struct kgenome_cfg_call *cl = &fr->cfg.call[k];

			if (cl->kind == KGENOME_CFG_CK_INDIRECT || cl->kind == KGENOME_CFG_CK_SYSCALL || cl->insn < bl->first)
				return WQ_BUSY;
			for (; at <= cl->insn - bl->first; at++)
				if (!kgenome_diag_wrapper_isrc_next(&it, &in))
					return WQ_BUSY;
			if (in.op != KGENOME_CELL_CALL || (in.flags & KGENOME_CELL_F_INDIRECT) || in.target == KGENOME_BROKEN)
				return WQ_BUSY;
			if (in.target == in.at + in.len || in.target == fr->off)
				continue;       /* the get-pc idiom; a call of itself */
			if (quiet_fn(c, in.target, depth + 1u) == WQ_BUSY)
				return WQ_BUSY;
		}
	}
	return WQ_QUIET;
}

static int quiet_frame(struct kgenome_diag_wrapper_ctx *c, const struct kgenome_func_set *fs, uint32_t fi, unsigned depth)
{
	const struct kgenome_frame_src src = { .obj = c->obj, .base = c->base, .size = c->size, .fs = fs, .wk = c->wk };
	const struct kgenome_frame *fr = kgenome_frame_get(kgenome_diag_frames(c->s), &src, fi);
	const int back = kgenome_frame_returns(fr, &src);
	uint32_t b;

	if (back < 0)
		return WQ_BUSY;
	if (!back)
		return WQ_NORET;
	if (fr->cfg.n_sys)
		return WQ_BUSY;
	for (b = 0; b < fr->cfg.n_all; b++)
		if (fr->cfg.b[b].reach && (fr->bits[b] & KGENOME_FRAME_B_LEAVES))
			return WQ_BUSY;
	return quiet_calls(c, fr, depth);
}

/* WQ_QUIET, WQ_NORET or WQ_BUSY for the function that starts at `fn`. */
static int quiet_fn(struct kgenome_diag_wrapper_ctx *c, uint64_t fn, unsigned depth)
{
	const struct kgenome_func_set *fs = kgenome_diag_funcs(c->s, c->obj);
	const uint32_t fi = kgenome_funcs_start(fs, fn);
	int q;

	if (fi == KGENOME_FUNCS_NONE || fs->v[fi].trust == KGENOME_FN_TRUST_NONE || depth > KGENOME_DIAG_WRAPPER_QUIET_DEPTH)
		return WQ_BUSY;
	if (!c->quiet) {
		if (!kgenome_diag_wrapper_charge(c, fs->n))
			return WQ_BUSY;
		c->quiet = calloc(fs->n, 1);
		if (!c->quiet) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return WQ_BUSY;
		}
	}
	if (c->quiet[fi] == WQ_READING)
		return WQ_BUSY;
	if (c->quiet[fi] != WQ_UNASKED)
		return c->quiet[fi];
	c->quiet[fi] = WQ_READING;
	q = quiet_frame(c, fs, fi, depth);
	c->quiet[fi] = (uint8_t)q;
	return q;
}

/* The calls a path made before it met the wrapper (the summary's pending record keeps them): every one to a function that comes back and enters
 * no kernel (a path through one that never comes back does not reach the wrapper). */
static int quiet_before(struct kgenome_diag_wrapper_ctx *c, const uint64_t *pre, unsigned n_pre, int more)
{
	unsigned i;

	if (more)
		return 0;
	for (i = 0; i < n_pre; i++)
		if (quiet_fn(c, pre[i], 0) != WQ_QUIET)
			return 0;
	return 1;
}

/*
 * From just after the call of a wrapper to the function's return: does every path enter no kernel and call nothing that does. The paths are
 * this one and the forward branches inside the span (as the summary's own), at most `room` of them queued; a jump out of the span is a tail
 * call, quiet when its target is; a path that runs out of the span or of the body bound has not reached the return, and the answer is no.
 */
static int rest_quiet(struct kgenome_diag_wrapper_ctx *c, uint64_t entry, uint64_t span, uint64_t from, unsigned body_max)
{
	uint64_t todo[KGENOME_DIAG_WRAPPER_PENDING_MIN];
	unsigned n_todo = 1, n_insn = 0;

	todo[0] = from;
	while (n_todo) {
		struct kgenome_diag_wrapper_isrc it;
		struct kgenome_diag_wrapper_insn in;
		int ended = 0;

		kgenome_diag_wrapper_isrc_walk(&it, c, todo[--n_todo]);
		while (!ended) {
			if (++n_insn > body_max || !kgenome_diag_wrapper_isrc_next(&it, &in) || in.at < entry || in.at - entry >= span)
				return 0;
			if (kgenome_diag_wrapper_is_kernel_entry(c, &in))
				return 0;
			switch (in.op) {
			case KGENOME_CELL_RET:
				ended = 1;
				break;
			case KGENOME_CELL_CALL:
				if ((in.flags & KGENOME_CELL_F_INDIRECT) || in.target == KGENOME_BROKEN)
					return 0;
				if (in.target != in.at + in.len) {
					const int q = quiet_fn(c, in.target, 0);

					if (q == WQ_BUSY)
						return 0;
					ended = q == WQ_NORET;  /* the path stops in it: what it does on the way out is no part of the job */
				}
				break;
			case KGENOME_CELL_JMP:
				if (in.flags & KGENOME_CELL_F_INDIRECT)
					return 0;
				if (in.target != KGENOME_BROKEN && in.target > in.at && in.target - entry < span) {
					kgenome_diag_wrapper_isrc_seek(&it, in.target);
					break;
				}
				if (in.target == KGENOME_BROKEN || quiet_fn(c, in.target, 0) == WQ_BUSY)
					return 0;
				ended = 1;              /* a tail call: its return is this function's */
				break;
			case KGENOME_CELL_JCC:
			case KGENOME_CELL_LOOP:
				if (in.target != KGENOME_BROKEN && in.target > in.at && in.target - entry < span) {
					if (n_todo == KGENOME_DIAG_WRAPPER_PENDING_MIN)
						return 0;       /* more arms than are held: not shown quiet */
					todo[n_todo++] = in.target;
				}
				break;
			default:
				break;
			}
		}
	}
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
		/*
		 * AND THE STACK: the seventh parameter on is above the return address. glibc's cancellable system calls pass the NUMBER there
		 * (__syscall_cancel(a1..a6, nr), __internal_syscall_cancel reads it at [rsp+8] of its entry), and the six arguments and the number
		 * are what a system call has. Without it the number was unknown at every level, no call of read/write/open/connect/send of a static
		 * glibc had a node, and the one `syscall` they share stood for all of them (LE-D4). Parameters 6 and 7: glibc's
		 * __syscall_cancel_arch, the deepest of them, takes the cancel word, the number and six arguments - two words above the registers (R).
		 */
		for (i = 0; i < KGENOME_DIAG_WRAPPER_STACK_PARAMS; i++) {
			struct kgenome_diag_wrapper_val v = { KGENOME_DIAG_WRAPPER_V_PARAM, 0, (int64_t)(6u + i) };

			kgenome_diag_wrapper_slot_put(c, &pend[0].f, (int32_t)(8u + 8u * i), v);
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
	pend[0].n_pre = 0;
	pend[0].pre_more = 0;
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
		uint64_t pre[KGENOME_DIAG_WRAPPER_PRE];
		uint8_t n_pre, pre_more;

		pend = c->pend;         /* it may have grown since the last path */
		p = &pend[--n_pend];
		n_insn = p->n;
		n_pre = p->n_pre;
		pre_more = p->pre_more;
		memcpy(pre, p->pre, sizeof pre);
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
			/*
			 * ONE JOB (see rest_quiet): a call of a wrapper is the function's job only when nothing it called before it on this path, and
			 * nothing from it to the return, enters a kernel. A jump to a wrapper is the end of the function by itself.
			 */
			if (callee && (!quiet_before(c, pre, n_pre, pre_more) ||
				       (in.op == KGENOME_CELL_CALL && !rest_quiet(c, entry, span, in.at + in.len, body_max))))
				break;
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
				/* (asked only if the path ends in a call of a wrapper: quiet_before) */
				if ((in.flags & KGENOME_CELL_F_INDIRECT) || in.target == KGENOME_BROKEN || n_pre == KGENOME_DIAG_WRAPPER_PRE)
					pre_more = 1;
				else if (in.target != in.at + in.len)
					pre[n_pre++] = in.target;
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
				pend[n_pend].n_pre = n_pre;
				pend[n_pend].pre_more = pre_more;
				memcpy(pend[n_pend].pre, pre, sizeof pre);
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
