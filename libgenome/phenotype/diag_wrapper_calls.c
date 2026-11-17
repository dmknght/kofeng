/*
 * diag_wrapper_calls.c - step 2, WALK THE CALLERS: what a call to a wrapper means at its call site, and the node it makes.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"

/* The i-th integer parameter of a call, as the caller holds it. */
static struct kgenome_diag_wrapper_val kgenome_diag_wrapper_call_param(const struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f, unsigned i)
{
	static const uint8_t p64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_CX, 8u, 9u };

	if (i >= KGENOME_DIAG_WRAPPER_REG_PARAM)
		return i - KGENOME_DIAG_WRAPPER_REG_PARAM < 16u ? f->reg[i - KGENOME_DIAG_WRAPPER_REG_PARAM] : kgenome_diag_wrapper_unk;
	if (c->wide)                    /* the seventh on are on the stack, the first of them at the top (the return address is not pushed yet) */
		return i < 6u ? f->reg[p64[i]] : kgenome_diag_wrapper_slot_get(f, -f->sp + (int32_t)(8u * (i - 6u)));
	/* cdecl: the last value pushed is the first argument. At the call the
	 * stack pointer has not yet taken the return address, so argument i is
	 * i words above the top. */
	return kgenome_diag_wrapper_slot_get(f, -f->sp + (int32_t)(4u * i));
}

/* The value of the j-th argument of a socketcall, read from the array the
 * caller built on its stack. */
static struct kgenome_diag_wrapper_val sockcall_arg(const struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f,
			      struct kgenome_diag_wrapper_val ptr, unsigned j)
{
	(void)c;
	if (ptr.t != KGENOME_DIAG_WRAPPER_V_SADDR)
		return kgenome_diag_wrapper_unk;
	return kgenome_diag_wrapper_slot_get(f, (int32_t)(ptr.v + 4 * (int64_t)j));
}

/* The wrapper's summary evaluated against the caller's state. */
void kgenome_diag_wrapper_eval_call(const struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f,
		      const struct kgenome_diag_wrapper_summary *ws, struct kgenome_diag_wrapper_effect *e)
{
	unsigned i;

	e->nr = ws->nr.t == KGENOME_DIAG_WRAPPER_V_PARAM ? kgenome_diag_wrapper_call_param(c, f, (unsigned)ws->nr.v) : ws->nr;
	for (i = 0; i < 6u; i++) {
		struct kgenome_diag_wrapper_val v = ws->arg[i];

		e->arg[i] = v.t == KGENOME_DIAG_WRAPPER_V_PARAM ? kgenome_diag_wrapper_call_param(c, f, (unsigned)v.v) : v;
	}
	e->has_arr = 0;
	if (ws->has_arr) {
		e->has_arr = 1;
		for (i = 0; i < 6u; i++) {
			struct kgenome_diag_wrapper_val v = ws->arr[i];

			e->arr[i] = v.t == KGENOME_DIAG_WRAPPER_V_PARAM ? kgenome_diag_wrapper_call_param(c, f, (unsigned)v.v) : v;
		}
	} else if (!c->wide && e->nr.t == KGENOME_DIAG_WRAPPER_V_CONST && e->nr.v == 102 &&
		   e->arg[1].t == KGENOME_DIAG_WRAPPER_V_SADDR) {
		e->has_arr = 1;
		for (i = 0; i < 6u; i++)
			e->arr[i] = sockcall_arg(c, f, e->arg[1], i);
	}
}

/*
 * The node a call to a wrapper makes, and what the call hands back. `in_fn` says the call is in a FUNCTION of the object's table (see
 * kgenome_diag_wrapper_pass_b): only there are the caller's values carried, so only there does the node get inputs and the call a result.
 */
static struct kgenome_diag_wrapper_val emit_call_node(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f, struct kgenome_diag_wrapper_summary *ws,
				const struct kgenome_diag_wrapper_insn *in, int in_fn)
{
	struct kgenome_diag_scan *s = c->s;
	struct kgenome_diag_wrapper_effect e;
	uint64_t arg[6], nr, sock_arr[6] = { 0 };
	struct kgenome_diag_wrapper_val av[6];
	unsigned have = 0, i;
	int bits = c->wide ? 64 : 32;
	uint16_t cap;
	uint8_t fl = 0;
	const char *nm = NULL;
	struct kgenome_diag_hit *h;

	kgenome_diag_wrapper_eval_call(c, f, ws, &e);
	if (e.nr.t != KGENOME_DIAG_WRAPPER_V_CONST)
		return kgenome_diag_wrapper_unk;                     /* which system call is not known: no node (UNKNOWN, never a guess - see supersede_param_sites) */
	nr = (uint64_t)e.nr.v;
	for (i = 0; i < 6u; i++) {
		av[i] = e.arg[i];
		if (av[i].t == KGENOME_DIAG_WRAPPER_V_CONST ||
		    (av[i].t == KGENOME_DIAG_WRAPPER_V_SET &&
		     kgenome_nucleo_arg_is_flags((unsigned)bits, (uint32_t)nr, i))) {
			arg[i] = (uint64_t)av[i].v;
			have |= 1u << i;
		} else {
			arg[i] = 0;
		}
	}
	/*
	 * i386's socketcall: the sub-call is argument 0 and the operation's own
	 * arguments are the array. What cap that is, and how its arguments map onto
	 * the roles, is the operation's - so the array replaces the register view.
	 */
	if (bits == 32 && nr == 102u) {
		unsigned jhave = 0, j;

		if (!(have & 1u))
			return kgenome_diag_wrapper_unk;             /* which operation is not known */
		for (j = 0; j < 6u; j++) {
			struct kgenome_diag_wrapper_val v = e.has_arr ? e.arr[j] : kgenome_diag_wrapper_unk;

			av[j] = v;
			if (v.t == KGENOME_DIAG_WRAPPER_V_CONST) {
				sock_arr[j] = (uint64_t)v.v;
				jhave |= 1u << j;
			} else {
				sock_arr[j] = 0;
			}
		}
		cap = kgenome_nucleo_cap_of_sockcall((uint32_t)arg[0], sock_arr, jhave, &fl);
		have = jhave;
	} else {
		cap = kgenome_nucleo_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
		nm = kgenome_nucleo_sys_name((unsigned)bits, (uint32_t)nr);
	}
	if (cap == KGENOME_NUCLEO_NONE)
		return kgenome_diag_wrapper_unk;
	h = kgenome_diag_hit_add(s, in->at, cap, fl);
	if (!h)
		return kgenome_diag_wrapper_unk;
	if ((cap == KGENOME_NUCLEO_ALLOC && !(have & (1u << 2))) ||
	    (cap == KGENOME_NUCLEO_NET_OPEN && (have & 3u) != 3u))
		h->bits |= KGENOME_DIAG_H_ARG_UNKNOWN;
	/*
	 * THE INPUTS ARE MAY. This walk reads the function in address order and takes no branch (diag_wrapper.c), so what it carries to the
	 * call is what the code laid out last before it left there: one path, not every path. Whether every path reaching the call gives this
	 * one producer is the lineage stage's question (FLOW joins the paths over the function's graph, diag_lineage.c), and a link it proves
	 * on every path it says PROVEN over this MAY (kgenome_diag_note_in_seen). (LE-D2: they were written PROVEN, and a value made on two
	 * arms was linked PROVEN from the arm laid out last: tests/lib/genome/lineage_sites.c t_truth_two_arms.)
	 */
	for (i = 0; i < 6u && in_fn; i++) {
		uint8_t role = kgenome_diag_role_of_arg(cap, i);

		if (role != KGENOME_DIAG_ROLE_NONE && av[i].t == KGENOME_DIAG_WRAPPER_V_NODE)
			(void)kgenome_diag_note_in_how(c->s, h, av[i].node, role,
						       KGENOME_DIAG_KIND_PRODUCED, KGENOME_DIAG_LINK_MAY);
	}
	if (bits == 64 && nm && kgenome_nucleo_sys_zero_on_success(nm))
		h->bits |= KGENOME_DIAG_H_ZERO_OK;
	ws->node_made = 1;
	if (kgenome_nucleo_hands_on(cap, nm)) {
		struct kgenome_diag_wrapper_val r = { KGENOME_DIAG_WRAPPER_V_NODE, (uint16_t)(s->n_hit - 1u), 0 };

		if (cap == KGENOME_NUCLEO_NET_OPEN || cap == KGENOME_NUCLEO_NET_RAW) {
			int nb = bits == 32 && nr == 102u
				 ? kgenome_nucleo_sockcall_nonblock((uint32_t)arg[0], sock_arr, have)
				 : kgenome_nucleo_sock_nonblock((unsigned)bits, (uint32_t)nr, arg, have);

			if (nb)
				kgenome_diag_hit_nonblock(s, in->at, r.node);
		}
		return in_fn ? r : kgenome_diag_wrapper_unk;
	}
	return kgenome_diag_wrapper_unk;
}

/* ---- pass B: the functions, in address order ------------------------------ */

static int has_u64(const uint64_t *v, uint32_t n, uint64_t x)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (v[mid] < x)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < n && v[lo] == x;
}

/* Whether the node at `at` is one a function hands back to its callers, read
 * from the table - the question the sorted set below answers in one lookup. */
static int fret_site(const struct kgenome_diag_wrapper_ctx *c, uint64_t at)
{
	uint32_t i;

	if (!c->fret)
		return 0;
	for (i = 0; i < c->wk->n_tgt; i++)
		if (c->fret[i] && c->fret[i] - 1u < c->s->n_hit &&
		    c->s->hit[c->fret[i] - 1u].at == at)
			return 1;
	return 0;
}

/* The sites some caller made a node for, sorted. The table is not read again
 * once pass B has ended, so the set is made once, at the first question. */
static void made_build(struct kgenome_diag_wrapper_ctx *c)
{
	uint32_t i;

	c->made_state = 2;
	if (c->n_ws) {
		if (!kgenome_diag_wrapper_charge(c, (uint64_t)c->n_ws * sizeof *c->made))
			return;
		c->made = malloc((size_t)c->n_ws * sizeof *c->made);
		if (!c->made)
			return;
	}
	for (i = 0; i < c->n_ws; i++)
		if (c->ws[i].node_made)
			c->made[c->n_made++] = c->ws[i].site;
	if (c->n_made)
		qsort(c->made, c->n_made, sizeof *c->made, kof_cmp_u64);
	c->made_state = 1;
}

/* Whether a summary at `site` has a node a caller made. */
int kgenome_diag_wrapper_site_made(struct kgenome_diag_wrapper_ctx *c, uint64_t site)
{
	uint32_t i;

	if (!c->made_state)
		made_build(c);
	if (c->made_state == 1)
		return has_u64(c->made, c->n_made, site);
	for (i = 0; i < c->n_ws; i++)
		if (c->ws[i].site == site && c->ws[i].node_made)
			return 1;
	return 0;
}

/* A wrapper some caller made a node for is answered at its callers; the node
 * the sweep made at the syscall inside it spoke for every caller at once and
 * for none of them, and is set aside - unless a helper hands that node back,
 * which is then the one callers use. One pass over the nodes against the sorted
 * set of such sites; it used to be a pass over the nodes, and one over the call
 * targets, for each wrapper. */
/*
 * A KERNEL ENTRY WHOSE NUMBER ITS CALLERS GIVE (a wrapper summarised with the number a parameter, and no path of it with a number of its own:
 * glibc's __internal_syscall_cancel, which every cancellable call of the program goes through) is no one system call: what each call of the
 * program is was decided at the call, from the caller's number, and a call whose number is not known is unknown there. A node any route makes
 * at the entry speaks for all of them at once (LE-D4: the sweep's mem-read and file-open nodes at glibc's shared `syscall`, the file-open taking
 * an fd from itself; the emulate route's node of the one call its run arrived with), and is set aside once every route has answered
 * (kgenome_diag_wrapper_param_settle); an opaque node (no capability) stays, saying the number is not known. Recorded here from the wrapper
 * table, by the summaries' own sites.
 */
static void supersede_param_sites(struct kgenome_diag_wrapper_ctx *c)
{
	struct kgenome_diag_scan *s = c->s;
	uint32_t i, k;

	for (i = 0; i < c->n_ws; i++) {
		const struct kgenome_diag_wrapper_summary *w = &c->ws[i];
		struct kgenome_diag_wrapper_isrc it;
		struct kgenome_diag_wrapper_insn in;
		int own = 0;

		if (w->flow != KGENOME_DIAG_WRAPPER_FLOW_NONE || w->nr.t != KGENOME_DIAG_WRAPPER_V_PARAM)
			continue;
		for (k = 0; k < c->n_ws && !own; k++)
			own = c->ws[k].site == w->site && c->ws[k].nr.t == KGENOME_DIAG_WRAPPER_V_CONST;
		if (own)
			continue;
		kgenome_diag_wrapper_isrc_walk(&it, c, w->site);
		if (!kgenome_diag_wrapper_isrc_next(&it, &in) || in.at != w->site || !kgenome_diag_wrapper_is_kernel_entry(c, &in))
			continue;               /* a call of an inner wrapper: its node, if any, is a caller's statement */
		if (!kgenome_diag_wrapper_push_u64(&s->param_site, &s->n_param_site, &s->cap_param_site, w->site)) {
			kgenome_diag_note(s, KGENOME_NOMEM);
			return;
		}
	}
}

void kgenome_diag_wrapper_param_settle(struct kgenome_diag_scan *s)
{
	uint32_t i, j;

	if (!s->n_param_site)
		return;
	qsort(s->param_site, s->n_param_site, sizeof *s->param_site, kof_cmp_u64);
	for (j = 0; j < s->n_hit; j++)
		if (s->hit[j].cap != KGENOME_NUCLEO_NONE && s->hit[j].at != KGENOME_BROKEN) {
			i = kof_lower_bound_u64(s->param_site, s->n_param_site, sizeof *s->param_site, 0, s->hit[j].at);
			if (i < s->n_param_site && s->param_site[i] == s->hit[j].at)
				s->hit[j].bits |= KGENOME_DIAG_H_SUPERSEDED;
		}
}

void kgenome_diag_wrapper_supersede(struct kgenome_diag_wrapper_ctx *c)
{
	struct kgenome_diag_scan *s = c->s;
	uint64_t *back = NULL, *set = NULL;
	uint32_t n_back = 0, n_set = 0, i, j;

	supersede_param_sites(c);
	if (c->made_state == 0)
		made_build(c);
	if (!c->n_made && c->made_state == 1)
		return;
	if (c->made_state == 1 && kgenome_diag_wrapper_charge(c, (uint64_t)(c->n_made +
			(c->fret ? c->wk->n_tgt : 0)) * sizeof *set)) {
		set = malloc((size_t)c->n_made * sizeof *set);
		back = malloc((size_t)(c->wk->n_tgt ? c->wk->n_tgt : 1u) * sizeof *back);
	}
	if (set && back) {
		/* the nodes a function hands back, by site */
		for (i = 0; c->fret && i < c->wk->n_tgt; i++)
			if (c->fret[i] && c->fret[i] - 1u < s->n_hit)
				back[n_back++] = s->hit[c->fret[i] - 1u].at;
		if (n_back)
			qsort(back, n_back, sizeof *back, kof_cmp_u64);
		for (i = 0; i < c->n_made; i++)         /* `made` is sorted, so is `set` */
			if (!has_u64(back, n_back, c->made[i]))
				set[n_set++] = c->made[i];
		for (j = 0; j < s->n_hit; j++)
			if (has_u64(set, n_set, s->hit[j].at))
				s->hit[j].bits |= KGENOME_DIAG_H_SUPERSEDED;
		free(set);
		free(back);
		return;
	}
	free(set);
	free(back);
	for (i = 0; i < c->n_ws; i++) {
		if (!c->ws[i].node_made || fret_site(c, c->ws[i].site))
			continue;
		for (j = 0; j < s->n_hit; j++)
			if (s->hit[j].at == c->ws[i].site)
				s->hit[j].bits |= KGENOME_DIAG_H_SUPERSEDED;
	}
}

/* The index of a call target, or -1. */
int kgenome_diag_wrapper_tgt_index(const struct kgenome_diag_wrapper_ctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->wk->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->wk->tgt[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->wk->n_tgt && c->wk->tgt[lo] == at ? (int)lo : -1;
}

/*
 * THE PIECE OF THE FUNCTION TABLE AN INSTRUCTION IS IN: the function that holds it (kgenome_funcs_at, the one lookup in the table), the
 * part of that function it is in, and where the piece ends - at the end of that part, or where the next entry or part of the table begins,
 * whichever is first. Code no entry holds (padding between bodies) is a piece of its own, up to the next start. Asked when the walk enters
 * a piece, so a function costs one lookup and not one per instruction. `in_fn` is a function the table vouches for: a unit of trust NONE is
 * code no metadata or descent partitioned (fntab_build.c) and is not one.
 */
struct wrapper_piece {
	uint64_t hi;            /* the first offset past the piece */
	int in_fn;
	int cur;                /* the call target the function starts at (its index in the walk's targets), or -1 */
};

static void piece_of(const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_func_set *fs, uint64_t at,
		     struct wrapper_piece *p)
{
	const uint32_t f = kgenome_funcs_at(fs, at);
	uint64_t hi = UINT64_MAX;
	uint32_t i, k, nr;

	p->in_fn = 0;
	p->cur = -1;
	if (fs && fs->n) {
		i = kof_lower_bound_u64(fs->v, fs->n, sizeof *fs->v, offsetof(struct kgenome_func, off), at + 1u);
		if (i < fs->n)
			hi = fs->v[i].off;
	}
	if (fs && fs->n_rng) {
		i = kof_lower_bound_u64(fs->rng, fs->n_rng, sizeof *fs->rng, offsetof(struct kgenome_func_range, off), at + 1u);
		if (i < fs->n_rng && fs->rng[i].off < hi)
			hi = fs->rng[i].off;
	}
	if (f != KGENOME_FUNCS_NONE) {
		nr = kgenome_funcs_n_ranges(fs, f);
		for (k = 0; k < nr; k++) {
			const struct kgenome_func_range r = kgenome_funcs_range(fs, f, k);

			if (r.off <= at && at - r.off < r.len) {
				if (r.off + r.len < hi)
					hi = r.off + r.len;
				break;
			}
		}
		p->in_fn = fs->v[f].trust != KGENOME_FN_TRUST_NONE;
		if (p->in_fn)
			p->cur = kgenome_diag_wrapper_tgt_index(c, fs->v[f].off);
	}
	p->hi = hi > at ? hi : at + 1u;
}

/*
 * PASS B: every call of a wrapper in the extent, in address order, with the caller's state carried from one instruction to the next.
 *
 * THE STATE IS ONE FUNCTION'S, AND THE FUNCTIONS ARE THE OBJECT'S TABLE (kgenome_diag_funcs: one partition, built once, read by everyone).
 * The registers and slots are reset where the walk enters a piece of the table - an entry, a further part of a function, code between bodies -
 * so nothing the code laid out before a function left in a register reaches it. (LE-D1: they were reset at direct-CALL targets only, a partition
 * of the walk's own, and a function entered by a tail jump inherited the registers of the function before it - a FALSE PROVEN link from an open
 * the write never sees: tests/lib/genome/lineage_sites.c t_truth_tail_jump_carry, lin_truth gcc -O2 -m32 -static.)
 *
 * A UNIT OF TRUST NONE IS NOT A FUNCTION: its calls of wrappers are nodes, but no value is carried between them there (no input, no result) -
 * the same rule the lineage stage keeps (kgenome_lineage_fn_get). TODO(owner): default applied 2026-11-17 = no links in a NONE unit; the
 * alternative is resetting at the walk's call targets inside it (the old rule, a second partition, with LE-D1's false links back there).
 */
void kgenome_diag_wrapper_pass_b(struct kgenome_diag_wrapper_ctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	const struct kgenome_func_set *fs = kgenome_diag_funcs(c->s, c->obj);
	struct kgenome_diag_wrapper_isrc it;
	struct kgenome_diag_wrapper_insn in;
	struct kgenome_diag_wrapper_frame f;
	struct wrapper_piece pc;

	pc.hi = 0;                      /* (no piece yet: the first instruction asks) */
	pc.in_fn = 0;
	pc.cur = -1;
	kgenome_diag_wrapper_frame_reset(&f);
	kgenome_diag_wrapper_isrc_scan(&it, c, seg, off, n);
	while (!c->s->halt && kgenome_diag_wrapper_isrc_next(&it, &in)) {
		struct kgenome_diag_wrapper_summary *ws;

		if (in.at >= pc.hi || !pc.hi) {
			piece_of(c, fs, in.at, &pc);
			kgenome_diag_wrapper_frame_reset(&f);
		}
		/*
		 * A FUNCTION THAT HANDS BACK WHAT IT MADE. Mirai builds its raw sockets
		 * in a helper - socket, IP_HDRINCL, O_NONBLOCK, `return fd` - and sends
		 * on the result in the attack routine, so the descriptor the send names
		 * is produced in another function. The helper's return value is the
		 * node; the callers, in the second walk, take it from there.
		 */
		if (in.op == KGENOME_CELL_RET && pc.cur >= 0 && c->fret &&
		    f.reg[KGENOME_CELL_REG_AX].t == KGENOME_DIAG_WRAPPER_V_NODE) {
			if (!c->fret[pc.cur] && c->fmiss && c->fmiss[pc.cur])
				c->need_round2 = 1;     /* a caller above asked too early */
			c->fret[pc.cur] = (uint32_t)f.reg[KGENOME_CELL_REG_AX].node + 1u;
		}
		if (in.op == KGENOME_CELL_CALL) {
			ws = (!(in.flags & KGENOME_CELL_F_INDIRECT) && in.target != KGENOME_BROKEN)
			     ? kgenome_diag_wrapper_summary_of(c, in.target) : NULL;
			{
				/* The arguments are read BEFORE the callee's clobbers are
				 * applied, and the result is put in AFTER them. A wrapper
				 * with several paths makes the node of each; they merge. */
				struct kgenome_diag_wrapper_val ret = kgenome_diag_wrapper_unk;

				if (ws) {
					uint32_t v, base = kgenome_diag_wrapper_summary_pos(c, in.target);

					for (v = base; v < c->n_ws &&
						       kgenome_diag_wrapper_summary_at(c, v)->entry == in.target; v++) {
						struct kgenome_diag_wrapper_val r = emit_call_node(c, &f,
							kgenome_diag_wrapper_summary_at(c, v), &in, pc.in_fn);

						if (r.t != KGENOME_DIAG_WRAPPER_V_UNK && ret.t == KGENOME_DIAG_WRAPPER_V_UNK)
							ret = r;
					}
				}
				kgenome_diag_wrapper_frame_call_unknown(c, &f);
				/*
				 * The helper's OWN node wins over the one a summary makes at
				 * the call: the summary stops at the first wrapper the helper
				 * calls (the socket) and knows nothing of the option calls
				 * after it, so the node it makes at the call has none of the
				 * helper's later links, and a send on it could never reach the
				 * IP_HDRINCL that made the socket raw-with-header.
				 */
				if (pc.in_fn && c->fret && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
				    in.target != KGENOME_BROKEN) {
					int ti = kgenome_diag_wrapper_tgt_index(c, in.target);

					if (ti >= 0 && c->fret[ti]) {
						ret.t = KGENOME_DIAG_WRAPPER_V_NODE;
						ret.node = (uint16_t)(c->fret[ti] - 1u);
					} else if (ti >= 0 && c->fmiss) {
						c->fmiss[ti] = 1;
					}
				}
				f.reg[KGENOME_CELL_REG_AX] = ret;
			}
			continue;
		}
		kgenome_diag_wrapper_frame_step(c, &f, &in);
	}
}

/* ---- the entry point ----------------------------------------------------- */

/* The entries, sorted and each once. */
void kgenome_diag_wrapper_tgt_unique(struct kgenome_diag_wrapper_ctx *c)
{
	uint32_t i, w = 0;

	if (c->wk->n_tgt)
		qsort(c->wk->tgt, c->wk->n_tgt, sizeof *c->wk->tgt, kof_cmp_u64);
	for (i = 0; i < c->wk->n_tgt; i++)
		if (!w || c->wk->tgt[w - 1u] != c->wk->tgt[i])
			c->wk->tgt[w++] = c->wk->tgt[i];
	c->wk->n_tgt = w;
}
