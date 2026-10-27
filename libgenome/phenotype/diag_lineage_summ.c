/*
 * diag_lineage_summ.c - STAGE 2: what a call to a function of the object means for the values that pass
 * through it, computed callee first. Part of the lineage stages; see diag_lineage_private.h.
 *
 * A FUNCTION'S SUMMARY says two things, and both are in the wrapper summary's own format
 * (struct kgenome_diag_wrapper_summary, flow != NONE) and its own pool (kgenome_diag_wrapper_summary_insert
 * / _pos / _at, kept here in a pool of the stage's own so a wrapper's walk never meets one):
 *
 *   SINK  parameter `param` reaches argument `role` of the node whose call is at `site`. (Whether it does so
 *         on every path, or only with a constant beside it, is the callee's own contribution to that consumer: it solved
 *         its own body, and the union at the consumer is MUST only if every context agrees.) The wrapper summary says the same thing about a system call
 *         ("my parameter 2 is its argument 0"); this is it for a node that is already there.
 *   RET   what the function may hand back: a node's result, a parameter, or - V_UNK - something no token
 *         names. A function that returns the descriptor it made is one record (this is what the
 *         wrapper walk's `fret` says for the one case it follows).
 *
 * AT A CALL, a SINK adds the caller's own value of that parameter to what reaches the node (the caller's
 * producers become links; a parameter of the caller's own becomes a SINK of the caller's, so a chain of
 * helpers is followed as far as it goes), and RET is the caller's value of rax afterwards.
 *
 * THE ORDER IS THE CALL GRAPH'S: strongly connected groups, callees first (Tarjan - the order a group is
 * completed in is already the reverse topological one). A function whose group is more than itself, or that
 * calls itself, is solved again until its summary stops changing, in a pass that writes no link; then once
 * more to write them. The rounds are bounded (KGENOME_LINEAGE_ROUNDS) and a group that has not settled says
 * so on the scan - the evidence is the last round's, which is a sound over-approximation: a summary that
 * is not yet known is `other`, never a producer it does not have.
 *
 * WHICH FUNCTIONS ARE SOLVED: those that can reach a node - one that has a node, or calls one that can (`rel`, a reverse
 * walk of the call graph from the nodes' functions). A helper with no node reaches no consumer and no producer, so it
 * only matters as a pass-through of a value (`int id(int fd) { return fd; }`), and leaving the others out is a measured
 * trade, not a proof: on the 100-file PE cell it kept 87 of 87 links and took the stage from 9.5 s to 4.2 s, on the
 * static stripped ELF cell it lost 12 of the 390 links the stage adds (3%) for about half the time. What a call to one
 * that was not solved returns is unknown with the reason W_SKIP, so the loss is reported (the unresolved set), not hidden.
 * How much of the rest is read and how often is the chain's business (diag_lineage_chain.c), and the budget's.
 *
 * WHAT THE CALLERS ARE. A function nobody calls is entered with parameters nothing proves, so its
 * parameters are `other` where they reach a node. A function called only through a pointer is, by the same
 * rule, seen as having callers if ANY direct call names it; the pointer calls are not modelled (said in
 * the tests, not hidden).
 */
#include <stddef.h>
#include <kofcmp.h>
#include "diag_lineage_private.h"

#define KGENOME_LINEAGE_ROUNDS 8u

uint32_t kgenome_lineage_fn_of_va(const struct kgenome_lineage *L, uint64_t va)
{
	const uint32_t lo = kof_lower_bound_u64(L->fn_by_va, L->n_fn, sizeof *L->fn_by_va, 0, va);

	return lo < L->n_fn && L->fn_by_va[lo].va == va ? L->fn_by_va[lo].fn : UINT32_MAX;
}

/* The function an offset lies in, or UINT32_MAX. */
uint32_t kgenome_lineage_fn_at(const struct kgenome_lineage *L, uint64_t off)
{
	const uint32_t lo = kof_first_ending_above_u64(L->fn, L->n_fn, sizeof *L->fn, offsetof(struct kgenome_lineage_fn, off),
						       offsetof(struct kgenome_lineage_fn, len), off);

	return lo < L->n_fn && L->fn[lo].off <= off ? lo : UINT32_MAX;
}

int kgenome_lineage_sum_find(struct kgenome_lineage *L, uint64_t entry, uint32_t *lo, uint32_t *hi)
{
	uint32_t p = kgenome_diag_wrapper_summary_pos(&L->sums, entry), q = p;

	while (q < L->sums.n_ws && kgenome_diag_wrapper_summary_at(&L->sums, q)->entry == entry)
		q++;
	*lo = p;
	*hi = q;
	return q > p;
}

/*
 * A CALL TO A FUNCTION OF THE OBJECT. Two things come of it and they are not asked for alike. The SINKS - the callee's
 * consumers that a parameter reaches get the caller's value of it - are applied on every run: the callee's link is MUST only
 * if every caller's value is accounted for, and a caller that passes a constant is a context too. The RETURN - what the
 * callee hands back - is applied only when the run has the SUMM stage (`want_ret`); without it rax is unknown with the
 * reason W_CALL, and an input that reaches a consumer so is the obligation that asks for the stage.
 */
void kgenome_lineage_apply(struct kgenome_lineage *L, struct kgenome_lineage_state *st, uint32_t callee,
			   struct kgenome_lineage_val *ret, int emit, int want_ret)
{
	struct kgenome_lineage_val r;
	uint32_t lo, hi, p;
	int any = 0;

	memset(&r, 0, sizeof r);
	if (!kgenome_lineage_sum_find(L, L->fn[callee].off, &lo, &hi)) {
		kgenome_lineage_val_unknown(ret, KGENOME_LINEAGE_W_SKIP);       /* not solved: it reaches no node, or is not done yet */
		/* a function that was not read may be wanted: if what it returns reaches a consumer, the caller's obligation asks for it */
		if ((L->plan & KGENOME_LINEAGE_S_DEMAND) && L->skipped && L->skipped[callee] == 1u && L->n_need < L->n_fn) {
			L->skipped[callee] = 2u;
			L->need[L->n_need++] = callee;
		}
		return;
	}
	/* A return that names no token (a constant, something unknown) is applied whatever the run: it costs a read of the record and
	 * no second solve. Only a return that is a producer or a parameter is what the SUMM stage is asked for. */
	for (p = lo; p < hi && !want_ret; p++) {
		const struct kgenome_diag_wrapper_summary *m = kgenome_diag_wrapper_summary_at(&L->sums, p);

		if (m->flow == KGENOME_DIAG_WRAPPER_FLOW_RET &&
		    (m->ret.t == KGENOME_DIAG_WRAPPER_V_NODE || m->ret.t == KGENOME_DIAG_WRAPPER_V_PARAM))
			break;
		if (p + 1u == hi)
			want_ret = 1;
	}
	for (p = lo; p < hi; p++) {
		const struct kgenome_diag_wrapper_summary *m = kgenome_diag_wrapper_summary_at(&L->sums, p);

		if (m->flow == KGENOME_DIAG_WRAPPER_FLOW_RET && want_ret) {
			any = 1;
			if (m->ret.t == KGENOME_DIAG_WRAPPER_V_CONST) {
				/* a group member not yet solved: it has returned nothing yet */
			} else if (m->ret.t == KGENOME_DIAG_WRAPPER_V_NODE) {
				(void)kgenome_lineage_val_add(L, &r, m->ret.node);
			} else if (m->ret.t == KGENOME_DIAG_WRAPPER_V_PARAM) {
				struct kgenome_lineage_val a = kgenome_lineage_arg(L, st, (unsigned)m->ret.v);

				(void)kgenome_lineage_val_join(L, &r, &a);
			} else {
				/* what the function returns that no token names, and why that is unknown (a constant stays one) */
				r.other = 1;
				r.why |= m->ret.v ? (uint32_t)m->ret.v : (uint32_t)KGENOME_LINEAGE_W_RET;
			}
		} else if (m->flow == KGENOME_DIAG_WRAPPER_FLOW_SINK && emit) {
			uint32_t node;
			struct kgenome_lineage_val a;

			if (!kgenome_lineage_site_of(L, m->site, &node))
				continue;
			a = kgenome_lineage_arg(L, st, m->param);
			kgenome_lineage_agg_add(L, node, m->role, &a, st->seeded);
		}
	}
	if (!want_ret) {
		kgenome_lineage_val_unknown(ret, KGENOME_LINEAGE_W_CALL);
		return;
	}
	if (!any) {
		r.other = 1;
		r.why |= KGENOME_LINEAGE_W_SKIP;
	}
	r.k = KGENOME_LINEAGE_A_NONE;
	r.v = 0;
	*ret = r;
}

/* ---- a function's summary, from what its solve found ---- */

static int cmp_sink(const void *a, const void *b)
{
	const struct kgenome_lineage_sink *x = a, *y = b;

	if (x->node != y->node)
		return x->node < y->node ? -1 : 1;
	if (x->role != y->role)
		return x->role < y->role ? -1 : 1;
	return x->param < y->param ? -1 : x->param > y->param;
}

static int cmp_tok(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static uint64_t fnv(uint64_t h, uint64_t v)
{
	return (h ^ v) * 0x100000001b3ull;
}

/* Publish function `fi`'s summary; 1 when it is not the one published before. */
static int publish(struct kgenome_lineage *L, uint32_t fi, struct kgenome_lineage_out *o)
{
	uint32_t t[KGENOME_LINEAGE_SET + 1u], nt = 0, i, lo, hi, k;
	uint32_t why;
	uint64_t h = 0xcbf29ce484222325ull;
	struct kgenome_diag_wrapper_summary m;

	if (o->n_sink)
		qsort(o->sink, o->n_sink, sizeof *o->sink, cmp_sink);
	/* the tokens of what it returns, in a canonical order; `other` is the one record that is not a token */
	if (!o->ret_seen || o->ret.other)
		t[nt++] = UINT32_MAX;
	why = o->ret_seen && o->ret.other ? o->ret.why : (uint32_t)KGENOME_LINEAGE_W_RET;
	if (o->ret_seen)
		for (i = 0; i < o->ret.n; i++)
			t[nt++] = o->ret.t[i];
	qsort(t, nt, sizeof *t, cmp_tok);
	for (i = 0; i < nt; i++)
		h = fnv(h, t[i]);
	h = fnv(h, why);
	for (i = 0; i < o->n_sink; i++)
		h = fnv(fnv(h, o->sink[i].node), (uint64_t)o->sink[i].role << 16 | (uint64_t)o->sink[i].param << 8);
	if (h == L->sumhash[fi])
		return 0;
	L->sumhash[fi] = h;
	if (kgenome_lineage_sum_find(L, L->fn[fi].off, &lo, &hi))
		for (k = lo; k < hi; k++)
			kgenome_diag_wrapper_summary_at(&L->sums, k)->flow = KGENOME_DIAG_WRAPPER_FLOW_DEAD;
	for (i = 0; i < nt; i++) {
		memset(&m, 0, sizeof m);
		m.entry = L->fn[fi].off;
		m.flow = KGENOME_DIAG_WRAPPER_FLOW_RET;
		if (t[i] == UINT32_MAX) {
			m.ret.t = KGENOME_DIAG_WRAPPER_V_UNK;
			m.ret.v = why;
		} else if (t[i] & KGENOME_LINEAGE_PARAM) {
			m.ret.t = KGENOME_DIAG_WRAPPER_V_PARAM;
			m.ret.v = (int64_t)(t[i] & 0xffu);
		} else {
			m.ret.t = KGENOME_DIAG_WRAPPER_V_NODE;
			m.ret.node = (uint16_t)t[i];
		}
		(void)kgenome_diag_wrapper_summary_insert(&L->sums, &m);
	}
	for (i = 0; i < o->n_sink; i++) {
		memset(&m, 0, sizeof m);
		m.entry = L->fn[fi].off;
		m.flow = KGENOME_DIAG_WRAPPER_FLOW_SINK;
		m.site = L->s->hit[o->sink[i].node].at;
		m.role = o->sink[i].role;
		m.param = o->sink[i].param;
		(void)kgenome_diag_wrapper_summary_insert(&L->sums, &m);
	}
	return 1;
}

/* Solve a function, and publish what it does. 1 when its summary changed. */
static int solve_publish(struct kgenome_lineage *L, uint32_t fi)
{
	struct kgenome_lineage_out o;
	int ch;

	memset(&o, 0, sizeof o);
	kgenome_lineage_solve(L, fi, &o);
	ch = publish(L, fi, &o);
	if (o.cap_sink)
		kgenome_lineage_uncharge(L, (uint64_t)o.cap_sink * sizeof *o.sink);
	free(o.sink);
	return ch;
}

/* ---- the call graph ---- */

struct lin_graph {
	uint32_t *fh, *fe;              /* callees of each function, CSR */
	uint32_t *rh, *re;              /* callers of each function, CSR */
	uint8_t  *self;                 /* calls itself */
	uint8_t  *rel;                  /* can reach a node: has one, or calls a function that can */
	uint32_t ne;
};

/* The edges: a direct call, or a direct jump to the entry of ANOTHER function (a tail call). */
static int graph_edges(const struct kgenome_codemap *cm, const struct kgenome_lineage *L, uint32_t *from, uint32_t *to,
		       uint32_t *n)
{
	uint32_t k, ne = 0;

	for (k = 0; k < cm->n; k++) {
		const struct kgenome_codemap_ref *r = &cm->v[k];
		uint32_t a, b;

		if ((r->kind != KGENOME_CM_CALL && r->kind != KGENOME_CM_JMP) || r->to == KGENOME_BROKEN ||
		    (r->flags & KGENOME_CMF_INDIRECT))
			continue;
		a = kgenome_lineage_fn_at(L, r->at);
		b = kgenome_lineage_fn_at(L, r->to);
		if (a == UINT32_MAX || b == UINT32_MAX || L->fn[b].off != r->to)
			continue;
		if (r->kind == KGENOME_CM_JMP && a == b)
			continue;       /* a loop to its own top is not a call */
		if (r->kind == KGENOME_CM_CALL && r->to == r->at + r->len)
			continue;       /* a call to the next instruction: the get-pc idiom, or a relocation's empty hole */
		if (from) {
			from[ne] = a;
			to[ne] = b;
		}
		ne++;
	}
	*n = ne;
	return 1;
}

static void graph_free(struct lin_graph *g)
{
	free(g->fh);
	free(g->fe);
	free(g->rh);
	free(g->re);
	free(g->self);
	free(g->rel);
	memset(g, 0, sizeof *g);
}

static int graph_build(struct kgenome_lineage *L, const struct kgenome_codemap *cm, struct lin_graph *g)
{
	const uint32_t nf = L->n_fn;
	uint32_t *from = NULL, *to = NULL, *fp = NULL, *rp = NULL, k, ne = 0;

	memset(g, 0, sizeof *g);
	(void)graph_edges(cm, L, NULL, NULL, &ne);
	g->ne = ne;
	from = malloc((size_t)(ne ? ne : 1u) * sizeof *from);
	to = malloc((size_t)(ne ? ne : 1u) * sizeof *to);
	g->fh = calloc((size_t)nf + 1u, sizeof *g->fh);
	g->rh = calloc((size_t)nf + 1u, sizeof *g->rh);
	g->fe = malloc((size_t)(ne ? ne : 1u) * sizeof *g->fe);
	g->re = malloc((size_t)(ne ? ne : 1u) * sizeof *g->re);
	g->self = calloc(nf ? nf : 1u, 1);
	g->rel = calloc(nf ? nf : 1u, 1);
	fp = malloc((size_t)(nf ? nf : 1u) * sizeof *fp);
	rp = malloc((size_t)(nf ? nf : 1u) * sizeof *rp);
	if (!from || !to || !g->fh || !g->rh || !g->fe || !g->re || !g->self || !g->rel || !fp || !rp) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		free(from);
		free(to);
		free(fp);
		free(rp);
		graph_free(g);
		return 0;
	}
	(void)graph_edges(cm, L, from, to, &ne);
	for (k = 0; k < ne; k++) {
		g->fh[from[k] + 1u]++;
		g->rh[to[k] + 1u]++;
		if (from[k] == to[k])
			g->self[from[k]] = 1;
	}
	for (k = 0; k < nf; k++) {
		g->fh[k + 1u] += g->fh[k];
		g->rh[k + 1u] += g->rh[k];
	}
	memcpy(fp, g->fh, (size_t)nf * sizeof *fp);
	memcpy(rp, g->rh, (size_t)nf * sizeof *rp);
	for (k = 0; k < ne; k++) {
		g->fe[fp[from[k]]++] = to[k];
		g->re[rp[to[k]]++] = from[k];
		if (from[k] != to[k])
			/* KNOWN DEFECT D8 (2026-10-24, R) [sev M]: `callers` counts direct calls only, so an exported or address-taken function with
			 * one direct caller has all its callers "accounted for" and its summary links come out MUST. Trigger: a function also
			 * called through a pointer or from outside the object. Effect: the link is MUST on one caller's value (link 451/f in
			 * the lineage audit), the others are never seen. Reproducer: none committed (agent-reported, STATUS D8). Fix: mark a
			 * function whose address is taken or exported as having an unknown caller and demote its links to MAY. */
			L->callers[to[k]]++;
	}
	/* the functions that can reach a node: a value can only travel between two nodes through them */
	{
		uint32_t *q = malloc((size_t)(nf ? nf : 1u) * sizeof *q), qh = 0, qt = 0;

		if (q) {
			for (k = 0; k < L->n_site; k++) {
				uint32_t f = kgenome_lineage_fn_at(L, L->site_at[k]);

				if (f != UINT32_MAX && !g->rel[f]) {
					g->rel[f] = 1;
					q[qt++] = f;
				}
			}
			while (qh < qt) {
				uint32_t f = q[qh++], e;

				for (e = g->rh[f]; e < g->rh[f + 1u]; e++)
					if (!g->rel[g->re[e]]) {
						g->rel[g->re[e]] = 1;
						q[qt++] = g->re[e];
					}
			}
			free(q);
		} else {
			memset(g->rel, 1, nf);
		}
	}
	free(from);
	free(to);
	free(fp);
	free(rp);
	return 1;
}

/*
 * THE GROUPS, callee first, and each one solved. Tarjan without recursion: the call graph of a static
 * binary has chains thousands deep and the stack of a thread is not what bounds the evidence.
 */
/* Replace a function's records by one return: nothing yet (`bottom`) or something no token names (`widen`). */
static void publish_ret(struct kgenome_lineage *L, uint32_t fi, int widen)
{
	struct kgenome_diag_wrapper_summary m;
	uint32_t lo, hi, k;

	if (kgenome_lineage_sum_find(L, L->fn[fi].off, &lo, &hi))
		for (k = lo; k < hi; k++)
			kgenome_diag_wrapper_summary_at(&L->sums, k)->flow = KGENOME_DIAG_WRAPPER_FLOW_DEAD;
	memset(&m, 0, sizeof m);
	m.entry = L->fn[fi].off;
	m.flow = KGENOME_DIAG_WRAPPER_FLOW_RET;
	m.ret.t = widen ? KGENOME_DIAG_WRAPPER_V_UNK : KGENOME_DIAG_WRAPPER_V_CONST;
	m.ret.v = widen ? KGENOME_LINEAGE_W_LIMIT : 0;
	(void)kgenome_diag_wrapper_summary_insert(&L->sums, &m);
	L->sumhash[fi] = widen ? 1u : 0u;
}

/*
 * THE FUNCTIONS THAT NEVER RETURN, from the object's own branches (the codemap): no ret, no jump out of the function, no jump
 * through a register or memory (a thunk), and at least one call or syscall (what it does before it stops). An object stripped of
 * names has no other way to know __stack_chk_fail and abort from their callers; the imports are named (diag_lineage_chain.c).
 */
static void noret_build(struct kgenome_lineage *L, const struct kgenome_codemap *cm)
{
	uint8_t *bad = calloc(L->n_fn ? L->n_fn : 1u, 1), *refs = calloc(L->n_fn ? L->n_fn : 1u, 1);
	uint32_t k, f;

	L->noret_fn = calloc(L->n_fn ? L->n_fn : 1u, 1);
	if (!bad || !refs || !L->noret_fn) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		free(L->noret_fn);
		L->noret_fn = NULL;
		free(bad);
		free(refs);
		return;
	}
	for (k = 0; k < cm->n; k++) {
		const struct kgenome_codemap_ref *r = &cm->v[k];

		f = kgenome_lineage_fn_at(L, r->at);
		if (f == UINT32_MAX)
			continue;
		if (r->kind == KGENOME_CM_RET) {
			bad[f] = 1;
		} else if (r->kind == KGENOME_CM_JMP || r->kind == KGENOME_CM_JCC || r->kind == KGENOME_CM_LOOP) {
			uint32_t t = (r->flags & KGENOME_CMF_INDIRECT) || r->to == KGENOME_BROKEN ? UINT32_MAX : kgenome_lineage_fn_at(L, r->to);

			if (r->kind == KGENOME_CM_JMP && (r->flags & KGENOME_CMF_INDIRECT))
				bad[f] = 1;
			else if (t != f)
				bad[f] = 1;
		} else {
			refs[f] = 1;    /* a call or a syscall */
		}
	}
	for (f = 0; f < L->n_fn; f++)
		L->noret_fn[f] = (uint8_t)(refs[f] && !bad[f]);
	free(bad);
	free(refs);
}

/* Does the function's summary say anything a caller can use: a sink, or a return that is a producer or a parameter. */
static int summary_nontrivial(struct kgenome_lineage *L, uint32_t fi)
{
	uint32_t lo, hi, p;

	if (!kgenome_lineage_sum_find(L, L->fn[fi].off, &lo, &hi))
		return 0;
	for (p = lo; p < hi; p++) {
		const struct kgenome_diag_wrapper_summary *m = kgenome_diag_wrapper_summary_at(&L->sums, p);

		if (m->flow == KGENOME_DIAG_WRAPPER_FLOW_SINK ||
		    (m->flow == KGENOME_DIAG_WRAPPER_FLOW_RET &&
		     (m->ret.t == KGENOME_DIAG_WRAPPER_V_NODE || m->ret.t == KGENOME_DIAG_WRAPPER_V_PARAM)))
			return 1;
	}
	return 0;
}

/*
 * IS THE FUNCTION WORTH READING? Only if a node is in it or a function it calls has a summary a caller can use (a sink, a producer
 * or a parameter returned): without either its own summary is empty, and decoding it and following its blocks finds nothing a
 * link could come of. The callees are done first, so this is known when the function's turn comes. The one thing it leaves out is
 * a function that only passes its own parameter back (`int id(int fd) { return fd; }`) and calls nothing useful - measured on the
 * cells, with the reach pruning above, in the numbers of diag_class.c.
 */
static int worth_reading(struct kgenome_lineage *L, const struct lin_graph *g, uint32_t fi)
{
	uint32_t e;

	if (L->has_site[fi])
		return 1;
	for (e = g->fh[fi]; e < g->fh[fi + 1u]; e++)
		if (L->nontriv[g->fe[e]])
			return 1;
	return 0;
}

/*
 * A FUNCTION THAT WAS NOT READ, AND IS WANTED. Not reading a function with no node in it and nothing useful below it costs the
 * helper that only hands a parameter back (`int second(int a, int b) { return b; }`) - and a caller whose result reaches a
 * consumer says so (W_SKIP pending in its last run: the callees it met are in `need`). Those are read now, between two
 * solves, and the caller is read again with their summaries; what the caller's own summary changes to is what ITS callers see,
 * as for any function. A bound of a few rounds: a chain of helpers each needing the next.
 */
static void demand_loop(struct kgenome_lineage *L, uint32_t fi)
{
	uint32_t round;

	if (!L->deferred) {                     /* the results reach nothing: nobody asked */
		for (round = 0; round < L->n_need; round++)
			L->skipped[L->need[round]] = 1u;
		L->n_need = 0;
		return;
	}

	for (round = 0; round < 4u && L->n_need; round++) {
		uint32_t list[8], n = 0, i, any = 0;

		for (i = 0; i < L->n_need; i++)
			if (n < 8u)
				list[n++] = L->need[i];
			else
				L->skipped[L->need[i]] = 1u;
		L->n_need = 0;
		for (i = 0; i < n; i++) {
			L->can_defer = 0;               /* (a function read on demand merges: one level of asking) */
			(void)solve_publish(L, list[i]);
			L->can_defer = 1;
			L->nontriv[list[i]] = (uint8_t)summary_nontrivial(L, list[i]);
			L->skipped[list[i]] = 3u;           /* read, on demand */
			L->st.demanded++;
			any = 1;
		}
		L->deferred = 0;
		if (any) {
			(void)solve_publish(L, fi);
			if (!L->deferred)
				return;
		}
		if (!any)
			break;
	}
	/* the rounds ended with a read still owed: settle it without asking again */
	for (round = 0; round < L->n_need; round++)
		L->skipped[L->need[round]] = 1u;
	L->n_need = 0;
	L->deferred = 0;
	L->no_defer = 1;
	(void)solve_publish(L, fi);
	L->no_defer = 0;
}

static void solve_group(struct kgenome_lineage *L, const struct lin_graph *g, const uint32_t *grp, uint32_t n)
{
	uint32_t i, round;

	if (n == 1u && !g->self[grp[0]]) {
		if (!(L->plan & KGENOME_LINEAGE_S_EAGER) && !worth_reading(L, g, grp[0])) {
			L->st.skipped++;
			L->skipped[grp[0]] = 1u;
			return;
		}
		L->can_defer = 1;               /* (only here is the read-again loop to follow) */
		(void)solve_publish(L, grp[0]);
		L->nontriv[grp[0]] = (uint8_t)summary_nontrivial(L, grp[0]);
		demand_loop(L, grp[0]);
		L->can_defer = 0;
		return;
	}
	/*
	 * A RECURSIVE GROUP IS SOLVED FROM BELOW: each member starts as a function that has returned nothing, and the rounds
	 * add what they find until a round adds nothing - the least fixpoint, which is what the executions of the program
	 * make (a function that returns its parameter, or the result of calling itself, returns the parameter). Started from
	 * "something no token names" the iteration could only ever keep it, and every recursive function would return
	 * `other`. If the rounds do not settle the group is widened to `other` and read once more: what was found so far
	 * is then not taken for the whole.
	 */
	for (i = 0; i < n; i++)
		publish_ret(L, grp[i], 0);
	L->dry = 1;
	for (round = 0; round < KGENOME_LINEAGE_ROUNDS; round++) {
		int ch = 0;

		for (i = 0; i < n; i++)
			ch |= solve_publish(L, grp[i]);
		if (!ch)
			break;
	}
	L->dry = 0;
	if (round == KGENOME_LINEAGE_ROUNDS) {
		kgenome_lineage_bound(L, KGENOME_LINEAGE_B_ROUNDS);
		for (i = 0; i < n; i++)
			publish_ret(L, grp[i], 1);
	}
	for (i = 0; i < n; i++) {
		(void)solve_publish(L, grp[i]);
		L->nontriv[grp[i]] = (uint8_t)summary_nontrivial(L, grp[i]);
	}
}

static void tarjan(struct kgenome_lineage *L, const struct lin_graph *g)
{
	const uint32_t nf = L->n_fn;
	uint32_t *idx = calloc(nf ? nf : 1u, sizeof *idx), *low = calloc(nf ? nf : 1u, sizeof *low);
	uint32_t *stk = malloc((size_t)(nf ? nf : 1u) * sizeof *stk), *cs = malloc((size_t)(nf ? nf : 1u) * sizeof *cs);
	uint32_t *ce = malloc((size_t)(nf ? nf : 1u) * sizeof *ce), *grp = malloc((size_t)(nf ? nf : 1u) * sizeof *grp);
	uint8_t *on = calloc(nf ? nf : 1u, 1);
	uint32_t next = 1, sp = 0, csp = 0, root;

	if (!idx || !low || !stk || !cs || !ce || !grp || !on) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		goto out;
	}
	for (root = 0; root < nf && !L->halt && !L->over_steps; root++) {
		if (idx[root] || !g->rel[root])
			continue;
		cs[0] = root;
		ce[0] = g->fh[root];
		csp = 1;
		idx[root] = low[root] = next++;
		stk[sp++] = root;
		on[root] = 1;
		while (csp) {
			uint32_t v = cs[csp - 1u];

			if (ce[csp - 1u] < g->fh[v + 1u]) {
				uint32_t w = g->fe[ce[csp - 1u]++];

				if (!g->rel[w])
					continue;
				if (!idx[w]) {
					idx[w] = low[w] = next++;
					stk[sp++] = w;
					on[w] = 1;
					cs[csp] = w;
					ce[csp] = g->fh[w];
					csp++;
				} else if (on[w] && idx[w] < low[v]) {
					low[v] = idx[w];
				}
				continue;
			}
			if (low[v] == idx[v]) {
				uint32_t n = 0, w;

				do {
					w = stk[--sp];
					on[w] = 0;
					grp[n++] = w;
				} while (w != v);
				if (!L->halt && !L->over_steps)
					solve_group(L, g, grp, n);
			}
			csp--;
			if (csp && low[v] < low[cs[csp - 1u]])
				low[cs[csp - 1u]] = low[v];
		}
	}
out:
	free(idx);
	free(low);
	free(stk);
	free(cs);
	free(ce);
	free(grp);
	free(on);
}

void kgenome_lineage_run_summ(struct kgenome_lineage *L)
{
	const struct kgenome_codemap *cm = kgenome_lineage_codemap(L);
	struct lin_graph g;
	uint32_t p;

	if (!cm || !L->n_fn)
		return;
	L->callers = calloc(L->n_fn, sizeof *L->callers);
	L->has_site = calloc(L->n_fn, 1);
	L->skipped = malloc(L->n_fn);
	if (L->skipped)
		memset(L->skipped, 1, L->n_fn);        /* (every function is unread until its turn: those that never get one are the pruned) */
	L->need = malloc((size_t)L->n_fn * sizeof *L->need);
	L->nontriv = calloc(L->n_fn, 1);
	L->sumhash = malloc((size_t)L->n_fn * sizeof *L->sumhash);
	if (!L->callers || !L->sumhash || !L->has_site || !L->nontriv || !L->skipped || !L->need) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return;
	}
	for (p = 0; p < L->n_fn; p++)
		L->sumhash[p] = 0;
	L->sums.s = L->s;
	for (p = 0; p < L->n_site; p++) {
		uint32_t f = kgenome_lineage_fn_at(L, L->site_at[p]);

		if (f != UINT32_MAX)
			L->has_site[f] = 1;
	}
	if (!graph_build(L, cm, &g))
		return;
	L->rel = g.rel;
	noret_build(L, cm);
	tarjan(L, &g);
	L->rel = NULL;
	L->ag = &L->glob;
	/* A function nobody calls is entered with parameters nothing proves: where one reaches a node,
	 * something no token names may be what arrives. */
	for (p = 0; p < L->sums.n_ws && !L->halt; p++) {
		const struct kgenome_diag_wrapper_summary *m = kgenome_diag_wrapper_summary_at(&L->sums, p);
		uint32_t f, node;

		if (m->flow != KGENOME_DIAG_WRAPPER_FLOW_SINK)
			continue;
		f = kgenome_lineage_fn_at(L, m->entry);
		if (f == UINT32_MAX || L->callers[f] || !kgenome_lineage_site_of(L, m->site, &node))
			continue;
		{
			struct kgenome_lineage_val o;

			kgenome_lineage_val_unknown(&o, KGENOME_LINEAGE_W_NOCALLER);
			kgenome_lineage_agg_add(L, node, m->role, &o, 0);
		}
	}
	graph_free(&g);
}
