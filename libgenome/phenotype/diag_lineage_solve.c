/*
 * diag_lineage_solve.c - ONE FUNCTION: its blocks, a fixpoint of the state over them, and the links at
 * the sites. Part of the lineage stages; see diag_lineage_private.h.
 *
 * THE FIXPOINT IS OVER BLOCKS, NOT OVER INSTRUCTIONS. The research prototype kept a state per
 * instruction and a 128-slot table in each; one block's state is all a join needs and a block is
 * stepped through once per visit. A visit copies the state at the top of a block, steps its instructions
 * and joins the result into each successor; a successor that changed is looked at again. The lattice
 * only grows (a set gains a token, a flag is set, a place becomes `other`, a stack address becomes
 * unknown), so it ends; the bound below is for the function a hostile object makes enormous.
 *
 * LINKS ARE WRITTEN FROM THE STATES THE FIXPOINT LEFT, in one more pass over the blocks, and not while it
 * runs: a state in the middle of the iteration holds fewer producers than the last one, and a link
 * written from it as MUST would be wrong by the time the function converged.
 *
 * WHAT A CALL IS. At a node (a call or a tail jump the scan has a node at) the arguments the capability's
 * roles name are read and added to what reaches the consumer, and the result is the node's, when the
 * capability hands one on (kgenome_nucleo_hands_on - the same question every route asks). At a direct
 * call to a function of the object, with SUMM, what the callee does is its summary. At anything else
 * the registers the callee may use are `other` and nothing else changes: the frame and the places beyond
 * it are kept across a call, as the wrapper walk keeps them (a callee that writes a global the caller then
 * reads is a miss, said here and not hidden).
 */
#include <stddef.h>
#include <kofcmp.h>
#include "diag_lineage_private.h"

/* ---- the decoded body ---- */

static void collect(void *user, const struct kgenome_cell_insn *in)
{
	struct kgenome_lineage *L = user;

	if (!in || L->halt)
		return;
	if (L->n_in == L->cap_in) {
		uint32_t nc = L->cap_in ? L->cap_in * 2u : 1024u;
		struct kgenome_cell_insn *ni;

		if (!kgenome_lineage_charge(L, (uint64_t)(nc - L->cap_in) * sizeof *ni))
			return;
		ni = realloc(L->in, (size_t)nc * sizeof *ni);
		if (!ni) {
			kgenome_lineage_uncharge(L, (uint64_t)(nc - L->cap_in) * sizeof *ni);
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			L->halt = 1;
			return;
		}
		L->in = ni;
		L->cap_in = nc;
	}
	L->in[L->n_in++] = *in;
}

int kgenome_lineage_decode(struct kgenome_lineage *L, uint32_t fi)
{
	const struct kgenome_lineage_fn *f = &L->fn[fi];

	L->n_in = 0;
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
		.obj = L->obj, .base = L->base, .size = L->size, .off = f->off, .n = f->len, .va = f->va,
		.fn = collect, .user = L, .wk = L->wk });
	return !L->halt;
}

/* ---- the sites and what reaches them ---- */

int kgenome_lineage_site_of(const struct kgenome_lineage *L, uint64_t at, uint32_t *node)
{
	const uint32_t lo = kof_lower_bound_u64(L->site_at, L->n_site, sizeof *L->site_at, 0, at);

	if (lo < L->n_site && L->site_at[lo] == at) {
		*node = L->site_node[lo];
		return 1;
	}
	return 0;
}

/* The node of the instruction: one whose `at` is the instruction's first byte, or - in a relocatable object, where the route that
 * makes the node marks the field the relocation patches - a byte inside it. */
int kgenome_lineage_site_in(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in, uint32_t *node)
{
	const uint32_t lo = kof_lower_bound_u64(L->site_at, L->n_site, sizeof *L->site_at, 0, in->at);

	if (lo < L->n_site && L->site_at[lo] < in->at + in->len) {
		*node = L->site_node[lo];
		return 1;
	}
	return 0;
}

/* KNOWN DEFECT REV-D7a (2026-10-24, Inference) [sev L]: agg_hash (the lineage aggregate table) is a hand-rolled open-addressing table with an unseeded multiplicative
 * hash, not the shared helper (diag_oatab.h / kof_hash64_slot): CLAUDE.md rule 2. Trigger: keys chosen by the file that
 * collide in the top bits. Effect: probe chains grow (the G1 flood in the script tables took 20.4 s for 65536 names).
 * Reproducer: none (review_arch D7, read). Fix: build it on kgenome_oatab (seeded, one probe step) like diag_text_sum. */
static uint32_t agg_hash(uint32_t k)
{
	return (k * 0x9e3779b1u) >> 7;
}

static struct kgenome_lineage_agg *agg_find(struct kgenome_lineage *L, struct kgenome_lineage_aggtab *t, uint32_t key)
{
	uint32_t m = t->cap - 1u, i;

	if (t->n * 2u >= t->cap) {
		struct kgenome_lineage_agg *old = t->v, *na;
		uint32_t oc = t->cap, nc = oc ? oc * 2u : 256u, k;

		if (!kgenome_lineage_charge(L, (uint64_t)nc * sizeof *na))
			return NULL;
		na = calloc(nc, sizeof *na);
		if (!na) {
			kgenome_lineage_uncharge(L, (uint64_t)nc * sizeof *na);
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			L->halt = 1;
			return NULL;
		}
		t->v = na;
		t->cap = nc;
		for (k = 0; k < oc; k++) {
			if (!old[k].key)
				continue;
			for (i = agg_hash(old[k].key) & (nc - 1u); na[i].key; i = (i + 1u) & (nc - 1u))
				;
			na[i] = old[k];
		}
		if (oc)
			kgenome_lineage_uncharge(L, (uint64_t)oc * sizeof *old);
		free(old);
		m = t->cap - 1u;
	}
	for (i = agg_hash(key) & m; t->v[i].key; i = (i + 1u) & m)
		if (t->v[i].key == key)
			return &t->v[i];
	t->v[i].key = key;
	t->n++;
	return &t->v[i];
}

/* The table of the function in hand is emptied for its next run. A table a big function grew is let go rather than
 * cleared for every small one after it. */
static void tab_reset(struct kgenome_lineage *L, struct kgenome_lineage_aggtab *t)
{
	if (!t->n)
		return;
	if (t->cap > 256u && t->n * 8u < t->cap) {
		kgenome_lineage_uncharge(L, (uint64_t)t->cap * sizeof *t->v);
		free(t->v);
		t->v = NULL;
		t->cap = 0;
	} else {
		memset(t->v, 0, (size_t)t->cap * sizeof *t->v);
	}
	t->n = 0;
}

/* What the last run of a function found goes into the object's table: the union of every context's value. */
static void merge_loc(struct kgenome_lineage *L)
{
	uint32_t k;

	for (k = 0; k < L->loc.cap; k++) {
		const struct kgenome_lineage_agg *x = &L->loc.v[k];
		struct kgenome_lineage_agg *a;
		uint8_t j, i;

		if (!x->key)
			continue;
		a = agg_find(L, &L->glob, x->key);
		if (!a)
			return;
		for (i = 0; i < x->n; i++) {
			for (j = 0; j < a->n && a->t[j] != x->t[i]; j++)
				;
			if (j < a->n)
				continue;
			if (a->n < KGENOME_LINEAGE_SET) {
				a->t[a->n++] = x->t[i];
			} else {
				a->other = 1;
				a->why |= KGENOME_LINEAGE_W_LIMIT;
				kgenome_lineage_bound(L, KGENOME_LINEAGE_B_CONSUMER);
			}
		}
		a->other |= x->other;
		a->param |= x->param;
		a->why |= x->why;
	}
}

static void out_sink(struct kgenome_lineage *L, uint32_t node, uint8_t role, uint8_t param)
{
	struct kgenome_lineage_out *o = L->out;
	uint32_t i;

	if (!o)
		return;
	for (i = 0; i < o->n_sink; i++)
		if (o->sink[i].node == node && o->sink[i].role == role && o->sink[i].param == param)
			return;
	if (o->n_sink == o->cap_sink) {
		uint32_t nc = o->cap_sink ? o->cap_sink * 2u : 16u;
		struct kgenome_lineage_sink *ns;

		if (!kgenome_lineage_charge(L, (uint64_t)(nc - o->cap_sink) * sizeof *ns))
			return;
		ns = realloc(o->sink, (size_t)nc * sizeof *ns);
		if (!ns) {
			kgenome_lineage_uncharge(L, (uint64_t)(nc - o->cap_sink) * sizeof *ns);
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			L->halt = 1;
			return;
		}
		o->sink = ns;
		o->cap_sink = nc;
	}
	o->sink[o->n_sink].node = node;
	o->sink[o->n_sink].role = role;
	o->sink[o->n_sink].param = param;
	o->n_sink++;
}

/*
 * A VALUE REACHES A CONSUMER. What reaches (node, role) is the union of every context's value, and the
 * link to a producer is MUST exactly when that union is that one producer and nothing else - so a
 * context adds its tokens, and `other` when it may also be something no token names (or, from a seeded
 * entry, when the whole path is less certain than a walk from the function's own entry). A PARAMETER
 * in the value is not added here: it is what the CALLERS supply, and each caller adds its own value
 * through the sink recorded for the summary.
 */
/* A global or a field a function reads and never stores to is not one LOCS could follow in it: the limit is the cell's (W_CELL).
 * Known once the walk has said which blocks are reached, so the reason is settled where it reaches a consumer. */
static uint32_t settle_why(const struct kgenome_lineage *L, uint32_t why)
{
	return (why & KGENOME_LINEAGE_W_MEM) && !L->fn_store ? (why & ~KGENOME_LINEAGE_W_MEM) | KGENOME_LINEAGE_W_CELL : why;
}

void kgenome_lineage_agg_add(struct kgenome_lineage *L, uint32_t node, uint8_t role,
			     const struct kgenome_lineage_val *v, int uncertain)
{
	struct kgenome_lineage_agg *a = NULL;
	uint8_t i;

	/* what is unknown of the value is what the run's obligations are made of (a constant is not one) */
	if (v->other)
		L->pend |= (settle_why(L, v->why) & ~KGENOME_LINEAGE_W_CONST);
	/* A pass that only learns a summary (a recursive group iterating) writes no link. */
	if (!L->dry) {
		a = agg_find(L, L->ag, ((node + 1u) << 8) | role);
		if (!a)
			return;
	}
	for (i = 0; i < v->n; i++) {
		uint8_t j;

		if (v->t[i] & KGENOME_LINEAGE_PARAM) {
			out_sink(L, node, role, (uint8_t)(v->t[i] & 0xffu));
			if (a)
				a->param = 1;
			continue;
		}
		if (!a || v->t[i] == node)      /* a node's own result coming round a loop is not a link to itself */
			continue;
		for (j = 0; j < a->n && a->t[j] != v->t[i]; j++)
			;
		if (j < a->n)
			continue;
		if (a->n < KGENOME_LINEAGE_SET) {
			a->t[a->n++] = v->t[i];
		} else {
			a->other = 1;           /* more producers than fit: MAY, and said */
			a->why |= KGENOME_LINEAGE_W_LIMIT;
			kgenome_lineage_bound(L, KGENOME_LINEAGE_B_CONSUMER);
		}
	}
	if (a && (v->other || uncertain)) {
		a->other = 1;
		if (v->other)
			a->why |= settle_why(L, v->why);
	}
}

static void out_ret(struct kgenome_lineage *L, const struct kgenome_lineage_val *v)
{
	struct kgenome_lineage_out *o = L->out;

	if (!o)
		return;
	if (v->other)
		L->pend |= (settle_why(L, v->why) & ~KGENOME_LINEAGE_W_CONST);
	if (!o->ret_seen) {
		o->ret = *v;
		o->ret.k = KGENOME_LINEAGE_A_NONE;
		o->ret_seen = 1;
	} else {
		(void)kgenome_lineage_val_join(L, &o->ret, v);
	}
}

/* ---- the blocks ---- */

static uint32_t find_va(const struct kgenome_lineage *L, uint64_t va)
{
	const uint32_t lo = kof_lower_bound_u64(L->in, L->n_in, sizeof *L->in, offsetof(struct kgenome_cell_insn, at_va), va);

	return lo < L->n_in && L->in[lo].at_va == va ? lo : UINT32_MAX;
}

static uint32_t block_of(const struct kgenome_lineage_cfg *g, uint32_t ins)
{
	uint32_t lo = 0, hi = g->nb;

	while (lo + 1u < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (g->bfirst[mid] <= ins)
			lo = mid;
		else
			hi = mid;
	}
	return lo;
}

static int is_branch(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_JMP || in->op == KGENOME_CELL_JCC || in->op == KGENOME_CELL_LOOP;
}

/* The block leaders: the entry, the target of a branch inside the function, and what follows a branch,
 * a return or an instruction that faults. */
static uint32_t leaders(const struct kgenome_lineage *L, uint8_t *ld)
{
	uint32_t i, nb = 0;

	ld[0] = 1;
	for (i = 0; i < L->n_in; i++) {
		const struct kgenome_cell_insn *in = &L->in[i];

		if (is_branch(in) && !(in->flags & KGENOME_CELL_F_INDIRECT) && in->target_va != KGENOME_BROKEN) {
			uint32_t j = find_va(L, in->target_va);

			if (j != UINT32_MAX)
				ld[j] = 1;
		}
		if ((is_branch(in) || in->op == KGENOME_CELL_RET || in->op == KGENOME_CELL_UD) && i + 1u < L->n_in)
			ld[i + 1u] = 1;
	}
	for (i = 0; i < L->n_in; i++)
		nb += ld[i];
	return nb;
}

/* The block `succ` has a new way in: join the state, and look at it again when it changed. A walk from a
 * seeded entry never joins into a block the function's own entry reached: what it knows is the less
 * certain, and the block's own state is not to be spoiled by it. */
static void propagate(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, uint32_t succ,
		      const struct kgenome_lineage_state *w)
{
	struct kgenome_lineage_state *to = &g->bs[succ];
	int ch;

	if (w->seeded && to->valid && !to->seeded)
		return;
	ch = kgenome_lineage_state_join(L, to, w);
	if (ch && !g->inq[succ]) {
		g->inq[succ] = 1;
		g->wl[(g->head + g->nw) % g->nb] = succ;
		g->nw++;
	}
}

void kgenome_lineage_cfg_enter(struct kgenome_lineage_cfg *g, uint32_t b, struct kgenome_lineage_state *st)
{
	g->bs[b] = *st;
	g->bs[b].valid = 1;
	memset(st, 0, sizeof *st);
	if (!g->inq[b]) {
		g->inq[b] = 1;
		g->wl[(g->head + g->nw) % g->nb] = b;
		g->nw++;
	}
}

/* The value of the node's result, when the capability hands one on. */
int kgenome_lineage_hands_on(const struct kgenome_lineage *L, const struct kgenome_diag_hit *h)
{
	const char *nm = NULL;

	if ((h->bits & KGENOME_DIAG_H_SYMREF) && h->symref < L->size)
		nm = (const char *)L->base + h->symref;
	return kgenome_nucleo_hands_on(h->cap, nm);
}

/* The words an i386 stdcall callee pops for this node, from the name it was reached by; -1 when the name is not
 * in the table (or the node has none). Asked once per node. */
static int site_pop(struct kgenome_lineage *L, uint32_t node)
{
	const struct kgenome_diag_hit *h = &L->s->hit[node];
	unsigned c;

	if (!L->argc)
		return -1;
	if (L->argc[node] == -2) {
		c = (h->bits & KGENOME_DIAG_H_SYMREF) && h->symref < L->size
		    ? kgenome_emu_win_argc_of_name((const char *)L->base + h->symref) : KGENOME_EMU_WIN_ARGC_UNKNOWN;
		L->argc[node] = c == KGENOME_EMU_WIN_ARGC_UNKNOWN ? (int16_t)-1 : (int16_t)c;
	}
	return L->argc[node];
}

/* Is this call one the program does not come back from: an import by name (the symbol route found it), or a function of the object
 * that has no way to return (diag_lineage_summ.c). */
int kgenome_lineage_call_noreturn(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in)
{
	uint32_t f;

	if (kgenome_diag_site_noreturn(L->s, in->at))
		return 1;
	if (!L->noret_fn || (in->flags & KGENOME_CELL_F_INDIRECT) || in->target_va == KGENOME_BROKEN)
		return 0;
	f = kgenome_lineage_fn_of_va(L, in->target_va);
	return f != UINT32_MAX && L->noret_fn[f];
}

/* One call, or a tail jump: `tail` leaves the function. */
static void do_call(struct kgenome_lineage *L, struct kgenome_lineage_state *w,
		    const struct kgenome_cell_insn *in, const struct kgenome_cell_insn *next,
		    int tail, int emit)
{
	struct kgenome_lineage_val ret;
	uint32_t node, callee = UINT32_MAX;
	const int32_t sp0 = w->sp;
	int pop = -1;

	kgenome_lineage_val_unknown(&ret, KGENOME_LINEAGE_W_STATUS);       /* (what a node that hands no handle on returns) */
	/* A jump leaves the return address where it was, so on a stack-passed ABI the callee's arguments
	 * are one word further up than they are for a call. */
	if (tail && w->spok)
		w->sp += L->abi.w;
	if (kgenome_lineage_site_in(L, in, &node)) {
		const struct kgenome_diag_hit *h = &L->s->hit[node];
		unsigned q;

		for (q = 0; q < 6u && emit; q++) {
			uint8_t role = kgenome_diag_role_of_arg(h->cap, q);
			struct kgenome_lineage_val a;

			if (role == KGENOME_DIAG_ROLE_NONE)
				continue;
			a = kgenome_lineage_arg(L, w, q);
			kgenome_lineage_agg_add(L, node, role, &a, w->seeded);
		}
		if (kgenome_lineage_hands_on(L, h)) {
			if (node < KGENOME_LINEAGE_PARAM) {
				kgenome_lineage_val_other(&ret);
				ret.other = 0;
				ret.why = 0;
				ret.t[0] = (uint16_t)node;
				ret.n = 1;
			} else {        /* a node past the 15 bits a token holds: its result is not followed, and the scan says so */
				kgenome_lineage_val_unknown(&ret, KGENOME_LINEAGE_W_LIMIT);
				kgenome_lineage_bound(L, KGENOME_LINEAGE_B_VALUE);
			}
		}
		pop = L->abi.callee_pops ? site_pop(L, node) : -1;
	} else {
		/* (a call to the next instruction is no call of a function: the get-pc idiom, and in a relocatable object the hole a
		 * relocation fills, whose displacement is zero) */
		if (!(in->flags & KGENOME_CELL_F_INDIRECT) && in->target_va != KGENOME_BROKEN && in->target_va != in->at_va + in->len)
			callee = kgenome_lineage_fn_of_va(L, in->target_va);
		if (callee != UINT32_MAX && (L->plan & KGENOME_LINEAGE_S_SUMM))
			kgenome_lineage_apply(L, w, callee, &ret, emit, (L->act & KGENOME_LINEAGE_S_SUMM) != 0);
		else
			kgenome_lineage_val_unknown(&ret, callee != UINT32_MAX ? KGENOME_LINEAGE_W_CALL : KGENOME_LINEAGE_W_EXT);
		if (callee != UINT32_MAX && L->abi.callee_pops && L->pop && L->pop[callee] >= 0)
			pop = L->pop[callee] / L->abi.w;
		else if (L->abi.callee_pops && L->pop && (in->flags & KGENOME_CELL_F_INDIRECT) && in->n_op &&
			 in->o[0].kind == KGENOME_CELL_O_MEM && in->o[0].reg == KGENOME_CELL_REG_NONE &&
			 in->o[0].index == KGENOME_CELL_REG_NONE)
			pop = kgenome_lineage_slot_pop(L, (uint64_t)in->o[0].disp & 0xffffffffu);
	}
	w->sp = sp0;
	if (tail) {
		if (emit && !w->seeded)
			out_ret(L, &ret);
		return;
	}
	kgenome_lineage_state_call(L, w, next, &ret, pop);
}

int kgenome_lineage_jmp_is_tail(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in)
{
	uint32_t node;

	if (kgenome_lineage_site_in(L, in, &node))
		return 1;
	if (in->flags & KGENOME_CELL_F_INDIRECT)
		return 0;
	return in->target_va == KGENOME_BROKEN || find_va(L, in->target_va) == UINT32_MAX;
}

/* One visit of block `b`: step its instructions from the state at its top. Without `emit` the result is
 * joined into the successors; with it the links and the summary are written and nothing is joined. */
static void block_run(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, uint32_t b, int emit)
{
	struct kgenome_lineage_state w;
	const uint32_t first = g->bfirst[b], end = g->bfirst[b + 1u];
	uint32_t i;
	int exits = 0;

	if (!kgenome_lineage_state_copy(L, &w, &g->bs[b]))
		return;
	L->act = g->bact[b];
	for (i = first; i < end; i++) {
		const struct kgenome_cell_insn *in = &L->in[i], *next = i + 1u < L->n_in ? &L->in[i + 1u] : NULL;

		if (g->left)
			g->left--;
		else
			g->cut = 1;
		L->steps++;
		switch (in->op) {
		case KGENOME_CELL_CALL:
			do_call(L, &w, in, next, 0, emit);
			if (kgenome_lineage_call_noreturn(L, in)) {
				/* nothing after it is this function's: not the rest of the block, not the next block */
				exits = 1;
				i = end - 1u;
			}
			break;
		case KGENOME_CELL_JMP:
			if (kgenome_lineage_jmp_is_tail(L, in)) {
				do_call(L, &w, in, next, 1, emit);
				exits = 1;
			}
			break;
		case KGENOME_CELL_JCC:
		case KGENOME_CELL_LOOP:
		case KGENOME_CELL_UD:
			break;
		case KGENOME_CELL_RET:
			if (emit && !w.seeded) {
				struct kgenome_lineage_val r = w.r[KGENOME_CELL_REG_AX];

				out_ret(L, &r);
			}
			exits = 1;
			break;
		default:
			kgenome_lineage_state_step(L, &w, in);
		}
	}
	if (!emit && !exits) {
		const struct kgenome_cell_insn *last = &L->in[end - 1u];
		int fall = 1;

		if (is_branch(last) && !(last->flags & KGENOME_CELL_F_INDIRECT) && last->target_va != KGENOME_BROKEN) {
			uint32_t j = find_va(L, last->target_va);

			if (j != UINT32_MAX)
				propagate(L, g, block_of(g, j), &w);
		}
		if (last->op == KGENOME_CELL_JMP || last->op == KGENOME_CELL_UD)
			fall = 0;
		if (fall && end < L->n_in)
			propagate(L, g, b + 1u, &w);
	}
	kgenome_lineage_state_free(L, &w);
}

int kgenome_lineage_cfg_run(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g)
{
	while (g->nw) {
		uint32_t b = g->wl[g->head];

		g->head = (g->head + 1u) % g->nb;
		g->nw--;
		g->inq[b] = 0;
		block_run(L, g, b, 0);
		if (g->cut || L->halt)
			return 0;
		if (L->s->bud.max_steps && L->steps > L->s->bud.max_steps) {
			L->over_steps = 1;
			kgenome_diag_note(L->s, KGENOME_OVER_BUDGET);
			return 0;
		}
	}
	return 1;
}

/* Emit the links and the summary from every block the walk reached (and, after the seed stage, those it entered). */
static void emit_blocks(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, const uint8_t *skip)
{
	uint32_t b;

	for (b = 0; b < g->nb && !L->halt; b++)
		if (g->bs[b].valid && !(skip && skip[b]))
			block_run(L, g, b, 1);
}

static void out_reset(struct kgenome_lineage_out *o)
{
	if (!o)
		return;
	o->n_sink = 0;
	o->ret_seen = 0;
	memset(&o->ret, 0, sizeof o->ret);
}

/* The blocks no walk from the entry reached are entered as seeds - those the SEED row of the table names (every one, when
 * the run is the eager reference) - and what they reach is emitted: the links are MAY. Returns the blocks entered. */
static uint32_t seed_phase(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g)
{
	const int eager = (L->plan & KGENOME_LINEAGE_S_EAGER) != 0;
	uint32_t b, seeded = 0;
	uint8_t *had;

	if (eager ? !(L->plan & KGENOME_LINEAGE_S_SEED) : !kgenome_lineage_seed_wanted(L, g))
		return 0;
	had = malloc(g->nb);
	if (!had) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return 0;
	}
	for (b = 0; b < g->nb; b++)
		had[b] = g->bs[b].valid;
	kgenome_lineage_seed(L, g, eager);
	if (!g->cut && !L->over_steps && !L->halt) {
		for (b = 0; b < g->nb; b++)
			seeded += g->bs[b].valid && !had[b];
		/* what a seed entered is reached now: the stages that follow a walk look at it (a store in it is one LOCS follows) */
		kgenome_lineage_mark_unreached(g);
		L->fn_store = kgenome_lineage_has_store(g);
		emit_blocks(L, g, had);
	}
	free(had);
	return seeded;
}

/* One run of the function's blocks with the stages in L->run: the fixpoint from the entry, then what it says at the sites -
 * and, when `seed`, the seeded blocks too. */
static int run_once(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, int seed)
{
	struct kgenome_lineage_state e;
	uint32_t b;

	for (b = 0; b < g->nb; b++) {
		kgenome_lineage_state_free(L, &g->bs[b]);
		memset(&g->bs[b], 0, sizeof g->bs[b]);
	}
	memset(g->inq, 0, g->nb);
	g->head = g->nw = 0;
	g->cut = 0;
	g->left = 64u * (uint64_t)L->n_in + 4096u;
	for (b = 0; b < g->nb; b++)
		g->bact[b] = (uint8_t)kgenome_lineage_act(L, g->bpred[b]);       /* once a run, not once a visit */
	L->pend = 0;
	L->nseeded = 0;
	tab_reset(L, &L->loc);
	out_reset(L->out);
	kgenome_lineage_state_entry(L, &e, (L->plan & KGENOME_LINEAGE_S_SUMM) != 0);
	kgenome_lineage_cfg_enter(g, 0, &e);
	if (!kgenome_lineage_cfg_run(L, g))
		return 0;
	kgenome_lineage_mark_unreached(g);
	L->fn_store = kgenome_lineage_has_store(g);
	emit_blocks(L, g, NULL);
	if (L->halt)
		return 0;
	if (seed)
		L->nseeded = seed_phase(L, g);
	return !g->cut && !L->over_steps && !L->halt;
}

/*
 * SOLVE ONE FUNCTION, as a chain (diag_lineage_chain.c). The blocks and what each holds are made once; FLOW runs;
 * the obligations it leaves ask for the stages their reasons name, and the function is run again with them - not
 * with every stage there is. Only the last run's links and summary are kept: an earlier run knew less, and what it
 * could not follow it wrote as unknown, which would make a sure link a doubtful one if it were added to the last's.
 *
 * The bound is on the cost of a function a hostile object makes enormous or pathological: 64 instructions stepped per
 * instruction it has, and a floor, for each run. A function that does not converge inside it writes NO links - states left
 * in the middle of an iteration would give a MUST that the rest of the iteration takes back - and the scan says
 * KGENOME_TRUNCATED.
 */
void kgenome_lineage_solve(struct kgenome_lineage *L, uint32_t fi, struct kgenome_lineage_out *out)
{
	struct kgenome_lineage_cfg g;
	uint8_t *ld = NULL;
	uint32_t i, b, nb;
	unsigned nruns = 1, seeded = 0;
	uint64_t cost;
	int ok;

	L->out = out;
	L->cur_fn = fi;
	L->ag = &L->loc;
	if (!kgenome_lineage_decode(L, fi) || !L->n_in)
		return;
	memset(&g, 0, sizeof g);
	cost = (uint64_t)L->n_in * (1u + 4u + 1u) + 8u;
	if (!kgenome_lineage_charge(L, cost))
		return;
	ld = calloc(L->n_in, 1);
	if (!ld) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		kgenome_lineage_uncharge(L, cost);
		return;
	}
	nb = leaders(L, ld);
	{
		const uint64_t gc = (uint64_t)nb * (sizeof *g.bs + sizeof *g.wl + 1u + sizeof *g.bpred + sizeof *g.bact) +
				    (uint64_t)(nb + 1u) * sizeof *g.bfirst;

		if (!kgenome_lineage_charge(L, gc)) {
			free(ld);
			kgenome_lineage_uncharge(L, cost);
			return;
		}
		g.nb = nb;
		g.bs = calloc(nb, sizeof *g.bs);
		g.wl = calloc(nb, sizeof *g.wl);
		g.inq = calloc(nb, 1);
		g.bpred = calloc(nb, sizeof *g.bpred);
		g.bact = calloc(nb, sizeof *g.bact);
		g.bfirst = calloc((size_t)nb + 1u, sizeof *g.bfirst);
		if (!g.bs || !g.wl || !g.inq || !g.bfirst || !g.bpred || !g.bact) {
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			L->halt = 1;
		}
		if (!L->halt) {
			for (i = 0, b = 0; i < L->n_in; i++)
				if (ld[i])
					g.bfirst[b++] = i;
			g.bfirst[nb] = L->n_in;
			kgenome_lineage_preds(L, &g);
			L->run = (L->plan & KGENOME_LINEAGE_S_EAGER) ? (L->plan & ~KGENOME_LINEAGE_S_EAGER) : KGENOME_LINEAGE_S_FLOW;
			/* The seeds wait for the last run: most functions are read once, and a seeded block is read at
			 * the end of it. What the seeds leave unaccounted for joins the obligations, and when it asks for a
			 * stage the function is run again, with its seeds. */
			ok = run_once(L, &g, 0);
			while (ok) {
				const unsigned next = (L->plan & KGENOME_LINEAGE_S_EAGER) ? 0u : kgenome_lineage_chain_next(L, &g);

				if (next) {
					L->run |= next;
					nruns++;
					ok = run_once(L, &g, (int)seeded);
					continue;
				}
				if (seeded)
					break;
				seeded = 1;
				L->nseeded = seed_phase(L, &g);
				ok = !g.cut && !L->over_steps && !L->halt;
			}
			/* A function that asked for a callee to be read (W_SKIP pending) is read again once it is: what this solve found is not
			 * merged, it would stay in the table beside what the second finds */
			if (ok && L->can_defer && !L->no_defer && L->n_need && (L->pend & KGENOME_LINEAGE_W_SKIP) && !L->dry) {
				L->deferred = 1;
			} else if (ok) {
				if (!L->dry)
					merge_loc(L);
				kgenome_lineage_stats_fn(L, &g, nruns, L->nseeded);
			} else if (g.cut) {
				kgenome_lineage_bound(L, KGENOME_LINEAGE_B_STEPS);
			}
			for (b = 0; b < nb; b++)
				kgenome_lineage_state_free(L, &g.bs[b]);
		}
		free(g.bs);
		free(g.wl);
		free(g.inq);
		free(g.bpred);
		free(g.bact);
		free(g.bfirst);
		kgenome_lineage_uncharge(L, gc);
	}
	free(ld);
	kgenome_lineage_uncharge(L, cost);
	L->out = NULL;
}
