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
#include "diag_oatab.h"

/* ---- the decoded body ---- */

static void collect(void *user, const struct kgenome_cell_insn *in)
{
	struct kgenome_lineage *L = user;

	if (!in) {
		L->n_skip++;            /* bytes that decoded as nothing: the frame is told, so its graph is the cut one it always was */
		return;
	}
	if (L->halt)
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

int kgenome_lineage_decode(struct kgenome_lineage *L, const struct kgenome_lineage_fn *f)
{
	L->n_in = 0;
	L->n_skip = 0;
	/* KNOWN DEFECT CS-2 (2026-10-30, M) [sev M]: kgenome_lineage_decode decodes the whole extent linearly, so literal pools, padding and jump-table data become instructions and leaders() makes blocks of them.
	 * Trigger: a function with an inline pool or trailing data (ARM, x86-64, MIPS). Effect: blocks with no incoming edge: 13% of ARM, 10.9% of x86-64, 2.3% of MIPS; 2088 UD on ARM; every signature built on them is polluted.
	 * Reproducer: /mnt/games/normtest/briefs/cfg_decision.md (section EVIDENCE) and /mnt/games/normtest/fix_cfg_survey/h/cfgsv.c.
	 * Fix: build blocks from the entry only (reachable blocks): the cfg builder lifted from this unit; this comment goes with the swap (CS-3). */
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

/*
 * THE TABLES OF WHAT REACHES A CONSUMER are the diagnose family's one open-addressing table (diag_oatab.h: when it grows, how its entries
 * move), keyed by (node + 1) << 8 | role. The probe is here once, for the insert and for the lookup the unresolved set asks
 * (kgenome_lineage_agg_get): it was written twice, in this file and in diag_lineage_chain.c, each with its own unseeded multiplicative hash
 * (REV-D7a, REV-D7b). The key is no name a file chooses - a node index the scan assigned in order and a role - so the hash needs no seed of
 * the text: it is the table's own finaliser (kgenome_oatab_fold), which spreads the dense indices over every slot bit.
 */
static uint32_t agg_hash(uint32_t k)
{
	return kgenome_oatab_fold((uint64_t)k * KGENOME_OATAB_K);
}

static uint32_t agg_slot_hash(void *ctx, const void *slot)
{
	(void)ctx;
	return agg_hash(((const struct kgenome_lineage_agg *)slot)->key);
}

/* The cell of `key`: the occupied one, or (insert) the empty one it goes in; NULL when absent and not inserting, or when memory or the
 * ledger refused the table's growth. */
static struct kgenome_lineage_agg *agg_slot(struct kgenome_lineage *L, struct kgenome_lineage_aggtab *t, uint32_t key, int insert)
{
	uint32_t i;

	if (insert) {
		const uint32_t nc = kgenome_oatab_want(t->n, t->cap, 256u);

		if (nc) {
			const uint32_t oc = t->cap;

			if (!kgenome_lineage_charge(L, (uint64_t)nc * sizeof *t->v))
				return NULL;
			if (!kgenome_oatab_rehash((void **)&t->v, &t->cap, nc, sizeof *t->v, agg_slot_hash, NULL, NULL)) {
				kgenome_lineage_uncharge(L, (uint64_t)nc * sizeof *t->v);
				kgenome_diag_note(L->s, KGENOME_NOMEM);
				L->halt = 1;
				return NULL;
			}
			if (oc)
				kgenome_lineage_uncharge(L, (uint64_t)oc * sizeof *t->v);
		}
	}
	if (!t->cap)
		return NULL;
	for (i = agg_hash(key) & (t->cap - 1u); t->v[i].key; i = kgenome_oatab_next(i, t->cap))
		if (t->v[i].key == key)
			return &t->v[i];
	if (!insert)
		return NULL;
	t->v[i].key = key;
	t->n++;
	return &t->v[i];
}

static struct kgenome_lineage_agg *agg_find(struct kgenome_lineage *L, struct kgenome_lineage_aggtab *t, uint32_t key)
{
	return agg_slot(L, t, key, 1);
}

const struct kgenome_lineage_agg *kgenome_lineage_agg_get(const struct kgenome_lineage_aggtab *t, uint32_t key)
{
	return agg_slot(NULL, (struct kgenome_lineage_aggtab *)(uintptr_t)t, key, 0);
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
	t->nx = 0;                      /* (its pool is the table's: emptied with it, kept for the next run) */
}

/* ---- the producers of a consumer: sixteen in the cell, the rest in the table's pool ---- */

void kgenome_lineage_agg_toks(const struct kgenome_lineage_aggtab *t, const struct kgenome_lineage_agg *a, uint16_t *out)
{
	uint32_t k, c;

	for (k = 0; k < a->n && k < KGENOME_LINEAGE_SET; k++)
		out[k] = a->t[k];
	for (c = a->more; c && k < a->n; c = t->x[c - 1u].next)
		out[k++] = t->x[c - 1u].tok;
}

static int agg_has(const struct kgenome_lineage_aggtab *t, const struct kgenome_lineage_agg *a, uint16_t tok)
{
	uint32_t k, c;

	for (k = 0; k < a->n && k < KGENOME_LINEAGE_SET; k++)
		if (a->t[k] == tok)
			return 1;
	for (c = a->more; c; c = t->x[c - 1u].next)
		if (t->x[c - 1u].tok == tok)
			return 1;
	return 0;
}

/* One more producer of `a`. The pool is charged to the ledger; when it refuses, the producer is lost and that is said (W_LIMIT, the bound
 * counted, the scan KGENOME_TRUNCATED) - the one bound left is the budget's. The test for a repeat walks the producers: a consumer of n
 * producers costs n per add (measured: the most any consumer of the 356-file A/B set held was below a hundred). */
static void agg_tok_add(struct kgenome_lineage *L, struct kgenome_lineage_aggtab *t, struct kgenome_lineage_agg *a, uint16_t tok)
{
	if (agg_has(t, a, tok))
		return;
	if (a->n < KGENOME_LINEAGE_SET) {
		a->t[a->n++] = tok;
		return;
	}
	if (t->nx == t->capx) {
		const uint32_t nc = kgenome_grow_cap(t->capx, 64u);
		struct kgenome_lineage_aggx *nx;

		if (!nc || !kgenome_lineage_charge(L, (uint64_t)(nc - t->capx) * sizeof *nx))
			goto lost;
		nx = realloc(t->x, (size_t)nc * sizeof *nx);
		if (!nx) {
			kgenome_lineage_uncharge(L, (uint64_t)(nc - t->capx) * sizeof *nx);
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			goto lost;
		}
		t->x = nx;
		t->capx = nc;
	}
	t->x[t->nx].tok = tok;
	t->x[t->nx].next = a->more;
	a->more = ++t->nx;
	a->n++;
	return;
lost:
	a->other = 1;
	a->why |= KGENOME_LINEAGE_W_LIMIT;
	kgenome_lineage_bound(L, KGENOME_LINEAGE_B_CONSUMER);
}

/* What the last run of a function found goes into the object's table: the union of every context's value. */
static void merge_loc(struct kgenome_lineage *L)
{
	uint32_t k;

	for (k = 0; k < L->loc.cap; k++) {
		const struct kgenome_lineage_agg *x = &L->loc.v[k];
		struct kgenome_lineage_agg *a;
		uint32_t i;

		if (!x->key)
			continue;
		a = agg_find(L, &L->glob, x->key);
		if (!a)
			return;
		{
			uint32_t c;

			for (i = 0; i < x->n && i < KGENOME_LINEAGE_SET; i++)
				agg_tok_add(L, &L->glob, a, x->t[i]);
			for (c = x->more; c; c = L->loc.x[c - 1u].next)
				agg_tok_add(L, &L->glob, a, L->loc.x[c - 1u].tok);
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
	uint32_t i;

	/* what is unknown of the value is what the run's obligations are made of (a constant is not one) */
	if (v->other)
		L->pend |= (settle_why(L, v->why) & ~KGENOME_LINEAGE_W_CONST);
	/* A pass that only learns a summary (a recursive group iterating) writes no link. */
	if (!L->dry) {
		a = agg_find(L, L->ag, ((node + 1u) << 8) | role);
		if (!a)
			return;
	}
	{
		uint16_t tk0[KGENOME_LINEAGE_VAL_INLINE], *tk = tk0;
		const uint32_t nt = kgenome_lineage_val_toks(L, v, tk0, KGENOME_LINEAGE_VAL_INLINE);

		if (nt > KGENOME_LINEAGE_VAL_INLINE) {
			tk = malloc((size_t)nt * sizeof *tk);
			if (!tk) {
				kgenome_diag_note(L->s, KGENOME_NOMEM);
				L->halt = 1;
				return;
			}
			(void)kgenome_lineage_val_toks(L, v, tk, nt);
		}
		for (i = 0; i < nt; i++) {
			if (tk[i] & KGENOME_LINEAGE_PARAM) {
				out_sink(L, node, role, (uint8_t)(tk[i] & 0xffu));
				if (a)
					a->param = 1;
				continue;
			}
			/* A STATUS token (a node's result that is no handle) is a producer of a system call's NUMBER only; at any other input it is
			 * what it was before it was a token, a value no producer names, for the reason W_STATUS. */
			if ((tk[i] & KGENOME_LINEAGE_STATUS) && role != KGENOME_DIAG_ROLE_NUMBER) {
				L->pend |= KGENOME_LINEAGE_W_STATUS;
				if (a) {
					a->other = 1;
					a->why |= KGENOME_LINEAGE_W_STATUS;
				}
				continue;
			}
			if (!a || KGENOME_LINEAGE_TOK_NODE(tk[i]) == node)      /* a node's own result coming round a loop is not a link to itself */
				continue;
			agg_tok_add(L, L->ag, a, tk[i]);
		}
		if (tk != tk0)
			free(tk);
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

/* ---- the blocks ----
 * The blocks and their successors are the function's FRAME's (phenotype/frame.h: celllysis/cfg.h's graph, built once for the lineage and the signature alike, with the real
 * byte order); what is here is what the fixpoint does over them. The frame is read only. A function that is not an entry of the engine's table has its frame made for this solve
 * and given back at its end, through the lineage's ledger. */

static void *fr_alloc(void *user, size_t n)
{
	struct kgenome_lineage *L = user;
	void *p;

	if (!kgenome_lineage_charge(L, n))
		return NULL;
	p = malloc(n);
	if (!p) {
		kgenome_lineage_uncharge(L, n);
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		L->halt = 1;
	}
	return p;
}

static void fr_release(void *user, void *p, size_t n)
{
	if (!p)
		return;
	free(p);
	kgenome_lineage_uncharge(user, n);
}

void kgenome_lineage_frame_src(struct kgenome_lineage *L, const struct kgenome_func_set *table)
{
	L->fsrc = (struct kgenome_frame_src){ .obj = L->obj, .base = L->base, .size = L->size, .fs = table, .wk = L->wk,
					      .mem = { fr_alloc, fr_release, L }, .facts = 1 };
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

/*
 * THE NODE'S RESULT IS AN OBJECT a later call is handed: the answer of the node's ROW (the import it is, kgenome_diag_hit.row), its
 * capability's when the route that made it knew no row. It read the node's `symref` as the callee's name, which is the symbol an
 * ARGUMENT named on a kernel module's node (KGENOME_DIAG_H_SYMREF): the row of that symbol answered for the call.
 */
int kgenome_lineage_hands_on(const struct kgenome_diag_hit *h)
{
	return kgenome_nucleo_call_hands_on(h->cap, h->row);
}

/* The words an i386 stdcall callee pops for this node, from the name of its row (an import by ordinal has one too); -1 when the
 * name is not in the table (or the node has no row). Asked once per node. */
static int site_pop(struct kgenome_lineage *L, uint32_t node)
{
	const struct kgenome_diag_hit *h = &L->s->hit[node];
	const char *nm;
	unsigned c;

	if (!L->argc)
		return -1;
	if (L->argc[node] == -2) {
		nm = kgenome_nucleo_name_of(h->row);
		c = nm ? kgenome_emu_win_argc_of_name(nm) : KGENOME_EMU_WIN_ARGC_UNKNOWN;
		L->argc[node] = c == KGENOME_EMU_WIN_ARGC_UNKNOWN ? (int16_t)-1 : (int16_t)c;
	}
	return L->argc[node];
}

/* Is this call one the program does not come back from: an import by name (the symbol route found it), or a function of the object
 * that has no way to return (diag_lineage_summ.c). */
int kgenome_lineage_call_noreturn(struct kgenome_lineage *L, const struct kgenome_cell_insn *in)
{
	uint32_t f;

	if (kgenome_diag_site_noreturn(L->s, in->at))
		return 1;
	if (!L->noret_fn || (in->flags & KGENOME_CELL_F_INDIRECT) || in->target_va == KGENOME_BROKEN)
		return 0;
	f = kgenome_lineage_fn_of_insn(L, in);
	return f != UINT32_MAX && kgenome_lineage_noret(L, f);
}

/* ---- THE SITE DISPATCHER: how a node takes its inputs ---- */

int kgenome_lineage_is_kentry(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in)
{
	if (in->op != KGENOME_CELL_SYSCALL && in->op != KGENOME_CELL_INT)
		return 0;
	if (in->at + 2u > L->size)
		return 0;
	/* the routes' own test, so a node the sweep made at a kernel entry is one this stage reads as one */
	return kgenome_diag_kernel_entry(L->obj, in->op, in->op == KGENOME_CELL_INT && in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM &&
					 in->o[0].imm == 0x80u, L->base + in->at);
}

enum kgenome_lineage_conv kgenome_lineage_site_conv(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in, uint32_t node)
{
	if (kgenome_lineage_is_kentry(L, in))
		return KGENOME_LINEAGE_C_SYS;
	/* a branch into memory a node made: what it runs is its operand, it passes no argument */
	if (L->s->hit[node].cap == KGENOME_NUCLEO_EXEC_REG && (in->flags & KGENOME_CELL_F_INDIRECT) && in->n_op)
		return KGENOME_LINEAGE_C_BRANCH;
	return KGENOME_LINEAGE_C_CALL;
}

/* The value input `q` of a site holds under its convention. */
static struct kgenome_lineage_val site_input(const struct kgenome_lineage *L, const struct kgenome_lineage_state *w, enum kgenome_lineage_conv conv,
					     unsigned q)
{
	struct kgenome_lineage_val v;

	if (conv != KGENOME_LINEAGE_C_SYS)
		return kgenome_lineage_arg(L, w, q);
	if (q < L->abi.n_sys_arg && L->abi.sys_arg[q] < 16u)
		return w->r[L->abi.sys_arg[q]];
	kgenome_lineage_val_other(&v);
	return v;
}

/*
 * A NODE IS REACHED: its inputs are added to what reaches it, and the value it hands back is answered. Every input the node has is
 * read, under the site's convention: the arguments its capability's roles name (a call's, or a system call's), the TARGET of a branch
 * node, and the NUMBER of a system call - the register that chose which call it is. The number is an input like any other: what reaches
 * it says whether it was a constant, a parameter of the function, or the RESULT of an earlier node (msfvenom's stager reads `read`'s
 * number out of connect's zero): its producers are links of role NUMBER, and the node's number class (kgenome_diag_hit.nr) is written
 * with them. The result: a handle is its node's token, any other answer is the node's STATUS token (diag_lineage_private.h).
 */
static void site_take(struct kgenome_lineage *L, struct kgenome_lineage_state *w, const struct kgenome_cell_insn *in, uint32_t node,
		      int emit, struct kgenome_lineage_val *ret)
{
	const struct kgenome_diag_hit *h = &L->s->hit[node];
	const enum kgenome_lineage_conv conv = kgenome_lineage_site_conv(L, in, node);
	struct kgenome_lineage_val a;
	unsigned q;

	if (emit) {
		if (conv == KGENOME_LINEAGE_C_BRANCH) {
			kgenome_lineage_read_op(L, w, in, &in->o[0], &a);
			kgenome_lineage_agg_add(L, node, KGENOME_DIAG_ROLE_TARGET, &a, w->seeded);
		} else {
			for (q = 0; q < 6u; q++) {
				const uint8_t role = kgenome_nucleo_call_role(h->cap, h->row, q);

				if (role == KGENOME_DIAG_ROLE_NONE)
					continue;
				a = site_input(L, w, conv, q);
				kgenome_lineage_agg_add(L, node, role, &a, w->seeded);
			}
		}
		if (conv == KGENOME_LINEAGE_C_SYS && L->abi.sys_nr < 16u)
			kgenome_lineage_agg_add(L, node, KGENOME_DIAG_ROLE_NUMBER, &w->r[L->abi.sys_nr], w->seeded);
	}
	if (node >= KGENOME_LINEAGE_NODE_MAX) {
		/* a node past what a token holds: its result is not followed, and the scan says so */
		kgenome_lineage_val_unknown(ret, kgenome_lineage_hands_on(h) ? KGENOME_LINEAGE_W_LIMIT : KGENOME_LINEAGE_W_STATUS);
		if (kgenome_lineage_hands_on(h))
			kgenome_lineage_bound(L, KGENOME_LINEAGE_B_VALUE);
		return;
	}
	memset(ret, 0, sizeof *ret);
	ret->n = 1;
	ret->t[0] = (uint16_t)(kgenome_lineage_hands_on(h) ? node : node | KGENOME_LINEAGE_STATUS);
}

/* A kernel entry: a node's inputs and answer when the scan has one here; what the kernel destroys either way. */
static void do_sys(struct kgenome_lineage *L, struct kgenome_lineage_state *w, const struct kgenome_cell_insn *in, int emit)
{
	struct kgenome_lineage_val ret;
	uint32_t node;
	unsigned i;

	if (!kgenome_lineage_site_in(L, in, &node)) {
		/* no node (a number the vocabulary has no word for, or one that could not be read): what it was before the dispatcher */
		kgenome_lineage_state_step(L, w, in);
		return;
	}
	site_take(L, w, in, node, emit, &ret);
	for (i = 0; i < L->abi.n_sys_clob; i++)
		kgenome_lineage_val_unknown(&w->r[L->abi.sys_clob[i]], KGENOME_LINEAGE_W_CLOBBER);
	w->r[L->abi.ret] = ret;
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

	/* A jump leaves the return address where it was, so on a stack-passed ABI the callee's arguments
	 * are one word further up than they are for a call. */
	if (tail && w->spok)
		w->sp += L->abi.w;
	if (kgenome_lineage_site_in(L, in, &node)) {
		site_take(L, w, in, node, emit, &ret);
		pop = L->abi.callee_pops ? site_pop(L, node) : -1;
	} else {
		/* (a call to the next instruction is no call of a function: the get-pc idiom, and in a relocatable object the hole a
		 * relocation fills, whose displacement is zero) */
		if (!(in->flags & KGENOME_CELL_F_INDIRECT) && in->target_va != KGENOME_BROKEN && in->target_va != in->at_va + in->len)
			callee = kgenome_lineage_fn_of_insn(L, in);
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

int kgenome_lineage_jmp_is_tail(const struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g, uint32_t b,
				const struct kgenome_cell_insn *in)
{
	uint32_t node;

	if (kgenome_lineage_site_in(L, in, &node))
		return 1;
	if (in->flags & KGENOME_CELL_F_INDIRECT)
		return 0;
	/* a direct jump whose target is an instruction of the function ends its block as a JUMP with an edge; any other leaves it */
	return g->cfg.b[b].term != KGENOME_CFG_T_JUMP;
}

/* One visit of block `b`: step its instructions from the state at its top. Without `emit` the result is
 * joined into the successors; with it the links and the summary are written and nothing is joined. */
static void block_run(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, uint32_t b, int emit)
{
	struct kgenome_lineage_state w;
	const uint32_t first = kgenome_lineage_bfirst(g, b), end = kgenome_lineage_bend(g, b);
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
			if (kgenome_lineage_jmp_is_tail(L, g, b, in)) {
				do_call(L, &w, in, next, 1, emit);
				exits = 1;
			}
			break;
		case KGENOME_CELL_JCC:
		case KGENOME_CELL_LOOP:
		case KGENOME_CELL_UD:
			break;
		case KGENOME_CELL_SYSCALL:
		case KGENOME_CELL_INT:
			if (!kgenome_lineage_is_kentry(L, in)) {
				kgenome_lineage_state_step(L, &w, in);
				break;
			}
			{
				/*
				 * EXIT AND EXIT_GROUP do not return: the routes list them with the imports that never do (kgenome_diag_noret_add) - by
				 * the number the SWEEP read, in address order, which can be wrong where the paths into the site disagree (`push rax;
				 * ...; pop rax` after an exit block hands the sweep the exit's 60 at a `read`). So the stage takes the word only where
				 * its own state agrees that the number is a constant on every path into this instruction; it computes no value, so
				 * two paths that load two different constants are not told apart (a limit, said; the next algorithm is a value set
				 * per register, which the stage does not keep by design).
				 */
				const struct kgenome_lineage_val *nr = &w.r[L->abi.sys_nr];
				const int nr_const = nr->n == 0u && nr->other && nr->why == KGENOME_LINEAGE_W_CONST;

				do_sys(L, &w, in, emit);
				if (nr_const && kgenome_diag_site_noreturn(L->s, in->at)) {
					exits = 1;
					i = end - 1u;
				}
			}
			break;
		case KGENOME_CELL_RET:
			/* where the flow goes after it is the block's successors: none, or - an ARM conditional return - the fall-through */
			if (emit && !w.seeded) {
				struct kgenome_lineage_val r = w.r[L->abi.ret];

				out_ret(L, &r);
			}
			break;
		default:
			kgenome_lineage_state_step(L, &w, in);
		}
	}
	if (!emit && !exits) {
		unsigned e;

		for (e = 0; e < 2u; e++) {
			const uint32_t succ = g->cfg.b[b].succ[e];

			if (succ != KGENOME_CFG_NONE)
				propagate(L, g, succ, &w);
		}
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
	struct kgenome_lineage_fn fn;
	const struct kgenome_lineage_fn *f = &fn;
	struct kgenome_frame own_fr;
	const struct kgenome_frame *fr;
	uint32_t b, nb;
	unsigned nruns = 1, seeded = 0;
	int ok;

	L->out = out;
	L->cur_fn = fi;
	L->ag = &L->loc;
	L->nvx = 0;                     /* the token chains of the last solve's values: its summary is published, nothing names them now */
	if (!kgenome_lineage_fn_get(L, fi, &fn) || !kgenome_lineage_decode(L, &fn) || !L->n_in)
		return;
	memset(&own_fr, 0, sizeof own_fr);
	memset(&g, 0, sizeof g);
	/* the function's instructions are read: a frame not yet made is made from them and decodes nothing */
	L->fsrc.pre = &(const struct kgenome_frame_insns){ .v = L->in, .n = L->n_in, .skipped = L->n_skip, .off = f->off, .len = f->len };
	fr = kgenome_frame_of_extent(L->frames, &L->fsrc, f->off, f->len, &own_fr);
	L->fsrc.pre = NULL;
	if (!fr) {
		L->out = NULL;      /* a refused charge was noted by the ledger, a failed allocation by fr_alloc */
		return;
	}
	if (fr->state != KGENOME_FRAME_OK || fr->n_insn != L->n_in) {
		/* No graph (undecodable at the entry, no rules, over the allowance): nothing to solve here. A count that differs from the decode just read is a frame
		 * that is not this function's: said, and not solved. */
		if (fr->state == KGENOME_FRAME_OK)
			kgenome_diag_note(L->s, KGENOME_BAD_INPUT);
		/* (a frame is UNSUPPORTED only for an architecture with no control-flow rules, and the lineage runs on x86 alone: kgenome_diag_run_lineage returns for any other, so no frame state
		 * of the other kinds - undecodable, over the allowance, no memory - needs a word of its own here: the frame carries its status and the scan's ledger the refusal) */
		kgenome_frame_release(&own_fr, &L->fsrc.mem);
		L->out = NULL;
		return;
	}
	/* (a graph made from a decode that stopped short is TRUNCATED, and a function whose bytes only decode in part is the ordinary case and not a limit: nothing to say. The one other way a graph
	 * is TRUNCATED is an architecture's delay slot or degraded class, which x86 has none of: with `cut` that is every case this stage meets, so there is no word of its own here.) */
	/* the facts of the blocks: found once for the function, from the instructions just read (a memo of the frame, which the signing never asks for) */
	if (!kgenome_frame_facts(fr, L->in)) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		L->halt = 1;
		kgenome_frame_release(&own_fr, &L->fsrc.mem);
		L->out = NULL;
		return;
	}
	g.fr = fr;
	g.cfg = fr->cfg;
	nb = g.cfg.n_all;
	{
		const uint64_t gc = (uint64_t)nb * (sizeof *g.bs + sizeof *g.wl + 1u + sizeof *g.bpred + sizeof *g.bact);

		if (!kgenome_lineage_charge(L, gc)) {
			kgenome_frame_release(&own_fr, &L->fsrc.mem);
			L->out = NULL;
			return;
		}
		g.nb = nb;
		g.bs = calloc(nb, sizeof *g.bs);
		g.wl = calloc(nb, sizeof *g.wl);
		g.inq = calloc(nb, 1);
		g.bpred = calloc(nb, sizeof *g.bpred);
		g.bact = calloc(nb, sizeof *g.bact);
		if (!g.bs || !g.wl || !g.inq || !g.bpred || !g.bact) {
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			L->halt = 1;
		}
		if (!L->halt) {
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
		kgenome_lineage_uncharge(L, gc);
	}
	kgenome_frame_release(&own_fr, &L->fsrc.mem);       /* a no-op when the frame is the cache's */
	L->out = NULL;
}
