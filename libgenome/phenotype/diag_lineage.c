/*
 * diag_lineage.c - the lineage stages' driver: the object's sites and functions, the stages the plan
 * names, and the links the stages found written onto the nodes. See diag_lineage.h for what the stages
 * are and diag_lineage_private.h for how the files share them.
 *
 * WHERE IT RUNS. After the routes and after the nodes are folded (merge_sites): a stage names a node by
 * its index and an index is only final then. It adds links to nodes the routes made and makes none.
 *
 * WHAT IT READS. The nodes that sit on a call or a jump (a node whose `at` is that instruction), the
 * functions of the object (the engine's function table, read by index), each function's FRAME
 * (phenotype/frame.h), and the code through the shared
 * reader (kgenome_diag_code_run: the walk's trace for an ELF, the decoder for a PE - one decode, whoever
 * asks). An object with no node on a call has nothing to link and costs one pass over its hits.
 *
 * WHAT IT WRITES. One link per (consumer node, argument, producer node), MUST first: a consumer holds four
 * links and a node a route proved is already there, so what is written afterwards is written in the order
 * of how sure it is. A MUST link is PROVEN; the others are KGENOME_DIAG_LINK_MAY (diag_vocab.h).
 */
#include <stddef.h>
#include <stdlib.h>
#include <kofcmp.h>
#include "diag_lineage_private.h"

/* ---- the codemap, the one other thing the stages read once ---- */

const struct kgenome_codemap *kgenome_lineage_codemap(struct kgenome_lineage *L)
{
	if (!L->cm_done) {
		uint64_t bytes;

		L->cm_done = 1;
		if (!kgenome_codemap_build(L->obj, L->base, L->size, NULL, L->wk, &L->cm)) {
			/* a refused build is a map that is missing, and so are the links made through it: said */
			kgenome_diag_note(L->s, L->cm.status ? L->cm.status : KGENOME_NOMEM);
			return NULL;
		}
		bytes = (uint64_t)L->cm.n * sizeof *L->cm.v + (uint64_t)L->cm.n_to * sizeof *L->cm.by_to;
		/* the table is the object's own size and not capped; the ledger says whether the scan may keep it */
		if (!kgenome_lineage_charge(L, bytes)) {
			kgenome_codemap_free(&L->cm);
			L->cm_done = 2;
			return NULL;
		}
		kgenome_diag_note(L->s, L->cm.status);
	}
	return L->cm_done == 1 ? &L->cm : NULL;
}

/* ---- the sites ---- */

static int cmp_site(const void *a, const void *b)
{
	const uint64_t *x = a, *y = b;

	if (x[0] != y[0])
		return x[0] < y[0] ? -1 : 1;
	return x[1] < y[1] ? -1 : x[1] > y[1];
}

/* The nodes with somewhere to be: an offset, a capability. The lowest-numbered of several at one
 * instruction speaks for it (the descriptor of a socket and its non-blocking mark share a call). */
static int sites_build(struct kgenome_lineage *L)
{
	struct kgenome_diag_scan *s = L->s;
	uint64_t (*v)[2];
	uint32_t i, n = 0;

	if (!s->n_hit)
		return 1;
	if (!kgenome_lineage_charge(L, (uint64_t)s->n_hit * (sizeof *v + sizeof *L->site_at + sizeof *L->site_node)))
		return 0;
	v = malloc((size_t)s->n_hit * sizeof *v);
	L->site_at = malloc((size_t)s->n_hit * sizeof *L->site_at);
	L->site_node = malloc((size_t)s->n_hit * sizeof *L->site_node);
	if (!v || !L->site_at || !L->site_node) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		free(v);
		return 0;
	}
	for (i = 0; i < s->n_hit; i++) {
		const struct kgenome_diag_hit *h = &s->hit[i];

		if (h->cap == KGENOME_NUCLEO_NONE || (h->bits & KGENOME_DIAG_H_SUPERSEDED) || h->at == KGENOME_BROKEN)
			continue;
		v[n][0] = h->at;
		v[n][1] = i;
		n++;
	}
	if (n)
		qsort(v, n, sizeof *v, cmp_site);
	for (i = 0; i < n; i++) {
		if (L->n_site && L->site_at[L->n_site - 1u] == v[i][0])
			continue;
		L->site_at[L->n_site] = v[i][0];
		L->site_node[L->n_site++] = (uint32_t)v[i][1];
	}
	free(v);
	return 1;
}

/* ---- the functions ---- */

/*
 * THE FUNCTIONS ARE THE ENGINE'S TABLE (kgenome_diag_funcs: one product, built once, case by case - genotype/image/fntab.h), read by index; the lineage keeps no list of
 * its own. `fi` everywhere in this stage is an index into `L->fs`. What the lineage adds to an index is only what is a fact of the stage: the entry address (below),
 * and the arrays that follow the index (callers, summaries).
 */

/* The address of the code at a file offset. A relocatable object has none (its sections are all at 0): the offset stands for it,
 * which is what every branch of it is relative to. */
static uint64_t fn_va(const struct kgenome_lineage *L, uint64_t off)
{
	uint64_t va = kgenome_image_off_to_addr(L->obj, off);

	return va == KGENOME_BROKEN && L->obj->format == KGENOME_FMT_ELF && kgenome_obj_elf(L->obj)->e_type == KGENOME_ELF_REL ? off : va;
}

int kgenome_lineage_fn_get(const struct kgenome_lineage *L, uint32_t fi, struct kgenome_lineage_fn *out)
{
	const struct kgenome_func *g = &L->fs->v[fi];
	uint64_t va;

	/* AN UNPARTITIONED EXTENT IS NOT A FUNCTION (trust NONE: the object declares no function, fntab_build.c): it has no entry to solve from and no callers, so it is
	 * neither solved nor a call target here; its nodes stay unlinked by the static lineage. LIMIT, named: such an object gets links only from the emulate route (next:
	 * the emulate-gap route reads the same table). A function's further ranges (a chained .pdata part, kgenome_funcs_range) are not read here: the solve covers range 0,
	 * so a node in a far part maps to its function (kgenome_funcs_at) and is not reached by that function's solve (limit; next: the frame over every range).
	 * TODO(owner): default applied 2026-11-16 = NONE units are not solved (measured cost: links apt 118->114, set356 8696->7402, pe120 1137->931, every loss
	 * in code no metadata declares); the alternative is solving a NONE unit from the entry point until the emulate-gap route exists.
	 * A DERIVED function (phase 2, fntab_derive.c: an entry the descent reached and the blocks it reaches) IS solved: it has an entry and a proven body.
	 * TODO(owner): default applied 2026-11-16 = DERIVED units are solved like HIGH ones (their first range, as for every function); the alternative is solving
	 * HIGH units only. Links before/after are reported as information, not as a gate (fix_pmeta5 report). */
	if (g->trust == KGENOME_FN_TRUST_NONE)
		return 0;
	if (g->off >= L->size || !g->len)
		return 0;
	va = fn_va(L, g->off);
	if (va == KGENOME_BROKEN)
		return 0;
	out->off = g->off;
	out->len = g->off + g->len > L->size ? L->size - g->off : g->len;
	out->va = va;
	return 1;
}

/* The function a direct call or jump goes to: the one whose entry ADDRESS is the target's, by a search of the entry addresses (`by_va`, made once for the object: the translation of an address
 * to an offset, a scan of the image's segments, was made again for every call of every solve). A relocatable object has no address map: its entry addresses are its offsets (fn_va). */
uint32_t kgenome_lineage_fn_of_insn(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in)
{
	const uint32_t lo = kof_lower_bound_u64(L->by_va, L->n_by_va, sizeof *L->by_va, 0, in->target_va);

	return lo < L->n_by_va && L->by_va[lo].va == in->target_va ? L->by_va[lo].fn : KGENOME_FUNCS_NONE;
}

_Static_assert(offsetof(struct kgenome_lineage_fnva, va) == 0, "kof_cmp_u64 reads the key from the start");

static int by_va_build(struct kgenome_lineage *L)
{
	uint32_t i;

	if (!L->n_fn)
		return 1;
	if (!kgenome_lineage_charge(L, (uint64_t)L->n_fn * sizeof *L->by_va))
		return 0;
	L->by_va = malloc((size_t)L->n_fn * sizeof *L->by_va);
	if (!L->by_va) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return 0;
	}
	for (i = 0; i < L->n_fn; i++) {
		struct kgenome_lineage_fn fn;

		if (!kgenome_lineage_fn_get(L, i, &fn))
			continue;
		L->by_va[L->n_by_va].va = fn.va;
		L->by_va[L->n_by_va++].fn = i;
	}
	if (L->n_by_va)
		qsort(L->by_va, L->n_by_va, sizeof *L->by_va, kof_cmp_u64);
	return 1;
}

static int fns_build(struct kgenome_lineage *L)
{
	const struct kgenome_func_set *fs = kgenome_diag_funcs(L->s, L->obj);

	L->fs = fs;
	kgenome_lineage_frame_src(L, fs);
	L->n_fn = fs->n;
	return by_va_build(L);
}

/* THE FUNCTION OF EACH END OF EVERY CODEMAP REFERENCE, decided once (it was found again, by a binary search each, by the return counts, the call graph twice - once to count
 * its edges and once to fill them - and the no-return pass). `ref_from` is the function that holds the instruction, `ref_to` the one that holds its target. */
int kgenome_lineage_refs(struct kgenome_lineage *L, const struct kgenome_codemap *cm)
{
	uint32_t k;

	if (L->ref_from || !cm->n)
		return 1;
	if (!kgenome_lineage_charge(L, (uint64_t)cm->n * 2u * sizeof *L->ref_from))
		return 0;
	L->ref_from = malloc((size_t)cm->n * 2u * sizeof *L->ref_from);
	if (!L->ref_from) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return 0;
	}
	L->ref_to = L->ref_from + cm->n;
	for (k = 0; k < cm->n; k++) {
		L->ref_from[k] = kgenome_funcs_at(L->fs, cm->v[k].at);
		L->ref_to[k] = cm->v[k].to == KGENOME_BROKEN ? KGENOME_FUNCS_NONE : kgenome_funcs_at(L->fs, cm->v[k].to);
	}
	return 1;
}

/* THE SITE OF EACH NODE'S FUNCTION, decided once here and read by the site's index (it was found again by every step that asked: the summaries, the chains, the
 * flat run). */
static int site_fns_build(struct kgenome_lineage *L)
{
	uint32_t k;

	if (!L->n_site)
		return 1;
	if (!kgenome_lineage_charge(L, (uint64_t)L->n_site * sizeof *L->site_fn))
		return 0;
	L->site_fn = malloc((size_t)L->n_site * sizeof *L->site_fn);
	if (!L->site_fn) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return 0;
	}
	for (k = 0; k < L->n_site; k++)
		L->site_fn[k] = kgenome_funcs_at(L->fs, L->site_at[k]);
	return 1;
}

int kgenome_lineage_slot_pop(const struct kgenome_lineage *L, uint64_t slot)
{
	uint32_t lo = 0, hi = L->n_slot_pop;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (L->slot_at[mid] < slot)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < L->n_slot_pop && L->slot_at[lo] == slot ? L->slot_words[lo] : -1;
}

/*
 * WHAT AN i386 STDCALL CALLEE POPS - the one thing the stack pointer of PE x86 code needs that the code does not say.
 * Per import slot: the table's argument count of the API (kgenome_emu_win_argc_of_name); per node it is asked from the
 * name the node was found by, and per function it is what the function's returns pop (the codemap carries `ret N`) -
 * a function that is one `jmp [slot]` is the import. See kgenome_lineage_state_call for why the count is known or the
 * stack pointer is not. PE x86 only: the one ABI whose callee pops.
 */
static int pops_build(struct kgenome_lineage *L)
{
	const struct kgenome_codemap *cm;
	const struct kgenome_pe_imptab *t;
	struct kgenome_diag_walk *wk;
	uint32_t i, n = 0;

	if (!L->abi.callee_pops)
		return 1;
	cm = kgenome_lineage_codemap(L);
	t = kgenome_diag_imports(L->s, L->obj);
	if (!cm || !t || !kgenome_lineage_refs(L, cm))
		return 0;
	if (!kgenome_lineage_charge(L, (uint64_t)L->s->n_hit * sizeof *L->argc + (uint64_t)L->n_fn * sizeof *L->pop +
				    (uint64_t)t->n * (sizeof *L->slot_at + sizeof *L->slot_words)))
		return 0;
	L->argc = malloc((size_t)(L->s->n_hit ? L->s->n_hit : 1u) * sizeof *L->argc);
	L->pop = malloc((size_t)(L->n_fn ? L->n_fn : 1u) * sizeof *L->pop);
	L->slot_at = malloc((size_t)(t->n ? t->n : 1u) * sizeof *L->slot_at);
	L->slot_words = malloc((size_t)(t->n ? t->n : 1u) * sizeof *L->slot_words);
	if (!L->argc || !L->pop || !L->slot_at || !L->slot_words) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return 0;
	}
	for (i = 0; i < L->s->n_hit; i++)
		L->argc[i] = -2;
	for (i = 0; i < L->n_fn; i++)
		L->pop[i] = -1;
	for (i = 0; i < t->n; i++) {
		char nm[KGENOME_PE_IMP_DLLLEN];
		unsigned c;

		if (!kgenome_pe_imp_name(kof_buf_make(L->base, L->size), &t->v[i], nm, sizeof nm))
			continue;
		c = kgenome_emu_win_argc_of_name(nm);
		if (c == KGENOME_EMU_WIN_ARGC_UNKNOWN)
			continue;
		L->slot_at[n] = t->v[i].slot;
		L->slot_words[n++] = (int16_t)c;
	}
	/* sorted together: a pair is its slot's key and its count */
	{
		uint32_t a, b;

		for (a = 1; a < n; a++) {
			uint64_t s = L->slot_at[a];
			int16_t w = L->slot_words[a];

			for (b = a; b > 0 && L->slot_at[b - 1u] > s; b--) {
				L->slot_at[b] = L->slot_at[b - 1u];
				L->slot_words[b] = L->slot_words[b - 1u];
			}
			L->slot_at[b] = s;
			L->slot_words[b] = w;
		}
	}
	L->n_slot_pop = n;
	/* the stubs the object's walk met: a function that is one `jmp [slot]` is the import it jumps to (the thunk a PE x86 calls instead of the slot) */
	wk = kgenome_diag_scan_walk(L->s);
	if (!kgenome_diag_walk_ensure(wk, L->obj, L->base, L->size, 1))
		wk = NULL;
	for (i = 0; i < cm->n; i++) {
		const struct kgenome_codemap_ref *r = &cm->v[i];
		uint32_t f;
		int16_t bytes;

		f = L->ref_from[i];
		if (f == UINT32_MAX)
			continue;
		if (r->kind != KGENOME_CM_RET)
			continue;
		bytes = (r->flags & KGENOME_CMF_POP) && r->nr < 0x7000u ? (int16_t)r->nr : (int16_t)0;
		/* every return of a function pops the same, or the function is not one whose count is known */
		if (L->pop[f] == -1)
			L->pop[f] = bytes;
		else if (L->pop[f] != bytes)
			L->pop[f] = -3;
	}
	for (i = 0; i < L->n_fn; i++) {
		int w;

		if (L->pop[i] == -3)
			L->pop[i] = -1;
		if (L->pop[i] >= 0)
			continue;
		w = kgenome_lineage_slot_pop(L, kgenome_diag_walk_thunk_slot(wk, L->fs->v[i].off));
		if (w >= 0)
			L->pop[i] = (int16_t)(w * L->abi.w);
	}
	return 1;
}

/* ---- the links ---- */

static int cmp_agg(const void *a, const void *b)
{
	uint32_t x = (*(const struct kgenome_lineage_agg *const *)a)->key;
	uint32_t y = (*(const struct kgenome_lineage_agg *const *)b)->key;

	return x < y ? -1 : x > y;
}

/*
 * ONE LINK, said by the stage. A link the stage proved on every path (MUST) is PROVEN even where a route said it first as MAY: the routes
 * that link while they find the nodes (the sweep's origins, the symbol route) read the code in address order and join two arms by
 * marking what they carry MAY, and kgenome_diag_note_in_how keeps the FIRST statement - so a link the stage proves over the function's
 * graph (msfvenom cleartext's `jmp rsi` into the mmap'd region, across a connect retry loop whose pushes and pops balance on both paths)
 * stayed MAY. The stage does not demote: a route's PROVEN it does not prove is a stronger claim it cannot refute from a value whose rest is
 * unknown. Answers what kgenome_diag_note_in_how answers (1: the input was lost: the ledger refused the table).
 */
static int link_say(struct kgenome_lineage *L, struct kgenome_diag_hit *h, uint16_t from, uint8_t role, int must)
{
	if (must)
		return kgenome_diag_note_in_seen(L->s, h, from, role, KGENOME_DIAG_KIND_PRODUCED);
	return kgenome_diag_note_in_how(L->s, h, from, role, KGENOME_DIAG_KIND_PRODUCED, KGENOME_DIAG_LINK_MAY);
}

/* The class of a system call's number from what reached it (enum kgenome_diag_nr): a producer on some path is RESULT, else a parameter is
 * PARAM, else a constant and nothing else is CONST. */
static uint8_t nr_class(const struct kgenome_lineage_agg *a)
{
	if (a->n)
		return KGENOME_DIAG_NR_RESULT;
	if (a->param)
		return KGENOME_DIAG_NR_PARAM;
	if (a->other && !(a->why & ~(uint32_t)KGENOME_LINEAGE_W_CONST))
		return KGENOME_DIAG_NR_CONST;
	return KGENOME_DIAG_NR_UNKNOWN;
}

/* A system call's number onto its node (diag_vocab.h, enum kgenome_diag_nr): the class, and for a RESULT the producer - the lowest node
 * index of those that reached it, so the answer does not follow the order the functions were solved in - how sure, and how many. */
static void nr_write(struct kgenome_lineage *L, const struct kgenome_lineage_agg *a)
{
	struct kgenome_diag_hit *h = kgenome_diag_hit_of(L->s, (a->key >> 8) - 1u);
	uint32_t lead = UINT32_MAX;
	uint32_t j;

	if (!h)
		return;
	h->nr = nr_class(a);
	h->nr_n = a->n > 255u ? 255u : (uint8_t)a->n;     /* (a count, saturated; every producer is an input of the node) */
	h->nr_from = KGENOME_DIAG_ORG_NONE;
	h->nr_how = KGENOME_DIAG_LINK_UNKNOWN;
	uint16_t *t = a->n ? malloc((size_t)a->n * sizeof *t) : NULL;

	if (a->n && !t) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return;
	}
	if (t)
		kgenome_lineage_agg_toks(&L->glob, a, t);
	for (j = 0; j < a->n; j++)
		if (KGENOME_LINEAGE_TOK_NODE(t[j]) < lead)
			lead = KGENOME_LINEAGE_TOK_NODE(t[j]);
	free(t);
	if (lead != UINT32_MAX) {
		h->nr_from = (uint16_t)lead;
		h->nr_how = a->n == 1u && !a->other ? KGENOME_DIAG_LINK_PROVEN : KGENOME_DIAG_LINK_MAY;
	}
}

static int cmp_tok16(const void *a, const void *b)
{
	const uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;

	return x < y ? -1 : x > y;
}

/* Write what reached each consumer onto the nodes: the sure ones first. */
static void links_write(struct kgenome_lineage *L)
{
	const struct kgenome_lineage_agg **v;
	uint32_t i, n = 0;
	unsigned pass;

	if (!L->glob.n)
		return;
	v = malloc((size_t)L->glob.n * sizeof *v);
	if (!v) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);     /* the links found are lost: said */
		return;
	}
	for (i = 0; i < L->glob.cap; i++) {
		const struct kgenome_lineage_agg *a = &L->glob.v[i];

		if (!a->key)
			continue;
		if ((a->key & 0xffu) == KGENOME_DIAG_ROLE_NUMBER)
			nr_write(L, a);         /* the class; its producers are links like any input's, below */
		if (a->n)
			v[n++] = a;
	}
	if (n)
		qsort(v, n, sizeof *v, cmp_agg);
	for (pass = 0; pass < 2u; pass++)
		for (i = 0; i < n; i++) {
			const struct kgenome_lineage_agg *a = v[i];
			const int must = a->n == 1u && !a->other;
			struct kgenome_diag_hit *h;
			uint16_t t0[KGENOME_LINEAGE_SET], *t = t0;
			uint32_t j;

			if (must != (pass == 0u))
				continue;
			h = kgenome_diag_hit_of(L->s, (a->key >> 8) - 1u);
			/* the producers in node order: which of them a full node refuses does not follow the order the table was filled in (the
			 * functions' solve order, the table's slot order) */
			if (a->n > KGENOME_LINEAGE_SET && !(t = malloc((size_t)a->n * sizeof *t))) {
				kgenome_diag_note(L->s, KGENOME_NOMEM);    /* this consumer's links are lost: said */
				continue;
			}
			kgenome_lineage_agg_toks(&L->glob, a, t);
			qsort(t, a->n, sizeof t[0], cmp_tok16);
			for (j = 0; j < a->n && h; j++)
				L->st.dropped += (uint64_t)link_say(L, h, (uint16_t)KGENOME_LINEAGE_TOK_NODE(t[j]), (uint8_t)(a->key & 0xffu), must);
			if (t != t0)
				free(t);
		}
	free(v);
}

/* ---- the run ---- */

/* The functions that hold a node, each once, solved without summaries. */
static void run_flat(struct kgenome_lineage *L)
{
	uint8_t *has = calloc(L->n_fn ? L->n_fn : 1u, 1);
	uint32_t i;

	if (!has) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return;
	}
	for (i = 0; i < L->n_site; i++)
		if (L->site_fn[i] != KGENOME_FUNCS_NONE)
			has[L->site_fn[i]] = 1;
	for (i = 0; i < L->n_fn && !L->halt && !L->over_steps; i++)
		if (has[i])
			kgenome_lineage_solve(L, i, NULL);
	free(has);
}

void kgenome_diag_run_lineage(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
			      const uint8_t *base, uint64_t size)
{
	struct kgenome_lineage L;
	struct kgenome_lineage_abi row;
	unsigned plan;

	/* the architecture is a row of the table (diag_lineage_arch.c), or the stages do not read the object */
	if (!kgenome_lineage_arch_of(obj, &row))
		return;
	plan = s->lineage_stages ? s->lineage_stages : kgenome_diag_lineage_plan(kgenome_diag_class_of(obj));
	if (!plan)
		return;
	memset(&L, 0, sizeof L);
	L.s = s;
	L.obj = obj;
	L.base = base;
	L.size = size;
	L.plan = plan;
	L.wk = s->walk;
	L.frames = kgenome_diag_frames(s);
	L.sums.s = s;
	L.abi = row;
	kgenome_diag_noret_settle(s);
	if (sites_build(&L) && L.n_site && fns_build(&L) && L.n_fn && site_fns_build(&L) && pops_build(&L)) {
		L.fn_run = calloc(L.n_fn, 1);       /* (without it the next-stage count says "not run") */
		if (plan & KGENOME_LINEAGE_S_SUMM)
			kgenome_lineage_run_summ(&L);
		else
			run_flat(&L);
		links_write(&L);
		kgenome_lineage_obligations(&L);
		s->lstats = L.st;
	}
	free(L.site_at);
	free(L.site_node);
	free(L.site_fn);
	free(L.by_va);
	free(L.ref_from);
	free(L.in);
	free(L.glob.v);
	free(L.glob.x);
	free(L.vx);
	free(L.loc.v);
	free(L.loc.x);
	free(L.callers);
	free(L.sumhash);
	free(L.has_site);
	free(L.fn_run);
	free(L.noret_fn);
	free(L.nontriv);
	free(L.skipped);
	free(L.need);
	free(L.pop);
	free(L.argc);
	free(L.slot_at);
	free(L.slot_words);
	free(L.sums.ws);
	free(L.sums.wi);
	if (L.cm_done == 1)
		kgenome_codemap_free(&L.cm);
	kgenome_ledger_release(&s->led, L.charged + L.sums.charged);
}
