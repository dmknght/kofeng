/*
 * diag_lineage.c - the lineage stages' driver: the object's sites and functions, the stages the plan
 * names, and the links the stages found written onto the nodes. See diag_lineage.h for what the stages
 * are and diag_lineage_private.h for how the files share them.
 *
 * WHERE IT RUNS. After the routes and after the nodes are folded (merge_sites): a stage names a node by
 * its index and an index is only final then. It adds links to nodes the routes made and makes none.
 *
 * WHAT IT READS. The nodes that sit on a call or a jump (a node whose `at` is that instruction), the
 * functions of the object (the engine's set, completed where the object does not name them all - a PE
 * lists only the functions with unwind data, and an x86 PE none), and the code through the shared
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

/* ---- the calling convention ---- */

static const uint8_t win64_arg[4] = { KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX, 8u, 9u };
static const uint8_t clob_sysv[9] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
static const uint8_t clob_win64[7] = { 0, 1, 2, 8, 9, 10, 11 };
static const uint8_t clob_i386[3] = { 0, 1, 2 };

static void abi_init(struct kgenome_lineage_abi *a, const struct kgenome_obj *obj)
{
	memset(a, 0, sizeof *a);
	if (obj->arch == KGENOME_ARCH_X86_64) {
		a->wide = 1;
		a->w = 8;
		if (obj->format == KGENOME_FMT_PE) {
			a->arg = win64_arg;
			a->n_arg = 4;
			a->clob = clob_win64;
			a->n_clob = (uint8_t)sizeof clob_win64;
			a->stack_first = 4;
			a->stack_off = 32;      /* the callee's shadow space for the four register arguments */
		} else {
			a->arg = kgenome_diag_sysv_arg;
			a->n_arg = 6;
			a->clob = clob_sysv;
			a->n_clob = (uint8_t)sizeof clob_sysv;
			a->stack_first = 6;
		}
	} else {
		a->w = 4;
		a->clob = clob_i386;
		a->n_clob = (uint8_t)sizeof clob_i386;
		a->callee_pops = obj->format == KGENOME_FMT_PE;
	}
}

/* ---- the codemap, the one other thing the stages read once ---- */

const struct kgenome_codemap *kgenome_lineage_codemap(struct kgenome_lineage *L)
{
	if (!L->cm_done) {
		uint64_t bytes;

		L->cm_done = 1;
		/* KNOWN DEFECT WP9-F8 (2026-10-25, M) [sev M]: kgenome_lineage_codemap returns NULL on a failed
		 * kgenome_codemap_build without noting the status. Trigger: allocation refused inside the code map build
		 * called by the lineage stages. Effect: the map is missing, so are the links the lineage makes through it,
		 * and the status stays OK (the note below is reached only on success). Reproducer:
		 * tests/lib/genome/diag_bin_oom.c KNOWN-MISS F8. Fix: before `return NULL` call kgenome_diag_note(L->s,
		 * L->cm.status ? L->cm.status : KGENOME_NOMEM). */
		if (!kgenome_codemap_build(L->obj, L->base, L->size, NULL, &L->cm))
			return NULL;
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

static int cmp_fn(const void *a, const void *b)
{
	const struct kgenome_lineage_fn *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

struct lin_ext {
	uint64_t off, len;
};

static int cmp_ext(const void *a, const void *b)
{
	const struct lin_ext *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

/* The function of the engine's set that holds `off`, or NULL. */
static const struct kgenome_func *engine_fn_at(const struct kgenome_func_set *fs, uint64_t off)
{
	const uint32_t lo = kof_first_ending_above_u64(fs->v, fs->n, sizeof *fs->v, offsetof(struct kgenome_func, off),
						       offsetof(struct kgenome_func, len), off);

	return lo < fs->n && fs->v[lo].off <= off ? &fs->v[lo] : NULL;
}

static int fns_room(struct kgenome_lineage *L, uint32_t n)
{
	if (!kgenome_lineage_charge(L, (uint64_t)n * (sizeof *L->fn + sizeof *L->fn_by_va)))
		return 0;
	L->fn = malloc((size_t)(n ? n : 1u) * sizeof *L->fn);
	L->fn_by_va = malloc((size_t)(n ? n : 1u) * sizeof *L->fn_by_va);
	if (!L->fn || !L->fn_by_va) {
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		return 0;
	}
	return 1;
}

_Static_assert(offsetof(struct kgenome_lineage_fnva, va) == 0, "kof_cmp_u64 reads the key from the start");

/* The functions ordered by entry address. */
static void order_by_va(struct kgenome_lineage *L)
{
	uint32_t i;

	for (i = 0; i < L->n_fn; i++) {
		L->fn_by_va[i].va = L->fn[i].va;
		L->fn_by_va[i].fn = i;
	}
	qsort(L->fn_by_va, L->n_fn, sizeof *L->fn_by_va, kof_cmp_u64);
}

/*
 * THE FUNCTIONS: the engine's set where the object names them, and, where it does not name them all,
 * the call targets in the gaps. A PE lists the functions with unwind data (x64 only) and a leaf function has
 * none; an x86 PE and a stripped file of no known layout have none at all. A call target that is not inside
 * a function of the set is the entry of one that runs to the next entry or the end of its code extent: the
 * same rule the engine's own set uses for a stripped ELF, and the one the research prototype used for a
 * PE. The entry point and the first byte of each code extent are entries too.
 */
/* The address of the code at a file offset. A relocatable object has none (its sections are all at 0): the offset stands for it,
 * which is what every branch of it is relative to. */
static uint64_t fn_va(const struct kgenome_lineage *L, uint64_t off)
{
	uint64_t va = kgenome_image_off_to_addr(L->obj, off);

	return va == KGENOME_BROKEN && L->obj->format == KGENOME_FMT_ELF && kgenome_obj_elf(L->obj)->e_type == KGENOME_ELF_REL ? off : va;
}

static int fns_build(struct kgenome_lineage *L)
{
	const struct kgenome_func_set *fs = kgenome_diag_funcs(L->s, L->obj);
	const int derive = !fs->n || L->obj->format == KGENOME_FMT_PE;
	struct lin_ext *ext = NULL;
	uint64_t *x = NULL;
	uint32_t n_ext = 0, nx = 0, i, k, total;
	uint32_t ei;

	if (!derive) {
		if (!fns_room(L, fs->n))
			return 0;
		for (i = 0; i < fs->n; i++) {
			uint64_t va = fn_va(L, fs->v[i].off);

			if (va == KGENOME_BROKEN || fs->v[i].off >= L->size || !fs->v[i].len)
				continue;
			L->fn[L->n_fn].off = fs->v[i].off;
			L->fn[L->n_fn].len = fs->v[i].off + fs->v[i].len > L->size ? L->size - fs->v[i].off : fs->v[i].len;
			L->fn[L->n_fn++].va = va;
		}
		order_by_va(L);
		return 1;
	}
	{
		const struct kgenome_codemap *cm = kgenome_lineage_codemap(L);
		uint32_t ne = kgenome_diag_extent_count(L->obj);

		ext = malloc((size_t)(ne ? ne : 1u) * sizeof *ext);
		x = malloc((size_t)((cm ? cm->n : 0u) + ne + 2u) * sizeof *x);
		if (!ext || !x) {
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			free(ext);
			free(x);
			return 0;
		}
		for (i = 0; i < ne; i++) {
			uint64_t at, have = kgenome_diag_extent(L->obj, i, L->size, &at);

			if (have) {
				ext[n_ext].off = at;
				ext[n_ext++].len = have;
				x[nx++] = at;           /* the first byte of a code extent is an entry */
			}
		}
		if (n_ext)
			qsort(ext, n_ext, sizeof *ext, cmp_ext);
		if (L->obj->entry_off < L->size)
			x[nx++] = L->obj->entry_off;
		for (i = 0; cm && i < cm->n; i++)
			if (cm->v[i].kind == KGENOME_CM_CALL && !(cm->v[i].flags & KGENOME_CMF_INDIRECT) &&
			    cm->v[i].to < L->size)
				x[nx++] = cm->v[i].to;
	}
	if (nx)
		qsort(x, nx, sizeof *x, cmp_u64);
	/* keep what is in a code extent and not inside a function the engine named */
	{
		uint32_t w = 0;

		for (i = 0; i < nx; i++) {
			uint32_t lo = 0, hi = n_ext;

			if (w && x[w - 1u] == x[i])
				continue;
			while (lo < hi) {
				uint32_t mid = lo + (hi - lo) / 2u;

				if (ext[mid].off + ext[mid].len <= x[i])
					lo = mid + 1u;
				else
					hi = mid;
			}
			if (lo >= n_ext || ext[lo].off > x[i] || engine_fn_at(fs, x[i]))
				continue;
			x[w++] = x[i];
		}
		nx = w;
	}
	total = fs->n + nx;
	if (!fns_room(L, total)) {
		free(ext);
		free(x);
		return 0;
	}
	for (i = 0; i < fs->n; i++) {
		uint64_t va = fn_va(L, fs->v[i].off);

		if (va == KGENOME_BROKEN || fs->v[i].off >= L->size || !fs->v[i].len)
			continue;
		L->fn[L->n_fn].off = fs->v[i].off;
		L->fn[L->n_fn].len = fs->v[i].off + fs->v[i].len > L->size ? L->size - fs->v[i].off : fs->v[i].len;
		L->fn[L->n_fn++].va = va;
	}
	for (k = 0, ei = 0; k < nx; k++) {
		uint64_t va = fn_va(L, x[k]), end;
		uint32_t lo = 0, hi = fs->n;

		if (va == KGENOME_BROKEN)
			continue;
		while (ei + 1u < n_ext && ext[ei].off + ext[ei].len <= x[k])
			ei++;
		end = ext[ei].off + ext[ei].len;
		if (k + 1u < nx && x[k + 1u] < end)
			end = x[k + 1u];
		/* ... and where the next function of the engine's set begins, if sooner */
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (fs->v[mid].off <= x[k])
				lo = mid + 1u;
			else
				hi = mid;
		}
		if (lo < fs->n && fs->v[lo].off < end)
			end = fs->v[lo].off;
		if (end <= x[k])
			continue;
		L->fn[L->n_fn].off = x[k];
		L->fn[L->n_fn].len = end - x[k];
		L->fn[L->n_fn++].va = va;
	}
	free(ext);
	free(x);
	if (L->n_fn)
		qsort(L->fn, L->n_fn, sizeof *L->fn, cmp_fn);
	order_by_va(L);
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

/* A function that is one `jmp [slot]` is the import it jumps to (the thunk a PE x86 calls instead of the slot). */
static uint64_t thunk_slot(const struct kgenome_lineage *L, const struct kgenome_lineage_fn *f)
{
	struct kgenome_cell_insn ci;
	uint32_t len;

	if (f->off >= L->size)
		return KGENOME_BROKEN;
	/* the first instruction only: the last thunk of a table runs, as a "function", to the end of its section */
	len = kgenome_cell_decode(L->obj->arch, 0, L->base + f->off,
				  f->len < 15u && f->len < L->size - f->off ? (uint32_t)f->len
				  : L->size - f->off < 15u ? (uint32_t)(L->size - f->off) : 15u, f->va, &ci);
	if (!len || ci.op != KGENOME_CELL_JMP || !(ci.flags & KGENOME_CELL_F_INDIRECT) || !ci.n_op ||
	    ci.o[0].kind != KGENOME_CELL_O_MEM || ci.o[0].reg != KGENOME_CELL_REG_NONE ||
	    ci.o[0].index != KGENOME_CELL_REG_NONE)
		return KGENOME_BROKEN;
	return (uint64_t)ci.o[0].disp & 0xffffffffu;
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
	uint32_t i, n = 0;

	if (!L->abi.callee_pops)
		return 1;
	cm = kgenome_lineage_codemap(L);
	t = kgenome_diag_imports(L->s, L->obj);
	if (!cm || !t)
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
	for (i = 0; i < cm->n; i++) {
		const struct kgenome_codemap_ref *r = &cm->v[i];
		uint32_t f;
		int16_t bytes;

		if (r->kind != KGENOME_CM_RET)
			continue;
		f = kgenome_lineage_fn_at(L, r->at);
		if (f == UINT32_MAX)
			continue;
		bytes = (r->flags & KGENOME_CMF_POP) && r->nr < 0x7000u ? (int16_t)r->nr : (int16_t)0;
		/* every return of a function pops the same, or the function is not one whose count is known */
		if (L->pop[f] == -1)
			L->pop[f] = bytes;
		else if (L->pop[f] != bytes)
			L->pop[f] = -3;
	}
	for (i = 0; i < L->n_fn; i++) {
		uint64_t slot;
		int w;

		if (L->pop[i] == -3)
			L->pop[i] = -1;
		if (L->pop[i] >= 0)
			continue;
		slot = thunk_slot(L, &L->fn[i]);
		w = slot == KGENOME_BROKEN ? -1 : kgenome_lineage_slot_pop(L, slot);
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
	for (i = 0; i < L->glob.cap; i++)
		if (L->glob.v[i].key && L->glob.v[i].n)
			v[n++] = &L->glob.v[i];
	if (n)
		qsort(v, n, sizeof *v, cmp_agg);
	for (pass = 0; pass < 2u; pass++)
		for (i = 0; i < n; i++) {
			const struct kgenome_lineage_agg *a = v[i];
			const int must = a->n == 1u && !a->other;
			struct kgenome_diag_hit *h;
			uint8_t j;

			if (must != (pass == 0u))
				continue;
			h = kgenome_diag_hit_of(L->s, (a->key >> 8) - 1u);
			for (j = 0; j < a->n && h; j++)
				L->st.dropped += (uint64_t)kgenome_diag_note_in_how(L->s, h, (uint16_t)a->t[j], (uint8_t)(a->key & 0xffu),
							 KGENOME_DIAG_KIND_PRODUCED,
							 must ? KGENOME_DIAG_LINK_PROVEN : KGENOME_DIAG_LINK_MAY);
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
	for (i = 0; i < L->n_site; i++) {
		uint32_t a = 0, b = L->n_fn;

		while (a < b) {
			uint32_t mid = a + (b - a) / 2u;

			if (L->fn[mid].off + L->fn[mid].len <= L->site_at[i])
				a = mid + 1u;
			else
				b = mid;
		}
		if (a < L->n_fn && L->fn[a].off <= L->site_at[i])
			has[a] = 1;
	}
	for (i = 0; i < L->n_fn && !L->halt && !L->over_steps; i++)
		if (has[i])
			kgenome_lineage_solve(L, i, NULL);
	free(has);
}

void kgenome_diag_run_lineage(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
			      const uint8_t *base, uint64_t size)
{
	struct kgenome_lineage L;
	unsigned plan;

	if (!obj || (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64))
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
	L.sums.s = s;
	abi_init(&L.abi, obj);
	if (sites_build(&L) && L.n_site && fns_build(&L) && L.n_fn && pops_build(&L)) {
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
	free(L.fn);
	free(L.fn_by_va);
	free(L.in);
	free(L.glob.v);
	free(L.loc.v);
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
