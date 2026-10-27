/*
 * codemap.c - kgenome_codemap_build. See codemap.h for what the table holds and what a syscall number means here.
 *
 * TWO READS OF THE CODE, and why not one. The first (kgenome_cell_step, no register model: a third of a step's cost) finds the branches and so the
 * places that are branched to. The second runs the register model, and has to know those places before it starts, because the model must be dropped
 * at each of them - a forward jump's target is not known from a single pass. The second read happens only when the first met a syscall.
 */

#include "codemap.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <kofcmp.h>

#include "diag_private.h"
#include "../celllysis/celllysis.h"
#include "../celllysis/nucleo.h"
#include "../celllysis/space.h"
#include "../genotype/image/elf_image.h"
#include "../genotype/image/image_addr.h"

struct cm_ext {
	uint64_t at, len;
};

struct cm_build {
	struct kgenome_codemap *m;
	uint32_t cap;
	const struct kgenome_elf_relocs *relocs;
	struct kgenome_cell_space sp;
	const struct kgenome_obj *obj;
	uint64_t size;
};

/* The code's extents: the object's own, else the whole buffer. Returns how many, in `ext` (malloc'd), 0 on no memory. */
static uint32_t cm_extents(const struct kgenome_obj *obj, uint64_t size, struct cm_ext **ext)
{
	uint32_t n = kgenome_diag_extent_count(obj), i, k = 0;
	struct cm_ext *v = malloc(((size_t)n + 1u) * sizeof *v);

	*ext = v;
	if (!v)
		return 0;
	for (i = 0; i < n; i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

		if (have) {
			v[k].at = at;
			v[k++].len = have;
		}
	}
	if (!k) {
		v[0].at = 0;
		v[0].len = size;
		k = 1;
	}
	return k;
}

static int cm_push(struct cm_build *b, const struct kgenome_codemap_ref *r)
{
	struct kgenome_codemap *m = b->m;

	if (m->n == b->cap) {
		/* KNOWN DEFECT REV-D8e (2026-10-25, Inference) [sev L]: cm_push (codemap.c) doubles a uint32 capacity (code map
		 * refs) with no overflow guard and no ledger charge. Trigger: an object with 2^31 or more elements of this kind
		 * (input over 2 GiB; the engine caps an object at 512 MiB, so only a host using the lib directly). Reproducer:
		 * none (read). Fix: use kof_tab_grow (kofcore/tabgrow.h, guards the doubling) or test cap against UINT32_MAX / 2
		 * before doubling. */
		uint32_t nc = b->cap ? b->cap * 2u : 1024u;
		struct kgenome_codemap_ref *nv = realloc(m->v, (size_t)nc * sizeof *nv);

		if (!nv)
			return 0;
		m->v = nv;
		b->cap = nc;
	}
	m->v[m->n++] = *r;
	return 1;
}

/* The kind of reference an instruction is, 0 when it is none. */
static unsigned cm_kind(const struct kgenome_cell_insn *in)
{
	switch (in->op) {
	case KGENOME_CELL_CALL:    return KGENOME_CM_CALL;
	case KGENOME_CELL_JMP:     return KGENOME_CM_JMP;
	case KGENOME_CELL_JCC:     return KGENOME_CM_JCC;
	case KGENOME_CELL_LOOP:    return KGENOME_CM_LOOP;
	case KGENOME_CELL_RET:     return KGENOME_CM_RET;
	case KGENOME_CELL_SYSCALL: return KGENOME_CM_SYSCALL;
	case KGENOME_CELL_INT:
		return in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM && in->o[0].imm == 0x80u ? KGENOME_CM_SYSCALL : 0u;
	default:                   return 0;
	}
}

static int cm_cmp_to(const void *a, const void *b, void *u)
{
	const struct kgenome_codemap_ref *v = u;
	const struct kgenome_codemap_ref *x = &v[*(const uint32_t *)a], *y = &v[*(const uint32_t *)b];

	if (x->to != y->to)
		return x->to < y->to ? -1 : 1;
	return x->at < y->at ? -1 : x->at > y->at;
}

/* ordered by (to, at): a shell sort, because qsort_r is not on every host this builds on. */
static void cm_sort_to(struct kgenome_codemap *m)
{
	uint32_t gap, i, j;

	for (gap = m->n_to / 2u; gap; gap /= 2u)
		for (i = gap; i < m->n_to; i++) {
			uint32_t t = m->by_to[i];

			for (j = i; j >= gap && cm_cmp_to(&t, &m->by_to[j - gap], m->v) < 0; j -= gap)
				m->by_to[j] = m->by_to[j - gap];
			m->by_to[j] = t;
		}
}

/*
 * THE OBSERVER of the engine's one reader of code (kgenome_diag_code_run): it serves an instruction from the object's trace when the diagnose walk
 * holds one and decodes it otherwise, and says the same either way, so this table is built from the same instructions the scan saw. It hands over
 * the target as an ADDRESS (target_va); the file offset of it is the image's to say.
 */
struct cm_obs {
	struct cm_build *b;
	int identity;   /* the object has no load address: the file is its own address space */
	int fail;
};

static void cm_observe(void *user, const struct kgenome_cell_insn *in)
{
	struct cm_obs *o = user;
	struct kgenome_codemap_ref r;
	unsigned kind;

	if (!in || o->fail)
		return;
	kind = cm_kind(in);
	if (!kind)
		return;
	memset(&r, 0, sizeof r);
	r.at = in->at;
	r.len = in->len;
	r.kind = (uint8_t)kind;
	r.to = KGENOME_BROKEN;
	if (in->flags & KGENOME_CELL_F_INDIRECT)
		r.flags |= KGENOME_CMF_INDIRECT;
	if (kind == KGENOME_CM_SYSCALL && in->op == KGENOME_CELL_INT)
		r.flags |= KGENOME_CMF_INT80;
	if (kind == KGENOME_CM_RET && in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM) {
		r.nr = (uint32_t)in->o[0].imm;
		r.flags |= KGENOME_CMF_POP;
	}
	if (o->b->relocs && kind != KGENOME_CM_SYSCALL && kind != KGENOME_CM_RET &&
	    kgenome_elf_reloc_in(o->b->relocs, in->at, in->len))
		r.flags |= KGENOME_CMF_RELOC;
	else if (kind != KGENOME_CM_SYSCALL && kind != KGENOME_CM_RET && !(in->flags & KGENOME_CELL_F_INDIRECT) &&
		 in->target_va != KGENOME_BROKEN) {
		r.to = o->identity ? in->target_va : kgenome_image_addr_to_off(o->b->obj, in->target_va);
		if (r.to >= o->b->size)
			r.to = KGENOME_BROKEN;  /* outside the object: a place the file does not hold */
		if (r.to != KGENOME_BROKEN && r.to <= r.at)
			r.flags |= KGENOME_CMF_BACK;
	}
	if (!cm_push(o->b, &r))
		o->fail = 1;
}

/* One extent, read once through the shared reader. 0 when memory ran out. */
static int cm_read_extent(struct cm_build *b, const struct cm_ext *e, uint64_t size, const uint8_t *base)
{
	uint64_t va = kgenome_image_off_to_addr(b->obj, e->at);
	struct cm_obs o = { b, va == KGENOME_BROKEN, 0 };

	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
		.obj = b->obj, .base = base, .size = size, .off = e->at, .n = e->len,
		.va = o.identity ? e->at : va, .fn = cm_observe, .user = &o });
	return !o.fail;
}

/* The register that holds a syscall's number on this object, as the cursor numbers it. -1: none we can read. */
static int cm_sel(const struct kgenome_obj *obj)
{
	const struct kgenome_nucleo_abi *fx;

	if (obj->arch == KGENOME_ARCH_X86 || obj->arch == KGENOME_ARCH_X86_64)
		return KGENOME_CELL_REG_AX;
	fx = kgenome_nucleo_abi_of(obj->arch);
	return fx ? (int)fx->sel : -1;
}

/* The next place at or after `off` that is a branch target, from the by_to order; UINT64_MAX when none. */
static uint64_t cm_next_target(const struct kgenome_codemap *m, uint32_t *p, uint64_t off)
{
	while (*p < m->n_to && m->v[m->by_to[*p]].to < off)
		(*p)++;
	return *p < m->n_to ? m->v[m->by_to[*p]].to : UINT64_MAX;
}

/*
 * The second read of one extent: the register model, dropped at each target and after each branch, and the number register read
 * at each syscall instruction BEFORE it runs. `ri` walks the references, in the order of `at`, as the read meets them.
 */
static void cm_numbers_extent(struct cm_build *b, const struct cm_ext *e, int sel, uint32_t *ri)
{
	struct kgenome_codemap *m = b->m;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	uint32_t tp = 0;
	int reset = 1;

	memset(&k, 0, sizeof k);
	if (!kgenome_cell_seek(&k, e->at, 0))
		return;
	while (k.at < e->at + e->len) {
		while (*ri < m->n && m->v[*ri].at < k.at)
			(*ri)++;
		if (reset || cm_next_target(m, &tp, k.at) == k.at) {
			(void)kgenome_cell_seek(&k, k.at, 0);   /* nothing is known across a join or a branch */
			reset = 0;
		}
		if (*ri < m->n && m->v[*ri].at == k.at && m->v[*ri].kind == KGENOME_CM_SYSCALL) {
			uint64_t nr;

			if (kgenome_cell_reg(&k, (uint8_t)sel, &nr) && nr <= 0xffffu) {
				m->v[*ri].nr = (uint32_t)nr;
				m->v[*ri].flags |= KGENOME_CMF_NR;
			}
		}
		if (!kgenome_cell_next(&k, &b->sp, &in)) {
			k.at++;
			reset = 1;
			continue;
		}
		/* a syscall too: it returns in the number register, and the model does not know that, so the next syscall would read this one's number */
		if (cm_kind(&in))
			reset = 1;
	}
}

static int cm_index(struct kgenome_codemap *m)
{
	uint32_t i;

	m->by_to = malloc(((size_t)m->n + 1u) * sizeof *m->by_to);
	if (!m->by_to)
		return 0;
	for (i = 0; i < m->n; i++)
		if (m->v[i].to != KGENOME_BROKEN)
			m->by_to[m->n_to++] = i;
	cm_sort_to(m);
	return 1;
}

int kgenome_codemap_build(const struct kgenome_obj *obj, const uint8_t *base, uint64_t size,
			  const struct kgenome_elf_relocs *relocs, struct kgenome_codemap *out)
{
	struct cm_build b;
	struct cm_ext *ext;
	uint32_t n, i, ri = 0;
	int sel = cm_sel(obj), ok = 1, any_sys = 0;

	memset(out, 0, sizeof *out);
	if (!obj || !base || !size || sel < 0)
		return 0;
	memset(&b, 0, sizeof b);
	b.m = out;
	b.relocs = relocs;
	b.obj = obj;
	b.size = size;
	kgenome_cell_space_init(&b.sp, obj, base, size);
	n = cm_extents(obj, size, &ext);
	if (!n) {
		free(ext);
		out->status = KGENOME_NOMEM;
		return 0;
	}
	/* KNOWN DEFECT WP9-F5 (2026-10-25, M) [sev M]: kgenome_codemap_build appends refs extent by extent, so m->v
	 * is not in order of `at` (codemap.h says it is) and holds duplicates. Trigger: two executable segments in
	 * descending file order, or overlapping ones. Effect: kgenome_codemap_at (binary search) silently misses
	 * refs that exist: evidence lost on a crafted ELF. Reproducer: tests/lib/genome/diag_known_misses.c f5
	 * (green until fixed). Fix: sort m->v by `at` and drop equal `at` before cm_index, or read the extents in
	 * ascending order. */
	for (i = 0; ok && i < n; i++)
		ok = cm_read_extent(&b, &ext[i], size, base);
	if (ok)
		ok = cm_index(out);
	for (i = 0; ok && i < out->n; i++)
		any_sys |= out->v[i].kind == KGENOME_CM_SYSCALL;
	for (i = 0; ok && any_sys && i < n; i++)
		cm_numbers_extent(&b, &ext[i], sel, &ri);
	free(ext);
	if (!ok) {
		kgenome_codemap_free(out);
		out->status = KGENOME_NOMEM;
		return 0;
	}
	return 1;
}

void kgenome_codemap_free(struct kgenome_codemap *m)
{
	/* KNOWN DEFECT WP9-F3 (2026-10-25, M) [sev L]: kgenome_codemap_free dereferences its argument, unlike every
	 * other free of the diagnose scan. Trigger: kgenome_codemap_free(NULL). Effect: NULL dereference.
	 * Reproducer: tests/lib/genome/diag_known_misses.c f3 (green until fixed). Fix: `if (!m) return;` first. */
	free(m->v);
	free(m->by_to);
	memset(m, 0, sizeof *m);
}

const struct kgenome_codemap_ref *kgenome_codemap_at(const struct kgenome_codemap *m, uint64_t at)
{
	const uint32_t lo = kof_lower_bound_u64(m->v, m->n, sizeof *m->v, offsetof(struct kgenome_codemap_ref, at), at);

	return lo < m->n && m->v[lo].at == at ? &m->v[lo] : NULL;
}

uint32_t kgenome_codemap_to(const struct kgenome_codemap *m, uint64_t to, uint32_t *first)
{
	uint32_t lo = 0, hi = m->n_to, n = 0;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (m->v[m->by_to[mid]].to < to)
			lo = mid + 1u;
		else
			hi = mid;
	}
	*first = lo;
	while (lo + n < m->n_to && m->v[m->by_to[lo + n]].to == to)
		n++;
	return n;
}
