/* vmatch.c - see vmatch.h. Sets are sorted, de-duplicated stack copies merged in one pass; groups are found by comparing with the
 * first diagnose of each group (bounded by KOF_VMATCH_FIRED_MAX). No allocation, no global. */
#include <string.h>

#include "vmatch.h"

#define VM_XMAX (KOF_VMATCH_KINDS * KOF_VMATCH_FIRED_MAX)

static int vm_lt(const struct kof_vmatch_elem *p, const struct kof_vmatch_elem *q)
{
	if (p->kind != q->kind)
		return p->kind < q->kind;
	if (p->a != q->a)
		return p->a < q->a;
	return p->b < q->b;
}

static int vm_eq(const struct kof_vmatch_elem *p, const struct kof_vmatch_elem *q)
{
	return p->kind == q->kind && p->a == q->a && p->b == q->b;
}

/* Sort ascending and remove repeats in place; returns the number of distinct elements. Shell sort: no recursion, no allocation (the
 * library qsort may allocate). */
static uint32_t vm_set(struct kof_vmatch_elem *s, uint32_t n)
{
	uint32_t gap, i, j, k;
	struct kof_vmatch_elem t;

	for (gap = n / 2u; gap > 0u; gap /= 2u)
		for (i = gap; i < n; i++) {
			t = s[i];
			for (j = i; j >= gap && vm_lt(&t, &s[j - gap]); j -= gap)
				s[j] = s[j - gap];
			s[j] = t;
		}
	for (i = 0, k = 0; i < n; i++)
		if (k == 0u || !vm_eq(&s[k - 1u], &s[i]))
			s[k++] = s[i];
	return k;
}

/* The one division: a Jaccard index in permille, rounded down, 1000 for two empty sets. */
static uint32_t vm_permille(uint32_t m, uint32_t u, uint32_t n)
{
	return (m + u + n) == 0u ? 1000u : (m * 1000u) / (m + u + n);
}

static int vm_same(const struct kof_vmatch_fired *a, const struct kof_vmatch_fired *b)
{
	if (!a->has_variant || !b->has_variant)
		return !a->has_variant && !b->has_variant;
	return a->family == b->family && a->variant == b->variant;
}

/* Merge two sorted sets: counts per kind, and the elements of M, U, N written at positions pos.. when they are below cap. */
static void vm_merge(const struct kof_vmatch_elem *x, uint32_t nx, const struct kof_vmatch_elem *v, uint32_t nv,
		     struct kof_vmatch_score *s, struct kof_vmatch_elem *out, uint32_t cap, uint32_t pos)
{
	uint32_t i, j, k, pass;
	uint32_t *cnt[3] = { s->kmatched, s->kunseen, s->kextra };

	/* pass 0: M, pass 1: U, pass 2: N; each is one walk, so each list is ascending and the three are contiguous */
	for (pass = 0; pass < 3u; pass++) {
		i = j = 0;
		while (i < nx || j < nv) {
			int in_x, in_v;
			const struct kof_vmatch_elem *e;

			if (j >= nv || (i < nx && vm_lt(&x[i], &v[j]))) {
				e = &x[i++]; in_x = 1; in_v = 0;
			} else if (i >= nx || vm_lt(&v[j], &x[i])) {
				e = &v[j++]; in_x = 0; in_v = 1;
			} else {
				e = &x[i++]; j++; in_x = in_v = 1;
			}
			if (pass == 0u ? (in_x && in_v) : pass == 1u ? (!in_x && in_v) : (in_x && !in_v)) {
				if (pos < cap)
					out[pos] = *e;
				pos++;
				cnt[pass][e->kind]++;
			}
		}
	}
	for (k = 0; k < KOF_VMATCH_KINDS; k++) {
		s->matched += s->kmatched[k];
		s->unseen += s->kunseen[k];
		s->extra += s->kextra[k];
		s->kpermille[k] = vm_permille(s->kmatched[k], s->kunseen[k], s->kextra[k]);
	}
	s->permille = vm_permille(s->matched, s->unseen, s->extra);
}

static void vm_put(struct kof_vmatch_elem *e, uint32_t kind, uint32_t a, uint32_t b)
{
	e->kind = kind;
	e->a = a;
	e->b = b;
}

void kof_vmatch(const struct kof_vmatch_req *rq, struct kof_vmatch_res *res)
{
	struct kof_vmatch_elem xs[VM_XMAX], vs[KOF_VMATCH_SET_MAX];
	uint32_t gid[KOF_VMATCH_FIRED_MAX], cnt[KOF_VMATCH_FIRED_MAX], rep[KOF_VMATCH_FIRED_MAX];
	uint32_t nf, nc, nxr = 0, nx, ng = 0, i, g, k, pos = 0, start = 0;
	int too_large = 0;

	if (!res)
		return;
	memset(res, 0, sizeof *res);
	if (!rq || (rq->n_fired && !rq->fired) || (rq->n_cand && !rq->cand) || (rq->group_cap && !rq->group) ||
	    (rq->entry_cap && !rq->entry) || (rq->score_cap && !rq->score) || (rq->elems_cap && !rq->elems) ||
	    (rq->x_kinds >> KOF_VMATCH_KINDS) != 0u) {
		res->status = KOF_VMATCH_BAD_REQUEST;
		return;
	}
	nf = rq->n_fired;
	nc = rq->n_cand;
	res->n_entries = nf;
	res->n_scores = nc;
	if (nf > KOF_VMATCH_FIRED_MAX || nc > KOF_VMATCH_CAND_MAX) {
		res->status = KOF_VMATCH_TOO_LARGE;
		return;
	}
	for (i = 0; i < nc; i++) {
		if (rq->cand[i].n_elem && !rq->cand[i].elem) {
			res->status = KOF_VMATCH_BAD_REQUEST;
			return;
		}
		if (rq->cand[i].n_elem <= KOF_VMATCH_SET_MAX)
			for (k = 0; k < rq->cand[i].n_elem; k++)
				if (rq->cand[i].elem[k].kind >= KOF_VMATCH_KINDS) {
					res->status = KOF_VMATCH_BAD_REQUEST;
					return;
				}
	}

	/* D(x) from what the fired diagnoses declared, the kinds the caller asked for */
	for (i = 0; i < nf; i++) {
		const struct kof_vmatch_fired *f = &rq->fired[i];

		if (rq->x_kinds & (1u << KOF_VMATCH_TAG))
			vm_put(&xs[nxr++], KOF_VMATCH_TAG, f->tag, 0);
		if (f->has_variant && (rq->x_kinds & (1u << KOF_VMATCH_FAMILY)))
			vm_put(&xs[nxr++], KOF_VMATCH_FAMILY, f->family, 0);
		if (f->has_variant && (rq->x_kinds & (1u << KOF_VMATCH_VARIANT)))
			vm_put(&xs[nxr++], KOF_VMATCH_VARIANT, f->family, f->variant);
	}
	nx = vm_set(xs, nxr);
	res->n_x = nx;
	for (i = 0; i < nx; i++)
		res->n_xk[xs[i].kind]++;

	/* groups: gid[i] = the group of fired diagnose i, in order of first appearance; cnt[g] its size; rep[g] its first diagnose */
	for (i = 0; i < nf; i++) {
		for (g = 0; g < ng; g++)
			if (vm_same(&rq->fired[rep[g]], &rq->fired[i]))
				break;
		if (g == ng) {
			rep[ng] = i;
			cnt[ng++] = 0;
		}
		gid[i] = g;
		cnt[g]++;
	}
	res->n_groups = ng;

	/* similarity of every candidate (all of them, so the totals are true), written while they fit */
	for (i = 0; i < nc; i++) {
		const struct kof_vmatch_cand *c = &rq->cand[i];
		struct kof_vmatch_score s;

		memset(&s, 0, sizeof s);
		s.family = c->family;
		s.variant = c->variant;
		s.elem_first = pos;
		if (c->n_elem > KOF_VMATCH_SET_MAX) {
			s.flags = KOF_VMATCH_SKIPPED;
			too_large = 1;
		} else {
			uint32_t nv;

			for (k = 0; k < c->n_elem; k++)         /* b is read for a variant only */
				vm_put(&vs[k], c->elem[k].kind, c->elem[k].a, c->elem[k].kind == KOF_VMATCH_VARIANT ? c->elem[k].b : 0);
			nv = vm_set(vs, c->n_elem);
			vm_merge(xs, nx, vs, nv, &s, rq->elems, rq->elems_cap, pos);
			pos += s.matched + s.unseen + s.extra;
		}
		if (i < rq->score_cap)
			rq->score[i] = s;
	}
	res->n_elems = pos;

	/* groups and entries: the entries of group g start at the sum of the sizes before it */
	for (g = 0; g < ng; g++) {
		if (g < rq->group_cap) {
			struct kof_vmatch_group *o = &rq->group[g];
			const struct kof_vmatch_fired *f = &rq->fired[rep[g]];

			o->has_variant = f->has_variant ? 1u : 0u;
			o->family = f->has_variant ? f->family : 0u;
			o->variant = f->has_variant ? f->variant : 0u;
			o->entry_first = start;
			o->entry_count = cnt[g];
			o->score_index = KOF_VMATCH_NONE;
			if (f->has_variant)
				for (k = 0; k < nc; k++)
					if (rq->cand[k].family == f->family && rq->cand[k].variant == f->variant) {
						o->score_index = k;
						break;
					}
		}
		rep[g] = start;                         /* reused: the next free position of group g */
		start += cnt[g];
	}
	for (i = 0; i < nf; i++) {
		uint32_t p = rep[gid[i]]++;

		if (p < rq->entry_cap) {
			rq->entry[p].diag = rq->fired[i].diag;
			rq->entry[p].tag = rq->fired[i].tag;
			rq->entry[p].type = rq->fired[i].type;
		}
	}

	res->status = too_large ? KOF_VMATCH_TOO_LARGE
		    : (ng > rq->group_cap || nf > rq->entry_cap || nc > rq->score_cap || pos > rq->elems_cap) ? KOF_VMATCH_TRUNCATED
		    : KOF_VMATCH_OK;
}
