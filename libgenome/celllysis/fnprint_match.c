/*
 * fnprint_match.c - a reference signature and the streaming match against it.
 *
 * WHAT THE NUMBER MEANS. The reference is the set of DISTINCT fingerprints of a
 * source object's AUTHOR and UNKNOWN functions, each weighted by its size (capped,
 * and scaled by class), so a function repeated a thousand times counts once and a
 * thousand junk copies of one stub add nothing. Matching an object against it is
 * CONTAINMENT OF THE REFERENCE: the weight of reference entries the object has,
 * over the reference's weight - what a rule asks. Junk the object adds does not
 * move it; junk the REFERENCE carries is weighted down by the class (UNKNOWN 25%,
 * tiny 0), not removed.
 *
 * Two levels: a strong hit (fp equal) counts fully, a weak hit (only the
 * opcode-class sequence equal) counts half in the "any" figure. A weak run that
 * is long is examined to a bound (WEAK_SCAN) and the rest is counted in
 * n_capped, so a flood of one shape cannot make the walk quadratic and cannot do
 * it silently.
 */
#include "fnprint_private.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <kofcmp.h>

#define WEAK_SCAN 8u

static int cmp_ent(const void *a, const void *b)
{
	const struct kgenome_fnprint_ref_ent *x = a, *y = b;

	if (x->fp != y->fp)
		return x->fp < y->fp ? -1 : 1;
	return x->weight < y->weight ? 1 : x->weight > y->weight ? -1 : 0;
}

struct wk { uint64_t fw; uint32_t idx; };

static int cmp_wk(const void *a, const void *b)
{
	const struct wk *x = a, *y = b;

	if (x->fw != y->fw)
		return x->fw < y->fw ? -1 : 1;
	return x->idx < y->idx ? -1 : x->idx > y->idx;
}

void kgenome_fnprint_ref_build(const struct kgenome_fnprint_set *s, struct kgenome_fnprint_ref *out)
{
	struct kgenome_fnprint_ref_ent *t;
	struct wk *w;
	uint32_t i, n = 0, m = 0;

	memset(out, 0, sizeof *out);
	if (!s || !s->n)
		return;
	t = malloc((size_t)s->n * sizeof *t);
	if (!t) {
		out->status = KGENOME_NOMEM;
		return;
	}
	for (i = 0; i < s->n; i++) {
		const struct kgenome_fnprint_fn *f = &s->fn[i];

		if (!f->weight || (f->reason & KGENOME_FNP_R_BAD))
			continue;
		t[n].fp = f->fp; t[n].fw = f->fw; t[n].weight = f->weight; t[n].mult = 1;
		t[n].off = f->off; t[n].len = f->len;
		n++;
	}
	qsort(t, n, sizeof *t, cmp_ent);
	for (i = 0; i < n; i++) {
		if (m && t[m - 1].fp == t[i].fp) {
			t[m - 1].mult++;
			continue;
		}
		t[m++] = t[i];
	}
	w = malloc((size_t)(m ? m : 1) * sizeof *w);
	out->by_weak = malloc((size_t)(m ? m : 1) * sizeof *out->by_weak);
	if (!w || !out->by_weak) {
		free(w); free(out->by_weak); free(t);
		memset(out, 0, sizeof *out);
		out->status = KGENOME_NOMEM;
		return;
	}
	for (i = 0; i < m; i++) {
		w[i].fw = t[i].fw; w[i].idx = i;
		out->total_w += t[i].weight;
	}
	qsort(w, m, sizeof *w, cmp_wk);
	for (i = 0; i < m; i++)
		out->by_weak[i] = w[i].idx;
	free(w);
	out->e = t;
	out->n = m;
}

void kgenome_fnprint_ref_free(struct kgenome_fnprint_ref *r)
{
	if (!r)
		return;
	free(r->e);
	free(r->by_weak);
	memset(r, 0, sizeof *r);
}

int kgenome_fnprint_match_init(struct kgenome_fnprint_match *m, const struct kgenome_fnprint_ref *r,
			       struct kgenome_ledger *led)
{
	const struct kgenome_fnprint_req *va = m->verify_ref, *vo = m->verify_obj;

	memset(m, 0, sizeof *m);
	m->verify_ref = va;
	m->verify_obj = vo;
	m->ref = r;
	m->led = led;
	if (!r || !r->n)
		return 1;
	if (led && !kgenome_ledger_charge(led, r->n)) {
		m->status = KGENOME_OVER_BUDGET;
		return 0;
	}
	m->hit = calloc(r->n, 1);
	if (!m->hit) {
		if (led)
			kgenome_ledger_release(led, r->n);
		m->status = KGENOME_NOMEM;
		return 0;
	}
	return 1;
}

void kgenome_fnprint_match_done(struct kgenome_fnprint_match *m)
{
	if (!m)
		return;
	if (m->led && m->hit && m->ref)
		kgenome_ledger_release(m->led, m->ref->n);
	free(m->hit);
	m->hit = NULL;
}

static uint32_t find_fp(const struct kgenome_fnprint_ref *r, uint64_t fp)
{
	const uint32_t lo = kof_lower_bound_u64(r->e, r->n, sizeof *r->e, offsetof(struct kgenome_fnprint_ref_ent, fp), fp);

	return lo < r->n && r->e[lo].fp == fp ? lo : UINT32_MAX;
}

static int strong_ok(struct kgenome_fnprint_match *m, uint32_t i, const struct kgenome_fnprint_fn *f)
{
	struct kgenome_fnprint_fn rep;

	if (!m->verify_ref || !m->verify_obj)
		return 1;
	memset(&rep, 0, sizeof rep);
	rep.off = m->ref->e[i].off;
	rep.len = m->ref->e[i].len;
	if (kgenome_fnprint_equal(m->verify_ref, &rep, m->verify_obj, f))
		return 1;
	m->n_collision++;
	return 0;
}

static void weak_feed(struct kgenome_fnprint_match *m, const struct kgenome_fnprint_fn *f)
{
	const struct kgenome_fnprint_ref *r = m->ref;
	uint32_t lo = 0, hi = r->n, k, seen = 0;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (r->e[r->by_weak[mid]].fw < f->fw)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (k = lo; k < r->n && r->e[r->by_weak[k]].fw == f->fw; k++) {
		uint32_t i = r->by_weak[k];

		if (seen++ >= WEAK_SCAN) {
			m->n_capped++;
			m->status = kgenome_status_merge(m->status, KGENOME_TRUNCATED);
			return;
		}
		if (m->hit[i] == KGENOME_FNP_HIT_NONE) {
			m->hit[i] = KGENOME_FNP_HIT_WEAK;
			m->weak_w += r->e[i].weight;
			m->n_weak++;
			return;
		}
	}
}

void kgenome_fnprint_match_feed(struct kgenome_fnprint_match *m, const struct kgenome_fnprint_fn *f)
{
	uint32_t i;

	if (!m || !m->hit || !m->ref->n || !f->weight ||
	    (f->reason & KGENOME_FNP_R_BAD))
		return;
	i = find_fp(m->ref, f->fp);
	if (i != UINT32_MAX && m->hit[i] != KGENOME_FNP_HIT_STRONG && strong_ok(m, i, f)) {
		if (m->hit[i] == KGENOME_FNP_HIT_WEAK) {
			m->weak_w -= m->ref->e[i].weight;
			m->n_weak--;
		}
		m->hit[i] = KGENOME_FNP_HIT_STRONG;
		m->strong_w += m->ref->e[i].weight;
		m->n_strong++;
		return;
	}
	if (i == UINT32_MAX || m->hit[i] != KGENOME_FNP_HIT_STRONG)
		weak_feed(m, f);
}

int kgenome_fnprint_match_visit(void *user, const struct kgenome_fnprint_fn *f)
{
	kgenome_fnprint_match_feed(user, f);
	return 0;
}

uint32_t kgenome_fnprint_match_strong_pm(const struct kgenome_fnprint_match *m)
{
	if (!m || !m->ref || !m->ref->total_w)
		return 0;
	return (uint32_t)(m->strong_w * 1000u / m->ref->total_w);
}

uint32_t kgenome_fnprint_match_any_pm(const struct kgenome_fnprint_match *m)
{
	if (!m || !m->ref || !m->ref->total_w)
		return 0;
	return (uint32_t)((m->strong_w * 2u + m->weak_w) * 500u / m->ref->total_w);
}
