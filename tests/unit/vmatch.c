/*
 * vmatch - the matching library of the verdict (libkofeng/verdictor/vmatch.c): similarity of D(x) and D(v) over three kinds of
 * evidence (tag, family, variant), and the grouping of fired diagnoses by their own declarations.
 *
 *   ORACLE   every subset of a pool of 6 fired diagnoses x every x_kinds mask x every subset of an 8-element profile universe
 *            (tags 1..3, families 1..2, variants (1,1) (2,1) (2,2)): M, U, N, J per kind and in total, and the listed elements,
 *            against a brute force written here on membership tables (no sorting, no merge; J by double division, truncated)
 *   GROUPS   one variant with two types keeps two entries and two types; the unattributed group; two variants keep two groups; the
 *            score beside a group is the candidate with the same family and variant; a tag shared by variants names no family
 *   BOUNDS   capacity 0 and too small: TRUNCATED with the true totals and the prefix of the full ordering; repeats count once; the
 *            largest set and one past it; the largest fired and candidate lists and one past; a bad request; two empty sets are 1000
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/verdictor/vmatch.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define NU 8u
static const struct kof_vmatch_elem U8[NU] = {
	{ KOF_VMATCH_TAG, 1, 0 }, { KOF_VMATCH_TAG, 2, 0 }, { KOF_VMATCH_TAG, 3, 0 },
	{ KOF_VMATCH_FAMILY, 1, 0 }, { KOF_VMATCH_FAMILY, 2, 0 },
	{ KOF_VMATCH_VARIANT, 1, 1 }, { KOF_VMATCH_VARIANT, 2, 1 }, { KOF_VMATCH_VARIANT, 2, 2 },
};

/* the pool: diag, tag, type, family, variant, has_variant */
static const struct kof_vmatch_fired POOL[6] = {
	{ 10, 1, 7, 0, 0, 0 }, { 11, 2, 7, 0, 0, 0 }, { 12, 1, 5, 1, 1, 1 },
	{ 13, 2, 6, 1, 1, 1 }, { 14, 3, 5, 2, 1, 1 }, { 15, 2, 5, 2, 2, 1 },
};

static void oracle(void)
{
	uint32_t fm, xk, ps;
	static struct kof_vmatch_elem out[3 * NU];
	static struct kof_vmatch_score sc[1];
	static struct kof_vmatch_group og[8];
	static struct kof_vmatch_entry oe[8];

	for (fm = 0; fm < 64u; fm++) {
		struct kof_vmatch_fired f[6];
		uint32_t nf = 0, i, k;

		for (i = 0; i < 6; i++)
			if (fm >> i & 1u)
				f[nf++] = POOL[i];
		for (xk = 0; xk < 8u; xk++) {
			int x[NU] = { 0 };

			/* D(x) by membership: which universe element does a fired diagnose put in, for the kinds asked */
			for (i = 0; i < nf; i++) {
				uint32_t u;

				for (u = 0; u < NU; u++) {
					const struct kof_vmatch_elem *e = &U8[u];

					if (!(xk >> e->kind & 1u))
						continue;
					if (e->kind == KOF_VMATCH_TAG && e->a == f[i].tag)
						x[u] = 1;
					if (e->kind == KOF_VMATCH_FAMILY && f[i].has_variant && e->a == f[i].family)
						x[u] = 1;
					if (e->kind == KOF_VMATCH_VARIANT && f[i].has_variant && e->a == f[i].family && e->b == f[i].variant)
						x[u] = 1;
				}
			}
			for (ps = 0; ps < 256u; ps++) {
				struct kof_vmatch_elem prof[2 * NU];
				struct kof_vmatch_cand c;
				struct kof_vmatch_req rq;
				struct kof_vmatch_res rs;
				uint32_t np = 0, M[3] = { 0 }, Un[3] = { 0 }, N[3] = { 0 }, tm = 0, tu = 0, tn = 0, pos, u;
				double j;

				for (u = 0; u < NU; u++)
					if (ps >> u & 1u) {
						prof[np++] = U8[u];
						if (u % 3u == 0u)               /* a repeat, and a stray b on a non-variant */
							prof[np++] = U8[u];
					}
				if (np) {
					prof[0].b = prof[0].kind == KOF_VMATCH_VARIANT ? prof[0].b : 99u;
				}
				c.family = 1; c.variant = 1; c.elem = prof; c.n_elem = np;
				memset(&rq, 0, sizeof rq);
				rq.fired = f; rq.n_fired = nf; rq.cand = &c; rq.n_cand = 1; rq.x_kinds = xk;
				rq.score = sc; rq.score_cap = 1; rq.elems = out; rq.elems_cap = 3 * NU;
				rq.group = og; rq.group_cap = 8; rq.entry = oe; rq.entry_cap = 8;
				kof_vmatch(&rq, &rs);
				CK(rs.status == KOF_VMATCH_OK);
				/* brute force */
				for (u = 0; u < NU; u++) {
					int inv = (ps >> u & 1u) != 0;

					if (x[u] && inv) { M[U8[u].kind]++; tm++; }
					if (!x[u] && inv) { Un[U8[u].kind]++; tu++; }
					if (x[u] && !inv) { N[U8[u].kind]++; tn++; }
				}
				CK(sc[0].matched == tm && sc[0].unseen == tu && sc[0].extra == tn);
				j = (tm + tu + tn) ? (1000.0 * tm / (double)(tm + tu + tn)) : 1000.0;
				CK(sc[0].permille == (uint32_t)j);
				for (k = 0; k < 3; k++) {
					uint32_t d = M[k] + Un[k] + N[k];

					CK(sc[0].kmatched[k] == M[k] && sc[0].kunseen[k] == Un[k] && sc[0].kextra[k] == N[k]);
					CK(sc[0].kpermille[k] == (uint32_t)(d ? (1000.0 * M[k] / (double)d) : 1000.0));
				}
				CK(rs.n_elems == tm + tu + tn && sc[0].elem_first == 0u);
				/* the listed elements: M, then U, then N, each in universe order (kind, a, b ascending = U8 order) */
				pos = 0;
				for (k = 0; k < 3; k++)
					for (u = 0; u < NU; u++) {
						int inv = (ps >> u & 1u) != 0;

						if ((k == 0 && x[u] && inv) || (k == 1 && !x[u] && inv) || (k == 2 && x[u] && !inv)) {
							CK(pos < rs.n_elems && !memcmp(&out[pos], &U8[u], sizeof out[0]));
							pos++;
						}
					}
				CK(pos == rs.n_elems);
				{
					uint32_t nxo = 0;

					for (u = 0; u < NU; u++)
						nxo += (uint32_t)x[u];
					CK(rs.n_x == nxo && rs.n_xk[0] + rs.n_xk[1] + rs.n_xk[2] == nxo);
				}
			}
		}
	}
}

static const struct kof_vmatch_elem T1 = { KOF_VMATCH_TAG, 1, 0 }, T2 = { KOF_VMATCH_TAG, 2, 0 }, T9 = { KOF_VMATCH_TAG, 9, 0 };

static void groups(void)
{
	/* mirai (family 1) variant 1 declared by two diagnoses with two types; variant 2 of the same family; one unattributed;
	 * family 0, variant 0 are ids like any other */
	struct kof_vmatch_fired f[5] = {
		{ 100, 1, 4, 1, 1, 1 }, { 101, 2, 9, 0, 0, 0 }, { 102, 1, 6, 1, 1, 1 }, { 103, 3, 4, 1, 2, 1 }, { 104, 5, 4, 0, 0, 1 },
	};
	struct kof_vmatch_elem pv1[2] = { T1, T2 }, pv2[1] = { { KOF_VMATCH_TAG, 3, 0 } };
	struct kof_vmatch_cand c[3] = { { 1, 1, pv1, 2 }, { 1, 2, pv2, 1 }, { 7, 7, pv1, 2 } };
	struct kof_vmatch_group g[8];
	struct kof_vmatch_entry e[8];
	struct kof_vmatch_score s[3];
	struct kof_vmatch_elem el[16];
	struct kof_vmatch_req rq;
	struct kof_vmatch_res rs;

	memset(&rq, 0, sizeof rq);
	rq.fired = f; rq.n_fired = 5; rq.cand = c; rq.n_cand = 3; rq.x_kinds = 1u << KOF_VMATCH_TAG;
	rq.group = g; rq.group_cap = 8; rq.entry = e; rq.entry_cap = 8; rq.score = s; rq.score_cap = 3;
	rq.elems = el; rq.elems_cap = 16;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_OK && rs.n_groups == 4 && rs.n_entries == 5);
	/* order of first appearance: (1,1) {100,102}, unattributed {101}, (1,2) {103}, (0,0) {104} */
	CK(g[0].has_variant && g[0].family == 1 && g[0].variant == 1 && g[0].entry_first == 0 && g[0].entry_count == 2);
	CK(e[0].diag == 100 && e[0].type == 4 && e[1].diag == 102 && e[1].type == 6);      /* two entries, two types, never merged */
	CK(!g[1].has_variant && g[1].entry_count == 1 && e[2].diag == 101 && e[2].type == 9 && g[1].score_index == KOF_VMATCH_NONE);
	CK(g[2].family == 1 && g[2].variant == 2 && e[3].diag == 103);
	CK(g[3].has_variant && g[3].family == 0 && g[3].variant == 0 && e[4].diag == 104);
	CK(g[0].score_index == 0 && g[2].score_index == 1 && g[3].score_index == KOF_VMATCH_NONE);
	/* D(x) = tags {1,2,3,5}: profile {1,2} matches 2 of 4; the candidate (7,7) with the same tags has the same numbers - the score
	 * does not look at the family, and the groups do not look at the score */
	CK(s[0].matched == 2 && s[0].unseen == 0 && s[0].extra == 2 && s[0].permille == 500);
	CK(s[1].matched == 1 && s[1].extra == 3 && s[1].permille == 250);
	CK(s[2].matched == s[0].matched && s[2].permille == s[0].permille && g[0].score_index == 0);
	/* the same sample asked for no scores gives the same groups */
	{
		struct kof_vmatch_group g2[8];
		struct kof_vmatch_entry e2[8];

		rq.cand = NULL; rq.n_cand = 0; rq.score = NULL; rq.score_cap = 0; rq.group = g2; rq.entry = e2;
		kof_vmatch(&rq, &rs);
		CK(rs.n_groups == 4 && g2[0].entry_count == 2 && g2[0].score_index == KOF_VMATCH_NONE && e2[1].type == 6);
	}
	/* kinds asked: family and variant evidence only from the declared variants; the unattributed diagnose adds none */
	rq.x_kinds = (1u << KOF_VMATCH_FAMILY) | (1u << KOF_VMATCH_VARIANT);
	rq.group = NULL; rq.group_cap = 0; rq.entry = NULL; rq.entry_cap = 0;
	kof_vmatch(&rq, &rs);
	CK(rs.n_xk[KOF_VMATCH_TAG] == 0 && rs.n_xk[KOF_VMATCH_FAMILY] == 2 && rs.n_xk[KOF_VMATCH_VARIANT] == 3 && rs.n_x == 5);
	CK(rs.status == KOF_VMATCH_TRUNCATED && rs.n_groups == 4);
}

static void bounds(void)
{
	struct kof_vmatch_fired f[2] = { { 1, 1, 1, 0, 0, 0 }, { 2, 2, 1, 0, 0, 0 } };
	struct kof_vmatch_elem p[4] = { T2, T9, T9, T9 };
	struct kof_vmatch_cand c[2] = { { 1, 1, p, 4 }, { 1, 2, p, 4 } };
	struct kof_vmatch_elem out[8], big[KOF_VMATCH_SET_MAX + 1];
	struct kof_vmatch_score s[2];
	struct kof_vmatch_group gg[2];
	struct kof_vmatch_entry ee[2];
	struct kof_vmatch_req rq;
	struct kof_vmatch_res rs;
	static struct kof_vmatch_fired many[KOF_VMATCH_FIRED_MAX + 1];
	static struct kof_vmatch_cand manyc[KOF_VMATCH_CAND_MAX + 1];
	uint32_t i;

	memset(&rq, 0, sizeof rq);
	rq.fired = f; rq.n_fired = 2; rq.cand = c; rq.n_cand = 2; rq.x_kinds = 1u << KOF_VMATCH_TAG;
	/* repeats count once: D(v) = {2, 9}, D(x) = {1, 2}: M {2}, U {9}, N {1}; J = 1/3 -> 333 */
	rq.score = s; rq.score_cap = 2; rq.elems = out; rq.elems_cap = 8;
	rq.group = gg; rq.group_cap = 2; rq.entry = ee; rq.entry_cap = 2;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_OK && s[0].matched == 1 && s[0].unseen == 1 && s[0].extra == 1 && s[0].permille == 333);
	CK(rs.n_elems == 6 && s[1].elem_first == 3 && out[0].a == 2 && out[1].a == 9 && out[2].a == 1);
	/* capacity 0: counts only, the true totals */
	rq.score = NULL; rq.score_cap = 0; rq.elems = NULL; rq.elems_cap = 0;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TRUNCATED && rs.n_elems == 6 && rs.n_scores == 2 && rs.n_entries == 2 && rs.n_groups == 1);
	/* smaller than needed: the prefix of the full ordering, the true total */
	rq.score = s; rq.score_cap = 1; rq.elems = out; rq.elems_cap = 4;
	memset(out, 0xee, sizeof out);
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TRUNCATED && rs.n_elems == 6 && s[1].elem_first == 3);
	CK(out[0].a == 2 && out[3].a == 2 && out[4].a == 0xeeeeeeeeu);                        /* the fifth element was not written */
	/* two empty sets: J = 1000 for all and for every kind */
	rq.n_fired = 0; rq.n_cand = 1; c[0].n_elem = 0; rq.score_cap = 2;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_OK && s[0].permille == 1000 && s[0].kpermille[0] == 1000 && s[0].kpermille[2] == 1000 && rs.n_x == 0);
	/* an empty x and a full profile: J = 0, one kind empty on both sides is 1000 */
	c[0].n_elem = 2;
	kof_vmatch(&rq, &rs);
	CK(s[0].permille == 0 && s[0].kpermille[KOF_VMATCH_TAG] == 0 && s[0].kpermille[KOF_VMATCH_FAMILY] == 1000);
	/* the largest set is computed, one more is skipped and the others are still scored */
	for (i = 0; i < KOF_VMATCH_SET_MAX + 1u; i++) {
		big[i].kind = KOF_VMATCH_TAG; big[i].a = i % 7u; big[i].b = 0;
	}
	rq.n_fired = 2; rq.n_cand = 2;
	c[0].elem = big; c[0].n_elem = KOF_VMATCH_SET_MAX;
	c[1].elem = big; c[1].n_elem = KOF_VMATCH_SET_MAX + 1u;
	rq.elems_cap = 8;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TOO_LARGE && !(s[0].flags & KOF_VMATCH_SKIPPED) && s[0].matched == 2 && s[0].unseen == 5);
	CK((s[1].flags & KOF_VMATCH_SKIPPED) && s[1].matched == 0 && s[1].permille == 0);
	/* the fired and candidate lists: the maximum is accepted, one more is refused with nothing computed */
	for (i = 0; i < KOF_VMATCH_FIRED_MAX + 1u; i++) {
		many[i].diag = i; many[i].tag = i; many[i].type = 1; many[i].has_variant = 1; many[i].family = i; many[i].variant = i;
	}
	memset(&rq, 0, sizeof rq);
	rq.fired = many; rq.n_fired = KOF_VMATCH_FIRED_MAX; rq.x_kinds = 7u;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TRUNCATED && rs.n_groups == KOF_VMATCH_FIRED_MAX && rs.n_x == 3u * KOF_VMATCH_FIRED_MAX);
	rq.n_fired = KOF_VMATCH_FIRED_MAX + 1u;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TOO_LARGE && rs.n_groups == 0 && rs.n_x == 0 && rs.n_entries == KOF_VMATCH_FIRED_MAX + 1u);
	for (i = 0; i < KOF_VMATCH_CAND_MAX + 1u; i++)
		manyc[i].family = i;
	rq.n_fired = 0; rq.cand = manyc; rq.n_cand = KOF_VMATCH_CAND_MAX;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TRUNCATED && rs.n_scores == KOF_VMATCH_CAND_MAX);
	rq.n_cand = KOF_VMATCH_CAND_MAX + 1u;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_TOO_LARGE && rs.n_scores == KOF_VMATCH_CAND_MAX + 1u);
	/* a bad request */
	memset(&rq, 0, sizeof rq);
	rq.n_fired = 1;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_BAD_REQUEST);
	memset(&rq, 0, sizeof rq);
	rq.x_kinds = 8u;
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_BAD_REQUEST);
	{
		struct kof_vmatch_elem bad = { 3, 0, 0 };
		struct kof_vmatch_cand bc = { 0, 0, &bad, 1 };

		memset(&rq, 0, sizeof rq);
		rq.cand = &bc; rq.n_cand = 1;
		kof_vmatch(&rq, &rs);
		CK(rs.status == KOF_VMATCH_BAD_REQUEST);
	}
	kof_vmatch(NULL, &rs);
	CK(rs.status == KOF_VMATCH_BAD_REQUEST);
	kof_vmatch(&rq, NULL);
	/* nothing fired, nothing asked: OK and empty */
	memset(&rq, 0, sizeof rq);
	kof_vmatch(&rq, &rs);
	CK(rs.status == KOF_VMATCH_OK && rs.n_groups == 0 && rs.n_x == 0);
}

int main(void)
{
	oracle();
	groups();
	bounds();
	printf("vmatch: %d failure(s)\n", fails);
	return fails ? 1 : 0;
}
