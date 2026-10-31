/*
 * engine/vmatch - the matching library of the verdict (libkofeng/verdictor/vmatch.c), a request decoded from the bytes (shape FZ_REQ).
 * The input is: n_fired, n_cand, x_kinds and four capacities (one byte each), then 5 bytes a fired diagnose (tag, type, family,
 * variant, has_variant) and, per candidate, a count and 3 bytes an element (kind, a, b); ids are taken modulo a small number so that
 * repeats, shared tags and equal variants are the common case. Held for every input:
 *   - totals: |M| + |N| = |D(x)|; per-kind counts add up to the totals; D(x) per kind adds up to n_x; J is in 0..1000 and is 1000 only
 *     when U and N are both empty; the groups hold every fired diagnose once (entry counts add up to n_fired, ranges are contiguous)
 *   - the arrays hold a PREFIX of the full ordering: the same request with room for everything agrees with the small one on what fit,
 *     and the status is TRUNCATED exactly when something did not fit (and the true totals are the same either way)
 *   - the order of a profile and a repeat inside it change nothing (reversed and doubled profile give the same numbers)
 *   - a score beside a group is the candidate of that family and variant, and the groups do not depend on the candidates
 */
#include <string.h>

#include "../../lib/fuzz_drv.h"
#include "../../../libkofeng/verdictor/vmatch.h"

#define VF_FIRED 24u
#define VF_CAND 6u
#define VF_ELEM 12u

static void vf_seeds(struct fz_corpus *c)
{
	static const uint8_t a[] = { 3, 2, 7, 4, 4, 4, 4,  1, 1, 0, 1, 1, 1,  2, 2, 0, 1, 1, 1,  3, 3, 0, 2, 1, 0,
				     3, 0, 1, 0, 2, 1, 0, 2, 2,  2, 2, 1, 0 };
	static const uint8_t b[] = { 0, 0, 0, 0, 0, 0, 0 };

	fz_corpus_add(c, "mixed", a, sizeof a);
	fz_corpus_add(c, "empty", b, sizeof b);
}

static int vf_same_numbers(const struct kof_vmatch_score *p, const struct kof_vmatch_score *q)
{
	return !memcmp(&p->matched, &q->matched, 3u * sizeof p->matched) && p->permille == q->permille &&
	       !memcmp(p->kmatched, q->kmatched, sizeof p->kmatched) && !memcmp(p->kunseen, q->kunseen, sizeof p->kunseen) &&
	       !memcmp(p->kextra, q->kextra, sizeof p->kextra) && !memcmp(p->kpermille, q->kpermille, sizeof p->kpermille);
}

static int vf_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kof_vmatch_fired f[VF_FIRED];
	struct kof_vmatch_elem pe[VF_CAND][VF_ELEM], re[VF_CAND][2u * VF_ELEM];
	struct kof_vmatch_cand cd[VF_CAND], rc[VF_CAND];
	struct kof_vmatch_group g[VF_FIRED], gb[VF_FIRED];
	struct kof_vmatch_entry e[VF_FIRED], eb[VF_FIRED];
	struct kof_vmatch_score s[VF_CAND], sb[VF_CAND], sr[VF_CAND];
	struct kof_vmatch_elem el[3u * VF_ELEM * VF_CAND + 8u], elb[3u * VF_ELEM * VF_CAND + 8u];
	struct kof_vmatch_req rq, big, rev;
	struct kof_vmatch_res rs, rb, rr;
	size_t at = 7;
	uint32_t i, j, k, nf, nc, sum = 0, cap_g, cap_e, cap_s, cap_i;

	if (n < 7u)
		return 0;
	nf = in[0] % (VF_FIRED + 1u);
	nc = in[1] % (VF_CAND + 1u);
	cap_g = in[3] % (VF_FIRED + 2u);
	cap_e = in[4] % (VF_FIRED + 2u);
	cap_s = in[5] % (VF_CAND + 2u);
	cap_i = in[6] % 64u;
	for (i = 0; i < nf; i++) {
		uint8_t r[5] = { 0 };

		for (j = 0; j < 5u; j++)
			r[j] = at < n ? in[at++] : 0;
		f[i].diag = i;
		f[i].tag = r[0] % 5u;
		f[i].type = r[1] % 3u;
		f[i].family = r[2] % 3u;
		f[i].variant = r[3] % 3u;
		f[i].has_variant = r[4] & 1u;
	}
	for (i = 0; i < nc; i++) {
		uint32_t ne = (at < n ? in[at++] : 0) % (VF_ELEM + 1u);

		for (j = 0; j < ne; j++) {
			uint8_t r[3] = { 0 };

			for (k = 0; k < 3u; k++)
				r[k] = at < n ? in[at++] : 0;
			pe[i][j].kind = r[0] % 3u;
			pe[i][j].a = r[1] % 4u;
			pe[i][j].b = r[2] % 3u;
		}
		cd[i].family = i % 2u;
		cd[i].variant = i / 2u;
		cd[i].elem = pe[i];
		cd[i].n_elem = ne;
		rc[i] = cd[i];
		for (j = 0; j < ne; j++) {                       /* reversed, and every element twice */
			re[i][2u * j] = pe[i][ne - 1u - j];
			re[i][2u * j + 1u] = pe[i][ne - 1u - j];
		}
		rc[i].elem = re[i];
		rc[i].n_elem = 2u * ne;
	}
	memset(&rq, 0, sizeof rq);
	rq.fired = f; rq.n_fired = nf; rq.cand = cd; rq.n_cand = nc; rq.x_kinds = in[2] & 7u;
	rq.group = g; rq.group_cap = cap_g; rq.entry = e; rq.entry_cap = cap_e; rq.score = s; rq.score_cap = cap_s;
	rq.elems = el; rq.elems_cap = cap_i;
	big = rq;
	big.group = gb; big.group_cap = VF_FIRED; big.entry = eb; big.entry_cap = VF_FIRED; big.score = sb; big.score_cap = VF_CAND;
	big.elems = elb; big.elems_cap = (uint32_t)(sizeof elb / sizeof elb[0]);
	rev = big;
	rev.cand = rc; rev.score = sr;
	kof_vmatch(&rq, &rs);
	kof_vmatch(&big, &rb);
	kof_vmatch(&rev, &rr);
	FZ_CHECK(c, rb.status == KOF_VMATCH_OK, "room for everything is not OK");
	FZ_CHECK(c, rs.n_groups == rb.n_groups && rs.n_elems == rb.n_elems && rs.n_x == rb.n_x && rs.n_entries == nf && rs.n_scores == nc,
		 "the true totals depend on the capacities");
	FZ_CHECK(c, (rs.status == KOF_VMATCH_TRUNCATED) == (rb.n_groups > cap_g || nf > cap_e || nc > cap_s || rb.n_elems > cap_i),
		 "TRUNCATED does not say exactly that something did not fit");
	FZ_CHECK(c, rr.n_elems == rb.n_elems && rr.n_x == rb.n_x, "a reversed, doubled profile changed the totals");
	FZ_CHECK(c, rb.n_xk[0] + rb.n_xk[1] + rb.n_xk[2] == rb.n_x, "D(x) per kind does not add up");
	for (i = 0; i < rb.n_groups; i++) {
		FZ_CHECK(c, gb[i].entry_first == sum, "group ranges are not contiguous");
		sum += gb[i].entry_count;
		FZ_CHECK(c, gb[i].score_index == KOF_VMATCH_NONE || gb[i].score_index < nc, "a score index out of range");
		if (gb[i].score_index != KOF_VMATCH_NONE)
			FZ_CHECK(c, cd[gb[i].score_index].family == gb[i].family && cd[gb[i].score_index].variant == gb[i].variant &&
				 gb[i].has_variant, "the score beside a group is another variant's");
		if (i < cap_g)
			FZ_CHECK(c, !memcmp(&g[i], &gb[i], sizeof g[i]), "a small group array disagrees with the full one");
	}
	FZ_CHECK(c, sum == nf, "the groups do not hold every fired diagnose once");
	for (i = 0; i < nf && i < cap_e; i++)
		FZ_CHECK(c, !memcmp(&e[i], &eb[i], sizeof e[i]), "a small entry array disagrees with the full one");
	for (i = 0; i < rb.n_elems && i < cap_i; i++)
		FZ_CHECK(c, !memcmp(&el[i], &elb[i], sizeof el[i]), "a small element array disagrees with the full one");
	for (i = 0; i < nc; i++) {
		const struct kof_vmatch_score *p = &sb[i];
		uint32_t kk;

		FZ_CHECK(c, vf_same_numbers(p, &sr[i]), "the order or a repeat in a profile changed the numbers");
		if (i < cap_s)
			FZ_CHECK(c, !memcmp(&s[i], p, sizeof *p), "a small score array disagrees with the full one");
		FZ_CHECK(c, p->matched + p->extra == rb.n_x, "M + N is not D(x)");
		FZ_CHECK(c, p->permille <= 1000u && (p->permille != 1000u || (p->unseen == 0u && p->extra == 0u)), "J out of range");
		for (kk = 0; kk < KOF_VMATCH_KINDS; kk++)
			FZ_CHECK(c, p->kmatched[kk] + p->kextra[kk] == rb.n_xk[kk] && p->kpermille[kk] <= 1000u, "a per-kind count is wrong");
		fz_digest(c, p->permille ^ (uint64_t)p->matched << 12 ^ (uint64_t)p->unseen << 20 ^ (uint64_t)p->extra << 28);
	}
	fz_digest(c, (uint64_t)rb.n_groups << 8 ^ rb.n_elems ^ (uint64_t)rb.n_x << 24 ^ (uint64_t)rs.status << 40);
	return rs.status == KOF_VMATCH_OK;
}

FZ_ADAPTER(diag_vmatch, .name = "engine/vmatch", .shape = FZ_REQ, .seeds = vf_seeds, .run = vf_run);
