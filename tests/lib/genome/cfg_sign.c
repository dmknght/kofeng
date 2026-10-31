/*
 * genome / cfg_sign - the signature of a function's shape (celllysis/cfg.h: labels, one WL round, canonical hash,
 * bottom-32 sketch, pct, anchor, view), through <kgenome.h> alone.
 *
 *   HAND         canonical hash and key of three tiny graphs computed step by step from the label rule (R)
 *   EXHAUSTIVE   every layout-valid graph of 1..5 blocks (each block: exit, fall, jump t, cond t): the canonical
 *                hash is the same for isomorphic graphs under ANY renumbering of the non-entry blocks, and
 *                the PARTITION of the graphs by canonical hash equals the partition by the exact WL1 multiset
 *                (labels as strings, no hash): equal hash exactly when the multisets are equal. The non-isomorphic
 *                graphs WL1 cannot tell apart are COUNTED and pinned: that number is the known limit.
 *   ISAS         the same graph assembled for six architectures has one signature
 *   PROPERTIES   random functions, fixed seeds: padding, calls, call targets, address shifts, unreachable junk
 *                after an exit, relayout of fall-through chains, and a swap of a conditional's successors do not
 *                move the signature; an exit turned into a jump, an extra edge and a removed block do
 *   DIFFERENTIAL the sketch equals the survey harness' sorted algorithm (cfg_kit.h ref_sign) element for element
 *   PCT          identical 100, disjoint 0, symmetric, monotone in the blocks changed, error against the exact
 *                Jaccard measured and bounded
 *   ANCHOR       11/12/13 reachable blocks; unreachable blocks do not count; the OR flags
 *   VIEW         the table a viewer draws: indices, labels, the status carried
 */
#include "cfg_kit.h"

/* measured, then pinned: see exhaustive() */
#define EXPECT_GRAPHS 128387u
#define EXPECT_WL1_COLLISIONS 2792u
#define EXPECT_WL1_ISO 8015u
/* measured 0.53 and 12.44 points over 1529 pairs (the survey's bk32 mean was 1.1): the bounds are twice and 1.6x those */
#define EXPECT_ERR_MEAN 1.1
#define EXPECT_ERR_MAX 20.0

/* The element of a sketch for (label, k-th occurrence), spelled out: the high word of the mix that starts at the domain seed (cfg.h). */
#define KEYOF(l, k) ((uint32_t)(rmix(rmix(KGENOME_CFG_KEY_SEED, (l)), (k)) >> 32))
/* ... and the element the sketch had before the domain separation: no key of today may be one of these by construction. */
#define KEY_UNSEEDED(l, k) ((uint32_t)(rmix((l), (k)) >> 32))

/* ---- 1. hand-computed ---- */
static void hand(void)
{
	/* one block, ret: label = mix(mix(mix(7, in 0), out 0), EXIT 3); WL1 over no edges = mix(mix(l, 0), 0) */
	const uint64_t l1 = rmix(rmix(rmix(7u, 0u), 0u), 3u);
	const uint64_t w1 = rmix(rmix(l1, 0u), 0u);
	const uint64_t sum1 = rmix(w1, 0x4d554c5449534554ull);
	struct gspec g;
	struct kgenome_cfg_sign s;

	memset(&g, 0, sizeof g);
	g.nb = 1; g.kind[0] = G_EXIT;
	CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s, NULL));
	CK(s.n_blk == 1 && s.n_key == 1 && s.status == KGENOME_OK);
	CK(s.canon == rmix(rmix(rmix(0x5151u, 1u), 0u), sum1));
	CK(s.key[0] == KEYOF(w1, 0u));
	CK(gspec_sign(&ISAS[0], &g, 0x1000, 1, &s, NULL) && s.canon == rmix(rmix(rmix(0x5151u, 1u), 0u), sum1));       /* rounds 1 == default */

	{
		/* B0 COND ->2 (falls into B1); B1 FALL into B2; B2 EXIT. (A fall into a block nothing else reaches would be ONE block.) */
		const uint64_t a0 = rmix(rmix(rmix(7u, 0u), 2u), 1u), a1 = rmix(rmix(rmix(7u, 1u), 1u), 0u), a2 = rmix(rmix(rmix(7u, 2u), 0u), 3u);
		const uint64_t b0 = rmix(rmix(a0, 0u), rmix(a2, 2u) + rmix(a1, 2u));
		const uint64_t b1 = rmix(rmix(a1, rmix(a0, 1u)), rmix(a2, 2u));
		const uint64_t b2 = rmix(rmix(a2, rmix(a0, 1u) + rmix(a1, 1u)), 0u);
		const uint64_t sum = rmix(b0, 0x4d554c5449534554ull) + rmix(b1, 0x4d554c5449534554ull) + rmix(b2, 0x4d554c5449534554ull);
		uint32_t e[3] = { KEYOF(b0, 0u), KEYOF(b1, 0u), KEYOF(b2, 0u) }, t;
		unsigned i, j;

		for (i = 0; i < 3; i++) for (j = i + 1; j < 3; j++) if (e[i] > e[j]) { t = e[i]; e[i] = e[j]; e[j] = t; }
		memset(&g, 0, sizeof g);
		g.nb = 3; g.kind[0] = G_COND; g.t[0] = 2; g.kind[1] = G_FALL; g.kind[2] = G_EXIT;
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s, NULL));
		CK(s.n_blk == 3 && s.n_key == 3 && s.key[0] == e[0] && s.key[1] == e[1] && s.key[2] == e[2]);
		CK(s.canon == rmix(rmix(rmix(0x5151u, 3u), 3u), sum));
	}
	{
		/* diamond: B0 COND ->2 (fall 1); B1 JUMP ->3; B2 FALL; B3 EXIT */
		const uint64_t c0 = rmix(rmix(rmix(7u, 0u), 2u), 1u), c1 = rmix(rmix(rmix(7u, 1u), 1u), 2u);
		const uint64_t c2 = rmix(rmix(rmix(7u, 1u), 1u), 0u), c3 = rmix(rmix(rmix(7u, 2u), 0u), 3u);
		const uint64_t d0 = rmix(rmix(c0, 0u), rmix(c1, 2u) + rmix(c2, 2u));
		const uint64_t d1 = rmix(rmix(c1, rmix(c0, 1u)), rmix(c3, 2u));
		const uint64_t d2 = rmix(rmix(c2, rmix(c0, 1u)), rmix(c3, 2u));
		const uint64_t d3 = rmix(rmix(c3, rmix(c1, 1u) + rmix(c2, 1u)), 0u);
		const uint64_t sum = rmix(d0, 0x4d554c5449534554ull) + rmix(d1, 0x4d554c5449534554ull) + rmix(d2, 0x4d554c5449534554ull) + rmix(d3, 0x4d554c5449534554ull);

		memset(&g, 0, sizeof g);
		g.nb = 4; g.kind[0] = G_COND; g.t[0] = 2; g.kind[1] = G_JUMP; g.t[1] = 3; g.kind[2] = G_FALL; g.kind[3] = G_EXIT;
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s, NULL));
		CK(s.n_blk == 4 && s.canon == rmix(rmix(rmix(0x5151u, 4u), 4u), sum));
		/* B1 (jump) and B2 (fall) differ only in their terminator class: four distinct labels, four elements */
		CK(s.n_key == 4);
	}
}

/* ---- 2. exhaustive over small graphs ---- */
struct gcase {
	uint64_t canon;
	uint32_t n_key, key[KGENOME_CFG_KEYS];
	char *wl1;              /* exact WL1 multiset, a string */
	char *iso;              /* canonical form under renumbering: a string */
};

static int cmp_wl1(const void *a, const void *b)
{
	return strcmp((*(const struct gcase *const *)a)->wl1, (*(const struct gcase *const *)b)->wl1);
}
static int cmp_iso(const void *a, const void *b)
{
	return strcmp((*(const struct gcase *const *)a)->iso, (*(const struct gcase *const *)b)->iso);
}
static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* The exact WL1 multiset of the reachable blocks: label0 = "in,out,term", label1 = label0 + sorted predecessor label0s + sorted successor label0s. */
static char *exact_wl1(const struct refg *r)
{
	uint32_t b, i, n = 0, indeg[64] = { 0 };
	char *l0[64], *l1[64];
	size_t cap = 4096, len = 0;
	char *out = malloc(cap);

	for (b = 0; b < r->nb; b++)
		if (r->reach[b])
			for (i = 0; i < 2; i++)
				if (r->succ[b][i] != KGENOME_CFG_NONE)
					indeg[r->succ[b][i]]++;
	for (b = 0; b < r->nb; b++) {
		l0[b] = NULL;
		if (r->reach[b]) {
			l0[b] = malloc(32);
			snprintf(l0[b], 32, "%u,%u,%u", indeg[b], (r->succ[b][0] != KGENOME_CFG_NONE) + (r->succ[b][1] != KGENOME_CFG_NONE), r->term[b]);
		}
	}
	for (b = 0; b < r->nb; b++) {
		char *ps[64], *ss[64];
		uint32_t np = 0, ns = 0, c;
		char buf[1024];
		int w;

		l1[b] = NULL;
		if (!r->reach[b])
			continue;
		for (c = 0; c < r->nb; c++) {
			if (!r->reach[c])
				continue;
			for (i = 0; i < 2; i++) {
				if (r->succ[c][i] == b)
					ps[np++] = l0[c];
				if (c == b && r->succ[b][i] != KGENOME_CFG_NONE)
					ss[ns++] = l0[r->succ[b][i]];
			}
		}
		qsort(ps, np, sizeof *ps, cmp_str);
		qsort(ss, ns, sizeof *ss, cmp_str);
		w = snprintf(buf, sizeof buf, "<%s|P", l0[b]);
		for (c = 0; c < np; c++)
			w += snprintf(buf + w, sizeof buf - (size_t)w, "(%s)", ps[c]);
		w += snprintf(buf + w, sizeof buf - (size_t)w, "|S");
		for (c = 0; c < ns; c++)
			w += snprintf(buf + w, sizeof buf - (size_t)w, "(%s)", ss[c]);
		l1[b] = strdup(buf);
		n++;
	}
	{
		char *sorted[64];
		uint32_t k = 0;

		for (b = 0; b < r->nb; b++)
			if (l1[b])
				sorted[k++] = l1[b];
		qsort(sorted, k, sizeof *sorted, cmp_str);
		len = (size_t)snprintf(out, cap, "nb%u,ne%u:", r->n_blk, r->n_edge);
		for (i = 0; i < k; i++)
			len += (size_t)snprintf(out + len, cap - len, "%s", sorted[i]);
	}
	for (b = 0; b < r->nb; b++) { free(l0[b]); free(l1[b]); }
	(void)n;
	return out;
}

/* The canonical form of the reachable graph under every renumbering that keeps block 0 first: the smallest encoding. */
static char *iso_form(const struct refg *r)
{
	uint32_t rb[8], n = 0, b, perm[8], i, k;
	char *best = NULL;
	char cur[512];

	for (b = 0; b < r->nb; b++)
		if (r->reach[b])
			rb[n++] = b;
	for (i = 0; i < n; i++)
		perm[i] = i;
	/* heap's algorithm would do; n <= 5 and block 0 fixed: iterate every permutation of positions 1..n-1 by next_permutation */
	for (;;) {
		uint32_t newidx[64];
		int w = 0;

		for (i = 0; i < n; i++)
			newidx[rb[perm[i]]] = i;
		for (i = 0; i < n; i++) {
			const uint32_t ob = rb[perm[i]];
			uint32_t s0 = r->succ[ob][0] == KGENOME_CFG_NONE ? 99u : newidx[r->succ[ob][0]];
			uint32_t s1 = r->succ[ob][1] == KGENOME_CFG_NONE ? 99u : newidx[r->succ[ob][1]];

			if (s0 > s1) { uint32_t t = s0; s0 = s1; s1 = t; }
			w += snprintf(cur + w, sizeof cur - (size_t)w, "%u:%u,%u;", r->term[ob], s0, s1);
		}
		if (!best || strcmp(cur, best) < 0) {
			free(best);
			best = strdup(cur);
		}
		/* next permutation of perm[1..n-1] */
		k = n;
		if (n < 3)
			break;
		for (i = n - 1; i > 1 && perm[i - 1] > perm[i]; i--)
			;
		if (i <= 1)
			break;
		k = i - 1;
		for (i = n - 1; perm[i] < perm[k]; i--)
			;
		{ uint32_t t = perm[k]; perm[k] = perm[i]; perm[i] = t; }
		for (i = k + 1, b = n - 1; i < b; i++, b--) { uint32_t t = perm[i]; perm[i] = perm[b]; perm[b] = t; }
	}
	return best;
}

static void exhaustive(void)
{
	struct gcase *cs = NULL, **by;
	size_t ncs = 0, capcs = 0, i, j;
	uint32_t nb;
	uint64_t n_graphs = 0, wl1_split = 0, iso_in_wl1 = 0, wl1_groups = 0, wl1_groups_multi = 0, bad_iso = 0, bad_part = 0;

	for (nb = 1; nb <= 5; nb++) {
		const uint32_t opts = 2u + 2u * nb;
		uint32_t c[5] = { 0 }, b;

		for (;;) {
			struct gspec g;
			struct kgenome_cfg_sign s;
			struct refg r;
			int valid = 1;

			memset(&g, 0, sizeof g);
			g.nb = nb;
			for (b = 0; b < nb; b++) {
				const uint32_t o = c[b];

				if (o == 0) { g.kind[b] = G_EXIT; }
				else if (o == 1) { g.kind[b] = G_FALL; }
				else if (o < 2u + nb) { g.kind[b] = G_JUMP; g.t[b] = o - 2u; }
				else { g.kind[b] = G_COND; g.t[b] = o - 2u - nb; if (b + 1u == nb) valid = 0; }
			}
			/* a fall into block b+1 makes a block boundary only when something else reaches b+1 (a jump or branch names it) */
			for (b = 0; b + 1u < nb && valid; b++) {
				uint32_t q;
				int named = 0;

				if (g.kind[b] != G_FALL)
					continue;
				for (q = 0; q < nb; q++)
					named |= (g.kind[q] == G_JUMP || g.kind[q] == G_COND) && g.t[q] == b + 1u;
				valid = named;
			}
			if (valid) {
				if (ncs == capcs) {
					capcs = capcs ? capcs * 2 : 4096;
					cs = realloc(cs, capcs * sizeof *cs);
				}
				if (!gspec_sign(&ISAS[0], &g, 0x1000, 0, &s, NULL)) { fails++; return; }
				gspec_ref(&g, &r);
				cs[ncs].canon = s.canon;
				cs[ncs].n_key = s.n_key;
				memcpy(cs[ncs].key, s.key, sizeof s.key);
				cs[ncs].wl1 = exact_wl1(&r);
				cs[ncs].iso = iso_form(&r);
				ncs++;
				refg_free(&r);
			}
			for (b = 0; b < nb && ++c[b] == opts; b++)
				c[b] = 0;
			if (b == nb)
				break;
		}
	}
	n_graphs = ncs;
	by = malloc(ncs * sizeof *by);

	/* (a) isomorphic graphs: one canonical hash (and one sketch) */
	for (i = 0; i < ncs; i++) by[i] = &cs[i];
	qsort(by, ncs, sizeof *by, cmp_iso);
	for (i = 1; i < ncs; i++)
		if (!strcmp(by[i]->iso, by[i - 1]->iso) && (by[i]->canon != by[i - 1]->canon || by[i]->n_key != by[i - 1]->n_key ||
		    memcmp(by[i]->key, by[i - 1]->key, by[i]->n_key * sizeof(uint32_t))))
			bad_iso++;
	CKM(bad_iso == 0, "%llu isomorphic pairs with different signatures", (unsigned long long)bad_iso);

	/* (b) the partition by canonical hash equals the partition by the exact WL1 multiset */
	for (i = 0; i < ncs; i++) by[i] = &cs[i];
	qsort(by, ncs, sizeof *by, cmp_wl1);
	for (i = 0; i < ncs; i = j) {
		j = i + 1;
		while (j < ncs && !strcmp(by[j]->wl1, by[i]->wl1))
			j++;
		wl1_groups++;
		for (size_t k = i + 1; k < j; k++)
			if (by[k]->canon != by[i]->canon)
				bad_part++;     /* the same exact multiset, two hashes */
		if (i && by[i]->canon == by[i - 1]->canon)
			bad_part++;             /* two exact multisets, one hash (a 64-bit collision, or a bug) */
	}
	CKM(bad_part == 0, "%llu partition disagreements between the hash and the exact WL1 multiset", (unsigned long long)bad_part);
	{
		/* distinct canonical hashes must be exactly as many as exact WL1 classes */
		uint64_t *cv = malloc(ncs * sizeof *cv), nd = 0;

		for (i = 0; i < ncs; i++) cv[i] = cs[i].canon;
		qsort(cv, ncs, sizeof *cv, rcmp64);
		for (i = 0; i < ncs; i++) nd += !i || cv[i] != cv[i - 1];
		CKM(nd == wl1_groups, "canonical hashes %llu, exact WL1 classes %llu", (unsigned long long)nd, (unsigned long long)wl1_groups);
		free(cv);
	}

	/* (c) the known limit: isomorphism classes that share a WL1 multiset, counted (R: the survey's regular-graph collisions) */
	for (i = 0; i < ncs; i = j) {
		uint64_t isos = 1;

		for (j = i + 1; j < ncs && !strcmp(by[j]->wl1, by[i]->wl1); j++)
			;
		/* by[] is sorted by wl1 only: count distinct iso strings in the run */
		{
			char **v = malloc((j - i) * sizeof *v);
			size_t k;

			for (k = i; k < j; k++) v[k - i] = by[k]->iso;
			qsort(v, j - i, sizeof *v, cmp_str);
			for (k = 1; k < j - i; k++) isos += strcmp(v[k], v[k - 1]) != 0;
			free(v);
		}
		if (isos > 1) {
			if (!wl1_groups_multi || wl1_groups_multi == 1000) {
				size_t k;

				printf("  example WL1 collision (class %llu):", (unsigned long long)wl1_groups_multi);
				for (k = i; k < j && k < i + 3; k++)
					printf("  [%s]", by[k]->iso);
				printf("\n");
			}
			wl1_groups_multi++;
			iso_in_wl1 += isos;
		}
	}
	wl1_split = wl1_groups;
	printf("  exhaustive: %llu graphs, %llu exact WL1 classes, %llu of them hold several non-isomorphic graphs (%llu iso classes): the WL1 limit\n",
	       (unsigned long long)n_graphs, (unsigned long long)wl1_split, (unsigned long long)wl1_groups_multi, (unsigned long long)iso_in_wl1);
	CKM(n_graphs == EXPECT_GRAPHS, "graph count %llu", (unsigned long long)n_graphs);
	CKM(wl1_groups_multi == EXPECT_WL1_COLLISIONS && iso_in_wl1 == EXPECT_WL1_ISO, "WL1 collision classes %llu / iso classes %llu (pinned %u / %u)",
	    (unsigned long long)wl1_groups_multi, (unsigned long long)iso_in_wl1, EXPECT_WL1_COLLISIONS, EXPECT_WL1_ISO);
	for (i = 0; i < ncs; i++) { free(cs[i].wl1); free(cs[i].iso); }
	free(cs);
	free(by);
}


/* ---- 3. the same graph on six architectures ---- */
static void isas(void)
{
	unsigned k, i;
	struct crng rg;

	crng_seed(&rg, 77);
	for (k = 0; k < 300; k++) {
		struct gspec g;
		struct kgenome_cfg_sign s0, s1;
		uint32_t b, nb = 3u + crng_below(&rg, 12);

		memset(&g, 0, sizeof g);
		g.nb = nb;
		for (b = 0; b < nb; b++) {
			const uint32_t roll = crng_below(&rg, 100);

			g.kind[b] = roll < 15 ? G_EXIT : roll < 55 ? G_JUMP : G_COND;
			if (b + 1u == nb && g.kind[b] == G_COND)
				g.kind[b] = G_EXIT;
			g.t[b] = crng_below(&rg, nb);
			g.pad[b] = (uint8_t)crng_below(&rg, 3);
			g.calls[b] = (uint8_t)crng_below(&rg, 2);
		}
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s0, NULL));
		for (i = 1; i < N_ISAS; i++) {
			CK(gspec_sign(&ISAS[i], &g, 0x20000u + 4u * k, 0, &s1, NULL));
			CKM(sign_eq(&s0, &s1), "graph %u: %s differs from x86-64", k, ISAS[i].name);
		}
	}
}

/* ---- 4. random functions: what must not move the signature, and what must ---- */
static void gspec_random(struct crng *r, uint32_t nb, struct gspec *g)
{
	uint32_t b, q;

	memset(g, 0, sizeof *g);
	g->nb = nb;
	for (b = 0; b < nb; b++) {
		const uint32_t roll = crng_below(r, 100);
		const int32_t d = (int32_t)crng_below(r, 9) - 4;
		int32_t t = (int32_t)b + d;

		g->kind[b] = roll < 15 ? G_EXIT : roll < 40 ? G_FALL : roll < 65 ? G_JUMP : G_COND;
		if (b + 1u == nb && g->kind[b] == G_COND)
			g->kind[b] = G_EXIT;
		if (crng_below(r, 10) == 0)
			t = (int32_t)crng_below(r, nb);
		g->t[b] = (uint32_t)(t < 0 ? 0 : t >= (int32_t)nb ? (int32_t)nb - 1 : t);
		g->pad[b] = (uint8_t)crng_below(r, 3);
		g->calls[b] = (uint8_t)crng_below(r, 2);
	}
	/* a fall is a block boundary only into a block something names */
	for (b = 0; b + 1u < nb; b++) {
		int named = 0;

		if (g->kind[b] != G_FALL)
			continue;
		for (q = 0; q < nb; q++)
			named |= (g->kind[q] == G_JUMP || g->kind[q] == G_COND) && g->t[q] == b + 1u;
		if (!named) {
			g->kind[b] = G_JUMP;
			g->t[b] = b + 1u;
		}
	}
}

static uint32_t reach_count(const struct gspec *g)
{
	struct refg r;
	uint32_t n;

	gspec_ref(g, &r);
	n = r.n_blk;
	refg_free(&r);
	return n;
}

/* Insert a block at `pos`; every target at or past it moves up. */
static void gspec_insert(struct gspec *g, uint32_t pos, uint8_t kind, uint32_t t)
{
	uint32_t b;

	for (b = g->nb; b > pos; b--) {
		g->kind[b] = g->kind[b - 1u];
		g->t[b] = g->t[b - 1u];
		g->pad[b] = g->pad[b - 1u];
		g->calls[b] = g->calls[b - 1u];
	}
	g->kind[pos] = kind; g->t[pos] = t; g->pad[pos] = 0; g->calls[pos] = 0;
	g->nb++;
	for (b = 0; b < g->nb; b++)
		if (b != pos && g->t[b] >= pos && (g->kind[b] == G_JUMP || g->kind[b] == G_COND))
			g->t[b]++;
}

/* The fall-through chains: a chain is a run of blocks each falling into the next (fall or cond). */
static void gspec_relayout(const struct gspec *g, struct crng *r, struct gspec *o)
{
	uint32_t head[64], len[64], nch = 0, b, i, perm[64], newpos[64], at = 0;

	for (b = 0; b < g->nb; b++) {
		const int joins = b && (g->kind[b - 1u] == G_FALL || g->kind[b - 1u] == G_COND);

		if (!joins) {
			head[nch] = b;
			len[nch] = 1;
			nch++;
		} else {
			len[nch - 1u]++;
		}
	}
	for (i = 0; i < nch; i++)
		perm[i] = i;
	/* shuffle chains 1..last; chain 0 holds the entry and stays first, and a chain that falls off the end of the function stays last */
	for (i = nch - 1u - (g->kind[g->nb - 1u] == G_FALL && nch > 1u ? 1u : 0u); i > 1; i--) {
		const uint32_t j = 1u + crng_below(r, i);
		const uint32_t t = perm[i];

		perm[i] = perm[j];
		perm[j] = t;
	}
	for (i = 0; i < nch; i++) {
		uint32_t q;

		for (q = 0; q < len[perm[i]]; q++)
			newpos[head[perm[i]] + q] = at++;
	}
	*o = *g;
	for (b = 0; b < g->nb; b++) {
		const uint32_t n = newpos[b];

		o->kind[n] = g->kind[b];
		o->pad[n] = g->pad[b];
		o->calls[n] = g->calls[b];
		o->t[n] = (g->kind[b] == G_JUMP || g->kind[b] == G_COND) ? newpos[g->t[b]] : 0u;
	}
}

static void properties(void)
{
	struct crng rg;
	unsigned trial, tested = 0, changed_exit = 0, tried_exit = 0, changed_edge = 0, tried_edge = 0;

	crng_seed(&rg, 424242);
	for (trial = 0; trial < 1500; trial++) {
		struct gspec g, v;
		struct kgenome_cfg_sign s0, s1;
		struct kgenome_cfg cg;
		uint32_t nb = 6u + crng_below(&rg, 40), b;
		const struct isa_t *isa = &ISAS[crng_below(&rg, N_ISAS)];
		char tag[64];

		gspec_random(&rg, nb, &g);
		if (reach_count(&g) < 4)
			continue;
		tested++;
		snprintf(tag, sizeof tag, "trial %u (%s, %u blocks)", trial, isa->name, nb);
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s0, NULL));

		/* padding, calls, another address, another architecture: addresses, sizes and displacements move, the shape does not */
		v = g;
		for (b = 0; b < v.nb; b++) { v.pad[b] = (uint8_t)crng_below(&rg, 4); v.calls[b] = (uint8_t)crng_below(&rg, 3); }
		CK(gspec_sign(isa, &v, 0x400000u + 4u * crng_below(&rg, 4096), 0, &s1, NULL));
		CKM(sign_eq(&s0, &s1), "%s: padding / calls / rebase / ISA moved the signature", tag);

		/* unreachable junk after an exit or a jump, jumping anywhere (also into the live code) */
		v = g;
		for (b = 0; b < 3 && v.nb < 60; b++) {
			uint32_t pos, tries;

			for (tries = 0; tries < 20; tries++) {
				pos = 1u + crng_below(&rg, v.nb);
				if (pos <= v.nb && v.kind[pos - 1u] != G_FALL && v.kind[pos - 1u] != G_COND && (pos == v.nb || 1))
					break;
			}
			if (tries == 20)
				break;
			if (pos == v.nb)
				gspec_insert(&v, pos, G_EXIT, 0);
			else
				gspec_insert(&v, pos, crng_below(&rg, 3) == 0 ? G_EXIT : G_JUMP, crng_below(&rg, v.nb));
		}
		CK(gspec_sign(&ISAS[0], &v, 0x1000, 0, &s1, NULL));
		CKM(sign_eq(&s0, &s1), "%s: unreachable junk moved the signature", tag);

		/* the fall-through chains in another order */
		gspec_relayout(&g, &rg, &v);
		CK(gspec_sign(&ISAS[0], &v, 0x1000, 0, &s1, NULL));
		CKM(sign_eq(&s0, &s1), "%s: relayout of the chains moved the signature", tag);

		/* call targets rewritten, and the successors of every conditional swapped: no change */
		{
			struct prog p;
			struct blob x;
			struct kgenome_cell_insn *in = NULL;
			uint32_t n, i;

			gspec_prog(&g, &p, NULL);
			CK(blob_make(&ISAS[0], &p, 0x1000, &x));
			CK(blob_cfg(&ISAS[0], &p, &x, &in, &cg) == KGENOME_OK);
			n = x.n_insn;
			for (i = 0; i < n; i++)
				if (in[i].op == KGENOME_CELL_CALL)
					in[i].target_va = crng_next(&rg);
			kgenome_cfg_free(&cg, NULL);
			{
				struct kgenome_cfg_req rq;

				memset(&rq, 0, sizeof rq);
				rq.in = in; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len;
				CK(kgenome_cfg_build(&rq, &cg) == KGENOME_OK);   /* every call target rewritten: they do not enter the graph at all */
			}
			CK(sign_of(&cg, 0, &s1) == KGENOME_OK && sign_eq(&s0, &s1));
			for (b = 0; b < cg.n_all; b++)
				if (cg.b[b].term == KGENOME_CFG_T_COND) {
					const uint32_t t = cg.b[b].succ[0];

					cg.b[b].succ[0] = cg.b[b].succ[1];
					cg.b[b].succ[1] = t;
				}
			CK(sign_of(&cg, 0, &s1) == KGENOME_OK);
			CKM(sign_eq(&s0, &s1), "%s: swapping the successors of conditionals moved the signature", tag);
			kgenome_cfg_free(&cg, NULL);
			free(in); blob_free(&x); prog_free(&p);
		}

		/* an exit turned into a jump (a new edge into a reachable block): the labels move */
		{
			struct refg r;
			uint32_t cand[64], nc = 0;

			gspec_ref(&g, &r);
			for (b = 0; b < g.nb; b++)
				if (r.reach[b] && g.kind[b] == G_EXIT)
					cand[nc++] = b;
			if (nc) {
				const uint32_t e = cand[crng_below(&rg, nc)];
				uint32_t t, tries = 0;

				do t = crng_below(&rg, g.nb); while ((!r.reach[t] || t == e) && ++tries < 50);
				if (tries < 50) {
					v = g;
					v.kind[e] = G_JUMP;
					v.t[e] = t;
					CK(gspec_sign(&ISAS[0], &v, 0x1000, 0, &s1, NULL));
					tried_exit++;
					changed_exit += !sign_eq(&s0, &s1);
				}
			}
			/* an edge removed: a jump to a reachable block becomes an exit */
			nc = 0;
			for (b = 0; b < g.nb; b++)
				if (r.reach[b] && g.kind[b] == G_JUMP)
					cand[nc++] = b;
			if (nc) {
				v = g;
				v.kind[cand[crng_below(&rg, nc)]] = G_EXIT;
				CK(gspec_sign(&ISAS[0], &v, 0x1000, 0, &s1, NULL));
				tried_edge++;
				changed_edge += !sign_eq(&s0, &s1);
			}
			refg_free(&r);
		}
	}
	printf("  properties: %u functions; exit->jump changed %u of %u, jump->exit changed %u of %u\n", tested, changed_exit, tried_exit, changed_edge, tried_edge);
	CK(tested > 500);
	CKM(changed_exit * 100 >= tried_exit * 97, "exit->jump moved the signature in only %u of %u", changed_exit, tried_exit);
	CKM(changed_edge * 100 >= tried_edge * 97, "jump->exit moved the signature in only %u of %u", changed_edge, tried_edge);
}

/* ---- 5. the sketch against the survey's sorted algorithm, element for element ---- */
static void differential(void)
{
	struct crng rg;
	unsigned trial, rounds, nd = 0;

	crng_seed(&rg, 9090);
	for (trial = 0; trial < 3000; trial++) {
		struct gspec g;
		struct kgenome_cfg_sign s;
		struct refg r;
		struct refsig rs;
		uint32_t nb = 1u + crng_below(&rg, 60);

		gspec_random(&rg, nb, &g);
		gspec_ref(&g, &r);
		for (rounds = 0; rounds <= 3; rounds++) {
			if (!gspec_sign(&ISAS[crng_below(&rg, N_ISAS)], &g, 0x1000, rounds, &s, NULL))
				continue;
			ref_sign(&r, rounds ? rounds : 1u, &rs);
			CKM(s.n_blk == r.n_blk && s.n_key == rs.n_key && !memcmp(s.key, rs.key, rs.n_key * sizeof *rs.key),
			    "trial %u rounds %u: sketch differs from the sorted reference (n_key %u/%u)", trial, rounds, s.n_key, rs.n_key);
			refsig_free(&rs);
			nd++;
		}
		refg_free(&r);
	}
	CK(nd > 10000);
	/* the canonical hash is a function of the same multiset: equal graphs (reference canon equal) <=> equal hash, over random pairs of graphs */
	{
		struct gspec gs[40];
		struct kgenome_cfg_sign ss[40];
		struct refsig rs[40];
		unsigned i, j, eq = 0;

		for (i = 0; i < 40; i++) {
			struct refg r;

			gspec_random(&rg, 3u + crng_below(&rg, 4), &gs[i]);        /* small, so that equal multisets actually occur */
			gspec_ref(&gs[i], &r);
			ref_sign(&r, 1, &rs[i]);
			refg_free(&r);
			CK(gspec_sign(&ISAS[0], &gs[i], 0x1000, 0, &ss[i], NULL));
		}
		for (i = 0; i < 40; i++)
			for (j = i + 1; j < 40; j++) {
				CKM((ss[i].canon == ss[j].canon) == (rs[i].canon == rs[j].canon), "canon relation differs from the reference (%u,%u)", i, j);
				eq += ss[i].canon == ss[j].canon;
			}
		for (i = 0; i < 40; i++) refsig_free(&rs[i]);
		CK(eq > 0);
	}
}

/* ---- 6. pct ---- */
static void pct(void)
{
	struct crng rg;
	unsigned trial, k, i;
	struct kgenome_cfg_sign a, b, e;
	double err_sum = 0, err_max = 0;
	unsigned err_n = 0;
	double mono[12] = { 0 };
	unsigned mono_n = 0;

	crng_seed(&rg, 31337);
	memset(&e, 0, sizeof e);
	/* identical, empty, disjoint */
	for (trial = 0; trial < 200; trial++) {
		struct gspec g;

		gspec_random(&rg, 4u + crng_below(&rg, 50), &g);
		if (reach_count(&g) < 2)
			continue;
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &a, NULL));
		CK(kgenome_cfg_pct(&a, &a) == 100u);
		CK(kgenome_cfg_pct(&a, &e) == 0u && kgenome_cfg_pct(&e, &a) == 0u && kgenome_cfg_pct(&e, &e) == 0u);
	}
	memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
	a.n_key = b.n_key = KGENOME_CFG_KEYS;
	for (i = 0; i < KGENOME_CFG_KEYS; i++) { a.key[i] = 2u * i; b.key[i] = 2u * i + 1u; }
	CK(kgenome_cfg_pct(&a, &b) == 0u && kgenome_cfg_pct(&b, &a) == 0u);
	/* half shared: the 32 smallest of the union hold 16 matches... a = evens, b = evens for 0..31 then odds */
	for (i = 0; i < KGENOME_CFG_KEYS; i++) b.key[i] = i < 16u ? 2u * i : 2u * i + 1u;
	CKM(kgenome_cfg_pct(&a, &b) == kgenome_cfg_pct(&b, &a), "pct is not symmetric");
	/* one element in common among 32 and 32, and it is the smallest: the union's 32 smallest are a0=b0, then 31 more of one side or the other */
	for (i = 0; i < KGENOME_CFG_KEYS; i++) { a.key[i] = 100u + 2u * i; b.key[i] = 100u + 2u * i + (i ? 1u : 0u); }
	CK(kgenome_cfg_pct(&a, &b) == 100u * 1u / KGENOME_CFG_KEYS);
	/* random sketches against a union-first-32 oracle written the plain way: sort the union, take 32, count the elements in both */
	for (trial = 0; trial < 20000; trial++) {
		uint32_t u[64], nu = 0, j, in_both = 0, want;
		uint32_t na = 1u + crng_below(&rg, 32), nb2 = 1u + crng_below(&rg, 32), range = 33u + crng_below(&rg, 100);

		memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
		/* sorted distinct values below `range` */
		for (i = 0; i < na; i++) { a.key[i] = crng_below(&rg, range); }
		qsort(a.key, na, sizeof a.key[0], rcmp32);
		for (i = 0, j = 0; i < na; i++) if (!j || a.key[i] != a.key[j - 1u]) a.key[j++] = a.key[i];
		a.n_key = j;
		for (i = 0; i < nb2; i++) { b.key[i] = crng_below(&rg, range); }
		qsort(b.key, nb2, sizeof b.key[0], rcmp32);
		for (i = 0, j = 0; i < nb2; i++) if (!j || b.key[i] != b.key[j - 1u]) b.key[j++] = b.key[i];
		b.n_key = j;
		for (i = 0; i < a.n_key; i++) u[nu++] = a.key[i];
		for (i = 0; i < b.n_key; i++) u[nu++] = b.key[i];
		qsort(u, nu, sizeof u[0], rcmp32);
		for (i = 0, j = 0; i < nu; i++) if (!j || u[i] != u[j - 1u]) u[j++] = u[i];
		nu = j > 32u ? 32u : j;
		for (i = 0; i < nu; i++) {
			uint32_t x = 0, y = 0, q;

			for (q = 0; q < a.n_key; q++) x |= a.key[q] == u[i];
			for (q = 0; q < b.n_key; q++) y |= b.key[q] == u[i];
			in_both += x && y;
		}
		want = in_both * 100u / nu;
		CKM(kgenome_cfg_pct(&a, &b) == want, "pct oracle: %u want %u", kgenome_cfg_pct(&a, &b), want);
		if (fails > 20) break;
	}
	/* a sketch of fewer than 32 against a longer one: the shorter is the whole set, the match is exact */
	a.n_key = 3; a.key[0] = 1; a.key[1] = 2; a.key[2] = 3;
	b.n_key = 6; b.key[0] = 1; b.key[1] = 2; b.key[2] = 3; b.key[3] = 4; b.key[4] = 5; b.key[5] = 6;
	CK(kgenome_cfg_pct(&a, &b) == 50u);

	/* symmetric over random graph pairs; monotone in the number of blocks changed; error against the exact Jaccard */
	for (trial = 0; trial < 1600; trial++) {
		struct gspec g, v;
		struct refg r0, r1;
		struct refsig f0, f1;
		struct kgenome_cfg_sign s0, s1, s2;
		struct refg rr;

		gspec_random(&rg, 30u + crng_below(&rg, 30), &g);
		gspec_ref(&g, &r0);
		if (r0.n_blk < 14) { refg_free(&r0); continue; }
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s0, NULL));
		ref_sign(&r0, 1, &f0);
		v = g;
		for (k = 0; k <= 10; k++) {
			uint32_t cand[64], nc = 0, bb;

			if (k) {
				/* change one more reachable block: flip exit <-> jump to a reachable block, or a jump to a different reachable target */
				gspec_ref(&v, &rr);
				for (bb = 0; bb < v.nb; bb++)
					if (rr.reach[bb])
						cand[nc++] = bb;
				bb = cand[crng_below(&rg, nc)];
				if (v.kind[bb] == G_EXIT) { v.kind[bb] = G_JUMP; v.t[bb] = cand[crng_below(&rg, nc)]; }
				else if (v.kind[bb] == G_JUMP) v.kind[bb] = G_EXIT;
				else if (v.kind[bb] == G_COND) v.t[bb] = cand[crng_below(&rg, nc)];
				else { v.kind[bb] = G_JUMP; v.t[bb] = bb + 1u < v.nb ? bb + 1u : bb; }
				refg_free(&rr);
			}
			CK(gspec_sign(&ISAS[0], &v, 0x1000, 0, &s1, NULL));
			CKM(kgenome_cfg_pct(&s0, &s1) == kgenome_cfg_pct(&s1, &s0), "pct not symmetric");
			mono[k] += kgenome_cfg_pct(&s0, &s1);
			if (k == 10)
				mono_n++;
			gspec_ref(&v, &r1);
			ref_sign(&r1, 1, &f1);
			{
				const double ex = ref_jaccard(&f0, &f1), d = (double)kgenome_cfg_pct(&s0, &s1) - ex;
				const double ad = d < 0 ? -d : d;

				err_sum += ad; err_n++;
				if (ad > err_max) err_max = ad;
				/* floored: never above the estimate's own truth by more than the sketch's noise, and 100 only when the sketches are equal */
				if (kgenome_cfg_pct(&s0, &s1) == 100u)
					CK(s0.n_key == s1.n_key && !memcmp(s0.key, s1.key, s0.n_key * sizeof *s0.key));
			}
			refsig_free(&f1);
			refg_free(&r1);
		}
		(void)s2;
		refsig_free(&f0);
		refg_free(&r0);
	}
	CK(mono_n > 100);
	for (k = 0; k < 11; k++)
		mono[k] /= mono_n;
	printf("  pct: mean by blocks changed:");
	for (k = 0; k <= 10; k++)
		printf(" %.1f", mono[k]);
	printf("\n  pct: |estimate - exact Jaccard| over %u pairs: mean %.2f max %.2f (points of 100)\n", err_n, err_sum / err_n, err_max);
	CK(mono[0] == 100.0);
	for (k = 1; k <= 10; k++)
		CKM(mono[k] <= mono[k - 1u] + 0.5, "pct not monotone at %u changed blocks: %.1f after %.1f", k, mono[k], mono[k - 1u]);
	CK(mono[10] < mono[0] - 15.0);
	CKM(err_sum / err_n < EXPECT_ERR_MEAN, "mean estimator error %.2f", err_sum / err_n);
	CKM(err_max < EXPECT_ERR_MAX, "max estimator error %.2f", err_max);
}

/* ---- 7. the anchor ---- */
static void anchor(void)
{
	unsigned nb;

	for (nb = 1; nb <= 20; nb++) {
		struct gspec g;
		struct kgenome_cfg_sign s;
		struct kgenome_cfg c;
		struct kgenome_cfg_anchor_req r = { .min_blk = 0 };
		uint32_t b;

		/* a chain of jumps, all reachable, then five unreachable blocks that must not count */
		memset(&g, 0, sizeof g);
		g.nb = nb + 5u;
		for (b = 0; b < nb; b++) { g.kind[b] = b + 1u == nb ? G_EXIT : G_JUMP; g.t[b] = b + 1u; }
		for (b = nb; b < nb + 5u; b++) { g.kind[b] = G_EXIT; }
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s, &c));
		CKM(c.n_blk == nb && c.n_all == nb + 5u, "chain %u: n_blk %u n_all %u", nb, c.n_blk, c.n_all);
		CKM(kgenome_cfg_anchor(&c, &r) == 1, "%u reachable blocks: anchor %d (the floor of 12 is gone: one block is enough)", nb, kgenome_cfg_anchor(&c, &r));
		CKM(kgenome_cfg_anchor(&c, NULL) == 1, "NULL request is the default");
		r.min_blk = 5;
		CKM(kgenome_cfg_anchor(&c, &r) == (nb >= 5u), "min 5, %u blocks", nb);
		r.min_blk = 13;
		CKM(kgenome_cfg_anchor(&c, &r) == (nb >= 13u), "min 13, %u blocks", nb);
		kgenome_cfg_free(&c, NULL);
	}
	CK(KGENOME_CFG_ANCHOR_MIN == 1u && KGENOME_CFG_MIN_KEYS == 1u);
	CK(!kgenome_cfg_anchor(NULL, NULL));
	{
		/* syscall and site flags: a 3-block function with a syscall and a marked instruction */
		struct prog p = { 0 };
		struct blob x;
		struct kgenome_cell_insn *in = NULL;
		struct kgenome_cfg g;
		struct kgenome_cfg_req rq;
		uint8_t site[16] = { 0 };
		struct kgenome_cfg_anchor_req r = { .min_blk = 12 };    /* the or-flags are tested against a floor the function does not reach */
		uint32_t n;

		prog_add(&p, O_NOP, 0); prog_add(&p, O_SYS, 0); prog_add(&p, O_RET, 0);
		CK(blob_make(&ISAS[0], &p, 0x1000, &x));
		n = blob_decode(&ISAS[0], &x, &in);
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + x.len;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_sys == 1 && g.n_site == 0);
		CK(!kgenome_cfg_anchor(&g, &r));
		r.or_flags = KGENOME_CFG_ANCHOR_SYS;
		CK(kgenome_cfg_anchor(&g, &r));
		r.or_flags = KGENOME_CFG_ANCHOR_SITE;
		CK(!kgenome_cfg_anchor(&g, &r));
		kgenome_cfg_free(&g, NULL);
		site[1] = 1;
		rq.site = site;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_site == 1);
		CK(kgenome_cfg_anchor(&g, &r));
		kgenome_cfg_free(&g, NULL);
		free(in); blob_free(&x); prog_free(&p);
	}
}

/* ---- 8. the view ---- */
static void view(void)
{
	struct gspec g;
	struct prog p;
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg c;
	struct kgenome_cfg_sign s;
	struct kgenome_cfg_sign_req sq;
	struct kgenome_cfg_view_req vq;
	struct kgenome_cfg_view v;
	uint64_t label[16];
	uint32_t i;

	/* 0 COND ->3 (falls into 1); 1 JUMP ->4 ; 2 EXIT (unreachable) ; 3 FALL ; 4 EXIT */
	memset(&g, 0, sizeof g);
	g.nb = 5;
	g.kind[0] = G_COND; g.t[0] = 3; g.kind[1] = G_JUMP; g.t[1] = 4; g.kind[2] = G_EXIT; g.kind[3] = G_FALL; g.kind[4] = G_EXIT;
	gspec_prog(&g, &p, NULL);
	CK(blob_make(&ISAS[0], &p, 0x1000, &x));
	CK(blob_cfg(&ISAS[0], &p, &x, &in, &c) == KGENOME_OK);
	CKM(c.n_all == 5 && c.n_blk == 4, "n_all %u n_blk %u", c.n_all, c.n_blk);
	memset(&sq, 0, sizeof sq);
	sq.g = &c; sq.label = label;
	CK(kgenome_cfg_sign(&sq, &s) == KGENOME_OK);
	CK(label[2] == 0 && label[0] != 0 && label[1] != 0 && label[3] != 0 && label[4] != 0);
	memset(&vq, 0, sizeof vq);
	vq.g = &c; vq.sign = &s; vq.label = label; vq.in = in;
	CK(kgenome_cfg_view_make(&vq, &v) == KGENOME_OK);
	CK(v.n_blk == 4 && v.blk && v.canon == s.canon && v.n_key == s.n_key && !memcmp(v.key, s.key, sizeof s.key));
	/* reachable blocks in layout order: 0, 1, 3, 4 -> view 0..3; block 3's successor (old 4) is view 3, old 0's target 3 is view 2 */
	CK(v.blk[0].term == KGENOME_CFG_T_COND && v.blk[0].succ[0] == 2 && v.blk[0].succ[1] == 1);
	CK(v.blk[1].term == KGENOME_CFG_T_JUMP && v.blk[1].succ[0] == 3 && v.blk[1].succ[1] == KGENOME_CFG_NONE);
	CK(v.blk[2].term == KGENOME_CFG_T_FALL && v.blk[2].succ[0] == 3);
	CK(v.blk[3].term == KGENOME_CFG_T_EXIT && v.blk[3].succ[0] == KGENOME_CFG_NONE);
	for (i = 0; i < 4; i++) {
		static const uint32_t old[4] = { 0, 1, 3, 4 };

		CK(v.blk[i].label == (uint32_t)label[old[i]]);
		CK(v.blk[i].off == in[c.b[old[i]].first].at && v.blk[i].n_insn == c.b[old[i]].n_insn);
	}
	CK(v.status == KGENOME_OK);
	kgenome_cfg_view_free(&v, NULL);
	CK(v.blk == NULL && v.n_blk == 0);
	kgenome_cfg_view_free(&v, NULL);
	/* the status travels: a cut graph gives a view that says so */
	kgenome_cfg_free(&c, NULL);
	{
		struct kgenome_cfg_req rq;

		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = x.n_insn; rq.arch = ISAS[0].arch; rq.va_lo = 0x1000; rq.va_hi = 0x1000 + x.len; rq.cut = 1;
		CK(kgenome_cfg_build(&rq, &c) == KGENOME_TRUNCATED);
		sq.g = &c;
		CK(kgenome_cfg_sign(&sq, &s) == KGENOME_TRUNCATED);
		vq.g = &c;
		CK(kgenome_cfg_view_make(&vq, &v) == KGENOME_TRUNCATED && v.status == KGENOME_TRUNCATED && v.n_blk == 4);
		kgenome_cfg_view_free(&v, NULL);
		kgenome_cfg_free(&c, NULL);
	}
	/* missing arguments */
	CK(kgenome_cfg_view_make(NULL, &v) == KGENOME_BAD_INPUT);
	vq.sign = NULL;
	CK(kgenome_cfg_view_make(&vq, &v) == KGENOME_BAD_INPUT);
	free(in); blob_free(&x); prog_free(&p);
}

/*
 * 7. DOMAIN SEPARATION. The keys of a CFG block are stored in a pack beside window hashes, as the same list of u32; they come from a hash that is
 * not the window hash and starts at KGENOME_CFG_KEY_SEED. Pinned: the seed is none of the constants the window hash is made of; no key of any
 * graph of up to five blocks (every graph, the exhaustive family) is the key the sketch had before the seed (the unseeded element of the same
 * label and occurrence); and the seed is what the key depends on (a graph signed twice is the same, the keys are not the unseeded ones, and
 * KEYOF spells the function out in the test).
 */
static void domain(void)
{
	static const uint64_t window_consts[] = { KGENOME_MUTATION_BASE, KGENOME_MUTATION_MIX, KGENOME_MUTATION_NG, KGENOME_MUTATION_MIN_HASH,
						  KGENOME_MUTATION_MINHASH_K, 0x9E3779B1u, 0x85EBCA77u };
	struct gspec g;
	struct kgenome_cfg_sign s;
	uint32_t i, differ = 0;

	for (i = 0; i < sizeof window_consts / sizeof *window_consts; i++)
		CK(KGENOME_CFG_KEY_SEED != window_consts[i] && (KGENOME_CFG_KEY_SEED >> 32) != window_consts[i] &&
		   (KGENOME_CFG_KEY_SEED & 0xffffffffu) != window_consts[i]);
	/* the one-block function: its only key is the SEEDED element of its label, and it is not the element the sketch had before the seed */
	{
		const uint64_t l1 = rmix(rmix(rmix(7u, 0u), 0u), 3u), w1 = rmix(rmix(l1, 0u), 0u);

		memset(&g, 0, sizeof g);
		g.nb = 1; g.kind[0] = G_EXIT;
		CK(gspec_sign(&ISAS[0], &g, 0x1000, 0, &s, NULL));
		CK(s.n_key == 1 && s.key[0] == KEYOF(w1, 0u) && s.key[0] != KEY_UNSEEDED(w1, 0u));
	}
	/* a seed that did nothing would make the two elements of a label equal: they differ for every one of 4096 labels and occurrences */
	for (i = 0; i < 4096u; i++) {
		const uint64_t l = rmix(i, 0x1234567u);

		differ += KEYOF(l, i & 7u) != KEY_UNSEEDED(l, i & 7u);
	}
	CK(differ == 4096u);
}

/* 8. A pack's list as keys: ascending, distinct, the 32 smallest - whatever order and repeats the source wrote. */
static void keys_sign(void)
{
	uint32_t raw[100], i;
	struct kgenome_cfg_sign k;

	for (i = 0; i < 100u; i++)
		raw[i] = (i * 2654435761u) ^ 0x9e3779b9u;        /* 100 distinct, no order */
	kgenome_cfg_keys_sign(&k, raw, 100u);
	CK(k.n_key == 32u);
	for (i = 1; i < 32u; i++)
		CK(k.key[i - 1u] < k.key[i]);
	{
		uint32_t cnt_below = 0, j;

		for (j = 0; j < 100u; j++)
			cnt_below += raw[j] < k.key[31];
		CK(cnt_below == 31u);                              /* k.key[31] is the 32nd smallest of the 100 */
	}
	raw[0] = raw[1] = raw[2] = 7u;                         /* repeats count once */
	kgenome_cfg_keys_sign(&k, raw, 3u);
	CK(k.n_key == 1u && k.key[0] == 7u);
	kgenome_cfg_keys_sign(&k, NULL, 5u);
	CK(k.n_key == 0u);
	kgenome_cfg_keys_sign(&k, raw, 0u);
	CK(k.n_key == 0u && k.canon == 0u);
}

int main(void)
{
	keys_sign();
	domain();
	hand();
	exhaustive();
	isas();
	properties();
	differential();
	pct();
	anchor();
	view();
	if (fails)
		printf("cfg_sign: %d FAILED\n", fails);
	else
		printf("cfg_sign: ok\n");
	return fails != 0;
}
