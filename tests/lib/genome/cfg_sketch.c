/*
 * genome / cfg_sketch - the bottom-32 sketch of celllysis/cfg_sign.c: how it is FORMED (the 32 smallest distinct elements of a multiset,
 * ascending) and how two are COMPARED (kgenome_cfg_overlap / kgenome_cfg_pct / kgenome_cfg_pct_callee: the matches among the 32
 * smallest of the union).
 *
 * THE ORACLE IS THE FIRST IMPLEMENTATION, spelled out below (`old_window_add`, `old_overlap`: a sorted 32-slot window and a branching
 * merge). The sketch is stored in packs and the threshold was measured on it, so the form that replaced it (a heap of the 32 smallest and
 * a branch-free merge) has to give the SAME keys for every input and the same hit/taken for every pair. Not "close": equal.
 *   FORM      kgenome_cfg_keys_sign over (a) every sequence of up to 8 elements over a 4-letter alphabet, (b) 0..40 distinct values in
 *             ascending, descending and shuffled order with repeats, the values 0 and 0xffffffff among them, (c) 31/32/33 distinct,
 *             (d) pools small enough that equal elements recur, (e) large random multisets over many seeds.
 *             kgenome_cfg_sign over hand-made graphs with random labels (struct policy: the keys from r->label by the old rule) and over
 *             hand-made call lists (callee policy: repeated identities, kinds), many seeds, 1..400 blocks.
 *   COMPARE   hit, taken and pct of pairs of ascending sketches: identical, disjoint, subset, interleaved, one empty, all sizes 0..32
 *             on both sides, 0xffffffff as a real element at the end of one or both sides (the merge must not read an exhausted side as a
 *             match), the 32-element cut; also against a set-theoretic oracle (the K smallest of the union, counted by membership).
 *
 * `cfg_sketch --bench [N]` (N: fewer repetitions, for callgrind) prints ns per call and per function for the form and the compare (not an assertion: a timing is not a test).
 */
#include "cfg_kit.h"

#include <time.h>

/* ---- the oracle: the first implementation, verbatim in behaviour ---- */

static void old_window_add(uint32_t *key, uint32_t *m, uint32_t e)
{
	uint32_t i;

	if (*m == KGENOME_CFG_KEYS && e >= key[KGENOME_CFG_KEYS - 1u])
		return;
	for (i = 0; i < *m && key[i] < e; i++)
		;
	if (i < *m && key[i] == e)
		return;
	if (*m < KGENOME_CFG_KEYS)
		(*m)++;
	memmove(&key[i + 1u], &key[i], (size_t)(*m - 1u - i) * sizeof *key);
	key[i] = e;
}

static void old_overlap(const uint32_t *a, uint32_t na, const uint32_t *b, uint32_t nb, uint32_t *hit_o, uint32_t *taken_o)
{
	uint32_t i = 0, j = 0, taken = 0, hit = 0;

	*hit_o = *taken_o = 0;
	if (!na || !nb)
		return;
	while (taken < KGENOME_CFG_KEYS && (i < na || j < nb)) {
		if (i < na && j < nb && a[i] == b[j]) {
			hit++;
			i++;
			j++;
		} else if (j >= nb || (i < na && a[i] < b[j])) {
			i++;
		} else {
			j++;
		}
		taken++;
	}
	*hit_o = hit;
	*taken_o = taken;
}

/* a second, set-theoretic oracle: the K smallest of the union, by membership (the sketches are ascending and distinct) */
static int has(const uint32_t *a, uint32_t n, uint32_t v)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (a[i] == v)
			return 1;
	return 0;
}

static void set_overlap(const uint32_t *a, uint32_t na, const uint32_t *b, uint32_t nb, uint32_t *hit_o, uint32_t *taken_o)
{
	uint32_t u[2u * KGENOME_CFG_KEYS], nu = 0, i, j, hit = 0, taken;

	*hit_o = *taken_o = 0;
	if (!na || !nb)
		return;
	for (i = 0; i < na; i++)
		u[nu++] = a[i];
	for (i = 0; i < nb; i++)
		if (!has(a, na, b[i]))
			u[nu++] = b[i];
	for (i = 1; i < nu; i++) {
		const uint32_t x = u[i];

		for (j = i; j && u[j - 1] > x; j--)
			u[j] = u[j - 1];
		u[j] = x;
	}
	taken = nu < KGENOME_CFG_KEYS ? nu : KGENOME_CFG_KEYS;
	for (i = 0; i < taken; i++)
		hit += has(a, na, u[i]) && has(b, nb, u[i]);
	*hit_o = hit;
	*taken_o = taken;
}

/* ---- helpers ---- */

static uint32_t rnd32(struct crng *r) { return (uint32_t)(crng_next(r) >> 16); }

static uint64_t n_cases;

/* the sketch of `v[0..n)` by the oracle, and by the lib; they must be equal in n_key and every key */
static void check_form(const uint32_t *v, uint32_t n, const char *what)
{
	struct kgenome_cfg_sign s;
	uint32_t want[KGENOME_CFG_KEYS], m = 0, i;

	for (i = 0; i < n; i++)
		old_window_add(want, &m, v[i]);
	kgenome_cfg_keys_sign(&s, v, n);
	n_cases++;
	if (s.n_key != m || memcmp(s.key, want, m * sizeof *want) != 0) {
		CKM(0, "%s: n=%u lib n_key %u (first %08x) oracle %u (first %08x)", what, n, s.n_key, s.n_key ? s.key[0] : 0u, m, m ? want[0] : 0u);
		return;
	}
	/* the part of the struct past n_key is zero: keys_sign zeroes first and promises nothing else */
	for (i = m; i < KGENOME_CFG_KEYS; i++)
		if (s.key[i] != 0) {
			CKM(0, "%s: slot %u past n_key is %08x", what, i, s.key[i]);
			return;
		}
}

static void form_exhaustive_small(void)
{
	uint32_t v[8], len, code, k;
	static const uint32_t alpha[4] = { 0u, 1u, 0x80000000u, 0xffffffffu };

	for (len = 0; len <= 8; len++) {
		uint32_t total = 1u << (2u * len);

		for (code = 0; code < total; code++) {
			for (k = 0; k < len; k++)
				v[k] = alpha[(code >> (2u * k)) & 3u];
			check_form(v, len, "alphabet4");
		}
	}
}

static void shuffle(struct crng *r, uint32_t *v, uint32_t n)
{
	uint32_t i;

	for (i = n; i > 1; i--) {
		const uint32_t j = (uint32_t)(crng_next(r) % i), t = v[i - 1];

		v[i - 1] = v[j];
		v[j] = t;
	}
}

static void form_distinct_counts(void)
{
	struct crng r;
	uint32_t n, seed, i, v[160] = { 0 }, w[160] = { 0 };

	for (n = 0; n <= 40; n++) {
		/* ascending, descending, and the values at the ends of the range among them */
		for (i = 0; i < n; i++)
			v[i] = i == 0 ? 0u : (i == n - 1 && n > 2 ? 0xffffffffu : i * 100003u);
		check_form(v, n, "ascending");
		for (i = 0; i < n; i++)
			w[i] = v[n - 1 - i];
		check_form(w, n, "descending");
		for (seed = 1; seed <= 60; seed++) {
			crng_seed(&r, seed * 977u + n);
			memcpy(w, v, n * sizeof *v);
			shuffle(&r, w, n);
			check_form(w, n, "shuffled");
			/* every element twice, then a third time for some: the k-th occurrence is a DIFFERENT element in the sketch, but here a repeat is the same value */
			for (i = 0; i < n; i++) {
				v[i + n] = w[i];
				if (i + 2u * n < 160u)
					v[i + 2u * n] = (i & 1u) ? w[i] : w[(i + 1u) % n];
			}
			if (3u * n <= 160u) {
				shuffle(&r, v, 3u * n);
				check_form(v, 3u * n, "repeated");
			}
			for (i = 0; i < n; i++)
				v[i] = i == 0 ? 0u : (i == n - 1 && n > 2 ? 0xffffffffu : i * 100003u);
		}
	}
	/* the smallest elements arrive last: every one of them enters a full sketch */
	for (n = 31; n <= 40; n++) {
		for (i = 0; i < n; i++)
			v[i] = 0xfffffff0u - i;
		check_form(v, n, "descending near max");
		for (i = 0; i < n; i++)
			v[i] = 1000u + i;
		check_form(v, n, "ascending small");
	}
}

static void form_ties_and_random(void)
{
	struct crng r;
	uint32_t seed, i, n, pool, v[6000];

	for (seed = 1; seed <= 400; seed++) {
		crng_seed(&r, seed);
		n = 1u + (uint32_t)(crng_next(&r) % 300u);
		/* pools of 2..80 values: equal elements recur, and 31/32/33 distinct elements are common */
		pool = 2u + (uint32_t)(crng_next(&r) % 79u);
		for (i = 0; i < n; i++)
			v[i] = (rnd32(&r) % pool) * 0x01000193u;
		check_form(v, n, "small pool");
		for (i = 0; i < n; i++)
			v[i] = rnd32(&r) % pool;
		check_form(v, n, "small values");
	}
	for (seed = 1; seed <= 300; seed++) {
		crng_seed(&r, 7000u + seed);
		n = 1u + (uint32_t)(crng_next(&r) % 6000u);
		for (i = 0; i < n; i++)
			v[i] = (uint32_t)crng_next(&r);
		check_form(v, n, "large random");
		/* the same with the top bits cleared: the smallest of a narrow range, so many ties after 30 bits */
		for (i = 0; i < n; i++)
			v[i] &= 0x3ffu;
		check_form(v, n, "narrow range");
	}
}

/* ---- the signing, over hand-made graphs ---- */

static void hand_graph(struct kgenome_cfg *g, struct kgenome_cfg_block *b, uint32_t n, struct crng *r)
{
	uint32_t i;

	memset(g, 0, sizeof *g);
	memset(b, 0, n * sizeof *b);
	for (i = 0; i < n; i++) {
		b[i].reach = (uint8_t)(i == 0 || (rnd32(r) % 5u) != 0);
		b[i].term = (uint8_t)(rnd32(r) % 4u);
		b[i].succ[0] = b[i].succ[1] = KGENOME_CFG_NONE;
		b[i].out_deg = 0;
	}
	for (i = 0; i < n; i++) {
		uint32_t e, t;

		if (!b[i].reach)
			continue;
		for (e = 0; e < (rnd32(r) % 3u); e++) {
			do
				t = rnd32(r) % n;
			while (!b[t].reach);
			b[i].succ[e] = t;
			b[i].out_deg++;
			b[t].in_deg++;
			g->n_edge++;
		}
		g->n_blk++;
	}
	g->b = b;
	g->n_all = n;
	g->status = KGENOME_OK;
}

static void sign_struct_matches(void)
{
	static struct kgenome_cfg_block b[512];
	static uint64_t label[512];
	struct crng r;
	uint32_t seed, n, i, rounds;

	for (seed = 1; seed <= 700; seed++) {
		struct kgenome_cfg g;
		struct kgenome_cfg_sign s;
		struct kgenome_cfg_sign_req rq;
		uint32_t want[KGENOME_CFG_KEYS], m = 0, run;
		static uint64_t seen_lab[512];
		uint32_t nseen = 0, j;

		crng_seed(&r, 31337u + seed);
		n = 1u + (seed <= 400u ? seed : (uint32_t)(crng_next(&r) % 400u));
		hand_graph(&g, b, n, &r);
		rounds = seed % 3u;     /* 0 means one round */
		memset(&rq, 0, sizeof rq);
		rq.g = &g;
		rq.rounds = (uint8_t)rounds;
		rq.label = label;
		CK(kgenome_cfg_sign(&rq, &s) == KGENOME_OK);
		/* the rule, from the labels the lib published: the k-th occurrence of a label is the element mix(mix(seed, label), k)>>32 */
		for (i = 0; i < n; i++) {
			if (!b[i].reach)
				continue;
			for (run = 0, j = 0; j < nseen; j++)
				run += seen_lab[j] == label[i];
			seen_lab[nseen++] = label[i];
			old_window_add(want, &m, kgenome_cfg_key(label[i], run));
		}
		n_cases++;
		CKM(s.n_key == m && memcmp(s.key, want, m * sizeof *want) == 0, "struct sign seed %u n %u: n_key %u want %u", seed, n, s.n_key, m);
		for (i = m; i < KGENOME_CFG_KEYS; i++)
			CKM(s.key[i] == 0, "struct sign: slot %u past n_key", i);
	}
}

static void sign_callees_match(void)
{
	static struct kgenome_cfg_block b[2];
	static struct kgenome_cfg_call call[512];
	struct crng r;
	uint32_t seed, i;

	for (seed = 1; seed <= 600; seed++) {
		struct kgenome_cfg g;
		struct kgenome_cfg_sign s;
		struct kgenome_cfg_sign_req rq;
		uint32_t want[KGENOME_CFG_KEYS], m = 0, n, pool, j, nseen = 0, run;
		static uint64_t seen[512];

		crng_seed(&r, 5150u + seed);
		memset(&g, 0, sizeof g);
		memset(b, 0, sizeof b);
		b[0].reach = 1;
		b[0].succ[0] = b[0].succ[1] = KGENOME_CFG_NONE;
		b[0].term = 3;
		g.b = b;
		g.n_all = 1;
		g.n_blk = 1;
		n = 1u + (seed <= 400u ? seed : (uint32_t)(crng_next(&r) % 400u));
		pool = 1u + (uint32_t)(crng_next(&r) % (seed % 2u ? 6u : 120u));
		for (i = 0; i < n; i++) {
			call[i].id = (rnd32(&r) % 9u) ? 1u + rnd32(&r) % pool : 0u;       /* about one in nine unresolved */
			call[i].kind = (uint8_t)(rnd32(&r) % 3u);
			call[i].insn = i;
		}
		g.call = call;
		g.n_call = n;
		memset(&rq, 0, sizeof rq);
		rq.g = &g;
		rq.policy = KGENOME_CFG_P_CALLEES;
		CK(kgenome_cfg_sign(&rq, &s) == KGENOME_OK);
		for (i = 0; i < n; i++) {
			const uint64_t id = kgenome_cfg_mix(call[i].id, call[i].kind);

			if (!call[i].id)
				continue;
			for (run = 0, j = 0; j < nseen; j++)
				run += seen[j] == id;
			seen[nseen++] = id;
			old_window_add(want, &m, kgenome_cfg_key(id, run));
		}
		n_cases++;
		CKM(s.n_ckey == m && memcmp(s.ckey, want, m * sizeof *want) == 0, "callee sign seed %u n %u: n_ckey %u want %u", seed, n, s.n_ckey, m);
		CK(s.n_key == 0);
	}
}

/*
 * Two callee identities whose first elements are EQUAL 32-bit keys (a collision of the high half of the mix: found here by search, there is no stored
 * constant): the callee sign must hold ONE of them, as the first form did, and then go on to the next distinct element. Both elements are tiny (< 2^24),
 * so they sit among the 32 smallest of any filler. This is the case the heap's exactness argument leaves to the second pass.
 */
struct kid { uint32_t key; uint32_t id; };

static int kid_cmp(const void *x, const void *y)
{
	const struct kid *a = x, *b = y;

	return a->key < b->key ? -1 : a->key > b->key ? 1 : (a->id > b->id) - (a->id < b->id);
}

static void sign_callees_collisions(void)
{
	static struct kid small[60000];
	static struct kgenome_cfg_block b[1];
	static struct kgenome_cfg_call call[1200];
	uint32_t n = 0, id, i, pairs[16][2], np = 0, p, v, fill, order;
	static const uint32_t fills[] = { 0, 1, 5, 29, 31, 32, 33, 40, 300, 1000 };

	for (id = 1; id <= 6000000u && n < 60000u; id++) {
		const uint32_t k = kgenome_cfg_key(kgenome_cfg_mix(id, 0), 0);

		if (k < (1u << 24)) {
			small[n].key = k;
			small[n].id = id;
			n++;
		}
	}
	qsort(small, n, sizeof *small, kid_cmp);
	for (i = 1; i < n && np < 16; i++)
		if (small[i].key == small[i - 1u].key) {
			pairs[np][0] = small[i - 1u].id;
			pairs[np][1] = small[i].id;
			np++;
		}
	CKM(np >= 3, "the search found %u colliding pairs of callee identities (need 3)", np);
	for (p = 0; p < np; p++)
		for (v = 0; v < sizeof fills / sizeof *fills; v++)
			for (order = 0; order < 6; order++) {
				struct kgenome_cfg g;
				struct kgenome_cfg_sign s;
				struct kgenome_cfg_sign_req rq;
				uint32_t want[KGENOME_CFG_KEYS], m = 0, nc = 0, j, run, nseen = 0;
				static uint64_t seen[1200];
				struct crng r;

				fill = fills[v];
				crng_seed(&r, 900u + p * 100u + v * 10u + order);
				/* the pair, the pair again (the second elements differ), and fillers of identities far from small keys; the order is rotated */
				call[nc++].id = pairs[p][order & 1u];
				call[nc++].id = pairs[p][(order & 1u) ^ 1u];
				if (order >= 2) {
					call[nc++].id = pairs[p][0];
					call[nc++].id = pairs[p][1];
				}
				for (j = 0; j < fill; j++)
					call[nc++].id = 7000000u + rnd32(&r) % 1000000u;
				if (order >= 4)
					for (j = 0; j < nc / 2u; j++) {
						const uint64_t t = call[j].id;

						call[j].id = call[nc - 1u - j].id;
						call[nc - 1u - j].id = t;
					}
				for (j = 0; j < nc; j++) {
					call[j].kind = 0;
					call[j].insn = j;
				}
				memset(&g, 0, sizeof g);
				memset(b, 0, sizeof b);
				b[0].reach = 1;
				b[0].succ[0] = b[0].succ[1] = KGENOME_CFG_NONE;
				b[0].term = 3;
				g.b = b;
				g.n_all = g.n_blk = 1;
				g.call = call;
				g.n_call = nc;
				memset(&rq, 0, sizeof rq);
				rq.g = &g;
				rq.policy = KGENOME_CFG_P_CALLEES;
				CK(kgenome_cfg_sign(&rq, &s) == KGENOME_OK);
				for (j = 0; j < nc; j++) {
					const uint64_t lab = kgenome_cfg_mix(call[j].id, call[j].kind);

					for (run = 0, i = 0; i < nseen; i++)
						run += seen[i] == lab;
					seen[nseen++] = lab;
					old_window_add(want, &m, kgenome_cfg_key(lab, run));
				}
				n_cases++;
				CKM(s.n_ckey == m && memcmp(s.ckey, want, m * sizeof *want) == 0, "collision pair %u fill %u order %u: n_ckey %u want %u", p, fill, order, s.n_ckey, m);
				for (i = m; i < KGENOME_CFG_KEYS; i++)
					CKM(s.ckey[i] == 0, "collision: slot %u past n_ckey is not zero", i);
			}
}

/* ---- the compare ---- */

static void set_sketch(struct kgenome_cfg_sign *s, const uint32_t *v, uint32_t n)
{
	memset(s, 0, sizeof *s);
	memcpy(s->key, v, n * sizeof *v);
	memcpy(s->ckey, v, n * sizeof *v);
	s->n_key = s->n_ckey = n;
}

static void check_pair(const uint32_t *a, uint32_t na, const uint32_t *b, uint32_t nb, const char *what)
{
	struct kgenome_cfg_sign sa, sb;
	uint32_t h0, t0, h1, t1, h2, t2, pct;

	set_sketch(&sa, a, na);
	set_sketch(&sb, b, nb);
	old_overlap(a, na, b, nb, &h0, &t0);
	set_overlap(a, na, b, nb, &h2, &t2);
	kgenome_cfg_overlap(&sa, &sb, &h1, &t1);
	n_cases++;
	CKM(h0 == h2 && t0 == t2, "%s: the two oracles disagree (na %u nb %u): %u/%u vs %u/%u", what, na, nb, h0, t0, h2, t2);
	CKM(h1 == h0 && t1 == t0, "%s: na %u nb %u: lib %u of %u, oracle %u of %u", what, na, nb, h1, t1, h0, t0);
	pct = t0 ? h0 * 100u / t0 : 0u;
	CKM(kgenome_cfg_pct(&sa, &sb) == pct, "%s: pct na %u nb %u: lib %u oracle %u", what, na, nb, kgenome_cfg_pct(&sa, &sb), pct);
	CKM(kgenome_cfg_pct_callee(&sa, &sb) == pct, "%s: pct_callee na %u nb %u: lib %u oracle %u", what, na, nb, kgenome_cfg_pct_callee(&sa, &sb), pct);
	CKM(kgenome_cfg_pct(&sb, &sa) == pct, "%s: pct is not symmetric (na %u nb %u)", what, na, nb);
}

/* `n` ascending distinct values from a universe `u` apart: base + i * step */
static void ramp(uint32_t *v, uint32_t n, uint32_t base, uint32_t step)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		v[i] = base + i * step;
}

static void compare_shapes(void)
{
	uint32_t a[KGENOME_CFG_KEYS], b[KGENOME_CFG_KEYS], na, nb, k, cut;
	struct crng r;

	for (na = 0; na <= KGENOME_CFG_KEYS; na++)
		for (nb = 0; nb <= KGENOME_CFG_KEYS; nb++) {
			/* identical prefixes, then disjoint, subset, interleaved, shifted by k */
			ramp(a, na, 10u, 2u);
			ramp(b, nb, 10u, 2u);
			check_pair(a, na, b, nb, "same ramp");
			ramp(b, nb, 11u, 2u);
			check_pair(a, na, b, nb, "interleaved");
			ramp(b, nb, 100000u, 1u);
			check_pair(a, na, b, nb, "disjoint above");
			ramp(a, na, 100000u, 1u);
			ramp(b, nb, 10u, 1u);
			check_pair(a, na, b, nb, "disjoint below");
			for (k = 1; k <= 5; k++) {
				ramp(a, na, 10u, 1u);
				ramp(b, nb, 10u + k, 1u);
				check_pair(a, na, b, nb, "shifted");
			}
			/* every second element of the longer one: a subset */
			ramp(a, na, 10u, 2u);
			ramp(b, nb, 10u, 4u);
			check_pair(a, na, b, nb, "stride 2 against 4");
			ramp(a, na, 0u, 1u);
			ramp(b, nb, 0u, 1u);
			check_pair(a, na, b, nb, "from zero");
			/* 0xffffffff is a real element at the end of one or both: an exhausted side must not look like a match */
			ramp(a, na, 0xffffffffu - (na ? na - 1u : 0u), 1u);
			ramp(b, nb, 0xffffffffu - (nb ? nb - 1u : 0u), 1u);
			check_pair(a, na, b, nb, "both end at max");
			ramp(b, nb, 0x1000u, 3u);
			check_pair(a, na, b, nb, "a ends at max, b low");
			check_pair(b, nb, a, na, "b low, a ends at max");
			ramp(a, na, 0x1000u, 3u);
			ramp(b, nb, 0xffffffffu - (nb ? nb - 1u : 0u), 1u);
			check_pair(a, na, b, nb, "a low, b ends at max");
		}
	/* the cut: `cut` shared elements first, then the rest differs, so the 32nd element of the union is shared or not */
	for (cut = 0; cut <= KGENOME_CFG_KEYS; cut++)
		for (na = cut; na <= KGENOME_CFG_KEYS; na++)
			for (nb = cut; nb <= KGENOME_CFG_KEYS; nb++) {
				uint32_t i;

				for (i = 0; i < na; i++)
					a[i] = i < cut ? 10u * i : 10u * i + 1u;
				for (i = 0; i < nb; i++)
					b[i] = i < cut ? 10u * i : 10u * i + 2u;
				check_pair(a, na, b, nb, "cut");
			}
	/* random pairs over a small universe (matches everywhere, ties of position), and over the full range */
	for (k = 1; k <= 4000; k++) {
		uint32_t i, uni = (k & 1u) ? 40u + (k % 50u) : 0u, tmp[200], nt, t;

		crng_seed(&r, 91u + k);
		for (t = 0; t < 2; t++) {
			uint32_t *dst = t ? b : a, n = (uint32_t)(crng_next(&r) % (KGENOME_CFG_KEYS + 1u)), m = 0;

			for (i = 0, nt = 0; i < 100u; i++)
				tmp[nt++] = uni ? rnd32(&r) % uni : (k % 7u == 0 ? 0xffffff00u + rnd32(&r) % 256u : rnd32(&r));
			/* distinct ascending: the sketch's own contract */
			{
				struct kgenome_cfg_sign s;

				kgenome_cfg_keys_sign(&s, tmp, nt);
				m = s.n_key < n ? s.n_key : n;
				memcpy(dst, s.key, m * sizeof *dst);
			}
			if (t)
				nb = m;
			else
				na = m;
		}
		check_pair(a, na, b, nb, "random pair");
	}
}

/* ---- the benchmark ---- */

static double now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* a pair of sketches whose compares are NOT predictable: two random subsets of one universe of `uni` values, `n` keys each */
static void random_sketch(struct kgenome_cfg_sign *s, struct crng *r, uint32_t uni, uint32_t n)
{
	uint32_t v[200], i, k = 0;

	for (i = 0; i < uni && k < 200u; i++)
		v[k++] = i * 2654435u + 17u;
	shuffle(r, v, k);
	kgenome_cfg_keys_sign(s, v, n);
}

static uint32_t bench_div = 1;     /* `--bench N`: N times fewer repetitions, for a run under callgrind */

static void bench(void)
{
	static struct kgenome_cfg_block bb[64][1024];
	static struct kgenome_cfg g[64];
	static struct kgenome_cfg_sign s[4096], rel[4096];
	static const uint32_t sizes[] = { 16, 40, 100, 400, 1000 };
	struct crng r;
	uint32_t z, i, rep;
	volatile uint32_t sink = 0;
	double t0, t1;

	crng_seed(&r, 424242u);
	for (z = 0; z < sizeof sizes / sizeof *sizes; z++) {
		const uint32_t n = sizes[z], reps = (400000u / n + 200u) / bench_div + 1u;

		for (i = 0; i < 64; i++)
			hand_graph(&g[i], bb[i], n, &r);
		t0 = now_ns();
		for (rep = 0; rep < reps; rep++)
			for (i = 0; i < 64; i++) {
				struct kgenome_cfg_sign_req rq;

				memset(&rq, 0, sizeof rq);
				rq.g = &g[i];
				kgenome_cfg_sign(&rq, &s[i]);
				sink += s[i].n_key;
			}
		t1 = now_ns();
		printf("BENCH sign %4u blocks: %7.1f ns per function\n", n, (t1 - t0) / ((double)reps * 64.0));
	}
	{
		static uint32_t raw[64][1000];
		struct kgenome_cfg_sign k;

		for (z = 0; z < sizeof sizes / sizeof *sizes; z++) {
			const uint32_t n = sizes[z], reps = (400000u / n + 200u) / bench_div + 1u;

			for (i = 0; i < 64; i++) {
				uint32_t j;

				for (j = 0; j < n; j++)
					raw[i][j] = (uint32_t)crng_next(&r);
			}
			t0 = now_ns();
			for (rep = 0; rep < reps; rep++)
				for (i = 0; i < 64; i++) {
					kgenome_cfg_keys_sign(&k, raw[i], n);
					sink += k.n_key;
				}
			t1 = now_ns();
			printf("BENCH form %4u random elements: %7.1f ns per sketch\n", n, (t1 - t0) / ((double)reps * 64.0));
		}
	}
	{
		static const uint32_t unis[3] = { 40, 33, 200 };
		static const char *const what[3] = { "32-key subsets of 40 values, about 24 shared", "32 of 33 values, near-identical", "32 of 200 values, mostly unrelated" };
		uint32_t h, t, tot = 0, q;
		const uint32_t creps = 2000000 / bench_div;

		/* 4096 sketches and a pair order the predictor cannot memorise (a loop over 64 pairs was measured 27 ns for the branching merge: learned by heart) */
		for (q = 0; q < 3; q++) {
			uint32_t x = 12345u;

			for (i = 0; i < 4096; i++) {
				random_sketch(&s[i], &r, unis[q], 32);
				random_sketch(&rel[i], &r, unis[q], 32);
			}
			t0 = now_ns();
			for (rep = 0; rep < creps; rep++) {
				x = x * 1664525u + 1013904223u;
				kgenome_cfg_overlap(&s[(x >> 8) & 4095u], &rel[(x >> 20) & 4095u], &h, &t);
				tot += h + t;
			}
			t1 = now_ns();
			printf("BENCH compare: %.1f ns per call (%s)\n", (t1 - t0) / creps, what[q]);
		}
		sink += tot;
	}
	(void)sink;
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--bench")) {
		if (argc > 2 && atoi(argv[2]) > 0)
			bench_div = (uint32_t)atoi(argv[2]);
		bench();
		return 0;
	}
	form_exhaustive_small();
	form_distinct_counts();
	form_ties_and_random();
	sign_struct_matches();
	sign_callees_match();
	sign_callees_collisions();
	compare_shapes();
	printf("cfg_sketch: %llu cases\n", (unsigned long long)n_cases);
	if (fails)
		printf("cfg_sketch: %d FAILED\n", fails);
	else
		printf("cfg_sketch: ok\n");
	return fails != 0;
}
