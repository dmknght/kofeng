/*
 * genome / cfg_estimator - is the CFG sketch (celllysis/cfg_sign.c) an ESTIMATOR OF THE JACCARD INDEX OF TWO MULTISETS, as cfg.h says?
 *
 * DEFECT S1 (2026-11-03). The sketch is the 32 smallest keys of the elements (label, k-th occurrence), and kgenome_cfg_overlap is hit / taken over the
 * 32 smallest of the union. That is the bottom-k estimator of Jaccard, and it is unbiased with variance about J(1-J)/k ONLY IF the keys of the
 * elements are independent uniform values. The first key function made (label, run) by two mix rounds in which `run` is a small integer: the keys of one
 * label came out as a near-arithmetic progression, so a label that repeats many times put MANY of its elements below every other label's. Measured on
 * the old code: cmake 0x3c5510 (77 blocks) against doxygen 0x23f4a0 (183 blocks), both dominated by one label, gave pct 100 for an exact J of 0.42.
 *
 * WHY THE OLD TESTS DID NOT SEE IT: (b) no boundary input. They check that the sketch EQUALS a reference built with the same key formula (cfg_sketch,
 * cfg_sign: the oracle spells the formula out, so a wrong formula is wrong in both), that the form is sorted, bounded and distinct, that identical
 * graphs give 100 and unrelated ones give a low number. None compared the estimate with the true Jaccard of two multisets where ONE label repeats
 * many times and the sizes differ, and none looked at the distribution of the estimate, only at single values.
 *
 * THE ORACLE IS ARITHMETIC, NOT A HASH: the exact Jaccard of two multisets is sum_l min(a_l, b_l) / sum_l max(a_l, b_l) over labels l (the sets
 * {(l, 0..a_l-1)} and {(l, 0..b_l-1)} intersect in min and unite in max elements). It is computed below from the counts the test chose.
 *
 * THE THEORY, k = 32. Let the union have N elements, J of them in both. With independent uniform keys the k smallest of the union are a uniformly
 * random k-subset of it, so `hit` is hypergeometric: E[hit / k] = J exactly, Var = J(1-J)/k * (N-k)/(N-1) <= J(1-J)/k. So the standard error of one
 * estimate is s = sqrt(J(1-J)/32) (at most 0.088), and z = (estimate - J) / s has mean 0 and root mean square <= 1 (the finite-population factor can
 * only lower it), whatever the multisets are. When the union has at most 32 elements the sketches are the sets and the estimate is exact.
 * The tests use deterministic seeds and fixed trial counts; a trial draws FRESH random 64-bit label identities, so the randomness is the hash's.
 *   (a) bias      mean(z) over all trials of a case within +-0.35 (T = 300 trials: the mean of T unit-variance values has sd 0.058, so 6 sigma)
 *   (b) spread    root mean square z <= 1.15 and the 99th percentile of |z| <= 3.2 (a normal's is 2.58; the discrete estimator has granularity 1/32)
 *   (c) the cmake/doxygen shape: one label x 77 against the same label x 183, J = 77/183 = 0.42: estimate never >= 0.9 and mean within 0.03
 *   (d) properties: symmetric; identical multisets give 100; disjoint ones give 0; mean estimate grows with the overlap
 *   (e) records: for one label the k-th occurrence's key is a record when it is below the keys of all earlier occurrences. Independent keys give
 *       H_n = 1 + 1/2 + ... + 1/n records in n occurrences (n = 183: 5.88), variance H_n - H_n^(2) (4.2). The old key gave 16.9 (survey, agent-reported).
 *       The serial correlation of the keys of runs r and r + d is checked the same way (independent: 0, standard error 1/sqrt(labels)).
 */
#include "cfg_kit.h"

#include <math.h>

static uint64_t n_cases;
static int id_seq;      /* 1: label identities are consecutive small integers (a symbol index), 0: random 64-bit */
static int verbose;     /* `cfg_estimator -v` prints the statistics each bound is set against */

/* ---- the oracle: exact multiset Jaccard from the counts ---- */
#define NL 8u
struct mset {
	uint32_t n;                     /* labels */
	uint32_t a[NL], b[NL];          /* count of each label in A and in B */
};

static double exact_j(const struct mset *m)
{
	uint64_t lo = 0, hi = 0;
	uint32_t i;

	for (i = 0; i < m->n; i++) {
		lo += m->a[i] < m->b[i] ? m->a[i] : m->b[i];
		hi += m->a[i] > m->b[i] ? m->a[i] : m->b[i];
	}
	return hi ? (double)lo / (double)hi : 1.0;
}

/* The lib's signature of a multiset of callee identities (kind 0): ONE block, `n` calls, policy CALLEES, so the sketch is of exactly {(id, k)}. */
#define MAXC 1024u
static struct kgenome_cfg_block cb[1];
static struct kgenome_cfg_call ccall[MAXC];

static void sketch_of(const uint64_t *id, const uint32_t *cnt, uint32_t nl, struct kgenome_cfg_sign *s)
{
	struct kgenome_cfg g;
	struct kgenome_cfg_sign_req rq;
	uint32_t i, j, n = 0;

	for (i = 0; i < nl; i++)
		for (j = 0; j < cnt[i] && n < MAXC; j++) {
			ccall[n].id = id[i];
			ccall[n].insn = n;
			ccall[n].kind = 0;
			n++;
		}
	memset(&g, 0, sizeof g);
	memset(cb, 0, sizeof cb);
	cb[0].reach = 1;
	cb[0].succ[0] = cb[0].succ[1] = KGENOME_CFG_NONE;
	cb[0].term = 3;
	g.b = cb;
	g.n_all = g.n_blk = 1;
	g.call = ccall;
	g.n_call = n;
	memset(&rq, 0, sizeof rq);
	rq.g = &g;
	rq.policy = KGENOME_CFG_P_CALLEES;
	CK(kgenome_cfg_sign(&rq, s) == KGENOME_OK);
}

/* One estimate of the Jaccard of the two multisets of `m`, with fresh random label identities from `r`: hit / taken of the lib's overlap over the two
 * callee sketches (copied into the key slots, where kgenome_cfg_overlap reads), and the pct the lib answers in both orders. */
struct est {
	double e;
	uint32_t pct, pct_rev, taken;
};

static struct est estimate(const struct mset *m, struct crng *r)
{
	uint64_t id[NL];
	struct kgenome_cfg_sign sa, sb, ka, kb;
	struct est x;
	uint32_t i, hit;

	const uint64_t base = crng_next(r) % 4096u;

	for (i = 0; i < m->n; i++)
		id[i] = id_seq ? base + i + 1u : crng_next(r) | 1u;     /* 0 is "unresolved" and makes no element */
	sketch_of(id, m->a, m->n, &sa);
	sketch_of(id, m->b, m->n, &sb);
	memset(&ka, 0, sizeof ka);
	memset(&kb, 0, sizeof kb);
	memcpy(ka.key, sa.ckey, sizeof ka.key);
	memcpy(kb.key, sb.ckey, sizeof kb.key);
	ka.n_key = sa.n_ckey;
	kb.n_key = sb.n_ckey;
	kgenome_cfg_overlap(&ka, &kb, &hit, &x.taken);
	x.e = x.taken ? (double)hit / (double)x.taken : 0.0;
	x.pct = kgenome_cfg_pct_callee(&sa, &sb);
	x.pct_rev = kgenome_cfg_pct_callee(&sb, &sa);
	return x;
}

static int cmp_dbl(const void *a, const void *b)
{
	const double x = *(const double *)a, y = *(const double *)b;

	return x < y ? -1 : x > y;
}

/* z of one estimate: (estimate - J) / sqrt(J(1-J)/32); 0 where J is 0 or 1 (the estimate must then be exact, checked by the caller) */
static double zof(double e, double j)
{
	const double v = j * (1.0 - j) / (double)KGENOME_CFG_KEYS;

	return v > 0 ? (e - j) / sqrt(v) : 0.0;
}

#define TMAX 400u
struct zstat {
	double mean, rms, p99, emean, emax, emin;
	uint32_t ge90;
};

/* T trials of one case; checks the per-trial properties (symmetry, an exact answer where J is 0 or 1, a union of at most 32 exact). */
static void run_case(const struct mset *m, uint32_t T, uint64_t seed, struct zstat *o, double *zs)
{
	struct crng r;
	const double j = exact_j(m);
	uint64_t un = 0;
	uint32_t t, i;
	double sz = 0, sq = 0, se = 0;
	static double az[TMAX];

	for (i = 0; i < m->n; i++)
		un += m->a[i] > m->b[i] ? m->a[i] : m->b[i];
	crng_seed(&r, seed);
	memset(o, 0, sizeof *o);
	o->emin = 2.0;
	for (t = 0; t < T; t++) {
		const struct est x = estimate(m, &r);
		const double z = zof(x.e, j);

		n_cases++;
		CKM(x.pct == x.pct_rev, "asymmetric pct %u vs %u (seed %llu trial %u)", x.pct, x.pct_rev, (unsigned long long)seed, t);
		CKM(x.pct == (uint32_t)(x.e * 100.0 + 1e-9) || x.taken == 0, "pct %u is not hit*100/taken of the overlap (%f)", x.pct, x.e);
		if (j == 0.0 || j == 1.0)
			CKM(x.e == j, "J %f: estimate %f must be exact", j, x.e);
		if (un <= KGENOME_CFG_KEYS)
			CKM(x.e == j, "union %llu <= 32: the sketches are the sets, estimate %f J %f", (unsigned long long)un, x.e, j);
		sz += z;
		sq += z * z;
		se += x.e;
		o->ge90 += x.e >= 0.9;
		if (x.e > o->emax)
			o->emax = x.e;
		if (x.e < o->emin)
			o->emin = x.e;
		az[t] = z < 0 ? -z : z;
		if (zs)
			zs[t] = z;
	}
	o->mean = sz / T;
	o->rms = sqrt(sq / T);
	o->emean = se / T;
	qsort(az, T, sizeof *az, cmp_dbl);
	o->p99 = az[(T * 99u) / 100u];
}

static void check_z(const struct zstat *z, const char *what, double j)
{
	CKM(fabs(z->mean) <= 0.35, "%s: J %.3f bias: mean z %.3f (estimate mean %.3f)", what, j, z->mean, z->emean);
	CKM(z->rms <= 1.15, "%s: J %.3f spread: rms z %.3f", what, j, z->rms);
	/* the normal approximation of the tail needs 32 J >= 3 and 32 (1-J) >= 3; beyond it the estimate is a Poisson count (J = 0.01: hit >= 3 of 32 has
	 * probability 0.35%, which would be 5 trials of 400 about one run in ten) and the bound is on the distance instead: 8 extra hits of 32 at J = 0.01 is 1e-8 */
	if (j >= 0.1 && j <= 0.9)
		CKM(z->p99 <= 3.2, "%s: J %.3f spread: p99 |z| %.3f (estimate range %.3f..%.3f)", what, j, z->p99, z->emin, z->emax);
	else
		CKM(z->emax - j <= 0.25 && j - z->emin <= 0.25, "%s: J %.3f spread: estimate range %.3f..%.3f", what, j, z->emin, z->emax);
}

/* ---- (a)(b) one label repeated p times against q times, a sweep of sizes; and a second label shared ---- */
static void case_sweep(void)
{
	static const uint32_t pq[][2] = {
		{77, 183}, {1, 2}, {20, 40}, {10, 100}, {50, 51}, {32, 64}, {40, 400}, {100, 300}, {5, 500}, {33, 66}, {90, 100}, {64, 128}, {200, 600}, {60, 90},
	};
	uint32_t c;

	for (c = 0; c < sizeof pq / sizeof pq[0]; c++) {
		struct mset m;
		struct zstat z;
		char w[64];

		memset(&m, 0, sizeof m);
		m.n = 1;
		m.a[0] = pq[c][0];
		m.b[0] = pq[c][1];
		run_case(&m, TMAX, 100u + c, &z, NULL);
		snprintf(w, sizeof w, "one label x%u vs x%u", pq[c][0], pq[c][1]);
		check_z(&z, w, exact_j(&m));
	}
	/* a shared label of fixed size beside the repeated one, and a private label on one side */
	for (c = 0; c < 12; c++) {
		struct mset m;
		struct zstat z;
		struct crng r;
		char w[64];

		crng_seed(&r, 500u + c);
		memset(&m, 0, sizeof m);
		m.n = 3;
		m.a[0] = 1u + crng_below(&r, 80);
		m.b[0] = 1u + crng_below(&r, 300);
		m.a[1] = m.b[1] = 1u + crng_below(&r, 60);
		m.a[2] = 0;
		m.b[2] = crng_below(&r, 40);
		run_case(&m, TMAX, 600u + c, &z, NULL);
		snprintf(w, sizeof w, "three labels case %u", c);
		check_z(&z, w, exact_j(&m));
	}
}

/* ---- (a)(b) random multisets, pooled: the statistics of all of them together are far tighter than one case ---- */
static void case_random_pool(void)
{
	uint32_t c, n = 0;
	double sz = 0, sq = 0, sabs = 0;
	static double zall[160u * 40u];
	struct crng r;
	uint32_t big = 0;

	crng_seed(&r, 4242);
	for (c = 0; c < 160; c++) {
		struct mset m;
		struct zstat z;
		static double zs[TMAX];
		uint32_t i, t, T = 40, rep = 1u + crng_below(&r, 3), cmax = 3u + crng_below(&r, 3) * 120u;

		memset(&m, 0, sizeof m);
		m.n = 1u + crng_below(&r, 6);
		for (i = 0; i < m.n; i++) {
			/* a label repeats many times in one multiset and rarely in the other: the shape of the defect */
			m.a[i] = crng_below(&r, cmax * rep);
			m.b[i] = crng_below(&r, 2u) ? m.a[i] / (1u + crng_below(&r, 4)) : crng_below(&r, cmax);
		}
		for (;;) {      /* a side holds at most MAXC calls: halve the counts until both sides fit */
			uint32_t sa = 0, sb = 0;

			for (i = 0; i < m.n; i++) {
				sa += m.a[i];
				sb += m.b[i];
			}
			if (sa <= MAXC && sb <= MAXC)
				break;
			for (i = 0; i < m.n; i++) {
				m.a[i] /= 2u;
				m.b[i] /= 2u;
			}
		}
		if (exact_j(&m) == 1.0 || exact_j(&m) == 0.0)
			continue;
		run_case(&m, T, 9000u + c, &z, zs);
		for (t = 0; t < T; t++) {
			zall[n++] = zs[t] < 0 ? -zs[t] : zs[t];
			sz += zs[t];
			sq += zs[t] * zs[t];
			sabs += zs[t] < 0 ? -zs[t] : zs[t];
		}
		big += z.ge90 && exact_j(&m) <= 0.5;
	}
	qsort(zall, n, sizeof *zall, cmp_dbl);
	/* pooled over n ~ 5000 trials: mean z has sd 1/sqrt(n) = 0.014 (bound 0.1 allows 7 sigma); rms z <= 1.05; the 99th percentile of |z| <= 2.9 */
	if (verbose)
		printf("pooled: %u trials mean z %.3f rms z %.3f mean|z| %.3f p99|z| %.3f\n", n, sz / n, sqrt(sq / n), sabs / n, zall[(n * 99u) / 100u]);
	CKM(fabs(sz / n) <= 0.10, "pooled random multisets: mean z %.3f over %u trials", sz / n, n);
	CKM(sqrt(sq / n) <= 1.05, "pooled random multisets: rms z %.3f", sqrt(sq / n));
	CKM(sabs / n <= 0.85, "pooled random multisets: mean |z| %.3f (a normal's is 0.80)", sabs / n);
	CKM(zall[(n * 99u) / 100u] <= 2.9, "pooled random multisets: p99 |z| %.3f", zall[(n * 99u) / 100u]);
	CKM(big == 0, "%u random cases with J <= 0.5 gave an estimate >= 0.9", big);
	CK(n > 3000u);
}

/* ---- (c) the shape of the survey's pair ---- */
static void case_cmake_doxygen(void)
{
	struct mset m;
	struct zstat z;

	memset(&m, 0, sizeof m);
	m.n = 1;
	m.a[0] = 77;
	m.b[0] = 183;
	run_case(&m, TMAX, 31337, &z, NULL);
	if (verbose)
		printf("77 vs 183: mean estimate %.3f (J %.3f) max %.3f min %.3f >=0.9: %u rms z %.3f\n", z.emean, 77.0 / 183.0, z.emax, z.emin, z.ge90, z.rms);
	CKM(z.ge90 == 0, "77 vs 183 of one label: %u of %u estimates >= 0.9 (old key: pct 100 for J 0.42)", z.ge90, TMAX);
	CKM(fabs(z.emean - 77.0 / 183.0) <= 0.03, "77 vs 183: mean estimate %.3f, J %.3f", z.emean, 77.0 / 183.0);
	CKM(z.emax <= 0.75, "77 vs 183: largest estimate %.3f", z.emax);
}

/* ---- (d) properties ---- */
static void case_properties(void)
{
	static const uint32_t q[] = {100, 80, 60, 40, 20, 10, 5};
	double prev = 2.0;
	uint32_t i;
	struct crng r;

	/* identical multisets: pct 100, in both orders, whatever the counts */
	for (i = 1; i <= 300; i += 7) {
		struct mset m;
		struct est x;

		memset(&m, 0, sizeof m);
		m.n = 2;
		m.a[0] = m.b[0] = i;
		m.a[1] = m.b[1] = 301u - i;
		crng_seed(&r, 70u + i);
		x = estimate(&m, &r);
		CKM(x.pct == 100u && x.pct_rev == 100u, "identical multisets (%u, %u): pct %u", i, 301u - i, x.pct);
	}
	/* disjoint: no shared label, pct 0 */
	for (i = 1; i <= 300; i += 13) {
		struct kgenome_cfg_sign sa, sb;
		uint64_t ia = 0x1111111111111111ull + i, ib = 0x2222222222222222ull + i;
		uint32_t ca = i, cb2 = 301u - i;

		sketch_of(&ia, &ca, 1, &sa);
		sketch_of(&ib, &cb2, 1, &sb);
		CKM(kgenome_cfg_pct_callee(&sa, &sb) == 0u, "disjoint labels x%u and x%u: pct %u", ca, cb2, kgenome_cfg_pct_callee(&sa, &sb));
	}
	/* the mean estimate falls as the overlap falls, and is near J at each step (one label x100 against x q) */
	for (i = 0; i < sizeof q / sizeof q[0]; i++) {
		struct mset m;
		struct zstat z;

		memset(&m, 0, sizeof m);
		m.n = 1;
		m.a[0] = 100;
		m.b[0] = q[i];
		run_case(&m, 300, 7000u + i, &z, NULL);
		CKM(z.emean < prev || q[i] == 100u, "mean estimate not decreasing with the overlap: q %u mean %.3f after %.3f", q[i], z.emean, prev);
		CKM(fabs(z.emean - q[i] / 100.0) <= 0.05, "x100 vs x%u: mean estimate %.3f, J %.3f", q[i], z.emean, q[i] / 100.0);
		prev = z.emean;
	}
}

/* ---- (e) the keys of one label ---- */
static double harmonic(uint32_t n, int sq)
{
	double h = 0;
	uint32_t i;

	for (i = 1; i <= n; i++)
		h += sq ? 1.0 / ((double)i * i) : 1.0 / i;
	return h;
}

static void case_records(void)
{
	static const uint32_t ns[] = {32, 77, 183, 1000};
	uint32_t c, l, r;
	struct crng g;
	static const uint32_t L = 2000;

	crng_seed(&g, 99);
	for (c = 0; c < sizeof ns / sizeof ns[0]; c++) {
		const double want = harmonic(ns[c], 0), var = want - harmonic(ns[c], 1);
		double sum = 0;

		crng_seed(&g, 99u + c);
		for (l = 0; l < L; l++) {
			const uint64_t lab = crng_next(&g);
			uint32_t min = 0xffffffffu, rec = 0;

			for (r = 0; r < ns[c]; r++) {
				const uint32_t k = kgenome_cfg_key(lab, r);

				if (k < min) {
					min = k;
					rec++;
				}
			}
			sum += rec;
		}
		if (verbose)
			printf("records in %u runs: mean %.3f, independent %.3f\n", ns[c], sum / L, want);
		/* mean of L records counts: sd sqrt(var / L); 7 sigma */
		CKM(fabs(sum / L - want) <= 7.0 * sqrt(var / L), "prefix-minimum records in %u runs: mean %.3f, independent keys %.3f (+-%.3f)", ns[c], sum / L, want, 7.0 * sqrt(var / L));
		n_cases++;
	}
}

static void case_serial(void)
{
	static const uint32_t ds[] = {1, 2, 3, 4, 7, 8, 16, 64};
	static const uint32_t L = 4000;
	uint32_t i, l, r;
	struct crng g;

	/* the keys of runs r and r + d of ONE label: correlation 0, standard error 1/sqrt(L) = 0.016 (bound 0.08, 5 sigma). Runs 0..3 each. */
	for (i = 0; i < sizeof ds / sizeof ds[0]; i++)
		for (r = 0; r < 4; r++) {
			double s = 0;

			crng_seed(&g, 1234u + i);
			for (l = 0; l < L; l++) {
				const uint64_t lab = crng_next(&g);
				const double u = kgenome_cfg_key(lab, r) / 4294967296.0 - 0.5, v = kgenome_cfg_key(lab, r + ds[i]) / 4294967296.0 - 0.5;

				s += u * v;
			}
			CKM(fabs(s / L * 12.0) <= 0.08, "keys of runs %u and %u of one label: correlation %.3f", r, r + ds[i], s / L * 12.0);
			n_cases++;
		}
	/* each run's key is uniform on 32 bits: mean 0.5 (sd of the mean 0.0046) and the top bit is a fair coin */
	for (r = 0; r < 12; r++) {
		double s = 0;
		uint32_t top = 0;

		crng_seed(&g, 555u + r);
		for (l = 0; l < L; l++) {
			const uint32_t k = kgenome_cfg_key(crng_next(&g), r);

			s += k / 4294967296.0;
			top += k >> 31;
		}
		CKM(fabs(s / L - 0.5) <= 0.03, "run %u: mean key %.4f", r, s / L);
		CKM(top > L / 2u - 200u && top < L / 2u + 200u, "run %u: top bit set %u of %u", r, top, L);
		n_cases++;
	}
}

/* Strict avalanche of the run: flipping one bit of the run changes each of the 32 bits of the key with probability 1/2, so about 16 bits change (the sd of
 * the mean over L pairs is 2.83/sqrt(L) = 0.063 for L = 2000; the bound 0.5 is 8 sigma). The same for a bit of the label. */
static void case_avalanche(void)
{
	static const uint32_t L = 2000;
	uint32_t b, l;
	struct crng g;

	crng_seed(&g, 77);
	for (b = 0; b < 12; b++) {
		double sr = 0, sl = 0;

		for (l = 0; l < L; l++) {
			const uint64_t lab = crng_next(&g);
			const uint32_t run = (uint32_t)(crng_next(&g) % 1000u);

			sr += __builtin_popcount(kgenome_cfg_key(lab, run) ^ kgenome_cfg_key(lab, run ^ (1u << b)));
			sl += __builtin_popcount(kgenome_cfg_key(lab, run) ^ kgenome_cfg_key(lab ^ (1ull << (b * 5u)), run));
		}
		CKM(fabs(sr / L - 16.0) <= 0.5, "flip run bit %u: %.2f key bits change, 16 expected", b, sr / L);
		CKM(fabs(sl / L - 16.0) <= 0.5, "flip label bit %u: %.2f key bits change, 16 expected", b * 5u, sl / L);
		n_cases++;
	}
}

int main(int argc, char **argv)
{
	verbose = argc > 1 && !strcmp(argv[1], "-v");
	case_records();
	case_serial();
	case_avalanche();
	case_cmake_doxygen();
	case_sweep();
	case_random_pool();
	case_properties();
	/* the same statistics when the identities a caller gives are consecutive small integers: the labels of the elements are then close, and the keys must still be independent */
	id_seq = 1;
	case_cmake_doxygen();
	case_sweep();
	case_random_pool();
	id_seq = 0;
	printf("cfg_estimator: %llu cases\n", (unsigned long long)n_cases);
	if (fails)
		printf("cfg_estimator: %d FAILED\n", fails);
	else
		printf("cfg_estimator: ok\n");
	return fails != 0;
}
