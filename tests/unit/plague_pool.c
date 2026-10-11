/*
 * plague_pool - the block's input pipeline, from the span to the hashes, and the
 * scan that reads them back, under hostile input sizes and shapes.
 *
 * WHAT IS PINNED, each a way the pipeline could be wrong while looking fine:
 *
 *   - THE POOL IS THE SET OF DISTINCT, NON-FLAT WINDOW HASHES, ascending, for
 *     every normalizer, at every length from 8 to a megabyte and for data of
 *     every shape that breaks a hash: random, ASCII, zeros, one repeated pair,
 *     long runs with islands, a counter. Checked against a brute force that
 *     recomputes each window from scratch, so the rolling update is what is on
 *     trial.
 *   - MEMBERSHIP IS EXACT: the bit table in front of the search may reject only
 *     what is not there. Bit i is set if and only if some window of the sample is
 *     pool[i].
 *   - THE CORE IS A SELECTION, not an estimate: ascending, a subset of the pool,
 *     monotone in both thresholds, and "no block" below the floor.
 *   - A SPAN THAT CONTAINS THE DATA GIVES THE SAME BLOCK however it is cut: shifted,
 *     grown or shrunk by a tenth or a half, with neighbours of any size. A span
 *     that does not contain it gives no block. This is the property the whole
 *     pipeline exists for.
 *   - THE SCAN COUNTS EACH HASH ONCE PER OBJECT: the score of every block equals a
 *     brute-force count of its hashes among the windows of all the units, for a
 *     set big enough that the bit table and the `top` reject are both exercised,
 *     with blocks of small hashes and blocks of uniform ones mixed. A false
 *     negative in either reject shows here as a missing hash.
 *   - SIZE DOES NOT MATTER TO THE SCORE: a block of 24 bytes in a unit of a
 *     megabyte, and a block of 64 KB in a unit of its own length, both read 100.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/overlord/plague/kofplague.h"

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static uint32_t rng_state = 0x9e3779b9u;

static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

/* ---- data of every shape ------------------------------------------------ */

enum shape { S_RANDOM, S_ASCII, S_ZERO, S_PAIR, S_ISLANDS, S_COUNTER, S_COUNT };

static void fill(uint8_t *b, size_t n, enum shape sh)
{
	size_t i;

	for (i = 0; i < n; i++) {
		switch (sh) {
		case S_RANDOM:  b[i] = (uint8_t)rnd(); break;
		case S_ASCII:   b[i] = (uint8_t)(32u + rnd() % 95u); break;
		case S_ZERO:    b[i] = 0; break;
		case S_PAIR:    b[i] = (i & 1u) ? 0xA5u : 0x5Au; break;
		case S_ISLANDS: b[i] = (rnd() % 97u == 0) ? (uint8_t)rnd() : 0x90u; break;
		default:        b[i] = (uint8_t)i; break;
		}
	}
}

/* ---- references written from first principles --------------------------- */

static int u32_cmp(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

/* Every window recomputed from its eight bytes: no rolling anywhere. */
static uint32_t window_at(const uint8_t *p, uint64_t at, uint32_t norm)
{
	uint32_t h = 0, i;

	for (i = 0; i < KOF_PLAGUE_NG; i++)
		h = h * KOF_PLAGUE_BASE + (uint32_t)kof_plague_byte(p, at + i, norm);
	return kof_plague_mix(h);
}

static uint32_t *ref_pool(const uint8_t *p, uint64_t n, uint32_t norm,
			  uint32_t *np)
{
	uint32_t *v, got = 0, k = 0;
	uint64_t at, eff = n;

	*np = 0;
	if (norm != KOF_PLAGUE_RAW) {
		if (n < 2)
			return NULL;
		eff = n - 1;
	}
	if (eff < KOF_PLAGUE_NG)
		return NULL;
	v = malloc((size_t)(eff - KOF_PLAGUE_NG + 1) * sizeof *v);
	if (!v)
		return NULL;
	for (at = 0; at + KOF_PLAGUE_NG <= eff; at++)
		if (!kof_plague_flat(p, at, norm))
			v[got++] = window_at(p, at, norm);
	if (!got) {
		free(v);
		return NULL;
	}
	qsort(v, got, sizeof *v, u32_cmp);
	for (at = 1, k = 1; at < got; at++)
		if (v[at] != v[k - 1])
			v[k++] = v[at];
	*np = k;
	return v;
}

static int has(const uint32_t *pool, uint32_t n, uint32_t v)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;

		if (pool[mid] < v)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < n && pool[lo] == v;
}

/* ---- the pool ------------------------------------------------------------ */

static void pool_cases(void)
{
	static const size_t sizes[] = { 8, 9, 15, 16, 23, 24, 25, 64, 255, 1000,
					4096, 65537, 1u << 20 };
	size_t si;
	uint32_t norm;
	int bad_len = 0, bad_val = 0, bad_ord = 0, nulls = 0;

	for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
		uint8_t *buf = malloc(sizes[si]);
		int sh;

		if (!buf) {
			check(0, "allocation");
			return;
		}
		for (sh = 0; sh < S_COUNT; sh++) {
			fill(buf, sizes[si], (enum shape)sh);
			for (norm = 0; norm < KOF_PLAGUE_NORM_COUNT; norm++) {
				uint32_t na = 0, nb = 0, i;
				uint32_t *a = kof_plague_pool(buf, sizes[si], norm, &na);
				uint32_t *b = ref_pool(buf, sizes[si], norm, &nb);

				if ((a == NULL) != (b == NULL)) {
					nulls++;
					free(a); free(b);
					continue;
				}
				if (!a)
					continue;
				if (na != nb)
					bad_len++;
				else {
					for (i = 0; i < na; i++) {
						if (a[i] != b[i])
							bad_val++;
						if (i && a[i] <= a[i - 1])
							bad_ord++;
					}
				}
				free(a);
				free(b);
			}
		}
		free(buf);
	}
	check(nulls == 0, "pool/no-pool agrees with the reference for every shape");
	check(bad_len == 0, "pool length equals the reference at every size and shape");
	check(bad_val == 0, "pool values equal the reference (rolling = recomputed)");
	check(bad_ord == 0, "pool is strictly ascending");
	{
		/* zeros and one repeated byte have no window worth keeping */
		static uint8_t z[4096];
		uint32_t n = 99;

		memset(z, 0x41, sizeof z);
		check(kof_plague_pool(z, sizeof z, KOF_PLAGUE_RAW, &n) == NULL && n == 0,
		      "a span of one repeated byte has no pool");
		check(kof_plague_pool(z, 7, KOF_PLAGUE_RAW, &n) == NULL,
		      "seven bytes have no window");
	}
}

static void minhash_cases(void)
{
	static uint8_t buf[8192];
	uint32_t out[KOF_PLAGUE_MINHASH_K], np = 0, got, i;
	uint32_t *pool;
	int bad = 0;

	fill(buf, sizeof buf, S_ASCII);
	pool = kof_plague_pool(buf, sizeof buf, KOF_PLAGUE_RAW, &np);
	got = kof_plague_minhash(buf, sizeof buf, KOF_PLAGUE_RAW, out);
	check(pool && got == KOF_PLAGUE_MINHASH_K, "a large span yields K hashes");
	for (i = 0; pool && i < got; i++)
		if (out[i] != pool[i])
			bad++;
	check(bad == 0, "minhash is the first K of the pool - one generator");
	free(pool);
	check(kof_plague_minhash(buf, 7, KOF_PLAGUE_RAW, out) == 0,
	      "under a window there is no hash");
	got = kof_plague_minhash(buf, 23, KOF_PLAGUE_RAW, out);
	check(got == 16, "23 bytes are 16 windows: the smallest block the floor allows");
}

/* ---- membership ---------------------------------------------------------- */

static void member_cases(void)
{
	static const size_t psz[] = { 24, 200, 3000, 20000 };
	static const size_t ssz[] = { 8, 100, 5000, 400000 };
	size_t a, b;
	int wrong = 0, cases = 0;

	for (a = 0; a < sizeof psz / sizeof psz[0]; a++)
		for (b = 0; b < sizeof ssz / sizeof ssz[0]; b++) {
			uint8_t *src = malloc(psz[a] + 1), *smp = malloc(ssz[b] + 1);
			uint32_t np = 0, *pool, i, nref = 0;
			uint32_t *ref;
			uint8_t *bits;
			int sh;

			if (!src || !smp) {
				check(0, "allocation");
				return;
			}
			for (sh = 0; sh < 3; sh++) {
				size_t share, k;

				fill(src, psz[a], sh == 0 ? S_RANDOM : sh == 1 ? S_ASCII
								       : S_ISLANDS);
				fill(smp, ssz[b], sh == 0 ? S_RANDOM : sh == 1 ? S_ASCII
								       : S_ISLANDS);
				/* half the sample is a copy of part of the source */
				share = psz[a] < ssz[b] ? psz[a] : ssz[b];
				for (k = 0; k < share / 2; k++)
					smp[ssz[b] / 3 + k < ssz[b] ? ssz[b] / 3 + k : k] =
						src[k];
				pool = kof_plague_pool(src, psz[a], KOF_PLAGUE_RAW, &np);
				ref = ref_pool(smp, ssz[b], KOF_PLAGUE_RAW, &nref);
				if (!pool) {
					free(ref);
					continue;
				}
				bits = calloc((np + 7) / 8, 1);
				kof_plague_member(pool, np, smp, ssz[b], KOF_PLAGUE_RAW, bits);
				for (i = 0; i < np; i++) {
					int got = (bits[i >> 3] >> (i & 7)) & 1;
					int want = ref && has(ref, nref, pool[i]);

					if (got != want)
						wrong++;
				}
				cases++;
				free(bits); free(pool); free(ref);
			}
			free(src); free(smp);
		}
	check(cases >= 30, "enough membership cases ran");
	check(wrong == 0, "bit i is set iff the sample has window pool[i]: no false "
	      "negative from the bit table, no false positive from the search");
}

/* ---- the core ------------------------------------------------------------ */

static void core_cases(void)
{
	static uint32_t pool[1000];
	static uint16_t pos[1000], bg[1000];
	uint32_t out[KOF_PLAGUE_MINHASH_K], out2[KOF_PLAGUE_MINHASH_K];
	uint32_t i, n, n2;
	int asc = 1, subset = 1;

	for (i = 0; i < 1000; i++) {
		pool[i] = i * 1000u + 7u;
		pos[i] = (uint16_t)(i % 5);       /* 0..4 positives hold it */
		bg[i] = (uint16_t)((i / 5) % 4);  /* 0..3 background files hold it */
	}
	n = kof_plague_core(pool, 1000, pos, 4, bg, 0, 32, out);
	for (i = 0; i < n; i++) {
		if (i && out[i] <= out[i - 1])
			asc = 0;
		if (!has(pool, 1000, out[i]))
			subset = 0;
	}
	check(n == 32 && asc && subset, "core is K ascending members of the pool");
	/* pos == 4 and bg == 0: i%5==4 and (i/5)%4==0 -> i = 4, 24, 44, ... */
	check(out[0] == 4 * 1000u + 7u && out[1] == 24 * 1000u + 7u,
	      "and they are the windows every positive holds and no background does");
	n2 = kof_plague_core(pool, 1000, pos, 3, bg, 0, 32, out2);
	check(n2 >= n, "a looser positive threshold never selects fewer");
	n2 = kof_plague_core(pool, 1000, pos, 4, bg, 2, 32, out2);
	check(n2 >= n, "a looser background threshold never selects fewer");
	check(kof_plague_core(pool, 1000, pos, 5, bg, 0, 32, out) == 0,
	      "no window held by five positives: no block");
	{
		uint16_t few[10] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

		check(kof_plague_core(pool, 10, few, 1, NULL, 0, 32, out) == 0,
		      "ten windows are under the floor of sixteen: no block");
	}
	check(kof_plague_core(NULL, 0, NULL, 1, NULL, 0, 32, out) == 0,
	      "nothing in, nothing out");
}

/* ---- the property the pipeline exists for -------------------------------- */

#define CORE_LEN 900

static uint32_t make_core(const uint8_t *const samples[], uint32_t n_pos,
			  const uint8_t *const bgs[], uint32_t n_bg, size_t sample_len,
			  size_t lo, size_t hi, uint32_t *out)
{
	uint32_t np = 0, i, j, k;
	uint32_t *pool = kof_plague_pool(samples[0] + lo, hi - lo, KOF_PLAGUE_RAW, &np);
	uint16_t *pos, *bg;
	uint8_t *bits;
	uint32_t got;

	if (!pool)
		return 0;
	pos = calloc(np, sizeof *pos);
	bg = calloc(np, sizeof *bg);
	bits = malloc((np + 7) / 8);
	for (j = 0; j < n_pos + n_bg; j++) {
		const uint8_t *s = j < n_pos ? samples[j] : bgs[j - n_pos];

		memset(bits, 0, (np + 7) / 8);
		kof_plague_member(pool, np, s, sample_len, KOF_PLAGUE_RAW, bits);
		for (i = 0; i < np; i++)
			if ((bits[i >> 3] >> (i & 7)) & 1) {
				if (j < n_pos)
					pos[i]++;
				else
					bg[i]++;
			}
	}
	got = kof_plague_core(pool, np, pos, n_pos, bg, 0, KOF_PLAGUE_MINHASH_K, out);
	(void)k;
	free(pool); free(pos); free(bg); free(bits);
	return got;
}

static void invariance_cases(void)
{
	enum { NS = 5, NB = 12 };
	size_t len = 6000, core_at = 2500;
	uint8_t *pos_w[NS], *bg_w[NB];
	const uint8_t *pos_s[NS], *bg_s[NB];
	uint8_t core[CORE_LEN];
	uint32_t base[KOF_PLAGUE_MINHASH_K], got[KOF_PLAGUE_MINHASH_K];
	uint32_t nbase, ngot, i, j;
	static const long shifts[][2] = {      /* span = [core_at + a, core_at + CORE_LEN + b] */
		{ -100, 100 }, { -10, 10 }, { -300, 300 }, { -900, 900 },
		{ -1500, 1500 }, { -50, 700 }, { -700, 50 }, { -2000, 2000 },
		{ 0, 0 }, { -1, 1 }
	};
	int same = 0, total = 0;

	fill(core, sizeof core, S_ASCII);
	for (i = 0; i < NS; i++) {
		pos_w[i] = malloc(len);
		fill(pos_w[i], len, S_RANDOM);          /* each sample: its own flanks */
		memcpy(pos_w[i] + core_at, core, CORE_LEN);
		pos_s[i] = pos_w[i];
	}
	for (j = 0; j < NB; j++) {
		bg_w[j] = malloc(len);
		fill(bg_w[j], len, (j & 1) ? S_ASCII : S_RANDOM);
		bg_s[j] = bg_w[j];
	}
	nbase = make_core(pos_s, NS, bg_s, NB, len,
			  core_at - 100, core_at + CORE_LEN + 100, base);
	check(nbase == KOF_PLAGUE_MINHASH_K, "a span holding the data yields a full block");
	for (i = 0; i < sizeof shifts / sizeof shifts[0]; i++) {
		size_t lo = (size_t)((long)core_at + shifts[i][0]);
		size_t hi = (size_t)((long)core_at + CORE_LEN + shifts[i][1]);

		ngot = make_core(pos_s, NS, bg_s, NB,
				 len, lo, hi, got);
		total++;
		if (ngot == nbase && memcmp(base, got, sizeof base) == 0)
			same++;
	}
	check(same == total, "the block is the same 32 hashes for every span that holds "
	      "the data, shifted, grown or shrunk");
	/* A span of the flanks only: nothing every sample holds and no background
	 * holds - "no block", not a block of accidents. */
	ngot = make_core(pos_s, NS, bg_s, NB, len,
			 100, 2000, got);
	check(ngot == 0, "a span without the data yields no block");
	/* One sample: no consensus is possible, the span's own smallest. The
	 * "invariant" is the whole span - a block of this kind is not validated. */
	ngot = make_core(pos_s, 1, bg_s, 0, len,
			 core_at - 100, core_at + CORE_LEN + 100, got);
	check(ngot == KOF_PLAGUE_MINHASH_K, "one sample still yields a block (unvalidated)");
	/* ... and that block changes when the span does: this is what two samples fix. */
	{
		uint32_t g2[KOF_PLAGUE_MINHASH_K], n2;

		n2 = make_core(pos_s, 1, bg_s, 0, len,
			       core_at - 900, core_at + CORE_LEN + 900, g2);
		check(n2 == KOF_PLAGUE_MINHASH_K && memcmp(g2, got, sizeof g2) != 0,
		      "with one sample the block depends on the span - the weakness "
		      "the consensus removes");
	}
	/* A background that holds the core removes it: contrast is what it is for. */
	{
		uint8_t *poisoned_w[NB];
		const uint8_t *poisoned[NB];
		uint32_t g3[KOF_PLAGUE_MINHASH_K], n3;

		for (j = 0; j < NB; j++) {
			poisoned_w[j] = malloc(len);
			memcpy(poisoned_w[j], bg_s[j], len);
			memcpy(poisoned_w[j] + 100, core, CORE_LEN);
			poisoned[j] = poisoned_w[j];
		}
		n3 = make_core(pos_s, NS, poisoned, NB,
			       len, core_at - 100, core_at + CORE_LEN + 100, g3);
		check(n3 == 0, "data the background also holds is not the block's");
		for (j = 0; j < NB; j++)
			free(poisoned_w[j]);
	}
	for (i = 0; i < NS; i++)
		free(pos_w[i]);
	for (j = 0; j < NB; j++)
		free(bg_w[j]);
}

/* ---- the scan counts each hash once per object --------------------------- */

#define RGN 1u

static void scan_cases(void)
{
	enum { NBLK = 3000, NUNIT = 24 };
	static const uint32_t K = 32;
	uint32_t *pool = malloc((size_t)NBLK * K * sizeof *pool);
	struct kof_plague_block *blk = calloc(NBLK, sizeof *blk);
	uint8_t *units[NUNIT];
	size_t ulen[NUNIT];
	struct kof_plague_set *set;
	struct kof_plague_ctx ctx;
	uint32_t b, i, u, np = 0;
	int bad = 0, total_seen = 0;

	/* Units of every size and shape. */
	for (u = 0; u < NUNIT; u++) {
		ulen[u] = (size_t)(24u + rnd() % (u < 4 ? 40u : 30000u));
		units[u] = malloc(ulen[u]);
		fill(units[u], ulen[u], (enum shape)(u % S_COUNT));
	}
	/* Blocks: from the units themselves (the hashes are in the object), from other
	 * random spans (they are not), and from half of each (half are). */
	for (b = 0; b < NBLK; b++) {
		uint8_t *src, *tmp = NULL;
		size_t sl = 24u + rnd() % 3000u;
		uint32_t got;

		if (b % 3 == 0) {
			u = rnd() % NUNIT;
			sl = ulen[u] < sl ? ulen[u] : sl;
			src = units[u] + (ulen[u] > sl ? rnd() % (uint32_t)(ulen[u] - sl) : 0);
		} else {
			tmp = malloc(sl);
			fill(tmp, sl, (enum shape)(rnd() % 3));
			if (b % 3 == 2 && sl >= 64) {
				u = rnd() % NUNIT;
				if (ulen[u] >= 32)
					memcpy(tmp, units[u], 32);
			}
			src = tmp;
		}
		got = kof_plague_minhash(src, sl, KOF_PLAGUE_RAW, pool + np);
		free(tmp);
		if (got < KOF_PLAGUE_MIN_HASH)
			got = 0;
		blk[b].first_hash = np;
		blk[b].n_hash = got ? got : KOF_PLAGUE_MIN_HASH;
		if (!got) {
			/* too thin: a filler block of arbitrary large hashes */
			for (i = 0; i < KOF_PLAGUE_MIN_HASH; i++)
				pool[np + i] = 0x80000000u + rnd() % 0x7fffffffu;
			got = KOF_PLAGUE_MIN_HASH;
		}
		blk[b].scan_mask = RGN;
		blk[b].norm = KOF_PLAGUE_RAW;
		np += got;
	}
	set = kof_plague_build(blk, NBLK, pool, np);
	check(set != NULL, "a set of three thousand blocks builds");
	if (!set || !kof_plague_ctx_init(&ctx, set)) {
		free(pool); free(blk);
		return;
	}
	kof_plague_begin(&ctx);
	for (u = 0; u < NUNIT; u++)
		kof_plague_unit(&ctx, RGN, KOF_PLAGUE_RAW, KOF_PLAGUE_SIDE_USER,
				units[u], ulen[u]);
	/* The reference: every window of every unit, brute force. */
	{
		uint32_t *all = NULL, nall = 0, cap = 0;

		for (u = 0; u < NUNIT; u++) {
			uint32_t n1 = 0, *p1 = ref_pool(units[u], ulen[u], KOF_PLAGUE_RAW, &n1);

			if (!p1)
				continue;
			if (nall + n1 > cap) {
				cap = (nall + n1) * 2;
				all = realloc(all, cap * sizeof *all);
			}
			memcpy(all + nall, p1, n1 * sizeof *all);
			nall += n1;
			free(p1);
		}
		qsort(all, nall, sizeof *all, u32_cmp);
		for (b = 0; b < NBLK; b++) {
			uint32_t want = 0, seen = 0, nh = 0;
			const uint32_t *h = kof_plague_block_hashes(set, b, &nh);

			for (i = 0; i < nh; i++)
				if (has(all, nall, h[i]))
					want++;
			kof_plague_counts(&ctx, b, &seen, &nh);
			if (seen != want)
				bad++;
			total_seen += (int)want;
		}
		free(all);
	}
	check(bad == 0, "every block's count equals a brute-force count of its hashes "
	      "among the windows of all the units (bit table and top reject lose none)");
	check(total_seen > 1000, "and the reference was not trivially empty");
	kof_plague_ctx_done(&ctx);
	kof_plague_set_free(set);
	for (u = 0; u < NUNIT; u++)
		free(units[u]);
	free(pool);
	free(blk);
}

/* ---- size does not matter to the score ----------------------------------- */

static void size_cases(void)
{
	static const size_t blk_sizes[] = { 24, 40, 100, 1000, 65536 };
	static const size_t unit_sizes[] = { 0, 4096, 1u << 20 };
	size_t bi, ui;
	int bad = 0, n = 0;

	for (bi = 0; bi < sizeof blk_sizes / sizeof blk_sizes[0]; bi++)
		for (ui = 0; ui < sizeof unit_sizes / sizeof unit_sizes[0]; ui++) {
			size_t bl = blk_sizes[bi];
			size_t ul = unit_sizes[ui] > bl ? unit_sizes[ui] : bl;
			uint8_t *blkb = malloc(bl), *unit = malloc(ul);
			uint32_t h[KOF_PLAGUE_MINHASH_K], nh;
			struct kof_plague_block pb;
			struct kof_plague_set *set;
			struct kof_plague_ctx ctx;

			fill(blkb, bl, S_RANDOM);
			fill(unit, ul, S_ASCII);
			memcpy(unit + (ul - bl) / 2, blkb, bl);
			nh = kof_plague_minhash(blkb, bl, KOF_PLAGUE_RAW, h);
			memset(&pb, 0, sizeof pb);
			pb.n_hash = nh;
			pb.scan_mask = RGN;
			set = kof_plague_build(&pb, 1, h, nh);
			if (set && kof_plague_ctx_init(&ctx, set)) {
				kof_plague_begin(&ctx);
				kof_plague_unit(&ctx, RGN, KOF_PLAGUE_RAW,
						KOF_PLAGUE_SIDE_USER, unit, ul);
				if (kof_plague_pct(&ctx, 0) != 100)
					bad++;
				n++;
				kof_plague_ctx_done(&ctx);
			}
			kof_plague_set_free(set);
			free(blkb); free(unit);
		}
	check(n == (int)(sizeof blk_sizes / sizeof blk_sizes[0] *
			 sizeof unit_sizes / sizeof unit_sizes[0]),
	      "every size combination ran");
	check(bad == 0, "a block of 24 B to 64 KB reads 100 in a unit of 4 KB to 1 MB "
	      "holding it");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	pool_cases();
	minhash_cases();
	member_cases();
	core_cases();
	invariance_cases();
	scan_cases();
	size_cases();
	if (failures) {
		printf("plague pool: %d check(s) failed\n", failures);
		return 1;
	}
	printf("plague pool: the pool, membership, the core, span invariance, the "
	       "union scan and size independence - ok\n");
	return 0;
}
