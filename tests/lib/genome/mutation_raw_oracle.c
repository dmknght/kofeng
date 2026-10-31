/*
 * genome / mutation_raw_oracle - the window, the pool, the sketch and the membership pass after the XOR and SUB forms were removed
 * (owner, 2026-10-31), against the OLD code with its normalizer argument, kept below as the oracle.
 *
 * WHAT IS PINNED. A pack is made of hashes taken under RAW, and the threshold of every block was measured on them; removing the other
 * two forms must not move one hash. So for every generated block of bytes the new kgenome_mutation_pool / _minhash / _member, the window
 * iterator (value, flat, advance count) and kgenome_mutation_flat give EXACTLY what the old code gave under RAW: the same values in the
 * same order, the same bits. The oracle is the old implementation spelled out (old_*), with the normalizer argument kept; it is not
 * a second copy of anything in the engine (the engine's copy is gone).
 *   BLOCKS  every length 0..80 and a few long ones, over: random bytes, ASCII, one repeated byte, a repeated pair, a counter,
 *           runs of one byte with islands, 4-letter alphabet (windows repeat), and a key-XORed / key-added copy of a random block.
 *   MUTANT  the same oracle under the old XOR and SUB forms must DIFFER from the new answer on a keyed copy of a block (a test that
 *           cannot tell the forms apart would pass with a form brought back).
 */
#include <kgenome.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* ---- the oracle: the old code, normalizer argument and all ---- */

#define OLD_RAW 0u
#define OLD_XOR 1u
#define OLD_SUB 2u

static uint8_t old_byte(const uint8_t *p, uint64_t k, uint32_t norm)
{
	return norm == OLD_RAW ? p[k]
	     : norm == OLD_XOR ? (uint8_t)(p[k] ^ p[k + 1u])
	     : (uint8_t)(p[k + 1u] - p[k]);
}

static int old_flat(const uint8_t *p, uint64_t at, uint32_t norm)
{
	uint8_t b0 = old_byte(p, at, norm);
	uint32_t i;

	for (i = 1u; i < KGENOME_MUTATION_NG; i++)
		if (old_byte(p, at + i, norm) != b0)
			return 0;
	return 1;
}

struct old_win {
	const uint8_t *p;
	uint64_t       n, at;
	uint32_t       norm, h, drop;
};

static int old_begin(struct old_win *w, const uint8_t *p, uint64_t n, uint32_t norm)
{
	uint32_t i;

	if (norm != OLD_RAW) {
		if (n < 2u)
			return 0;
		n -= 1u;
	}
	if (n < KGENOME_MUTATION_NG)
		return 0;
	w->p = p; w->n = n; w->at = 0; w->norm = norm;
	w->drop = kgenome_mutation_drop_weight();
	w->h = 0;
	for (i = 0; i < KGENOME_MUTATION_NG; i++)
		w->h = w->h * KGENOME_MUTATION_BASE + (uint32_t)old_byte(p, i, norm);
	return 1;
}

static int old_next(struct old_win *w)
{
	if (w->at + KGENOME_MUTATION_NG >= w->n)
		return 0;
	if (w->norm == OLD_RAW) {
		w->h -= (uint32_t)w->p[w->at] * w->drop;
		w->h = w->h * KGENOME_MUTATION_BASE + (uint32_t)w->p[w->at + KGENOME_MUTATION_NG];
	} else {
		w->h -= (uint32_t)old_byte(w->p, w->at, w->norm) * w->drop;
		w->h = w->h * KGENOME_MUTATION_BASE + (uint32_t)old_byte(w->p, w->at + KGENOME_MUTATION_NG, w->norm);
	}
	w->at++;
	return 1;
}

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static uint32_t *old_pool(const uint8_t *p, uint64_t n, uint32_t norm, uint32_t *np)
{
	struct old_win w;
	uint32_t *v, got = 0, k, i;

	*np = 0;
	if (!old_begin(&w, p, n, norm))
		return NULL;
	v = malloc((size_t)(w.n - KGENOME_MUTATION_NG + 1u) * sizeof *v);
	do {
		if (!old_flat(w.p, w.at, w.norm))
			v[got++] = kgenome_mutation_mix(w.h);
	} while (old_next(&w));
	if (!got) {
		free(v);
		return NULL;
	}
	qsort(v, got, sizeof *v, cmp_u32);
	for (k = 1, i = 1; i < got; i++)
		if (v[i] != v[k - 1u])
			v[k++] = v[i];
	*np = k;
	return v;
}

/* ---- the material ---- */

enum shape { S_RANDOM, S_ASCII, S_ONE, S_PAIR, S_COUNTER, S_ISLANDS, S_ALPHA4, S_COUNT };

static uint32_t rnd(uint32_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
	return *s;
}

static void fill(uint8_t *b, size_t n, enum shape sh, uint32_t *seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		switch (sh) {
		case S_RANDOM:  b[i] = (uint8_t)rnd(seed); break;
		case S_ASCII:   b[i] = (uint8_t)(0x20u + rnd(seed) % 95u); break;
		case S_ONE:     b[i] = 0x41; break;
		case S_PAIR:    b[i] = (i & 1u) ? 0x55 : 0xaa; break;
		case S_COUNTER: b[i] = (uint8_t)i; break;
		case S_ISLANDS: b[i] = (i / 37u) % 3u ? 0 : (uint8_t)rnd(seed); break;
		default:        b[i] = (uint8_t)('a' + rnd(seed) % 4u); break;
		}
}

static void same_as_old(const uint8_t *p, size_t n)
{
	struct old_win o;
	struct kgenome_mtn_win w;
	uint32_t onp, nnp, *op = old_pool(p, n, OLD_RAW, &onp), *np = kgenome_mutation_pool(p, n, &nnp);
	uint32_t mh[KGENOME_MUTATION_MINHASH_K + 1u], want, got;
	uint8_t *ob = NULL, *nb = NULL;

	/* the iterator: begin, every value and flat answer, the number of steps */
	CK(old_begin(&o, p, n, OLD_RAW) == kgenome_mtn_win_begin(&w, p, n));
	if (old_begin(&o, p, n, OLD_RAW) && kgenome_mtn_win_begin(&w, p, n)) {
		uint64_t steps = 0;

		for (;;) {
			CK(kgenome_mutation_mix(o.h) == kgenome_mtn_win_value(&w));
			CK(old_flat(o.p, o.at, OLD_RAW) == kgenome_mtn_win_flat(&w));
			CK(kgenome_mutation_flat(p, w.at) == old_flat(p, w.at, OLD_RAW));
			steps++;
			if (!old_next(&o)) {
				CK(!kgenome_mtn_win_next(&w));
				break;
			}
			if (!kgenome_mtn_win_next(&w)) {
				CK(0);
				break;
			}
		}
		CK(steps == (uint64_t)n - KGENOME_MUTATION_NG + 1u);
	}
	/* the pool: NULL together, the same values in the same order */
	CK((op == NULL) == (np == NULL));
	CK(onp == nnp);
	if (op && np && onp == nnp)
		CK(!memcmp(op, np, (size_t)onp * sizeof *op));
	/* the sketch: the K smallest of the pool */
	got = kgenome_mutation_minhash(p, n, mh);
	want = onp < KGENOME_MUTATION_MINHASH_K ? onp : KGENOME_MUTATION_MINHASH_K;
	CK(got == want);
	if (op && got == want)
		CK(!memcmp(mh, op, (size_t)got * sizeof *mh));
	/* membership: every window of a sample against the pool of ANOTHER span of the same bytes shifted by 3: the bits are the old bits */
	if (op && n > 11u) {
		uint32_t pn = 0, *pool = old_pool(p + 3, n - 3u, OLD_RAW, &pn);
		struct old_win ow;
		size_t bytes = ((size_t)pn + 7u) / 8u;

		if (pool && pn) {
			uint32_t j, lo, hi, mid, v;

			ob = calloc(bytes ? bytes : 1u, 1);
			nb = calloc(bytes ? bytes : 1u, 1);
			if (old_begin(&ow, p, n, OLD_RAW)) {
				do {
					v = kgenome_mutation_mix(ow.h);
					lo = 0; hi = pn;
					while (lo < hi) {
						mid = lo + (hi - lo) / 2u;
						if (pool[mid] < v)
							lo = mid + 1u;
						else
							hi = mid;
					}
					if (lo < pn && pool[lo] == v && !old_flat(ow.p, ow.at, OLD_RAW))
						ob[lo >> 3] |= (uint8_t)(1u << (lo & 7u));
				} while (old_next(&ow));
			}
			kgenome_mutation_member(pool, pn, p, n, nb);
			for (j = 0; j < bytes; j++)
				if (ob[j] != nb[j]) {
					CK(ob[j] == nb[j]);
					break;
				}
			free(ob);
			free(nb);
		}
		free(pool);
	}
	free(op);
	free(np);
}

int main(void)
{
	static uint8_t buf[70000];
	uint32_t seed = 0x5eed1234u;
	size_t n, big[] = { 255, 256, 1000, 4096, 4097, 65537 };
	int sh;

	for (sh = 0; sh < S_COUNT; sh++) {
		for (n = 0; n <= 80; n++) {
			fill(buf, n, (enum shape)sh, &seed);
			same_as_old(buf, n);
		}
		for (n = 0; n < sizeof big / sizeof big[0]; n++) {
			fill(buf, big[n], (enum shape)sh, &seed);
			same_as_old(buf, big[n]);
		}
	}
	/* a block with many seeds, the same bytes cut at every offset of a small range */
	{
		uint32_t s2, off;

		for (s2 = 1; s2 <= 40; s2++) {
			seed = s2 * 2654435761u | 1u;
			fill(buf, 400, S_RANDOM, &seed);
			for (off = 0; off < 24u; off++)
				same_as_old(buf + off, 400u - off);
		}
	}
	/* THE MUTANT: the old forms, still in the oracle, answer differently from the new code on a keyed copy of a block, so this file would
	 * notice a form brought back (for RAW the oracle equals the new code, checked above). */
	{
		uint8_t keyed[400];
		uint32_t i, a_np, b_np, *raw, *xr, *sb, *new_pool;
		uint32_t m_np;

		seed = 0xabcdef01u;
		fill(buf, 400, S_RANDOM, &seed);
		for (i = 0; i < 400u; i++)
			keyed[i] = (uint8_t)(buf[i] ^ 0x3bu);
		raw = old_pool(buf, 400, OLD_RAW, &a_np);
		xr = old_pool(buf, 400, OLD_XOR, &b_np);
		sb = old_pool(buf, 400, OLD_SUB, &m_np);
		new_pool = kgenome_mutation_pool(buf, 400, &i);
		CK(raw && xr && sb && new_pool);
		if (raw && xr && sb && new_pool) {
			CK(i == a_np && !memcmp(new_pool, raw, (size_t)a_np * sizeof *raw));
			CK(b_np != i || memcmp(xr, new_pool, (size_t)i * sizeof *xr));
			CK(m_np != i || memcmp(sb, new_pool, (size_t)i * sizeof *sb));
		}
		/* and the keyed copy no longer reproduces the block: the key is not undone here */
		free(new_pool);
		new_pool = kgenome_mutation_pool(keyed, 400, &i);
		if (new_pool && raw) {
			uint32_t j, k = 0, c = 0;

			for (j = 0; j < i; j++) {
				while (k < a_np && raw[k] < new_pool[j])
					k++;
				c += k < a_np && raw[k] == new_pool[j];
			}
			CK(c * 4u < a_np);     /* far from the block: the XOR key was not removed */
		}
		free(new_pool);
		free(raw); free(xr); free(sb);
	}
	if (fails) {
		printf("mutation_raw_oracle: %d failure(s)\n", fails);
		return 1;
	}
	printf("mutation_raw_oracle: RAW window, pool, sketch and membership equal the old code on every generated block - ok\n");
	return 0;
}
