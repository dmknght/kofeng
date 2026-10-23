/*
 * uncoat / strfn_defect_work - L11 of the lexer audit: kuncoat_strfn's search loops (replace, split, map: strfn.c). Each position of the subject was compared with
 * the whole of the search text, so a subject of n bytes and a search of m bytes cost n * m comparisons - a text of "a" and a search of "aaa...b" is the worst case,
 * about 6 s a call at 1 MiB. They were not tuned, they were wrong about their bound: the subject is searched once, in time linear in n + m (the two-way search), whatever
 * the two texts are.
 *
 * Asserted by WORK (tests/lib/work_count.h): the comparison loops of strfn.c are counted as basic blocks, and libc's memcmp and memmem, which they call, are wrapped
 * (-Wl,--wrap=memcmp, --wrap=memmem): memcmp counts the bytes it looks at before it finds the first difference, memmem the bytes of the subject it is asked to pass
 * over (up to the occurrence it finds or the end) and of the search text - the cost a linear search has; what glibc does inside is its own and [Unverified] here. The same shape at 4 KiB and at 16 KiB, the search a quarter of the subject:
 * growth at most 6 and at most 400 a byte (the case-folding search and the map are allowed 32 compares a byte and a megabyte, so the bound is a few hundred blocks
 * a byte at these sizes, and what is asserted is that it IS a bound: the old code grew x16 and its answer was the work itself). Then, the search must still be right: a model (the naive search) over every subject and search of a small alphabet agrees
 * with the real one for replace, split and map, with and without case folding.
 *
 * Why the old tests missed it: (b) strfn.c and strfn_lists.c compare against python and perl on subjects of a few bytes (so does the oracle; 60,000 cases) - no search
 * longer than the subject's tenth, no subject longer than a page; and nothing counted work.
 *
 * usage: strfn_defect_work   (built with -fsanitize-coverage=trace-pc, --wrap=memcmp and --wrap=memmem)
 */

#include <decoders/strfn.c>

#include "../work_count.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int __real_memcmp(const void *a, const void *b, size_t n);
int __wrap_memcmp(const void *a, const void *b, size_t n);
int __wrap_memcmp(const void *a, const void *b, size_t n)
{
	if (work_on) {
		const uint8_t *x = a, *y = b;
		size_t k = 0;

		while (k < n && x[k] == y[k])
			k++;
		work_n += k + 1u;
	}
	return __real_memcmp(a, b, n);
}

void *__real_memmem(const void *h, size_t hl, const void *nd, size_t nl);
void *__wrap_memmem(const void *h, size_t hl, const void *nd, size_t nl);
void *__wrap_memmem(const void *h, size_t hl, const void *nd, size_t nl)
{
	void *r = __real_memmem(h, hl, nd, nl);

	if (work_on)
		work_n += (r ? (size_t)((const char *)r - (const char *)h) + nl : hl) + nl;
	return r;
}

static uint64_t run(uint32_t algo, uint32_t flags, uint32_t k32, const uint8_t *key, uint32_t klen, const uint8_t *in, uint32_t n)
{
	struct kuncoat_step s;
	uint8_t *out = malloc((size_t)n * 3u + 64u);
	uint64_t w = 0;

	if (!out)
		abort();
	memset(&s, 0, sizeof s);
	s.algo = algo;
	s.dir = KUNCOAT_DECODE;
	s.flags = flags;
	s.k32 = k32;
	s.key = key;
	s.key_len = klen;
	WORK_BEGIN();
	(void)kuncoat_strfn(&s, in, n, out, (uint64_t)n * 3u + 64u, &w);
	free(out);
	return work_end();
}

/* subject "a" x n, search "a" x (n / 4 - 1) then "b": nothing matches and every position nearly does (a search that keeps case is memmem's and costs n + m;
 * one that folds case or a map reaches its allowance and answers OVER_BUDGET, which is the status asserted below) */
static void shape(const char *name, uint32_t algo, uint32_t flags, int tcl_map)
{
	uint32_t sizes[2] = { 16384u, 65536u }, k;
	uint64_t w[2];

	for (k = 0; k < 2; k++) {
		uint32_t n = sizes[k], m = n / 4u, klen;
		uint8_t *in = malloc(n), *key = malloc(m + 8u);

		if (!in || !key)
			abort();
		memset(in, 'a', n);
		memset(key, 'a', m - 1u);
		key[m - 1u] = 'b';
		if (algo == KUNCOAT_ALGO_REPLACE) {
			key[m] = 'X';                        /* search then replacement */
			klen = m + 1u;
			w[k] = run(algo, flags, m, key, klen, in, n);
		} else if (algo == KUNCOAT_ALGO_SPLIT) {
			w[k] = run(algo, flags, 0, key, m, in, n);
		} else {
			key[m] = ' ';                        /* a tcl list: the search, a blank, the replacement */
			key[m + 1u] = 'X';
			klen = m + 2u;
			(void)tcl_map;
			w[k] = run(algo, flags, 0, key, klen, in, n);
		}
		free(in);
		free(key);
	}
	fails += !work_grows_linearly(name, w[0], sizes[0], w[1], sizes[1], 400);
}

/* a naive search, the model */
static int naive_at(const uint8_t *in, const uint8_t *key, uint32_t klen, int icase)
{
	uint32_t k;

	for (k = 0; k < klen; k++) {
		uint8_t a = in[k], b = key[k];

		if (icase) {
			a = (uint8_t)(a >= 'A' && a <= 'Z' ? a + 32 : a);
			b = (uint8_t)(b >= 'A' && b <= 'Z' ? b + 32 : b);
		}
		if (a != b)
			return 0;
	}
	return 1;
}

/* replace, as php's str_replace of one string reads: every non-overlapping occurrence from the left (the first only with F_FIRST) */
static uint32_t model_replace(const uint8_t *in, uint32_t n, const uint8_t *from, uint32_t fl, const uint8_t *to, uint32_t tl, int icase, int first, uint8_t *out)
{
	uint32_t i = 0, w = 0;
	int done = 0;

	while (i < n) {
		if (!done && n - i >= fl && naive_at(in + i, from, fl, icase)) {
			memcpy(out + w, to, tl);
			w += tl;
			i += fl;
			done = first;
		} else {
			out[w++] = in[i++];
		}
	}
	return w;
}

static void differential(void)
{
	static const char alpha[] = "aAb";
	uint32_t na = (uint32_t)strlen(alpha), ln, lk, k, idx[16];
	uint64_t cases = 0;

	/* every subject of 0..7 bytes against every search of 1..4 bytes over the alphabet, with every flag combination of case and first */
	for (ln = 0; ln <= 7; ln++) {
		for (k = 0; k < ln; k++)
			idx[k] = 0;
		for (;;) {
			uint8_t in[8];

			for (k = 0; k < ln; k++)
				in[k] = (uint8_t)alpha[idx[k]];
			for (lk = 1; lk <= 4; lk++) {
				uint32_t kk, kidx[4], f;

				for (kk = 0; kk < lk; kk++)
					kidx[kk] = 0;
				for (;;) {
					uint8_t key[8], want[64], got[64];
					uint8_t to[2] = { 'X', 'Y' };

					for (kk = 0; kk < lk; kk++)
						key[kk] = (uint8_t)alpha[kidx[kk]];
					key[lk] = 'X';
					key[lk + 1u] = 'Y';
					for (f = 0; f < 4u; f++) {
						struct kuncoat_step s;
						uint64_t w = 0;
						uint32_t wn;
						int icase = (f & 1u) != 0, first = (f & 2u) != 0;

						memset(&s, 0, sizeof s);
						s.algo = KUNCOAT_ALGO_REPLACE;
						s.dir = KUNCOAT_DECODE;
						s.flags = (icase ? KUNCOAT_F_ICASE : 0u) | (first ? KUNCOAT_F_FIRST : 0u);
						s.k32 = lk;
						s.key = key;
						s.key_len = lk + 2u;
						cases++;
						if (kuncoat_strfn(&s, in, ln, got, sizeof got, &w) != KUNCOAT_OK)
							w = 0xffffu;
						wn = model_replace(in, ln, key, lk, to, 2, icase, first, want);
						if (w != wn || memcmp(got, want, wn)) {
							printf("  FAIL replace [%.*s] in [%.*s] flags %u: got %llu bytes, model %u\n", (int)lk, key, (int)ln, in, f, (unsigned long long)w, wn);
							fails++;
							return;
						}
					}
					for (kk = 0; kk < lk && ++kidx[kk] == na; kk++)
						kidx[kk] = 0;
					if (kk == lk)
						break;
				}
			}
			for (k = 0; k < ln && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == ln)
				break;
		}
	}
	printf("  strfn_defect_work: %llu replace cases against the naive search\n", (unsigned long long)cases);
}

/* split, as php's explode reads it: pieces cut at every non-overlapping occurrence from the left; DROPTRAIL takes the empty ones off the END */
static uint32_t model_split(const uint8_t *in, uint32_t n, const uint8_t *key, uint32_t kl, int icase, int drop, uint32_t *po, uint32_t *pl)
{
	uint32_t i = 0, from = 0, np = 0;

	for (;;) {
		uint32_t at = n;
		int hit = 0;

		for (; i + kl <= n; i++)
			if (naive_at(in + i, key, kl, icase)) {
				at = i;
				hit = 1;
				break;
			}
		po[np] = from;
		pl[np++] = at - from;
		if (!hit)
			break;
		i = at + kl;
		from = i;
	}
	while (drop && np && !pl[np - 1u])
		np--;
	return np;
}

static void differential_split(void)
{
	static const char alpha[] = "aAb";
	uint32_t na = (uint32_t)strlen(alpha), ln, lk, k, idx[16];
	uint64_t cases = 0;

	for (ln = 0; ln <= 7; ln++) {
		for (k = 0; k < ln; k++)
			idx[k] = 0;
		for (;;) {
			uint8_t in[8];

			for (k = 0; k < ln; k++)
				in[k] = (uint8_t)alpha[idx[k]];
			for (lk = 1; lk <= 3; lk++) {
				uint32_t kk, kidx[3], f;

				for (kk = 0; kk < lk; kk++)
					kidx[kk] = 0;
				for (;;) {
					uint8_t key[4];

					for (kk = 0; kk < lk; kk++)
						key[kk] = (uint8_t)alpha[kidx[kk]];
					for (f = 0; f < 4u; f++) {
						struct kuncoat_step s;
						uint8_t got[256];
						uint64_t w = 0, at = 0;
						uint32_t po[16], pl[16], np, g = 0;
						const uint8_t *p;
						uint32_t l;
						int icase = (f & 1u) != 0, drop = (f & 2u) != 0, broken = 0, bad = 0;

						memset(&s, 0, sizeof s);
						s.algo = KUNCOAT_ALGO_SPLIT;
						s.dir = KUNCOAT_DECODE;
						s.flags = (icase ? KUNCOAT_F_ICASE : 0u) | (drop ? KUNCOAT_F_DROPTRAIL : 0u);
						s.key = key;
						s.key_len = lk;
						cases++;
						if (kuncoat_strfn(&s, in, ln, got, sizeof got, &w) != KUNCOAT_OK)
							bad = 1;
						np = model_split(in, ln, key, lk, icase, drop, po, pl);
						while (!bad && kof_strlist_next(got, w, &at, &p, &l, &broken) > 0) {
							if (g >= np || l != pl[g] || memcmp(p, in + po[g], l))
								bad = 1;
							g++;
						}
						if (bad || broken || g != np) {
							printf("  FAIL split of [%.*s] by [%.*s] flags %u: %u pieces, model %u\n", (int)ln, in, (int)lk, key, f, g, np);
							fails++;
							return;
						}
					}
					for (kk = 0; kk < lk && ++kidx[kk] == na; kk++)
						kidx[kk] = 0;
					if (kk == lk)
						break;
				}
			}
			for (k = 0; k < ln && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == ln)
				break;
		}
	}
	printf("  strfn_defect_work: %llu split cases against the naive search\n", (unsigned long long)cases);
}

/* tcl's string map: at each position the first key of the list that is there, written as its value; the text after it goes on after the key */
static void differential_map(void)
{
	static const char alpha[] = "ab";
	uint32_t na = (uint32_t)strlen(alpha), ln, k, idx[16];
	uint64_t cases = 0;

	for (ln = 0; ln <= 8; ln++) {
		for (k = 0; k < ln; k++)
			idx[k] = 0;
		for (;;) {
			uint8_t in[10];
			static const char *const maps[] = { "a X", "a X b Y", "ab X a Y", "a X ab Y", "b {} a Z", "aa X a Y ab W", "bb X b Y" };
			uint32_t m;

			for (k = 0; k < ln; k++)
				in[k] = (uint8_t)alpha[idx[k]];
			for (m = 0; m < sizeof maps / sizeof maps[0]; m++) {
				struct kuncoat_step s;
				uint8_t got[256], want[256];
				uint64_t w = 0;
				uint32_t wn = 0, i = 0;
				const char *keys[3], *vals[3];
				uint32_t kl[3], vl[3], nk = 0;
				char copy[64], *tok, *save = NULL;
				int has_empty = 0;

				memset(&s, 0, sizeof s);
				s.algo = KUNCOAT_ALGO_MAP;
				s.dir = KUNCOAT_DECODE;
				s.key = (const uint8_t *)maps[m];
				s.key_len = (uint32_t)strlen(maps[m]);
				cases++;
				{       /* the map's words, written here: key value key value ...; "{}" is the empty value */
					uint32_t t = 0;
					const char *w2[8];

					snprintf(copy, sizeof copy, "%s", maps[m]);
					for (tok = strtok_r(copy, " ", &save); tok && t < 8u; tok = strtok_r(NULL, " ", &save))
						w2[t++] = tok;
					for (k = 0; k + 1u < t && nk < 3u; k += 2u) {
						keys[nk] = w2[k];
						kl[nk] = (uint32_t)strlen(w2[k]);
						has_empty = !strcmp(w2[k + 1u], "{}");
						vals[nk] = has_empty ? "" : w2[k + 1u];
						vl[nk] = (uint32_t)strlen(vals[nk]);
						nk++;
					}
				}
				while (i < ln) {
					uint32_t q, hit = 0;

					for (q = 0; q < nk && !hit; q++)
						if (ln - i >= kl[q] && !memcmp(in + i, keys[q], kl[q])) {
							memcpy(want + wn, vals[q], vl[q]);
							wn += vl[q];
							i += kl[q];
							hit = 1;
						}
					if (!hit)
						want[wn++] = in[i++];
				}
				if (kuncoat_strfn(&s, in, ln, got, sizeof got, &w) != KUNCOAT_OK || w != wn || memcmp(got, want, wn)) {
					printf("  FAIL map {%s} of [%.*s]: %llu bytes, model %u\n", maps[m], (int)ln, in, (unsigned long long)w, wn);
					fails++;
					return;
				}
			}
			for (k = 0; k < ln && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == ln)
				break;
		}
	}
	printf("  strfn_defect_work: %llu map cases against the naive search\n", (unsigned long long)cases);
}

/* a search the allowance cannot pay for is a STATUS, never a wrong answer: case-folded search of a quarter of the subject, near misses everywhere */
static void over_budget(void)
{
	uint32_t n = 1u << 17, m = n / 4u;
	uint8_t *in = malloc(n), *key = malloc(m + 1u), *out = malloc((size_t)n * 2u);
	struct kuncoat_step s;
	uint64_t w = 0;

	if (!in || !key || !out)
		abort();
	memset(in, 'a', n);
	memset(key, 'a', m - 1u);
	key[m - 1u] = 'b';
	key[m] = 'X';
	memset(&s, 0, sizeof s);
	s.algo = KUNCOAT_ALGO_REPLACE;
	s.dir = KUNCOAT_DECODE;
	s.flags = KUNCOAT_F_ICASE;
	s.k32 = m;
	s.key = key;
	s.key_len = m + 1u;
	CK(kuncoat_strfn(&s, in, n, out, (uint64_t)n * 2u, &w) == KUNCOAT_OVER_BUDGET);
	s.flags = 0;                    /* and the same search that keeps case is answered, in full: nothing matches, the subject comes back */
	w = 0;
	CK(kuncoat_strfn(&s, in, n, out, (uint64_t)n * 2u, &w) == KUNCOAT_OK && w == n && !memcmp(out, in, n));
	free(in);
	free(key);
	free(out);
}

int main(void)
{
	if (!work_selfcheck())
		return 1;
	shape("strfn replace of `a` x n/4-1 + b in `a` x n", KUNCOAT_ALGO_REPLACE, 0, 0);
	shape("strfn replace icase", KUNCOAT_ALGO_REPLACE, KUNCOAT_F_ICASE, 0);
	shape("strfn split by `a` x n/4-1 + b", KUNCOAT_ALGO_SPLIT, 0, 0);
	shape("strfn split icase", KUNCOAT_ALGO_SPLIT, KUNCOAT_F_ICASE, 0);
	shape("strfn map {a..ab X}", KUNCOAT_ALGO_MAP, 0, 1);
	differential();
	differential_split();
	differential_map();
	over_budget();
	printf(fails ? "strfn_defect_work: %d FAILED\n" : "strfn_defect_work: ok\n", fails);
	return fails != 0;
}
