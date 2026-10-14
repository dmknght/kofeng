/*
 * norm_bounds_cache - kof_exe_norm_masked holds the next kept byte and the next dropped byte
 * for as long as each is still the answer instead of walking the map to it again.
 *
 * THE DEFECT. `lim`, the end of the stretch a rule may rewrite, is the nearer of the next kept
 * byte and the next dropped byte, and was found again from the current offset every time the
 * last answer had been used up. A map does not change while the walk runs, so the walk to the
 * far one was made again for every run in between: MEASURED (callgrind, 234 dynamic ELF with
 * their views) 40 811 calls of keep_bound at 294 000 instructions each, 19 % of the scan.
 *
 * WHAT THIS HOLDS IT TO. The answer must not move. Every case builds an object, a keep map, a
 * drop map and a boundary list, runs the walk and folds the return value, the output bytes, the
 * moved boundaries and the `fired` mask into one hash. The families are the ones the cache
 * can get wrong: a drop map with a single far bit and a keep map of many short runs (the
 * quadratic case), both maps with bits at every distance, a bit exactly at the offset the walk
 * has reached, a run that ends where the map does, maps that are absent, and plain random
 * ones. EXPECT is the hash the walk gave BEFORE the change (the unchanged function, run
 * over the same cases); a different value is a different view.
 *
 * It also checks what a hash cannot say about itself: the output is never longer than the input,
 * the boundaries come back ascending, and the same case run twice gives the same answer.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../libkofeng/analyzers/normalize/executables.h"

#define EXPECT 0x683d1fcc78d840efull

static unsigned s = 0x2468ace1u;
static unsigned rnd(void) { s = s * 1103515245u + 12345u; return s >> 8; }
static uint64_t fold(uint64_t h, uint64_t v) { return (h ^ v) * 1099511628211ull; }
static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void setbit(uint8_t *m, uint64_t i) { m[i >> 3] |= (uint8_t)(1u << (i & 7u)); }

static uint64_t one(uint64_t n, unsigned family, uint64_t h)
{
	uint8_t *in = malloc(n), *out = malloc(n), *keep = calloc((n + 7) / 8 + 8, 1), *drop = calloc((n + 7) / 8 + 8, 1);
	uint64_t mark[16], mark_out[16], i, r, r2;
	uint8_t *out2 = malloc(n);
	struct kof_exe_norm_req rq;
	struct kof_exe_norm_res res;
	uint32_t k, nm = 0;

	for (i = 0; i < n; i++) {
		unsigned m = rnd() % 8u;
		in[i] = m < 3 ? 0 : m < 5 ? (uint8_t)('A' + rnd() % 26u) : (uint8_t)rnd();
		if (rnd() % 16u == 0)
			in[i + 1 < n ? i + 1 : i] = 0;
	}
	switch (family) {
	case 0:         /* one far dropped bit, many short kept runs */
		setbit(drop, n - 1u - rnd() % (n / 8u + 1u));
		for (i = 0; i + 40u < n; i += 40u + rnd() % 40u)
			for (k = 0; k < 8u; k++)
				setbit(keep, i + k);
		break;
	case 1:         /* a kept byte far away, drop runs near */
		setbit(keep, n - 1u - rnd() % (n / 8u + 1u));
		for (i = 0; i + 40u < n; i += 40u + rnd() % 40u)
			setbit(drop, i + rnd() % 8u);
		break;
	case 2:         /* both, bits at every distance */
		for (k = 0; k < 40u; k++) {
			setbit(keep, rnd() % n);
			setbit(drop, rnd() % n);
		}
		break;
	case 3:         /* bits exactly where the walk will be: byte after each zero run */
		for (i = 1; i < n; i++)
			if (in[i - 1] == 0 && in[i] != 0 && rnd() % 5u == 0)
				setbit(rnd() % 2u ? keep : drop, i);
		break;
	case 4:         /* nothing kept or dropped */
		break;
	case 5:         /* dropped and kept runs whole words long, ends at the end of the map */
		for (i = 0; i < n; i++) {
			if ((i / 61u) % 7u == 3u)
				setbit(drop, i);
			if ((i / 97u) % 5u == 1u)
				setbit(keep, i);
		}
		break;
	default:
		for (i = 0; i < n; i++) {
			if (rnd() % 97u == 0) setbit(keep, i);
			if (rnd() % 211u == 0) setbit(drop, i);
		}
	}
	for (k = 0; k < 16u; k++)
		mark[k] = rnd() % (n + 1u);
	for (k = 1; k < 16u; k++)
		if (mark[k] < mark[k - 1])
			mark[k] = mark[k - 1];
	nm = 16u;
	for (k = 0; k < 4u; k++) {      /* with and without each map, and with and without boundaries */
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n = n;
		rq.keep = (k & 1u) ? keep : NULL;
		rq.drop = (k & 2u) ? drop : NULL;
		rq.ops = KOF_EXE_NORM_UNWIDE | KOF_EXE_NORM_NULLRUN;
		rq.mark = mark; rq.n_mark = nm;
		memset(out, 0xa5, n); memset(mark_out, 0, sizeof mark_out);
		res.out = out; res.cap = n; res.mark_out = mark_out; res.fired = 0;
		r = kof_exe_norm_masked(&rq, &res);
		CK(r <= n);
		for (i = 1; i < nm; i++)
			CK(mark_out[i] >= mark_out[i - 1]);
		memset(out2, 0x5a, n);
		res.out = out2; memset(mark_out, 0, sizeof mark_out);
		r2 = kof_exe_norm_masked(&rq, &res);
		CK(r2 == r && memcmp(out, out2, (size_t)r) == 0);
		h = fold(h, r); h = fold(h, res.fired);
		for (i = 0; i < r; i++)
			h = fold(h, out[i]);
		for (i = 0; i < nm; i++)
			h = fold(h, mark_out[i]);
	}
	free(in); free(out); free(out2); free(keep); free(drop);
	return h;
}

int main(void)
{
	uint64_t h = 1469598103934665603ull;
	unsigned it;

	for (it = 0; it < 700u; it++) {
		uint64_t n = it % 11u == 0 ? 8u + rnd() % 64u : 256u + rnd() % 60000u;
		h = one(n, it % 7u, h);
	}
	printf("norm_bounds_cache hash %016llx\n", (unsigned long long)h);
	if (EXPECT)
		CK(h == EXPECT);
	printf("norm_bounds_cache: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
