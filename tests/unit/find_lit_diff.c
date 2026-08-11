/*
 * find_lit_diff - differential test for the case-insensitive literal search.
 *
 * Exists because kof_match_find_set's folded path was rewritten to keep its skip
 * inside memchr, and that rewrite is index arithmetic in the hot path: an anchor
 * offset subtracted from a match position, two overlapping memchr spans, and
 * bounds that must not underflow when the needle is as long as the haystack. The
 * kind of code that passes a corpus run while being wrong on a case the corpus
 * happens not to contain.
 *
 * So it is checked against the obvious implementation exhaustively rather than by
 * example. The alphabet is tiny and mixed case on purpose - "aAbB:" makes
 * near-misses and fold collisions dense, which is where this class of bug lives -
 * and the colon means patterns both with and without a case-invariant byte are
 * generated, so both branches are covered.
 *
 * The optimised routine is included from the matcher rather than copied, so this
 * cannot silently drift from what actually runs.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* The .c, not the header: find_lit is static, and a copy here could drift from
 * the one that runs. */
#include "../../libkofeng/kofmatchers/kofmatch.c"

/* The definition the optimised one has to agree with: fold both sides, compare at
 * every position, leftmost wins. */
static int ref_find(const uint8_t *h, uint64_t hl, const uint8_t *n, uint64_t nl,
		    uint64_t *f)
{
	uint64_t i, j;

	if (nl == 0 || nl > hl)
		return 0;
	for (i = 0; i + nl <= hl; i++) {
		for (j = 0; j < nl; j++)
			if (fold(h[i + j]) != fold(n[j]))
				break;
		if (j == nl) {
			*f = i;
			return 1;
		}
	}
	return 0;
}

int main(void)
{
	static const char AB[] = "aAbB:";
	const int K = (int)sizeof AB - 1;
	uint8_t hay[8], nee[4];
	long cases = 0, mism = 0;
	int hl, nl;

	for (hl = 1; hl <= 6; hl++)
		for (nl = 1; nl <= 3; nl++) {
			long H = 1, N = 1, ih, in;
			int t;

			for (t = 0; t < hl; t++) H *= K;
			for (t = 0; t < nl; t++) N *= K;

			for (ih = 0; ih < H; ih++) {
				long v = ih;
				for (t = 0; t < hl; t++) {
					hay[t] = (uint8_t)AB[v % K];
					v /= K;
				}
				for (in = 0; in < N; in++) {
					long w = in;
					uint64_t f1 = ~0ull, f2 = ~0ull;
					int r1, r2;

					for (t = 0; t < nl; t++) {
						nee[t] = (uint8_t)AB[w % K];
						w /= K;
					}
					r1 = ref_find(hay, (uint64_t)hl, nee,
						      (uint64_t)nl, &f1);
					r2 = find_lit(hay, (uint64_t)hl, nee,
						      (uint64_t)nl, 1, &f2);
					cases++;
					if (r1 == r2 && (!r1 || f1 == f2))
						continue;
					if (mism < 5) {
						int z;
						printf("MISMATCH hay=\"");
						for (z = 0; z < hl; z++)
							putchar(hay[z]);
						printf("\" needle=\"");
						for (z = 0; z < nl; z++)
							putchar(nee[z]);
						printf("\" ref=%d@%llu opt=%d@%llu\n",
						       r1, (unsigned long long)f1,
						       r2, (unsigned long long)f2);
					}
					mism++;
				}
			}
		}

	printf("find_lit nocase: %ld cases, %ld mismatches\n", cases, mism);
	return mism != 0;
}
