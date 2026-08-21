/*
 * find_lit_diff - differential test for find_lit, both cases.
 *
 * The nocase=1 half exists because kof_match_find_set's folded path was rewritten
 * to keep its skip inside memchr, and that rewrite is index arithmetic in the hot
 * path: an anchor offset subtracted from a match position, two overlapping memchr
 * spans, and bounds that must not underflow when the needle is as long as the
 * haystack. The kind of code that passes a corpus run while being wrong on a case
 * the corpus happens not to contain.
 *
 * The nocase=0 half exists for the same reason, over kof_memmem: the POSIX side
 * delegates to the platform's memmem, trusted as-is, but the Windows side
 * (kofplatform.h, exercised whenever this test itself is built on that target) is
 * a hand written Knuth-Morris-Pratt search, and a failure-function loop is exactly
 * the kind of index arithmetic this file's whole approach exists to catch.
 *
 * So both are checked against the obvious implementation exhaustively rather than
 * by example. The alphabet is tiny and mixed case on purpose - "aAbB:" makes
 * near-misses and fold collisions dense, which is where this class of bug lives -
 * and the colon means patterns both with and without a case-invariant byte are
 * generated, so both branches are covered.
 *
 * The optimised routine is included from the matcher rather than copied, so this
 * cannot silently drift from what actually runs.
 */

/* Before any include, not after: this file includes kofmatch.c below, which
 * includes kofplatform.h, whose POSIX branch needs the real memmem declared
 * (a GNU/BSD extension) to compile kof_memmem's body - but by the time that
 * nested #define _GNU_SOURCE in kofmatch.c itself would run, this file's own
 * <string.h> a few lines down has already been processed and its include
 * guard blocks memmem's declaration from ever appearing. Defined here, first,
 * so it's in effect before <string.h> is seen at all, from either copy. */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* The .c, not the header: find_lit is static, and a copy here could drift from
 * the one that runs. */
#include "../../libkofeng/kofmatchers/kofmatch.c"

/* Same shape, no folding - what nocase=0 has to agree with. */
static int ref_find_exact(const uint8_t *h, uint64_t hl, const uint8_t *n,
			  uint64_t nl, uint64_t *f)
{
	uint64_t i, j;

	if (nl == 0 || nl > hl)
		return 0;
	for (i = 0; i + nl <= hl; i++) {
		for (j = 0; j < nl; j++)
			if (h[i + j] != n[j])
				break;
		if (j == nl) {
			*f = i;
			return 1;
		}
	}
	return 0;
}

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
					if (r1 == r2 && (!r1 || f1 == f2)) {
						/* fall through to the nocase=0 check below */
					} else {
						if (mism < 5) {
							int z;
							printf("MISMATCH(nocase) hay=\"");
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

					/* Same hay/needle, exact match this time - what
					 * kof_memmem (POSIX: the real memmem; Windows:
					 * the hand written KMP in kofplatform.h) has to
					 * agree with. */
					r1 = ref_find_exact(hay, (uint64_t)hl, nee,
							     (uint64_t)nl, &f1);
					r2 = find_lit(hay, (uint64_t)hl, nee,
						      (uint64_t)nl, 0, &f2);
					cases++;
					if (r1 == r2 && (!r1 || f1 == f2))
						continue;
					if (mism < 10) {
						int z;
						printf("MISMATCH(exact) hay=\"");
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

	printf("find_lit: %ld cases, %ld mismatches\n", cases, mism);
	return mism != 0;
}
