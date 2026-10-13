/*
 * kofmatch_lit.h - the literal search of kofmatch.c: fold and find_lit.
 *
 * Here and not in kofmatch.c so that the differential test (tests/unit/
 * find_lit_diff.c) runs the routine that runs in the scan, not a copy of it and
 * not a .c file included whole. Both functions are plain `static`, as they were
 * in kofmatch.c: the matcher's own translation unit is the only one that scans
 * with them, and a header of `static inline` would hand the compiler a hint the
 * original did not give.
 *
 * Needs _GNU_SOURCE before any include (memmem - see kof_memmem in kofplatform.h).
 */
#ifndef KOFENG_DETECTORS_PATTERN_KOFMATCH_LIT_H
#define KOFENG_DETECTORS_PATTERN_KOFMATCH_LIT_H

#include <stdint.h>
#include <string.h>

#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofplatform.h"

/* One byte of what swar_lower does to four - see kof_lower_byte. */
static uint8_t fold(uint8_t c)
{
	return kof_lower_byte(c);
}

/*
 * Literal search over [hay, hay+hlen) for needle.
 *
 * The case sensitive path is kof_memmem: on POSIX the real memmem, vectorised in
 * any real libc and Two-Way internally on glibc, so it is both fast in the
 * ordinary case and immune to the failure mode a memchr-anchored scan has on a
 * haystack that repeats the needle's first byte - a run of one byte value turns
 * every position into a candidate, and a naive verify-per-candidate loop pays
 * O(hlen*nlen) for it. That case is not hypothetical for this engine: object
 * padding, zero-filled sections and repeated bytes in packed data are ordinary,
 * not adversarial, inputs. See kof_memmem in kofplatform.h for the Windows side,
 * which does not have memmem and gets the same worst-case bound from
 * Knuth-Morris-Pratt instead.
 */
static int find_lit(const uint8_t *hay, uint64_t hlen,
		    const uint8_t *needle, uint64_t nlen,
		    int nocase, uint64_t *found)
{
	if (nlen == 0 || nlen > hlen)
		return 0;

	if (!nocase) {
		const void *q = kof_memmem(hay, (size_t)hlen, needle, (size_t)nlen);
		if (!q)
			return 0;
		*found = (uint64_t)((const uint8_t *)q - hay);
		return 1;
	}

	/*
	 * Folded search, keeping the skip inside memchr too - folding every byte in
	 * scalar code measured 1.55 GB/s against 12.5 GB/s for this.
	 *
	 * Two ways to vectorise it, in order of preference: anchor on a byte that has
	 * no case, since a non-letter matches only itself and one memchr finds every
	 * candidate; otherwise memchr for both cases of the first byte and take
	 * whichever comes first.
	 *
	 * The inner compare folds on the fly. It only runs at candidate positions, so
	 * it is not where the time goes.
	 */
	{
		uint64_t last = hlen - nlen;   /* last possible start; nlen <= hlen */
		uint64_t anchor = 0, i, j;
		int has_anchor = 0;

		for (i = 0; i < nlen; i++) {
			uint8_t c = needle[i];
			if (!kof_is_alpha(c)) {
				anchor = i;
				has_anchor = 1;
				break;
			}
		}

		if (has_anchor) {
			uint64_t at = anchor;      /* scanning anchor positions */
			uint64_t end = last + anchor;

			while (at <= end) {
				const uint8_t *q = memchr(hay + at, needle[anchor],
							  (size_t)(end - at + 1));
				uint64_t s;
				if (!q)
					return 0;
				s = (uint64_t)(q - hay) - anchor;
				for (j = 0; j < nlen; j++)
					if (fold(hay[s + j]) != fold(needle[j]))
						break;
				if (j == nlen) {
					*found = s;
					return 1;
				}
				at = (uint64_t)(q - hay) + 1;
			}
			return 0;
		}

		{
			uint8_t lo = fold(needle[0]);
			uint8_t up = (uint8_t)(lo - 32);   /* lo is a letter here */
			uint64_t s = 0;
			/*
			 * ONCE A CASE IS ABSENT FROM THE TAIL IT STAYS ABSENT.
			 *
			 * memchr returning NULL over [s, last] says the byte is
			 * in none of it, and `s` only ever grows - so every
			 * later call for that case would scan the same bytes to
			 * reach the same NULL. Without this the loop kept
			 * issuing it: with one case missing and the other
			 * frequent, the absent one rescanned the whole
			 * remaining span at every one of the ~n candidates, and
			 * the search went quadratic. Measured on a haystack of
			 * 0x41 with the needle "abc": 64 KB 0.014 s, 256 KB
			 * 0.251 s, 1 MB 5.9 s - an all-letter case-insensitive
			 * pattern over a few megabytes was minutes of one
			 * scan, reachable from the viewer's find box and from
			 * any object too large for the presence table.
			 */
			int lo_gone = 0, up_gone = 0;

			while (s <= last) {
				size_t span = (size_t)(last - s + 1);
				const uint8_t *q = NULL, *q2 = NULL;

				if (!lo_gone) {
					q = memchr(hay + s, lo, span);
					if (!q)
						lo_gone = 1;
				}
				if (!up_gone) {
					q2 = memchr(hay + s, up, span);
					if (!q2)
						up_gone = 1;
				}
				if (q2 && (!q || q2 < q))
					q = q2;
				if (!q)
					return 0;
				s = (uint64_t)(q - hay);
				for (j = 1; j < nlen; j++)
					if (fold(hay[s + j]) != fold(needle[j]))
						break;
				if (j == nlen) {
					*found = s;
					return 1;
				}
				s++;
			}
			return 0;
		}
	}
}

#endif /* KOFENG_DETECTORS_PATTERN_KOFMATCH_LIT_H */
