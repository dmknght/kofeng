/*
 * hunt_cand_at - the candidate search of the diagnose sweep is linear in the object.
 *
 * FOUND BY timing hostile-shaped objects at 32 KB, 128 KB and 512 KB and looking at
 * the ratio: an ELF whose code is `0f 0b` repeated cost 0.035 s, 0.67 s and 3.2 s at
 * 128 KB, 512 KB and 1 MB (16 s at 2 MB). kgenome_diag_cand_at ran two memchr over the
 * whole rest of the object per false lead, and when one lead byte (0xcd) does not occur
 * the search ran to the end every time. The same for all `0f 05` (every position a real
 * hit) and all `cd 80`.
 *
 * Two things are checked: the position returned is the one a byte-at-a-time search
 * returns (random buffers over a small alphabet, so every kind of near miss occurs, from
 * every offset), and 4 MB of each hostile shape is answered in well under what the
 * quadratic search needed for 1 MB (a bound of seconds with a margin of two orders:
 * the fixed code needs milliseconds).
 */

#include "caps_fix.h"
#include "../../libgenome/phenotype/diag_scan_private.h"

#include <time.h>

static uint64_t ref_cand(const uint8_t *p, uint64_t from, uint64_t n)
{
	uint64_t i;

	for (i = from; i + 1u < n; i++)
		if ((p[i] == 0x0f && (p[i + 1u] == 0x05 || p[i + 1u] == 0x34)) ||
		    (p[i] == 0xcd && p[i + 1u] == 0x80))
			return i;
	return n;
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* Every candidate of the object, the way the sweep asks for them. */
static uint64_t walk_all(const uint8_t *p, uint64_t n)
{
	uint64_t c, k = 0;

	for (c = kgenome_diag_cand_at(p, 0, n); c < n; c = kgenome_diag_cand_at(p, c + 1u, n))
		k++;
	return k;
}

int main(void)
{
	static const uint8_t alpha[] = { 0x0f, 0xcd, 0x05, 0x34, 0x80, 0x0b, 0x90 };
	static uint8_t buf[600];
	uint64_t seed = 12345, n, from, i, k;
	size_t big = 4u << 20;
	uint8_t *b = malloc(big);

	for (k = 0; k < 4000; k++) {
		n = k % 600u;
		for (i = 0; i < n; i++) {
			seed = seed * 6364136223846793005ull + 1442695040888963407ull;
			buf[i] = alpha[(seed >> 33) % sizeof alpha];
		}
		/* a long run of nothing, so the window has to grow, on some of them */
		if (k % 7 == 0 && n > 300)
			memset(buf + 20, 0x90, n - 40u);
		for (from = 0; from <= n + 1u && from < 700u; from += 1u + k % 5u)
			CK(kgenome_diag_cand_at(buf, from, n) == ref_cand(buf, from, n));
	}
	CK(kgenome_diag_cand_at(buf, 0, 0) == 0);
	CK(kgenome_diag_cand_at(buf, 0, 1) == 1);

	if (b) {
		static const uint8_t shapes[][2] = { { 0x0f, 0x0b }, { 0x0f, 0x05 }, { 0xcd, 0x80 }, { 0xcd, 0x81 }, { 0x90, 0x0f } };
		unsigned s;

		for (s = 0; s < sizeof shapes / sizeof shapes[0]; s++) {
			double t0;
			uint64_t hits;

			for (i = 0; i + 1u < big; i += 2u) {
				b[i] = shapes[s][0];
				b[i + 1u] = shapes[s][1];
			}
			t0 = now();
			hits = walk_all(b, big);
			CK(now() - t0 < 3.0);
			CK(hits == (s == 1 || s == 2 ? big / 2u : 0u) || s == 3 || s == 4);
		}
		free(b);
	}
	if (fails)
		return 1;
	printf("hunt_cand_at: ok\n");
	return 0;
}
