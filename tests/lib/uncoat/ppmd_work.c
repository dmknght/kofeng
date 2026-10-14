/*
 * ppmd_work - what a PPMd model start costs, counted rather than timed.
 *
 * A RAR3 block header can restart the model ("reset") with an arena of up to 256 MB
 * asked, and every restart used to clear the whole arena (64 MB here) whatever the
 * previous block had touched: a few bytes of input per block bought a memset of
 * megabytes. A start now clears what the last run wrote. The source is included with
 * a memset that counts, so the bytes cleared are counted; a count is the same on
 * a slow machine and a fast one. (ppmd_over.c is the other half: the allowance.)
 */

#include "hostile_common.h"

/* The product carries no counter: the test counts the bytes the model clears by
 * wrapping memset while it includes the source. Everything the model memsets is
 * counted (the arena clears dominate by orders of magnitude; the rest is small
 * tables), so the bound below is on the sum. */
static uint64_t kuncoat_ppmd_work;
static void *work_memset(void *p, int c, size_t n)
{
	kuncoat_ppmd_work += (uint64_t)n;
	return memset(p, c, n);
}
#define memset work_memset

#include "../../../libuncoat/decompressors/ppmd.c"

#undef memset

#define NSTARTS 300u
#define SYMS 50u

static uint8_t rnd[1u << 22];

static void fill(uint64_t seed)
{
	size_t i;

	for (i = 0; i < sizeof rnd; i++)
		rnd[i] = (uint8_t)hv_rng32(&seed);
}

/* NSTARTS restarts of a 64 MB model, SYMS symbols between them. */
static void start_cost(void)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	unsigned i, k;
	uint64_t bound = (uint64_t)NSTARTS * (256u << 10);

	CK(m != NULL);
	if (!m)
		return;
	for (i = 0; i < NSTARTS; i++) {
		hv_at(1, i);
		CKF(kuncoat_ppmd_start_asked(m, 8, 64u << 20, rnd, sizeof rnd, 0) == 1, "start %u", i);
		for (k = 0; k < SYMS; k++)
			(void)kuncoat_ppmd_next(m);
	}
	printf("  (%u starts of a %u MB arena: %llu bytes cleared, bound %llu)\n", NSTARTS, 64u,
	       (unsigned long long)kuncoat_ppmd_work, (unsigned long long)bound);
	CKF(kuncoat_ppmd_work <= bound, "%llu bytes cleared over %u starts", (unsigned long long)kuncoat_ppmd_work, NSTARTS);
	kuncoat_ppmd_free(m);
}

/* Clearing only what was written must still leave the arena as a fresh one: the same
 * input decodes to the same symbols after a long run that filled and restarted a small
 * arena many times. */
static void clean_start(void)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	static int a[20000], b[20000];
	unsigned k, n = sizeof a / sizeof a[0];

	CK(m != NULL);
	if (!m)
		return;
	hv_at(2, 0);
	CK(kuncoat_ppmd_start_asked(m, 6, 1u << 20, rnd, sizeof rnd, 0) == 1);
	for (k = 0; k < n; k++)
		a[k] = kuncoat_ppmd_next(m);
	/* a long run in between that fills the 1 MB arena and restarts it repeatedly */
	CK(kuncoat_ppmd_start_asked(m, 6, 1u << 20, rnd + 5, sizeof rnd - 5u, 0) == 1);
	for (k = 0; k < 400000u; k++)
		if (kuncoat_ppmd_next(m) < 0)
			break;
	CK(kuncoat_ppmd_start_asked(m, 6, 1u << 20, rnd, sizeof rnd, 0) == 1);
	for (k = 0; k < n; k++)
		b[k] = kuncoat_ppmd_next(m);
	CK(!memcmp(a, b, sizeof a));
	kuncoat_ppmd_free(m);
}

HV_GROUP(start_cost)
HV_GROUP(clean_start)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	fill(0xA11CE5ull);
	hv_expect_clean("start cost", hv_grp_start_cost, NULL, 60);
	hv_expect_clean("clean start", hv_grp_clean_start, NULL, 60);
	return hv_done("ppmd_work");
}
