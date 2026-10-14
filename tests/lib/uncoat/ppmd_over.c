/*
 * ppmd_over - a PPMd model that asked for more arena than this build gives.
 *
 * A RAR3 block header names an arena of up to 256 MB and this build allocates at most
 * KUNCOAT_PPMD_ARENA_MAX. A model with less memory than the encoder's restarts at a
 * DIFFERENT point and every byte after is wrong, so the first time the smaller arena
 * runs out where the asked one would not have, the model stops and says so
 * (kuncoat_ppmd_over) instead of decoding on. The source is included with a small
 * allowance so that point is reached within the few hundred symbols a random input
 * decodes before the range coder gives out. (The full arena itself is set up by
 * hand: see over_arena.)
 */

#define KUNCOAT_PPMD_ARENA_MAX (24u << 10)

#include "hostile_common.h"

#include "../../../libuncoat/decompressors/ppmd.c"

static uint8_t rnd[1u << 20];

/* A model that asked for more than it is given: it decodes while the smaller arena is
 * enough and stops (over) the first time it fills, where the encoder's would not have;
 * a model that asked for exactly what it got just restarts, as the format does. */
static void over_arena(void)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	unsigned k;
	int r = 0;

	CK(m != NULL);
	if (!m)
		return;
	hv_at(3, 0);
	CK(kuncoat_ppmd_start_asked(m, 16, 100u << 20, rnd, sizeof rnd, 0) == 1);
	/* The arena is full when the text area meets the units: the state the model reaches
	 * by itself after tens of megabytes of input, put there directly (a random input
	 * stops decoding long before that, and the encoder is not in this tree). */
	for (k = 0; k < 200u; k++) {
		m->text = m->units_start;
		r = kuncoat_ppmd_next(m);
		if (r < 0)
			break;
	}
	CKF(r < 0 && kuncoat_ppmd_over(m) == 1, "asked 100 MB, given 24 KB: stopped %d, over %d after %u symbols", r,
	    kuncoat_ppmd_over(m), k);
	/* once over, always over */
	CK(kuncoat_ppmd_next(m) == -1 && kuncoat_ppmd_over(m) == 1);
	/* a request over the format's own 256 MB, and under the floor, is refused outright */
	CK(kuncoat_ppmd_start_asked(m, 8, (256u << 20) + 1u, rnd, sizeof rnd, 0) == 0);
	CK(kuncoat_ppmd_start_asked(m, 8, 100, rnd, sizeof rnd, 0) == 0);
	/* asked == given: the same full arena restarts as the format says, never "over" */
	CK(kuncoat_ppmd_start_asked(m, 16, 24u << 10, rnd, sizeof rnd, 0) == 1);
	for (k = 0; k < 200u; k++) {
		m->text = m->units_start;
		if (kuncoat_ppmd_next(m) < 0)
			break;
	}
	CK(kuncoat_ppmd_over(m) == 0);
	kuncoat_ppmd_free(m);
}

HV_GROUP(over_arena)

int main(void)
{
	uint64_t seed = 0xA11CE5ull;
	size_t i;

	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; i < sizeof rnd; i++)
		rnd[i] = (uint8_t)hv_rng32(&seed);
	hv_expect_clean("over arena", hv_grp_over_arena, NULL, 120);
	return hv_done("ppmd_over");
}
