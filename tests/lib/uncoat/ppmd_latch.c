/*
 * ppmd_latch - kuncoat_ppmd_next answers -1 when "the stream or the model gave out"
 * (ppmd.h), and a model that gave out stays out: a call after a -1 is a -1 again until
 * kuncoat_ppmd_resume or a new start (WP5-F-PPMD-1).
 *
 * Old tests missed it: (b) every caller (rar3.c) stops at the first -1 and no test called
 * next once more after it, so the escape walk that moved min_context to the suffix and
 * returned without latching was never seen to continue from a different context.
 */
#include <uncoat.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rng_state;

static uint32_t rng(void)
{
	rng_state = rng_state * 1664525u + 1013904223u;
	return rng_state >> 8;
}

int main(void)
{
	static uint8_t in[2003];
	unsigned seed, again = 0, models = 0, bad = 0;
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();

	if (!m) {
		printf("ppmd_latch: out of memory\n");
		return 1;
	}
	for (seed = 0; seed < 400u; seed++) {
		unsigned i, k;
		int r = 0;

		rng_state = seed * 2654435761u + 1u;
		for (i = 0; i < sizeof in; i++)
			in[i] = (uint8_t)rng();
		if (!kuncoat_ppmd_start_asked(m, 2 + (int)(seed % 6u), 1u << 20, in, sizeof in, 0))
			continue;
		models++;
		for (k = 0; k < 20000u; k++) {
			r = kuncoat_ppmd_next(m);
			if (r < 0)
				break;
		}
		if (r >= 0)
			continue;
		again++;
		for (k = 0; k < 8u; k++)
			if (kuncoat_ppmd_next(m) != -1) {
				bad++;
				printf("  FAIL seed %u: symbol after a -1\n", seed);
				break;
			}
	}
	kuncoat_ppmd_free(m);
	if (again < 20u) {
		printf("  FAIL only %u of %u models ever gave out: the test does not reach the case\n", again, models);
		return 1;
	}
	printf("ppmd_latch: %s (%u models, %u gave out, %u continued)\n", bad ? "FAILED" : "ok", models, again, bad);
	return bad != 0;
}
