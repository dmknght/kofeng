#define _GNU_SOURCE
/*
 * blk_table_grow - the viewer's block table has no capacity constant: it holds every row the engine offers (owner, 2026-11-03: "Bang block cua viewer
 * nen cap phat dong thay vi limit 4096 khoi").
 *
 * WHAT IT PINS (data layer, kofeditor.c blk_reserve; the table's window and scroll are the viewer's and need a struct view: not covered here).
 *   grow     5000 rows (more than the old 4096) are reserved and kept, in the order written, each with the id it was given
 *   hash     draft_hash differs when row 4999 is ticked and when it is unticked again (the last row was past the old cap)
 *   refuse   an allocation the harness refuses (every allocation of the growth, in turn): blk_reserve answers 0, the rows already held stay
 *            intact, and the draft SAYS so (warn, warn_bad) - never a silent drop
 * Seam: tests/unit/oom_harness.h (the linker wraps malloc/realloc; oh_fail_at refuses the n-th allocation).
 * Why the old tests missed it: (a) the cap line `n_blk >= MTN_MAX_BLOCK` in the carve was never executed by a test (no fixture held 4096 rows);
 * (b) the editor tests used 64 rows; (c) the viewer took "fewer rows" for "fewer blocks" - nothing asserted the count the engine returned.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oom_harness.h"
#include "../../kofexamine/kofeditor.h"

#define ROWS 5000u

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static void fill(struct kof_editor *e, uint32_t from, uint32_t to)
{
	uint32_t i;

	for (i = from; i < to; i++) {
		memset(&e->dr.blk[i], 0, sizeof e->dr.blk[i]);
		e->dr.blk[i].id = 0x1000u + i;
		e->dr.blk[i].off = 16u * i;
	}
	e->dr.n_blk = to;
}

int main(void)
{
	struct kof_editor E;
	uint32_t i, h0, h1, step;

	oh_init();
	memset(&E, 0, sizeof E);

	/* grow: one row at a time, as the carve asks. */
	for (i = 0; i < ROWS; i++) {
		CHECK(blk_reserve(&E, i + 1u), "row %u refused", i);
		fill(&E, i, i + 1u);
	}
	CHECK(E.dr.n_blk == ROWS && E.dr.cap_blk >= ROWS, "held %u cap %u", E.dr.n_blk, E.dr.cap_blk);
	for (i = 0; i < ROWS; i++)
		CHECK(E.dr.blk[i].id == 0x1000u + i && E.dr.blk[i].off == 16u * i, "row %u changed", i);

	/* hash: the last row is past the old cap. */
	h0 = draft_hash(&E);
	blk_set_picked(&E, ROWS - 1u, 1);
	h1 = draft_hash(&E);
	CHECK(h0 != h1, "ticking row 4999 left the hash unchanged");
	blk_set_picked(&E, ROWS - 1u, 0);
	CHECK(draft_hash(&E) == h0, "unticking row 4999 did not restore the hash");

	/* refuse: every allocation of one growth, in turn. */
	free(E.dr.blk);
	memset(&E.dr, 0, sizeof E.dr);
	CHECK(blk_reserve(&E, 8u), "first reserve");
	fill(&E, 0, 8u);
	for (step = 1; step <= 4; step++) {
		uint32_t cap = E.dr.cap_blk, n = E.dr.n_blk;
		int ok;

		E.dr.warn[0] = 0;
		E.dr.warn_bad = 0;
		oh_seen = 0; oh_fail_at = step; oh_armed = 1;
		ok = blk_reserve(&E, cap + 1u);
		oh_armed = 0;
		if (!ok) {
			CHECK(E.dr.warn[0] && E.dr.warn_bad, "refusal %u said nothing", step);
			CHECK(E.dr.n_blk == n && E.dr.cap_blk == cap, "refusal %u moved the table", step);
		}
		for (i = 0; i < n; i++)
			CHECK(E.dr.blk[i].id == 0x1000u + i, "refusal %u damaged row %u", step, i);
	}
	free(E.dr.blk);
	if (!fails)
		printf("blk_table_grow: ok\n");
	return fails ? 1 : 0;
}
