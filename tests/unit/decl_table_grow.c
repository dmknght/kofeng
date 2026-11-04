#define _GNU_SOURCE
/*
 * decl_table_grow - the draft's strings table has no capacity constant: it holds every marker the author declares (owner, 2026-11-03: no fixed caps in
 * the draft model). MAX_DECL (32) was the old one.
 *
 * WHAT IT PINS (data layer, kofeditor_decl.c decl_reserve / decl_push / decl_remove; the panel's columns and edit codes are the viewer's and need a
 * struct view: covered by the tui draft tests).
 *   grow     5000 rows (more than 32, and more than the 100 edit codes the old band held) are pushed and kept, in order, each with its own bytes
 *   hash     draft_hash differs when row 4999 is edited and when it is put back (the last row was past the old cap)
 *   remove   removing row 0 of 5000 keeps the other 4999 in order
 *   clear    draft_clear empties the table and keeps the allocation
 *   refuse   an allocation the harness refuses (every allocation of one growth, in turn): decl_reserve answers 0, the rows held stay intact and
 *            the draft SAYS so (warn, warn_bad) - never a silent drop
 * Seam: tests/unit/oom_harness.h (the linker wraps malloc/realloc; oh_fail_at refuses the n-th allocation).
 * Why the old tests missed it: (a) the line `n_decl >= MAX_DECL` (decl_add, decl_add_text, the chooser) was never executed with a full table;
 * (b) every fixture held at most 8 markers; (c) nothing asserted the count of markers kept, only that nothing crashed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oom_harness.h"
#include "../../kofexamine/kofeditor.h"

#define ROWS 5000u

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static void put(struct kof_editor *e, uint32_t i)
{
	struct decl *d = decl_push(e);

	if (!d)
		return;
	d->bytes = malloc(4u);
	memcpy(d->bytes, &i, 4u);
	d->nbytes = d->len = 4u;
}

static uint32_t at(const struct kof_editor *e, uint32_t i)
{
	uint32_t v = 0;

	memcpy(&v, e->dr.decl[i].bytes, 4u);
	return v;
}

int main(void)
{
	struct kof_editor E;
	uint32_t i, h0, h1, step, cap;

	oh_init();
	memset(&E, 0, sizeof E);

	for (i = 0; i < ROWS; i++)
		put(&E, i);
	CHECK(E.dr.n_decl == ROWS && E.dr.cap_decl >= ROWS, "held %u cap %u", E.dr.n_decl, E.dr.cap_decl);
	for (i = 0; i < E.dr.n_decl && i < ROWS; i++)
		CHECK(at(&E, i) == i, "row %u changed", i);

	h0 = draft_hash(&E);
	E.dr.decl[ROWS - 1u].bytes[0] ^= 1u;
	h1 = draft_hash(&E);
	CHECK(h0 != h1, "editing row 4999 left the hash unchanged");
	E.dr.decl[ROWS - 1u].bytes[0] ^= 1u;
	CHECK(draft_hash(&E) == h0, "putting row 4999 back did not restore the hash");

	decl_remove(&E, 0);
	CHECK(E.dr.n_decl == ROWS - 1u, "removed one, %u left", E.dr.n_decl);
	for (i = 0; i < E.dr.n_decl && i < ROWS - 1u; i++)
		CHECK(at(&E, i) == i + 1u, "row %u after removal", i);

	cap = E.dr.cap_decl;
	draft_clear(&E);
	CHECK(E.dr.n_decl == 0 && E.dr.cap_decl == cap && E.dr.decl, "clear lost the table");
	free(E.dr.decl);
	memset(&E.dr, 0, sizeof E.dr);

	/* refuse: every allocation of one growth, in turn. */
	for (i = 0; i < 8u; i++)
		put(&E, i);
	for (step = 1; step <= 4; step++) {
		uint32_t cp = E.dr.cap_decl, n = E.dr.n_decl;
		int ok;

		E.dr.warn[0] = 0;
		E.dr.warn_bad = 0;
		oh_seen = 0; oh_fail_at = step; oh_armed = 1;
		ok = decl_reserve(&E, cp + 1u);
		oh_armed = 0;
		if (!ok) {
			CHECK(E.dr.warn[0] && E.dr.warn_bad, "refusal %u said nothing", step);
			CHECK(E.dr.n_decl == n && E.dr.cap_decl == cp, "refusal %u moved the table", step);
		}
		for (i = 0; i < n; i++)
			CHECK(at(&E, i) == i, "refusal %u damaged row %u", step, i);
	}
	for (i = 0; i < E.dr.n_decl; i++)
		free(E.dr.decl[i].bytes);
	free(E.dr.decl);
	if (!fails)
		printf("decl_table_grow: ok\n");
	return fails ? 1 : 0;
}
