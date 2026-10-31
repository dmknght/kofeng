/*
 * fnprint_bsketch_oom - kgenome_fnprint_bsketch_build with every allocation refused in turn (WP9-F14).
 *
 * The builder published start/from/to (n_start > 0) before `reached` was allocated, and on a refused allocation set NOMEM and returned with
 * reached NULL: a reader that trusts "one reached flag per start" faulted. The rule now: a sketch has its flags or it has no starts and no
 * edges and says NOMEM. Nothing is left on the ledger after the free, whichever allocation was refused.
 *
 * Old tests missed it: (b) no test refused the allocation (allocation failure was exercised only by the fuzz, whose row read `reached` only
 * when it was set, so the NULL was never dereferenced).
 */
#include <stdlib.h>

#include "fnprint_kit.h"

static struct fk_var V0 = { 0x1000, 0x2000, 0x12345678u };

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);

static long armed, seen, fail_at;

static int refuse(void)
{
	return armed && ++seen == fail_at;
}

void *__wrap_malloc(size_t n) { return refuse() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b) { return refuse() ? NULL : __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n) { return refuse() ? NULL : __real_realloc(p, n); }

int main(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_bsketch g;
	struct kgenome_ledger led;
	uint64_t e, m, site[4], a, b, c, z, w;
	long allocs, k, refused_with_starts = 0, refusals = 0;

	fk_init(&o);
	z = fk_stub(&o, 1, site + 3);
	w = fk_func(&o, 4, 40, &V0);
	e = fk_entry(&o, 0);
	m = fk_stub(&o, 2, site);
	a = fk_stub(&o, 1, site + 2);
	b = fk_func(&o, 1, 40, &V0);
	c = fk_func(&o, 2, 40, &V0);
	fk_call_to(&o, site[0], a);
	fk_call_to(&o, site[1], b);
	fk_call_to(&o, site[2], c);
	fk_call_to(&o, site[3], w);
	{ int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7)); memcpy(o.b + e + 3, &d, 4); }
	(void)z;

	kgenome_ledger_init(&led, 0);
	armed = 1; seen = 0; fail_at = 0;
	kgenome_fnprint_bsketch_build(&g, o.b, 0, o.n, 0, m, &led);
	armed = 0;
	allocs = seen;
	CK(g.status == KGENOME_OK && g.n_start > 0 && g.reached);
	kgenome_fnprint_bsketch_free(&g);
	CK(led.used == 0);
	CK(allocs > 3);

	for (k = 1; k <= allocs; k++) {
		kgenome_ledger_init(&led, 0);
		armed = 1; seen = 0; fail_at = k;
		kgenome_fnprint_bsketch_build(&g, o.b, 0, o.n, 0, m, &led);
		armed = 0; fail_at = 0;
		refusals++;
		/* the invariant: starts imply flags, and a refusal is said */
		if (g.n_start && !g.reached)
			refused_with_starts++;
		CK(g.n_start == 0 || g.reached != NULL);
		CK(g.status != KGENOME_OK);
		if (g.reached)
			CK(g.start && g.from && g.to);
		kgenome_fnprint_bsketch_free(&g);
		CK(led.used == 0);
	}
	if (refused_with_starts)
		printf("  %ld of %ld refusals left starts without flags\n", refused_with_starts, refusals);
	fk_free(&o);
	if (hk_fails) {
		printf("fnprint_bsketch_oom: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("fnprint_bsketch_oom: ok (%ld refusals)\n", refusals);
	return 0;
}
