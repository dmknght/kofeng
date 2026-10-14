/*
 * funcs_status - a function set that a limit cut says so on the object.
 *
 * kgenome_func_set.status (NOMEM, TRUNCATED, OVER_BUDGET) was written by the builder and
 * read nowhere in the engine: the set feeds the plague units (scan_feed.c) and the
 * view's remap, so a set cut short made every rule that reads a function look like
 * "no such function". funcs_of now calls oc_scan_limit for a cut set, so the object
 * comes back broken = KOF_BROKEN_LIMIT.
 *
 * HOW A CUT IS MADE. The set is built into an array that grows by realloc; the first
 * growth is 256 records, and the one allocation is failed here (a realloc of exactly that
 * size, once, armed) while the plain ELF fixture is scanned through the whole pipeline
 * with the similarity rules of tests/sigs/mutations, which ask for the functions. The
 * control is the same scan with nothing failed: it must not be cut. realloc is
 * interposed in this program, which a sanitizer's allocator does not allow: under one
 * the case is reported as skipped.
 */

#define _GNU_SOURCE

#include "caps_fix.h"
#include "caps_e2e.h"
#include <genotype/image/funcs.h>

#ifndef __SANITIZE_ADDRESS__
#define CAN_FAIL 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#undef CAN_FAIL
#endif
#endif

#ifdef CAN_FAIL
extern void *__libc_realloc(void *, size_t);

static size_t fail_size;
static int fail_armed, fail_hit;

void *realloc(void *p, size_t n)
{
	if (fail_armed && n == fail_size) {
		fail_armed = 0;
		fail_hit = 1;
		return NULL;
	}
	return __libc_realloc(p, n);
}
#endif

static uint8_t buf[1u << 20];

static unsigned limit_objects(size_t n)
{
	struct e2e r;
	unsigned i, k = 0;

	if (!e2e_scan(buf, n, &r))
		return 0xffffu;
	for (i = 0; i < r.n; i++)
		k += r.o[i].broken == KOF_BROKEN_LIMIT;
	return k;
}

int main(int argc, char **argv)
{
	FILE *f = fopen("build/test/fixtures/plain-elf64", "rb");
	size_t n;

	(void)argc; (void)argv;
	if (!f || !e2e_open(NULL)) {
		printf("funcs_status: no fixture or database - nothing tested\n");
		return 0;
	}
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);
#ifdef CAN_FAIL
	CK(limit_objects(n) == 0u);                     /* the control */
	fail_size = 256u * sizeof(struct kgenome_func);
	fail_hit = 0;
	fail_armed = 1;
	{
		unsigned cut = limit_objects(n);

		fail_armed = 0;
		CK(fail_hit == 1);                      /* the allocation was reached */
		CK(cut >= 1u);                          /* and the object says so */
	}
	CK(limit_objects(n) == 0u);                     /* nothing is left behind */
#else
	printf("  (a sanitizer owns malloc: the failing-allocation case is skipped)\n");
#endif
	if (fails) {
		printf("funcs_status: %d check(s) failed\n", fails);
		return 1;
	}
	printf("funcs_status: a function set cut by a limit makes the object broken=LIMIT\n");
	return 0;
}
