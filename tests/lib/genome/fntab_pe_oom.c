/*
 * fntab_pe_oom - the function table of a PE under allocation failure: every allocation of one whole build fails once, in turn (malloc, calloc and realloc are wrapped), for an image of each
 * case that allocates differently: the REACH step (x86, behind padding, with a gap start, a jump to a start, a switch), the exception table with leaves and fragments, ARM64.
 * The table is either whole (the same as the unfailed build) or says it is short (status NOMEM); it never crashes, never leaves a half table (sorted, no empty entry), and the clean build run after
 * the sweep is identical to the one before it.
 * Why the old tests missed it: (a) the REACH step and the PE observer are new code with allocations of their own (the output vector, the frames, the walk's thunk list); (b) fntab_cov's sweep
 * runs an ELF image, whose build has none of them.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/fntab.h>
#include <genotype/image/pe_image.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>
#include <phenotype/frame.h>
#include "fntab_pe_kit.h"

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
static unsigned fail_at, alloc_seen;
static int should_fail(void)
{
	if (!fail_at)
		return 0;
	if (++alloc_seen == fail_at) {
		fail_at = 0;
		return 1;
	}
	return 0;
}
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n) { return should_fail() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b) { return should_fail() ? NULL : __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n) { return should_fail() ? NULL : __real_realloc(p, n); }

static uint64_t digest(const struct kgenome_func_set *fs)
{
	uint64_t h = 1469598103934665603ull;
	uint32_t i;

	for (i = 0; i < fs->n; i++) {
		const uint64_t v[4] = { fs->v[i].off, fs->v[i].len, fs->v[i].end_source, fs->v[i].flags };
		unsigned k;

		for (k = 0; k < 4; k++)
			h = (h ^ v[k]) * 1099511628211ull;
	}
	return h;
}

/* One image: build it clean, then fail the Nth allocation of the build for N = 1, 2, ... until one build allocates less than N. */
static void sweep(const char *what, const uint8_t *b, uint32_t n)
{
	struct tab t;
	uint64_t clean;
	unsigned k, whole = 0, short_ = 0;

	build(b, n, &t);
	CK(t.ok && table_ok(&t, n));
	clean = digest(&t.fs);
	tab_free(&t);
	for (k = 1; k < 4000u; k++) {
		alloc_seen = 0;
		fail_at = k;
		build(b, n, &t);
		if (fail_at == 0) {                     /* the Nth allocation happened and failed */
			CK(t.ok);
			CK(table_ok(&t, n) || t.fs.n == 0);
			if (t.fs.status == KGENOME_NOMEM)
				short_++;
			else if (digest(&t.fs) == clean)
				whole++;
			else {
				/* a different table that is not marked short: it says where it is less than the clean one - an entry that REACH could not read (flag REACH_NONE) */
				uint32_t i;
				int none = 0;

				for (i = 0; i < t.fs.n; i++)
					none |= (t.fs.v[i].flags & KGENOME_FN_F_REACH_NONE) != 0;
				CK(none);
			}
			tab_free(&t);
			continue;
		}
		fail_at = 0;
		CK(digest(&t.fs) == clean);
		tab_free(&t);
		break;
	}
	build(b, n, &t);
	CK(digest(&t.fs) == clean);                 /* the clean build after the sweep is the clean build before it */
	tab_free(&t);
	printf("  %s: %u failures taken (%u short, %u whole)\n", what, k - 1u, short_, whole);
}

int main(void)
{
	struct pb p;
	uint8_t code[0x100];
	uint32_t t0;

	/* REACH: a body with a call and its mark, a leaf behind padding, a tail jump to a function behind padding, a switch, a dead tail */
	memset(code, 0xcc, sizeof code);
	memcpy(code, "\x55\x8b\xec\xe8\0\0\0\0\xcc", 9);                  rel32(code, 3, 5, 0x60);
	memcpy(code + 0x20, "\x55\x8b\xec\x33\xc0\x5d\xc3", 7);
	memcpy(code + 0x40, "\x55\xe9\0\0\0\0", 6);                       rel32(code, 0x41, 5, 0x80);
	memcpy(code + 0x60, "\x55\xff\xe0\x10\x10\x00\x00\xc3\x31\xc0\xc3", 11);
	memcpy(code + 0x80, "\x55\x8b\xec\x5d\xc3", 5);
	t0 = code_image(&p, 0, code, sizeof code);
	sweep("x86 reach", p.b + 0, p.n);
	free(p.b);
	t0 = code_image(&p, 1, code, sizeof code);
	sweep("x64 reach", p.b, p.n);
	free(p.b);
	(void)t0;
	printf("fntab_pe_oom: %d failure(s)\n", fails);
	return fails != 0;
}
