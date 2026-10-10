/*
 * funcs_remap - the functions of a normalised view, found again from its parent's.
 *
 * A view is the parent with padding collapsed and the library taken out, so its
 * functions are the parent's bytes at new offsets. What this pins: a function
 * that survives is found at its new offset with its symbol fields intact; one the
 * library owned (cut out) and one whose body the collapse rewrote are absent; the
 * order is kept; and nothing is read past either buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + i * 7u + (i >> 3));
}

int main(void)
{
	/* parent: A(0..64) pad(16 zeros) LIB(80..144) B(144..208) C(208..272) */
	uint8_t par[272], view[256];
	struct kof_func f[4];
	struct kof_func_set pf, out;
	size_t at = 0;

	memset(par, 0, sizeof par);
	fill(par, 64, 1);
	fill(par + 80, 64, 50);
	fill(par + 144, 64, 100);
	fill(par + 208, 64, 150);
	/* the view: A, the pad collapsed to 2 bytes, the library cut, B, then C
	 * with a zero run inside it shortened (so C is not byte-identical) */
	memset(view, 0, sizeof view);
	memcpy(view + at, par, 64); at += 64;
	at += 2;
	memcpy(view + at, par + 144, 64); at += 64;
	memcpy(view + at, par + 208, 30); at += 30;
	at += 2;
	memcpy(view + at, par + 208 + 30, 10); at += 10;     /* the run shrank */

	memset(f, 0, sizeof f);
	f[0].off = 0;   f[0].len = 64; f[0].value = 0x1000; f[0].shndx = 1;
	f[1].off = 80;  f[1].len = 64; f[1].value = 0x1050;      /* the library's */
	f[2].off = 144; f[2].len = 64; f[2].value = 0x1090;
	f[3].off = 208; f[3].len = 64; f[3].value = 0x10d0;
	pf.v = f; pf.n = 4; pf.oom = 0;

	kof_funcs_remap(par, sizeof par, &pf, view, at, &out);
	check(out.n == 2, "A and B survive; the library's and the rewritten C do not");
	if (out.n == 2) {
		check(out.v[0].off == 0 && out.v[0].len == 64, "A stays at 0");
		check(out.v[0].value == 0x1000 && out.v[0].shndx == 1,
		      "A keeps its symbol fields");
		check(out.v[1].off == 66 && out.v[1].len == 64,
		      "B moves to 66, after A and the collapsed pad");
		check(out.v[1].value == 0x1090, "B keeps its value");
		check(memcmp(view + out.v[1].off, par + 144, 64) == 0,
		      "B's bytes are where it says");
	}
	kof_funcs_free(&out);

	/* nothing to map, and a hostile function extent, are both empty answers */
	pf.n = 0;
	kof_funcs_remap(par, sizeof par, &pf, view, at, &out);
	check(out.n == 0 && !out.v, "no functions in, none out");
	f[0].off = 1000; f[0].len = 64; pf.n = 1;
	kof_funcs_remap(par, sizeof par, &pf, view, at, &out);
	check(out.n == 0, "an extent past the parent is skipped, not read");
	kof_funcs_remap(NULL, 0, &pf, view, at, &out);
	check(out.n == 0, "no parent, no functions");

	if (failures) {
		printf("funcs_remap: %d failure(s)\n", failures);
		return 1;
	}
	printf("funcs_remap: survive/cut/rewritten, offsets, fields, bounds - ok\n");
	return 0;
}
