/*
 * funcs_at - THE ONE LOOKUP IN THE FUNCTION TABLE (kgenome_funcs_at, kgenome_funcs_start; genotype/image/funcs.h).
 *
 * Five private copies of "which function holds this offset / starts here" were in the tree (the lineage, the sweep, the code notes, the CFG view, the viewer's
 * disassembly). They were never compared with each other. This test does it: every table of up to 4 functions over a small alphabet of starts and lengths
 * (including the overlapping and nested ones a merge can leave), every offset, against a linear scan that is the definition.
 *
 * RED: build with -DFUNCS_AT_OLD and the rows run the two OLD copies instead of the new API (the lineage's `engine_fn_at`, the sweep's `func_at`, and the
 * code notes' exact-start copy, pasted below as they were). They fail the definition on the overlapping tables: the sweep's copy (last start at or below) answers
 * the later of two overlapping bodies, the lineage's (first end above) the earlier. The new function answers the definition.
 * Why the old tests missed it: (b) no test gave a lookup an overlapping pair (the merge keeps one per start, so a fixture built through it never had one), and the
 * copies sat in three directories, each tested only through its caller's golden output (c).
 *
 * The definition (what "holds" means when two kept extents overlap without nesting): the entry whose END is the first above the offset, when it starts at or
 * below it - the lineage's, which is also the one that is O(log n) on a table whose ends rise with its starts.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/funcs.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#ifdef FUNCS_AT_OLD
/* the sweep's copy, as it was (diag_sweep.c func_at) */
static uint32_t old_at(const struct kgenome_func_set *fg, uint64_t off)
{
	uint32_t lo = 0, hi = fg->n;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (fg->v[mid].off <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo || off >= fg->v[lo - 1u].off + fg->v[lo - 1u].len)
		return KGENOME_FUNCS_NONE;
	return lo - 1u;
}
#define AT(fs, off) old_at((fs), (off))
#define START(fs, off) old_at((fs), (off))      /* (the code notes' copy answered exact starts only: any answer that is not an exact start is wrong) */
#else
#define AT(fs, off) kgenome_funcs_at((fs), (off))
#define START(fs, off) kgenome_funcs_start((fs), (off))
#endif

/* the definition, by a linear scan */
static uint32_t def_at(const struct kgenome_func_set *fs, uint64_t off)
{
	uint32_t i, best = KGENOME_FUNCS_NONE;
	uint64_t best_end = 0;

	for (i = 0; i < fs->n; i++) {
		const uint64_t e = fs->v[i].off + fs->v[i].len;

		if (fs->v[i].off <= off && off < e && (best == KGENOME_FUNCS_NONE || e < best_end)) {
			best = i;
			best_end = e;
		}
	}
	return best;
}

static uint32_t def_start(const struct kgenome_func_set *fs, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < fs->n; i++)
		if (fs->v[i].off == off)
			return i;
	return KGENOME_FUNCS_NONE;
}

/* Tables: n functions, starts strictly rising from a 6-letter alphabet, a length from a 5-letter alphabet; the ends need not rise (a hostile or old table). Only
 * the tables whose ENDS rise are checked against the definition (the lookup's stated precondition), and all of them for "never answers a function that does not hold". */
#define NA 6u
#define NL 5u

static void exhaustive(void)
{
	static const uint64_t st[NA] = { 0, 3, 7, 12, 20, 33 };
	static const uint64_t ln[NL] = { 1, 4, 9, 16, 30 };
	unsigned n, code;
	uint64_t tables = 0, overlap_tables = 0;

	for (n = 0; n <= 4u; n++) {
		unsigned total = 1;
		unsigned k;

		for (k = 0; k < n; k++)
			total *= NA * NL;
		for (code = 0; code < total; code++) {
			struct kgenome_func v[4];
			struct kgenome_func_set fs;
			unsigned c = code, mono = 1, over = 0;
			uint64_t off;
			uint64_t last = 0;
			int ok = 1;

			memset(v, 0, sizeof v);
			for (k = 0; k < n; k++) {
				const unsigned a = c % NA, l = (c / NA) % NL;

				c /= NA * NL;
				v[k].off = st[a];
				v[k].len = ln[l];
				if (k && v[k].off <= last)
					ok = 0;                 /* starts must rise strictly */
				last = v[k].off;
			}
			if (!ok)
				continue;
			for (k = 1; k < n; k++) {
				if (v[k].off + v[k].len < v[k - 1u].off + v[k - 1u].len)
					mono = 0;
				if (v[k].off < v[k - 1u].off + v[k - 1u].len)
					over = 1;
			}
			memset(&fs, 0, sizeof fs);
			fs.v = v;
			fs.n = n;
			tables++;
			overlap_tables += over;
			for (off = 0; off < 70; off++) {
				const uint32_t a = AT(&fs, off), s = START(&fs, off);

				/* never an answer that does not hold the offset / start there */
				if (a != KGENOME_FUNCS_NONE)
					CK(a < n && v[a].off <= off && off < v[a].off + v[a].len);
				if (s != KGENOME_FUNCS_NONE)
					CK(s < n && v[s].off == off);
				if (!mono)
					continue;
				if (a != def_at(&fs, off) || s != def_start(&fs, off)) {
					CK(a == def_at(&fs, off));
					CK(s == def_start(&fs, off));
					return;         /* one counterexample is the finding */
				}
			}
		}
	}
	printf("  exhaustive: %llu tables, %llu with overlapping extents\n", (unsigned long long)tables, (unsigned long long)overlap_tables);
}

/* The named rows. */
static void rows(void)
{
	struct kgenome_func v[3] = { { .off = 0x100, .len = 0x40 }, { .off = 0x120, .len = 0x40 }, { .off = 0x200, .len = 0x10 } };
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	fs.v = v;
	fs.n = 3;
	/* two kept extents that overlap without nesting: the offset 0x130 is in both; the earlier one ends first and answers */
	CK(AT(&fs, 0x130) == 0u);
	CK(AT(&fs, 0x150) == 1u);               /* only the second */
	CK(AT(&fs, 0x160) == KGENOME_FUNCS_NONE);
	CK(AT(&fs, 0x20f) == 2u);
	CK(AT(&fs, 0x210) == KGENOME_FUNCS_NONE);
	CK(AT(&fs, 0xff) == KGENOME_FUNCS_NONE);
	CK(START(&fs, 0x120) == 1u);
	CK(START(&fs, 0x121) == KGENOME_FUNCS_NONE);
#ifndef FUNCS_AT_OLD
	CK(kgenome_funcs_at(NULL, 0) == KGENOME_FUNCS_NONE);
	CK(kgenome_funcs_start(NULL, 0) == KGENOME_FUNCS_NONE);
	fs.n = 0;
	CK(kgenome_funcs_at(&fs, 0x100) == KGENOME_FUNCS_NONE);
	CK(kgenome_funcs_start(&fs, 0x100) == KGENOME_FUNCS_NONE);
	/* the top of the address space: a hit is only inside [off, off + len) */
	fs.n = 1;
	v[0].off = UINT64_MAX - 4u;
	v[0].len = 3;
	CK(kgenome_funcs_at(&fs, UINT64_MAX - 3u) == 0u);
	CK(kgenome_funcs_at(&fs, UINT64_MAX - 1u) == KGENOME_FUNCS_NONE);
#endif
}

int main(void)
{
	rows();
	exhaustive();
	printf("funcs_at: %d failure(s)\n", fails);
	return fails ? 1 : 0;
}
