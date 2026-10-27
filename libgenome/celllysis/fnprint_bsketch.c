/*
 * fnprint_bsketch.c - an approximate call graph read from the BYTES, with no decode.
 *
 * Candidate (b) of the prediction stage. The edges are found by the opcode byte and a displacement
 * that lands inside the text: `E8 rel32` (call), `E9 rel32` (jmp), `0F 8x rel32` (jcc) and
 * `lea r64,[rip+rel32]` (REX.W 8D, modrm mod=00 rm=101). A displacement is a 32-bit signed number, so
 * "lands inside a text of a few hundred KB" is a one-in-4096 coincidence for a byte pattern that is not
 * an instruction: the false edges are rare by construction (measured in fnprint_pred_eval.md).
 *
 * WHAT IT CANNOT SEE, and why it is only a prior: an indirect call, a switch table, a function that only
 * a data table names, an edge made by `mov r,imm` of a non-PIE address, a call through the GOT. A
 * byte that is part of another instruction (a disp32 that happens to start with E8) adds an edge that
 * is not one. Reached means "plausibly called from the entry's main", which a static link's library
 * functions are as well; so reached is never "author" (that is a decision about bytes, fnprint_libtab.c)
 * and unreached is never an exclusion.
 */
#include "fnprint.h"

#include <stdlib.h>
#include <string.h>

#include <kofcmp.h>

struct vec {
	uint64_t *v;
	uint64_t n, cap;
};

static int vec_push(struct vec *a, struct kgenome_ledger *led, uint64_t *charged, uint64_t x)
{
	if (a->n == a->cap) {
		uint64_t nc = a->cap ? a->cap * 2u : 1024u;
		uint64_t *nv;

		if (led && !kgenome_ledger_charge(led, (nc - a->cap) * sizeof *nv))
			return 0;
		nv = realloc(a->v, (size_t)nc * sizeof *nv);
		if (!nv) {
			if (led)
				kgenome_ledger_release(led, (nc - a->cap) * sizeof *nv);
			return 0;
		}
		*charged += (nc - a->cap) * sizeof *nv;
		a->v = nv;
		a->cap = nc;
	}
	a->v[a->n++] = x;
	return 1;
}

void kgenome_fnprint_bsketch_free(struct kgenome_fnprint_bsketch *g)
{
	if (!g)
		return;
	if (g->led)
		kgenome_ledger_release(g->led, g->bytes);
	free(g->start); free(g->from); free(g->to); free(g->reached);
	memset(g, 0, sizeof *g);
}

uint32_t kgenome_fnprint_bsketch_find(const struct kgenome_fnprint_bsketch *g, uint64_t off)
{
	uint32_t lo = 0, hi = g->n_start;

	while (lo < hi) {
		uint32_t m = lo + (hi - lo) / 2u;

		if (g->start[m] <= off)
			lo = m + 1u;
		else
			hi = m;
	}
	return lo ? lo - 1u : UINT32_MAX;
}

static int in_text(uint64_t t, uint64_t lo, uint64_t hi)
{
	return t >= lo && t < hi;
}

/* The target of the edge at p[i], if p[i..] is one of the four shapes and the target is inside [lo,hi). */
static int edge_at(const uint8_t *p, uint64_t i, uint64_t lo, uint64_t hi, uint64_t *to, int *is_call)
{
	uint8_t b = p[i];
	uint64_t len;
	int32_t d;

	*is_call = 0;
	if (b == 0xE8 || b == 0xE9) {
		len = 5;
		*is_call = b == 0xE8;
	} else if (b == 0x0F && i + 1 < hi && (p[i + 1] & 0xF0u) == 0x80u) {
		len = 6;
	} else if ((b == 0x48 || b == 0x4C) && i + 2 < hi && p[i + 1] == 0x8D && (p[i + 2] & 0xC7u) == 0x05u) {
		len = 7;
		*is_call = 1;       /* an address taken: a function the program names */
	} else {
		return 0;
	}
	if (i + len > hi)
		return 0;
	memcpy(&d, p + i + len - 4, 4);
	*to = (uint64_t)((int64_t)(i + len) + d);
	return in_text(*to, lo, hi);
}

uint64_t kgenome_fnprint_bsketch_main(const uint8_t *p, uint64_t n, uint64_t entry, int64_t va_delta,
				      uint64_t lo, uint64_t hi)
{
	uint64_t i, end = entry + 160u, to = KGENOME_BROKEN;

	if (entry >= n)
		return KGENOME_BROKEN;
	if (end > n)
		end = n;
	for (i = entry; i + 5 <= end; i++) {
		int32_t d;

		if (p[i] == 0xE8 || (p[i] == 0xFF && p[i + 1] == 0x15))
			break;          /* the stub's first call: what it loads before is its argument */
		if ((p[i] == 0x48 || p[i] == 0x4C) && i + 7 <= end && p[i + 1] == 0x8D && (p[i + 2] & 0xC7u) == 0x05u &&
		    (p[i + 2] & 0x38u) == 0x38u) {          /* lea rdi,[rip+rel] */
			memcpy(&d, p + i + 3, 4);
			to = (uint64_t)((int64_t)(i + 7) + d);
			i += 6;
		} else if (p[i] == 0x48 && i + 7 <= end && p[i + 1] == 0xC7 && p[i + 2] == 0xC7) {   /* mov rdi,imm32 */
			uint32_t imm;

			memcpy(&imm, p + i + 3, 4);
			to = (uint64_t)((int64_t)imm - va_delta);
			i += 6;
		} else if (p[i] == 0xBF) {                                                      /* mov edi,imm32 */
			uint32_t imm;

			memcpy(&imm, p + i + 1, 4);
			to = (uint64_t)((int64_t)imm - va_delta);
			i += 4;
		}
	}
	return in_text(to, lo, hi) ? to : KGENOME_BROKEN;
}

void kgenome_fnprint_bsketch_build(struct kgenome_fnprint_bsketch *g, const uint8_t *p, uint64_t lo, uint64_t hi,
				   int64_t va_delta, uint64_t root, struct kgenome_ledger *led)
{
	struct vec st = { 0 }, fr = { 0 }, to = { 0 };
	uint64_t i, charged = 0, k, w;
	uint32_t *stk = NULL, sp = 0, j;

	(void)va_delta;
	memset(g, 0, sizeof *g);
	g->led = led;
	if (!p || hi <= lo)
		return;
	if (root != KGENOME_BROKEN && in_text(root, lo, hi) && !vec_push(&st, led, &charged, root))
		goto over;
	for (i = lo; i + 5 <= hi; i++) {
		uint64_t t;
		int call;

		if (p[i] != 0xE8 && p[i] != 0xE9 && p[i] != 0x0F && p[i] != 0x48 && p[i] != 0x4C)
			continue;
		if (!edge_at(p, i, lo, hi, &t, &call))
			continue;
		if (!vec_push(&fr, led, &charged, i) || !vec_push(&to, led, &charged, t))
			goto over;
		if (call && !vec_push(&st, led, &charged, t))
			goto over;
	}
	g->scanned = hi - lo;
	/* starts: sorted, distinct */
	if (st.n)
		qsort(st.v, (size_t)st.n, sizeof *st.v, kof_cmp_u64);
	for (i = k = 0; i < st.n; i++)
		if (!k || st.v[i] != st.v[k - 1])
			st.v[k++] = st.v[i];
	st.n = k;
	g->start = st.v; g->n_start = (uint32_t)st.n;
	g->from = fr.v; g->to = to.v; g->n_edge = (uint32_t)fr.n;
	g->bytes = charged;
	/* KNOWN DEFECT WP9-F14 (2026-10-25, M) [sev L]: the bsketch builder publishes start/from/to with n_start >
	 * 0 before reached is allocated, and on a refused allocation sets status NOMEM and returns with reached
	 * NULL. Trigger: that calloc/malloc refused (fnprint is off the scan path). Effect: a reader of reached[i]
	 * faults (UBSAN null load). Reproducer: fuzz diag/fnprint_bytes (failk); tests_wp9/findings/F14_note.txt.
	 * Fix: allocate reached before publishing start/from/to, or on failure free them and zero n_start/n_edge. */
	g->reached = calloc(g->n_start ? g->n_start : 1u, 1);
	stk = malloc((g->n_start ? g->n_start : 1u) * sizeof *stk);
	if (!g->reached || !stk) {
		g->status = KGENOME_NOMEM;
		free(stk);
		return;
	}
	if (root != KGENOME_BROKEN && (j = kgenome_fnprint_bsketch_find(g, root)) != UINT32_MAX) {
		g->reached[j] = 1;
		stk[sp++] = j;
	}
	while (sp) {
		uint64_t a, b, e0, e1;

		j = stk[--sp];
		a = g->start[j];
		b = j + 1u < g->n_start ? g->start[j + 1u] : hi;
		/* the edges whose origin lies in [a, b) */
		e0 = 0; e1 = g->n_edge;
		while (e0 < e1) { w = e0 + (e1 - e0) / 2u; if (g->from[w] < a) e0 = w + 1u; else e1 = w; }
		for (; e0 < g->n_edge && g->from[e0] < b; e0++) {
			uint32_t t = kgenome_fnprint_bsketch_find(g, g->to[e0]);

			if (t != UINT32_MAX && !g->reached[t]) {
				g->reached[t] = 1;
				stk[sp++] = t;
			}
		}
	}
	for (j = 0; j < g->n_start; j++)
		g->n_reached += g->reached[j];
	free(stk);
	return;
over:
	g->status = KGENOME_OVER_BUDGET;     /* the sketch is incomplete and says so: no edge is claimed absent */
	free(st.v); free(fr.v); free(to.v);
	if (led)
		kgenome_ledger_release(led, charged);
	g->bytes = 0;
}
