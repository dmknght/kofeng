/*
 * fnprint_reach.c - who calls whom, for the stretch of an object between the
 * entry and the frontier.
 *
 * WHY. A pass in address order decides a function when it reaches it, and the
 * only thing it knows is where the function lies. In a gcc/ld link the program's
 * code lies between the entry stub and the C runtime's start (static) or after the
 * startup helpers (dynamic) - but "between" includes code that is not the
 * program's: the four crtbegin helpers behind `_start`, and in a static link the
 * static functions of libc-start.o that lie before `__libc_start_main` (measured:
 * 13 functions and 7 KiB for a hello-world, more than main itself). Layout alone
 * cannot tell them from the program's own helpers; a direct call chain from main
 * can: the program reaches its own code, nothing the program calls reaches the
 * runtime's start-up code.
 *
 * WHAT IS AN EDGE. A direct call, a direct jump or a conditional jump that leaves
 * its function (a tail call, a cold part), and an address of a code location taken
 * by the code (lea reg,[rip+x]; mov reg,imm; push imm: a handler handed to
 * signal(), a callback). An edge counts when it lands exactly on the start of a
 * held record. NOT an edge: a function pointer stored in a data table (no data
 * is read here), an indirect call or jump. A function only a data table names is
 * therefore not reached; it is still the program's when it lies between two
 * reached functions (ISLAND), and unreached outside them it is startup code.
 *
 * WHAT IS DECIDED. Reached -> AUTHOR. Not reached, between the first and the
 * last reached function -> AUTHOR (island). Not reached before the first reached
 * function (the crt helpers) -> LIB. Not reached after the last: LIB when the
 * runtime follows the program in the file (static), kept AUTHOR when it does not
 * (dynamic: the libraries are not in the file). No function reached at all: LIB
 * (static) / UNKNOWN (dynamic: startup code and a program that reaches its code
 * only through pointers look the same). Functions a name, a known-library
 * fingerprint, a wrapper or a thunk already called LIB keep that, and a name that
 * says author keeps that.
 *
 * COST. The records and edges of the stretch are held until it is decided: the
 * memory grows with the stretch (the program plus the runtime start-up), not with
 * the object; it is charged to the ledger; when a charge or an allocation is
 * refused the pass falls back to the layout rule for the rest and says so
 * (stat.n_region_over).
 */
#include "fnprint_private.h"

#include <stdlib.h>
#include <string.h>

void kgenome_fnprint_reach_free(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led)
{
	if (led)
		kgenome_ledger_release(led, r->charged);
	free(r->v);
	free(r->e);
	memset(r, 0, sizeof *r);
}

void kgenome_fnprint_reach_reset(struct kgenome_fnprint_reach *r)
{
	r->n = 0;
	r->ne = 0;
	r->root_ne = 0;
	r->have_root = 0;
}

static int grow_e(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led)
{
	uint32_t ncap = r->ecap ? r->ecap * 2u : 1024u;
	uint64_t add = (uint64_t)(ncap - r->ecap) * sizeof *r->e;
	uint64_t *nv;

	if (ncap < r->ecap || (led && !kgenome_ledger_charge(led, add)))
		return 0;
	nv = realloc(r->e, (size_t)ncap * sizeof *r->e);
	if (!nv) {
		if (led)
			kgenome_ledger_release(led, add);
		return 0;
	}
	r->e = nv;
	r->ecap = ncap;
	r->charged += add;
	return 1;
}

int kgenome_fnprint_reach_edge(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led, uint64_t off)
{
	if (r->failed)
		return 0;
	if (r->ne == r->ecap && !grow_e(r, led)) {
		r->failed = 1;
		return 0;
	}
	r->e[r->ne++] = off;
	return 1;
}

int kgenome_fnprint_reach_hold(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led,
			       const struct kgenome_fnprint_fn *f, uint32_t e0, uint32_t ne)
{
	if (r->failed)
		return 0;
	if (r->max && r->n >= r->max) {         /* the cost bound: decided by the layout rule from here, and said so */
		r->failed = 1;
		return 0;
	}
	if (r->n == r->cap) {
		uint32_t ncap = r->cap ? r->cap * 2u : 256u;
		uint64_t add = (uint64_t)(ncap - r->cap) * sizeof *r->v;
		struct kgenome_fnprint_rfn *nv;

		if (ncap < r->cap || (led && !kgenome_ledger_charge(led, add))) {
			r->failed = 1;
			return 0;
		}
		nv = realloc(r->v, (size_t)ncap * sizeof *r->v);
		if (!nv) {
			if (led)
				kgenome_ledger_release(led, add);
			r->failed = 1;
			return 0;
		}
		r->v = nv;
		r->cap = ncap;
		r->charged += add;
	}
	r->v[r->n].f = *f;
	r->v[r->n].e0 = e0;
	r->v[r->n].ne = ne;
	r->v[r->n].reached = 0;
	r->n++;
	return 1;
}

/* The held record that starts exactly at `off`, or UINT32_MAX. Records ascend by offset. */
static uint32_t find_start(const struct kgenome_fnprint_reach *r, uint64_t off)
{
	uint32_t lo = 0, hi = r->n;

	while (lo < hi) {
		uint32_t m = lo + (hi - lo) / 2u;

		if (r->v[m].f.off < off)
			lo = m + 1u;
		else
			hi = m;
	}
	return lo < r->n && r->v[lo].f.off == off ? lo : UINT32_MAX;
}

/* Mark what `from`'s edges land on; push the new ones on the stack. Returns the new stack depth. */
static uint32_t visit_edges(struct kgenome_fnprint_reach *r, uint32_t e0, uint32_t ne, uint32_t *stk, uint32_t sp)
{
	uint32_t k;

	for (k = 0; k < ne; k++) {
		uint32_t t = find_start(r, r->e[e0 + k]);

		if (t != UINT32_MAX && !r->v[t].reached) {
			r->v[t].reached = 1;
			stk[sp++] = t;
		}
	}
	return sp;
}

static uint32_t closure(struct kgenome_fnprint_reach *r, uint32_t *stk)
{
	uint32_t sp = 0, i, n_reached = 0;

	for (i = 0; i < r->n; i++)
		if (r->v[i].f.reason & KGENOME_FNP_R_MAIN) {
			r->v[i].reached = 1;
			stk[sp++] = i;
		}
	if (r->have_root)
		sp = visit_edges(r, r->root_e0, r->root_ne, stk, sp);
	while (sp) {
		uint32_t i2 = stk[--sp];

		sp = visit_edges(r, r->v[i2].e0, r->v[i2].ne, stk, sp);
	}
	for (i = 0; i < r->n; i++)
		n_reached += r->v[i].reached;
	return n_reached;
}

/* Does the layout rule's provisional AUTHOR stand to be reconsidered? */
static int reconsider(const struct kgenome_fnprint_fn *f)
{
	return f->cls == KGENOME_FNP_AUTHOR && !(f->reason & (KGENOME_FNP_R_MAIN | KGENOME_FNP_R_NAME_AUTHOR)) &&
	       (f->reason & (KGENOME_FNP_R_BELOW | KGENOME_FNP_R_DYNAMIC));
}

static void set_class(struct kgenome_fnprint_rfn *x, const struct kgenome_fnprint_opts *o, uint8_t cls, uint32_t why,
		      struct kgenome_fnprint_stat *sx)
{
	struct kgenome_fnprint_fn *f = &x->f;

	f->cls = cls;
	f->reason |= why;
	f->weight = (f->reason & (KGENOME_FNP_R_TINY | KGENOME_FNP_R_UNDECODED | KGENOME_FNP_R_OVERLAP))
		    ? 0 : kgenome_fnprint_weight(o, f->cls, f->n_insn);
	if (why == KGENOME_FNP_R_REACHED)
		sx->n_reached++;
	else if (why == KGENOME_FNP_R_ISLAND)
		sx->n_island++;
}

void kgenome_fnprint_reach_resolve(struct kgenome_fnprint_reach *r, const struct kgenome_fnprint_req *rq,
				   const struct kgenome_fnprint_opts *o, struct kgenome_fnprint_stat *sx)
{
	uint32_t *stk, i, lo = UINT32_MAX, hi = 0;
	int dynamic = rq->link == KGENOME_FNP_LINK_DYNAMIC;

	if (!r->n)
		return;
	stk = malloc((size_t)r->n * sizeof *stk);
	if (!stk || r->failed) {
		/* nothing to decide with: the layout rule stands, and the stat says it did */
		sx->n_region_over += r->n;
		free(stk);
		return;
	}
	if (!closure(r, stk))
		lo = UINT32_MAX;
	for (i = 0; i < r->n; i++)
		if (r->v[i].reached && !(r->v[i].f.reason & KGENOME_FNP_R_MAIN)) {
			if (lo == UINT32_MAX)
				lo = i;
			hi = i;
		}
	for (i = 0; i < r->n; i++) {
		struct kgenome_fnprint_rfn *x = &r->v[i];

		if (!reconsider(&x->f))
			continue;
		if (x->reached)
			set_class(x, o, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_REACHED, sx);
		else if (lo != UINT32_MAX && i > lo && i < hi)
			set_class(x, o, KGENOME_FNP_AUTHOR, KGENOME_FNP_R_ISLAND, sx);
		else if (lo != UINT32_MAX && i < lo)
			set_class(x, o, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED, sx);
		else if (!dynamic)
			set_class(x, o, KGENOME_FNP_LIB, KGENOME_FNP_R_UNREACHED, sx);
		else if (lo == UINT32_MAX)
			set_class(x, o, KGENOME_FNP_UNKNOWN, KGENOME_FNP_R_UNREACHED, sx);
		/* dynamic, behind the last reached function: the program's, as before */
	}
	free(stk);
}
