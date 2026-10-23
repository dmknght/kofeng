/*
 * diag_match_index - the matcher (detectors/linkage/kofdiag.c) against the reading of it that asks every node of the object about every spec, written here.
 *
 * The matcher finds the children of a bound node through an index of what points at it (succ_idx) instead of reading every node for each spec. What it must keep is the
 * answer of the full reading: whether a diagnose is there, and WHICH nodes it bound - the first instance in node order, with the backtracking over the roots that the
 * full reading does. The reference below is that reading: for each spec under a bound parent, every node in ascending order that passes spec_ok and linked.
 *
 * RANDOM GRAPHS AND DIAGNOSES, from small alphabets so that matches are common: nodes of 9 capabilities (with the generic pairs net-read/mem-read, read/mem-read,
 * write/mem-write, alloc-exec/alloc, so that a rule naming the generic word accepts the specific node), flags, the bits that exclude a node (ARG_UNKNOWN, SUPERSEDED), a stack region,
 * a literal value; 0 to 4 inputs from any node (earlier, later, itself), the stack, none, the same parent twice, with roles and both kinds. Diagnoses of 1 to 6 specs in a tree
 * whose parents are earlier specs (a chain, a fan, a diamond of two children on one parent), with roles, kinds and values demanded or not. 40,000 cases of up to 150 nodes.
 *
 * usage: diag_match_index [cases]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include <kofmod/kofdiagtree.h>
#include <phenotype/diag_scan_state.h>
#include <celllysis/nucleo.h>
#include <phenotype/diag_vocab.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/*
 * ALLOCATION REFUSED, on glibc: calloc and malloc are interposed (the executable's own definitions win over libc's, which they call through) and the Nth allocation
 * after arming says no. The index is built with four allocations and any of them may fail; the matcher must then answer from the full reading, the same
 * bindings. Skipped, and says so, elsewhere and under AddressSanitizer (which interposes the allocator itself).
 */
#if defined(__GLIBC__) && !defined(__SANITIZE_ADDRESS__)
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_malloc(size_t);

static int fail_at;     /* 0: never; n: the nth allocation from now fails */
static int allocs;      /* how many allocations were asked since the last arm */

void *calloc(size_t a, size_t b)
{
	allocs++;
	if (fail_at && allocs == fail_at)
		return NULL;
	return __libc_calloc(a, b);
}

/* malloc'd memory comes back filled with 0xa5: an entry a build left unwritten reads as node 42405, past every graph here, instead of whatever the heap held */
void *malloc(size_t n)
{
	void *p;

	allocs++;
	if (fail_at && allocs == fail_at)
		return NULL;
	p = __libc_malloc(n);
	if (p)
		memset(p, 0xa5, n);
	return p;
}
#define HAVE_INTERPOSE 1
#endif

static uint32_t rs = 424242u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 8;
}

static const uint16_t CAPS[] = {
	KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ALLOC_EXEC, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_READ,
	KGENOME_NUCLEO_WRITE, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_HEAP
};
#define NCAP (sizeof CAPS / sizeof CAPS[0])

/* ---- the reference: the full reading ---- */
static int ref_spec_ok(const struct kgenome_diag_hit *h, const struct kof_diag_node *sp)
{
	if (h->cap != sp->cap) {
		uint16_t g = h->cap;
		int kind = 0;

		while ((g = kgenome_nucleo_cap_generic(g)) != KGENOME_NUCLEO_NONE)
			if (g == sp->cap) { kind = 1; break; }
		if (!kind)
			return 0;
	}
	if ((h->flags & sp->flags) != sp->flags)
		return 0;
	if (h->bits & (KGENOME_DIAG_H_ARG_UNKNOWN | KGENOME_DIAG_H_SUPERSEDED))
		return 0;
	if (sp->bits & KOF_DIAG_B_VAL)
		if (!(h->bits & KGENOME_DIAG_H_VAL) || h->val != sp->val)
			return 0;
	return 1;
}

static int ref_linked(const struct kgenome_diag_hit *child, uint16_t parent_idx, const struct kgenome_diag_hit *parent, uint8_t role, uint8_t want)
{
	uint8_t i;

	want &= (uint8_t)(KOF_DIAG_B_PRODUCED | KOF_DIAG_B_SHARED);
	for (i = 0; i < child->n_in; i++) {
		if (role != KGENOME_DIAG_ROLE_NONE && child->in[i].role != role)
			continue;
		if (want) {
			uint8_t is = child->in[i].kind == KGENOME_DIAG_KIND_SHARED ? (uint8_t)KOF_DIAG_B_SHARED : (uint8_t)KOF_DIAG_B_PRODUCED;

			if (!(want & is))
				continue;
		}
		if (child->in[i].from == parent_idx)
			return 1;
		if (child->in[i].from == KGENOME_DIAG_FROM_STACK && (parent->bits & KGENOME_DIAG_H_REGION_STACK))
			return 1;
	}
	return 0;
}

static int ref_bind(const struct kgenome_diag_scan *s, const struct kof_diag *d, uint8_t k, uint16_t *bound)
{
	uint8_t c;
	uint32_t i;

	for (c = 0; c < d->n_node; c++) {
		if (d->node[c].parent != k)
			continue;
		for (i = 0; i < s->n_hit; i++) {
			if (!ref_spec_ok(&s->hit[i], &d->node[c]))
				continue;
			if (!ref_linked(&s->hit[i], bound[k], &s->hit[bound[k]], d->node[c].role, d->node[c].bits))
				continue;
			bound[c] = (uint16_t)i;
			if (ref_bind(s, d, c, bound))
				goto next;
		}
		return 0;
next:
		;
	}
	return 1;
}

static int ref_first(const struct kgenome_diag_scan *s, const struct kof_diag *d, uint16_t *out)
{
	uint16_t bound[256];
	uint32_t i;

	for (i = 0; i < s->n_hit; i++) {
		if (!ref_spec_ok(&s->hit[i], &d->node[0]))
			continue;
		memset(bound, 0xff, sizeof bound);
		bound[0] = (uint16_t)i;
		if (!ref_bind(s, d, 0, bound))
			continue;
		memcpy(out, bound, d->n_node * sizeof *out);
		return 1;
	}
	return 0;
}

/* ---- the value-flow join, against reachability computed here: an input from a node is an edge parent -> here, except the BUFFER role, which is here -> parent ---- */
static int ref_reach(const struct kgenome_diag_scan *s, uint16_t cap, const uint16_t *a, uint8_t na, const uint16_t *b, uint8_t nb)
{
	static uint8_t flow[160][160], seen[160];
	uint32_t i, k, u, v, x, changed;

	memset(flow, 0, sizeof flow);
	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < s->hit[i].n_in; k++) {
			uint16_t p = s->hit[i].in[k].from;

			if (p >= s->n_hit)
				continue;
			if (s->hit[i].in[k].role == KGENOME_DIAG_ROLE_BUFFER)
				flow[i][p] = 1;
			else
				flow[p][i] = 1;
		}
	for (x = 0; x < nb; x++) {
		if (b[x] >= s->n_hit || s->hit[b[x]].cap != cap)
			continue;
		memset(seen, 0, sizeof seen);
		seen[b[x]] = 1;
		do {
			changed = 0;
			for (u = 0; u < s->n_hit; u++)
				if (seen[u])
					for (v = 0; v < s->n_hit; v++)
						if (flow[u][v] && !seen[v]) {
							seen[v] = 1;
							changed = 1;
						}
		} while (changed);
		/* the start counts only through an edge: a node bound by both is not reached by itself unless a path leads back to it, but a target that IS the start is */
		for (k = 0; k < na; k++)
			if (a[k] < s->n_hit && seen[a[k]])
				return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int cases = argc > 1 ? atoi(argv[1]) : 40000, r;
	unsigned long found = 0, deep = 0, stack_hits = 0, generic_hits = 0, refused_runs = 0, allocs_seen = 0, joins = 0, joined = 0;
	static struct kgenome_diag_hit hit[160];
	struct kgenome_diag_scan s;

	for (r = 0; r < cases; r++) {
		uint32_t n = 1u + rnd() % 150u, i, nn = 1u + rnd() % 6u, k;
		struct kof_diag_node node[6];
		struct kof_diag d;
		uint16_t got[256], want[256];
		uint8_t nb = 0;
		int fa, fb;

		memset(hit, 0, sizeof hit);
		for (i = 0; i < n; i++) {
			struct kgenome_diag_hit *h = &hit[i];
			uint32_t ni = rnd() % 5u;

			h->at = i;
			h->cap = CAPS[rnd() % NCAP];
			h->flags = (uint16_t)(rnd() % 4u);
			if (rnd() % 8u == 0) h->bits |= KGENOME_DIAG_H_ARG_UNKNOWN;
			if (rnd() % 8u == 0) h->bits |= KGENOME_DIAG_H_SUPERSEDED;
			if (rnd() % 4u == 0) h->bits |= KGENOME_DIAG_H_REGION_STACK;
			if (rnd() % 3u == 0) { h->bits |= KGENOME_DIAG_H_VAL; h->val = rnd() % 3u; }
			h->n_in = (uint8_t)ni;
			for (k = 0; k < ni; k++) {
				uint32_t pick = rnd() % 10u;

				/* a source in the graph, itself, the one just past the end and the one after it (not nodes), the stack, none, or the same parent twice */
				h->in[k].from = pick == 0 ? (uint16_t)KGENOME_DIAG_FROM_STACK : pick == 1 ? (uint16_t)0xffffu
					      : pick == 2 ? (uint16_t)i : pick == 3 && k ? h->in[k - 1u].from
					      : pick == 4 && rnd() % 4u == 0 ? (uint16_t)(n + rnd() % 2u) : (uint16_t)(rnd() % n);
				h->in[k].role = (uint8_t)(rnd() % 4u);
				h->in[k].kind = (uint8_t)(rnd() & 1u);
			}
		}
		memset(&s, 0, sizeof s);
		s.hit = hit;
		s.n_hit = n;
		s.cap_hit = 160u;
		for (k = 0; k < nn; k++) {
			memset(&node[k], 0, sizeof node[k]);
			node[k].cap = CAPS[rnd() % NCAP];
			node[k].flags = (uint16_t)(rnd() % 3u);
			node[k].parent = k ? (uint8_t)(rnd() % k) : (uint8_t)KOF_DIAG_NO_PARENT;
			node[k].role = (uint8_t)(rnd() % 4u);
			if (rnd() % 3u == 0) node[k].bits |= KOF_DIAG_B_PRODUCED;
			if (rnd() % 3u == 0) node[k].bits |= KOF_DIAG_B_SHARED;
			if (rnd() % 6u == 0) { node[k].bits |= KOF_DIAG_B_VAL; node[k].val = rnd() % 3u; }
		}
		memset(&d, 0, sizeof d);
		d.n_node = (uint8_t)nn;
		d.node = node;
		d.name = "t";
		memset(got, 0xee, sizeof got);
		memset(want, 0xee, sizeof want);
		/* the join: random bound sets over the same graph (the nodes of cap CAPS[0], reached from the b set, among the a set) */
		{
			uint16_t ab[8], bb[8];
			uint8_t na = (uint8_t)(rnd() % 5u), nbb = (uint8_t)(rnd() % 5u), q;
			uint16_t jcap = CAPS[rnd() % NCAP];

			for (q = 0; q < na; q++)
				ab[q] = (uint16_t)(rnd() % (n + 1u));      /* one past the end too: not a node, and ignored */
			for (q = 0; q < nbb; q++)
				bb[q] = (uint16_t)(rnd() % (n + 1u));
			joins++;
			CK((kof_diag_flow_join(&s, jcap, ab, na, bb, nbb) != 0) == (ref_reach(&s, jcap, ab, na, bb, nbb) != 0));
			joined += kof_diag_flow_join(&s, jcap, ab, na, bb, nbb) != 0;
		}
		fa = ref_first(&s, &d, want);
#ifdef HAVE_INTERPOSE
		allocs = 0;
		fail_at = 0;
#endif
		fb = kof_diag_match(&s, &d, got, &nb);
#ifdef HAVE_INTERPOSE
		allocs_seen += (unsigned long)allocs;
		if (allocs && r % 8 == 0) {
			int a, na = allocs;

			for (a = 1; a <= na; a++) {
				uint16_t g2[256];
				uint8_t nb2 = 0;

				memset(g2, 0xee, sizeof g2);
				allocs = 0;
				fail_at = a;
				CK(kof_diag_match(&s, &d, g2, &nb2) == fa);
				fail_at = 0;
				if (fa)
					CK(nb2 == nn && memcmp(g2, want, nn * sizeof *g2) == 0);
				refused_runs++;
			}
		}
#endif
		CK(fa == fb);
		if (fa && fb) {
			CK(nb == nn);
			CK(memcmp(got, want, nn * sizeof *got) == 0);
			found++;
			deep += nn > 2u;
			for (k = 0; k < nn; k++) {
				stack_hits += (hit[want[k]].bits & KGENOME_DIAG_H_REGION_STACK) != 0;
				generic_hits += hit[want[k]].cap != node[k].cap;
			}
		}
		if (fails) {
			printf("  case %d: n=%u nn=%u ref %d got %d\n", r, n, nn, fa, fb);
			return 1;
		}
	}
	/* the cases must exercise what the index is for, whatever number was asked: a run that found next to nothing proves nothing */
	CK(found > (unsigned long)cases / 40u);
	CK(deep > (unsigned long)cases / 160u);
	CK(stack_hits > (unsigned long)cases / 400u);
	CK(generic_hits > (unsigned long)cases / 400u);
	CK(joined > joins / 20u && joined < joins);      /* reachable in some cases and not in others */
#ifdef HAVE_INTERPOSE
	CK(refused_runs > (unsigned long)cases / 100u);
	CK(allocs_seen > 0);
#else
	printf("diag_match_index: allocation-refused group skipped (not glibc, or sanitised)\n");
#endif
	(void)refused_runs;
	(void)allocs_seen;
	printf("diag_match_index: %d cases, %lu found (%lu with 3+ specs, %lu binds on a stack-region parent, %lu on a generic word), %s\n", cases, found, deep, stack_hits, generic_hits, fails ? "FAILED" : "ok");
	return fails != 0;
}
