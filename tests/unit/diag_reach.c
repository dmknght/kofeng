/*
 * diag_reach - a diagnose link through nodes in between, and a diagnose of two blocks that meet (2026-11-14).
 *
 * Owner: "a link must survive an intermediate wrapper and an intermediate call node" (an earlier rule), and "two chosen links
 * that meet through one node: the signature must be able to state that node as required". The matcher linked a child to its
 * parent only when an input named the parent's node directly (DL-1); this pins the reached tier that replaced it, the edges it
 * may walk (kofdiag.c, "A LINK THROUGH NODES IN BETWEEN"), its work bound (UNKNOWN, never a wrong no), and the two-block
 * diagnose (KOF_DIAG_B_JOIN) with its loader rules. Also DL-2 (the join compared a capability for equality) and DL-3 (a parent
 * cycle was loaded and its nodes silently never bound).
 *
 * Every graph is built here by hand, node by node and link by link - the shape is the statement, no sample is needed.
 * Why the old tests missed DL-1: (b) every graph they built linked a tail to its head in one hop; the multi-hop shape was
 * never an input. DL-2: (b) every join test named the hit's exact word. DL-3: (b) no record with a parent cycle was built
 * (the fuzz's parents are always earlier nodes).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/databases/diagsrc.h"
#include <phenotype/diag_private.h>
#include "../../libkofeng/kofcore/kofmod/kofcap.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, \
	__LINE__, #c); fails++; } } while (0)

#define NMAX 6000u
static struct kgenome_diag_hit hits[NMAX];
static struct kgenome_diag_scan s;

static void reset(void)
{
	free(s.adj_head);
	free(s.adj_edge);
	memset(hits, 0, sizeof hits);
	memset(&s, 0, sizeof s);
	s.hit = hits;
	s.cap_hit = NMAX;
}

static uint16_t nd(uint16_t cap)
{
	kgenome_diag_hit_add(&s, 0x1000u + s.n_hit * 0x10u, cap, 0);
	return (uint16_t)(s.n_hit - 1u);
}

static void edge_k(uint16_t node, uint16_t from, uint8_t role, uint8_t kind)
{
	kgenome_diag_note_in(&s, kgenome_diag_hit_of(&s, node), from, role, kind);
}

static void edge(uint16_t node, uint16_t from, uint8_t role)
{
	edge_k(node, from, role, KGENOME_DIAG_KIND_PRODUCED);
}

/* A star diagnose as the builder writes it: the head, then tails that name no role (the record's role is 0). */
static struct kof_diag_node spec[8];
static struct kof_diag dg;

static void star(uint16_t head, uint16_t head_flags, const uint16_t *tail, uint8_t n_tail, const uint8_t *tail_bits)
{
	uint8_t k;

	memset(spec, 0, sizeof spec);
	spec[0].cap = head;
	spec[0].flags = head_flags;
	spec[0].parent = KOF_DIAG_NO_PARENT;
	for (k = 0; k < n_tail; k++) {
		spec[k + 1u].cap = tail[k];
		spec[k + 1u].parent = 0;
		spec[k + 1u].bits = tail_bits ? tail_bits[k] : 0;
	}
	memset(&dg, 0, sizeof dg);
	dg.id = 1;
	dg.analysis = KOF_DIAG_ANALYSIS_SYSCALL;
	dg.n_node = (uint8_t)(n_tail + 1u);
	dg.name = "t";
	dg.node = spec;
}

static void rwx_star(void)
{
	static const uint16_t t[] = { KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_EXEC_REG };

	star(KGENOME_NUCLEO_ALLOC_EXEC, 0, t, 2, NULL);
}

/* The value-flow graph is a product of the scan, built once (kofdiag.c diag_flow_build); a test that adds nodes to a scan
 * it already matched gives the old graph back first. */
static void regraph(void)
{
	free(s.adj_head);
	free(s.adj_edge);
	s.adj_head = NULL;
	s.adj_edge = NULL;
	s.adj_built = 0;
}

static int known(uint16_t *bind, uint8_t *nb)
{
	regraph();
	return kof_diag_match_known(&s, &dg, bind, nb);
}

/* ---- A: through nodes in between ---- */
static void reach_cases(void)
{
	uint16_t b[8];
	uint8_t nb = 0;

	/* 1. A WRAPPER HANDS THE POINTER ON: mmap -> my_alloc returns it -> read into it, jump to it. Red before: no input of the read
	 * or the jump names the mmap. */
	{
		uint16_t m, w, r, e;

		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		w = nd(KGENOME_NUCLEO_DYNCALL);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(w, m, KGENOME_DIAG_ROLE_VALUE);
		edge(r, w, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, w, KGENOME_DIAG_ROLE_TARGET);
		rwx_star();
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES);
		CK(nb == 3 && b[0] == m && b[1] == r && b[2] == e);
	}
	/* 2. A CALL NODE PASSES THE VALUE ON: decode -> a call that hands it on -> eval. */
	{
		uint16_t d, c, v;
		static const uint16_t t[] = { KGENOME_NUCLEO_EVAL };

		reset();
		d = nd(KGENOME_NUCLEO_DECODE);
		c = nd(KGENOME_NUCLEO_DYNCALL);
		v = nd(KGENOME_NUCLEO_EVAL);
		edge(c, d, KGENOME_DIAG_ROLE_VALUE);
		edge(v, c, KGENOME_DIAG_ROLE_VALUE);
		star(KGENOME_NUCLEO_DECODE, 0, t, 1, NULL);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[0] == d && b[1] == v);
		/* two calls in between */
		{
			uint16_t c2, v2;

			reset();
			d = nd(KGENOME_NUCLEO_DECODE);
			c = nd(KGENOME_NUCLEO_DYNCALL);
			c2 = nd(KGENOME_NUCLEO_DYNCALL);
			v2 = nd(KGENOME_NUCLEO_EVAL);
			edge(c, d, KGENOME_DIAG_ROLE_VALUE);
			edge(c2, c, KGENOME_DIAG_ROLE_VALUE);
			edge(v2, c2, KGENOME_DIAG_ROLE_VALUE);
			CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == v2);
		}
	}
	/* 3. A COPY IN BETWEEN: a read into a scratch buffer, a copy of it into the region, a jump to the region. The jump runs what
	 * the read produced (its input is TARGET: it consumes the region, so a written-into edge counts). */
	{
		uint16_t h, r, g, c, e;
		static const uint16_t t[] = { KGENOME_NUCLEO_EXEC_REG };

		reset();
		h = nd(KGENOME_NUCLEO_HEAP);
		r = nd(KGENOME_NUCLEO_NET_READ);
		g = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		c = nd(KGENOME_NUCLEO_MEM_WRITE);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(r, h, KGENOME_DIAG_ROLE_BUFFER);
		edge(c, h, KGENOME_DIAG_ROLE_SOURCE);
		edge(c, g, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, g, KGENOME_DIAG_ROLE_TARGET);
		star(KGENOME_NUCLEO_NET_READ, 0, t, 1, NULL);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[0] == r && b[1] == e);
		/* 4. ... and NOT when the copy reads another buffer: the bytes run never came off the read. */
		reset();
		h = nd(KGENOME_NUCLEO_HEAP);
		(void)nd(KGENOME_NUCLEO_HEAP);
		r = nd(KGENOME_NUCLEO_NET_READ);
		g = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		c = nd(KGENOME_NUCLEO_MEM_WRITE);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(r, h, KGENOME_DIAG_ROLE_BUFFER);
		edge(c, (uint16_t)(h + 1u), KGENOME_DIAG_ROLE_SOURCE);
		edge(c, g, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, g, KGENOME_DIAG_ROLE_TARGET);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
	}
	/* 5. A CHILD THAT WRITES THROUGH A POINTER needs the POINTER from the parent: a second read into the region a first read
	 * filled is not linked to the first (the region holds its bytes, its pointer is the region's). */
	{
		uint16_t g, r, r2;
		static const uint16_t t[] = { KGENOME_NUCLEO_MEM_READ };

		reset();
		g = nd(KGENOME_NUCLEO_ALLOC);
		r = nd(KGENOME_NUCLEO_NET_READ);
		r2 = nd(KGENOME_NUCLEO_READ);
		edge(r, g, KGENOME_DIAG_ROLE_BUFFER);
		edge(r2, g, KGENOME_DIAG_ROLE_BUFFER);
		star(KGENOME_NUCLEO_NET_READ, 0, t, 1, NULL);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		(void)r2;
	}
	/* 6. A CYCLE ON THE WAY: mmap -> a <-> b -> jump. Walked once each, and found; and without the jump, a clean no. */
	{
		uint16_t m, a, c, r, e;

		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		a = nd(KGENOME_NUCLEO_DYNCALL);
		c = nd(KGENOME_NUCLEO_DYNCALL);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(a, m, KGENOME_DIAG_ROLE_VALUE);
		edge(a, c, KGENOME_DIAG_ROLE_SOURCE);
		edge(c, a, KGENOME_DIAG_ROLE_VALUE);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, c, KGENOME_DIAG_ROLE_TARGET);
		rwx_star();
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[2] == e);
		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		a = nd(KGENOME_NUCLEO_DYNCALL);
		c = nd(KGENOME_NUCLEO_DYNCALL);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(a, m, KGENOME_DIAG_ROLE_VALUE);
		edge(a, c, KGENOME_DIAG_ROLE_SOURCE);
		edge(c, a, KGENOME_DIAG_ROLE_VALUE);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, nd(KGENOME_NUCLEO_ALLOC_EXEC), KGENOME_DIAG_ROLE_TARGET);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
	}
	/* 6b. NOT THROUGH A NAME: the request names a file, a constant is written to it (fopen($_GET['p']) ; fwrite($h, 'x')): the
	 * write is not linked to the request - through a PATH input, nor through one the route left unclassified (NONE, as the
	 * text route records fopen's). A request decoded and then opened as a path is (the PATH is the last hop). */
	{
		uint16_t q, o, w, d, o2;
		static const uint16_t tw[] = { KGENOME_NUCLEO_WRITE };
		static const uint16_t to[] = { KGENOME_NUCLEO_FILE_OPEN };

		reset();
		q = nd(KGENOME_NUCLEO_REQUEST);
		o = nd(KGENOME_NUCLEO_FILE_OPEN);
		w = nd(KGENOME_NUCLEO_WRITE);
		edge(o, q, KGENOME_DIAG_ROLE_PATH);
		edge(w, o, KGENOME_DIAG_ROLE_FD);
		star(KGENOME_NUCLEO_REQUEST, 0, tw, 1, NULL);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		reset();
		q = nd(KGENOME_NUCLEO_REQUEST);
		o = nd(KGENOME_NUCLEO_FILE_OPEN);
		w = nd(KGENOME_NUCLEO_WRITE);
		edge(o, q, KGENOME_DIAG_ROLE_NONE);
		edge(w, o, KGENOME_DIAG_ROLE_FD);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		reset();
		q = nd(KGENOME_NUCLEO_REQUEST);
		d = nd(KGENOME_NUCLEO_DECODE);
		o2 = nd(KGENOME_NUCLEO_FILE_OPEN);
		edge(d, q, KGENOME_DIAG_ROLE_VALUE);
		edge(o2, d, KGENOME_DIAG_ROLE_PATH);
		star(KGENOME_NUCLEO_REQUEST, 0, to, 1, NULL);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == o2);
		(void)w;
	}
	/* 6c. THE REACHED CANDIDATES ARE TRIED IN NODE ORDER, as the direct ones are, whatever order the walk reached them in: the
	 * jump two hops away (lower index) before the one a hop away (higher index) - the first that binds is the lowest node. */
	{
		uint16_t m, a, c, e_far, e_near;
		static const uint16_t t[] = { KGENOME_NUCLEO_EXEC_REG };

		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		a = nd(KGENOME_NUCLEO_DYNCALL);
		c = nd(KGENOME_NUCLEO_DYNCALL);
		e_far = nd(KGENOME_NUCLEO_EXEC_REG);
		e_near = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(a, m, KGENOME_DIAG_ROLE_VALUE);
		edge(c, a, KGENOME_DIAG_ROLE_VALUE);
		edge(e_far, c, KGENOME_DIAG_ROLE_TARGET);
		edge(e_near, a, KGENOME_DIAG_ROLE_TARGET);
		star(KGENOME_NUCLEO_ALLOC_EXEC, 0, t, 1, NULL);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == e_far);
		(void)e_near;
	}
	/* 7. THE DIRECT TIER FIRST: a tail with a direct candidate (higher index) and a reached one (lower index) binds the direct one,
	 * as the matcher always did. */
	{
		uint16_t m, w, e_reach, r, e_direct;

		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		w = nd(KGENOME_NUCLEO_DYNCALL);
		e_reach = nd(KGENOME_NUCLEO_EXEC_REG);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e_direct = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(w, m, KGENOME_DIAG_ROLE_VALUE);
		edge(e_reach, w, KGENOME_DIAG_ROLE_TARGET);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e_direct, m, KGENOME_DIAG_ROLE_TARGET);
		rwx_star();
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == r && b[2] == e_direct);
		(void)e_reach;
	}
	/* 8. THE KIND: SHARED is "the same object", which a produced hop breaks; PRODUCED is the child's own input (the last hop);
	 * either names an object, which travels on value edges only (8b). */
	{
		uint16_t m, x, t;
		static const uint16_t tc[] = { KGENOME_NUCLEO_MEM_WRITE };
		uint8_t want = KOF_DIAG_B_SHARED;

		reset();
		m = nd(KGENOME_NUCLEO_HEAP);
		x = nd(KGENOME_NUCLEO_DYNCALL);
		t = nd(KGENOME_NUCLEO_MEM_WRITE);
		edge_k(x, m, KGENOME_DIAG_ROLE_VALUE, KGENOME_DIAG_KIND_PRODUCED);
		edge_k(t, x, KGENOME_DIAG_ROLE_SOURCE, KGENOME_DIAG_KIND_SHARED);
		star(KGENOME_NUCLEO_HEAP, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		want = KOF_DIAG_B_PRODUCED;
		star(KGENOME_NUCLEO_HEAP, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);           /* the last hop is SHARED */
		want = 0;
		star(KGENOME_NUCLEO_HEAP, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES);

		reset();
		m = nd(KGENOME_NUCLEO_HEAP);
		x = nd(KGENOME_NUCLEO_DYNCALL);
		t = nd(KGENOME_NUCLEO_MEM_WRITE);
		edge_k(x, m, KGENOME_DIAG_ROLE_VALUE, KGENOME_DIAG_KIND_SHARED);
		edge_k(t, x, KGENOME_DIAG_ROLE_SOURCE, KGENOME_DIAG_KIND_SHARED);
		want = KOF_DIAG_B_SHARED;
		star(KGENOME_NUCLEO_HEAP, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == t);

		reset();
		m = nd(KGENOME_NUCLEO_HEAP);
		x = nd(KGENOME_NUCLEO_DYNCALL);
		t = nd(KGENOME_NUCLEO_MEM_WRITE);
		edge_k(x, m, KGENOME_DIAG_ROLE_VALUE, KGENOME_DIAG_KIND_SHARED);
		edge_k(t, x, KGENOME_DIAG_ROLE_SOURCE, KGENOME_DIAG_KIND_PRODUCED);
		want = KOF_DIAG_B_PRODUCED;
		star(KGENOME_NUCLEO_HEAP, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == t);
	}
	/* 8b. copy_from_user wrote into the allocation copy_to_user reads: the bytes flow (no kind named: yes), the object does not
	 * (PRODUCED named: no - the hop through the allocation is a write into it, not a value handed on). */
	{
		uint16_t h, f, t;
		static const uint16_t tc[] = { KGENOME_NUCLEO_COPY_TO_USER };
		uint8_t want = KOF_DIAG_B_PRODUCED;

		reset();
		h = nd(KGENOME_NUCLEO_HEAP);
		f = nd(KGENOME_NUCLEO_COPY_FROM_USER);
		t = nd(KGENOME_NUCLEO_COPY_TO_USER);
		edge(f, h, KGENOME_DIAG_ROLE_BUFFER);
		edge(t, h, KGENOME_DIAG_ROLE_SOURCE);
		star(KGENOME_NUCLEO_COPY_FROM_USER, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		want = 0;
		star(KGENOME_NUCLEO_COPY_FROM_USER, 0, tc, 1, &want);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[0] == f && b[1] == t);
	}
	/* 9. A ROLE THE DIAGNOSE NAMES is the child's own input (C: a BUFFER-role tail fed by the head directly was suspected not to
	 * link - it does, and through a wrapper it does too). */
	{
		uint16_t m, w, r;

		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		memset(spec, 0, sizeof spec);
		spec[0].cap = KGENOME_NUCLEO_ALLOC_EXEC;
		spec[0].parent = KOF_DIAG_NO_PARENT;
		spec[1].cap = KGENOME_NUCLEO_MEM_READ;
		spec[1].parent = 0;
		spec[1].role = KGENOME_DIAG_ROLE_BUFFER;
		dg.n_node = 2;
		dg.node = spec;
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == r);
		reset();
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		w = nd(KGENOME_NUCLEO_DYNCALL);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		edge(w, m, KGENOME_DIAG_ROLE_VALUE);
		edge(r, w, KGENOME_DIAG_ROLE_BUFFER);
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == r);
		spec[1].role = KGENOME_DIAG_ROLE_FD;            /* the read's FD is not from the region: no */
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
	}
}

/*
 * ---- the work bound: many heads, each reaching a long chain that leads nowhere the diagnose wants. 2000 heads cost far more than
 * KOF_DIAG_REACH_WALKS walks of the graph: the answer is UNKNOWN, not no. Ten heads are within it: no. And with the tail at the
 * chain's end the first head matches before the bound is near.
 */
static void bound_case(void)
{
	uint16_t b[8];
	uint8_t nb = 0;
	uint32_t i;
	uint16_t first = 0, last = 0;

	/* four heads on the chain's first node (a node keeps four inputs; a fifth would mark the scan TRUNCATED and every
	 * no an UNKNOWN for that reason): within the bound, a clean no; with the tail at the chain's end, a yes */
	for (i = 0; i < 2u; i++) {
		uint32_t heads = 4u, L = 2000u, k;

		reset();
		for (k = 0; k < L; k++) {
			uint16_t c = nd(KGENOME_NUCLEO_DYNCALL);

			if (k)
				edge(c, (uint16_t)(c - 1u), KGENOME_DIAG_ROLE_VALUE);
			else
				first = c;
			last = c;
		}
		for (k = 0; k < heads; k++)
			edge(first, nd(KGENOME_NUCLEO_ALLOC_EXEC), KGENOME_DIAG_ROLE_VALUE);
		if (i == 1u)
			edge(nd(KGENOME_NUCLEO_EXEC_REG), last, KGENOME_DIAG_ROLE_TARGET);
		{
			static const uint16_t t[] = { KGENOME_NUCLEO_EXEC_REG };

			star(KGENOME_NUCLEO_ALLOC_EXEC, 0, t, 1, NULL);
		}
		if (i == 0u)
			CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		else
			CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[0] == L);
	}
	/* every head on the chain: fan the heads over the chain's first 2000 nodes, one each, so every walk is long */
	{
		uint32_t k, L = 2000u;

		reset();
		for (k = 0; k < L; k++) {
			uint16_t c = nd(KGENOME_NUCLEO_DYNCALL);

			if (k)
				edge(c, (uint16_t)(c - 1u), KGENOME_DIAG_ROLE_VALUE);
		}
		for (k = 0; k < L; k++)
			edge((uint16_t)k, nd(KGENOME_NUCLEO_ALLOC_EXEC), KGENOME_DIAG_ROLE_SOURCE);
		CK(known(b, &nb) == KOF_DIAG_MATCH_UNKNOWN);
		regraph();
		CK(kof_diag_match(&s, &dg, b, &nb) == 0);
		/* the same graph with only the last ten heads: within the bound, a clean no */
		reset();
		for (k = 0; k < L; k++) {
			uint16_t c = nd(KGENOME_NUCLEO_DYNCALL);

			if (k)
				edge(c, (uint16_t)(c - 1u), KGENOME_DIAG_ROLE_VALUE);
		}
		for (k = L - 10u; k < L; k++)
			edge((uint16_t)k, nd(KGENOME_NUCLEO_ALLOC_EXEC), KGENOME_DIAG_ROLE_SOURCE);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		for (k = 0; k < 10u; k++)
			edge((uint16_t)k, nd(KGENOME_NUCLEO_ALLOC_EXEC), KGENOME_DIAG_ROLE_SOURCE);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);         /* ten more heads at the START walk all of the chain: still within */
	}
}

/*
 * ---- the scratch the reached tier needs is charged to the scan's ledger; refused, the answer is UNKNOWN, never no. The graph is built
 * first with room to spare (a refusal THERE marks the scan itself OVER_BUDGET, which is the scan's own limit, tested elsewhere), then the
 * ledger is left with no room. A match the direct tier finds needs no scratch and is still YES.
 */
static void two_blocks(void);

static void ledger_case(void)
{
	uint16_t b[8], m, w, r, e, ab[1] = { 0 };
	uint8_t nb = 0;

	reset();
	m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
	w = nd(KGENOME_NUCLEO_DYNCALL);
	r = nd(KGENOME_NUCLEO_MEM_READ);
	e = nd(KGENOME_NUCLEO_EXEC_REG);
	edge(w, m, KGENOME_DIAG_ROLE_VALUE);
	edge(r, w, KGENOME_DIAG_ROLE_BUFFER);
	edge(e, w, KGENOME_DIAG_ROLE_TARGET);
	rwx_star();
	(void)kof_diag_flow_join(&s, KGENOME_NUCLEO_MEM_READ, ab, 1, ab, 1);      /* the graph, built and charged */
	s.led.limit = s.led.used + 1u;
	CK(kof_diag_match_known(&s, &dg, b, &nb) == KOF_DIAG_MATCH_UNKNOWN);
	CK(kgenome_diag_scan_status(&s) == KGENOME_OK);                           /* the scan itself is whole */
	two_blocks();
	CK(kof_diag_match_known(&s, &dg, b, &nb) == KOF_DIAG_MATCH_UNKNOWN);
	/* direct links need nothing more */
	edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
	edge(e, m, KGENOME_DIAG_ROLE_TARGET);
	rwx_star();
	CK(kof_diag_match_known(&s, &dg, b, &nb) == KOF_DIAG_MATCH_YES && b[1] == r && b[2] == e);
	s.led.limit = 0;
}

/* ---- DL-2: the join reads its capability as a spec does ---- */
static void join_kind_case(void)
{
	uint16_t m, so, r, e, ab[2], bb[2];

	reset();
	m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
	so = nd(KGENOME_NUCLEO_NET_OPEN);
	r = nd(KGENOME_NUCLEO_NET_READ);        /* the run proved the descriptor a socket: net-recv, a kind of mem-read */
	e = nd(KGENOME_NUCLEO_EXEC_REG);
	edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
	edge(r, so, KGENOME_DIAG_ROLE_FD);
	edge(e, m, KGENOME_DIAG_ROLE_TARGET);
	ab[0] = m; ab[1] = e;
	bb[0] = so; bb[1] = r;
	regraph();
	CK(kof_diag_flow_join(&s, KGENOME_NUCLEO_MEM_READ, ab, 2, bb, 2) == 1);
	CK(kof_diag_flow_join(&s, KGENOME_NUCLEO_NET_READ, ab, 2, bb, 2) == 1);
	CK(kof_diag_flow_join(&s, KGENOME_NUCLEO_MEM_WRITE, ab, 2, bb, 2) == 0);
}

/* ---- B: two blocks that meet ---- */
static struct kof_diag_node two[8];

static void two_blocks(void)
{
	memset(two, 0, sizeof two);
	two[0].cap = KGENOME_NUCLEO_ALLOC_EXEC; two[0].parent = KOF_DIAG_NO_PARENT;
	two[1].cap = KGENOME_NUCLEO_MEM_READ;   two[1].parent = 0;
	two[2].cap = KGENOME_NUCLEO_EXEC_REG;   two[2].parent = 0;
	two[3].cap = KGENOME_NUCLEO_NET_OPEN;   two[3].parent = KOF_DIAG_NO_PARENT;
	two[4].cap = KGENOME_NUCLEO_NET_CONNECT; two[4].parent = 3;
	two[5].cap = KGENOME_NUCLEO_MEM_READ;   two[5].parent = 3; two[5].bits = KOF_DIAG_B_JOIN;
	memset(&dg, 0, sizeof dg);
	dg.id = 2;
	dg.analysis = KOF_DIAG_ANALYSIS_SYSCALL;
	dg.n_node = 6;
	dg.name = "stager_join";
	dg.node = two;
}

static void block_cases(void)
{
	uint16_t b[8];
	uint8_t nb = 0;

	/* The stager: the read's buffer is the W+X region and its descriptor the socket - ONE read, both blocks. */
	{
		uint16_t m, so, c, r, e;

		reset();
		so = nd(KGENOME_NUCLEO_NET_OPEN);
		c = nd(KGENOME_NUCLEO_NET_CONNECT);
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(c, so, KGENOME_DIAG_ROLE_FD);
		edge(r, so, KGENOME_DIAG_ROLE_FD);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, m, KGENOME_DIAG_ROLE_TARGET);
		two_blocks();
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES);
		CK(nb == 6 && b[0] == m && b[1] == r && b[2] == e && b[3] == so && b[4] == c && b[5] == r);
	}
	/* The decoy: a socket read into a scratch buffer, a FILE read into the region. Both blocks are there and do not meet. */
	{
		uint16_t m, so, c, f, h, r1, r2, e;

		reset();
		so = nd(KGENOME_NUCLEO_NET_OPEN);
		c = nd(KGENOME_NUCLEO_NET_CONNECT);
		f = nd(KGENOME_NUCLEO_FILE_OPEN);
		h = nd(KGENOME_NUCLEO_HEAP);
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		r1 = nd(KGENOME_NUCLEO_MEM_READ);
		r2 = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(c, so, KGENOME_DIAG_ROLE_FD);
		edge(r1, so, KGENOME_DIAG_ROLE_FD);
		edge(r1, h, KGENOME_DIAG_ROLE_BUFFER);
		edge(r2, f, KGENOME_DIAG_ROLE_FD);
		edge(r2, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, m, KGENOME_DIAG_ROLE_TARGET);
		two_blocks();
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		/* each block alone is there - the join is what says no; and with the scratch copied into the region: the bytes run came off the socket -> it meets */
		{
			uint16_t cp = nd(KGENOME_NUCLEO_MEM_WRITE);

			edge(cp, h, KGENOME_DIAG_ROLE_SOURCE);
			edge(cp, m, KGENOME_DIAG_ROLE_BUFFER);
			two_blocks();
			CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[5] == r1);
		}
	}
	/* The socket read twice: four bytes of length into the stack first, the stage into the region second. The second block's
	 * first read fails the join and the next one is tried (the join is checked while the block binds). */
	{
		uint16_t m, so, c, r1, r2, e;

		reset();
		so = nd(KGENOME_NUCLEO_NET_OPEN);
		c = nd(KGENOME_NUCLEO_NET_CONNECT);
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		r1 = nd(KGENOME_NUCLEO_MEM_READ);
		r2 = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(c, so, KGENOME_DIAG_ROLE_FD);
		edge(r1, so, KGENOME_DIAG_ROLE_FD);
		edge(r1, KGENOME_DIAG_FROM_STACK, KGENOME_DIAG_ROLE_BUFFER);
		edge(r2, so, KGENOME_DIAG_ROLE_FD);
		edge(r2, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, m, KGENOME_DIAG_ROLE_TARGET);
		two_blocks();
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[1] == r2 && b[5] == r2);
		(void)r1;
	}
	/* The second block's read reached through a wrapper (its descriptor passed on by a call), and the join still asked of it:
	 * the read fills a scratch buffer, not the region, so the blocks do not meet (mutation M9: the join was not asked of a
	 * candidate the reached tier found). And when it fills the region, they do. */
	{
		uint16_t m, so, c, w, h, r, r2, e;
		int fill;

		for (fill = 0; fill < 2; fill++) {
			reset();
			so = nd(KGENOME_NUCLEO_NET_OPEN);
			c = nd(KGENOME_NUCLEO_NET_CONNECT);
			w = nd(KGENOME_NUCLEO_DYNCALL);
			h = nd(KGENOME_NUCLEO_HEAP);
			m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
			r = nd(KGENOME_NUCLEO_MEM_READ);
			r2 = nd(KGENOME_NUCLEO_MEM_READ);
			e = nd(KGENOME_NUCLEO_EXEC_REG);
			edge(c, so, KGENOME_DIAG_ROLE_FD);
			edge(w, so, KGENOME_DIAG_ROLE_VALUE);
			edge(r, w, KGENOME_DIAG_ROLE_FD);
			edge(r, fill ? m : h, KGENOME_DIAG_ROLE_BUFFER);
			edge(r2, nd(KGENOME_NUCLEO_FILE_OPEN), KGENOME_DIAG_ROLE_FD);
			edge(r2, m, KGENOME_DIAG_ROLE_BUFFER);
			edge(e, m, KGENOME_DIAG_ROLE_TARGET);
			two_blocks();
			if (fill)
				CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[5] == r);
			else
				CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
		}
	}
	/* A join on the second block's ROOT (the socket must reach what the first bound: the region its read fills). */
	{
		uint16_t m, so, c, r, e;

		reset();
		so = nd(KGENOME_NUCLEO_NET_OPEN);
		c = nd(KGENOME_NUCLEO_NET_CONNECT);
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(c, so, KGENOME_DIAG_ROLE_FD);
		edge(r, so, KGENOME_DIAG_ROLE_FD);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, m, KGENOME_DIAG_ROLE_TARGET);
		two_blocks();
		two[5].bits = 0;
		two[3].bits = KOF_DIAG_B_JOIN;
		CK(known(b, &nb) == KOF_DIAG_MATCH_YES && b[3] == so);
		/* a socket nothing of the first block's reaches from */
		reset();
		so = nd(KGENOME_NUCLEO_NET_OPEN);
		c = nd(KGENOME_NUCLEO_NET_CONNECT);
		m = nd(KGENOME_NUCLEO_ALLOC_EXEC);
		r = nd(KGENOME_NUCLEO_MEM_READ);
		e = nd(KGENOME_NUCLEO_EXEC_REG);
		edge(c, so, KGENOME_DIAG_ROLE_FD);
		edge(r, nd(KGENOME_NUCLEO_FILE_OPEN), KGENOME_DIAG_ROLE_FD);
		edge(r, m, KGENOME_DIAG_ROLE_BUFFER);
		edge(e, m, KGENOME_DIAG_ROLE_TARGET);
		edge(nd(KGENOME_NUCLEO_MEM_READ), so, KGENOME_DIAG_ROLE_FD);
		CK(known(b, &nb) == KOF_DIAG_MATCH_NO);
	}
}

/* ---- the loader: one block or two, every node in one ---- */
static uint8_t rec[512];

static size_t rec_begin(uint8_t n_node)
{
	rec[0] = n_node;
	rec[1] = 0;
	rec[2] = (uint8_t)KOF_DIAG_ANALYSIS_SYSCALL;
	rec[3] = 1;
	rec[4] = 'x';
	return 5u;
}

static size_t rec_node(size_t at, uint16_t cap, uint8_t parent, uint8_t bits)
{
	rec[at++] = (uint8_t)cap;
	rec[at++] = (uint8_t)(cap >> 8);
	rec[at++] = 0;
	rec[at++] = 0;
	rec[at++] = parent;
	rec[at++] = 0;
	rec[at++] = bits;
	rec[at++] = 0;
	return at;
}

static int load(size_t n, struct kof_diag *out)
{
	static struct kof_diag_node node[KOF_DIAG_MAX_NODE];
	static char name[256], needs[1024];
	struct kof_diag_store st;
	int ok;

	st.node = node;
	st.name = name;
	st.needs = needs;
	st.name_cap = sizeof name;
	st.needs_cap = sizeof needs;
	st.max_node = (uint8_t)KOF_DIAG_MAX_NODE;
	ok = kof_diag_load(kof_buf_make(rec, n), out, &st);
	if (ok)
		kof_diag_form_free(out);
	return ok;
}

static void loader_cases(void)
{
	struct kof_diag d;
	size_t at;

	/* DL-3: a parent cycle beside the root. Red before: loaded, and the cycle's nodes never bound. */
	at = rec_begin(3);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 2, 0);
	at = rec_node(at, KGENOME_NUCLEO_EXEC_REG, 1, 0);
	CK(load(at, &d) == 0);
	/* the same nodes as a star load */
	at = rec_begin(3);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, 0);
	at = rec_node(at, KGENOME_NUCLEO_EXEC_REG, 0, 0);
	CK(load(at, &d) == 1 && d.n_node == 3);
	/* a chain (a tree deeper than a star) loads */
	at = rec_begin(3);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, 0);
	at = rec_node(at, KGENOME_NUCLEO_EXEC_REG, 1, 0);
	CK(load(at, &d) == 1);
	/* two blocks with a join in the second: loads */
	at = rec_begin(4);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, 0);
	at = rec_node(at, KGENOME_NUCLEO_NET_OPEN, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 2, KOF_DIAG_B_JOIN);
	CK(load(at, &d) == 1 && d.n_node == 4 && (d.node[3].bits & KOF_DIAG_B_JOIN));
	/* two blocks, no join: refused */
	at = rec_begin(4);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, 0);
	at = rec_node(at, KGENOME_NUCLEO_NET_OPEN, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 2, 0);
	CK(load(at, &d) == 0);
	/* a join in the FIRST block: refused */
	at = rec_begin(4);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, KOF_DIAG_B_JOIN);
	at = rec_node(at, KGENOME_NUCLEO_NET_OPEN, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 2, 0);
	CK(load(at, &d) == 0);
	/* a join in a one-block record: refused */
	at = rec_begin(2);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, KOF_DIAG_B_JOIN);
	CK(load(at, &d) == 0);
	/* three roots: refused */
	at = rec_begin(4);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_NET_OPEN, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_HEAP, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 1, KOF_DIAG_B_JOIN);
	CK(load(at, &d) == 0);
	/* two blocks and a sequence (it makes THE head): refused */
	at = rec_begin(4);
	at = rec_node(at, KGENOME_NUCLEO_ALLOC_EXEC, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 0, 0);
	at = rec_node(at, KGENOME_NUCLEO_NET_OPEN, KOF_DIAG_NO_PARENT, 0);
	at = rec_node(at, KGENOME_NUCLEO_MEM_READ, 2, KOF_DIAG_B_JOIN);
	rec[at++] = 0;                          /* the legacy count */
	rec[at++] = (uint8_t)KDIG_SEC_SEQUENCE;
	rec[at++] = 4;
	rec[at++] = (uint8_t)KGENOME_NUCLEO_KPROBE_REG;
	rec[at++] = (uint8_t)(KGENOME_NUCLEO_KPROBE_REG >> 8);
	rec[at++] = (uint8_t)KGENOME_NUCLEO_KPROBE_UNREG;
	rec[at++] = (uint8_t)(KGENOME_NUCLEO_KPROBE_UNREG >> 8);
	CK(load(at, &d) == 0);
}

/* ---- the source language: two heads, a join ---- */
static int src_errs;
static void src_err(void *ud, int line, const char *msg)
{
	(void)ud; (void)line; (void)msg;
	src_errs++;
}
static void src_warn(void *ud, const char *msg)
{
	(void)ud; (void)msg;
}

static int resolve(const char *text, struct kof_dsrc_view *v)
{
	static struct kof_dsrc d;
	const struct kof_dsrc_report rep = { src_err, src_warn, NULL };

	src_errs = 0;
	kof_dsrc_parse(text, strlen(text), &d, &rep);
	if (!src_errs)
		kof_dsrc_resolve(&d, v, &rep);
	return src_errs;
}

#define SRC_HEAD "KOF_DIAG_NAME(j);\nKOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);\n" \
	"KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n" \
	"KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);\n"

static void source_cases(void)
{
	struct kof_dsrc_view v, v1;
	uint64_t h2;

	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_CONNECT);\n"
		   "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\nKOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 0);
	CK(v.n_nd == 6);
	CK(v.nd[0].parent == KOF_DIAG_NO_PARENT && v.nd[1].parent == 0 && v.nd[2].parent == 0);
	CK(v.nd[3].parent == KOF_DIAG_NO_PARENT && v.nd[4].parent == 3 && v.nd[5].parent == 3);
	CK(!(v.nd[1].bits & KOF_DIAG_B_JOIN) && (v.nd[5].bits & KOF_DIAG_B_JOIN));
	h2 = kof_dsrc_view_body_hash(&v);
	kof_dsrc_view_free(&v);
	/* the same nodes cut differently are another diagnose */
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
		   "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_CONNECT);\nKOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 0);
	CK(kof_dsrc_view_body_hash(&v) != h2);
	kof_dsrc_view_free(&v);
	/* one block: the record a star always was */
	CK(resolve(SRC_HEAD, &v1) == 0);
	CK(v1.n_nd == 3 && v1.nd[0].parent == KOF_DIAG_NO_PARENT && v1.nd[1].parent == 0 && v1.nd[2].parent == 0);
	kof_dsrc_view_free(&v1);
	/* the refusals */
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n", &v) == 1);
	kof_dsrc_view_free(&v);
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 1);
	kof_dsrc_view_free(&v);
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_CONNECT);\n"
		   "KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 1);       /* no mem-read in the second block */
	kof_dsrc_view_free(&v);
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
		   "KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\nKOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 1);  /* twice there */
	kof_dsrc_view_free(&v);
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
		   "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_HEAP, 0);\nKOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) >= 1);   /* three heads */
	kof_dsrc_view_free(&v);
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_SEQUENCE(KOF_NUCLEO_KPROBE_REG, KOF_NUCLEO_KPROBE_UNREG);\n"
		   "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
		   "KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 1);
	kof_dsrc_view_free(&v);
	/* an action belongs to the head of its block */
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_CRED_PREPARE, 0);\n"
		   "KOF_DIAG_ACTION(KOF_NUCLEO_CRED_PREPARE, KOF_NUCLEO_ACTION_WRITE, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
		   "KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 0);
	CK(v.n_nd == 6 && v.nd[4].parent == 3 && (v.nd[4].bits & KOF_DIAG_B_VAL));
	kof_dsrc_view_free(&v);
	CK(resolve(SRC_HEAD "KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);\n"
		   "KOF_DIAG_ACTION(KOF_NUCLEO_ALLOC_EXEC, KOF_NUCLEO_ACTION_WRITE, 0);\nKOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);\n"
		   "KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);\n", &v) == 1);   /* names the first block's head */
	kof_dsrc_view_free(&v);
	/* the printer writes the join back as it was read */
	{
		struct kof_dsrc_item it;
		char out[128];

		memset(&it, 0, sizeof it);
		it.kind = KDS_JOIN;
		it.a = KGENOME_NUCLEO_MEM_READ;
		CK(kof_dsrc_print(&it, out, sizeof out) > 0 && !strcmp(out, "KOF_DIAG_DECLARE_JOIN(KOF_NUCLEO_MEM_READ);"));
	}
}

int main(void)
{
	reach_cases();
	bound_case();
	ledger_case();
	join_kind_case();
	block_cases();
	loader_cases();
	source_cases();
	free(s.adj_head);
	free(s.adj_edge);
	printf("diag_reach: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
