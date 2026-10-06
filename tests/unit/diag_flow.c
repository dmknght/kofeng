/*
 * diag_flow - the join that follows the links, not the one that looks one up.
 *
 * A stager proves itself by a shape: the bytes a socket read produced are the
 * bytes that get executed. The old join asked whether ONE node was bound by
 * both the socket diagnose and the exec diagnose - true when a single
 * read(fd, region, n) both touches the socket and fills the region, and FALSE
 * the moment a payload reads into a scratch buffer and copies that into the
 * region. The read and the region are then two hops apart with the copy
 * between them, and "links in the middle that still link" is exactly what a
 * reachability join is for and a shared-node lookup is not.
 *
 * The three graphs are built by hand - mirroring diag_kind.c - so the test
 * states the shape rather than depending on a sample to contain it, and so a
 * staged sample is not needed to prove the algorithm the staged sample would
 * need.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../libkofeng/detectors/pathogen/diag_int.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, \
	__LINE__, #c); fails++; } } while (0)

/* add a node, return its index */
static uint16_t nd(struct kof_diag_scan *s, uint16_t cap)
{
	kof_diag_hit_add(s, 0x1000u + s->n_hit * 0x10u, cap, 0);
	return (uint16_t)(s->n_hit - 1u);
}

static void edge(struct kof_diag_scan *s, uint16_t node, uint16_t from,
		 uint8_t role)
{
	struct kof_diag_hit *h = kof_diag_hit_of(s, node);

	if (h)
		kof_diag_note_in(h, from, role, KOF_DIAG_KIND_PRODUCED);
}

static void reset(struct kof_diag_scan *s, struct kof_diag_hit *hits,
		  uint32_t cap)
{
	free(s->adj_head);
	free(s->adj_edge);
	memset(hits, 0, sizeof(struct kof_diag_hit) * cap);
	memset(s, 0, sizeof *s);
	s->hit = hits;
	s->cap_hit = cap;
}

int main(void)
{
	struct kof_diag_hit hits[8];
	struct kof_diag_scan s;
	uint16_t a_bind[4], b_bind[4];

	memset(&s, 0, sizeof s);
	s.hit = hits;
	s.cap_hit = 8u;

	/*
	 * ONE: THE DIRECT STAGER. One read is both the socket read and the
	 * fill of the region - net-open -> read -> region -> exec, the shape
	 * a shared-node lookup already caught. The reachability join must
	 * still catch it: a zero or one hop path is a path.
	 */
	{
		uint16_t region = nd(&s, KOF_NUCLEO_ALLOC_EXEC);
		uint16_t sock   = nd(&s, KOF_NUCLEO_NET_OPEN);
		uint16_t rd     = nd(&s, KOF_NUCLEO_MEM_READ);
		uint16_t ex     = nd(&s, KOF_NUCLEO_EXEC_REG);

		edge(&s, rd, region, KOF_DIAG_ROLE_BUFFER);   /* read -> region */
		edge(&s, rd, sock,   KOF_DIAG_ROLE_FD);       /* sock -> read   */
		edge(&s, ex, region, KOF_DIAG_ROLE_TARGET);   /* region -> exec */

		a_bind[0] = region; a_bind[1] = rd; a_bind[2] = ex;  /* MEMEXEC */
		b_bind[0] = sock;   b_bind[1] = rd;                  /* NETRECV */
		CK(kof_diag_flow_join(&s, KOF_NUCLEO_MEM_READ,
				      a_bind, 3u, b_bind, 2u) == 1);
		printf("  direct stager: %s\n", fails ? "FAIL" : "matched");
	}

	/*
	 * TWO: THE STAGED STAGER. The read fills a SCRATCH buffer and a copy
	 * moves it into the region - read -> scratch -> copy -> region ->
	 * exec. No node is bound by both diagnoses now: the read touches the
	 * socket, the region is entered, and nothing is both. The old lookup
	 * returns no; the walk must return yes, because the value still
	 * arrives.
	 */
	{
		int before = fails;
		uint16_t region, sock, rd, scratch, cpy, ex;

		reset(&s, hits, 8u);
		region  = nd(&s, KOF_NUCLEO_ALLOC_EXEC);
		sock    = nd(&s, KOF_NUCLEO_NET_OPEN);
		scratch = nd(&s, KOF_NUCLEO_HEAP);
		rd      = nd(&s, KOF_NUCLEO_MEM_READ);
		cpy     = nd(&s, KOF_NUCLEO_MEM_WRITE);
		ex      = nd(&s, KOF_NUCLEO_EXEC_REG);

		edge(&s, rd,  sock,    KOF_DIAG_ROLE_FD);      /* sock -> read     */
		edge(&s, rd,  scratch, KOF_DIAG_ROLE_BUFFER);  /* read -> scratch  */
		edge(&s, cpy, scratch, KOF_DIAG_ROLE_SOURCE);  /* scratch -> copy  */
		edge(&s, cpy, region,  KOF_DIAG_ROLE_BUFFER);  /* copy -> region   */
		edge(&s, ex,  region,  KOF_DIAG_ROLE_TARGET);  /* region -> exec   */

		/* MEMEXEC binds only the region and the exec - it cannot bind
		 * a read, there is none into the region. */
		a_bind[0] = region; a_bind[1] = ex;
		b_bind[0] = sock;   b_bind[1] = rd;
		CK(kof_diag_flow_join(&s, KOF_NUCLEO_MEM_READ,
				      a_bind, 2u, b_bind, 2u) == 1);
		printf("  staged stager (scratch in between): %s\n",
		       fails > before ? "FAIL" : "matched");
	}

	/*
	 * THREE: THE COPY READS A DIFFERENT BUFFER. The socket read fills
	 * scratch A; the copy into the region reads scratch B. The bytes
	 * executed never came off the wire, and the join must say so - this
	 * is what separates a reachability walk from "both behaviours are
	 * present somewhere in the file".
	 */
	{
		int before = fails;
		uint16_t region, sock, rd, scratchA, scratchB, cpy, ex;

		reset(&s, hits, 8u);
		region   = nd(&s, KOF_NUCLEO_ALLOC_EXEC);
		sock     = nd(&s, KOF_NUCLEO_NET_OPEN);
		scratchA = nd(&s, KOF_NUCLEO_HEAP);
		scratchB = nd(&s, KOF_NUCLEO_HEAP);
		rd       = nd(&s, KOF_NUCLEO_MEM_READ);
		cpy      = nd(&s, KOF_NUCLEO_MEM_WRITE);
		ex       = nd(&s, KOF_NUCLEO_EXEC_REG);

		edge(&s, rd,  sock,     KOF_DIAG_ROLE_FD);
		edge(&s, rd,  scratchA, KOF_DIAG_ROLE_BUFFER); /* read -> A    */
		edge(&s, cpy, scratchB, KOF_DIAG_ROLE_SOURCE); /* B -> copy    */
		edge(&s, cpy, region,   KOF_DIAG_ROLE_BUFFER); /* copy -> region */
		edge(&s, ex,  region,   KOF_DIAG_ROLE_TARGET);

		a_bind[0] = region; a_bind[1] = ex;
		b_bind[0] = sock;   b_bind[1] = rd;
		CK(kof_diag_flow_join(&s, KOF_NUCLEO_MEM_READ,
				      a_bind, 2u, b_bind, 2u) == 0);
		printf("  unrelated buffer (must not match): %s\n",
		       fails > before ? "FAIL" : "silent");
	}

	free(s.adj_head);
	free(s.adj_edge);
	printf("diag flow: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
