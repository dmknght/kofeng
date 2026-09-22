/* See ovlflow.h. */

#include "ovlflow.h"

#include <string.h>

uint8_t kof_ovlf_weight(uint8_t cap)
{
	switch (cap) {
	case KOF_CAP_FILE_OPEN:                        /* 66.62% */
		return KOF_OVLF_W_COMMON;
	case KOF_CAP_READ:                             /* 14.89% */
	case KOF_CAP_WRITE:                            /* 12.61% */
		return KOF_OVLF_W_ORDINARY;
	case KOF_CAP_EXEC_IMAGE:                       /*  8.36% */
	case KOF_CAP_SLEEP:                            /*  6.74% */
	case KOF_CAP_SPAWN:                            /*  6.19% */
	case KOF_CAP_ALLOC:                            /*  5.29% */
	case KOF_CAP_NET_OPEN:                         /*  3.52% */
	case KOF_CAP_PTRACE:                           /*  2.38% */
	case KOF_CAP_NET_CONNECT:                      /*  1.76% */
	case KOF_CAP_NET_ACCEPT:                       /*  1.07% */
		return KOF_OVLF_W_NOTABLE;
	case KOF_CAP_MEMFD:                            /*  0.07% */
	case KOF_CAP_ALLOC_EXEC:                       /*  0.10% */
		return KOF_OVLF_W_RARE;
	default:
		return 0;
	}
}

/*
 * WHICH CAPABILITIES ARE NEAR NEIGHBOURS.
 *
 * Not everything that differs differs equally. `read` and `recvfrom` already
 * arrive as one capability, so what is left here is coarser: a variant that
 * maps with mmap where another used mprotect is the same program, and one that
 * opens a socket where another connected one is doing the same kind of thing
 * one step earlier.
 *
 * SMALL AND STATED, rather than a full matrix. Every row is a claim, and a
 * matrix of claims nobody checked is how a "flexible" matcher becomes one that
 * matches everything. Three families, each of which a variant really does move
 * inside.
 */
static uint8_t family(uint8_t cap)
{
	switch (cap) {
	case KOF_CAP_ALLOC:
	case KOF_CAP_ALLOC_EXEC:
		return 1;
	case KOF_CAP_NET_OPEN:
	case KOF_CAP_NET_CONNECT:
	case KOF_CAP_NET_ACCEPT:
		return 2;
	case KOF_CAP_READ:
	case KOF_CAP_WRITE:
		return 3;
	default:
		return 0;
	}
}

int kof_ovlf_worth(const struct kof_flow_node *v, uint32_t n)
{
	uint32_t i, w = 0;

	if (!v || n < KOF_OVLF_MIN_NODES)
		return 0;
	for (i = 0; i < n; i++)
		w += kof_ovlf_weight(v[i].cap);
	return w >= KOF_OVLF_MIN_WEIGHT;
}

/*
 * THE COST MODEL, in the same units as the weights.
 *
 * A mismatch is PRICED AND NOT FORBIDDEN, which is the whole difference
 * between this and a pattern: a variant that swapped one step for another is
 * still the same program and should still line up, having paid for it.
 *
 * AFFINE GAPS - opening one costs, extending it costs less - because that is
 * the shape junk code has. A polymorphic engine inserts a BLOCK of filler in
 * one place; it does not sprinkle one instruction in twenty places. Measured
 * on the meterpreter stager: six junk instructions between two nodes moved the
 * normalised gap from 11 to 16, all of it in one run.
 */
#define S_FAMILY   1    /* aligned within a family, on top of nothing */
#define S_MISMATCH (-2)
#define S_GAP_OPEN (-3)
#define S_GAP_EXT  (-1)

#define AMAX 64u        /* the table's side; a region longer than this is
			 * clipped, and kof_flow already bounds what a sweep
			 * records */

/* Where a cell came from, so the alignment can be walked back. */
enum { FROM_NONE = 0, FROM_DIAG, FROM_UP, FROM_LEFT };

int kof_ovlf_align(const struct kof_flow_node *a, uint32_t na,
		   const struct kof_flow_node *b, uint32_t nb,
		   struct kof_ovlf_hit *out)
{
	/*
	 * NOT `static`, WHICH IS WHAT THEY WERE.
	 *
	 * The engine scans on N threads - see --jobs and unit_scan_mt - and a
	 * static matrix is one matrix shared by all of them: two threads
	 * aligning two different pairs would overwrite each other's cells and
	 * both would come back with a score neither pair has. Nothing memory
	 * unsafe, because the bounds are fixed, but a similarity answer that
	 * depends on what another thread was doing is worse than no answer.
	 *
	 * 12.6 KB of frame, against -Wframe-larger-than=131072.
	 */
	int16_t h[AMAX + 1u][AMAX + 1u];
	uint8_t bt[AMAX + 1u][AMAX + 1u];
	uint32_t i, j, bi = 0, bj = 0;
	int16_t best = 0;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!kof_ovlf_worth(a, na) || !kof_ovlf_worth(b, nb))
		return 0;
	if (na > AMAX) na = AMAX;
	if (nb > AMAX) nb = AMAX;

	memset(h, 0, sizeof h);
	memset(bt, 0, sizeof bt);

	for (i = 1; i <= na; i++) {
		for (j = 1; j <= nb; j++) {
			uint8_t ca = a[i - 1u].cap, cb = b[j - 1u].cap;
			int16_t diag, up, left, v;

			if (ca == cb)
				diag = (int16_t)(h[i - 1u][j - 1u] +
						 kof_ovlf_weight(ca));
			else if (family(ca) && family(ca) == family(cb))
				diag = (int16_t)(h[i - 1u][j - 1u] + S_FAMILY);
			else
				diag = (int16_t)(h[i - 1u][j - 1u] +
						 S_MISMATCH);

			up = (int16_t)(h[i - 1u][j] +
				       (bt[i - 1u][j] == FROM_UP ? S_GAP_EXT
								 : S_GAP_OPEN));
			left = (int16_t)(h[i][j - 1u] +
					 (bt[i][j - 1u] == FROM_LEFT
					  ? S_GAP_EXT : S_GAP_OPEN));

			v = diag;
			bt[i][j] = FROM_DIAG;
			if (up > v)   { v = up;   bt[i][j] = FROM_UP; }
			if (left > v) { v = left; bt[i][j] = FROM_LEFT; }
			/*
			 * LOCAL: a cell never goes below zero, which is what
			 * lets the alignment START anywhere. Without it the
			 * loader segment inside a trojan would be dragged
			 * under by the two hundred nodes in front of it.
			 */
			if (v < 0) { v = 0; bt[i][j] = FROM_NONE; }
			h[i][j] = v;
			if (v > best) { best = v; bi = i; bj = j; }
		}
	}
	if (!best)
		return 0;

	out->a_last = (uint8_t)(bi - 1u);
	out->b_last = (uint8_t)(bj - 1u);

	/* Walk back from the best cell to where it fell to zero: that run is
	 * the segment, and counting it is what the caller is told. */
	i = bi; j = bj;
	while (i && j && h[i][j] > 0) {
		if (bt[i][j] == FROM_DIAG) {
			uint8_t ca = a[i - 1u].cap, cb = b[j - 1u].cap;

			if (ca == cb) {
				if (out->matched < 255u) out->matched++;
				if (kof_ovlf_weight(ca) >= KOF_OVLF_W_RARE &&
				    out->rare < 255u)
					out->rare++;
				/*
				 * A MATCH THAT CARRIES THE EDGE COUNTS APART.
				 * "Both allocate" and "both allocate, and both
				 * jump into what they allocated" are different
				 * claims - see KOF_FLOWF_EXECUTED.
				 */
				if ((a[i - 1u].flags & (KOF_FLOWF_EXECUTED)) &&
				    (b[j - 1u].flags & (KOF_FLOWF_EXECUTED)) &&
				    out->chained < 255u)
					out->chained++;
				else if (kof_flow_from_any(&a[i - 1u]) &&
					 kof_flow_from_any(&b[j - 1u]) &&
					 out->chained < 255u)
					out->chained++;
			} else if (family(ca) && family(ca) == family(cb)) {
				if (out->related < 255u) out->related++;
			} else {
				if (out->mismatch < 255u) out->mismatch++;
			}
			out->a_first = (uint8_t)(i - 1u);
			out->b_first = (uint8_t)(j - 1u);
			i--; j--;
		} else if (bt[i][j] == FROM_UP) {
			if (out->gap_len < 255u) out->gap_len++;
			if (bt[i - 1u][j] != FROM_UP && out->gaps < 255u)
				out->gaps++;
			i--;
		} else if (bt[i][j] == FROM_LEFT) {
			if (out->gap_len < 255u) out->gap_len++;
			if (bt[i][j - 1u] != FROM_LEFT && out->gaps < 255u)
				out->gaps++;
			j--;
		} else {
			break;
		}
	}
	return out->matched ? 1 : 0;
}

uint32_t kof_ovlf_chain_nodes(const struct kof_ovlf_chain *c,
			      struct kof_flow_node *out)
{
	uint32_t i;

	if (!c || !out)
		return 0;
	memset(out, 0, sizeof *out * (c->n > KOF_OVLF_CHAIN_MAX
				      ? KOF_OVLF_CHAIN_MAX : c->n));
	for (i = 0; i < c->n && i < KOF_OVLF_CHAIN_MAX; i++) {
		out[i].cap = c->s[i].cap;
		out[i].flags = c->s[i].flags;
		out[i].step = i;
		/* The link comes back as an index, which is what the aligner
		 * and kof_flow_from_any read. */
		if (c->s[i].back && c->s[i].back <= i)
			out[i].from[0] = (uint16_t)(i - c->s[i].back + 1u);
	}
	return i;
}

int kof_ovlf_chain_of(const struct kof_flow_node *v, uint32_t n,
		      struct kof_ovlf_chain *out)
{
	uint32_t i, j;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!kof_ovlf_worth(v, n))
		return 0;
	if (n > KOF_OVLF_CHAIN_MAX)
		n = KOF_OVLF_CHAIN_MAX;
	for (i = 0; i < n; i++) {
		out->s[i].cap = v[i].cap;
		out->s[i].flags = (uint8_t)(v[i].flags & KOF_OVLF_FLAG_KEEP);
		/*
		 * The first argument that names an earlier node, turned into a
		 * distance. A producer that fell outside the region keeps the
		 * step unlinked rather than pointing at nothing.
		 */
		for (j = 0; j < KOF_FLOW_ARGS; j++) {
			uint32_t src;

			if (!v[i].from[j])
				continue;
			src = v[i].from[j] - 1u;
			if (src < i && i - src < 256u) {
				out->s[i].back = (uint8_t)(i - src);
				break;
			}
		}
	}
	out->n = (uint8_t)n;
	return 1;
}

uint32_t kof_ovlf_chain_mask(const struct kof_ovlf_chain *c)
{
	uint32_t i, m = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->n && i < KOF_OVLF_CHAIN_MAX; i++) {
		/*
		 * `cap` is one byte out of a stored chain, and a stored chain
		 * arrives from a .ksig on disk. A shift by 32 or more is
		 * UNDEFINED, not merely wrong - so the vocabulary's own bound
		 * is checked here rather than assumed of the file.
		 */
		if (c->s[i].cap >= KOF_CAP_COUNT)
			continue;
		m |= 1u << c->s[i].cap;
	}
	return m;
}

/*
 * HOW MUCH OF A STORED CHAIN A REGION CARRIES.
 *
 * NOT kof_ovlf_align, and the difference is the whole point.
 *
 * The aligner is SYMMETRIC - neither side is the rule - so it compares
 * capabilities and nothing else; the flags only colour what it reports. A rule
 * is not symmetric: "two allocations that are writable AND executable" is a
 * different claim from "two allocations", and measured, the second is one that
 * libswscale answers yes to. So the flags a rule asked for are REQUIRED here,
 * by containment: a step may carry more than the reference asked, never less.
 *
 *
 * ORDER IS ENFORCED ONLY WHERE A LINK DEMANDS IT.
 *
 * This was a total order and that was wrong. A compiler is free to open the
 * socket before it maps the page or after; both are the same program, and a
 * matcher that pins the order it happened to see pins an accident of layout.
 * `socket, mmap, read` and `mmap, socket, read` are one shape.
 *
 * What is NOT free is a step that consumes what an earlier one produced: read
 * cannot fill the mapping before mmap returned it. That constraint is already
 * recorded - kof_ovlf_step.back - and it is the ONLY thing here that fixes an
 * order. Everything else matches in any order.
 *
 * SO THE LINKS ARE THE SKELETON AND THE REST IS A SET. Which also says how
 * much a chain is worth on each platform, and the measurement is not
 * comforting: links were found in 13.6% of multi-node regions in /usr/bin and
 * in NONE of 1501 PE regions, because Windows compilers spill the returned
 * pointer to a stack slot that this sweep does not follow. On a PE, therefore,
 * a chain today is a SET of capabilities with a span bound and no skeleton at
 * all - which is the honest description of it, and the reason a PE chain rule
 * should lean on the flags rather than on the sequence.
 *
 * THE GAP IS COUNTED IN NODES, which is the unit junk code cannot move.
 * Inserting instructions changes the byte distance and the instruction
 * distance and leaves the node distance alone - measured, six junk
 * instructions moved the normalised gap from 11 to 16 and moved the node
 * sequence not at all. Bytes are what bases/signatures/meterp_00.c pins and
 * are the reason it misses variants. With the order gone the bound applies to
 * the whole matched SPAN rather than to each consecutive pair, which is the
 * same claim over a set instead of a sequence.
 *
 * GREEDY, AND SAID SO. A step takes the first node that satisfies it, which
 * can strand a later step whose link needed that node. Both sides hold at most
 * KOF_OVLF_CHAIN_MAX steps and links are sparse, so the exhaustive answer
 * would differ rarely and cost a search; if a measured case ever turns up, it
 * belongs here rather than in a threshold somewhere else.
 */
#define KOF_OVLF_CHAIN_GAP 4u   /* nodes allowed between two matched steps */

/* Does this node satisfy this step - capability, the flags the rule asked for,
 * and the link if it asked for one. `at` holds which node each earlier step
 * took, so a link is checked against the node that actually matched. */
static int step_fits(const struct kof_ovlf_step *st, uint32_t i,
		     const struct kof_flow_node *v, uint32_t j,
		     const uint8_t *at, const uint8_t *have)
{
	uint32_t q, src;

	if (v[j].cap != st->cap || (v[j].flags & st->flags) != st->flags)
		return 0;
	if (!st->back)
		return 1;
	if (st->back > i || !have[i - st->back])
		return 0;      /* the producer is not in this match */
	src = at[i - st->back];
	for (q = 0; q < KOF_FLOW_ARGS; q++)
		if (v[j].from[q] && v[j].from[q] - 1u == src)
			return 1;
	return 0;
}

uint32_t kof_ovlf_chain_pct(const struct kof_ovlf_chain *ref,
			    const struct kof_flow_node *v, uint32_t n)
{
	uint32_t start, best = 0;

	if (!ref || !ref->n || !v || !n)
		return 0;
	if (n > KOF_OVLF_CHAIN_MAX)
		n = KOF_OVLF_CHAIN_MAX;

	for (start = 0; start < n; start++) {
		uint8_t at[KOF_OVLF_CHAIN_MAX], have[KOF_OVLF_CHAIN_MAX];
		uint32_t used = 0, got = 0, lo = n, hi = 0, i;

		memset(have, 0, sizeof have);
		/*
		 * The reference's own order is a topological one - a link
		 * always points backwards - so walking it in index order means
		 * a producer is already placed when its consumer is tried.
		 */
		for (i = 0; i < ref->n && i < KOF_OVLF_CHAIN_MAX; i++) {
			uint32_t j;

			for (j = start; j < n; j++) {
				if (used & (1u << j))
					continue;
				if (!step_fits(&ref->s[i], i, v, j, at, have))
					continue;
				used |= 1u << j;
				at[i] = (uint8_t)j;
				have[i] = 1;
				got++;
				if (j < lo) lo = j;
				if (j > hi) hi = j;
				break;
			}
		}
		/*
		 * AND THE MATCH HAS TO BE ONE STRETCH OF CODE. Without this a
		 * step matched at the top of a large region and another at the
		 * bottom would read as a chain, and they are two unrelated
		 * things that happen to be in one function.
		 */
		if (got > 1u && hi - lo + 1u - got >
		    KOF_OVLF_CHAIN_GAP * (got - 1u))
			continue;
		if (got > best)
			best = got;
		if (best >= ref->n)
			break;
	}
	return best * 100u / ref->n;
}
