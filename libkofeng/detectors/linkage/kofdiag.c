/*
 * kofdiag.c - the matcher: take a diagnose, walk it over the nodes an object
 * holds, and say whether it is there and which nodes it bound.
 *
 * The nodes themselves are found in libgenome/phenotype (diag_scan.h); this
 * file only reads them.
 */

#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "../../databases/pack/diagform.h"
#include <phenotype/diag_scan_state.h>
#include "../../kofcore/kofdebug.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/elf.h"
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <celllysis/space.h>
#include "../../analyzers/parsers/binaries/funcs.h"
#include "../../analyzers/parsers/binaries/elf/elf_parse.h"

/* ---- matching ------------------------------------------------------------
 *
 * THE PARENT GENERATES THE CHILDREN. It does not filter them.
 *
 * The obvious shape - take every node matching each spec and try the
 * combinations - is a product of the pool sizes, and the pools are not
 * small: MEASURED, one 1.1 MB sample here holds 447 indirect calls, so a
 * three-node diagnose over two such pools is two hundred thousand tries.
 *
 * What makes the real shape cheap is that a node already records WHICH node
 * it took its value from. So a child is not looked for among all nodes of
 * its capability - it is looked for among the nodes that point AT THE
 * PARENT ALREADY BOUND, which is usually none or one. The walk is then the
 * size of the diagnose, once per candidate root, and the root is the rarest
 * node by construction - see the note on anchors in kofmod/kofdiagtree.h.
 */

/* The NUL-terminated name a hit pointed at, or NULL. */
static const char *hit_sym(const struct kgenome_diag_scan *s,
			   const struct kgenome_diag_hit *h)
{
	uint64_t i;

	if (!s || !s->base || !(h->bits & KGENOME_DIAG_H_SYMREF) ||
	    h->symref >= s->size)
		return NULL;
	/* Terminated inside the object, or it is not a name. */
	for (i = h->symref; i < s->size; i++)
		if (!s->base[i])
			return (const char *)(s->base + h->symref);
	return NULL;
}

/*
 * THE WORD THE RULE NAMED, OR ANY KIND OF IT. A rule saying mem-read is
 * satisfied by net-recv, because net-recv IS a mem-read whose descriptor
 * turned out to be a socket - see kgenome_nucleo_cap_generic. Comparing for
 * equality made a rule stop matching whenever the engine learned something
 * more about the program it described. The ONE test of it: the matcher's spec
 * and the join's capability both ask here (the join compared for equality and
 * missed a socket read named by mem-read: DL-2).
 */
static int cap_is(uint16_t have, uint16_t want)
{
	uint16_t g = have;

	if (have == want)
		return 1;
	while ((g = kgenome_nucleo_cap_generic(g)) != KGENOME_NUCLEO_NONE)
		if (g == want)
			return 1;
	return 0;
}

/* A node satisfies a spec when it has the capability, carries every flag the
 * spec demands, and is not one whose meaning the walk could not read. The
 * last is the point of KGENOME_DIAG_H_ARG_UNKNOWN: a `mmap` whose prot could not
 * be followed is not evidence of a buffer OR of a code region. */
static int spec_ok(const struct kgenome_diag_scan *s,
		   const struct kgenome_diag_hit *h,
		   const struct kof_diag_node *sp)
{
	if (!cap_is(h->cap, sp->cap))
		return 0;
	if ((h->flags & sp->flags) != sp->flags)
		return 0;
	if (h->bits & (KGENOME_DIAG_H_ARG_UNKNOWN | KGENOME_DIAG_H_SUPERSEDED))
		return 0;
	/*
	 * AND THE VALUE, WHEN THE DIAGNOSE NAMED ONE - see KOF_DIAG_B_VAL.
	 *
	 * The node must have written a LITERAL and it must be that one. A
	 * node whose value the model never learnt does not match: "we could
	 * not tell" is not the same answer as "it wrote zero", and folding
	 * them would let an author who can lose the model write anything.
	 */
	if (sp->bits & KOF_DIAG_B_VAL) {
		if (!(h->bits & KGENOME_DIAG_H_VAL) || h->val != sp->val)
			return 0;
	}
	/*
	 * AND A FIELD OF THE NAMED SYMBOL - see KOF_DIAG_B_FIELD_OF. A FIELD,
	 * so offset zero does not count: that is the handle itself, which a
	 * module passes to the kernel all day.
	 */
	if (sp->bits & KOF_DIAG_B_FIELD_OF) {
		const char *nm = hit_sym(s, h);

		if (!nm || !sp->sym || !h->symadd ||
		    !kof_streq_(nm, sp->sym))
			return 0;
	}
	return 1;
}

/*
 * IS THIS NODE LINKED TO THAT ONE, in the role the diagnose asked for.
 *
 * TWO WAYS, AND THE DIAGNOSE NAMES NEITHER. A value link - the child took
 * the parent's result - and a region link, where the parent established a
 * region and the child's address lies in it. msfvenom needs both and in the
 * same rule: on x86-64 `mmap` returns the pointer, on i386 `mprotect`
 * returns zero and names the region in an argument. A diagnose that had to
 * say which would need two copies of itself, so it says neither and this
 * accepts either.
 *
 * AND `how` IS NOT READ - A DECISION, NOT AN OMISSION (audit R4). A link the routes keep is one the program can
 * produce: PROVEN says the walk or the run showed it on every path it read, MAY says it is on some path or
 * through a callee that was not read (kgenome_diag_link, diag_vocab.h). The diagnose asks whether the relation
 * exists, so a MAY link satisfies it exactly as a PROVEN one does; a diagnose that had to choose would be two
 * diagnoses, and the choice would hide a stager behind a branch. How sure a link is, is REPORTED (the dump,
 * the viewer, kgenome_diag_in.how). tests/unit/diag_linked_how.c pins this: if the decision changes, that test
 * changes with it and the corpus identity counts move.
 */
/*
 * DOES THIS INPUT OF THE CHILD SAY WHAT THE DIAGNOSE ASKED OF THE LINK: its
 * role, and its kind. The one filter of an input, for a direct link and a
 * reached one alike (the kind is the child's own input - the last hop; what
 * a reached link asks of the hops before it is in reach_mode).
 */
static int in_takes(const struct kgenome_diag_in *in, uint8_t role, uint8_t want)
{
	/* A node that names no role takes the link whatever the role: the
	 * role is the child's own argument, which the engine derived from
	 * the capability (kgenome_diag_role_of_arg) and the diagnose need not
	 * restate. */
	if (role != KGENOME_DIAG_ROLE_NONE && in->role != role)
		return 0;
	/*
	 * AND OF WHICH KIND, where the diagnose says - see KOF_DIAG_B_SHARED.
	 * Neither bit is "either", which is what a diagnose written before
	 * the kinds existed asked for and still asks for.
	 */
	want &= (uint8_t)(KOF_DIAG_B_PRODUCED | KOF_DIAG_B_SHARED);
	if (want) {
		uint8_t is = in->kind == KGENOME_DIAG_KIND_SHARED
			     ? (uint8_t)KOF_DIAG_B_SHARED
			     : (uint8_t)KOF_DIAG_B_PRODUCED;

		if (!(want & is))
			return 0;
	}
	return 1;
}

static int linked(const struct kgenome_diag_hit *child, uint16_t parent_idx,
		  const struct kgenome_diag_hit *parent, uint8_t role,
		  uint8_t want)
{
	uint8_t i;

	for (i = 0; i < child->n_in; i++) {
		if (!in_takes(&child->in[i], role, want))
			continue;
		if (child->in[i].from == parent_idx)
			return 1;
		if (child->in[i].from == KGENOME_DIAG_FROM_STACK &&
		    (parent->bits & KGENOME_DIAG_H_REGION_STACK))
			return 1;
	}
	return 0;
}

/*
 * A GRAPH OVER THE NODES, AS OFFSETS AND ONE FLAT LIST - the form both graphs of this file take (the matcher's index of successors below and the value-flow graph the joins walk):
 * `head` holds nsrc + 1 offsets and the targets of source u are edge[head[u] .. head[u + 1]), in the order the edges were produced. The caller says only WHICH edges there
 * are, by a walk that calls `emit(src, dst)` for each; it is run twice, once to count per source and once to fill, so the two passes cannot disagree about what an edge is.
 * 1 and the two arrays (the caller's to free), or 0 for want of memory with nothing allocated.
 */
typedef void (*csr_emit)(void *c, uint32_t src, uint32_t dst);
typedef void (*csr_edges)(const struct kgenome_diag_scan *s, csr_emit emit, void *c);

struct csr_pass {
	uint32_t *head, *cur;
	uint16_t *edge;
	uint32_t  n;
};

static void csr_count(void *c, uint32_t src, uint32_t dst)
{
	struct csr_pass *p = c;

	(void)dst;
	p->head[src + 1u]++;
	p->n++;
}

static void csr_fill(void *c, uint32_t src, uint32_t dst)
{
	struct csr_pass *p = c;

	p->edge[p->head[src] + p->cur[src]++] = (uint16_t)dst;
}

static int csr_build(const struct kgenome_diag_scan *s, uint32_t nsrc, csr_edges edges, uint32_t **head, uint16_t **edge)
{
	struct csr_pass p = { NULL, NULL, NULL, 0 };
	uint32_t i;

	p.head = calloc((size_t)nsrc + 1u, sizeof *p.head);
	if (!p.head)
		return 0;
	edges(s, csr_count, &p);
	for (i = 0; i < nsrc; i++)
		p.head[i + 1u] += p.head[i];
	p.edge = malloc(((size_t)p.n + 1u) * sizeof *p.edge);
	p.cur = calloc((size_t)nsrc + 1u, sizeof *p.cur);
	if (!p.edge || !p.cur) {
		free(p.head);
		free(p.edge);
		free(p.cur);
		return 0;
	}
	edges(s, csr_fill, &p);
	free(p.cur);
	*head = p.head;
	*edge = p.edge;
	return 1;
}

/*
 * THE CHILDREN OF A BOUND NODE, found by what points at it and not by reading every node for each question.
 *
 * bind_from asked, for every spec under a bound parent, every node of the object whether it was that spec and linked to the parent
 * (callgrind over 71 php files: 35 M spec_ok calls for 78.5 k binds, 1.5 G of 4.1 G instructions). A node that is linked to the parent
 * has an input taken FROM it (linked() reads exactly that), so the candidates are the nodes that name the parent in `in[]`, plus - for a
 * parent that established the stack region - the nodes whose input is the stack. This index lists both, in ascending node order, and
 * the candidates are walked in that order, so the first node that passes is the one the full scan found first: the same spec_ok and
 * linked decide, over a smaller set that holds every node they could accept.
 *
 * Built when the first root has matched (a diagnose with no root pays nothing), once per match_each call. When memory is refused
 * the candidates are every node in turn, as before.
 */
struct succ_idx {
	uint32_t *head;         /* n_hit + 2: the nodes with an input from p are edge[head[p] .. head[p + 1]); the stack is the source n_hit */
	uint16_t *edge;         /* each list ascending, each node once */
	int       tried;        /* the build was attempted (and head is NULL when it failed) */
};

/* Is input `k` of the hit the first of its inputs to name that source (a node that names the same parent twice is one candidate, not two). */
static int first_from(const struct kgenome_diag_hit *h, uint8_t k)
{
	uint8_t j;

	for (j = 0; j < k; j++)
		if (h->in[j].from == h->in[k].from)
			return 0;
	return 1;
}

/* The edges of the index: a node that takes an input from a node is that node's successor, and one that takes an input from the stack is the stack's (the source n_hit). */
static void succ_edges(const struct kgenome_diag_scan *s, csr_emit emit, void *c)
{
	uint32_t i;
	uint8_t k;

	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < s->hit[i].n_in && k < 4u; k++) {
			uint16_t p = s->hit[i].in[k].from;

			if (!first_from(&s->hit[i], k))
				continue;
			if (p < s->n_hit)
				emit(c, p, i);
			else if (p == KGENOME_DIAG_FROM_STACK)
				emit(c, s->n_hit, i);
		}
}

static void succ_free(struct succ_idx *x)
{
	free(x->head);
	free(x->edge);
	memset(x, 0, sizeof *x);
}

static void succ_build(const struct kgenome_diag_scan *s, struct succ_idx *x)
{
	x->tried = 1;
	if (!csr_build(s, s->n_hit + 1u, succ_edges, &x->head, &x->edge))
		succ_free(x);
	x->tried = 1;
}

/* The walk over the candidates of one bound parent: the two ascending lists merged, or every node when there is no index. */
struct cand {
	const uint16_t *a, *ae, *b, *be;
	uint32_t        all, n;
	int             indexed;
};

static void cand_begin(struct cand *c, const struct kgenome_diag_scan *s, struct succ_idx *x, uint16_t parent)
{
	memset(c, 0, sizeof *c);
	if (!x->tried)
		succ_build(s, x);
	c->n = s->n_hit;
	if (!x->head)
		return;
	c->indexed = 1;
	c->a = x->edge + x->head[parent];
	c->ae = x->edge + x->head[parent + 1u];
	if (s->hit[parent].bits & KGENOME_DIAG_H_REGION_STACK) {
		c->b = x->edge + x->head[s->n_hit];
		c->be = x->edge + x->head[s->n_hit + 1u];
	}
}

/* The next candidate node, or n_hit when there is none. */
static uint32_t cand_next(struct cand *c)
{
	uint32_t v;

	if (!c->indexed)
		return c->all < c->n ? c->all++ : c->n;
	if (c->a < c->ae && (c->b >= c->be || *c->a <= *c->b)) {
		v = *c->a++;
		if (c->b < c->be && *c->b == v)
			c->b++;         /* in both lists: once */
		return v;
	}
	return c->b < c->be ? *c->b++ : c->n;
}

/*
 * ---- THE VALUE-FLOW GRAPH, AND REACHING ACROSS IT -----------------------
 *
 * A hit records its edges as "where each of my inputs came from", tagged
 * with a role. A join needs the transitive question - does the value a
 * socket read produced reach the region that was executed - and the bytes
 * do not have to arrive in one step: a stager may read into a scratch
 * buffer and copy that into the executable region, so the read and the
 * region are two hops apart with the copy between them. The old join asked
 * only whether one node was bound by both diagnoses, which is the zero-hop
 * case and the one a scratch buffer steps around.
 *
 * SO THE EDGES ARE TURNED INTO A DIRECTED GRAPH, once, and the join is a
 * walk. The direction is VALUE FLOW, which the role decides and which is
 * not the same as the in[] relation:
 *
 *   FD / SOURCE   the parent PRODUCED this value - it flows parent -> here
 *   TARGET        control goes to the parent region - its bytes are what
 *                 runs, so parent -> here (the region's value becomes the
 *                 execution)
 *   BUFFER        this call WRITES INTO the parent - the value flows the
 *                 other way, here -> parent (what we read/built lands in
 *                 that region)
 *
 * On a plain stager this makes net-open -> read -> region -> exec one
 * directed chain, and a read whose buffer is a scratch page instead of the
 * region extends it by exactly the copy node in between.
 */
/* The edges of the value-flow graph: an input from a node is an edge parent -> here, except where this call WRITES INTO the parent (the BUFFER role), which is here -> parent. */
static void flow_edges(const struct kgenome_diag_scan *s, csr_emit emit, void *c)
{
	uint32_t i;
	uint8_t k;

	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < s->hit[i].n_in; k++) {
			uint16_t p = s->hit[i].in[k].from;

			if (p >= s->n_hit)
				continue;       /* NONE / STACK, not a node */
			if (s->hit[i].in[k].role == KGENOME_DIAG_ROLE_BUFFER)
				emit(c, i, p);
			else
				emit(c, p, i);
		}
}

static int diag_flow_build(struct kgenome_diag_scan *s)
{
	uint64_t bytes, tmp;

	if (s->adj_built)
		return s->adj_head != NULL;
	s->adj_built = 1;
	if (!s->n_hit)
		return 0;
	/*
	 * THE GRAPH IS A PRODUCT, CHARGED TO THE SCAN'S LEDGER like the nodes it is
	 * built from: n_hit + 1 offsets and at most four edges a node (the
	 * stack/none sentinels are not edges), plus a cursor per node while it is
	 * filled. Refused when the caller's allowance cannot hold it - the ledger
	 * then says KGENOME_OVER_BUDGET on the scan, so the "no" a join gives
	 * afterwards is a "cannot say" to whoever reads the status.
	 */
	bytes = ((uint64_t)s->n_hit + 1u) * sizeof *s->adj_head +
		(uint64_t)s->n_hit * 4u * sizeof *s->adj_edge;
	tmp = (uint64_t)s->n_hit * sizeof(uint32_t);
	if (!kgenome_ledger_charge(&s->led, bytes + tmp))
		return 0;
	if (!csr_build(s, s->n_hit, flow_edges, &s->adj_head, &s->adj_edge)) {
		kgenome_ledger_release(&s->led, bytes + tmp);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	/* The cursor was scratch: only the graph stays charged. */
	kgenome_ledger_release(&s->led, tmp);
	return 1;
}

/*
 * WHICH EDGES A WALK MAY TAKE. Zero is every value-flow edge (the join between two diagnoses, and a matcher link
 * whose last hop consumes what it is handed). FLOW_VALUE keeps only the edges along which the VALUE ITSELF travels -
 * a node took the previous node's value in an input that is not BUFFER - and drops the edges where a call wrote into
 * a region (BUFFER, reversed): a pointer handed on through a wrapper is a value edge, the bytes a read put into a
 * region are not the region's pointer. FLOW_SHARED keeps only the edges whose link is SHARED (the same object).
 *
 * Decided per edge from the nodes' own inputs (at most four each), so the graph carries no second edge table: the
 * filter costs at most eight compares an edge, and a walk with mode zero pays none.
 */
#define FLOW_VALUE  1u
#define FLOW_SHARED 2u
/*
 * ONLY THROUGH AN INPUT THAT CARRIES DATA: a walk goes on from a node it entered through an input of role VALUE, SOURCE,
 * FD or TARGET (and through a write into a region, BUFFER reversed), never one it entered through a PATH or through an
 * input the route did not classify (role NONE). A path NAMES a resource and the node hands back a NEW object (a handle,
 * a module), not the path's value: `$h = fopen($_GET['p'], 'w'); fwrite($h, 'x');` writes a constant into a file the
 * request named, not the request's data - tests/unit/diag_text_golden.c pins that php_request_write does not fire on it,
 * and it did when the matcher walked through the open (measured 2026-11-14; the text route records that argument with
 * role NONE, the binary routes record no NONE link at all - kgenome_diag_role_of_arg). The last hop may be any role (the
 * child's own input: request -> decode -> include(it) is linked). A descriptor is walked: what a read takes through it
 * is what the socket or file carries (socket -> read -> region -> jump). The join between two diagnoses
 * (kof_diag_flow_join) walks with mode zero, as it always did.
 */
#define FLOW_DATA   4u

static int flow_edge_ok(const struct kgenome_diag_scan *s, uint16_t u, uint16_t v, unsigned mode)
{
	const struct kgenome_diag_hit *hu = &s->hit[u], *hv = &s->hit[v];
	uint8_t k;

	/* v took u's value: an input of v from u that is not a write into u */
	for (k = 0; k < hv->n_in && k < 4u; k++)
		if (hv->in[k].from == u && hv->in[k].role != KGENOME_DIAG_ROLE_BUFFER &&
		    (!(mode & FLOW_DATA) || (hv->in[k].role != KGENOME_DIAG_ROLE_PATH &&
					       hv->in[k].role != KGENOME_DIAG_ROLE_NONE)) &&
		    (!(mode & FLOW_SHARED) || hv->in[k].kind == KGENOME_DIAG_KIND_SHARED))
			return 1;
	if (mode & FLOW_VALUE)
		return 0;
	/* u wrote into v (u's BUFFER input names v): what u produced lands in v */
	for (k = 0; k < hu->n_in && k < 4u; k++)
		if (hu->in[k].from == v && hu->in[k].role == KGENOME_DIAG_ROLE_BUFFER &&
		    (!(mode & FLOW_SHARED) || hu->in[k].kind == KGENOME_DIAG_KIND_SHARED))
			return 1;
	return 0;
}

/*
 * ONE WALK'S STATE: the set it reached (a bit a node) and the same nodes in the order it reached them, which is the
 * walk's queue and also the list a caller clears the set by (flow_walk_reset touches only what was set, not n_hit / 8
 * bytes). `work` counts the edges examined against `cap`, shared by every walk of one match; NULL is no bound (the
 * join between two diagnoses: one walk of at most V + E over a visited set shared by its starts).
 */
struct flow_walk {
	uint8_t  *seen;
	uint16_t *q;
	uint32_t  n;
	uint64_t *work;
	uint64_t  cap;
};

static int bit_has(const uint8_t *b, uint32_t i)
{
	return (b[i >> 3] >> (i & 7u)) & 1u;
}

static void bit_set(uint8_t *b, uint32_t i)
{
	b[i >> 3] |= (uint8_t)(1u << (i & 7u));
}

static void flow_walk_reset(struct flow_walk *w)
{
	uint32_t i;

	for (i = 0; i < w->n; i++)
		w->seen[w->q[i] >> 3] = 0;
	w->n = 0;
}

/*
 * THE ONE REACHABILITY ROUTINE of the engine over a diagnose graph: the join between two diagnoses
 * (kof_diag_flow_join), a link through nodes in between (the matcher's reached tier) and the meeting of a diagnose's
 * two blocks (KOF_DIAG_B_JOIN) all walk here.
 *
 * Does the value at `start` reach a node whose bit is set in `tgt`, following value-flow edges `mode` allows. 1 yes,
 * 0 no, -1 the work bound ran out first (the walk could not say: the caller answers UNKNOWN, never no). With `tgt`
 * NULL it reaches everything it can and answers 0: w->seen and w->q are then the set. Breadth first, each node
 * expanded once; a start the set already holds answers 0 at once (a start an earlier start reached found no target).
 * The graph must be built (diag_flow_build).
 */
static int diag_flow_reach(const struct kgenome_diag_scan *s, uint16_t start, const uint8_t *tgt,
			   unsigned mode, struct flow_walk *w)
{
	uint32_t h;

	if (start >= s->n_hit || bit_has(w->seen, start))
		return 0;
	if (tgt && bit_has(tgt, start))
		return 1;
	bit_set(w->seen, start);
	h = w->n;
	w->q[w->n++] = start;
	while (h < w->n) {
		uint16_t u = w->q[h++];
		uint32_t j;

		for (j = s->adj_head[u]; j < s->adj_head[u + 1u]; j++) {
			uint16_t v = s->adj_edge[j];

			if (w->work && ++*w->work > w->cap)
				return -1;
			if (bit_has(w->seen, v))
				continue;
			if (mode && !flow_edge_ok(s, u, v, mode))
				continue;
			if (tgt && bit_has(tgt, v))
				return 1;
			bit_set(w->seen, v);
			w->q[w->n++] = v;
		}
	}
	return 0;
}

/*
 * DOES A NODE OF `cap` BOUND BY `b` REACH ANY NODE BOUND BY `a`.
 *
 * The join a verdict asks, as reachability rather than a shared node: the
 * bytes a socket read produced (a node of `cap`, bound by the net diagnose
 * `b`) flow - directly or through a copy - into the region the exec
 * diagnose `a` is about. `a_bind`/`b_bind` are the node sets the match
 * returned for each. A node of `cap` is one of that word or of a kind of it
 * (cap_is), as the matcher reads a spec: a socket read is net-recv, and a
 * join named mem-read must see it.
 */
int kof_diag_flow_join(struct kgenome_diag_scan *s, uint16_t cap,
		       const uint16_t *a_bind, uint8_t na,
		       const uint16_t *b_bind, uint8_t nb)
{
	uint8_t tgt[(KGENOME_MAX_INDEX + 7u) / 8u];
	uint8_t seen[(KGENOME_MAX_INDEX + 7u) / 8u];
	struct flow_walk w;
	uint16_t *q;
	uint8_t x;
	int hit = 0;

	if (!s || !diag_flow_build(s) || !a_bind || !b_bind)
		return 0;
	memset(tgt, 0, sizeof tgt);
	memset(seen, 0, sizeof seen);
	for (x = 0; x < na; x++)
		if (a_bind[x] < s->n_hit)
			bit_set(tgt, a_bind[x]);
	/* The walk's queue is scratch for this call, charged while it is held. */
	if (!kgenome_ledger_charge(&s->led, (uint64_t)s->n_hit * sizeof *q))
		return 0;
	q = malloc((size_t)s->n_hit * sizeof *q);
	if (!q) {
		kgenome_ledger_release(&s->led, (uint64_t)s->n_hit * sizeof *q);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	w.seen = seen;
	w.q = q;
	w.n = 0;
	w.work = NULL;
	w.cap = 0;
	for (x = 0; x < nb && !hit; x++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, b_bind[x]);

		if (h && cap_is(h->cap, cap))
			hit = diag_flow_reach(s, b_bind[x], tgt, 0u, &w) > 0;
	}
	free(q);
	kgenome_ledger_release(&s->led, (uint64_t)s->n_hit * sizeof *q);
	return hit;
}

/*
 * ==== A LINK THROUGH NODES IN BETWEEN (owner, 2026-11-14) ====================
 *
 * "A link must survive an intermediate wrapper and an intermediate call node" - an earlier rule, which the matcher
 * broke: a child was linked to its parent only when one of its inputs named the parent's node DIRECTLY (DL-1). A
 * pointer handed through a wrapper (mmap -> my_alloc returns it -> read into it), a value passed through a call node
 * (decode -> a call that hands it on -> eval) or bytes copied through a scratch buffer (read -> scratch -> copy ->
 * region -> jump) put one node between the two, and the diagnose did not match.
 *
 * SO A CHILD IS LINKED IN TWO TIERS, the direct one first:
 *
 *   direct   an input names the parent (or the stack region the parent made) - exactly what `linked` always
 *            answered, tried first and in the same order, so every match the direct rule found is found with the
 *            same nodes bound.
 *   reached  only when no direct candidate binds: an input of the child (its role and kind as the diagnose asks,
 *            in_takes) names a node x that the parent's value REACHES over the value-flow graph (diag_flow_reach, the
 *            one walk). Which edges the path may take is the decision below.
 *
 * DECIDED: AN INTERMEDIATE NODE NEED NOT BE OF A "PASS-THROUGH" KIND, and no table of such kinds exists. The edge
 * says it: a node whose input took the previous node's value carries that value on (it is the node's own input,
 * found by the route that read the program), and a node that wrote into a region put its bytes there. A list of
 * pass-through capabilities would be a second statement of what the links already record, and a wrapper the list
 * did not name would break the link again. What the path may take depends on what the CHILD does with x:
 *
 *   the child's input is BUFFER (it writes through x's pointer): the POINTER must be the parent's - every hop a
 *            value edge (FLOW_VALUE). A region that a read wrote into is not the read's pointer.
 *   any other role (it consumes x: runs it, reads from it, uses it as a descriptor, a path or a value): any
 *            value-flow edge - bytes read into a scratch buffer and copied into the region the child jumps to
 *            are the bytes it runs.
 *   and on every path: only through an input that carries data (FLOW_DATA, above) - not through a PATH, which names a
 *            resource the node makes a new object of, nor through an input the route did not classify. That is the
 *            whole of the "pass-through" decision: by the ROLE of the input, not by the capability of the node.
 *
 * THE KIND (KOF_DIAG_B_PRODUCED / _SHARED): the child's own input carries it, as before (the last hop). A kind is a
 * statement about the OBJECT - the child holds what the parent made, or the same object - and an object travels only
 * along value edges: a call that wrote into a region did not hand the region its object. So a tail that names a kind
 * walks value edges only (FLOW_VALUE), and SHARED ("the same object", which a produced hop breaks) SHARED value edges
 * only (FLOW_SHARED); a tail that names neither walks every edge. Pinned by tests/unit/diag_kind.c: copy_to_user
 * reads the buffer copy_from_user filled, and that is NOT copy_from_user's produced object (the content hop through
 * the allocation is not taken for PRODUCED). MAY counts as PROVEN on every hop (audit R4, see `linked`).
 *
 * THE BOUND (a cap bounds cost and is reported, never a silent no): the walks of one match share
 * KOF_DIAG_REACH_WALKS whole-graph walks of work (edges examined, candidates tried), at least KOF_DIAG_REACH_FLOOR.
 * A parent's reached set is walked once and kept for all its children (a level of the tree holds one), so a star
 * costs two walks a head candidate whose direct tier failed. When the bound runs out, or the scratch the reached
 * tier needs is refused by the scan's ledger, the reached tier stops for the rest of that match and a "no" becomes
 * KOF_DIAG_MATCH_UNKNOWN (kof_diag_match_known), which the scanner reports as the diagnose's unknown bit.
 */
#define KOF_DIAG_REACH_WALKS 32u
#define KOF_DIAG_REACH_FLOOR 65536u

/* What one bound parent reaches, kept while its children are bound: the set over every edge, the set over value
 * edges only, and the nodes that take an input from a reached node (the candidates), ascending. */
struct reach_lvl {
	struct flow_walk all, val;
	uint8_t  *cand;
	uint16_t *cl;
	uint32_t  ncl;
	uint16_t  from;
	unsigned  kmode;
	int       made;
	uint8_t  *mem;
};

struct bind_ctx {
	struct kgenome_diag_scan *s;
	const struct kof_diag *d;
	struct succ_idx idx;
	int       flow;         /* 0 not asked yet, 1 the value-flow graph is built, -1 it could not be */
	uint64_t  work, cap;    /* the reached tier's work, one bound for the whole match */
	int       limited;      /* the bound or the scratch ran out: a "no" from this match is a "cannot say" */
	uint64_t  charged;      /* scratch bytes charged to the scan's ledger (kgenome_ledger_try) */
	struct reach_lvl *lvl;  /* one a depth of the tree, made on first use */
	uint8_t   blk[256];     /* the block of each node: 0 the first root's, 1 the second root's */
	uint8_t  *tgt;          /* while the second block is bound: the nodes the first block bound */
	struct flow_walk jw;    /* the walk a KOF_DIAG_B_JOIN node asks */
	uint8_t  *jmem;
};

/* Scratch for the match, charged to the scan's ledger while it is held. NULL, and the match is limited, when the
 * ledger or the allocator refuses: the reached tier then answers "cannot say", never "no". */
static void *bc_alloc(struct bind_ctx *m, size_t n)
{
	void *p;

	if (!kgenome_ledger_try(&m->s->led, n)) {
		m->limited = 1;
		return NULL;
	}
	p = calloc(1, n);
	if (!p) {
		kgenome_ledger_release(&m->s->led, n);
		m->limited = 1;
		return NULL;
	}
	m->charged += n;
	return p;
}

static void bc_free(struct bind_ctx *m)
{
	uint8_t k;

	if (m->lvl)
		for (k = 0; k < m->d->n_node; k++)
			free(m->lvl[k].mem);
	free(m->lvl);
	free(m->tgt);
	free(m->jmem);
	kgenome_ledger_release(&m->s->led, m->charged);
	m->charged = 0;
}

/* The value-flow graph for the reached tier, built once a scan, and the match's work bound sized from it. */
static int bc_flow(struct bind_ctx *m)
{
	if (!m->flow) {
		m->flow = diag_flow_build(m->s) ? 1 : -1;
		if (m->flow > 0) {
			uint64_t ve = (uint64_t)m->s->n_hit + m->s->adj_head[m->s->n_hit];

			m->cap = (uint64_t)KOF_DIAG_REACH_WALKS * ve;
			if (m->cap < KOF_DIAG_REACH_FLOOR)
				m->cap = KOF_DIAG_REACH_FLOOR;
		} else if (m->s->n_hit) {
			m->limited = 1;         /* refused by the ledger (the scan says OVER_BUDGET) or memory */
		}
	}
	return m->flow > 0;
}

/* The bytes of a set of n bits, rounded to two so the node lists placed after it stay aligned for uint16_t. */
static size_t set_bytes(uint32_t n)
{
	return ((size_t)n + 15u) / 16u * 2u;
}

/* A walk's two arrays out of one block. */
static void walk_place(struct flow_walk *w, uint8_t **at, uint32_t n, uint64_t *work, uint64_t cap)
{
	w->seen = *at;
	*at += set_bytes(n);
	w->q = (uint16_t *)(void *)*at;
	*at += (size_t)n * sizeof *w->q;
	w->n = 0;
	w->work = work;
	w->cap = cap;
}

static int u16_cmp(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;

	return (x > y) - (x < y);
}

/*
 * THE REACHED SETS OF `from` AT THIS DEPTH, and the candidates they give: kept until the depth binds another parent
 * or asks another kind. 0 when the work bound or the scratch ran out (the match is then limited).
 */
static int lvl_make(struct bind_ctx *m, uint8_t depth, uint16_t from, unsigned kmode)
{
	const struct kgenome_diag_scan *s = m->s;
	const uint32_t n = s->n_hit;
	struct reach_lvl *L;
	uint32_t i;

	if (!m->lvl) {
		m->lvl = calloc(m->d->n_node, sizeof *m->lvl);
		if (!m->lvl) {
			m->limited = 1;
			return 0;
		}
	}
	L = &m->lvl[depth];
	if (!L->mem) {
		/* three sets of n bits and three lists of n nodes */
		uint8_t *at = L->mem = bc_alloc(m, 3u * (set_bytes(n) + (size_t)n * sizeof(uint16_t)));

		if (!at)
			return 0;
		walk_place(&L->all, &at, n, &m->work, m->cap);
		walk_place(&L->val, &at, n, &m->work, m->cap);
		L->cand = at;
		at += set_bytes(n);
		L->cl = (uint16_t *)(void *)at;
	}
	if (L->made && L->from == from && L->kmode == kmode)
		return 1;
	L->made = 0;
	flow_walk_reset(&L->all);
	flow_walk_reset(&L->val);
	if (diag_flow_reach(s, from, NULL, kmode, &L->all) < 0 ||
	    diag_flow_reach(s, from, NULL, kmode | FLOW_VALUE, &L->val) < 0) {
		m->limited = 1;
		return 0;
	}
	/* The candidates: every node with an input from a reached node other than the parent itself (those are the
	 * direct tier's). Through the successor index when it was built, else every node. */
	L->ncl = 0;
	if (m->idx.head) {
		for (i = 1; i < L->all.n; i++) {
			uint16_t x = L->all.q[i];
			uint32_t j;

			for (j = m->idx.head[x]; j < m->idx.head[x + 1u]; j++) {
				uint16_t c = m->idx.edge[j];

				if (!bit_has(L->cand, c)) {
					bit_set(L->cand, c);
					L->cl[L->ncl++] = c;
				}
			}
		}
		for (i = 0; i < L->ncl; i++)
			L->cand[L->cl[i] >> 3] = 0;
		/* ascending, as the direct tier walks its candidates: the first that binds is the lowest node */
		qsort(L->cl, L->ncl, sizeof *L->cl, u16_cmp);
	} else if (L->all.n > 1u) {
		for (i = 0; i < n; i++)
			L->cl[L->ncl++] = (uint16_t)i;
	}
	L->from = from;
	L->kmode = kmode;
	L->made = 1;
	return 1;
}

/* Is the child linked to `from` through nodes in between: an input it takes (in_takes) names a node the parent
 * reached - over value edges only when the child writes through it (BUFFER), over every edge otherwise. */
static int linked_reach(const struct reach_lvl *L, const struct kgenome_diag_hit *child, uint16_t from,
			uint32_t n_hit, uint8_t role, uint8_t want)
{
	uint8_t k;

	for (k = 0; k < child->n_in && k < 4u; k++) {
		uint16_t x = child->in[k].from;

		if (x >= n_hit || x == from || !in_takes(&child->in[k], role, want))
			continue;
		if (bit_has(child->in[k].role == KGENOME_DIAG_ROLE_BUFFER ? L->val.seen : L->all.seen, x))
			return 1;
	}
	return 0;
}

/*
 * A NODE MARKED KOF_DIAG_B_JOIN binds only a node that reaches what the first block bound (zero hops: the same node).
 * Every other node passes. A walk that ran out of work, or a graph that could not be built, is a refusal and limits
 * the match.
 */
static int join_ok(struct bind_ctx *m, uint8_t c, uint16_t i)
{
	int r;

	if (!(m->d->node[c].bits & KOF_DIAG_B_JOIN))
		return 1;
	if (!m->tgt)
		return 0;
	if (bit_has(m->tgt, i))
		return 1;
	if (!bc_flow(m))
		return 0;
	if (!m->jmem) {
		uint8_t *at = m->jmem = bc_alloc(m, set_bytes(m->s->n_hit) + (size_t)m->s->n_hit * sizeof(uint16_t));

		if (!at)
			return 0;
		walk_place(&m->jw, &at, m->s->n_hit, &m->work, m->cap);
	}
	r = diag_flow_reach(m->s, i, m->tgt, 0u, &m->jw);
	flow_walk_reset(&m->jw);
	if (r < 0)
		m->limited = 1;
	return r > 0;
}

static int bind_from(struct bind_ctx *m, uint8_t k, uint16_t *bound, uint8_t depth);

/* The reached tier for child spec c of bound node k: see the note above. */
static int bind_reached(struct bind_ctx *m, uint8_t k, uint8_t c, uint16_t *bound, uint8_t depth)
{
	const struct kgenome_diag_scan *s = m->s;
	const struct kof_diag_node *sp = &m->d->node[c];
	const unsigned kb = sp->bits & (KOF_DIAG_B_PRODUCED | KOF_DIAG_B_SHARED);
	const unsigned kmode = FLOW_DATA | (kb == KOF_DIAG_B_SHARED ? FLOW_VALUE | FLOW_SHARED
					       : kb == KOF_DIAG_B_PRODUCED ? FLOW_VALUE : 0u);
	struct reach_lvl *L;
	uint32_t q;

	if (m->limited || !bc_flow(m) || !lvl_make(m, depth, bound[k], kmode))
		return 0;
	L = &m->lvl[depth];
	for (q = 0; q < L->ncl; q++) {
		uint16_t i = L->cl[q];
		const struct kgenome_diag_hit *h = &s->hit[i];

		if (++m->work > m->cap) {
			m->limited = 1;
			return 0;
		}
		/* tried by the direct tier, with the same subtree to bind */
		if (linked(h, bound[k], &s->hit[bound[k]], sp->role, sp->bits))
			continue;
		if (!spec_ok(s, h, sp) || !linked_reach(L, h, bound[k], s->n_hit, sp->role, sp->bits))
			continue;
		bound[c] = i;
		if (!join_ok(m, c, i))
			continue;
		if (bind_from(m, c, bound, (uint8_t)(depth + 1u)))
			return 1;
		if (m->limited)
			return 0;
		/* the deeper level may have walked from another parent; this level's sets are its own */
	}
	return 0;
}

/* Bind spec[k] and everything under it. `bound` holds the node index chosen
 * for each spec so far. Depth is the diagnose's own, which is a handful. */
static int bind_from(struct bind_ctx *m, uint8_t k, uint16_t *bound, uint8_t depth)
{
	const struct kgenome_diag_scan *s = m->s;
	const struct kof_diag *d = m->d;
	uint8_t c;

	for (c = 0; c < d->n_node; c++) {
		struct cand cd;
		uint32_t i;

		if (d->node[c].parent != k)
			continue;
		cand_begin(&cd, s, &m->idx, bound[k]);
		for (i = cand_next(&cd); i < s->n_hit; i = cand_next(&cd)) {
			if (!spec_ok(s, &s->hit[i], &d->node[c]))
				continue;
			if (!linked(&s->hit[i], bound[k], &s->hit[bound[k]],
				    d->node[c].role, d->node[c].bits))
				continue;
			bound[c] = (uint16_t)i;
			if (!join_ok(m, c, (uint16_t)i))
				continue;
			if (bind_from(m, c, bound, (uint8_t)(depth + 1u)))
				goto next;
		}
		if (bind_reached(m, k, c, bound, depth))
			goto next;
		return 0;               /* a branch of the tree has no match */
next:
		;
	}
	return 1;
}

/*
 * EVERY PLACE A TREE MATCHES, one call of `fn` for each, with the node each of
 * the diagnose's own nodes was bound to. `fn` returns zero to stop.
 *
 * THIS IS THE MATCHER; kof_diag_match is the first-instance reading of it.
 * It stopped at the first root that satisfied the tree and every later
 * question - the names a diagnose carries, in particular - was answered from
 * that one place. A module with two probes on two symbols has two matches of
 * the same tree, and a diagnose "carrying" a name from the second was a
 * diagnose the engine had never looked at.
 *
 * TWO BLOCKS (KOF_DIAG_DECLARE_JOIN): for each instance of the first block, every instance of the second whose
 * KOF_DIAG_B_JOIN nodes reach what that first instance bound. The join is checked WHILE the second block binds, so
 * a candidate that fails it gives way to the next one (a socket's first read may be the length read and its second
 * the stage). The first block is bound as a single block always was: its first instance per root candidate. Each
 * second-block root tried costs one unit of the match's work bound.
 *
 * Answers 1 when a bound ran out (the reached tier, a join, the scratch): a "no" is then a "cannot say".
 */
typedef int (*diag_inst_fn)(void *user, const uint16_t *bound, uint8_t n_node);

static int match_each(struct kgenome_diag_scan *s, const struct kof_diag *d,
		      diag_inst_fn fn, void *user)
{
	uint16_t bound[256];
	uint32_t i, j;
	uint8_t root = KOF_DIAG_NO_PARENT, root2 = KOF_DIAG_NO_PARENT, k;
	struct bind_ctx m;
	int lim;

	/* n_node is a uint8_t, so 255 is its ceiling already - the bound that
	 * matters is `bound[]` below holding one slot per node, and 256 is
	 * more than a uint8_t can index past. */
	if (!s || !d || !d->n_node)
		return 0;
	memset(&m, 0, sizeof m);
	m.s = s;
	m.d = d;
	for (k = 0; k < d->n_node; k++)
		if (d->node[k].parent == KOF_DIAG_NO_PARENT) {
			if (root == KOF_DIAG_NO_PARENT)
				root = k;
			else if (root2 == KOF_DIAG_NO_PARENT)
				root2 = k;
		}
	if (root == KOF_DIAG_NO_PARENT)
		return 0;               /* no root: not a tree */
	/* The block of each node: the root its parents lead to (the loader refused a cycle; the step bound is the node count). */
	for (k = 0; k < d->n_node; k++) {
		uint8_t p = k, steps = 0;

		while (d->node[p].parent != KOF_DIAG_NO_PARENT && d->node[p].parent < d->n_node && steps++ < d->n_node)
			p = d->node[p].parent;
		m.blk[k] = (uint8_t)(p == root2);
	}

	for (i = 0; i < s->n_hit; i++) {
		if (!spec_ok(s, &s->hit[i], &d->node[root]))
			continue;
		memset(bound, 0xff, sizeof bound);
		bound[root] = (uint16_t)i;
		if (!bind_from(&m, root, bound, 0))
			continue;
		if (root2 == KOF_DIAG_NO_PARENT) {
			if (!fn(user, bound, d->n_node))
				goto out;
			continue;
		}
		/* The second block, against what this instance of the first bound. */
		if (!bc_flow(&m))
			break;
		if (!m.tgt && !(m.tgt = bc_alloc(&m, set_bytes(s->n_hit))))
			break;
		for (k = 0; k < d->n_node; k++)
			if (!m.blk[k] && bound[k] < s->n_hit)
				bit_set(m.tgt, bound[k]);
		for (j = 0; j < s->n_hit; j++) {
			if (!spec_ok(s, &s->hit[j], &d->node[root2]))
				continue;
			if (++m.work > m.cap) {
				m.limited = 1;
				break;
			}
			bound[root2] = (uint16_t)j;
			if (!join_ok(&m, root2, (uint16_t)j) || !bind_from(&m, root2, bound, 0))
				continue;
			if (!fn(user, bound, d->n_node))
				goto out;
		}
		for (k = 0; k < d->n_node; k++)
			if (!m.blk[k] && bound[k] < s->n_hit)
				m.tgt[bound[k] >> 3] = 0;
		if (m.limited)
			break;
	}
out:
	lim = m.limited;
	succ_free(&m.idx);
	bc_free(&m);
	return lim;
}

struct first_match {
	uint16_t *out;
	uint8_t  *n_out;
	int       found;
};

static int first_cb(void *user, const uint16_t *bound, uint8_t n_node)
{
	struct first_match *f = user;
	uint8_t k, n = 0;

	/*
	 * EVERY BOUND NODE COMES BACK, not a declared subset.
	 *
	 * The diagnose used to mark the ones it offered as join points, and
	 * only those were returned. That put a fact about TWO behaviours
	 * inside the declaration of ONE - the author of the stager's read had
	 * to know the socket diagnose existed - and it silently lost the join
	 * whenever the mark was on the wrong node. The verdict names the
	 * capability it wants the two to meet at instead, so the engine has to
	 * hand back everything they bound.
	 */
	for (k = 0; k < n_node && f->out; k++)
		f->out[n++] = bound[k];
	if (f->n_out)
		*f->n_out = n;
	f->found = 1;
	return 0;                       /* the first instance is the answer */
}

/* The first instance, and whether a bound of the match ran out (match_each). */
static int match_first(struct kgenome_diag_scan *s, const struct kof_diag *d,
		       uint16_t *bind_out, uint8_t *n_bind, int *limited)
{
	struct first_match f;
	int lim;

	if (n_bind)
		*n_bind = 0;
	f.out = bind_out;
	f.n_out = n_bind;
	f.found = 0;
	lim = match_each(s, d, first_cb, &f);
	if (limited)
		*limited = lim;
	return f.found;
}

int kof_diag_match(struct kgenome_diag_scan *s, const struct kof_diag *d,
		   uint16_t *bind_out, uint8_t *n_bind)
{
	return match_first(s, d, bind_out, n_bind, NULL);
}

/*
 * DID THE SCAN STOP SHORT OF WHAT THE OBJECT HOLDS. The ONE place the engine
 * reads the genome's answer about its own completeness: kgenome_diag_scan_status
 * is KGENOME_OK only when no limit fired in any routine (a node store that filled,
 * a run stopped while it was still going, a name or a link refused, the
 * caller's memory allowance spent), so a 0 from the matcher is a "no" only then.
 */
static int scan_limited(const struct kgenome_diag_scan *s)
{
	return kgenome_diag_scan_status(s) != KGENOME_OK;
}

/* A "no" is UNKNOWN when the scan stopped short OR the match itself did (the reached tier's work bound, a join's
 * walk, the scratch the ledger refused): either way the relation may be there and was not looked at. */
int kof_diag_match_known(struct kgenome_diag_scan *s, const struct kof_diag *d,
			 uint16_t *bind_out, uint8_t *n_bind)
{
	int limited = 0;

	if (match_first(s, d, bind_out, n_bind, &limited))
		return KOF_DIAG_MATCH_YES;
	return limited || scan_limited(s) ? KOF_DIAG_MATCH_UNKNOWN : KOF_DIAG_MATCH_NO;
}

struct name_probe {
	const struct kgenome_diag_scan *s;
	const char *name;
	int         found;
};

/* Was the name read at ANY node this instance bound. */
static int name_cb(void *user, const uint16_t *bound, uint8_t n_node)
{
	struct name_probe *np = user;
	uint8_t k;

	for (k = 0; k < n_node; k++) {
		uint16_t b = bound[k];

		if (b < np->s->n_hit &&
		    kgenome_diag_str_at_node(np->s, np->s->hit[b].cap, b, np->name)) {
			np->found = 1;
			return 0;
		}
	}
	return 1;
}

int kof_diag_scan_name(struct kgenome_diag_scan *s, const struct kof_diag *d,
		       const char *name)
{
	struct name_probe np;

	if (!s || !d || !name)
		return 0;
	np.s = s;
	np.name = name;
	np.found = 0;
	match_each(s, d, name_cb, &np);
	return np.found;
}

uint32_t kof_diag_graph_build(struct kgenome_diag_scan *s, uint8_t *out,
			      uint32_t cap)
{
	uint32_t i, need, cut = 0;

	if (!s || !out || !s->n_hit)
		return 0;
	need = KOF_GR_HDRLEN + s->n_hit * KOF_GR_RECLEN;
	if (need > cap)
		return 0;       /* refused whole - a half graph answers wrong */
	memset(out, 0, need);
	out[KOF_GR_H_COUNT]      = (uint8_t)s->n_hit;
	out[KOF_GR_H_COUNT + 1u] = (uint8_t)(s->n_hit >> 8);
	out[KOF_GR_H_COUNT + 2u] = (uint8_t)(s->n_hit >> 16);
	out[KOF_GR_H_COUNT + 3u] = (uint8_t)(s->n_hit >> 24);
	for (i = 0; i < s->n_hit; i++) {
		const struct kgenome_diag_hit *h = &s->hit[i];
		uint8_t *r = out + KOF_GR_HDRLEN + i * KOF_GR_RECLEN;
		uint8_t k, nin = h->n_in > KOF_GR_IN_FIT
			       ? (uint8_t)KOF_GR_IN_FIT : h->n_in;

		/* The record holds KOF_GR_IN_FIT links; link k sits at byte
		 * 22 + 4k and the guard here is the local one, not the
		 * arithmetic of kofdiagtree.h held in the reader's head. */
		if (h->n_in > nin)
			cut++;

		kof_st_le64(r + KOF_GR_R_AT, h->at);
		kof_st_le64(r + KOF_GR_R_ATTR, h->attr);
		kof_st_le16(r + KOF_GR_R_CAP, h->cap);
		kof_st_le16(r + KOF_GR_R_FLAGS, h->flags);
		/* No bit is told to a rule yet: the one there was said `attr`
		 * is a name's offset, and names are no longer carried that
		 * way. The byte stays in the format at zero. */
		r[KOF_GR_R_BITS] = 0u;
		r[KOF_GR_R_NIN] = nin;
		for (k = 0; k < nin; k++) {
			uint8_t *p = r + KOF_GR_R_IN + k * KOF_GR_IN_STRIDE;

			kof_st_le16(p, h->in[k].from);
			p[2] = h->in[k].role;
			p[3] = h->in[k].kind == KGENOME_DIAG_KIND_SHARED
			     ? (uint8_t)KGENOME_DIAG_KIND_SHARED
			     : (uint8_t)KGENOME_DIAG_KIND_PRODUCED;
		}
	}
	/* A node of the scan keeps up to four inputs, the record two. The rest
	 * are not in the block and that is said where the scan's other limits are
	 * (rule 4): the status the engine reads for "this graph stops short". */
	if (cut)
		kgenome_diag_note(s, KGENOME_TRUNCATED);
	return need;
}

