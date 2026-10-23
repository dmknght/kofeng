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

/* A node satisfies a spec when it has the capability, carries every flag the
 * spec demands, and is not one whose meaning the walk could not read. The
 * last is the point of KGENOME_DIAG_H_ARG_UNKNOWN: a `mmap` whose prot could not
 * be followed is not evidence of a buffer OR of a code region. */
static int spec_ok(const struct kgenome_diag_scan *s,
		   const struct kgenome_diag_hit *h,
		   const struct kof_diag_node *sp)
{
	/*
	 * THE WORD THE RULE NAMED, OR ANY KIND OF IT. A rule saying mem-read
	 * is satisfied by net-recv, because net-recv IS a mem-read whose
	 * descriptor turned out to be a socket - see kgenome_nucleo_cap_generic.
	 * Comparing for equality made a rule stop matching whenever the
	 * engine learned something more about the program it described.
	 */
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
static int linked(const struct kgenome_diag_hit *child, uint16_t parent_idx,
		  const struct kgenome_diag_hit *parent, uint8_t role,
		  uint8_t want)
{
	uint8_t i;

	/*
	 * AND OF WHICH KIND, where the diagnose says - see KOF_DIAG_B_SHARED.
	 * Neither bit is "either", which is what a diagnose written before
	 * the kinds existed asked for and still asks for.
	 */
	want &= (uint8_t)(KOF_DIAG_B_PRODUCED | KOF_DIAG_B_SHARED);

	for (i = 0; i < child->n_in; i++) {
		/* A node that names no role takes the link whatever the role: the
		 * role is the child's own argument, which the engine derived from
		 * the capability (kgenome_diag_role_of_arg) and the diagnose need not
		 * restate. */
		if (role != KGENOME_DIAG_ROLE_NONE && child->in[i].role != role)
			continue;
		if (want) {
			uint8_t is = child->in[i].kind == KGENOME_DIAG_KIND_SHARED
				     ? (uint8_t)KOF_DIAG_B_SHARED
				     : (uint8_t)KOF_DIAG_B_PRODUCED;

			if (!(want & is))
				continue;
		}
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

struct bind_ctx {
	const struct kgenome_diag_scan *s;
	const struct kof_diag *d;
	struct succ_idx idx;
};

/* Bind spec[k] and everything under it. `bound` holds the node index chosen
 * for each spec so far. Depth is the diagnose's own, which is a handful. */
static int bind_from(struct bind_ctx *m, uint8_t k, uint16_t *bound)
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
			if (bind_from(m, c, bound))
				goto next;
		}
		return 0;               /* a branch of the tree has no match */
next:
		;
	}
	return 1;
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
 * Does the value at `start` reach any node whose bit is set in `tgt`,
 * following value-flow edges. One O(V+E) walk over a reused frontier - the
 * visited set means a node is expanded once however many starts share it.
 */
static int diag_flow_reach(struct kgenome_diag_scan *s, uint16_t start,
			   const uint8_t *tgt, uint8_t *seen, uint16_t *stk)
{
	uint32_t sp = 0;

	if (start >= s->n_hit || (seen[start >> 3] & (1u << (start & 7u))))
		return 0;
	if (tgt[start >> 3] & (1u << (start & 7u)))
		return 1;
	seen[start >> 3] |= (uint8_t)(1u << (start & 7u));
	stk[sp++] = start;
	while (sp) {
		uint16_t u = stk[--sp];
		uint32_t j;

		for (j = s->adj_head[u]; j < s->adj_head[u + 1u]; j++) {
			uint16_t v = s->adj_edge[j];

			if (seen[v >> 3] & (1u << (v & 7u)))
				continue;
			if (tgt[v >> 3] & (1u << (v & 7u)))
				return 1;
			seen[v >> 3] |= (uint8_t)(1u << (v & 7u));
			stk[sp++] = v;
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
 * returned for each.
 */
int kof_diag_flow_join(struct kgenome_diag_scan *s, uint16_t cap,
		       const uint16_t *a_bind, uint8_t na,
		       const uint16_t *b_bind, uint8_t nb)
{
	uint8_t tgt[(KGENOME_MAX_INDEX + 7u) / 8u];
	uint8_t seen[(KGENOME_MAX_INDEX + 7u) / 8u];
	uint16_t *stk;
	uint8_t x;
	int hit = 0;

	if (!s || !diag_flow_build(s) || !a_bind || !b_bind)
		return 0;
	memset(tgt, 0, sizeof tgt);
	memset(seen, 0, sizeof seen);
	for (x = 0; x < na; x++)
		if (a_bind[x] < s->n_hit)
			tgt[a_bind[x] >> 3] |= (uint8_t)(1u << (a_bind[x] & 7u));
	/* The walk's frontier is scratch for this call, charged while it is held. */
	if (!kgenome_ledger_charge(&s->led, (uint64_t)s->n_hit * sizeof *stk))
		return 0;
	stk = malloc((size_t)s->n_hit * sizeof *stk);
	if (!stk) {
		kgenome_ledger_release(&s->led, (uint64_t)s->n_hit * sizeof *stk);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	for (x = 0; x < nb && !hit; x++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, b_bind[x]);

		if (h && h->cap == cap)
			hit = diag_flow_reach(s, b_bind[x], tgt, seen, stk);
	}
	free(stk);
	kgenome_ledger_release(&s->led, (uint64_t)s->n_hit * sizeof *stk);
	return hit;
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
 */
typedef int (*diag_inst_fn)(void *user, const uint16_t *bound, uint8_t n_node);

static void match_each(const struct kgenome_diag_scan *s, const struct kof_diag *d,
		       diag_inst_fn fn, void *user)
{
	uint16_t bound[256];
	uint32_t i;
	uint8_t root;
	struct bind_ctx m = { s, d, { NULL, NULL, 0 } };

	/* n_node is a uint8_t, so 255 is its ceiling already - the bound that
	 * matters is `bound[]` below holding one slot per node, and 256 is
	 * more than a uint8_t can index past. */
	if (!s || !d || !d->n_node)
		return;
	for (root = 0; root < d->n_node; root++)
		if (d->node[root].parent == KOF_DIAG_NO_PARENT)
			break;
	if (root == d->n_node)
		return;                 /* no root: not a tree */

	for (i = 0; i < s->n_hit; i++) {
		if (!spec_ok(s, &s->hit[i], &d->node[root]))
			continue;
		memset(bound, 0xff, sizeof bound);
		bound[root] = (uint16_t)i;
		if (!bind_from(&m, root, bound))
			continue;
		if (!fn(user, bound, d->n_node)) {
			succ_free(&m.idx);
			return;
		}
	}
	succ_free(&m.idx);
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

int kof_diag_match(const struct kgenome_diag_scan *s, const struct kof_diag *d,
		   uint16_t *bind_out, uint8_t *n_bind)
{
	struct first_match f;

	if (n_bind)
		*n_bind = 0;
	f.out = bind_out;
	f.n_out = n_bind;
	f.found = 0;
	match_each(s, d, first_cb, &f);
	return f.found;
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

int kof_diag_match_known(const struct kgenome_diag_scan *s, const struct kof_diag *d,
			 uint16_t *bind_out, uint8_t *n_bind)
{
	if (kof_diag_match(s, d, bind_out, n_bind))
		return KOF_DIAG_MATCH_YES;
	return scan_limited(s) ? KOF_DIAG_MATCH_UNKNOWN : KOF_DIAG_MATCH_NO;
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

int kof_diag_scan_name(const struct kgenome_diag_scan *s, const struct kof_diag *d,
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

/* ---- loading -------------------------------------------------------------
 *
 * A RECORD IS ONE DIAGNOSE and nothing else - no module, no pattern, no blob.
 * The records of a database are carried in diag-<kind>.kdig packs (see
 * load_diagnoses in dbloader.c), which is a file beside the packs rather than a
 * section inside one: the pack header carries a fixed-size section table, so
 * one more section is a format change every database in existence has to be
 * rebuilt for, and none of what a pack exists to carry applies here.
 *
 * EVERYTHING IS BOUNDS CHECKED AGAINST THE RECORD'S OWN LENGTH, and a record
 * that does not add up is refused whole rather than loaded in part. A diagnose
 * half read is a diagnose that matches something its author did not write.
 */

int kof_diag_load(kof_buf rec, struct kof_diag *out, const struct kof_diag_store *st)
{
	const uint8_t *b = rec.p;
	const uint64_t n = rec.n;
	struct kof_diag_node *node = st->node;
	char *name = st->name, *needs = st->needs;
	const uint32_t name_cap = st->name_cap, needs_cap = st->needs_cap;
	const uint8_t max_node = st->max_node;
	uint32_t n_node, nlen, i;
	/* How much of the string store a node attribute has taken - the
	 * signs below continue from here, because both are words this
	 * diagnose carries and one buffer is one thing to bound. */
	uint32_t nused = 0;
	uint64_t at;

	if (!b || !out || !node || !name || n < 4u)
		return 0;
	n_node = (uint32_t)b[0] | ((uint32_t)b[1] << 8);
	nlen   = b[3];
	if (!n_node || n_node > max_node || nlen + 1u > name_cap)
		return 0;
	at = 4u + nlen;
	if (n < at || (n - at) / 8u < n_node)
		return 0;

	memcpy(name, b + 4, nlen);
	name[nlen] = 0;
	memset(out, 0, sizeof *out);
	out->analysis = b[2];
	out->n_node = (uint8_t)n_node;
	out->name = name;
	out->node = node;

	for (i = 0; i < n_node; i++) {
		const uint8_t *r = b + at;
		uint32_t alen;

		if ((uint64_t)(r - b) + 8u > n)
			return 0;
		node[i].cap    = (uint16_t)(r[0] | (r[1] << 8));
		node[i].flags  = (uint16_t)(r[2] | (r[3] << 8));
		node[i].parent = r[4];
		node[i].role   = r[5];
		node[i].bits   = r[6];
		node[i].attr_len = r[7];
		alen = r[7];
		at += 8u;
		if (at + alen > n)
			return 0;
		/*
		 * (kind, length, payload)*, and an unknown kind is skipped by
		 * its length rather than refused - that is what the length is
		 * for. A length that runs past the run refuses the record,
		 * like everything else here.
		 */
		{
			uint32_t k = 0;

			while (k + 2u <= alen) {
				uint32_t kind = b[at + k];
				uint32_t klen = b[at + k + 1u];

				k += 2u;
				if (k + klen > alen)
					return 0;
				/*
				 * THE NAME GOES IN THE DIAGNOSE'S OWN
				 * STRING STORE, beside the signs - it is the
				 * same kind of thing, a word this diagnose
				 * carries, and a second buffer would be a
				 * second thing to bound.
				 */
				if (kind == KDIG_ATTR_SYM && klen &&
				    needs && needs_cap) {
					if (nused + klen + 1u > needs_cap)
						return 0;
					memcpy(needs + nused, b + at + k, klen);
					needs[nused + klen] = 0;
					node[i].sym = needs + nused;
					nused += klen + 1u;
				}
				if (kind == KDIG_ATTR_VALUE && klen == 8u) {
					uint64_t v = 0;
					unsigned q;

					for (q = 0; q < 8u; q++)
						v |= (uint64_t)b[at + k + q]
						     << (q * 8u);
					node[i].val = v;
				}
				k += klen;
			}
		}
		at += alen;
		/*
		 * A PARENT THAT IS NOT A NODE HERE, or a node that is its own
		 * parent, is a file this build did not write. Refuse rather
		 * than clamp: a clamped index points at a real node, and the
		 * diagnose then quietly means something else.
		 */
		if (node[i].parent != KOF_DIAG_NO_PARENT &&
		    (node[i].parent >= n_node || node[i].parent == i))
			return 0;
		if (node[i].role >= KGENOME_DIAG_ROLE_COUNT)
			return 0;
	}
	/*
	 * ---- THE SIGNS, IF THE PACK CARRIES ANY -------------------------
	 *
	 * A trailing section, so a pack written before they existed simply
	 * ends after its nodes and answers none. Refused WHOLE on anything
	 * that does not add up, like the rest of the record: a diagnose with
	 * half its signs read would be filtered by a condition nobody wrote.
	 */
	if (needs && needs_cap && at < n) {
		uint32_t cnt = b[at++], k, used = nused;

		/*
		 * THE NAMES AN OLDER PACK WROTE HERE ARE SKIPPED, not read: the
		 * sign is now a capability (KDIG_SEC_NEEDS), and a diagnose
		 * built before that simply has no sign, which is the cheaper
		 * kind of wrong - it runs where it could have been spared.
		 */
		if (cnt > KOF_DIAG_MAX_NEED)
			return 0;
		for (k = 0; k < cnt; k++) {
			uint32_t L;

			if (at >= n)
				return 0;
			L = b[at++];
			if (!L || L >= KOF_DIAG_NEED_LEN || at + L > n)
				return 0;
			at += L;
		}
		/*
		 * ---- AND THE TAGGED SECTIONS AFTER THEM ----------------
		 *
		 * An unknown tag is SKIPPED and not refused: the length is
		 * there so a later build can add a section without every
		 * reader having to be taught it first. A length that runs
		 * past the end is a different matter and refuses the whole
		 * record, like everything else here.
		 */
		while (at + 2u <= n) {
			uint32_t tag = b[at], len = b[at + 1u];

			at += 2u;
			if (at + len > n)
				return 0;
			/*
			 * (fact u16, value u64) pairs - see KOF_DIAG_HAS_ATTRB.
			 * A FACT THIS BUILD DOES NOT KNOW REFUSES THE WHOLE
			 * RECORD: a condition silently dropped is a diagnose
			 * that runs on the files its author excluded, and it
			 * would do so quietly.
			 */
			/* The capabilities the object must import - u16 each. */
			if (tag == KDIG_SEC_NEEDS) {
				uint32_t q;

				if ((len & 1u) || len / 2u > KOF_DIAG_MAX_NEED)
					return 0;
				for (q = 0; q < len / 2u; q++)
					out->needcap[q] = (uint16_t)(b[at + 2u * q] |
							(b[at + 2u * q + 1u] << 8));
				out->n_needcap = (uint8_t)(len / 2u);
			}
			/* The two calls the head is built from - see
			 * KOF_DIAG_DECLARE_SEQUENCE. A length that is not two caps
			 * refuses the record: half a sequence would be a head built
			 * from something nobody wrote. */
			if (tag == KDIG_SEC_SEQUENCE) {
				if (len != 4u)
					return 0;
				out->seq_first = (uint16_t)(b[at] | (b[at + 1] << 8));
				out->seq_then  = (uint16_t)(b[at + 2] | (b[at + 3] << 8));
				if (!out->seq_first || !out->seq_then)
					return 0;
			}
			if (tag == KDIG_SEC_USERS && len >= 1u) {
				out->users_known = 1;
				out->n_users = b[at];
				out->users_off = (uint32_t)at;
				out->users_len = len;
			}
			/*
			 * THE SYMBOLS THE CODE MUST REFER INTO - see
			 * KOF_DIAG_DECLARE_SYMBOL. Same shape and the same string store as
			 * the signs, and refused whole on anything that does not
			 * add up, for the same reason: a diagnose with half its
			 * references read would be gated by a condition nobody
			 * wrote.
			 */
			if (tag == KDIG_SEC_REFS && len >= 1u && needs && needs_cap) {
				uint32_t cnt2 = b[at], z, p2 = (uint32_t)(at + 1u);

				if (cnt2 > KOF_DIAG_MAX_NEED)
					return 0;
				for (z = 0; z < cnt2; z++) {
					uint32_t L2;

					if (p2 >= at + len)
						return 0;
					L2 = b[p2++];
					if (!L2 || L2 >= KOF_DIAG_NEED_LEN ||
					    p2 + L2 > at + len ||
					    used + L2 + 1u > needs_cap)
						return 0;
					memcpy(needs + used, b + p2, L2);
					needs[used + L2] = 0;
					out->ref[z] = needs + used;
					used += L2 + 1u;
					p2 += L2;
				}
				out->n_ref = (uint8_t)cnt2;
			}
			/* The disease: an id and its type, nothing else. A length that is
			 * not five refuses the record like the rest - half an id is a
			 * different behaviour - and so does a type that is no maltype. */
			if (tag == KDIG_SEC_DISEASE) {
				if (len != 5u || b[at + 4u] >= KOF_MALTYPE_COUNT)
					return 0;
				out->disease = (uint32_t)b[at] | ((uint32_t)b[at + 1u] << 8) |
					       ((uint32_t)b[at + 2u] << 16) |
					       ((uint32_t)b[at + 3u] << 24);
				out->disease_type = b[at + 4u];
				if (!out->disease)
					return 0;
			}
			if (tag == KDIG_SEC_WHEN) {
				uint32_t q;

				if (len % 10u)
					return 0;
				if (len / 10u > KOF_DIAG_MAX_WHEN)
					return 0;
				for (q = 0; q + 10u <= len; q += 10u) {
					const uint8_t *w = b + at + q;
					uint64_t v = 0;
					unsigned t;
					uint16_t fc = (uint16_t)(w[0] |
							 (w[1] << 8));

					if (!fc || fc >= KOF_FACT_COUNT)
						return 0;
					for (t = 0; t < 8u; t++)
						v |= (uint64_t)w[2 + t]
						     << (t * 8u);
					out->when[out->n_when].fact = fc;
					out->when[out->n_when].val = v;
					out->n_when++;
				}
			}
			at += len;
		}
	}

	/* Exactly one root, because the matcher descends from one. */
	{
		uint32_t roots = 0;

		for (i = 0; i < n_node; i++)
			if (node[i].parent == KOF_DIAG_NO_PARENT)
				roots++;
		if (roots != 1u)
			return 0;
	}
	return 1;
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

