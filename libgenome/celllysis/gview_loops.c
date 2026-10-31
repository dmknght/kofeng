/*
 * gview_loops.c - WHICH EDGES OF A GRAPH TO LOOK AT ARE LOOPS (gview.h: `loop` of an edge, KGENOME_GV_NF_LOOP_HEAD of a node). The engine decides what a loop is,
 * the viewer only draws it (CLAUDE.md rule 11): a RETREATING edge is one to a node still on the walk's stack (a depth-first walk from `entry`, edges in the order they
 * are listed); it is a LOOP link when its target DOMINATES its source (a natural loop: the target is the loop head and every way round passes through it), and RETREAT when
 * it does not (irreducible flow: a cycle with two entries). The dominators are the iterative algorithm of Cooper, Harvey and Kennedy over the reverse post-order, with the
 * dominator tree numbered once so that "does a dominate b" is two comparisons.
 *
 * BOUNDS. The walk is linear. The dominators are computed for at most KGENOME_GV_DOM_MAX nodes and the iteration is bounded in passes (32) and in intersection steps
 * (64 per node and edge plus a floor): past either the retreating edges are all RETREAT, no head is marked and the result is TRUNCATED - "not computed" is said, never
 * guessed as a loop. A reducible graph settles in two passes.
 */
#include <stdint.h>
#include <string.h>

#include "cfg_private.h"
#include "gview.h"

#define NONE_ 0xffffffffu
#define DOM_PASSES 32u

struct lp {
	uint32_t *first, *rpo, *pos, *stk, *cur, *idom, *tin, *tout, *pfirst, *pidx, *child, *sib;
	uint8_t  *st, *ret;
};

static size_t lp_bytes(uint32_t n, uint32_t m)
{
	return ((size_t)n * 11u + (size_t)n + 2u + (size_t)m) * sizeof(uint32_t) + (size_t)n + (size_t)m + 16u;
}

static void lp_carve(struct lp *p, void *mem, uint32_t n, uint32_t m)
{
	uint32_t *u = mem;

	p->first = u; u += n + 1u;
	p->rpo = u; u += n;
	p->pos = u; u += n;
	p->stk = u; u += n;
	p->cur = u; u += n;
	p->idom = u; u += n;
	p->tin = u; u += n;
	p->tout = u; u += n;
	p->pfirst = u; u += n + 1u;
	p->pidx = u; u += m;
	p->child = u; u += n;
	p->sib = u; u += n;
	p->st = (uint8_t *)u;
	p->ret = p->st + n;
}

static uint32_t intersect(const struct lp *p, uint32_t a, uint32_t b, uint64_t *steps)
{
	while (a != b) {
		while (p->pos[a] > p->pos[b]) {
			a = p->idom[a];
			(*steps)++;
		}
		while (p->pos[b] > p->pos[a]) {
			b = p->idom[b];
			(*steps)++;
		}
	}
	return a;
}

enum kgenome_status kgenome_gv_loops(struct kgenome_gv *gv, const struct kgenome_budget *budget, const struct kgenome_cfg_mem *mem)
{
	const uint32_t n = gv->n_node, m = gv->n_edge;
	struct lp p;
	void *w;
	size_t bytes;
	uint32_t i, e, sp = 0, cnt = 0;
	int exact;

	if (!n || !m)
		return KGENOME_OK;
	bytes = lp_bytes(n, m);
	if (kgenome_cfg_over(budget, bytes))
		return KGENOME_OVER_BUDGET;
	w = kgenome_cfg_alloc(mem, bytes);
	if (!w)
		return KGENOME_NOMEM;
	memset(w, 0, bytes);
	lp_carve(&p, w, n, m);
	for (e = 0; e < m; e++) {
		if (gv->edge[e].from >= n || gv->edge[e].to >= n || (e && gv->edge[e].from < gv->edge[e - 1u].from)) {
			kgenome_cfg_release(mem, w, bytes);
			return KGENOME_BAD_INPUT;
		}
		p.first[gv->edge[e].from + 1u]++;
	}
	for (i = 0; i < n; i++)
		p.first[i + 1u] += p.first[i];
	for (i = 0; i < n; i++)
		p.cur[i] = p.first[i];
	/* the walk: retreating edges and the reverse post-order of what the entry reaches */
	{
		const uint32_t s0 = gv->entry < n ? gv->entry : 0u;

		p.st[s0] = 1;
		p.stk[sp++] = s0;
	}
	while (sp) {
		const uint32_t u = p.stk[sp - 1u];

		if (p.cur[u] < p.first[u + 1u]) {
			const uint32_t ed = p.cur[u]++, s = gv->edge[ed].to;

			if (!p.st[s]) {
				p.st[s] = 1;
				p.stk[sp++] = s;
			} else if (p.st[s] == 1) {
				p.ret[ed] = 1;
			}
			continue;
		}
		sp--;
		p.st[u] = 2;
		p.rpo[cnt++] = u;
	}
	for (i = 0; i < cnt / 2u; i++) {
		const uint32_t x = p.rpo[i];

		p.rpo[i] = p.rpo[cnt - 1u - i];
		p.rpo[cnt - 1u - i] = x;
	}
	for (i = 0; i < n; i++)
		p.pos[i] = NONE_;
	for (i = 0; i < cnt; i++)
		p.pos[p.rpo[i]] = i;
	exact = n <= KGENOME_GV_DOM_MAX;
	if (exact) {
		/* predecessors of the reachable nodes, then the dominators */
		uint64_t steps = 0, limit = 64ull * ((uint64_t)n + m) + 1024u;
		uint32_t pass, changed = 1;

		for (e = 0; e < m; e++)
			if (p.pos[gv->edge[e].from] != NONE_)
				p.pfirst[gv->edge[e].to + 1u]++;
		for (i = 0; i < n; i++)
			p.pfirst[i + 1u] += p.pfirst[i];
		for (i = 0; i < n; i++)
			p.cur[i] = p.pfirst[i];
		for (e = 0; e < m; e++)
			if (p.pos[gv->edge[e].from] != NONE_)
				p.pidx[p.cur[gv->edge[e].to]++] = gv->edge[e].from;
		for (i = 0; i < n; i++)
			p.idom[i] = NONE_;
		p.idom[p.rpo[0]] = p.rpo[0];
		for (pass = 0; changed && pass < DOM_PASSES && steps <= limit; pass++) {
			changed = 0;
			for (i = 1; i < cnt && steps <= limit; i++) {
				const uint32_t b = p.rpo[i];
				uint32_t k, ni = NONE_;

				for (k = p.pfirst[b]; k < p.pfirst[b + 1u]; k++) {
					const uint32_t q = p.pidx[k];

					if (p.idom[q] == NONE_)
						continue;
					ni = ni == NONE_ ? q : intersect(&p, q, ni, &steps);
				}
				if (ni != NONE_ && p.idom[b] != ni) {
					p.idom[b] = ni;
					changed = 1;
				}
			}
		}
		if (changed || steps > limit)
			exact = 0;
	}
	if (exact) {
		/* number the dominator tree: tin and tout of every reachable node, iteratively */
		uint32_t t = 0;

		for (i = 0; i < n; i++)
			p.child[i] = p.sib[i] = NONE_;
		for (i = cnt; i-- > 1;) {
			const uint32_t b = p.rpo[i];

			p.sib[b] = p.child[p.idom[b]];
			p.child[p.idom[b]] = b;
		}
		sp = 0;
		p.stk[sp++] = p.rpo[0];
		p.tin[p.rpo[0]] = t++;
		memcpy(p.cur, p.child, (size_t)n * sizeof *p.cur);
		while (sp) {
			const uint32_t u = p.stk[sp - 1u];

			if (p.cur[u] != NONE_) {
				const uint32_t c = p.cur[u];

				p.cur[u] = p.sib[c];
				p.tin[c] = t++;
				p.stk[sp++] = c;
			} else {
				p.tout[u] = t++;
				sp--;
			}
		}
	}
	for (e = 0; e < m; e++) {
		const uint32_t u = gv->edge[e].from, v = gv->edge[e].to;

		gv->edge[e].loop = KGENOME_GV_LOOP_NONE;
		if (!p.ret[e])
			continue;
		if (exact && p.tin[v] <= p.tin[u] && p.tout[u] <= p.tout[v]) {
			gv->edge[e].loop = KGENOME_GV_LOOP_LINK;
			gv->node[v].flags |= KGENOME_GV_NF_LOOP_HEAD;
		} else {
			gv->edge[e].loop = KGENOME_GV_LOOP_RETREAT;
		}
	}
	kgenome_cfg_release(mem, w, bytes);
	return exact ? KGENOME_OK : KGENOME_TRUNCATED;
}
