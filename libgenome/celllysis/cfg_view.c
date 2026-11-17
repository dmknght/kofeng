/*
 * cfg_view.c - what a viewer draws of a function's graph and signature, made by the lib so that the viewer
 * computes nothing (CLAUDE.md rule 11): the reachable blocks with the offset of each, its terminator class, its
 * successors as indices into the SAME table, the low 32 bits of its final label, and the canonical hash and
 * keys of the signature. The status travels with it: a dialog that shows a graph cut short must say so.
 */
#include <string.h>

#include "cfg_private.h"

enum kgenome_status kgenome_cfg_view_make(const struct kgenome_cfg_view_req *r, struct kgenome_cfg_view *out)
{
	const struct kgenome_cfg *g;
	struct kgenome_cfg_view_block *vb;
	struct kgenome_cfg_view_unreach *ub;
	uint32_t *rank, i, k = 0, u = 0;
	size_t vb_n, rk_n, un_n;

	memset(out, 0, sizeof *out);
	if (!r || !r->g || !r->sign || !r->in) {
		out->status = KGENOME_BAD_INPUT;
		return out->status;
	}
	g = r->g;
	out->canon = r->sign->canon;
	out->n_key = r->sign->n_key;
	memcpy(out->key, r->sign->key, sizeof out->key);
	out->n_edge = g->n_edge;
	out->status = kgenome_status_merge(g->status, r->sign->status);
	if (!g->n_all)
		return out->status;
	/* ONE allocation holds the reachable blocks and then the unreachable ones; the rank table is the temporary. */
	vb_n = (size_t)g->n_blk * sizeof *vb;
	un_n = (size_t)(g->n_all - g->n_blk) * sizeof *ub;
	rk_n = (size_t)g->n_all * sizeof *rank;
	if (kgenome_cfg_over(r->budget, vb_n + un_n + rk_n)) {
		out->status = kgenome_status_merge(out->status, KGENOME_OVER_BUDGET);
		return out->status;
	}
	vb = kgenome_cfg_alloc(&r->mem, vb_n + un_n);
	rank = vb ? kgenome_cfg_alloc(&r->mem, rk_n) : NULL;
	if (!vb || !rank) {
		kgenome_cfg_release(&r->mem, vb, vb_n + un_n);
		out->status = kgenome_status_merge(out->status, KGENOME_NOMEM);
		return out->status;
	}
	for (i = 0; i < g->n_all; i++)
		rank[i] = g->b[i].reach ? k++ : KGENOME_CFG_NONE;
	for (i = 0; i < g->n_all; i++) {
		const struct kgenome_cfg_block *b = &g->b[i];
		struct kgenome_cfg_view_block *o;

		if (!b->reach) {
			ub = (struct kgenome_cfg_view_unreach *)(void *)(vb + g->n_blk);
			ub[u].off = r->in[b->first].at;
			ub[u++].n_insn = b->n_insn;
			continue;
		}
		o = &vb[rank[i]];
		o->off = r->in[b->first].at;
		o->n_insn = b->n_insn;
		o->term = b->term;
		o->succ[0] = b->succ[0] == KGENOME_CFG_NONE ? KGENOME_CFG_NONE : rank[b->succ[0]];
		o->succ[1] = b->succ[1] == KGENOME_CFG_NONE ? KGENOME_CFG_NONE : rank[b->succ[1]];
		o->label = r->label ? (uint32_t)r->label[i] : 0u;
		o->in_deg = b->in_deg;
		o->out_deg = b->out_deg;
		o->n_call = b->n_call;
		o->call_kinds = b->call_kinds;
	}
	kgenome_cfg_release(&r->mem, rank, rk_n);
	out->n_blk = g->n_blk;
	out->blk = vb;
	out->n_unr = u;
	out->unr = (const struct kgenome_cfg_view_unreach *)(const void *)(vb + g->n_blk);
	out->bytes_ = vb_n + un_n;
	return out->status;
}

void kgenome_cfg_view_free(struct kgenome_cfg_view *v, const struct kgenome_cfg_mem *mem)
{
	if (!v)
		return;
	kgenome_cfg_release(mem, (void *)(uintptr_t)v->blk, v->bytes_);
	memset(v, 0, sizeof *v);
}
