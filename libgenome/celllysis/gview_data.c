/*
 * gview_data.c - the data type of a graph to look at (gview.h): its allocation in one block through the caller's allocator, and what a box holds.
 * The places are the viewer's (kofexamine/kv_graph.c); nothing here lays anything out.
 */
#include <stdio.h>
#include <string.h>

#include "cfg_private.h"
#include "gview.h"

enum kgenome_status kgenome_gv_alloc(struct kgenome_gv *gv, const struct kgenome_gv_size *sz, const struct kgenome_budget *budget,
				     const struct kgenome_cfg_mem *mem)
{
	const uint32_t n_node = sz->n_node, n_edge = sz->n_edge, n_xline = sz->n_xline, n_note = sz->n_note, n_aside = sz->n_aside;
	/* each array starts on 8 bytes: an element of the aside holds a uint64 and the arrays before it are not a multiple of 8 (12-byte edges, 100-byte notes) */
	const size_t o_edge = ((size_t)n_node * sizeof *gv->node + 7u) & ~(size_t)7u, o_xline = (o_edge + (size_t)n_edge * sizeof *gv->edge + 7u) & ~(size_t)7u,
		     o_note = (o_xline + (size_t)n_xline * sizeof *gv->xline + 7u) & ~(size_t)7u,
		     o_aside = (o_note + (size_t)n_note * sizeof *gv->note + 7u) & ~(size_t)7u, tot = o_aside + (size_t)n_aside * sizeof *gv->aside;
	char *p;

	memset(gv, 0, sizeof *gv);
	gv->id_prefix = 'N';
	if (kgenome_cfg_over(budget, tot))
		return KGENOME_OVER_BUDGET;
	if (!tot)
		return KGENOME_OK;              /* nothing to hold, nothing allocated: the free has nothing to give back */
	p = kgenome_cfg_alloc(mem, tot);
	if (!p)
		return KGENOME_NOMEM;
	memset(p, 0, tot);
	gv->node = n_node ? (struct kgenome_gv_node *)(void *)p : NULL;
	gv->edge = n_edge ? (struct kgenome_gv_edge *)(void *)(p + o_edge) : NULL;
	gv->xline = n_xline ? (struct kgenome_gv_xline *)(void *)(p + o_xline) : NULL;
	gv->note = n_note ? (struct kgenome_gv_note *)(void *)(p + o_note) : NULL;
	gv->aside = n_aside ? (struct kgenome_gv_aside *)(void *)(p + o_aside) : NULL;
	gv->n_node = n_node;
	gv->n_edge = n_edge;
	gv->n_xline = n_xline;
	gv->n_note = n_note;
	gv->n_aside = n_aside;
	gv->bytes_ = tot;
	return KGENOME_OK;
}

void kgenome_gv_free(struct kgenome_gv *gv, const struct kgenome_cfg_mem *mem)
{
	if (!gv)
		return;
	/* the five arrays are one block: it starts at the first array that exists */
	{
		void *base = gv->node ? (void *)gv->node : gv->edge ? (void *)gv->edge : gv->xline ? (void *)gv->xline : gv->note ? (void *)gv->note : (void *)gv->aside;

		kgenome_cfg_release(mem, base, gv->bytes_);
	}
	memset(gv, 0, sizeof *gv);
}


/* The index of the first extra line of `node` in the sorted array, or n_xline when it has none. */
static uint32_t xline_first(const struct kgenome_gv *gv, uint32_t node)
{
	uint32_t lo = 0, hi = gv->n_xline;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (gv->xline[mid].node < node)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo;
}

const char *kgenome_gv_box_line(const struct kgenome_gv *gv, uint32_t node, uint32_t i, char *buf, size_t cap)
{
	uint32_t at, held = 0, shown, k;

	if (!gv || node >= gv->n_node)
		return NULL;
	if (i < 2u)
		return gv->node[node].line[i];
	at = xline_first(gv, node);
	while (at + held < gv->n_xline && gv->xline[at + held].node == node)
		held++;
	shown = held < KGENOME_GV_BOX_X ? held : KGENOME_GV_BOX_X;
	k = i - 2u;
	if (k < shown)
		return gv->xline[at + k].text;
	if (k == shown && gv->node[node].xtotal > shown && buf && cap) {
		snprintf(buf, cap, "+%u more%s%s", (unsigned)(gv->node[node].xtotal - shown), gv->xnoun[0] ? " " : "", gv->xnoun);
		return buf;
	}
	return NULL;
}
