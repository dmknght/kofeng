#define _GNU_SOURCE

/*
 * kv_graph.c - the graph drawing: one try, the shrinking of the prefix, the entry points. See kv_graph.h for the contract, the style and the bounds.
 *
 * THE PARTS. The phases below are in kv_graph_rank.c ((1) and the first half of (3)), kv_graph_route.c (lanes, ports, tracks) and kv_graph_paint.c (segments, cells, the window);
 * what they share is kv_graph_private.h. This file runs them in order and owns the bound on how many times the prefix may shrink.
 *
 * ORDER OF WORK. (1) the walk: reverse post-order from the entry (the successors of a node are visited last-first so its FIRST edge ends up left),
 * back edges, levels; linear in the whole graph. (2) the prefix of the walk that is to be drawn. (3) for that prefix only: boxes, the edges as
 * chains of items through virtual nodes, the barycenter sweeps, the placement, the lanes, the ports, the tracks of every channel, the rows, the
 * segments, the cells. When the canvas does not fit the caps the prefix shrinks and (3) runs again, a bounded number of times.
 *
 * GEOMETRY. Ranks are bands of rows (a band is as tall as its tallest box); between two bands is a CHANNEL: an exit row (the letters), the tracks
 * (one row each, horizontal runs of edges that change column) and an arrow row. Channel 0 above the first band and channel NL below the last
 * exist only when a lane edge needs a track in them. A track holds the horizontal runs of its channel that leave one blank column between them.
 * Every line segment of an edge is orthogonal; consecutive segments of an edge share their corner cell, and the glyph of a cell is a function of
 * the sides the lines through it connect to, so a corner, a crossing and a plain run cannot be mistaken for each other.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv_graph_private.h"

#define SHRINK_TRIES 10u

static int lay_try(const struct kv_graph_in *in, const struct kv_graph_walk *wk, uint32_t P, struct kv_graph *g)
{
	const uint32_t max_cols = in->max_cols ? in->max_cols : KV_GRAPH_COLS_DEF, max_rows = in->max_rows ? in->max_rows : KV_GRAPH_ROWS_DEF;
	struct kv_graph_ctx c;
	int rc;

	memset(&c, 0, sizeof c);
	c.in = in;
	c.wk = wk;
	c.g = g;
	g->n_edge_not_drawn = g->n_line_cut = g->n_share = g->n_lane = g->n_dummy = g->n_skipped = 0;
	rc = kv_graph_step_alloc(&c, P);
	if (rc != TRY_OK)
		return rc;
	kv_graph_step_wires(&c);
	kv_graph_step_order(&c);
	kv_graph_step_place(&c);
	kv_graph_step_lanes(&c);
	g->n_edge_not_drawn = c.edge_cut + (in->n_edge - c.drawn_deg);
	kv_graph_step_ports(&c);
	kv_graph_step_tracks(&c);
	if (c.width > max_cols || c.height > max_rows || (uint64_t)c.width * c.height > KV_GRAPH_CELLS_MAX)
		rc = TRY_FIT;
	else
		rc = kv_graph_step_emit(&c);
	free(c.mem);
	if (rc != TRY_OK) {
		free(g->mem_);
		free(g->cell);
		g->mem_ = NULL;
		g->box = NULL;
		g->wire = NULL;
		g->seg = NULL;
		g->cell = NULL;
		g->n_box = g->n_wire = g->n_seg = 0;
		g->width = g->height = 0;
	}
	return rc;
}

void kv_graph_free(struct kv_graph *g)
{
	if (!g)
		return;
	free(g->mem_);
	free(g->cell);
	memset(g, 0, sizeof *g);
}

enum kv_graph_status kv_graph_layout(const struct kv_graph_in *in, struct kv_graph *g)
{
	struct kv_graph_walk wk;
	void *wm;
	uint32_t P, tries, i;
	int rc = TRY_FIT;

	if (!g)
		return KV_GS_BAD_INPUT;
	memset(g, 0, sizeof *g);
	if (!in || !in->text || (in->n_edge && !in->edge) || (in->n_node && in->entry >= in->n_node)) {
		g->status = KV_GS_BAD_INPUT;
		return g->status;
	}
	g->n_node = in->n_node;
	if (!in->n_node)
		return g->status;
	wm = malloc(WALK_BYTES(in->n_node, in->n_edge));
	if (!wm) {
		g->status = KV_GS_NOMEM;
		return g->status;
	}
	if (!kv_graph_walk_make(in, wm, &wk)) {
		free(wm);
		g->status = KV_GS_BAD_INPUT;
		return g->status;
	}
	P = in->max_node ? in->max_node : KV_GRAPH_MAX_NODE;
	if (P > in->n_node)
		P = in->n_node;
	for (tries = 0; tries <= SHRINK_TRIES; tries++) {
		rc = lay_try(in, &wk, P, g);
		if (rc != TRY_FIT || P <= 1u)
			break;
		P = P * 3u / 4u;
		if (!P)
			P = 1;
		g->n_shrunk++;
	}
	if (rc == TRY_NOMEM) {
		free(wm);
		kv_graph_free(g);
		g->n_node = in->n_node;
		g->status = KV_GS_NOMEM;
		return g->status;
	}
	if (rc == TRY_FIT) {                            /* even one box does not fit the canvas: nothing is drawn and everything is counted */
		P = 0;
		g->width = g->height = 0;
		g->n_edge_not_drawn = in->n_edge;
		g->n_dummy = g->n_rank = g->n_lane = g->n_share = 0;
	}
	g->n_not_drawn = in->n_node - P;
	for (i = 0; i < KV_GRAPH_REST && P + i < in->n_node; i++)
		g->rest[g->n_rest++] = wk.rpo[P + i];
	/* the edges of nodes that are not drawn are in the list too, while it has room */
	for (i = P; i < in->n_node && g->n_skipped < KV_GRAPH_REST; i++) {
		uint32_t e;

		for (e = wk.first[wk.rpo[i]]; e < wk.first[wk.rpo[i] + 1u] && g->n_skipped < KV_GRAPH_REST; e++) {
			g->skip[g->n_skipped].edge = e;
			g->skip[g->n_skipped++].why = KV_GW_END;
		}
	}
	if (g->n_not_drawn || g->n_edge_not_drawn || g->n_line_cut)
		g->status = KV_GS_TRUNCATED;
	free(wm);
	return g->status;
}
