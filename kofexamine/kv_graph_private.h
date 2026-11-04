/*
 * kv_graph_private.h - what the parts of the graph drawing share (kv_graph.c, kv_graph_rank.c, kv_graph_route.c, kv_graph_paint.c). Not part of the surface:
 * kv_graph.h is. The parts are the PHASES of one layout, in the order they run:
 *   kv_graph_rank.c   the walk (ranks), the boxes and the chains of items, the order inside a rank, the placement      (kv_graph_walk_make, kv_graph_step_alloc/wires/order/place)
 *   kv_graph_route.c  the lanes of the left margin, the ports, the tracks of every channel, the rows                  (kv_graph_step_lanes/ports/tracks)
 *   kv_graph_paint.c  the segments and the cells of what the steps decided, and the window                           (kv_graph_step_emit, kv_graph_window)
 *   kv_graph.c        one try, the shrinking of the prefix, the entry points                                          (kv_graph_layout, kv_graph_free)
 * Pure, like the header of the surface: no engine, no view, no kv.h.
 */
#ifndef KV_GRAPH_PRIVATE_H
#define KV_GRAPH_PRIVATE_H

#include <stddef.h>
#include <stdint.h>

#include "kv_graph.h"

/* ---- the walk (linear in the graph) ---- */

struct kv_graph_walk {
	uint32_t *rpo, *pos, *stk, *cur, *first, *lvl;
	uint8_t  *st, *bk;      /* per node: 0 new, 1 on the stack, 2 done; per edge: 1 = drawn through a lane */
};

#define WALK_BYTES(n, m) ((size_t)(n) * (6u * sizeof(uint32_t) + 1u) + sizeof(uint32_t) + (size_t)(m))

/* ---- the layout of the drawn prefix ---- */

struct kv_graph_wr {                     /* one drawn edge */
	uint32_t edge, from, to;        /* input edge; items (the walk position of the ends) */
	uint32_t d0, nc;                /* the dummies: items d0 .. d0 + nc - 1 */
	uint32_t p0;                    /* the first piece */
	uint32_t j, k;                  /* this is the j-th of the k drawn edges of its source */
	uint8_t  cond, loop, back, skip, self;
	uint8_t  out_shared;
	int32_t  out_col, in_col, lane_col;
	uint32_t lane;                  /* 0 nearest the boxes */
	uint32_t ce, ci;                /* the channels of a lane edge: below the tail, below the head (the head is entered from below) */
};

#define NOCOL ((int32_t)0x80000000)
struct kv_graph_hp {                     /* a horizontal run that needs a track */
	uint32_t chan, id, track, wire;
	int32_t  lo, hi;
	int32_t  top0, top1;            /* the columns of the vertical runs that come down to it from the top of the channel (NOCOL: none) */
	int32_t  bot;                   /* the column of the vertical run that goes on down from it to the bottom of the channel */
};

struct kv_graph_port {
	uint32_t key;                   /* item * 2 + side: 0 the bottom of the box (edges out, back edges in), 1 its top (forward edges in) */
	int32_t  other;
	uint32_t wire;
	uint8_t  role;                  /* 0 the edge leaves here, 1 a forward edge arrives, 2 a back edge arrives from below */
};

struct kv_graph_top {                    /* a column a vertical run of a channel starts from at its top: where an edge leaves a box or a virtual node, or comes up to a head */
	uint32_t chan;
	int32_t  col;
	uint32_t wire;
};

struct kv_graph_lay {
	uint32_t P, Dub, D, I, NL, W, Npc, Nback, Nhp;
	uint32_t *layer, *bw, *bh, *key, *ordpos, *lay0, *lay_item;
	int32_t  *x;
	struct kv_graph_wr *wr;
	uint32_t *pc_a, *pc_b, *pc_w;
	uint32_t *dn_first, *dn_pc, *up_first, *up_pc;
	int64_t  *tmp_a, *tmp_b, *tmp_w;
	uint32_t *tmp_c;
	uint32_t *chan_t, *chan_y0, *band_y0, *band_h;
	uint32_t *track_of;
	struct kv_graph_hp *hp;
	struct kv_graph_port *port;
	struct kv_graph_top *top, *bot;
	uint32_t n_top, n_bot;
	uint8_t  *occ;
	int32_t  *tr_end;
};

struct kv_graph_ctx {
	const struct kv_graph_in *in;
	const struct kv_graph_walk *wk;
	struct kv_graph *g;
	struct kv_graph_lay L;
	char *mem;
	uint32_t ub_edge, ub_dummy, drawn_deg, edge_cut, lines_cut, nlane;
	int32_t M, Wb;
	uint32_t width, height;
};

enum { TRY_OK = 0, TRY_FIT, TRY_NOMEM };

static inline int32_t kv_graph_item_cx(const struct kv_graph_lay *L, uint32_t it)
{
	return L->x[it] + (int32_t)(L->bw[it] / 2u);
}

/* kv_graph_rank.c */
int kv_graph_walk_make(const struct kv_graph_in *in, void *mem, struct kv_graph_walk *wk);
void kv_graph_note_skip(struct kv_graph *g, uint32_t edge, uint8_t why);
int kv_graph_step_alloc(struct kv_graph_ctx *c, uint32_t P);
void kv_graph_step_wires(struct kv_graph_ctx *c);
void kv_graph_step_order(struct kv_graph_ctx *c);
void kv_graph_step_place(struct kv_graph_ctx *c);
/* kv_graph_route.c */
void kv_graph_step_lanes(struct kv_graph_ctx *c);
void kv_graph_step_ports(struct kv_graph_ctx *c);
void kv_graph_step_tracks(struct kv_graph_ctx *c);
/* kv_graph_paint.c */
int kv_graph_step_emit(struct kv_graph_ctx *c);

#endif /* KV_GRAPH_PRIVATE_H */
