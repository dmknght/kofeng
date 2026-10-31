#define _GNU_SOURCE

/*
 * kv_graph.c - the graph drawing. See kv_graph.h for the contract, the style and the bounds.
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

#include "kofview.h"
#include "kv_graph.h"

#define GAP_BOX 3
#define GAP_DUM 2
#define BOX_MIN_W 8u
#define SHRINK_TRIES 10u

/* ---- the walk (linear in the graph) ---- */

struct walk {
	uint32_t *rpo, *pos, *stk, *cur, *first, *lvl;
	uint8_t  *st, *bk;      /* per node: 0 new, 1 on the stack, 2 done; per edge: 1 = drawn through a lane */
};

#define WALK_BYTES(n, m) ((size_t)(n) * (6u * sizeof(uint32_t) + 1u) + sizeof(uint32_t) + (size_t)(m))

/* 0: the edges are not sorted by `from` or name a node that is not there. */
static int walk_make(const struct kv_graph_in *in, void *mem, struct walk *wk)
{
	const uint32_t n = in->n_node, m = in->n_edge;
	uint32_t i, sp = 0, cnt = 0, e, root, r;

	memset(mem, 0, WALK_BYTES(n, m));
	wk->rpo = mem;
	wk->pos = wk->rpo + n;
	wk->stk = wk->pos + n;
	wk->cur = wk->stk + n;
	wk->lvl = wk->cur + n;
	wk->first = wk->lvl + n;
	wk->st = (uint8_t *)(wk->first + n + 1u);
	wk->bk = wk->st + n;
	for (e = 0; e < m; e++) {
		if (in->edge[e].from >= n || in->edge[e].to >= n || (e && in->edge[e].from < in->edge[e - 1u].from))
			return 0;
		wk->first[in->edge[e].from + 1u]++;
		wk->bk[e] = in->edge[e].loop != KV_GL_NONE;     /* what the engine calls a loop link or a retreating edge goes back, whatever the walk would say */
	}
	for (i = 0; i < n; i++)
		wk->first[i + 1u] += wk->first[i];
	for (i = 0; i < n; i++)
		wk->cur[i] = wk->first[i + 1u];         /* edges are taken from the last to the first: the first edge's subtree finishes last, so it is first in the order */
	for (r = 0; r <= n; r++) {
		const uint32_t from = cnt;

		root = r == 0 ? in->entry : r - 1u;
		if (root >= n || wk->st[root])
			continue;
		wk->st[root] = 1;
		wk->stk[sp++] = root;
		while (sp) {
			const uint32_t u = wk->stk[sp - 1u];

			if (wk->cur[u] > wk->first[u]) {
				const uint32_t ed = --wk->cur[u];
				const uint32_t s = in->edge[ed].to;

				if (wk->bk[ed])
					continue;
				if (!wk->st[s]) {
					wk->st[s] = 1;
					wk->stk[sp++] = s;
				} else if (wk->st[s] == 1) {
					wk->bk[ed] = 1;
				}
				continue;
			}
			sp--;
			wk->st[u] = 2;
			wk->rpo[cnt++] = u;                     /* post-order of this root: reversed below */
		}
		{
			uint32_t a = from, b = cnt - 1u;

			while (a < b) {
				const uint32_t x = wk->rpo[a];

				wk->rpo[a++] = wk->rpo[b];
				wk->rpo[b--] = x;
			}
		}
	}
	for (i = 0; i < n; i++)
		wk->pos[wk->rpo[i]] = i;
	for (i = 0; i < n; i++) {                       /* an edge that does not point down the order (a cross edge into an earlier root's part) is routed like a back edge */
		const uint32_t u = wk->rpo[i];

		for (e = wk->first[u]; e < wk->first[u + 1u]; e++)
			if (!wk->bk[e] && wk->pos[in->edge[e].to] <= i)
				wk->bk[e] = 1;
	}
	for (i = 0; i < n; i++) {                       /* every forward edge goes down the order, so one pass settles the levels */
		const uint32_t u = wk->rpo[i];

		for (e = wk->first[u]; e < wk->first[u + 1u]; e++) {
			const uint32_t s = in->edge[e].to;

			if (!wk->bk[e] && wk->lvl[s] < wk->lvl[u] + 1u)
				wk->lvl[s] = wk->lvl[u] + 1u;
		}
	}
	return 1;
}

/* ---- the layout of the drawn prefix ---- */

struct arena {
	char  *p;
	size_t n;
};

static void *take(struct arena *a, size_t bytes)
{
	void *r = a->p ? a->p + a->n : NULL;

	a->n += (bytes + 15u) & ~(size_t)15u;
	return r;
}

struct wr {                     /* one drawn edge */
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
struct hp {                     /* a horizontal run that needs a track */
	uint32_t chan, id, track, wire;
	int32_t  lo, hi;
	int32_t  top0, top1;            /* the columns of the vertical runs that come down to it from the top of the channel (NOCOL: none) */
	int32_t  bot;                   /* the column of the vertical run that goes on down from it to the bottom of the channel */
};

struct port {
	uint32_t key;                   /* item * 2 + side: 0 the bottom of the box (edges out, back edges in), 1 its top (forward edges in) */
	int32_t  other;
	uint32_t wire;
	uint8_t  role;                  /* 0 the edge leaves here, 1 a forward edge arrives, 2 a back edge arrives from below */
};

struct top {                    /* a column a vertical run of a channel starts from at its top: where an edge leaves a box or a virtual node, or comes up to a head */
	uint32_t chan;
	int32_t  col;
	uint32_t wire;
};

struct lay {
	uint32_t P, Dub, D, I, NL, W, Npc, Nback, Nhp;
	uint32_t *layer, *bw, *bh, *key, *ordpos, *lay0, *lay_item;
	int32_t  *x;
	struct wr *wr;
	uint32_t *pc_a, *pc_b, *pc_w;
	uint32_t *dn_first, *dn_pc, *up_first, *up_pc;
	int64_t  *tmp_a, *tmp_b, *tmp_w;
	uint32_t *tmp_c;
	uint32_t *chan_t, *chan_y0, *band_y0, *band_h;
	uint32_t *track_of;
	struct hp *hp;
	struct port *port;
	struct top *top, *bot;
	uint32_t n_top, n_bot;
	uint8_t  *occ;
	int32_t  *tr_end;
};

static int32_t fdiv(int64_t a, int64_t b)
{
	int64_t q = a / b;

	if ((a % b != 0) && ((a < 0) != (b < 0)))
		q--;
	return (int32_t)q;
}

static int32_t item_cx(const struct lay *L, uint32_t it)
{
	return L->x[it] + (int32_t)(L->bw[it] / 2u);
}

static int32_t gap_of(const struct lay *L, uint32_t a, uint32_t b)
{
	return L->bh[a] && L->bh[b] ? GAP_BOX : GAP_DUM;
}

struct keyed {
	int64_t  key;
	uint32_t cur, item;
};

static int keyed_cmp(const void *pa, const void *pb)
{
	const struct keyed *a = pa, *b = pb;

	if (a->key != b->key)
		return a->key < b->key ? -1 : 1;
	return a->cur < b->cur ? -1 : a->cur > b->cur;
}

static int hp_cmp(const void *pa, const void *pb)
{
	const struct hp *a = pa, *b = pb;

	if (a->chan != b->chan)
		return a->chan < b->chan ? -1 : 1;
	if (a->lo != b->lo)
		return a->lo < b->lo ? -1 : 1;
	if (a->hi != b->hi)
		return a->hi < b->hi ? -1 : 1;
	return a->id < b->id ? -1 : a->id > b->id;
}

static int port_cmp(const void *pa, const void *pb)
{
	const struct port *a = pa, *b = pb;

	if (a->key != b->key)
		return a->key < b->key ? -1 : 1;
	return a->wire < b->wire ? -1 : a->wire > b->wire ? 1 : (int)a->role - (int)b->role;
}

/* ---- ordering within a rank ---- */

/* One pass over rank `l`: each item goes to the mean position of its neighbours in the rank before it (down) or after it (up). An item with no neighbour that way is a
 * fixed point: it keeps its place and the others are sorted around it (its position and a mean of the other rank's positions are not comparable). */
static void order_rank(struct lay *L, uint32_t l, int down)
{
	const uint32_t n0 = L->lay0[l], n1 = L->lay0[l + 1u];
	struct keyed *k = (struct keyed *)(void *)L->tmp_a;
	uint32_t *slot = L->tmp_c;
	uint32_t i, q, nm = 0, j;

	for (i = n0; i < n1; i++) {
		const uint32_t it = L->lay_item[i];
		const uint32_t b = down ? L->up_first[it] : L->dn_first[it], e = down ? L->up_first[it + 1u] : L->dn_first[it + 1u];
		int64_t sum = 0;

		if (e == b) {
			slot[i - n0] = it;
			continue;
		}
		slot[i - n0] = 0xffffffffu;
		for (q = b; q < e; q++) {
			const uint32_t pc = down ? L->up_pc[q] : L->dn_pc[q];

			sum += L->ordpos[down ? L->pc_a[pc] : L->pc_b[pc]];
		}
		k[nm].key = sum * 1024 / (int64_t)(e - b);
		k[nm].cur = L->ordpos[it];
		k[nm++].item = it;
	}
	qsort(k, nm, sizeof *k, keyed_cmp);
	for (i = n0, j = 0; i < n1; i++) {
		const uint32_t it = slot[i - n0] != 0xffffffffu ? slot[i - n0] : k[j++].item;

		L->lay_item[i] = it;
		L->ordpos[it] = i - n0;
	}
}

/* ---- placement within a rank ---- */

/* The weighted least-squares positions, in the order the rank has, that keep the minimum gap: pool adjacent violators over the desired left edges minus the
 * offsets the gaps force. A heavy item (weight 32: the only child of its parent) barely moves, the light ones around it take the displacement. */
static void place_rank(struct lay *L, uint32_t l, const int64_t *desired_left, const int64_t *wt)
{
	const uint32_t n0 = L->lay0[l], n1 = L->lay0[l + 1u];
	int64_t *csum = L->tmp_b, *offs = L->tmp_b + (n1 - n0), *cw = L->tmp_w + (n1 - n0);
	uint32_t *ccnt = L->tmp_c, nc = 0, i;
	int32_t off = 0;

	for (i = n0; i < n1; i++) {
		const uint32_t it = L->lay_item[i];

		if (i > n0)
			off += (int32_t)L->bw[L->lay_item[i - 1u]] + gap_of(L, L->lay_item[i - 1u], it);
		offs[i - n0] = off;
		csum[nc] = (desired_left[i - n0] - off) * wt[i - n0];
		cw[nc] = wt[i - n0];
		ccnt[nc] = 1;
		nc++;
		while (nc > 1u && fdiv(csum[nc - 2u], cw[nc - 2u]) > fdiv(csum[nc - 1u], cw[nc - 1u])) {
			csum[nc - 2u] += csum[nc - 1u];
			cw[nc - 2u] += cw[nc - 1u];
			ccnt[nc - 2u] += ccnt[nc - 1u];
			nc--;
		}
	}
	{
		uint32_t c, at = n0;

		for (c = 0; c < nc; c++) {
			const int32_t m = fdiv(csum[c], cw[c]);
			uint32_t q;

			for (q = 0; q < ccnt[c]; q++, at++)
				L->x[L->lay_item[at]] = m + (int32_t)offs[at - n0];
		}
	}
}

/* Where the j-th of k forward edges leaves its box, from the box's centre: the first straight below the centre (the spine of the picture), the others spread to the right. */
static int32_t port_rel(uint32_t w, uint32_t j, uint32_t k)
{
	return k < 2u ? 0 : (int32_t)((j * (w - 4u)) / (2u * (k - 1u)));
}

#define W_SPINE 32      /* the weight of an item whose only parent reaches it by its first forward edge: it stands straight below */
#define W_FIRST 32      /* the weight of the first edge's end when a parent looks for the place that suits its children */

static void sweep_x(struct lay *L, uint32_t l, int down)
{
	const uint32_t n0 = L->lay0[l], n1 = L->lay0[l + 1u];
	int64_t *des = L->tmp_a, *wt = L->tmp_w;
	uint32_t i, q;

	for (i = n0; i < n1; i++) {
		const uint32_t it = L->lay_item[i];
		const uint32_t b = down ? L->up_first[it] : L->dn_first[it], e = down ? L->up_first[it + 1u] : L->dn_first[it + 1u];
		int64_t sum = 0, sw = 0;

		for (q = b; q < e; q++) {
			const uint32_t pc = down ? L->up_pc[q] : L->dn_pc[q];
			const struct wr *w = &L->wr[L->pc_w[pc]];
			const uint32_t a = L->pc_a[pc];
			const int32_t po = (a == w->from && L->bh[a]) ? port_rel(L->bw[a], w->j, w->k) : 0;
			const int64_t pw = down ? 1 : (a == w->from && w->j == 0 ? W_FIRST : 1);

			sum += pw * (down ? item_cx(L, a) + po : item_cx(L, L->pc_b[pc]) - po);
			sw += pw;
		}
		des[i - n0] = (e > b ? fdiv(sum, sw) : item_cx(L, it)) - (int64_t)(L->bw[it] / 2u);
		wt[i - n0] = down ? (e - b == 1u && L->wr[L->pc_w[L->up_pc[b]]].j == 0 ? W_SPINE : 1) : (e > b ? 2 : 1);
	}
	place_rank(L, l, des, wt);
}

/* ---- the whole layout of the first P nodes of the walk ---- */

enum { TRY_OK = 0, TRY_FIT, TRY_NOMEM };

static uint32_t box_lines(const struct kv_graph_in *in, uint32_t node, uint32_t *wmax, uint32_t *cut)
{
	uint32_t i = 0, w = 0;
	const char *t;

	while (i < KV_GRAPH_BOX_LINES && (t = in->text(in->user, node, i)) != NULL) {
		size_t n = strlen(t);

		if (n > KV_GRAPH_LINE_MAX)
			n = KV_GRAPH_LINE_MAX;
		if (n > w)
			w = (uint32_t)n;
		i++;
	}
	if (i == KV_GRAPH_BOX_LINES && in->text(in->user, node, i))
		(*cut)++;
	*wmax = w;
	return i ? i : 1u;
}

static void put_seg(struct kv_graph *g, struct kv_graph_wire *wr, int32_t x0, int32_t y0, int32_t x1, int32_t y1)
{
	struct kv_graph_seg *s;

	if (wr->n_seg) {                /* a vertical run that goes on (or begins in the next cell) is one segment */
		s = &g->seg[wr->seg0 + wr->n_seg - 1u];
		if (s->x0 == s->x1 && x0 == x1 && s->x1 == x0 && s->y1 >= s->y0 && y1 >= y0 && (y0 == s->y1 || y0 == s->y1 + 1)) {
			s->y1 = y1;
			return;
		}
	}
	s = &g->seg[wr->seg0 + wr->n_seg];
	s->x0 = x0;
	s->y0 = y0;
	s->x1 = x1;
	s->y1 = y1;
	wr->n_seg++;
	g->n_seg++;
}

static void paint_line(struct kv_graph *g, const struct kv_graph_seg *s, uint8_t kind)
{
	int32_t x = s->x0, y = s->y0;
	const int dx = s->x1 > s->x0 ? 1 : s->x1 < s->x0 ? -1 : 0, dy = s->y1 > s->y0 ? 1 : s->y1 < s->y0 ? -1 : 0;

	for (;;) {
		const int first = x == s->x0 && y == s->y0, last = x == s->x1 && y == s->y1;

		if (x >= 0 && y >= 0 && (uint32_t)x < g->width && (uint32_t)y < g->height) {
			struct kv_graph_cell *c = &g->cell[(size_t)y * g->width + (uint32_t)x];

			c->g = KV_GG_LINE;
			if (!last)
				c->mask |= dy > 0 ? KV_GM_S : dy < 0 ? KV_GM_N : dx > 0 ? KV_GM_E : KV_GM_W;
			if (!first)
				c->mask |= dy > 0 ? KV_GM_N : dy < 0 ? KV_GM_S : dx > 0 ? KV_GM_W : KV_GM_E;
			if (!c->kind)
				c->kind = kind;
		}
		if (last)
			break;
		x += dx;
		y += dy;
	}
}

/* The cell kind of a viewer's mark: none stays 0, a mark past the slots is none. */
static uint8_t mark_kind(uint8_t mark)
{
	return mark && mark < KV_GRAPH_MARKS ? (uint8_t)(KV_GRAPH_MARK0 - 1u + mark) : 0;
}

static void paint_box(struct kv_graph *g, const struct kv_graph_box *b, const struct kv_graph_in *in)
{
	uint32_t r, c, i = 0;
	const char *t;

#define CELL(X, Y) (&g->cell[(size_t)(Y) * g->width + (size_t)(X)])
	for (r = 0; r < b->h; r++)
		for (c = 0; c < b->w; c++) {
			const int top = r == 0, bot = r + 1u == b->h, lft = c == 0, rgt = c + 1u == b->w;
			struct kv_graph_cell *p = CELL((uint32_t)b->x + c, (uint32_t)b->y + r);

			p->g = (top && lft) ? KV_GG_BTL : (top && rgt) ? KV_GG_BTR : (bot && lft) ? KV_GG_BBL : (bot && rgt) ? KV_GG_BBR :
			       (top || bot) ? KV_GG_BH : (lft || rgt) ? KV_GG_BV : KV_GG_EMPTY;
			p->mask = 0;
			p->kind = 0;
			if (in->mark && p->g != KV_GG_EMPTY)
				p->kind = mark_kind(in->mark(in->user, b->node, -1));
		}
	while (i < b->h - 2u && (t = in->text(in->user, b->node, i)) != NULL) {
		size_t n = strlen(t), k;

		if (n > KV_GRAPH_LINE_MAX)
			n = KV_GRAPH_LINE_MAX;
		for (k = 0; k < n; k++) {
			struct kv_graph_cell *p = CELL((uint32_t)b->x + 2u + k, (uint32_t)b->y + 1u + i);
			char ch = t[k];

			if (n == KV_GRAPH_LINE_MAX && k + 1u == n && strlen(t) > n)
				ch = '~';
			p->g = KV_GG_TEXT;
			p->ch = ch >= 0x20 && ch < 0x7f ? ch : '?';
			p->kind = in->mark ? mark_kind(in->mark(in->user, b->node, (int32_t)i)) : 0;
		}
		i++;
	}
#undef CELL
}

/* ---- the steps of one try ---- */

struct ctx {
	const struct kv_graph_in *in;
	const struct walk *wk;
	struct kv_graph *g;
	struct lay L;
	char *mem;
	uint32_t ub_edge, ub_dummy, drawn_deg, edge_cut, lines_cut, nlane;
	int32_t M, Wb;
	uint32_t width, height;
};

static void note_skip(struct kv_graph *g, uint32_t edge, uint8_t why)
{
	if (g->n_skipped < KV_GRAPH_REST) {
		g->skip[g->n_skipped].edge = edge;
		g->skip[g->n_skipped].why = why;
		g->n_skipped++;
	}
}

/* The bounds of what is drawn and the one allocation of the work arrays. */
static int step_alloc(struct ctx *c, uint32_t P)
{
	const struct walk *wk = c->wk;
	struct lay *L = &c->L;
	struct arena ar;
	uint32_t i, e, NL = 0, pass;

	for (i = 0; i < P; i++) {
		const uint32_t u = wk->rpo[i];

		c->drawn_deg += wk->first[u + 1u] - wk->first[u];
		if (wk->lvl[u] + 1u > NL)
			NL = wk->lvl[u] + 1u;
		for (e = wk->first[u]; e < wk->first[u + 1u]; e++) {
			const uint32_t v = c->in->edge[e].to;

			if (wk->pos[v] >= P)
				continue;
			c->ub_edge++;
			if (!wk->bk[e] && wk->lvl[v] - wk->lvl[u] > 1u && c->ub_dummy < KV_GRAPH_MAX_DUMMY)
				c->ub_dummy += wk->lvl[v] - wk->lvl[u] - 1u;
		}
	}
	if (c->ub_edge > KV_GRAPH_MAX_EDGE)
		c->ub_edge = KV_GRAPH_MAX_EDGE;
	if (c->ub_dummy > KV_GRAPH_MAX_DUMMY)
		c->ub_dummy = KV_GRAPH_MAX_DUMMY;
	L->P = P;
	L->Dub = c->ub_dummy;
	L->I = P + c->ub_dummy;
	L->NL = NL;
	{
		const uint32_t I = L->I, WE = c->ub_edge ? c->ub_edge : 1u, NP = c->ub_edge + c->ub_dummy + 1u, J = (I > WE ? I : WE) + 1u, ub_dummy = c->ub_dummy;

		memset(&ar, 0, sizeof ar);
		for (pass = 0; pass < 2; pass++) {
			L->layer = take(&ar, (size_t)I * 4u);
			L->bw = take(&ar, (size_t)I * 4u);
			L->bh = take(&ar, (size_t)I * 4u);
			L->key = take(&ar, (size_t)I * 4u);
			L->ordpos = take(&ar, (size_t)I * 4u);
			L->lay0 = take(&ar, ((size_t)NL + 2u) * 4u);
			L->lay_item = take(&ar, (size_t)I * 4u);
			L->x = take(&ar, (size_t)I * 4u);
			L->wr = take(&ar, (size_t)WE * sizeof *L->wr);
			L->pc_a = take(&ar, (size_t)NP * 4u);
			L->pc_b = take(&ar, (size_t)NP * 4u);
			L->pc_w = take(&ar, (size_t)NP * 4u);
			L->dn_first = take(&ar, ((size_t)I + 1u) * 4u);
			L->dn_pc = take(&ar, (size_t)NP * 4u);
			L->up_first = take(&ar, ((size_t)I + 1u) * 4u);
			L->up_pc = take(&ar, (size_t)NP * 4u);
			L->tmp_a = take(&ar, (size_t)J * 16u);          /* sweep keys (16 bytes each) or desired positions */
			L->tmp_b = take(&ar, (size_t)J * 16u);          /* clusters and offsets, the columns of one side of a box */
			L->tmp_w = take(&ar, (size_t)J * 16u);          /* item weights and cluster weights */
			L->tmp_c = take(&ar, (size_t)J * 4u);           /* cluster sizes, the fill of the ranks, the lane order */
			L->chan_t = take(&ar, ((size_t)NL + 2u) * 4u);
			L->chan_y0 = take(&ar, ((size_t)NL + 2u) * 4u);
			L->band_y0 = take(&ar, ((size_t)NL + 2u) * 4u);
			L->band_h = take(&ar, ((size_t)NL + 2u) * 4u);
			L->track_of = take(&ar, ((size_t)NP + 2u * WE + 1u) * 4u);
			L->hp = take(&ar, ((size_t)NP + 2u * WE + 1u) * sizeof *L->hp);
			L->port = take(&ar, (2u * (size_t)WE + 1u) * sizeof *L->port);
			L->top = take(&ar, ((size_t)NP + 2u * WE + 1u) * sizeof *L->top);
			L->bot = take(&ar, ((size_t)ub_dummy + 1u) * sizeof *L->bot);
			L->occ = take(&ar, (size_t)KV_GRAPH_MAX_LANE * ((size_t)NL + 2u));
			L->tr_end = take(&ar, ((size_t)NP + 2u * WE + 1u) * 4u);
			if (!pass) {
				c->mem = calloc(1, ar.n ? ar.n : 1u);
				if (!c->mem)
					return TRY_NOMEM;
				ar.p = c->mem;
				ar.n = 0;
			}
		}
	}
	return TRY_OK;
}

/* The boxes (sizes from the text) and the edges drawn, in the order of the walk; a forward edge becomes a chain of items through virtual nodes. */
static void step_wires(struct ctx *c)
{
	const struct walk *wk = c->wk;
	const struct kv_graph_in *in = c->in;
	struct lay *L = &c->L;
	const uint32_t P = L->P;
	uint32_t i, e, W = 0, D = 0, Npc = 0, Nback = 0;

	for (i = 0; i < P; i++) {
		const uint32_t u = wk->rpo[i];
		uint32_t wmax, n = box_lines(in, u, &wmax, &c->lines_cut);

		L->layer[i] = wk->lvl[u];
		L->bw[i] = wmax + 4u < BOX_MIN_W ? BOX_MIN_W : wmax + 4u;
		L->bh[i] = n + 2u;
		L->key[i] = i * 4u + 2u;
	}
	for (i = 0; i < P; i++) {
		const uint32_t u = wk->rpo[i];
		uint32_t jf = 0, k0 = W;

		for (e = wk->first[u]; e < wk->first[u + 1u]; e++) {
			const uint32_t v = in->edge[e].to;
			struct wr *w;
			uint32_t nc = 0;

			if (wk->pos[v] >= P) {
				note_skip(c->g, e, KV_GW_END);
				c->edge_cut++;
				continue;
			}
			if (W >= c->ub_edge || (!wk->bk[e] && D + (nc = wk->lvl[v] - wk->lvl[u] - 1u) > c->ub_dummy)) {
				note_skip(c->g, e, KV_GW_CAP);
				c->edge_cut++;
				continue;
			}
			w = &L->wr[W];
			w->edge = e;
			w->from = i;
			w->to = wk->pos[v];
			w->cond = in->edge[e].cond;
			w->loop = in->edge[e].loop;
			w->back = wk->bk[e];
			w->self = w->from == w->to;
			if (!w->back) {
				uint32_t q;

				w->j = jf++;
				w->d0 = P + D;
				w->nc = nc;
				w->p0 = Npc;
				for (q = 0; q < nc; q++) {
					L->layer[P + D + q] = wk->lvl[u] + 1u + q;
					L->bw[P + D + q] = 1u;
					L->bh[P + D + q] = 0;
					L->key[P + D + q] = i * 4u + 1u;
				}
				for (q = 0; q <= nc; q++) {
					L->pc_a[Npc + q] = q == 0 ? i : P + D + q - 1u;
					L->pc_b[Npc + q] = q == nc ? wk->pos[v] : P + D + q;
					L->pc_w[Npc + q] = W;
				}
				D += nc;
				Npc += nc + 1u;
			} else {
				if (w->loop == KV_GL_NONE)
					w->loop = KV_GL_RETREAT;        /* the walk found it going back: not a loop link the engine named */
				w->ce = wk->lvl[u] + 1u;
				w->ci = wk->lvl[v] + 1u;
				Nback++;
			}
			W++;
		}
		for (e = k0; e < W; e++)
			L->wr[e].k = jf;
	}
	L->D = D;
	L->W = W;
	L->Npc = Npc;
	L->Nback = Nback;
	c->g->n_dummy = D;
	c->g->n_line_cut = c->lines_cut;
}

/* The ranks: items by layer in the order of their keys, then the barycenter sweeps. */
static void step_order(struct ctx *c)
{
	struct lay *L = &c->L;
	const uint32_t I = L->P + L->D, NL = L->NL;
	uint32_t i, e, l, r;

	for (e = 0; e < L->Npc; e++) {
		L->dn_first[L->pc_a[e] + 1u]++;
		L->up_first[L->pc_b[e] + 1u]++;
	}
	for (i = 0; i < I; i++) {
		L->dn_first[i + 1u] += L->dn_first[i];
		L->up_first[i + 1u] += L->up_first[i];
	}
	{
		uint32_t *cur = L->tmp_c;

		for (i = 0; i < I; i++)
			cur[i] = L->dn_first[i];
		for (e = 0; e < L->Npc; e++)
			L->dn_pc[cur[L->pc_a[e]]++] = e;
		for (i = 0; i < I; i++)
			cur[i] = L->up_first[i];
		for (e = 0; e < L->Npc; e++)
			L->up_pc[cur[L->pc_b[e]]++] = e;
	}
	for (i = 0; i < I; i++)
		L->lay0[L->layer[i] + 1u]++;
	for (l = 0; l < NL; l++)
		L->lay0[l + 1u] += L->lay0[l];
	{
		struct keyed *k = (struct keyed *)(void *)L->tmp_a;
		uint32_t *fill = L->tmp_c;

		for (i = 0; i < I; i++) {
			k[i].key = (int64_t)L->layer[i] * ((int64_t)1 << 40) + L->key[i];
			k[i].cur = i;
			k[i].item = i;
		}
		qsort(k, I, sizeof *k, keyed_cmp);
		for (l = 0; l < NL; l++)
			fill[l] = L->lay0[l];
		for (i = 0; i < I; i++) {
			const uint32_t it = k[i].item;

			L->lay_item[fill[L->layer[it]]] = it;
			L->ordpos[it] = fill[L->layer[it]]++ - L->lay0[L->layer[it]];
		}
	}
	for (r = 0; r < KV_GRAPH_SWEEPS; r++) {
		for (l = 1; l < NL; l++)
			order_rank(L, l, 1);
		for (l = NL; l-- > 1;)
			order_rank(L, l - 1u, 0);
	}
}

/* x: packed from the left, then rounds of centring on the ports of the rank before (down) and after (up); the last pass is up, so a box stands over its first child. */
static void step_place(struct ctx *c)
{
	struct lay *L = &c->L;
	const uint32_t I = L->P + L->D, NL = L->NL;
	uint32_t i, l, r, q;
	int32_t xmin = 0x7fffffff, xmax = -0x7fffffff;

	for (l = 0; l < NL; l++) {
		int32_t x = 0;

		for (q = L->lay0[l]; q < L->lay0[l + 1u]; q++) {
			const uint32_t it = L->lay_item[q];

			if (q > L->lay0[l])
				x += (int32_t)L->bw[L->lay_item[q - 1u]] + gap_of(L, L->lay_item[q - 1u], it);
			L->x[it] = x;
		}
	}
	for (r = 0; r < KV_GRAPH_SWEEPS; r++) {
		for (l = 1; l < NL; l++)
			sweep_x(L, l, 1);
		for (l = NL; l-- > 1;)
			sweep_x(L, l - 1u, 0);
	}
	for (i = 0; i < I; i++) {
		if (L->x[i] < xmin)
			xmin = L->x[i];
		if (L->x[i] + (int32_t)L->bw[i] > xmax)
			xmax = L->x[i] + (int32_t)L->bw[i];
	}
	for (i = 0; i < I; i++)
		L->x[i] -= xmin;
	c->Wb = xmax - xmin;
}

static void span_of(const struct wr *w, uint32_t *lo, uint32_t *hi)
{
	*lo = w->ce < w->ci ? w->ce : w->ci;
	*hi = w->ce < w->ci ? w->ci : w->ce;
}

/* The lanes of the left margin: one per loop edge, shared by edges whose channel ranges do not overlap, the shorter nearer the boxes. A self-loop is a hook and needs none. */
static void step_lanes(struct ctx *c)
{
	struct lay *L = &c->L;
	uint32_t *order = L->tmp_c, nbk = 0, e, a, b, nl = 0;

	for (e = 0; e < L->W; e++)
		if (L->wr[e].back && !L->wr[e].self)
			order[nbk++] = e;
	for (a = 1; a < nbk; a++) {         /* insertion sort by (span, low, index): the entries are the loop edges, a handful as a rule and MAX_EDGE at the very most */
		const uint32_t v = order[a];
		uint32_t lo_v, hi_v;

		span_of(&L->wr[v], &lo_v, &hi_v);
		for (b = a; b > 0; b--) {
			const uint32_t u = order[b - 1u];
			uint32_t lo_u, hi_u;

			span_of(&L->wr[u], &lo_u, &hi_u);
			if (hi_u - lo_u < hi_v - lo_v || (hi_u - lo_u == hi_v - lo_v && (lo_u < lo_v || (lo_u == lo_v && u < v))))
				break;
			order[b] = u;
		}
		order[b] = v;
	}
	for (b = 0; b < nbk; b++) {
		struct wr *w = &L->wr[order[b]];
		uint32_t lo, hi, ln, ch;

		span_of(w, &lo, &hi);
		for (ln = 0; ln < KV_GRAPH_MAX_LANE; ln++) {
			uint8_t *oc = L->occ + (size_t)ln * ((size_t)L->NL + 2u);

			for (ch = lo; ch <= hi && !oc[ch]; ch++)
				;
			if (ch > hi) {
				for (ch = lo; ch <= hi; ch++)
					oc[ch] = 1;
				break;
			}
		}
		if (ln == KV_GRAPH_MAX_LANE) {
			w->skip = 1;
			c->edge_cut++;
			note_skip(c->g, w->edge, KV_GW_LANE);
			continue;
		}
		w->lane = ln;
		if (ln + 1u > nl)
			nl = ln + 1u;
	}
	c->nlane = nl;
	c->M = (int32_t)(2u * nl);
	c->width = (uint32_t)c->M + (uint32_t)c->Wb;
	{
		uint32_t i;

		for (i = 0; i < L->P + L->D; i++)
			L->x[i] += c->M;
		for (e = 0; e < L->W; e++)
			if (L->wr[e].back && !L->wr[e].skip && !L->wr[e].self)
				L->wr[e].lane_col = c->M - 2 - 2 * (int32_t)L->wr[e].lane;
	}
}

/* Where the other end of the edge a port record stands: a column the port would like to be at. */
static int32_t port_other(const struct lay *L, const struct port *p)
{
	const struct wr *w = &L->wr[p->wire];

	if (p->role == 1)               /* a forward edge arrives: the column it left its source by, or the virtual node before it */
		return w->nc ? L->x[w->d0 + w->nc - 1u] : w->out_col;
	if (w->self)
		return p->role == 0 ? L->x[w->from] + (int32_t)L->bw[w->from] : L->x[w->from] + (int32_t)L->bw[w->from] + 1;
	if (w->back)
		return w->lane_col;
	return item_cx(L, w->nc ? w->d0 : w->to);       /* a forward edge leaves: towards the centre of the next box or virtual node */
}

static int top_cmp(const void *pa, const void *pb)
{
	const struct top *a = pa, *b = pb;

	if (a->chan != b->chan)
		return a->chan < b->chan ? -1 : 1;
	if (a->col != b->col)
		return a->col < b->col ? -1 : 1;
	return a->wire < b->wire ? -1 : a->wire > b->wire;
}

/* Does an edge that is none of the `m` edges of the port records at `p` have a vertical run on column `col` of channel `chan`, in `arr` (the runs from the top, or the runs
 * into the virtual nodes at the bottom)? Two runs on one column of a channel would read as one line. */
static int col_taken(const struct top *arr, uint32_t n, uint32_t chan, int32_t col, const struct port *p, uint32_t m)
{
	uint32_t lo = 0, hi = n, k;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (arr[mid].chan < chan || (arr[mid].chan == chan && arr[mid].col < col))
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (; lo < n && arr[lo].chan == chan && arr[lo].col == col; lo++) {
		for (k = 0; k < m && p[k].wire != arr[lo].wire; k++)
			;
		if (k == m)
			return 1;
	}
	return 0;
}

/* The ports of one side of one box: `m` records in L->port[a..a+m), sorted by where the other end is, given distinct columns as near it as the box allows. A bottom keeps off
 * the columns of the virtual nodes of the rank below (L->bot), a top (a forward edge arriving) keeps off every column an edge of its channel starts a run from (L->top). */
static void ports_assign(struct ctx *c, uint32_t a, uint32_t m)
{
	struct lay *L = &c->L;
	const uint32_t it = L->port[a].key >> 1, side = L->port[a].key & 1u, chan = L->layer[it];
	const int32_t lo = L->x[it] + 1, hi = L->x[it] + (int32_t)L->bw[it] - 2;
	int32_t *col = (int32_t *)(void *)L->tmp_b, *fr = col + m, nfree = 0, q, r;

	for (q = 0; (uint32_t)q < m; q++)
		L->port[a + (uint32_t)q].other = port_other(L, &L->port[a + (uint32_t)q]);
	for (q = 1; (uint32_t)q < m; q++) {         /* by (other, wire): insertion sort, the groups are a box's edges on one side */
		const struct port v = L->port[a + (uint32_t)q];

		for (r = q; r > 0 && (L->port[a + (uint32_t)r - 1u].other > v.other || (L->port[a + (uint32_t)r - 1u].other == v.other && L->port[a + (uint32_t)r - 1u].wire > v.wire)); r--)
			L->port[a + (uint32_t)r] = L->port[a + (uint32_t)r - 1u];
		L->port[a + (uint32_t)r] = v;
	}
	/* the columns this side may use: all of the box's inner width, less (on a top) those another edge's run starts from; fewer than the edges: all of them, shared */
	{
		int32_t cc;

		for (cc = lo; cc <= hi; cc++)
			if (side == 0u ? !col_taken(L->bot, L->n_bot, chan + 1u, cc, &L->port[a], m) : !col_taken(L->top, L->n_top, chan, cc, &L->port[a], m))
				fr[nfree++] = cc;
	}
	if ((uint32_t)nfree < m) {
		nfree = 0;
		for (q = lo; q <= hi; q++)
			fr[nfree++] = q;
	}
	{
		int32_t prev = -1;

		for (q = 0; (uint32_t)q < m; q++) {
			int32_t k = 0;

			while (k + 1 < nfree && fr[k] < L->port[a + (uint32_t)q].other)
				k++;
			if (k <= prev)
				k = prev + 1;
			if (k >= nfree)
				k = nfree - 1;
			col[q] = k;
			prev = k;
		}
		for (q = (int32_t)m; q-- > 1;)
			if (col[q - 1] >= col[q])
				col[q - 1] = col[q] - 1 < 0 ? 0 : col[q] - 1;
		for (q = 0; (uint32_t)q < m; q++)
			col[q] = fr[col[q]];
	}
	for (q = 0; (uint32_t)q < m; q++) {
		struct wr *w = &L->wr[L->port[a + (uint32_t)q].wire];
		const int shared = (q && col[q] == col[q - 1]) || ((uint32_t)q + 1u < m && col[q] == col[q + 1]);

		if (shared && q)
			c->g->n_share++;
		if (L->port[a + (uint32_t)q].role == 0) {
			w->out_col = col[q];
			w->out_shared = (uint8_t)shared;
		} else {
			w->in_col = col[q];
		}
	}
}

/* The columns of the virtual nodes: a run of the channel above each ends there. */
static void bots_make(struct ctx *c)
{
	struct lay *L = &c->L;
	uint32_t e, q, n = 0;

	for (e = 0; e < L->W; e++)
		if (!L->wr[e].skip && !L->wr[e].back)
			for (q = 0; q < L->wr[e].nc; q++) {
				L->bot[n].chan = L->layer[L->wr[e].d0 + q];
				L->bot[n].col = L->x[L->wr[e].d0 + q];
				L->bot[n++].wire = e;
			}
	L->n_bot = n;
	qsort(L->bot, n, sizeof *L->bot, top_cmp);
}

/* The columns every channel's vertical runs start from, once the bottoms of the boxes and the virtual nodes are known: the edge that owns the run is recorded with it. */
static void tops_make(struct ctx *c)
{
	struct lay *L = &c->L;
	uint32_t e, q, n = 0;

	for (e = 0; e < L->W; e++) {
		const struct wr *w = &L->wr[e];

		if (w->skip)
			continue;
		if (!w->back) {
			for (q = 0; q <= w->nc; q++) {
				L->top[n].chan = L->layer[L->pc_a[w->p0 + q]] + 1u;
				L->top[n].col = q == 0 ? w->out_col : L->x[L->pc_a[w->p0 + q]];
				L->top[n++].wire = e;
			}
		} else {
			L->top[n].chan = w->ce;
			L->top[n].col = w->out_col;
			L->top[n++].wire = e;
			L->top[n].chan = w->ci;
			L->top[n].col = w->in_col;
			L->top[n++].wire = e;
		}
	}
	L->n_top = n;
	qsort(L->top, n, sizeof *L->top, top_cmp);
}

/* The columns an edge leaves its box by (the bottom), arrives at the top of its box by (a forward edge) or at the bottom of its box by (a back edge). The bottoms go first
 * (they look at the centres and the lanes); then every top looks at the column its edge left by, so an edge that can run straight does, and keeps off the columns other
 * edges of its channel run from. */
static void step_ports(struct ctx *c)
{
	struct lay *L = &c->L;
	uint32_t np = 0, a, e, side;

	for (e = 0; e < L->W; e++) {
		const struct wr *w = &L->wr[e];

		if (w->skip)
			continue;
		L->port[np].key = w->from * 2u;
		L->port[np].role = 0;
		L->port[np++].wire = e;
		L->port[np].wire = e;
		if (w->back) {
			L->port[np].key = w->to * 2u;
			L->port[np++].role = 2;
		} else {
			L->port[np].key = w->to * 2u + 1u;
			L->port[np++].role = 1;
		}
	}
	qsort(L->port, np, sizeof *L->port, port_cmp);
	bots_make(c);
	for (side = 0; side < 2u; side++) {
		if (side == 1u)
			tops_make(c);
		for (a = 0; a < np;) {
			uint32_t b = a;

			while (b < np && L->port[b].key == L->port[a].key)
				b++;
			if ((L->port[a].key & 1u) == side)
				ports_assign(c, a, b - a);
			a = b;
		}
	}
}

/* The horizontal runs of every channel and their tracks, then the rows of the bands and the channels. */
#define PREC_MAX 256u           /* a channel with more runs than this is given its tracks by the plain left-to-right rule: the precedence rule is cubic in the runs */

/* The tracks of the runs of one channel, hp[i..j): first-fit from the left, in the order the runs are sorted in. */
static void tracks_plain(struct lay *L, uint32_t i, uint32_t j)
{
	uint32_t nt = 0, t;

	for (; i < j; i++) {
		for (t = 0; t < nt && L->tr_end[t] + 1 >= L->hp[i].lo; t++)
			;
		if (t == nt)
			nt++;
		L->tr_end[t] = L->hp[i].hi;
		L->hp[i].track = t;
	}
}

/* The tracks of one channel with the rule that keeps two lines from sharing a column: a run that starts at the top of the channel on column c lies ABOVE a run that ends at the
 * bottom of it on c (a line comes down to its track and stops, the other starts below it). Runs are taken in an order that respects that and each goes on the first track
 * below the ones it must be above and clear of the runs already there; a cycle of such demands (not satisfiable) is broken at the run that comes first in the sort. */
static void tracks_ordered(struct lay *L, uint32_t i0, uint32_t j0)
{
	const uint32_t n = j0 - i0;
	uint8_t after[PREC_MAX][PREC_MAX / 8u], placed[PREC_MAX];
	uint16_t indeg[PREC_MAX], min_t[PREC_MAX];
	uint32_t a, b, done = 0;

	memset(after, 0, sizeof after);
	memset(placed, 0, sizeof placed);
	memset(indeg, 0, sizeof indeg);
	memset(min_t, 0, sizeof min_t);
	for (a = 0; a < n; a++)
		for (b = 0; b < n; b++) {
			const struct hp *p = &L->hp[i0 + a], *q = &L->hp[i0 + b];

			if (a == b || p->wire == q->wire || q->bot == NOCOL || (p->top0 != q->bot && p->top1 != q->bot))
				continue;
			if (!(after[a][b / 8u] & (1u << (b % 8u)))) {
				after[a][b / 8u] |= (uint8_t)(1u << (b % 8u));
				indeg[b]++;
			}
		}
	while (done < n) {
		uint32_t pick = n, t;

		for (a = 0; a < n && pick == n; a++)
			if (!placed[a] && !indeg[a])
				pick = a;
		if (pick == n)                  /* a cycle: the first run left */
			for (a = 0; a < n && pick == n; a++)
				if (!placed[a])
					pick = a;
		for (t = min_t[pick];; t++) {
			int clash = 0;

			for (b = 0; b < n && !clash; b++)
				clash = placed[b] && L->hp[i0 + b].track == t && L->hp[i0 + b].lo <= L->hp[i0 + pick].hi + 1 && L->hp[i0 + pick].lo <= L->hp[i0 + b].hi + 1;
			if (!clash)
				break;
		}
		L->hp[i0 + pick].track = t;
		placed[pick] = 1;
		done++;
		for (b = 0; b < n; b++)
			if ((after[pick][b / 8u] & (1u << (b % 8u))) && !placed[b]) {
				if (indeg[b])
					indeg[b]--;
				if (min_t[b] < t + 1u)
					min_t[b] = (uint16_t)(t + 1u);
			}
	}
}

/* The horizontal runs of every channel and their tracks, then the rows of the bands and the channels. */
static void step_tracks(struct ctx *c)
{
	struct lay *L = &c->L;
	const uint32_t NL = L->NL;
	uint32_t nh = 0, e, i, ch, y = 0;

	for (e = 0; e < L->W; e++) {
		const struct wr *w = &L->wr[e];
		uint32_t q;

		if (w->skip)
			continue;
		if (!w->back) {
			for (q = 0; q <= w->nc; q++) {
				const int32_t xt = q == 0 ? w->out_col : L->x[L->pc_a[w->p0 + q]], xb = q == w->nc ? w->in_col : L->x[L->pc_b[w->p0 + q]];

				L->track_of[w->p0 + q] = 0xffffffffu;
				if (xt == xb)
					continue;
				L->hp[nh].chan = L->layer[L->pc_a[w->p0 + q]] + 1u;
				L->hp[nh].lo = xt < xb ? xt : xb;
				L->hp[nh].hi = xt < xb ? xb : xt;
				L->hp[nh].id = w->p0 + q;
				L->hp[nh].wire = e;
				L->hp[nh].top0 = xt;
				L->hp[nh].top1 = NOCOL;
				L->hp[nh].bot = xb;
				nh++;
			}
		} else if (w->self) {
			L->hp[nh].chan = w->ce;
			L->hp[nh].lo = w->out_col < w->in_col ? w->out_col : w->in_col;
			L->hp[nh].hi = w->out_col < w->in_col ? w->in_col : w->out_col;
			L->hp[nh].id = L->Npc + 2u * e;
			L->hp[nh].wire = e;
			L->hp[nh].top0 = w->out_col;
			L->hp[nh].top1 = w->in_col;
			L->hp[nh].bot = NOCOL;
			nh++;
		} else {
			const uint32_t gid = L->Npc + 2u * e;

			L->hp[nh].chan = w->ce;
			L->hp[nh].lo = w->out_col < w->lane_col ? w->out_col : w->lane_col;
			L->hp[nh].hi = w->out_col < w->lane_col ? w->lane_col : w->out_col;
			L->hp[nh].id = gid;
			L->hp[nh].wire = e;
			L->hp[nh].top0 = w->out_col;
			L->hp[nh].top1 = NOCOL;
			L->hp[nh].bot = NOCOL;
			nh++;
			L->hp[nh].chan = w->ci;
			L->hp[nh].lo = w->in_col < w->lane_col ? w->in_col : w->lane_col;
			L->hp[nh].hi = w->in_col < w->lane_col ? w->lane_col : w->in_col;
			L->hp[nh].id = gid + 1u;
			L->hp[nh].wire = e;
			L->hp[nh].top0 = w->in_col;
			L->hp[nh].top1 = NOCOL;
			L->hp[nh].bot = NOCOL;
			nh++;
		}
	}
	L->Nhp = nh;
	qsort(L->hp, nh, sizeof *L->hp, hp_cmp);
	for (ch = 0; ch <= NL; ch++)
		L->chan_t[ch] = 0;
	for (i = 0; i < nh;) {
		uint32_t j = i, k, nt = 0;

		while (j < nh && L->hp[j].chan == L->hp[i].chan)
			j++;
		if (j - i <= PREC_MAX)
			tracks_ordered(L, i, j);
		else
			tracks_plain(L, i, j);
		for (k = i; k < j; k++) {
			L->track_of[L->hp[k].id] = L->hp[k].track;
			if (L->hp[k].track + 1u > nt)
				nt = L->hp[k].track + 1u;
		}
		L->chan_t[L->hp[i].chan] = nt;
		i = j;
	}
	for (ch = 0; ch < NL; ch++)
		L->band_h[ch] = 1;
	for (i = 0; i < L->P; i++)
		if (L->bh[i] > L->band_h[L->layer[i]])
			L->band_h[L->layer[i]] = L->bh[i];
	for (ch = 0; ch <= NL; ch++) {
		const uint32_t T = L->chan_t[ch];

		L->chan_y0[ch] = y;
		y += (ch == 0 || ch == NL) ? (T ? T + 1u : 0u) : T + 2u;
		if (ch < NL) {
			L->band_y0[ch] = y;
			y += L->band_h[ch];
		}
	}
	c->height = y;
}

/* The result: boxes, wires, segments, the cells. TRY_NOMEM when an allocation fails. */
static int step_emit(struct ctx *c)
{
	struct lay *L = &c->L;
	struct kv_graph *g = c->g;
	const uint32_t P = L->P, W = L->W, Npc = L->Npc;
	size_t nseg_max = 0, rtotal;
	struct kv_graph_box *bx;
	struct kv_graph_wire *wv;
	char *rmem;
	uint32_t e, i, nw = 0;

	for (e = 0; e < W; e++)
		if (!L->wr[e].skip)
			nseg_max += L->wr[e].back ? 6u : 4u * L->wr[e].nc + 3u;
	rtotal = ((size_t)P * sizeof *g->box + 15u) / 16u * 16u + ((size_t)W * sizeof *g->wire + 15u) / 16u * 16u + nseg_max * sizeof *g->seg + 16u;
	rmem = calloc(1, rtotal);
	g->cell = calloc((size_t)c->width * c->height + 1u, sizeof *g->cell);
	if (!rmem || !g->cell) {
		free(rmem);
		free(g->cell);
		g->cell = NULL;
		return TRY_NOMEM;
	}
	g->width = c->width;
	g->height = c->height;
	g->box = (struct kv_graph_box *)(void *)rmem;
	g->wire = (struct kv_graph_wire *)(void *)(rmem + ((size_t)P * sizeof *g->box + 15u) / 16u * 16u);
	g->seg = (struct kv_graph_seg *)(void *)((char *)g->wire + ((size_t)W * sizeof *g->wire + 15u) / 16u * 16u);
	g->mem_ = rmem;
	g->n_box = P;
	g->n_rank = L->NL;
	g->n_lane = c->nlane;
	bx = g->box;
	for (i = 0; i < P; i++) {
		bx[i].node = c->wk->rpo[i];
		bx[i].x = L->x[i];
		bx[i].y = (int32_t)L->band_y0[L->layer[i]];
		bx[i].w = L->bw[i];
		bx[i].h = L->bh[i];
		bx[i].rank = L->layer[i];
		paint_box(g, &bx[i], c->in);
	}
	wv = g->wire;
	for (e = 0; e < W; e++) {
		const struct wr *w = &L->wr[e];
		struct kv_graph_wire *o;
		const struct kv_graph_box *bf = &bx[w->from], *bt = &bx[w->to];
		const int32_t ys = bf->y + (int32_t)bf->h;
		uint32_t q;

		if (w->skip)
			continue;
		o = &wv[nw++];
		o->edge = w->edge;
		o->seg0 = g->n_seg;
		o->n_seg = 0;
		o->cond = w->cond;
		o->loop = w->loop;
		o->back = w->back;
		o->letter = w->cond == KV_GC_T ? 'T' : w->cond == KV_GC_F ? 'F' : 0;
		o->ly = -1;
		if (!w->back) {
			o->arrow = 'v';
			for (q = 0; q <= w->nc; q++) {
				const uint32_t a = L->pc_a[w->p0 + q], b = L->pc_b[w->p0 + q];
				const uint32_t ch = L->layer[a] + 1u;
				const int32_t xt = q == 0 ? w->out_col : L->x[a], xb = q == w->nc ? w->in_col : L->x[b];
				const int32_t y_start = q == 0 ? ys : (int32_t)L->band_y0[L->layer[a]];
				const int32_t y_arrow = (int32_t)(L->chan_y0[ch] + (L->chan_t[ch] + 2u) - 1u);
				const uint32_t tr = L->track_of[w->p0 + q];

				if (tr == 0xffffffffu) {
					put_seg(g, o, xt, y_start, xt, y_arrow);
				} else {
					const int32_t yt = (int32_t)(L->chan_y0[ch] + 1u + tr);

					put_seg(g, o, xt, y_start, xt, yt);
					put_seg(g, o, xt, yt, xb, yt);
					put_seg(g, o, xb, yt, xb, y_arrow);
				}
				o->ax = xb;
				o->ay = y_arrow;
			}
		} else if (w->self) {
			const int32_t rt = (int32_t)(L->chan_y0[w->ce] + 1u + L->track_of[Npc + 2u * e]);

			o->arrow = '^';
			put_seg(g, o, w->out_col, ys, w->out_col, rt);
			put_seg(g, o, w->out_col, rt, w->in_col, rt);
			put_seg(g, o, w->in_col, rt, w->in_col, ys);
			o->ax = w->in_col;
			o->ay = ys;
		} else {
			const int32_t re = (int32_t)(L->chan_y0[w->ce] + 1u + L->track_of[Npc + 2u * e]);
			const int32_t ri = (int32_t)(L->chan_y0[w->ci] + 1u + L->track_of[Npc + 2u * e + 1u]);
			const int32_t yt = bt->y + (int32_t)bt->h;

			o->arrow = '^';
			put_seg(g, o, w->out_col, ys, w->out_col, re);
			put_seg(g, o, w->out_col, re, w->lane_col, re);
			put_seg(g, o, w->lane_col, re, w->lane_col, ri);
			put_seg(g, o, w->lane_col, ri, w->in_col, ri);
			put_seg(g, o, w->in_col, ri, w->in_col, yt);
			o->ax = w->in_col;
			o->ay = yt;
		}
		if (o->letter && !w->out_shared) {
			o->lx = w->out_col;
			o->ly = ys;
		}
	}
	g->n_wire = nw;
	/* the lines first, then the letters and the arrowheads over them */
	for (e = 0; e < nw; e++) {
		const struct kv_graph_wire *o = &wv[e];
		const uint8_t k = (uint8_t)(1u + o->loop * 3u + o->cond);
		uint32_t q;

		for (q = 0; q < o->n_seg; q++)
			paint_line(g, &g->seg[o->seg0 + q], k);
	}
	for (e = 0; e < nw; e++) {
		const struct kv_graph_wire *o = &wv[e];

		if (o->ly >= 0 && (uint32_t)o->lx < g->width && (uint32_t)o->ly < g->height) {
			struct kv_graph_cell *cl = &g->cell[(size_t)o->ly * g->width + (uint32_t)o->lx];

			cl->g = KV_GG_LABEL;
			cl->ch = o->letter;
		}
		if ((uint32_t)o->ax < g->width && o->ay >= 0 && (uint32_t)o->ay < g->height) {
			struct kv_graph_cell *cl = &g->cell[(size_t)o->ay * g->width + (uint32_t)o->ax];

			cl->g = KV_GG_ARROW;
			cl->ch = o->arrow;
		}
	}
	return TRY_OK;
}

static int lay_try(const struct kv_graph_in *in, const struct walk *wk, uint32_t P, struct kv_graph *g)
{
	const uint32_t max_cols = in->max_cols ? in->max_cols : KV_GRAPH_COLS_DEF, max_rows = in->max_rows ? in->max_rows : KV_GRAPH_ROWS_DEF;
	struct ctx c;
	int rc;

	memset(&c, 0, sizeof c);
	c.in = in;
	c.wk = wk;
	c.g = g;
	g->n_edge_not_drawn = g->n_line_cut = g->n_share = g->n_lane = g->n_dummy = g->n_skipped = 0;
	rc = step_alloc(&c, P);
	if (rc != TRY_OK)
		return rc;
	step_wires(&c);
	step_order(&c);
	step_place(&c);
	step_lanes(&c);
	g->n_edge_not_drawn = c.edge_cut + (in->n_edge - c.drawn_deg);
	step_ports(&c);
	step_tracks(&c);
	if (c.width > max_cols || c.height > max_rows || (uint64_t)c.width * c.height > KV_GRAPH_CELLS_MAX)
		rc = TRY_FIT;
	else
		rc = step_emit(&c);
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
	struct walk wk;
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
	if (!walk_make(in, wm, &wk)) {
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

/* ---- the window ---- */

struct kv_graph_style kv_graph_style_default(void)
{
	struct kv_graph_style s;

	memset(&s, 0, sizeof s);
#ifdef KOFVIEW_ASCII_BOX
	s.ascii = 1;
#endif
	return s;
}

unsigned kv_graph_cell_attr(const struct kv_graph_cell *c)
{
	if (c->kind >= KV_GRAPH_MARK0)
		return c->kind;                 /* a box's border or text, marked by the viewer */
	if (c->g != KV_GG_LINE && c->g != KV_GG_LABEL && c->g != KV_GG_ARROW)
		return 0;
	return c->kind;
}

/* The glyph of a line cell from the sides it connects to. The straight runs of a loop link are dotted and those of a retreating edge are dotted another way; a corner
 * and a junction are the same for every kind (there is no dotted corner), so what is drawn there is still a function of the sides alone. */
static const char *line_glyph(unsigned mask, int ascii, unsigned loop)
{
	static const char *const asc[16] = { " ", "|", "-", "'", "|", "|", ".", "+", "-", "'", "-", "+", ".", "+", "+", "+" };
	static const char *const uni[16] = {
		" ", "\xe2\x94\x82", "\xe2\x94\x80", "\xe2\x94\x94", "\xe2\x94\x82", "\xe2\x94\x82", "\xe2\x94\x8c", "\xe2\x94\x9c",
		"\xe2\x94\x80", "\xe2\x94\x98", "\xe2\x94\x80", "\xe2\x94\xb4", "\xe2\x94\x90", "\xe2\x94\xa4", "\xe2\x94\xac", "\xe2\x94\xbc" };
	const int vert = mask == KV_GM_N || mask == KV_GM_S || mask == (KV_GM_N | KV_GM_S), horz = mask == KV_GM_E || mask == KV_GM_W || mask == (KV_GM_E | KV_GM_W);

	if (loop == KV_GL_LOOP) {
		if (vert)
			return ascii ? ":" : "\xe2\x94\x86";            /* U+2506 */
		if (horz)
			return ascii ? "=" : "\xe2\x94\x84";            /* U+2504 */
	} else if (loop == KV_GL_RETREAT) {
		if (vert)
			return ascii ? "!" : "\xe2\x94\x8a";            /* U+250A */
		if (horz)
			return ascii ? "~" : "\xe2\x94\x88";            /* U+2508 */
	}
	return ascii ? asc[mask & 15u] : uni[mask & 15u];
}

static const char *cell_glyph(const struct kv_graph_cell *c, int ascii, char *tmp)
{
	switch (c->g) {
	case KV_GG_TEXT:
	case KV_GG_LABEL:
	case KV_GG_ARROW:
		tmp[0] = c->ch ? c->ch : ' ';
		tmp[1] = 0;
		return tmp;
	case KV_GG_LINE:
		return line_glyph(c->mask, ascii, c->kind ? (c->kind - 1u) / 3u : 0u);
	case KV_GG_BTL: return ascii ? "." : G_TL;
	case KV_GG_BTR: return ascii ? "." : G_TR;
	case KV_GG_BBL: return ascii ? "`" : G_BL;
	case KV_GG_BBR: return ascii ? "'" : G_BR;
	case KV_GG_BH: return ascii ? "-" : G_H;
	case KV_GG_BV: return ascii ? "|" : G_V;
	default: return " ";
	}
}

size_t kv_graph_window(const struct kv_graph *g, uint32_t row, uint32_t x0, uint32_t ncols, const struct kv_graph_style *st, char *out, size_t cap)
{
	size_t w = 0;
	uint32_t c;
	unsigned cur = 0;
	char tmp[2];
	const char *off = st->off ? st->off : "";

	if (!cap)
		return 0;
	for (c = 0; c < ncols; c++) {
		const struct kv_graph_cell *cell = (row < g->height && x0 + c < g->width && x0 + c >= x0) ? &g->cell[(size_t)row * g->width + x0 + c] : NULL;
		const unsigned a = cell ? kv_graph_cell_attr(cell) : 0u;
		const char *gl = cell ? cell_glyph(cell, st->ascii, tmp) : " ";
		const char *at;
		size_t n;

		if (a != cur) {
			if (cur && st->attr[cur]) {
				n = strlen(off);
				if (w + n + 1u > cap)
					break;
				memcpy(out + w, off, n);
				w += n;
			}
			at = a ? st->attr[a] : NULL;
			if (at) {
				n = strlen(at);
				if (w + n + 1u > cap)
					break;
				memcpy(out + w, at, n);
				w += n;
			}
			cur = a;
		}
		n = strlen(gl);
		if (w + n + 1u > cap)
			break;
		memcpy(out + w, gl, n);
		w += n;
	}
	if (cur && st->attr[cur] && w + strlen(off) + 1u <= cap) {
		memcpy(out + w, off, strlen(off));
		w += strlen(off);
	}
	out[w] = 0;
	return w;
}
