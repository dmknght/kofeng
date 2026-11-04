#define _GNU_SOURCE

/*
 * kv_graph_rank.c - the first phases of the graph drawing (see kv_graph.c for the order of work and kv_graph.h for the contract): the walk that gives every node its
 * rank, the boxes and the edges as chains of items through virtual nodes, the barycenter order inside a rank, and the placement (the spine). Pure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv_graph_private.h"

#define GAP_BOX 3
#define GAP_DUM 2
#define BOX_MIN_W 8u

/* 0: the edges are not sorted by `from` or name a node that is not there. */
int kv_graph_walk_make(const struct kv_graph_in *in, void *mem, struct kv_graph_walk *wk)
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

struct kv_graph_arena {
	char  *p;
	size_t n;
};

static void *take(struct kv_graph_arena *a, size_t bytes)
{
	void *r = a->p ? a->p + a->n : NULL;

	a->n += (bytes + 15u) & ~(size_t)15u;
	return r;
}

static int32_t fdiv(int64_t a, int64_t b)
{
	int64_t q = a / b;

	if ((a % b != 0) && ((a < 0) != (b < 0)))
		q--;
	return (int32_t)q;
}

static int32_t gap_of(const struct kv_graph_lay *L, uint32_t a, uint32_t b)
{
	return L->bh[a] && L->bh[b] ? GAP_BOX : GAP_DUM;
}

struct kv_graph_keyed {
	int64_t  key;
	uint32_t cur, item;
};

static int keyed_cmp(const void *pa, const void *pb)
{
	const struct kv_graph_keyed *a = pa, *b = pb;

	if (a->key != b->key)
		return a->key < b->key ? -1 : 1;
	return a->cur < b->cur ? -1 : a->cur > b->cur;
}

/* ---- ordering within a rank ---- */

/* One pass over rank `l`: each item goes to the mean position of its neighbours in the rank before it (down) or after it (up). An item with no neighbour that way is a
 * fixed point: it keeps its place and the others are sorted around it (its position and a mean of the other rank's positions are not comparable). */
static void order_rank(struct kv_graph_lay *L, uint32_t l, int down)
{
	const uint32_t n0 = L->lay0[l], n1 = L->lay0[l + 1u];
	struct kv_graph_keyed *k = (struct kv_graph_keyed *)(void *)L->tmp_a;
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
static void place_rank(struct kv_graph_lay *L, uint32_t l, const int64_t *desired_left, const int64_t *wt)
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

static void sweep_x(struct kv_graph_lay *L, uint32_t l, int down)
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
			const struct kv_graph_wr *w = &L->wr[L->pc_w[pc]];
			const uint32_t a = L->pc_a[pc];
			const int32_t po = (a == w->from && L->bh[a]) ? port_rel(L->bw[a], w->j, w->k) : 0;
			const int64_t pw = down ? 1 : (a == w->from && w->j == 0 ? W_FIRST : 1);

			sum += pw * (down ? kv_graph_item_cx(L, a) + po : kv_graph_item_cx(L, L->pc_b[pc]) - po);
			sw += pw;
		}
		des[i - n0] = (e > b ? fdiv(sum, sw) : kv_graph_item_cx(L, it)) - (int64_t)(L->bw[it] / 2u);
		wt[i - n0] = down ? (e - b == 1u && L->wr[L->pc_w[L->up_pc[b]]].j == 0 ? W_SPINE : 1) : (e > b ? 2 : 1);
	}
	place_rank(L, l, des, wt);
}

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

void kv_graph_note_skip(struct kv_graph *g, uint32_t edge, uint8_t why)
{
	if (g->n_skipped < KV_GRAPH_REST) {
		g->skip[g->n_skipped].edge = edge;
		g->skip[g->n_skipped].why = why;
		g->n_skipped++;
	}
}

/* ---- the steps of one try ---- */

/* The bounds of what is drawn and the one allocation of the work arrays. */
int kv_graph_step_alloc(struct kv_graph_ctx *c, uint32_t P)
{
	const struct kv_graph_walk *wk = c->wk;
	struct kv_graph_lay *L = &c->L;
	struct kv_graph_arena ar;
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
void kv_graph_step_wires(struct kv_graph_ctx *c)
{
	const struct kv_graph_walk *wk = c->wk;
	const struct kv_graph_in *in = c->in;
	struct kv_graph_lay *L = &c->L;
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
			struct kv_graph_wr *w;
			uint32_t nc = 0;

			if (wk->pos[v] >= P) {
				kv_graph_note_skip(c->g, e, KV_GW_END);
				c->edge_cut++;
				continue;
			}
			if (W >= c->ub_edge || (!wk->bk[e] && D + (nc = wk->lvl[v] - wk->lvl[u] - 1u) > c->ub_dummy)) {
				kv_graph_note_skip(c->g, e, KV_GW_CAP);
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
void kv_graph_step_order(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
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
		struct kv_graph_keyed *k = (struct kv_graph_keyed *)(void *)L->tmp_a;
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
void kv_graph_step_place(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
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
