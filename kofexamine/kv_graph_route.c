#define _GNU_SOURCE

/*
 * kv_graph_route.c - the routing phases of the graph drawing (see kv_graph.c for the order of work and kv_graph.h for the contract): the lanes of the left margin, the
 * ports of every box, the horizontal runs of every channel and their tracks, and the rows of the bands and channels that follow from them. Pure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv_graph_private.h"

static int hp_cmp(const void *pa, const void *pb)
{
	const struct kv_graph_hp *a = pa, *b = pb;

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
	const struct kv_graph_port *a = pa, *b = pb;

	if (a->key != b->key)
		return a->key < b->key ? -1 : 1;
	return a->wire < b->wire ? -1 : a->wire > b->wire ? 1 : (int)a->role - (int)b->role;
}

static void span_of(const struct kv_graph_wr *w, uint32_t *lo, uint32_t *hi)
{
	*lo = w->ce < w->ci ? w->ce : w->ci;
	*hi = w->ce < w->ci ? w->ci : w->ce;
}

/* The lanes of the left margin: one per loop edge, shared by edges whose channel ranges do not overlap, the shorter nearer the boxes. A self-loop is a hook and needs none. */
void kv_graph_step_lanes(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
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
		struct kv_graph_wr *w = &L->wr[order[b]];
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
			kv_graph_note_skip(c->g, w->edge, KV_GW_LANE);
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
static int32_t port_other(const struct kv_graph_lay *L, const struct kv_graph_port *p)
{
	const struct kv_graph_wr *w = &L->wr[p->wire];

	if (p->role == 1)               /* a forward edge arrives: the column it left its source by, or the virtual node before it */
		return w->nc ? L->x[w->d0 + w->nc - 1u] : w->out_col;
	if (w->self)
		return p->role == 0 ? L->x[w->from] + (int32_t)L->bw[w->from] : L->x[w->from] + (int32_t)L->bw[w->from] + 1;
	if (w->back)
		return w->lane_col;
	return kv_graph_item_cx(L, w->nc ? w->d0 : w->to);       /* a forward edge leaves: towards the centre of the next box or virtual node */
}

static int top_cmp(const void *pa, const void *pb)
{
	const struct kv_graph_top *a = pa, *b = pb;

	if (a->chan != b->chan)
		return a->chan < b->chan ? -1 : 1;
	if (a->col != b->col)
		return a->col < b->col ? -1 : 1;
	return a->wire < b->wire ? -1 : a->wire > b->wire;
}

/* Does an edge that is none of the `m` edges of the port records at `p` have a vertical run on column `col` of channel `chan`, in `arr` (the runs from the top, or the runs
 * into the virtual nodes at the bottom)? Two runs on one column of a channel would read as one line. */
static int col_taken(const struct kv_graph_top *arr, uint32_t n, uint32_t chan, int32_t col, const struct kv_graph_port *p, uint32_t m)
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
static void ports_assign(struct kv_graph_ctx *c, uint32_t a, uint32_t m)
{
	struct kv_graph_lay *L = &c->L;
	const uint32_t it = L->port[a].key >> 1, side = L->port[a].key & 1u, chan = L->layer[it];
	const int32_t lo = L->x[it] + 1, hi = L->x[it] + (int32_t)L->bw[it] - 2;
	int32_t *col = (int32_t *)(void *)L->tmp_b, *fr = col + m, nfree = 0, q, r;

	for (q = 0; (uint32_t)q < m; q++)
		L->port[a + (uint32_t)q].other = port_other(L, &L->port[a + (uint32_t)q]);
	for (q = 1; (uint32_t)q < m; q++) {         /* by (other, wire): insertion sort, the groups are a box's edges on one side */
		const struct kv_graph_port v = L->port[a + (uint32_t)q];

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
		struct kv_graph_wr *w = &L->wr[L->port[a + (uint32_t)q].wire];
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
static void bots_make(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
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
static void tops_make(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
	uint32_t e, q, n = 0;

	for (e = 0; e < L->W; e++) {
		const struct kv_graph_wr *w = &L->wr[e];

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
void kv_graph_step_ports(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
	uint32_t np = 0, a, e, side;

	for (e = 0; e < L->W; e++) {
		const struct kv_graph_wr *w = &L->wr[e];

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
static void tracks_plain(struct kv_graph_lay *L, uint32_t i, uint32_t j)
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
static void tracks_ordered(struct kv_graph_lay *L, uint32_t i0, uint32_t j0)
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
			const struct kv_graph_hp *p = &L->hp[i0 + a], *q = &L->hp[i0 + b];

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
void kv_graph_step_tracks(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
	const uint32_t NL = L->NL;
	uint32_t nh = 0, e, i, ch, y = 0;

	for (e = 0; e < L->W; e++) {
		const struct kv_graph_wr *w = &L->wr[e];
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
