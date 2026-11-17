#define _GNU_SOURCE

/*
 * kv_graph_paint.c - the last phase of the graph drawing (see kv_graph.c for the order of work and kv_graph.h for the contract): the boxes, the wires as segments and
 * the cells of what the earlier phases decided, and the window of the canvas a viewer reads. Pure: it draws nothing in colour, it only keeps each cell's kind.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofview.h"
#include "kv_graph_private.h"

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

static void paint_line(struct kv_graph *g, const struct kv_graph_seg *s, uint8_t kind, uint8_t sure, uint8_t carry)
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
			/* KNOWN DEFECT LV-D5 (2026-11-17, M) [sev L]: paint_line keeps the FIRST wire's kind and sure on a shared cell, so a MAY/UNKNOWN/BROKEN wire whose straight cells are all shared
			 * shows no dash. Trigger: parallel links from one producer (lgf rand ... dag: 2/14/14 graphs in 3000); 0 in set356. Effect: a link drawn as more certain than it is.
			 * Fix: on a shared straight cell keep the least sure of the wires (or give each wire its own column). */
			if (!c->kind) {
				c->kind = kind;
				c->sure = sure;
				c->carry = carry;
			}
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

/* The result: boxes, wires, segments, the cells. TRY_NOMEM when an allocation fails. */
int kv_graph_step_emit(struct kv_graph_ctx *c)
{
	struct kv_graph_lay *L = &c->L;
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
		const struct kv_graph_wr *w = &L->wr[e];
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
		o->sure = w->sure;
		o->carry = w->carry;
		o->back = w->back;
		o->bx = -1;
		o->letter = w->cond == KV_GC_T ? 'T' : w->cond == KV_GC_F ? 'F' : 0;
		o->ly = -1;
		if (!w->back) {
			o->arrow = w->sure == KV_GSR_UNKNOWN ? '?' : w->sure == KV_GSR_BROKEN ? 'x' : 'v';
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
			paint_line(g, &g->seg[o->seg0 + q], k, o->sure, o->carry);
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
	/* the labels last, beside their arrowheads, only on cells nothing else took (the ports were spread for them: kv_graph_step_ports) */
	for (e = 0, nw = 0; e < W; e++) {
		const struct kv_graph_wr *w = &L->wr[e];
		struct kv_graph_wire *o;
		uint32_t k;
		int free_ = 1;

		if (w->skip)
			continue;
		o = &wv[nw++];
		if (!w->blen)
			continue;
		for (k = 0; k < w->blen + 1u && free_; k++) {
			const int32_t x = o->ax + 1 + (int32_t)k;

			free_ = x >= 0 && (uint32_t)x < g->width && o->ay >= 0 && (uint32_t)o->ay < g->height &&
				g->cell[(size_t)o->ay * g->width + (uint32_t)x].g == KV_GG_EMPTY;
		}
		if (!free_) {
			g->n_label_cut++;
			continue;
		}
		o->bx = o->ax + 2;
		o->blen = w->blen;
		for (k = 0; k < w->blen; k++) {
			struct kv_graph_cell *cl = &g->cell[(size_t)o->ay * g->width + (uint32_t)(o->bx + (int32_t)k)];
			const char ch = w->label[k];

			cl->g = KV_GG_LABEL;
			cl->ch = ch >= 0x20 && ch < 0x7f ? ch : '?';
			cl->kind = (uint8_t)(1u + o->loop * 3u + o->cond);
			cl->sure = o->sure;
			cl->carry = o->carry;
		}
	}
	return TRY_OK;
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

/* The glyph of a line cell from the sides it connects to. The straight runs of a loop link are dotted and those of a retreating edge are dotted another way, and a
 * lineage's link that is not SURE is dashed by how sure it is (kv_graph.h, enum kv_graph_sure); a corner and a junction are the same for every kind (there is no
 * dotted corner), so what is drawn there is still a function of the sides alone. */
static const char *line_glyph(unsigned mask, int ascii, unsigned loop, unsigned sure, unsigned carry)
{
	static const char *const asc[16] = { " ", "|", "-", "'", "|", "|", ".", "+", "-", "'", "-", "+", ".", "+", "+", "+" };
	static const char *const uni[16] = {
		" ", "\xe2\x94\x82", "\xe2\x94\x80", "\xe2\x94\x94", "\xe2\x94\x82", "\xe2\x94\x82", "\xe2\x94\x8c", "\xe2\x94\x9c",
		"\xe2\x94\x80", "\xe2\x94\x98", "\xe2\x94\x80", "\xe2\x94\xb4", "\xe2\x94\x90", "\xe2\x94\xa4", "\xe2\x94\xac", "\xe2\x94\xbc" };
	const int vert = mask == KV_GM_N || mask == KV_GM_S || mask == (KV_GM_N | KV_GM_S), horz = mask == KV_GM_E || mask == KV_GM_W || mask == (KV_GM_E | KV_GM_W);

	/* KNOWN DEFECT LV-D6 (2026-11-17, R) [sev L]: line_glyph decides by `loop` before `sure`, so a lineage link that closes a cycle is drawn retreating whatever its certainty:
	 * its MAY/UNKNOWN/BROKEN is not visible. Trigger: a lineage cycle (0 back edges in set356). Reproducer: lgf rand SEED N 12 (cyclic). Fix: a sure-specific dotted run for back edges. */
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
	} else if (sure == KV_GSR_MAY || (sure == KV_GSR_SURE && carry == KV_GCA_CONTROL)) {    /* a control link: MAY's dashes (kv_graph.h) */
		if (vert)
			return ascii ? ";" : "\xe2\x95\x8e";            /* U+254E */
		if (horz)
			return ascii ? "_" : "\xe2\x95\x8c";            /* U+254C */
	} else if (sure == KV_GSR_UNKNOWN) {
		if (vert)
			return ascii ? "?" : "\xe2\x95\x8f";            /* U+254F */
		if (horz)
			return ascii ? "?" : "\xe2\x95\x8d";            /* U+254D */
	} else if (sure == KV_GSR_BROKEN) {
		if (vert)
			return ascii ? "x" : "\xe2\x94\x8b";            /* U+250B */
		if (horz)
			return ascii ? "x" : "\xe2\x94\x89";            /* U+2509 */
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
		return line_glyph(c->mask, ascii, c->kind ? (c->kind - 1u) / 3u : 0u, c->sure, c->carry);
	case KV_GG_BTL: return ascii ? "." : G_TL;
	case KV_GG_BTR: return ascii ? "." : G_TR;
	case KV_GG_BBL: return ascii ? "`" : G_BL;
	case KV_GG_BBR: return ascii ? "'" : G_BR;
	case KV_GG_BH: return ascii ? "-" : G_H;
	case KV_GG_BV: return ascii ? "|" : G_V;
	default: return " ";
	}
}

/* Is cell (x, y) on the wire of an edge the style lights? A run of the wires of the lit edges, which are the reader's few picks; nothing is kept between calls. */
static int lit_at(const struct kv_graph *g, const struct kv_graph_style *st, int32_t x, int32_t y)
{
	uint32_t w, q;

	for (w = 0; w < g->n_wire; w++) {
		const struct kv_graph_wire *o = &g->wire[w];

		if (o->edge >= st->n_lit || !st->lit[o->edge])
			continue;
		for (q = 0; q < o->n_seg; q++) {
			const struct kv_graph_seg *s = &g->seg[o->seg0 + q];
			const int32_t xa = s->x0 < s->x1 ? s->x0 : s->x1, xb = s->x0 < s->x1 ? s->x1 : s->x0;
			const int32_t ya = s->y0 < s->y1 ? s->y0 : s->y1, yb = s->y0 < s->y1 ? s->y1 : s->y0;

			if (x >= xa && x <= xb && y >= ya && y <= yb)
				return 1;
		}
		if (x == o->ax && y == o->ay)
			return 1;
	}
	return 0;
}

size_t kv_graph_window(const struct kv_graph *g, uint32_t row, uint32_t x0, uint32_t ncols, const struct kv_graph_style *st, char *out, size_t cap)
{
	size_t w = 0;
	uint32_t c;
	unsigned cur = 0;
	char tmp[2];
	const char *off = st->off ? st->off : "";
	const int any_lit = st->lit && st->n_lit && st->lit_attr;

	if (!cap)
		return 0;
	for (c = 0; c < ncols; c++) {
		const struct kv_graph_cell *cell = (row < g->height && x0 + c < g->width && x0 + c >= x0) ? &g->cell[(size_t)row * g->width + x0 + c] : NULL;
		const unsigned a = !cell ? 0u : any_lit && (cell->g == KV_GG_LINE || cell->g == KV_GG_ARROW || cell->g == KV_GG_LABEL) &&
				   lit_at(g, st, (int32_t)(x0 + c), (int32_t)row) ? KV_GRAPH_KINDS : kv_graph_cell_attr(cell);
		const char *gl = cell ? cell_glyph(cell, st->ascii, tmp) : " ";
		const char *at;
		size_t n;

		if (a != cur) {
			if (cur && (cur == KV_GRAPH_KINDS ? st->lit_attr != NULL : st->attr[cur] != NULL)) {
				n = strlen(off);
				if (w + n + 1u > cap)
					break;
				memcpy(out + w, off, n);
				w += n;
			}
			at = a == KV_GRAPH_KINDS ? st->lit_attr : a ? st->attr[a] : NULL;
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
	if (cur && (cur == KV_GRAPH_KINDS ? st->lit_attr != NULL : st->attr[cur] != NULL) && w + strlen(off) + 1u <= cap) {
		memcpy(out + w, off, strlen(off));
		w += strlen(off);
	}
	out[w] = 0;
	return w;
}
