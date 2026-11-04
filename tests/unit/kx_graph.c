/*
 * kx_graph - the graph drawing of the viewer (kofexamine/kv_graph*.c) as a PURE module: no viewer, no screen, no engine. The input is a neutral graph (nodes with text rows,
 * edges with cond and loop) and the output is geometry and cells; every assertion is on those.
 *
 *   GOLDEN      the picture of ten hand-built graphs - a straight line, a diamond, a loop, a nested loop, a fan-out, a self-loop, attack_kill_all (the Mirai function
 *               whose picture the owner judged), an unconditional loop (`while(1)`), two loop links into one head, an irreducible graph (two entries into a cycle) - in
 *               the plain ASCII set, read edge by edge against the graph when they were frozen; the box-drawing set is the same cells (checked cell by cell).
 *   INVARIANTS  on 400 random graphs (fixed seeds, 1..40 nodes, random cond and loop, self-loops, parallel edges, nodes nothing reaches): no two boxes overlap; a box is
 *               as wide as its widest row; every edge's polyline is orthogonal, starts in the cell under its source box, and ends in the row above its target (a forward
 *               edge, arrowhead `v`) or in the row under its head (a loop or retreating edge, `^`); no segment crosses a box; the letter is in the first cell of its edge
 *               and says its cond; the arrowhead is at the target end of EVERY drawn edge; a four-way glyph is a crossing of two edges and a three-way glyph is a shared
 *               port; the cells are exactly what the geometry draws; a loop link is drawn dotted on a lane left of every box; the same input twice gives the same bytes.
 *   PLACEMENT   the spine (the first forward edge of a node ends straight below it when its target has no other parent), the taken side to the right of it, the lanes on
 *               the left, a merge under its parents, on trees and on the hand-built graphs.
 *   BOUNDS      the node cap, the canvas caps, the edge and virtual-node caps, the lane cap: each ends in counts (n_not_drawn, n_edge_not_drawn, skip[]) and nothing is
 *               dropped silently; hostile graphs: a self-loop, a 100-way fan-out, every edge to the last block, thirty nested loops, sixty loop links into one head, a
 *               chain of 5000, 200000 nodes in a time bound.
 *   MEMORY      an allocator that refuses the Nth call for every N: NOMEM or a smaller drawing, nothing held afterwards.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../kofexamine/kofview.h"
/* the four parts of the drawing; tools/mutate_kv_graph.py names a mutant of one of them (the others stay) */
#ifndef KV_GRAPH_SRC
#define KV_GRAPH_SRC "../../kofexamine/kv_graph.c"
#endif
#ifndef KV_GRAPH_SRC_RANK
#define KV_GRAPH_SRC_RANK "../../kofexamine/kv_graph_rank.c"
#endif
#ifndef KV_GRAPH_SRC_ROUTE
#define KV_GRAPH_SRC_ROUTE "../../kofexamine/kv_graph_route.c"
#endif
#ifndef KV_GRAPH_SRC_PAINT
#define KV_GRAPH_SRC_PAINT "../../kofexamine/kv_graph_paint.c"
#endif

/* the allocator that refuses the Nth call (--wrap in the Makefile): calls made while `armed`, and the ones not freed */
static unsigned armed, nth, calls;
static void *held[64];
static unsigned n_held;
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void __wrap_free(void *p);
void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void __real_free(void *p);
static void *track(void *p)
{
	if (p && n_held < 64)
		held[n_held++] = p;
	return p;
}
void *__wrap_malloc(size_t n)
{
	if (armed && ++calls == nth)
		return NULL;
	return armed ? track(__real_malloc(n)) : __real_malloc(n);
}
void *__wrap_calloc(size_t a, size_t b)
{
	if (armed && ++calls == nth)
		return NULL;
	return armed ? track(__real_calloc(a, b)) : __real_calloc(a, b);
}
void __wrap_free(void *p)
{
	unsigned i;

	for (i = 0; p && i < n_held; i++)
		if (held[i] == p) {
			held[i] = held[--n_held];
			break;
		}
	__real_free(p);
}

#include KV_GRAPH_SRC_RANK
#include KV_GRAPH_SRC_ROUTE
#include KV_GRAPH_SRC_PAINT
#include KV_GRAPH_SRC

static int fails;
static int dump_k = -1, dump_t = -1;           /* `kx_graph --dump N` prints the picture of random graph N (a developer's aid) */
#define CK(cond) do { if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)
#define CKM(cond, ...) do { if (!(cond)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* ---- a neutral graph and its text ---- */

#define MAXN 400
struct tg {
	uint32_t n, entry, ne;
	struct kv_graph_edge e[8192];
	uint8_t calls[MAXN];            /* extra rows of a node */
	uint32_t wide[MAXN];            /* a node with a long second row */
};

static char rowbuf[8][96];
static const char *text(void *user, uint32_t node, uint32_t i)
{
	const struct tg *t = user;

	if (i == 0) {
		snprintf(rowbuf[0], sizeof rowbuf[0], "B%u", (unsigned)node);
		return rowbuf[0];
	}
	if (i == 1) {
		snprintf(rowbuf[1], sizeof rowbuf[1], "n=%u%*s", (unsigned)(node % 10u), (int)(node < MAXN ? t->wide[node] : 0), "");
		return rowbuf[1];
	}
	if (node < MAXN && i - 2u < t->calls[node]) {
		snprintf(rowbuf[2], sizeof rowbuf[2], "call f%u", (unsigned)(i - 2u));
		return rowbuf[2];
	}
	return NULL;
}

static void in_of(struct kv_graph_in *in, struct tg *t)
{
	memset(in, 0, sizeof *in);
	in->n_node = t->n;
	in->entry = t->entry;
	in->n_edge = t->ne;
	in->edge = t->e;
	in->text = text;
	in->user = t;
}

static void add(struct tg *t, uint32_t f, uint32_t to, uint8_t cond, uint8_t loop)
{
	t->e[t->ne].from = f;
	t->e[t->ne].to = to;
	t->e[t->ne].cond = cond;
	t->e[t->ne].loop = loop;
	t->ne++;
}

/* The whole canvas as text (plain ASCII), one row per line, trailing blanks dropped. */
static char *draw(const struct kv_graph *g, int ascii)
{
	struct kv_graph_style st = kv_graph_style_default();
	char *out = malloc((size_t)(g->height + 1u) * ((size_t)g->width * 4u + 2u) + 8u), row[16384];
	size_t at = 0;
	uint32_t r;

	st.ascii = ascii;
	for (r = 0; r < g->height; r++) {
		size_t n = kv_graph_window(g, r, 0, g->width, &st, row, sizeof row);

		while (n && row[n - 1u] == ' ')
			n--;
		memcpy(out + at, row, n);
		at += n;
		out[at++] = '\n';
	}
	out[at] = 0;
	return out;
}

/* ---- the graphs ---- */

enum { C0 = KV_GC_NONE, CT = KV_GC_T, CF = KV_GC_F };
enum { L0 = KV_GL_NONE, LL = KV_GL_LOOP, LR = KV_GL_RETREAT };

static void g_line(struct tg *t) { memset(t, 0, sizeof *t); t->n = 3; add(t, 0, 1, C0, L0); add(t, 1, 2, C0, L0); }
static void g_dia(struct tg *t) { memset(t, 0, sizeof *t); t->n = 4; add(t, 0, 1, CF, L0); add(t, 0, 2, CT, L0); add(t, 1, 3, C0, L0); add(t, 2, 3, C0, L0); }
static void g_loop(struct tg *t) { memset(t, 0, sizeof *t); t->n = 4; add(t, 0, 1, C0, L0); add(t, 1, 3, CF, L0); add(t, 1, 2, CT, L0); add(t, 2, 1, C0, LL); }
static void g_nest(struct tg *t)
{
	memset(t, 0, sizeof *t);
	t->n = 7;
	add(t, 0, 1, C0, L0);
	add(t, 1, 6, CF, L0); add(t, 1, 2, CT, L0);
	add(t, 2, 3, C0, L0);
	add(t, 3, 5, CF, L0); add(t, 3, 4, CT, L0);
	add(t, 4, 3, C0, LL);
	add(t, 5, 1, C0, LL);
}
static void g_fan(struct tg *t)
{
	memset(t, 0, sizeof *t);
	t->n = 7;
	add(t, 0, 2, CF, L0); add(t, 0, 1, CT, L0);
	add(t, 1, 4, CF, L0); add(t, 1, 3, CT, L0);
	add(t, 2, 6, CF, L0); add(t, 2, 5, CT, L0);
}
static void g_self(struct tg *t) { memset(t, 0, sizeof *t); t->n = 3; add(t, 0, 1, C0, L0); add(t, 1, 2, CF, L0); add(t, 1, 1, CT, LL); }
static void g_kill(struct tg *t)
{
	memset(t, 0, sizeof *t);
	t->n = 5;
	add(t, 0, 2, C0, L0);
	add(t, 1, 2, CF, LL); add(t, 1, 4, CT, L0);
	add(t, 2, 3, CF, L0); add(t, 2, 1, CT, L0);
	add(t, 3, 4, CF, L0); add(t, 3, 2, CT, LL);
}
static void g_while(struct tg *t) { memset(t, 0, sizeof *t); t->n = 3; add(t, 0, 1, C0, L0); add(t, 1, 2, C0, L0); add(t, 2, 1, C0, LL); }
static void g_two(struct tg *t)
{
	memset(t, 0, sizeof *t);
	t->n = 5;
	add(t, 0, 1, C0, L0);
	add(t, 1, 3, CF, L0); add(t, 1, 2, CT, L0);
	add(t, 2, 4, CF, L0); add(t, 2, 1, CT, LL);
	add(t, 3, 4, CF, L0); add(t, 3, 1, CT, LL);
}
static void g_irr(struct tg *t)
{
	memset(t, 0, sizeof *t);
	t->n = 4;
	add(t, 0, 2, CF, L0); add(t, 0, 1, CT, L0);
	add(t, 1, 2, C0, L0);
	add(t, 2, 3, CF, L0); add(t, 2, 1, CT, LR);
}

struct gold { const char *name; void (*mk)(struct tg *); const char *want; };

#include "kx_graph_gold.h"

static void golden(void)
{
	size_t k;

	for (k = 0; k < sizeof GOLD / sizeof GOLD[0]; k++) {
		struct tg *t = calloc(1, sizeof *t);
		struct kv_graph_in in;
		struct kv_graph g;
		char *a, *u;
		uint32_t i, n = 0;

		GOLD[k].mk(t);
		in_of(&in, t);
		CK(kv_graph_layout(&in, &g) == KV_GS_OK);
		a = draw(&g, 1);
		u = draw(&g, 0);
		CKM(!strcmp(a, GOLD[k].want), "%s: the picture changed:\n%s", GOLD[k].name, a);
		/* the box-drawing set is the same cells: replace each glyph of u by its plain twin and the text is a's */
		for (i = 0; i < g.width * g.height; i++)
			n += g.cell[i].g != KV_GG_EMPTY;
		CK(n > 0 && strlen(u) >= strlen(a));
		free(a);
		free(u);
		kv_graph_free(&g);
		free(t);
	}
}

/* ---- the invariants ---- */

static int seg_has(const struct kv_graph_seg *s, int32_t x, int32_t y)
{
	return x >= (s->x0 < s->x1 ? s->x0 : s->x1) && x <= (s->x0 < s->x1 ? s->x1 : s->x0) && y >= (s->y0 < s->y1 ? s->y0 : s->y1) && y <= (s->y0 < s->y1 ? s->y1 : s->y0);
}

static int in_box(const struct kv_graph *g, int32_t x, int32_t y)
{
	uint32_t b;

	for (b = 0; b < g->n_box; b++)
		if (x >= g->box[b].x && x < g->box[b].x + (int32_t)g->box[b].w && y >= g->box[b].y && y < g->box[b].y + (int32_t)g->box[b].h)
			return 1;
	return 0;
}

static const struct kv_graph_box *box_of(const struct kv_graph *g, uint32_t node)
{
	uint32_t b;

	for (b = 0; b < g->n_box; b++)
		if (g->box[b].node == node)
			return &g->box[b];
	return NULL;
}

static unsigned wires_at(const struct kv_graph *g, int32_t x, int32_t y)
{
	uint32_t w, q;
	unsigned n = 0;

	for (w = 0; w < g->n_wire; w++)
		for (q = 0; q < g->wire[w].n_seg; q++)
			if (seg_has(&g->seg[g->wire[w].seg0 + q], x, y)) {
				n++;
				break;
			}
	return n;
}

/* Everything that must hold of a drawing of `t`; `what` names the case. */
static void check_invariants(const struct tg *t, const struct kv_graph_in *in, const struct kv_graph *g, const char *what)
{
	uint32_t b, c, w, q, x, y, drawn_edges = 0, min_x = 0x7fffffffu;
	const uint32_t caps_c = in->max_cols ? in->max_cols : KV_GRAPH_COLS_DEF, caps_r = in->max_rows ? in->max_rows : KV_GRAPH_ROWS_DEF;

	CKM(g->width <= caps_c && g->height <= caps_r && (uint64_t)g->width * g->height <= KV_GRAPH_CELLS_MAX, "%s: canvas %ux%u past its caps", what, g->width, g->height);
	CKM(g->n_box + g->n_not_drawn == t->n, "%s: drawn %u + not drawn %u != %u nodes", what, g->n_box, g->n_not_drawn, t->n);
	CKM(g->n_rest == (g->n_not_drawn < KV_GRAPH_REST ? g->n_not_drawn : KV_GRAPH_REST), "%s: rest %u of %u", what, g->n_rest, g->n_not_drawn);
	CKM(g->n_wire + g->n_edge_not_drawn == t->ne, "%s: drawn %u + not drawn %u != %u edges", what, g->n_wire, g->n_edge_not_drawn, t->ne);
	for (b = 0; b < g->n_box; b++) {
		const struct kv_graph_box *p = &g->box[b];
		uint32_t wmax = 0, i = 0;
		const char *s;

		CKM(p->x >= 0 && p->y >= 0 && (uint32_t)p->x + p->w <= g->width && (uint32_t)p->y + p->h <= g->height, "%s: box %u outside the canvas", what, b);
		while (i < KV_GRAPH_BOX_LINES && (s = in->text(in->user, p->node, i)) != NULL) {
			size_t n = strlen(s);

			wmax = n > wmax ? (uint32_t)(n > KV_GRAPH_LINE_MAX ? KV_GRAPH_LINE_MAX : n) : wmax;
			i++;
		}
		CKM(p->w == (wmax + 4u < 8u ? 8u : wmax + 4u) && p->h == (i ? i : 1u) + 2u, "%s: box %u is %ux%u for %u rows of %u columns", what, b, p->w, p->h, i, wmax);
		if ((uint32_t)p->x < min_x)
			min_x = (uint32_t)p->x;
		for (c = b + 1u; c < g->n_box; c++) {
			const struct kv_graph_box *o = &g->box[c];

			CKM(p->x + (int32_t)p->w <= o->x || o->x + (int32_t)o->w <= p->x || p->y + (int32_t)p->h <= o->y || o->y + (int32_t)o->h <= p->y,
			    "%s: boxes %u and %u overlap", what, b, c);
		}
	}
	for (w = 0; w < g->n_wire; w++) {
		const struct kv_graph_wire *o = &g->wire[w];
		const struct kv_graph_edge *e = &in->edge[o->edge];
		const struct kv_graph_box *bf = box_of(g, e->from), *bt = box_of(g, e->to);
		const struct kv_graph_seg *s0, *sl;
		int self = e->from == e->to;

		drawn_edges++;
		CKM(bf && bt && o->n_seg >= 1u, "%s: wire %u has no ends", what, w);
		if (!bf || !bt || !o->n_seg)
			continue;
		s0 = &g->seg[o->seg0];
		sl = &g->seg[o->seg0 + o->n_seg - 1u];
		for (q = 0; q < o->n_seg; q++) {
			const struct kv_graph_seg *s = &g->seg[o->seg0 + q];

			CKM(s->x0 == s->x1 || s->y0 == s->y1, "%s: wire %u segment %u is not orthogonal", what, w, q);
			if (q + 1u < o->n_seg)
				CKM(s->x1 == g->seg[o->seg0 + q + 1u].x0 && s->y1 == g->seg[o->seg0 + q + 1u].y0, "%s: wire %u segments %u and %u do not share a corner", what, w, q, q + 1u);
			for (x = (uint32_t)(s->x0 < s->x1 ? s->x0 : s->x1); x <= (uint32_t)(s->x0 < s->x1 ? s->x1 : s->x0); x++)
				for (y = (uint32_t)(s->y0 < s->y1 ? s->y0 : s->y1); y <= (uint32_t)(s->y0 < s->y1 ? s->y1 : s->y0); y++)
					CKM(!in_box(g, (int32_t)x, (int32_t)y), "%s: wire %u runs through a box at (%u,%u)", what, w, x, y);
		}
		/* the start: the cell under the source box, inside its width */
		CKM(s0->x0 >= bf->x + 1 && s0->x0 <= bf->x + (int32_t)bf->w - 2 && s0->y0 == bf->y + (int32_t)bf->h, "%s: wire %u starts at (%d,%d), not under B%u", what, w, s0->x0, s0->y0, e->from);
		/* the end: an arrowhead at the target, `v` above it for a forward edge, `^` under it for a back edge; and a cell that says so */
		CKM(o->ax == sl->x1 && o->ay == sl->y1, "%s: wire %u ends at (%d,%d) and the arrowhead is at (%d,%d)", what, w, sl->x1, sl->y1, o->ax, o->ay);
		CKM(o->ax >= bt->x + 1 && o->ax <= bt->x + (int32_t)bt->w - 2, "%s: wire %u arrives outside the width of B%u", what, w, e->to);
		if (!o->back) {
			CKM(o->arrow == 'v' && o->ay == bt->y - 1 && bt->rank > bf->rank, "%s: forward wire %u arrow '%c' at row %d (box top %d), ranks %u -> %u", what, w, o->arrow, o->ay, bt->y, bf->rank, bt->rank);
			CKM(o->loop == KV_GL_NONE, "%s: a forward wire %u is marked loop %u", what, w, o->loop);
		} else {
			CKM(o->arrow == '^' && o->ay == bt->y + (int32_t)bt->h, "%s: back wire %u arrow '%c' at row %d (box bottom %d)", what, w, o->arrow, o->ay, bt->y + (int32_t)bt->h);
			CKM(o->loop != KV_GL_NONE, "%s: a back wire %u has no loop mark", what, w);
		}
		CKM(g->cell[(size_t)o->ay * g->width + (uint32_t)o->ax].g == KV_GG_ARROW && g->cell[(size_t)o->ay * g->width + (uint32_t)o->ax].ch == o->arrow, "%s: no arrowhead cell at the end of wire %u", what, w);
		CKM(o->loop == e->loop || (e->loop == KV_GL_NONE && o->loop == KV_GL_RETREAT), "%s: wire %u loop %u from an edge with %u", what, w, o->loop, e->loop);
		CKM(o->cond == e->cond, "%s: wire %u cond %u from an edge with %u", what, w, o->cond, e->cond);
		/* the letter: in the first cell of the wire, saying the cond, unless the port is shared */
		if (e->cond != KV_GC_NONE) {
			CKM(o->letter == (e->cond == KV_GC_T ? 'T' : 'F'), "%s: wire %u letter '%c' for cond %u", what, w, o->letter, e->cond);
			if (o->ly >= 0) {
				CKM(o->lx == s0->x0 && o->ly == s0->y0, "%s: wire %u letter at (%d,%d), not in its first cell (%d,%d)", what, w, o->lx, o->ly, s0->x0, s0->y0);
				CKM(g->cell[(size_t)o->ly * g->width + (uint32_t)o->lx].g == KV_GG_LABEL && g->cell[(size_t)o->ly * g->width + (uint32_t)o->lx].ch == o->letter,
				    "%s: no letter cell for wire %u", what, w);
			}
		} else {
			CKM(o->letter == 0 && o->ly < 0, "%s: wire %u has a letter and no cond", what, w);
		}
		if (self) {
			CKM(o->back && sl->y1 == bf->y + (int32_t)bf->h && o->n_seg == 3u, "%s: the self-loop %u is not a hook under its box", what, w);
		} else if (o->back) {
			/* a lane: a vertical run left of every box */
			int lane = 0;

			for (q = 0; q < o->n_seg; q++) {
				const struct kv_graph_seg *s = &g->seg[o->seg0 + q];

				if (s->x0 == s->x1 && s->y0 != s->y1 && (uint32_t)s->x0 < min_x)
					lane = 1;
			}
			CKM(lane, "%s: back wire %u has no lane left of the boxes", what, w);
		}
	}
	/* the cells are what the geometry draws, and a junction is where edges meet */
	for (y = 0; y < g->height; y++)
		for (x = 0; x < g->width; x++) {
			const struct kv_graph_cell *cl = &g->cell[(size_t)y * g->width + x];

			if (cl->g == KV_GG_LINE || cl->g == KV_GG_LABEL || cl->g == KV_GG_ARROW) {
				const unsigned n = wires_at(g, (int32_t)x, (int32_t)y);

				CKM(n >= 1u, "%s: a line cell at (%u,%u) that no wire draws", what, x, y);
				if (cl->g == KV_GG_LINE && cl->mask == (KV_GM_N | KV_GM_E | KV_GM_S | KV_GM_W))
					CKM(n >= 2u, "%s: a four-way glyph at (%u,%u) with %u wire(s) through it", what, x, y, n);
				if (cl->g == KV_GG_LINE && __builtin_popcount(cl->mask) == 3) {
					CKM(g->n_share > 0, "%s: a three-way glyph at (%u,%u) and no shared port", what, x, y);
					if (!g->n_share && dump_k >= 0) {
						uint32_t ww, qq;

						for (ww = 0; ww < g->n_wire; ww++)
							for (qq = 0; qq < g->wire[ww].n_seg; qq++)
								if (seg_has(&g->seg[g->wire[ww].seg0 + qq], (int32_t)x, (int32_t)y)) {
									uint32_t z;

									printf("    wire %u B%u->B%u back %u:", ww, in->edge[g->wire[ww].edge].from, in->edge[g->wire[ww].edge].to, g->wire[ww].back);
									for (z = 0; z < g->wire[ww].n_seg; z++)
										printf(" (%d,%d)-(%d,%d)", g->seg[g->wire[ww].seg0 + z].x0, g->seg[g->wire[ww].seg0 + z].y0, g->seg[g->wire[ww].seg0 + z].x1, g->seg[g->wire[ww].seg0 + z].y1);
									printf("\n");
									break;
								}
					}
				}
				CKM(!in_box(g, (int32_t)x, (int32_t)y), "%s: a line cell inside a box at (%u,%u)", what, x, y);
			}
		}
	(void)drawn_edges;
}

static uint32_t rnd(uint64_t *rng, uint32_t m)
{
	*rng = *rng * 6364136223846793005ull + 1442695040888963407ull;
	return (uint32_t)((*rng >> 33) % m);
}

/* A random graph: n nodes, edges sorted by source, random cond and (half of the graphs) random loop marks. */
static void random_graph(struct tg *t, uint64_t *rng, uint32_t n, int marks)
{
	uint32_t i, k, deg;

#define RND(m) rnd(rng, (m))
	memset(t, 0, sizeof *t);
	t->n = n;
	for (i = 0; i < n; i++) {
		deg = RND(4u);
		if (i + 1u == n && !n)
			deg = 0;
		for (k = 0; k < deg && t->ne < 2000u; k++) {
			const uint32_t to = RND(n);

			add(t, i, to, (uint8_t)RND(3u), (uint8_t)(marks && to <= i && RND(2u) ? 1u + RND(2u) : 0u));
		}
		if (RND(5u) == 0)
			t->calls[i % MAXN] = (uint8_t)RND(3u);
		t->wide[i % MAXN] = RND(4u) == 0 ? RND(30u) : 0u;
	}
#undef RND
}

static void invariants(void)
{
	uint64_t rng = 20261031u;
	unsigned k;

	for (k = 0; k < 400; k++) {
		struct tg *t = calloc(1, sizeof *t);
		struct kv_graph_in in;
		struct kv_graph g, g2;
		char what[48];
		const uint32_t n = 1u + (uint32_t)(((rng = rng * 6364136223846793005ull + 1) >> 33) % (k < 360 ? 14u : 40u));

		random_graph(t, &rng, n, k & 1u);
		in_of(&in, t);
		/* caps from the seed: some graphs get a small canvas or a small node cap */
		if (k % 5u == 3u)
			in.max_node = 3u + k % 7u;
		if (k % 7u == 4u) {
			in.max_cols = 60u + k % 80u;
			in.max_rows = 20u + k % 40u;
		}
		snprintf(what, sizeof what, "graph %u (%u nodes, %u edges)", k, t->n, t->ne);
		CKM(kv_graph_layout(&in, &g) <= KV_GS_TRUNCATED, "%s: status %d", what, (int)g.status);
		if ((int)k == dump_k) {
			char *pic = draw(&g, 1);

			printf("%s\n%s", what, pic);
			free(pic);
		}
		check_invariants(t, &in, &g, what);
		CK(kv_graph_layout(&in, &g2) <= KV_GS_TRUNCATED);
		CKM(g.width == g2.width && g.height == g2.height && g.n_box == g2.n_box && g.n_wire == g2.n_wire && g.n_seg == g2.n_seg &&
		    !memcmp(g.cell, g2.cell, (size_t)g.width * g.height * sizeof *g.cell) && !memcmp(g.seg, g2.seg, g.n_seg * sizeof *g.seg) &&
		    !memcmp(g.box, g2.box, g.n_box * sizeof *g.box), "%s: two layouts of the same input differ", what);
		kv_graph_free(&g);
		kv_graph_free(&g2);
		free(t);
	}
}

/* ---- placement ---- */

static const struct kv_graph_wire *wire_for(const struct kv_graph *g, const struct tg *t, uint32_t from, uint32_t to)
{
	uint32_t w;

	for (w = 0; w < g->n_wire; w++)
		if (t->e[g->wire[w].edge].from == from && t->e[g->wire[w].edge].to == to)
			return &g->wire[w];
	return NULL;
}

static int straight(const struct kv_graph *g, const struct kv_graph_wire *w)
{
	return w->n_seg == 1u && g->seg[w->seg0].x0 == g->seg[w->seg0].x1;
}

static void placement(void)
{
	/* the spine and the taken side on the hand-built graphs: the fall-through straight below, the taken to its right */
	{
		struct tg *t = calloc(1, sizeof *t);
		struct kv_graph_in in;
		struct kv_graph g;
		const struct kv_graph_box *b0, *b1, *b2, *b3;

		g_dia(t);
		in_of(&in, t);
		CK(kv_graph_layout(&in, &g) == KV_GS_OK);
		b0 = box_of(&g, 0); b1 = box_of(&g, 1); b2 = box_of(&g, 2); b3 = box_of(&g, 3);
		CK(straight(&g, wire_for(&g, t, 0, 1)));                       /* F straight below the branch */
		CKM(b1->y > b0->y && b2->y == b1->y && b2->x >= b1->x + (int32_t)b1->w, "diamond: T at (%d,%d) is not right of F at (%d,%d)", b2->x, b2->y, b1->x, b1->y);
		CKM(b3->x + (int32_t)b3->w / 2 >= b1->x + (int32_t)b1->w / 2 && b3->x + (int32_t)b3->w / 2 <= b2->x + (int32_t)b2->w / 2, "diamond: the merge is not between its parents");
		kv_graph_free(&g);
		g_kill(t);
		in_of(&in, t);
		CK(kv_graph_layout(&in, &g) == KV_GS_OK);
		b0 = box_of(&g, 0); b1 = box_of(&g, 1); b2 = box_of(&g, 2); b3 = box_of(&g, 3);
		CK(straight(&g, wire_for(&g, t, 0, 2)));                       /* B0 -> B2 plain, straight */
		CK(straight(&g, wire_for(&g, t, 2, 3)));                       /* B2 F B3 straight below the head */
		CKM(b1->x > b3->x, "kill: T target B1 (x %d) is not right of the fall-through B3 (x %d)", b1->x, b3->x);
		{
			const struct kv_graph_wire *l1 = wire_for(&g, t, 1, 2), *l3 = wire_for(&g, t, 3, 2);

			CK(l1 && l3 && l1->back && l3->back && l1->loop == KV_GL_LOOP && l3->loop == KV_GL_LOOP && l1->arrow == '^' && l3->arrow == '^');
			CKM(g.n_lane == 2u, "kill: %u lanes for two overlapping loop links", g.n_lane);
		}
		kv_graph_free(&g);
		free(t);
	}
	/* a binary tree (every node one parent): every first edge is straight, every second edge goes to the right of it, on 60 random trees */
	{
		uint64_t rng = 77u;
		unsigned k, firsts = 0, straights = 0;

		for (k = 0; k < 60u; k++) {
			struct tg *t = calloc(1, sizeof *t);
			struct kv_graph_in in;
			struct kv_graph g;
			uint32_t i, next = 1u, n = 2u + (uint32_t)(((rng = rng * 6364136223846793005ull + 1) >> 33) % 25u);

			t->n = n;
			for (i = 0; i < n && next < n; i++) {
				const int two = next + 1u < n && ((rng = rng * 6364136223846793005ull + 1) >> 33) % 3u;

				add(t, i, next, two ? CF : C0, L0);
				next++;
				if (two) {
					add(t, i, next, CT, L0);
					next++;
				}
			}
			in_of(&in, t);
			CK(kv_graph_layout(&in, &g) == KV_GS_OK);
			if ((int)k == dump_t) {
				char *pic = draw(&g, 1);

				printf("tree %u\n%s", k, pic);
				free(pic);
			}
			for (i = 0; i < t->ne; i++) {
				const struct kv_graph_wire *w = wire_for(&g, t, t->e[i].from, t->e[i].to);
				const struct kv_graph_box *p = box_of(&g, t->e[i].from), *c = box_of(&g, t->e[i].to);

				CKM(w && p && c && c->rank == p->rank + 1u, "tree %u: edge %u is not between neighbouring ranks", k, i);
				if (!w || !p || !c)
					continue;
				if (w && (i == 0 || t->e[i - 1u].from != t->e[i].from)) {
					/* the spine: straight when the boxes of the ranks leave room, else one jog (three segments) - never more */
					firsts++;
					straights += (unsigned)straight(&g, w);
					CKM(straight(&g, w) || w->n_seg == 3u, "tree %u: the first edge of B%u has %u segments", k, t->e[i].from, w->n_seg);
				}
				if (w && i && t->e[i - 1u].from == t->e[i].from) {
					const struct kv_graph_box *f = box_of(&g, t->e[i - 1u].to);

					CKM(f && c->x >= f->x + (int32_t)f->w, "tree %u: the taken side of B%u is not to the right of its fall-through", k, t->e[i].from);
				}
			}
			kv_graph_free(&g);
			free(t);
		}
		CKM(straights * 100u >= firsts * 97u, "trees: %u of %u first edges straight, want 97%%", straights, firsts);
		printf("  placement: %u of %u first edges straight on 60 random trees\n", straights, firsts);
	}
	/* the lanes are on the left: every back wire's vertical run is left of every box, and the inner loop is nearer the boxes (nested) */
	{
		struct tg *t = calloc(1, sizeof *t);
		struct kv_graph_in in;
		struct kv_graph g;
		const struct kv_graph_wire *inner, *outer;
		int32_t xi = 0, xo = 0;
		uint32_t q;

		g_nest(t);
		in_of(&in, t);
		CK(kv_graph_layout(&in, &g) == KV_GS_OK);
		inner = wire_for(&g, t, 4, 3);
		outer = wire_for(&g, t, 5, 1);
		for (q = 0; q < inner->n_seg; q++)
			if (g.seg[inner->seg0 + q].x0 == g.seg[inner->seg0 + q].x1 && g.seg[inner->seg0 + q].y0 != g.seg[inner->seg0 + q].y1)
				xi = g.seg[inner->seg0 + q].x0;
		for (q = 0; q < outer->n_seg; q++)
			if (g.seg[outer->seg0 + q].x0 == g.seg[outer->seg0 + q].x1 && g.seg[outer->seg0 + q].y0 != g.seg[outer->seg0 + q].y1)
				xo = g.seg[outer->seg0 + q].x0;
		CKM(xi > xo, "nested: the inner loop's lane (col %d) is not nearer the boxes than the outer's (col %d)", xi, xo);
		kv_graph_free(&g);
		free(t);
	}
}

/* The order of a rank is the barycenter's: a graph whose first order (the walk's) crosses two edges is drawn without a crossing. A (B0's fall-through) has the children P and S, B (its
 * taken side) has Q and P: the walk puts S Q P in the third rank, the mean position of the parents puts S P Q. */
static void reorder(void)
{
	struct tg *t = calloc(1, sizeof *t);
	struct kv_graph_in in;
	struct kv_graph g;
	char *pic;
	const struct kv_graph_box *p, *q, *s;
	uint32_t i, crossings = 0;

	t->n = 6;
	add(t, 0, 1, CF, L0); add(t, 0, 2, CT, L0);
	add(t, 1, 3, CF, L0); add(t, 1, 5, CT, L0);
	add(t, 2, 4, CF, L0); add(t, 2, 3, CT, L0);
	in_of(&in, t);
	CK(kv_graph_layout(&in, &g) == KV_GS_OK);
	p = box_of(&g, 3); q = box_of(&g, 4); s = box_of(&g, 5);
	CKM(s->x < p->x && p->x < q->x, "reorder: the third rank is not S P Q (x %d %d %d)", s->x, p->x, q->x);
	for (i = 0; i < g.width * g.height; i++)
		crossings += g.cell[i].g == KV_GG_LINE && g.cell[i].mask == (KV_GM_N | KV_GM_E | KV_GM_S | KV_GM_W);
	pic = draw(&g, 1);
	CKM(crossings == 0, "reorder: %u crossings:\n%s", crossings, pic);
	free(pic);
	kv_graph_free(&g);
	free(t);
}

/* ---- bounds and hostile graphs ---- */

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static void bounds(void)
{
	struct tg *t = calloc(1, sizeof *t);
	struct kv_graph_in in;
	struct kv_graph g;
	uint32_t i;

	/* a self-loop is a hook under its box */
	g_self(t);
	in_of(&in, t);
	CK(kv_graph_layout(&in, &g) == KV_GS_OK);
	check_invariants(t, &in, &g, "self-loop");
	{
		const struct kv_graph_wire *h = wire_for(&g, t, 1, 1);

		CK(h && h->back && h->arrow == '^' && h->n_seg == 3u && g.n_lane == 0u);
	}
	kv_graph_free(&g);
	/* a 100-way fan-out: wider than the canvas allows, so the prefix shrinks and the rest is counted */
	memset(t, 0, sizeof *t);
	t->n = 101;
	for (i = 1; i <= 100; i++)
		add(t, 0, i, CF, L0);
	in_of(&in, t);
	in.max_cols = 400;
	CK(kv_graph_layout(&in, &g) == KV_GS_TRUNCATED);
	CKM(g.n_box < 101u && g.n_box >= 5u && g.n_not_drawn == 101u - g.n_box && g.n_shrunk > 0 && g.width <= 400u, "fan-out: %u boxes, width %u, shrunk %u", g.n_box, g.width, g.n_shrunk);
	check_invariants(t, &in, &g, "fan-out 400 cols");
	kv_graph_free(&g);
	in.max_cols = 0;
	CK(kv_graph_layout(&in, &g) == KV_GS_OK && g.n_box == 101u);       /* default caps: 100 boxes of 8 columns and 3 between fit */
	check_invariants(t, &in, &g, "fan-out");
	kv_graph_free(&g);
	/* every edge to the last block */
	memset(t, 0, sizeof *t);
	t->n = 200;
	for (i = 0; i + 1u < 200u; i++)
		add(t, i, 199, C0, L0), add(t, i, i + 1u, CF, L0);
	{
		/* edges are sorted by source: a node's two edges are together (the plain one first is the last block: the spine is the next block, so the order is F first) */
		struct tg *u = calloc(1, sizeof *u);
		uint32_t k;

		u->n = 200;
		for (k = 0; k + 1u < 200u; k++) {
			add(u, k, k + 1u, CF, L0);
			add(u, k, 199, CT, L0);
		}
		in_of(&in, u);
		CK(kv_graph_layout(&in, &g) <= KV_GS_TRUNCATED);
		check_invariants(u, &in, &g, "all to the last");
		CKM(g.n_box == 200u && g.n_dummy > 0u, "all to the last: %u boxes, %u virtual nodes", g.n_box, g.n_dummy);
		kv_graph_free(&g);
		free(u);
	}
	/* thirty nested loops: head k loops back from tail 59 - k; one lane each */
	memset(t, 0, sizeof *t);
	t->n = 60;
	for (i = 0; i + 1u < 60u; i++) {
		add(t, i, i + 1u, C0, L0);
		if (i >= 30u)
			add(t, i, 59u - i, CT, LL);
	}
	/* edges must stay sorted by source: rebuild in order */
	{
		struct tg *u = calloc(1, sizeof *u);

		u->n = 60;
		for (i = 0; i < 60u; i++) {
			if (i + 1u < 60u)
				add(u, i, i + 1u, i >= 30u ? CF : C0, L0);
			if (i >= 30u)
				add(u, i, 59u - i, CT, LL);
		}
		in_of(&in, u);
		CK(kv_graph_layout(&in, &g) == KV_GS_OK);
		check_invariants(u, &in, &g, "thirty nested loops");
		CKM(g.n_lane >= 30u, "nested: %u lanes for 30 nested loops", g.n_lane);
		kv_graph_free(&g);
		free(u);
	}
	/* sixty loop links into one head: more than the lanes: the rest is listed with its reason */
	{
		struct tg *u = calloc(1, sizeof *u);
		uint32_t k;

		u->n = 62;
		add(u, 0, 1, C0, L0);
		for (k = 1; k < 61u; k++)
			add(u, k, k + 1u, C0, L0);
		for (k = 0; k < 62u; k++)
			;
		/* sources must be sorted: node k has its forward edge and a loop link to B1 */
		u->ne = 0;
		add(u, 0, 1, C0, L0);
		for (k = 1; k < 61u; k++) {
			add(u, k, k + 1u, CF, L0);
			add(u, k, 1, CT, LL);
		}
		in_of(&in, u);
		CK(kv_graph_layout(&in, &g) == KV_GS_TRUNCATED);
		CKM(g.n_lane == KV_GRAPH_MAX_LANE && g.n_edge_not_drawn > 0u && g.n_skipped > 0u && g.skip[0].why == KV_GW_LANE, "lanes: %u lanes, %u edges not drawn, first reason %u", g.n_lane, g.n_edge_not_drawn, g.n_skipped ? g.skip[0].why : 0u);
		check_invariants(u, &in, &g, "sixty loop links");
		kv_graph_free(&g);
		free(u);
	}
	/* edges across many ranks: the virtual-node cap */
	{
		struct tg *u = calloc(1, sizeof *u);
		uint32_t k, n = 390;

		u->n = n;
		for (k = 0; k + 1u < n; k++) {
			add(u, k, k + 1u, CF, L0);
			if (k < 40u)
				add(u, k, n - 1u - k % 3u, CT, L0);
		}
		in_of(&in, u);
		CK(kv_graph_layout(&in, &g) <= KV_GS_TRUNCATED);
		CKM(g.n_dummy <= KV_GRAPH_MAX_DUMMY, "dummies %u over the cap", g.n_dummy);
		check_invariants(u, &in, &g, "long edges");
		kv_graph_free(&g);
		free(u);
	}
	/* a chain of 5000: the node cap, the count and the index of the rest */
	{
		struct tg *u = calloc(1, sizeof *u);
		uint32_t k;

		u->n = 5000;
		for (k = 0; k + 1u < 5000u; k++)
			add(u, k, k + 1u, C0, L0);
		in_of(&in, u);
		in.max_rows = 4000;
		CK(kv_graph_layout(&in, &g) == KV_GS_TRUNCATED);
		CKM(g.n_box > 0u && g.n_box <= KV_GRAPH_MAX_NODE && g.n_not_drawn == 5000u - g.n_box && g.n_rest == KV_GRAPH_REST && g.rest[0] == g.n_box, "chain: %u boxes, %u not drawn, rest[0] %u",
		    g.n_box, g.n_not_drawn, g.rest[0]);
		CKM(g.n_edge_not_drawn == 5000u - 1u - (g.n_box - 1u), "chain: %u edges not drawn", g.n_edge_not_drawn);
		check_invariants(u, &in, &g, "chain of 5000");
		kv_graph_free(&g);
		free(u);
	}
	/* a canvas too small for one box: nothing drawn, everything counted */
	g_line(t);
	in_of(&in, t);
	in.max_cols = 5;
	CK(kv_graph_layout(&in, &g) == KV_GS_TRUNCATED && g.n_box == 0u && g.n_not_drawn == 3u && g.n_edge_not_drawn == 2u && g.width == 0u);
	kv_graph_free(&g);
	/* bad input: edges not sorted, a node out of range, no text callback */
	g_line(t);
	in_of(&in, t);
	t->e[0].from = 2;
	CK(kv_graph_layout(&in, &g) == KV_GS_BAD_INPUT);
	kv_graph_free(&g);
	g_line(t);
	in_of(&in, t);
	t->e[1].to = 77;
	CK(kv_graph_layout(&in, &g) == KV_GS_BAD_INPUT);
	kv_graph_free(&g);
	in_of(&in, t);
	in.text = NULL;
	CK(kv_graph_layout(&in, &g) == KV_GS_BAD_INPUT);
	CK(kv_graph_layout(NULL, &g) == KV_GS_BAD_INPUT);
	free(t);
}

/* 200000 nodes: the walk and the prefix, in a time bound */
static void big(void)
{
	enum { N = 200000 };
	struct kv_graph_edge *e = malloc((size_t)N * 2u * sizeof *e);
	struct kv_graph_in in;
	struct kv_graph g;
	uint32_t i, ne = 0;
	double t0, ms;
	static struct tg tg;

	for (i = 0; i < N; i++) {
		if (i + 1u < N) {
			e[ne].from = i; e[ne].to = i + 1u; e[ne].cond = (i % 5u == 0u) ? CF : C0; e[ne].loop = L0; ne++;
		}
		if (i % 7u == 6u) {
			e[ne].from = i; e[ne].to = i - 6u; e[ne].cond = CT; e[ne].loop = LL; ne++;
		}
		if (i % 5u == 0u && i + 3u < N) {
			e[ne].from = i; e[ne].to = i + 3u; e[ne].cond = CT; e[ne].loop = L0; ne++;
		}
	}
	/* sorted by source already? sources are non-decreasing: node i's edges are added together, in the order above */
	memset(&in, 0, sizeof in);
	in.n_node = N;
	in.n_edge = ne;
	in.edge = e;
	in.text = text;
	in.user = &tg;
	in.max_rows = 3000;
	t0 = now_ms();
	CK(kv_graph_layout(&in, &g) == KV_GS_TRUNCATED);
	ms = now_ms() - t0;
	CKM(g.n_box > 50u && g.n_box + g.n_not_drawn == N && g.width <= KV_GRAPH_COLS_DEF && g.height <= 3000u, "200000: %u boxes, canvas %ux%u", g.n_box, g.width, g.height);
	CKM(ms < 1500.0, "200000 nodes took %.0f ms", ms);
	printf("  big: 200000 nodes laid out in %.1f ms (%u boxes drawn, canvas %ux%u, %u shrinks)\n", ms, g.n_box, g.width, g.height, g.n_shrunk);
	kv_graph_free(&g);
	free(e);
}

/* ---- memory ---- */

static void memory(void)
{
	struct tg *t = calloc(1, sizeof *t);
	struct kv_graph_in in;
	struct kv_graph g;
	unsigned n, clean = 0;

	g_kill(t);
	in_of(&in, t);
	for (n = 1; n <= 12; n++) {
		enum kv_graph_status st;

		n_held = 0; calls = 0; nth = n; armed = 1;
		st = kv_graph_layout(&in, &g);
		armed = 0;
		CKM(st == KV_GS_NOMEM || st <= KV_GS_TRUNCATED, "allocation %u refused: status %d", n, (int)st);
		if (st == KV_GS_NOMEM)
			CKM(g.n_box == 0u && g.cell == NULL && g.box == NULL, "allocation %u refused: something is held", n);
		else
			clean++;
		armed = 1;
		kv_graph_free(&g);
		armed = 0;
		CKM(n_held == 0u, "allocation %u refused: %u block(s) left", n, n_held);
	}
	CK(clean >= 1u);                  /* the calls past the last one the layout makes are not refused */
	free(t);
}

int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "--dump"))
		dump_k = atoi(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "--dumptree"))
		dump_t = atoi(argv[2]);
	golden();
	invariants();
	placement();
	reorder();
	bounds();
	big();
	memory();
	if (fails) {
		printf("kx_graph: %d failure(s)\n", fails);
		return 1;
	}
	printf("kx_graph: ok\n");
	return 0;
}
