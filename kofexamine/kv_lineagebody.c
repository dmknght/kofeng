#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofview.h"
#include "kv_cfgbody.h"        /* kv_cfgbody_style/_mark_attr/_edge_attr: the same palette, reused */
#include "kv_lineagebody.h"

/*
 * The BODY of the Lineage tab (kv_cfgdlg.c): the function's slice of the object's value-flow
 * graph (kof_lineageview_build) in two panes - the drawing (kv_graph*.c, the same module the
 * Graph tab uses) and what it left out, then the engine's rows of the links, each with a tick
 * box whose press lights its edge. Nothing here decides a thing of the graph or composes a
 * word of a link: the rows are the engine's (gv.note), the places kv_graph's.
 */

#define LGV_MAX_COLS 1600u
#define LGV_MAX_ROWS 2400u
#define LGV_INDEX_ENT 8u
#define LGV_WHEEL_ROWS 3u
#define LGV_WHEEL_COLS 8u
#define LGV_BOX 4u              /* "[x] ": the tick box and its gap, before a link's row */

static void list_add(char ***l, uint32_t *n, const char *fmt, ...)
{
	char line[512], **nx;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line, sizeof line, fmt, ap);
	va_end(ap);
	nx = realloc(*l, ((size_t)*n + 1u) * sizeof *nx);
	if (!nx)
		return;
	*l = nx;
	(*l)[*n] = strdup(line);
	if ((*l)[*n])
		(*n)++;
}

static void list_free(char ***l, uint32_t *n)
{
	uint32_t i;

	for (i = 0; i < *n; i++)
		free((*l)[i]);
	free(*l);
	*l = NULL;
	*n = 0;
}

void kv_lineagebody_free(struct kv_lineage_body *b)
{
	kv_graph_free(&b->g);
	kgenome_gv_free(&b->gv, NULL);
	list_free(&b->xl, &b->n_xl);
	free(b->tick);
	free(b->lit);
	memset(b, 0, sizeof *b);
}

static const char *box_text(void *user, uint32_t node, uint32_t i)
{
	struct kv_lineage_body *u = user;

	return kgenome_gv_box_line(&u->gv, node, i, u->scratch, sizeof u->scratch);
}

static uint8_t box_mark(void *user, uint32_t node, int32_t line)
{
	const struct kv_lineage_body *u = user;

	if (line < 0)
		return node == u->gv.entry ? KV_CFG_MK_ENTRY : KV_CFG_MK_NONE;
	return KV_CFG_MK_NONE;
}

static struct kv_graph_edge *graph_edges(const struct kgenome_gv *gv)
{
	struct kv_graph_edge *e = calloc(gv->n_edge ? gv->n_edge : 1u, sizeof *e);
	uint32_t i;

	for (i = 0; e && i < gv->n_edge; i++) {
		e[i].from = gv->edge[i].from;
		e[i].to = gv->edge[i].to;
		e[i].cond = gv->edge[i].cond;
		e[i].loop = gv->edge[i].loop;
		e[i].sure = gv->edge[i].sure;
		e[i].carry = gv->edge[i].carry;
		e[i].label = gv->edge[i].label;        /* the engine's word: the same one as the link's row */
	}
	return e;
}

/* What the drawing could not hold (as kv_cfgbody.c's own note_left_out): said under the drawing, in its pane. */
static void note_left_out(struct kv_lineage_body *u)
{
	const struct kv_graph *g = &u->g;
	const struct kgenome_gv *gv = &u->gv;
	char line[256];
	size_t w = 0;
	uint32_t i, ent = 0;

	/* a drawing the layout refused is said: the head's counts (on the Overview) would otherwise stand over an empty page (2026-11-14) */
	if (g->status == KV_GS_BAD_INPUT || g->status == KV_GS_NOMEM)
		list_add(&u->xl, &u->n_xl, "the graph was not drawn: %s", g->status == KV_GS_NOMEM ? "no memory for the drawing" : "the layout refused its edges");
	if (gv->status != KGENOME_OK)                   /* the engine's own refusal: its last head line says why */
		list_add(&u->xl, &u->n_xl, "%s", gv->n_head ? gv->head[gv->n_head - 1u] : "the graph was not made");
	if (g->n_not_drawn) {
		list_add(&u->xl, &u->n_xl, "... %u more node(s) not drawn; index (id @ offset):", (unsigned)g->n_not_drawn);
		line[0] = 0;
		for (i = 0; i < g->n_rest; i++) {
			const uint32_t n = g->rest[i];

			w += (size_t)snprintf(line + w, sizeof line - w, "  %c%u@0x%llx", gv->id_prefix, (unsigned)n, (unsigned long long)gv->node[n].off);
			if (++ent == LGV_INDEX_ENT || i + 1u == g->n_rest) {
				list_add(&u->xl, &u->n_xl, "%s", line);
				line[0] = 0;
				w = 0;
				ent = 0;
			}
		}
		if (g->n_not_drawn > g->n_rest)
			list_add(&u->xl, &u->n_xl, "  ... %u more not indexed", (unsigned)(g->n_not_drawn - g->n_rest));
	}
	if (g->n_label_cut)
		list_add(&u->xl, &u->n_xl, "... %u link label(s) not drawn (no room beside the arrowhead): the rows below name every link", (unsigned)g->n_label_cut);
	if (g->n_edge_not_drawn) {
		list_add(&u->xl, &u->n_xl, "... %u link(s) not drawn:", (unsigned)g->n_edge_not_drawn);
		for (i = 0; i < g->n_skipped; i++) {
			const struct kgenome_gv_edge *e = &gv->edge[g->skip[i].edge];
			const char *why = g->skip[i].why == KV_GW_END ? "an end is not drawn" : g->skip[i].why == KV_GW_CAP ? "past the edge cap" : "no lane left";

			list_add(&u->xl, &u->n_xl, "  %c%u -> %c%u (%s)", gv->id_prefix, (unsigned)e->from, gv->id_prefix, (unsigned)e->to, why);
		}
		if (g->n_edge_not_drawn > g->n_skipped)
			list_add(&u->xl, &u->n_xl, "  ... %u more not listed", (unsigned)(g->n_edge_not_drawn - g->n_skipped));
	}
}

void kv_lineagebody_make(struct kv_lineage_body *u, const struct kof_lineageview_req *rq)
{
	struct kv_graph_in in;
	struct kv_graph_edge *e;

	memset(u, 0, sizeof *u);
	(void)kof_lineageview_build(rq, &u->gv);
	u->tick = calloc(u->gv.n_note + 1u, 1);
	u->lit = calloc(u->gv.n_edge + 1u, 1);
	e = graph_edges(&u->gv);
	memset(&in, 0, sizeof in);
	in.n_node = u->gv.n_node;
	in.entry = u->gv.entry;
	in.n_edge = u->gv.n_edge;
	in.edge = e;
	in.text = box_text;
	in.mark = box_mark;
	in.user = u;
	/* KNOWN DEFECT LV-D1 (2026-11-17, M) [sev M]: kv_lineagebody_make lays every unlinked node in one rank and caps the canvas at LGV_MAX_COLS (1600), so kv_graph_layout
	 * shrinks the prefix and drops boxes (counted, index of the first 64). Trigger: a function with more than about 70 unlinked nodes. Effect: 54 of 19,673 set356 functions;
	 * 094_4c38 fcn at 0x6b5b2: 12,723 of 12,793 nodes not drawn. Reproducer: /mnt/games/normtest/lin_truth/drv/lgf check DB FILE -v (D_counted_not_drawn).
	 * Fix: list the unlinked nodes as rows instead of boxes (owner decision, followups FU-9). */
	in.max_cols = LGV_MAX_COLS;
	in.max_rows = LGV_MAX_ROWS;
	in.sources_first = 1;          /* a value flow has no one entry: every producer nothing feeds is a start */
	in.ordered = u->gv.ordered;    /* the engine's: the nodes are in program order */
	if (e || !in.n_edge)
		(void)kv_graph_layout(&in, &u->g);
	free(e);
	note_left_out(u);
}

/* The rows of the top pane's content (the drawing, then what it left out) and of the table (the links). */
static uint32_t pane_rows(const struct kv_lineage_body *u)
{
	return u->g.height + u->n_xl;
}

/*
 * THE SPLIT of a room of `room` rows: one rule row between the panes; each pane gets what it holds when both fit, the table at most half when
 * the drawing needs more and the drawing at most half when the table does; when both need more than half, halves (the owner's layout).
 */
void kv_lineagebody_size(struct kv_lineage_body *u, uint32_t room, uint32_t *n_row, uint32_t *n_col)
{
	const uint32_t want_t = pane_rows(u), want_b = u->gv.n_note ? u->gv.n_note : 1u;
	const uint32_t avail = room > 1u ? room - 1u : 0u, half = avail / 2u;
	uint32_t top;

	if (want_t + want_b <= avail)
		top = want_t;
	else if (want_b <= half)
		top = avail - want_b;
	else if (want_t <= half)
		top = want_t;
	else
		top = avail - half;
	u->room = room;
	u->top = top;
	if (u->g_off + top > want_t)
		u->g_off = want_t > top ? want_t - top : 0u;
	if (u->t_off + (avail - top) > want_b)
		u->t_off = want_b > avail - top ? want_b - (avail - top) : 0u;
	*n_row = room;
	*n_col = 0;
}

/* `t` from its `hoff`-th column, `ncols` wide. */
static void put_text(const char *t, uint32_t hoff, uint32_t ncols, char *out, size_t cap)
{
	if (t && hoff < strlen(t))
		snprintf(out, cap, "%.*s", (int)ncols, t + hoff);
}

void kv_lineagebody_row(const void *user, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap)
{
	const struct kv_lineage_body *u = user;
	const uint32_t gh = u->g.height;

	(void)hoff;
	if (cap < 2 || !ncols)
		return;
	out[0] = ' ';
	out[1] = 0;
	if (row < u->top) {
		const uint32_t r = u->g_off + row;

		if (r < gh) {
			struct kv_graph_style st = kv_cfgbody_style();

			st.lit = u->lit;
			st.n_lit = u->gv.n_edge;
			st.lit_attr = A_SEL;
			kv_graph_window(&u->g, r, u->g_hoff, ncols - 1u, &st, out + 1, cap - 1u);
		} else if (r - gh < u->n_xl) {
			put_text(u->xl[r - gh], u->g_hoff, ncols - 1u, out + 1, cap - 1u);
		}
	} else if (row == u->top) {
		char rule[160];
		const uint32_t shown = u->room > u->top + 1u ? u->room - u->top - 1u : 0u;

		/* the rule between the panes: the engine's title of the rows, and which of them the pane shows when it does not show all */
		if (u->gv.n_note > shown && shown)
			snprintf(rule, sizeof rule, "-- %s (rows %u-%u) --", u->gv.note_title, (unsigned)u->t_off + 1u,
				 (unsigned)(u->t_off + shown < u->gv.n_note ? u->t_off + shown : u->gv.n_note));
		else
			snprintf(rule, sizeof rule, "-- %s --", u->gv.note_title[0] ? u->gv.note_title : "links: none");
		put_text(rule, 0, ncols - 1u, out + 1, cap - 1u);
	} else {
		const uint32_t r = u->t_off + (row - u->top - 1u);
		char line[KGENOME_GV_NOTE + 8u];

		if (r >= u->gv.n_note)
			return;
		/* a link drawn as an edge has a tick box; one with no edge (its producer is outside the function, or the stack) has nothing to light */
		snprintf(line, sizeof line, "%s%s", u->gv.note[r].link ? (u->tick[r] ? "[x] " : "[ ] ") : " -  ", u->gv.note[r].text);
		put_text(line, u->t_hoff, ncols - 1u, out + 1, cap - 1u);
	}
}

void kv_lineagebody_wheel(struct kv_lineage_body *u, uint32_t row, int up, int side)
{
	const uint32_t d = side ? LGV_WHEEL_COLS : LGV_WHEEL_ROWS;
	uint32_t *at;

	if (row < u->top)
		at = side ? &u->g_hoff : &u->g_off;
	else if (row > u->top)
		at = side ? &u->t_hoff : &u->t_off;
	else
		return;
	*at = up ? (*at > d ? *at - d : 0u) : *at + d;   /* down: clamped by kv_lineagebody_size, sideways by the text running out */
	if (side && row < u->top && u->g_hoff > (u->g.width > 8u ? u->g.width - 8u : 0u))
		u->g_hoff = u->g.width > 8u ? u->g.width - 8u : 0u;
	if (side && row > u->top && u->t_hoff > KGENOME_GV_NOTE)
		u->t_hoff = KGENOME_GV_NOTE;
}

int kv_lineagebody_press(struct kv_lineage_body *u, uint32_t row, int col)
{
	uint32_t r;

	if (row <= u->top || col < 1 || col > (int)LGV_BOX - 1 || u->t_hoff)
		return 0;
	r = u->t_off + (row - u->top - 1u);
	if (r >= u->gv.n_note || !u->gv.note[r].link || u->gv.note[r].link > u->gv.n_edge)
		return 0;
	u->tick[r] = (uint8_t)!u->tick[r];
	u->lit[u->gv.note[r].link - 1u] = u->tick[r];
	return 1;
}
