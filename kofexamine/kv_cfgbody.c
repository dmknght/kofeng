#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofview.h"
#include "kv_cfgbody.h"

/*
 * The BODY of the CFG dialog of a function (kv_cfgdlg.c) for the two tabs that need no view: what the dialog lists and draws, as rows, with no screen and no view - so the
 * tests read the same rows the dialog shows (tests/unit/cfg_view_scene.c prints them, tests/tui/t_cfg_view.py compares the screen with them).
 *
 *   Overview   the engine's head lines (the function, the extent, the counts, the canonical hash, the keys, the anchor - or the one sentence of why there is no graph),
 *              then the calls as a TABLE (every struct kof_cfgview_call: its block, its instruction's offset, its kind, its target, the object's name for it), then the
 *              unreachable blocks the engine listed. Every cell is a field the engine returned; nothing is derived here.
 *   Graph      the drawing (the engine's graph laid out and drawn by kv_graph.c), then what the drawing did not show (the nodes and edges past its bounds, one line each).
 *
 * The facts are the engine's lines, listed as they came; the owner reviews their layout later. Nothing here decides a thing of the graph.
 */

#define CFG_MAX_COLS 1600u              /* the canvas of the drawing: at most this wide and this tall (kv_graph.h also bounds the cells) */
#define CFG_MAX_ROWS 2400u
#define CFG_INDEX_ENT 8u                /* nodes named on a line of the index of the nodes not drawn */

static void list_free(char ***l, uint32_t *n)
{
	uint32_t i;

	for (i = 0; i < *n; i++)
		free((*l)[i]);
	free(*l);
	*l = NULL;
	*n = 0;
}

void kv_cfgbody_free(struct kv_cfg_body *b)
{
	kv_graph_free(&b->g);
	kof_cfgview_free(&b->cf);
	free(b->fl);
	list_free(&b->xl, &b->n_xl);
	list_free(&b->ol, &b->n_ol);
	memset(b, 0, sizeof *b);
}

/* The text of one row of a box: the engine's (kgenome_gv_box_line). */
static const char *box_text(void *user, uint32_t node, uint32_t i)
{
	struct kv_cfg_body *u = user;

	return kgenome_gv_box_line(&u->cf.gv, node, i, u->scratch, sizeof u->scratch);
}

/* One owned line appended to a list of rows. */
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

/* What the drawing could not hold, said line by line: the nodes past its bounds (an index of ids and offsets) and the edges it did not draw. Counted by kv_graph, never dropped. */
static void note_left_out(struct kv_cfg_body *u)
{
	const struct kv_graph *g = &u->g;
	const struct kgenome_gv *gv = &u->cf.gv;
	char line[256];
	size_t w = 0;
	uint32_t i, ent = 0;

	if (g->n_not_drawn) {
		list_add(&u->xl, &u->n_xl, "... %u more block(s) not drawn; index (id @ offset):", (unsigned)g->n_not_drawn);
		line[0] = 0;
		for (i = 0; i < g->n_rest; i++) {
			const uint32_t n = g->rest[i];

			w += (size_t)snprintf(line + w, sizeof line - w, "  %c%u@0x%llx", gv->id_prefix, (unsigned)n, (unsigned long long)gv->node[n].off);
			if (++ent == CFG_INDEX_ENT || i + 1u == g->n_rest) {
				list_add(&u->xl, &u->n_xl, "%s", line);
				line[0] = 0;
				w = 0;
				ent = 0;
			}
		}
		if (g->n_not_drawn > g->n_rest)
			list_add(&u->xl, &u->n_xl, "  ... %u more not indexed", (unsigned)(g->n_not_drawn - g->n_rest));
	}
	if (g->n_edge_not_drawn) {
		list_add(&u->xl, &u->n_xl, "... %u edge(s) not drawn:", (unsigned)g->n_edge_not_drawn);
		for (i = 0; i < g->n_skipped; i++) {
			const struct kgenome_gv_edge *e = &gv->edge[g->skip[i].edge];
			const char *why = g->skip[i].why == KV_GW_END ? "an end is not drawn" : g->skip[i].why == KV_GW_CAP ? "past the edge cap" : "no lane left";

			list_add(&u->xl, &u->n_xl, "  %c%u -%s-> %c%u (%s)", gv->id_prefix, (unsigned)e->from, e->cond == KGENOME_GV_COND_T ? "T" : e->cond == KGENOME_GV_COND_F ? "F" : "",
				 gv->id_prefix, (unsigned)e->to, why);
		}
		if (g->n_edge_not_drawn > g->n_skipped)
			list_add(&u->xl, &u->n_xl, "  ... %u more not listed", (unsigned)(g->n_edge_not_drawn - g->n_skipped));
	}
}

/* The edges of the engine's graph, as kv_graph names them (the same values: kv_graph.h). */
static struct kv_graph_edge *graph_edges(const struct kgenome_gv *gv)
{
	struct kv_graph_edge *e = calloc(gv->n_edge ? gv->n_edge : 1u, sizeof *e);
	uint32_t i;

	for (i = 0; e && i < gv->n_edge; i++) {
		e[i].from = gv->edge[i].from;
		e[i].to = gv->edge[i].to;
		e[i].cond = gv->edge[i].cond;
		e[i].loop = gv->edge[i].loop;
	}
	return e;
}

/* The mark of a part of a box, read off the engine's graph: the entry's border, a loop head's first row, the call rows of a node that holds calls. */
static uint8_t box_mark(void *user, uint32_t node, int32_t line)
{
	const struct kv_cfg_body *u = user;
	const struct kgenome_gv *gv = &u->cf.gv;

	if (line < 0)
		return node == gv->entry ? KV_CFG_MK_ENTRY : KV_CFG_MK_NONE;
	if (line == 0)
		return (gv->node[node].flags & KGENOME_GV_NF_LOOP_HEAD) ? KV_CFG_MK_LOOP_HEAD : KV_CFG_MK_NONE;
	if (line >= 2 && gv->node[node].xtotal)
		return KV_CFG_MK_CALL;
	return KV_CFG_MK_NONE;
}

const char *kv_cfgbody_edge_attr(unsigned cond, unsigned loop)
{
	if (cond == KGENOME_GV_COND_T)
		return A_SIZE;
	if (cond == KGENOME_GV_COND_F)
		return A_BAD;
	if (loop == KGENOME_GV_LOOP_LINK)
		return A_WARN;
	if (loop == KGENOME_GV_LOOP_RETREAT)
		return A_HEUR;
	return NULL;
}

const char *kv_cfgbody_mark_attr(unsigned mark)
{
	switch (mark) {
	case KV_CFG_MK_ENTRY: return A_LOC;
	case KV_CFG_MK_LOOP_HEAD: return A_WARN;
	case KV_CFG_MK_CALL: return A_ID;
	default: return NULL;
	}
}

struct kv_graph_style kv_cfgbody_style(void)
{
	struct kv_graph_style st = kv_graph_style_default();
	unsigned loop, cond, m;

	for (loop = 0; loop < 3u; loop++)
		for (cond = 0; cond < 3u; cond++)
			st.attr[1u + loop * 3u + cond] = kv_cfgbody_edge_attr(cond, loop);
	for (m = 1; m < KV_GRAPH_MARKS && m <= KV_CFG_MK_CALL; m++)
		st.attr[KV_GRAPH_MARK0 - 1u + m] = kv_cfgbody_mark_attr(m);
	st.off = A_OFF;
	return st;
}

static void lay_out(struct kv_cfg_body *u)
{
	struct kv_graph_in in;
	struct kv_graph_edge *e = graph_edges(&u->cf.gv);
	uint32_t i;

	memset(&in, 0, sizeof in);
	in.n_node = u->cf.gv.n_node;
	in.entry = u->cf.gv.entry;
	in.n_edge = u->cf.gv.n_edge;
	in.edge = e;
	in.text = box_text;
	in.mark = box_mark;
	in.user = u;
	in.max_cols = CFG_MAX_COLS;
	in.max_rows = CFG_MAX_ROWS;
	if (e || !in.n_edge)
		(void)kv_graph_layout(&in, &u->g);
	free(e);
	u->fl = calloc((size_t)u->cf.n_lines + 1u, sizeof *u->fl);
	if (u->fl && u->cf.text) {
		char *p = u->cf.text;

		for (i = 0; i < u->cf.n_lines && *p; i++) {
			u->fl[u->n_fl++] = p;
			p += strcspn(p, "\n");
			if (*p)
				*p++ = 0;
		}
	}
	note_left_out(u);
	u->n_col = u->g.width;
	for (i = 0; i < u->n_xl; i++)
		if (strlen(u->xl[i]) > u->n_col)
			u->n_col = (uint32_t)strlen(u->xl[i]);
}

/*
 * The spelling of a call's kind in a table cell. The engine spells it in two places of its own (cfgview.c and codenotes.c, `kind_word`, both static) and exports neither, so
 * this is a third copy of three words, kept equal to theirs until the engine exports one.
 */
/* KNOWN DEFECT CFGTAB-1 (2026-10-31, R) [sev L]: call_kind_word spells enum kgenome_cfg_call_kind a third time (cfgview.c and codenotes.c have `kind_word`, static).
 * Trigger: a word changes in the engine only. Effect: the Overview's table and the engine's own lines (the notes, the boxes) say different words for one call.
 * Reproducer: tests/tui/t_cfg_view.py, overview_calls_table_cells_are_the_engines_fields (compares the kind cell with the engine's note line). Fix: export one
 * `kof_cfgview_kind_word` from analyzers/cfgview.c, call it here and in codenotes.c, delete this function. */
static const char *call_kind_word(unsigned k)
{
	switch (k) {
	case KGENOME_CFG_CK_SYSCALL: return "syscall";
	case KGENOME_CFG_CK_INDIRECT: return "call indirect";
	default: return "call";
	}
}

/* The Overview's rows: the head, the calls table, the unreachable blocks. Fields of the engine's answer, one cell each. */
static void overview_make(struct kv_cfg_body *u)
{
	const struct kof_cfgview *cf = &u->cf;
	const struct kgenome_gv *gv = &cf->gv;
	uint32_t i, nh = gv->n_head && gv->n_head < u->n_fl ? gv->n_head : u->n_fl;
	size_t wb = 5, wa = 6, wk = 4, wt = 6;
	char b[16], a[32], t[32];

	for (i = 0; i < nh; i++)
		list_add(&u->ol, &u->n_ol, "%s", u->fl[i]);
	u->n_head = u->n_ol;
	if (cf->n_call) {
		list_add(&u->ol, &u->n_ol, "%s", "");
		list_add(&u->ol, &u->n_ol, "%s", gv->note_title);
		for (i = 0; i < cf->n_call; i++) {
			const struct kof_cfgview_call *c = &cf->call[i];
			size_t n;

			n = (size_t)snprintf(b, sizeof b, "B%u", (unsigned)c->blk);
			wb = n > wb ? n : wb;
			n = (size_t)snprintf(a, sizeof a, "0x%llx", (unsigned long long)c->at);
			wa = n > wa ? n : wa;
			n = strlen(call_kind_word(c->kind));
			wk = n > wk ? n : wk;
			n = c->target == KGENOME_BROKEN ? 1u : (size_t)snprintf(t, sizeof t, "0x%llx", (unsigned long long)c->target);
			wt = n > wt ? n : wt;
		}
		list_add(&u->ol, &u->n_ol, "  %-*s  %-*s  %-*s  %-*s  %s", (int)wb, "block", (int)wa, "offset", (int)wk, "kind", (int)wt, "target", "name");
		for (i = 0; i < cf->n_call; i++) {
			const struct kof_cfgview_call *c = &cf->call[i];

			snprintf(b, sizeof b, "B%u", (unsigned)c->blk);
			snprintf(a, sizeof a, "0x%llx", (unsigned long long)c->at);
			if (c->target == KGENOME_BROKEN)
				snprintf(t, sizeof t, "-");
			else
				snprintf(t, sizeof t, "0x%llx", (unsigned long long)c->target);
			list_add(&u->ol, &u->n_ol, "  %-*s  %-*s  %-*s  %-*s  %s", (int)wb, b, (int)wa, a, (int)wk, call_kind_word(c->kind), (int)wt, t, c->name);
		}
	}
	if (gv->aside_title[0]) {
		list_add(&u->ol, &u->n_ol, "%s", "");
		if (!gv->n_aside) {
			if (gv->aside_none[0])
				list_add(&u->ol, &u->n_ol, "%s", gv->aside_none);
		} else {
			list_add(&u->ol, &u->n_ol, "%s", gv->aside_title);
			for (i = 0; i < gv->n_aside; i++)
				list_add(&u->ol, &u->n_ol, "  %s", gv->aside[i].text);
		}
	}
	for (i = 0; i < u->n_ol; i++)
		if (strlen(u->ol[i]) > u->ol_col)
			u->ol_col = (uint32_t)strlen(u->ol[i]);
}

void kv_cfgbody_make(struct kv_cfg_body *u, const struct kof_cfgview_req *rq)
{
	memset(u, 0, sizeof *u);
	(void)kof_cfgview_build(rq, &u->cf);
	lay_out(u);
	overview_make(u);
	u->n_row = u->g.height + u->n_xl;
	if (!u->n_row)
		u->n_row = u->n_head;           /* no drawing: the Graph tab says what the engine said of why */
	if (!u->g.height && !u->n_xl)
		for (uint32_t i = 0; i < u->n_head; i++)
			if (strlen(u->ol[i]) > u->n_col)
				u->n_col = (uint32_t)strlen(u->ol[i]);
}

void kv_cfgbody_size(const struct kv_cfg_body *u, unsigned tab, uint32_t *n_row, uint32_t *n_col)
{
	*n_row = *n_col = 0;
	if (tab == KV_CFG_TAB_OVERVIEW) {
		*n_row = u->n_ol;
		*n_col = u->ol_col;
	} else if (tab == KV_CFG_TAB_GRAPH) {
		*n_row = u->n_row;
		*n_col = u->n_col;
	}
}

/* One row of the body from column `hoff`: a row of the Overview, or a row of the drawing and then a line about what was left out. */
void kv_cfgbody_row(const void *user, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap)
{
	const struct kv_cfg_body *u = user;
	const char *t = NULL;
	const uint32_t gh = u->g.height;

	if (cap < 2 || !ncols)
		return;
	out[0] = ' ';
	out[1] = 0;
	if (u->tab == KV_CFG_TAB_OVERVIEW) {
		t = row < u->n_ol ? u->ol[row] : NULL;
	} else if (row < gh) {
		const struct kv_graph_style st = kv_cfgbody_style();

		kv_graph_window(&u->g, row, hoff, ncols - 1u, &st, out + 1, cap - 1u);
		return;
	} else if (row - gh < u->n_xl) {
		t = u->xl[row - gh];
	} else if (!gh && !u->n_xl && row < u->n_head) {
		t = u->ol[row];
	}
	if (t && hoff < strlen(t))
		snprintf(out + 1, cap - 1u, "%.*s", (int)(ncols - 1u), t + hoff);
}
