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
 *   Overview   the engine's head lines (the function, the extent, the counts, the unit id, the keys (the CFG hash, called Scaffold in the docs) - or the one sentence of why there is no graph),
 *              then the calls as a TABLE (every struct kof_cfgview_call: its block, its instruction's offset, its kind, its target, the object's name for it), then the
 *              unreachable blocks the engine listed. Every cell is a field the engine returned; nothing is derived here.
 *   Graph      the drawing (the engine's graph laid out and drawn by kv_graph*.c), then what the drawing did not show (the nodes and edges past its bounds, one line each).
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

/*
 * THE COLOURS OF THE OVERVIEW, by the label the viewer knows (the engine's lines stay plain text): a label dim (A_DIM), a value in the colour the Properties dialog and the Blocks
 * table already use for its kind - a name and the hashes A_ID, an offset or an address A_LOC, a non-ok status A_WARN - and a number in the terminal's own colour. The label of a
 * `key=value` word is its key and its `=`. Nothing is derived: the class of a word is read off its spelling and its row's first word.
 */
#define OV_ROW_MAX 512u

static int ov_is_hex8(const char *t, size_t n)
{
	size_t i;

	if (n != 8u)
		return 0;
	for (i = 0; i < n; i++)
		if (!((t[i] >= '0' && t[i] <= '9') || (t[i] >= 'a' && t[i] <= 'f')))
			return 0;
	return 1;
}

static void ov_paint(size_t a, size_t b, const char *attr, const char **at)
{
	size_t i;

	for (i = a; i < b; i++)
		at[i] = attr;
}

static void ov_attrs(const char *row, const char **at)
{
	const size_t len = strlen(row);
	size_t i = 0, tok = 0, kind_toks = 1;
	int is_func = 0, is_head = 0, is_head_tbl = 0, is_call = 0, is_asideh = 0;

	memset((void *)at, 0, len * sizeof *at);
	while (i < len) {
		size_t b, e;
		const char *eq, *t;

		while (i < len && row[i] == ' ')
			i++;
		if (i >= len)
			break;
		b = i;
		while (i < len && row[i] != ' ')
			i++;
		e = i;
		t = row + b;
		eq = memchr(t, '=', e - b);
		if (tok == 0) {
			const size_t n = e - b;

			is_func = n == 8u && !memcmp(t, "function", 8);
			is_head = (n == 6u && !memcmp(t, "extent", 6)) || (n == 4u && !memcmp(t, "unit", 4)) || (n == 4u && !memcmp(t, "keys", 4)) ||
				  (n == 3u && !memcmp(t, "CFG", 3) && !strncmp(row + e, "  reachable=", 12));
			is_head_tbl = n == 5u && !memcmp(t, "block", 5) && !strncmp(row + e, "  offset", 8);
			is_asideh = !strncmp(row, "unreachable blocks:", 19);
			is_call = row[0] == ' ' && t[0] == 'B' && n > 1u;
			if (is_head_tbl) {
				ov_paint(b, len, A_DIM, at);       /* the header of the calls table */
				return;
			}
			if (is_func || is_head || is_asideh || (n == 6u && !memcmp(t, "calls:", 6)))
				ov_paint(b, e, A_DIM, at);
			else if (ov_is_hex8(t, n))
				ov_paint(b, e, A_ID, at);          /* a continuation row of the keys */
			else if (n > 2u && t[0] == '0' && t[1] == 'x')
				ov_paint(b, e, A_LOC, at);         /* an unreachable block's offset */
		} else if (is_func) {
			ov_paint(b, len, A_ID, at);                /* the function's name: it may hold spaces */
			return;
		} else if (is_asideh && tok == 1u) {
			ov_paint(b, e, A_DIM, at);                 /* "blocks:" of "unreachable blocks: N" */
		} else if (is_call && tok >= 2u && tok <= 1u + kind_toks + 1u) {
			/* `  B4  0x2a  call  0x10  name` or `... call indirect  -  name`: the offset and the target are places; the name is the rest of the row */
			if (tok == 2u && e - b == 4u && !memcmp(t, "call", 4) && i < len && !strncmp(row + i, "  indirect", 10))
				kind_toks = 2u;
			if (tok == 1u + kind_toks + 1u) {
				size_t n = i;

				if (e - b > 2u && t[0] == '0' && t[1] == 'x')
					ov_paint(b, e, A_LOC, at);
				while (n < len && row[n] == ' ')
					n++;
				if (n < len)
					ov_paint(n, len, A_ID, at);
				return;
			}
		} else if (eq && eq > t) {
			ov_paint(b, (size_t)(eq - row) + 1u, A_DIM, at);
			if ((size_t)(eq - t) == 6u && !memcmp(t, "status", 6))
				ov_paint((size_t)(eq - row) + 1u, e, A_WARN, at);
		} else if (e - b > 2u && t[0] == '0' && t[1] == 'x') {
			ov_paint(b, e, A_LOC, at);
		} else if (ov_is_hex8(t, e - b)) {
			ov_paint(b, e, A_ID, at);
		}
		tok++;
	}
}

const char *kv_cfgbody_text_attr(const char *row, size_t at)
{
	const char *a[OV_ROW_MAX];

	if (!row || strlen(row) >= OV_ROW_MAX || at >= strlen(row))
		return NULL;
	ov_attrs(row, a);
	return a[at];
}

/* A window of an Overview row from column `hoff`, `n` columns, with the escapes of the attributes above; one A_OFF closes a coloured run. */
static void ov_window(const char *row, uint32_t hoff, uint32_t n, char *out, size_t cap)
{
	const char *a[OV_ROW_MAX], *cur = NULL;
	const size_t len = strlen(row);
	size_t w = 0, i;

	if (len >= OV_ROW_MAX) {
		snprintf(out, cap, "%.*s", (int)n, hoff < len ? row + hoff : "");
		return;
	}
	ov_attrs(row, a);
	for (i = hoff; i < len && i - hoff < n; i++) {
		const size_t room = cap - w;

		if (a[i] != cur) {
			if (cur && room > sizeof A_OFF + 8u)
				w += (size_t)snprintf(out + w, cap - w, "%s", A_OFF);
			if (a[i] && cap - w > 16u)
				w += (size_t)snprintf(out + w, cap - w, "%s", a[i]);
			cur = a[i];
		}
		if (cap - w < sizeof A_OFF + 2u)
			break;
		out[w++] = row[i];
	}
	if (cur && cap - w > sizeof A_OFF)
		w += (size_t)snprintf(out + w, cap - w, "%s", A_OFF);
	out[w] = 0;
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
		if (row < u->n_ol)
			ov_window(u->ol[row], hoff, ncols - 1u, out + 1, cap - 1u);
		return;
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
