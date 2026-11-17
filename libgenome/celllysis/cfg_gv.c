/*
 * cfg_gv.c - the THIN FILLER of the generic graph view (gview.h) for the control-flow graph of one function: reachable blocks -> nodes, successors
 * -> edges with their kind and letter, unreachable blocks -> the aside, the signature -> head lines. Every place in the drawing is the viewer's
 * (kofexamine/kv_graph.c); what is here is words and kinds. A lineage filler is this file with other nodes and other kinds.
 */
#include <stdio.h>
#include <string.h>

#include "cfg_private.h"
#include "gview.h"

static const char *term_name(unsigned t)
{
	switch (t) {
	case KGENOME_CFG_T_FALL: return "FALL";
	case KGENOME_CFG_T_COND: return "COND";
	case KGENOME_CFG_T_JUMP: return "JUMP";
	default: return "EXIT";
	}
}

#define KEYS_PER_ROW 6u

static void head_lines(struct kgenome_gv *gv, const struct kgenome_cfg_gv_req *r)
{
	const struct kgenome_cfg_view *v = r->v;
	uint32_t nk = v->n_key, shown = r->max_keys ? r->max_keys : 16u, i, j;
	unsigned t;

#define HL(...) do { if (gv->n_head < KGENOME_GV_HEAD_MAX) snprintf(gv->head[gv->n_head++], KGENOME_GV_HEAD_COLS, __VA_ARGS__); } while (0)
	for (t = 0; t < 2u; t++)
		if (r->title[t] && r->title[t][0])
			HL("%s", r->title[t]);
	/* The counts the list below repeats (unreachable, all) are not here, and the status is said only when it is not ok: a cut is reported (rule 4), a clean run is not a fact. */
	if (v->status == KGENOME_OK)
		HL("CFG  reachable=%u  edges=%u", (unsigned)v->n_blk, (unsigned)v->n_edge);
	else
		HL("CFG  reachable=%u  edges=%u  status=%s", (unsigned)v->n_blk, (unsigned)v->n_edge, kgenome_status_name(v->status));
	if (shown > KGENOME_CFG_KEYS)
		shown = KGENOME_CFG_KEYS;
	if (shown > nk)
		shown = nk;
	if (!nk)
		HL("keys   none");
	for (i = 0; i < shown; i += KEYS_PER_ROW) {
		char *p = gv->head[gv->n_head < KGENOME_GV_HEAD_MAX ? gv->n_head : KGENOME_GV_HEAD_MAX - 1u];
		const size_t cap = KGENOME_GV_HEAD_COLS;
		size_t w = (size_t)snprintf(p, cap, "%s", i ? "       " : "keys   ");

		for (j = i; j < shown && j < i + KEYS_PER_ROW; j++)
			w += (size_t)snprintf(p + w, cap - w, "%s%08x", j > i ? " " : "", (unsigned)v->key[j]);
		if (j == shown && shown < nk)
			snprintf(p + w, cap - w, " (+%u more)", (unsigned)(nk - shown));
		if (gv->n_head < KGENOME_GV_HEAD_MAX)
			gv->n_head++;
	}
#undef HL
}

enum kgenome_status kgenome_cfg_gv_make(const struct kgenome_cfg_gv_req *r, struct kgenome_gv *out)
{
	const struct kgenome_cfg_view *v;
	uint32_t i, k, ne = 0, e = 0;
	enum kgenome_status st;

	if (!out)
		return KGENOME_BAD_INPUT;
	memset(out, 0, sizeof *out);
	if (!r || !r->v || (r->v->n_blk && !r->v->blk) || (r->v->n_unr && !r->v->unr)) {
		out->status = KGENOME_BAD_INPUT;
		return out->status;
	}
	v = r->v;
	for (i = 0; i < v->n_blk; i++)
		ne += (uint32_t)(v->blk[i].succ[0] != KGENOME_CFG_NONE) + (uint32_t)(v->blk[i].succ[1] != KGENOME_CFG_NONE);
	st = kgenome_gv_alloc(out, &(const struct kgenome_gv_size){ .n_node = v->n_blk, .n_edge = ne, .n_xline = r->n_xline, .n_note = r->n_note,
					 .n_aside = v->n_unr }, r->budget, &r->mem);
	if (st != KGENOME_OK) {
		/* nothing to draw, but the head (the signature) is inline and still said, with the reason the graph is not there */
		out->id_prefix = 'B';
		out->status = kgenome_status_merge(v->status, st);
		head_lines(out, r);
		snprintf(out->head[out->n_head < KGENOME_GV_HEAD_MAX ? out->n_head : KGENOME_GV_HEAD_MAX - 1u], KGENOME_GV_HEAD_COLS, "graph not drawn: %s",
			 st == KGENOME_OVER_BUDGET ? "over budget" : "no memory");
		if (out->n_head < KGENOME_GV_HEAD_MAX)
			out->n_head++;
		return out->status;
	}
	out->id_prefix = 'B';
	out->status = v->status;
	snprintf(out->xnoun, sizeof out->xnoun, "calls");
	for (i = 0; i < v->n_blk; i++) {
		const struct kgenome_cfg_view_block *b = &v->blk[i];
		struct kgenome_gv_node *n = &out->node[i];

		n->off = b->off;
		n->ext = b->n_insn;
		n->label = b->label;
		n->kind = b->term;
		n->xtotal = b->n_call;
		/* a block's edges stand left to right: the fall-through first (the spine of the drawing follows it), then the taken side */
		for (k = 2u; k-- > 0;) {
			if (b->succ[k] == KGENOME_CFG_NONE)
				continue;
			out->edge[e].from = i;
			out->edge[e].to = b->succ[k];
			out->edge[e].cond = b->term == KGENOME_CFG_T_COND ? (uint8_t)(k ? KGENOME_GV_COND_F : KGENOME_GV_COND_T) : (uint8_t)KGENOME_GV_COND_NONE;
			e++;
		}
	}
	out->entry = 0;
	/* the loops are the engine's: a loop link is a back edge into a node that dominates its source */
	out->status = kgenome_status_merge(out->status, kgenome_gv_loops(out, r->budget, &r->mem));
	for (i = 0; i < v->n_blk; i++) {
		const struct kgenome_cfg_view_block *b = &v->blk[i];
		struct kgenome_gv_node *n = &out->node[i];

		snprintf(n->line[0], KGENOME_GV_LINE, "B%u%s 0x%llx n_insn=%u %s", (unsigned)i, (n->flags & KGENOME_GV_NF_LOOP_HEAD) ? " @" : "", (unsigned long long)b->off,
			 (unsigned)b->n_insn, term_name(b->term));
		snprintf(n->line[1], KGENOME_GV_LINE, "in=%u out=%u call=%u #%08x", (unsigned)b->in_deg, (unsigned)b->out_deg, (unsigned)b->n_call,
			 (unsigned)b->label);
	}
	for (i = 0; i < v->n_unr; i++) {
		out->aside[i].off = v->unr[i].off;
		out->aside[i].ext = v->unr[i].n_insn;
		snprintf(out->aside[i].text, sizeof out->aside[i].text, "0x%llx n_insn=%u", (unsigned long long)v->unr[i].off, (unsigned)v->unr[i].n_insn);
	}
	snprintf(out->aside_title, sizeof out->aside_title, "unreachable blocks: %u", (unsigned)v->n_unr);
	snprintf(out->aside_none, sizeof out->aside_none, "unreachable blocks: none");
	head_lines(out, r);
	return out->status;
}
