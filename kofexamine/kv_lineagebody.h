/*
 * kv_lineagebody.h - the BODY of the Lineage tab of the CFG dialog (kv_lineagebody.c): the
 * function's slice of the object's value-flow graph (kof_lineageview_build), laid out and
 * drawn by kv_graph*.c - the same drawing module the Graph tab uses, over a different graph.
 *
 * TWO PANES (owner, 2026-11-14): the top one is the drawing, scrolled on its own; under a rule,
 * the bottom one is the TABLE OF THE LINKS (the engine's rows, gv.note[]), one tick box each,
 * scrolled on its own. A press on a box ticks the link and its edge is lit in the drawing; a
 * press again puts it out. Nothing else: no key. The counts the engine says of the graph (its
 * head) are the Overview's (kv_cfgdlg.c), not this tab's.
 * No screen, no view, no global: the dialog asks for rows, same shape as kv_cfgbody.h.
 */
#ifndef KV_LINEAGEBODY_H
#define KV_LINEAGEBODY_H

#include "kv_graph.h"
#include "../libkofeng/analyzers/lineageview.h"

struct kv_lineage_body {
	struct kgenome_gv gv;            /* the engine's answer: this function's nodes, every link (edges) and one row per link (notes) */
	struct kv_graph   g;             /* the drawing of gv */
	char            **xl;            /* what the drawing left out: one line each (owned strings), under the drawing in the top pane */
	uint32_t          n_xl;
	uint8_t          *tick;          /* one per link row: ticked by a press */
	uint8_t          *lit;           /* one per edge: the drawing lights it (kv_graph_style.lit) - an edge of a ticked row */
	uint32_t          room;          /* the body rows the dialog has (set by kv_lineagebody_size, each frame) */
	uint32_t          top;           /* the rows of the top pane in that room; the rule is the next row, the table the rest */
	uint32_t          g_off, g_hoff, t_off, t_hoff;    /* each pane's own scroll: down and sideways */
	char              scratch[64];   /* the text of a box row made on the spot (kgenome_gv_box_line's buffer) */
};

/* Ask the engine for the function's slice (rq: kof_lineageview_req, the object's kof_result.lineage and lineage_in kept whole)
 * and lay it out. Always safe to free. */
void kv_lineagebody_make(struct kv_lineage_body *b, const struct kof_lineageview_req *rq);
void kv_lineagebody_free(struct kv_lineage_body *b);
/* The body in a room of `room` rows: it fills them all (n_row = room, the panes scroll themselves; n_col: the box's own width is enough). */
void kv_lineagebody_size(struct kv_lineage_body *b, uint32_t room, uint32_t *n_row, uint32_t *n_col);
/* Row `row` of the room, `ncols` wide (hoff is the panes' own): a margin column, then the drawing, the rule or a link row. */
void kv_lineagebody_row(const void *body, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap);
/* The wheel over row `row` of the room: the pane under it scrolls (down / up; sideways when `side`). */
void kv_lineagebody_wheel(struct kv_lineage_body *b, uint32_t row, int up, int side);
/* A press at row `row`, column `col` of the room (the margin column is 0): on the tick box of a link row it ticks or puts out that link. 1: it did. */
int kv_lineagebody_press(struct kv_lineage_body *b, uint32_t row, int col);

#endif /* KV_LINEAGEBODY_H */
