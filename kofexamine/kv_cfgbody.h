/*
 * kv_cfgbody.h - the BODY of the CFG dialog (kv_cfgbody.c): the engine's answer for one function (kof_cfgview), as the rows of two of its three tabs - the Overview (the
 * engine's facts - the CFG hash among them, called Scaffold in the docs - and the calls as a table) and the Graph (the engine's graph laid out and drawn by kv_graph*.c). The third tab, Disasm, is the panel's own rows of the
 * function (kv_disasm.c, dis_func_rows) and needs a view, so the dialog (kv_cfgdlg.c) holds it. No screen, no view, no global: the dialog asks for rows, and so do the tests.
 */
#ifndef KV_CFGBODY_H
#define KV_CFGBODY_H

#include "kv_graph.h"
#include "../libkofeng/analyzers/cfgview.h"

/* The tabs of the dialog, in the order of the strip. */
enum kv_cfg_tab { KV_CFG_TAB_OVERVIEW = 0, KV_CFG_TAB_DISASM, KV_CFG_TAB_GRAPH, KV_CFG_TABS };

struct kv_cfg_body {
	struct kof_cfgview cf;          /* the engine's answer; its graph (cf.gv) and its facts text (cf.text, cut into lines in place) */
	struct kv_graph g;              /* the drawing of cf.gv */
	char **fl;                      /* the facts text, one line each (pointers into cf.text); the first n_head are the head */
	uint32_t n_fl;
	char **xl;                      /* what the drawing left out: nodes and edges not drawn, one line each (owned strings) */
	uint32_t n_xl;
	char **ol;                      /* the rows of the Overview: the head, the calls table, the unreachable blocks (owned strings) */
	uint32_t n_ol, ol_col;
	uint32_t n_head;                /* the first n_head rows of ol are the engine's head lines (the facts, or the one sentence of why there is no graph) */
	uint32_t n_row, n_col;          /* rows of the Graph and the widest of them */
	uint32_t tab;                   /* the tab kv_cfgbody_row answers for: KV_CFG_TAB_OVERVIEW or KV_CFG_TAB_GRAPH (set by the caller before it asks) */
	char scratch[64];               /* the text of a box row that is made on the spot (`+N more calls`) */
};

/*
 * THE COLOURS OF THE GRAPH TAB, each chosen from what the engine's graph (struct kgenome_gv) already says, with the viewer's own palette (kofview.h):
 *   an edge, by its cond and loop:  T green (A_SIZE), F red (A_BAD); an unconditional loop link yellow (A_WARN), an unconditional retreating edge magenta (A_HEUR), any other
 *                                   unconditional edge in the terminal's own colour. A colour per KIND, never per edge, so a crossing stays readable; the loop kinds are also
 *                                   told by their dotted glyphs.
 *   the entry node's border         cyan (A_LOC)
 *   a loop head's first row         yellow (A_WARN): the node flag KGENOME_GV_NF_LOOP_HEAD
 *   the call rows of a block        blue (A_ID): the rows past the first two, which the engine fills for a node that holds calls (xtotal)
 * The viewer computes none of it.
 */
enum kv_cfg_mark { KV_CFG_MK_NONE = 0, KV_CFG_MK_ENTRY, KV_CFG_MK_LOOP_HEAD, KV_CFG_MK_CALL };
/* The attribute of an edge of kind (cond, loop) as the engine's enums (kgenome_gv_cond, kgenome_gv_loop), or NULL for none. */
const char *kv_cfgbody_edge_attr(unsigned cond, unsigned loop);
/* The attribute of a box mark (enum kv_cfg_mark), or NULL. */
const char *kv_cfgbody_mark_attr(unsigned mark);
/* The style the Graph tab draws with: the glyph set of kv_graph_style_default and the attributes above. */
struct kv_graph_style kv_cfgbody_style(void);

/*
 * THE COLOURS OF THE OVERVIEW: the attribute of the character `at` of one Overview row (the engine's plain line, as the viewer knows its label), or NULL for the terminal's own.
 * A label is dim (A_DIM); a value takes the colour its kind has in the Properties dialog and the Blocks table: a name and the unit id and the keys A_ID, an offset or an
 * address A_LOC, a status that is not ok A_WARN; a number is plain. Nothing is derived: the class is the word's spelling and its row's first word.
 */
const char *kv_cfgbody_text_attr(const char *row, size_t at);

/* Ask the engine for the function in `rq` and make the rows. Always safe to free; a function the engine could not make a graph of has its sentence as the facts. */
void kv_cfgbody_make(struct kv_cfg_body *b, const struct kof_cfgview_req *rq);
void kv_cfgbody_free(struct kv_cfg_body *b);
/* The size of a tab's body: rows, and the widest row in columns (without the margin column). */
void kv_cfgbody_size(const struct kv_cfg_body *b, unsigned tab, uint32_t *n_row, uint32_t *n_col);
/* Row `row` of tab `b->tab` from column `hoff`, `ncols` columns wide, as the dialog draws it: a margin column, then the text or the cells of the drawing (plain set: no escapes). */
void kv_cfgbody_row(const void *body, uint32_t row, uint32_t hoff, uint32_t ncols, char *out, size_t cap);

#endif /* KV_CFGBODY_H */
