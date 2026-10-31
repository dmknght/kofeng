/*
 * kv_graph.h - THE GRAPH DRAWING of the viewer (kv_graph.c): boxes in ranks, edges routed between them, as text cells. Pure: no terminal, no
 * view, no global, and no engine type; the input is a neutral description of a graph and the output is GEOMETRY (boxes, edges as orthogonal
 * segments, the canvas) and the CELLS drawn from it.
 *
 * WHAT THIS IS AND IS NOT. The layout is presentation, not analysis: the viewer still computes no verdict, no hash and no graph content. The
 * nodes, the edges, their kinds and letters, every word in a box and every fact about the function are the engine's (struct kgenome_gv, filled by
 * the lib from the control-flow graph); this unit decides only WHERE a box and a line go, the way `dot` does for a hierarchy.
 *
 * THE STYLE (top-down, hierarchical, `dot`-like):
 *   - a RANK (layer) is the longest path from the entry over the forward edges; every forward edge points down;
 *   - the order inside a rank is a bounded number of barycenter sweeps (KV_GRAPH_SWEEPS), ties kept as they were, so the first edge of a node stands
 *     left of its later ones and the result is the same on every run;
 *   - the SPINE: the first forward edge of a node ends straight below it (a box that is the only child of its parent is placed under it, with a heavy
 *     weight in the least-squares placement), the later forward edges go to the right of it; a merge box is centred under the mean of its parents;
 *   - an edge leaves the BOTTOM of its source box and a forward edge arrives at the TOP of its target box with `v`; a long edge passes through a
 *     virtual node in every rank it crosses, so it never runs through a box;
 *   - THREE KINDS OF LINK, two independent properties of an edge (the engine's `cond` and `loop`):
 *       plain          solid line, no letter                      (cond none, loop none)
 *       conditional    solid line, the letter T or F at its tail   (cond T / F)
 *       loop link      a DOTTED line (`:` and `=` in plain ASCII), arrowhead `^`, on the LEFT lanes; it keeps its T / F letter when it is conditional
 *       retreating     an edge that goes back and is not a natural loop (irreducible flow): a third dotted style (`!` and `~`), arrowhead `^`, left lanes
 *     the line of a loop link leaves the bottom of its tail, runs down to a track, along a lane in the left margin (one lane per edge, shared by edges
 *     whose rank ranges do not overlap, the inner loop nearer the boxes) and comes back to a track below its HEAD and enters the head's bottom from
 *     below with `^`; a self-loop is a short hook under its box, out at one bottom port and back in at the next with `^`;
 *   - the letter of an edge stands in the cell right under its source box, on its first row;
 *   - a crossing of two lines is the four-way glyph (`+`), a corner is `'` / `.` (or the box-drawing corner): both are derived from the lines that
 *     meet in the cell, so a picture cannot show a junction that is not there. Edges that share a port (more edges at a side of a box than it has
 *     columns) are counted in n_share.
 * Every segment of the geometry carries its edge's cond and loop, and every cell the same, so a viewer may colour (T green, F red) or style by them; this
 * unit paints nothing itself.
 *
 * BOUNDS ARE THE CALLER'S AND NOTHING IS DROPPED SILENTLY (CLAUDE.md rule 4). At most max_node boxes (the first ones in reverse post-order, which is
 * closed under forward predecessors), at most max_cols x max_rows cells; when the drawing does not fit the prefix is shortened (a bounded number of
 * times) and the rest is COUNTED: n_not_drawn, n_edge_not_drawn, and the first KV_GRAPH_REST ids of what was not drawn in walk order. A cap of
 * virtual nodes (KV_GRAPH_MAX_DUMMY) and of drawn edges (KV_GRAPH_MAX_EDGE) is a DoS bound: an edge past it is not drawn and counted. The walk, the
 * levels and the choice of the prefix are linear in the nodes and edges (200000 nodes cost the walk and nothing else); the sweeps are bounded
 * work over the DRAWN part only.
 */
#ifndef KV_GRAPH_H
#define KV_GRAPH_H

#include <stddef.h>
#include <stdint.h>

#define KV_GRAPH_MAX_NODE 400u          /* boxes drawn when the caller names no other */
#define KV_GRAPH_MAX_EDGE 4096u         /* edges drawn */
#define KV_GRAPH_MAX_DUMMY 8192u        /* virtual nodes (one per rank an edge crosses) */
#define KV_GRAPH_MAX_LANE 48u           /* lanes of the left margin */
#define KV_GRAPH_SWEEPS 4u              /* barycenter rounds (one down and one up pass each), and placement rounds */
#define KV_GRAPH_LINE_MAX 44u           /* columns of one line of a box; a longer line ends in `~` */
#define KV_GRAPH_BOX_LINES 12u          /* lines of a box; a box with more is cut and counted in n_line_cut */
#define KV_GRAPH_REST 64u               /* ids of the nodes that were not drawn that are kept */
#define KV_GRAPH_COLS_DEF 4096u
#define KV_GRAPH_ROWS_DEF 4096u
/* why an edge is not drawn */
#define KV_GW_END 1u            /* an end is a node that is not drawn */
#define KV_GW_CAP 2u            /* past the edge cap or the virtual-node cap */
#define KV_GW_LANE 3u           /* no lane left for it */
#define KV_GRAPH_CELLS_MAX (4u << 20)   /* cells of the canvas, whatever max_cols and max_rows say (4 bytes each) */

/* The two properties of an edge, as the engine states them (kgenome_gv_cond, kgenome_gv_loop: the same values). */
enum kv_graph_cond { KV_GC_NONE = 0, KV_GC_T, KV_GC_F };
enum kv_graph_loop { KV_GL_NONE = 0, KV_GL_LOOP, KV_GL_RETREAT };

enum kv_graph_status { KV_GS_OK = 0, KV_GS_TRUNCATED, KV_GS_BAD_INPUT, KV_GS_NOMEM };

struct kv_graph_edge {
	uint32_t from, to;              /* node indices; the edges are sorted by `from`, a node's edges in the order they should stand left to right */
	uint8_t  cond;                  /* enum kv_graph_cond: T and F are drawn as a letter under the source box, none draws none */
	uint8_t  loop;                  /* enum kv_graph_loop: a loop link or a retreating edge is a back edge (never walked forward); none may still turn out to go back, and is then drawn as retreating */
};

struct kv_graph_in {
	uint32_t n_node, entry;
	uint32_t n_edge;
	const struct kv_graph_edge *edge;
	/* Line `i` of the box of `node`, NULL after the last. The text is read while the graph is made and not kept. */
	const char *(*text)(void *user, uint32_t node, uint32_t i);
	void *user;
	/* OPTIONAL: a mark of a part of a box, for a viewer that colours it: the border of `node` when `line` is -1, else its text line `line`. 0 is none, 1..KV_GRAPH_MARKS-1 is the
	 * viewer's own slot (the engine's data it stands for is the viewer's to say); the layout keeps it on the cells and decides nothing by it. NULL: no marks. */
	uint8_t (*mark)(void *user, uint32_t node, int32_t line);
	uint32_t max_node;              /* 0 = KV_GRAPH_MAX_NODE */
	uint32_t max_cols, max_rows;    /* the canvas; 0 = KV_GRAPH_COLS_DEF / KV_GRAPH_ROWS_DEF */
};

struct kv_graph_box {
	uint32_t node;
	int32_t  x, y;                  /* top-left cell of the box (its border) */
	uint32_t w, h;                  /* with the border */
	uint32_t rank;
};

struct kv_graph_seg {
	int32_t x0, y0, x1, y1;         /* a horizontal or a vertical run of cells, in the order of travel (source to target), both ends included */
};

struct kv_graph_wire {
	uint32_t edge;                  /* index into the input's edges */
	uint32_t seg0, n_seg;           /* its segments, in order of travel; consecutive segments share their corner cell */
	uint8_t  cond, loop;            /* as given, loop = RETREAT for an edge the walk found going back that the input did not call a loop */
	uint8_t  back;                  /* routed through a lane (or a hook): leaves the tail's bottom, enters the head's bottom from below */
	char     letter;                /* 'T', 'F' or 0 */
	char     arrow;                 /* `v` (a forward edge enters the top of its target), `^` (a back edge enters the bottom of its head) */
	int32_t  lx, ly;                /* the cell of the letter (ly < 0: none) */
	int32_t  ax, ay;                /* the cell of the arrowhead */
};

/* one cell of the canvas */
struct kv_graph_cell {
	uint8_t g;                      /* enum kv_graph_glyph */
	uint8_t mask;                   /* for a line: the sides it connects to (KV_GM_*) */
	uint8_t kind;                   /* the edge drawn here: 1 + loop * 3 + cond (kv_graph_cell_attr); a box's border or text cell: KV_GRAPH_MARK0 - 1 + its mark (kv_graph_in.mark), else 0 */
	char    ch;                     /* a letter, an arrowhead or a character of a box's text */
};

enum kv_graph_glyph { KV_GG_EMPTY = 0, KV_GG_TEXT, KV_GG_BTL, KV_GG_BTR, KV_GG_BBL, KV_GG_BBR, KV_GG_BH, KV_GG_BV, KV_GG_LINE, KV_GG_ARROW, KV_GG_LABEL };
#define KV_GM_N 1u
#define KV_GM_E 2u
#define KV_GM_S 4u
#define KV_GM_W 8u

struct kv_graph {
	enum kv_graph_status status;    /* TRUNCATED when a bound fired (and the numbers below say which) */
	uint32_t n_node;                /* nodes in the input */
	uint32_t n_box;                 /* boxes drawn (n_drawn) */
	struct kv_graph_box *box;
	uint32_t n_wire;
	struct kv_graph_wire *wire;
	uint32_t n_seg;
	struct kv_graph_seg *seg;
	uint32_t width, height;         /* the canvas */
	struct kv_graph_cell *cell;     /* width * height, row by row */
	uint32_t n_not_drawn;           /* nodes that did not fit */
	uint32_t n_edge_not_drawn;      /* edges with an end that was not drawn, or past the edge or virtual-node cap, or with no lane left */
	uint32_t n_skipped;             /* entries of skip[] */
	struct { uint32_t edge; uint8_t why; } skip[KV_GRAPH_REST];   /* the first edges that are not drawn, in the order of the walk, and why (KV_GW_*) */
	uint32_t n_rest;                /* ids in rest[] (at most KV_GRAPH_REST) */
	uint32_t rest[KV_GRAPH_REST];   /* the first nodes that were not drawn, in the order of the walk */
	uint32_t n_rank, n_dummy, n_lane, n_share, n_line_cut, n_shrunk;
	void    *mem_;                  /* private */
};

/* Lay the graph out and draw its cells. `g` is zeroed first and always safe to free. Returns g->status. */
enum kv_graph_status kv_graph_layout(const struct kv_graph_in *in, struct kv_graph *g);
void kv_graph_free(struct kv_graph *g);

/* ---- drawing a window of the canvas ---- */

#define KV_GRAPH_MARK0 10u              /* the first attribute slot of a box mark: mark m (1..) is slot KV_GRAPH_MARK0 - 1 + m */
#define KV_GRAPH_MARKS 7u               /* marks 0 (none) .. 6 */
#define KV_GRAPH_KINDS (KV_GRAPH_MARK0 + KV_GRAPH_MARKS - 1u)   /* attribute slots: 0 none, 1 + loop * 3 + cond for the nine (loop, cond) pairs, then the box marks (kv_graph_cell_attr) */
struct kv_graph_style {
	int ascii;                      /* 1: the plain set (`|` `-` `+` `'` `.`); 0: box drawing for lines and the viewer's own glyphs for boxes */
	const char *attr[KV_GRAPH_KINDS]; /* a string written before the run of cells of a kind (NULL: none); index = kv_graph_cell_attr() */
	const char *off;                /* written when a run of coloured cells ends (NULL: nothing) */
};
/* The style the viewer uses: box drawing unless the build is KOFVIEW_ASCII_BOX; no attributes. */
struct kv_graph_style kv_graph_style_default(void);
/* The index into style.attr of a cell: 0 for a box, its text or an empty cell, else 1 + loop * 3 + cond of the edge drawn there. */
unsigned kv_graph_cell_attr(const struct kv_graph_cell *c);

/* Row `row` of the canvas from column `x0`, `ncols` columns wide, written to `out` (NUL-ended, at most `cap` bytes): cells past the canvas are
 * blanks and a row past it is all blanks. Returns the bytes written. The text is exactly `ncols` columns. */
size_t kv_graph_window(const struct kv_graph *g, uint32_t row, uint32_t x0, uint32_t ncols, const struct kv_graph_style *st, char *out, size_t cap);

#endif /* KV_GRAPH_H */
