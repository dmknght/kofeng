/*
 * gview.h - A GRAPH TO LOOK AT: the one DATA type a viewer's graph dialog is drawn from. Public part header of kgenome (celllysis/): cfg_gv.c is
 * the thin filler for the control-flow graph of one function (cfg.h).
 *
 * WHY A GENERIC TYPE. The control-flow graph of a function is the first thing a researcher looks at to CHOOSE what a rule is made of; the
 * lineage graph (the sites of a program and the links between them) is the next, and the two must not need two data types (CLAUDE.md rule 2). So
 * the type knows nothing of a function or of a link: it holds NODES, EDGES, NOTES, ASIDE entries and a HEAD, and the filler of each kind says what
 * they are. A node is a box of two text rows and a few more lines the filler composed; an edge carries its two kind properties (cond and loop, below: a
 * lineage's MUST / MAY would be a cond of their own); a note is one line of annotation about a node; the head is
 * the lines of facts about the whole graph (a title, hashes, a status, the anchor's numbers); an aside is what the graph holds and does not draw (the
 * CFG's unreachable blocks). The filler decides the words.
 *
 * WHERE THE PLACES ARE DECIDED. Not here. Where a box and a line go is presentation, and the viewer's own drawing module (kofexamine/kv_graph.c)
 * lays it out from these nodes and edges; this unit has no layout and no text renderer. The edges are sorted by `from` (a node's edges in the order
 * they should stand left to right), which is all the viewer asks of them.
 *
 * WHERE A LINEAGE FILLER PLUGS IN (not written here): nodes = the sites (kgenome_lineage_* product: its node array, `at` for the offset), edges =
 * the links in the order each node lists them, the kind its state (MUST, MAY, none), status = the lineage's own three states carried in `status` and
 * in a head line, notes = what the node reads or writes. It fills `struct kgenome_gv`; the dialog and the engine's API shape (a request, a graph, a
 * status, caller-owned memory) are the CFG's.
 *
 * BOUNDS. The text of one row is at most KGENOME_GV_LINE - 1 characters, the head KGENOME_GV_HEAD_MAX lines. What a filler holds fewer of than it has
 * is counted beside the array (`note_total`, a node's `xtotal`), never dropped silently.
 */
#ifndef KGENOME_GVIEW_H
#define KGENOME_GVIEW_H

#include <stddef.h>
#include <stdint.h>

#include "../kgenome_status.h"
#include "../kgenome_budget.h"
#include "cfg.h"

#define KGENOME_GV_LINE 60u             /* one row of a box: 58 columns and a terminator */
#define KGENOME_GV_NOTE 96u
#define KGENOME_GV_HEAD_MAX 20u
#define KGENOME_GV_HEAD_COLS 112u
#define KGENOME_GV_BOX_X 4u             /* extra lines of a box that kgenome_gv_box_line gives before it says how many it left out */

/*
 * The kind of an edge is TWO independent properties, so that the three kinds of link a researcher tells apart (an ordinary link, a conditional link T / F,
 * a loop link) and their combinations are all data and none is guessed by a viewer:
 *   cond  none     the link is unconditional: a jump, or the fall-through of a block that does not branch;
 *         T / F    a branch's taken / fall-through side;
 *   loop  none     a forward link;
 *         LOOP     a back edge whose target DOMINATES its source: a natural loop's link (the target is the loop head);
 *         RETREAT  a retreating edge that is not a natural loop (the target does not dominate the source: irreducible flow), or any retreating edge when
 *                  the dominators were not computed (a graph past KGENOME_GV_DOM_MAX nodes, or a work bound): the status says so.
 */
enum kgenome_gv_cond { KGENOME_GV_COND_NONE = 0, KGENOME_GV_COND_T, KGENOME_GV_COND_F };
enum kgenome_gv_loop { KGENOME_GV_LOOP_NONE = 0, KGENOME_GV_LOOP_LINK, KGENOME_GV_LOOP_RETREAT };
#define KGENOME_GV_NF_LOOP_HEAD 1u      /* node flag: the target of at least one loop link */
#define KGENOME_GV_DOM_MAX 200000u      /* nodes the dominators are computed for; the iterative algorithm is also bounded in passes and says so when cut */

struct kgenome_gv_node {
	uint64_t off;                   /* where it is (a file offset): the filler's own meaning, carried for a tool that wants the data */
	uint32_t ext;                   /* its extent in the filler's unit */
	uint32_t label;                 /* the filler's label of it (for the CFG: the low 32 bits of the block's WL label) */
	uint8_t  kind;                  /* the filler's class of node (for the CFG: enum kgenome_cfg_term) */
	uint8_t  flags;                 /* KGENOME_GV_NF_* */
	uint32_t xtotal;                /* the extra lines the filler has for it IN ALL (for the CFG: its calls); the array `xline` holds some of them */
	char     line[2][KGENOME_GV_LINE];      /* the first two rows of its box, composed by the filler */
};

struct kgenome_gv_edge {
	uint32_t from, to;              /* node indices */
	uint8_t  cond;                  /* enum kgenome_gv_cond */
	uint8_t  loop;                  /* enum kgenome_gv_loop */
};

/* One extra row of the box of `node` (the CFG: `call <name>`); the entries are sorted by node, a node's rows in the order they are drawn. */
struct kgenome_gv_xline {
	uint32_t node;
	char     text[KGENOME_GV_LINE];
};

struct kgenome_gv_note {
	uint32_t node;
	char     text[KGENOME_GV_NOTE];
};

struct kgenome_gv_aside {
	uint64_t off;
	uint32_t ext;
	char     text[48];              /* the whole line the aside entry is listed as */
};

struct kgenome_gv {
	char     id_prefix;             /* what a node's index is spelled with in the text lists: 'B' (block) for the CFG */
	uint32_t entry;                 /* the node the walk starts from */
	uint32_t n_node;
	struct kgenome_gv_node *node;
	uint32_t n_edge;                /* edges, sorted by `from` (a node's edges are together, in the order they were made) */
	struct kgenome_gv_edge *edge;
	uint32_t n_xline;
	struct kgenome_gv_xline *xline; /* sorted by node */
	uint32_t n_note;
	struct kgenome_gv_note *note;   /* in the order they are listed */
	uint32_t note_total;            /* notes the filler has IN ALL when it holds only the first n_note of them (0: n_note); the rest are counted, not listed */
	uint32_t n_aside;
	struct kgenome_gv_aside *aside;
	uint32_t n_head;                /* the head: lines above the drawing */
	char     head[KGENOME_GV_HEAD_MAX][KGENOME_GV_HEAD_COLS];
	char     note_title[KGENOME_GV_HEAD_COLS];      /* the line above the notes ("calls: 4 ...") */
	char     aside_title[KGENOME_GV_HEAD_COLS];     /* the line above the aside ("unreachable blocks ...: 3"); empty = none listed */
	char     xnoun[16];             /* what the extra lines are, for the box's `+N more <noun>` (the CFG: "calls") */
	char     aside_none[KGENOME_GV_HEAD_COLS];      /* the line that says there is none, when n_aside is 0 and the title is set (may be empty) */
	enum kgenome_status status;     /* the filler's: how complete the graph is (a viewer may add its own bounds beside it, never into it) */
	size_t   bytes_;                /* private: what kgenome_gv_free gives back */
};

/* Allocate the five arrays in ONE block through the caller's allocator (zeroed), set the counts and pointers, zero the rest. NOMEM or OVER_BUDGET: nothing is held. */
struct kgenome_gv_size {
	uint32_t n_node, n_edge, n_xline, n_note, n_aside;
};
enum kgenome_status kgenome_gv_alloc(struct kgenome_gv *gv, const struct kgenome_gv_size *size, const struct kgenome_budget *budget,
				     const struct kgenome_cfg_mem *mem);
void kgenome_gv_free(struct kgenome_gv *gv, const struct kgenome_cfg_mem *mem);

/*
 * Mark the loops of a graph (gview_loops.c): sets the `loop` of every edge and KGENOME_GV_NF_LOOP_HEAD of the targets of loop links, from `gv->entry` and the edges as
 * listed (sorted by `from`). OK, or TRUNCATED when the dominators were not computed in full (every retreating edge is then RETREAT and no head is marked), or
 * NOMEM / OVER_BUDGET / BAD_INPUT when nothing was marked (every edge keeps loop none: a viewer that walks the graph itself still finds the edges that go back).
 */
enum kgenome_status kgenome_gv_loops(struct kgenome_gv *gv, const struct kgenome_budget *budget, const struct kgenome_cfg_mem *mem);

/*
 * Row `i` of the box of `node`, NULL after the last: the two rows of the node, then at most KGENOME_GV_BOX_X of its extra lines, then one row that says
 * how many of its xtotal lines are not in the box (`+N more`) when there are any. The text is the node's own or is written to `buf`; it is valid until
 * the next call that uses the same `buf`. The one place that says what a box holds, so a viewer does not decide it.
 */
const char *kgenome_gv_box_line(const struct kgenome_gv *gv, uint32_t node, uint32_t i, char *buf, size_t cap);

#endif /* KGENOME_GVIEW_H */
