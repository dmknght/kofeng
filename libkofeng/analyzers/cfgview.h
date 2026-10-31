/*
 * cfgview.h - THE CONTROL-FLOW GRAPH OF ONE FUNCTION, ON REQUEST: what a tool shows when a person asks "what is the shape of this function".
 *
 * ON REQUEST, NOT IN A SCAN (like kof_codenotes_build and kof_callnames_build): a scan never builds it. It is built at the ask, from the
 * function's bytes, in well under a millisecond for a small function (tests/unit/cfg_view_api.c prints the figures); nothing is cached here, a
 * caller that asks again for the same function pays again, and a caller that wants it kept keeps `struct kof_cfgview`.
 *
 * ONE DECODE, THE ENGINE'S: the instructions are read by kgenome_diag_code_run (the reader every walk of the code shares), once, with the
 * object's own byte order, and handed to kgenome_cfg_build / kgenome_cfg_sign / kgenome_cfg_anchor / kgenome_cfg_view_make /
 * kgenome_cfg_gv_make. This unit decides nothing about a graph; it asks the lib and names what the lib found with what the engine
 * knows (the function table, the symbol block, the call-name table).
 *
 * THE EXTENT IS THE CALLER'S: `func_off`/`func_len` are one entry of the object's function table (the row's FIRST function: a unit that
 * groups several small functions is drawn by the one the signature would be about). An extent that is not an entry of `funcs`, or that
 * leaves the object, is BAD_INPUT: this unit does not look for boundaries.
 *
 * NAMES ARE NOT EVIDENCE. A callee's name here is what the object's own tables say (a symbol, `rand@plt`, `fcn_<offset>` for a function
 * nothing names, kof_func_name); a stripped or re-linked build changes every one of them, which is why the structural signature reads none. The text says so.
 *
 * STATUS, as the lib's own values, the worst of the decode, the graph, the signature, the view and the text: TRUNCATED (the decode stopped
 * before the extent's end, or a bound of the drawing fired), OVER_BUDGET (`max_bytes` was not enough: no graph is claimed), BAD_INPUT,
 * UNSUPPORTED (an architecture the cfg table has no row for), NOMEM. A cap bounds COST and is always said: in `status` and in the text.
 */
#ifndef KOFENG_CFGVIEW_H
#define KOFENG_CFGVIEW_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include <genotype/image/funcs.h>
#include <phenotype/callnames.h>
#include <celllysis/cfg.h>
#include <celllysis/gview.h>

#define KOF_CFGVIEW_NAME 64u
#define KOF_CFGVIEW_MAX_BYTES (64ull << 20)     /* the allowance when the caller names none: ~560000 instructions (120 bytes each) */
#define KOF_CFGVIEW_CALL_LINES 24u      /* calls listed in the text; the table holds every one */
#define KOF_CFGVIEW_NOTES 48u           /* call notes the graph holds text for (the rest are counted in note_total) */
#define KOF_CFGVIEW_XLINES 1024u        /* call lines the boxes of the graph hold in all (a block's first KGENOME_GV_BOX_X calls); the names are read for as many calls */
#define KOF_CFGVIEW_ASIDE_LINES 8u      /* unreachable blocks listed in the facts text */

struct kof_cfgview_req {
	const struct kof_obj_ctx *ctx;          /* the object: format, architecture, parsed header (byte order, address map) */
	kof_buf data;                           /* the object's bytes */
	uint64_t func_off, func_len;            /* the function: a file offset and its size */
	const struct kgenome_func_set *funcs;   /* the object's functions: the extent must be one of them; NULL = not checked */
	const uint8_t *sym;                     /* the symbol block, for names (may be NULL) */
	uint32_t sym_n;
	const struct kgenome_callnames *names;  /* optional: the import table, for `rand@plt` */
	uint32_t anchor_min;                    /* 0 = KGENOME_CFG_ANCHOR_MIN */
	uint64_t max_bytes;                     /* what the decode and each lib call may hold; 0 = KOF_CFGVIEW_MAX_BYTES */
};

/* One call or system call of a reachable block, in instruction order. */
struct kof_cfgview_call {
	uint32_t blk;                           /* index into view.blk */
	uint8_t  kind;                          /* enum kgenome_cfg_call_kind */
	uint64_t at;                            /* file offset of the instruction */
	uint64_t target;                        /* file offset of a direct target, KGENOME_BROKEN when there is none */
	char     name[KOF_CFGVIEW_NAME];        /* the object's name for it, "" for none: an untrusted label */
};

struct kof_cfgview {
	enum kgenome_status status;
	uint8_t  arch;
	int      be;                            /* the byte order the code was decoded in */
	int      mapped;                        /* the object's address map was used (else an address is the file offset) */
	uint64_t func_off, func_len, func_va;
	uint32_t n_insn;                        /* instructions decoded, once */
	uint64_t n_skip;                        /* bytes that decoded as nothing and were stepped over: not 0 means the status is TRUNCATED */
	/* the lib's answer on the same bytes */
	struct kgenome_cfg_view view;           /* reachable blocks, unreachable list, canon, keys, n_edge, status */
	uint32_t n_all;                         /* every block of the function (view.n_blk + view.n_unr) */
	uint32_t n_site, n_sys;
	uint32_t anchor_min;
	int      anchor_pass;                   /* reachable blocks >= anchor_min */
	/* what the graph holds of calls: counts are exact, the table has every one, names are filled for the first KOF_CFGVIEW_CALL_LINES * 2 */
	struct kof_cfgview_call *call;
	uint32_t n_call;
	char     name[KOF_CFGVIEW_NAME];        /* the function's name: its symbol, or `fcn_<offset>` (kof_func_name) */
	/* THE GRAPH the viewer draws (nodes, edges, the calls as notes and as the extra lines of the boxes, the head); the places are the viewer's */
	struct kgenome_gv gv;
	/* THE FACTS the dialog lists: the head (the function's own lines, the counts, the hashes, the anchor), the calls, the unreachable blocks, one line each,
	 * NUL-ended, owned. The first `n_top` lines stand above the drawing, the others below it. A failure has one line saying why (n_top 0). */
	char    *text;
	size_t   text_len;
	uint32_t n_lines, n_top;
};

/*
 * Build. Returns 1 when `out->view` holds a graph (possibly TRUNCATED), 0 when no graph was made (`out->status` says why and `out->text` says it too).
 * `out` is zeroed first: always safe to free. Memory comes from malloc and is bounded by `max_bytes` for each stage.
 */
int kof_cfgview_build(const struct kof_cfgview_req *rq, struct kof_cfgview *out);
void kof_cfgview_free(struct kof_cfgview *v);

#endif /* KOFENG_CFGVIEW_H */
