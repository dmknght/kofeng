/*
 * cfgsign.h - THE CFG SIGNATURE OF ONE FUNCTION: decode (once) -> graph -> signature -> floor. The ONE function (kof_cfgsign_function)
 * that the scanner's feed, the viewer's table and the CFG dialog all call; none of them decodes a function for a graph by itself.
 *
 * WHAT IT DECIDES AND WHAT IT DOES NOT. It makes the signature the lib defines (cfg.h) for a function of the object and says whether
 * it counts: SIGNED (the function is of a code region and has a reachable block: the floor of 12 blocks is gone, owner 2026-11-01), BELOW_FLOOR (a graph
 * was made and no block is reachable, or the caller asked for a higher `floor`: the unit stays listed and unsigned), UNDECODABLE, UNSUPPORTED (no rule table for the architecture),
 * OVER_BUDGET (the lib's allowance for one call: the function holds more instructions or blocks than it may) and NOMEM. Each is a
 * per-function REASON a viewer prints; none is silent. Which functions are offered at all is the CUT's decision (kgenome_mutation_units:
 * the library's functions are not units), not this function's: every unit it is asked about is signed. Big-endian objects are read in their own byte order (kgenome_diag_code_run).
 *
 * COST. A call decodes `len` bytes once and builds the graph once. There is no work allowance of its own (the cost is measured, not
 * capped); memory goes through the host's allocator, which charges the scan's ledger as every other allocation, and is released before
 * the call returns unless the caller asked to KEEP the graph (the viewer), then kof_cfgsign_release gives it back.
 */
#ifndef KOFENG_CFGSIGN_H
#define KOFENG_CFGSIGN_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include <genotype/image/funcs.h>
#include <celllysis/cfg.h>

enum kof_cfgsign_state {
	KOF_CFGSIGN_SIGNED = 0,
	KOF_CFGSIGN_BELOW_FLOOR,        /* fewer reachable blocks than the floor (default one: no reachable block) */
	KOF_CFGSIGN_UNDECODABLE,        /* the extent is not in the object, or no instruction decodes there */
	KOF_CFGSIGN_UNSUPPORTED,        /* no control-flow rules for the architecture */
	KOF_CFGSIGN_OVER_BUDGET,        /* the lib's allowance for one call (kgenome_budget.max_bytes) is not enough for this function */
	KOF_CFGSIGN_NOMEM
};

/* The words a viewer prints for a state (the reason of an unsigned unit). */
const char *kof_cfgsign_state_name(enum kof_cfgsign_state s);

/*
 * THE CALLER'S LEDGER: the allocator that charges the scan's memory (NULL: malloc), and what one call may hold (0 = 64 MiB, the CFG view's
 * allowance). Nothing else: there is no work allowance.
 */
struct kof_cfgsign_host {
	struct kgenome_cfg_mem mem;
	uint64_t max_bytes;
};

struct kof_cfgsign_req {
	const struct kof_obj_ctx *ctx;  /* the object: architecture, parsed header (byte order, address map) */
	kof_buf data;                   /* the object's bytes */
	uint64_t off, len;              /* the function: file offset and size */
	uint32_t floor;                 /* reachable blocks needed to be SIGNED; 0 = KGENOME_CFG_ANCHOR_MIN (one) */
	int      keep;                  /* 1: hand back the instructions, the graph and the labels (kof_cfgsign_release) */
	const struct kof_cfgsign_host *host;    /* may be NULL */
};

struct kof_cfgsign {
	enum kof_cfgsign_state state;
	enum kgenome_status    status;          /* the worst status of decode, graph and signature */
	struct kgenome_cfg_sign sign;           /* valid when a graph was made: state SIGNED or BELOW_FLOOR */
	uint32_t n_insn;                        /* instructions decoded */
	uint64_t n_skip;                        /* bytes that decoded as nothing */
	int      be;                            /* the object's code byte order */
	int      mapped;                        /* the address map was used */
	uint64_t func_va;
	/* kept when `keep` was asked: */
	struct kgenome_cell_insn *in;
	struct kgenome_cfg g;
	uint64_t *label;                        /* g.n_all entries */
	size_t   in_bytes_, label_bytes_;       /* private */
};

/* Sign the function [off, off + len). `out` is zeroed first and is always safe to release. Returns out->state. */
enum kof_cfgsign_state kof_cfgsign_function(const struct kof_cfgsign_req *rq, struct kof_cfgsign *out);
void kof_cfgsign_release(struct kof_cfgsign *r, const struct kgenome_cfg_mem *mem);

#endif /* KOFENG_CFGSIGN_H */
