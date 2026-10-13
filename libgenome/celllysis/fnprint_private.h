/*
 * fnprint_private.h - what the parts of the fnprint family share: the token
 * form of one instruction, the per-function accumulator, and the one decision.
 */
#ifndef KGENOME_FNPRINT_PRIVATE_H
#define KGENOME_FNPRINT_PRIVATE_H

#include "fnprint.h"

/* The most tokens one instruction yields: its class word, and per operand a
 * shape word and a value word (three operands). Weak: one. */
#define KGENOME_FNPRINT_TOK_MAX 8u

struct kgenome_fnprint_tok {
	uint64_t s[KGENOME_FNPRINT_TOK_MAX];   /* strong */
	uint32_t ns;
	uint64_t w;                /* weak; 0 when the instruction is not hashed */
};

/*
 * WHERE A LOCAL BRANCH LANDS is a position in the program, not a byte offset: the same instructions
 * with a different alignment pad before a loop head (nopl vs nopw), with or without the ENDBR a
 * -fcf-protection build puts first, land on the same instruction at another byte offset. The
 * function keeps the padding it met (offset, bytes) and the targets of its local branches, and at
 * its end each target is counted in bytes of everything that is not padding. Scratch the pass reuses
 * for every function: it grows with the largest function, not with the object.
 */
struct kgenome_fnprint_pos {
	uint32_t *pad_at, *pad_cum;     /* a padding instruction starts at pad_at[i]; pad_cum[i] bytes of padding up to and including it */
	uint32_t n_pad, cap_pad;
	uint32_t *tgt;                  /* local branch targets, in the order of the branches */
	uint32_t n_tgt, cap_tgt;
	uint64_t charged;
	int      failed;                /* a growth was refused: targets are folded as byte offsets from then on */
};

/* One function being read: the accumulators and the counters the decision uses. */
struct kgenome_fnprint_acc {
	uint64_t fp, fw;
	uint32_t pend_bad;         /* undecodable bytes not yet mixed: trailing ones are padding */
	uint32_t n_insn, n_bad, n_call, n_branch, n_syscall, n_zero;
	uint8_t  last_op;          /* class of the last instruction hashed */
	uint8_t  has_ind;
};

/*
 * THE REGION. The one thing a pass in address order cannot know about a function
 * is who calls it: the callers of a static helper may come after it. For the
 * stretch of the object between the entry and the frontier - the program's code
 * and the runtime's start behind it - the pass therefore HOLDS the decided
 * records and their outgoing edges until the frontier is seen (or the walk
 * ends) and decides them together. What is held is bounded by the stretch, not
 * by the object, charged to the ledger, and when it does not fit the functions
 * are emitted with the layout rule alone and the stat says how many (n_region_over).
 */
struct kgenome_fnprint_rfn {
	struct kgenome_fnprint_fn f;
	uint32_t e0, ne;            /* its edges in the pool */
	uint8_t  reached;
};

struct kgenome_fnprint_reach {
	struct kgenome_fnprint_rfn *v;
	uint32_t n, cap, max;       /* max: the most records held at once */
	uint64_t *e;                /* file offsets: call/jump targets, addresses taken */
	uint32_t ne, ecap;
	uint32_t root_e0, root_ne;  /* main's edges when main itself is not held (it lies before the entry) */
	int      have_root;
	int      failed;            /* an allocation or the charge was refused: no closure for this walk */
	uint64_t charged;
};

/* The state of one pass: scalars only, and the region above. */
struct kgenome_fnprint_state {
	uint64_t main_off;         /* KGENOME_BROKEN: none */
	uint64_t entry_off;        /* start of the entry function; KGENOME_BROKEN: none */
	uint64_t lib0;             /* start of the function the entry stub calls last; KGENOME_BROKEN: none */
	uint32_t seeds;            /* library seeds seen after main */
	int      latched;
	uint64_t frontier;
	uint64_t prev_end;
	uint64_t prev_off;
	int      have_prev;
	uint64_t steps;
	/* the unit being built: scalars, not a list */
	int      run_open;
	uint64_t run_lo, run_hi;
	uint32_t run_side;
	int      stop;
	struct kgenome_fnprint_reach rc;
	struct kgenome_fnprint_pos pos;
	int      region;           /* the reachability rule applies to this walk */
};

/* Normalise one instruction. `rel_at` is its offset in the function, `len` the
 * function's length: a branch that lands inside is kept as the offset it lands
 * at; anything that leaves is a class (and `ext`, when the hook names it). */
void kgenome_fnprint_tokens(const struct kgenome_cell_insn *in, uint64_t rel_at, uint64_t flen,
		uint64_t ext, struct kgenome_fnprint_tok *t);

/* The position scratch. */
void kgenome_fnprint_pos_reset(struct kgenome_fnprint_pos *s);
void kgenome_fnprint_pos_free(struct kgenome_fnprint_pos *s, struct kgenome_ledger *led);
void kgenome_fnprint_pos_pad(struct kgenome_fnprint_pos *s, struct kgenome_ledger *led, uint64_t at, uint32_t len);
void kgenome_fnprint_pos_target(struct kgenome_fnprint_pos *s, struct kgenome_ledger *led, uint64_t tgt);
/* Target `i` in bytes of non-padding before it. */
uint64_t kgenome_fnprint_pos_adj(const struct kgenome_fnprint_pos *s, uint32_t i);
/* The fingerprint with the targets folded in (s may be NULL: nothing to fold). */
uint64_t kgenome_fnprint_pos_fold(const struct kgenome_fnprint_pos *s, uint64_t fp);
/* Does the instruction branch to a place inside the function [0, flen)? offset of the target in *to. */
int kgenome_fnprint_local_target(const struct kgenome_cell_insn *in, uint64_t rel_at, uint64_t flen, uint64_t *to);

/* Is the instruction at p (n bytes available, decoded to length 4) an ENDBR: padding to the fingerprint. */
int kgenome_fnprint_is_landing_pad(const uint8_t *p, uint32_t n);

void kgenome_fnprint_acc_init(struct kgenome_fnprint_acc *a);
void kgenome_fnprint_acc_good(struct kgenome_fnprint_acc *a, const struct kgenome_cell_insn *in, const struct kgenome_fnprint_tok *t);
void kgenome_fnprint_acc_bad(struct kgenome_fnprint_acc *a);

/* The two weights: how much a function counts, by class and size. */
uint32_t kgenome_fnprint_weight(const struct kgenome_fnprint_opts *o, uint8_t cls, uint32_t n_insn);

/* Is a diagnose node in [off, off+len)? Nodes ascending. */
int kgenome_fnprint_has_node(const struct kgenome_fnprint_hints *h, uint64_t off, uint64_t len);

/* Fill an opts' zeros with the defaults. */
void kgenome_fnprint_opts_resolve(struct kgenome_fnprint_opts *o);

/* The decision for one function, from its own signals and the pass state. */
void kgenome_fnprint_decide(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_opts *o,
		struct kgenome_fnprint_state *st, struct kgenome_fnprint_fn *f, int name,
		int is_entry, int in_diag);


/* ---- the region (fnprint_reach.c) ------------------------------------------ */

struct kgenome_ledger;
void kgenome_fnprint_reach_free(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led);
/* Append one edge to the pool; 0 when it could not be stored (the region is then failed). */
int  kgenome_fnprint_reach_edge(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led, uint64_t off);
/* Hold a decided function whose edges are pool[e0, e0+ne). 0: not held (failed / no memory). */
int  kgenome_fnprint_reach_hold(struct kgenome_fnprint_reach *r, struct kgenome_ledger *led,
		const struct kgenome_fnprint_fn *f, uint32_t e0, uint32_t ne);
/* Decide the held records from the edges: classes, reasons and weights are rewritten in place. */
void kgenome_fnprint_reach_resolve(struct kgenome_fnprint_reach *r, const struct kgenome_fnprint_req *rq,
		const struct kgenome_fnprint_opts *o, struct kgenome_fnprint_stat *sx);
/* Forget the held records (the arrays stay). */
void kgenome_fnprint_reach_reset(struct kgenome_fnprint_reach *r);

#endif
