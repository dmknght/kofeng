/*
 * diag_lineage_private.h - what the files of the lineage stages share. NOT PART OF THE SURFACE.
 *
 * THE LINEAGE STAGES are the part of the diagnose scan that says which node's value reaches which
 * node's argument THROUGH THE PROGRAM - registers, stack slots, globals, heap fields, calls - on the
 * object the engine ends with (the deepest recovered code), by following control flow instead of
 * address order. diag_lineage.h is what a caller reads; diag_lineage.c is the driver.
 *
 *   state    diag_lineage_state.c   a value (the producers it may be), the state of a program point,
 *                                   the join of two, and what one instruction does to it
 *   solve    diag_lineage_solve.c   one function: blocks, a fixpoint over them, links at the sites
 *   summ     diag_lineage_summ.c    the functions in callee-first order and what a call to one means
 *   seed     diag_lineage_seed.c    code no walk from a function's entry reaches
 *   (route)  diag_elfimp.c          the nodes of a linked ELF - not a stage: it makes the sites
 *
 * WHAT A VALUE IS. A set of TOKENS - the producers (the nodes whose result the value is) and, when the
 * function is summarised, the parameters it may be - and a flag, `other`: the value may also be
 * something no token names (a constant, an unknown, a parameter of a function with no caller). A link is
 * MUST exactly when the set is one producer and `other` is clear. That is the whole definition and the
 * tests state it independently of this code: every path to the argument yields that producer.
 */
#ifndef KGENOME_DIAG_LINEAGE_PRIVATE_H
#define KGENOME_DIAG_LINEAGE_PRIVATE_H

#include "diag_scan_private.h"
#include "diag_wrapper_private.h"
#include "diag_lineage.h"
#include "emu.h"
#include "codemap.h"

/*
 * HOW MANY TOKENS A VALUE HOLDS. Sixteen. The research prototype's eight overflowed on 14 of the 300 corpus files (a large switch
 * or state machine joins the results of many allocations into one register), which the scan says as KGENOME_TRUNCATED and
 * the file as "Limit reached"; sixteen overflows on 2 of them, 32 on 1, 64 on none, at a cost in the size of every value and every
 * state copy (about 8% of the stages' instructions from 8 to 16 [M]). A further producer does not vanish silently: the value widens
 * to `other` (so its links are MAY, never a wrong MUST) and the scan says it - a bound on the width of one value, not on how many
 * links an object may hold.
 */
#define KGENOME_LINEAGE_SET 16u

/* A token is a producer's node index (below this bit: a link names its producer in 16 bits, so a node past it is not tracked and the value
 * says so - the same bound as the summary's `node`), or this bit and a parameter number. A token is 16 bits: a value is 16 of them, and a state
 * is 16 values, copied and compared at every join. */
#define KGENOME_LINEAGE_PARAM 0x8000u

/* How many parameters a summary names: the six an x86-64 call passes in registers, and for a
 * stack ABI the first six words above the return address. */
#define KGENOME_LINEAGE_NPARAM 6u

/* What a value is when it is an ADDRESS the walk can name. */
enum { KGENOME_LINEAGE_A_NONE = 0, KGENOME_LINEAGE_A_STACK, KGENOME_LINEAGE_A_ABS };

struct kgenome_lineage_val {
	int64_t  v;                     /* the address, when k is not NONE: for STACK an offset from the
					 * stack pointer at the function's entry (the return address is 0) */
	uint8_t  k;                     /* KGENOME_LINEAGE_A_* */
	uint8_t  n;                     /* tokens in t[] */
	uint8_t  other;                 /* may also be a value no token names */
	uint8_t  _pad;
	uint32_t why;                   /* KGENOME_LINEAGE_W_*: why the part no token names is unknown (zero when `other` is clear) */
	uint16_t t[KGENOME_LINEAGE_SET];
};

/* A place a value is kept, keyed by what it is: the key's top nibble says which space. */
#define KGENOME_LINEAGE_KEY_STACK 1u
#define KGENOME_LINEAGE_KEY_GLOB  2u
#define KGENOME_LINEAGE_KEY_HEAP  3u

struct kgenome_lineage_slot {
	uint64_t key;
	struct kgenome_lineage_val v;
};

/* The state of a program point. `slot` is sorted by key; a place absent from it holds `other`. */
struct kgenome_lineage_state {
	struct kgenome_lineage_val r[16];
	struct kgenome_lineage_slot *slot;
	uint32_t n_slot, cap_slot;
	int32_t  sp;                    /* the stack pointer, from its value at the entry */
	uint8_t  spok;                  /* sp is known */
	uint8_t  pshs;                  /* words pushed since the stack pointer last changed otherwise (i386 callee-pops) */
	uint8_t  valid;                 /* this point is reached */
	uint8_t  seeded;                /* ... only through a seeded entry (diag_lineage_seed.c) */
};

/* The calling convention the object's code is read under. */
struct kgenome_lineage_abi {
	const uint8_t *arg;             /* the registers arguments 0.. are passed in */
	const uint8_t *clob;            /* the registers a call destroys */
	uint8_t  n_arg, n_clob;
	uint8_t  wide;                  /* x86-64 */
	uint8_t  w;                     /* the machine word: 4 or 8 */
	uint8_t  stack_first;           /* index of the first argument passed on the stack (words above the return address); 0 on i386 */
	int32_t  stack_off;             /* where it is, from the stack pointer at the call (Windows x64 skips 32 bytes of shadow space) */
	uint8_t  callee_pops;           /* a call to a site pops what was pushed for it unless an `add esp` follows (PE x86) */
};

/* A function by its entry address, for the lookup (the address is the first member: kofcmp.h). */
struct kgenome_lineage_fnva {
	uint64_t va;
	uint32_t fn;
};

/* One function of the object. */
struct kgenome_lineage_fn {
	uint64_t off, len, va;          /* file offset, length, address of the entry */
};

/* The consumer (site, role) a value reaches, as the sum of every context that reaches it. */
struct kgenome_lineage_agg {
	uint32_t key;                   /* (node + 1) << 8 | role; 0 is a free cell */
	uint8_t  n, other;
	uint8_t  param;                 /* a parameter reached it: what the callers supply is not known here */
	uint8_t  _pad;
	uint32_t why;                   /* the reasons of the unknown part (W_*), ORed over the contexts */
	uint16_t t[KGENOME_LINEAGE_SET];
};

/* A table of them, open-addressed. One is the object's (what every function solved adds to); one is the run's of the
 * function in hand, which the next run of the same function replaces and the last one is merged into the object's. */
struct kgenome_lineage_aggtab {
	struct kgenome_lineage_agg *v;
	uint32_t n, cap;
};

/*
 * WHAT A BLOCK HOLDS, as bits read off the decode of its function once (diag_lineage_chain.c, one loop over the
 * instructions that are already decoded). The rows of the selection table name these, not an `if` on the format.
 */
#define KGENOME_LINEAGE_P_NODE      0x001u  /* a call or a jump the scan has a node at */
#define KGENOME_LINEAGE_P_PRODUCER  0x002u  /* ... whose result is a handle */
#define KGENOME_LINEAGE_P_CALL_INT  0x004u  /* a direct call to a function of the object that reaches a node */
#define KGENOME_LINEAGE_P_CALL_SKIP 0x008u  /* ... to one that does not (it is not solved) */
#define KGENOME_LINEAGE_P_ICALL     0x010u  /* an indirect call or jump */
#define KGENOME_LINEAGE_P_MEMCELL   0x020u  /* a memory operand beyond the stack pointer's own: a place LOCS may name */
#define KGENOME_LINEAGE_P_STACKARG  0x040u  /* i386 callee-pops: a push in a block that calls */
#define KGENOME_LINEAGE_P_EXTCALL   0x080u  /* a direct call or jump to something that is no function and no node */
#define KGENOME_LINEAGE_P_UNREACHED 0x100u  /* set after the walk from the entry: this block was not reached */
#define KGENOME_LINEAGE_P_MEMSTORE  0x200u  /* a store to a place beyond the stack pointer's own */
#define KGENOME_LINEAGE_P_BPCELL    0x400u  /* (only while the loop runs) a memory operand through rbp: the frame, or a place */
#define KGENOME_LINEAGE_P_BPSTORE   0x800u  /* ... a store through it */

/* A parameter that reaches a site's argument: one record of a function's summary, before it is one of the pool's. */
struct kgenome_lineage_sink {
	uint32_t node;                  /* the consumer */
	uint8_t  role;
	uint8_t  param;
};

/* What one function does, built by the pass that solves it. */
struct kgenome_lineage_out {
	struct kgenome_lineage_val ret;
	uint8_t  ret_seen;              /* a ret was reached */
	struct kgenome_lineage_sink *sink;
	uint32_t n_sink, cap_sink;
};

/* The whole stage. */
struct kgenome_lineage {
	struct kgenome_diag_scan *s;
	const struct kgenome_obj *obj;
	const uint8_t *base;
	uint64_t size;
	unsigned plan;                  /* KGENOME_LINEAGE_S_*: the stages the class allows (the coarse filter) */
	unsigned run;                   /* the stages the solve in hand runs: FLOW, and what the function's obligations asked for */
	unsigned act;                   /* ... of those, the ones active on the block being stepped (its predicates hold) */
	struct kgenome_lineage_abi abi;
	struct kgenome_diag_walk *wk;   /* the object's decode, or NULL */
	/* the functions, sorted by offset and disjoint */
	struct kgenome_lineage_fn *fn;
	uint32_t n_fn;
	/* the sites: nodes at a call or a jump, sorted by `at` */
	uint64_t *site_at;
	uint32_t *site_node;
	uint32_t n_site;
	/* the decoded function in hand */
	struct kgenome_cell_insn *in;
	uint32_t n_in, cap_in;
	/* every function's summary, in the wrapper's own format and the wrapper's own pool functions */
	struct kgenome_diag_wrapper_ctx sums;
	/* what reaches each consumer: the object's table, the function-in-hand's, and the one adds go to */
	struct kgenome_lineage_aggtab glob, loc, *ag;
	uint32_t nseeded;               /* blocks the last run entered as seeds */
	uint32_t pend;                  /* the reasons of the unknown parts that reached a consumer, a sink or the return in this run */
	const uint8_t *rel;             /* per function: it reaches a node (diag_lineage_summ.c), or NULL before the graph is built */
	struct kgenome_diag_lineage_stats st;
	/* the cost: instructions the stages stepped, against the scan's step budget */
	uint64_t steps;
	int      over_steps;
	int      halt;
	uint64_t charged;
	/* the function being solved */
	struct kgenome_lineage_out *out;
	uint32_t cur_fn;
	uint32_t *callers;              /* per function: the direct calls into it */
	int      fn_store;              /* the function in hand holds a store to a place beyond the frame (in a block the walk reached) */
	uint8_t  *noret_fn;             /* per function: no way to return (no ret, no jump out, no jump through a register, a call or a syscall) */
	uint8_t  *fn_run;               /* per function: the stages of its last run */
	uint8_t  *has_site;             /* per function: it holds a node */
	uint8_t  *skipped;              /* per function: not read because nothing in it or below it is useful; 2 = a caller needs its return */
	uint32_t *need;                 /* the skipped functions the function in hand needs read, and how many */
	uint32_t n_need;
	int      can_defer, no_defer, deferred;    /* the solve in hand must merge (no_defer); the last solve left its merge for a second read (deferred) */
	uint8_t  *nontriv;              /* per function: its summary has a sink, or returns a producer or a parameter */
	uint64_t *sumhash;              /* per function: what its summary was when last published */
	struct kgenome_lineage_fnva *fn_by_va;  /* the functions ordered by entry address */
	int      dry;                   /* solve to learn a summary, and write no link (a recursive group iterating) */
	int16_t  *pop;                  /* per function: the bytes its returns pop (an i386 stdcall callee), or -1 when not known */
	int16_t  *argc;                 /* per node: the stdcall argument count of the API it is, -1 when not known, -2 not asked yet */
	uint64_t *slot_at;              /* the import slots of a PE x86 whose API has a known argument count, sorted, and that count */
	int16_t  *slot_words;
	uint32_t n_slot_pop;
	/* the object's calls and jumps, read once through the shared reader: the call graph's edges and, for an
	 * object whose functions are not all named, where the others begin */
	struct kgenome_codemap cm;
	int      cm_done;
};

/* ---- state ---- */
/* A value no token names and the reason it is unknown (KGENOME_LINEAGE_W_*). _other is the one with no better reason. */
void kgenome_lineage_val_unknown(struct kgenome_lineage_val *v, unsigned why);
void kgenome_lineage_val_other(struct kgenome_lineage_val *v);
/* Add a token to a value; 1 when it changed. */
int  kgenome_lineage_val_add(struct kgenome_lineage *L, struct kgenome_lineage_val *v, uint32_t t);
/* Join `b` into `a`; 1 when `a` changed. A value that no longer fits widens to `other` and notes the scan. */
int  kgenome_lineage_val_join(struct kgenome_lineage *L, struct kgenome_lineage_val *a,
			      const struct kgenome_lineage_val *b);
int  kgenome_lineage_state_copy(struct kgenome_lineage *L, struct kgenome_lineage_state *dst,
				const struct kgenome_lineage_state *src);
void kgenome_lineage_state_free(struct kgenome_lineage *L, struct kgenome_lineage_state *st);
int  kgenome_lineage_state_join(struct kgenome_lineage *L, struct kgenome_lineage_state *to,
				const struct kgenome_lineage_state *from);
void kgenome_lineage_state_entry(struct kgenome_lineage *L, struct kgenome_lineage_state *st, int params);
void kgenome_lineage_state_step(struct kgenome_lineage *L, struct kgenome_lineage_state *st,
				const struct kgenome_cell_insn *in);
/* The value of argument `i` of a call, as the caller holds it at the call. */
struct kgenome_lineage_val kgenome_lineage_arg(const struct kgenome_lineage *L,
					       const struct kgenome_lineage_state *st, unsigned i);
/* A call has returned: the registers it destroys are `other`, `ret` is what rax holds and `pop` the words an
 * i386 stdcall callee popped (-1 when not known) - see the note in diag_lineage_state.c. */
void kgenome_lineage_state_call(struct kgenome_lineage *L, struct kgenome_lineage_state *st,
				const struct kgenome_cell_insn *next, const struct kgenome_lineage_val *ret, int pop);
/* The memory the allocation (and the ledger) for one state's slots costs. */
/* A bound of the stages fired: counted in the stats, not set on the scan. */
#define KGENOME_LINEAGE_B_VALUE    0u
#define KGENOME_LINEAGE_B_CONSUMER 1u
#define KGENOME_LINEAGE_B_STEPS    2u
#define KGENOME_LINEAGE_B_ROUNDS   3u
void kgenome_lineage_bound(struct kgenome_lineage *L, unsigned kind);
int  kgenome_lineage_charge(struct kgenome_lineage *L, uint64_t n);
void kgenome_lineage_uncharge(struct kgenome_lineage *L, uint64_t n);

/* ---- solve ---- */
/*
 * THE BLOCKS OF THE FUNCTION IN HAND and the state at the top of each: what the fixpoint works on and
 * what the seed stage adds entries to.
 */
struct kgenome_lineage_cfg {
	uint32_t nb;
	uint32_t *bfirst;               /* nb + 1: the first instruction of each block, then the count */
	struct kgenome_lineage_state *bs;
	uint32_t *wl;                   /* the blocks to look at, a ring of nb */
	uint8_t  *inq;
	uint32_t head, nw;
	uint64_t left;                  /* instructions this function may still be stepped */
	int      cut;                   /* the function's own bound fired */
	uint16_t *bpred;                /* nb: what each block holds, KGENOME_LINEAGE_P_* */
	uint8_t  *bact;                 /* nb: the stages active on each block in this run */
};
/* Solve one function: its links go to the aggregate and, when `out` is not NULL, what it does to the
 * summary. */
void kgenome_lineage_solve(struct kgenome_lineage *L, uint32_t fi, struct kgenome_lineage_out *out);
/* Run the worklist to a fixpoint: 1 when it converged, 0 when a bound ended it. */
int  kgenome_lineage_cfg_run(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g);
/* Make block `b` a point the walk starts from, in `st` (taken over). */
void kgenome_lineage_cfg_enter(struct kgenome_lineage_cfg *g, uint32_t b, struct kgenome_lineage_state *st);
/* The seed stage: entries for the blocks the walk from the function's own entry did not reach - those the selection table
 * names (diag_lineage_chain.c), or every one of them when `all`. */
void kgenome_lineage_seed(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, int all);
/* Is this call one the program does not come back from. */
int  kgenome_lineage_call_noreturn(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in);
/* The node of an instruction (see diag_lineage_solve.c). */
int  kgenome_lineage_site_in(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in, uint32_t *node);
int  kgenome_lineage_site_of(const struct kgenome_lineage *L, uint64_t at, uint32_t *node);
/* Is this jump a call that does not return here: to a node, or out of the function. */
int  kgenome_lineage_jmp_is_tail(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in);
/* Does the node's capability hand a handle on in its result. */
int  kgenome_lineage_hands_on(const struct kgenome_lineage *L, const struct kgenome_diag_hit *h);
/* The function whose entry is the address, or UINT32_MAX. */
uint32_t kgenome_lineage_fn_of_va(const struct kgenome_lineage *L, uint64_t va);
/* The function an offset lies in, or UINT32_MAX. */
uint32_t kgenome_lineage_fn_at(const struct kgenome_lineage *L, uint64_t off);
void kgenome_lineage_agg_add(struct kgenome_lineage *L, uint32_t node, uint8_t role,
			     const struct kgenome_lineage_val *v, int uncertain);
/* The words an i386 stdcall callee pops, for a call through the import slot at `slot` - or -1. */
int  kgenome_lineage_slot_pop(const struct kgenome_lineage *L, uint64_t slot);
/* The decoded body of function `fi`, into L->in. 0 when memory ran out. */
int  kgenome_lineage_decode(struct kgenome_lineage *L, uint32_t fi);

/* The object's codemap, built on the first ask (NULL when memory or the ledger refused). */
const struct kgenome_codemap *kgenome_lineage_codemap(struct kgenome_lineage *L);

/* ---- summ ---- */
/* The records of `entry` in the pool, as a run [*lo, *hi) of positions. */
int  kgenome_lineage_sum_find(struct kgenome_lineage *L, uint64_t entry, uint32_t *lo, uint32_t *hi);
void kgenome_lineage_run_summ(struct kgenome_lineage *L);
/* A call to function `fi`: the value it returns in the caller's terms, and the sinks it applies. */
void kgenome_lineage_apply(struct kgenome_lineage *L, struct kgenome_lineage_state *st, uint32_t callee,
			   struct kgenome_lineage_val *ret, int emit, int want_ret);

/* ---- chain: which stage runs on which code (diag_lineage_chain.c) ---- */
void     kgenome_lineage_preds(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g);
unsigned kgenome_lineage_act(const struct kgenome_lineage *L, uint16_t bpred);
void     kgenome_lineage_mark_unreached(struct kgenome_lineage_cfg *g);
int      kgenome_lineage_has_store(const struct kgenome_lineage_cfg *g);
unsigned kgenome_lineage_chain_next(const struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g);
int      kgenome_lineage_seed_wanted(const struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g);
int      kgenome_lineage_seed_block(const struct kgenome_lineage_cfg *g, uint32_t b);
void     kgenome_lineage_stats_fn(struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g, unsigned nruns,
				  uint32_t seeded);
void     kgenome_lineage_obligations(struct kgenome_lineage *L);

#endif /* KGENOME_DIAG_LINEAGE_PRIVATE_H */
