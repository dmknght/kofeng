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
#include <celllysis/cfg.h>
#include "emu.h"
#include "codemap.h"
#include "frame.h"

/*
 * HOW MANY TOKENS A VALUE HOLDS: as many as reach it. The first KGENOME_LINEAGE_VAL_INLINE are in the value itself (t[]), the rest in the
 * stage's token pool (L->vx), as an immutable chain the value names by its head (`more`): a value copied shares the chain, and a token added
 * to one copy makes a new head that points at the old one, so no copy changes another (kgenome_lineage_val_add). The pool is the solve's: it
 * is emptied when the next function's solve starts, and charged to the ledger; a refusal is the one bound left (B_VALUE: the value widens to
 * `other` with W_LIMIT, the scan says TRUNCATED).
 *
 * Sixteen tokens and no more was the bound before (LG-12): the research prototype's eight overflowed on 14 of the 300 corpus files, sixteen
 * on 2 - MEASURED again on the 356-file A/B set before the fix: B_VALUE fired 69 times in 2 files (corp300 030: 8, 080: 61), both said
 * TRUNCATED, and every token past sixteen was a producer the value lost. Fourteen inline keep the value at 48 bytes with the chain's head.
 * MEASURED after the fix: B_VALUE fires on none of the 356 files, corp300 080 is no longer TRUNCATED, the links of the set are the same
 * 7611 (the lost producers reached no consumer there; tests/lib/genome/lineage_sites.c t_wide_value is one where they do), lineage Ir on
 * the 30-file callgrind set 10.82 G -> 10.97 G (+1.4%: the values of 15 and 16 tokens now walk a chain).
 *
 * KGENOME_LINEAGE_SET is the inline width of a CONSUMER's producers (struct kgenome_lineage_agg), which spill to their own pool (LG-11).
 */
#define KGENOME_LINEAGE_SET 16u
#define KGENOME_LINEAGE_VAL_INLINE 14u

/* A token is a producer's node index (below KGENOME_LINEAGE_STATUS: a node past it is not tracked and the value says so - kgenome_lineage_bound
 * B_VALUE), or the PARAM bit and a parameter number, or the STATUS bit and a node index. A token is 16 bits: a value is 16 of them, and a state
 * is 16 values, copied and compared at every join.
 *
 * A STATUS TOKEN is the result of a node whose capability hands no handle on (connect's 0, a byte count): a value, not an object, so it is no
 * producer of a descriptor, a buffer or a path - at those inputs it reads as `other` with the reason W_STATUS, exactly as before it was a token -
 * and it never names a heap object (place_resolve). It is a token so that ONE input can say whose result it is: the NUMBER of a system call
 * (KGENOME_DIAG_ROLE_NUMBER), where msfvenom's stagers leave connect's zero in rax and the next syscall reads it as `read`. The node bound
 * moved from 32768 to 16384 to make the bit: an object past it says so (B_VALUE), it does not lose a link silently. */
#define KGENOME_LINEAGE_PARAM  0x8000u
#define KGENOME_LINEAGE_STATUS 0x4000u
#define KGENOME_LINEAGE_NODE_MAX KGENOME_LINEAGE_STATUS     /* a node index a token can hold */
#define KGENOME_LINEAGE_TOK_NODE(t) ((uint32_t)(t) & (KGENOME_LINEAGE_STATUS - 1u))

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
	uint16_t t[KGENOME_LINEAGE_VAL_INLINE];
	uint32_t more;                  /* the head cell + 1 of the tokens past t[] in the solve's pool (L->vx), 0: none */
};
_Static_assert(sizeof(struct kgenome_lineage_val) == 48, "a value is 48 bytes: every state copies sixteen of them at every join");

/* A place a value is kept, keyed by what it is: the key's top nibble says which space. */
#define KGENOME_LINEAGE_KEY_STACK 1u
#define KGENOME_LINEAGE_KEY_GLOB  2u
#define KGENOME_LINEAGE_KEY_HEAP  3u
#define KGENOME_LINEAGE_KEY_LSTK  4u   /* a word pushed while the stack pointer is not known, by its depth from where it was lost */

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
	int16_t  ld;                    /* when sp is not known: the words pushed since it was lost and not popped (their values are the slots
					 * of space KGENOME_LINEAGE_KEY_LSTK, by depth); -1 when not known either (diag_lineage_state.c, sp_lost) */
};

struct kgenome_lineage;
struct kgenome_lineage_state;

/*
 * THE ARCHITECTURE ROW (diag_lineage_arch.c): everything the stages ask a machine and an ABI, in ONE place, the way the emulator is a
 * core plus a row per architecture (emu_private.h, struct kgenome_emu_arch). The core - the lattice, the join, the slots, the fixpoint,
 * the summaries, the chain - asks the row and never the architecture: what a register is for, how a call passes its arguments and what
 * it destroys, how a system call passes its number and arguments and what it destroys, and what one instruction does to the provenance
 * state (`step`). An object whose (arch, format) has no row is not read (kgenome_lineage_arch_of answers NULL), and the reason each missing
 * architecture has none is written at the table.
 */
struct kgenome_lineage_abi {
	const char *name;
	unsigned arch, fmt;             /* KGENOME_ARCH_*; KGENOME_FMT_* or 0 for any format */
	/* the registers with a role */
	uint8_t  sp, fp, ret;           /* the stack pointer, the frame pointer, where a call's answer comes back */
	/* the CALL convention */
	const uint8_t *arg;             /* the registers arguments 0.. are passed in */
	const uint8_t *clob;            /* the registers a call destroys */
	uint8_t  n_arg, n_clob;
	uint8_t  wide;                  /* 64-bit: an absolute address is not truncated to 32 bits */
	uint8_t  w;                     /* the machine word: 4 or 8 */
	uint8_t  stack_first;           /* index of the first argument passed on the stack (words above the return address); 0 on i386 */
	int32_t  stack_off;             /* where it is, from the stack pointer at the call (Windows x64 skips 32 bytes of shadow space) */
	uint8_t  callee_pops;           /* a call to a site pops what was pushed for it unless an `add esp` follows (PE x86) */
	/* the SYSTEM CALL convention: the number's register, the argument registers (kgenome_diag_arg_regs: the one table the routes read
	 * them from, filled in by kgenome_lineage_arch_of), what the kernel entry destroys besides the result */
	uint8_t  sys_nr;
	const uint8_t *sys_arg;
	uint8_t  n_sys_arg;
	const uint8_t *sys_clob;
	uint8_t  n_sys_clob;
	/* what one instruction that is no call, jump, return or kernel entry does to the state */
	void (*step)(struct kgenome_lineage *L, struct kgenome_lineage_state *st, const struct kgenome_cell_insn *in);
};

/* The row of the object's architecture and format, filled in (the argument registers of its system calls); 0 when none exists. */
int kgenome_lineage_arch_of(const struct kgenome_obj *obj, struct kgenome_lineage_abi *out);

/*
 * HOW A SITE TAKES ITS INPUTS: decided once per site from the instruction it is and the node's capability (kgenome_lineage_site_conv), and
 * the one switch that reads an input (kgenome_lineage_site_input). Before, a site was always a call and its inputs the call convention's
 * arguments - so a node at a `syscall` had no input at all in this stage, and a branch through a register (EXEC_REG: `jmp rsi` into a
 * region a node made) had none either (its capability names no argument role): its TARGET was only the linear sweep's.
 */
enum kgenome_lineage_conv {
	KGENOME_LINEAGE_C_CALL = 0,     /* a call or a tail jump to an API or a function: the call convention's arguments */
	KGENOME_LINEAGE_C_SYS,          /* a kernel entry: the system call convention's arguments, and its NUMBER */
	KGENOME_LINEAGE_C_BRANCH        /* a branch through a register or memory the node is about: its TARGET is the branch's operand */
};

/* One function of the object as the stage reads it (kgenome_lineage_fn_get): the table's entry with its extent clamped to the object, and the address of its entry. */
struct kgenome_lineage_fn {
	uint64_t off, len, va;          /* file offset, length, address of the entry */
};

/* The consumer (site, role) a value reaches, as the sum of every context that reaches it. */
struct kgenome_lineage_agg {
	uint32_t key;                   /* (node + 1) << 8 | role; 0 is a free cell */
	uint32_t n;                     /* the producers: the first KGENOME_LINEAGE_SET in t[], the rest in the table's pool from `more` */
	uint8_t  other;
	uint8_t  param;                 /* a parameter reached it: what the callers supply is not known here */
	uint16_t _pad;
	uint32_t why;                   /* the reasons of the unknown part (W_*), ORed over the contexts */
	uint32_t more;                  /* the first pool cell + 1 of the producers past t[], 0: none */
	uint16_t t[KGENOME_LINEAGE_SET];
};

/* A producer of a consumer past its first KGENOME_LINEAGE_SET: a cell of the table's pool, chained. */
struct kgenome_lineage_aggx {
	uint32_t next;                  /* the next cell + 1, 0: the last */
	uint16_t tok;
};

/* A table of them, open-addressed. One is the object's (what every function solved adds to); one is the run's of the
 * function in hand, which the next run of the same function replaces and the last one is merged into the object's. A consumer
 * holds as many producers as reach it (the pool, charged to the ledger): sixteen a consumer was a cap that deleted evidence -
 * MEASURED, it fired 25 times on corp300 057 once the system call sites were read, and the file said TRUNCATED for it. */
struct kgenome_lineage_aggtab {
	struct kgenome_lineage_agg *v;
	uint32_t n, cap;
	struct kgenome_lineage_aggx *x;
	uint32_t nx, capx;
};

/* Every producer of `a` (a->n of them) into `out`. */
void kgenome_lineage_agg_toks(const struct kgenome_lineage_aggtab *t, const struct kgenome_lineage_agg *a, uint16_t *out);

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
	/* THE FUNCTIONS: the engine's table, read by index (`fs`) */
	const struct kgenome_func_set *fs;
	struct kgenome_func_set own;
	/* THE FRAMES (phenotype/frame.h): the cache of the object's, and what a frame is made from. `fsrc.fs` is the table the cache is keyed by: a function that is an entry of it is read from the cache, any other (an extent the table clamps) is made and given back after its solve. */
	struct kgenome_frame_cache *frames;
	struct kgenome_frame_src fsrc;
	uint64_t own_charged;
	uint32_t n_fn;
	struct kgenome_lineage_fnva { uint64_t va; uint32_t fn; } *by_va;   /* the entry address of each function the stage can read, with its index, sorted by address (the first member: kofcmp.h) */
	uint32_t n_by_va;
	uint32_t *site_fn;              /* per site: the function that holds it (KGENOME_FUNCS_NONE: none), decided once */
	uint32_t *ref_from, *ref_to;    /* per codemap reference: the function that holds the instruction / its target (the second array is the first's tail), decided once */
	/* the sites: nodes at a call or a jump, sorted by `at` */
	uint64_t *site_at;
	uint32_t *site_node;
	uint32_t n_site;
	/* the decoded function in hand */
	struct kgenome_cell_insn *in;
	uint32_t n_in, cap_in;
	uint64_t n_skip;                /* bytes of the function in hand that decoded as nothing */
	/* every function's summary, in the wrapper's own format and the wrapper's own pool functions */
	struct kgenome_diag_wrapper_ctx sums;
	/* what reaches each consumer: the object's table, the function-in-hand's, and the one adds go to */
	struct kgenome_lineage_aggtab glob, loc, *ag;
	/* the tokens of values past their inline ones: an immutable chain per value (struct kgenome_lineage_val.more), the solve's */
	struct kgenome_lineage_aggx *vx;
	uint32_t nvx, capvx;
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
	uint8_t  *noret_fn;             /* per function: 0 not asked, 1 no way to return (kgenome_lineage_noret), 2 it can; NULL: the stage does not use it */
	uint8_t  *fn_run;               /* per function: the stages of its last run */
	uint8_t  *has_site;             /* per function: it holds a node */
	uint8_t  *skipped;              /* per function: not read because nothing in it or below it is useful; 2 = a caller needs its return */
	uint32_t *need;                 /* the skipped functions the function in hand needs read, and how many */
	uint32_t n_need;
	int      can_defer, no_defer, deferred;    /* the solve in hand must merge (no_defer); the last solve left its merge for a second read (deferred) */
	uint8_t  *nontriv;              /* per function: its summary has a sink, or returns a producer or a parameter */
	uint64_t *sumhash;              /* per function: what its summary was when last published */
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
/* Every token of a value into `out` (at most `cap`); answers how many the value has. */
uint32_t kgenome_lineage_val_toks(const struct kgenome_lineage *L, const struct kgenome_lineage_val *v, uint16_t *out, uint32_t cap);
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
/* The value an operand holds (a register, an immediate, a place). */
void kgenome_lineage_read_op(const struct kgenome_lineage *L, const struct kgenome_lineage_state *st,
			     const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *o,
			     struct kgenome_lineage_val *out);
/* The x86 and x86-64 transfer function: the `step` of their rows. */
void kgenome_lineage_step_x86(struct kgenome_lineage *L, struct kgenome_lineage_state *st, const struct kgenome_cell_insn *in);
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
	const struct kgenome_frame *fr; /* the function's frame (phenotype/frame.h), read only: its graph is `cfg`, its facts of each block `fr->bits` */
	struct kgenome_cfg cfg;         /* the frame's graph (a copy of the header; the arrays are the frame's): `first`, `n_insn` and successors as block indices; nb == cfg.n_all */
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
int  kgenome_lineage_call_noreturn(struct kgenome_lineage *L, const struct kgenome_cell_insn *in);
/* Has function `fi` no way to return: read from its FRAME's reachable blocks, once (a memo in `noret_fn`). */
int  kgenome_lineage_noret(struct kgenome_lineage *L, uint32_t fi);
/* How the site at instruction `in` (node `node`) takes its inputs. */
enum kgenome_lineage_conv kgenome_lineage_site_conv(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in, uint32_t node);
/* Is `in` an entry to the kernel under the object's architecture (the routes' own test, kgenome_diag_kernel_entry). */
int  kgenome_lineage_is_kentry(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in);
/* The node of an instruction (see diag_lineage_solve.c). */
int  kgenome_lineage_site_in(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in, uint32_t *node);
int  kgenome_lineage_site_of(const struct kgenome_lineage *L, uint64_t at, uint32_t *node);
/* Is this jump, the end of block `b`, a call that does not return here: to a node, or out of the function (a block that does
 * not end in a local jump). */
int  kgenome_lineage_jmp_is_tail(const struct kgenome_lineage *L, const struct kgenome_lineage_cfg *g, uint32_t b,
				 const struct kgenome_cell_insn *in);
/* The instructions of block `b` are [first, end). */
static inline uint32_t kgenome_lineage_bfirst(const struct kgenome_lineage_cfg *g, uint32_t b)
{
	return g->cfg.b[b].first;
}
static inline uint32_t kgenome_lineage_bend(const struct kgenome_lineage_cfg *g, uint32_t b)
{
	return g->cfg.b[b].first + g->cfg.b[b].n_insn;
}
/* Does the node's result hand an object on: its row's answer, its capability's when it has no row (diag_lineage_solve.c). */
int  kgenome_lineage_hands_on(const struct kgenome_diag_hit *h);
/* The function whose entry is the target of the call or jump `in`, or UINT32_MAX. */
uint32_t kgenome_lineage_fn_of_insn(const struct kgenome_lineage *L, const struct kgenome_cell_insn *in);
/* The function `fi` as the stage reads it; 0 when it has no code the stage can read (outside the object, no length, no address). */
int kgenome_lineage_fn_get(const struct kgenome_lineage *L, uint32_t fi, struct kgenome_lineage_fn *out);
/* What a frame of a function is made from (the allocator is the lineage's ledger): `table` is the engine's function table, the cache's key. */
void kgenome_lineage_frame_src(struct kgenome_lineage *L, const struct kgenome_func_set *table);
/* The function of each end of every reference of `cm`, decided once (L->ref_from, L->ref_to); 0 when memory or the ledger refused. Idempotent. */
int kgenome_lineage_refs(struct kgenome_lineage *L, const struct kgenome_codemap *cm);
/* The cell of `key` ((node + 1) << 8 | role) in a table of what reaches the consumers, or NULL: a lookup, nothing inserted. */
const struct kgenome_lineage_agg *kgenome_lineage_agg_get(const struct kgenome_lineage_aggtab *t, uint32_t key);
void kgenome_lineage_agg_add(struct kgenome_lineage *L, uint32_t node, uint8_t role,
			     const struct kgenome_lineage_val *v, int uncertain);
/* The words an i386 stdcall callee pops, for a call through the import slot at `slot` - or -1. */
int  kgenome_lineage_slot_pop(const struct kgenome_lineage *L, uint64_t slot);
/* The decoded body of function `fi`, into L->in. 0 when memory ran out. */
int  kgenome_lineage_decode(struct kgenome_lineage *L, const struct kgenome_lineage_fn *f);

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
