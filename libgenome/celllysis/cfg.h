/*
 * cfg.h - THE CONTROL-FLOW GRAPH OF ONE FUNCTION, and a signature of its shape. Public part header of kgenome
 * (celllysis/): cfg_build.c (blocks, edges), cfg_isa.c (the one table of what a branch does, per
 * architecture), cfg_sign.c (labels, Weisfeiler-Lehman, canonical hash, sketch, pct), cfg_anchor.c (is the
 * function worth hashing) and cfg_view.c (what a viewer draws).
 *
 * WHY. The similarity blocks built from raw 8-byte windows over function content were measured ineffective
 * (x86-64 5/60, other architectures 0): a recompile moves every byte. The SHAPE of a function survives it more
 * often, and the shape does not need a callee, a jump value, a name or a PLT order - all of which a stripped or
 * re-linked build changes. The label of a block is therefore (in-degree, out-degree, terminator class) and
 * nothing else. The choice of this label, of one Weisfeiler-Lehman round and of a bottom-32 sketch was made by
 * measurement over two families and 56354 clean functions (/mnt/games/normtest/briefs/cfg_decision.md); its limits
 * are there too and are not repeated as claims here: same-name ground truth only, two families, no clean
 * ARM/i386/MIPS file, a changed -O defeats it. The anchor (a floor of 12 reachable blocks, chosen there) is GONE
 * (owner, 2026-11-01): every function with a reachable block is signed; see KGENOME_CFG_ANCHOR_MIN and
 * IMPROVE cfg-small-1 in cfg_sign.c.
 *
 * ONE BUILDER. The blocks of a function used to be made by the lineage solver only (diag_lineage_solve.c) and
 * stored as addresses that every graph walk re-resolved by binary search. Both now read this: successors are
 * block INDICES, resolved once (rule 5), and the lineage's blocks ARE these blocks (rule 10).
 *
 * WHAT THE CALLER GIVES. The instructions, DECODED ONCE by the caller (no decode here), in increasing address
 * order, with the extent [va_lo, va_hi) of the function. A branch whose target is not an instruction of the
 * array is a way OUT of the function (a tail call): it is no edge. A call is never an edge or a block end.
 * x86 `rep`, `cmov`, `setcc` and `call` have no rule: they do not split a block.
 *
 * WHAT IS IN THE GRAPH. EVERY block of the array is made (`n_all`, the lineage seeds unreached code), and each
 * carries `reach`: reachable from the entry along edges. The signature, the degrees, `n_blk` and `n_edge` count
 * REACHABLE blocks only (padding, literal pools and code reached only through a jump table are not the
 * function's shape: ARM Gafgyt exact recall .35 -> .71, M).
 *
 * MEMORY IS THE CALLER'S: every allocation goes through `struct kgenome_cfg_mem` (the engine charges its scan
 * ledger there; NULL callbacks mean malloc/free). A refusal is a status, never a crash and never a leak: the
 * product built so far is released and the status says NOMEM. `budget->max_bytes` (0 or no budget: none)
 * bounds what one call may hold; over it the call allocates nothing and says OVER_BUDGET - "cannot say", not
 * "no blocks" (rule 4). Time is linear in the instructions (and n log n nowhere): there is no cap on blocks.
 *
 * THREADS. No writable global state; a call touches only what it is handed.
 *
 * REACH_INDIRECT (owner work package, 2026-11-04, cfg_build.c): an indirect `jmp` - through a register or a
 * `[base+index*scale+disp]` memory operand - is resolved against a switch/jump table when the caller supplies
 * `req->switch_src` (cfg_build.c's own comment has the five-step algorithm and its named limits). Resolved, it is
 * KGENOME_CFG_T_SWITCH with its N targets in the auxiliary array `switch_tgt[]` (kgenome_cfg_block.switch_first/n_switch),
 * read like `call[]` and NEVER folded into `succ[2]`/`reach`/`n_blk`/`n_edge`: this keeps the WHAT IS IN THE GRAPH
 * paragraph above (and cfg_sign.c's measured WL signature) completely unchanged for every existing caller, because
 * `switch_src` is NULL for all of them today - the feature is strictly additive and opt-in, never a default. The one
 * caller `switch_src` exists for is fntab_reach.c's REACH_INDIRECT gap (its own header comment): a lower-bound reach
 * walk that wants the table's real edges to size a function's extent, NOT the similarity signature.
 */
#ifndef KGENOME_CFG_H
#define KGENOME_CFG_H

#include <stddef.h>
#include <stdint.h>

#include "../kgenome_status.h"
#include "../kgenome_budget.h"
#include "cell.h"

#define KGENOME_CFG_NONE   0xffffffffu  /* no successor / no block */
#define KGENOME_CFG_KEYS   32u          /* elements of a sketch: the bottom 32 */
/* the build's first work area, per input instruction: two u32 (jump target, block of an instruction) and one class byte; refused as OVER_BUDGET before anything is allocated */
#define KGENOME_CFG_BUILD_BYTES_PER_INSN (2u * sizeof(uint32_t) + 1u)
#define KGENOME_CFG_ANCHOR_MIN 1u       /* reachable blocks a function needs to be hashed: one (a function with none has nothing to sign) */
#define KGENOME_CFG_ROUNDS_MAX 8u
/*
 * THE FLOOR OF 12 REACHABLE BLOCKS IS GONE (owner, 2026-11-01: "dung wl1 de them hash cho cac ham nho"). It was chosen from a measured
 * false-positive cliff between 10 and 12 blocks; the owner decided that a small function gets its hash anyway and that the user's own
 * threshold handles the rest, so the number is no longer a condition of being signed. What remains is that a function with NO reachable
 * block has no element to sign. Every reachable block is one distinct element (the label paired with its k-th occurrence), so a signed
 * function holds at least this many (up to 32). It is the minimum a CFG block may carry in a pack, in place of
 * KGENOME_MUTATION_MIN_HASH (16, a number chosen for window hashes); the block record (n_hash u16, a slice of the pool) has no minimum
 * of its own, only the checks that ask kgenome_mutation_block_min.
 */
#define KGENOME_CFG_MIN_KEYS   KGENOME_CFG_ANCHOR_MIN
/*
 * DOMAIN SEPARATION. A CFG block is stored in a pack as a list of u32, the same record a window block is. The keys are therefore made
 * with a hash that is not the window hash (mutation_window.h: a rolling polynomial and 2654435761) and starts from this constant, which
 * no window constant equals (tests/lib/genome/cfg_sign.c), so a window of bytes and a graph label meet only by the chance of two
 * independent 32-bit values.
 */
#define KGENOME_CFG_KEY_SEED   0x43464753454b4559ull

/*
 * REACH_INDIRECT (owner work package, 2026-11-04): the cost cap on how many jump-table entries ONE switch site reads when no
 * `cmp`/`sub` against an immediate bounds the index (step 3 of kgenome_cfg_switch_resolve, cfg_build.c). This is a cap on
 * COST, never a claimed true table size (rule 4): a site that reads exactly this many valid entries sets
 * kgenome_cfg_block.switch_capped, which says "more cases may exist, unread" rather than silently treating the cap as the
 * table's end. A found `cmp`/`sub` bound (the common case: the compiler's own bounds check) is used exactly and is not
 * clamped by this number when it is smaller; a bound LARGER than this cap is itself clamped here (named limit: a hostile
 * or obfuscated bounds check cannot make one call read without end).
 */
#define KGENOME_CFG_SWITCH_MAX_CASES 4096u

/* How a block ends. EXIT: ret, iret, a trap, an indirect or far jump, a jump out of the extent. A conditional exit
 * (an ARM conditional return, a conditional jump out of the extent) keeps its fall-through and is FALL.
 * SWITCH (REACH_INDIRECT): an indirect jmp that kgenome_cfg_build resolved against a caller-supplied `switch_src` (cfg_req.switch_src)
 * into one or more real targets - the auxiliary array `kgenome_cfg.switch_tgt[block.switch_first .. +block.n_switch)`, instruction
 * INDICES exactly like `kgenome_cfg_call.insn` (never block indices: resolution runs before blocks are finalised, mirroring how
 * `call[]` is a fact beside the block and not inside `succ[2]`, cfg_build.c). It is NEVER produced when `switch_src` is NULL (every
 * existing caller: lineage, codenotes, cfgview, kofexaminer --blocks): an indirect jmp that cannot or was not asked to be resolved
 * stays EXIT exactly as before - this is the one and only behaviour change gate, and it is additive. `succ[0]`/`succ[1]` of a SWITCH
 * block stay KGENOME_CFG_NONE and `out_deg` 0: switch edges are NOT folded into `reach`/`n_blk`/`n_edge`/`in_deg` or the WL signature's
 * message passing (cfg_sign.c is unchanged and untouched by this work package) - the measured decision that code reached only through
 * a jump table is not part of a function's structural shape (ARM Gafgyt .35 -> .71, above) stays exactly as it was; `switch_tgt[]` is
 * a plain ADDITIONAL FACT for a consumer that wants it (fntab_reach.c's REACH_INDIRECT gap, see fntab_reach.c's own header comment),
 * read like `call[]`, never walked by the graph's own reachability pass. */
enum kgenome_cfg_term {
	KGENOME_CFG_T_FALL = 0,         /* falls into the next block (or off the end of the array: no successor) */
	KGENOME_CFG_T_COND,             /* a local conditional branch: succ[0] the target, succ[1] the fall-through */
	KGENOME_CFG_T_JUMP,             /* a local unconditional jump: succ[0] the target */
	KGENOME_CFG_T_EXIT,             /* no successor */
	KGENOME_CFG_T_SWITCH            /* an indirect jmp resolved to N targets in kgenome_cfg.switch_tgt[]; see above */
};

/*
 * WHAT A CALL (OR A SYSTEM CALL) IS, as a fact the graph carries and never interprets. The lib knows an instruction's class and flags
 * (a call, an indirect call, a syscall instruction); WHAT is called - an import's name, a local function, a syscall number - is the
 * caller's knowledge (the call-name table, the codemap, the function table), so the caller hands it in through
 * `kgenome_cfg_req.callee` as an opaque 64-bit identity and a kind, once per call instruction of a REACHABLE block. 0 is "unresolved".
 * The lib stores it in `kgenome_cfg.call` and the second signature (policy CALLEES) scores it; the structural label never reads it.
 */
enum kgenome_cfg_call_kind {
	KGENOME_CFG_CK_NONE = 0,
	KGENOME_CFG_CK_DIRECT,          /* a direct call whose target the caller did not classify */
	KGENOME_CFG_CK_LOCAL,           /* a function of the object (the caller says so) */
	KGENOME_CFG_CK_IMPORT,          /* an import, through a stub or a slot (the caller says so) */
	KGENOME_CFG_CK_INDIRECT,        /* a call through a register or memory */
	KGENOME_CFG_CK_SYSCALL          /* a system call instruction (syscall, sysenter, svc, int 0x80) */
};

struct kgenome_cfg_call {
	uint64_t id;                    /* the caller's identity of the callee; 0 = unresolved */
	uint32_t insn;                  /* index of the instruction in the caller's array */
	uint8_t  kind;                  /* enum kgenome_cfg_call_kind */
	uint8_t  pad_[3];
};

struct kgenome_cfg_block {
	uint32_t first;                 /* index of its first instruction in the caller's array */
	uint32_t n_insn;                /* instructions, a delay slot included */
	uint32_t succ[2];               /* block indices (layout order) or KGENOME_CFG_NONE; see enum kgenome_cfg_term */
	uint32_t in_deg;                /* edges into it FROM REACHABLE BLOCKS (edges, not distinct predecessors) */
	uint32_t call_first;            /* its calls and system calls are kgenome_cfg.call[call_first .. call_first + n_call) (reachable blocks only) */
	uint32_t n_call;                /* how many: no cap */
	/*
	 * REACH_INDIRECT: valid only when `term == KGENOME_CFG_T_SWITCH` (always 0/0 otherwise, including every build where `switch_src` was NULL).
	 * Its resolved targets are kgenome_cfg.switch_tgt[switch_first .. switch_first + n_switch), INSTRUCTION indices (as kgenome_cfg_call.insn is),
	 * not block indices - resolution runs before blocks exist. `switch_capped` says resolution stopped because it reached
	 * KGENOME_CFG_SWITCH_MAX_CASES (or a found cmp/sub bound larger than it) while every entry read so far was valid: more cases may be unread
	 * (rule 4, report a cap, never claim "this is all of them"). It is 0 when resolution stopped on the first invalid entry (a callback refusal, an
	 * entry outside [va_lo, va_hi), or an entry that does not land on a decoded instruction) - the ordinary, expected end of a real table.
	 */
	uint32_t switch_first;
	uint32_t n_switch;
	/* WHERE THE BLOCK IS, in bytes: the address of its first instruction less the request's `va_lo` (the function's start). Blocks are in layout order and contiguous
	 * over the decoded instructions, so a block's byte length is the next block's `at` less its own (the last one: the extent's length less its `at`) - nothing is stored
	 * twice. A consumer that wants the bytes of a block (to decode it again, to show it) needs no instruction array. Saturates at UINT32_MAX (a function of 4 GiB). */
	uint32_t at;
	uint8_t  out_deg;               /* 0..2; 0 for a SWITCH block (its edges are the auxiliary array, not succ[]; see enum kgenome_cfg_term) */
	uint8_t  term;                  /* enum kgenome_cfg_term */
	uint8_t  reach;                 /* 1: reachable from block 0 */
	uint8_t  call_kinds;            /* bit (1 << kind) for every kind among its calls */
	uint8_t  switch_capped;         /* REACH_INDIRECT: 1 = resolution stopped at the cost cap, not at an invalid entry (see above) */
};

/* The caller's allocator. NULL `alloc` = malloc and NULL `release` = free. `release` is told the size it was asked for. */
struct kgenome_cfg_mem {
	void *(*alloc)(void *user, size_t n);
	void  (*release)(void *user, void *p, size_t n);
	void  *user;
};

/* ONE allocation through the caller's allocator (NULL callbacks: malloc / free); NULL when refused. `release` is told the size asked for. The one implementation:
 * the graph, its view, the frame (phenotype/frame.h) and the signing (analyzers/cfgsign.c) all allocate through it. */
void *kgenome_cfg_alloc(const struct kgenome_cfg_mem *mem, size_t n);
void kgenome_cfg_release(const struct kgenome_cfg_mem *mem, void *p, size_t n);

/*
 * Request flags. SPLIT_EXITS: a conditional branch whose target is not in the function STILL ends its block (the exit is dropped, the
 * fall-through stays the only edge). The signature does not set it (a conditional tail call is not a block end there: measured, the
 * survey's winner), the lineage solver does, so its blocks - and the per-block predicates and stage selection that follow them - are
 * the ones it always had.
 */
#define KGENOME_CFG_F_SPLIT_EXITS 1u
/* x86: an `int3` or `hlt` right after a call ends the path, as a `ud2` does. It is the compiler's mark that the call does not return (MSVC puts one after every call it knows is
 * noreturn: the exit of the function is the call), so the code after it is not the next instruction of this path. Whether it applies is the CALLER's knowledge of the toolchain
 * (the frame sets it for a PE); the table of the architecture does not say it, because the same bytes are padding in a function that goes on. */
#define KGENOME_CFG_F_TRAP_EXITS  2u

/* The caller's knowledge of a callee, asked once per call or syscall instruction of a reachable block. Returns the identity (0: unresolved)
 * and may set *kind to an enum kgenome_cfg_call_kind; left 0 the lib's own reading stands (indirect, syscall, otherwise DIRECT). */
struct kgenome_cfg_callee_src {
	uint64_t (*id_of)(void *user, uint32_t insn, const struct kgenome_cell_insn *in, uint8_t *kind);
	void *user;
};

/*
 * REACH_INDIRECT: the caller's access to the object's bytes AT AN ARBITRARY VA (cfg_build.c sees only `req->bytes`/`bytes_len`, which the
 * caller already gives it for a DIFFERENT reason (MIPS branch classification) and which is not necessarily VA-addressable - a PE's RVA is not
 * a file offset - so a switch table, which usually sits in a different section from the code, needs the caller's own image/VA map. Mirrors
 * `kgenome_cfg_callee_src` exactly: one callback, NULL = the feature is off (cfg_build.c then never attempts switch resolution at all, so a
 * caller that does not fill this pays nothing and sees nothing different - see enum kgenome_cfg_term, KGENOME_CFG_T_SWITCH).
 *
 * `read_at`: fill `out` with `len` bytes read at address `va`, judged by the CALLER to be inside bytes it considers part of the object (its
 * image, not necessarily "executable" - a jump table lives in rodata). Returns 1 on a full, trusted read; 0 otherwise (unmapped, short, or the
 * caller does not want to vouch for it) - kgenome_cfg_build treats 0 exactly like an out-of-range table entry (rule 4: stop, record why).
 */
struct kgenome_cfg_switch_src {
	int (*read_at)(void *user, uint64_t va, void *out, uint32_t len);
	void *user;
};

struct kgenome_cfg_req {
	const struct kgenome_cell_insn *in;     /* decoded by the caller, strictly increasing at_va */
	uint32_t n_in;
	unsigned arch;                          /* enum kgenome_arch; no table row for it: UNSUPPORTED */
	int      be;                            /* big-endian code */
	uint64_t va_lo, va_hi;                  /* the function's extent: a target outside it leaves the function */
	/*
	 * THE OBJECT BYTES `in[i].at` INDEXES - today only KGENOME_CFG_F_TRAP_EXITS reads them (the literal
	 * 0xcc/0xf4 of a one-byte int3/hlt right after a CALL). MIPS used to need them too, to tell `b` (beq
	 * r,r) from a genuine conditional branch, because the decoder gave a branch no registers (CS-4, fixed);
	 * the decoder now does, so NULL costs a MIPS caller nothing. NULL with TRAP_EXITS set simply never
	 * finds the mark; nothing is TRUNCATED on that account alone.
	 */
	const uint8_t *bytes;
	uint64_t       bytes_len;
	const uint8_t *site;                    /* optional, n_in bytes: non-zero = a diagnose site at this instruction */
	int      cut;                           /* the caller's decode stopped before the extent's end: status TRUNCATED */
	unsigned flags;                         /* KGENOME_CFG_F_* */
	struct kgenome_cfg_callee_src callee;   /* optional: identities of callees; NULL id_of = every call unresolved */
	struct kgenome_cfg_switch_src switch_src; /* optional (REACH_INDIRECT): NULL read_at = no switch resolution attempted, ever (additive, see above) */
	struct kgenome_budget *budget;          /* optional; max_bytes bounds this call */
	struct kgenome_cfg_mem mem;
};

struct kgenome_cfg {
	struct kgenome_cfg_block *b;            /* n_all blocks in layout order */
	uint32_t n_all;                         /* every block */
	uint32_t n_blk;                         /* reachable blocks */
	uint32_t n_edge;                        /* edges between reachable blocks */
	uint32_t n_site;                        /* instructions of reachable blocks marked by `site` */
	uint32_t n_sys;                         /* syscall instructions of reachable blocks */
	struct kgenome_cfg_call *call;          /* the calls and syscalls of reachable blocks, in instruction order (NULL when there are none) */
	uint32_t n_call;                        /* entries in `call` */
	uint32_t call_cap_;                     /* private: entries allocated */
	/* REACH_INDIRECT: resolved switch targets, instruction indices, in the order found (table order), sliced per block by
	 * kgenome_cfg_block.switch_first/n_switch exactly as `call` is by call_first/n_call. NULL when `req->switch_src.read_at` was NULL or no
	 * switch resolved: a caller that did not ask pays nothing and sees nothing (see enum kgenome_cfg_term, KGENOME_CFG_T_SWITCH). */
	uint32_t *switch_tgt;
	uint32_t n_switch_tgt;                  /* entries in `switch_tgt` */
	uint32_t switch_cap_;                   /* private: entries allocated */
	enum kgenome_status status;
};

/* Build the graph of `req->in`. The result is zeroed first, so it is always safe to free. Returns out->status. */
enum kgenome_status kgenome_cfg_build(const struct kgenome_cfg_req *req, struct kgenome_cfg *out);
void kgenome_cfg_free(struct kgenome_cfg *g, const struct kgenome_cfg_mem *mem);

/* ---- the signature ---- */

/* What a signature is made of. 0 = STRUCT, the measured result (cfg_decision.md); CALLEES scores the callees' identities alone (a diagnose that
 * declares a lineage-like relation wants these), BOTH makes the two, scored apart (kgenome_cfg_pct, kgenome_cfg_pct_callee). */
#define KGENOME_CFG_P_STRUCT  1u
#define KGENOME_CFG_P_CALLEES 2u
#define KGENOME_CFG_P_BOTH    3u

struct kgenome_cfg_sign_req {
	const struct kgenome_cfg *g;
	unsigned policy;                        /* KGENOME_CFG_P_*; 0 = STRUCT */
	uint8_t  rounds;                        /* Weisfeiler-Lehman rounds; 0 = 1 (the measured choice), at most KGENOME_CFG_ROUNDS_MAX */
	uint64_t *label;                        /* optional, g->n_all entries: the final label of each reachable block (0 for the others) */
	struct kgenome_budget *budget;
	struct kgenome_cfg_mem mem;
};

struct kgenome_cfg_sign {
	uint64_t canon;                         /* 64-bit hash of (n_blk, n_edge, multiset of labels): isomorphic-looking graphs equal */
	uint32_t n_blk;
	uint32_t n_key;                         /* distinct elements held, at most KGENOME_CFG_KEYS, ascending */
	uint32_t key[KGENOME_CFG_KEYS];         /* the bottom-32 sketch of the multiset {(label, k-th occurrence)} */
	/*
	 * THE SECOND SIGNATURE (policy CALLEES or BOTH), over the callees' identities and nothing structural: the multiset of
	 * (kind, identity, k-th occurrence) of the RESOLVED calls (identity != 0) of reachable blocks, the same bottom-32 machinery.
	 * An unresolved call adds nothing and a function with none resolved has n_ckey 0: zeros never match each other.
	 */
	uint64_t ccanon;
	uint32_t n_cid;                         /* resolved calls counted */
	uint32_t n_ckey;
	uint32_t ckey[KGENOME_CFG_KEYS];
	enum kgenome_status status;             /* the worse of the graph's status and this call's */
};

enum kgenome_status kgenome_cfg_sign(const struct kgenome_cfg_sign_req *req, struct kgenome_cfg_sign *out);

/*
 * Estimated Jaccard of the two multisets, 0..100 (floored, never overstated): the matches among the 32 smallest
 * elements of the union. Symmetric; 100 for equal sketches; 0 when either has no element (a function that was
 * not hashed is not "similar" to anything). 100 does not prove equal graphs: `canon` does that.
 */
uint32_t kgenome_cfg_pct(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b);
/*
 * A sketch from keys that came from somewhere else (a block of a pack: up to 128 hashes in the order the source wrote them, maybe repeating): the distinct
 * values ascending, the 32 smallest. `out` is zeroed first; only `key` and `n_key` are set. The one place that turns a pack's list into something kgenome_cfg_pct
 * and kgenome_cfg_overlap can read, which need ascending, distinct keys.
 */
void kgenome_cfg_keys_sign(struct kgenome_cfg_sign *out, const uint32_t *key, uint32_t n);

/* The two numbers kgenome_cfg_pct is the ratio of (pct = floor(100 * hit / taken)): the matches among the `taken` smallest elements of the union. 0 and 0 when either has no element. */
void kgenome_cfg_overlap(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b, uint32_t *hit, uint32_t *taken);
/* The same over the callee sketch (`ckey`): 0..100, symmetric, 0 when either function has no resolved callee. */
uint32_t kgenome_cfg_pct_callee(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b);

/* ---- the anchor: is the function worth hashing ---- */

#define KGENOME_CFG_ANCHOR_SYS  1u      /* also pass a function that contains a syscall instruction */
#define KGENOME_CFG_ANCHOR_SITE 2u      /* also pass a function that contains a diagnose site */
#define KGENOME_CFG_ANCHOR_CALLEES 4u   /* also pass a function that calls EVERY identity of `need` (needs n_need > 0; 0 never matches) */

struct kgenome_cfg_anchor_req {
	uint32_t min_blk;                       /* reachable blocks; 0 = KGENOME_CFG_ANCHOR_MIN */
	uint32_t or_flags;                      /* KGENOME_CFG_ANCHOR_* */
	const uint64_t *need;                   /* identities a function must call, for KGENOME_CFG_ANCHOR_CALLEES */
	uint32_t n_need;
};

/* 1 when the function passes. A graph whose status is not OK is judged on what it holds: the caller reads the status. */
int kgenome_cfg_anchor(const struct kgenome_cfg *g, const struct kgenome_cfg_anchor_req *req);

/* ---- what a viewer draws (the viewer computes nothing) ---- */

struct kgenome_cfg_view_block {
	uint64_t off;                           /* offset of the block's first instruction (cell_insn.at) */
	uint32_t n_insn;
	uint8_t  term;                          /* enum kgenome_cfg_term */
	uint32_t succ[2];                       /* indices into THIS table (reachable blocks, layout order) or KGENOME_CFG_NONE */
	uint32_t label;                         /* low 32 bits of the block's final label */
	uint32_t in_deg;                        /* edges into it from reachable blocks */
	uint32_t n_call;                        /* calls and system calls in it */
	uint8_t  out_deg;
	uint8_t  call_kinds;                    /* bit (1 << enum kgenome_cfg_call_kind) */
};

/* A block that is in the array and not reachable from the entry (padding, a literal pool, code only a jump table reaches): listed apart, never drawn. */
struct kgenome_cfg_view_unreach {
	uint64_t off;
	uint32_t n_insn;
};

struct kgenome_cfg_view {
	uint32_t n_blk;
	const struct kgenome_cfg_view_block *blk;
	uint32_t n_unr;                         /* blocks of the array that are not reachable */
	const struct kgenome_cfg_view_unreach *unr;
	uint32_t n_edge;                        /* edges between reachable blocks */
	uint64_t canon;
	uint32_t n_key;
	uint32_t key[KGENOME_CFG_KEYS];
	enum kgenome_status status;             /* the dialog says so when it is TRUNCATED or OVER_BUDGET */
	size_t   bytes_;                        /* private: what kgenome_cfg_view_free gives back */
};

struct kgenome_cfg_view_req {
	const struct kgenome_cfg *g;
	const struct kgenome_cfg_sign *sign;
	const uint64_t *label;                  /* the `label` array the sign call filled (g->n_all entries) */
	const struct kgenome_cell_insn *in;     /* the array the graph was built from */
	struct kgenome_budget *budget;
	struct kgenome_cfg_mem mem;
};

enum kgenome_status kgenome_cfg_view_make(const struct kgenome_cfg_view_req *req, struct kgenome_cfg_view *out);
void kgenome_cfg_view_free(struct kgenome_cfg_view *v, const struct kgenome_cfg_mem *mem);

/*
 * THE VIEW AS A GRAPH TO LOOK AT. The type is the generic one (gview.h): this function FILLS it from a view - the reachable blocks as nodes
 * (`B<n> 0x<off> n_insn=<k> <term>` and `in= out= call= #<label>`, and the block's call count as the node's `xtotal`), the edges with the kinds T taken /
 * F fall-through / J jump and their letters, the unreachable blocks as the aside, a head that carries the signature (the function's own lines first,
 * then the counts, the canonical hash, the keys, the anchor with its numbers) - and the notes and the extra box lines the caller will fill (`n_note`,
 * `n_xline` zeroed entries). It composes the words and decides nothing about places (the viewer's kv_graph.c does): a lineage filler is the same shape
 * with other nodes and other kinds.
 */
struct kgenome_gv;

struct kgenome_cfg_gv_req {
	const struct kgenome_cfg_view *v;
	const char *title[2];                   /* optional lines that open the head (the function's name and extent: the caller's words) */
	uint32_t max_keys;                      /* keys listed in the head; 0 = 16 (at most KGENOME_CFG_KEYS) */
	uint32_t anchor_min;                    /* the anchor's block count for the anchor line; 0 = KGENOME_CFG_ANCHOR_MIN */
	uint32_t n_note;                        /* zeroed note entries to allocate for the caller to fill */
	uint32_t n_xline;                       /* zeroed extra box lines to allocate for the caller to fill (sorted by node) */
	struct kgenome_budget *budget;
	struct kgenome_cfg_mem mem;
};

/* Fill `out` (release with kgenome_gv_free and the same allocator). Returns out->status: the view's, worse of OVER_BUDGET / NOMEM / BAD_INPUT when nothing was made. */
enum kgenome_status kgenome_cfg_gv_make(const struct kgenome_cfg_gv_req *req, struct kgenome_gv *out);

#endif /* KGENOME_CFG_H */
