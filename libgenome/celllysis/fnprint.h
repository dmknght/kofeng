/*
 * fnprint.h - the functions of an object that BELONG TO THE EVIDENCE, decided
 * while the object is read, and what they are worth as a similarity.
 *
 * PROTOTYPE, AND A SEPARATE PRODUCT. Nothing in the scan path calls this: it is
 * the function-level counterpart of the block similarity (mutation.h) built to
 * be measured beside it. The block similarity freezes a lib/user decision into
 * every block at generate time and the scanner recomputes it with a heuristic
 * that depends on the engine version; the span lists that carry it are capped
 * and silent when they fill. Here the decision is taken at SCAN time, one
 * function at a time, from the function's own bytes and a few scalars.
 *
 * ONE PASS, ONE DECODE, BOUNDED MEMORY. kgenome_fnprint_walk iterates the
 * object's function set (the one set kgenome_funcs_build produces, remapped for a
 * view) once. For each function it decodes the bytes once, fingerprints the
 * instruction sequence, decides AUTHOR / LIB / UNKNOWN with the reason, hands the
 * record to the caller's visitor and forgets it. What it holds between functions
 * is a handful of scalars (struct kgenome_fnprint_state): the memory of a walk
 * does not grow with the number of functions or with the size of the object.
 * The caller's accumulators (a per-reference hit table, the matcher's
 * per-block counters) are the caller's and are charged to a kgenome_ledger.
 *
 * A FINGERPRINT depends on the function's bytes and nothing else: the
 * instruction sequence with operands normalised so that where the function sits,
 * what it is linked against and which register the allocator chose for an
 * absolute address do not change it - see fnprint_token.c for the exact table.
 * `fp` keeps registers and small immediates; `fw` is the opcode-class sequence
 * only and survives a changed register allocation or constant.
 *
 * RELEVANCE uses the function's own signals (a library name, membership of a
 * known-library fingerprint table, a syscall wrapper, a thunk, size), two scalars
 * of state - the function the entry stub hands to the C runtime as `main` and the
 * address where library code is first seen after it (the frontier; a static link
 * puts the runtime's start, the target of the entry's call, there at the latest) -
 * and, for the stretch between the entry and the frontier, the CALL GRAPH from
 * main: who reaches whom decides what the layout cannot (the crtbegin helpers and
 * libc-start's own static functions lie between the entry and the program's
 * code, and behind it). That stretch is HELD until it is decided (fnprint_reach.c);
 * what is held is bounded by the stretch, charged to the ledger, and reported when
 * it does not fit. The rules and their blind spots are written where they are
 * (fnprint_rel.c, fnprint_reach.c) and measured in fnprint_gcc_eval.md.
 *
 * CODE THE SET DID NOT ENTER. When the caller says the extents are runs from one
 * entry to the next (KGENOME_FNP_EXT_ENTRY_WALK), the code left after a body's
 * first terminal is read as functions of its own; main is cut out of any extent
 * that holds it. Pieces carry KGENOME_FNP_R_SPLIT and are not in n_funcs.
 *
 * NO SILENT LIMIT. A budget that fires sets the status of the walk's stat and
 * counts what was not visited; nothing is dropped without a number.
 */
#ifndef KGENOME_FNPRINT_H
#define KGENOME_FNPRINT_H

#include <stdint.h>

#include "../kgenome_status.h"
#include "../kgenome_budget.h"
#include <genotype/image/funcs.h>
#include "celllysis.h"
#include "mutation.h"

enum kgenome_fnprint_class {
	KGENOME_FNP_UNKNOWN = 0,    /* kept, weighted low, and said so */
	KGENOME_FNP_AUTHOR,
	KGENOME_FNP_LIB
};

enum kgenome_fnprint_link {
	KGENOME_FNP_LINK_UNKNOWN = 0,   /* not told: no function is called author without evidence */
	KGENOME_FNP_LINK_DYNAMIC,       /* has an interpreter: a library function is not in the file */
	KGENOME_FNP_LINK_STATIC
};

/* WHY a function has its class: bits, several may hold. */
#define KGENOME_FNP_R_NAME_LIB     (1u << 0)   /* symbol says library */
#define KGENOME_FNP_R_NAME_AUTHOR  (1u << 1)   /* symbol says not library */
#define KGENOME_FNP_R_LIBDB        (1u << 2)   /* fingerprint is in the known-library table */
#define KGENOME_FNP_R_THUNK        (1u << 3)   /* a few instructions ending in a jump/ret */
#define KGENOME_FNP_R_WRAPPER      (1u << 4)   /* small, holds a kernel entry: a syscall wrapper */
#define KGENOME_FNP_R_STARTUP      (1u << 5)   /* the entry function itself */
#define KGENOME_FNP_R_BELOW        (1u << 6)   /* between main's neighbourhood and the frontier */
#define KGENOME_FNP_R_BEYOND       (1u << 7)   /* past the frontier: library territory */
#define KGENOME_FNP_R_NO_FRONTIER  (1u << 8)   /* static, no frontier seen: cannot say author */
#define KGENOME_FNP_R_NO_MAIN      (1u << 9)   /* static, the entry stub names no main */
#define KGENOME_FNP_R_TINY         (1u << 10)  /* under the size floor: weight 0 */
#define KGENOME_FNP_R_BAD          (1u << 11)  /* extent is bogus: zero, out of range, overflow */
#define KGENOME_FNP_R_HUGE         (1u << 12)  /* longer than opt.huge_len */
#define KGENOME_FNP_R_OVERLAP      (1u << 13)  /* starts inside the previous function */
#define KGENOME_FNP_R_UNDECODED    (1u << 14)  /* mostly bytes that do not decode */
#define KGENOME_FNP_R_DYNAMIC      (1u << 15)  /* dynamic object: author by link kind */
#define KGENOME_FNP_R_DIAG         (1u << 16)  /* holds a diagnose node the caller named */
#define KGENOME_FNP_R_PRE_SEED     (1u << 17)  /* a library seed after main, frontier not yet latched */
#define KGENOME_FNP_R_PRE_ENTRY    (1u << 18)  /* static: before the entry stub, and not main: startup groups of the libraries */
#define KGENOME_FNP_R_MAIN         (1u << 19)  /* the function the entry stub hands to the runtime */
#define KGENOME_FNP_R_SPLIT        (1u << 20)  /* a piece of a listed extent: code the set did not enter (see fnprint_walk.c) */
#define KGENOME_FNP_R_LIB_START    (1u << 21)  /* at or past the function the entry stub calls last: the runtime's own start */
#define KGENOME_FNP_R_REACHED      (1u << 22)  /* a direct call, jump or address-of chain from main reaches it */
#define KGENOME_FNP_R_ISLAND       (1u << 23)  /* not reached, but between two reached functions: the program's own */
#define KGENOME_FNP_R_ZEROES       (1u << 25)  /* a quarter of its instructions are `add [rax],al`: zero bytes, not code */
#define KGENOME_FNP_R_UNREACHED    (1u << 24)  /* between the entry and the program's code, or behind it: startup code */

struct kgenome_fnprint_fn {
	uint64_t off, len;
	uint64_t body_len;              /* what was read: the extent up to the first terminal (the rest is the tail) */
	uint64_t fp, fw;
	uint32_t n_insn, n_bad, n_call, n_branch, n_syscall;
	uint32_t n_zero;                /* `add [rax],al` (bytes 00 00): what zero bytes decode to; code has almost none */
	uint32_t reason;
	uint32_t index;                 /* position in the caller's function set */
	uint32_t weight;                /* what it adds to a signature */
	uint8_t  cls;                   /* enum kgenome_fnprint_class */
	uint8_t  last_op;               /* class of its last instruction */
};

/* The name of function `i` of the set: 0 unknown, 1 library, 2 not library. */
typedef int (*kgenome_fnprint_name_fn)(void *user, uint32_t i);
/* A tag for a direct call or jump that leaves the function and lands at file
 * offset `to` (an import's name, say); 0 when there is none. */
typedef uint64_t (*kgenome_fnprint_ext_fn)(void *user, uint64_t to);
/* One function, valid until the call returns. Non-zero stops the walk. */
typedef int (*kgenome_fnprint_visit_fn)(void *user, const struct kgenome_fnprint_fn *f);

struct kgenome_fnprint_hints {
	kgenome_fnprint_name_fn name;  void *name_user;
	kgenome_fnprint_ext_fn  ext;   void *ext_user;
	/* Fingerprints known to be library code, ascending. */
	const uint64_t *lib_fp;        uint32_t n_lib_fp;
	/*
	 * File offsets of the diagnose nodes the rule asks about, ASCENDING (the
	 * graph is the engine's product, borrowed and not charged here; a list that
	 * is not ascending is refused with KGENOME_BAD_INPUT and no node is used).
	 */
	const uint64_t *node_at;       uint32_t n_node;
};

/* Zero in any field means the default. */
struct kgenome_fnprint_opts {
	uint32_t tiny_insn;     /* under this many instructions: weight 0 (6) */
	uint64_t huge_len;      /* longer than this: flagged (1 MiB) */
	uint32_t wcap;          /* a function weighs at most this many instructions (256) */
	uint32_t w_author;      /* percent of its size an AUTHOR function weighs (100) */
	uint32_t w_unknown;     /* ...an UNKNOWN one (25) */
	uint32_t w_lib;         /* ...a LIB one (0) */
	uint32_t seeds_latch;   /* library seeds after main before the frontier latches (3) */
	uint32_t wrapper_insn;  /* a function this small holding a kernel entry is a wrapper (48) */
	uint32_t thunk_insn;    /* a function this small, no call, ending in a jump (3) */
	uint32_t region_max;    /* functions held at once for the reachability decision (262144) */
	/* Ablation: the rules added for gcc-built objects, off one by one so the
	 * measurement can say what each one is worth. Zero is "all on". */
	uint32_t off;           /* KGENOME_FNP_OFF_* bits */
};

#define KGENOME_FNP_OFF_SPLIT_TAILS  (1u << 0)  /* do not read code left after a body's first terminal */
#define KGENOME_FNP_OFF_SPLIT_MAIN   (1u << 1)  /* do not cut an extent at main */
#define KGENOME_FNP_OFF_ENTRY_ORDER  (1u << 2)  /* no PRE_ENTRY / LIB_START / MAIN rules */
#define KGENOME_FNP_OFF_THUNK_RET    (1u << 3)  /* a tiny function ending in ret is a thunk on x86-64 too (the old rule) */
#define KGENOME_FNP_OFF_REACH        (1u << 4)  /* no reachability from main (the frontier / entry order rules alone) */

enum kgenome_fnprint_pick {
	KGENOME_FNP_PICK_AUTHOR = 1,      /* units are the AUTHOR functions */
	KGENOME_FNP_PICK_UNKNOWN = 2,     /* ...plus the UNKNOWN ones */
	KGENOME_FNP_PICK_DIAG = 4,        /* only functions holding a node; replaces the class pick */
	/*
	 * EVERY BYTE, SIDED AT CREDIT TIME: the rule recorded for the block
	 * similarity (hash continuously, decide the side only for scoring). All
	 * functions are units - a LIB one on the LIB side, the others on the USER
	 * side - and so are the bytes between functions and the margins [lo, hi)
	 * (USER: nothing attributes them). No byte is left out because of a label.
	 */
	KGENOME_FNP_PICK_SIDED = 8
};

/*
 * THE UNITS, STREAMED. Selected functions that are within `gap` bytes of each
 * other are one unit [off, len) of the object, handed to `fn` the moment the
 * next function does not extend it. Same callback as kgenome_mutation_units,
 * so what is credited is the object's own bytes through the existing matcher;
 * `first` is always NULL. `side` is USER except in KGENOME_FNP_PICK_SIDED, where a
 * function the walk decided is LIB is offered on the LIB side.
 */
struct kgenome_fnprint_units {
	kgenome_mutation_unit_fn fn;
	void                    *user;
	uint32_t                 pick;      /* enum kgenome_fnprint_pick bits; 0: none */
	uint32_t                 gap;       /* 32 when 0; the largest hole a unit spans */
	uint64_t                 lo, hi;    /* SIDED: the extent the pass covers (0,0: between functions only) */
};

/* The counters of a walk: what it saw, what it decided, whether it finished. */
struct kgenome_fnprint_stat {
	enum kgenome_status status;
	uint32_t n_funcs;               /* in the set */
	uint32_t n_visited;
	uint32_t n_skipped;             /* not reached: budget or visitor stop */
	uint32_t n_author, n_lib, n_unknown;
	uint32_t n_bad, n_overlap, n_huge, n_unsorted;
	uint32_t n_split;               /* pieces cut from listed extents (not in n_funcs / n_visited) */
	uint32_t n_region;              /* functions held for the reachability decision (the most at once: region_peak) */
	uint32_t n_reached, n_island;
	uint32_t region_peak;
	uint32_t n_region_over;         /* decided without reachability: the region or its edges did not fit */
	uint32_t n_units, n_unit_funcs;
	uint64_t n_insn;                /* decoded */
	uint64_t unit_bytes;
	uint64_t main_off;              /* KGENOME_BROKEN: none found */
	uint64_t frontier_off;          /* KGENOME_BROKEN: none latched */
	uint64_t scratch_bytes;         /* what the walk charged to the ledger */
};

/*
 * WHERE THE EXTENTS COME FROM. A symbol (or a table like .pdata) states where a function ends: the bytes
 * after its first return belong to it (the blocks behind a jump table, an asm function's second exit).
 * An entry walk states only where a function starts: its extent runs to the next entry it found, and
 * whatever lies between is in the tail. The walk cuts the code it finds in a tail - only in extents
 * the caller says are such runs; with no word, nothing is cut.
 */
enum kgenome_fnprint_extents {
	KGENOME_FNP_EXT_UNKNOWN = 0,    /* not told: the extents are taken as they are */
	KGENOME_FNP_EXT_SIZED,          /* the producer stated the size (symbols, .pdata) */
	KGENOME_FNP_EXT_ENTRY_WALK      /* from one entry to the next: may hold unentered functions */
};

struct kgenome_fnprint_req {
	const uint8_t *p;
	uint64_t       n;
	unsigned       arch;
	int            be;
	const struct kgenome_cell_space *space;  /* NULL: va == file offset */
	const struct kgenome_func_set   *funcs;
	uint64_t       entry_off;                /* KGENOME_BROKEN: none */
	/*
	 * The end of the last code SECTION (file offset), when the object has section headers; 0 or
	 * KGENOME_BROKEN: not known. An entry walk runs its last extent to the end of the code SEGMENT, and a
	 * segment may carry data behind the code (.rodata, .eh_frame, relocation entries in a layout with
	 * no separate code segment): with the section end known the last extent is cut there and its tail
	 * is read; without it the last extent's tail is not read.
	 */
	uint64_t       code_end;
	enum kgenome_fnprint_link link;
	enum kgenome_fnprint_extents extents;
	struct kgenome_fnprint_hints hint;
	struct kgenome_fnprint_opts  opt;
	const struct kgenome_budget *budget;     /* NULL: defaults for n */
	struct kgenome_ledger       *led;        /* NULL: not charged */
	kgenome_fnprint_visit_fn     visit;      /* may be NULL */
	void                        *user;
	struct kgenome_fnprint_units units;      /* .fn NULL: no units */
	struct kgenome_fnprint_stat *stat;       /* required */
};

/* The single pass. Always fills rq->stat. */
void kgenome_fnprint_walk(const struct kgenome_fnprint_req *rq);

/* Is the set ascending by offset? O(n) time, O(1) memory. The walk's relevance
 * rules read address order; an unsorted set is counted in stat.n_unsorted. */
int kgenome_fnprint_sorted(const struct kgenome_func_set *s);

/*
 * THE "COLLECT EVERYTHING FIRST" VARIANT, kept as the reference the streaming
 * pass is tested against and as the way to build a signature. It allocates one
 * record per function (charged to the ledger; over the allowance it stops and
 * says KGENOME_OVER_BUDGET) - the growth the streaming walk does not have.
 */
struct kgenome_fnprint_set {
	struct kgenome_fnprint_fn *fn;
	uint32_t n;
	uint64_t bytes;                 /* charged */
	struct kgenome_fnprint_stat stat;
};
void kgenome_fnprint_collect(const struct kgenome_fnprint_req *rq,
			     struct kgenome_fnprint_set *out);
void kgenome_fnprint_set_free(struct kgenome_fnprint_set *s, struct kgenome_ledger *led);

/*
 * EXACT VERIFICATION of two functions a fingerprint says are equal: the
 * normalised instruction streams compared token by token, no hash. Returns 1
 * equal, 0 different. The collision test of a 64-bit hash.
 */
int kgenome_fnprint_equal(const struct kgenome_fnprint_req *a, const struct kgenome_fnprint_fn *fa,
			  const struct kgenome_fnprint_req *b, const struct kgenome_fnprint_fn *fb);

/*
 * ---- THE SIGNATURE AND THE MATCH ------------------------------------------
 *
 * A reference is a set of distinct fingerprints with weights, ascending by
 * `fp`: what a rule would carry. An object is matched against it STREAMING:
 * each function the walk visits is looked up and sets a byte in the match's hit
 * table (2 bytes per reference entry, charged); nothing of the object is kept.
 * Containment of the reference in the object is the matched weight over the
 * reference's weight; the table says WHICH entries matched.
 */
struct kgenome_fnprint_ref_ent {
	uint64_t fp, fw;
	uint32_t weight;
	uint32_t mult;                  /* how many functions of the source had this fp */
	uint64_t off, len;              /* a representative, for exact verification */
};

struct kgenome_fnprint_ref {
	struct kgenome_fnprint_ref_ent *e;
	uint32_t n;
	uint32_t *by_weak;              /* indices ordered by fw */
	uint64_t total_w;               /* sum of weights */
	enum kgenome_status status;
};

/* From a collected set: the functions of non-zero weight (a LIB function weighs 0 unless
 * the options say otherwise), one
 * entry per distinct fp (the largest weight stands). */
void kgenome_fnprint_ref_build(const struct kgenome_fnprint_set *s, struct kgenome_fnprint_ref *out);
void kgenome_fnprint_ref_free(struct kgenome_fnprint_ref *r);

enum { KGENOME_FNP_HIT_NONE = 0, KGENOME_FNP_HIT_STRONG = 1, KGENOME_FNP_HIT_WEAK = 2 };

struct kgenome_fnprint_match {
	const struct kgenome_fnprint_ref *ref;
	uint8_t *hit;                   /* one byte per reference entry */
	/* The reference object's bytes, to verify a strong hit exactly; NULL: trust the hash. */
	const struct kgenome_fnprint_req *verify_ref;
	const struct kgenome_fnprint_req *verify_obj;
	uint64_t strong_w, weak_w;      /* weight of entries hit strongly / only weakly */
	uint32_t n_strong, n_weak;
	uint32_t n_collision;           /* verified unequal: not counted */
	uint32_t n_capped;              /* weak candidates not examined (a run longer than the bound) */
	struct kgenome_ledger *led;
	enum kgenome_status status;
};
int  kgenome_fnprint_match_init(struct kgenome_fnprint_match *m, const struct kgenome_fnprint_ref *r,
				struct kgenome_ledger *led);
void kgenome_fnprint_match_done(struct kgenome_fnprint_match *m);
/* One function of the object being matched. Usable as a visitor's body. */
void kgenome_fnprint_match_feed(struct kgenome_fnprint_match *m, const struct kgenome_fnprint_fn *f);
/* Weighted containment of the reference, in per mille: strong only, and with weak at half. */
uint32_t kgenome_fnprint_match_strong_pm(const struct kgenome_fnprint_match *m);
uint32_t kgenome_fnprint_match_any_pm(const struct kgenome_fnprint_match *m);

/* Visitor adapter: user is a struct kgenome_fnprint_match *. */
int kgenome_fnprint_match_visit(void *user, const struct kgenome_fnprint_fn *f);

#endif /* KGENOME_FNPRINT_H */
