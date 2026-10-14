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
 * RELEVANCE, AND WHAT MAY TAKE CODE OUT OF THE EVIDENCE. The evidence is every function (and every window)
 * except what the object's own BYTES prove is library: a fingerprint in the known-library table, or most
 * of the function's windows in the known-library window table (fnprint_libtab.c, built from library bytes).
 * Everything else the rules can say - a symbol's name, a marker string, the layout (the entry stub, the
 * frontier, the order of the link), reachability from main, a thunk's or a wrapper's shape, a size - is
 * ADVICE: it orders work and explains a report (f->advice, R_ADVISED), and the function stays UNKNOWN,
 * kept and counted (stat.n_advised). Reason: an author who patches the file (renames a function, strips
 * it, rewrites a string, relinks in another order, puts his code behind a libc-looking prologue)
 * changes every one of those signals and none of his function's bytes; a filter that excludes on them
 * creates blind spots an adversary steers (fnprint_adv_names.c, fnprint_adv_stream.c; the scan path's
 * own trueline tiers are pinned as known misses in tests/unit/fnprint_adv_trueline.c). The old
 * behaviour is kept behind KGENOME_FNP_OPT_LEGACY_EXCLUDE so the measurements of the rules in
 * fnprint_gcc_eval.md stay reproducible. Two scalars of state - the function the entry stub hands to the
 * C runtime as `main` and the address where library code is first seen after it (the frontier) - and the
 * CALL GRAPH from main still decide the ADVICE for the stretch between the entry and the frontier
 * (fnprint_reach.c); what is held there is bounded by the stretch, charged to the ledger, and reported
 * when it does not fit.
 *
 * THE WINDOW STREAM (fnprint_wdb.c) is the same idea one level down and without a decode: one rolling
 * pass over the code bytes, each window credited to the LIB side if it is in the library window table and
 * to the USER side otherwise, against a database of blocks. It is the cheaper path (no second decode,
 * fnprint_pred_eval.md) and it cannot be steered by anything but the bytes.
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
#define KGENOME_FNP_R_ADVISED      (1u << 26)  /* a rule that reads a name, layout or shape said LIB: advice, the function stays UNKNOWN (see advice) */
#define KGENOME_FNP_R_LIBWIN       (1u << 27)  /* most of its windows are in the known-library window table: library BYTES */

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
	/*
	 * ADVICE: what the rules an adversary can steer (a name, the layout, the entry stub's shape,
	 * size, a raw kernel entry) say. It orders work and explains a report; it never removes a
	 * function from the evidence: cls is LIB only on grounds of the function's own bytes
	 * (R_LIBDB, R_LIBWIN) unless the caller asks for the legacy behaviour (OPT_LEGACY_EXCLUDE).
	 */
	uint8_t  advice;                /* enum kgenome_fnprint_class */
	uint32_t n_win, n_win_lib;      /* non-flat windows of the body, and how many are in the library table (0,0: no table) */
};

struct kgenome_fnprint_libtab;

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
	/* Windows of known library BYTES (built from bytes, never from names): a function most of
	 * whose windows are in it is LIB by its own content. NULL: none. */
	const struct kgenome_fnprint_libtab *libtab;
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
	uint32_t flags;         /* KGENOME_FNP_OPT_* bits */
	uint32_t libwin_pct;    /* percent of a function's windows that must be in the library table (60) */
	uint32_t libwin_min;    /* ...and at least this many windows must be known (8): a stub proves nothing */
	uint32_t w_advised;     /* percent of its size an UNKNOWN function the advice calls LIB weighs (25) */
};

/*
 * THE LEGACY BEHAVIOUR: a name, the layout, the entry stub, a syscall wrapper or a thunk may call a
 * function LIB and so take it out of the evidence. Kept so the measurements of the rules stay
 * reproducible (fnprint_gcc_eval.md); not the default, because every one of those grounds can be
 * flipped by an author who patches the file without changing the function's bytes (see
 * docs and fnprint_adv_*.c).
 */
#define KGENOME_FNP_OPT_LEGACY_EXCLUDE (1u << 0)

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
	uint32_t n_advised;             /* UNKNOWN functions a name, the layout or a shape called library: kept, weighed at w_advised */
	uint32_t n_libwin;              /* functions library by their own windows */
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

/*
 * ---- KNOWN-LIBRARY WINDOWS: the one exclusion ground that is made of bytes ---------------------
 *
 * A table of window values (the same 8-byte rolling window, mixed, that the block similarity
 * hashes: mutation_window.h) taken from the BYTES of library code. A window in it is library by its
 * content; an author cannot put a window in it without writing library bytes, and a payload placed
 * inside a library function keeps its own windows out of the table, so it stays evidence. Names,
 * markers, layout and shape are not consulted. [Inference] windows that cover a relocated field
 * (a rel32 whose value depends on the link) differ between two links, so the table recognises the
 * part of the library the relocations do not touch; fnprint_pred_eval.md measures how much.
 *
 * `sel_bits`: keep and ask only the windows whose mixed value has its low `sel_bits` bits zero
 * (1 in 2^sel_bits): a smaller table, and a vote instead of a verdict per window.
 * NO SILENT LIMIT: the table grows by doubling, charged to the ledger; an add the ledger refuses is
 * counted (n_refused) and the table says KGENOME_OVER_BUDGET: it is then INCOMPLETE (a miss is not
 * proof of "not library") and the caller is told so.
 */
struct kgenome_fnprint_libtab {
	uint32_t *slot;                 /* open addressing; 0 is empty (a value 0 is stored as 1) */
	uint64_t  cap;                  /* power of two, or 0 */
	uint64_t  n;                    /* distinct values held */
	uint64_t  n_seen;               /* windows offered to add */
	uint64_t  n_refused;            /* values that did not fit: the table is incomplete */
	uint64_t  bytes;                /* charged to the ledger */
	uint32_t  sel_bits;
	enum kgenome_status status;
	struct kgenome_ledger *led;     /* may be NULL */
};

int  kgenome_fnprint_libtab_init(struct kgenome_fnprint_libtab *t, uint32_t sel_bits, struct kgenome_ledger *led);
void kgenome_fnprint_libtab_free(struct kgenome_fnprint_libtab *t);
/* Add the windows of library bytes p[0,n) (flat windows are not content and are left out). */
void kgenome_fnprint_libtab_add(struct kgenome_fnprint_libtab *t, const uint8_t *p, uint64_t n);
/* Add one window value (a table loaded from a list, or mined from a corpus); 1 when held, 0 when not sampled or refused. */
int  kgenome_fnprint_libtab_put(struct kgenome_fnprint_libtab *t, uint32_t v);
/* Does the table keep this value (a sampled one)? */
int  kgenome_fnprint_libtab_sampled(const struct kgenome_fnprint_libtab *t, uint32_t v);
/* Is this value in the table? 0 for a value the table does not sample. */
int  kgenome_fnprint_libtab_has(const struct kgenome_fnprint_libtab *t, uint32_t v);

struct kgenome_fnprint_libvote {
	uint32_t n_win;                 /* non-flat windows of the bytes */
	uint32_t n_sampled;             /* ...of them the table samples */
	uint32_t n_hit;                 /* ...of them in the table */
};
void kgenome_fnprint_libvote(const struct kgenome_fnprint_libtab *t, const uint8_t *p, uint64_t n,
			     struct kgenome_fnprint_libvote *out);

/*
 * THE RELOCATION MASK: bytes in, the same bytes out with every 32-bit displacement that points
 * somewhere inside the object (plus or minus `slack`) zeroed - the rel32 of `call`, `jmp`, `jcc`, and the
 * disp32 of the RIP-relative forms of the common one-byte and `0F xx` opcodes - found by the opcode byte
 * and the plausibility of the target, no decode. WHY: a window that covers such a field holds a number
 * the LINK chose, so the same library function is a different set of windows in every binary (measured
 * in fnprint_pred_eval.md: 5-14% of the library's windows miss the table for that reason, and the
 * residue is exactly what makes library blocks credit across unrelated programs). A displacement that
 * is not an instruction's is masked too (a false mask costs a window of discrimination, the same
 * on both sides of every comparison, because the table, the blocks and the object are all masked by this
 * one function). out == p is allowed (in place). Returns the number of fields masked.
 */
uint64_t kgenome_fnprint_relmask(const uint8_t *p, uint64_t n, uint8_t *out, uint64_t slack);

/*
 * ---- CHEAP PREDICTION WITHOUT DECODING (candidates (b) and (d)) ----------------------------------
 *
 * Statistics of a chunk of bytes, in one pass: is it data? Zero bytes, printable ASCII and the
 * number of distinct byte values among the first 64. Bounded and reported; used as a PRIOR (a
 * caller that skips what it says is data must say so: fnprint_wpass_stat.n_skip_chunks / skip_bytes).
 */
struct kgenome_fnprint_bstat {
	uint32_t n, zero, ascii, hi;    /* bytes, zero bytes, 0x20..0x7e, >= 0x80 */
};
void kgenome_fnprint_bstat(const uint8_t *p, uint32_t n, struct kgenome_fnprint_bstat *out);
int  kgenome_fnprint_bstat_is_data(const struct kgenome_fnprint_bstat *s);

/*
 * THE BYTE-LEVEL CALL-GRAPH SKETCH: edges from `call rel32`, `jmp rel32`, `jcc rel32` and
 * `lea r,[rip+rel32]` found by looking for the opcode bytes whose displacement lands inside the
 * text [lo,hi) - no instruction is decoded. A function is the stretch from a call or lea target to the
 * next one; the closure from `root` marks the stretches a chain of edges reaches. The chain is an
 * approximation (indirect calls, tables and data pointers are not edges; a byte that only looks like
 * an opcode can add one) and it is only a PRIOR: reached means "plausibly the program's or a library
 * function the program calls", never "author", and unreached is never an exclusion.
 */
struct kgenome_fnprint_bsketch {
	uint64_t *start;                /* ascending: candidate function starts (call and lea targets, root) */
	uint32_t  n_start;
	uint64_t *from, *to;            /* edges, ascending by from */
	uint32_t  n_edge;
	uint8_t  *reached;              /* per start */
	uint32_t  n_reached;
	uint64_t  scanned;              /* bytes looked at */
	uint64_t  bytes;                /* charged */
	enum kgenome_status status;
	struct kgenome_ledger *led;
};
void kgenome_fnprint_bsketch_build(struct kgenome_fnprint_bsketch *g, const uint8_t *p, uint64_t lo, uint64_t hi,
				   int64_t va_delta, uint64_t root, struct kgenome_ledger *led);
void kgenome_fnprint_bsketch_free(struct kgenome_fnprint_bsketch *g);
/* The index of the stretch holding `off`, or UINT32_MAX. */
uint32_t kgenome_fnprint_bsketch_find(const struct kgenome_fnprint_bsketch *g, uint64_t off);
/* The entry stub's `main`: the lea/mov of an address into rdi (edi) in the first 160 bytes at `entry`
 * that precedes the stub's first call; KGENOME_BROKEN if the stub has none of that shape. */
uint64_t kgenome_fnprint_bsketch_main(const uint8_t *p, uint64_t n, uint64_t entry, int64_t va_delta, uint64_t lo, uint64_t hi);

/*
 * ---- THE WINDOW STREAM: one rolling pass, no decode --------------------------------------------
 *
 * The database side. A block is `n` hashes (<= KGENOME_FNP_WDB_MAXN) of one side with a tag (the
 * rule or family it belongs to). Built once, read-only afterwards, shared by threads; the mutable
 * counters are a kgenome_fnprint_wctx, one per scan.
 *
 * STRUCTURE (measured against the matcher's sorted pair array in fnprint_pred_eval.md): the hashes
 * sorted, as parallel arrays (key, block, slot), a bucket index over the top bits of the key (one
 * load to the equal range instead of a binary search), a bit filter sized from a bits-per-hash the
 * caller chooses. A run of equal keys is credited once per object per side whatever the number of
 * windows that produce it (a hot key is not quadratic in the number of its windows).
 * NO SILENT LIMIT: a block count or hash count that does not fit the index widths, or the ledger,
 * refuses the build with a status and a count; nothing is truncated.
 */
#define KGENOME_FNP_WDB_MAXN 128u
/* A key held by this many pairs is HOT: its run is walked once per object and side, however many windows repeat it. */
#define KGENOME_FNP_WDB_HOT  32u

struct kgenome_fnprint_wblock {
	uint32_t first;                 /* index of its first hash in the pool */
	uint32_t n;                     /* hashes: 1 .. KGENOME_FNP_WDB_MAXN */
	uint32_t side;                  /* enum kgenome_mutation_side */
	uint32_t tag;                   /* the rule/family it belongs to (< n_tag) */
};

struct kgenome_fnprint_wdb_opts {
	uint32_t filter_bits_per_hash;  /* 32 when 0; 0xFFFFFFFF: no filter */
	uint32_t bucket_bits;           /* 0: from the number of keys (about 4 keys per bucket) */
	uint32_t n_tag;                 /* tags in use (>= 1 + the largest tag) */
	struct kgenome_ledger *led;
};

struct kgenome_fnprint_wdb {
	const struct kgenome_fnprint_wblock *blk;
	const uint32_t *pool;
	uint32_t  n_blk, n_tag;
	uint64_t  n_pair;
	uint32_t *key;                  /* ascending, one per pair */
	uint32_t *ref;                  /* block << 7 | slot of the pair (KGENOME_FNP_WDB_MAXN is 128) */
	uint32_t *bucket;               /* [(top >> shift) + 2]: first pair with key >> shift >= b */
	uint32_t *hot_first;            /* first pair of each key held by KGENOME_FNP_WDB_HOT blocks or more */
	uint32_t  n_hot;
	uint32_t  bucket_bits, shift;
	uint64_t *filter; uint64_t filter_mask;     /* bits - 1 (0: none) */
	uint32_t  words;                /* 32-bit words per block in a context's seen mask */
	uint32_t  top;                  /* the largest key: a value above it is in no block */
	uint64_t  n_key;                /* distinct keys */
	uint64_t  max_run;              /* the longest run of one key: the hottest hash */
	uint64_t *tag_pairs;            /* [n_tag] pairs of each tag */
	uint32_t  filter_bpk;           /* bits per hash the filter was sized with (0xFFFFFFFF: none) */
	uint64_t  bytes;                /* charged */
	enum kgenome_status status;
	struct kgenome_ledger *led;
};

/* A block count the (block << 7 | slot) word holds: 2^25. A larger set is refused, not cut. */
#define KGENOME_FNP_WDB_MAX_BLOCKS (1u << 25)

int  kgenome_fnprint_wdb_build(struct kgenome_fnprint_wdb *d, const struct kgenome_fnprint_wblock *blk, uint32_t n_blk,
			       const uint32_t *pool, uint64_t n_pool, const struct kgenome_fnprint_wdb_opts *o);
void kgenome_fnprint_wdb_free(struct kgenome_fnprint_wdb *d);

/*
 * THE CONTEXT: per-scan counters. A generation stamp per block replaces the clear and a bit per
 * slot replaces a stamp per pair (4 bytes per block instead of 4 per hash). A small direct-mapped
 * cache of (key, generation, sides) makes the repeat of a hot key one load.
 *
 * RETIREMENT (opt-in, default OFF): `kgenome_fnprint_wctx_retire(c, tag)` makes lookups skip the
 * tag's blocks; the filter is rebuilt from the live keys once `rebuild_pct` percent of the pairs
 * went dead. It is a METHOD to measure: a retired tag's credit stops growing, which conflicts with a
 * detection that weighs several evidence items together; nothing retires unless the caller calls it
 * or sets a policy in the pass request.
 */
#define KGENOME_FNP_KC 4096u

struct kgenome_fnprint_kc {
	uint32_t key, tag;              /* tag: generation << 2 | sides done */
};

struct kgenome_fnprint_dxrun;           /* the decision state of one context (fnprint_dx.c) */

struct kgenome_fnprint_wctx {
	const struct kgenome_fnprint_wdb *db;
	uint32_t *stamp;                /* per block: generation of its count */
	uint32_t *count;                /* per block: distinct slots credited */
	uint32_t *mask;                 /* [n_blk * words] */
	struct kgenome_fnprint_kc kc[KGENOME_FNP_KC];
	uint32_t *hstamp;               /* per hot key: generation << 2 | sides done (exact, no collisions) */
	uint8_t  *dead;                 /* per tag: retired */
	uint8_t  *decided;              /* per tag: a block reached decide_pct this object */
	uint32_t  gen, n_dead, n_decided, n_tag_used;   /* n_tag_used: tags that hold at least one block */
	uint32_t  policy, decide_pct;   /* enum kgenome_fnprint_retire_policy; the percent that decides a tag */
	int       stop;                 /* the policy says: stop the pass */
	uint64_t  n_lookup, n_search, n_credit, n_skip_dead, n_hot_repeat, n_dead_pairs, n_rebuild;
	uint64_t  n_walked;             /* pairs examined by the equal-range walks (the cost of a hot key, in pairs) */
	uint64_t  bytes;
	uint64_t *rfilter;              /* the rebuilt filter once retirement shrank the live set (NULL: db's) */
	uint64_t  rfilter_mask;
	uint32_t  rtop;
	uint32_t  rebuild_pct;
	uint64_t  rebuilt_at;           /* n_dead_pairs when the filter was last rebuilt */
	struct kgenome_fnprint_dxrun *dxr;  /* NULL: no decision state (the default) */
	uint8_t  *bdead;                /* dxr's per-block flags: a block no live diagnose wants any more (NULL: none) */
	const uint32_t *dx_need_min;    /* dxr's index: the fewest credited hashes at which any diagnose counts block b (the hot path's one test) */
	uint64_t  n_bdead;
	uint64_t  rem;                  /* DX: windows still to come, as last told (a rebuild of the filter is worth it only when many are) */
	enum kgenome_status status;
	struct kgenome_ledger *led;
};

int  kgenome_fnprint_wctx_init(struct kgenome_fnprint_wctx *c, const struct kgenome_fnprint_wdb *d, struct kgenome_ledger *led);
void kgenome_fnprint_wctx_done(struct kgenome_fnprint_wctx *c);
/* A new object: counters restart and retirement is per object, so it is cleared here. */
void kgenome_fnprint_wctx_begin(struct kgenome_fnprint_wctx *c);
/* Credit one window value to the live blocks of this side that hold it. */
void kgenome_fnprint_wctx_credit(struct kgenome_fnprint_wctx *c, uint32_t v, uint32_t side);
/* Distinct hashes of block b credited this object. */
uint32_t kgenome_fnprint_wctx_count(const struct kgenome_fnprint_wctx *c, uint32_t b);
/* Retire a tag (opt-in): its blocks are no longer looked up. */
void kgenome_fnprint_wctx_retire(struct kgenome_fnprint_wctx *c, uint32_t tag, uint32_t rebuild_pct);

/*
 * RETIREMENT POLICIES. NONE and DX are the ones a scan may use. TAG, TAG_STOP and
 * STOP_FIRST are FIRST-HIT policies (a tag is dropped, or the pass ends, at the first
 * verdict): they are opt-in prototype code for measuring what stopping early would cost,
 * and they CONFLICT WITH CLUSTER DETECTION - a cluster is read off the whole set of
 * blocks that matched, and a pass that ended at the first tag hides the rest of the set
 * from it. They are not for the default, and the default (NONE) never uses them. The
 * decision-complete policy (DX) is the one that cannot change an answer: it stops only for
 * what is already MET or provably IMPOSSIBLE.
 */
enum kgenome_fnprint_retire_policy {
	KGENOME_FNP_RETIRE_NONE = 0,    /* the default: every tag keeps being evaluated */
	KGENOME_FNP_RETIRE_TAG = 1,     /* a tag whose block reaches `decide_pct` is retired */
	KGENOME_FNP_RETIRE_TAG_STOP = 2,/* ...and the pass stops when every tag is retired (first-verdict policy) */
	KGENOME_FNP_RETIRE_STOP_FIRST = 3,/* the pass stops at the first tag detected */
	/*
	 * DECISION-COMPLETE (needs kgenome_fnprint_dx_attach): work stops for a diagnose only when its
	 * outcome can no longer change - MET (its required blocks already reached their percent) or
	 * IMPOSSIBLE (what is still to be seen cannot reach it) - and the pass stops when every consumer
	 * (a cluster, or a diagnose on its own) is decided. A single hit decides nothing.
	 */
	KGENOME_FNP_RETIRE_DX = 4
};

struct kgenome_fnprint_wpass_stat {
	uint64_t n_win;                 /* windows rolled */
	uint64_t n_cand;                /* passed the cheap rejects (top, filter) */
	uint64_t n_lib;                 /* ...of them in the library table: credited to the LIB side */
	uint64_t n_flat;
	uint64_t n_skip_chunks, skip_bytes;     /* chunks the statistics called data and skipped (opt-in) */
	uint32_t n_bad_ext;             /* ranges that run past rq->n: skipped, the pass is incomplete and says so */
	uint64_t bytes_in;              /* bytes of the ranges given */
	uint64_t n_stop_bytes;          /* bytes not rolled because the policy stopped the pass */
	uint32_t n_decided;             /* tags decided (retirement policies) */
	int      stopped;
	uint64_t n_win_rolled;          /* windows actually rolled (n_win minus what a stop left) */
	uint64_t n_win_unvisited;       /* windows of ranges never started because the pass was already decided */
	enum kgenome_status status;     /* KGENOME_BAD_INPUT: a policy that needs state it was not given */
};

#define KGENOME_FNP_WP_SKIP_DATA   (1u << 0)   /* opt-in: skip chunks the byte statistics call data */

struct kgenome_fnprint_wpass_req {
	const uint8_t *p;
	uint64_t       n;               /* bytes at p: a range that does not fit is skipped and counted (stat.n_bad_ext), never read */
	const struct kof_range *ext;   /* ranges to roll (code segments, units) */
	uint32_t n_ext;
	const struct kgenome_fnprint_libtab *lib;  /* NULL: every window is USER */
	struct kgenome_fnprint_wctx *c;
	uint32_t flags;                 /* KGENOME_FNP_WP_* */
	uint32_t policy;                /* enum kgenome_fnprint_retire_policy; 0 (the default) retires nothing */
	uint32_t decide_pct;            /* a block at this percent of its hashes decides its tag (70) */
	struct kgenome_fnprint_wpass_stat *stat;
};
void kgenome_fnprint_wpass(const struct kgenome_fnprint_wpass_req *rq);

/*
 * UNITS FROM WINDOWS, no decode and no function set: the runs of p[0,n) whose windows are NOT in the
 * library table. A run is closed when more than `gap` consecutive windows are library; a run with fewer
 * than `min_win` non-library windows is dropped (boundary windows of library code: the few windows
 * that straddle the edge of a library function or hold padding are not in any table and are common to
 * every program that links the same library, so a unit made of them would credit across unrelated
 * programs - measured in fnprint_pred_eval.md). Each run is handed to `fn` once, in order; non-zero
 * stops. Returns the number of runs offered; `*dropped` counts the runs under the floor.
 */
typedef int (*kgenome_fnprint_run_fn)(void *user, uint64_t off, uint64_t len, uint32_t n_win);
uint32_t kgenome_fnprint_runs(const uint8_t *p, uint64_t n, const struct kgenome_fnprint_libtab *lib,
			      uint32_t gap, uint32_t min_win, kgenome_fnprint_run_fn fn, void *user, uint32_t *dropped);

/*
 * The block a unit of bytes makes, by the same rule as the generator (kgenome_mutation_minhash):
 * the `k` smallest distinct non-flat window values of p[0,n) that are NOT in the library table.
 * Returns how many (<= k), ascending in out.
 */
uint32_t kgenome_fnprint_wsketch(const uint8_t *p, uint64_t n, const struct kgenome_fnprint_libtab *lib,
				 uint32_t *out, uint32_t k);

/*
 * ---- DECISION-COMPLETE INTERRUPT -------------------------------------------------------------
 *
 * A DIAGNOSE here is the evidence a detection asks the block credit for: a list of blocks of the
 * database, `need` of which must each hold `pct` percent of their hashes. A CLUSTER is a list of
 * diagnoses of which `k` must hold. A consumer (what the engine finally reads) is a cluster; a diagnose
 * that stands alone is a cluster of one (k = n = 1). Credit only grows during a pass, so
 *
 *   diagnose MET        a block count crossed its percent: `need` blocks have. Final: no later window
 *                       can undo it.
 *   diagnose IMPOSSIBLE the blocks not yet at their percent cannot get there: a block with `c` of its
 *                       `n` hashes credited, `m` of them still missing, can gain at most
 *                       min(m, windows_left x dup) more, where dup is the most slots of the block that
 *                       share one value (a window credits all of them at once). With no window left
 *                       (windows_left 0, the end of the pass) every diagnose that is not MET is
 *                       IMPOSSIBLE, so a finished pass decides everything: no outcome is left open.
 *   cluster MET         k members MET.   cluster IMPOSSIBLE   more than n-k members IMPOSSIBLE.
 *
 * What stops, and when. A diagnose that is decided (or that no undecided cluster lists any more: RELEASED)
 * stops taking credit: its blocks are dropped from the lookup once no wanted diagnose lists them (a block may
 * be listed by several), and the filter is rebuilt from the live keys. When every cluster is decided
 * the pass stops. The state, not the growing credit, is what a consumer reads afterwards: a block of a
 * decided diagnose is dropped only when enough windows are still to come for that to pay (at least 16 per
 * pair of the database; `rem`, as the pass or the caller last said it), and a dropped block keeps the count it
 * had, a LOWER BOUND of its credit in the full computation; every other block has its full count unless the
 * pass stopped. A consumer that wants the exact credit (a report that prints the percent) must not turn the
 * policy on.
 * Nothing is dropped on a single hit: a block reaching its percent counts towards `need`, and `need`
 * blocks are what decide. The sweep for IMPOSSIBLE runs when the windows left fall under the largest
 * count any block needs (<= 128): on a clean object nothing is decided before that, so the saving
 * of this interrupt is on the objects that match, never on the ones that do not (stated in
 * fnprint_sel_eval.md).
 */
enum kgenome_fnprint_dstate {
	KGENOME_FNP_D_UNDECIDED = 0,
	KGENOME_FNP_D_MET,
	KGENOME_FNP_D_IMPOSSIBLE,
	KGENOME_FNP_D_RELEASED          /* no undecided cluster lists it: nobody reads it */
};

struct kgenome_fnprint_dx {
	uint32_t first, n;              /* its blocks: ref[first .. first+n) */
	uint32_t need;                  /* blocks that must reach pct (0: met at once) */
	uint32_t pct;                   /* percent of a block's hashes (0: 70) */
};

struct kgenome_fnprint_cl {
	uint32_t first, n;              /* its members: mem[first .. first+n), diagnose indices */
	uint32_t k;                     /* members that must hold (0: held at once) */
};

struct kgenome_fnprint_dxdesc {
	const struct kgenome_fnprint_dx *dx;  uint32_t n_dx;
	const uint32_t *ref;                  uint64_t n_ref;       /* block indices of the wdb */
	const struct kgenome_fnprint_cl *cl;  uint32_t n_cl;        /* NULL: every diagnose is a consumer on its own */
	const uint32_t *mem;                  uint64_t n_mem;
};

/* The read-only index of a description: shared by every context of the database, any number of threads. */
struct kgenome_fnprint_dxdb {
	const struct kgenome_fnprint_wdb *db;
	struct kgenome_fnprint_dxdesc desc;     /* borrowed, except the singleton clusters it makes itself */
	struct kgenome_fnprint_cl *own_cl;
	uint32_t *own_mem;
	uint32_t *rv_first, *rv_dx;             /* block -> the diagnoses that list it, one entry per listing */
	uint32_t *need_min;                     /* per block: the fewest credited hashes at which any diagnose counts it */
	uint8_t  *dup;                          /* per block: the most slots that share one value */
	uint32_t *dxc_first, *dxc_cl;           /* diagnose -> the clusters that list it, one entry per listing */
	uint32_t  trigger;                      /* windows left at or under which IMPOSSIBLE can hold */
	uint64_t  bytes;
	enum kgenome_status status;
	struct kgenome_ledger *led;
};

int  kgenome_fnprint_dxdb_build(struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_wdb *d,
				const struct kgenome_fnprint_dxdesc *desc, struct kgenome_ledger *led);
void kgenome_fnprint_dxdb_free(struct kgenome_fnprint_dxdb *x);

/* Give a context its decision state (before the first wctx_begin; the context's ledger is charged). */
int  kgenome_fnprint_dx_attach(struct kgenome_fnprint_wctx *c, const struct kgenome_fnprint_dxdb *x);
/*
 * At most `remaining` windows can still arrive: the pass calls it after each range, a caller that feeds
 * values itself calls it when it knows (0 = the object is exhausted). Decides what the bound decides.
 */
void kgenome_fnprint_dx_remain(struct kgenome_fnprint_wctx *c, uint64_t remaining);
enum kgenome_fnprint_dstate kgenome_fnprint_dx_state(const struct kgenome_fnprint_wctx *c, uint32_t dx);
enum kgenome_fnprint_dstate kgenome_fnprint_dx_cluster(const struct kgenome_fnprint_wctx *c, uint32_t cl);
/* Clusters still undecided (0: the pass has nothing left to do). */
uint32_t kgenome_fnprint_dx_open(const struct kgenome_fnprint_wctx *c);
/* The reference answer: the outcome of a description from FINAL counts of a run that retired nothing. */
int  kgenome_fnprint_dx_full(const struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_wctx *c, uint32_t cl);

/*
 * ---- WHICH FUNCTIONS ARE ROLLED --------------------------------------------------------------
 *
 * kgenome_fnprint_sel_plan turns the function extents of an object into the ranges a pass rolls, by
 * bytes alone (a name is not evidence). Each policy bit says what it may remove and whether that is exact:
 *
 *   FLAT    a function of one repeated byte, or shorter than a window: every window is flat. EXACT.
 *   DUP     a function whose bytes equal an earlier one's (verified, not trusted to the hash): its
 *           windows are a set already credited. EXACT, and it carries the object's repeated stubs.
 *   TINY    shorter than `tiny` bytes. NOT exact (a block can be cut from a small function).
 *   SAMPLE  none of `k` sampled windows is a key of the database. NOT exact: a window that was not
 *           sampled is not looked at. The skipped windows are counted (n_skip_win) so that the bound
 *           "credit lost <= windows skipped" is stated, and a caller can re-roll the skipped ranges.
 *   ORDER   (exact: it only changes the order) functions whose sample hits rare keys go first.
 *   LIB     most of `k` sampled windows are in the library window table (bytes decide, never a name):
 *           the function is library bytes. NOT exact: the residual windows of a mostly-library
 *           function are not looked at; counted (n_lib) like the others.
 */
#define KGENOME_FNP_SEL_FLAT    (1u << 0)
#define KGENOME_FNP_SEL_DUP     (1u << 1)
#define KGENOME_FNP_SEL_TINY    (1u << 2)
#define KGENOME_FNP_SEL_SAMPLE  (1u << 3)
#define KGENOME_FNP_SEL_ORDER   (1u << 4)
#define KGENOME_FNP_SEL_LIB     (1u << 5)
#define KGENOME_FNP_SEL_EXACT   (KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_ORDER)

struct kgenome_fnprint_sel_stat {
	enum kgenome_status status;
	uint32_t n_in, n_out;
	uint32_t n_bad;                 /* extents outside the object: dropped and counted */
	uint32_t n_flat, n_dup, n_tiny, n_sample, n_lib;        /* removed, by policy */
	uint32_t n_hit;                 /* kept because a sampled window is a key */
	uint64_t win_in, win_out;       /* windows of the extents given / of the ranges returned */
	uint64_t n_probe;               /* sampled windows computed */
	uint64_t bytes_hashed;          /* bytes read to nominate duplicates (at most 48 per function) */
	uint64_t bytes_compared;        /* length of the candidates compared to verify a nomination (an upper bound: a compare stops at the first difference) */
	uint32_t n_dup_cap;             /* functions kept because DUP_TRIES candidates did not match: counted, never silent */
	uint64_t scratch_bytes;
};

struct kgenome_fnprint_sel_req {
	const uint8_t *p;
	uint64_t       n;
	const struct kof_range *fn;     /* the function extents */
	uint32_t       n_fn;
	uint32_t       policy;          /* KGENOME_FNP_SEL_* bits */
	uint32_t       tiny;            /* TINY: bytes under which a function is dropped (64) */
	uint32_t       sample_k;        /* SAMPLE/ORDER: windows probed per function (8) */
	const struct kgenome_fnprint_wdb *db;   /* SAMPLE/ORDER: the keys; NULL: every probe misses */
	const struct kgenome_fnprint_libtab *lib;   /* LIB: the library window table */
	uint32_t       lib_pct;         /* LIB: percent of the probed windows the table must hold (90) */
	uint32_t       lib_min;         /* LIB: probed windows the table must sample at least (8): a stub proves nothing */
	struct kof_range *out;          /* room for n_fn ranges */
	uint32_t        *out_fn;        /* may be NULL: the index in `fn` of each returned range */
	struct kgenome_ledger *led;
	struct kgenome_fnprint_sel_stat *stat;
};
void kgenome_fnprint_sel_plan(const struct kgenome_fnprint_sel_req *rq);

#endif /* KGENOME_FNPRINT_H */
