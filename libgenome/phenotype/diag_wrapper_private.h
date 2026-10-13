/*
 * diag_wrapper_private.h - what the files of the syscall-wrapper analysis share. NOT PART OF THE SURFACE.
 */
#ifndef KGENOME_DIAG_WRAPPER_PRIVATE_H
#define KGENOME_DIAG_WRAPPER_PRIVATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "diag_scan.h"
#include "diag_private.h"
#include <kofcore.h>
#include <kofcmp.h>
#include <celllysis/capability.h>
#include <celllysis/cell.h>
#include <genotype/image/elf_image.h>
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <celllysis/space.h>

/*
 * HOW FAR A WRAPPER MAY SPAN: the length of its FUNCTION - from its entry to the
 * next call target - and never less than KGENOME_DIAG_WRAPPER_SPAN_MIN. It was a fixed 256 bytes,
 * MEASURED as enough on 27 sites in 25 static i386 bots (33 bytes there), and it
 * dropped the connect() nodes of a wrapper that began 260 bytes before its
 * `int 0x80`: the site stayed one opaque node. Scaled with the function it is a
 * bound that follows the input; what keeps the larger span from costing the
 * walk is the total step budget of kgenome_diag_wrapper_summarise (KGENOME_DIAG_WRAPPER_STEPS_MIN), because lifting the
 * span, the pending queue and the body together was MEASURED to hang - the number
 * of paths explodes, which per-path numbers cannot prevent.
 */
#define KGENOME_DIAG_WRAPPER_SPAN_MIN 256u

/*
 * THE STEP BUDGET OF ONE kgenome_diag_wrapper_summarise(): every instruction read on any path of it,
 * at most max(KGENOME_DIAG_WRAPPER_STEPS_MIN, 8 x the span in bytes). The per-path numbers below
 * stay per path - the body, pending and variant bounds below, which scale with
 * the span - because they bound what ONE path may do and the explosion is in how
 * many paths there are; this bounds that. Reached, it ends the summary where it is, keeps the variants found and
 * sets KGENOME_TRUNCATED.
 */
#define KGENOME_DIAG_WRAPPER_STEPS_MIN 4096u

/*
 * THE WRAPPER LEVELS ARE ITERATED TO A FIXPOINT: a level adds the functions
 * whose straight line ends in a call to a wrapper found by the one before, and
 * the search stops when a level adds nothing. There is no depth ceiling of its
 * own - it was a fixed 64, which is not a measurement of how deep wrappers nest
 * (socket() around __socketcall around the syscall is three) and stopped a chain
 * of seventy with the evidence unread. What bounds a pathological chain is what
 * bounds everything else the walk does: the caller's whole-object step budget
 * (kgenome_budget.max_steps). A level costs one pass over the call targets, so
 * each pass is charged its target count against that budget; when the budget
 * cannot pay for another pass the search stops where it is, keeps what it found
 * and sets KGENOME_OVER_BUDGET. A chain can be at most as deep as there are call
 * targets, and the budget is 64 steps per byte of code.
 */
/*
 * THE THREE PER-PATH BOUNDS SCALE WITH THE FUNCTION, as the span does. They were
 * fixed (48 instructions, 6 queued arms, 4 variants), measured on the 33-byte
 * glibc wrapper, and a wrapper a researcher padded or branched past them was
 * "too long" however small the object: the cap hid the evidence it stood in
 * front of (CLAUDE.md rule 4). Now each is a function of the span, with the old
 * number as its floor, and what keeps the larger bound from being the hang the
 * fixed lift measured is the same thing that was keeping it - the TOTAL step
 * budget of one summary (KGENOME_DIAG_WRAPPER_STEPS_MIN, 8 x span) and the caller's whole-object
 * one (kgenome_budget.max_steps). A path cannot read more instructions than the
 * span has bytes; a function cannot queue more arms than it has branches; the
 * variants are the paths that end in a kernel entry. Reaching a bound still sets
 * KGENOME_TRUNCATED.
 *
 *   body      instructions of ONE path   max(KGENOME_DIAG_WRAPPER_BODY_MIN, span) for a function
 *                                        that HOLDS a kernel entry (the level-0
 *                                        summary, where the walk has something to
 *                                        reach); KGENOME_DIAG_WRAPPER_BODY_MIN for the levels above,
 *                                        which look for a call to a wrapper in
 *                                        functions that mostly have none - lifted
 *                                        for all of them it was MEASURED at +45%
 *                                        and +58% of the scan of two small bots
 *   pending   arms queued at once        max(KGENOME_DIAG_WRAPPER_PENDING_MIN, span / 8), grown on
 *                                        demand and charged to the ledger
 *   variants  summaries kept             max(KGENOME_DIAG_WRAPPER_VARIANTS_MIN, span / 8) up to
 *                                        KGENOME_DIAG_WRAPPER_VARIANTS_CEIL (a table the walk holds
 *                                        once, so the ceiling is its size)
 */
#define KGENOME_DIAG_WRAPPER_BODY_MIN        48u

#define KGENOME_DIAG_WRAPPER_PENDING_MIN      6u

#define KGENOME_DIAG_WRAPPER_VARIANTS_MIN     4u

#define KGENOME_DIAG_WRAPPER_VARIANTS_CEIL   64u

/* Stack slots remembered for one function. A frame that keeps more distinct
 * descriptors alive than this loses the oldest, which is a missed link. */
#define KGENOME_DIAG_WRAPPER_SLOTS  192u

enum { KGENOME_DIAG_WRAPPER_V_UNK = 0, KGENOME_DIAG_WRAPPER_V_CONST, KGENOME_DIAG_WRAPPER_V_NODE, KGENOME_DIAG_WRAPPER_V_SADDR, KGENOME_DIAG_WRAPPER_V_PARAM, KGENOME_DIAG_WRAPPER_V_SET };

struct kgenome_diag_wrapper_val {
	uint8_t  t;
	uint16_t node;          /* KGENOME_DIAG_WRAPPER_V_NODE */
	int64_t  v;             /* KGENOME_DIAG_WRAPPER_V_CONST value, KGENOME_DIAG_WRAPPER_V_SADDR canonical offset, KGENOME_DIAG_WRAPPER_V_PARAM index,
				 * KGENOME_DIAG_WRAPPER_V_SET the bits known to be set (the rest unknown) */
};

static const struct kgenome_diag_wrapper_val kgenome_diag_wrapper_unk = { KGENOME_DIAG_WRAPPER_V_UNK, 0, 0 };

struct kgenome_diag_wrapper_slot {
	int32_t   off;
	struct kgenome_diag_wrapper_val v;
};

/* The symbolic state of ONE function. */
struct kgenome_diag_wrapper_frame {
	struct kgenome_diag_wrapper_val reg[16];
	int32_t   sp;           /* bytes pushed since entry */
	int       bp_known;
	int32_t   bp_off;       /* canonical offset the frame pointer holds */
	/*
	 * n_slot and next come BEFORE the slots, and that is the point: a slot past
	 * n_slot is never read (slot_find walks n_slot, kgenome_diag_wrapper_slot_put writes at n_slot or
	 * at `next` once the table is full), so resetting or copying a state is a
	 * copy of everything above `slot` and of n_slot slots - not of the 4.6 KB
	 * table. MEASURED: a state is reset at every function and copied at every
	 * queued branch of every summary, and the full copies were the larger part of
	 * what the wrapper walk cost on a static binary.
	 */
	uint32_t  n_slot, next;
	struct kgenome_diag_wrapper_slot slot[KGENOME_DIAG_WRAPPER_SLOTS];
};

/* 4096 bits: a function-pointer table's worth of distinct globals read before
 * they are written is the realistic ceiling, and a full table only means the
 * second round runs, as it always did. */
#define KGENOME_DIAG_WRAPPER_GMISS_WORDS 64u

/* One global that holds the result of a node. */
struct kgenome_diag_wrapper_glob {
	uint64_t addr;
	struct kgenome_diag_wrapper_val v;
};

/* A path of a summary waiting to be walked: the state at the branch, where it
 * goes, and how many instructions the path to it has cost. */
struct kgenome_diag_wrapper_pending {
	struct kgenome_diag_wrapper_frame f;
	uint64_t at;
	unsigned n;
};

/*
 * WHAT A FAILED SUMMARY SAW: the direct call and jump targets its walk met that
 * were not wrappers (yet). A summary is a deterministic function of the code and
 * of the wrapper table, and only the table changes between two attempts - so the
 * attempt can come out differently ONLY if one of these has since become a
 * wrapper. The fixpoint over the levels retries a function exactly then, instead
 * of walking every function again at every level (which is what a level was):
 * the same answers, a fraction of the walks. `more` is set when the walk met
 * more than KGENOME_DIAG_WRAPPER_SEEN, and such a function is always retried - the filter is exact
 * or it is not applied.
 */
#define KGENOME_DIAG_WRAPPER_SEEN 6u

struct kgenome_diag_wrapper_tseen {
	uint64_t cal[KGENOME_DIAG_WRAPPER_SEEN];
	uint8_t  n;
	uint8_t  more;
	uint8_t  done;          /* attempted at least once */
};

/* What a wrapper is. */
struct kgenome_diag_wrapper_summary {
	uint64_t entry, site;   /* file offsets; `site` is the syscall, or the call to an inner wrapper */
	struct kgenome_diag_wrapper_val nr;           /* KGENOME_DIAG_WRAPPER_V_CONST or KGENOME_DIAG_WRAPPER_V_PARAM */
	struct kgenome_diag_wrapper_val arg[6];       /* the kernel's arguments, in kernel order */
	/* i386 socketcall: the arguments of the OPERATION, which live in an array
	 * the wrapper (or the function around it) builds on its stack. */
	int      has_arr;
	struct kgenome_diag_wrapper_val arr[6];
	int      node_made;     /* a call-site node was made for it */
};

/* What a call to a wrapper means at one call site, in the caller's values. */
struct kgenome_diag_wrapper_effect {
	struct kgenome_diag_wrapper_val nr;
	struct kgenome_diag_wrapper_val arg[6];
	int       has_arr;
	struct kgenome_diag_wrapper_val arr[6];
};

/* What this file reads of an instruction. */
struct kgenome_diag_wrapper_op {
	uint8_t kind, reg, index, scale, size, flags, seg;
	int64_t v;              /* the immediate (IMM, REL) or the displacement (MEM) */
};

struct kgenome_diag_wrapper_insn {
	uint64_t at, at_va, target;
	uint16_t wmask;
	uint8_t  op, len, n_op, flags;
	struct kgenome_diag_wrapper_op o[3];
};

/*
 * ---- THE WALK, A PRODUCT OF THE OBJECT --------------------------------------
 *
 * Every instruction of every executable segment is decoded ONCE, and what that
 * walk finds is kept here for everyone who needs it: the direct-call targets
 * (the entries - kgenome_diag_funcs_of reads them to find the functions of an
 * object that kept no symbols), the kernel-entry instructions (the wrapper
 * resolution starts at them) and, when somebody will read the code again, the
 * decode trace (see "THE DECODE, ONCE"). Before this the entries and the
 * wrappers each made the walk, so a stripped x86 ELF decoded its code twice.
 *
 * The scanner latches one per object and hands it to the diagnose scan through
 * struct kgenome_diag_inputs; a caller with none gets one owned by the scan.
 */
struct kgenome_diag_wrapper_index { uint32_t at, pos; };

struct kgenome_diag_wrapper_seg {
	uint64_t lo, hi;        /* the range the walk covered */
	uint32_t pos, end;      /* its records: [pos, end) of the stream */
	uint32_t ix, n_ix;      /* and its index entries */
	uint32_t n;             /* records */
	uint8_t  complete;      /* the trace holds every instruction of it */
	uint8_t  given_up;      /* the stream is a prefix of the walk */
};

struct kgenome_diag_walk {
	const uint8_t *base;            /* what it was made from */
	uint64_t size;
	int      built;                 /* tgt and site are the answer */
	int      has_trace;             /* the trace was asked for when it was built */
	int      sites;                 /* x86: kernel entries were recorded */
	uint64_t *tgt;                  /* sorted unique direct-call targets */
	uint32_t n_tgt, cap_tgt;
	uint64_t *site;                 /* kernel-entry instruction offsets */
	uint32_t n_site, cap_site;
	uint8_t *tr;                    /* the record stream */
	uint32_t n_tr, cap_tr;
	struct kgenome_diag_wrapper_index *ix;                /* every W_TRACE_EVERY-th record */
	uint32_t n_ix, cap_ix;
	struct kgenome_diag_wrapper_seg tseg[KGENOME_ELF_MAX_SEGMENTS];
	uint64_t pk_end, pk_delta;      /* the packer's: where the last record ended */
	int      tr_on;                 /* offsets fit the record */
	/*
	 * THE LEDGER THE TRACE IS CHARGED TO: the scan's, while a scan holds this
	 * walk (kgenome_diag_walk_bind), NULL otherwise. Charged SOFT - see
	 * kgenome_ledger_try: the trace is a cache and a refusal only means the code
	 * is decoded again, so it must not read as a limit on the answer.
	 */
	struct kgenome_ledger *lg;
	uint64_t lg_charged;            /* what of the trace `lg` holds charged */
};

struct kgenome_diag_wrapper_ctx {
	struct kgenome_diag_scan *s;
	const struct kgenome_obj *obj;
	const uint8_t *base;
	uint64_t size;
	struct kgenome_cell_space sp;           /* the object's code, as celllysis reads it */
	int wide;                       /* x86-64 */
	int w;                          /* the machine word, 4 or 8 */
	struct kgenome_diag_walk *wk;       /* the object's walk, see above */
	uint32_t *fret;                 /* per call target: the node + 1 its AX holds at ret */
	uint8_t  *fmiss;                /* per call target: a call asked before it was set */
	uint64_t *open;                 /* sites whose NUMBER the sweep could not read */
	uint32_t n_open, cap_open;
	struct kgenome_diag_wrapper_summary *ws;                /* the wrappers, by entry */
	uint32_t n_ws, cap_ws;
	struct kgenome_diag_wrapper_glob *glob;
	uint32_t n_glob, cap_glob;
	/*
	 * WHETHER A SECOND WALK CAN SEE ANYTHING THE FIRST DID NOT - see the note
	 * at the two rounds in kgenome_diag_run_wrappers. A global read before the
	 * walk had put anything there sets its bit in `gmiss` (hashed, so a
	 * collision costs a needless second round and never a missed one); a
	 * global entry CREATED while its bit is set is the one case in which the
	 * second round differs.
	 */
	uint64_t gmiss[KGENOME_DIAG_WRAPPER_GMISS_WORDS];
	int      need_round2;
	/* The wrapper walk's whole-object step total, against kgenome_budget.max_steps. */
	uint64_t steps;
	int      over_steps;
	/* A cap cut the summary just made: a path ended at its body bound, a branch arm
	 * was not queued (pending), a variant was not kept (variants) or the step
	 * budget ended it. Read by the caller, which decides whether the cut cost an
	 * explanation - see the level-0 loop. */
	int      cut;
	/* Bytes this walk charged to the scan's ledger (the per-target arrays, the
	 * wrapper table, the globals), given back when it ends. */
	uint64_t charged;
	struct kgenome_diag_wrapper_pending *pend;             /* the paths of one summary, kept between summaries */
	uint32_t cap_pend;              /* ...and how many it holds room for */
	struct kgenome_diag_wrapper_summary  *var;              /* the summaries of one call: KGENOME_DIAG_WRAPPER_VARIANTS_CEIL, once */
	struct kgenome_diag_wrapper_tseen *tseen;            /* per call target - see struct kgenome_diag_wrapper_tseen */
};

static inline void kgenome_diag_wrapper_winsn_of(struct kgenome_diag_wrapper_insn *w, const struct kgenome_cell_insn *in)
{
	unsigned i, n = in->n_op < 3u ? in->n_op : 3u;

	w->at = in->at;
	w->at_va = in->at_va;
	w->target = in->target;
	w->wmask = (uint16_t)in->wmask;
	w->op = in->op;
	w->len = in->len;
	w->n_op = (uint8_t)n;
	w->flags = in->flags;
	for (i = 0; i < 3u; i++) {
		struct kgenome_diag_wrapper_op *d = &w->o[i];

		if (i >= n) {           /* absent: say so, as the decoder does */
			d->kind = KGENOME_CELL_O_NONE;
			d->reg = d->index = d->seg = KGENOME_CELL_REG_NONE;
			d->scale = d->size = d->flags = 0;
			d->v = 0;
			continue;
		}
		d->kind = in->o[i].kind;
		d->reg = in->o[i].reg;
		d->index = in->o[i].index;
		d->scale = in->o[i].scale;
		d->size = in->o[i].size;
		d->flags = in->o[i].flags;
		d->seg = in->o[i].seg;
		d->v = d->kind == KGENOME_CELL_O_MEM ? in->o[i].disp
		     : d->kind == KGENOME_CELL_O_IMM || d->kind == KGENOME_CELL_O_REL
		       ? (int64_t)in->o[i].imm : 0;
	}
}

/* The one place an instruction is decoded in this file. */
static inline int kgenome_diag_wrapper_decode(const struct kgenome_diag_wrapper_ctx *c, struct kgenome_cell_cur *k, struct kgenome_diag_wrapper_insn *w)
{
	struct kgenome_cell_insn ci;

	if (!kgenome_cell_step(k, &c->sp, &ci))
		return 0;
	kgenome_diag_wrapper_winsn_of(w, &ci);
	return 1;
}

/*
 * ---- the record --------------------------------------------------------------
 *
 *   rlen ctl op len flags wmask(2)  [at(4)] [delta(8)] [target(4)]  operand*
 *
 * `at` is the end of the record before unless ctl says otherwise (a walk that
 * stepped over bytes that did not decode, and every WT_EVERY-th record, which
 * must be readable alone because the index points at it). `delta` is
 * at_va - at, repeated from the record before unless ctl says otherwise; an
 * operand is its seven bytes and its value, zigzag-varint.
 */
#define KGENOME_DIAG_WRAPPER_TRACE_HAS_AT    0x01u

#define KGENOME_DIAG_WRAPPER_TRACE_HAS_DELTA 0x02u

#define KGENOME_DIAG_WRAPPER_TRACE_HAS_TGT   0x04u

#define KGENOME_DIAG_WRAPPER_TRACE_NOP_SHIFT 4u

/* A record read back. `at` and `delta` are the reader's, because a record that
 * does not carry them takes them from the one before. */
struct kgenome_diag_wrapper_reader {
	const uint8_t *p;
	uint64_t at, delta;
};

/*
 * ---- ONE STREAM OF INSTRUCTIONS, WHEREVER IT COMES FROM ------------------------
 *
 * Two ways to read, and the caller cannot tell where an instruction came from:
 *
 *   SCAN, for a linear sweep of a segment (kgenome_diag_wrapper_pass_b): reads the trace of that
 *     segment from its first record, and decodes the rest if the trace is a
 *     prefix. Bytes that do not decode are stepped over - in the trace they are
 *     the gap before the next record, which is the walk pass_a made.
 *   WALK, for following a function body (kgenome_diag_wrapper_summarise): starts at any offset and
 *     goes on from there; an instruction that does not decode ends the walk.
 *     Seeking to an offset the trace holds replays from it; to one it does not,
 *     decodes. The walk leaves the trace when the next record is not the
 *     instruction at its offset and decodes from there.
 */
struct kgenome_diag_wrapper_isrc {
	struct kgenome_diag_wrapper_ctx *c;
	uint64_t at;                    /* where the next instruction is read */
	uint64_t end;                   /* a scan stops at or after this */
	struct kgenome_diag_wrapper_reader rd;
	const uint8_t *rend;            /* the trace being replayed, or NULL */
	int scan;
	int whole;                      /* the trace holds the whole of the range */
	struct kgenome_cell_cur k;
	int kat;                        /* `k` is positioned at `at` */
};

/* Parameter numbers from here up are registers, not stack slots. */
#define KGENOME_DIAG_WRAPPER_REG_PARAM 16u

/* ---- what one part offers another ---- */

int kgenome_diag_wrapper_charge(struct kgenome_diag_wrapper_ctx *c, uint64_t n);
void kgenome_diag_wrapper_frame_reset(struct kgenome_diag_wrapper_frame *f);
void kgenome_diag_wrapper_frame_copy(struct kgenome_diag_wrapper_frame *dst,
		const struct kgenome_diag_wrapper_frame *src);
void kgenome_diag_wrapper_slot_put(struct kgenome_diag_wrapper_ctx *c,
		struct kgenome_diag_wrapper_frame *f, int32_t off, struct kgenome_diag_wrapper_val v);
struct kgenome_diag_wrapper_val kgenome_diag_wrapper_slot_get(struct kgenome_diag_wrapper_frame *f,
		int32_t off);
void kgenome_diag_wrapper_frame_step(struct kgenome_diag_wrapper_ctx *c,
		struct kgenome_diag_wrapper_frame *f, const struct kgenome_diag_wrapper_insn *in);
void kgenome_diag_wrapper_frame_call_unknown(struct kgenome_diag_wrapper_ctx *c,
		struct kgenome_diag_wrapper_frame *f);
int kgenome_diag_wrapper_push_u64(uint64_t **v, uint32_t *n, uint32_t *cap, uint64_t x);
int kgenome_diag_wrapper_is_kernel_entry(const struct kgenome_diag_wrapper_ctx *c,
		const struct kgenome_diag_wrapper_insn *in);
void kgenome_diag_wrapper_trace_get(struct kgenome_diag_wrapper_reader *r,
		struct kgenome_diag_wrapper_insn *w);
int kgenome_diag_wrapper_trace_lower(const struct kgenome_diag_walk *wk,
		const struct kgenome_diag_wrapper_seg *g, uint64_t off, struct kgenome_diag_wrapper_reader *r);
void kgenome_diag_wrapper_isrc_scan(struct kgenome_diag_wrapper_isrc *it,
		struct kgenome_diag_wrapper_ctx *c, unsigned seg, uint64_t off, uint64_t n);
void kgenome_diag_wrapper_isrc_seek(struct kgenome_diag_wrapper_isrc *it, uint64_t off);
void kgenome_diag_wrapper_isrc_walk(struct kgenome_diag_wrapper_isrc *it,
		struct kgenome_diag_wrapper_ctx *c, uint64_t off);
int kgenome_diag_wrapper_isrc_next(struct kgenome_diag_wrapper_isrc *it,
		struct kgenome_diag_wrapper_insn *w);
int kgenome_diag_wrapper_site_open(const struct kgenome_diag_wrapper_ctx *c, uint64_t at);
int kgenome_diag_wrapper_site_wrapped(const struct kgenome_diag_scan *s, uint64_t at);
int kgenome_diag_wrapper_tseen_retry(const struct kgenome_diag_wrapper_ctx *c,
		const struct kgenome_diag_wrapper_tseen *t);
unsigned kgenome_diag_wrapper_summarise(struct kgenome_diag_wrapper_ctx *c, uint64_t entry,
		struct kgenome_diag_wrapper_tseen *seen, int holds_site);
int kgenome_diag_wrapper_summary_insert(struct kgenome_diag_wrapper_ctx *c,
		const struct kgenome_diag_wrapper_summary *t);
struct kgenome_diag_wrapper_summary *kgenome_diag_wrapper_summary_of(struct kgenome_diag_wrapper_ctx *c,
		uint64_t entry);
int kgenome_diag_wrapper_entry_of(const struct kgenome_diag_wrapper_ctx *c, uint64_t site,
		uint64_t *entry);
void kgenome_diag_wrapper_eval_call(const struct kgenome_diag_wrapper_ctx *c,
		struct kgenome_diag_wrapper_frame *f, const struct kgenome_diag_wrapper_summary *ws,
		struct kgenome_diag_wrapper_effect *e);
int kgenome_diag_wrapper_fret_site(const struct kgenome_diag_wrapper_ctx *c, uint64_t at);
int kgenome_diag_wrapper_tgt_index(const struct kgenome_diag_wrapper_ctx *c, uint64_t at);
void kgenome_diag_wrapper_pass_b(struct kgenome_diag_wrapper_ctx *c, unsigned seg, uint64_t off,
		uint64_t n);
void kgenome_diag_wrapper_tgt_unique(struct kgenome_diag_wrapper_ctx *c);
void kgenome_diag_wrapper_walk_drop_trace(struct kgenome_diag_walk *wk);

#endif /* KGENOME_DIAG_WRAPPER_PRIVATE_H */
