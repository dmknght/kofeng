/*
 * diag_wrap.c - THE SYSCALL IS INSIDE A LIBRARY FUNCTION, AND THE PROGRAM IS
 * THE CALLERS.
 *
 * A bot built against a static libc does not execute `mov eax,41; syscall` where
 * it opens a socket. It executes `call socket`, and one function somewhere in the
 * binary holds the only `syscall` instruction there is:
 *
 *     socket:  push rbx
 *              movslq edx,rdx ; movslq esi,rsi ; movslq edi,rdi   <- the PARAMETERS
 *              mov eax,0x29
 *              syscall
 *
 * Read at that instruction the arguments are the function's own parameters, so
 * the node said "a socket of an unknown kind", stood in one place for every
 * socket the program makes, and could carry no link to anything - the descriptor
 * it returned goes to eighty call sites, and the arguments of those are the
 * caller's too. MEASURED on 1000 Bazaar Linux bots: 122 of 146 old Mirai had a
 * network node and one of them had a node with any link.
 *
 * SO THE NODES BELONG AT THE CALL SITES, which is where the program says what
 * it is doing, and the function is a SUMMARY that says what a call to it means:
 * which system call, and which of the caller's values become which argument.
 * That is what a relocatable object's imports already are - a name at a call
 * site with a capability - and the same machinery (an origin that is carried from
 * the node that produced a value to the node that takes it) links them.
 *
 *   1. SUMMARISE. Every syscall instruction has an entry: the nearest direct-call
 *      target before it. If the straight line from the entry to the instruction
 *      reaches it without a branch, and the registers the kernel reads are the
 *      function's parameters (possibly moved or widened on the way) or constants,
 *      the function is a wrapper and the summary says which.
 *   2. WALK THE CALLERS, function by function, with a small symbolic state: which
 *      node produced the value in each register, in each stack slot of this frame,
 *      and in each global. A call to a wrapper makes a node at the call, with the
 *      arguments the summary maps from what the caller holds; what it returns is
 *      that node.
 *
 * WHAT THIS DOES NOT CLAIM. The walk is linear in address order and takes no
 * branch, so a value is "carried" when nothing overwrote the place it was kept
 * before the next use - a MAY link, as the rest of the static routes are. A write
 * through a pointer clears nothing. Calls to anything but a wrapper forget the
 * registers a callee may clobber and keep what is on the stack and in globals.
 * x86 and x86-64 only; the stack arguments of cdecl are read, regparm and
 * fastcall are not.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lineages.h"
#include "diag_int.h"
#include <kofcore.h>
#include <genotype/image/cmp.h>
#include <celllysis/capability.h>
#include <celllysis/cell.h>
#include <genotype/image/elf_image.h>
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <celllysis/space.h>

/*
 * HOW FAR A WRAPPER MAY SPAN: the length of its FUNCTION - from its entry to the
 * next call target - and never less than W_SPAN_MIN. It was a fixed 256 bytes,
 * MEASURED as enough on 27 sites in 25 static i386 bots (33 bytes there), and it
 * dropped the connect() nodes of a wrapper that began 260 bytes before its
 * `int 0x80`: the site stayed one opaque node. Scaled with the function it is a
 * bound that follows the input; what keeps the larger span from costing the
 * walk is the total step budget of summarise (W_STEPS_MIN), because lifting the
 * span, the pending queue and the body together was MEASURED to hang - the number
 * of paths explodes, which per-path numbers cannot prevent.
 */
#define W_SPAN_MIN 256u
/*
 * THE STEP BUDGET OF ONE summarise(): every instruction read on any path of it,
 * at most max(W_STEPS_MIN, 8 x the span in bytes). The per-path numbers below
 * stay per path - the body, pending and variant bounds below, which scale with
 * the span - because they bound what ONE path may do and the explosion is in how
 * many paths there are; this bounds that. Reached, it ends the summary where it is, keeps the variants found and
 * sets KGENOME_TRUNCATED.
 */
#define W_STEPS_MIN 4096u
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
 * budget of one summary (W_STEPS_MIN, 8 x span) and the caller's whole-object
 * one (kgenome_budget.max_steps). A path cannot read more instructions than the
 * span has bytes; a function cannot queue more arms than it has branches; the
 * variants are the paths that end in a kernel entry. Reaching a bound still sets
 * KGENOME_TRUNCATED.
 *
 *   body      instructions of ONE path   max(W_BODY_MIN, span) for a function
 *                                        that HOLDS a kernel entry (the level-0
 *                                        summary, where the walk has something to
 *                                        reach); W_BODY_MIN for the levels above,
 *                                        which look for a call to a wrapper in
 *                                        functions that mostly have none - lifted
 *                                        for all of them it was MEASURED at +45%
 *                                        and +58% of the scan of two small bots
 *   pending   arms queued at once        max(W_PENDING_MIN, span / 8), grown on
 *                                        demand and charged to the ledger
 *   variants  summaries kept             max(W_VARIANTS_MIN, span / 8) up to
 *                                        W_VARIANTS_CEIL (a table the walk holds
 *                                        once, so the ceiling is its size)
 */
#define W_BODY_MIN        48u
#define W_PENDING_MIN      6u
#define W_VARIANTS_MIN     4u
#define W_VARIANTS_CEIL   64u
/* Stack slots remembered for one function. A frame that keeps more distinct
 * descriptors alive than this loses the oldest, which is a missed link. */
#define W_SLOTS  192u

enum { V_UNK = 0, V_CONST, V_NODE, V_SADDR, V_PARAM, V_SET };

struct sv {
	uint8_t  t;
	uint16_t node;          /* V_NODE */
	int64_t  v;             /* V_CONST value, V_SADDR canonical offset, V_PARAM index,
				 * V_SET the bits known to be set (the rest unknown) */
};

static const struct sv UNK = { V_UNK, 0, 0 };

struct slot {
	int32_t   off;
	struct sv v;
};

/* The symbolic state of ONE function. */
struct fstate {
	struct sv reg[16];
	int32_t   sp;           /* bytes pushed since entry */
	int       bp_known;
	int32_t   bp_off;       /* canonical offset the frame pointer holds */
	/*
	 * n_slot and next come BEFORE the slots, and that is the point: a slot past
	 * n_slot is never read (slot_find walks n_slot, slot_put writes at n_slot or
	 * at `next` once the table is full), so resetting or copying a state is a
	 * copy of everything above `slot` and of n_slot slots - not of the 4.6 KB
	 * table. MEASURED: a state is reset at every function and copied at every
	 * queued branch of every summary, and the full copies were the larger part of
	 * what the wrapper walk cost on a static binary.
	 */
	uint32_t  n_slot, next;
	struct slot slot[W_SLOTS];
};

/* 4096 bits: a function-pointer table's worth of distinct globals read before
 * they are written is the realistic ceiling, and a full table only means the
 * second round runs, as it always did. */
#define GMISS_WORDS 64u
#define GMISS_BIT(a) ((unsigned)(((a) * 0x9e3779b97f4a7c15ull) >> 52) & 4095u)

/* One global that holds the result of a node. */
struct glob {
	uint64_t addr;
	struct sv v;
};

/* A path of a summary waiting to be walked: the state at the branch, where it
 * goes, and how many instructions the path to it has cost. */
struct wpend {
	struct fstate f;
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
 * more than W_SEEN, and such a function is always retried - the filter is exact
 * or it is not applied.
 */
#define W_SEEN 6u
struct tseen {
	uint64_t cal[W_SEEN];
	uint8_t  n;
	uint8_t  more;
	uint8_t  done;          /* attempted at least once */
};

/* What a wrapper is. */
struct wsum {
	uint64_t entry, site;   /* file offsets; `site` is the syscall, or the call to an inner wrapper */
	struct sv nr;           /* V_CONST or V_PARAM */
	struct sv arg[6];       /* the kernel's arguments, in kernel order */
	/* i386 socketcall: the arguments of the OPERATION, which live in an array
	 * the wrapper (or the function around it) builds on its stack. */
	int      has_arr;
	struct sv arr[6];
	int      node_made;     /* a call-site node was made for it */
};

/* What a call to a wrapper means at one call site, in the caller's values. */
struct ev {
	struct sv nr;
	struct sv arg[6];
	int       has_arr;
	struct sv arr[6];
};

/* What this file reads of an instruction. */
struct wop {
	uint8_t kind, reg, index, scale, size, flags, seg;
	int64_t v;              /* the immediate (IMM, REL) or the displacement (MEM) */
};

struct winsn {
	uint64_t at, at_va, target;
	uint16_t wmask;
	uint8_t  op, len, n_op, flags;
	struct wop o[3];
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
struct widx { uint32_t at, pos; };

struct wseg {
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
	struct widx *ix;                /* every W_TRACE_EVERY-th record */
	uint32_t n_ix, cap_ix;
	struct wseg tseg[KGENOME_ELF_MAX_SEGMENTS];
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

struct wctx {
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
	struct wsum *ws;                /* the wrappers, by entry */
	uint32_t n_ws, cap_ws;
	struct glob *glob;
	uint32_t n_glob, cap_glob;
	/*
	 * WHETHER A SECOND WALK CAN SEE ANYTHING THE FIRST DID NOT - see the note
	 * at the two rounds in kgenome_diag_run_wrappers. A global read before the
	 * walk had put anything there sets its bit in `gmiss` (hashed, so a
	 * collision costs a needless second round and never a missed one); a
	 * global entry CREATED while its bit is set is the one case in which the
	 * second round differs.
	 */
	uint64_t gmiss[GMISS_WORDS];
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
	struct wpend *pend;             /* the paths of one summary, kept between summaries */
	uint32_t cap_pend;              /* ...and how many it holds room for */
	struct wsum  *var;              /* the summaries of one call: W_VARIANTS_CEIL, once */
	struct tseen *tseen;            /* per call target - see struct tseen */
};

/* Charge `n` bytes of the wrapper walk's own tables to the scan's ledger. 0 when
 * the allowance refuses (the ledger says KGENOME_OVER_BUDGET) - the caller keeps
 * what it has and does not grow. */
static int wcharge(struct wctx *c, uint64_t n)
{
	if (!kgenome_ledger_charge(&c->s->led, n))
		return 0;
	c->charged += n;
	return 1;
}

/* ---- the symbolic state ------------------------------------------------- */

static void st_reset(struct fstate *f)
{
	memset(f, 0, offsetof(struct fstate, slot));
}

/* A copy of a state: what is above the slot table, and the slots in use. */
static void st_copy(struct fstate *dst, const struct fstate *src)
{
	memcpy(dst, src, offsetof(struct fstate, slot));
	memcpy(dst->slot, src->slot, (size_t)src->n_slot * sizeof src->slot[0]);
	/* A full table is a ring: every slot is live, and `next` is in the header. */
}

static struct slot *slot_find(struct fstate *f, int32_t off)
{
	uint32_t i;

	for (i = 0; i < f->n_slot; i++)
		if (f->slot[i].off == off)
			return &f->slot[i];
	return NULL;
}

static void slot_put(struct wctx *c, struct fstate *f, int32_t off, struct sv v)
{
	struct slot *p = slot_find(f, off);

	if (p) {
		p->v = v;
		return;
	}
	if (v.t == V_UNK)
		return;                 /* nothing to remember */
	if (f->n_slot < W_SLOTS) {
		f->slot[f->n_slot].off = off;
		f->slot[f->n_slot++].v = v;
		return;
	}
	/* THE FRAME HOLDS MORE LIVE SLOTS THAN W_SLOTS: the oldest is overwritten,
	 * which can be a link missed - said, not silent. */
	kgenome_diag_note(c->s, KGENOME_TRUNCATED);
	f->slot[f->next].off = off;
	f->slot[f->next].v = v;
	f->next = (f->next + 1u) % W_SLOTS;
}

static struct sv slot_get(struct fstate *f, int32_t off)
{
	struct slot *p = slot_find(f, off);

	return p ? p->v : UNK;
}

static struct glob *glob_find(struct wctx *c, uint64_t addr)
{
	uint32_t i;

	for (i = 0; i < c->n_glob; i++)
		if (c->glob[i].addr == addr)
			return &c->glob[i];
	return NULL;
}

static void glob_put(struct wctx *c, uint64_t addr, struct sv v)
{
	struct glob *g = glob_find(c, addr);

	if (g) {
		g->v = v;
		return;
	}
	if (v.t != V_NODE)
		return;                 /* only a produced value is worth a global */
	if (c->gmiss[GMISS_BIT(addr) >> 6] & (1ull << (GMISS_BIT(addr) & 63u)))
		c->need_round2 = 1;     /* it was read before it existed */
	if (c->n_glob == c->cap_glob) {
		uint32_t nc = c->cap_glob ? c->cap_glob * 2u : 64u;
		struct glob *ng;

		if (!wcharge(c, (uint64_t)(nc - c->cap_glob) * sizeof *ng))
			return;
		ng = realloc(c->glob, (size_t)nc * sizeof *ng);
		if (!ng) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return;
		}
		c->glob = ng;
		c->cap_glob = nc;
	}
	c->glob[c->n_glob].addr = addr;
	c->glob[c->n_glob++].v = v;
}

/* Where a memory operand is, in a space the walk can name: the frame (a
 * canonical offset from the function's entry stack pointer) or a global (an
 * address). 0 = somewhere else, which neither reads nor invalidates. */
enum { LOC_NONE = 0, LOC_STACK, LOC_GLOBAL };

static int mem_loc(const struct wctx *c, const struct fstate *f,
		   const struct winsn *in, const struct wop *o,
		   int64_t *key)
{
	if (o->kind != KGENOME_CELL_O_MEM || o->index != KGENOME_CELL_REG_NONE)
		return LOC_NONE;
	if (o->seg != KGENOME_CELL_REG_NONE && o->seg != KGENOME_CELL_SEG_DS &&
	    o->seg != KGENOME_CELL_SEG_SS)
		return LOC_NONE;        /* fs: and gs: are thread data */
	if (o->flags & KGENOME_CELL_OF_RIPREL) {
		if (in->at_va == KGENOME_BROKEN)
			return LOC_NONE;
		*key = (int64_t)(in->at_va + in->len) + o->v;
		return LOC_GLOBAL;
	}
	if (o->reg == KGENOME_CELL_REG_NONE) {
		*key = o->v & (c->wide ? -1ll : 0xffffffffll);
		return LOC_GLOBAL;
	}
	if (o->reg == KGENOME_CELL_REG_SP) {
		*key = -(int64_t)f->sp + o->v;
		return LOC_STACK;
	}
	if (o->reg == KGENOME_CELL_REG_BP && f->bp_known) {
		*key = (int64_t)f->bp_off + o->v;
		return LOC_STACK;
	}
	/*
	 * ANY REGISTER THAT HOLDS A STACK ADDRESS names a frame slot the same way sp
	 * does. A variadic function spills its register arguments into a save area
	 * and reads them back through a pointer into it - `lea 0x20(%rsp),%rax;
	 * add $0x10,%rax; mov (%rax),%rdx` is how fcntl, open and ioctl fetch their
	 * third argument - so before this the F_SETFL flags were stored and then
	 * read from "somewhere else", and no fcntl node on x86-64 carried a flag.
	 */
	if (o->reg < 16u && f->reg[o->reg].t == V_SADDR) {
		*key = f->reg[o->reg].v + o->v;
		return LOC_STACK;
	}
	return LOC_NONE;
}

static struct sv load(struct wctx *c, struct fstate *f,
		      const struct winsn *in, const struct wop *o)
{
	int64_t key;

	switch (o->kind) {
	case KGENOME_CELL_O_REG:
		if (o->reg >= 16u || o->size < 4u)
			return UNK;
		return f->reg[o->reg];
	case KGENOME_CELL_O_IMM: {
		struct sv v = { V_CONST, 0, (int64_t)o->v };

		return v;
	}
	case KGENOME_CELL_O_MEM:
		if (o->size < 4u)
			return UNK;
		switch (mem_loc(c, f, in, o, &key)) {
		case LOC_STACK:
			return slot_get(f, (int32_t)key);
		case LOC_GLOBAL: {
			struct glob *g = glob_find(c, (uint64_t)key);

			if (!g)
				c->gmiss[GMISS_BIT((uint64_t)key) >> 6] |=
					1ull << (GMISS_BIT((uint64_t)key) & 63u);
			return g ? g->v : UNK;
		}
		default:
			return UNK;
		}
	default:
		return UNK;
	}
}

static void store(struct wctx *c, struct fstate *f, const struct winsn *in,
		  const struct wop *o, struct sv v)
{
	int64_t key;

	if (o->kind == KGENOME_CELL_O_REG) {
		if (o->reg < 16u)
			f->reg[o->reg] = o->size >= 4u ? v : UNK;
		return;
	}
	if (o->kind != KGENOME_CELL_O_MEM)
		return;
	if (o->size < 4u)
		v = UNK;
	switch (mem_loc(c, f, in, o, &key)) {
	case LOC_STACK:
		slot_put(c, f, (int32_t)key, v);
		break;
	case LOC_GLOBAL:
		glob_put(c, (uint64_t)key, v);
		break;
	default:
		break;
	}
}

/* ---- one instruction ------------------------------------------------------ */

/*
 * The effect of an instruction that is NOT a call on the symbolic state. A
 * handful of shapes are followed exactly - the moves, the widening, the stack
 * pointer - and everything else forgets what it writes, which is the honest
 * default: a register that was rewritten holds nothing this walk can name.
 */
static void st_step(struct wctx *c, struct fstate *f, const struct winsn *in)
{
	const struct wop *d = &in->o[0], *s = &in->o[1];
	int w = c->w;
	uint32_t r;

	switch (in->op) {
	case KGENOME_CELL_NOP:
		return;
	case KGENOME_CELL_MOV:
		if (in->n_op >= 2u) {
			struct sv v = load(c, f, in, s);

			/* mov bp,sp: the frame pointer now names this frame. */
			if (d->kind == KGENOME_CELL_O_REG && d->reg == KGENOME_CELL_REG_BP &&
			    s->kind == KGENOME_CELL_O_REG && s->reg == KGENOME_CELL_REG_SP) {
				f->bp_known = 1;
				f->bp_off = -f->sp;
				f->reg[KGENOME_CELL_REG_BP].t = V_SADDR;
				f->reg[KGENOME_CELL_REG_BP].v = -f->sp;
				return;
			}
			/* A copy of the stack pointer is a stack ADDRESS. */
			if (d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
			    s->reg == KGENOME_CELL_REG_SP && d->size >= 4u && d->reg < 16u) {
				f->reg[d->reg].t = V_SADDR;
				f->reg[d->reg].v = -f->sp;
				f->reg[d->reg].node = 0;
				return;
			}
			store(c, f, in, d, v);
			return;
		}
		break;
	case KGENOME_CELL_MOVSX:
	case KGENOME_CELL_MOVZX:
	case KGENOME_CELL_WIDEN:
		/* A 32-bit value widened to 64 is the same value as far as a
		 * handle or a parameter is concerned (movslq edx,rdx). */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG &&
		    s->kind == KGENOME_CELL_O_REG && s->size >= 4u && d->reg < 16u &&
		    s->reg < 16u) {
			f->reg[d->reg] = f->reg[s->reg];
			return;
		}
		if (in->op == KGENOME_CELL_WIDEN)
			return;         /* cdqe in place */
		break;
	case KGENOME_CELL_XCHG:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG &&
		    s->kind == KGENOME_CELL_O_REG && d->reg < 16u && s->reg < 16u) {
			struct sv t = f->reg[d->reg];

			f->reg[d->reg] = f->reg[s->reg];
			f->reg[s->reg] = t;
			return;
		}
		break;
	case KGENOME_CELL_LEA:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u &&
		    s->kind == KGENOME_CELL_O_MEM && s->index == KGENOME_CELL_REG_NONE &&
		    !(s->flags & KGENOME_CELL_OF_RIPREL)) {
			if (s->reg == KGENOME_CELL_REG_SP) {
				f->reg[d->reg].t = V_SADDR;
				f->reg[d->reg].v = -(int64_t)f->sp + s->v;
				f->reg[d->reg].node = 0;
				if (d->reg == KGENOME_CELL_REG_BP) {
					f->bp_known = 1;
					f->bp_off = (int32_t)f->reg[d->reg].v;
				}
				return;
			}
			if (s->reg == KGENOME_CELL_REG_BP && f->bp_known) {
				f->reg[d->reg].t = V_SADDR;
				f->reg[d->reg].v = (int64_t)f->bp_off + s->v;
				f->reg[d->reg].node = 0;
				return;
			}
		}
		break;
	case KGENOME_CELL_XOR:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
		    d->reg == s->reg && d->reg < 16u) {
			f->reg[d->reg].t = V_CONST;
			f->reg[d->reg].v = 0;
			f->reg[d->reg].node = 0;
			return;
		}
		break;
	case KGENOME_CELL_PUSH:
		if (in->n_op >= 1u) {
			struct sv v = load(c, f, in, d);

			f->sp += w;
			slot_put(c, f, -f->sp, v);
		}
		return;
	case KGENOME_CELL_POP:
		if (in->n_op >= 1u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u)
			f->reg[d->reg] = slot_get(f, -f->sp);
		f->sp -= w;
		return;
	case KGENOME_CELL_ADD:
	case KGENOME_CELL_SUB:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG &&
		    d->reg == KGENOME_CELL_REG_SP && s->kind == KGENOME_CELL_O_IMM) {
			f->sp += in->op == KGENOME_CELL_SUB ? (int32_t)s->v
						    : -(int32_t)s->v;
			return;
		}
		/* A stack address moved by a constant is another stack address. */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u &&
		    d->size >= 4u && s->kind == KGENOME_CELL_O_IMM &&
		    f->reg[d->reg].t == V_SADDR) {
			f->reg[d->reg].v += in->op == KGENOME_CELL_SUB ? -(int64_t)(int32_t)s->v
							       : (int64_t)(int32_t)s->v;
			return;
		}
		break;
	case KGENOME_CELL_OR:
		/*
		 * `flags | O_NONBLOCK`, where flags is whatever F_GETFL returned.
		 * The result is not a number, but it is a number with a bit that is
		 * certainly set, and that bit is the claim fcntl(F_SETFL) is read
		 * for. gcc writes the 0x800 as `or ah, 8` (80 cc 08): 80 of 95
		 * samples with an OR of that bit in the 146-sample mirai x86 set
		 * use that form, which a model that reads only 4-byte operands
		 * never sees.
		 */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u &&
		    s->kind == KGENOME_CELL_O_IMM && d->size != 2u) {
			uint64_t bit = (uint64_t)s->v;
			struct sv *rv = &f->reg[d->reg];

			if (d->size == 1u) {
				bit &= 0xffu;
				if (d->flags & KGENOME_CELL_OF_HIGH8)
					bit <<= 8;
			}
			if (rv->t == V_CONST) {
				rv->v |= (int64_t)bit;
			} else {
				int64_t keep = rv->t == V_SET ? rv->v : 0;

				rv->t = V_SET;
				rv->node = 0;
				rv->v = keep | (int64_t)bit;
			}
			return;
		}
		break;
	case KGENOME_CELL_RET:
		st_reset(f);
		return;
	case KGENOME_CELL_CMP:
	case KGENOME_CELL_TEST:
	case KGENOME_CELL_JCC:
	case KGENOME_CELL_JMP:
		return;                 /* nothing written; the walk is linear */
	default:
		break;
	}
	/* Anything else forgets what it wrote. */
	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r)) {
			if (r == KGENOME_CELL_REG_SP)
				continue;
			f->reg[r] = UNK;
		}
	{
		int64_t key;

		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_MEM &&
		    (in->o[0].flags & KGENOME_CELL_OF_WRITE)) {
			switch (mem_loc(c, f, in, &in->o[0], &key)) {
			case LOC_STACK:
				slot_put(c, f, (int32_t)key, UNK);
				break;
			case LOC_GLOBAL:
				glob_put(c, (uint64_t)key, UNK);
				break;
			default:
				break;
			}
		}
	}
}

/* What a call to something the walk does not summarise leaves behind: the
 * registers the callee may use are gone, the frame and the globals are not. */
static void st_call_unknown(struct wctx *c, struct fstate *f)
{
	static const uint8_t cs64[] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
	static const uint8_t cs32[] = { 0, 1, 2 };
	const uint8_t *cs = c->wide ? cs64 : cs32;
	uint32_t n = c->wide ? (uint32_t)sizeof cs64 : (uint32_t)sizeof cs32, i;

	for (i = 0; i < n; i++)
		f->reg[cs[i]] = UNK;
}

/* ---- pass A: call targets and syscall sites -------------------------------- */

static int push_u64(uint64_t **v, uint32_t *n, uint32_t *cap, uint64_t x)
{
	if (*n == *cap) {
		uint32_t nc = *cap ? *cap * 2u : 256u;
		uint64_t *nv = realloc(*v, (size_t)nc * sizeof **v);

		if (!nv)
			return 0;
		*v = nv;
		*cap = nc;
	}
	(*v)[(*n)++] = x;
	return 1;
}

/* The one kernel-entry test is kgenome_diag_kernel_entry (nodes.c). */
static int is_kernel_entry(const struct wctx *c, const struct winsn *in)
{
	return kgenome_diag_kernel_entry(c->obj, in->op,
				     in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM &&
				     in->o[0].v == 0x80, c->base + in->at);
}

/*
 * ---- THE DECODE, ONCE ------------------------------------------------------
 *
 * A decode is a pure function of the bytes at an offset: the same offset in the
 * same space gives the same instruction however it is reached. pass_a decodes
 * every instruction of every executable segment, pass_b reads the same ones
 * again (twice, when a global is read before it is written) and `summarise`
 * walks function bodies that pass_a has already decoded - MEASURED on a 7.2 MB
 * static x86 ELF, 3.25 M + 0.39 M decodes of a ~1.6 M instruction image, and a
 * decode is ~800 Ir against ~100 for reading one back. So the first decode is
 * kept and every later read of an offset the trace holds is served from it.
 *
 * THE TRACE IS A CACHE, NOT A SECOND WALK. Nothing is read from it that decoding
 * would not have returned: a record is a struct winsn - what this file reads of
 * an instruction, and the only form of one it sees - packed, and unpacking gives
 * back that struct field for field. Checked end to end: the node dump of 1119
 * files is byte for byte the one decoding every time, and so it is with the
 * stream cut to 4 KiB, 150 KiB, 2 MiB and 8 MiB, which makes the prefix, the
 * seek-into-the-middle and the decode-after-the-end paths carry most of it. An
 * offset the trace does not hold is decoded exactly as before. The code below has
 * ONE decoder entry, wdecode(), for both.
 *
 * WHAT A winsn LEAVES OUT of struct kgenome_cell_insn: `cond` and `target_va`, which
 * nothing here reads, `wmask` above bit 15 (only the sixteen general registers
 * are tracked), and the displacement/immediate that the operand's kind makes
 * meaningless. Leaving them out is what lets it be packed; reading one would
 * not compile.
 *
 * THE BOUND IS ON MEMORY, NOT ON WHAT IS FOUND. The record stream is limited to
 * W_TRACE_BYTES and its index (one entry per W_TRACE_EVERY records, 8 bytes, at
 * most 1/14 of the stream) comes on top. MEASURED on a 7.2 MB static ELF, 1,025,877
 * instructions pack to 22,795,487 bytes - 22.2 each against the 120 of a
 * kgenome_cell_insn - so the same 32 MiB that held 262144 instructions as cell_insns
 * holds about 1.5 M.
 * Past it the stream stops growing and the rest of the image is decoded again:
 * a trace is a prefix of its segment's walk, and the walk continues from where
 * the prefix ends, so nothing is dropped from the analysis, only from the cache.
 * Rule 4.
 */
#define W_TRACE_BYTES  (32u << 20)
#define W_TRACE_EVERY  16u
#define W_REC_MAX      80u

static void winsn_of(struct winsn *w, const struct kgenome_cell_insn *in)
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
		struct wop *d = &w->o[i];

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
static int wdecode(const struct wctx *c, struct kgenome_cell_cur *k, struct winsn *w)
{
	struct kgenome_cell_insn ci;

	if (!kgenome_cell_step(k, &c->sp, &ci))
		return 0;
	winsn_of(w, &ci);
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
#define WT_HAS_AT    0x01u
#define WT_HAS_DELTA 0x02u
#define WT_HAS_TGT   0x04u
#define WT_NOP_SHIFT 4u

static uint8_t *put_vz(uint8_t *p, int64_t v)
{
	uint64_t z = ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);

	while (z >= 0x80u) {
		*p++ = (uint8_t)(z | 0x80u);
		z >>= 7;
	}
	*p++ = (uint8_t)z;
	return p;
}

static int64_t get_vz(const uint8_t **pp)
{
	const uint8_t *p = *pp;
	uint64_t z = 0;
	unsigned sh = 0;

	for (;;) {
		uint8_t b = *p++;

		z |= (uint64_t)(b & 0x7fu) << sh;
		if (!(b & 0x80u))
			break;
		sh += 7u;
	}
	*pp = p;
	return (int64_t)(z >> 1) ^ -(int64_t)(z & 1u);
}

static void walk_drop_trace(struct kgenome_diag_walk *wk);

/* Charge the trace's growth to the scan's ledger when a scan holds the walk -
 * SOFT (kgenome_ledger_try): the trace is a cache, and a refusal only means the
 * code is decoded again, the answer unchanged. 0 = do not grow it. */
static int wtrace_charge(struct kgenome_diag_walk *wk, uint64_t n)
{
	if (!wk->lg)
		return 1;
	if (!kgenome_ledger_try(wk->lg, n))
		return 0;
	wk->lg_charged += n;
	return 1;
}

static void trace_give_up(struct wseg *g)
{
	g->complete = 0;
	g->given_up = 1;
}

/* Keep what pass_a saw. Once a segment has been given up it stays given up: a
 * trace is a prefix of the walk and never has a hole in it. */
static void trace_put(struct wctx *c, unsigned seg, const struct winsn *w)
{
	struct wseg *g = &c->wk->tseg[seg];
	uint8_t rec[W_REC_MAX], *p = rec + 7;
	uint64_t delta = w->at_va - w->at;
	unsigned ctl = 0, i;
	int first;

	if (g->given_up)
		return;
	first = !(g->n % W_TRACE_EVERY);
	/* An offset or a target that does not fit 32 bits: the image is not one
	 * this record can hold (size is checked at open, a target is not). */
	if (w->at > 0xffffffffu ||
	    (w->target != KGENOME_BROKEN && w->target > 0xffffffffu)) {
		trace_give_up(g);
		return;
	}
	if (first || w->at != c->wk->pk_end) {
		ctl |= WT_HAS_AT;
		memcpy(p, &(uint32_t){ (uint32_t)w->at }, 4);
		p += 4;
	}
	if (first || delta != c->wk->pk_delta) {
		ctl |= WT_HAS_DELTA;
		memcpy(p, &delta, 8);
		p += 8;
	}
	if (w->target != KGENOME_BROKEN) {
		ctl |= WT_HAS_TGT;
		memcpy(p, &(uint32_t){ (uint32_t)w->target }, 4);
		p += 4;
	}
	ctl |= (unsigned)w->n_op << WT_NOP_SHIFT;
	for (i = 0; i < w->n_op; i++) {
		const struct wop *o = &w->o[i];

		p[0] = o->kind; p[1] = o->reg; p[2] = o->index; p[3] = o->scale;
		p[4] = o->size; p[5] = o->flags; p[6] = o->seg;
		p = put_vz(p + 7, o->v);
	}
	rec[0] = (uint8_t)(p - rec);
	rec[1] = (uint8_t)ctl;
	rec[2] = w->op;
	rec[3] = w->len;
	rec[4] = w->flags;
	rec[5] = (uint8_t)w->wmask;
	rec[6] = (uint8_t)(w->wmask >> 8);

	if (c->wk->n_tr + rec[0] > c->wk->cap_tr) {
		size_t nc = c->wk->cap_tr ? (size_t)c->wk->cap_tr * 2u : 1u << 16;
		uint8_t *nt;

		if (nc > W_TRACE_BYTES)
			nc = W_TRACE_BYTES;
		if (c->wk->n_tr + rec[0] > nc ||
		    !wtrace_charge(c->wk, nc - c->wk->cap_tr) ||
		    !(nt = realloc(c->wk->tr, nc))) {
			trace_give_up(g);
			return;
		}
		c->wk->tr = nt;
		c->wk->cap_tr = (uint32_t)nc;
	}
	if (first) {
		if (c->wk->n_ix == c->wk->cap_ix) {
			uint32_t nc = c->wk->cap_ix ? c->wk->cap_ix * 2u : 1024u;
			struct widx *nx;

			if (!wtrace_charge(c->wk, (uint64_t)(nc - c->wk->cap_ix) * sizeof *nx)) {
				trace_give_up(g);
				return;
			}
			nx = realloc(c->wk->ix, (size_t)nc * sizeof *nx);
			if (!nx) {
				trace_give_up(g);
				return;
			}
			c->wk->ix = nx;
			c->wk->cap_ix = nc;
		}
		c->wk->ix[c->wk->n_ix].at = (uint32_t)w->at;
		c->wk->ix[c->wk->n_ix].pos = c->wk->n_tr;
		c->wk->n_ix++;
		g->n_ix++;
	}
	memcpy(c->wk->tr + c->wk->n_tr, rec, rec[0]);
	c->wk->n_tr += rec[0];
	g->end = c->wk->n_tr;
	g->n++;
	c->wk->pk_end = w->at + w->len;
	c->wk->pk_delta = delta;
}

/* A record read back. `at` and `delta` are the reader's, because a record that
 * does not carry them takes them from the one before. */
struct wrd {
	const uint8_t *p;
	uint64_t at, delta;
};

static void trace_get(struct wrd *r, struct winsn *w)
{
	const uint8_t *p = r->p, *q = p + 7;
	unsigned ctl = p[1], n = (ctl >> WT_NOP_SHIFT) & 3u, i;

	w->op = p[2];
	w->len = p[3];
	w->flags = p[4];
	w->wmask = kof_ld_le16(p + 5);
	if (ctl & WT_HAS_AT) {
		uint32_t a;

		memcpy(&a, q, 4);
		r->at = a;
		q += 4;
	}
	if (ctl & WT_HAS_DELTA) {
		memcpy(&r->delta, q, 8);
		q += 8;
	}
	w->at = r->at;
	w->at_va = r->at + r->delta;
	if (ctl & WT_HAS_TGT) {
		uint32_t t;

		memcpy(&t, q, 4);
		w->target = t;
		q += 4;
	} else {
		w->target = KGENOME_BROKEN;
	}
	w->n_op = (uint8_t)n;
	for (i = 0; i < n; i++) {
		struct wop *o = &w->o[i];

		o->kind = q[0]; o->reg = q[1]; o->index = q[2]; o->scale = q[3];
		o->size = q[4]; o->flags = q[5]; o->seg = q[6];
		q += 7;
		o->v = get_vz(&q);
	}
	for (; i < 3u; i++) {
		struct wop *o = &w->o[i];

		o->kind = KGENOME_CELL_O_NONE;
		o->reg = o->index = o->seg = KGENOME_CELL_REG_NONE;
		o->scale = o->size = o->flags = 0;
		o->v = 0;
	}
	r->at += w->len;
	r->p = p + p[0];
}

/* The first record of the trace of segment `g` at or after `off`, if it holds one.
 * The index gets within W_TRACE_EVERY records of it and the rest is a walk over
 * record headers, which carry their own length. A `off` before the segment's
 * first record starts at that record. */
static int trace_lower(const struct kgenome_diag_walk *wk, const struct wseg *g,
		       uint64_t off, struct wrd *r)
{
	uint32_t lo = 0, hi = g->n_ix;
	const uint8_t *p, *pend = wk->tr + g->end;
	uint64_t at = 0, delta = 0;

	if (off >= g->hi || !g->n_ix)
		return 0;
	if (off >= g->lo) {
		while (lo < hi) {               /* the last entry at or before `off` */
			uint32_t mid = lo + (hi - lo) / 2u;

			if (wk->ix[g->ix + mid].at <= off)
				lo = mid + 1u;
			else
				hi = mid;
		}
	}
	p = wk->tr + (lo ? wk->ix[g->ix + lo - 1u].pos : g->pos);
	while (p < pend) {
		unsigned ctl = p[1];
		const uint8_t *q = p + 7;

		if (ctl & WT_HAS_AT) {
			uint32_t a;

			memcpy(&a, q, 4);
			at = a;
			q += 4;
		}
		if (ctl & WT_HAS_DELTA)
			memcpy(&delta, q, 8);
		if (at >= off) {
			r->p = p;
			r->at = at;
			r->delta = delta;
			return 1;
		}
		at += p[3];
		p += p[0];
	}
	return 0;
}

/* The record the trace of segment `g` holds AT `off`, if it holds one. */
static int trace_find(const struct wctx *c, const struct wseg *g, uint64_t off,
		      struct wrd *r)
{
	struct wrd t;

	if (off < g->lo || off >= g->hi || !trace_lower(c->wk, g, off, &t) ||
	    t.at != off)
		return 0;
	*r = t;
	return 1;
}

/*
 * ---- ONE STREAM OF INSTRUCTIONS, WHEREVER IT COMES FROM ------------------------
 *
 * Two ways to read, and the caller cannot tell where an instruction came from:
 *
 *   SCAN, for a linear sweep of a segment (pass_b): reads the trace of that
 *     segment from its first record, and decodes the rest if the trace is a
 *     prefix. Bytes that do not decode are stepped over - in the trace they are
 *     the gap before the next record, which is the walk pass_a made.
 *   WALK, for following a function body (summarise): starts at any offset and
 *     goes on from there; an instruction that does not decode ends the walk.
 *     Seeking to an offset the trace holds replays from it; to one it does not,
 *     decodes. The walk leaves the trace when the next record is not the
 *     instruction at its offset and decodes from there.
 */
struct isrc {
	struct wctx *c;
	uint64_t at;                    /* where the next instruction is read */
	uint64_t end;                   /* a scan stops at or after this */
	struct wrd rd;
	const uint8_t *rend;            /* the trace being replayed, or NULL */
	int scan;
	int whole;                      /* the trace holds the whole of the range */
	struct kgenome_cell_cur k;
	int kat;                        /* `k` is positioned at `at` */
};

static void isrc_scan(struct isrc *it, struct wctx *c, unsigned seg,
		      uint64_t off, uint64_t n)
{
	const struct wseg *g = &c->wk->tseg[seg];

	memset(it, 0, sizeof *it);
	it->c = c;
	it->at = off;
	it->end = off + n;
	it->scan = 1;
	if (g->n) {
		it->rd.p = c->wk->tr + g->pos;
		it->rend = c->wk->tr + g->end;
		it->whole = g->complete;
	}
}

static void isrc_seek(struct isrc *it, uint64_t off)
{
	struct wctx *c = it->c;
	unsigned i;

	it->at = off;
	it->kat = 0;
	it->rend = NULL;
	for (i = 0; i < KGENOME_ELF_MAX_SEGMENTS; i++)
		if (trace_find(c, &c->wk->tseg[i], off, &it->rd)) {
			it->rend = c->wk->tr + c->wk->tseg[i].end;
			return;
		}
}

static void isrc_walk(struct isrc *it, struct wctx *c, uint64_t off)
{
	memset(it, 0, sizeof *it);
	it->c = c;
	it->end = UINT64_MAX;
	isrc_seek(it, off);
}

static int isrc_next(struct isrc *it, struct winsn *w)
{
	if (it->rend) {
		if (it->rd.p < it->rend) {
			struct wrd t = it->rd;

			trace_get(&t, w);
			/* A scan takes the next record wherever it is - the bytes
			 * before it did not decode. A walk takes it only where it
			 * is. */
			if (it->scan || w->at == it->at) {
				it->rd = t;
				it->at = w->at + w->len;
				return 1;
			}
		} else if (it->whole) {
			return 0;
		} else {
			it->at = it->rd.at;     /* where the prefix ends */
		}
		it->rend = NULL;
		it->kat = 0;
	}
	for (;;) {
		if (it->at >= it->end)
			return 0;
		if (!it->kat) {
			kgenome_cell_seek(&it->k, it->at, 0);
			it->kat = 1;
		}
		if (wdecode(it->c, &it->k, w)) {
			it->at = it->k.at;
			return 1;
		}
		if (!it->scan)
			return 0;
		it->k.at++;                     /* data in the code: step over it */
		it->at = it->k.at;
	}
}

/*
 * ---- THE INSTRUCTIONS OF ONE RUN, FOR AN OBSERVER ----------------------------
 *
 * The xref sweep (libgenome/celllysis/xref.c) asks for the instructions of a
 * range of the file, cut the way ITS answers need (a section: where its register
 * map starts empty), and it used to decode them itself - a second decode of code
 * this walk decodes and keeps. This is the one reader of an object's
 * instructions that hands them over: from the trace where the trace holds the
 * very instruction the sweep would have decoded, from kgenome_cell_decode (the one
 * decoder) otherwise. The observer cannot tell which, and does not need to.
 *
 * WHAT "THE VERY INSTRUCTION" MEANS, because the answer must be identical to
 * decoding the run on its own and a linear sweep is alignment-sensitive. A run
 * starts at `off`, reads on a window that ends at `off + n`, and an instruction
 * that does not fit the window does not decode - so a trace record is taken
 * only when it starts exactly at the position the run has reached, ends inside
 * the window, and was decoded for the same address (at_va, which differs only
 * when a section header claims an address its segment does not give it). Any
 * other position is decoded afresh, one byte on after a failure, exactly as the
 * run alone would, and the next position that coincides with a record goes back
 * to the trace. A run that begins before the walk did (the headers; the bytes
 * before an entry the walk started at) is decoded up to the walk's first
 * record. The trace is a prefix when it was cut at W_TRACE_BYTES: past it every
 * position is decoded afresh. Rule 4: a bound on memory, never on what the
 * sweep sees.
 *
 * WHAT A TRACE RECORD LEAVES OUT of a kgenome_cell_insn is put back here: `cond` is not
 * read by the observer, `target_va` is the one decode_x86.c computes (the
 * relative operand added to the end of the instruction - the trace is x86's, and
 * only x86's), and operands beyond the three a kgenome_cell_insn holds do not exist.
 */
static void cinsn_of(struct kgenome_cell_insn *ci, const struct winsn *w)
{
	unsigned i;

	memset(ci, 0, sizeof *ci);
	ci->op = w->op;
	ci->len = w->len;
	ci->n_op = w->n_op;
	ci->flags = w->flags;
	ci->wmask = w->wmask;
	ci->at = w->at;
	ci->at_va = w->at_va;
	ci->target = w->target;
	ci->target_va = KGENOME_BROKEN;
	for (i = 0; i < w->n_op; i++) {
		const struct wop *o = &w->o[i];
		struct kgenome_cell_operand *d = &ci->o[i];

		d->kind = o->kind;
		d->reg = o->reg;
		d->index = o->index;
		d->scale = o->scale;
		d->size = o->size;
		d->flags = o->flags;
		d->seg = o->seg;
		if (o->kind == KGENOME_CELL_O_MEM)
			d->disp = o->v;
		else if (o->kind == KGENOME_CELL_O_IMM || o->kind == KGENOME_CELL_O_REL)
			d->imm = (uint64_t)o->v;
		if (o->kind == KGENOME_CELL_O_REL)
			ci->target_va = w->at_va + w->len +
					(uint64_t)(int64_t)(int32_t)d->imm;
	}
	for (; i < 3u; i++) {
		ci->o[i].kind = KGENOME_CELL_O_NONE;
		ci->o[i].reg = ci->o[i].index = ci->o[i].seg = KGENOME_CELL_REG_NONE;
	}
}

void kgenome_diag_code_run(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
		       const uint8_t *base, uint64_t size, uint64_t off,
		       uint64_t n, uint64_t va, kgenome_cell_insn_fn fn, void *user,
		       struct kgenome_code_run_stats *st)
{
	struct kgenome_cell_insn ci;
	struct winsn pk;                /* the next record the trace holds */
	struct wrd nx;
	const uint8_t *rend = NULL;
	uint64_t at = off, end;
	unsigned i;
	int pk_ok = 0;
	int64_t delta;

	if (!obj || !base || !fn || off >= size)
		return;
	end = n > size - off ? size : off + n;
	delta = (int64_t)(va - off);
	if (wk && wk->built && wk->has_trace && wk->tr && wk->base == base &&
	    wk->size == size) {
		for (i = 0; i < KGENOME_ELF_MAX_SEGMENTS; i++) {
			const struct wseg *g = &wk->tseg[i];

			/* A run that begins before the walk did (the headers, the
			 * bytes before an entry) is decoded up to the first record
			 * and read from the trace from there. */
			if (g->end > g->pos && off < g->hi && end > g->lo &&
			    trace_lower(wk, g, off, &nx)) {
				rend = wk->tr + g->end;
				trace_get(&nx, &pk);
				pk_ok = 1;
				break;
			}
		}
	}
	while (at < end) {
		/* `nx` reads on from the record `pk` was taken from. */
		while (pk_ok && pk.at < at) {           /* catch up with the run */
			if (nx.p < rend)
				trace_get(&nx, &pk);
			else
				pk_ok = 0;
		}
		if (pk_ok && pk.at == at && at + pk.len <= end &&
		    pk.at_va == at + (uint64_t)delta) {
			cinsn_of(&ci, &pk);
			fn(user, &ci);
			at += pk.len;
			if (st)
				st->from_trace++;
			continue;
		}
		/*
		 * THE ONE DECODER, directly: kgenome_cell_decode is what every cursor wraps,
		 * and this run is one segment of one address mapping, so what the
		 * cursor adds (the segment lookup, the target's file offset) is work
		 * the observer would throw away - MEASURED, through kgenome_cell_step it
		 * cost 17% more than the sweep it replaced, which read this window
		 * with kgenome_cell_decode itself. The window is what is left of the run.
		 */
		{
			uint64_t left = end - at;
			uint32_t len = kgenome_cell_decode(obj->arch, 0, base + at,
						   left > UINT32_MAX ? UINT32_MAX
								     : (uint32_t)left,
						   at + (uint64_t)delta, &ci);

			if (len) {
				ci.at = at;
				fn(user, &ci);
				at += len;
				if (st)
					st->decoded++;
			} else {
				fn(user, NULL); /* data in the code: one byte on */
				at++;
				if (st)
					st->skipped++;
			}
		}
	}
}

/*
 * WHY THE WHOLE IMAGE IS DECODED HERE, and not only the windows around syscall
 * sites and around the callers of a wrapper found by searching the bytes for
 * `e8 rel32` that lands on it. Tried, and measured against this pass:
 *
 *   - THE CALL TARGETS a byte search names are not the ones decoding finds. Over
 *     255 ELF files: 299,857 decoded, 304,425 by bytes, 20,166 of the decoded ones
 *     missing (the `jmp` thunks a function starts with, which need to know the
 *     instruction before them is a ret/jmp/nop, and calls behind a prefix) and
 *     24,734 invented (an `e8` inside an immediate or a displacement whose bytes
 *     happen to land in the image). Putting the byte-found set in place of this
 *     pass's changes the node dump of 79 of 1119 files (one lost 218 of 394
 *     nodes) with `e8` alone, and 248 with a heuristic for the `e9` thunks.
 *   - THE SYSCALL SITES a byte search names are a superset (18,915 decoded,
 *     20,649 by bytes, none missing) and the extra ones are harmless: a site only
 *     selects an entry, and summarise decodes forward from that entry, so a site
 *     in the middle of an instruction is never reached. Replacing this pass's
 *     sites with the byte-found ones changes no file of the 1119.
 *
 * So the sites could come from bytes; the call targets cannot - an entry is a
 * fact about alignment and alignment is a decode. Hence one decode of the image,
 * kept (see THE DECODE, ONCE) and read from there.
 */
static int pass_a(struct wctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	struct kgenome_cell_cur k;
	struct winsn in;
	struct wseg *g = &c->wk->tseg[seg];

	/* Whether the instruction before ended a function's straight line. */
	int boundary = 1;

	memset(&k, 0, sizeof k);
	g->lo = off;
	g->hi = off + n;
	g->pos = c->wk->n_tr;
	g->end = c->wk->n_tr;
	g->ix = c->wk->n_ix;
	g->complete = c->wk->tr_on != 0;
	g->given_up = !c->wk->tr_on;
	if (!kgenome_cell_seek(&k, off, 0))
		return 1;
	while (k.at < off + n) {
		if (!wdecode(c, &k, &in)) {
			k.at++;                 /* data in the code: step over it */
			continue;
		}
		trace_put(c, seg, &in);
		if (in.op == KGENOME_CELL_CALL && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
		    in.target != KGENOME_BROKEN) {
			if (!push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, in.target))
				return 0;
		} else if (in.op == KGENOME_CELL_JMP && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
			   in.target != KGENOME_BROKEN && boundary) {
			/*
			 * A THUNK: `jmp X` as the first instruction of a function
			 * makes X an entry, though nothing CALLS it. musl keeps its
			 * generic syscall(nr, a1..a6) at X and gives the cancellable
			 * wrappers a one-instruction stub that jumps to it - sendto
			 * and connect both enter there, and with X not an entry the
			 * syscall inside it was attributed to no function and every
			 * socket send of the program was lost. Found by reading the
			 * 79 x86-64 Bazaar files that had a raw socket and no send.
			 */
			if (!push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, in.target))
				return 0;
		} else if (c->wk->sites && is_kernel_entry(c, &in)) {
			if (!push_u64(&c->wk->site, &c->wk->n_site, &c->wk->cap_site, in.at))
				return 0;
		}
		boundary = in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_JMP ||
			   in.op == KGENOME_CELL_NOP;
	}
	return 1;
}

static struct sv call_param(const struct wctx *c, struct fstate *f, unsigned i);
static void eval_call(const struct wctx *c, struct fstate *f,
		      const struct wsum *ws, struct ev *e);
static struct wsum *wsum_of(struct wctx *c, uint64_t entry);

/* ---- summarise one wrapper ------------------------------------------------- */

/* Parameter numbers from here up are registers, not stack slots. */
#define W_REG_PARAM 16u

static int site_open(const struct wctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->n_open;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->open[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_open && c->open[lo] == at;
}

/* Is `at` a site the i386 socketcall analysis was left holding - see s->wrap. */
static int site_wrapped(const struct kgenome_diag_scan *s, uint64_t at)
{
	uint32_t i;

	for (i = 0; i < s->n_wrap; i++)
		if (s->wrap[i] == at)
			return 1;
	return 0;
}

/* One path through a wrapper that ended in a syscall or a call to a wrapper,
 * turned into a summary. 1 when it says something about the parameters. */
static int summarise_end(struct wctx *c, struct fstate *f, uint64_t entry,
			 const struct winsn *in, struct wsum *callee,
			 struct wsum *out)
{
	static const uint8_t k64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t k32[] = { KGENOME_CELL_REG_BX, KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DI, KGENOME_CELL_REG_BP };
	const uint8_t *kr = c->wide ? k64 : k32;
	int any_param = 0;
	unsigned i;

	memset(out, 0, sizeof *out);
	out->entry = entry;
	out->site = in->at;
	if (!callee) {
		out->nr = f->reg[KGENOME_CELL_REG_AX];
		for (i = 0; i < 6; i++) {
			out->arg[i] = f->reg[kr[i]];
			if (out->arg[i].t != V_CONST && out->arg[i].t != V_PARAM &&
			    out->arg[i].t != V_SET)
				out->arg[i] = UNK;
			if (out->arg[i].t == V_PARAM)
				any_param = 1;
		}
	} else {
		struct ev e;

		eval_call(c, f, callee, &e);
		out->nr = e.nr;
		for (i = 0; i < 6; i++) {
			out->arg[i] = e.arg[i];
			if (out->arg[i].t != V_CONST && out->arg[i].t != V_PARAM &&
			    out->arg[i].t != V_SET)
				out->arg[i] = UNK;
			if (out->arg[i].t == V_PARAM)
				any_param = 1;
		}
		out->has_arr = e.has_arr;
		for (i = 0; i < 6 && e.has_arr; i++) {
			out->arr[i] = e.arr[i];
			if (out->arr[i].t != V_CONST && out->arr[i].t != V_PARAM)
				out->arr[i] = UNK;
			if (out->arr[i].t == V_PARAM)
				any_param = 1;
		}
	}
	if (out->nr.t != V_CONST && out->nr.t != V_PARAM)
		return 0;
	if (out->nr.t == V_PARAM)
		any_param = 1;
	/*
	 * A REGISTER PARAMETER (the number or an argument) is believed only where
	 * the sweep itself could not read the number. Held to every function, it
	 * accepted every syscall site that a mis-partitioned fragment reaches with
	 * the registers untouched, and made each call of the fragment a node:
	 * MEASURED on one x86 file, 40 -> 206 write nodes and the connect nodes
	 * gone. A real register-convention helper (musl's __vsyscall) is exactly
	 * the site the sweep reports as opaque.
	 */
	if (!callee && !site_open(c, in->at)) {
		if (out->nr.t == V_PARAM && out->nr.v >= (int64_t)W_REG_PARAM)
			return 0;
		/* An argument register nobody set is not a parameter either. */
		any_param = out->nr.t == V_PARAM;
		for (i = 0; i < 6; i++) {
			if (out->arg[i].t == V_PARAM &&
			    out->arg[i].v >= (int64_t)W_REG_PARAM)
				out->arg[i] = UNK;
			if (out->arg[i].t == V_PARAM)
				any_param = 1;
		}
	}
	return any_param;
}

/*
 * What the function that begins at `entry` is, if it is a wrapper: a path that
 * ends in a kernel entry (a level-0 wrapper, the one that holds the syscall) or
 * in a call to a wrapper already summarised (a wrapper of a wrapper - uClibc's
 * socket() is `build the array; call __socketcall(1, array)`). Both ends are the
 * same question - what does this mean in terms of MY parameters - so both are
 * answered by evaluating the state where the path ends.
 *
 * MORE THAN ONE PATH, because a wrapper branches on what it was asked: uClibc's
 * fcntl takes fcntl64 for the three commands that need it and fcntl for the
 * rest, and both are summarised. The paths here are forward conditional jumps
 * inside the function and nothing else; each gives a variant, and a call is
 * evaluated against every variant - so a call whose command is not known makes
 * the node either path would have made, and the nodes merge when they agree.
 */
/* The span of the function at `entry`: its length to the next call target, never
 * less than W_SPAN_MIN - see the note there. */
static uint64_t span_of(const struct wctx *c, uint64_t entry)
{
	uint32_t lo = 0, hi = c->wk->n_tgt;
	uint64_t end, span;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->wk->tgt[mid] <= entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	end = lo < c->wk->n_tgt ? c->wk->tgt[lo] : c->size;
	span = end > entry ? end - entry : 0;
	return span < W_SPAN_MIN ? W_SPAN_MIN : span;
}

/* Note a direct target that was not a wrapper. */
static void tseen_note(struct tseen *t, uint64_t target)
{
	unsigned i;

	for (i = 0; i < t->n; i++)
		if (t->cal[i] == target)
			return;
	if (t->n < W_SEEN)
		t->cal[t->n++] = target;
	else
		t->more = 1;
}

/* Could a new attempt at this function come out differently now. */
static int tseen_retry(const struct wctx *c, const struct tseen *t)
{
	unsigned i;

	if (!t->done || t->more)
		return 1;
	for (i = 0; i < t->n; i++) {
		uint32_t lo = 0, hi = c->n_ws;

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (c->ws[mid].entry < t->cal[i])
				lo = mid + 1u;
			else
				hi = mid;
		}
		if (lo < c->n_ws && c->ws[lo].entry == t->cal[i])
			return 1;
	}
	return 0;
}

/* Room for one more queued path: the table doubles on demand, each growth charged
 * to the scan's ledger. 0 when it cannot (the allowance, or memory): the caller
 * treats the arm as not queued, and the status says why. */
static int pend_room(struct wctx *c, unsigned n_pend)
{
	struct wpend *np;
	uint32_t nc;

	if (n_pend < c->cap_pend)
		return 1;
	nc = c->cap_pend ? c->cap_pend * 2u : W_PENDING_MIN * 2u;
	if (!wcharge(c, (uint64_t)(nc - c->cap_pend) * sizeof *np))
		return 0;
	np = realloc(c->pend, (size_t)nc * sizeof *np);
	if (!np) {
		kgenome_ledger_release(&c->s->led, (uint64_t)(nc - c->cap_pend) * sizeof *np);
		c->charged -= (uint64_t)(nc - c->cap_pend) * sizeof *np;
		kgenome_diag_note(c->s, KGENOME_NOMEM);
		return 0;
	}
	c->pend = np;
	c->cap_pend = nc;
	return 1;
}

/* The summaries of one call, written into the walk's table (valid until the next
 * summarise): at most `var_max` of them. */
static unsigned summarise(struct wctx *c, uint64_t entry, struct tseen *seen, int holds_site)
{
	static const uint8_t p64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_CX, 8u, 9u };
	static const uint8_t pr32[] = { KGENOME_CELL_REG_AX, KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX,
					KGENOME_CELL_REG_BX, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DI,
					KGENOME_CELL_REG_BP };
	struct wpend *pend;
	unsigned n_pend = 0, n_out = 0, i;
	const uint64_t span = span_of(c, entry);
	const uint64_t step_max = 8u * span > W_STEPS_MIN ? 8u * span : W_STEPS_MIN;
	/* The per-path bounds, as functions of the span - see W_BODY_MIN. */
	const unsigned body_max = holds_site && span > W_BODY_MIN
				? (unsigned)(span > 0xffffffu ? 0xffffffu : span) : W_BODY_MIN;
	const unsigned pend_max = span / 8u > W_PENDING_MIN ? (unsigned)(span / 8u > 0xffffffu
								? 0xffffffu : span / 8u)
							    : W_PENDING_MIN;
	const unsigned var_max = span / 8u < W_VARIANTS_MIN ? W_VARIANTS_MIN
			       : span / 8u > W_VARIANTS_CEIL ? W_VARIANTS_CEIL
			       : (unsigned)(span / 8u);
	struct wsum *out;
	uint64_t steps = 0;

	c->cut = 0;
	if (c->over_steps)
		return 0;
	if (!c->var) {
		if (!wcharge(c, (uint64_t)W_VARIANTS_CEIL * sizeof *c->var))
			return 0;
		c->var = malloc((size_t)W_VARIANTS_CEIL * sizeof *c->var);
		if (!c->var) {
			kgenome_ledger_release(&c->s->led,
					       (uint64_t)W_VARIANTS_CEIL * sizeof *c->var);
			c->charged -= (uint64_t)W_VARIANTS_CEIL * sizeof *c->var;
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return 0;
		}
	}
	out = c->var;
	if (seen) {
		/* Attempted: a function is walked again only if this record says a
		 * wrapper has appeared among what it met. Re-noted from scratch. */
		seen->n = 0;
		seen->more = 0;
		seen->done = 1;
	}
	if (!pend_room(c, 0))
		return 0;
	pend = c->pend;
	st_reset(&pend[0].f);
	if (c->wide) {
		for (i = 0; i < 6; i++) {
			pend[0].f.reg[p64[i]].t = V_PARAM;
			pend[0].f.reg[p64[i]].v = i;
		}
	} else {
		/* cdecl: the return address is at offset 0 and the arguments above it */
		for (i = 0; i < 8; i++) {
			struct sv v = { V_PARAM, 0, (int64_t)i };

			slot_put(c, &pend[0].f, (int32_t)(4u + 4u * i), v);
		}
		/*
		 * AND THE REGISTERS, because i386 has no register convention that a
		 * libc is obliged to keep: musl's __vsyscall takes the number in eax
		 * and the arguments in edx, ecx and edi, and enters the kernel from a
		 * helper it reaches with a `call` to the middle of itself. A register
		 * parameter is numbered W_REG_PARAM + register, so a call site can say
		 * which of its own registers it means. MEASURED: 31 of the 400 x86
		 * Bazaar files had no node but one opaque site, all through this helper.
		 */
		for (i = 0; i < sizeof pr32; i++) {
			pend[0].f.reg[pr32[i]].t = V_PARAM;
			pend[0].f.reg[pr32[i]].v = (int64_t)(W_REG_PARAM + pr32[i]);
		}
	}
	pend[0].at = entry;
	pend[0].n = 0;
	n_pend = 1;
	while (n_pend && n_out < var_max) {
		struct wpend *p;
		struct isrc it;
		struct winsn in;
		/*
		 * A COPY, not the table's own entry. The entry that was just taken is
		 * the very slot the next forward branch queues its taken path into, so
		 * walking it in place made the queued path inherit what the fall-through
		 * had since done to the state (musl's __vsyscall: the path that enters
		 * the kernel was evaluated with the stack the other path had pushed
		 * onto, and its number came out unknown).
		 */
		struct fstate fcur;
		struct fstate *f = &fcur;
		unsigned n_insn;

		pend = c->pend;         /* it may have grown since the last path */
		p = &pend[--n_pend];
		n_insn = p->n;
		st_copy(&fcur, &p->f);
		isrc_walk(&it, c, p->at);
		for (;;) {
			struct wsum *callee = NULL;
			uint32_t v;
			int ended = 0;

			if (++n_insn > body_max) {
				c->cut = 1;
				break;
			}
			/* THE TOTAL: every instruction of every path of this summary. */
			if (++steps > step_max) {
				c->cut = 1;
				kgenome_diag_note(c->s, KGENOME_TRUNCATED);
				n_pend = 0;     /* and no path is taken up after it */
				break;
			}
			/* AND THE OBJECT'S: the caller's budget for the whole walk. */
			if (c->s->bud.max_steps && ++c->steps > c->s->bud.max_steps) {
				c->over_steps = 1;
				kgenome_diag_note(c->s, KGENOME_OVER_BUDGET);
				n_pend = 0;
				break;
			}
			if (!isrc_next(&it, &in))
				break;
			/* A direct jump to a function already summarised is a TAIL
			 * CALL: the same question as a call that is followed by ret. */
			if ((in.op == KGENOME_CELL_CALL || in.op == KGENOME_CELL_JMP) &&
			    !(in.flags & KGENOME_CELL_F_INDIRECT) && in.target != KGENOME_BROKEN) {
				callee = wsum_of(c, in.target);
				if (!callee && seen)
					tseen_note(seen, in.target);
			}
			if (is_kernel_entry(c, &in)) {
				if (summarise_end(c, f, entry, &in, NULL, &out[n_out]))
					n_out++;
				break;
			}
			if (callee) {
				uint32_t base = (uint32_t)(callee - c->ws);

				/* A jump leaves the return address where it was, so on a
				 * stack-passed ABI the callee's arguments are one word
				 * further up than they are for a call. */
				if (in.op == KGENOME_CELL_JMP && !c->wide)
					f->sp -= c->w;

				for (v = base; v < c->n_ws &&
					       c->ws[v].entry == c->ws[base].entry; v++) {
					if (n_out >= var_max) {
						c->cut = 1;     /* a variant it would have kept */
						break;
					}
					if (summarise_end(c, f, entry, &in, &c->ws[v],
							  &out[n_out]))
						n_out++;
				}
				ended = 1;
			}
			if (ended)
				break;
			/*
			 * A CALL TO SOMETHING THAT IS NOT A WRAPPER does not end the walk:
			 * it clobbers the caller-saved registers and leaves the frame as it
			 * was. uClibc's fcntl brackets the real call with
			 * pthread_setcancelstate(1, ..) ... (0, ..), and stopping at the
			 * first of them summarised no fcntl at all - 84 of 86 x86 Bazaar
			 * files that set O_NONBLOCK produced no node for it.
			 */
			if (in.op == KGENOME_CELL_CALL) {
				st_call_unknown(c, f);
				continue;
			}
			if (in.op == KGENOME_CELL_JCC && in.target != KGENOME_BROKEN &&
			    in.target > in.at && in.target - entry <= span &&
			    (n_pend >= pend_max || !pend_room(c, n_pend)))
				c->cut = 1;     /* an arm that was not queued, and the path ends */
			if (in.op == KGENOME_CELL_JCC && in.target != KGENOME_BROKEN &&
			    in.target > in.at && in.target - entry <= span &&
			    n_pend < pend_max && n_pend < c->cap_pend) {
				/* the taken path, later; this one carries on */
				pend = c->pend;
				st_copy(&pend[n_pend].f, f);
				pend[n_pend].at = in.target;
				pend[n_pend].n = n_insn;
				n_pend++;
				continue;
			}
			if (in.op == KGENOME_CELL_JMP && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
			    in.target != KGENOME_BROKEN && in.target > in.at &&
			    in.target - entry <= span) {
				isrc_seek(&it, in.target);
				continue;
			}
			/* a call to something else, a return, a jump out: not this path */
			if (in.op == KGENOME_CELL_CALL || in.op == KGENOME_CELL_JMP || in.op == KGENOME_CELL_JCC ||
			    in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_LOOP)
				break;
			st_step(c, f, &in);
		}
	}
	/* The variants were full with paths still queued: arms never visited. */
	if (n_pend && n_out >= var_max)
		c->cut = 1;
	return n_out;
}

/* Keeps the table sorted by entry as it grows, so the lookup above is valid at
 * every moment - the level search consults it while it is being extended. */
static int ws_insert(struct wctx *c, const struct wsum *t)
{
	uint32_t lo = 0, hi = c->n_ws;

	if (c->n_ws == c->cap_ws) {
		uint32_t nc = c->cap_ws ? c->cap_ws * 2u : 32u;
		struct wsum *nw;

		if (!wcharge(c, (uint64_t)(nc - c->cap_ws) * sizeof *nw))
			return 0;
		nw = realloc(c->ws, (size_t)nc * sizeof *nw);
		if (!nw) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return 0;
		}
		c->ws = nw;
		c->cap_ws = nc;
	}
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->ws[mid].entry < t->entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	memmove(&c->ws[lo + 1u], &c->ws[lo], (size_t)(c->n_ws - lo) * sizeof *c->ws);
	c->ws[lo] = *t;
	c->n_ws++;
	return 1;
}

static struct wsum *wsum_of(struct wctx *c, uint64_t entry)
{
	uint32_t lo = 0, hi = c->n_ws;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->ws[mid].entry < entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_ws && c->ws[lo].entry == entry ? &c->ws[lo] : NULL;
}

/* The nearest call target at or before `site`: the function the site is in. No
 * distance limit - the span a summary may cover is the function's own length
 * (span_of), and a site a long way past its entry simply is not reached by
 * the bounded walk, which is reported if it leaves the site unexplained. */
static int entry_of(const struct wctx *c, uint64_t site, uint64_t *entry)
{
	uint32_t lo = 0, hi = c->wk->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->wk->tgt[mid] <= site)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo)
		return 0;
	*entry = c->wk->tgt[lo - 1u];
	return 1;
}

/* ---- the node a call to a wrapper makes ----------------------------------- */

/* The i-th integer parameter of a call, as the caller holds it. */
static struct sv call_param(const struct wctx *c, struct fstate *f, unsigned i)
{
	static const uint8_t p64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_CX, 8u, 9u };

	if (i >= W_REG_PARAM)
		return i - W_REG_PARAM < 16u ? f->reg[i - W_REG_PARAM] : UNK;
	if (c->wide)
		return i < 6u ? f->reg[p64[i]] : UNK;
	/* cdecl: the last value pushed is the first argument. At the call the
	 * stack pointer has not yet taken the return address, so argument i is
	 * i words above the top. */
	return slot_get(f, -f->sp + (int32_t)(4u * i));
}

/* The value of the j-th argument of a socketcall, read from the array the
 * caller built on its stack. */
static struct sv sockcall_arg(const struct wctx *c, struct fstate *f,
			      struct sv ptr, unsigned j)
{
	(void)c;
	if (ptr.t != V_SADDR)
		return UNK;
	return slot_get(f, (int32_t)(ptr.v + 4 * (int64_t)j));
}

/* The wrapper's summary evaluated against the caller's state. */
static void eval_call(const struct wctx *c, struct fstate *f,
		      const struct wsum *ws, struct ev *e)
{
	unsigned i;

	e->nr = ws->nr.t == V_PARAM ? call_param(c, f, (unsigned)ws->nr.v) : ws->nr;
	for (i = 0; i < 6u; i++) {
		struct sv v = ws->arg[i];

		e->arg[i] = v.t == V_PARAM ? call_param(c, f, (unsigned)v.v) : v;
	}
	e->has_arr = 0;
	if (ws->has_arr) {
		e->has_arr = 1;
		for (i = 0; i < 6u; i++) {
			struct sv v = ws->arr[i];

			e->arr[i] = v.t == V_PARAM ? call_param(c, f, (unsigned)v.v) : v;
		}
	} else if (!c->wide && e->nr.t == V_CONST && e->nr.v == 102 &&
		   e->arg[1].t == V_SADDR) {
		e->has_arr = 1;
		for (i = 0; i < 6u; i++)
			e->arr[i] = sockcall_arg(c, f, e->arg[1], i);
	}
}

static struct sv emit_call_node(struct wctx *c, struct fstate *f, struct wsum *ws,
				const struct winsn *in)
{
	struct kgenome_diag_scan *s = c->s;
	struct ev e;
	uint64_t arg[6], nr, sock_arr[6] = { 0 };
	struct sv av[6];
	unsigned have = 0, i;
	int bits = c->wide ? 64 : 32;
	uint16_t cap;
	uint8_t fl = 0;
	const char *nm = NULL;
	struct kgenome_diag_hit *h;

	eval_call(c, f, ws, &e);
	if (e.nr.t != V_CONST)
		return UNK;                     /* which system call is not known */
	nr = (uint64_t)e.nr.v;
	for (i = 0; i < 6u; i++) {
		av[i] = e.arg[i];
		if (av[i].t == V_CONST ||
		    (av[i].t == V_SET &&
		     kgenome_flow_arg_is_flags((unsigned)bits, (uint32_t)nr, i))) {
			arg[i] = (uint64_t)av[i].v;
			have |= 1u << i;
		} else {
			arg[i] = 0;
		}
	}
	/*
	 * i386's socketcall: the sub-call is argument 0 and the operation's own
	 * arguments are the array. What cap that is, and how its arguments map onto
	 * the roles, is the operation's - so the array replaces the register view.
	 */
	if (bits == 32 && nr == 102u) {
		unsigned jhave = 0, j;

		if (!(have & 1u))
			return UNK;             /* which operation is not known */
		for (j = 0; j < 6u; j++) {
			struct sv v = e.has_arr ? e.arr[j] : UNK;

			av[j] = v;
			if (v.t == V_CONST) {
				sock_arr[j] = (uint64_t)v.v;
				jhave |= 1u << j;
			} else {
				sock_arr[j] = 0;
			}
		}
		cap = kgenome_flow_cap_of_sockcall((uint32_t)arg[0], sock_arr, jhave, &fl);
		have = jhave;
	} else {
		cap = kgenome_flow_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
		nm = kgenome_sys_name((unsigned)bits, (uint32_t)nr);
	}
	if (cap == KGENOME_NUCLEO_NONE)
		return UNK;
	h = kgenome_diag_hit_add(s, in->at, cap, fl);
	if (!h)
		return UNK;
	if ((cap == KGENOME_NUCLEO_ALLOC && !(have & (1u << 2))) ||
	    (cap == KGENOME_NUCLEO_NET_OPEN && (have & 3u) != 3u))
		h->bits |= KGENOME_DIAG_H_ARG_UNKNOWN;
	for (i = 0; i < 6u; i++) {
		uint8_t role = kgenome_diag_role_of_arg(cap, i);

		if (role != KGENOME_DIAG_ROLE_NONE && av[i].t == V_NODE)
			kgenome_diag_note_in(c->s, h, av[i].node, role,
					 KGENOME_DIAG_KIND_PRODUCED);
	}
	if (bits == 64 && nm && kgenome_sys_zero_on_success(nm))
		h->bits |= KGENOME_DIAG_H_ZERO_OK;
	ws->node_made = 1;
	if (kgenome_flow_hands_on(cap, nm)) {
		struct sv r = { V_NODE, (uint16_t)(s->n_hit - 1u), 0 };

		if (cap == KGENOME_NUCLEO_NET_OPEN || cap == KGENOME_NUCLEO_NET_RAW) {
			int nb = bits == 32 && nr == 102u
				 ? kgenome_flow_sockcall_nonblock((uint32_t)arg[0], sock_arr, have)
				 : kgenome_flow_sock_nonblock((unsigned)bits, (uint32_t)nr, arg, have);

			if (nb)
				kgenome_diag_hit_nonblock(s, in->at, r.node);
		}
		return r;
	}
	return UNK;
}

/* ---- pass B: the functions, in address order ------------------------------ */

/* Whether the node at `at` is one a function hands back to its callers. */
static int fret_site(const struct wctx *c, uint64_t at)
{
	uint32_t i;

	if (!c->fret)
		return 0;
	for (i = 0; i < c->wk->n_tgt; i++)
		if (c->fret[i] && c->fret[i] - 1u < c->s->n_hit &&
		    c->s->hit[c->fret[i] - 1u].at == at)
			return 1;
	return 0;
}

/* The index of a call target, or -1. */
static int tgt_index(const struct wctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->wk->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->wk->tgt[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->wk->n_tgt && c->wk->tgt[lo] == at ? (int)lo : -1;
}

static void pass_b(struct wctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	struct isrc it;
	struct winsn in;
	struct fstate f;
	int cur = -1;                   /* the call target this code belongs to */
	uint32_t ei;                    /* the first call target not before the code */

	st_reset(&f);
	isrc_scan(&it, c, seg, off, n);
	/*
	 * THE ENTRY TEST IS A MERGE, NOT A SEARCH. The instructions of one scan come
	 * in increasing offset and the targets are sorted, so a position that only
	 * moves forward answers "is this an entry" - a binary search per
	 * instruction was ~90 Ir of a pass that costs ~300 per instruction.
	 */
	{
		uint32_t lo = 0, hi = c->wk->n_tgt;

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (c->wk->tgt[mid] < off)
				lo = mid + 1u;
			else
				hi = mid;
		}
		ei = lo;
	}
	while (!c->s->halt && isrc_next(&it, &in)) {
		struct wsum *ws;

		while (ei < c->wk->n_tgt && c->wk->tgt[ei] < in.at)
			ei++;
		if (ei < c->wk->n_tgt && c->wk->tgt[ei] == in.at) {
			st_reset(&f);
			cur = (int)ei;
		}
		/*
		 * A FUNCTION THAT HANDS BACK WHAT IT MADE. Mirai builds its raw sockets
		 * in a helper - socket, IP_HDRINCL, O_NONBLOCK, `return fd` - and sends
		 * on the result in the attack routine, so the descriptor the send names
		 * is produced in another function. The helper's return value is the
		 * node; the callers, in the second walk, take it from there.
		 */
		if (in.op == KGENOME_CELL_RET && cur >= 0 && c->fret &&
		    f.reg[KGENOME_CELL_REG_AX].t == V_NODE) {
			if (!c->fret[cur] && c->fmiss && c->fmiss[cur])
				c->need_round2 = 1;     /* a caller above asked too early */
			c->fret[cur] = (uint32_t)f.reg[KGENOME_CELL_REG_AX].node + 1u;
		}
		if (in.op == KGENOME_CELL_CALL) {
			ws = (!(in.flags & KGENOME_CELL_F_INDIRECT) && in.target != KGENOME_BROKEN)
			     ? wsum_of(c, in.target) : NULL;
			{
				/* The arguments are read BEFORE the callee's clobbers are
				 * applied, and the result is put in AFTER them. A wrapper
				 * with several paths makes the node of each; they merge. */
				struct sv ret = UNK;

				if (ws) {
					uint32_t v, base = (uint32_t)(ws - c->ws);

					for (v = base; v < c->n_ws &&
						       c->ws[v].entry == c->ws[base].entry; v++) {
						struct sv r = emit_call_node(c, &f, &c->ws[v], &in);

						if (r.t != V_UNK && ret.t == V_UNK)
							ret = r;
					}
				}
				st_call_unknown(c, &f);
				/*
				 * The helper's OWN node wins over the one a summary makes at
				 * the call: the summary stops at the first wrapper the helper
				 * calls (the socket) and knows nothing of the option calls
				 * after it, so the node it makes at the call has none of the
				 * helper's later links, and a send on it could never reach the
				 * IP_HDRINCL that made the socket raw-with-header.
				 */
				if (c->fret && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
				    in.target != KGENOME_BROKEN) {
					int ti = tgt_index(c, in.target);

					if (ti >= 0 && c->fret[ti]) {
						ret.t = V_NODE;
						ret.node = (uint16_t)(c->fret[ti] - 1u);
					} else if (ti >= 0 && c->fmiss) {
						c->fmiss[ti] = 1;
					}
				}
				f.reg[KGENOME_CELL_REG_AX] = ret;
			}
			continue;
		}
		st_step(c, &f, &in);
	}
}

/* ---- the entry point ----------------------------------------------------- */

/* The entries, sorted and each once. */
static void tgt_unique(struct wctx *c)
{
	uint32_t i, w = 0;

	if (c->wk->n_tgt)
		qsort(c->wk->tgt, c->wk->n_tgt, sizeof *c->wk->tgt, kgenome_cmp_u64);
	for (i = 0; i < c->wk->n_tgt; i++)
		if (!w || c->wk->tgt[w - 1u] != c->wk->tgt[i])
			c->wk->tgt[w++] = c->wk->tgt[i];
	c->wk->n_tgt = w;
}

void kgenome_diag_run_wrappers(struct kgenome_diag_scan *s,
			   const struct kgenome_obj *obj,
			   const uint8_t *base, uint64_t size)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	struct kgenome_diag_walk *wk;
	struct wctx c;
	uint32_t i;

	if (!e || !e->valid)
		return;
	if (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64)
		return;
	wk = kgenome_diag_scan_walk(s);
	if (!wk)
		return;
	memset(&c, 0, sizeof c);
	c.s = s;
	c.obj = obj;
	c.base = base;
	kgenome_cell_space_init(&c.sp, obj, base, size);
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;
	c.wk = wk;
	/* The walk is the object's, made once: it is already here when the
	 * functions were asked for first, and made here otherwise. */
	if (!kgenome_diag_walk_ensure(wk, obj, base, size, 1)) {
		kgenome_diag_note(s, KGENOME_NOMEM);     /* the decode walk could not be held */
		return;
	}
	if (!wk->n_site)
		goto opaque;
	for (i = 0; i < s->n_hit; i++)
		if (s->hit[i].cap == KGENOME_NUCLEO_NONE &&
		    (s->hit[i].bits & KGENOME_DIAG_H_OPAQUE) &&
		    !push_u64(&c.open, &c.n_open, &c.cap_open, s->hit[i].at)) {
			kgenome_diag_note(s, KGENOME_NOMEM);
			goto out;
		}
	/* qsort's base is declared nonnull, and with no elements it is NULL. */
	if (c.n_open)
		qsort(c.open, c.n_open, sizeof *c.open, kgenome_cmp_u64);
	tgt_unique(&c);
	if (!wcharge(&c, (uint64_t)(wk->n_tgt ? wk->n_tgt : 1u) *
			 (sizeof *c.fret + sizeof *c.fmiss)))
		goto out;
	c.fret = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.fret);
	c.fmiss = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.fmiss);
	if (!c.fret || !c.fmiss) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	if (!wcharge(&c, (uint64_t)(wk->n_tgt ? wk->n_tgt : 1u) * sizeof *c.tseen))
		goto out;
	c.tseen = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.tseen);
	if (!c.tseen) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	/*
	 * LEVEL 0: the functions that hold a syscall. THEN THE LEVELS: the functions
	 * whose straight line ends in a call to one already found, again and again
	 * until a level adds nothing (socket() around __socketcall around the
	 * syscall is three; the step budget is the bound).
	 */
	c.cap_ws = wk->n_site + 64u;
	if (!wcharge(&c, (uint64_t)c.cap_ws * sizeof *c.ws)) {
		c.cap_ws = 0;
		goto out;
	}
	c.ws = calloc(c.cap_ws, sizeof *c.ws);
	if (!c.ws) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	for (i = 0; i < wk->n_site; i++) {
		uint64_t entry;
		struct wsum *t;
		unsigned nt, v;

		int ti;

		if (!entry_of(&c, wk->site[i], &entry))
			continue;
		if (wsum_of(&c, entry))
			continue;
		ti = tgt_index(&c, entry);
		/* A function with several sites is summarised once, and again only if
		 * a wrapper has appeared among what its walk met - see struct tseen. */
		if (ti >= 0 && !tseen_retry(&c, &c.tseen[ti]))
			continue;
		nt = summarise(&c, entry, ti >= 0 ? &c.tseen[ti] : NULL, 1);
		t = c.var;
		/*
		 * A CAP CUT THE SUMMARY OF THE FUNCTION THAT HOLDS THIS SITE, and it cost an
		 * explanation when the sweep could not read the site either (the cap is
		 * what left it unexplained) or when the summary that WAS made is partial
		 * (a wrapper whose other arms were dropped): the scan says so.
		 *
		 * NOT FOR EVERY CUT. A function of two hundred instructions that holds a
		 * syscall deep inside is the ordinary case in a static libc, the body bound ends
		 * its walk, nothing was found and the sweep read the site directly - that
		 * loses no evidence and is not reported, or every static binary would
		 * come back "partial". (Measured on the prof set: see the report. One
		 * case this does not catch: a wrapper whose every arm is cut before
		 * it yields a summary, at a site the sweep read from the caller's stale
		 * constants - W_PENDING in tests/unit/caps_wrap.c.)
		 */
		if (c.cut && (nt > 0 || site_open(&c, wk->site[i]) ||
			      site_wrapped(s, wk->site[i])))
			kgenome_diag_note(s, KGENOME_TRUNCATED);
		for (v = 0; v < nt; v++)
			(void)ws_insert(&c, &t[v]);
	}
	if (c.n_ws) {
		uint32_t added = 0;

		/* TO A FIXPOINT, bounded by the step budget: see the note on levels. */
		for (;;) {
			added = 0;
			if (s->bud.max_steps && c.steps + wk->n_tgt > s->bud.max_steps) {
				/* another pass cannot be paid for: whatever it would have added
				 * was never looked for, and the scan says so. */
				kgenome_diag_note(s, KGENOME_OVER_BUDGET);
				break;
			}
			c.steps += wk->n_tgt;
			for (i = 0; i < wk->n_tgt; i++) {
				struct wsum *t;
				unsigned nt, v;

				if (wsum_of(&c, wk->tgt[i]) || !tseen_retry(&c, &c.tseen[i]))
					continue;
				nt = summarise(&c, wk->tgt[i], &c.tseen[i], 0);
				t = c.var;
				for (v = 0; v < nt; v++) {
					if (!ws_insert(&c, &t[v]))
						break;
					added++;
				}
			}
			if (!added || c.over_steps)
				break;
		}
	}
	if (!c.n_ws)
		goto opaque;
	/*
	 * TWICE, because a descriptor kept in a global is stored where the program
	 * dials out and read where it listens, and which of the two functions comes
	 * first in the file is the compiler's business. The second walk starts with
	 * every global the first one saw produced, so a read that came before the
	 * write in address order still finds it. The nodes it makes are the first
	 * walk's again, merged by site at the end of the scan, with the links the
	 * first walk could not yet have.
	 */
	{
		unsigned round;

		/*
		 * THE SECOND ROUND ONLY WHEN IT CAN DIFFER. It starts with the
		 * globals the first produced, so it changes the result exactly
		 * when some global was read before the first round had written it
		 * (need_round2) or a call asked for what a helper returns before the
		 * walk had reached the helper. Otherwise it would decode the whole image again
		 * to arrive at the same nodes: MEASURED, pass_b is a full linear
		 * decode and this was the third of three over the same bytes.
		 */
		for (round = 0; round < 2u; round++) {
			if (round && !c.need_round2)
				break;
			for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
				uint64_t at, have = kgenome_diag_walk_range(obj, e, i, size, &at);

				if (have)
					pass_b(&c, i, at, have);
			}
		}
	}
	/* A wrapper some caller made a node for is answered at its callers; the
	 * node the sweep made at the syscall inside it spoke for every caller at
	 * once and for none of them, and is set aside. */
	for (i = 0; i < c.n_ws; i++) {
		uint32_t j;

		if (!c.ws[i].node_made || fret_site(&c, c.ws[i].site))
			continue;       /* a helper's own node is the one callers use */
		for (j = 0; j < s->n_hit; j++)
			if (s->hit[j].at == c.ws[i].site &&
			    !(s->hit[j].bits & KGENOME_DIAG_H_SUPERSEDED))
				s->hit[j].bits |= KGENOME_DIAG_H_SUPERSEDED;
	}
opaque:
	/* A socketcall of an unknown kind is a different statement from no
	 * socketcall at all: a site nobody called with a value this could read
	 * says so, once, rather than saying nothing. */
	for (i = 0; i < s->n_wrap; i++) {
		uint32_t j;
		int made = 0;

		for (j = 0; j < c.n_ws; j++)
			if (c.ws[j].site == s->wrap[i] && c.ws[j].node_made)
				made = 1;
		if (!made) {
			struct kgenome_diag_hit *h = kgenome_diag_hit_add(s, s->wrap[i],
								  KGENOME_NUCLEO_NONE, 0);

			if (h)
				h->bits |= KGENOME_DIAG_H_OPAQUE;
		}
	}
out:
	/* The trace STAYS with a walk the scanner owns, to the end of the object:
	 * the xref sweep reads the same instructions (see kgenome_diag_code_run), and
	 * the scanner frees the walk when the next object begins. A walk this scan
	 * made for itself has no other reader - nobody can hand it to the sweep - so
	 * its trace goes now, as it always did: a tool that keeps a scan alive to
	 * show it must not keep an object's worth of decode with it. */
	if (wk == s->own_walk)
		walk_drop_trace(wk);
	free(c.open);
	free(c.pend);
	free(c.var);
	free(c.tseen);
	free(c.fret);
	free(c.fmiss);
	free(c.ws);
	free(c.glob);
	kgenome_ledger_release(&s->led, c.charged);
}

/*
 * THE WALK'S LIFE. One walk per object, made on the first ask and read by every
 * later one - the functions (the entries) and the wrapper resolution (the
 * entries, the kernel-entry sites and, in the same decode, the trace).
 *
 * `want_trace` is the caller saying it will read the code again after this. A
 * walk made without one that is later asked for one is made again (what two
 * walks cost before this existed); one made with it serves both. The trace is
 * bounded by W_TRACE_BYTES exactly as it was. It lives as long as the walk does
 * - to the end of the object - because two readers use it, the wrapper
 * resolution and the xref sweep (kgenome_diag_code_run), and which asks first is
 * the rules' business. It is freed with the walk, or when a walk made without
 * one is made again.
 */
struct kgenome_diag_walk *kgenome_diag_walk_new(void)
{
	return calloc(1, sizeof(struct kgenome_diag_walk));
}

static void walk_drop_trace(struct kgenome_diag_walk *wk)
{
	if (!wk)
		return;
	if (wk->lg)
		kgenome_ledger_release(wk->lg, wk->lg_charged);
	wk->lg_charged = 0;
	free(wk->tr);
	free(wk->ix);
	wk->tr = NULL;
	wk->ix = NULL;
	wk->n_tr = wk->cap_tr = wk->n_ix = wk->cap_ix = 0;
	wk->has_trace = 0;
	memset(wk->tseg, 0, sizeof wk->tseg);
}

static void walk_reset(struct kgenome_diag_walk *wk)
{
	struct kgenome_ledger *lg = wk->lg;

	walk_drop_trace(wk);
	free(wk->tgt);
	free(wk->site);
	memset(wk, 0, sizeof *wk);
	wk->lg = lg;                    /* who holds the walk is not part of what it holds */
}

/*
 * A SCAN TAKES THE WALK, or lets it go. While bound, the walk's trace is
 * charged to the scan's ledger (what it already holds, now; what it grows by,
 * as it grows); unbound - the scan is freed, and the walk goes on to the next
 * reader in the object's life - nothing refers to a ledger that is gone.
 */
void kgenome_diag_walk_bind(struct kgenome_diag_walk *wk, struct kgenome_ledger *lg)
{
	if (!wk || wk->lg == lg)
		return;
	if (wk->lg)
		kgenome_ledger_release(wk->lg, wk->lg_charged);
	wk->lg = lg;
	wk->lg_charged = 0;
	if (lg) {
		uint64_t have = (uint64_t)wk->cap_tr + (uint64_t)wk->cap_ix * sizeof *wk->ix;

		if (have && kgenome_ledger_try(lg, have))
			wk->lg_charged = have;
	}
}

void kgenome_diag_walk_free(struct kgenome_diag_walk *wk)
{
	if (!wk)
		return;
	walk_reset(wk);
	free(wk);
}

/* The walk of the executable segments of an ELF, through celllysis, whichever
 * architecture it has a decoder for. Kernel-entry sites are x86's and are
 * recorded for x86 only. 1 when it holds the answer. */
int kgenome_diag_walk_ensure(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, int want_trace)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	struct wctx c;
	uint32_t i;
	int x86 = obj->arch == KGENOME_ARCH_X86 || obj->arch == KGENOME_ARCH_X86_64;

	if (!wk || !e || !e->valid || obj->format != KGENOME_FMT_ELF)
		return 0;
	if (wk->built && wk->base == base && wk->size == size &&
	    (wk->has_trace || !want_trace))
		return 1;
	walk_reset(wk);
	memset(&c, 0, sizeof c);
	c.obj = obj;
	c.base = base;
	kgenome_cell_space_init(&c.sp, obj, base, size);
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;
	c.wk = wk;
	wk->base = base;
	wk->size = size;
	wk->sites = x86;
	wk->has_trace = want_trace && x86;
	wk->tr_on = wk->has_trace && size <= 0xffffffffu;
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		uint64_t at, have = kgenome_diag_walk_range(obj, e, i, size, &at);

		if (have && !pass_a(&c, i, at, have)) {
			walk_reset(wk);
			return 0;
		}
	}
	tgt_unique(&c);
	wk->built = 1;
	return 1;
}

const uint64_t *kgenome_diag_walk_entries(const struct kgenome_diag_walk *wk, uint32_t *n)
{
	*n = wk->n_tgt;
	return wk->tgt;
}

/* The scan's walk: the one it was given, else one of its own. */
struct kgenome_diag_walk *kgenome_diag_scan_walk(struct kgenome_diag_scan *s)
{
	if (!s->walk) {
		s->own_walk = kgenome_diag_walk_new();
		s->walk = s->own_walk;
		kgenome_diag_walk_bind(s->walk, &s->led);
	}
	return s->walk;
}
