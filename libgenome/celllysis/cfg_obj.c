/*
 * cfg_obj.c - kgenome_cfg_obj_build: the blocks of a whole object, by recursive descent from the entries the caller trusts. See cfg.h, THE BLOCK LAYER,
 * for what the product holds and what it does not know.
 *
 * THREE STEPS. (1) THE DESCENT: a worklist of offsets (the seeds, then every direct branch and call target met); from each, instructions are read in
 * order until the flow leaves (a jump, a return, an exit, after the delay slots), the bytes stop being code, the path reaches an instruction another
 * path already read (a join), or a direct call WAITS for its callee (below). A byte map says, for every byte of the extents, whether an instruction
 * starts there, is inside one, or neither, so each offset is read ONCE whatever reaches it. (2) THE PROOF, when nothing is left to read and calls still
 * wait: which callees cannot return (their callers' continuations are never read) and which depend on a recursion cycle (resolved as returning, said);
 * then (1) again with what was released. (3) THE BLOCKS: the instructions in address order, cut at the leaders (a seed, a target, the instruction after
 * a block end, a join, the end of a call whose callee does not return); successors resolved to block indices once.
 *
 * WHETHER A RETURN CAN BE REACHED ("R", fx X_RET), kept per instruction as it is read, never recomputed: an instruction has R when it is a return, a
 * conditional exit, an indirect jump or the last one before a stop for want of code (each of those may return: the conservative side), or when an
 * instruction it leads to has R - its fall-through, its branch target, and for a direct call the continuation AND the callee both. When R becomes true at
 * an instruction it is handed back to what leads to it (the instruction that runs into it, found in the byte map; the branches that target it and the
 * calls that wait on it, kept in a list per place), so the whole propagation costs one visit per instruction and per edge (Horn clauses by counting).
 * A waiting call is RELEASED (its continuation queued, read once) the moment its callee gets R.
 *
 * TODO(owner): option b (deferred fall-through) chosen by default over option a (rebuild with a noret list) - coordinator default 2026-11-16: one decode per
 * instruction and no second pass; the old behaviour ("a call is assumed to return") is not kept as an option, because the only behaviour a call to a
 * returning callee can have is the same in both (the same instructions, the same blocks), so the old one is this one with every proof skipped (rule 10).
 *
 * WHY NOT THE LINEAR WALK. The walk (diag_wrapper_walk.c) reads every byte of a code extent in order, so data in the code (strings, tables, literal
 * pools) becomes instructions and its "calls" become function starts (D6), and an instruction stream that desynchronised stays wrong until it happens to
 * resynchronise. Here an offset is read only when a path that runs reaches it. The walk's decode is not repeated: an offset the walk decoded at the same
 * alignment is read back from its trace through the space's `held` (kgenome_diag_walk_hold); `n_fresh` counts the ones it had not (a target inside what
 * the linear walk read as one instruction, i.e. where the two disagree).
 */
#include "cfg_private.h"
#include "celllysis.h"

#include <string.h>

/* The byte map: the low two bits are the state of the byte, the rest are facts of an instruction start. */
#define M_STATE    0x03u
#define M_START    0x01u        /* an instruction starts here */
#define M_BODY     0x02u        /* inside an instruction (not its first byte) */
#define M_LEAD     0x04u        /* a block starts here: a seed, a target, after a block end, a join */
#define M_SEED     0x08u
#define M_CALLED   0x10u
#define M_BRANCHED 0x20u

/* One instruction read: what steps (2) and (3) need of it and nothing more (32 bytes). */
#define R_CALL     0x01u        /* a call (it does not end a block) */
#define R_INDIRECT 0x02u        /* a call through a register or memory */
#define R_LINKED   0x04u        /* ARM: a jump the instruction before made a call */
#define R_FRESH    0x08u        /* decoded here: `held` did not answer */
#define R_FLOW     0x10u        /* the flow instruction of its block: `term` and `target` are its */
#define R_TRAP     0x20u        /* the trap behind a call that does not return (traps): it runs on into nothing */

/* What the proof knows of it (`fx`). */
#define X_RET      0x01u        /* a return may be reached from here */
#define X_WAIT     0x02u        /* a direct call whose continuation waits for its callee */
#define X_DEAD     0x04u        /* a direct call whose callee is proven not to return: term T_NORET, the continuation is not read */
#define X_ASSUMED  0x08u        /* the entry of a callee resolved as returning by assumption */
#define X_FINAL    0x10u        /* proven, for good, to reach no return (a later round does not look at it again) */

#define NIL 0xffffffffu

struct rec {
	uint64_t off;
	uint64_t target;        /* a direct branch's or call's target (file offset), else KGENOME_BROKEN */
	uint32_t in;            /* the first edge (struct ie) that names this instruction: a branch to it, a call waiting on it; NIL */
	uint8_t  len;
	uint8_t  flags;         /* R_* */
	uint8_t  term;          /* enum kgenome_cfg_obj_term, for R_FLOW */
	uint8_t  stop;          /* enum kgenome_cfg_obj_why: the path stopped right after this instruction */
	uint8_t  fx;            /* X_* (on the HEAD of a delay slot: the branch or the call) */
	uint8_t  back;          /* a delay slot: how many records back its branch or call is (0: not a slot) */
	uint8_t  pad_[2];
};

/* An edge into a place: `src` (a record) is a branch to it, or (`call`) a call that waits on it. */
struct ie {
	uint32_t src, next;
	uint8_t  call;
	uint8_t  pad_[3];
};

struct wl {
	uint64_t off, from;     /* a place to read, and the branch or call that named it (KGENOME_BROKEN for a seed) */
	uint32_t rec;           /* a released continuation: the last record of its call (no leader is made; a stop is said on it); NIL for a target */
	uint32_t pad_;
};

struct ext {
	uint64_t off, len, map;  /* the extent, and where its bytes begin in the map */
};

struct ctx {
	const struct kgenome_cfg_obj_req *rq;
	struct kgenome_cfg_obj *out;
	const struct kgenome_cfg_isa *isa;
	struct kgenome_cell_space sp;   /* the caller's, with `held` counted */
	int code_be;            /* the code's byte order (the space's, less ARM BE8) */
	struct ext *ext;
	uint32_t n_ext, cap_ext;
	uint64_t *bt;           /* step (3): the direct target of each block's flow instruction */
	uint32_t cap_bt;
	uint8_t *map;
	uint32_t *ix;           /* per byte of the map: the record that starts there (M_START), else the first edge waiting for the place, else NIL */
	uint64_t map_n;
	struct rec *r;
	uint32_t n_r, cap_r;
	struct wl *wl;
	uint32_t n_wl, cap_wl;
	struct ie *ie;
	uint32_t n_ie, cap_ie;
	uint32_t *q;            /* records whose R was just set, to hand back to what leads to them */
	uint32_t n_q, cap_q;
	uint32_t n_wait;        /* calls waiting for their callee */
	uint64_t served;        /* answers `held` gave */
	uint64_t held;          /* bytes this call holds (the budget's measure) */
	uint64_t max_insn;
	int over;               /* the work bound or the byte bound fired */
	int no_wait;            /* the proof rounds are spent (KGENOME_CFG_OBJ_PROOF_ROUNDS): a call no longer waits, its callee is assumed to return */
	int nomem;
};

static uint32_t held_counted(void *priv, uint64_t off, uint64_t va, uint32_t left, struct kgenome_cell_insn *out)
{
	struct ctx *c = priv;
	const uint32_t n = c->rq->sp->held(c->rq->sp->held_priv, off, va, left, out);

	if (n)
		c->served++;
	return n;
}

/* Grow an array of `each`-byte entries to hold `need`, charged to the call's allowance. 0: refused (`over` or `nomem` says which). */
static int grow(struct ctx *c, void **v, uint32_t *cap, uint32_t need, size_t each)
{
	uint32_t nc;
	void *nv;

	if (need <= *cap)
		return 1;
	nc = *cap ? *cap : 64u;
	while (nc < need)
		nc = nc > UINT32_MAX / 2u ? UINT32_MAX : nc * 2u;
	/* while the entries are copied the old array and the new one are both held: that is what the allowance is asked for */
	if (kgenome_cfg_over(c->rq->budget, c->held + (uint64_t)nc * each)) {
		c->over = 1;
		return 0;
	}
	nv = kgenome_cfg_alloc(&c->rq->mem, (size_t)nc * each);
	if (!nv) {
		c->nomem = 1;
		return 0;
	}
	if (*v) {
		memcpy(nv, *v, (size_t)*cap * each);
		kgenome_cfg_release(&c->rq->mem, *v, (size_t)*cap * each);
	}
	c->held += (uint64_t)(nc - *cap) * each;
	*v = nv;
	*cap = nc;
	return 1;
}

/* The extent that holds `off`, or -1. The extents are few (a segment or section table) and sorted. */
static int ext_of(const struct ctx *c, uint64_t off)
{
	uint32_t lo = 0, hi = c->n_ext;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (c->ext[mid].off <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo || off - c->ext[lo - 1u].off >= c->ext[lo - 1u].len)
		return -1;
	return (int)(lo - 1u);
}

static uint8_t *map_at(const struct ctx *c, int k, uint64_t off)
{
	return c->map + c->ext[k].map + (off - c->ext[k].off);
}

static uint32_t *ix_at(const struct ctx *c, int k, uint64_t off)
{
	return c->ix + c->ext[k].map + (off - c->ext[k].off);
}

/* The branch or call a delay slot belongs to; any other record is its own head. */
static uint32_t head_of(const struct ctx *c, uint32_t i)
{
	return i - c->r[i].back;
}

/* The last record of head `i` (its last delay slot, or itself) and, in *x, the place after it. */
static uint32_t slot_end(const struct ctx *c, uint32_t i, uint64_t *x)
{
	uint32_t j = i;

	while (j + 1u < c->n_r && c->r[j + 1u].back == j + 1u - i)
		j++;
	*x = c->r[j].off + c->r[j].len;
	return j;
}

/* Does head `i` run on into the place after it (*x)? A conditional branch or exit does, an instruction that does not change the flow does, a call does once
 * its callee is known to return; a path that stopped does not. */
static int falls(const struct ctx *c, uint32_t i, uint64_t *x)
{
	const struct rec *r = &c->r[i];

	if (c->r[slot_end(c, i, x)].stop)
		return 0;
	if (r->flags & R_FLOW)
		return r->term == KGENOME_CFG_OBJ_T_COND || r->term == KGENOME_CFG_OBJ_T_COND_EXIT;
	return !(r->fx & (X_WAIT | X_DEAD));
}

static void loose(struct ctx *c, uint64_t from, uint64_t target, uint8_t why)
{
	struct kgenome_cfg_obj *o = c->out;

	if (from == KGENOME_BROKEN)
		return;                 /* a seed: its entry says why (step 3) */
	if (!grow(c, (void **)&o->loose, &o->cap_loose_, o->n_loose + 1u, sizeof *o->loose))
		return;
	memset(&o->loose[o->n_loose], 0, sizeof *o->loose);
	o->loose[o->n_loose].from = from;
	o->loose[o->n_loose].target = target;
	o->loose[o->n_loose].why = why;
	o->n_loose++;
}

/* R is true at record `i` (at its head): hand it back to what leads there (drain). A refused allocation loses the hand-back and sets `over` / `nomem`, and the
 * proof then proves nothing (resolve). */
static void set_ret(struct ctx *c, uint32_t i)
{
	i = head_of(c, i);
	if (c->r[i].fx & X_RET)
		return;
	c->r[i].fx |= X_RET;
	if (!grow(c, (void **)&c->q, &c->cap_q, c->n_q + 1u, sizeof *c->q))
		return;
	c->q[c->n_q++] = i;
}

/* Record that `src` (a branch, or a call when `call`) goes to the place whose list head is `*head`. */
static void edge_in(struct ctx *c, uint32_t *head, uint32_t src, uint8_t call)
{
	uint32_t h = *head;     /* `head` may point into a table edge_in does not grow (the map's index, a record): read before the growth all the same */

	if (!grow(c, (void **)&c->ie, &c->cap_ie, c->n_ie + 1u, sizeof *c->ie))
		return;
	c->ie[c->n_ie].src = src;
	c->ie[c->n_ie].next = h;
	c->ie[c->n_ie].call = call;
	*head = c->n_ie++;
}

/* A place the flow names: a leader with the fact `flag`, read later when no path has read it yet. The extent that holds it, or -1 when it cannot be read
 * (outside every extent, inside another instruction: LOOSE, said; or the worklist could not grow). */
static int push(struct ctx *c, uint64_t off, uint64_t from, uint8_t flag)
{
	int k;
	uint8_t *m;

	if (off == KGENOME_BROKEN || (k = ext_of(c, off)) < 0) {
		loose(c, from, off, KGENOME_CFG_OBJ_W_OUTSIDE);
		return -1;
	}
	m = map_at(c, k, off);
	if ((*m & M_STATE) == M_BODY) {
		loose(c, from, off, KGENOME_CFG_OBJ_W_OVERLAP);
		return -1;
	}
	*m |= (uint8_t)(M_LEAD | flag);
	if ((*m & M_STATE) == M_START)
		return k;               /* read already: the leader bit is all it needs */
	if (!grow(c, (void **)&c->wl, &c->cap_wl, c->n_wl + 1u, sizeof *c->wl))
		return -1;
	c->wl[c->n_wl].off = off;
	c->wl[c->n_wl].from = from;
	c->wl[c->n_wl].rec = NIL;
	c->wl[c->n_wl].pad_ = 0;
	c->n_wl++;
	return k;
}

/* The record at a place the flow named and that was read, when it can carry an edge: an instruction start that is no delay slot. NIL otherwise. */
static uint32_t rec_at(const struct ctx *c, int k, uint64_t off)
{
	uint32_t j;

	if ((*map_at(c, k, off) & M_STATE) != M_START)
		return NIL;
	j = *ix_at(c, k, off);
	return j != NIL && !c->r[j].back ? j : NIL;
}

/* Record `i` is a direct branch to `x`: R reaches it from there. A target this descent cannot read (outside, overlap, a delay slot) may return. */
static void branch_to(struct ctx *c, uint32_t i, uint64_t x)
{
	const int k = push(c, x, c->r[i].off, M_BRANCHED);
	uint32_t j;

	if (k < 0) {
		set_ret(c, i);
		return;
	}
	if ((*map_at(c, k, x) & M_STATE) != M_START) {
		edge_in(c, ix_at(c, k, x), i, 0);
		return;
	}
	if ((j = rec_at(c, k, x)) == NIL || (c->r[j].fx & X_RET))
		set_ret(c, i);
	else
		edge_in(c, &c->r[j].in, i, 0);
}

static void dead(struct ctx *c, uint32_t i)
{
	struct rec *r = &c->r[i];

	if (r->fx & X_WAIT)
		c->n_wait--;
	r->fx = (uint8_t)((r->fx & ~X_WAIT) | X_DEAD);
	r->flags |= R_FLOW;
	r->term = KGENOME_CFG_OBJ_T_NORET;
	c->out->n_noret_call++;
}

/* Record `i` is a direct call to `in->target`. 1 when the path stops after the call's delay slots: the callee's answer is not known yet (the call WAITS) or the
 * callee is proven not to return (DEAD). 0: the path goes on - the callee returns, or this descent cannot read it (outside the extents, inside another
 * instruction, in the other instruction set) and it is assumed to return, as a call through a register is. */
/* KNOWN DEFECT FPART-D4 (2026-11-17, M) [sev L]: call_to assumes a callee it cannot read (through a register, outside the extents: a PLT slot, exact code) returns,
 * so the bytes after `call *__libc_start_main@GOT; hlt` are read on into the alignment padding. Trigger: x86 _start of dynamic and uClibc builds.
 * Effect: the derived _start is longer than its symbol by the padding (R2: 2 twins, 280 CHA no-unwind builds), no byte of another function is taken.
 * Reproducer: /mnt/games/normtest/fix_part/h/r12.py (stripped twins, out/t4_twins/fail.txt). Fix: FU-PM5-6, the return status of an exact callee by the same descent. */
static int call_to(struct ctx *c, uint32_t i, const struct kgenome_cell_insn *in)
{
	const uint64_t x = in->target;
	int k;
	uint32_t j;

	if (kgenome_cfg_isa_interworks(c->isa, in, c->sp.base, c->sp.size, c->code_be)) {
		loose(c, in->at, x, KGENOME_CFG_OBJ_W_ISA);
		return 0;
	}
	if ((k = push(c, x, in->at, M_CALLED)) < 0 || c->no_wait)
		return 0;
	if ((*map_at(c, k, x) & M_STATE) != M_START) {
		edge_in(c, ix_at(c, k, x), i, 1);
	} else {
		if ((j = rec_at(c, k, x)) == NIL || (c->r[j].fx & X_RET))
			return 0;
		if (c->r[j].fx & X_FINAL) {
			dead(c, i);
			return 1;
		}
		edge_in(c, &c->r[j].in, i, 1);
	}
	c->r[i].fx |= X_WAIT;
	c->n_wait++;
	return 1;
}

/* The waiting call `k` (a head) may go on: its callee returns, or is assumed to. Its continuation is read once, as part of the call's block (no leader). */
static void release(struct ctx *c, uint32_t k)
{
	uint64_t x;
	uint32_t last;
	uint32_t j;
	int e;

	if (!(c->r[k].fx & X_WAIT))
		return;
	c->r[k].fx &= (uint8_t)~X_WAIT;
	c->n_wait--;
	last = slot_end(c, k, &x);
	e = ext_of(c, x);
	if (e < 0 || (*map_at(c, e, x) & M_STATE) == M_BODY) {
		c->r[last].stop = e < 0 ? KGENOME_CFG_OBJ_W_OUTSIDE : KGENOME_CFG_OBJ_W_OVERLAP;
		set_ret(c, k);
		return;
	}
	if ((*map_at(c, e, x) & M_STATE) == M_START) {        /* another path read it (a target there): a join */
		j = *ix_at(c, e, x);
		if (c->r[head_of(c, j)].fx & X_RET)
			set_ret(c, k);
		return;
	}
	if (!grow(c, (void **)&c->wl, &c->cap_wl, c->n_wl + 1u, sizeof *c->wl)) {
		c->r[last].stop = KGENOME_CFG_OBJ_W_BUDGET;    /* the continuation could not be queued: said on the call */
		return;
	}
	c->wl[c->n_wl].off = x;
	c->wl[c->n_wl].from = c->r[k].off;
	c->wl[c->n_wl].rec = last;
	c->wl[c->n_wl].pad_ = 0;
	c->n_wl++;
}

/* Edges into a place whose answer will not be known (from `e` on): a branch to it may return, a call to it is assumed to return. */
static void unknown_edges(struct ctx *c, uint32_t e)
{
	for (; e != NIL; e = c->ie[e].next) {
		if (c->ie[e].call)
			release(c, c->ie[e].src);
		else
			set_ret(c, c->ie[e].src);
	}
}

/* The edges waiting at a place that will not be read (inside another instruction, bytes that decode as nothing, the work bound). */
static void orphan(struct ctx *c, int k, uint64_t off)
{
	uint32_t *h = ix_at(c, k, off), e = *h;

	if ((*map_at(c, k, off) & M_STATE) == M_START)
		return;
	*h = NIL;
	unknown_edges(c, e);
}

/* The record whose bytes end exactly at `x` in extent `k`, or NIL (the map's states, read back at most one instruction's length). */
static uint32_t ends_at(const struct ctx *c, int k, uint64_t x)
{
	uint64_t y = x;

	while (y > c->ext[k].off && x - y < 16u) {
		const uint8_t s = *map_at(c, k, --y) & M_STATE;

		if (s == M_START) {
			const uint32_t j = *ix_at(c, k, y);

			return j != NIL && c->r[j].off + c->r[j].len == x ? j : NIL;
		}
		if (s != M_BODY)
			return NIL;
	}
	return NIL;
}

/* Hand every R that was set back to what leads to it, until nothing is left: the instruction that runs into it, the branches to it, the calls waiting on it. */
static void drain(struct ctx *c)
{
	while (c->n_q) {
		const uint32_t i = c->q[--c->n_q];
		const int k = ext_of(c, c->r[i].off);
		uint32_t p, e;
		uint64_t y;

		if (k >= 0 && (p = ends_at(c, k, c->r[i].off)) != NIL) {
			p = head_of(c, p);
			if (falls(c, p, &y) && y == c->r[i].off)
				set_ret(c, p);
		}
		for (e = c->r[i].in; e != NIL; e = c->ie[e].next) {
			if (c->ie[e].call)
				release(c, c->ie[e].src);
			else
				set_ret(c, c->ie[e].src);
		}
	}
}

/* The term of a flow instruction, from the one table (cfg_isa.c). KGENOME_CFG_OBJ_T_FALL: it does not change the flow. */
static uint8_t term_of(const struct ctx *c, const struct kgenome_cell_insn *in)
{
	int deg = 0;

	if (!kgenome_cfg_op_is_flow(in->op))
		return KGENOME_CFG_OBJ_T_FALL;
	switch (kgenome_cfg_isa_class(c->isa, in, c->sp.be, NULL, 0, &deg)) {
	case KGENOME_CFG_X_BR_COND:
		return KGENOME_CFG_OBJ_T_COND;
	case KGENOME_CFG_X_BR_JUMP:
		return KGENOME_CFG_OBJ_T_JUMP;
	case KGENOME_CFG_X_COND_EXIT:
		return KGENOME_CFG_OBJ_T_COND_EXIT;
	case KGENOME_CFG_X_EXIT:
		if (kgenome_cfg_isa_returns(c->isa, in))
			return KGENOME_CFG_OBJ_T_RET;
		if (in->op == KGENOME_CELL_JMP && (in->flags & KGENOME_CELL_F_INDIRECT) && !(in->flags & KGENOME_CELL_F_FAR))
			return KGENOME_CFG_OBJ_T_INDIRECT;
		return KGENOME_CFG_OBJ_T_EXIT;
	default:
		return KGENOME_CFG_OBJ_T_FALL;
	}
}

/* Is `in`, which starts in extent `k`, free to be read: inside the extent, and no byte of it read by another path? The why when not. */
static uint8_t room_for(const struct ctx *c, int k, const struct kgenome_cell_insn *in)
{
	const uint8_t *m;
	uint32_t i;

	if (in->len > c->ext[k].len - (in->at - c->ext[k].off))
		return KGENOME_CFG_OBJ_W_OUTSIDE;
	m = map_at(c, k, in->at);
	for (i = 1; i < in->len; i++)
		if (m[i] & M_STATE)
			return KGENOME_CFG_OBJ_W_OVERLAP;
	return KGENOME_CFG_OBJ_W_NONE;
}

/* A new record for `in` at `at` (extent `k`): the map, the index, the edges that waited for the place. NIL when the table could not grow. */
static uint32_t rec_new(struct ctx *c, int k, const struct kgenome_cell_insn *in, uint64_t served0)
{
	uint8_t *m = map_at(c, k, in->at);
	uint32_t *x = ix_at(c, k, in->at);
	struct rec *r;
	uint32_t i;

	if (!grow(c, (void **)&c->r, &c->cap_r, c->n_r + 1u, sizeof *c->r))
		return NIL;
	i = c->n_r++;
	c->out->n_insn++;
	*m = (uint8_t)((*m & ~M_STATE) | M_START);
	memset(m + 1, M_BODY, in->len - 1u);
	r = &c->r[i];
	memset(r, 0, sizeof *r);
	r->off = in->at;
	r->len = in->len;
	r->target = KGENOME_BROKEN;
	r->in = *x;                     /* the branches and calls that named the place before it was read */
	*x = i;
	if (c->served == served0) {
		r->flags |= R_FRESH;
		c->out->n_fresh++;
	}
	return i;
}

/* What a path does once the delay slots of its last flow instruction or call are read. */
enum after { A_NONE = 0, A_BRANCH, A_WAIT };

/* Read one path from the worklist's entry `w`. */
static void run(struct ctx *c, const struct wl *w)
{
	struct kgenome_cell_cur cur;
	struct kgenome_cell_insn in, prev;
	uint64_t at = w->off;
	int k = ext_of(c, at), have_prev = 0, falls_on = 1;
	uint32_t first = c->n_r, head = NIL, slots = 0;
	enum after act = A_NONE;
	uint8_t why;

	if (k < 0)
		return;                 /* push() and release() checked it */
	memset(&cur, 0, sizeof cur);
	(void)kgenome_cell_seek(&cur, at, 0);
	for (;;) {
		uint8_t *m, t;
		uint64_t served0;
		uint32_t i;
		int call, waits = 0;

		if (at - c->ext[k].off >= c->ext[k].len) {
			why = KGENOME_CFG_OBJ_W_OUTSIDE;
			goto stop;
		}
		m = map_at(c, k, at);
		if ((*m & M_STATE) == M_START) {
			/* a join: the path runs into an instruction read before (the start of the path that read it: a leader); what it reaches is this path's too */
			const uint32_t p = c->n_r > first ? c->n_r - 1u : w->rec, j = *ix_at(c, k, at);

			if (p != NIL && j != NIL && (c->r[head_of(c, j)].fx & X_RET))
				set_ret(c, p);
			return;
		}
		if ((*m & M_STATE) == M_BODY) {
			why = KGENOME_CFG_OBJ_W_OVERLAP;
			goto stop;
		}
		if (c->out->n_insn >= c->max_insn) {
			c->over = 1;
			why = KGENOME_CFG_OBJ_W_BUDGET;
			goto stop;
		}
		served0 = c->served;
		if (cur.at != at)
			(void)kgenome_cell_seek(&cur, at, 0);
		if (!kgenome_cell_step(&cur, &c->sp, &in) || !in.len || in.at != at) {
			why = KGENOME_CFG_OBJ_W_UNDECODABLE;
			goto stop;
		}
		if ((why = room_for(c, k, &in)) != KGENOME_CFG_OBJ_W_NONE)
			goto stop;
		if ((i = rec_new(c, k, &in, served0)) == NIL)
			return;
		call = in.op == KGENOME_CELL_CALL || kgenome_cfg_isa_linked(c->isa, have_prev ? &prev : NULL, &in);
		if (call) {
			c->r[i].flags |= R_CALL;
			if (in.op != KGENOME_CELL_CALL)
				c->r[i].flags |= R_LINKED;
			if ((in.flags & KGENOME_CELL_F_INDIRECT) || in.op != KGENOME_CELL_CALL) {
				c->r[i].flags |= R_INDIRECT;
				c->out->n_indirect_call++;
			} else {
				c->r[i].target = in.target;
				if (slots)      /* a call in a delay slot (UNPREDICTABLE on MIPS): its target is read, the call is assumed to return */
					(void)push(c, in.target, at, M_CALLED);
				else
					waits = call_to(c, i, &in);
			}
		}
		if (slots) {
			/* a delay slot: it runs with its branch or call and belongs to its block; a flow instruction there is not followed (UNPREDICTABLE). A branch
			 * elsewhere that named this place as its target goes into a delay slot: what follows is not modelled, so it may return. */
			const uint32_t e = c->r[i].in;

			c->r[i].back = (uint8_t)(i - head);
			c->r[i].in = NIL;
			unknown_edges(c, e);
			slots--;
		} else {
			/* The block ends after the flow instruction, or after its delay slots (cfg_isa.c: MIPS 1). A call that waits ends the PATH after its own slots,
			 * not the block: its continuation is read when it is released. */
			t = call ? KGENOME_CFG_OBJ_T_FALL : term_of(c, &in);
			if (t != KGENOME_CFG_OBJ_T_FALL) {
				c->r[i].flags |= R_FLOW;
				c->r[i].term = t;
				if (t == KGENOME_CFG_OBJ_T_COND || t == KGENOME_CFG_OBJ_T_JUMP) {
					c->r[i].target = in.target;
					branch_to(c, i, in.target);
				}
				if (t == KGENOME_CFG_OBJ_T_INDIRECT)
					c->out->n_indirect_jmp++;
				if (t == KGENOME_CFG_OBJ_T_RET || t == KGENOME_CFG_OBJ_T_COND_EXIT || t == KGENOME_CFG_OBJ_T_INDIRECT)
					set_ret(c, i);
				falls_on = t == KGENOME_CFG_OBJ_T_COND || t == KGENOME_CFG_OBJ_T_COND_EXIT;
				act = A_BRANCH;
			} else {
				act = waits ? A_WAIT : A_NONE;
			}
			if (t != KGENOME_CFG_OBJ_T_FALL || call) {
				head = i;
				slots = c->isa->delay_slots;
			}
		}
		at += in.len;
		prev = in;
		have_prev = 1;
		if (!slots && act == A_BRANCH) {
			act = A_NONE;
			if (!falls_on)
				return;
			falls_on = 1;
			if (at - c->ext[k].off < c->ext[k].len)
				*map_at(c, k, at) |= M_LEAD;    /* the instruction after a block end starts one */
		}
		if (!slots && act == A_WAIT)
			return;         /* the call waits for its callee (or its callee does not return): the continuation is read on release */
		continue;
stop:
		if (c->n_r > first) {
			c->r[c->n_r - 1u].stop = why;
			set_ret(c, c->n_r - 1u);
		} else if (w->rec != NIL) {
			c->r[w->rec].stop = why;
			set_ret(c, w->rec);
		} else {
			loose(c, w->from, w->off, why);
			orphan(c, k, w->off);
		}
		return;
	}
}

/* ---- (2) the proof ---------------------------------------------------------------------------------------------------------------------------------- */

/* The callee record of the waiting call `i`, or NIL when it was never read (its place was orphaned and the call released then: not reached here). */
static uint32_t callee_of(const struct ctx *c, uint32_t i)
{
	const int k = ext_of(c, c->r[i].target);

	return k < 0 ? NIL : rec_at(c, k, c->r[i].target);
}

/* The `n`-th way on from head `i` that the proof follows (0: the branch target, 1: the fall-through, 2: the callee of a waiting call - a DEPENDENCY, *dep 1),
 * or NIL. Only places that were read and carry no R are followed (a place with R would have given `i` its R). */
static uint32_t way(const struct ctx *c, uint32_t i, unsigned n, int *dep)
{
	const struct rec *r = &c->r[i];
	uint32_t j = NIL;
	uint64_t x;
	int k;

	*dep = 0;
	if (n == 0 && (r->flags & R_FLOW) && (r->term == KGENOME_CFG_OBJ_T_COND || r->term == KGENOME_CFG_OBJ_T_JUMP) && (k = ext_of(c, r->target)) >= 0)
		j = rec_at(c, k, r->target);
	else if (n == 1 && falls(c, i, &x) && (k = ext_of(c, x)) >= 0 && (*map_at(c, k, x) & M_STATE) == M_START)
		j = head_of(c, *ix_at(c, k, x));
	else if (n == 2 && (r->fx & X_WAIT)) {
		j = callee_of(c, i);
		*dep = 1;
	}
	return j != NIL && !(c->r[j].fx & (X_RET | X_FINAL)) ? j : NIL;
}

#define B_CYCLE 1u      /* a component holds a dependency edge: its members are on a recursion cycle */
#define B_REACH 2u      /* a component reaches one that does */

struct proof {
	uint32_t *num, *low, *scc, *stk, *cs;   /* Tarjan: visit order (0: not yet), low link, component; the component stack; the call stack (node, next way) */
	uint8_t *bad;                           /* per component: B_CYCLE, B_REACH */
	uint32_t n_stk, n_cs, n_num, n_scc;
	size_t bytes;
};

static void proof_free(struct ctx *c, struct proof *p)
{
	if (p->num)
		kgenome_cfg_release(&c->rq->mem, p->num, p->bytes);
	c->held -= p->bytes;
	memset(p, 0, sizeof *p);
}

/* One allocation for the proof's arrays, charged to the allowance: 0 when refused. */
static int proof_new(struct ctx *c, struct proof *p)
{
	const size_t n = c->n_r ? c->n_r : 1u;
	uint8_t *b;

	memset(p, 0, sizeof *p);
	p->bytes = n * (7u * sizeof(uint32_t)) + n;
	if (kgenome_cfg_over(c->rq->budget, c->held + p->bytes)) {
		c->over = 1;
		return 0;
	}
	b = kgenome_cfg_alloc(&c->rq->mem, p->bytes);
	if (!b) {
		c->nomem = 1;
		return 0;
	}
	memset(b, 0, p->bytes);
	c->held += p->bytes;
	p->num = (uint32_t *)b;
	p->low = p->num + n;
	p->scc = p->low + n;
	p->stk = p->scc + n;
	p->cs = p->stk + n;                     /* 2n: (node, way) pairs */
	p->bad = (uint8_t *)(p->cs + 2u * n);
	return 1;
}

/* The components of what the waiting callees reach (Tarjan, iterative: a component is finished after every component it reaches). A component is bad when a
 * dependency edge joins two of its members (a call waits on a function it is part of) or when it reaches a bad one. */
static void proof_from(struct ctx *c, struct proof *p, uint32_t root)
{
	if (p->num[root])
		return;
	p->num[root] = p->low[root] = ++p->n_num;
	p->stk[p->n_stk++] = root;
	p->scc[root] = NIL;
	p->cs[0] = root;
	p->cs[1] = 0;
	p->n_cs = 1;
	while (p->n_cs) {
		uint32_t *top = &p->cs[2u * (p->n_cs - 1u)];
		const uint32_t v = top[0];
		int dep;

		if (top[1] < 3u) {
			const uint32_t w2 = way(c, v, top[1]++, &dep);

			if (w2 == NIL)
				continue;
			if (!p->num[w2]) {
				p->num[w2] = p->low[w2] = ++p->n_num;
				p->stk[p->n_stk++] = w2;
				p->scc[w2] = NIL;
				p->cs[2u * p->n_cs] = w2;
				p->cs[2u * p->n_cs + 1u] = 0;
				p->n_cs++;
			} else if (p->scc[w2] == NIL && p->num[w2] < p->low[v]) {
				p->low[v] = p->num[w2];         /* on the stack: the same component */
			}
			continue;
		}
		p->n_cs--;
		if (p->n_cs) {
			const uint32_t u = p->cs[2u * (p->n_cs - 1u)];

			if (p->low[v] < p->low[u])
				p->low[u] = p->low[v];
		}
		if (p->low[v] == p->num[v]) {
			const uint32_t s = p->n_scc++;
			uint32_t a = p->n_stk, b;

			do
				p->scc[p->stk[--a]] = s;
			while (p->stk[a] != v);
			/* B_CYCLE: a dependency edge between two members; B_REACH: a way out into a component that is either (finished before this one) */
			for (b = a; b < p->n_stk; b++)
				for (unsigned n = 0; n < 3u; n++) {
					const uint32_t w2 = way(c, p->stk[b], n, &dep);

					if (w2 == NIL)
						continue;
					if (p->scc[w2] == s)
						p->bad[s] |= dep ? B_CYCLE : 0u;
					else if (p->bad[p->scc[w2]])
						p->bad[s] |= B_REACH;
				}
			p->n_stk = a;
		}
	}
}

static void assume(struct ctx *c, uint32_t j)
{
	if (c->r[j].fx & X_RET)
		return;
	c->r[j].fx |= X_ASSUMED;
	c->out->n_assumed++;
	set_ret(c, j);
}

/* Every waiting call goes on: its callee is assumed to return. The call is released here and not only through its callee's R, which a refused allocation
 * may have kept from being handed back: every call of this loop stops waiting. */
static void assume_all(struct ctx *c)
{
	uint32_t i;

	for (i = 0; i < c->n_r && c->n_wait; i++)
		if (c->r[i].fx & X_WAIT) {
			const uint32_t j = callee_of(c, i);

			if (j != NIL)
				assume(c, j);
			release(c, i);
		}
}

/*
 * THE PROOF, made when nothing is left to read and calls still wait. Every such call waits on a callee with no R. A callee whose reach (everything read that
 * it leads to, a waiting call leading to ITS callee) holds no recursion cycle cannot return, ever: nothing it reaches can still get R (every place it leads to
 * was read, and every call it waits on is in the same position) - so it is FINAL, and every call to it is DEAD. A callee that is ON a recursion cycle (a
 * component with a dependency edge inside) is resolved as RETURNING (assumed, said); a callee that only reaches one waits for the next round, which the
 * assumption may answer. Each round sets R on at least one callee or kills at least one call, so the rounds end; KGENOME_CFG_OBJ_PROOF_ROUNDS bounds them.
 */
static void resolve(struct ctx *c)
{
	struct proof p;
	uint32_t i, before = c->n_wait;

	c->out->n_round++;
	/* a refused allocation may have lost an R hand-back: then nothing is proved (a call that does not return is assumed to, code kept) */
	if (c->out->n_round > KGENOME_CFG_OBJ_PROOF_ROUNDS)
		c->no_wait = 1;         /* from here every call goes on at once: the rest of the descent is one pass, as it was before calls waited */
	if (c->over || c->nomem || c->no_wait || !proof_new(c, &p)) {
		assume_all(c);
		drain(c);
		return;
	}
	for (i = 0; i < c->n_r; i++)
		if (c->r[i].fx & X_WAIT) {
			const uint32_t j = callee_of(c, i);

			if (j != NIL && !(c->r[j].fx & (X_RET | X_FINAL)))
				proof_from(c, &p, j);
		}
	for (i = 0; i < c->n_r; i++)
		if (p.num[i] && !p.bad[p.scc[i]])
			c->r[i].fx |= X_FINAL;
	for (i = 0; i < c->n_r; i++)
		if (c->r[i].fx & X_WAIT) {
			const uint32_t j = callee_of(c, i);

			if (j == NIL)
				release(c, i);
			else if (c->r[j].fx & X_FINAL)
				dead(c, i);
			else if (p.num[j] && (p.bad[p.scc[j]] & B_CYCLE))
				assume(c, j);
		}
	proof_free(c, &p);
	drain(c);
	if (c->n_wait == before) {      /* cannot happen (a component on a cycle holds a waiting callee); a guard against an endless loop all the same */
		assume_all(c);
		drain(c);
	}
}

/* ---- (3) the blocks ---------------------------------------------------------------------------------------------------------------------------------- */

static int rec_cmp(const void *a, const void *b)
{
	const struct rec *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static int seed_cmp(const void *a, const void *b)
{
	const struct kgenome_cfg_obj_seed *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static int ext_cmp(const void *a, const void *b)
{
	const struct ext *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

/* The block that STARTS at `off`, or KGENOME_CFG_NONE. */
static uint32_t blk_start(const struct kgenome_cfg_obj *o, uint64_t off)
{
	const uint32_t i = kgenome_cfg_obj_block_at(o, off);

	return i != KGENOME_CFG_NONE && o->b[i].off == off ? i : KGENOME_CFG_NONE;
}

uint32_t kgenome_cfg_obj_block_at(const struct kgenome_cfg_obj *g, uint64_t off)
{
	uint32_t lo = 0, hi;

	if (!g)
		return KGENOME_CFG_NONE;
	hi = g->n_b;
	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (g->b[mid].off <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo || off - g->b[lo - 1u].off >= g->b[lo - 1u].len)
		return KGENOME_CFG_NONE;
	return lo - 1u;
}

/* Step (3): the instructions in address order cut into blocks, their calls, and the successors as indices. */
static void blocks(struct ctx *c)
{
	struct kgenome_cfg_obj *o = c->out;
	uint32_t i, cur = KGENOME_CFG_NONE;

	qsort(c->r, c->n_r, sizeof *c->r, rec_cmp);
	for (i = 0; i < c->n_r; i++) {
		const struct rec *r = &c->r[i];
		const int k = ext_of(c, r->off);
		const uint8_t m = *map_at(c, k, r->off);
		struct kgenome_cfg_obj_block *b;

		/* A block starts at a leader and nowhere else: every path starts at a pushed offset (a leader), the instruction after a block end that falls
		 * through is made one, and nothing else begins a run - an instruction behind a stop, a jump or a call that does not return is reached only as a
		 * target; a released continuation goes on in its call's block. */
		if (cur == KGENOME_CFG_NONE || (m & M_LEAD)) {
			/* the record before (in address order) runs on into this leader: it ends where this starts, its path did not stop, and it is no call (a
			 * call's continuation is where a callee returns to, which a function may start at when the call does not return) */
			const struct rec *p = i ? &c->r[i - 1u - c->r[i - 1u].back] : NULL;
			const int fallen = p && i && c->r[i - 1u].off + c->r[i - 1u].len == r->off && !c->r[i - 1u].stop && !(p->flags & (R_CALL | R_TRAP)) &&
					   !(p->fx & X_DEAD) && (!(p->flags & R_FLOW) || p->term == KGENOME_CFG_OBJ_T_COND || p->term == KGENOME_CFG_OBJ_T_COND_EXIT);

			if (!grow(c, (void **)&o->b, &o->cap_b_, o->n_b + 1u, sizeof *o->b))
				return;
			if (!grow(c, (void **)&c->bt, &c->cap_bt, o->n_b + 1u, sizeof *c->bt))
				return;
			cur = o->n_b++;
			c->bt[cur] = KGENOME_BROKEN;
			b = &o->b[cur];
			memset(b, 0, sizeof *b);
			b->off = r->off;
			b->succ[0] = b->succ[1] = KGENOME_CFG_NONE;
			b->call_first = o->n_call;
			b->flags = (uint8_t)(((m & M_SEED) ? KGENOME_CFG_OBJ_B_SEED : 0u) | ((m & M_CALLED) ? KGENOME_CFG_OBJ_B_CALLED : 0u) |
					     ((m & M_BRANCHED) ? KGENOME_CFG_OBJ_B_BRANCHED : 0u) | ((c->r[i - r->back].fx & X_RET) ? 0u : KGENOME_CFG_OBJ_B_NORET) |
					     ((r->fx & X_ASSUMED) ? KGENOME_CFG_OBJ_B_ASSUMED : 0u) | (fallen ? KGENOME_CFG_OBJ_B_FALLEN : 0u));
		}
		b = &o->b[cur];
		b->len += r->len;
		b->n_insn++;
		if (r->flags & R_FRESH)
			b->flags |= KGENOME_CFG_OBJ_B_FRESH;
		if (r->flags & R_FLOW) {
			b->term = r->term;
			c->bt[cur] = r->target;
		}
		if (r->stop) {
			b->term = KGENOME_CFG_OBJ_T_STOP;
			b->stop = r->stop;
		}
		if (r->flags & R_CALL) {
			struct kgenome_cfg_obj_call *k2;

			if (!grow(c, (void **)&o->call, &o->cap_call_, o->n_call + 1u, sizeof *o->call))
				return;
			k2 = &o->call[o->n_call++];
			memset(k2, 0, sizeof *k2);
			k2->at = r->off;
			k2->target = r->target;
			k2->blk = cur;
			k2->flags = (uint8_t)(((r->flags & R_INDIRECT) ? KGENOME_CFG_OBJ_C_INDIRECT : 0u) | ((r->flags & R_LINKED) ? KGENOME_CFG_OBJ_C_LINKED : 0u) |
					      ((r->fx & X_DEAD) ? KGENOME_CFG_OBJ_C_NORET : 0u));
			b->n_call++;
		}
	}
	/* the successors, once every block is known */
	for (i = 0; i < o->n_b; i++) {
		struct kgenome_cfg_obj_block *b = &o->b[i];
		const uint8_t t = b->term;

		if (t == KGENOME_CFG_OBJ_T_COND || t == KGENOME_CFG_OBJ_T_JUMP)
			b->succ[0] = c->bt[i] == KGENOME_BROKEN ? KGENOME_CFG_NONE : blk_start(o, c->bt[i]);
		if (t == KGENOME_CFG_OBJ_T_FALL || t == KGENOME_CFG_OBJ_T_COND || t == KGENOME_CFG_OBJ_T_COND_EXIT)
			b->succ[1] = blk_start(o, b->off + b->len);
	}
	for (i = 0; i < o->n_call; i++)
		o->call[i].tgt_blk = o->call[i].target == KGENOME_BROKEN ? KGENOME_CFG_NONE : blk_start(o, o->call[i].target);
}

/* The seeds as the layer answered them: one entry per offset, its block or the reason it has none. */
static void entries(struct ctx *c, struct kgenome_cfg_obj_seed *sd, uint32_t n)
{
	struct kgenome_cfg_obj *o = c->out;
	uint32_t i;

	qsort(sd, n, sizeof *sd, seed_cmp);
	for (i = 0; i < n; i++) {
		struct kgenome_cfg_obj_entry *e;
		int k;

		if (o->n_e && o->e[o->n_e - 1u].off == sd[i].off) {
			o->e[o->n_e - 1u].src |= sd[i].src;
			continue;
		}
		if (!grow(c, (void **)&o->e, &o->cap_e_, o->n_e + 1u, sizeof *o->e))
			return;
		e = &o->e[o->n_e++];
		memset(e, 0, sizeof *e);
		e->off = sd[i].off;
		e->src = sd[i].src;
		e->blk = blk_start(o, sd[i].off);
		if (e->blk != KGENOME_CFG_NONE)
			continue;
		k = ext_of(c, sd[i].off);
		if (k < 0)
			e->why = KGENOME_CFG_OBJ_W_OUTSIDE;
		else if ((*map_at(c, k, sd[i].off) & M_STATE) == M_BODY)
			e->why = KGENOME_CFG_OBJ_W_OVERLAP;
		else if (c->over)
			e->why = KGENOME_CFG_OBJ_W_BUDGET;
		else
			e->why = KGENOME_CFG_OBJ_W_UNDECODABLE;
	}
}

void kgenome_cfg_obj_free(struct kgenome_cfg_obj *g, const struct kgenome_cfg_mem *mem)
{
	if (!g)
		return;
	if (g->b)
		kgenome_cfg_release(mem, g->b, (size_t)g->cap_b_ * sizeof *g->b);
	if (g->call)
		kgenome_cfg_release(mem, g->call, (size_t)g->cap_call_ * sizeof *g->call);
	if (g->e)
		kgenome_cfg_release(mem, g->e, (size_t)g->cap_e_ * sizeof *g->e);
	if (g->loose)
		kgenome_cfg_release(mem, g->loose, (size_t)g->cap_loose_ * sizeof *g->loose);
	memset(g, 0, sizeof *g);
}

/* The extents, sorted, clipped to the object, and their place in the map; the map and its index. 0: refused (`over` / `nomem`). */
static int extents(struct ctx *c, const struct kgenome_cfg_obj_req *req)
{
	uint64_t total = 0;
	uint32_t i;

	if (!grow(c, (void **)&c->ext, &c->cap_ext, req->n_ext + 1u, sizeof *c->ext))
		return 0;
	for (i = 0; i < req->n_ext; i++) {
		uint64_t off = req->ext[i].off, len = req->ext[i].len;

		if (off >= req->sp->size || !len)
			continue;
		if (len > req->sp->size - off)
			len = req->sp->size - off;
		c->ext[c->n_ext].off = off;
		c->ext[c->n_ext].len = len;
		c->n_ext++;
	}
	qsort(c->ext, c->n_ext, sizeof *c->ext, ext_cmp);
	for (i = 0; i < c->n_ext; i++) {
		if (i && c->ext[i].off < c->ext[i - 1u].off + c->ext[i - 1u].len) {         /* overlapping extents: the later one starts where the earlier ends */
			const uint64_t e = c->ext[i - 1u].off + c->ext[i - 1u].len, end = c->ext[i].off + c->ext[i].len;

			c->ext[i].off = e;
			c->ext[i].len = end > e ? end - e : 0;
		}
		c->ext[i].map = total;
		total += c->ext[i].len;
	}
	c->max_insn = req->max_insn ? req->max_insn : total;
	/* the map (a byte a place) and its index (a record or a list of edges a place) */
	if (total > (uint64_t)SIZE_MAX / 8u || kgenome_cfg_over(req->budget, c->held + total * (1u + sizeof *c->ix))) {
		c->over = 1;
		return 0;
	}
	if (!total)
		return 1;
	c->map = kgenome_cfg_alloc(&req->mem, (size_t)total);
	c->ix = c->map ? kgenome_cfg_alloc(&req->mem, (size_t)total * sizeof *c->ix) : NULL;
	if (!c->map || !c->ix) {
		c->nomem = 1;
		return 0;
	}
	c->held += total * (1u + sizeof *c->ix);
	c->map_n = total;
	memset(c->map, 0, (size_t)total);
	memset(c->ix, 0xff, (size_t)total * sizeof *c->ix);
	return 1;
}

/*
 * THE TRAP BEHIND A CALL THAT DOES NOT RETURN (PM5-D2, fixed 2026-11-17). A path ends at a call proven not to return (T_NORET), so the instruction the compiler
 * puts behind it to stop a run that should never come back (`call __libc_start_main; hlt`, `call abort; ud2`, `call f; int3`) was never decoded and belonged to
 * no function (stripped twins: 41 x86-64 + 10 i386 derived ends short by exactly that byte). After the descent, the ONE instruction right behind each such
 * call (after its delay slots) is read when nothing read it and nothing named it (no leader: a seed, a target, a call's target there is someone's start), it
 * is inside the extent, and it is a trap by the one table (kgenome_cfg_isa_trap); it goes in the call's block, which still ends T_NORET. Anything else behind
 * the call stays unread (it may be the start of another function). Each place is still decoded once; the work bound counts it.
 */
static void traps(struct ctx *c)
{
	const uint32_t n = c->n_r;
	uint32_t i;

	for (i = 0; i < n && !c->nomem; i++) {
		struct kgenome_cell_cur cur;
		struct kgenome_cell_insn in;
		uint64_t x, served0;
		uint8_t *m;
		uint32_t j;
		int k;

		if (!(c->r[i].fx & X_DEAD) || c->out->n_insn >= c->max_insn)
			continue;
		(void)slot_end(c, i, &x);
		if ((k = ext_of(c, x)) < 0)
			continue;
		m = map_at(c, k, x);
		if (*m)                         /* read, inside an instruction, or named by something: not the call's */
			continue;
		memset(&cur, 0, sizeof cur);
		(void)kgenome_cell_seek(&cur, x, 0);
		served0 = c->served;
		if (!kgenome_cell_step(&cur, &c->sp, &in) || !in.len || in.at != x || room_for(c, k, &in) != KGENOME_CFG_OBJ_W_NONE ||
		    !kgenome_cfg_isa_trap(c->isa, &in, c->sp.base, c->sp.size))
			continue;
		if ((j = rec_new(c, k, &in, served0)) != NIL)
			c->r[j].flags |= R_TRAP;
	}
}

/* Steps (1) and (2): read until nothing is left, prove what the waiting calls come to, read what that released; until no call waits. */
static void descend(struct ctx *c)
{
	uint32_t i;

	for (;;) {
		while (c->n_wl && !c->nomem && !(c->over && c->out->n_insn >= c->max_insn)) {
			const struct wl w = c->wl[--c->n_wl];

			run(c, &w);
			drain(c);
		}
		if (c->nomem || (c->over && c->out->n_insn >= c->max_insn) || !c->n_wait)
			break;
		resolve(c);
	}
	/* the work bound or memory stopped the descent with calls still waiting, or released and not read: their continuations were not read, said on the call */
	for (i = 0; i < c->n_wl; i++)
		if (c->wl[i].rec != NIL && !c->r[c->wl[i].rec].stop)
			c->r[c->wl[i].rec].stop = KGENOME_CFG_OBJ_W_BUDGET;
	for (i = 0; i < c->n_r && c->n_wait; i++)
		if (c->r[i].fx & X_WAIT) {
			uint64_t x;

			c->r[i].fx &= (uint8_t)~X_WAIT;
			c->n_wait--;
			c->r[slot_end(c, i, &x)].stop = KGENOME_CFG_OBJ_W_BUDGET;
		}
}

enum kgenome_status kgenome_cfg_obj_build(const struct kgenome_cfg_obj_req *req, struct kgenome_cfg_obj *out)
{
	struct ctx c;
	struct kgenome_cfg_obj_seed *sd = NULL;
	uint32_t i;

	if (!out)
		return KGENOME_BAD_INPUT;
	memset(out, 0, sizeof *out);
	if (!req || !req->sp || !req->sp->base || (req->n_ext && !req->ext) || (req->n_seed && !req->seed))
		return out->status = KGENOME_BAD_INPUT;
	memset(&c, 0, sizeof c);
	c.rq = req;
	c.out = out;
	c.isa = kgenome_cfg_isa_of(req->sp->arch);
	if (!c.isa)
		return out->status = KGENOME_UNSUPPORTED;
	c.sp = *req->sp;
	c.code_be = req->sp->be && !req->sp->code_le;
	if (req->sp->held) {
		c.sp.held = held_counted;
		c.sp.held_priv = &c;
	}
	if (!extents(&c, req))
		goto done;
	/* (1) the descent: the seeds first, then every place the flow names */
	if (req->n_seed) {
		if (kgenome_cfg_over(req->budget, c.held + (uint64_t)req->n_seed * sizeof *sd)) {
			c.over = 1;
			goto done;
		}
		sd = kgenome_cfg_alloc(&req->mem, (size_t)req->n_seed * sizeof *sd);
		if (!sd) {
			c.nomem = 1;
			goto done;
		}
		memcpy(sd, req->seed, (size_t)req->n_seed * sizeof *sd);
		c.held += (uint64_t)req->n_seed * sizeof *sd;
	}
	for (i = 0; i < req->n_seed; i++) {
		const int k = ext_of(&c, sd[i].off);

		if (k >= 0 && (*map_at(&c, k, sd[i].off) & M_STATE) != M_BODY)
			*map_at(&c, k, sd[i].off) |= M_SEED;
		(void)push(&c, sd[i].off, KGENOME_BROKEN, 0);
	}
	descend(&c);
	if (!c.nomem)
		traps(&c);
	/* (3) the blocks, the calls, the successors, the entries */
	if (!c.nomem)
		blocks(&c);
	if (!c.nomem && sd)
		entries(&c, sd, req->n_seed);
done:
	if (sd)
		kgenome_cfg_release(&req->mem, sd, (size_t)req->n_seed * sizeof *sd);
	if (c.map)
		kgenome_cfg_release(&req->mem, c.map, (size_t)c.map_n);
	if (c.ix)
		kgenome_cfg_release(&req->mem, c.ix, (size_t)c.map_n * sizeof *c.ix);
	if (c.r)
		kgenome_cfg_release(&req->mem, c.r, (size_t)c.cap_r * sizeof *c.r);
	if (c.wl)
		kgenome_cfg_release(&req->mem, c.wl, (size_t)c.cap_wl * sizeof *c.wl);
	if (c.ie)
		kgenome_cfg_release(&req->mem, c.ie, (size_t)c.cap_ie * sizeof *c.ie);
	if (c.q)
		kgenome_cfg_release(&req->mem, c.q, (size_t)c.cap_q * sizeof *c.q);
	if (c.ext)
		kgenome_cfg_release(&req->mem, c.ext, (size_t)c.cap_ext * sizeof *c.ext);
	if (c.bt)
		kgenome_cfg_release(&req->mem, c.bt, (size_t)c.cap_bt * sizeof *c.bt);
	if (c.nomem) {
		kgenome_cfg_obj_free(out, &req->mem);
		return out->status = KGENOME_NOMEM;
	}
	out->status = c.over ? KGENOME_OVER_BUDGET : KGENOME_OK;
	return out->status;
}
