/*
 * diag_origin.c - the origin map: which node each register and stack slot of the walk was last given its value by.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

void kgenome_diag_org_clear(struct kgenome_diag_orgs *w, uint8_t r)
{
	if (r < 16u) {
		w->reg[r].node = KGENOME_DIAG_ORG_NONE;
		/* The symbol, the second producer and the weakness go with it: they all answer the same
		 * question - where did this value come from - and leaving one
		 * behind would have a register naming a symbol it no longer
		 * holds. */
		memset(w->reg[r].alt_p1, 0, sizeof w->reg[r].alt_p1);
		w->reg[r].may = 0;
		w->reg[r].symoff = 0;
		w->reg[r].symadd = 0;
	}
}

uint16_t kgenome_diag_org_of(const struct kgenome_diag_orgs *w, uint8_t r)
{
	return r < 16u ? w->reg[r].node : KGENOME_DIAG_ORG_NONE;
}

void kgenome_diag_org_set(struct kgenome_diag_orgs *w, uint8_t r, uint16_t node)
{
	if (r >= 16u)
		return;
	w->reg[r].node = node;
	/* One question, several fields - see struct kgenome_diag_org. A register that now
	 * holds what a node produced is no longer naming a symbol, and it holds it on every path. */
	memset(w->reg[r].alt_p1, 0, sizeof w->reg[r].alt_p1);
	w->reg[r].may = 0;
	w->reg[r].symoff = 0;
	w->reg[r].symadd = 0;
}

/*
 * FORGET WHAT EVERY REGISTER THIS INSTRUCTION WRITES CAME FROM, then put
 * back the one case this follows.
 *
 * `wmask` and not the first operand, for the reason cell_track records: an
 * instruction writes registers it does not name, and names registers it
 * only reads. Getting that backwards on `mul` cost the i386 samples their
 * whole network half.
 */
void kgenome_diag_org_set_sym(struct kgenome_diag_orgs *w, uint8_t r, uint32_t symoff,
			  int32_t symadd)
{
	if (!w || r >= 16u)
		return;
	w->reg[r].node = KGENOME_DIAG_ORG_NONE;
	memset(w->reg[r].alt_p1, 0, sizeof w->reg[r].alt_p1);
	w->reg[r].may = 0;
	w->reg[r].symoff = symoff;
	w->reg[r].symadd = symadd;
}

uint32_t kgenome_diag_org_sym(const struct kgenome_diag_orgs *w, uint8_t r, int32_t *add)
{
	if (!w || r >= 16u)
		return 0;
	if (add)
		*add = w->reg[r].symadd;
	return w->reg[r].symoff;
}

/* ---- THE STACK RING -----------------------------------------------------------------------------------
 *
 * One slot per word the program pushed, the newest KGENOME_DIAG_ORG_STK of them (see struct kgenome_diag_orgs). It
 * used to count `push` and `pop` and nothing else, so everything else that moves the stack pointer left the
 * ring where it was: after `add esp,4` (a cdecl caller taking its argument back) the next pop took the argument's
 * slot and not the one below it, which lost the link; and with one such call a few instructions apart the depth
 * grew until the ring overflowed (MEASURED: 8 corpus files OK -> TRUNCATED at mask 0x3). The ring now follows
 * what the stack pointer does by a constant: add/sub of an immediate, `leave`, `mov esp,ebp` and `lea esp,[ebp-N]`
 * through the depth the frame pointer was given (bp_depth). A move by a register, `alloca`, or anything else the
 * walk cannot compute leaves the ring as it was - the old behaviour, the honest "not followed".
 */
static void ring_push(struct kgenome_diag_orgs *w, uint16_t v, const uint16_t alt[KGENOME_DIAG_ORG_ALT], uint8_t may)
{
	if (w->n_stk >= KGENOME_DIAG_ORG_STK) {
		/* the slot this push reuses belongs to the push KGENOME_DIAG_ORG_STK below it */
		if (w->stk[w->n_stk % KGENOME_DIAG_ORG_STK] != KGENOME_DIAG_ORG_NONE &&
		    w->n_stk - KGENOME_DIAG_ORG_STK >= w->n_lost)
			w->stk_cut = 1;         /* an origin that is gone for good */
		if (w->n_stk - KGENOME_DIAG_ORG_STK + 1u > w->n_lost)
			w->n_lost = w->n_stk - KGENOME_DIAG_ORG_STK + 1u;
	}
	w->stk[w->n_stk % KGENOME_DIAG_ORG_STK] = v;
	memcpy(w->stk_alt_p1[w->n_stk % KGENOME_DIAG_ORG_STK], alt, sizeof w->stk_alt_p1[0]);
	w->stk_may[w->n_stk % KGENOME_DIAG_ORG_STK] = may;
	w->n_stk++;
}

/* `count` slots that hold nothing: the room `sub esp,N` makes. A count past the ring is a depth and no more work
 * (every slot the ring holds is empty after KGENOME_DIAG_ORG_STK of them), and the depth is bounded so that it
 * cannot wrap. */
#define RING_DEPTH_MAX 0x100000u
static void ring_push_none(struct kgenome_diag_orgs *w, uint32_t count)
{
	static const uint16_t none[KGENOME_DIAG_ORG_ALT];
	uint32_t i, direct = count < KGENOME_DIAG_ORG_STK ? count : KGENOME_DIAG_ORG_STK;

	for (i = 0; i < direct; i++)
		ring_push(w, KGENOME_DIAG_ORG_NONE, none, 0);
	if (count > direct) {
		const uint64_t depth = (uint64_t)w->n_stk + (count - direct);

		w->n_stk = depth > RING_DEPTH_MAX ? RING_DEPTH_MAX : (uint32_t)depth;
		if (w->n_stk > KGENOME_DIAG_ORG_STK && w->n_lost < w->n_stk - KGENOME_DIAG_ORG_STK)
			w->n_lost = w->n_stk - KGENOME_DIAG_ORG_STK;
	}
}

/* The stack pointer moved DOWN by `count` slots (sub esp,N): room for them if the ring can hold them without pushing a
 * slot the walk still carries out of its window, and a count kept in sp_gap if not. */
static void ring_grow(struct kgenome_diag_orgs *w, uint32_t count)
{
	if ((uint64_t)w->n_stk + count - w->n_lost <= KGENOME_DIAG_ORG_STK) {
		ring_push_none(w, count);
		return;
	}
	w->sp_gap = count > RING_DEPTH_MAX - w->sp_gap ? RING_DEPTH_MAX : w->sp_gap + count;
}

/* The stack pointer went UP by `count` slots: the room it made first, then what was pushed. */
static void ring_shrink(struct kgenome_diag_orgs *w, uint32_t count)
{
	const uint32_t t = count < w->sp_gap ? count : w->sp_gap;

	w->sp_gap -= t;
	count -= t;
	w->n_stk = count >= w->n_stk ? 0u : w->n_stk - count;
	if (w->n_lost > w->n_stk)
		w->n_lost = w->n_stk;
}

/* put the stack pointer at an absolute depth: what `leave`, `mov esp,ebp` and `lea esp,[ebp-N]` do */
static void ring_depth(struct kgenome_diag_orgs *w, uint32_t depth)
{
	const uint64_t now = (uint64_t)w->n_stk + w->sp_gap;

	if (depth > now)
		ring_grow(w, (uint32_t)(depth - now));
	else
		ring_shrink(w, (uint32_t)(now - depth));
}

/* What the instruction does to the stack pointer when it is a constant, as a number of slots (positive: the stack
 * grew). Sets *ok to 0 when it is not one. `unit` is the word: the stack register's own width. */
static int64_t sp_delta(const struct kgenome_cell_insn *in, uint8_t sp, int *ok)
{
	int64_t v;
	unsigned unit;

	*ok = 0;
	if (in->n_op < 2u || in->o[0].kind != KGENOME_CELL_O_REG || in->o[0].reg != sp ||
	    in->o[1].kind != KGENOME_CELL_O_IMM || (in->op != KGENOME_CELL_ADD && in->op != KGENOME_CELL_SUB))
		return 0;
	unit = in->o[0].size;
	if (unit != 4u && unit != 8u)
		return 0;
	v = unit == 4u ? (int64_t)(int32_t)(uint32_t)in->o[1].imm : (int64_t)in->o[1].imm;
	if (in->op == KGENOME_CELL_ADD)
		v = -v;
	*ok = 1;
	return v / (int64_t)unit;
}

static void ring_follow(struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in)
{
	const uint8_t sp = KGENOME_CELL_REG_SP, bp = KGENOME_CELL_REG_BP;
	const uint64_t spbp = (1ull << sp) | (1ull << bp);
	int ok;
	int64_t d;

	if (w->sp)
		return;
	d = sp_delta(in, sp, &ok);
	if (ok) {
		if (d > 0)
			ring_grow(w, d > RING_DEPTH_MAX ? RING_DEPTH_MAX : (uint32_t)d);
		else if (d < 0)
			ring_shrink(w, -d > RING_DEPTH_MAX ? RING_DEPTH_MAX : (uint32_t)-d);
		return;
	}
	if (in->op == KGENOME_CELL_MOV && in->n_op > 1u && in->o[0].kind == KGENOME_CELL_O_REG &&
	    in->o[1].kind == KGENOME_CELL_O_REG) {
		if (in->o[0].reg == bp && in->o[1].reg == sp) {
			w->bp_depth = w->n_stk + w->sp_gap;     /* the frame is made here */
			w->bp_known = 1;
			return;
		}
		if (in->o[0].reg == sp && in->o[1].reg == bp && w->bp_known) {
			ring_depth(w, w->bp_depth);             /* mov esp,ebp */
			return;
		}
	}
	if (in->op == KGENOME_CELL_LEA && in->n_op > 1u && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == sp &&
	    in->o[1].kind == KGENOME_CELL_O_MEM && in->o[1].reg == bp && in->o[1].index == KGENOME_CELL_REG_NONE &&
	    (in->o[0].size == 4u || in->o[0].size == 8u) && w->bp_known) {
		const int64_t slots = -in->o[1].disp / (int64_t)in->o[0].size;  /* below the frame pointer: more */
		const int64_t at = (int64_t)w->bp_depth + slots;

		ring_depth(w, at < 0 ? 0u : at > RING_DEPTH_MAX ? RING_DEPTH_MAX : (uint32_t)at);
		return;
	}
	/* `leave` is `mov esp,ebp; pop ebp`; the decoder gives it no class and no operand, only the two registers it writes */
	if (in->op == KGENOME_CELL_OTHER && !in->n_op && in->wmask == spbp) {
		if (w->bp_known) {
			ring_depth(w, w->bp_depth);
			ring_shrink(w, 1u);
		}
		w->bp_known = 0;                                /* rbp is the caller's again */
		return;
	}
	if (in->wmask & (1ull << bp))
		w->bp_known = 0;                                /* anything else that writes it */
}

void kgenome_diag_org_step(struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in)
{
	uint8_t r, d, e;

	if (in->op == KGENOME_CELL_PUSH) {
		uint16_t v = KGENOME_DIAG_ORG_NONE, alt[KGENOME_DIAG_ORG_ALT] = { 0 };
		uint8_t may = 0;

		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg < 16u) {
			v = w->reg[in->o[0].reg].node;
			memcpy(alt, w->reg[in->o[0].reg].alt_p1, sizeof alt);
			may = w->reg[in->o[0].reg].may;
		}
		ring_push(w, v, alt, may);
		return;
	}
	if (in->op == KGENOME_CELL_POP) {
		uint16_t v = KGENOME_DIAG_ORG_NONE, alt[KGENOME_DIAG_ORG_ALT] = { 0 };
		uint8_t may = 0;

		if (w->n_stk) {
			w->n_stk--;
			if (w->n_stk >= w->n_lost) {
				v = w->stk[w->n_stk % KGENOME_DIAG_ORG_STK];
				memcpy(alt, w->stk_alt_p1[w->n_stk % KGENOME_DIAG_ORG_STK], sizeof alt);
				may = w->stk_may[w->n_stk % KGENOME_DIAG_ORG_STK];
			}
		}
		/* A popped LIST names no operand; wmask has them all. */
		for (r = 0; r < 16u; r++)
			if (in->wmask & (1ull << r))
				kgenome_diag_org_clear(w, r);
		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg < 16u) {
			kgenome_diag_org_set(w, in->o[0].reg, v);
			memcpy(w->reg[in->o[0].reg].alt_p1, alt, sizeof alt);
			w->reg[in->o[0].reg].may = may;
		}
		if (in->wmask & (1ull << KGENOME_CELL_REG_BP))
			w->bp_known = 0;        /* `pop ebp` gives the caller's frame pointer back */
		return;
	}
	ring_follow(w, in);
	if (in->op == KGENOME_CELL_XCHG && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[1].kind == KGENOME_CELL_O_REG) {
		struct kgenome_diag_org a;

		d = in->o[0].reg; e = in->o[1].reg;
		if (d >= 16u || e >= 16u)
			return;
		a = w->reg[d];
		w->reg[d] = w->reg[e];
		w->reg[e] = a;
		/* the symbol was never swapped (it is a different question) and a node made here is not one */
		w->reg[d].symoff = w->reg[e].symoff = 0;
		w->reg[d].symadd = w->reg[e].symadd = 0;
		return;
	}
	if (in->op == KGENOME_CELL_MOV && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].size >= 4u) {
		if (in->o[1].kind == KGENOME_CELL_O_REG) {
			/*
			 * A VALUE TAKEN FROM THE STACK POINTER IS A STACK
			 * ADDRESS, and that is a provenance of its own.
			 * msfvenom's i386 stager makes the stack executable
			 * and jumps into it; mprotect returns 0, so there is
			 * no pointer to follow from the allocation to the
			 * jump and the only thing that links them is that
			 * both addresses came off esp.
			 */
			if (in->o[1].reg == (w->sp ? w->sp : KGENOME_CELL_REG_SP)) {
				kgenome_diag_org_set(w, in->o[0].reg, KGENOME_DIAG_ORG_STACK);
			} else if (in->o[0].reg < 16u && in->o[1].reg < 16u) {
				const struct kgenome_diag_org src = w->reg[in->o[1].reg];

				/* the whole origin moves: the second producer and the weakness with it */
				kgenome_diag_org_set(w, in->o[0].reg, src.node);
				memcpy(w->reg[in->o[0].reg].alt_p1, src.alt_p1, sizeof src.alt_p1);
				w->reg[in->o[0].reg].may = src.may;
			} else {
				kgenome_diag_org_clear(w, in->o[0].reg);
			}
			return;
		}
		kgenome_diag_org_clear(w, in->o[0].reg);
		return;
	}
	/*
	 * AND/SHR/SHL OVER A STACK ADDRESS IS STILL A STACK ADDRESS. The
	 * i386 stager rounds esp down to a page with `shr 0xc; shl 0xc`
	 * before handing it to mprotect; killing the provenance there breaks
	 * the only link that sample has.
	 */
	if ((in->op == KGENOME_CELL_AND || in->op == KGENOME_CELL_SHR || in->op == KGENOME_CELL_SHL) &&
	    in->n_op && in->o[0].kind == KGENOME_CELL_O_REG &&
	    kgenome_diag_org_of(w, in->o[0].reg) == KGENOME_DIAG_ORG_STACK)
		return;

	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r))
			kgenome_diag_org_clear(w, r);
}

/* ---- WHAT THE LINEAR WALK DOES AT A CONTROL TRANSFER ------------------------------------------
 *
 * See the note in diag_private.h. The origin map is one straight line's; these are what a call, a
 * return and a join of two paths do to it, so that a link that comes out of the walk is a link the
 * program can produce and is MAY when it is not on every path.
 */
int kgenome_diag_org_any(const struct kgenome_diag_orgs *w)
{
	uint32_t i;

	for (i = 0; i < 16u; i++)
		if (w->reg[i].node != KGENOME_DIAG_ORG_NONE)
			return 1;
	for (i = w->n_lost; i < w->n_stk; i++)
		if (w->stk[i % KGENOME_DIAG_ORG_STK] != KGENOME_DIAG_ORG_NONE)
			return 1;
	return 0;
}

void kgenome_diag_org_link(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
			   const struct kgenome_diag_orgs *w, uint8_t r, uint8_t role, uint8_t kind)
{
	const struct kgenome_diag_org *o;
	unsigned i;

	if (!h || r >= 16u)
		return;
	o = &w->reg[r];
	if (o->node == KGENOME_DIAG_ORG_NONE)
		return;
	(void)kgenome_diag_note_in_how(s, h, o->node, role, kind,
				       o->may ? KGENOME_DIAG_LINK_MAY : KGENOME_DIAG_LINK_PROVEN);
	for (i = 0; i < KGENOME_DIAG_ORG_ALT && o->alt_p1[i]; i++)
		(void)kgenome_diag_note_in_how(s, h, (uint16_t)(o->alt_p1[i] - 1u), role, kind,
					       KGENOME_DIAG_LINK_MAY);
}

void kgenome_diag_org_demote(struct kgenome_diag_orgs *w, uint16_t mask)
{
	uint32_t i;

	for (i = 0; i < 16u; i++)
		if ((mask & (1u << i)) && w->reg[i].node != KGENOME_DIAG_ORG_NONE)
			w->reg[i].may = 1;
}

void kgenome_diag_org_kill(struct kgenome_diag_orgs *w, uint16_t mask)
{
	uint8_t r;

	for (r = 0; r < 16u; r++)
		if (mask & (1u << r))
			kgenome_diag_org_clear(w, r);
}

int kgenome_diag_org_kill_stack(struct kgenome_diag_orgs *w)
{
	uint32_t i;
	int lost = 0;

	for (i = w->n_lost; i < w->n_stk; i++)
		if (w->stk[i % KGENOME_DIAG_ORG_STK] != KGENOME_DIAG_ORG_NONE)
			lost = 1;
	/* an empty ring, and not one that remembers a depth: the next function starts at the bottom of its own
	 * frame (a phantom depth of a hundred slots was MEASURED to make the ring overflow in a long window) */
	w->n_stk = 0;
	w->n_lost = 0;
	w->bp_known = 0;                /* and the frame pointer was that function's */
	w->sp_gap = 0;
	return lost;
}

/* ---- A CALL: WHAT THE CALLEE DID TO THE REGISTERS ------------------------------------------------------
 *
 * Moved here from the sweep, which was the only route that asked it: the symbol route (diag_sym.c) had the same
 * question and no answer, because a decoder gives CALL no written register (W3/W5 there were X2). One callee
 * reader and one policy, for both.
 */
enum diag_callee_kind { CALLEE_NONE = 0, CALLEE_UNKNOWN, CALLEE_KNOWN, CALLEE_GETPC };

void kgenome_diag_callees_init(struct kgenome_diag_callees *c, const struct kgenome_cell_space *sp, unsigned arch,
			       uint64_t off, uint64_t n)
{
	memset(c, 0, sizeof *c);
	c->sp = sp;
	c->off = off;
	c->n = n;
	/* the complement of what a call must give back (celllysis keeps the one row, so the constant map and this
	 * cannot disagree about a register); an architecture without a row loses every register to a callee */
	c->caller_saved = (uint16_t)~kgenome_cell_call_keeps(arch);
}

/*
 * Is it a call at all: `call next` (the address of the next instruction) or a callee that begins by popping its own
 * return address. One decode, no memo - asked for every direct call, also where no register is carried.
 */
static int callee_getpc(const struct kgenome_diag_callees *c, const struct kgenome_cell_insn *call)
{
	struct kgenome_cell_cur kc;
	struct kgenome_cell_insn ci;

	if (call->target == call->at + call->len)
		return 1;
	if (call->target < c->off || call->target >= c->off + c->n)
		return 0;
	memset(&kc, 0, sizeof kc);
	return kgenome_cell_seek(&kc, call->target, 0) && kgenome_cell_next(&kc, c->sp, &ci) && ci.op == KGENOME_CELL_POP;
}

/*
 * WHAT A DIRECT CALLEE WRITES, read from its first instruction to the first `ret`. Only a straight line
 * is a statement: a branch or a call inside it makes the other paths unread, and "unknown" is the answer.
 * A register pushed before anything wrote it and popped back is not written (`push rbx; ...; pop rbx`).
 * The bound is KGENOME_DIAG_CALLEE_INSN and the answers are remembered per target (KGENOME_DIAG_CALLEE_MEMO), so a
 * call in a loop costs one reading.
 */
static int callee_scan(struct kgenome_diag_callees *c, const struct kgenome_cell_insn *call, uint16_t *writes)
{
	struct kgenome_cell_cur kc;
	struct kgenome_cell_insn ci;
	uint16_t mask = 0, pushed = 0, restored = 0;
	unsigned i, slot = (unsigned)((call->target * 0x9e3779b97f4a7c15ull) >> 58);
	int kind = CALLEE_UNKNOWN;

	*writes = 0;
	if (call->target == call->at + call->len)
		return CALLEE_GETPC;                    /* `call next`: the address of the next instruction */
	if (c->memo[slot].kind && c->memo[slot].target == call->target) {
		*writes = c->memo[slot].writes;
		return c->memo[slot].kind;
	}
	if (call->target < c->off || call->target >= c->off + c->n)
		return CALLEE_UNKNOWN;
	memset(&kc, 0, sizeof kc);
	if (!kgenome_cell_seek(&kc, call->target, 0))
		return CALLEE_UNKNOWN;
	for (i = 0; i < KGENOME_DIAG_CALLEE_INSN; i++) {
		if (!(kc.at < c->off + c->n && kgenome_cell_next(&kc, c->sp, &ci)))
			break;
		if (i == 0 && ci.op == KGENOME_CELL_POP) {
			kind = CALLEE_GETPC;            /* it takes its own return address off the stack */
			break;
		}
		if (ci.op == KGENOME_CELL_RET) {
			mask = (uint16_t)(mask & ~(pushed & restored));
			kind = CALLEE_KNOWN;
			break;
		}
		if (ci.op == KGENOME_CELL_CALL || ci.op == KGENOME_CELL_JMP || ci.op == KGENOME_CELL_JCC ||
		    ci.op == KGENOME_CELL_LOOP || ci.op == KGENOME_CELL_IRET)
			break;                          /* the paths are not all read */
		if (ci.op == KGENOME_CELL_PUSH && ci.n_op && ci.o[0].kind == KGENOME_CELL_O_REG && ci.o[0].reg < 16u &&
		    !(mask & (1u << ci.o[0].reg)))
			pushed = (uint16_t)(pushed | (1u << ci.o[0].reg));
		if (ci.op == KGENOME_CELL_POP && ci.n_op && ci.o[0].kind == KGENOME_CELL_O_REG && ci.o[0].reg < 16u &&
		    (pushed & (1u << ci.o[0].reg)))
			restored = (uint16_t)(restored | (1u << ci.o[0].reg));
		mask = (uint16_t)(mask | (uint16_t)(ci.wmask & 0xffffu));
	}
	*writes = kind == CALLEE_KNOWN ? mask : 0u;
	c->memo[slot].target = call->target;
	c->memo[slot].writes = *writes;
	c->memo[slot].kind = (uint8_t)kind;
	return kind;
}

/* KNOWN DEFECT X11b (2026-10-24, R) [sev M]: kgenome_diag_org_call leaves the ring as it was after a call, so the words an
 * i386 stdcall callee pops (`ret N`) stay as phantom slots. Trigger: `push a; push b; call stdcall_fn` then a later
 * pop or push. Effect: the ring drifts by N/4 slots per call and a later pop takes an argument's producer (a wrong
 * link) or the ring overflows into TRUNCATED. Reproducer: none (read). Fix: shrink the ring by the callee's pop
 * count, as kgenome_lineage_state_call does from the codemap `ret N` or the API's argc table. */
void kgenome_diag_org_call(struct kgenome_diag_orgs *w, struct kgenome_diag_callees *c,
			   const struct kgenome_cell_insn *in, int target_unknown)
{
	const uint16_t cs = c->caller_saved;
	const int direct = !target_unknown && !(in->flags & KGENOME_CELL_F_INDIRECT) && in->target != KGENOME_BROKEN;
	uint16_t live = 0, writes = 0;
	unsigned r;
	int kind = CALLEE_UNKNOWN;

	for (r = 0; r < 16u; r++)
		if ((cs & (1u << r)) && w->reg[r].node != KGENOME_DIAG_ORG_NONE)
			live = (uint16_t)(live | (1u << r));
	/* the callee is read when a register is carried that it could take; otherwise only the one question that
	 * changes the ring: does it fetch the program counter */
	if (direct)
		kind = live ? callee_scan(c, in, &writes) : callee_getpc(c, in) ? CALLEE_GETPC : CALLEE_UNKNOWN;
	if (kind == CALLEE_GETPC) {
		ring_push_none(w, 1u);          /* the return address the pop after it takes back */
		return;
	}
	if (!live)
		return;
	if (kind == CALLEE_KNOWN)
		kgenome_diag_org_kill(w, (uint16_t)(live & writes));
	else
		kgenome_diag_org_demote(w, live);
}

/* One register's two paths. `b` NULL: the path that holds nothing. 1 when a producer past the four is dropped. */
static int rec_merge(struct kgenome_diag_org *a, const struct kgenome_diag_org *b)
{
	static const struct kgenome_diag_org none = { KGENOME_DIAG_ORG_NONE, { 0 }, 0, 0, 0 };
	uint16_t pa[1u + KGENOME_DIAG_ORG_ALT], pb[1u + KGENOME_DIAG_ORG_ALT];
	uint16_t d[2u * (1u + KGENOME_DIAG_ORG_ALT)];
	unsigned na = 0, nb = 0, n = 0, i, k, in_b = 0;
	int lost = 0;

	if (!b)
		b = &none;
	/*
	 * A REGISTER THIS PATH HAS NO PRODUCER IN STAYS WITHOUT ONE, whatever the other path holds. The other
	 * path's producer could reach the consumer too - a link - but it would be a link the walk never made,
	 * and bringing a killed origin back at every join keeps windows open for the length of the function
	 * (MEASURED: 4 of 300 corpus files turned from whole to cut on the stack ring). Two producers, or one
	 * producer and a path with none, are what is merged (W4); one the walk already lost is not found again.
	 */
	if (a->node == KGENOME_DIAG_ORG_NONE)
		return 0;
	if (a->node == b->node && !memcmp(a->alt_p1, b->alt_p1, sizeof a->alt_p1) && a->may == b->may &&
	    a->symoff == b->symoff && a->symadd == b->symadd)
		return 0;
	/* the producers of each path, the node first, and the distinct ones of both in the walk's order */
	if (a->node != KGENOME_DIAG_ORG_NONE)
		pa[na++] = a->node;
	for (i = 0; na && i < KGENOME_DIAG_ORG_ALT && a->alt_p1[i]; i++)
		pa[na++] = (uint16_t)(a->alt_p1[i] - 1u);
	if (b->node != KGENOME_DIAG_ORG_NONE)
		pb[nb++] = b->node;
	for (i = 0; nb && i < KGENOME_DIAG_ORG_ALT && b->alt_p1[i]; i++)
		pb[nb++] = (uint16_t)(b->alt_p1[i] - 1u);
	for (i = 0; i < na + nb; i++) {
		const uint16_t v = i < na ? pa[i] : pb[i - na];

		for (k = 0; k < n; k++)
			if (d[k] == v)
				break;
		if (k == n)
			d[n++] = v;
	}
	/* the paths hold the same producers when every one of a's is b's and the counts agree */
	for (i = 0; i < na; i++) {
		for (k = 0; k < nb; k++)
			if (pa[i] == pb[k])
				break;
		in_b += k < nb;
	}
	if (n > 1u + KGENOME_DIAG_ORG_ALT) {
		lost = 1;
		n = 1u + KGENOME_DIAG_ORG_ALT;
	}
	{
		const int same_set = na == nb && in_b == na;
		const uint8_t may = (uint8_t)(a->may | b->may | (same_set ? 0u : 1u));

		a->node = n ? d[0] : KGENOME_DIAG_ORG_NONE;
		memset(a->alt_p1, 0, sizeof a->alt_p1);
		for (i = 1; i < n; i++)
			a->alt_p1[i - 1u] = (uint16_t)(d[i] + 1u);
		a->may = n ? may : 0u;
	}
	if (a->symoff != b->symoff || a->symadd != b->symadd) {
		a->symoff = 0;
		a->symadd = 0;
	}
	return lost;
}

int kgenome_diag_org_merge(struct kgenome_diag_orgs *to, const struct kgenome_diag_orgs *from)
{
	uint32_t i;
	int lost = 0;

	for (i = 0; i < 16u; i++)
		lost |= rec_merge(&to->reg[i], from ? &from->reg[i] : NULL);
	/*
	 * THE STACK, slot by slot from the bottom: slot i is the i-th push on both paths. A slot the other path
	 * does not hold (it is shallower, or the ring wrapped past it) is the path that holds nothing there, so
	 * what the walk's own path pushed is MAY. The walk's depth stays its own: it pops what it pushed.
	 */
	for (i = to->n_lost; i < to->n_stk; i++) {
		const unsigned s = i % KGENOME_DIAG_ORG_STK;
		struct kgenome_diag_org a = { to->stk[s], { 0 }, to->stk_may[s], 0, 0 };
		struct kgenome_diag_org b = { KGENOME_DIAG_ORG_NONE, { 0 }, 0, 0, 0 };
		int have = 0;

		memcpy(a.alt_p1, to->stk_alt_p1[s], sizeof a.alt_p1);
		if (from && i >= from->n_lost && i < from->n_stk) {
			b.node = from->stk[s];
			memcpy(b.alt_p1, from->stk_alt_p1[s], sizeof b.alt_p1);
			b.may = from->stk_may[s];
			have = 1;
		}
		lost |= rec_merge(&a, have ? &b : NULL);
		to->stk[s] = a.node;
		memcpy(to->stk_alt_p1[s], a.alt_p1, sizeof a.alt_p1);
		to->stk_may[s] = a.may;
	}
	return lost;
}

/* ---- the object's nodes --------------------------------------------------
 *
 * Flat and in the order the walk produced them, which for a linear sweep is
 * address order. Nothing depends on that order - see the note in
 * kofmod/kofdiagtree.h about why a provenance tree is not a sequence - but it
 * makes a dump readable, and a reader comparing two runs of the same object
 * gets the same file twice.
 */
