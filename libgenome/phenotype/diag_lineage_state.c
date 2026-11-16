/*
 * diag_lineage_state.c - the abstract state of a program point: a value (which producers it may be),
 * the places values are kept, the join of two states and what one instruction does to a state.
 * Part of the lineage stages; see diag_lineage_private.h for what they are and what is shared.
 *
 * WHY A NEW TRANSFER FUNCTION AND NOT kgenome_diag_wrapper_frame_step. That one moves ONE value per place
 * along ONE path: a value is a constant, a node, a stack address or a parameter, and where two paths meet
 * there is nothing to meet them with. This one moves a SET of producers, joins at a merge and keeps the
 * places a block-structured fixpoint needs; the two share the convention that decides what a place IS - a
 * stack slot is named by its offset from the stack pointer at the function's entry (the return address is
 * 0), so `[rsp+8]` and `[rbp-8]` after `mov rbp,rsp` are one slot - and the tests state that convention
 * once, independently of both (the oracle of tests/lib/genome/lineage_flow.c runs frames addressed through either register).
 */
#include "diag_lineage_private.h"

/* the row's stack pointer: every function below has the stage in hand */
#define SP (L->abi.sp)

int kgenome_lineage_charge(struct kgenome_lineage *L, uint64_t n)
{
	if (!kgenome_ledger_charge(&L->s->led, n)) {
		L->halt = 1;                    /* the ledger said KGENOME_OVER_BUDGET */
		return 0;
	}
	L->charged += n;
	return 1;
}

void kgenome_lineage_uncharge(struct kgenome_lineage *L, uint64_t n)
{
	kgenome_ledger_release(&L->s->led, n);
	L->charged -= n;
}

/*
 * A BOUND OF THE STAGES FIRED: a value with more producers than it holds, a consumer with more than it holds, a function that did
 * not converge in its steps, a recursive group that did not settle. What was lost is evidence (a producer, a link), so the scan
 * SAYS it (KGENOME_TRUNCATED, as every bound of the lib) and the kind is counted (kgenome_diag_lineage_stats.bounded). The
 * bounds are SIZED so that they do not fire on ordinary code: the token set is 16 (8 fired on 14 of the 300 corpus files and
 * turned 14 of them into "Limit reached"; 16 fires on 2, 32 on 1, 64 on none - the cost of a value is its size), the steps of a
 * function 64 per instruction and a floor (fired 0 times on the 5 cells), the group rounds 8 (0 times).
 */
void kgenome_lineage_bound(struct kgenome_lineage *L, unsigned kind)
{
	L->st.bounded[kind]++;
	kgenome_diag_note(L->s, KGENOME_TRUNCATED);
}

/* ---- a value ---- */

void kgenome_lineage_val_unknown(struct kgenome_lineage_val *v, unsigned why)
{
	memset(v, 0, sizeof *v);
	v->other = 1;
	v->why = why;
}

void kgenome_lineage_val_other(struct kgenome_lineage_val *v)
{
	kgenome_lineage_val_unknown(v, KGENOME_LINEAGE_W_OPAQUE);
}

/* Does the value hold token `t`: its inline tokens, then its chain. */
static int val_has(const struct kgenome_lineage *L, const struct kgenome_lineage_val *v, uint32_t t)
{
	uint32_t i, c;

	for (i = 0; i < v->n; i++)
		if (v->t[i] == t)
			return 1;
	for (c = v->more; c; c = L->vx[c - 1u].next)
		if (L->vx[c - 1u].tok == t)
			return 1;
	return 0;
}

uint32_t kgenome_lineage_val_toks(const struct kgenome_lineage *L, const struct kgenome_lineage_val *v, uint16_t *out, uint32_t cap)
{
	uint32_t n = 0, i, c;

	for (i = 0; i < v->n; i++, n++)
		if (n < cap)
			out[n] = v->t[i];
	for (c = v->more; c; c = L->vx[c - 1u].next, n++)
		if (n < cap)
			out[n] = L->vx[c - 1u].tok;
	return n;
}

/*
 * Add a token; 1 when the value changed. Past the inline ones a token is a new head of the value's chain in the solve's pool (see
 * KGENOME_LINEAGE_SET in diag_lineage_private.h): the chain is never written in place, so the copies of the value that share it keep what
 * they had. Only the ledger bounds it: a refusal widens the value to `other` (W_LIMIT, its links MAY) and the scan says a bound fired.
 */
int kgenome_lineage_val_add(struct kgenome_lineage *L, struct kgenome_lineage_val *v, uint32_t t)
{
	if (val_has(L, v, t))
		return 0;
	if (v->n < KGENOME_LINEAGE_VAL_INLINE) {
		v->t[v->n++] = (uint16_t)t;
		return 1;
	}
	if (L->nvx == L->capvx) {
		const uint32_t nc = kgenome_grow_cap(L->capvx, 256u);
		struct kgenome_lineage_aggx *nv;

		if (!nc || !kgenome_lineage_charge(L, (uint64_t)(nc - L->capvx) * sizeof *nv))
			goto lost;
		nv = realloc(L->vx, (size_t)nc * sizeof *nv);
		if (!nv) {
			kgenome_lineage_uncharge(L, (uint64_t)(nc - L->capvx) * sizeof *nv);
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			goto lost;
		}
		L->vx = nv;
		L->capvx = nc;
	}
	L->vx[L->nvx].tok = (uint16_t)t;
	L->vx[L->nvx].next = v->more;
	v->more = ++L->nvx;
	return 1;
lost:
	kgenome_lineage_bound(L, KGENOME_LINEAGE_B_VALUE);
	if (v->other && (v->why & KGENOME_LINEAGE_W_LIMIT))
		return 0;
	v->other = 1;
	v->why |= KGENOME_LINEAGE_W_LIMIT;
	return 1;
}

int kgenome_lineage_val_join(struct kgenome_lineage *L, struct kgenome_lineage_val *a,
			     const struct kgenome_lineage_val *b)
{
	int ch = 0;
	uint8_t i;

	/* the common case at a join: the two paths hold the very same value (one chain is one set: it is never written in place) */
	if (a->n == b->n && a->more == b->more && a->other == b->other && a->why == b->why && a->k == b->k && a->v == b->v &&
	    !memcmp(a->t, b->t, (size_t)a->n * sizeof a->t[0]))
		return 0;
	for (i = 0; i < b->n; i++)
		ch |= kgenome_lineage_val_add(L, a, b->t[i]);
	{
		uint32_t c;

		/* (b's chain is read before a gains cells: a new head of a's points at a's old one, never into b's) */
		for (c = b->more; c; c = L->vx[c - 1u].next)
			ch |= kgenome_lineage_val_add(L, a, L->vx[c - 1u].tok);
	}
	if (b->other) {
		/* the reasons add; a reason gained alone does not make the block be read again (it changes no link, and the fixpoint would
		 * run on it for nothing) */
		ch |= !a->other;
		a->other = 1;
		a->why |= b->why;
	}
	if (a->k != KGENOME_LINEAGE_A_NONE && (a->k != b->k || a->v != b->v)) {
		a->k = KGENOME_LINEAGE_A_NONE;
		a->v = 0;
		ch = 1;
	}
	return ch;
}

static void val_tok(struct kgenome_lineage_val *v, uint32_t t)
{
	memset(v, 0, sizeof *v);
	v->t[0] = (uint16_t)t;
	v->n = 1;
}

static void val_addr(struct kgenome_lineage_val *v, uint8_t k, int64_t a)
{
	kgenome_lineage_val_unknown(v, KGENOME_LINEAGE_W_CONST);       /* an address is a value that names no producer, and is known */
	v->k = k;
	v->v = a;
}

/* 64-bit address arithmetic wraps as the machine's does (a hostile immediate must not be signed
 * overflow); the sum is a name for a place, never ordered by magnitude. */
static int64_t wadd(int64_t a, int64_t b)
{
	return (int64_t)((uint64_t)a + (uint64_t)b);
}

/* ---- the places ---- */

static uint64_t key_make(unsigned space, uint64_t payload)
{
	return ((uint64_t)space << 60) | (payload & ((1ull << 60) - 1u));
}

static uint64_t key_stack(int64_t off)
{
	return key_make(KGENOME_LINEAGE_KEY_STACK, (uint64_t)(uint32_t)(int32_t)off);
}

/* The place an operand names, or 0 when it is none the walk can follow. What is followed: a slot of the
 * frame (through the stack pointer or any register holding a stack address), a global at a fixed
 * address (RIP-relative, absolute, or through a register holding one) and, with LOCS, a field of an
 * object ONE node produced - base register holds exactly that node's result. An index register, a
 * segment other than the data ones (fs: and gs: are thread data) and anything else is not a place. */
static unsigned place_resolve(const struct kgenome_lineage *L, const struct kgenome_lineage_state *st,
			      const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *o,
			      int locs, uint64_t *key)
{
	const struct kgenome_lineage_val *b;

	if (o->kind != KGENOME_CELL_O_MEM || o->index != KGENOME_CELL_REG_NONE)
		return 0;
	if (o->seg != KGENOME_CELL_REG_NONE && o->seg != KGENOME_CELL_SEG_DS && o->seg != KGENOME_CELL_SEG_SS)
		return 0;
	if (o->flags & KGENOME_CELL_OF_RIPREL) {
		if (!locs || in->at_va == KGENOME_BROKEN)
			return 0;
		*key = key_make(KGENOME_LINEAGE_KEY_GLOB, (uint64_t)wadd((int64_t)(in->at_va + in->len), o->disp));
		return KGENOME_LINEAGE_KEY_GLOB;
	}
	if (o->reg == KGENOME_CELL_REG_NONE) {
		if (!locs)
			return 0;
		*key = key_make(KGENOME_LINEAGE_KEY_GLOB,
				L->abi.wide ? (uint64_t)o->disp : (uint64_t)o->disp & 0xffffffffu);
		return KGENOME_LINEAGE_KEY_GLOB;
	}
	if (o->reg == SP) {
		if (!st->spok)
			return 0;
		*key = key_stack(wadd(st->sp, o->disp));
		return KGENOME_LINEAGE_KEY_STACK;
	}
	if (o->reg >= 16u)
		return 0;
	b = &st->r[o->reg];
	if (b->k == KGENOME_LINEAGE_A_STACK) {
		*key = key_stack(wadd(b->v, o->disp));
		return KGENOME_LINEAGE_KEY_STACK;
	}
	if (locs && b->k == KGENOME_LINEAGE_A_ABS) {
		*key = key_make(KGENOME_LINEAGE_KEY_GLOB, (uint64_t)wadd(b->v, o->disp));
		return KGENOME_LINEAGE_KEY_GLOB;
	}
	/* (a STATUS token is a value, not an object: connect's zero names no field) */
	if (locs && b->n == 1 && !b->more && !b->other && !(b->t[0] & (KGENOME_LINEAGE_PARAM | KGENOME_LINEAGE_STATUS))) {
		*key = key_make(KGENOME_LINEAGE_KEY_HEAP, ((uint64_t)b->t[0] << 32) | (uint32_t)(int32_t)o->disp);
		return KGENOME_LINEAGE_KEY_HEAP;
	}
	return 0;
}

/* ... for the stages the block is run with (the ones active on it). */
static unsigned place_of(const struct kgenome_lineage *L, const struct kgenome_lineage_state *st,
			 const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *o, uint64_t *key)
{
	return place_resolve(L, st, in, o, (L->act & KGENOME_LINEAGE_S_LOCS) != 0, key);
}

/* The first slot whose key is not below `key`. */
static uint32_t slot_pos(const struct kgenome_lineage_state *st, uint64_t key)
{
	uint32_t lo = 0, hi = st->n_slot;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (st->slot[mid].key < key)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo;
}

static const struct kgenome_lineage_val *slot_get(const struct kgenome_lineage_state *st, uint64_t key)
{
	uint32_t p = slot_pos(st, key);

	return p < st->n_slot && st->slot[p].key == key ? &st->slot[p].v : NULL;
}

static int slot_room(struct kgenome_lineage *L, struct kgenome_lineage_state *st, uint32_t want)
{
	struct kgenome_lineage_slot *ns;
	uint32_t nc;

	if (want <= st->cap_slot)
		return 1;
	nc = st->cap_slot ? st->cap_slot : 4u;
	while (nc < want)
		nc *= 2u;
	if (!kgenome_lineage_charge(L, (uint64_t)(nc - st->cap_slot) * sizeof *ns))
		return 0;
	ns = realloc(st->slot, (size_t)nc * sizeof *ns);
	if (!ns) {
		kgenome_lineage_uncharge(L, (uint64_t)(nc - st->cap_slot) * sizeof *ns);
		kgenome_diag_note(L->s, KGENOME_NOMEM);
		L->halt = 1;
		return 0;
	}
	st->slot = ns;
	st->cap_slot = nc;
	return 1;
}

static void slot_put(struct kgenome_lineage *L, struct kgenome_lineage_state *st, uint64_t key,
		     const struct kgenome_lineage_val *v)
{
	uint32_t p = slot_pos(st, key);

	if (p < st->n_slot && st->slot[p].key == key) {
		st->slot[p].v = *v;
		return;
	}
	if (!slot_room(L, st, st->n_slot + 1u))
		return;
	memmove(&st->slot[p + 1u], &st->slot[p], (size_t)(st->n_slot - p) * sizeof *st->slot);
	st->slot[p].key = key;
	st->slot[p].v = *v;
	st->n_slot++;
}

/*
 * THE WORDS PUSHED WHILE THE STACK POINTER IS NOT KNOWN (LG-9). Where two paths meet with the stack at two depths, no slot of the frame
 * can be named through the stack pointer any more - and what is pushed and popped AFTER that point is still consistent among itself on
 * every path: msfvenom's exit block is reached at depth 0 and at depth 8, and its `push 60; pop rax` was lost with the stack pointer, so
 * the exit's number was unknown, the stage could not take the exit as one, and the error path fell through into the success path's
 * `pop rsi` (lineage_sites.c variant 7). So the state keeps, from the point the stack pointer was lost, the words pushed and not yet
 * popped: `ld` of them, slots of their own space by depth, and a pop takes the top one back OUT of the state.
 *
 * WHY NOT A FRESH STACK BASE AT THE JOIN (tried, MEASURED, rejected): giving the joining block a stack pointer of its own made every
 * later `mov [esp+x]` a slot too - on a Go i386 binary (corp300 277) the states at the joins held 143 slots on average against 52, the
 * fixpoint visited 670796 blocks against 423356 and made 928837 joins against 583056, for no link more: lineage Ir +24.7% on the
 * 30-file callgrind set, the three worst files x1.8 to x1.9 in time. The words pushed are only what a pop can take back, so only they
 * are kept, and a pop deletes what it takes (nothing accumulates): on the same file 450761 visits, 620888 joins, 51.3 slots a join
 * (without either form: 423356, 583056, 51.6), and on corp300 041 208369 / 287616 / 21.8 against 199428 / 275339 / 21.6 - the cost of
 * following the pushes, and no other. Callgrind, the 30-file set, lineage Ir: base 10.44 G, the fresh base 13.01 G, this 10.82 G (+3.7%,
 * the system call sites included); warm wall time of the 356-file A/B within 1% of base. A move of the stack pointer by anything but a push or a pop of whole
 * words, two paths that meet with two different local depths, or a path with a known stack pointer meeting one with words pending,
 * make the local depth unknown too (ld -1): what was pushed before it is then not taken for what a pop gives.
 */
static void lstk_drop(struct kgenome_lineage_state *st)
{
	uint32_t p = slot_pos(st, key_make(KGENOME_LINEAGE_KEY_LSTK, 0)), q = p;

	while (q < st->n_slot && (st->slot[q].key >> 60) == KGENOME_LINEAGE_KEY_LSTK)
		q++;
	if (q > p) {
		memmove(&st->slot[p], &st->slot[q], (size_t)(st->n_slot - q) * sizeof *st->slot);
		st->n_slot -= q - p;
	}
}

/* The stack pointer is no longer known: what is pushed from here is counted from here. */
static void sp_lost(struct kgenome_lineage_state *st)
{
	st->spok = 0;
	st->ld = 0;
	lstk_drop(st);
}

/* ... and the words pushed since are not known either. */
static void ld_lost(struct kgenome_lineage_state *st)
{
	st->ld = -1;
	lstk_drop(st);
}

/* The stack pointer is known again (`mov rsp, rbp`): the words counted while it was not are below it or above it - not the local stack. */
static void sp_found(struct kgenome_lineage_state *st, int32_t sp)
{
	st->sp = sp;
	st->spok = 1;
	st->ld = 0;
	lstk_drop(st);
}

/* The stack moved UP by `words` (a pop is 1, `sub esp, 8` on x86-64 is -1) while its pointer is not known: the local depth follows, or is lost
 * past its bottom. */
static void ld_move(struct kgenome_lineage_state *st, int32_t words)
{
	int32_t n;
	uint32_t p;

	if (st->ld < 0)
		return;
	n = st->ld - words;
	if (n < 0 || n > 0x7fff) {
		ld_lost(st);
		return;
	}
	/* the words above the new top are popped: out of the state */
	while ((p = slot_pos(st, key_make(KGENOME_LINEAGE_KEY_LSTK, (uint64_t)n))) < st->n_slot &&
	       (st->slot[p].key >> 60) == KGENOME_LINEAGE_KEY_LSTK) {
		memmove(&st->slot[p], &st->slot[p + 1u], (size_t)(st->n_slot - p - 1u) * sizeof *st->slot);
		st->n_slot--;
	}
	st->ld = (int16_t)n;
}

/* ---- the state ---- */

int kgenome_lineage_state_copy(struct kgenome_lineage *L, struct kgenome_lineage_state *dst,
			       const struct kgenome_lineage_state *src)
{
	struct kgenome_lineage_slot *ns = NULL;

	if (src->n_slot) {
		if (!kgenome_lineage_charge(L, (uint64_t)src->n_slot * sizeof *ns))
			return 0;
		ns = malloc((size_t)src->n_slot * sizeof *ns);
		if (!ns) {
			kgenome_lineage_uncharge(L, (uint64_t)src->n_slot * sizeof *ns);
			kgenome_diag_note(L->s, KGENOME_NOMEM);
			L->halt = 1;
			return 0;
		}
		memcpy(ns, src->slot, (size_t)src->n_slot * sizeof *ns);
	}
	*dst = *src;
	dst->slot = ns;
	dst->cap_slot = src->n_slot;
	return 1;
}

void kgenome_lineage_state_free(struct kgenome_lineage *L, struct kgenome_lineage_state *st)
{
	if (st->cap_slot)
		kgenome_lineage_uncharge(L, (uint64_t)st->cap_slot * sizeof *st->slot);
	free(st->slot);
	st->slot = NULL;
	st->n_slot = st->cap_slot = 0;
}

/*
 * THE JOIN OF TWO STATES. A place on one side only is `other` on the other - it was never written on that
 * path, and nothing says what it held - so the merged value keeps the tokens and gains the flag: the
 * producer reaches on some path, not on all. 1 when `to` changed.
 */
int kgenome_lineage_state_join(struct kgenome_lineage *L, struct kgenome_lineage_state *to,
			       const struct kgenome_lineage_state *from)
{
	int ch = 0;
	uint32_t i, j, add = 0;

	if (!to->valid) {
		kgenome_lineage_state_free(L, to);
		if (!kgenome_lineage_state_copy(L, to, from))
			return 0;
		to->valid = 1;
		return 1;
	}
	/* the common case: the path that arrives holds what the block already held. The bytes are equal only if the
	 * values are, so this never skips a change - it only skips the work of finding there was none. */
	/* (a state with no slot holds a NULL table, and memcmp may not be handed NULL even for no bytes) */
	if (!memcmp(to->r, from->r, sizeof to->r) && to->n_slot == from->n_slot &&
	    (!to->n_slot || !memcmp(to->slot, from->slot, (size_t)to->n_slot * sizeof *to->slot)) &&
	    to->spok == from->spok &&
	    (!to->spok || to->sp == from->sp) && to->pshs == from->pshs && to->seeded == from->seeded && to->ld == from->ld)
		return 0;
	for (i = 0; i < 16u; i++)
		ch |= kgenome_lineage_val_join(L, &to->r[i], &from->r[i]);
	/* two depths at one join: the stack pointer is lost, and what the block pushes from here is counted from here (see sp_lost) */
	if (to->spok && (!from->spok || to->sp != from->sp)) {
		sp_lost(to);
		ch = 1;
	} else if (!to->spok && to->ld >= 0 && (from->spok ? 0 : from->ld) != to->ld) {
		ld_lost(to);
		ch = 1;
	}
	if (to->pshs && to->pshs != from->pshs) {       /* 0 is the top: once there it does not change again */
		to->pshs = 0;
		ch = 1;
	}
	if (to->seeded && !from->seeded) {
		to->seeded = 0;
		ch = 1;
	}
	for (i = 0, j = 0; i < to->n_slot || j < from->n_slot;) {
		if (i < to->n_slot && (j >= from->n_slot || to->slot[i].key < from->slot[j].key)) {
			const uint32_t w = (to->slot[i].key >> 60) == KGENOME_LINEAGE_KEY_STACK ? KGENOME_LINEAGE_W_SLOT : KGENOME_LINEAGE_W_CELL;

			if (!to->slot[i].v.other || !(to->slot[i].v.why & w)) {
				to->slot[i].v.other = 1;
				to->slot[i].v.why |= w;                 /* not written on the other path */
				ch = 1;
			}
			i++;
		} else if (j < from->n_slot && (i >= to->n_slot || from->slot[j].key < to->slot[i].key)) {
			add++;
			j++;
		} else {
			ch |= kgenome_lineage_val_join(L, &to->slot[i].v, &from->slot[j].v);
			i++;
			j++;
		}
	}
	if (add && slot_room(L, to, to->n_slot + add)) {
		/* merge from the back, so no slot moves twice */
		int64_t a = (int64_t)to->n_slot - 1, b = (int64_t)from->n_slot - 1, w = (int64_t)(to->n_slot + add) - 1;

		while (b >= 0) {
			if (a >= 0 && to->slot[a].key > from->slot[b].key) {
				to->slot[w--] = to->slot[a--];
			} else if (a >= 0 && to->slot[a].key == from->slot[b].key) {
				to->slot[w--] = to->slot[a--];
				b--;
			} else {
				to->slot[w].key = from->slot[b].key;
				to->slot[w].v = from->slot[b].v;
				to->slot[w].v.other = 1;
				to->slot[w].v.why |= (from->slot[b].key >> 60) == KGENOME_LINEAGE_KEY_STACK ? KGENOME_LINEAGE_W_SLOT : KGENOME_LINEAGE_W_CELL;
				to->slot[w].v.k = KGENOME_LINEAGE_A_NONE;
				w--;
				b--;
			}
		}
		to->n_slot += add;
		ch = 1;
	}
	return ch;
}

void kgenome_lineage_state_entry(struct kgenome_lineage *L, struct kgenome_lineage_state *st, int params)
{
	const struct kgenome_lineage_abi *a = &L->abi;
	unsigned i;

	memset(st, 0, sizeof *st);
	for (i = 0; i < 16u; i++)
		kgenome_lineage_val_unknown(&st->r[i], KGENOME_LINEAGE_W_ENTRY);
	st->spok = 1;
	st->valid = 1;
	if (!params)
		return;
	for (i = 0; i < KGENOME_LINEAGE_NPARAM; i++) {
		struct kgenome_lineage_val v;

		val_tok(&v, KGENOME_LINEAGE_PARAM | i);
		if (i < a->n_arg) {
			st->r[a->arg[i]] = v;
		} else if (i >= a->stack_first && a->w) {
			/* in the callee the return address is at 0 and the first stack argument above it
			 * (above the shadow space on Windows x64) */
			slot_put(L, st, key_stack((int64_t)a->stack_off + a->w + (int64_t)a->w * (int64_t)(i - a->stack_first)), &v);
		}
	}
}

struct kgenome_lineage_val kgenome_lineage_arg(const struct kgenome_lineage *L,
					       const struct kgenome_lineage_state *st, unsigned i)
{
	const struct kgenome_lineage_abi *a = &L->abi;
	struct kgenome_lineage_val v;
	const struct kgenome_lineage_val *p;

	kgenome_lineage_val_unknown(&v, KGENOME_LINEAGE_W_ENTRY);
	if (i < a->n_arg)
		return st->r[a->arg[i]];
	if (i < a->stack_first)
		return v;
	if (!st->spok) {
		v.why = KGENOME_LINEAGE_W_STACK;
		return v;
	}
	p = slot_get(st, key_stack(wadd(st->sp, (int64_t)a->stack_off + (int64_t)a->w * (int64_t)(i - a->stack_first))));
	return p ? *p : v;
}

/* ---- one instruction ---- */

/* The value an operand holds. */
void kgenome_lineage_read_op(const struct kgenome_lineage *L, const struct kgenome_lineage_state *st,
		    const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *o,
		    struct kgenome_lineage_val *out)
{
	uint64_t key;
	unsigned kind;
	const struct kgenome_lineage_val *p;

	switch (o->kind) {
	case KGENOME_CELL_O_REG:
		if (o->reg >= 16u || o->size < 4u || (o->flags & KGENOME_CELL_OF_HIGH8)) {
			kgenome_lineage_val_unknown(out, KGENOME_LINEAGE_W_NARROW);
		} else if (o->reg == SP) {
			if (st->spok)
				val_addr(out, KGENOME_LINEAGE_A_STACK, st->sp);
			else
				kgenome_lineage_val_unknown(out, KGENOME_LINEAGE_W_STACK);
		} else {
			*out = st->r[o->reg];
		}
		return;
	case KGENOME_CELL_O_IMM:
		val_addr(out, KGENOME_LINEAGE_A_ABS, (int64_t)o->imm);
		return;
	case KGENOME_CELL_O_MEM:
		kgenome_lineage_val_other(out);
		if (o->size < 4u) {
			out->why = KGENOME_LINEAGE_W_NARROW;
			return;
		}
		if ((kind = place_of(L, st, in, o, &key)) != 0) {
			if ((p = slot_get(st, key)) != NULL)
				*out = *p;
			else if (kind == KGENOME_LINEAGE_KEY_STACK && (int32_t)(uint32_t)key >= (int32_t)L->abi.w)
				out->why = KGENOME_LINEAGE_W_ENTRY;     /* above the return address: an argument the caller pushed */
			else        /* a place the function has not written: its frame (filled through a pointer or by a callee) or a cell */
				out->why = kind == KGENOME_LINEAGE_KEY_STACK ? KGENOME_LINEAGE_W_SLOT : KGENOME_LINEAGE_W_CELL;
		} else if (o->reg == SP && !st->spok) {
			out->why = KGENOME_LINEAGE_W_STACK;
		} else if (!(L->act & KGENOME_LINEAGE_S_LOCS) && place_resolve(L, st, in, o, 1, &key)) {
			/* a place LOCS would follow (settled to W_CELL where it reaches a consumer when the function stores to no such place) */
			out->why = KGENOME_LINEAGE_W_MEM;
		} else if (o->reg != KGENOME_CELL_REG_NONE || o->index != KGENOME_CELL_REG_NONE) {
			out->why = KGENOME_LINEAGE_W_ADDR;              /* an address the walk has no name for */
		}
		return;
	default:
		kgenome_lineage_val_other(out);
	}
}

/* Make an operand hold a value. A write to the stack pointer is followed when it is a stack address
 * (`mov rsp, rbp` in an epilogue) and loses the stack otherwise. */
static void write_op(struct kgenome_lineage *L, struct kgenome_lineage_state *st,
		     const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *o,
		     const struct kgenome_lineage_val *v)
{
	uint64_t key;
	struct kgenome_lineage_val oth;

	kgenome_lineage_val_unknown(&oth, KGENOME_LINEAGE_W_NARROW);
	if (o->kind == KGENOME_CELL_O_REG) {
		if (o->reg >= 16u)
			return;
		if (o->reg == SP) {
			if (v->k == KGENOME_LINEAGE_A_STACK && o->size >= 4u)
				sp_found(st, (int32_t)v->v);
			else if (st->spok)
				sp_lost(st);
			else
				ld_lost(st);
			st->pshs = 0;
			return;
		}
		st->r[o->reg] = o->size >= 4u && !(o->flags & KGENOME_CELL_OF_HIGH8) ? *v : oth;
		return;
	}
	if (o->kind == KGENOME_CELL_O_MEM && place_of(L, st, in, o, &key))
		slot_put(L, st, key, o->size >= 4u ? v : &oth);
}

/* Why the value an instruction writes is unknown when the transfer function has no rule for it: arithmetic and logic make a
 * computed value, the rest is a gap. */
static unsigned unmodelled_reason(const struct kgenome_cell_insn *in)
{
	switch (in->op) {
	case KGENOME_CELL_ADD: case KGENOME_CELL_SUB: case KGENOME_CELL_ADC: case KGENOME_CELL_SBB:
	case KGENOME_CELL_AND: case KGENOME_CELL_OR: case KGENOME_CELL_XOR: case KGENOME_CELL_NOT: case KGENOME_CELL_NEG:
	case KGENOME_CELL_INC: case KGENOME_CELL_DEC: case KGENOME_CELL_SHL: case KGENOME_CELL_SHR: case KGENOME_CELL_SAR:
	case KGENOME_CELL_ROL: case KGENOME_CELL_ROR: case KGENOME_CELL_RCL: case KGENOME_CELL_RCR:
	case KGENOME_CELL_MUL: case KGENOME_CELL_IMUL: case KGENOME_CELL_DIV: case KGENOME_CELL_IDIV:
	case KGENOME_CELL_LEA: case KGENOME_CELL_CMOV: case KGENOME_CELL_SETCC:
	case KGENOME_CELL_WIDEN:        /* cdq/cqo: the sign of eax */
		return KGENOME_LINEAGE_W_COMPUTED;
	default:
		return KGENOME_LINEAGE_W_OPAQUE;
	}
}

static void forget_written(struct kgenome_lineage *L, struct kgenome_lineage_state *st,
			   const struct kgenome_cell_insn *in)
{
	struct kgenome_lineage_val oth;
	unsigned r;
	uint64_t key;

	kgenome_lineage_val_unknown(&oth, unmodelled_reason(in));
	for (r = 0; r < 16u; r++) {
		if (!(in->wmask & (1ull << r)))
			continue;
		if (r == SP) {
			if (st->spok)
				sp_lost(st);
			else
				ld_lost(st);
			st->pshs = 0;
		} else {
			st->r[r] = oth;
		}
	}
	/* a memory operand the instruction writes holds what it made now */
	if (in->n_op && in->o[0].kind == KGENOME_CELL_O_MEM && (in->o[0].flags & KGENOME_CELL_OF_WRITE) &&
	    place_of(L, st, in, &in->o[0], &key))
		slot_put(L, st, key, &oth);
}

void kgenome_lineage_state_step(struct kgenome_lineage *L, struct kgenome_lineage_state *st,
				const struct kgenome_cell_insn *in)
{
	L->abi.step(L, st, in);
}

/* THE x86 AND x86-64 TRANSFER FUNCTION (the `step` of their rows, diag_lineage_arch.c). */
void kgenome_lineage_step_x86(struct kgenome_lineage *L, struct kgenome_lineage_state *st, const struct kgenome_cell_insn *in)
{
	const struct kgenome_cell_operand *d = &in->o[0], *s = &in->o[1];
	struct kgenome_lineage_val v;
	const int w = L->abi.w;

	switch (in->op) {
	case KGENOME_CELL_NOP:
	case KGENOME_CELL_CMP:
	case KGENOME_CELL_TEST:
		return;
	case KGENOME_CELL_MOV:
		if (in->n_op >= 2u) {
			kgenome_lineage_read_op(L, st, in, s, &v);
			write_op(L, st, in, d, &v);
			return;
		}
		break;
	case KGENOME_CELL_MOVSX:
	case KGENOME_CELL_MOVZX:
	case KGENOME_CELL_WIDEN:
		/* A 32-bit value widened is the same value as far as a handle is concerned (movslq edx,rdx);
		 * the engine's wrapper walk says the same. */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
		    s->size >= 4u && d->reg < 16u && s->reg < 16u && d->reg != SP && s->reg != SP) {
			st->r[d->reg] = st->r[s->reg];
			return;
		}
		/*
		 * THE OPERAND-LESS WIDENINGS ARE TWO KINDS (the decoder says which by the register it writes, cell_state.c reads it the same way).
		 * cwde/cdqe widen eax in place: the same value, kept. cdq/cqo fill edx with the SIGN of eax: a value computed from eax, not eax
		 * and not what edx held - this returned without forgetting edx, so a producer left in rdx outlived the `cqo` that destroyed it
		 * (LG-1: `mov rdx, rax(malloc); cqo; mov rsi, rdx; call read` linked read's buffer to malloc as PROVEN).
		 */
		if (in->op == KGENOME_CELL_WIDEN && !(in->wmask & ~(1ull << L->abi.ret)))
			return;
		break;
	case KGENOME_CELL_XCHG:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
		    d->reg < 16u && s->reg < 16u && d->reg != SP && s->reg != SP) {
			v = st->r[d->reg];
			st->r[d->reg] = st->r[s->reg];
			st->r[s->reg] = v;
			return;
		}
		break;
	case KGENOME_CELL_LEA:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u && d->reg != SP &&
		    s->kind == KGENOME_CELL_O_MEM && s->index == KGENOME_CELL_REG_NONE &&
		    (s->seg == KGENOME_CELL_REG_NONE || s->seg == KGENOME_CELL_SEG_DS)) {
			kgenome_lineage_val_unknown(&v, KGENOME_LINEAGE_W_COMPUTED);
			if (s->flags & KGENOME_CELL_OF_RIPREL) {
				if (in->at_va != KGENOME_BROKEN)
					val_addr(&v, KGENOME_LINEAGE_A_ABS, wadd((int64_t)(in->at_va + in->len), s->disp));
			} else if (s->reg == KGENOME_CELL_REG_NONE) {
				val_addr(&v, KGENOME_LINEAGE_A_ABS, s->disp);
			} else if (s->reg == SP) {
				if (st->spok)
					val_addr(&v, KGENOME_LINEAGE_A_STACK, wadd(st->sp, s->disp));
			} else if (s->reg < 16u) {
				const struct kgenome_lineage_val *b = &st->r[s->reg];

				/* a pointer plus an offset is the same object */
				v = *b;
				if (v.k != KGENOME_LINEAGE_A_NONE)
					v.v = wadd(v.v, s->disp);
			}
			st->r[d->reg] = v;
			return;
		}
		break;
	case KGENOME_CELL_AND:
		/*
		 * `and esp, -16` after the frame is made (what main of a gcc program does) puts the stack pointer somewhere below where it
		 * was, by an amount the code does not say. What follows is addressed through the new value, consistently among itself, and
		 * never meets a slot of the old frame (those are named through the frame pointer): so the stack pointer is a NEW BASE, far
		 * below, as a seeded entry's is - and not unknown, which lost every argument of every call after it.
		 */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg == SP && s->kind == KGENOME_CELL_O_IMM && st->spok) {
			st->sp -= 1 << 20;
			st->pshs = 0;
			return;
		}
		break;
	case KGENOME_CELL_XOR:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
		    d->reg == s->reg && d->reg < 16u && d->reg != SP) {
			kgenome_lineage_val_unknown(&st->r[d->reg], KGENOME_LINEAGE_W_CONST);     /* zero: a constant, no producer */
			return;
		}
		break;
	case KGENOME_CELL_PUSH:
		if (in->n_op >= 1u) {
			kgenome_lineage_read_op(L, st, in, d, &v);
			if (st->spok) {
				st->sp -= w;
				slot_put(L, st, key_stack(st->sp), &v);
			} else if (st->ld >= 0 && st->ld < 0x7fff) {
				slot_put(L, st, key_make(KGENOME_LINEAGE_KEY_LSTK, (uint64_t)st->ld), &v);
				st->ld++;
			} else {
				ld_lost(st);
			}
			if (st->pshs < 250u)
				st->pshs++;
			return;
		}
		break;
	case KGENOME_CELL_POP:
		if (in->n_op >= 1u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u) {
			const struct kgenome_lineage_val *p = st->spok ? slot_get(st, key_stack(st->sp))
							      : st->ld > 0 ? slot_get(st, key_make(KGENOME_LINEAGE_KEY_LSTK, (uint64_t)(st->ld - 1))) : NULL;

			if (d->reg != SP) {
				if (p)
					st->r[d->reg] = *p;
				else
					kgenome_lineage_val_unknown(&st->r[d->reg],
								    st->spok ? KGENOME_LINEAGE_W_SLOT : KGENOME_LINEAGE_W_STACK);
			}
		}
		if (st->spok)
			st->sp += w;
		else
			ld_move(st, 1);
		if (st->pshs)
			st->pshs--;
		return;
	case KGENOME_CELL_ADD:
	case KGENOME_CELL_SUB:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_IMM && d->reg < 16u) {
			/* the immediate is the sample's: the sum is held where no real frame comes */
			int64_t imm = (int64_t)(int32_t)s->imm;

			if (in->op == KGENOME_CELL_SUB)
				imm = -imm;
			if (d->reg == SP) {
				int64_t n = (int64_t)st->sp + imm;

				if (!st->spok)
					imm % w ? ld_lost(st) : ld_move(st, (int32_t)(imm / w));
				else if (n > KGENOME_DIAG_WRAPPER_SP_LIM || n < -KGENOME_DIAG_WRAPPER_SP_LIM)
					sp_lost(st);
				else
					st->sp = (int32_t)n;
				st->pshs = 0;
				return;
			}
			if (d->size >= 4u) {
				/* a pointer moved by a constant is a pointer into the same object */
				if (st->r[d->reg].k != KGENOME_LINEAGE_A_NONE)
					st->r[d->reg].v = wadd(st->r[d->reg].v, imm);
				return;
			}
		}
		break;
	default:
		break;
	}
	forget_written(L, st, in);
}

/*
 * A CALL HAS RETURNED. The registers it destroys are `other` and rax holds `ret`.
 *
 * A STDCALL CALLEE POPS WHAT WAS PUSHED FOR IT, a cdecl one does not (its caller adds esp, and that is the
 * next instruction), and the instruction stream does not say how many words a callee takes: the pushes
 * since the stack pointer last moved include the arguments of a call that is still being built
 * (`connect(socket(2,1,6), &a, n)` pushes n and &a before it calls socket), and a guess that the callee popped
 * everything pushed is wrong exactly there - the errors then cancel at the outer call, so a check at the
 * return cannot find them (measured on the generated PE x86 programs: wrong links, stack back at 0).
 * So the count is KNOWN or the stack is not: an API's is its stdcall argument count from the emulator's own
 * table of names (kgenome_emu_win_argc_of_name), an internal function's is the `ret N` of its returns (the
 * codemap carries it), and a call with neither leaves the stack pointer UNKNOWN when anything is pending
 * (the frame pointer still names the frame). A call whose arguments are all in registers pushed nothing.
 */
void kgenome_lineage_state_call(struct kgenome_lineage *L, struct kgenome_lineage_state *st,
				const struct kgenome_cell_insn *next, const struct kgenome_lineage_val *ret, int pop)
{
	const struct kgenome_lineage_abi *a = &L->abi;
	unsigned i;

	for (i = 0; i < a->n_clob; i++)
		kgenome_lineage_val_unknown(&st->r[a->clob[i]], KGENOME_LINEAGE_W_CLOBBER);
	if (ret)
		st->r[a->ret] = *ret;
	if (a->callee_pops) {
		const int cdecl_clean = next && next->op == KGENOME_CELL_ADD && next->n_op >= 2u &&
					next->o[0].kind == KGENOME_CELL_O_REG && next->o[0].reg == SP;

		if (cdecl_clean) {
			/* the caller's own `add esp` follows and takes them */
		} else if (pop >= 0) {
			if (st->spok)
				st->sp += (int32_t)(a->w * pop);
			else
				ld_move(st, pop);
			st->pshs = st->pshs > (uint8_t)pop ? (uint8_t)(st->pshs - pop) : 0;
		} else if (st->pshs) {
			if (st->spok)
				sp_lost(st);
			else
				ld_lost(st);
		}
	} else {
		st->pshs = 0;
	}
}
