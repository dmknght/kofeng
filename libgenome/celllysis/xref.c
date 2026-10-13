/* One sweep of the code, and what it did with each address. See disasm_xref.h. */

#include "xref.h"

#include <stdlib.h>
#include <string.h>

#include "celllysis.h"

/* A general register is an index below this; the same number means "not one". */
#define NGPR 16u

/*
 * HOW MANY ADDRESSES ONE SWEEP MAY REMEMBER.
 *
 * The caller bounds the code it hands over - the rule that asks refuses an
 * object whose code is over eight kilobytes - so this is a second bound on a
 * different axis: a pathological eight kilobytes is a few thousand
 * instructions, and remembering every distinct address they name would be a
 * table the size of the code. Five hundred and twelve is far past what the
 * loaders measured name (nine at most), and hitting it sets `full` rather than
 * dropping a row silently, so a caller can tell "not used" from "not known".
 */
#define USE_MAX 512u

/*
 * AND A TABLE TO FIND THEM IN.
 *
 * The list was searched from the front for every address recorded, and that is
 * quadratic in the number of distinct addresses one sweep names: measured over
 * /usr/bin it was two hundred and twenty thousand comparisons against four
 * thousand nine hundred instructions decoded - the bookkeeping cost forty five
 * times the disassembly it was bookkeeping for.
 *
 * Open addressed, twice the entries so the load factor stays at a half, and a
 * multiply-shift mix rather than the low bits: data addresses are aligned and
 * clustered, so the low bits are the ones that collide.
 */
#define USE_HASH 1024u

/*
 * HOW MANY REGIONS ONE SWEEP MAY DISTINGUISH.
 *
 * A region ends at a RET, so this is roughly the function count of the code
 * swept - and the code swept is bounded at eight kilobytes, which no compiler
 * fills with more than a few dozen functions. Past the cap everything falls
 * into the last region, which blurs the grouping rather than losing it.
 *
 * Measured over 4940 ELF files: the most regions one sweep ever distinguished
 * was 35, and the cap was never reached. Sixty four is not a guess any more.
 */
#define USE_RGN 64u

/*
 * WHAT A REGISTER IS HOLDING, as far as this sweep can tell.
 *
 * `va` is a data address that reached this register, either as the address
 * itself (LEA) or as what was loaded from it (MOV from memory). The two are
 * deliberately not told apart: for an array the address IS the payload, for a
 * pointer variable the loaded value is, and in both cases calling the register
 * means the variable led to execution.
 *
 * Sixteen because that is the general purpose file; anything wider than a GPR
 * is not going to be a call target.
 */

/*
 * A FEW STACK SLOTS, because an unoptimised build puts the address in one.
 *
 *     lea  rax, [rip+0x2ed8]     # shellcode
 *     mov  [rbp-8], rax          <- here
 *     mov  rax, [rbp-8]
 *     call rax
 *
 * That is what gcc -O0 emits for a local function pointer, and without these
 * the trail ends at the store. Keyed by base register and displacement, and
 * only for rbp and rsp: a slot reached through any other base is not a local
 * and following it would need the dataflow this file does not do.
 *
 * Eight is what a function that hands one address to one call needs; a
 * displacement that does not fit evicts the oldest, which loses a finding
 * rather than inventing one.
 */
/* The two registers whose stack slots are followed, by the decoder's numbering. */
#define GPR_RSP KGENOME_CELL_REG_SP
#define GPR_RBP KGENOME_CELL_REG_BP

#define NSLOT 8u

struct slot {
	uint32_t base;          /* NGPR when the entry is free */
	int64_t  disp;
	uint64_t va;
};

struct kgenome_xref {
	/*
	 * THE RUN IN PROGRESS: what the registers and the locals hold since
	 * kgenome_xref_begin. A run is the unit the caller cuts the code into, and
	 * it is where this state is empty; see kgenome_xref_begin.
	 */
	uint64_t run_reg[NGPR];
	struct slot run_slot[NSLOT];
	uint32_t run_next_slot;
	uint32_t run_rgn;
	int      run_on;                /* x86, and a run has begun */
	uint64_t va[USE_MAX];
	uint8_t  flag[USE_MAX];
	uint16_t slot[USE_HASH];        /* index into va[] plus one; 0 is empty */
	/*
	 * The same entries in address order, built once when the sweep is done.
	 *
	 * The hash answers "is this exact address here" in one probe, which is
	 * what recording needs; it cannot answer "anything in this range",
	 * which is what asking needs. Sorting five hundred entries once is
	 * nothing next to the sweep that produced them, and it turns a range
	 * question into a binary search.
	 */
	uint16_t order[USE_MAX];
	/*
	 * EVERY region that referred to it, one bit each.
	 *
	 * A bitmap rather than the first one, because the question asked of it
	 * is "did anything outside the startup set mention this", and the first
	 * region to mention a variable is often the startup that initialises
	 * it. USE_RGN is 64 so the map is one word.
	 */
	uint64_t rgn[USE_MAX];
	uint64_t rgn_at[USE_RGN];       /* where each region starts */
	uint8_t  rgn_flag[USE_RGN];     /* what that region does: RGN_* below */
	/*
	 * WHO CALLS WHOM, as addresses until the sweep has seen them all.
	 *
	 * A direct call names a code address, and which region that address
	 * belongs to is only known once the sweep has passed it - so the edge
	 * is kept unresolved and turned into a region pair afterwards.
	 */
	uint8_t  edge_from[USE_RGN];
	uint64_t edge_to[USE_RGN];
	uint32_t n_edge;
	/* Addresses the caller named as startup, resolved to regions once the
	 * sweep has seen them all. */
	uint64_t start_at[USE_RGN];
	uint32_t n_start;
	uint64_t startup;               /* one bit per startup region */
	uint32_t n_rgn;
	uint32_t n;
	uint32_t sorted;
	int      full;
};

static uint32_t h_of(uint64_t va)
{
	va *= 0x9E3779B97F4A7C15ull;
	return (uint32_t)(va >> 52) & (USE_HASH - 1u);
}

/* The slot this address is in, or the empty slot it belongs in. */
static uint32_t h_find(const struct kgenome_xref *u, uint64_t va)
{
	uint32_t h = h_of(va);

	while (u->slot[h] && u->va[u->slot[h] - 1u] != va) {
			h = (h + 1u) & (USE_HASH - 1u);
	}
	return h;
}

static void note(struct kgenome_xref *u, uint64_t va, uint32_t f, uint32_t rgn)
{
	uint32_t h;

	if (!va)
		return;
	h = h_find(u, va);
	if (u->slot[h]) {
		u->flag[u->slot[h] - 1u] |= (uint8_t)f;
		u->rgn[u->slot[h] - 1u] |=
			(uint64_t)1 << (rgn < USE_RGN ? rgn : USE_RGN - 1u);
		return;
	}
	if (u->n == USE_MAX) {
		u->full = 1;
		return;
	}
	u->va[u->n] = va;
	u->flag[u->n] = (uint8_t)f;
	u->rgn[u->n] = 0;
	u->n++;
	u->rgn[u->n - 1u] |= (uint64_t)1 << (rgn < USE_RGN ? rgn : USE_RGN - 1u);
	u->slot[h] = (uint16_t)u->n;
}

/* The GPR an operand names, or NGPR when it names none. */
static uint32_t gpr_of(const struct kgenome_cell_operand *op)
{
	return op->kind == KGENOME_CELL_O_REG && op->reg < NGPR ? op->reg : NGPR;
}

/*
 * The stack slot a memory operand names, or NSLOT when it names none this
 * sweep will follow. rbp and rsp only - see the note on NSLOT.
 */
static uint32_t slot_of(struct slot *slot, const struct kgenome_cell_operand *op,
			int make, uint32_t *next)
{
	uint32_t i;
	uint32_t base;
	int64_t  disp;

	if (op->kind != KGENOME_CELL_O_MEM || op->reg == KGENOME_CELL_REG_NONE ||
	    op->index != KGENOME_CELL_REG_NONE || (op->flags & KGENOME_CELL_OF_RIPREL))
		return NSLOT;
	base = op->reg;
	if (base != GPR_RBP && base != GPR_RSP)
		return NSLOT;
	disp = op->disp;
	for (i = 0; i < NSLOT; i++)
		if (slot[i].base == base && slot[i].disp == disp)
			return i;
	if (!make)
		return NSLOT;
	i = (*next)++ % NSLOT;
	slot[i].base = base;
	slot[i].disp = disp;
	slot[i].va   = 0;
	return i;
}

/*
 * The absolute address a memory operand names, or 0 when it names none this
 * sweep can resolve.
 *
 * Rip-relative only, and that is not a shortcut: position independent code is
 * what every current toolchain emits, an absolute displacement in 64 bit code
 * is rare enough to be noise, and a base register would need the dataflow this
 * file has already said it does not do.
 */
static uint64_t mem_va(const struct kgenome_cell_insn *in, const struct kgenome_cell_operand *op)
{
	if (op->kind != KGENOME_CELL_O_MEM || !(op->flags & KGENOME_CELL_OF_RIPREL))
		return 0;
	return in->at_va + in->len + (uint64_t)op->disp;
}

struct kgenome_xref *kgenome_xref_new(void)
{
	return calloc(1, sizeof(struct kgenome_xref));
}

void kgenome_xref_begin(struct kgenome_xref *u, unsigned arch)
{
	uint32_t i;

	if (!u)
		return;
	/*
	 * The sweep tracks x86 registers and rip-relative operands; what the
	 * decoder says of another architecture's code would be read as if it
	 * were that. Nothing recorded is "nothing known" and the caller says so.
	 */
	u->run_on = arch == KGENOME_ARCH_X86 || arch == KGENOME_ARCH_X86_64;
	if (!u->run_on)
		return;
	for (i = 0; i < NSLOT; i++)
		u->run_slot[i].base = NGPR;
	u->run_next_slot = 0;
	/* A run of code starts a region, and every RET ends one. */
	u->run_rgn = u->n_rgn < USE_RGN ? u->n_rgn++ : USE_RGN - 1u;
	/* Each run starts knowing nothing: a register left over from the end of
	 * one section says nothing about the start of the next. */
	memset(u->run_reg, 0, sizeof u->run_reg);
}

void kgenome_xref_feed(void *user, const struct kgenome_cell_insn *in)
{
	struct kgenome_xref *u = user;
	uint64_t *reg;
	struct slot *slot;
	uint32_t *next_slot;
	uint32_t rgn;
	const struct kgenome_cell_operand *ops;
	uint32_t nops, i, dst = NGPR, len;
	uint64_t formed = 0, wm, rip;
	int near_br, direct, indirect, is_call;

	if (!u || !u->run_on)
		return;
	reg = u->run_reg;
	slot = u->run_slot;
	next_slot = &u->run_next_slot;
	rgn = u->run_rgn;
	if (!in) {
		/*
		 * One byte on rather than giving up.
		 *
		 * A linear sweep meets data between functions - jump
		 * tables, alignment padding, a literal pool - and that
		 * is not a reason to stop reading the code after it.
		 * Resynchronising costs at most one byte per byte of
		 * data, which the size bound already covers.
		 */
		memset(reg, 0, sizeof u->run_reg);
		return;
	}
	ops = in->o;
	rip = in->at_va;
	len = in->len;
	nops = in->n_op;
	/* A near call or jump: a far one leaves the segment and is
	 * neither. */
	is_call = in->op == KGENOME_CELL_CALL && !(in->flags & KGENOME_CELL_F_FAR);
	near_br = is_call || (in->op == KGENOME_CELL_JMP && !(in->flags & KGENOME_CELL_F_FAR));
	indirect = near_br && (in->flags & KGENOME_CELL_F_INDIRECT);
	direct = near_br && !indirect;

	/*
	 * AN INDIRECT CALL OR JUMP, FIRST, because it reads the map
	 * this instruction is about to change.
	 */
	/*
	 * A DIRECT CALL OR JUMP COUNTS TOO, and leaving it out was
	 * wrong.
	 *
	 * "A direct call names a code address, never a variable" is
	 * true of code a compiler wrote for itself and false of this:
	 * gcc -O2 turns `((void(*)())shellcode)()` into a relative call
	 * straight to the variable, because the target is a constant it
	 * can compute. The address is what matters, not how the
	 * instruction encoded it; whether that address is a variable is
	 * the caller's question, not this sweep's.
	 */
	if (direct && in->target_va != KGENOME_BROKEN) {
		uint32_t k = is_call ? KGENOME_XREF_CALL : KGENOME_XREF_JUMP;
		uint64_t t = in->target_va;

		note(u, t, KGENOME_XREF_READ | k, rgn);
		/*
		 * AND REMEMBER WHO CALLS WHOM.
		 *
		 * The target is a code address; which region it lands
		 * in is not known until the sweep reaches it, so the
		 * address is kept and resolved after.
		 */
		if (is_call && u->n_edge < USE_RGN) {
			u->edge_from[u->n_edge] = (uint8_t)rgn;
			u->edge_to[u->n_edge] = t;
			u->n_edge++;
		}
	}
	if (indirect && is_call)
		u->rgn_flag[rgn] |= KGENOME_XREF_RGN_ICALL;
	if (indirect) {
		uint32_t k = is_call ? KGENOME_XREF_CALL : KGENOME_XREF_JUMP;

		for (i = 0; i < nops; i++) {
			const struct kgenome_cell_operand *op = &ops[i];
			uint32_t r = gpr_of(op);
			uint64_t m;

			if (r < NGPR && reg[r])
				note(u, reg[r], KGENOME_XREF_READ | k, rgn);
			/* call [rip+d] - the pointer is named by the
			 * instruction itself, no register involved. */
			m = mem_va(in, op);
			if (m)
				note(u, m, KGENOME_XREF_READ | k, rgn);
		}
	}

	/*
	 * EVERY TRACKED ADDRESS STILL IN A REGISTER AT A CALL is an
	 * argument, as far as this can tell.
	 *
	 * No knowledge of any calling convention, on purpose: which
	 * registers carry arguments differs by ABI and by architecture,
	 * and a sweep that guessed would be wrong on the first Windows
	 * binary. "It was in a register when a call happened" is the
	 * fact; whether that means it was passed is the caller's
	 * question, and a rule that wants certainty has CALL for that.
	 */
	if (is_call) {
		uint32_t r;

		for (r = 0; r < NGPR; r++)
			if (reg[r])
				note(u, reg[r],
				     KGENOME_XREF_READ | KGENOME_XREF_ARG, rgn);
	}

	/*
	 * WHAT THIS INSTRUCTION PUTS INTO A REGISTER.
	 *
	 * LEA gives the address, a load gives what is at it, and a
	 * register to register move carries either along. Everything
	 * else that writes a GPR ends what was known about it - which
	 * is the conservative direction: a forgotten register loses a
	 * finding, a remembered stale one invents evidence.
	 */
	for (i = 0; i < nops; i++) {
		const struct kgenome_cell_operand *op = &ops[i];
		uint64_t m;

		if ((op->flags & KGENOME_CELL_OF_WRITE)) {
			uint32_t r = gpr_of(op);
			uint64_t w = mem_va(in, op);

			if (r < NGPR && dst == NGPR)
				dst = r;
			if (w)
				note(u, w, KGENOME_XREF_WRITE, rgn);
		}
		if ((op->flags & KGENOME_CELL_OF_READ)) {
			m = mem_va(in, op);
			if (m) {
				note(u, m, KGENOME_XREF_READ, rgn);
				formed = m;
			} else if (in->op == KGENOME_CELL_MOV) {
				uint32_t r = gpr_of(op);
				uint32_t sl;

				if (r < NGPR && reg[r])
					formed = reg[r];
				sl = slot_of(slot, op, 0, next_slot);
				if (sl < NSLOT && slot[sl].va)
					formed = slot[sl].va;
			}
		}
	}
	if (in->op == KGENOME_CELL_LEA) {
		/* LEA's memory operand is an address generation and is
		 * not read, so the loop above never saw it. */
		for (i = 0; i < nops; i++) {
			uint64_t m = mem_va(in, &ops[i]);

			if (m) {
				note(u, m, KGENOME_XREF_READ, rgn);
				formed = m;
			}
		}
	}
	/*
	 * EVERY REGISTER IT WRITES IS FORGOTTEN, the ones it does not
	 * name included - `cltq` has no operand and still replaces rax,
	 * and `mul` fills the one above its operand. The sweep used to
	 * forget only the first written operand it could see, which
	 * kept a stale address in a register the instruction had just
	 * overwritten; MEASURED on /usr/bin/ul, a `movl optind, %eax ;
	 * cltq` left optind's address in rax until the next call and
	 * the call recorded it as an argument. wmask is the decoder's
	 * own answer to "what did this write", so it is read, not
	 * re-derived from the operands.
	 */
	for (wm = in->wmask & (((uint64_t)1 << NGPR) - 1u); wm; wm &= wm - 1u)
		reg[(uint32_t)__builtin_ctzll(wm)] = 0;
	if (dst < NGPR)
		reg[dst] = (in->op == KGENOME_CELL_LEA || in->op == KGENOME_CELL_MOV)
			 ? formed : 0;
	/*
	 * A store of a tracked address into a local. Only for MOV, and
	 * only when something was tracked: a store of anything else
	 * ends what the slot held, for the same reason a register write
	 * does.
	 */
	if (in->op == KGENOME_CELL_MOV)
		for (i = 0; i < nops; i++) {
			const struct kgenome_cell_operand *op = &ops[i];
			uint32_t sl;

			if (!(op->flags & KGENOME_CELL_OF_WRITE))
				continue;
			sl = slot_of(slot, op, formed != 0, next_slot);
			if (sl < NSLOT)
				slot[sl].va = formed;
		}

	/*
	 * A RET ENDS THE REGION. The next instruction starts another,
	 * and it starts knowing nothing: a register or a local from
	 * the function that just returned says nothing about the one
	 * that follows it.
	 */
	if (in->op == KGENOME_CELL_RET) {
		rgn = u->n_rgn < USE_RGN ? u->n_rgn++ : USE_RGN - 1u;
		if (rgn < USE_RGN)
			u->rgn_at[rgn] = rip + len;
		memset(reg, 0, sizeof u->run_reg);
		for (i = 0; i < NSLOT; i++)
			slot[i].base = NGPR;
	}
	u->run_rgn = rgn;
}

/* Insertion sort over the index. n is at most USE_MAX and the array is nearly
 * ordered already - addresses are recorded roughly as the code names them - so
 * this beats anything cleverer at this size. */
static void order_build(struct kgenome_xref *u)
{
	uint32_t i, j;
	uint64_t reach = 0;

	for (i = 0; i < u->n; i++)
		u->order[i] = (uint16_t)i;
	for (i = 1; i < u->n; i++) {
		uint16_t key = u->order[i];

		for (j = i; j && u->va[u->order[j - 1u]] > u->va[key]; j--)
			u->order[j] = u->order[j - 1u];
		u->order[j] = key;
	}
	/*
	 * WHICH REGIONS ARE STARTUP, before anything else uses the answer.
	 *
	 * Each address the caller named lands in the last region that starts at
	 * or before it.
	 */
	for (i = 0; i < u->n_start; i++) {
		uint32_t r, best = USE_RGN;

		for (r = 0; r < u->n_rgn; r++)
			if (u->rgn_at[r] <= u->start_at[i] &&
			    (best == USE_RGN || u->rgn_at[r] > u->rgn_at[best]))
				best = r;
		if (best < USE_RGN)
			u->startup |= (uint64_t)1 << best;
	}

	/*
	 * NOW THAT EVERY REGION IS KNOWN, resolve who calls whom.
	 *
	 * A call target is an address; the region it belongs to is the last
	 * region that starts at or before it. Regions are recorded in sweep
	 * order, which is address order within a run, so this is a walk rather
	 * than a search.
	 */
	for (i = 0; i < u->n_edge; i++) {
		uint32_t r, best = USE_RGN;

		for (r = 0; r < u->n_rgn; r++)
			if (u->rgn_at[r] <= u->edge_to[i] &&
			    (best == USE_RGN || u->rgn_at[r] > u->rgn_at[best]))
				best = r;
		if (best < USE_RGN &&
		    (u->rgn_flag[best] & KGENOME_XREF_RGN_ICALL))
			u->rgn_flag[u->edge_from[i]] |= KGENOME_XREF_RGN_NEAR;
		/*
		 * AND WHAT STARTUP CODE REACHES IS STARTUP TOO, one level.
		 *
		 * register_tm_clones and its siblings are named by nothing:
		 * no symbol, no array, no relocation. They are found by being
		 * what frame_dummy calls, and one level is enough because the
		 * toolchain's helpers do not nest deeper than that.
		 */
		if (best < USE_RGN &&
		    (u->startup & ((uint64_t)1 << u->edge_from[i])))
			reach |= (uint64_t)1 << best;
	}
	u->startup |= reach;
	u->sorted = 1;
}

uint32_t kgenome_xref_in(struct kgenome_xref *u, uint64_t va, uint64_t n)
{
	uint32_t lo = 0, hi, f = 0;

	if (!u || !va)
		return 0;
	if (!u->sorted)
		order_build(u);
	if (n < 1u)
		n = 1u;
	hi = u->n;
	while (lo < hi) {                       /* first entry >= va */
		uint32_t mid = lo + (hi - lo) / 2u;

		if (u->va[u->order[mid]] < va)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (; lo < u->n && u->va[u->order[lo]] < va + n; lo++) {
		uint32_t e = u->order[lo], r;

		f |= u->flag[e];
		/* Anything outside the startup set having mentioned it is the
		 * one fact a rule about a person's program wants first. */
		if (u->rgn[e] & ~u->startup)
			f |= KGENOME_XREF_USER;
		/*
		 * And what the regions that referred to it do. The address
		 * facts are about the variable; these are about the code
		 * around it, and a caller that wants only the first can mask
		 * the rest off.
		 *
		 * Every region that mentioned it, not the first: the map is a
		 * bitmap, and indexing the flag array with it - which is what
		 * this did for one build - reads whatever is at bit position
		 * sixty-something of an array of sixty-four.
		 */
		for (r = 0; r < USE_RGN; r++)
			if (u->rgn[e] & ((uint64_t)1 << r))
				f |= u->rgn_flag[r];
	}
	return f;
}

int kgenome_xref_full(const struct kgenome_xref *u)
{
	return u ? u->full : 0;
}

int kgenome_xref_startup(struct kgenome_xref *u, uint64_t va)
{
	if (!u || u->n_start >= USE_RGN)
		return 0;              /* no room: see the note in xref.h */
	if (va)
		u->start_at[u->n_start++] = va;
	return 1;
}

void kgenome_xref_free(struct kgenome_xref *u)
{
	free(u);
}
