/* SPDX-License-Identifier: Apache-2.0 */
/* One sweep of the code, and what it did with each address. See disasm_xref.h. */

#include "xref.h"

#include <stdlib.h>
#include <string.h>

#include "bddisasm.h"

/*
 * HOW MANY ADDRESSES ONE SWEEP MAY REMEMBER.
 *
 * The caller bounds the code it hands over - the rule that asks refuses an
 * object whose code is over eight kilobytes - so this is a second bound on a
 * different axis: a pathological eight kilobytes is a few thousand
 * instructions, and remembering every distinct address they name would be a
 * table the size of the code. Two hundred and fifty six is far past what the
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
#define NGPR 16u

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
#define NSLOT 8u

struct slot {
	uint32_t base;          /* NGPR when the entry is free */
	int64_t  disp;
	uint64_t va;
};

struct kof_xref {
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
static uint32_t h_find(const struct kof_xref *u, uint64_t va)
{
	uint32_t h = h_of(va);

	while (u->slot[h] && u->va[u->slot[h] - 1u] != va) {
			h = (h + 1u) & (USE_HASH - 1u);
	}
	return h;
}

static void note(struct kof_xref *u, uint64_t va, uint32_t f, uint32_t rgn)
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
static uint32_t gpr_of(const ND_OPERAND *op)
{
	if (op->Type != ND_OP_REG || op->Info.Register.Type != ND_REG_GPR)
		return NGPR;
	return op->Info.Register.Reg < NGPR ? op->Info.Register.Reg : NGPR;
}


/*
 * The stack slot a memory operand names, or NSLOT when it names none this
 * sweep will follow. rbp and rsp only - see the note on NSLOT.
 */
static uint32_t slot_of(struct slot *slot, const ND_OPERAND *op, int make,
			uint32_t *next)
{
	uint32_t i;
	uint32_t base;
	int64_t  disp;

	if (op->Type != ND_OP_MEM || !op->Info.Memory.HasBase ||
	    op->Info.Memory.HasIndex || op->Info.Memory.IsRipRel)
		return NSLOT;
	base = op->Info.Memory.Base;
	if (base != NDR_RBP && base != NDR_RSP)
		return NSLOT;
	disp = op->Info.Memory.HasDisp ? (int64_t)op->Info.Memory.Disp : 0;
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
static uint64_t mem_va(const INSTRUX *ix, const ND_OPERAND *op, uint64_t rip)
{
	if (op->Type != ND_OP_MEM || !op->Info.Memory.HasDisp)
		return 0;
	if (!op->Info.Memory.IsRipRel)
		return 0;
	return rip + ix->Length + op->Info.Memory.Disp;
}

struct kof_xref *kof_xref_new(void)
{
	return calloc(1, sizeof(struct kof_xref));
}

void kof_xref_add(struct kof_xref *u, const uint8_t *code, uint32_t code_n,
		     uint64_t code_va, unsigned bits)
{
	uint64_t reg[NGPR];
	struct slot slot[NSLOT];
	uint32_t at = 0, next_slot = 0, rgn;

	if (!u || !code || !code_n)
		return;
	for (at = 0; at < NSLOT; at++)
		slot[at].base = NGPR;
	at = 0;
	/* A run of code starts a region, and every RET ends one. */
	rgn = u->n_rgn < USE_RGN ? u->n_rgn++ : USE_RGN - 1u;
	/* Each run starts knowing nothing: a register left over from the end of
	 * one section says nothing about the start of the next. */
	memset(reg, 0, sizeof reg);

	while (at < code_n) {
		INSTRUX ix;
		uint32_t i, dst = NGPR;
		uint64_t rip = code_va + at;
		uint64_t formed = 0;

		if (!ND_SUCCESS(NdDecodeEx(&ix, code + at, code_n - at,
					   bits == 32 ? ND_CODE_32 : ND_CODE_64,
					   bits == 32 ? ND_DATA_32 : ND_DATA_64))) {
			/*
			 * One byte on rather than giving up.
			 *
			 * A linear sweep meets data between functions - jump
			 * tables, alignment padding, a literal pool - and that
			 * is not a reason to stop reading the code after it.
			 * Resynchronising costs at most one byte per byte of
			 * data, which the size bound already covers.
			 */
			at++;
			memset(reg, 0, sizeof reg);
			continue;
		}

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
		if (ix.Instruction == ND_INS_CALLNR ||
		    ix.Instruction == ND_INS_JMPNR) {
			uint32_t k = ix.Instruction == ND_INS_CALLNR
				   ? KOF_XREF_CALL : KOF_XREF_JUMP;

			for (i = 0; i < ix.OperandsCount; i++) {
				uint64_t t;

				if (ix.Operands[i].Type != ND_OP_OFFS)
					continue;
				t = rip + ix.Length +
				    ix.Operands[i].Info.RelativeOffset.Rel;
				note(u, t, KOF_XREF_READ | k, rgn);
				/*
				 * AND REMEMBER WHO CALLS WHOM.
				 *
				 * The target is a code address; which region it
				 * lands in is not known until the sweep reaches
				 * it, so the address is kept and resolved after.
				 */
				if (ix.Instruction == ND_INS_CALLNR &&
				    u->n_edge < USE_RGN) {
					u->edge_from[u->n_edge] = (uint8_t)rgn;
					u->edge_to[u->n_edge] = t;
					u->n_edge++;
				}
			}
		}
		if (ix.Instruction == ND_INS_CALLNI)
			u->rgn_flag[rgn] |= KOF_XREF_RGN_ICALL;
		if (ix.Instruction == ND_INS_CALLNI ||
		    ix.Instruction == ND_INS_JMPNI) {
			uint32_t k = ix.Instruction == ND_INS_CALLNI
				   ? KOF_XREF_CALL : KOF_XREF_JUMP;

			for (i = 0; i < ix.OperandsCount; i++) {
				const ND_OPERAND *op = &ix.Operands[i];
				uint32_t r = gpr_of(op);
				uint64_t m;

				if (r < NGPR && reg[r])
					note(u, reg[r], KOF_XREF_READ | k, rgn);
				/* call [rip+d] - the pointer is named by the
				 * instruction itself, no register involved. */
				m = mem_va(&ix, op, rip);
				if (m)
					note(u, m, KOF_XREF_READ | k, rgn);
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
		if (ix.Instruction == ND_INS_CALLNR ||
		    ix.Instruction == ND_INS_CALLNI) {
			uint32_t r;

			for (r = 0; r < NGPR; r++)
				if (reg[r])
					note(u, reg[r],
					     KOF_XREF_READ | KOF_XREF_ARG, rgn);
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
		for (i = 0; i < ix.OperandsCount; i++) {
			const ND_OPERAND *op = &ix.Operands[i];
			uint64_t m;

			if (op->Access.Write) {
				uint32_t r = gpr_of(op);
				uint64_t w = mem_va(&ix, op, rip);

				if (r < NGPR && dst == NGPR)
					dst = r;
				if (w)
					note(u, w, KOF_XREF_WRITE, rgn);
			}
			if (op->Access.Read) {
				m = mem_va(&ix, op, rip);
				if (m) {
					note(u, m, KOF_XREF_READ, rgn);
					formed = m;
				} else if (ix.Instruction == ND_INS_MOV) {
					uint32_t r = gpr_of(op);
					uint32_t sl;

					if (r < NGPR && reg[r])
						formed = reg[r];
					sl = slot_of(slot, op, 0, &next_slot);
					if (sl < NSLOT && slot[sl].va)
						formed = slot[sl].va;
				}
			}
		}
		if (ix.Instruction == ND_INS_LEA) {
			/* LEA's memory operand is an address generation and is
			 * not read, so the loop above never saw it. */
			for (i = 0; i < ix.OperandsCount; i++) {
				uint64_t m = mem_va(&ix, &ix.Operands[i], rip);

				if (m) {
					note(u, m, KOF_XREF_READ, rgn);
					formed = m;
				}
			}
		}
		if (dst < NGPR)
			reg[dst] = (ix.Instruction == ND_INS_LEA ||
				    ix.Instruction == ND_INS_MOV) ? formed : 0;
		/*
		 * A store of a tracked address into a local. Only for MOV, and
		 * only when something was tracked: a store of anything else
		 * ends what the slot held, for the same reason a register write
		 * does.
		 */
		if (ix.Instruction == ND_INS_MOV)
			for (i = 0; i < ix.OperandsCount; i++) {
				const ND_OPERAND *op = &ix.Operands[i];
				uint32_t sl;

				if (!op->Access.Write)
					continue;
				sl = slot_of(slot, op, formed != 0, &next_slot);
				if (sl < NSLOT)
					slot[sl].va = formed;
			}

		/*
		 * A RET ENDS THE REGION. The next instruction starts another,
		 * and it starts knowing nothing: a register or a local from
		 * the function that just returned says nothing about the one
		 * that follows it.
		 */
		if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_RETF) {
			rgn = u->n_rgn < USE_RGN ? u->n_rgn++ : USE_RGN - 1u;
			if (rgn < USE_RGN)
				u->rgn_at[rgn] = rip + ix.Length;
			memset(reg, 0, sizeof reg);
			for (i = 0; i < NSLOT; i++)
				slot[i].base = NGPR;
		}
		at += ix.Length;
	}
}

/* Insertion sort over the index. n is at most USE_MAX and the array is nearly
 * ordered already - addresses are recorded roughly as the code names them - so
 * this beats anything cleverer at this size. */
static void order_build(struct kof_xref *u)
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
		    (u->rgn_flag[best] & KOF_XREF_RGN_ICALL))
			u->rgn_flag[u->edge_from[i]] |= KOF_XREF_RGN_NEAR;
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

uint32_t kof_xref_in(struct kof_xref *u, uint64_t va, uint64_t n)
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
			f |= KOF_XREF_USER;
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

int kof_xref_full(const struct kof_xref *u)
{
	return u ? u->full : 0;
}

void kof_xref_startup(struct kof_xref *u, uint64_t va)
{
	if (u && va && u->n_start < USE_RGN)
		u->start_at[u->n_start++] = va;
}

void kof_xref_free(struct kof_xref *u)
{
	free(u);
}
