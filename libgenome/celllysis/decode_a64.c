/*
 * a64.c - AArch64 (ARMv8-A, the A64 instruction set) into the engine's one
 * instruction form.
 *
 * WRITTEN FROM THE ENCODING STRUCTURE, NOT FROM ANOTHER DECODER. A64 is a
 * fixed four-byte word and its top level is bits 28..25, so the first step is
 * one index into a sixteen-entry table of group handlers - the same method
 * decode_mips.c uses for its primary opcode. Each group then splits on the
 * few bit-fields the architecture reference gives it, and every instruction
 * is decided by masks on the word, never by comparing strings or walking a
 * list of cases. A reference decoder was used only as an ORACLE, offline, by
 * tools/celllysis/a64_diff.c, to find where this one disagrees; none of its
 * code or tables is here.
 *
 * WHAT IS DECIDED AND WHAT IS NOT. The groups the sweep reads - data
 * processing (immediate and register), branches and system, loads and stores
 * - are decoded completely: validity, class, operands, written registers.
 * Scalar floating point, Advanced SIMD, SVE and SME are a different matter:
 * their length is always four and they are CELL_OTHER, and what is decided is
 * the one thing the sweep asks of them, which general registers they write
 * (fmov x0,d0; fcvtzs x0,d0; umov; smov; the SVE element counts, ...).
 * Whether a particular word in those spaces is allocated is NOT decided - see
 * g_simd.
 *
 * UNALLOCATED WORDS are CELL_UD with nothing written. CELL_UD is also the
 * class of `udf` itself: both are "defined to fault", and a walk that meets
 * either has left the code. A caller that must tell them apart reads the
 * word: udf is exactly the words whose top sixteen bits are zero.
 *
 * REGISTERS. x0..x30 are 0..30 and sp is 31 (wmask bit 31). xzr/wzr have no
 * number: a destination that is the zero register writes nothing (no wmask
 * bit) and a source that is the zero register is emitted as CELL_O_IMM 0, so
 * the constant map sees the zero instead of a register it cannot know. A w
 * register is size 4 (its write zero-extends, as on x86-64), an x register
 * size 8. Which register 31 means is decided per operand slot by the
 * architecture (sp for an address base and for add/sub/logical-immediate
 * destinations, zero everywhere else); this file follows it slot by slot.
 *
 * OPERAND FORMS (documented here once, referred to below).
 *
 *   Two-operand ALU, the form the constant map computes:  when the first
 *   source is also the destination, `add x0,x0,#4` is  o[0]=x0 (W|R)  o[1]=#4.
 *   When it is not, `add x0,x1,#4` is  o[0]=x0 (W)  o[1]=x1  o[2]=#4 - the
 *   architecture's three-operand form, which the map does not read (it takes
 *   o[1] as the second source for every class), so a consumer must handle
 *   n_op==3 itself. Adding an operand the map ignores would be a silent
 *   wrong answer; the alternative of folding it into two operands cannot be
 *   written.
 *   A second source that carries a shift or an extension the form cannot name
 *   (`add x0,x1,x2,lsl #3`, `add x0,x1,w2,uxtw`) makes the instruction
 *   CELL_OTHER: its class would otherwise promise an arithmetic the operands
 *   do not state. Same for bic/orn/eon (no class), cmn, ccmp and every
 *   conditional select.
 *   Load:   CELL_MOV  o[0]=Rt (W)  o[1]=MEM.  Store: CELL_MOV  o[0]=MEM (W)
 *   o[1]=source reg or #0.  MEM: reg=base (31=sp), index/scale for a register
 *   offset (an uxtw/sxtw extension of the index is not carried), disp, size =
 *   bytes accessed.  A post-index access is [base] with disp 0 and the
 *   increment in o[2] (single-register forms only; a pair has no free slot);
 *   a pre-index access carries the increment as disp.
 *   Literal load: MEM with CELL_OF_RIPREL and reg CELL_REG_NONE. DISP IS
 *   RELATIVE TO THE ADDRESS OF THE INSTRUCTION ITSELF (at_va), not to the
 *   next one: literal address = at_va + disp. That is how A64 defines PC and
 *   differs from the x86 rip-relative convention, so a consumer must not add
 *   len.
 *   Branches: o[0] is always CELL_O_REL and the target is in target_va (the
 *   engine resolves `target`). cbz/cbnz add o[1]=the tested register, tbz/
 *   tbnz add o[1]=the register and o[2]=the bit number. `cond` carries the
 *   standard A64 condition code for b.cond (0=eq .. 14=al, 15=nv) and, so
 *   that a consumer can tell the two apart, 0 (eq) for cbz/tbz and 1 (ne) for
 *   cbnz/tbnz, which is the condition they branch on.
 *
 * CHEAP DECISIONS MADE ONCE: a word whose "should be zero/one" bits are not
 * what the architecture asks (SBZ/SBO) is decoded as the instruction, not
 * rejected - the CPU treats it as constrained-unpredictable, and the
 * consequence of being wrong the other way is losing a real instruction.
 */
#include <string.h>

/* KOF_BROKEN - the sentinel cell.h names for a target there is not. */
#include "kofmod/cell.h"
#include "decode.h"

#define NOREG CELL_REG_NONE

/* ---- small helpers ------------------------------------------------------ */

static inline int64_t sx(uint32_t v, unsigned bits)
{
	uint32_t m = 1u << (bits - 1u);

	return (int64_t)(v ^ m) - (int64_t)m;
}

static inline uint64_t szmask(unsigned sz)
{
	return sz == 4u ? 0xffffffffull : ~0ull;
}

/* A register this instruction writes. 31 is the zero register: nothing. */
static inline void wr_zr(struct cell_insn *o, unsigned r)
{
	if (r != 31u)
		o->wmask |= 1ull << r;
}

/* A register that is sp when it is 31 (an address base, add/sub destination). */
static inline void wr_sp(struct cell_insn *o, unsigned r)
{
	o->wmask |= 1ull << r;
}

/* A fresh operand: nothing set, and no register, index or segment named. */
static void o_clr(struct cell_operand *p)
{
	memset(p, 0, sizeof *p);
	p->reg = p->index = p->seg = NOREG;
}

static void o_reg(struct cell_operand *p, unsigned r, unsigned sz, unsigned fl)
{
	o_clr(p);
	p->kind = CELL_O_REG;
	p->reg = (uint8_t)r;
	p->size = (uint8_t)sz;
	p->flags = (uint8_t)fl;
}

static void o_imm(struct cell_operand *p, uint64_t v, unsigned sz)
{
	o_clr(p);
	p->kind = CELL_O_IMM;
	p->imm = v;
	p->size = (uint8_t)sz;
}

/*
 * A DESTINATION THAT IS THE ZERO REGISTER: written, and gone. It is a register
 * operand with no register (CELL_REG_NONE), not an immediate, so a consumer that
 * clears the destination it names clears nothing and one that reads o[0].reg as
 * an index finds the "no register" value it already tests for.
 */
static void o_dead(struct cell_operand *p, unsigned sz)
{
	o_clr(p);
	p->kind = CELL_O_REG;
	p->size = (uint8_t)sz;
	p->flags = CELL_OF_WRITE;
}

/* A source where 31 is the zero register: that is a constant, not a register. */
static void o_zr(struct cell_operand *p, unsigned r, unsigned sz)
{
	if (r == 31u)
		o_imm(p, 0, sz);
	else
		o_reg(p, r, sz, CELL_OF_READ);
}

/* A source where 31 is sp. */
static void o_sp(struct cell_operand *p, unsigned r, unsigned sz)
{
	o_reg(p, r, sz, CELL_OF_READ);
}

static void o_mem(struct cell_operand *p, unsigned base, int64_t disp,
		  unsigned acc, unsigned fl)
{
	o_clr(p);
	p->kind = CELL_O_MEM;
	p->reg = (uint8_t)base;
	p->scale = 1u;
	p->size = (uint8_t)acc;
	p->flags = (uint8_t)fl;
	p->disp = disp;
}

static void o_rel(struct cell_insn *o, uint64_t tgt)
{
	o_clr(&o->o[0]);
	o->target_va = tgt;
	o->target = tgt;
	o->o[0].kind = CELL_O_REL;
}

/* Unallocated: defined to fault, writes nothing. */
static void ud(struct cell_insn *o)
{
	memset(o->o, 0, sizeof o->o);
	{
		unsigned i;

		for (i = 0; i < 3u; i++)
			o->o[i].reg = o->o[i].index = o->o[i].seg = NOREG;
	}
	o->op = CELL_UD;
	o->n_op = 0;
	o->cond = 0;
	o->flags = 0;
	o->wmask = 0;
	o->target = o->target_va = KOF_BROKEN;
}

/* A write to the zero register that does nothing else. */
static void nop(struct cell_insn *o)
{
	o->op = CELL_NOP;
	o->n_op = 0;
	o->wmask = 0;
}

/* Something decoded and not one of the classes; o[0] is its one register. */
static void other_rd(struct cell_insn *o, unsigned rd, unsigned sz, int sp)
{
	o->op = CELL_OTHER;
	if (sp || rd != 31u) {
		wr_sp(o, rd);
		o->n_op = 1u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
	}
}

/*
 * dst = a OP b, in the forms the header comment describes. `a` and `b` are
 * already operands (a register, or CELL_O_IMM 0 for the zero register, or a
 * real immediate). `sp_dst` says register 31 as a destination is sp.
 */
static void emit_bin(struct cell_insn *o, unsigned cls, unsigned sz,
		     unsigned rd, int sp_dst,
		     const struct cell_operand *a, const struct cell_operand *b)
{
	o->op = (uint8_t)cls;
	if (!sp_dst && rd == 31u) {
		nop(o);
		return;
	}
	wr_sp(o, rd);
	if (a->kind == CELL_O_IMM && a->imm == 0 &&
	    (cls == CELL_ADD || cls == CELL_OR || cls == CELL_XOR ||
	     cls == CELL_AND || cls == CELL_SUB)) {
		/* The zero register as first source: the instruction is a
		 * move, a negation, or a constant. */
		o->n_op = 2u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
		if (cls == CELL_AND) {
			o->op = CELL_MOV;
			o_imm(&o->o[1], 0, sz);
		} else if (cls != CELL_SUB) {
			o->op = CELL_MOV;
			o->o[1] = *b;
		} else if (b->kind == CELL_O_IMM) {
			o->op = CELL_MOV;
			o_imm(&o->o[1], (0ull - b->imm) & szmask(sz), sz);
		} else if (b->reg == rd) {
			o->op = CELL_NEG;
			o->n_op = 1u;
			o->o[0].flags = CELL_OF_WRITE | CELL_OF_READ;
		} else {
			o->op = CELL_OTHER;
			o->n_op = 1u;
		}
		return;
	}
	if (a->kind == CELL_O_REG && a->reg == rd) {
		o->n_op = 2u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE | CELL_OF_READ);
		o->o[1] = *b;
	} else {
		o->n_op = 3u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
		o->o[1] = *a;
		o->o[2] = *b;
	}
}

/* ---- the logical-immediate decoder --------------------------------------- */

/*
 * The bitmask an N:immr:imms triple names: a run of S+1 ones, rotated right by
 * R inside an element of 2^len bits, replicated to the register width.
 * Returns 0 for the triples the architecture leaves unallocated (an all-ones
 * run, or an element wider than the register).
 */
static int bitmask_imm(unsigned n, unsigned imms, unsigned immr, unsigned dsz,
		       uint64_t *out)
{
	unsigned v = (n << 6) | (~imms & 63u);
	unsigned len = 0, esize, levels, s, r, e;
	uint64_t w, emask;

	if (v < 2u)
		return 0;
	while (v >> (len + 1u))
		len++;
	esize = 1u << len;
	if (esize > dsz)
		return 0;
	levels = esize - 1u;
	if ((imms & levels) == levels)
		return 0;
	s = imms & levels;
	r = immr & levels;
	emask = esize == 64u ? ~0ull : (1ull << esize) - 1u;
	w = (1ull << (s + 1u)) - 1u;
	if (r)
		w = ((w >> r) | (w << (esize - r))) & emask;
	for (e = esize; e < dsz; e <<= 1)
		w |= w << e;
	*out = w;
	return 1;
}

/* ---- data processing: immediate ----------------------------------------- */

static void g_dpimm(struct cell_insn *o, uint32_t x, uint64_t va)
{
	unsigned sf = x >> 31, sz = sf ? 8u : 4u;
	unsigned rd = x & 31u, rn = (x >> 5) & 31u;

	switch ((x >> 23) & 7u) {
	case 0:
	case 1: {                               /* adr, adrp */
		uint64_t imm = (((x >> 5) & 0x7ffffu) << 2) | ((x >> 29) & 3u);
		int64_t d = sx((uint32_t)imm, 21);
		uint64_t a;

		if (sf)
			a = (va & ~0xfffull) + (uint64_t)(d * 4096);
		else
			a = va + (uint64_t)d;
		o->op = CELL_LEA;
		if (rd == 31u) {
			nop(o);
			break;
		}
		wr_zr(o, rd);
		o->n_op = 2u;
		o_reg(&o->o[0], rd, 8u, CELL_OF_WRITE);
		o_imm(&o->o[1], a, 8u);
		break;
	}
	case 2: {                               /* add/sub immediate */
		unsigned op = (x >> 30) & 1u, s = (x >> 29) & 1u;
		uint64_t imm = (uint64_t)((x >> 10) & 0xfffu);
		struct cell_operand a, b;

		if ((x >> 22) & 1u)
			imm <<= 12;
		o_sp(&a, rn, sz);
		o_imm(&b, imm, sz);
		if (s && rd == 31u) {           /* cmp / cmn */
			o->op = op ? CELL_CMP : CELL_OTHER;
			if (op) {
				o->n_op = 2u;
				o->o[0] = a;
				o->o[1] = b;
			}
			break;
		}
		if (!op && !s && imm == 0) {
			/* add xd,xn,#0 is a move (sp is where the assembler
			 * spells it so); a move is the form the map copies. */
			o->op = CELL_MOV;
			wr_sp(o, rd);
			o->n_op = 2u;
			o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
			o->o[1] = a;
			break;
		}
		emit_bin(o, op ? CELL_SUB : CELL_ADD, sz, rd, !s, &a, &b);
		break;
	}
	case 3: {
		/* add/sub with tags (addg, subg), and min/max immediate */
		if ((x >> 22) & 1u) {
			/* smax/umax/smin/umin: sf op S must be 0 0 0 and opc
			 * 21:18 below 4 */
			if ((x >> 29) != (sf << 2) || ((x >> 18) & 15u) > 3u) {
				ud(o);
				break;
			}
			other_rd(o, rd, sz, 0);
			break;
		}
		if (sf != 1u || ((x >> 29) & 1u) || ((x >> 14) & 3u)) {
			ud(o);
			break;
		}
		other_rd(o, rd, 8u, 1);
		break;
	}
	case 4: {                               /* logical immediate */
		unsigned opc = (x >> 29) & 3u, nn = (x >> 22) & 1u;
		uint64_t m;
		struct cell_operand a, b;

		if ((!sf && nn) ||
		    !bitmask_imm(nn, (x >> 10) & 63u, (x >> 16) & 63u,
				 sf ? 64u : 32u, &m)) {
			ud(o);
			break;
		}
		o_zr(&a, rn, sz);
		o_imm(&b, m, sz);
		if (opc == 3u) {                /* ands / tst */
			if (rd == 31u) {
				o->op = CELL_TEST;
				o->n_op = 2u;
				o->o[0] = a;
				o->o[1] = b;
				break;
			}
			emit_bin(o, CELL_AND, sz, rd, 0, &a, &b);
			break;
		}
		emit_bin(o, opc == 0 ? CELL_AND : opc == 1u ? CELL_OR : CELL_XOR,
			 sz, rd, 1, &a, &b);
		break;
	}
	case 5: {                               /* move wide */
		unsigned opc = (x >> 29) & 3u, hw = (x >> 21) & 3u;
		uint64_t imm = (uint64_t)((x >> 5) & 0xffffu) << (hw * 16u);

		if (opc == 1u || (!sf && hw > 1u)) {
			ud(o);
			break;
		}
		if (opc == 3u) {
			/*
			 * movk replaces sixteen bits and keeps the rest. No
			 * class carries that, so it is CELL_OTHER with the
			 * facts a consumer needs to fold it itself:
			 * o[1]=the bits to OR in, o[2]=the mask they replace
			 * - new = (old & ~o[2]) | o[1]. MEASURED not to fit
			 * the constant map: it has one source operand.
			 */
			o->op = CELL_OTHER;
			if (rd == 31u)
				break;
			wr_zr(o, rd);
			o->n_op = 3u;
			o_reg(&o->o[0], rd, sz, CELL_OF_WRITE | CELL_OF_READ);
			o_imm(&o->o[1], imm, sz);
			o_imm(&o->o[2], 0xffffull << (hw * 16u), sz);
			break;
		}
		if (opc == 0)
			imm = ~imm & szmask(sz);
		if (rd == 31u) {
			nop(o);
			break;
		}
		o->op = CELL_MOV;
		wr_zr(o, rd);
		o->n_op = 2u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
		o_imm(&o->o[1], imm, sz);
		break;
	}
	case 6: {                               /* bitfield */
		unsigned opc = (x >> 29) & 3u, nn = (x >> 22) & 1u;
		unsigned immr = (x >> 16) & 63u, imms = (x >> 10) & 63u;
		unsigned top = sf ? 63u : 31u;
		struct cell_operand a, b;

		if (opc == 3u || nn != sf || (!sf && ((immr | imms) & 32u))) {
			ud(o);
			break;
		}
		if (rd == 31u) {
			o->op = CELL_OTHER;
			break;
		}
		o_zr(&a, rn, sz);
		if (opc == 1u) {                /* bfm: bfi, bfxil, bfc */
			other_rd(o, rd, sz, 0);
			break;
		}
		if (opc == 2u && imms == top) { /* lsr */
			o_imm(&b, immr, sz);
			emit_bin(o, CELL_SHR, sz, rd, 0, &a, &b);
		} else if (opc == 0 && imms == top) {   /* asr */
			o_imm(&b, immr, sz);
			emit_bin(o, CELL_SAR, sz, rd, 0, &a, &b);
		} else if (opc == 2u && imms != top && imms + 1u == immr) {
			o_imm(&b, top - imms, sz);      /* lsl */
			emit_bin(o, CELL_SHL, sz, rd, 0, &a, &b);
		} else if (immr == 0 && (imms == 7u || imms == 15u ||
					 (opc == 0 && sf && imms == 31u)) &&
			   (opc == 0 || !sf)) {
			/* uxtb/uxth (32-bit only) and sxtb/sxth/sxtw. A zero
			 * register source makes it the constant 0, which
			 * nothing needs a class for. */
			o->op = opc == 0 ? CELL_MOVSX : CELL_MOVZX;
			wr_zr(o, rd);
			o->n_op = 2u;
			o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
			o->o[1] = a;
			o->o[1].size = (uint8_t)(imms == 7u ? 1u : imms == 15u
						 ? 2u : 4u);
		} else {
			other_rd(o, rd, sz, 0);
		}
		if (o->op != CELL_OTHER && o->op != CELL_NOP && o->n_op == 2u &&
		    o->o[1].kind == CELL_O_IMM && a.kind == CELL_O_IMM &&
		    (o->op == CELL_SHL || o->op == CELL_SHR ||
		     o->op == CELL_SAR)) {
			/* A shift of the zero register is the constant 0. */
			o->op = CELL_MOV;
			o_imm(&o->o[1], 0, sz);
		}
		break;
	}
	default: {                              /* extract: extr, ror */
		unsigned n7 = (x >> 22) & 1u, imms = (x >> 10) & 63u;
		unsigned rm = (x >> 16) & 31u;

		if (((x >> 29) & 3u) || ((x >> 21) & 1u) || n7 != sf ||
		    (!sf && (imms & 32u))) {
			ud(o);
			break;
		}
		if (rn == rm && rn != 31u && rd != 31u) {       /* ror #imm */
			struct cell_operand a, b;

			o_reg(&a, rn, sz, CELL_OF_READ);
			o_imm(&b, imms, sz);
			emit_bin(o, CELL_ROR, sz, rd, 0, &a, &b);
		} else {
			other_rd(o, rd, sz, 0);
		}
		break;
	}
	}
}

/* ---- branches, exception generation, system ------------------------------ */

/* Which hints change a register: PAC/AUT in lr or x17, XPACLRI, CHKFEAT. */
static uint64_t hint_wmask(unsigned h)
{
	switch (h) {
	case 7u:                                /* xpaclri */
	case 24u: case 25u: case 26u: case 27u: /* paciaz paciasp pacibz pacibsp */
	case 28u: case 29u: case 30u: case 31u: /* autiaz autiasp autibz autibsp */
		return 1ull << 30;
	case 8u: case 10u: case 12u: case 14u:  /* pac/aut ia/ib 1716 */
		return 1ull << 17;
	case 40u:                               /* chkfeat x16 */
		return 1ull << 16;
	default:
		return 0;
	}
}

static void g_system(struct cell_insn *o, uint32_t x)
{
	unsigned rt = x & 31u, l = (x >> 21) & 1u, op0 = (x >> 19) & 3u;
	unsigned crn = (x >> 12) & 15u, crm = (x >> 8) & 15u;
	unsigned op1 = (x >> 16) & 7u, op2 = (x >> 5) & 7u;

	if (op0 >= 2u) {                        /* msr/mrs, system register */
		unsigned reg = (x >> 5) & 0x7fffu;

		o->op = CELL_PRIV;
		o->n_op = 2u;
		if (l) {                        /* mrs */
			o_reg(&o->o[0], rt, 8u, CELL_OF_WRITE);
			o_imm(&o->o[1], reg, 4u);
			wr_zr(o, rt);
			if (rt == 31u)
				o_dead(&o->o[0], 8u);
		} else {                        /* msr */
			o_imm(&o->o[0], reg, 4u);
			o_zr(&o->o[1], rt, 8u);
		}
		return;
	}
	if (op0 == 1u) {                        /* sys, sysl: dc ic tlbi at */
		o->op = CELL_OTHER;
		if (l)
			wr_zr(o, rt);
		return;
	}
	if (l) {
		/* tstart, ttest (FEAT_TME): the result goes to Rt */
		if (op0 == 0 && op1 == 3u && crn == 3u && op2 == 3u && crm < 2u) {
			o->op = CELL_OTHER;
			wr_zr(o, rt);
			return;
		}
		ud(o);
		return;
	}
	if (crn == 3u && op1 == 3u && op2 == 3u && crm == 0 && rt == 31u) {
		o->op = CELL_OTHER;             /* tcommit */
		return;
	}
	if (crn == 2u && op1 == 3u && rt == 31u) {      /* hint #crm:op2 */
		unsigned h = (crm << 3) | op2;

		o->wmask = hint_wmask(h);
		o->op = o->wmask ? CELL_OTHER : CELL_NOP;
		return;
	}
	if (crn == 3u && rt == 31u &&
	    (op2 == 2u || op2 == 4u || op2 == 5u || op2 == 6u || op2 == 7u ||
	     (op2 == 1u && (crm & 3u) == 2u))) {
		o->op = CELL_OTHER;             /* clrex, dsb, dmb, isb, sb */
		return;
	}
	if (crn == 4u && rt == 31u) {           /* msr pstate-field, #imm */
		o->op = CELL_PRIV;
		return;
	}
	if (crn == 1u && crm == 0 && op1 == 3u && op2 < 2u) {
		o->op = CELL_NOP;               /* wfet, wfit */
		return;
	}
	ud(o);
}

static void g_branch(struct cell_insn *o, uint32_t x, uint64_t va)
{
	unsigned sf = x >> 31;

	if ((x & 0x7c000000u) == 0x14000000u) {         /* b, bl */
		o->op = sf ? CELL_CALL : CELL_JMP;
		o->n_op = 1u;
		o_rel(o, va + (uint64_t)(sx(x & 0x3ffffffu, 26) * 4));
		if (sf)
			o->wmask |= 1ull << 30;
	} else if ((x & 0x7e000000u) == 0x34000000u) {  /* cbz, cbnz */
		unsigned rt = x & 31u;

		o->op = CELL_JCC;
		o->cond = (uint8_t)((x >> 24) & 1u);
		o->n_op = 2u;
		o_rel(o, va + (uint64_t)(sx((x >> 5) & 0x7ffffu, 19) * 4));
		o_zr(&o->o[1], rt, sf ? 8u : 4u);
	} else if ((x & 0x7e000000u) == 0x36000000u) {  /* tbz, tbnz */
		unsigned rt = x & 31u;

		o->op = CELL_JCC;
		o->cond = (uint8_t)((x >> 24) & 1u);
		o->n_op = 3u;
		o_rel(o, va + (uint64_t)(sx((x >> 5) & 0x3fffu, 14) * 4));
		o_zr(&o->o[1], rt, (x >> 31) ? 8u : 4u);
		o_imm(&o->o[2], ((x >> 26) & 32u) | ((x >> 19) & 31u), 1u);
	} else if ((x & 0xff000000u) == 0x54000000u) {  /* b.cond, bc.cond */
		o->op = CELL_JCC;
		o->cond = (uint8_t)(x & 15u);
		o->n_op = 1u;
		o_rel(o, va + (uint64_t)(sx((x >> 5) & 0x7ffffu, 19) * 4));
	} else if ((x & 0xff000000u) == 0xd4000000u) {  /* exception generation */
		unsigned opc = (x >> 21) & 7u, op2 = (x >> 2) & 7u;
		unsigned ll = x & 3u, imm = (x >> 5) & 0xffffu;

		if (op2) {
			ud(o);
			return;
		}
		if (opc == 0 && ll >= 1u)
			o->op = ll == 1u ? CELL_SYSCALL : CELL_PRIV; /* svc hvc smc */
		else if (opc == 1u && ll == 0)
			o->op = CELL_INT;                       /* brk */
		else if (opc == 2u && ll == 0)
			o->op = CELL_INT;                       /* hlt */
		else if (opc == 5u && ll >= 1u)
			o->op = CELL_PRIV;                      /* dcps1..3 */
		else if (opc == 3u && ll == 0)
			o->op = CELL_OTHER;                     /* tcancel */
		else {
			ud(o);
			return;
		}
		o->n_op = 1u;
		o_imm(&o->o[0], imm, 2u);
	} else if ((x & 0xffc00000u) == 0xd5000000u) {  /* system */
		g_system(o, x);
	} else if ((x & 0xfe000000u) == 0xd6000000u) {  /* branch register */
		unsigned opc = (x >> 21) & 15u, op2 = (x >> 16) & 31u;
		unsigned op3 = (x >> 10) & 63u, rn = (x >> 5) & 31u;
		unsigned op4 = x & 31u;
		unsigned cls = 0, ind = 1, reg = rn;

		if (op2 != 31u) {
			ud(o);
			return;
		}
		if (op3 == 0) {
			if (op4 || opc > 5u || opc == 3u) {
				ud(o);
				return;
			}
			cls = opc == 0 ? CELL_JMP : opc == 1u ? CELL_CALL :
			      opc == 2u ? CELL_RET : CELL_IRET;
			if (opc >= 4u) {
				if (rn != 31u) {
					ud(o);
					return;
				}
				ind = 0;
				if (opc == 5u)
					cls = CELL_PRIV;        /* drps */
			}
		} else if (op3 == 2u || op3 == 3u) {
			/* the pointer-authenticating forms; Rm sits in op4 for
			 * the non-Z variants and is not a destination */
			if (opc == 0 || opc == 1u) {
				if (op4 != 31u) {
					ud(o);
					return;
				}
				cls = opc ? CELL_CALL : CELL_JMP;
			} else if (opc == 8u || opc == 9u) {
				cls = opc == 9u ? CELL_CALL : CELL_JMP;
			} else if ((opc == 2u || opc == 4u) && rn == 31u &&
				   op4 == 31u) {
				cls = opc == 2u ? CELL_RET : CELL_IRET;
				if (opc == 4u)
					ind = 0;
				else
					reg = 30u;
			} else {
				ud(o);
				return;
			}
		} else {
			ud(o);
			return;
		}
		o->op = (uint8_t)cls;
		if (cls == CELL_IRET || cls == CELL_PRIV)
			return;
		o->flags = ind ? CELL_F_INDIRECT : 0;
		o->n_op = 1u;
		o_reg(&o->o[0], reg, 8u, CELL_OF_READ);
		if (reg == 31u)
			o_imm(&o->o[0], 0, 8u);
		if (cls == CELL_CALL)
			o->wmask |= 1ull << 30;
	} else {
		ud(o);
	}
}

/* ---- loads and stores --------------------------------------------------- */

enum { LK_ST, LK_LD, LK_PF, LK_VST, LK_VLD };

struct lsk {
	uint8_t acc;            /* bytes accessed */
	uint8_t dsz;            /* destination register size, 4 or 8 */
	uint8_t kind;           /* LK_* */
};

/* What (size, opc, V) names in the single-register forms. 0 = unallocated. */
static int ls_kind(unsigned size, unsigned opc, unsigned v, int allow_pf,
		   struct lsk *k)
{
	k->acc = (uint8_t)(1u << size);
	k->dsz = size == 3u ? 8u : 4u;
	if (v) {
		if (size == 0 && opc >= 2u) {
			k->acc = 16u;
			k->kind = opc == 2u ? LK_VST : LK_VLD;
			return 1;
		}
		if (opc >= 2u)
			return 0;
		k->kind = opc ? LK_VLD : LK_VST;
		return 1;
	}
	switch (opc) {
	case 0:
		k->kind = LK_ST;
		return 1;
	case 1:
		k->kind = LK_LD;
		return 1;
	case 2:
		if (size < 2u) {                /* ldrsb, ldrsh into x */
			k->kind = LK_LD;
			k->dsz = 8u;
			return 1;
		}
		if (size == 2u) {               /* ldrsw */
			k->kind = LK_LD;
			k->dsz = 8u;
			return 1;
		}
		if (!allow_pf)
			return 0;
		k->kind = LK_PF;
		return 1;
	default:
		if (size >= 2u)
			return 0;
		k->kind = LK_LD;                /* ldrsb, ldrsh into w */
		k->dsz = 4u;
		return 1;
	}
}

/* Emit one single-register access. `wb` is the written base, or 32 for none. */
static void ls_emit(struct cell_insn *o, const struct lsk *k, unsigned rt,
		    const struct cell_operand *m, unsigned wb, int has_inc,
		    int64_t inc)
{
	switch (k->kind) {
	case LK_LD:
		if (rt == 31u) {
			o->op = CELL_OTHER;
			o->n_op = 1u;
			o->o[0] = *m;
			break;
		}
		o->op = CELL_MOV;
		o->n_op = 2u;
		wr_zr(o, rt);
		o_reg(&o->o[0], rt, k->dsz, CELL_OF_WRITE);
		o->o[1] = *m;
		o->o[1].flags |= CELL_OF_READ;
		break;
	case LK_ST:
		o->op = CELL_MOV;
		o->n_op = 2u;
		o->o[0] = *m;
		o->o[0].flags |= CELL_OF_WRITE;
		o_zr(&o->o[1], rt, k->dsz);
		break;
	default:
		o->op = CELL_OTHER;
		o->n_op = 1u;
		o->o[0] = *m;
		o->o[0].flags |= k->kind == LK_VST ? CELL_OF_WRITE : CELL_OF_READ;
		break;
	}
	if (wb < 32u)
		wr_sp(o, wb);
	if (has_inc && o->n_op == 2u) {
		o_imm(&o->o[2], (uint64_t)inc, 8u);
		o->n_op = 3u;
	}
}

static void ls_pair(struct cell_insn *o, uint32_t x)
{
	unsigned opc = x >> 30, v = (x >> 26) & 1u, mode = (x >> 23) & 3u;
	unsigned l = (x >> 22) & 1u, rt2 = (x >> 10) & 31u;
	unsigned rn = (x >> 5) & 31u, rt = x & 31u;
	unsigned scale, dsz = 4u, acc;
	int64_t disp = sx((x >> 15) & 0x7fu, 7);
	struct cell_operand m;

	if (opc == 3u || (v == 0 && opc == 1u && mode == 0)) {
		ud(o);
		return;
	}
	if (v) {
		scale = 4u << opc;
		acc = scale;
	} else if (opc == 1u) {
		scale = l ? 4u : 16u;           /* ldpsw, stgp */
		acc = l ? 4u : 16u;
		dsz = 8u;
	} else {
		scale = opc ? 8u : 4u;
		acc = scale;
		dsz = opc ? 8u : 4u;
	}
	disp *= (int64_t)scale;
	if (mode == 1u)
		disp = 0;               /* post-index: the access is [base] */
	o_mem(&m, rn, disp, acc * 2u, l ? CELL_OF_READ : CELL_OF_WRITE);
	o->op = CELL_OTHER;
	if (mode == 1u || mode == 3u)
		wr_sp(o, rn);
	if (v) {
		o->n_op = 1u;
		o->o[0] = m;
		return;
	}
	o->n_op = 3u;
	if (l) {
		o_reg(&o->o[0], rt, dsz, CELL_OF_WRITE);
		o_reg(&o->o[1], rt2, dsz, CELL_OF_WRITE);
		if (rt == 31u)
			o_dead(&o->o[0], dsz);
		else
			wr_zr(o, rt);
		if (rt2 == 31u)
			o_dead(&o->o[1], dsz);
		else
			wr_zr(o, rt2);
	} else {
		o_zr(&o->o[0], rt, dsz);
		o_zr(&o->o[1], rt2, dsz);
	}
	o->o[2] = m;
}

static void ls_excl(struct cell_insn *o, uint32_t x)
{
	unsigned size = x >> 30, o2 = (x >> 23) & 1u, l = (x >> 22) & 1u;
	unsigned o1 = (x >> 21) & 1u, rs = (x >> 16) & 31u;
	unsigned rt2 = (x >> 10) & 31u, rn = (x >> 5) & 31u, rt = x & 31u;
	struct lsk k;
	struct cell_operand m;

	k.acc = (uint8_t)(1u << size);
	k.dsz = size == 3u ? 8u : 4u;
	o_mem(&m, rn, 0, k.acc, l ? CELL_OF_READ : CELL_OF_WRITE);
	if (!o2 && !o1) {
		if (l) {                        /* ldxr, ldaxr */
			k.kind = LK_LD;
			ls_emit(o, &k, rt, &m, 32u, 0, 0);
		} else {                        /* stxr, stlxr: status in Rs */
			o->op = CELL_OTHER;
			o->n_op = 3u;
			o_reg(&o->o[0], rs, 4u, CELL_OF_WRITE);
			o_zr(&o->o[1], rt, k.dsz);
			o->o[2] = m;
			if (rs == 31u)
				o_dead(&o->o[0], 4u);
			else
				wr_zr(o, rs);
		}
	} else if (!o2) {
		if (size >= 2u) {               /* ldxp, ldaxp, stxp, stlxp */
			unsigned psz = size == 3u ? 8u : 4u;

			o_mem(&m, rn, 0, psz * 2u, l ? CELL_OF_READ : CELL_OF_WRITE);
			o->op = CELL_OTHER;
			o->n_op = 3u;
			if (l) {
				o_reg(&o->o[0], rt, psz, CELL_OF_WRITE);
				o_reg(&o->o[1], rt2, psz, CELL_OF_WRITE);
				wr_zr(o, rt);
				wr_zr(o, rt2);
				if (rt == 31u)
					o_dead(&o->o[0], psz);
				if (rt2 == 31u)
					o_dead(&o->o[1], psz);
				o->o[2] = m;
			} else {
				o_reg(&o->o[0], rs, 4u, CELL_OF_WRITE);
				o_zr(&o->o[1], rt, psz);
				o->o[2] = m;
				wr_zr(o, rs);
				if (rs == 31u)
					o_dead(&o->o[0], 4u);
			}
		} else {                        /* casp: a register pair */
			if ((rs & 1u) || (rt & 1u)) {
				ud(o);
				return;
			}
			o->op = CELL_OTHER;
			o->n_op = 3u;
			o_reg(&o->o[0], rs, 4u << size, CELL_OF_WRITE | CELL_OF_READ);
			o_reg(&o->o[1], rt, 4u << size, CELL_OF_READ);
			o_mem(&o->o[2], rn, 0, 8u << size,
			      CELL_OF_READ | CELL_OF_WRITE);
			if (rs != 31u) {
				wr_zr(o, rs);
				wr_zr(o, rs + 1u);
			} else {
				o_dead(&o->o[0], 4u << size);
			}
		}
	} else if (!o1) {                       /* ldar, stlr, ldlar, stllr */
		k.kind = l ? LK_LD : LK_ST;
		ls_emit(o, &k, rt, &m, 32u, 0, 0);
	} else {                                /* cas */
		o->op = CELL_OTHER;
		o->n_op = 3u;
		o_reg(&o->o[0], rs, k.dsz, CELL_OF_WRITE | CELL_OF_READ);
		o_zr(&o->o[1], rt, k.dsz);
		o_mem(&o->o[2], rn, 0, k.acc, CELL_OF_READ | CELL_OF_WRITE);
		if (rs == 31u)
			o_dead(&o->o[0], k.dsz);
		else
			wr_zr(o, rs);
	}
}

/* The 111 group, bit 24 clear: unscaled, post/pre-index, unprivileged,
 * register offset, atomics, and the pointer-authenticated load. */
static void ls_reg(struct cell_insn *o, uint32_t x)
{
	unsigned size = x >> 30, v = (x >> 26) & 1u, opc = (x >> 22) & 3u;
	unsigned rn = (x >> 5) & 31u, rt = x & 31u, m11 = (x >> 10) & 3u;
	struct lsk k;
	struct cell_operand m;
	int64_t imm9 = sx((x >> 12) & 0x1ffu, 9);

	if (!((x >> 21) & 1u)) {
		/* bit 21 clear: imm9 forms; 11:10 is the addressing mode */
		unsigned mode = m11;    /* 0 unscaled, 1 post, 2 unpriv, 3 pre */

		if (!ls_kind(size, opc, v, mode == 0, &k) ||
		    (mode == 2u && (v || k.kind == LK_PF))) {
			ud(o);
			return;
		}
		o_mem(&m, rn, mode == 1u ? 0 : imm9, k.acc, 0);
		ls_emit(o, &k, rt, &m, (mode == 1u || mode == 3u) ? rn : 32u,
			mode == 1u, imm9);
		return;
	}
	if (m11 == 2u) {                        /* register offset */
		unsigned opt = (x >> 13) & 7u, s = (x >> 12) & 1u;
		unsigned rm = (x >> 16) & 31u;

		if (!(opt & 2u) || !ls_kind(size, opc, v, 1, &k)) {
			ud(o);
			return;
		}
		o_mem(&m, rn, 0, k.acc, 0);
		if (rm != 31u)
			m.index = (uint8_t)rm;
		if (s) {
			unsigned sh = k.acc == 16u ? 4u : size;

			m.scale = (uint8_t)(1u << sh);
		}
		ls_emit(o, &k, rt, &m, 32u, 0, 0);
		return;
	}
	if (m11 == 0) {                         /* atomic memory operations */
		unsigned a = (x >> 23) & 1u, r = (x >> 22) & 1u;
		unsigned rs = (x >> 16) & 31u, o3 = (x >> 15) & 1u;
		unsigned op = (x >> 12) & 7u;
		unsigned dsz = size == 3u ? 8u : 4u;

		if (v) {
			ud(o);
			return;
		}
		if (o3 && op == 4u) {           /* ldapr */
			if (!a || r) {
				ud(o);
				return;
			}
			k.acc = (uint8_t)(1u << size);
			k.dsz = (uint8_t)dsz;
			k.kind = LK_LD;
			o_mem(&m, rn, 0, k.acc, 0);
			ls_emit(o, &k, rt, &m, 32u, 0, 0);
			return;
		}
		if (o3 && op != 0) {
			/*
			 * FEAT_LS64: ld64b and st64b move eight consecutive
			 * registers, st64bv and st64bv0 also return a status in
			 * Rs. The data registers are an even pair-aligned run
			 * that ends at or before x29, which is what a reference
			 * decoder was seen to accept (Rt even and at most 22).
			 */
			if (size != 3u || a || r || (op != 1u && op != 2u &&
			    op != 3u && op != 5u) || (rt & 1u) || rt > 22u) {
				ud(o);
				return;
			}
			o->op = CELL_OTHER;
			o->n_op = 1u;
			o_mem(&o->o[0], rn, 0, 64u, op == 5u ? CELL_OF_READ :
			      CELL_OF_WRITE);
			if (op == 5u)
				o->wmask |= 0xffull << rt;
			else if (op != 1u)
				wr_zr(o, rs);
			return;
		}
		/* ldadd.. and swp: Rs is the operand, Rt receives the old value */
		o->op = CELL_OTHER;
		o->n_op = 3u;
		o_zr(&o->o[0], rs, dsz);
		o_reg(&o->o[1], rt, dsz, CELL_OF_WRITE);
		o_mem(&o->o[2], rn, 0, 1u << size, CELL_OF_READ | CELL_OF_WRITE);
		if (rt == 31u)
			o_dead(&o->o[1], dsz);
		else
			wr_zr(o, rt);
		return;
	}
	/* 11:10 is 01 or 11: ldraa, ldrab (size 11, V 0) */
	if (size != 3u || v) {
		ud(o);
		return;
	}
	{
		unsigned w = (x >> 11) & 1u;
		int64_t d = sx((((x >> 22) & 1u) << 9) | ((x >> 12) & 0x1ffu), 10) * 8;

		k.acc = 8u;
		k.dsz = 8u;
		k.kind = LK_LD;
		o_mem(&m, rn, d, 8u, 0);
		ls_emit(o, &k, rt, &m, w ? rn : 32u, 0, 0);
	}
}

/* Load/store memory tags: stg, stzg, st2g, stz2g, ldg, stgm, ldgm, stzgm. */
static void ls_tags(struct cell_insn *o, uint32_t x)
{
	unsigned opc = (x >> 22) & 3u, op2 = (x >> 10) & 3u;
	unsigned rn = (x >> 5) & 31u, rt = x & 31u;
	unsigned imm9 = (x >> 12) & 0x1ffu;

	o->op = CELL_OTHER;
	if (op2 == 0) {
		if (opc == 1u) {                /* ldg */
			wr_zr(o, rt);
			return;
		}
		if (imm9) {                     /* stzgm, stgm, ldgm: imm is 0 */
			ud(o);
			return;
		}
		if (opc == 3u)                  /* ldgm */
			wr_zr(o, rt);
		return;
	}
	if (op2 != 2u)
		wr_sp(o, rn);                   /* post- or pre-index */
}

static void ls_simd_struct(struct cell_insn *o, uint32_t x)
{
	unsigned rn = (x >> 5) & 31u;
	unsigned post = (x >> 23) & 1u;

	if (x >> 31) {
		ud(o);
		return;
	}
	if (!((x >> 24) & 1u)) {                /* multiple structures */
		unsigned opc = (x >> 12) & 15u;

		if (((x >> 21) & 1u) ||
		    opc > 10u || (opc != 0 && opc != 2u && opc != 4u &&
				  opc != 6u && opc != 7u && opc != 8u &&
				  opc != 10u) ||
		    (!post && ((x >> 16) & 31u))) {
			ud(o);
			return;
		}
	} else if (!post && ((x >> 16) & 31u)) {
		ud(o);
		return;
	}
	o->op = CELL_OTHER;
	if (post)
		wr_sp(o, rn);
}

static void g_ls(struct cell_insn *o, uint32_t x, uint64_t va)
{
	unsigned v = (x >> 26) & 1u, size = x >> 30;
	unsigned rn = (x >> 5) & 31u, rt = x & 31u;
	struct lsk k;
	struct cell_operand m;

	(void)va;
	switch ((x >> 28) & 3u) {
	case 0:                                 /* 001 */
		if (v) {
			ls_simd_struct(o, x);
		} else if (!((x >> 24) & 1u)) {
			ls_excl(o, x);
		} else {
			ud(o);
		}
		break;
	case 1:                                 /* 011 */
		if (!((x >> 24) & 1u)) {        /* literal */
			unsigned opc = x >> 30;
			int64_t d = sx((x >> 5) & 0x7ffffu, 19) * 4;

			if (v ? opc == 3u : 0) {
				ud(o);
				break;
			}
			if (!v && opc == 3u) {  /* prfm literal */
				o->op = CELL_OTHER;
				break;
			}
			k.acc = (uint8_t)(4u << opc);
			k.dsz = opc == 0 ? 4u : 8u;
			k.kind = v ? LK_VLD : LK_LD;
			if (!v && opc == 2u)
				k.acc = 4u;
			else if (!v && opc == 1u)
				k.acc = 8u;
			o_mem(&m, NOREG, d, k.acc, CELL_OF_RIPREL);
			ls_emit(o, &k, rt, &m, 32u, 0, 0);
		} else if (!(x >> 30) && !((x >> 21) & 1u) &&
			   ((x >> 10) & 3u) == 1u) {
			/*
			 * FEAT_MOPS: the cpyf and cpy families (prologue, main,
			 * epilogue) and the set and setg families. A reference with these encodings in it
			 * shows the shape: sz 00, bits 25:24 01, bit 21 0,
			 * bits 11:10 01; op1 0..2 is a copy with any option
			 * nibble, op1 3 is a set and its option nibble stops at
			 * 11. Both rewrite the pointer and count registers
			 * they name: a copy all three, a set the destination
			 * and the count (the data register is only read).
			 */
			unsigned op1 = (x >> 22) & 3u, op2 = (x >> 12) & 15u;
			unsigned rs = (x >> 16) & 31u;

			if (op1 == 3u && op2 >= 12u) {
				ud(o);
				break;
			}
			o->op = CELL_OTHER;
			wr_zr(o, rt);
			wr_zr(o, rn);
			if (op1 != 3u)
				wr_zr(o, rs);
		} else if (!v && ((x >> 21) & 1u) && (x >> 24) == 0xd9u) {
			ls_tags(o, x);
		} else if (!v && !((x >> 21) & 1u) && !((x >> 10) & 3u)) {
			/* stlur, ldapur, ldapursw, ldapursb/h */
			unsigned opc = (x >> 22) & 3u;
			int64_t d = sx((x >> 12) & 0x1ffu, 9);

			if (!ls_kind(size, opc, 0, 0, &k)) {
				ud(o);
				break;
			}
			o_mem(&m, rn, d, k.acc, 0);
			ls_emit(o, &k, rt, &m, 32u, 0, 0);
		} else {
			ud(o);
		}
		break;
	case 2:                                 /* 101: pairs */
		ls_pair(o, x);
		break;
	default:                                /* 111 */
		if ((x >> 24) & 1u) {           /* unsigned immediate */
			unsigned opc = (x >> 22) & 3u;
			unsigned sh;

			if (!ls_kind(size, opc, v, 1, &k)) {
				ud(o);
				break;
			}
			sh = k.acc == 16u ? 4u : size;
			o_mem(&m, rn, (int64_t)((x >> 10) & 0xfffu) << sh,
			      k.acc, 0);
			ls_emit(o, &k, rt, &m, 32u, 0, 0);
		} else {
			ls_reg(o, x);
		}
		break;
	}
}

/* ---- data processing: register ------------------------------------------ */

static int is_plain_shift(unsigned imm6)
{
	return imm6 == 0;
}

static void g_dpreg(struct cell_insn *o, uint32_t x, uint64_t va)
{
	(void)va;
	unsigned sf = x >> 31, sz = sf ? 8u : 4u;
	unsigned rd = x & 31u, rn = (x >> 5) & 31u, rm = (x >> 16) & 31u;
	struct cell_operand a, b;

	if (!((x >> 28) & 1u)) {
		unsigned imm6 = (x >> 10) & 63u, shift = (x >> 22) & 3u;
		unsigned opc = (x >> 29) & 3u;

		if (!((x >> 24) & 1u)) {        /* logical, shifted register */
			unsigned nn = (x >> 21) & 1u;

			if (!sf && (imm6 & 32u)) {
				ud(o);
				return;
			}
			o_zr(&a, rn, sz);
			o_zr(&b, rm, sz);
			if (opc == 3u && rd == 31u) {   /* tst, bics xzr */
				o->op = nn ? CELL_OTHER : CELL_TEST;
				if (!nn && is_plain_shift(imm6)) {
					o->n_op = 2u;
					o->o[0] = a;
					o->o[1] = b;
				} else {
					o->op = CELL_OTHER;
				}
				return;
			}
			if (nn) {
				if (opc == 1u && rn == 31u && is_plain_shift(imm6)) {
					/* mvn */
					if (rd == 31u) {
						nop(o);
					} else if (b.kind == CELL_O_REG &&
						   b.reg == rd) {
						o->op = CELL_NOT;
						wr_zr(o, rd);
						o->n_op = 1u;
						o_reg(&o->o[0], rd, sz,
						      CELL_OF_WRITE | CELL_OF_READ);
					} else if (b.kind == CELL_O_IMM) {
						o->op = CELL_MOV;
						wr_zr(o, rd);
						o->n_op = 2u;
						o_reg(&o->o[0], rd, sz,
						      CELL_OF_WRITE);
						o_imm(&o->o[1], szmask(sz), sz);
					} else {
						other_rd(o, rd, sz, 0);
					}
					return;
				}
				other_rd(o, rd, sz, 0);         /* bic, orn, eon */
				return;
			}
			if (!is_plain_shift(imm6) && rn != 31u) {
				other_rd(o, rd, sz, 0);
				return;
			}
			if (!is_plain_shift(imm6)) {
				/* orr xd,xzr,xm,shift #n: the shifted move; its
				 * shifted value is no operand a class can state. */
				other_rd(o, rd, sz, 0);
				return;
			}
			emit_bin(o, opc == 0 || opc == 3u ? CELL_AND :
				 opc == 1u ? CELL_OR : CELL_XOR, sz, rd, 0,
				 &a, &b);
			return;
		}
		/* add/sub, shifted or extended register */
		{
			unsigned op = (x >> 30) & 1u, s = (x >> 29) & 1u;
			int plain;

			if ((x >> 21) & 1u) {   /* extended register */
				unsigned option = (x >> 13) & 7u;
				unsigned imm3 = (x >> 10) & 7u;

				if (shift != 0 || imm3 > 4u) {
					ud(o);
					return;
				}
				plain = option == (sf ? 3u : 2u) && imm3 == 0;
				o_sp(&a, rn, sz);
				o_zr(&b, rm, sz);
				if (s && rd == 31u) {
					o->op = CELL_OTHER;
					if (op && plain) {
						o->op = CELL_CMP;
						o->n_op = 2u;
						o->o[0] = a;
						o->o[1] = b;
					}
					return;
				}
				if (!plain) {
					other_rd(o, rd, sz, !s);
					return;
				}
				emit_bin(o, op ? CELL_SUB : CELL_ADD, sz, rd, !s, &a, &b);
				return;
			}
			if (shift == 3u || (!sf && (imm6 & 32u))) {
				ud(o);
				return;
			}
			o_zr(&a, rn, sz);
			o_zr(&b, rm, sz);
			plain = is_plain_shift(imm6);
			if (s && rd == 31u) {
				o->op = CELL_OTHER;
				if (op && plain) {
					o->op = CELL_CMP;
					o->n_op = 2u;
					o->o[0] = a;
					o->o[1] = b;
				}
				return;
			}
			if (!plain) {
				other_rd(o, rd, sz, 0);
				return;
			}
			emit_bin(o, op ? CELL_SUB : CELL_ADD, sz, rd, 0, &a, &b);
			return;
		}
	}
	if ((x >> 24) & 1u) {                   /* three source */
		unsigned op54 = (x >> 29) & 3u, op31 = (x >> 21) & 7u;
		unsigned o0 = (x >> 15) & 1u, ra = (x >> 10) & 31u;

		if (op54 || (!sf && op31) ||
		    op31 == 3u || op31 == 4u || op31 == 7u ||
		    ((op31 == 2u || op31 == 6u) && o0)) {
			ud(o);
			return;
		}
		if (rd == 31u) {
			nop(o);
			return;
		}
		if (op31 == 0 && !o0 && ra == 31u) {            /* mul */
			o_zr(&a, rn, sz);
			o_zr(&b, rm, sz);
			emit_bin(o, CELL_MUL, sz, rd, 0, &a, &b);
		} else if ((op31 == 2u || op31 == 6u) ||
			   ((op31 == 1u || op31 == 5u) && !o0 && ra == 31u)) {
			/* smulh, umulh, smull, umull */
			unsigned isz = (op31 & 3u) == 2u ? 8u : 4u;

			o_zr(&a, rn, isz);
			o_zr(&b, rm, isz);
			emit_bin(o, op31 >= 5u ? CELL_MUL : CELL_IMUL, 8u, rd,
				 0, &a, &b);
		} else {                        /* madd, msub, smaddl, ... */
			other_rd(o, rd, sz, 0);
		}
		return;
	}
	switch ((x >> 21) & 7u) {
	case 0:                                 /* add/sub with carry, flags */
		if ((x >> 29) & 1u && ((x >> 10) & 63u) != 0) {
			/* setf8, setf16, rmif: flags only */
			if ((x & 0xffffbc1fu) == 0x3a00080du ||
			    (x & 0xffe07c10u) == 0xba000400u) {
				o->op = CELL_OTHER;
				return;
			}
			ud(o);
			return;
		}
		if ((x >> 10) & 63u) {
			ud(o);
			return;
		}
		o_zr(&a, rn, sz);
		o_zr(&b, rm, sz);
		if (rd == 31u && !((x >> 29) & 1u)) {
			nop(o);
			return;
		}
		if (rd == 31u) {
			o->op = CELL_OTHER;
			return;
		}
		emit_bin(o, ((x >> 30) & 1u) ? CELL_SBB : CELL_ADC, sz, rd, 0,
			 &a, &b);
		if (o->op == CELL_MOV)
			o->op = CELL_OTHER, o->n_op = 1u;
		return;
	case 2:                                 /* conditional compare */
		if (!((x >> 29) & 1u) || ((x >> 10) & 1u) || ((x >> 4) & 1u)) {
			ud(o);
			return;
		}
		o->op = CELL_OTHER;
		o->cond = (uint8_t)((x >> 12) & 15u);
		return;
	case 4: {                               /* conditional select */
		unsigned op2 = (x >> 10) & 3u;

		if (((x >> 29) & 1u) || op2 > 1u) {
			ud(o);
			return;
		}
		other_rd(o, rd, sz, 0);
		o->cond = (uint8_t)((x >> 12) & 15u);
		return;
	}
	case 6: {                               /* one and two source */
		unsigned s = (x >> 29) & 1u, opcode = (x >> 10) & 63u;

		if ((x >> 30) & 1u) {           /* one source */
			unsigned opcode2 = (x >> 16) & 31u;

			if (s || opcode2 > 1u) {
				ud(o);
				return;
			}
			if (opcode2 == 0) {
				/* rbit rev16 rev32/rev clz cls; rev (x) is 64-bit only */
				if (opcode > 5u || (!sf && opcode == 3u)) {
					ud(o);
					return;
				}
			} else if (!sf || opcode > 17u ||
				   (opcode >= 8u && rn != 31u)) {
				/* pointer authentication: pac*, aut* take a
				 * modifier register (opcode < 8); the Z forms
				 * (8..15) and xpaci/xpacd (16, 17) have none, so
				 * Rn must be 31 */
				ud(o);
				return;
			}
			other_rd(o, rd, sz, 0);
			return;
		}
		/* two source */
		if (s) {                        /* subps */
			if (!sf || opcode != 0) {
				ud(o);
				return;
			}
			o->op = CELL_OTHER;
			wr_zr(o, rd);
			return;
		}
		switch (opcode) {
		case 0: case 4: case 5: case 12:        /* subp irg gmi pacga */
			if (!sf) {
				ud(o);
				return;
			}
			other_rd(o, rd, 8u, opcode == 4u);
			return;
		case 2: case 3: case 8: case 9: case 10: case 11: {
			unsigned cls = opcode == 2u ? CELL_DIV :
				       opcode == 3u ? CELL_IDIV :
				       opcode == 8u ? CELL_SHL :
				       opcode == 9u ? CELL_SHR :
				       opcode == 10u ? CELL_SAR : CELL_ROR;

			o_zr(&a, rn, sz);
			o_zr(&b, rm, sz);
			emit_bin(o, cls, sz, rd, 0, &a, &b);
			if (o->op == CELL_MOV) {
				o->op = CELL_OTHER;
				o->n_op = 1u;
			}
			return;
		}
		default:
			if (opcode >= 16u && opcode < 24u &&
			    (sf ? (opcode & 3u) == 3u : (opcode & 3u) != 3u)) {
				other_rd(o, rd, sz, 0);     /* crc32, crc32c */
				return;
			}
			ud(o);
			return;
		}
	}
	default:
		ud(o);
		return;
	}
}

/* ---- scalar floating point, Advanced SIMD, SVE, SME ---------------------- */

/*
 * LENGTH FOUR, CELL_OTHER, AND THE GENERAL REGISTERS IT WRITES. Nothing here is
 * a class the sweep asks about. What it does ask is whether the instruction
 * wrote x0..x30, because a vector instruction that moves a value to a general
 * register ends the constant map's knowledge of it: fmov x0,d0, fcvtzs x0,d0,
 * umov, smov, and the SVE element counts.
 *
 * VALIDITY IS DECIDED ONLY WHERE THE WRITE IS: the floating point <-> integer
 * conversions, the fixed-point conversions and the umov/smov group are
 * checked for allocation because a word that merely resembles them must not
 * claim a register. Every other word in these spaces is reported as a valid
 * CELL_OTHER that writes no general register: that is a statement about the
 * registers, which is what was measured, and NOT a claim that the word is
 * allocated. A vector space the size of this one has thousands of reserved
 * holes, and their only effect on the sweep is that data in them reads as code
 * which writes nothing.
 */
static int fp_int(uint32_t x, unsigned *gw)
{
	unsigned sf = x >> 31, type = (x >> 22) & 3u, rmode = (x >> 19) & 3u;
	unsigned opc = (x >> 16) & 7u;

	*gw = 0;
	if (type == 2u) {               /* fmov to/from the top half of a q */
		*gw = opc == 6u;
		return sf && rmode == 1u && (opc == 6u || opc == 7u);
	}
	switch (opc) {
	case 0: case 1:
		*gw = 1;
		return 1;
	case 2: case 3:
		return rmode == 0;
	case 4: case 5:
		*gw = 1;
		return rmode == 0;
	default:
		if (rmode == 0) {
			*gw = opc == 6u;
			return type == 0 ? sf == 0 : type == 1u ? sf != 0 : 1;
		}
		if (rmode == 3u && opc == 6u && type == 1u && !sf) {
			*gw = 1;                /* fjcvtzs */
			return 1;
		}
		return 0;
	}
}

static void g_simd(struct cell_insn *o, uint32_t x, uint64_t va)
{
	(void)va;
	unsigned rd = x & 31u, sf = x >> 31;
	unsigned gw = 0;

	o->op = CELL_OTHER;
	if ((x & 0x7f20fc00u) == 0x1e200000u) {
		if (!fp_int(x, &gw)) {
			ud(o);
			return;
		}
	} else if ((x & 0x7f200000u) == 0x1e000000u) {
		/* fixed-point conversions: fcvtzs/fcvtzu to a general register,
		 * scvtf/ucvtf from one */
		unsigned type = (x >> 22) & 3u, rmode = (x >> 19) & 3u;
		unsigned opc = (x >> 16) & 7u;

		if (type == 2u || (!sf && !((x >> 15) & 1u)) ||
		    !((rmode == 3u && opc < 2u) ||
		      (rmode == 0 && (opc == 2u || opc == 3u)))) {
			ud(o);
			return;
		}
		gw = opc < 2u;
	} else if ((x & 0xbfe08400u) == 0x0e000400u) {
		/* advanced simd copy: smov and umov write a general register */
		unsigned imm4 = (x >> 11) & 15u, imm5 = (x >> 16) & 31u;
		unsigned q = (x >> 30) & 1u, sz;

		if (imm4 == 5u || imm4 == 7u) {
			if (imm5 & 1u)
				sz = 0;
			else if (imm5 & 2u)
				sz = 1u;
			else if (imm5 & 4u)
				sz = 2u;
			else if (imm5 & 8u)
				sz = 3u;
			else {
				ud(o);
				return;
			}
			if (imm4 == 5u ? (sz == 3u || (!q && sz == 2u))
				       : (q ? sz != 3u : sz == 3u)) {
				ud(o);
				return;
			}
			gw = 1;
			sf = q;
		}
	}
	if (gw && rd != 31u) {
		wr_zr(o, rd);
		o->n_op = 1u;
		o_reg(&o->o[0], rd, sf ? 8u : 4u, CELL_OF_WRITE);
	}
}

/*
 * THE SVE WORDS THAT WRITE A GENERAL REGISTER, which is all the sweep asks of
 * this space (vector, predicate and memory forms write none; every SVE load and
 * store is addressed through a base register it does not change). One row per
 * family, Rd/Rdn in bits 4:0 for all of them. The masks were found by
 * enumerating the whole 2^28-word space against a reference decoder (every
 * word whose first operand is a general register, minus ctermeq/ctermne,
 * which only read it) and written here as families: the element-size field
 * is free, the rest of each pattern fixed. sp marks the two whose Rd is sp at
 * 31; for the others 31 is the zero register and nothing is written.
 *
 * The streaming-mode forms addsvl/addspl/rdsvl are the same patterns with bit
 * 11 set; the reference does not decode them and the architecture does, so
 * bit 11 is left free in those three rows. Nothing here decides whether a
 * word in this space is allocated - see g_simd.
 */
static const struct sve_gpr {
	uint32_t mask, val;
	uint8_t sp;
} g_sve_gpr[] = {
	{ 0xffe0f000u, 0x04205000u, 1 },        /* addvl, addsvl */
	{ 0xffe0f000u, 0x04605000u, 1 },        /* addpl, addspl */
	{ 0xfffff000u, 0x04bf5000u, 0 },        /* rdvl, rdsvl */
	{ 0xff30fc00u, 0x0420e000u, 0 },        /* cntb cnth cntw cntd */
	{ 0xff30f800u, 0x0430e000u, 0 },        /* incb..incd, decb..decd */
	{ 0xff20f000u, 0x0420f000u, 0 },        /* sq/uq inc/dec b..d, scalar */
	{ 0xff3fc200u, 0x25208000u, 0 },        /* cntp */
	{ 0xff3efe00u, 0x252c8800u, 0 },        /* incp, decp, scalar */
	{ 0xff3cfa00u, 0x25288800u, 0 },        /* sq/uq inc/dec p, scalar */
	{ 0xff3ee000u, 0x0520a000u, 0 },        /* lasta, lastb */
	{ 0xff3ee000u, 0x0530a000u, 0 },        /* clasta, clastb */
};

static void g_sve(struct cell_insn *o, uint32_t x, uint64_t va)
{
	unsigned i, rd = x & 31u;

	(void)va;

	o->op = CELL_OTHER;
	/* An unrolled scan of eleven rows, on a space that is a sixteenth of all
	 * words and where the first byte rules out most rows: not worth a table
	 * index of its own. */
	for (i = 0; i < sizeof g_sve_gpr / sizeof *g_sve_gpr; i++) {
		if ((x & g_sve_gpr[i].mask) != g_sve_gpr[i].val)
			continue;
		if (g_sve_gpr[i].sp || rd != 31u)
			wr_sp(o, rd);
		if (g_sve_gpr[i].sp || rd != 31u) {
			o->n_op = 1u;
			o_reg(&o->o[0], rd, 8u, CELL_OF_WRITE);
		}
		return;
	}
}

/* Bits 28..25 are 0000: udf, and SME (bit 31 set) - which writes no general
 * register. Anything else in this group is unallocated. */
static void g_reserved(struct cell_insn *o, uint32_t x, uint64_t va)
{
	(void)va;
	if (!(x >> 16))
		ud(o);                  /* udf #imm16 */
	else if (x >> 31)
		o->op = CELL_OTHER;
	else
		ud(o);
}

/* Bits 28..25 are 0001 or 0011: no instruction lives there. */
static void g_unalloc(struct cell_insn *o, uint32_t x, uint64_t va)
{
	(void)x;
	(void)va;
	ud(o);
}

/* ---- the entry point ---------------------------------------------------- */

typedef void (*a64_group)(struct cell_insn *, uint32_t, uint64_t);

/* Bits 28..25 of the word index this table: the A64 top-level decode. */
static const a64_group g_top[16] = {
	[0x0] = g_reserved, [0x1] = g_unalloc, [0x2] = g_sve,  [0x3] = g_unalloc,
	[0x4] = g_ls,       [0x5] = g_dpreg,   [0x6] = g_ls,   [0x7] = g_simd,
	[0x8] = g_dpimm,    [0x9] = g_dpimm,   [0xa] = g_branch,
	[0xb] = g_branch,   [0xc] = g_ls,      [0xd] = g_dpreg,
	[0xe] = g_ls,       [0xf] = g_simd,
};

uint32_t cell_decode_a64(const uint8_t *p, uint32_t n, uint64_t va,
			struct cell_insn *out)
{
	uint32_t x;

	if (!p || n < 4u || !out)
		return 0;
	x = (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
	    (uint32_t)p[1] << 8 | p[0];

	memset(out, 0, sizeof *out);
	out->len = 4u;
	out->at = va;
	out->at_va = va;
	/* KOF_BROKEN, not (uint64_t)-1 - see decode_mips.c. */
	out->target = KOF_BROKEN;
	out->target_va = KOF_BROKEN;
	out->o[0].reg = out->o[0].index = out->o[0].seg = NOREG;
	out->o[1].reg = out->o[1].index = out->o[1].seg = NOREG;
	out->o[2].reg = out->o[2].index = out->o[2].seg = NOREG;

	g_top[(x >> 25) & 15u](out, x, va);
	return 4u;
}
