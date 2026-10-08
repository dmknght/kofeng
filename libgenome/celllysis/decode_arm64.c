/*
 * decode_arm64.c - AArch64 (the A64 instruction set of Armv8-A and later) into
 * celllysis's one instruction form.
 *
 * THE DECODING IS GENOTYPE'S (libgenome/genotype/arm64): a table that says which
 * instruction a word is. This file is the translation, and the only place in the
 * engine that reads one of its instructions: it takes the identity, pulls the
 * fields it needs through genotype's accessors, and produces the class, the
 * registers written and the operand forms below. It used to be both at once, a
 * decoder written straight into struct cell_insn; the split is what lets the
 * table be checked against the architecture on its own and this file be checked
 * against the engine's vocabulary on its own.
 *
 * THE CLASS IS A TABLE LOOKUP (g_ent[id].cls, as decode_x86.c's g_cls), and so is
 * the choice of handler: one indexed call per instruction, no chain of tests. A
 * handler exists per FORM - add/subtract immediate, a literal load, a pair - and
 * several identities share one. What a handler still decides is what the
 * identity alone cannot: that `add x0, x1, #0` is a move, that `subs xzr, ...` is
 * a compare, that a write to the zero register writes nothing.
 *
 * WHAT IS DECIDED AND WHAT IS NOT. The groups the sweep reads - data processing
 * (immediate and register), branches and system, loads and stores - are decoded
 * completely: validity, class, operands, written registers. Scalar floating
 * point, Advanced SIMD, SVE and SME are different: their length is always four
 * and they are CELL_OTHER, and what is decided is the one thing the sweep asks of
 * them, which general registers they write (fmov x0,d0; fcvtzs x0,d0; umov; smov;
 * the SVE element counts, ...). Which words of those spaces are allocated is
 * genotype's statement and is limited to the families that write a register: see
 * THE VECTOR SPACES in arm64.h.
 *
 * UNALLOCATED WORDS are CELL_UD with nothing written. CELL_UD is also the class of
 * `udf` itself: both are "defined to fault", and a walk that meets either has left
 * the code. A caller that must tell them apart reads the word: udf is exactly the
 * words whose top sixteen bits are zero.
 *
 * REGISTERS. x0..x30 are 0..30 and sp is 31 (wmask bit 31). xzr/wzr have no
 * number: a destination that is the zero register writes nothing (no wmask bit)
 * and a source that is the zero register is emitted as CELL_O_IMM 0, so the
 * constant map sees the zero instead of a register it cannot know. A w register
 * is size 4 (its write zero-extends, as on x86-64), an x register size 8. Which
 * register 31 means is decided per operand slot by the architecture (sp for an
 * address base and for add/sub/logical-immediate destinations, zero everywhere
 * else); this file follows it slot by slot.
 *
 * OPERAND FORMS (documented here once, referred to below).
 *
 *   Two-operand ALU, the form the constant map computes:  when the first source
 *   is also the destination, `add x0,x0,#4` is  o[0]=x0 (W|R)  o[1]=#4. When it
 *   is not, `add x0,x1,#4` is  o[0]=x0 (W)  o[1]=x1  o[2]=#4 - the architecture's
 *   three-operand form, which the map does not read (it takes o[1] as the second
 *   source for every class), so a consumer must handle n_op==3 itself. Adding an
 *   operand the map ignores would be a silent wrong answer; the alternative of
 *   folding it into two operands cannot be written.
 *   A second source that carries a shift or an extension the form cannot name
 *   (`add x0,x1,x2,lsl #3`, `add x0,x1,w2,uxtw`) makes the instruction CELL_OTHER:
 *   its class would otherwise promise an arithmetic the operands do not state.
 *   Same for bic/orn/eon (no class), cmn, ccmp and every conditional select.
 *   Load:   CELL_MOV  o[0]=Rt (W)  o[1]=MEM.  Store: CELL_MOV  o[0]=MEM (W)
 *   o[1]=source reg or #0.  MEM: reg=base (31=sp), index/scale for a register
 *   offset (an uxtw/sxtw extension of the index is not carried), disp, size =
 *   bytes accessed.  A post-index access is [base] with disp 0 and the increment
 *   in o[2] (single-register forms only; a pair has no free slot); a pre-index
 *   access carries the increment as disp.
 *   Literal load: MEM with CELL_OF_RIPREL and reg CELL_REG_NONE. DISP IS RELATIVE
 *   TO THE ADDRESS OF THE INSTRUCTION ITSELF (at_va), not to the next one: literal
 *   address = at_va + disp. That is how A64 defines PC and differs from the x86
 *   rip-relative convention, so a consumer must not add len.
 *   Branches: o[0] is always CELL_O_REL and the target is in target_va (the engine
 *   resolves `target`). cbz/cbnz add o[1]=the tested register, tbz/tbnz add
 *   o[1]=the register and o[2]=the bit number. `cond` carries the standard A64
 *   condition code for b.cond (0=eq .. 14=al, 15=nv) and, so that a consumer can
 *   tell the two apart, 0 (eq) for cbz/tbz and 1 (ne) for cbnz/tbnz, which is the
 *   condition they branch on.
 *
 * CHEAP DECISIONS MADE ONCE: a word whose "should be zero/one" bits are not what
 * the architecture asks (SBZ/SBO) is decoded as the instruction, not rejected -
 * the CPU treats it as constrained-unpredictable, and the consequence of being
 * wrong the other way is losing a real instruction.
 *
 * EQUIVALENCE. The decoder this replaced was kept as a frozen reference and
 * every word of the 32-bit space was decoded by both, at several addresses, with
 * every field of struct cell_insn compared: tools/celllysis/arm64_equiv.c.
 */
#include <string.h>

/* KOF_BROKEN - the sentinel cell.h names for a target there is not. */
#include "kofmod/cell.h"
#include "decode.h"
#include <arm64/arm64.h>

#define NOREG CELL_REG_NONE

/* ---- small helpers ------------------------------------------------------ */

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
	unsigned i;

	memset(o->o, 0, sizeof o->o);
	for (i = 0; i < 3u; i++)
		o->o[i].reg = o->o[i].index = o->o[i].seg = NOREG;
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

/* ---- the identity table ------------------------------------------------- */

typedef void (*a64_handler)(struct cell_insn *o, const struct gt_arm64_insn *in,
			    uint64_t va, unsigned cls);

struct a64_ent {
	uint8_t cls;                    /* enum cell_op_class: the base class of the identity */
	a64_handler h;
};

/* ---- unallocated, and instructions that only name a class --------------- */

static void h_ud(struct cell_insn *o, const struct gt_arm64_insn *in, uint64_t va,
		 unsigned cls)
{
	(void)in;
	(void)va;
	(void)cls;
	ud(o);
}

/* Valid, writes nothing, carries nothing but its class. */
static void h_class(struct cell_insn *o, const struct gt_arm64_insn *in,
		    uint64_t va, unsigned cls)
{
	(void)in;
	(void)va;
	o->op = (uint8_t)cls;
}

/* A hint that names a general register: pacia*, autia*, xpaclri, chkfeat. */
static void h_hint_lr(struct cell_insn *o, const struct gt_arm64_insn *in,
		      uint64_t va, unsigned cls)
{
	(void)in;
	(void)va;
	o->op = (uint8_t)cls;
	o->wmask = 1ull << 30;
}

static void h_hint_x17(struct cell_insn *o, const struct gt_arm64_insn *in,
		       uint64_t va, unsigned cls)
{
	(void)in;
	(void)va;
	o->op = (uint8_t)cls;
	o->wmask = 1ull << 17;
}

static void h_hint_x16(struct cell_insn *o, const struct gt_arm64_insn *in,
		       uint64_t va, unsigned cls)
{
	(void)in;
	(void)va;
	o->op = (uint8_t)cls;
	o->wmask = 1ull << 16;
}

/* An instruction that writes Rt and nothing else we model: sysl, tstart, ttest, ldg, ldgm. */
static void h_wr_rt(struct cell_insn *o, const struct gt_arm64_insn *in,
		    uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	wr_zr(o, gt_arm64_rt(in));
}

/* Conditional compare: the condition is the only thing it carries. */
static void h_ccmp(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	o->cond = (uint8_t)gt_arm64_cond_select(in);
}

/* Conditional select: Rd is written, the condition is carried. */
static void h_csel(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	other_rd(o, gt_arm64_rd(in), gt_arm64_sf(in) ? 8u : 4u, 0);
	o->cond = (uint8_t)gt_arm64_cond_select(in);
}

/* One source or an unclassed register-to-register form: Rd, of the width sf says. */
static void h_rd(struct cell_insn *o, const struct gt_arm64_insn *in, uint64_t va,
		 unsigned cls)
{
	(void)va;
	(void)cls;
	other_rd(o, gt_arm64_rd(in), gt_arm64_sf(in) ? 8u : 4u, 0);
}

/* Rd is an X register whatever sf says, and 31 is the zero register: subp, gmi, pacga. */
static void h_rd64(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	other_rd(o, gt_arm64_rd(in), 8u, 0);
}

/* The same where 31 is sp: irg, addg, subg */
static void h_rd64_sp(struct cell_insn *o, const struct gt_arm64_insn *in,
		      uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	other_rd(o, gt_arm64_rd(in), 8u, 1);
}

/* subps: Rd is written, no operand is built */
static void h_subps(struct cell_insn *o, const struct gt_arm64_insn *in,
		    uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	wr_zr(o, gt_arm64_rd(in));
}

/* The vector spaces' general-register writers: o[0] is Rd, as wide as `wide` says. */
static void gp_write(struct cell_insn *o, unsigned rd, unsigned wide)
{
	o->op = CELL_OTHER;
	if (rd != 31u) {
		wr_zr(o, rd);
		o->n_op = 1u;
		o_reg(&o->o[0], rd, wide ? 8u : 4u, CELL_OF_WRITE);
	}
}

/* floating point <-> integer and fixed-point conversions into a general register: width is sf */
static void h_fp_to_gp(struct cell_insn *o, const struct gt_arm64_insn *in,
		       uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	gp_write(o, gt_arm64_rd(in), gt_arm64_sf(in));
}

/* smov and umov: width is Q (bit 30) */
static void h_simd_to_gp(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	gp_write(o, gt_arm64_rd(in), gt_arm64_bits(in, 30, 1));
}

/* SVE addvl and addpl: Rd is sp at 31, and the write is always there */
static void h_sve_sp(struct cell_insn *o, const struct gt_arm64_insn *in,
		     uint64_t va, unsigned cls)
{
	unsigned rd = gt_arm64_rd(in);

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	wr_sp(o, rd);
	o->n_op = 1u;
	o_reg(&o->o[0], rd, 8u, CELL_OF_WRITE);
}

/* the other SVE families that write a general register: 31 is the zero register */
static void h_sve_zr(struct cell_insn *o, const struct gt_arm64_insn *in,
		     uint64_t va, unsigned cls)
{
	unsigned rd = gt_arm64_rd(in);

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	if (rd != 31u) {
		wr_sp(o, rd);
		o->n_op = 1u;
		o_reg(&o->o[0], rd, 8u, CELL_OF_WRITE);
	}
}

/* ---- data processing: immediate ----------------------------------------- */

static void h_adr(struct cell_insn *o, const struct gt_arm64_insn *in, uint64_t va,
		  unsigned cls)
{
	unsigned rd = gt_arm64_rd(in);
	int64_t d = gt_arm64_adr_imm(in);
	uint64_t a;

	if (in->id == GT_ARM64_I_ADRP)
		a = (va & ~0xfffull) + (uint64_t)(d * 4096);
	else
		a = va + (uint64_t)d;
	o->op = (uint8_t)cls;
	if (rd == 31u) {
		nop(o);
		return;
	}
	wr_zr(o, rd);
	o->n_op = 2u;
	o_reg(&o->o[0], rd, 8u, CELL_OF_WRITE);
	o_imm(&o->o[1], a, 8u);
}

static void h_addsub_imm(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in);
	unsigned sub = cls == CELL_SUB, s = gt_arm64_bits(in, 29, 1);
	uint64_t imm = gt_arm64_addsub_imm(in);
	struct cell_operand a, b;

	(void)va;
	o_sp(&a, rn, sz);
	o_imm(&b, imm, sz);
	if (s && rd == 31u) {           /* cmp / cmn */
		o->op = sub ? CELL_CMP : CELL_OTHER;
		if (sub) {
			o->n_op = 2u;
			o->o[0] = a;
			o->o[1] = b;
		}
		return;
	}
	if (!sub && !s && imm == 0) {
		/* add xd,xn,#0 is a move (sp is where the assembler
		 * spells it so); a move is the form the map copies. */
		o->op = CELL_MOV;
		wr_sp(o, rd);
		o->n_op = 2u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
		o->o[1] = a;
		return;
	}
	emit_bin(o, cls, sz, rd, !s, &a, &b);
}

/* smax, umax, smin, umin (FEAT_CSSC) */
static void h_minmax_imm(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	other_rd(o, gt_arm64_rd(in), gt_arm64_sf(in) ? 8u : 4u, 0);
}

static void h_logic_imm(struct cell_insn *o, const struct gt_arm64_insn *in,
			uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in);
	struct cell_operand a, b;

	(void)va;
	o_zr(&a, rn, sz);
	o_imm(&b, gt_arm64_logical_imm(in), sz);
	if (in->id == GT_ARM64_I_ANDS_IMM) {    /* ands / tst */
		if (rd == 31u) {
			o->op = CELL_TEST;
			o->n_op = 2u;
			o->o[0] = a;
			o->o[1] = b;
			return;
		}
		emit_bin(o, cls, sz, rd, 0, &a, &b);
		return;
	}
	emit_bin(o, cls, sz, rd, 1, &a, &b);
}

static void h_movn_movz(struct cell_insn *o, const struct gt_arm64_insn *in,
			uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u, rd = gt_arm64_rd(in);
	uint64_t imm = gt_arm64_movw_imm(in);

	(void)va;
	if (in->id == GT_ARM64_I_MOVN)
		imm = ~imm & szmask(sz);
	if (rd == 31u) {
		nop(o);
		return;
	}
	o->op = (uint8_t)cls;
	wr_zr(o, rd);
	o->n_op = 2u;
	o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
	o_imm(&o->o[1], imm, sz);
}

/*
 * movk replaces sixteen bits and keeps the rest. No class carries that, so it is
 * CELL_OTHER with the facts a consumer needs to fold it itself: o[1]=the bits to
 * OR in, o[2]=the mask they replace - new = (old & ~o[2]) | o[1]. MEASURED not to
 * fit the constant map: it has one source operand.
 */
static void h_movk(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u, rd = gt_arm64_rd(in);

	(void)va;
	o->op = (uint8_t)cls;
	if (rd == 31u)
		return;
	wr_zr(o, rd);
	o->n_op = 3u;
	o_reg(&o->o[0], rd, sz, CELL_OF_WRITE | CELL_OF_READ);
	o_imm(&o->o[1], gt_arm64_movw_imm(in), sz);
	o_imm(&o->o[2], 0xffffull << gt_arm64_movw_shift(in), sz);
}

static void h_bitfield(struct cell_insn *o, const struct gt_arm64_insn *in,
		       uint64_t va, unsigned cls)
{
	unsigned sf = gt_arm64_sf(in), sz = sf ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in);
	unsigned immr = gt_arm64_immr(in), imms = gt_arm64_imms(in);
	unsigned top = sf ? 63u : 31u;
	int sbfm = in->id == GT_ARM64_I_SBFM, ubfm = in->id == GT_ARM64_I_UBFM;
	struct cell_operand a, b;

	(void)va;
	(void)cls;
	if (rd == 31u) {
		o->op = CELL_OTHER;
		return;
	}
	o_zr(&a, rn, sz);
	if (in->id == GT_ARM64_I_BFM) {         /* bfm: bfi, bfxil, bfc */
		other_rd(o, rd, sz, 0);
		return;
	}
	if (ubfm && imms == top) {              /* lsr */
		o_imm(&b, immr, sz);
		emit_bin(o, CELL_SHR, sz, rd, 0, &a, &b);
	} else if (sbfm && imms == top) {       /* asr */
		o_imm(&b, immr, sz);
		emit_bin(o, CELL_SAR, sz, rd, 0, &a, &b);
	} else if (ubfm && imms != top && imms + 1u == immr) {
		o_imm(&b, top - imms, sz);      /* lsl */
		emit_bin(o, CELL_SHL, sz, rd, 0, &a, &b);
	} else if (immr == 0 && (imms == 7u || imms == 15u ||
				 (sbfm && sf && imms == 31u)) &&
		   (sbfm || !sf)) {
		/* uxtb/uxth (32-bit only) and sxtb/sxth/sxtw. A zero
		 * register source makes it the constant 0, which
		 * nothing needs a class for. */
		o->op = sbfm ? CELL_MOVSX : CELL_MOVZX;
		wr_zr(o, rd);
		o->n_op = 2u;
		o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
		o->o[1] = a;
		o->o[1].size = (uint8_t)(imms == 7u ? 1u : imms == 15u ? 2u : 4u);
	} else {
		other_rd(o, rd, sz, 0);
	}
	if (o->op != CELL_OTHER && o->op != CELL_NOP && o->n_op == 2u &&
	    o->o[1].kind == CELL_O_IMM && a.kind == CELL_O_IMM &&
	    (o->op == CELL_SHL || o->op == CELL_SHR || o->op == CELL_SAR)) {
		/* A shift of the zero register is the constant 0. */
		o->op = CELL_MOV;
		o_imm(&o->o[1], 0, sz);
	}
}

/* extr, and its ror alias when both sources are one register */
static void h_extr(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in), rm = gt_arm64_rm(in);

	(void)va;
	(void)cls;
	if (rn == rm && rn != 31u && rd != 31u) {       /* ror #imm */
		struct cell_operand a, b;

		o_reg(&a, rn, sz, CELL_OF_READ);
		o_imm(&b, gt_arm64_imms(in), sz);
		emit_bin(o, CELL_ROR, sz, rd, 0, &a, &b);
	} else {
		other_rd(o, rd, sz, 0);
	}
}

/* ---- branches, exception generation, system ------------------------------ */

static void h_branch_imm(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	o->op = (uint8_t)cls;
	o->n_op = 1u;
	o_rel(o, va + (uint64_t)gt_arm64_branch_off(in));
	if (cls == CELL_CALL)
		o->wmask |= 1ull << 30;
}

static void h_cbz(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	o->op = (uint8_t)cls;
	o->cond = (uint8_t)gt_arm64_bits(in, 24, 1);
	o->n_op = 2u;
	o_rel(o, va + (uint64_t)gt_arm64_branch_off(in));
	o_zr(&o->o[1], gt_arm64_rt(in), gt_arm64_sf(in) ? 8u : 4u);
}

static void h_tbz(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	o->op = (uint8_t)cls;
	o->cond = (uint8_t)gt_arm64_bits(in, 24, 1);
	o->n_op = 3u;
	o_rel(o, va + (uint64_t)gt_arm64_branch_off(in));
	o_zr(&o->o[1], gt_arm64_rt(in), gt_arm64_sf(in) ? 8u : 4u);
	o_imm(&o->o[2], gt_arm64_tbz_bit(in), 1u);
}

static void h_bcond(struct cell_insn *o, const struct gt_arm64_insn *in,
		    uint64_t va, unsigned cls)
{
	o->op = (uint8_t)cls;
	o->cond = (uint8_t)gt_arm64_cond_branch(in);
	o->n_op = 1u;
	o_rel(o, va + (uint64_t)gt_arm64_branch_off(in));
}

/* svc, hvc, smc, brk, hlt, dcps1..3, tcancel: the 16-bit immediate is the one operand */
static void h_exc(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	o->n_op = 1u;
	o_imm(&o->o[0], gt_arm64_imm16(in), 2u);
}

/*
 * Branch to a register. The forms that return from an exception or drop out of
 * debug state (eret, drps, eretaa, eretab) have no target register; the others
 * are indirect. The authenticating returns (retaa, retab) take lr, not Rn.
 */
static void h_breg(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned reg = gt_arm64_rn(in);

	(void)va;
	o->op = (uint8_t)cls;
	if (cls == CELL_IRET || cls == CELL_PRIV)
		return;
	if (in->id == GT_ARM64_I_RETAA || in->id == GT_ARM64_I_RETAB)
		reg = 30u;
	o->flags = CELL_F_INDIRECT;
	o->n_op = 1u;
	o_reg(&o->o[0], reg, 8u, CELL_OF_READ);
	if (reg == 31u)
		o_imm(&o->o[0], 0, 8u);
	if (cls == CELL_CALL)
		o->wmask |= 1ull << 30;
}

static void h_mrs(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	unsigned rt = gt_arm64_rt(in);

	(void)va;
	o->op = (uint8_t)cls;
	o->n_op = 2u;
	o_reg(&o->o[0], rt, 8u, CELL_OF_WRITE);
	o_imm(&o->o[1], gt_arm64_sysreg(in), 4u);
	wr_zr(o, rt);
	if (rt == 31u)
		o_dead(&o->o[0], 8u);
}

static void h_msr(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	o->n_op = 2u;
	o_imm(&o->o[0], gt_arm64_sysreg(in), 4u);
	o_zr(&o->o[1], gt_arm64_rt(in), 8u);
}

/* ---- loads and stores --------------------------------------------------- */

enum { LK_ST, LK_LD, LK_PF, LK_VST, LK_VLD };

struct lsk {
	uint8_t acc;            /* bytes accessed */
	uint8_t dsz;            /* destination register size, 4 or 8 */
	uint8_t kind;           /* LK_* */
};

/* what genotype says a single-register access does with its register, in this file's terms */
static const uint8_t g_lk[] = {
	[GT_ARM64_K_STORE] = LK_ST, [GT_ARM64_K_LOAD] = LK_LD,
	[GT_ARM64_K_LOAD_S64] = LK_LD, [GT_ARM64_K_LOAD_S32] = LK_LD,
	[GT_ARM64_K_PREFETCH] = LK_PF, [GT_ARM64_K_STORE_FP] = LK_VST,
	[GT_ARM64_K_LOAD_FP] = LK_VLD
};

/* The access of a single-register identity: its size, the width of the register it moves and what it does. */
static void lsk_of(struct lsk *k, const struct gt_arm64_insn *in)
{
	unsigned kd = gt_arm64_lskind(in);

	k->acc = (uint8_t)gt_arm64_ldst_bytes(in);
	k->dsz = kd == GT_ARM64_K_LOAD_S64 ? 8u
	       : kd == GT_ARM64_K_LOAD_S32 ? 4u
	       : gt_arm64_size(in) == 3u ? 8u : 4u;
	k->kind = g_lk[kd];
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

/*
 * One register, any address form. The form is genotype's (amode): an unsigned or
 * unscaled offset is [Xn, #off]; a post-index access is [Xn] with the increment
 * as o[2]; a pre-index access carries the increment as disp; a register offset
 * is index and scale (S, bit 12, scales the index by the access size).
 */
static void h_ls_single(struct cell_insn *o, const struct gt_arm64_insn *in,
			uint64_t va, unsigned cls)
{
	unsigned rn = gt_arm64_rn(in), rt = gt_arm64_rt(in);
	unsigned am = gt_arm64_amode(in);
	struct lsk k;
	struct cell_operand m;

	(void)va;
	(void)cls;
	lsk_of(&k, in);
	switch (am) {
	case GT_ARM64_AM_POST: {
		int64_t inc = gt_arm64_ldst_off(in);

		o_mem(&m, rn, 0, k.acc, 0);
		ls_emit(o, &k, rt, &m, rn, 1, inc);
		break;
	}
	case GT_ARM64_AM_PRE:
		o_mem(&m, rn, gt_arm64_ldst_off(in), k.acc, 0);
		ls_emit(o, &k, rt, &m, rn, 0, 0);
		break;
	case GT_ARM64_AM_REG: {
		unsigned rm = gt_arm64_rm(in);

		o_mem(&m, rn, 0, k.acc, 0);
		if (rm != 31u)
			m.index = (uint8_t)rm;
		if (gt_arm64_bits(in, 12, 1)) {
			unsigned sh = k.acc == 16u ? 4u : gt_arm64_size(in);

			m.scale = (uint8_t)(1u << sh);
		}
		ls_emit(o, &k, rt, &m, 32u, 0, 0);
		break;
	}
	default:                                /* unsigned offset, unscaled, unprivileged */
		o_mem(&m, rn, gt_arm64_ldst_off(in), k.acc, 0);
		ls_emit(o, &k, rt, &m, 32u, 0, 0);
		break;
	}
}

/* ldr (literal), ldrsw (literal), prfm (literal) */
static void h_ls_literal(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	struct lsk k;
	struct cell_operand m;

	(void)va;
	(void)cls;
	if (in->id == GT_ARM64_I_PRFM_LIT) {
		o->op = CELL_OTHER;
		return;
	}
	k.acc = (uint8_t)gt_arm64_ldst_bytes(in);
	k.dsz = in->id == GT_ARM64_I_LDR_LIT_W ? 4u : 8u;
	k.kind = in->id == GT_ARM64_I_LDR_LIT_FP ? LK_VLD : LK_LD;
	o_mem(&m, NOREG, gt_arm64_ldst_off(in), k.acc, CELL_OF_RIPREL);
	ls_emit(o, &k, gt_arm64_rt(in), &m, 32u, 0, 0);
}

static void h_ls_pair(struct cell_insn *o, const struct gt_arm64_insn *in,
		      uint64_t va, unsigned cls)
{
	unsigned rn = gt_arm64_rn(in), rt = gt_arm64_rt(in), rt2 = gt_arm64_rt2(in);
	unsigned opc = gt_arm64_size(in), l = gt_arm64_bits(in, 22, 1);
	unsigned am = gt_arm64_amode(in), kd = gt_arm64_lskind(in);
	unsigned acc = gt_arm64_ldst_bytes(in);
	unsigned dsz = opc == 1u || opc == 2u ? 8u : 4u;
	int64_t disp = gt_arm64_ldst_off(in);
	struct cell_operand m;

	(void)va;
	(void)cls;
	if (am == GT_ARM64_AM_POST)
		disp = 0;               /* post-index: the access is [base] */
	o_mem(&m, rn, disp, acc * 2u, l ? CELL_OF_READ : CELL_OF_WRITE);
	o->op = CELL_OTHER;
	if (am == GT_ARM64_AM_POST || am == GT_ARM64_AM_PRE)
		wr_sp(o, rn);
	if (kd == GT_ARM64_K_STORE_FP || kd == GT_ARM64_K_LOAD_FP) {
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

/* ldxr, ldaxr, ldar, ldlar, stlr, stllr, ldapr: a plain access through [Xn] */
static void h_ls_ordered(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	unsigned size = gt_arm64_size(in), l = gt_arm64_bits(in, 22, 1);
	struct lsk k;
	struct cell_operand m;

	(void)va;
	(void)cls;
	k.acc = (uint8_t)(1u << size);
	k.dsz = size == 3u ? 8u : 4u;
	k.kind = in->id == GT_ARM64_I_STLR ? LK_ST : LK_LD;
	/* ldapr is the one that builds its operand with no direction */
	o_mem(&m, gt_arm64_rn(in), 0, k.acc,
	      in->id == GT_ARM64_I_LDAPR ? 0u : l ? CELL_OF_READ : CELL_OF_WRITE);
	ls_emit(o, &k, gt_arm64_rt(in), &m, 32u, 0, 0);
}

/* stxr, stlxr: the status goes to Rs */
static void h_stxr(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned size = gt_arm64_size(in), rs = gt_arm64_rs(in);
	unsigned dsz = size == 3u ? 8u : 4u;
	struct cell_operand m;

	(void)va;
	(void)cls;
	o_mem(&m, gt_arm64_rn(in), 0, 1u << size, CELL_OF_WRITE);
	o->op = CELL_OTHER;
	o->n_op = 3u;
	o_reg(&o->o[0], rs, 4u, CELL_OF_WRITE);
	o_zr(&o->o[1], gt_arm64_rt(in), dsz);
	o->o[2] = m;
	if (rs == 31u)
		o_dead(&o->o[0], 4u);
	else
		wr_zr(o, rs);
}

/* ldxp, ldaxp: two registers loaded */
static void h_ldxp(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned rt = gt_arm64_rt(in), rt2 = gt_arm64_rt2(in);
	unsigned psz = gt_arm64_size(in) == 3u ? 8u : 4u;

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	o->n_op = 3u;
	o_reg(&o->o[0], rt, psz, CELL_OF_WRITE);
	o_reg(&o->o[1], rt2, psz, CELL_OF_WRITE);
	wr_zr(o, rt);
	wr_zr(o, rt2);
	if (rt == 31u)
		o_dead(&o->o[0], psz);
	if (rt2 == 31u)
		o_dead(&o->o[1], psz);
	o_mem(&o->o[2], gt_arm64_rn(in), 0, psz * 2u, CELL_OF_READ);
}

/* stxp, stlxp: two registers stored, the status goes to Rs */
static void h_stxp(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned rs = gt_arm64_rs(in);
	unsigned psz = gt_arm64_size(in) == 3u ? 8u : 4u;

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	o->n_op = 3u;
	o_reg(&o->o[0], rs, 4u, CELL_OF_WRITE);
	o_zr(&o->o[1], gt_arm64_rt(in), psz);
	o_mem(&o->o[2], gt_arm64_rn(in), 0, psz * 2u, CELL_OF_WRITE);
	wr_zr(o, rs);
	if (rs == 31u)
		o_dead(&o->o[0], 4u);
}

/* casp: a register pair, which the architecture takes as an even Rs and Rt (genotype has checked) */
static void h_casp(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned size = gt_arm64_size(in), rs = gt_arm64_rs(in);

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	o->n_op = 3u;
	o_reg(&o->o[0], rs, 4u << size, CELL_OF_WRITE | CELL_OF_READ);
	o_reg(&o->o[1], gt_arm64_rt(in), 4u << size, CELL_OF_READ);
	o_mem(&o->o[2], gt_arm64_rn(in), 0, 8u << size, CELL_OF_READ | CELL_OF_WRITE);
	if (rs != 31u) {
		wr_zr(o, rs);
		wr_zr(o, rs + 1u);
	} else {
		o_dead(&o->o[0], 4u << size);
	}
}

/* cas, casa, casl, casal: Rs is compared with memory and receives the old value */
static void h_cas(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	unsigned size = gt_arm64_size(in), rs = gt_arm64_rs(in);
	unsigned dsz = size == 3u ? 8u : 4u;

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	o->n_op = 3u;
	o_reg(&o->o[0], rs, dsz, CELL_OF_WRITE | CELL_OF_READ);
	o_zr(&o->o[1], gt_arm64_rt(in), dsz);
	o_mem(&o->o[2], gt_arm64_rn(in), 0, 1u << size, CELL_OF_READ | CELL_OF_WRITE);
	if (rs == 31u)
		o_dead(&o->o[0], dsz);
	else
		wr_zr(o, rs);
}

/* ldadd.. and swp: Rs is the operand, Rt receives the old value */
static void h_atomic(struct cell_insn *o, const struct gt_arm64_insn *in,
		     uint64_t va, unsigned cls)
{
	unsigned size = gt_arm64_size(in), rt = gt_arm64_rt(in);
	unsigned dsz = size == 3u ? 8u : 4u;

	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	o->n_op = 3u;
	o_zr(&o->o[0], gt_arm64_rs(in), dsz);
	o_reg(&o->o[1], rt, dsz, CELL_OF_WRITE);
	o_mem(&o->o[2], gt_arm64_rn(in), 0, 1u << size, CELL_OF_READ | CELL_OF_WRITE);
	if (rt == 31u)
		o_dead(&o->o[1], dsz);
	else
		wr_zr(o, rt);
}

/*
 * FEAT_LS64: ld64b and st64b move eight consecutive registers, st64bv and
 * st64bv0 also return a status in Rs.
 */
static void h_ls64(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	(void)va;
	(void)cls;
	o->op = CELL_OTHER;
	o->n_op = 1u;
	o_mem(&o->o[0], gt_arm64_rn(in), 0, 64u,
	      in->id == GT_ARM64_I_LD64B ? CELL_OF_READ : CELL_OF_WRITE);
	if (in->id == GT_ARM64_I_LD64B)
		o->wmask |= 0xffull << gt_arm64_rt(in);
	else if (in->id != GT_ARM64_I_ST64B)
		wr_zr(o, gt_arm64_rs(in));
}

/* ldraa, ldrab: a pointer-authenticated load, with writeback in the pre-index form */
static void h_ldra(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	struct lsk k;
	struct cell_operand m;
	unsigned rn = gt_arm64_rn(in);
	int pre = in->id == GT_ARM64_I_LDRAA_PRE || in->id == GT_ARM64_I_LDRAB_PRE;

	(void)va;
	(void)cls;
	k.acc = 8u;
	k.dsz = 8u;
	k.kind = LK_LD;
	o_mem(&m, rn, gt_arm64_ldst_off(in), 8u, 0);
	ls_emit(o, &k, gt_arm64_rt(in), &m, pre ? rn : 32u, 0, 0);
}

/* Advanced SIMD load/store structures: only the base register of a post-indexed form is written. */
static void h_simd_struct(struct cell_insn *o, const struct gt_arm64_insn *in,
			  uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	if (in->id == GT_ARM64_I_SIMD_STRUCT_MULT_POST ||
	    in->id == GT_ARM64_I_SIMD_STRUCT_SINGLE_POST)
		wr_sp(o, gt_arm64_rn(in));
}

/*
 * FEAT_MOPS: the cpyf and cpy families (prologue, main, epilogue) and the set and
 * setg families. Both rewrite the pointer and count registers they name: a copy
 * all three, a set the destination and the count (the data register is only
 * read).
 */
static void h_mops(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	wr_zr(o, gt_arm64_rt(in));
	wr_zr(o, gt_arm64_rn(in));
	if (in->id == GT_ARM64_I_MOPS_CPY)
		wr_zr(o, gt_arm64_rs(in));
}

/* Memory tags (FEAT_MTE): the post- and pre-indexed stores write their base. */
static void h_tag_store(struct cell_insn *o, const struct gt_arm64_insn *in,
			uint64_t va, unsigned cls)
{
	(void)va;
	o->op = (uint8_t)cls;
	if (gt_arm64_amode(in) != GT_ARM64_AM_OFFSET)
		wr_sp(o, gt_arm64_rn(in));
}

/* ---- data processing: register ------------------------------------------ */

/* logical, shifted register */
static void h_logic_reg(struct cell_insn *o, const struct gt_arm64_insn *in,
			uint64_t va, unsigned cls)
{
	unsigned sf = gt_arm64_sf(in), sz = sf ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in), rm = gt_arm64_rm(in);
	unsigned opc = gt_arm64_bits(in, 29, 2), nn = gt_arm64_bits(in, 21, 1);
	int plain = gt_arm64_bits(in, 10, 6) == 0;
	struct cell_operand a, b;

	(void)va;
	o_zr(&a, rn, sz);
	o_zr(&b, rm, sz);
	if (opc == 3u && rd == 31u) {           /* tst, bics xzr */
		o->op = nn ? CELL_OTHER : CELL_TEST;
		if (!nn && plain) {
			o->n_op = 2u;
			o->o[0] = a;
			o->o[1] = b;
		} else {
			o->op = CELL_OTHER;
		}
		return;
	}
	if (nn) {
		if (opc == 1u && rn == 31u && plain) {
			/* mvn */
			if (rd == 31u) {
				nop(o);
			} else if (b.kind == CELL_O_REG && b.reg == rd) {
				o->op = CELL_NOT;
				wr_zr(o, rd);
				o->n_op = 1u;
				o_reg(&o->o[0], rd, sz, CELL_OF_WRITE | CELL_OF_READ);
			} else if (b.kind == CELL_O_IMM) {
				o->op = CELL_MOV;
				wr_zr(o, rd);
				o->n_op = 2u;
				o_reg(&o->o[0], rd, sz, CELL_OF_WRITE);
				o_imm(&o->o[1], szmask(sz), sz);
			} else {
				other_rd(o, rd, sz, 0);
			}
			return;
		}
		other_rd(o, rd, sz, 0);         /* bic, orn, eon */
		return;
	}
	if (!plain) {
		/* orr xd,xzr,xm,shift #n: the shifted move; its shifted value is
		 * no operand a class can state. */
		other_rd(o, rd, sz, 0);
		return;
	}
	emit_bin(o, cls, sz, rd, 0, &a, &b);
}

/* add, adds, sub, subs: shifted register */
static void h_addsub_reg(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in), rm = gt_arm64_rm(in);
	unsigned op = cls == CELL_SUB, s = gt_arm64_bits(in, 29, 1);
	int plain = gt_arm64_bits(in, 10, 6) == 0;
	struct cell_operand a, b;

	(void)va;
	o_zr(&a, rn, sz);
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
		other_rd(o, rd, sz, 0);
		return;
	}
	emit_bin(o, cls, sz, rd, 0, &a, &b);
}

/* add, adds, sub, subs: extended register */
static void h_addsub_ext(struct cell_insn *o, const struct gt_arm64_insn *in,
			 uint64_t va, unsigned cls)
{
	unsigned sf = gt_arm64_sf(in), sz = sf ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in), rm = gt_arm64_rm(in);
	unsigned op = cls == CELL_SUB, s = gt_arm64_bits(in, 29, 1);
	unsigned option = gt_arm64_bits(in, 13, 3), imm3 = gt_arm64_bits(in, 10, 3);
	int plain = option == (sf ? 3u : 2u) && imm3 == 0;
	struct cell_operand a, b;

	(void)va;
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
	emit_bin(o, cls, sz, rd, !s, &a, &b);
}

/* madd, msub, smaddl, smsubl, smulh, umaddl, umsubl, umulh */
static void h_mul3(struct cell_insn *o, const struct gt_arm64_insn *in,
		   uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in), rn = gt_arm64_rn(in), rm = gt_arm64_rm(in);
	unsigned op31 = gt_arm64_bits(in, 21, 3), o0 = gt_arm64_bits(in, 15, 1);
	unsigned ra = gt_arm64_ra(in);
	struct cell_operand a, b;

	(void)va;
	(void)cls;
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
		emit_bin(o, op31 >= 5u ? CELL_MUL : CELL_IMUL, 8u, rd, 0, &a, &b);
	} else {                                /* madd, msub, smaddl, ... */
		other_rd(o, rd, sz, 0);
	}
}

/* adc, adcs, sbc, sbcs */
static void h_adc(struct cell_insn *o, const struct gt_arm64_insn *in,
		  uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	unsigned rd = gt_arm64_rd(in);
	unsigned s = gt_arm64_bits(in, 29, 1);
	struct cell_operand a, b;

	(void)va;
	o_zr(&a, gt_arm64_rn(in), sz);
	o_zr(&b, gt_arm64_rm(in), sz);
	if (rd == 31u && !s) {
		nop(o);
		return;
	}
	if (rd == 31u) {
		o->op = CELL_OTHER;
		return;
	}
	emit_bin(o, cls, sz, rd, 0, &a, &b);
	if (o->op == CELL_MOV)
		o->op = CELL_OTHER, o->n_op = 1u;
}

/* udiv, sdiv, lslv, lsrv, asrv, rorv */
static void h_shift_div(struct cell_insn *o, const struct gt_arm64_insn *in,
			uint64_t va, unsigned cls)
{
	unsigned sz = gt_arm64_sf(in) ? 8u : 4u;
	struct cell_operand a, b;

	(void)va;
	o_zr(&a, gt_arm64_rn(in), sz);
	o_zr(&b, gt_arm64_rm(in), sz);
	emit_bin(o, cls, sz, gt_arm64_rd(in), 0, &a, &b);
	if (o->op == CELL_MOV) {
		o->op = CELL_OTHER;
		o->n_op = 1u;
	}
}

/* ---- the table ---------------------------------------------------------- */

#define E(id, cls, fn) [GT_ARM64_I_##id] = { (uint8_t)(cls), fn }

static const struct a64_ent g_ent[GT_ARM64_I_COUNT] = {
	E(INVALID, CELL_UD, h_ud), E(UDF, CELL_UD, h_ud),
	E(SME, CELL_OTHER, h_class), E(SVE, CELL_OTHER, h_class),
	E(ADDVL, CELL_OTHER, h_sve_sp), E(ADDPL, CELL_OTHER, h_sve_sp),
	E(RDVL, CELL_OTHER, h_sve_zr), E(CNTELEM, CELL_OTHER, h_sve_zr),
	E(INCDECELEM, CELL_OTHER, h_sve_zr), E(SQINCDECELEM, CELL_OTHER, h_sve_zr),
	E(CNTP, CELL_OTHER, h_sve_zr), E(INCDECP, CELL_OTHER, h_sve_zr),
	E(SQINCDECP, CELL_OTHER, h_sve_zr), E(LASTAB, CELL_OTHER, h_sve_zr),
	E(CLASTAB, CELL_OTHER, h_sve_zr),

	E(FPSIMD, CELL_OTHER, h_class),
	E(FCVTS_GP, CELL_OTHER, h_fp_to_gp), E(FCVTU_GP, CELL_OTHER, h_fp_to_gp),
	E(SCVTF_GP, CELL_OTHER, h_class), E(UCVTF_GP, CELL_OTHER, h_class),
	E(FCVTAS_GP, CELL_OTHER, h_fp_to_gp), E(FCVTAU_GP, CELL_OTHER, h_fp_to_gp),
	E(FMOV_FP_TO_GP, CELL_OTHER, h_fp_to_gp), E(FMOV_GP_TO_FP, CELL_OTHER, h_class),
	E(FJCVTZS, CELL_OTHER, h_fp_to_gp),
	E(FMOV_TOP_TO_GP, CELL_OTHER, h_fp_to_gp), E(FMOV_TOP_FROM_GP, CELL_OTHER, h_class),
	E(FCVTZS_FIXED, CELL_OTHER, h_fp_to_gp), E(FCVTZU_FIXED, CELL_OTHER, h_fp_to_gp),
	E(SCVTF_FIXED, CELL_OTHER, h_class), E(UCVTF_FIXED, CELL_OTHER, h_class),
	E(SMOV, CELL_OTHER, h_simd_to_gp), E(UMOV, CELL_OTHER, h_simd_to_gp),

	E(ADR, CELL_LEA, h_adr), E(ADRP, CELL_LEA, h_adr),
	E(ADD_IMM, CELL_ADD, h_addsub_imm), E(ADDS_IMM, CELL_ADD, h_addsub_imm),
	E(SUB_IMM, CELL_SUB, h_addsub_imm), E(SUBS_IMM, CELL_SUB, h_addsub_imm),
	E(SMAX_IMM, CELL_OTHER, h_minmax_imm), E(UMAX_IMM, CELL_OTHER, h_minmax_imm),
	E(SMIN_IMM, CELL_OTHER, h_minmax_imm), E(UMIN_IMM, CELL_OTHER, h_minmax_imm),
	E(ADDG, CELL_OTHER, h_rd64_sp), E(SUBG, CELL_OTHER, h_rd64_sp),
	E(AND_IMM, CELL_AND, h_logic_imm), E(ORR_IMM, CELL_OR, h_logic_imm),
	E(EOR_IMM, CELL_XOR, h_logic_imm), E(ANDS_IMM, CELL_AND, h_logic_imm),
	E(MOVN, CELL_MOV, h_movn_movz), E(MOVZ, CELL_MOV, h_movn_movz),
	E(MOVK, CELL_OTHER, h_movk),
	E(SBFM, CELL_OTHER, h_bitfield), E(BFM, CELL_OTHER, h_bitfield),
	E(UBFM, CELL_OTHER, h_bitfield), E(EXTR, CELL_OTHER, h_extr),

	E(B, CELL_JMP, h_branch_imm), E(BL, CELL_CALL, h_branch_imm),
	E(CBZ, CELL_JCC, h_cbz), E(CBNZ, CELL_JCC, h_cbz), E(BCOND, CELL_JCC, h_bcond),
	E(TBZ, CELL_JCC, h_tbz), E(TBNZ, CELL_JCC, h_tbz),
	E(SVC, CELL_SYSCALL, h_exc), E(HVC, CELL_PRIV, h_exc), E(SMC, CELL_PRIV, h_exc),
	E(BRK, CELL_INT, h_exc), E(HLT, CELL_INT, h_exc),
	E(DCPS1, CELL_PRIV, h_exc), E(DCPS2, CELL_PRIV, h_exc), E(DCPS3, CELL_PRIV, h_exc),
	E(TCANCEL, CELL_OTHER, h_exc),
	E(BR, CELL_JMP, h_breg), E(BLR, CELL_CALL, h_breg), E(RET, CELL_RET, h_breg),
	E(ERET, CELL_IRET, h_breg), E(DRPS, CELL_PRIV, h_breg),
	E(BRAAZ, CELL_JMP, h_breg), E(BRABZ, CELL_JMP, h_breg),
	E(BLRAAZ, CELL_CALL, h_breg), E(BLRABZ, CELL_CALL, h_breg),
	E(BRAA, CELL_JMP, h_breg), E(BRAB, CELL_JMP, h_breg),
	E(BLRAA, CELL_CALL, h_breg), E(BLRAB, CELL_CALL, h_breg),
	E(RETAA, CELL_RET, h_breg), E(RETAB, CELL_RET, h_breg),
	E(ERETAA, CELL_IRET, h_breg), E(ERETAB, CELL_IRET, h_breg),

	E(MRS, CELL_PRIV, h_mrs), E(MSR, CELL_PRIV, h_msr),
	E(SYS, CELL_OTHER, h_class), E(SYSL, CELL_OTHER, h_wr_rt),
	E(TSTART, CELL_OTHER, h_wr_rt), E(TTEST, CELL_OTHER, h_wr_rt),
	E(TCOMMIT, CELL_OTHER, h_class), E(HINT, CELL_NOP, h_class),
	E(XPACLRI, CELL_OTHER, h_hint_lr), E(HINT_PAC_LR, CELL_OTHER, h_hint_lr),
	E(HINT_PAC_X17, CELL_OTHER, h_hint_x17), E(CHKFEAT, CELL_OTHER, h_hint_x16),
	E(CLREX, CELL_OTHER, h_class), E(DSB, CELL_OTHER, h_class),
	E(DSB_NXS, CELL_OTHER, h_class), E(DMB, CELL_OTHER, h_class),
	E(ISB, CELL_OTHER, h_class), E(SB, CELL_OTHER, h_class),
	E(MSR_PSTATE, CELL_PRIV, h_class),
	E(WFET, CELL_NOP, h_class), E(WFIT, CELL_NOP, h_class),

	E(STXR, CELL_OTHER, h_stxr), E(LDXR, CELL_OTHER, h_ls_ordered),
	E(STXP, CELL_OTHER, h_stxp), E(LDXP, CELL_OTHER, h_ldxp),
	E(CASP, CELL_OTHER, h_casp), E(STLR, CELL_OTHER, h_ls_ordered),
	E(LDAR, CELL_OTHER, h_ls_ordered), E(CAS, CELL_OTHER, h_cas),
	E(LDADD, CELL_OTHER, h_atomic), E(LDCLR, CELL_OTHER, h_atomic),
	E(LDEOR, CELL_OTHER, h_atomic), E(LDSET, CELL_OTHER, h_atomic),
	E(LDSMAX, CELL_OTHER, h_atomic), E(LDSMIN, CELL_OTHER, h_atomic),
	E(LDUMAX, CELL_OTHER, h_atomic), E(LDUMIN, CELL_OTHER, h_atomic),
	E(SWP, CELL_OTHER, h_atomic), E(LDAPR, CELL_OTHER, h_ls_ordered),
	E(ST64B, CELL_OTHER, h_ls64), E(ST64BV0, CELL_OTHER, h_ls64),
	E(ST64BV, CELL_OTHER, h_ls64), E(LD64B, CELL_OTHER, h_ls64),
	E(LDRAA, CELL_OTHER, h_ldra), E(LDRAB, CELL_OTHER, h_ldra),
	E(LDRAA_PRE, CELL_OTHER, h_ldra), E(LDRAB_PRE, CELL_OTHER, h_ldra),
	E(SIMD_STRUCT_MULT, CELL_OTHER, h_simd_struct),
	E(SIMD_STRUCT_MULT_POST, CELL_OTHER, h_simd_struct),
	E(SIMD_STRUCT_SINGLE, CELL_OTHER, h_simd_struct),
	E(SIMD_STRUCT_SINGLE_POST, CELL_OTHER, h_simd_struct),
	E(MOPS_CPY, CELL_OTHER, h_mops), E(MOPS_SET, CELL_OTHER, h_mops),
	E(LDG, CELL_OTHER, h_wr_rt), E(STGM, CELL_OTHER, h_class),
	E(STZGM, CELL_OTHER, h_class), E(LDGM, CELL_OTHER, h_wr_rt),
	E(STG_POST, CELL_OTHER, h_tag_store), E(STG_OFF, CELL_OTHER, h_tag_store),
	E(STG_PRE, CELL_OTHER, h_tag_store), E(STZG_POST, CELL_OTHER, h_tag_store),
	E(STZG_OFF, CELL_OTHER, h_tag_store), E(STZG_PRE, CELL_OTHER, h_tag_store),
	E(ST2G_POST, CELL_OTHER, h_tag_store), E(ST2G_OFF, CELL_OTHER, h_tag_store),
	E(ST2G_PRE, CELL_OTHER, h_tag_store), E(STZ2G_POST, CELL_OTHER, h_tag_store),
	E(STZ2G_OFF, CELL_OTHER, h_tag_store), E(STZ2G_PRE, CELL_OTHER, h_tag_store),

	E(LDR_LIT_W, CELL_MOV, h_ls_literal), E(LDR_LIT_X, CELL_MOV, h_ls_literal),
	E(LDRSW_LIT, CELL_MOV, h_ls_literal), E(PRFM_LIT, CELL_OTHER, h_ls_literal),
	E(LDR_LIT_FP, CELL_OTHER, h_ls_literal),

	E(STR_UOFF, CELL_MOV, h_ls_single), E(LDR_UOFF, CELL_MOV, h_ls_single),
	E(LDRS64_UOFF, CELL_MOV, h_ls_single), E(LDRS32_UOFF, CELL_MOV, h_ls_single),
	E(PRFM_UOFF, CELL_OTHER, h_ls_single),
	E(STR_FP_UOFF, CELL_OTHER, h_ls_single), E(LDR_FP_UOFF, CELL_OTHER, h_ls_single),
	E(STUR, CELL_MOV, h_ls_single), E(LDUR, CELL_MOV, h_ls_single),
	E(LDURS64, CELL_MOV, h_ls_single), E(LDURS32, CELL_MOV, h_ls_single),
	E(PRFUM, CELL_OTHER, h_ls_single),
	E(STUR_FP, CELL_OTHER, h_ls_single), E(LDUR_FP, CELL_OTHER, h_ls_single),
	E(STR_POST, CELL_MOV, h_ls_single), E(LDR_POST, CELL_MOV, h_ls_single),
	E(LDRS64_POST, CELL_MOV, h_ls_single), E(LDRS32_POST, CELL_MOV, h_ls_single),
	E(STR_FP_POST, CELL_OTHER, h_ls_single), E(LDR_FP_POST, CELL_OTHER, h_ls_single),
	E(STR_PRE, CELL_MOV, h_ls_single), E(LDR_PRE, CELL_MOV, h_ls_single),
	E(LDRS64_PRE, CELL_MOV, h_ls_single), E(LDRS32_PRE, CELL_MOV, h_ls_single),
	E(STR_FP_PRE, CELL_OTHER, h_ls_single), E(LDR_FP_PRE, CELL_OTHER, h_ls_single),
	E(STTR, CELL_MOV, h_ls_single), E(LDTR, CELL_MOV, h_ls_single),
	E(LDTRS64, CELL_MOV, h_ls_single), E(LDTRS32, CELL_MOV, h_ls_single),
	E(STR_REG, CELL_MOV, h_ls_single), E(LDR_REG, CELL_MOV, h_ls_single),
	E(LDRS64_REG, CELL_MOV, h_ls_single), E(LDRS32_REG, CELL_MOV, h_ls_single),
	E(PRFM_REG, CELL_OTHER, h_ls_single),
	E(STR_FP_REG, CELL_OTHER, h_ls_single), E(LDR_FP_REG, CELL_OTHER, h_ls_single),
	E(STLUR, CELL_MOV, h_ls_single), E(LDAPUR, CELL_MOV, h_ls_single),
	E(LDAPURS64, CELL_MOV, h_ls_single), E(LDAPURS32, CELL_MOV, h_ls_single),

	E(STNP, CELL_OTHER, h_ls_pair), E(LDNP, CELL_OTHER, h_ls_pair),
	E(STNP_FP, CELL_OTHER, h_ls_pair), E(LDNP_FP, CELL_OTHER, h_ls_pair),
	E(STP_POST, CELL_OTHER, h_ls_pair), E(STP_OFF, CELL_OTHER, h_ls_pair),
	E(STP_PRE, CELL_OTHER, h_ls_pair), E(LDP_POST, CELL_OTHER, h_ls_pair),
	E(LDP_OFF, CELL_OTHER, h_ls_pair), E(LDP_PRE, CELL_OTHER, h_ls_pair),
	E(STGP_POST, CELL_OTHER, h_ls_pair), E(STGP_OFF, CELL_OTHER, h_ls_pair),
	E(STGP_PRE, CELL_OTHER, h_ls_pair), E(LDPSW_POST, CELL_OTHER, h_ls_pair),
	E(LDPSW_OFF, CELL_OTHER, h_ls_pair), E(LDPSW_PRE, CELL_OTHER, h_ls_pair),
	E(STP_FP_POST, CELL_OTHER, h_ls_pair), E(STP_FP_OFF, CELL_OTHER, h_ls_pair),
	E(STP_FP_PRE, CELL_OTHER, h_ls_pair), E(LDP_FP_POST, CELL_OTHER, h_ls_pair),
	E(LDP_FP_OFF, CELL_OTHER, h_ls_pair), E(LDP_FP_PRE, CELL_OTHER, h_ls_pair),

	E(AND_REG, CELL_AND, h_logic_reg), E(BIC_REG, CELL_OTHER, h_logic_reg),
	E(ORR_REG, CELL_OR, h_logic_reg), E(ORN_REG, CELL_OTHER, h_logic_reg),
	E(EOR_REG, CELL_XOR, h_logic_reg), E(EON_REG, CELL_OTHER, h_logic_reg),
	E(ANDS_REG, CELL_AND, h_logic_reg), E(BICS_REG, CELL_OTHER, h_logic_reg),
	E(ADD_REG, CELL_ADD, h_addsub_reg), E(ADDS_REG, CELL_ADD, h_addsub_reg),
	E(SUB_REG, CELL_SUB, h_addsub_reg), E(SUBS_REG, CELL_SUB, h_addsub_reg),
	E(ADD_EXT, CELL_ADD, h_addsub_ext), E(ADDS_EXT, CELL_ADD, h_addsub_ext),
	E(SUB_EXT, CELL_SUB, h_addsub_ext), E(SUBS_EXT, CELL_SUB, h_addsub_ext),
	E(MADD, CELL_OTHER, h_mul3), E(MSUB, CELL_OTHER, h_mul3),
	E(SMADDL, CELL_OTHER, h_mul3), E(SMSUBL, CELL_OTHER, h_mul3),
	E(SMULH, CELL_OTHER, h_mul3), E(UMADDL, CELL_OTHER, h_mul3),
	E(UMSUBL, CELL_OTHER, h_mul3), E(UMULH, CELL_OTHER, h_mul3),
	E(ADC, CELL_ADC, h_adc), E(ADCS, CELL_ADC, h_adc),
	E(SBC, CELL_SBB, h_adc), E(SBCS, CELL_SBB, h_adc),
	E(SETF8, CELL_OTHER, h_class), E(SETF16, CELL_OTHER, h_class),
	E(RMIF, CELL_OTHER, h_class),
	E(CCMN_REG, CELL_OTHER, h_ccmp), E(CCMN_IMM, CELL_OTHER, h_ccmp),
	E(CCMP_REG, CELL_OTHER, h_ccmp), E(CCMP_IMM, CELL_OTHER, h_ccmp),
	E(CSEL, CELL_OTHER, h_csel), E(CSINC, CELL_OTHER, h_csel),
	E(CSINV, CELL_OTHER, h_csel), E(CSNEG, CELL_OTHER, h_csel),
	E(RBIT, CELL_OTHER, h_rd), E(REV16, CELL_OTHER, h_rd), E(REV, CELL_OTHER, h_rd),
	E(REV64, CELL_OTHER, h_rd), E(CLZ, CELL_OTHER, h_rd), E(CLS, CELL_OTHER, h_rd),
	E(PACIA, CELL_OTHER, h_rd), E(PACIB, CELL_OTHER, h_rd), E(PACDA, CELL_OTHER, h_rd),
	E(PACDB, CELL_OTHER, h_rd), E(AUTIA, CELL_OTHER, h_rd), E(AUTIB, CELL_OTHER, h_rd),
	E(AUTDA, CELL_OTHER, h_rd), E(AUTDB, CELL_OTHER, h_rd),
	E(PACIZA, CELL_OTHER, h_rd), E(PACIZB, CELL_OTHER, h_rd), E(PACDZA, CELL_OTHER, h_rd),
	E(PACDZB, CELL_OTHER, h_rd), E(AUTIZA, CELL_OTHER, h_rd), E(AUTIZB, CELL_OTHER, h_rd),
	E(AUTDZA, CELL_OTHER, h_rd), E(AUTDZB, CELL_OTHER, h_rd),
	E(XPACI, CELL_OTHER, h_rd), E(XPACD, CELL_OTHER, h_rd),
	E(UDIV, CELL_DIV, h_shift_div), E(SDIV, CELL_IDIV, h_shift_div),
	E(LSLV, CELL_SHL, h_shift_div), E(LSRV, CELL_SHR, h_shift_div),
	E(ASRV, CELL_SAR, h_shift_div), E(RORV, CELL_ROR, h_shift_div),
	E(SUBP, CELL_OTHER, h_rd64), E(SUBPS, CELL_OTHER, h_subps),
	E(IRG, CELL_OTHER, h_rd64_sp), E(GMI, CELL_OTHER, h_rd64), E(PACGA, CELL_OTHER, h_rd64),
	E(CRC32B, CELL_OTHER, h_rd), E(CRC32H, CELL_OTHER, h_rd), E(CRC32W, CELL_OTHER, h_rd),
	E(CRC32X, CELL_OTHER, h_rd), E(CRC32CB, CELL_OTHER, h_rd), E(CRC32CH, CELL_OTHER, h_rd),
	E(CRC32CW, CELL_OTHER, h_rd), E(CRC32CX, CELL_OTHER, h_rd)
};

/* ---- the entry point ---------------------------------------------------- */

/*
 * What every decode starts from: length 4, no operand, no register named, and
 * KOF_BROKEN - not (uint64_t)-1, see decode_mips.c - for a target there is not.
 *
 * COPIED, AND NOT CONST ON PURPOSE. Built as a memset and a handful of stores,
 * the 144-byte clear becomes `rep stos`, which costs more than the rest of the
 * instruction: MEASURED over 8.3 M words of real AArch64 code, one thread, the
 * decode took 22.2 ns that way and 16.8 ns when the structure is copied from this
 * template with vector moves (the decoder this one replaced spent 19.6 ns, with
 * the clear). A const template is folded back into the clear by the compiler;
 * this one is never written after it is built, which is the only property it
 * needs to be shared between threads.
 */
#define FRESH_OP { .reg = NOREG, .index = NOREG, .seg = NOREG }
static struct cell_insn g_fresh = {
	.len = 4u, .target = KOF_BROKEN, .target_va = KOF_BROKEN,
	.o = { FRESH_OP, FRESH_OP, FRESH_OP }
};

uint32_t cell_decode_arm64(const uint8_t *p, uint32_t n, uint64_t va,
			   struct cell_insn *out)
{
	struct gt_arm64_insn in;
	const struct a64_ent *e;
	uint32_t x;

	if (!p || n < 4u || !out)
		return 0;
	x = (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
	    (uint32_t)p[1] << 8 | p[0];

	*out = g_fresh;
	out->at = va;
	out->at_va = va;

	(void)gt_arm64_decode(&in, x);
	e = &g_ent[in.id];
	e->h(out, &in, va, e->cls);
	return 4u;
}
