/*
 * decode_ppc.c - PowerPC (32-bit and 64-bit, either byte order) into celllysis's one instruction form.
 *
 * THE DECODING IS GENOTYPE'S (libgenome/genotype/ppc): a table that says which instruction a word is.
 * This file is the translation, as decode_arm64.c is for AArch64: the class, the registers written and
 * the operand forms below. It reads the instruction through genotype's accessors and nowhere else.
 *
 * REGISTERS. r0..r31 are 0..31 in wmask and in an operand. The registers that are not GPRs but that an
 * instruction writes and a reader of the constant map must forget are named by number as well:
 * LR 32, CTR 33, XER 34, CR 35 (the whole condition register, as one: a Rc bit or a compare writes
 * one field of it and the map does not distinguish the fields). FPRs and vector registers have no
 * number: a floating point instruction is KGENOME_CELL_FPU with no operand, and its only wmask bits are
 * CR (Rc, compares). A register is size 4 in a 32-bit object and 8 in a 64-bit one.
 *
 * RA = 0 IS NOT r0. In addi, addis and every load and store form of address, a zero RA field means the
 * VALUE zero: `addi r3,0,5` is `li r3,5` (a KGENOME_CELL_MOV of #5) and `lwz r3,8(0)` is a memory
 * operand with no base register (reg KGENOME_CELL_REG_NONE).
 *
 * OPERAND FORMS (as decode_arm64.c).
 *   Two-operand ALU: when the first source is also the destination, `addi r3,r3,4` is o[0]=r3 (W|R)
 *   o[1]=#4; otherwise o[0]=rD (W) o[1]=src1 o[2]=src2, the three-operand form. A destination that is
 *   not the instruction's RT is the logical forms' RA (`or ra,rs,rb`): o[0]=ra o[1]=rs o[2]=rb.
 *   SUBF is `rD = rB - rA`: its operands are written minuend first, o[1]=rB o[2]=rA, so the class SUB
 *   means what it says. SUBFIC (imm - rA) and SUBFZE/SUBFME have no class that says so: KGENOME_CELL_OTHER.
 *   Load: KGENOME_CELL_MOV (KGENOME_CELL_MOVZX for lbz/lhz, KGENOME_CELL_MOVSX for lha/lwa) o[0]=rT (W) o[1]=MEM.
 *   Store: KGENOME_CELL_MOV o[0]=MEM (W) o[1]=rS. MEM: reg = base (NONE for RA=0), index = RB of an indexed
 *   form (scale 1), disp, size = bytes. An update form (lwzu, stwux...) also writes RA (wmask).
 *   A byte-reversed access (lwbrx, stwbrx) moves a DIFFERENT value than its class would say:
 *   KGENOME_CELL_OTHER. Floating point loads and stores are KGENOME_CELL_FPU with the MEM operand only.
 *   Branches: o[0] is KGENOME_CELL_O_REL for B/BC with the target in target_va (AA: the absolute address,
 *   wrapped to 32 bits in a 32-bit object); o[1]=BO, o[2]=BI (IMM) for BC. The class: B is JMP (CALL with
 *   LK); BC whose BO says "always" is the same; BC that decrements CTR is LOOP; other BC is JCC; BC with
 *   LK is a CALL (the get-pc idiom `bcl 20,31,.+4`, and a conditional call returns to the next
 *   instruction either way). BCLR / BCCTR are indirect: o[0]=REG LR / CTR, class RET (blr, LK clear),
 *   JMP|F_INDIRECT (bctr) or CALL|F_INDIRECT (LK set: blrl, bctrl). `cond` is 0 when BO says "always" and
 *   1 for any condition (a conditional return is a conditional EXIT: cfg_isa.c). A write of the link
 *   register by LK is in wmask; a CTR-decrementing branch writes CTR.
 *   sc: KGENOME_CELL_SYSCALL; wmask is the registers the Linux kernel ABI may change (r0, r3..r12, CR,
 *   CTR, XER) [Inference: the ELF ABI's volatile set, which the kernel's syscall ABI keeps].
 *
 * A 64-BIT OBJECT (`wide`): a 32-bit word operation (rlwinm and the rotates, slw, srw, sraw, srawi, mullw, mulhw,
 * divw ...) acts on the low word and defines the upper one in a way no class here says, so it is KGENOME_CELL_OTHER
 * with its writes kept; the 64-bit forms (ld, std, sld, mulld ...) have their classes. In a 32-bit object a 64-bit-only
 * word is UD (genotype refuses it: ppc.h). The constant map holds r0..r15 only (cell_state.h), so r16..r31 are
 * written (wmask) but never known: the limit is the map's, the next step is a 32-register map.
 * A branch target is the displacement against the instruction's own address; AA gives the absolute address,
 * sign-extended to 64 bits when wide and wrapped to 32 bits otherwise.
 *
 * WHAT IS NOT SAID. An UNSUPPORTED word (AltiVec, SPE, VSX, quad and pair loads: ppc.h) is
 * KGENOME_CELL_OTHER with length 4 and NO write: an SPE instruction writes a 64-bit GPR and an mfvsrd a
 * GPR, and this does not know which word is which - the constant map may keep a stale value for it.
 * An INVALID word is KGENOME_CELL_UD, length 4 (an instruction the table does not cover is, here, the
 * end of a walk, as with decode_arm64.c). lswx writes an unknown number of registers: every GPR.
 */
#include <string.h>

#include <celllysis/cell.h>
#include "decode.h"
#include <genotype/ppc/ppc.h>

#define R_LR  32u
#define R_CTR 33u
#define R_XER 34u
#define R_CR  35u
#define W(r)  (1ull << (r))
#define ALL_GPR 0xffffffffull

struct pc {
	struct kgenome_cell_insn *o;
	struct kgenome_ppc_insn in;
	uint64_t va;
	int wide;
};

static uint64_t trunc_to(const struct pc *c, int64_t v)
{
	return c->wide ? (uint64_t)v : (uint64_t)(uint32_t)v;
}

static void op_reg(struct pc *c, unsigned i, unsigned reg, unsigned flags)
{
	struct kgenome_cell_operand *p = &c->o->o[i];

	p->kind = KGENOME_CELL_O_REG;
	p->reg = (uint8_t)reg;
	p->size = c->wide ? 8u : 4u;
	p->flags = (uint8_t)flags;
}

static void op_imm(struct pc *c, unsigned i, uint64_t v)
{
	struct kgenome_cell_operand *p = &c->o->o[i];

	p->kind = KGENOME_CELL_O_IMM;
	p->imm = v;
	p->size = c->wide ? 8u : 4u;
}

static void op_mem(struct pc *c, unsigned i, unsigned base, unsigned index, int64_t disp, unsigned size,
		   unsigned flags)
{
	struct kgenome_cell_operand *p = &c->o->o[i];

	p->kind = KGENOME_CELL_O_MEM;
	p->reg = (uint8_t)base;
	p->index = (uint8_t)index;
	p->scale = 1;
	p->size = (uint8_t)size;
	p->flags = (uint8_t)flags;
	p->disp = disp;
}

/* rD = src1 (op) src2 where src2 is a register or an immediate: the two-operand form when rD is src1 */
static void alu(struct pc *c, unsigned cls, unsigned rd, unsigned rs1, int imm_form, uint64_t src2)
{
	c->o->op = (uint8_t)cls;
	c->o->wmask |= W(rd);
	if (rd == rs1) {
		op_reg(c, 0, rd, KGENOME_CELL_OF_WRITE | KGENOME_CELL_OF_READ);
		if (imm_form)
			op_imm(c, 1, src2);
		else
			op_reg(c, 1, (unsigned)src2, KGENOME_CELL_OF_READ);
		c->o->n_op = 2;
		return;
	}
	op_reg(c, 0, rd, KGENOME_CELL_OF_WRITE);
	op_reg(c, 1, rs1, KGENOME_CELL_OF_READ);
	if (imm_form)
		op_imm(c, 2, src2);
	else
		op_reg(c, 2, (unsigned)src2, KGENOME_CELL_OF_READ);
	c->o->n_op = 3;
}

/* rD = op(rS): the one-source forms (not, neg, extend), two operands, or one when rD is rS */
static void alu1(struct pc *c, unsigned cls, unsigned rd, unsigned rs, unsigned srcsize)
{
	c->o->op = (uint8_t)cls;
	c->o->wmask |= W(rd);
	if (rd == rs) {
		op_reg(c, 0, rd, KGENOME_CELL_OF_WRITE | KGENOME_CELL_OF_READ);
		c->o->n_op = 1;
	} else {
		op_reg(c, 0, rd, KGENOME_CELL_OF_WRITE);
		op_reg(c, 1, rs, KGENOME_CELL_OF_READ);
		c->o->n_op = 2;
	}
	if (srcsize)
		c->o->o[rd == rs ? 0 : 1].size = (uint8_t)srcsize;
}

static void mov_reg(struct pc *c, unsigned rd, unsigned rs)
{
	c->o->op = KGENOME_CELL_MOV;
	c->o->wmask |= W(rd);
	op_reg(c, 0, rd, KGENOME_CELL_OF_WRITE);
	op_reg(c, 1, rs, KGENOME_CELL_OF_READ);
	c->o->n_op = 2;
}

static void mov_imm(struct pc *c, unsigned rd, int64_t v)
{
	c->o->op = KGENOME_CELL_MOV;
	c->o->wmask |= W(rd);
	op_reg(c, 0, rd, KGENOME_CELL_OF_WRITE);
	op_imm(c, 1, trunc_to(c, v));
	c->o->n_op = 2;
}

/* The shared tail of every instruction that may record or overflow. */
static void flags_rc_oe(struct pc *c, int has_oe)
{
	if (kgenome_ppc_rc(&c->in))
		c->o->wmask |= W(R_CR);
	if (has_oe && kgenome_ppc_oe(&c->in))
		c->o->wmask |= W(R_XER);
}

/* ---- loads and stores ------------------------------------------------------------------------- */

enum { LS_LOAD, LS_LOADZ, LS_LOADS, LS_STORE, LS_OTHER, LS_FLOAD, LS_FSTORE };

static void ldst(struct pc *c, unsigned kind, unsigned size, int indexed, int update, int64_t disp)
{
	unsigned ra = kgenome_ppc_ra(&c->in), rt = kgenome_ppc_rt(&c->in), rb = kgenome_ppc_rb(&c->in);
	unsigned base, index = KGENOME_CELL_REG_NONE, mi, ri;
	unsigned mflags;

	if (indexed) {
		if (ra == 0 && !update) {
			base = rb;      /* EA = (0) + RB */
		} else {
			base = ra;
			index = rb;
		}
		disp = 0;
	} else {
		base = (ra == 0 && !update) ? KGENOME_CELL_REG_NONE : ra;
	}
	if (update)
		c->o->wmask |= W(ra);
	switch (kind) {
	case LS_LOAD:  c->o->op = KGENOME_CELL_MOV;   break;
	case LS_LOADZ: c->o->op = KGENOME_CELL_MOVZX; break;
	case LS_LOADS: c->o->op = KGENOME_CELL_MOVSX; break;
	case LS_STORE: c->o->op = KGENOME_CELL_MOV;   break;
	case LS_OTHER: c->o->op = KGENOME_CELL_OTHER; return;     /* byte-reversed, string, external control: no operand claimed */
	default:       c->o->op = KGENOME_CELL_FPU;   break;
	}
	if (kind == LS_STORE || kind == LS_FSTORE) {
		mflags = KGENOME_CELL_OF_WRITE;
		mi = 0; ri = 1;
	} else {
		mflags = KGENOME_CELL_OF_READ;
		mi = (kind == LS_FLOAD) ? 0u : 1u; ri = 0;
	}
	if (kind == LS_FLOAD || kind == LS_FSTORE) {
		op_mem(c, 0, base, index, disp, size, mflags);
		c->o->n_op = 1;
		return;
	}
	op_mem(c, mi, base, index, disp, size, mflags);
	if (kind == LS_STORE) {
		op_reg(c, ri, rt, KGENOME_CELL_OF_READ);
	} else {
		op_reg(c, ri, rt, KGENOME_CELL_OF_WRITE);
		c->o->wmask |= W(rt);
	}
	c->o->n_op = 2;
}

/* ---- branches --------------------------------------------------------------------------------- */

#define BO_ALWAYS(bo) (((bo) & 0x14u) == 0x14u)         /* branch regardless of CR and CTR */
#define BO_DECR(bo)   (!((bo) & 0x04u))                 /* the branch decrements CTR */

static void branch(struct pc *c)
{
	struct kgenome_cell_insn *o = c->o;
	const struct kgenome_ppc_insn *in = &c->in;
	unsigned id = in->id, bo = kgenome_ppc_bo(in), lk = kgenome_ppc_lk(in);
	int has;
	uint64_t t;

	if (lk)
		o->wmask |= W(R_LR);
	if (id == KGENOME_PPC_I_B) {
		o->op = lk ? KGENOME_CELL_CALL : KGENOME_CELL_JMP;
	} else if (id == KGENOME_PPC_I_BC) {
		if (BO_DECR(bo))
			o->wmask |= W(R_CTR);
		o->cond = (uint8_t)(BO_ALWAYS(bo) ? 0u : 1u);
		o->op = lk ? KGENOME_CELL_CALL : BO_ALWAYS(bo) ? KGENOME_CELL_JMP
		      : BO_DECR(bo) ? KGENOME_CELL_LOOP : KGENOME_CELL_JCC;
	}
	if (id == KGENOME_PPC_I_B || id == KGENOME_PPC_I_BC) {
		t = kgenome_ppc_branch_target(in, c->va, c->wide, &has);
		(void)has;
		o->target_va = t;
		o->o[0].kind = KGENOME_CELL_O_REL;
		o->n_op = 1;
		if (id == KGENOME_PPC_I_BC) {
			op_imm(c, 1, bo);
			op_imm(c, 2, kgenome_ppc_bi(in));
			o->n_op = 3;
		}
		return;
	}
	/* bclr / bcctr */
	if (id == KGENOME_PPC_I_BCCTR) {
		o->flags |= KGENOME_CELL_F_INDIRECT;
		o->op = lk ? KGENOME_CELL_CALL : KGENOME_CELL_JMP;
		op_reg(c, 0, R_CTR, KGENOME_CELL_OF_READ);
	} else {
		if (BO_DECR(bo))
			o->wmask |= W(R_CTR);
		if (lk) {
			o->flags |= KGENOME_CELL_F_INDIRECT;
			o->op = KGENOME_CELL_CALL;
		} else {
			o->op = KGENOME_CELL_RET;
		}
		op_reg(c, 0, R_LR, KGENOME_CELL_OF_READ);
	}
	o->cond = (uint8_t)(BO_ALWAYS(bo) ? 0u : 1u);
	op_imm(c, 1, bo);
	op_imm(c, 2, kgenome_ppc_bi(in));
	o->n_op = 3;
}

/*
 * A 32-bit word operation (rlwinm, slw, srw, sraw, srawi, mullw, mulhw, divw ...) in a 64-bit object acts on the low word and
 * defines the upper word in a way no class here says (slw clears it, sraw sign-fills it): no class, the write is kept.
 */
static int word_op_wide(struct pc *c, unsigned dest)
{
	if (!c->wide)
		return 0;
	c->o->wmask |= W(dest);
	return 1;
}

/* ---- rotates ---------------------------------------------------------------------------------- */

static uint32_t rot_mask(unsigned mb, unsigned me)
{
	uint32_t a = 0xffffffffu >> mb, b = 0xffffffffu << (31u - me);

	return mb <= me ? (a & b) : (a | b);
}

static void rlwinm(struct pc *c)
{
	unsigned ra = kgenome_ppc_ra(&c->in), rs = kgenome_ppc_rs(&c->in), sh = kgenome_ppc_sh(&c->in);
	unsigned mb = kgenome_ppc_mb(&c->in), me = kgenome_ppc_me(&c->in);

	c->o->wmask |= W(ra);
	if (c->wide)
		return;
	if (mb == 0 && me == 31u) {
		if (sh == 0) {
			mov_reg(c, ra, rs);
			return;
		}
		alu(c, KGENOME_CELL_ROL, ra, rs, 1, sh);
	} else if (mb == 0 && me == 31u - sh) {
		alu(c, KGENOME_CELL_SHL, ra, rs, 1, sh);
	} else if (me == 31u && sh == 32u - mb && mb != 0) {
		alu(c, KGENOME_CELL_SHR, ra, rs, 1, mb);
	} else if (sh == 0) {
		alu(c, KGENOME_CELL_AND, ra, rs, 1, rot_mask(mb, me));
	}
	/* anything else is a rotate and mask no class names: OTHER with the write kept */
}

/* ---- the table of what an identity is ---------------------------------------------------------- */

static void f_fp(struct pc *c)
{
	c->o->op = KGENOME_CELL_FPU;
	flags_rc_oe(c, 0);
}

static void decode_id(struct pc *c)
{
	struct kgenome_cell_insn *o = c->o;
	const struct kgenome_ppc_insn *in = &c->in;
	unsigned rt = kgenome_ppc_rt(in), ra = kgenome_ppc_ra(in), rb = kgenome_ppc_rb(in);
	int64_t simm = kgenome_ppc_simm(in);
	unsigned uimm = kgenome_ppc_uimm(in);
	unsigned spr, to;

	switch (in->id) {
	case KGENOME_PPC_I_UNSUPPORTED:
		return;
	case KGENOME_PPC_I_INVALID:
		o->op = KGENOME_CELL_UD;
		return;
	/* D-form arithmetic */
	case KGENOME_PPC_I_ADDI:
		if (ra == 0)
			mov_imm(c, rt, simm);
		else
			alu(c, KGENOME_CELL_ADD, rt, ra, 1, trunc_to(c, simm));
		return;
	case KGENOME_PPC_I_ADDIS:
		if (ra == 0)
			mov_imm(c, rt, simm * 65536);
		else
			alu(c, KGENOME_CELL_ADD, rt, ra, 1, trunc_to(c, simm * 65536));
		return;
	case KGENOME_PPC_I_ADDIC: case KGENOME_PPC_I_ADDIC_:
		alu(c, KGENOME_CELL_ADD, rt, ra, 1, trunc_to(c, simm));
		o->wmask |= W(R_XER) | (in->id == KGENOME_PPC_I_ADDIC_ ? W(R_CR) : 0);
		return;
	case KGENOME_PPC_I_MULLI:
		alu(c, KGENOME_CELL_IMUL, rt, ra, 1, trunc_to(c, simm));
		return;
	case KGENOME_PPC_I_SUBFIC:
		o->wmask |= W(rt) | W(R_XER);
		return;
	case KGENOME_PPC_I_CMPI: case KGENOME_PPC_I_CMPLI:
		o->op = KGENOME_CELL_CMP;
		o->wmask |= W(R_CR);
		op_reg(c, 0, ra, KGENOME_CELL_OF_READ);
		op_imm(c, 1, in->id == KGENOME_PPC_I_CMPI ? trunc_to(c, simm) : uimm);
		o->n_op = 2;
		return;
	case KGENOME_PPC_I_ORI:
		if (ra == 0 && rt == 0 && uimm == 0) {
			o->op = KGENOME_CELL_NOP;
			return;
		}
		alu(c, KGENOME_CELL_OR, ra, rt, 1, uimm);
		return;
	case KGENOME_PPC_I_ORIS:  alu(c, KGENOME_CELL_OR, ra, rt, 1, (uint64_t)uimm << 16); return;
	case KGENOME_PPC_I_XORI:  alu(c, KGENOME_CELL_XOR, ra, rt, 1, uimm); return;
	case KGENOME_PPC_I_XORIS: alu(c, KGENOME_CELL_XOR, ra, rt, 1, (uint64_t)uimm << 16); return;
	case KGENOME_PPC_I_ANDI_:  alu(c, KGENOME_CELL_AND, ra, rt, 1, uimm); o->wmask |= W(R_CR); return;
	case KGENOME_PPC_I_ANDIS_: alu(c, KGENOME_CELL_AND, ra, rt, 1, (uint64_t)uimm << 16); o->wmask |= W(R_CR); return;
	/* branches, system call, traps */
	case KGENOME_PPC_I_B: case KGENOME_PPC_I_BC: case KGENOME_PPC_I_BCLR: case KGENOME_PPC_I_BCCTR:
		branch(c);
		return;
	case KGENOME_PPC_I_SC:
		o->op = KGENOME_CELL_SYSCALL;
		o->wmask |= W(0) | 0x1ff8ull | W(R_CR) | W(R_CTR) | W(R_XER);   /* r0, r3..r12 */
		return;
	case KGENOME_PPC_I_TWI: case KGENOME_PPC_I_TDI:
		to = rt;
		o->op = to == 31u ? KGENOME_CELL_UD : KGENOME_CELL_INT;
		return;
	case KGENOME_PPC_I_TW: case KGENOME_PPC_I_TD:
		to = rt;
		o->op = to == 31u ? KGENOME_CELL_UD : KGENOME_CELL_INT;
		return;
	case KGENOME_PPC_I_RFI: case KGENOME_PPC_I_RFID:
		o->op = KGENOME_CELL_IRET;
		return;
	/* rotates */
	case KGENOME_PPC_I_RLWINM:
		rlwinm(c);
		o->wmask |= W(ra) | (kgenome_ppc_rc(in) ? W(R_CR) : 0);
		return;
	case KGENOME_PPC_I_RLWNM:
		if (!c->wide && kgenome_ppc_mb(in) == 0 && kgenome_ppc_me(in) == 31u)
			alu(c, KGENOME_CELL_ROL, ra, rt, 0, rb);
		o->wmask |= W(ra) | (kgenome_ppc_rc(in) ? W(R_CR) : 0);
		return;
	case KGENOME_PPC_I_RLWIMI:
	case KGENOME_PPC_I_RLDICL: case KGENOME_PPC_I_RLDICR: case KGENOME_PPC_I_RLDIC:
	case KGENOME_PPC_I_RLDIMI: case KGENOME_PPC_I_RLDCL: case KGENOME_PPC_I_RLDCR:
		o->wmask |= W(ra) | (kgenome_ppc_rc(in) ? W(R_CR) : 0);
		return;
	/* D-form loads and stores */
	case KGENOME_PPC_I_LWZ:  ldst(c, LS_LOAD, 4, 0, 0, simm); return;
	case KGENOME_PPC_I_LWZU: ldst(c, LS_LOAD, 4, 0, 1, simm); return;
	case KGENOME_PPC_I_LBZ:  ldst(c, LS_LOADZ, 1, 0, 0, simm); return;
	case KGENOME_PPC_I_LBZU: ldst(c, LS_LOADZ, 1, 0, 1, simm); return;
	case KGENOME_PPC_I_LHZ:  ldst(c, LS_LOADZ, 2, 0, 0, simm); return;
	case KGENOME_PPC_I_LHZU: ldst(c, LS_LOADZ, 2, 0, 1, simm); return;
	case KGENOME_PPC_I_LHA:  ldst(c, LS_LOADS, 2, 0, 0, simm); return;
	case KGENOME_PPC_I_LHAU: ldst(c, LS_LOADS, 2, 0, 1, simm); return;
	case KGENOME_PPC_I_STW:  ldst(c, LS_STORE, 4, 0, 0, simm); return;
	case KGENOME_PPC_I_STWU: ldst(c, LS_STORE, 4, 0, 1, simm); return;
	case KGENOME_PPC_I_STB:  ldst(c, LS_STORE, 1, 0, 0, simm); return;
	case KGENOME_PPC_I_STBU: ldst(c, LS_STORE, 1, 0, 1, simm); return;
	case KGENOME_PPC_I_STH:  ldst(c, LS_STORE, 2, 0, 0, simm); return;
	case KGENOME_PPC_I_STHU: ldst(c, LS_STORE, 2, 0, 1, simm); return;
	case KGENOME_PPC_I_LMW:
		ldst(c, LS_LOAD, 4, 0, 0, simm);
		o->wmask |= ALL_GPR & ~((1ull << rt) - 1ull);       /* rT .. r31 */
		return;
	case KGENOME_PPC_I_STMW: ldst(c, LS_STORE, 4, 0, 0, simm); return;
	case KGENOME_PPC_I_LFS:  ldst(c, LS_FLOAD, 4, 0, 0, simm); return;
	case KGENOME_PPC_I_LFSU: ldst(c, LS_FLOAD, 4, 0, 1, simm); return;
	case KGENOME_PPC_I_LFD:  ldst(c, LS_FLOAD, 8, 0, 0, simm); return;
	case KGENOME_PPC_I_LFDU: ldst(c, LS_FLOAD, 8, 0, 1, simm); return;
	case KGENOME_PPC_I_STFS:  ldst(c, LS_FSTORE, 4, 0, 0, simm); return;
	case KGENOME_PPC_I_STFSU: ldst(c, LS_FSTORE, 4, 0, 1, simm); return;
	case KGENOME_PPC_I_STFD:  ldst(c, LS_FSTORE, 8, 0, 0, simm); return;
	case KGENOME_PPC_I_STFDU: ldst(c, LS_FSTORE, 8, 0, 1, simm); return;
	case KGENOME_PPC_I_LD:  ldst(c, LS_LOAD, 8, 0, 0, kgenome_ppc_ds(in)); return;
	case KGENOME_PPC_I_LDU: ldst(c, LS_LOAD, 8, 0, 1, kgenome_ppc_ds(in)); return;
	case KGENOME_PPC_I_LWA: ldst(c, LS_LOADS, 4, 0, 0, kgenome_ppc_ds(in)); return;
	case KGENOME_PPC_I_STD:  ldst(c, LS_STORE, 8, 0, 0, kgenome_ppc_ds(in)); return;
	case KGENOME_PPC_I_STDU: ldst(c, LS_STORE, 8, 0, 1, kgenome_ppc_ds(in)); return;
	/* indexed loads and stores */
	case KGENOME_PPC_I_LWZX:  ldst(c, LS_LOAD, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_LWZUX: ldst(c, LS_LOAD, 4, 1, 1, 0); return;
	case KGENOME_PPC_I_LBZX:  ldst(c, LS_LOADZ, 1, 1, 0, 0); return;
	case KGENOME_PPC_I_LBZUX: ldst(c, LS_LOADZ, 1, 1, 1, 0); return;
	case KGENOME_PPC_I_LHZX:  ldst(c, LS_LOADZ, 2, 1, 0, 0); return;
	case KGENOME_PPC_I_LHZUX: ldst(c, LS_LOADZ, 2, 1, 1, 0); return;
	case KGENOME_PPC_I_LHAX:  ldst(c, LS_LOADS, 2, 1, 0, 0); return;
	case KGENOME_PPC_I_LHAUX: ldst(c, LS_LOADS, 2, 1, 1, 0); return;
	case KGENOME_PPC_I_LWAX:  ldst(c, LS_LOADS, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_LWAUX: ldst(c, LS_LOADS, 4, 1, 1, 0); return;
	case KGENOME_PPC_I_LDX:   ldst(c, LS_LOAD, 8, 1, 0, 0); return;
	case KGENOME_PPC_I_LDUX:  ldst(c, LS_LOAD, 8, 1, 1, 0); return;
	case KGENOME_PPC_I_LWARX: ldst(c, LS_LOAD, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_LDARX: ldst(c, LS_LOAD, 8, 1, 0, 0); return;
	case KGENOME_PPC_I_STWX:  ldst(c, LS_STORE, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_STWUX: ldst(c, LS_STORE, 4, 1, 1, 0); return;
	case KGENOME_PPC_I_STBX:  ldst(c, LS_STORE, 1, 1, 0, 0); return;
	case KGENOME_PPC_I_STBUX: ldst(c, LS_STORE, 1, 1, 1, 0); return;
	case KGENOME_PPC_I_STHX:  ldst(c, LS_STORE, 2, 1, 0, 0); return;
	case KGENOME_PPC_I_STHUX: ldst(c, LS_STORE, 2, 1, 1, 0); return;
	case KGENOME_PPC_I_STDX:  ldst(c, LS_STORE, 8, 1, 0, 0); return;
	case KGENOME_PPC_I_STDUX: ldst(c, LS_STORE, 8, 1, 1, 0); return;
	case KGENOME_PPC_I_STWCX_: ldst(c, LS_STORE, 4, 1, 0, 0); o->wmask |= W(R_CR); return;
	case KGENOME_PPC_I_STDCX_: ldst(c, LS_STORE, 8, 1, 0, 0); o->wmask |= W(R_CR); return;
	case KGENOME_PPC_I_LFSX:  ldst(c, LS_FLOAD, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_LFSUX: ldst(c, LS_FLOAD, 4, 1, 1, 0); return;
	case KGENOME_PPC_I_LFDX:  ldst(c, LS_FLOAD, 8, 1, 0, 0); return;
	case KGENOME_PPC_I_LFDUX: ldst(c, LS_FLOAD, 8, 1, 1, 0); return;
	case KGENOME_PPC_I_STFSX:  ldst(c, LS_FSTORE, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_STFSUX: ldst(c, LS_FSTORE, 4, 1, 1, 0); return;
	case KGENOME_PPC_I_STFDX:  ldst(c, LS_FSTORE, 8, 1, 0, 0); return;
	case KGENOME_PPC_I_STFDUX: ldst(c, LS_FSTORE, 8, 1, 1, 0); return;
	case KGENOME_PPC_I_STFIWX: ldst(c, LS_FSTORE, 4, 1, 0, 0); return;
	case KGENOME_PPC_I_LHBRX: case KGENOME_PPC_I_LWBRX: case KGENOME_PPC_I_ECIWX:
		o->wmask |= W(rt);
		return;
	case KGENOME_PPC_I_LSWI: {
		unsigned nb = kgenome_ppc_rb(in) ? kgenome_ppc_rb(in) : 32u, k, regs = (nb + 3u) / 4u;

		for (k = 0; k < regs; k++)
			o->wmask |= W((rt + k) & 31u);
		return;
	}
	case KGENOME_PPC_I_LSWX:
		o->wmask |= ALL_GPR;
		return;
	/* arithmetic and logic, X and XO forms */
	case KGENOME_PPC_I_ADD:
		alu(c, KGENOME_CELL_ADD, rt, ra, 0, rb);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_ADDC:
		alu(c, KGENOME_CELL_ADD, rt, ra, 0, rb);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_ADDE:
		alu(c, KGENOME_CELL_ADC, rt, ra, 0, rb);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_ADDZE:
		alu1(c, KGENOME_CELL_ADC, rt, ra, 0);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_ADDME: case KGENOME_PPC_I_SUBFZE: case KGENOME_PPC_I_SUBFME:
		o->wmask |= W(rt) | W(R_XER);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_SUBF:
		alu(c, KGENOME_CELL_SUB, rt, rb, 0, ra);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_SUBFC:
		alu(c, KGENOME_CELL_SUB, rt, rb, 0, ra);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_SUBFE:
		alu(c, KGENOME_CELL_SBB, rt, rb, 0, ra);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_NEG:
		alu1(c, KGENOME_CELL_NEG, rt, ra, 0);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_MULLW: case KGENOME_PPC_I_MULLD:
		if (in->id == KGENOME_PPC_I_MULLW && word_op_wide(c, rt)) {
			flags_rc_oe(c, 1);
			return;
		}
		alu(c, KGENOME_CELL_IMUL, rt, ra, 0, rb);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_MULHW: case KGENOME_PPC_I_MULHWU: case KGENOME_PPC_I_MULHD: case KGENOME_PPC_I_MULHDU:
		if ((in->id == KGENOME_PPC_I_MULHW || in->id == KGENOME_PPC_I_MULHWU) && word_op_wide(c, rt)) {
			flags_rc_oe(c, 0);
			return;
		}
		alu(c, KGENOME_CELL_MUL, rt, ra, 0, rb);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_DIVW: case KGENOME_PPC_I_DIVD:
		if (in->id == KGENOME_PPC_I_DIVW && word_op_wide(c, rt)) {
			flags_rc_oe(c, 1);
			return;
		}
		alu(c, KGENOME_CELL_IDIV, rt, ra, 0, rb);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_DIVWU: case KGENOME_PPC_I_DIVDU:
		if (in->id == KGENOME_PPC_I_DIVWU && word_op_wide(c, rt)) {
			flags_rc_oe(c, 1);
			return;
		}
		alu(c, KGENOME_CELL_DIV, rt, ra, 0, rb);
		flags_rc_oe(c, 1);
		return;
	case KGENOME_PPC_I_AND: alu(c, KGENOME_CELL_AND, ra, rt, 0, rb); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_XOR: alu(c, KGENOME_CELL_XOR, ra, rt, 0, rb); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_OR:
		if (rt == rb)
			mov_reg(c, ra, rt);             /* or ra,rs,rs is mr */
		else
			alu(c, KGENOME_CELL_OR, ra, rt, 0, rb);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_NOR:
		if (rt == rb)
			alu1(c, KGENOME_CELL_NOT, ra, rt, 0);   /* nor ra,rs,rs is not */
		else
			o->wmask |= W(ra);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_ANDC: case KGENOME_PPC_I_ORC: case KGENOME_PPC_I_NAND: case KGENOME_PPC_I_EQV:
	case KGENOME_PPC_I_CNTLZW: case KGENOME_PPC_I_CNTLZD:
		o->wmask |= W(ra);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_SLW: case KGENOME_PPC_I_SLD:
		if (in->id == KGENOME_PPC_I_SLW && word_op_wide(c, ra)) {
			flags_rc_oe(c, 0);
			return;
		}
		alu(c, KGENOME_CELL_SHL, ra, rt, 0, rb); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_SRW: case KGENOME_PPC_I_SRD:
		if (in->id == KGENOME_PPC_I_SRW && word_op_wide(c, ra)) {
			flags_rc_oe(c, 0);
			return;
		}
		alu(c, KGENOME_CELL_SHR, ra, rt, 0, rb); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_SRAW: case KGENOME_PPC_I_SRAD:
		if (in->id == KGENOME_PPC_I_SRAW && word_op_wide(c, ra)) {
			o->wmask |= W(R_XER);
			flags_rc_oe(c, 0);
			return;
		}
		alu(c, KGENOME_CELL_SAR, ra, rt, 0, rb);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_SRAWI:
		if (word_op_wide(c, ra)) {
			o->wmask |= W(R_XER);
			flags_rc_oe(c, 0);
			return;
		}
		alu(c, KGENOME_CELL_SAR, ra, rt, 1, rb);
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_SRADI:
		alu(c, KGENOME_CELL_SAR, ra, rt, 1, rb | (((in->word >> 1) & 1u) << 5));
		o->wmask |= W(R_XER);
		flags_rc_oe(c, 0);
		return;
	case KGENOME_PPC_I_EXTSB: alu1(c, KGENOME_CELL_WIDEN, ra, rt, 1); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_EXTSH: alu1(c, KGENOME_CELL_WIDEN, ra, rt, 2); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_EXTSW: alu1(c, KGENOME_CELL_WIDEN, ra, rt, 4); flags_rc_oe(c, 0); return;
	case KGENOME_PPC_I_CMP: case KGENOME_PPC_I_CMPL:
		o->op = KGENOME_CELL_CMP;
		o->wmask |= W(R_CR);
		op_reg(c, 0, ra, KGENOME_CELL_OF_READ);
		op_reg(c, 1, rb, KGENOME_CELL_OF_READ);
		o->n_op = 2;
		return;
	case KGENOME_PPC_I_ISEL:
		o->wmask |= W(rt);
		return;
	/* condition register and special registers */
	case KGENOME_PPC_I_MCRF: case KGENOME_PPC_I_CRNOR: case KGENOME_PPC_I_CRANDC: case KGENOME_PPC_I_CRXOR:
	case KGENOME_PPC_I_CRNAND: case KGENOME_PPC_I_CRAND: case KGENOME_PPC_I_CREQV: case KGENOME_PPC_I_CRORC:
	case KGENOME_PPC_I_CROR: case KGENOME_PPC_I_MTFSB1: case KGENOME_PPC_I_MTFSB0:
		o->wmask |= W(R_CR);
		return;
	case KGENOME_PPC_I_MCRXR:
		o->wmask |= W(R_CR) | W(R_XER);
		return;
	case KGENOME_PPC_I_MTCRF:
		o->op = KGENOME_CELL_MOV_SPECIAL;
		o->wmask |= W(R_CR);
		return;
	case KGENOME_PPC_I_MFCR: case KGENOME_PPC_I_MFTB: case KGENOME_PPC_I_MFSR: case KGENOME_PPC_I_MFSRIN:
		o->op = in->id == KGENOME_PPC_I_MFSR || in->id == KGENOME_PPC_I_MFSRIN ? KGENOME_CELL_PRIV : KGENOME_CELL_MOV_SPECIAL;
		o->wmask |= W(rt);
		return;
	case KGENOME_PPC_I_MFMSR:
		o->op = KGENOME_CELL_PRIV;
		o->wmask |= W(rt);
		return;
	case KGENOME_PPC_I_MFSPR:
		spr = kgenome_ppc_spr(in);
		o->wmask |= W(rt);
		if (spr == 8u || spr == 9u || spr == 1u) {
			mov_reg(c, rt, spr == 8u ? R_LR : spr == 9u ? R_CTR : R_XER);
			return;
		}
		o->op = KGENOME_CELL_MOV_SPECIAL;
		op_reg(c, 0, rt, KGENOME_CELL_OF_WRITE);
		op_imm(c, 1, spr);
		o->n_op = 2;
		return;
	case KGENOME_PPC_I_MTSPR:
		spr = kgenome_ppc_spr(in);
		if (spr == 8u || spr == 9u || spr == 1u) {
			unsigned sp = spr == 8u ? R_LR : spr == 9u ? R_CTR : R_XER;

			mov_reg(c, sp, rt);
			return;
		}
		o->op = KGENOME_CELL_MOV_SPECIAL;
		op_imm(c, 0, spr);
		op_reg(c, 1, rt, KGENOME_CELL_OF_READ);
		o->n_op = 2;
		return;
	case KGENOME_PPC_I_MTMSR: case KGENOME_PPC_I_MTSR: case KGENOME_PPC_I_MTSRIN: case KGENOME_PPC_I_TLBIE:
	case KGENOME_PPC_I_TLBIA: case KGENOME_PPC_I_TLBSYNC: case KGENOME_PPC_I_DCBI:
		o->op = KGENOME_CELL_PRIV;
		return;
	case KGENOME_PPC_I_FCMPU: case KGENOME_PPC_I_FCMPO: case KGENOME_PPC_I_MCRFS:
		o->op = KGENOME_CELL_FPU;
		o->wmask |= W(R_CR);
		return;
	default:
		break;
	}
	if (in->id >= KGENOME_PPC_I_FDIVS && in->id <= KGENOME_PPC_I_FCFID) {
		f_fp(c);
		return;
	}
	/* cache and synchronisation, stwbrx/sthbrx/stsw*, ecowx, dcb*, icbi, isync, sync, eieio: OTHER, no register write */
}

uint32_t kgenome_cell_decode_ppc(const uint8_t *p, uint32_t n, uint64_t va, int be, int wide,
				 struct kgenome_cell_insn *out)
{
	struct pc c;
	uint32_t x;
	unsigned k;

	if (!p || n < 4u || !out)
		return 0;
	x = be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3])
	       : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]);
	memset(out, 0, sizeof *out);
	out->len = 4u;
	out->at = va;
	out->at_va = va;
	out->target = KGENOME_BROKEN;
	out->target_va = KGENOME_BROKEN;
	for (k = 0; k < 3; k++)
		out->o[k].reg = out->o[k].index = out->o[k].seg = KGENOME_CELL_REG_NONE;
	c.o = out;
	c.va = va;
	c.wide = wide != 0;
	(void)kgenome_ppc_decode(&c.in, x, c.wide);
	decode_id(&c);
	return 4u;
}
