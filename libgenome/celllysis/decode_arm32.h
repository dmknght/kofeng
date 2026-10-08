/*
 * decode_arm32.h - what cell_decode_arm32 and cell_decode_thumb agree on.
 *
 * THESE ARE ADAPTERS. Which instruction a word or a pair of halfwords IS, is
 * genotype's (libgenome/genotype/arm32: gt_arm32_decode, gt_thumb_decode); the
 * two decoders here turn its answer - an instruction name and the raw fields -
 * into struct cell_insn: the class, the registers written, the operands in the
 * convention below.
 *
 * Two adapters, one convention. A consumer reads an ARM state instruction and a
 * Thumb state one the same way, so the way an operand is spelled lives here once
 * and not in two files that would drift (CLAUDE.md rule 2).
 *
 * ---- THE CONVENTION, which a consumer has to know ------------------------
 *
 * REGISTERS are r0..r15 as 0..15 (sp 13, lr 14, pc 15) in `reg` and in
 * `wmask`. The flags register is not a bit in wmask: S-suffixed forms and
 * compares write it and the mask does not say so.
 *
 * `cond` is the ARM condition field of the instruction as written, 0..14.
 * 0xE means "always" and is also what the unconditional space (ARM state cond=0xF)
 * and every Thumb instruction that carries no condition report. A JCC has the
 * condition it branches on (cbz is EQ, cbnz is NE). A NON-branch with
 * cond != 0xE still decodes with its normal class and its normal wmask: its
 * writes are "maybe" writes and a consumer that keeps a constant map must
 * treat them so. cell.h is not changed and no flag was added for it.
 *
 * AN IT BLOCK IS NOT TRACKED. A Thumb-2 `it` is decoded as CELL_OTHER with
 * length 2 and the up-to-four instructions it governs report cond 0xE: the
 * decoder is stateless, and a caller that wants the condition of an
 * instruction inside the block has to carry the IT state itself.
 *
 * THE PC. Branch targets use the architectural rule - ARM state pc+8, Thumb state pc+4 -
 * and are stored in `target_va` AND `target` (the engine resolves `target`
 * to a file offset afterwards, as it does for MIPS). A target that is Thumb
 * code reached from ARM state (blx imm) or ARM state reached from Thumb state (blx imm) is
 * stored with bit 0 CLEAR - the address of the instruction, not the
 * interworking address. An indirect branch has target = target_va = KOF_BROKEN
 * and CELL_F_INDIRECT.
 *
 * A PC-RELATIVE LITERAL (`ldr rt, [pc, #x]`, `adr`) is a CELL_O_MEM operand
 * with reg = 15, CELL_OF_RIPREL set, and `disp` already measured from the
 * instruction itself:
 *
 *        literal address = at_va + disp
 *
 * so a consumer needs no knowledge of the pc+8 / Align(pc,4)+4 rules. For ARM state
 * disp = 8 +/- imm12; for Thumb disp = (Align(at_va + 4, 4) - at_va) +/- imm,
 * which is 4 or 2 plus the offset. (x86's RIPREL disp is measured from the
 * NEXT instruction; this one is measured from this one - a consumer shared
 * between the two has to know which.) `adr` and `add rd, pc, #imm` are
 * CELL_LEA with the same operand.
 *
 * OPERAND FORMS, per class:
 *   MOV  rd, #imm        o0 REG(w), o1 IMM            (mov, mvn imm, movw)
 *   MOV  rd, rm          o0 REG(w), o1 REG(r)
 *   load rt,[..]         o0 REG(w), o1 MEM(r)    class MOV (word), MOVZX
 *                        (ldrb, ldrh), MOVSX (ldrsb, ldrsh)
 *   store rt,[..]        o0 MEM(w), o1 REG(r)    class MOV - no register
 *                        in wmask except a written-back base
 *   ALU rd, op2          o0 REG(w), o1 REG/IMM        when rd == rn and op2 is
 *                        an immediate or a plain register: add sub and orr
 *                        eor adc sbc, as `d op= s` - the form cell_state's
 *                        constant map computes with (`add r0,r0,#4` is r0 += 4)
 *   ALU rd, rn, op2      o0 REG(w), o1 REG(r), o2 REG/IMM    otherwise - rd != rn,
 *                        or a SHIFTED op2 - ARM's own three operands as MIPS
 *                        has them. cell_state reads o1 of this as the source,
 *                        so it computes it wrong (measured: `sub r0,r0,#1`
 *                        after r0 = 5 left r0 known as 0), until it has an
 *                        arm for three operands
 *   CMP/TEST rn, op2     o0 REG(r), o1 REG/IMM
 *   NOT/NEG rd, rm       o0 REG(w), o1 REG(r)    only when rd == rm, and for NOT
 *                        only with nothing shifted: `d = ~d`, `d = -d` are the
 *                        only meaning cell_state gives them. Any other mvn or
 *                        negate is CELL_OTHER with the same operands
 *   shifts rd, rm, n     o0 REG(w), o1 REG(r), o2 IMM amount or REG
 *   JMP/CALL imm         o0 REL            JCC: o0 REL (cbz: o1 REG)
 *   JMP/CALL reg         o0 REG(r)         CELL_F_INDIRECT
 *   JMP through memory   o0 MEM(r)         ldr pc,[...]  CELL_F_INDIRECT
 *   RET                  bx lr: o0 REG lr; pop {..pc}: n_op 0; INDIRECT
 *   PUSH/POP one reg     o0 REG
 *   PUSH/POP a list      n_op 0 and the list as a bit mask in o0.imm (o0.kind
 *                        is CELL_O_NONE, so cell_state's push/pop arm sees
 *                        "no register" and pushes one unknown slot)
 *   LDM/STM other base   o0 REG base, o1 IMM register list
 *   SYSCALL              o0 IMM  (the svc immediate)
 *   INT (bkpt)           o0 IMM
 *
 * A SOURCE OPERAND THAT IS SHIFTED (`add r0, r1, r2, lsl #2`, `eor r3, r3, r2,
 * ror #5`) is a REG operand that carries the shift: `scale` is the shift kind
 * (ARM_SH_*), `disp` the immediate amount, and `index` the register holding
 * the amount for a register-specified shift (CELL_REG_NONE otherwise). The
 * class stays the arithmetic one, so a rule asking for XOR finds it; a
 * consumer that folds constants must look at `scale` first and treat a
 * shifted operand as unknown.
 *
 * A MEM OPERAND has the base in `reg`, the index in `index` (or NONE), `disp`
 * the signed offset of the ACCESS, `scale` the index multiplier (1<<lsl; 0 when
 * the index is shifted by something that is not a small LSL) and `size` the
 * access width. `imm` on a MEM operand: bit 0 set = the index register is
 * SUBTRACTED; bits 8.. the ARM_SH_* kind of a non-LSL index shift. A
 * post-indexed access (`ldr r0,[r1],#4`) has disp 0 and no index - the access
 * is at the base - and a third operand carrying what the base moves by: IMM
 * (two's complement), or REG (its `imm` is 1 when the register is subtracted,
 * and it carries the shift like any source operand).
 *
 * CELL_UD is an encoding the architecture DEFINES to fault (udf, and the
 * unallocated encodings of the integer space). CELL_OTHER is "valid, not a
 * class the engine asks about" and says nothing about whether the space was
 * checked: the coprocessor, VFP and Advanced SIMD spaces are not validity-
 * checked - they are always OTHER with the right length and the right wmask.
 */
#ifndef KOFENG_CELLLYSIS_DECODE_ARM32_H
#define KOFENG_CELLLYSIS_DECODE_ARM32_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "kofmod/cell.h"
#include "decode.h"

#define ARM_SH_NONE 0u
#define ARM_SH_LSL  1u
#define ARM_SH_LSR  2u
#define ARM_SH_ASR  3u
#define ARM_SH_ROR  4u
#define ARM_SH_RRX  5u

#define ARM_SP 13u
#define ARM_LR 14u
#define ARM_PC 15u

#define ARM_R(r) (1ull << (r))

/* Bytes to a halfword / word in the byte order the caller says. */
static inline uint32_t arm_h(const uint8_t *p, int be)
{
	return be ? ((uint32_t)p[0] << 8 | p[1])
		  : ((uint32_t)p[1] << 8 | p[0]);
}

static inline uint32_t arm_w(const uint8_t *p, int be)
{
	return be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
		     (uint32_t)p[2] << 8 | p[3])
		  : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
		     (uint32_t)p[1] << 8 | p[0]);
}

/*
 * Every field in its "nothing here" state - which is not all-zero: an absent
 * register is CELL_REG_NONE, and "no target" is KOF_BROKEN.
 *
 * FIELD BY FIELD, and not memset or a struct copy: gcc turns either of those
 * (120 bytes) into `rep stos` / `rep movs`, whose start-up cost was the better
 * part of a decode. MEASURED, on the .text of the 21 Mirai ARM binaries
 * (110.5M ARM state and 203.8M Thumb state decodes, one pinned core, machine under load):
 * memset 28.4 / 26.9 ns per instruction, field by field 18.3 / 15.0.
 */
static inline void arm_begin(struct cell_insn *o, uint64_t va, uint32_t len)
{
	unsigned i;

	o->op = 0;
	o->len = (uint8_t)len;
	o->n_op = 0;
	o->cond = 0xEu;
	o->flags = 0;
	o->_pad[0] = o->_pad[1] = o->_pad[2] = 0;
	o->wmask = 0;
	o->at = va;
	o->at_va = va;
	o->target = KOF_BROKEN;
	o->target_va = KOF_BROKEN;
	for (i = 0; i < 3u; i++) {
		struct cell_operand *d = &o->o[i];

		d->kind = 0;
		d->reg = CELL_REG_NONE;
		d->index = CELL_REG_NONE;
		d->scale = 0;
		d->size = 0;
		d->flags = 0;
		d->seg = CELL_REG_NONE;
		d->_pad = 0;
		d->disp = 0;
		d->imm = 0;
	}
}

static inline void arm_reg(struct cell_operand *d, uint32_t r, unsigned fl)
{
	d->kind = CELL_O_REG;
	d->reg = (uint8_t)r;
	d->size = 4u;
	d->flags = (uint8_t)fl;
}

static inline void arm_imm(struct cell_operand *d, uint64_t v)
{
	d->kind = CELL_O_IMM;
	d->imm = v;
	d->size = 4u;
}

static inline void arm_mem(struct cell_operand *d, uint32_t base, int64_t disp,
			   unsigned size, unsigned fl)
{
	/* every field, so an operand built on the stack carries no garbage */
	*d = (struct cell_operand){ .kind = CELL_O_MEM, .reg = (uint8_t)base,
				    .index = CELL_REG_NONE, .scale = 1u,
				    .size = (uint8_t)size, .flags = (uint8_t)fl,
				    .seg = CELL_REG_NONE, .disp = disp };
}

/*
 * A whole operand in one expression, for the ones built outside the instruction
 * (a source operand data processing takes by pointer): every field is written, in
 * three stores, where a memset and the fields after it were nine.
 */
static inline void arm_op_reg(struct cell_operand *d, uint32_t r, unsigned fl)
{
	*d = (struct cell_operand){ .kind = CELL_O_REG, .reg = (uint8_t)r,
				    .index = CELL_REG_NONE, .size = 4u,
				    .flags = (uint8_t)fl, .seg = CELL_REG_NONE };
}

static inline void arm_op_imm(struct cell_operand *d, uint64_t v)
{
	*d = (struct cell_operand){ .kind = CELL_O_IMM, .reg = CELL_REG_NONE,
				    .index = CELL_REG_NONE, .size = 4u,
				    .seg = CELL_REG_NONE, .imm = v };
}

/* The shift a source operand carries; see the convention above. */
static inline void arm_shift(struct cell_operand *d, unsigned kind,
			     uint32_t amount, uint32_t rs)
{
	d->scale = (uint8_t)kind;
	d->disp = (int64_t)amount;
	if (kind != ARM_SH_NONE && rs != 0xffu)
		d->index = (uint8_t)rs;
}

static inline unsigned arm_popcount16(uint32_t v)
{
	unsigned n = 0;

	v &= 0xffffu;
	while (v) {
		v &= v - 1u;
		n++;
	}
	return n;
}

/* The lowest set bit's index of a non-zero register list. */
static inline unsigned arm_lowest(uint32_t v)
{
	unsigned i = 0;

	while (!(v & 1u)) {
		v >>= 1;
		i++;
	}
	return i;
}

/*
 * A PUSH or a POP of a register list, which two decoders spell the same.
 * `list` is r0..r15 as bits; for a pop the written mask is the list plus sp.
 * A list that contains pc makes a pop a RET: the indirect branch is the point
 * of it, and it still reports every register it writes.
 */
static inline void arm_pushpop(struct cell_insn *o, int pop, uint32_t list)
{
	o->op = pop ? CELL_POP : CELL_PUSH;
	o->wmask = ARM_R(ARM_SP);
	if (pop)
		o->wmask |= list;
	if (arm_popcount16(list) == 1u) {
		o->n_op = 1u;
		arm_reg(&o->o[0], arm_lowest(list), pop ? CELL_OF_WRITE
							: CELL_OF_READ);
	} else {
		o->o[0].imm = list;
	}
	if (pop && (list & ARM_R(ARM_PC))) {
		o->op = CELL_RET;
		o->flags |= CELL_F_INDIRECT;
		o->n_op = 0;
		o->o[0].kind = CELL_O_NONE;
		o->o[0].reg = CELL_REG_NONE;
		o->o[0].imm = list;
	}
}

/* decode_arm32_common.c */
void kof_arm_clr(struct cell_insn *o);
void kof_arm_ud(struct cell_insn *o);
void kof_arm_other(struct cell_insn *o, uint64_t mask);
/*
 * THE REGISTERS A WRITE NAMES BUT DOES NOT SPELL, as a recipe the id table
 * carries: one flag per register field of the instruction word (ARM state's, or
 * Thumb state's 32-bit one as first halfword << 16 | second - the fields sit at
 * the same bit positions in both). arm_wm turns a recipe and a word into a mask.
 */
#define ARM_WM_F0   0x01u       /* the register in bits 3:0 */
#define ARM_WM_F8   0x02u       /* bits 11:8 */
#define ARM_WM_F12  0x04u       /* bits 15:12 */
#define ARM_WM_F16  0x08u       /* bits 19:16 */
#define ARM_WM_F12N 0x10u       /* the register after bits 15:12, modulo 16 (ldrexd) */
#define ARM_WM_PC   0x20u       /* pc: the instruction branches */

static inline uint64_t arm_wm(unsigned recipe, uint32_t w)
{
	uint64_t m = 0;

	if (recipe & ARM_WM_F0)
		m |= ARM_R(w & 15u);
	if (recipe & ARM_WM_F8)
		m |= ARM_R((w >> 8) & 15u);
	if (recipe & ARM_WM_F12)
		m |= ARM_R((w >> 12) & 15u);
	if (recipe & ARM_WM_F16)
		m |= ARM_R((w >> 16) & 15u);
	if (recipe & ARM_WM_F12N)
		m |= ARM_R((((w >> 12) & 15u) + 1u) & 15u);
	if (recipe & ARM_WM_PC)
		m |= ARM_R(ARM_PC);
	return m;
}

/*
 * The data-processing family, from the ARM state opcode (0..15; 16 is Thumb-2's orn),
 * the S bit, the registers and the second operand `src` - an IMM, or a REG
 * carrying its shift. `pc_off` is where pc-relative reads are measured from
 * (8 for ARM state); 0 turns off the `add rd, pc, #imm` -> LEA reading.
 */
void kof_arm_dp(struct cell_insn *o, unsigned opc, unsigned s, unsigned rn,
		unsigned rd, const struct cell_operand *src, int64_t pc_off);

#endif /* KOFENG_CELLLYSIS_DECODE_ARM32_H */
