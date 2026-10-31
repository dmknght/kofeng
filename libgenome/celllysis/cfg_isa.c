/*
 * cfg_isa.c - THE ONE TABLE of what a branch does, per architecture. Nothing else in the cfg family (and, since
 * the lineage solver builds its blocks here, nothing in the lineage either) asks an architecture a question
 * about control flow; a new architecture is a new row and, when its decoder leaves something out, a comment here.
 *
 * WHAT A ROW SAYS, each member a measurement or a fact of the ISA and not a taste:
 *
 *   delay_slots     MIPS: the instruction after a branch runs on both paths and is part of the branch's block
 *                   (the survey: without it the block after a branch starts at its slot and every MIPS graph is
 *                   wrong; measured with -n delay in the survey harness).
 *   predicated      ARM: any instruction carries a condition, and a `bx lr`, `mov pc, lr`, `ldm {.., pc}` or
 *                   `ldr pc` that is conditional is a CONDITIONAL exit: the fall-through stays an edge. The
 *                   decoder writes the condition code (14 = always) into `cond` for every ARM instruction.
 *                   1914 conditional returns in the survey set (Mirai ARM).
 *   jcc_always      AArch64 `b.cond` with condition 14 (al) or 15 (nv) is an unconditional jump. The decoder
 *                   puts the condition code of `b.cond` into `cond` and bit 24 (0/1) for cbz/tbz, so 14 and 15
 *                   can only be a `b.cond`.
 *   read_word       MIPS: the decoder (decode_mips.c) records a branch's target and nothing else: no registers,
 *                   no condition (DEFECT CS-4). `b` is `beq r,r` and `bgez $0` is a jump; `bltzal`/`bgezal` (REGIMM
 *                   with rt bit 4) are calls that write ra, not branches. The table reads the instruction word
 *                   from the object bytes (`in->at` is an offset into them) and says so by `degraded` when it
 *                   was not given them. When the decoder is changed to carry the registers, this goes.
 *   int_syscall     x86: `int 0x80` is the i386 system call.
 *
 * THE EXIT RULES, the same for every row (the survey's terminator classes, cfg_decision.md):
 *   local JCC / LOOP              conditional branch: target and fall-through
 *   JCC / LOOP out of the extent  not a terminator at all: the exit is dropped, the block goes on (a conditional
 *                                 tail call; measured as "FALL")
 *   local JMP                     jump: target only
 *   indirect or far JMP, RET, IRET, UD
 *                                 exit; conditional on a predicated row = a conditional exit
 *   JMP out of the extent         exit (a tail call)
 *   CALL, rep, cmov, setcc, int   no rule
 * NOT HANDLED, said here so nobody reads silence as coverage: Thumb (the architecture value has no Thumb, the
 * caller decodes it), noreturn calls (a block goes on after `call exit`), MIPS branch-likely and coprocessor
 * branches (the decoder does not classify them as branches), a switch's indirect jump (an exit: the code reached
 * only through its table is unreachable and is not part of the signature).
 */
#include <stddef.h>

#include "cfg_private.h"

#define NA 0xffu

static const struct kgenome_cfg_isa g_isa[] = {
	{ .arch = KGENOME_ARCH_X86,    .jcc_always_lo = NA, .jcc_always_hi = NA, .int_syscall = 0x80 },
	{ .arch = KGENOME_ARCH_X86_64, .jcc_always_lo = NA, .jcc_always_hi = NA },
	{ .arch = KGENOME_ARCH_ARM,    .jcc_always_lo = NA, .jcc_always_hi = NA, .predicated = 1, .always_cond = 14 },
	{ .arch = KGENOME_ARCH_ARM64,  .jcc_always_lo = 14, .jcc_always_hi = 15 },
	{ .arch = KGENOME_ARCH_MIPS,   .jcc_always_lo = NA, .jcc_always_hi = NA, .delay_slots = 1, .read_word = 1 },
	{ .arch = KGENOME_ARCH_MIPS64, .jcc_always_lo = NA, .jcc_always_hi = NA, .delay_slots = 1, .read_word = 1 },
};

const struct kgenome_cfg_isa *kgenome_cfg_isa_of(unsigned arch)
{
	size_t i;

	for (i = 0; i < sizeof g_isa / sizeof *g_isa; i++)
		if (g_isa[i].arch == arch)
			return &g_isa[i];
	return NULL;
}

/* MIPS branch word at the instruction's offset; 0 when the bytes are not there. */
static int mips_word(const struct kgenome_cell_insn *in, int be, const uint8_t *bytes, uint64_t n, uint32_t *w)
{
	const uint8_t *p;

	if (!bytes || in->len != 4u || in->at > n || n - in->at < 4u)
		return 0;
	p = bytes + in->at;
	*w = be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3])
		: ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]);
	return 1;
}

static enum kgenome_cfg_x mips_branch(const struct kgenome_cell_insn *in, int be, const uint8_t *bytes, uint64_t n,
				      int *degraded)
{
	uint32_t w, opc, rs, rt;

	if (!mips_word(in, be, bytes, n, &w)) {
		*degraded = 1;          /* cannot tell `b` from a conditional: conditional, and say so */
		return KGENOME_CFG_X_BR_COND;
	}
	opc = w >> 26;
	rs = (w >> 21) & 31u;
	rt = (w >> 16) & 31u;
	if (opc == 1u) {
		if (rt & 0x10u)         /* bltzal, bgezal and the likely forms: a call that writes ra */
			return KGENOME_CFG_X_NONE;
		if (rt == 1u && rs == 0u)       /* bgez $0: always */
			return KGENOME_CFG_X_BR_JUMP;
	} else if (opc == 4u && rs == rt) {     /* beq r,r: `b` */
		return KGENOME_CFG_X_BR_JUMP;
	}
	return KGENOME_CFG_X_BR_COND;
}

static int is_predicated(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in)
{
	return isa->predicated && in->cond != isa->always_cond;
}

enum kgenome_cfg_x kgenome_cfg_isa_class(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in, int be,
					 const uint8_t *bytes, uint64_t n, int *degraded)
{
	switch (in->op) {
	case KGENOME_CELL_JCC:
		if (isa->read_word)
			return mips_branch(in, be, bytes, n, degraded);
		if (in->cond >= isa->jcc_always_lo && in->cond <= isa->jcc_always_hi && isa->jcc_always_lo != NA)
			return KGENOME_CFG_X_BR_JUMP;
		return KGENOME_CFG_X_BR_COND;
	case KGENOME_CELL_LOOP:
		return KGENOME_CFG_X_BR_COND;
	case KGENOME_CELL_JMP:
		if (in->flags & (KGENOME_CELL_F_INDIRECT | KGENOME_CELL_F_FAR))
			return is_predicated(isa, in) ? KGENOME_CFG_X_COND_EXIT : KGENOME_CFG_X_EXIT;
		return KGENOME_CFG_X_BR_JUMP;
	case KGENOME_CELL_RET:
	case KGENOME_CELL_IRET:
		return is_predicated(isa, in) ? KGENOME_CFG_X_COND_EXIT : KGENOME_CFG_X_EXIT;
	case KGENOME_CELL_UD:
		return KGENOME_CFG_X_EXIT;
	default:
		return KGENOME_CFG_X_NONE;
	}
}