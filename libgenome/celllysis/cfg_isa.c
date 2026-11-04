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
 *   (PowerPC uses `predicated` with always_cond 0: see its row.)
 *   jcc_always      AArch64 `b.cond` with condition 14 (al) or 15 (nv) is an unconditional jump. The decoder
 *                   puts the condition code of `b.cond` into `cond` and bit 24 (0/1) for cbz/tbz, so 14 and 15
 *                   can only be a `b.cond`.
 *   (MIPS/MIPS64 used to read the instruction word back out of the object bytes here, because the decoder gave a
 *   branch no registers and no condition (CS-4, fixed 2026-11-05): decode_mips.c now fills `cond` (MIPS_COND_*,
 *   decode_mips.c - ten values, kept to 4 bits so the walk's packed trace still holds a MIPS branch, trace_arch.c)
 *   and the compared registers for every MIPS branch, so mips_branch_class() below reads the decoded instruction -
 *   `b` is `beq(l) r,r`, `bgez $0` is a jump, `bltzal`/`bgezal`/their likely forms are calls that write ra, not
 *   branches - and never touches `bytes`/`be`/`n`/`degraded`, which no row still needs.)
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
 * caller decodes it), noreturn calls (a block goes on after `call exit`), a switch's indirect jump (an exit: the
 * code reached only through its table is unreachable and is not part of the signature), the FP condition-code
 * NUMBER a COP1 BC branch tests (cc, decode_mips.c: this engine does not track FP flag values to resolve it,
 * only that a BC branch exists and whether it is a likely form).
 */
#include <stddef.h>

#include "cfg_private.h"

#define NA 0xffu

static const struct kgenome_cfg_isa g_isa[] = {
	{ .arch = KGENOME_ARCH_X86,    .jcc_always_lo = NA, .jcc_always_hi = NA, .int_syscall = 0x80 },
	{ .arch = KGENOME_ARCH_X86_64, .jcc_always_lo = NA, .jcc_always_hi = NA },
	{ .arch = KGENOME_ARCH_ARM,    .jcc_always_lo = NA, .jcc_always_hi = NA, .predicated = 1, .always_cond = 14 },
	{ .arch = KGENOME_ARCH_ARM64,  .jcc_always_lo = 14, .jcc_always_hi = 15 },
	/* PowerPC: no delay slot. `cond` is 0 for a branch whose BO says "always" and 1 for any condition, so a conditional
	 * blr / bctr (the only conditional indirect exits) is a conditional exit, as a predicated ARM return is. A `bc` that is
	 * "always" is already classed JMP by the decoder, so jcc_always is unused. */
	{ .arch = KGENOME_ARCH_PPC,    .jcc_always_lo = NA, .jcc_always_hi = NA, .predicated = 1, .always_cond = 0 },
	{ .arch = KGENOME_ARCH_PPC64,  .jcc_always_lo = NA, .jcc_always_hi = NA, .predicated = 1, .always_cond = 0 },
	{ .arch = KGENOME_ARCH_MIPS,   .jcc_always_lo = NA, .jcc_always_hi = NA, .delay_slots = 1 },
	{ .arch = KGENOME_ARCH_MIPS64, .jcc_always_lo = NA, .jcc_always_hi = NA, .delay_slots = 1 },
};

const struct kgenome_cfg_isa *kgenome_cfg_isa_of(unsigned arch)
{
	size_t i;

	for (i = 0; i < sizeof g_isa / sizeof *g_isa; i++)
		if (g_isa[i].arch == arch)
			return &g_isa[i];
	return NULL;
}

/*
 * CS-4 (fixed): a MIPS branch's `cond` (decode_mips.c's MIPS_COND_*) names exactly which comparison this is -
 * 0 bltz, 1 bgez, 2 bltzal, 3 bgezal, 4 beq, 5 bne, 6 blez, 7 bgtz, 8 bc1f, 9 bc1t - ten values kept to 4 bits
 * (the walk's packed trace record gives up the day `cond` needs more, trace_arch.c, measured) by leaving the
 * "likely" bit out of it: it is CL-3's KGENOME_CELL_F_ANNUL, which this switch does not need to read at all
 * (whether a branch is local and resolved, a call, or carries its own "always" shape is the same question for
 * the plain and the likely form of it).
 */
static enum kgenome_cfg_x mips_branch_class(const struct kgenome_cell_insn *in)
{
	switch (in->cond) {
	case 2: case 3:                                        /* bltzal/bgezal(l): a call that writes ra */
		return KGENOME_CFG_X_NONE;
	case 1:                                                 /* bgez $0: always */
		return in->o[1].reg == 0u ? KGENOME_CFG_X_BR_JUMP : KGENOME_CFG_X_BR_COND;
	case 4:                                                 /* beq(l) r,r: `b` */
		return in->o[1].reg == in->o[2].reg ? KGENOME_CFG_X_BR_JUMP : KGENOME_CFG_X_BR_COND;
	default:                                                /* 0 bltz, 5-7 bne/blez/bgtz, 8-9 bc1f/bc1t */
		return KGENOME_CFG_X_BR_COND;
	}
}

static int is_predicated(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in)
{
	return isa->predicated && in->cond != isa->always_cond;
}

enum kgenome_cfg_x kgenome_cfg_isa_class(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in, int be,
					 const uint8_t *bytes, uint64_t n, int *degraded)
{
	/*
	 * CS-4 (fixed): no row still needs the object bytes to classify a branch - MIPS was the only one
	 * that did (mips_branch_class() above reads the decoded `cond`/operands instead). Kept as parameters
	 * so this signature does not change for every caller and test the day another architecture needs
	 * them; cfg_build.c's own `degraded`/`slot_missing` TRUNCATED reporting is unaffected either way.
	 */
	(void)be;
	(void)bytes;
	(void)n;
	(void)degraded;
	switch (in->op) {
	case KGENOME_CELL_JCC:
		if (isa->arch == KGENOME_ARCH_MIPS || isa->arch == KGENOME_ARCH_MIPS64)
			return mips_branch_class(in);
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