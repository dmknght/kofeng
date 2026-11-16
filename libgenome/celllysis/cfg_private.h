/*
 * cfg_private.h - what the parts of the cfg family share (cfg_build.c, cfg_isa.c, cfg_sign.c, cfg_anchor.c,
 * cfg_view.c). Not installed, not part of the surface.
 */
#ifndef KGENOME_CFG_PRIVATE_H
#define KGENOME_CFG_PRIVATE_H

#include <stdlib.h>

#include "cfg.h"

/* ---- the ISA table (cfg_isa.c) ---- */

/* What one instruction does to the control flow. */
enum kgenome_cfg_x {
	KGENOME_CFG_X_NONE = 0,         /* nothing: it does not end a block */
	KGENOME_CFG_X_BR_COND,          /* a conditional branch with a target (an exit when the target is not local) */
	KGENOME_CFG_X_BR_JUMP,          /* an unconditional jump with a target (an exit when the target is not local) */
	KGENOME_CFG_X_EXIT,             /* ends the function's flow: ret, iret, trap, indirect or far jump */
	KGENOME_CFG_X_COND_EXIT         /* leaves the function only when a condition holds: the fall-through stays */
};

/* One row per architecture. See cfg_isa.c for what each member means and for the measurement behind it. */
struct kgenome_cfg_isa {
	uint8_t arch;                   /* the enum kgenome_arch value the row is for */
	uint8_t delay_slots;            /* instructions that run after a branch and belong to its block */
	uint8_t predicated;             /* a ret / indirect jump carries a condition in `cond` (ARM) */
	uint8_t always_cond;            /* value of `cond` that means "always" for a predicated instruction */
	uint8_t jcc_always_lo, jcc_always_hi;   /* values of `cond` that make a JCC unconditional (0xff: none) */
	uint8_t int_syscall;            /* `int N` with N = this is a syscall (x86: 0x80); 0 none */
};

const struct kgenome_cfg_isa *kgenome_cfg_isa_of(unsigned arch);

/* Cheap filter for the build loop: can this op class change the flow at all? */
static inline int kgenome_cfg_op_is_flow(unsigned op)
{
	return op == KGENOME_CELL_JMP || op == KGENOME_CELL_JCC || op == KGENOME_CELL_LOOP ||
	       op == KGENOME_CELL_RET || op == KGENOME_CELL_IRET || op == KGENOME_CELL_UD;
}

/*
 * The class of one instruction. `be`/`bytes`/`n`/`degraded` are unused since CS-4 (fixed, 2026-11-05: MIPS was
 * the only row that ever read the object bytes, and now reads the decoded `cond`/operands instead) - kept in the
 * signature so it need not change again for every caller and test the day another architecture's decoder leaves
 * something out that only the bytes can supply.
 */
enum kgenome_cfg_x kgenome_cfg_isa_class(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in, int be,
					 const uint8_t *bytes, uint64_t n, int *degraded);

/* FU-ARM-PAIR: is the jump `in` a CALL because the instruction right before it, `prev`, put the return address in the link register (ARMv4 has no
 * `blx rN`: uClibc built for armv4, Mirai/Gafgyt ARM call through `mov lr, pc; mov pc, rN`)? `prev` NULL: no. Read one instruction at a time the jump
 * leaves the function and the code behind it is reached by nothing. The block layer (cfg_obj.c) asks; the graph of one function (cfg_build.c) does
 * not yet, because its shape signs a function and every ARM pack's CFG hashes would move (STEP B 2 measures and moves them, TODO(owner) re-signing). */
/* Is the exit `in` a RETURN, though the decoder gives it as a jump through a register: MIPS `jr $ra` (the o32/n64 return; the decoder keeps it JMP because
 * `jr` names any register). A RET of the decoder is one by itself. The block layer asks (a return is not an unresolved indirect jump). */
int kgenome_cfg_isa_returns(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in);
/* Does the direct call `in` go into the OTHER instruction set, so its target cannot be read with the caller's decoder? ARM: `blx label` (the encoding's condition
 * field is 0b1111, the unconditional space; the target is Thumb code). The decoder gives it as a CALL like `bl` and its trace record keeps only four flag bits, so
 * the word is read back from `bytes` (`n` of them, `code_be`: the code is big-endian). Every other row: no. The block layer asks before it follows a call. */
int kgenome_cfg_isa_interworks(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in, const uint8_t *bytes, uint64_t n, int code_be);
int kgenome_cfg_isa_linked(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *prev, const struct kgenome_cell_insn *in);
/* The trap a compiler puts behind a call that does not return: ud2 / udf on every row, x86 `hlt` and `int3` (cfg_isa.c). */
int kgenome_cfg_isa_trap(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in, const uint8_t *bytes, uint64_t n);

/* Is this a syscall instruction (the SYSCALL class, or `int N` where the row says so)? Asked of every instruction twice by the builder: inline, the
 * common answer is one compare (measured: 29.4 M Ir of 245 M in kgenome_cfg_build as a call, over 1.85 M instructions). */
static inline int kgenome_cfg_isa_is_syscall(const struct kgenome_cfg_isa *isa, const struct kgenome_cell_insn *in)
{
	if (in->op == KGENOME_CELL_SYSCALL)
		return 1;
	return in->op == KGENOME_CELL_INT && isa->int_syscall && in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM && in->o[0].imm == isa->int_syscall;
}

/* ---- memory and the budget (cfg_build.c) ---- */

/* (kgenome_cfg_alloc / kgenome_cfg_release, the one allocation through the caller's allocator, are in cfg.h: the frame and the signing use them too.) */
/* Would holding `bytes` exceed the call's allowance (budget->max_bytes; none or 0: no allowance)? */
int kgenome_cfg_over(const struct kgenome_budget *bud, uint64_t bytes);

/* ---- hashing (cfg_sign.c; the test oracle in tests/lib/genome/cfg_*.c spells the same function out) ---- */

static inline uint64_t kgenome_cfg_mix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	h *= 0xff51afd7ed558ccdull;
	return h ^ (h >> 33);
}

/* Full avalanche of one word (the splitmix64 finalizer): every input bit changes every output bit with probability 1/2. */
static inline uint64_t kgenome_cfg_avalanche(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

/*
 * The element of a sketch for label `lab`, its `run`-th occurrence: the high 32 bits of a mix that starts at KGENOME_CFG_KEY_SEED (domain separation, cfg.h).
 *
 * THE RUN IS AVALANCHED BEFORE IT IS MIXED IN (defect S1, 2026-11-03). The bottom-k estimate (kgenome_cfg_overlap) is unbiased with variance J(1-J)/32 only
 * when the elements' keys are independent. With `run` mixed in as the small integer it is, the keys of one label were a near-arithmetic progression (correlation
 * of the keys of runs 0 and 1: 0.93) and a label that repeats n times put about 16 of its elements, not 6 (n = 183), below all the others: cmake 0x3c5510 (77
 * blocks) against doxygen 0x23f4a0 (183 blocks) gave pct 100 for an exact J of 0.42, mean |error| 0.183 and worst 0.635 against 0.059 for independent keys
 * (survey, agent-reported). Proved by tests/lib/genome/cfg_estimator.c: records, serial correlation, avalanche, estimate against the exact multiset Jaccard.
 * Not done: avalanching the label too. The labels are WL hashes or a mix of the caller's identity, and the test with consecutive small identities passes.
 * Every element changes, so a pack that holds CFG keys made by the old function does not match.
 */
static inline uint32_t kgenome_cfg_key(uint64_t lab, uint32_t run)
{
	return (uint32_t)(kgenome_cfg_mix(kgenome_cfg_mix(KGENOME_CFG_KEY_SEED, lab), kgenome_cfg_avalanche(run)) >> 32);
}

#endif /* KGENOME_CFG_PRIVATE_H */
