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
