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
	uint8_t read_word;              /* the decoder gives no branch registers: read the word (MIPS, CS-4) */
	uint8_t int_syscall;            /* `int N` with N = this is a syscall (x86: 0x80); 0 none */
};

const struct kgenome_cfg_isa *kgenome_cfg_isa_of(unsigned arch);

/* Cheap filter for the build loop: can this op class change the flow at all? */
static inline int kgenome_cfg_op_is_flow(unsigned op)
{
	return op == KGENOME_CELL_JMP || op == KGENOME_CELL_JCC || op == KGENOME_CELL_LOOP ||
	       op == KGENOME_CELL_RET || op == KGENOME_CELL_IRET || op == KGENOME_CELL_UD;
}

/* The class of one instruction. `bytes`/`n` are the object bytes `in->at` indexes (may be NULL unless read_word);
 * `*degraded` is set when the table needed the bytes and did not have them. */
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

/* One allocation through the caller's allocator (NULL callbacks: malloc / free). NULL when refused. */
void *kgenome_cfg_alloc(const struct kgenome_cfg_mem *mem, size_t n);
void kgenome_cfg_release(const struct kgenome_cfg_mem *mem, void *p, size_t n);
/* Would holding `bytes` exceed the call's allowance (budget->max_bytes; none or 0: no allowance)? */
int kgenome_cfg_over(const struct kgenome_budget *bud, uint64_t bytes);

/* ---- hashing (cfg_sign.c; the test oracle in tests/lib/genome/cfg_*.c spells the same function out) ---- */

static inline uint64_t kgenome_cfg_mix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	h *= 0xff51afd7ed558ccdull;
	return h ^ (h >> 33);
}

/* The element of a sketch for label `lab`, its `run`-th occurrence: the high 32 bits of a mix that starts at KGENOME_CFG_KEY_SEED (domain separation, cfg.h). */
static inline uint32_t kgenome_cfg_key(uint64_t lab, uint32_t run)
{
	return (uint32_t)(kgenome_cfg_mix(kgenome_cfg_mix(KGENOME_CFG_KEY_SEED, lab), run) >> 32);
}

#endif /* KGENOME_CFG_PRIVATE_H */
