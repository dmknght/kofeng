/*
 * cell_state.h - what a walk over decoded code knows: register constants and a
 * small modelled stack. See cell_state.c for what it will and will not do.
 */
#ifndef KGENOME_CELL_STATE_H
#define KGENOME_CELL_STATE_H

#include <stdint.h>

struct kgenome_cell_insn;

#define KGENOME_CELL_STACK 16u

struct kgenome_cell_state {
	uint64_t reg[16];
	uint16_t known;         /* bit i: reg[i] holds a derived constant */
	/*
	 * A SMALL MODELLED STACK, and it is here for one idiom.
	 *
	 * Every position-independent decryptor finds itself the same way:
	 *
	 *     call $+5        <- pushes the address of the next instruction
	 *     pop  reg        <- and reg now holds it
	 *
	 * The pushed value is something a static walk KNOWS - it is the
	 * cursor - so refusing to model the stack throws away the one fact the
	 * whole idiom exists to produce. Measured: without this, the walk
	 * loses the register on all four Sality samples at the first pop, and
	 * a `push reg; ret` hand-over cannot be followed at all.
	 *
	 * SIXTEEN SLOTS AND NO MORE. This is not a stack a program runs on; it
	 * is the handful of values a prologue puts there before taking them
	 * back. A walk that pushes past the end simply loses the oldest, which
	 * is the same honest "unknown" every other limit here produces.
	 */
	uint64_t stk[KGENOME_CELL_STACK];
	uint16_t stk_known;     /* bit i: stk[i] is a derived constant */
	uint8_t  stk_n;
	/*
	 * THE REGISTERS A CALL THAT RETURNS LEAVES ALONE, one bit each; every other register is unknown after
	 * it (see KGENOME_CELL_CALL in kgenome_cell_state_track). Zero, which is what a reset state holds and
	 * what a caller that has no cursor over it gets, keeps nothing: the answer that needs no knowledge
	 * of the architecture. The cursor sets it before it tracks a call (kgenome_cell_call_keeps).
	 */
	uint16_t call_keeps;
};

void kgenome_cell_state_reset(struct kgenome_cell_state *k);
int  kgenome_cell_state_reg(const struct kgenome_cell_state *k, uint8_t r, uint64_t *out);
int  kgenome_cell_state_stack_top(const struct kgenome_cell_state *k, uint64_t *out);
/*
 * The registers a call that returns leaves alone, by the calling convention of the architecture: the callee-saved
 * registers of the System V ABIs (x86-64, i386 - cdecl, stdcall and fastcall keep the same four - and the
 * AArch32 ABI). A Windows x64 callee keeps rsi and rdi as well, which this treats as the callee's: the safe
 * side. Every architecture without a row, and AArch64 (whose tracked registers x0-x15 are all the callee's),
 * keeps nothing. A callee that breaks its ABI (hand-written code, the i386 get-pc thunks) is not covered: the
 * same limit the sweep's origin map states for its callees.
 */
uint16_t kgenome_cell_call_keeps(unsigned arch);
/* Apply one decoded instruction to the map. */
void kgenome_cell_state_track(struct kgenome_cell_state *k, const struct kgenome_cell_insn *in);

#endif /* KGENOME_CELL_STATE_H */
