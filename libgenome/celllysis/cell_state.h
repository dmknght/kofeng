/*
 * cell_state.h - what a walk over decoded code knows: register constants and a
 * small modelled stack. See cell_state.c for what it will and will not do.
 */
#ifndef KOFENG_CELL_STATE_H
#define KOFENG_CELL_STATE_H

#include <stdint.h>

struct cell_insn;

#define CELL_STACK 16u

struct cell_state {
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
	uint64_t stk[CELL_STACK];
	uint16_t stk_known;     /* bit i: stk[i] is a derived constant */
	uint8_t  stk_n;
};

void cell_state_reset(struct cell_state *k);
int  cell_state_reg(const struct cell_state *k, uint8_t r, uint64_t *out);
int  cell_state_stack_top(const struct cell_state *k, uint64_t *out);
/* Apply one decoded instruction to the map. */
void cell_state_track(struct cell_state *k, const struct cell_insn *in);

#endif /* KOFENG_CELL_STATE_H */
