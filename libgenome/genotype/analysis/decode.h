/*
 * decode.h - one decoded instruction, in the one form the engine reads.
 *
 * WHY THIS EXISTS.
 *
 * The sweep used to read whatever the decoder in front of it produced:
 * the decoder's INSTRUX on x86, hand-written bit tests for ARM, two more for
 * Thumb and the half-word encodings. So the same question - does this write
 * a register, where does this branch go, is this a call - was answered four
 * times in four spellings, and every one of them had to be kept correct
 * against the same corpus. A fifth architecture meant a fifth copy of the
 * sweep, not a fifth decoder.
 *
 * The form itself is kofmod/kdis.h's, which a signature module already
 * reads. One form, not two: a rule and the engine see the same instruction
 * the same way, and nothing has to be translated between them.
 *
 * NOT TEXT. There is no mnemonic string anywhere in it. A consumer that
 * wanted to know whether something was a call compared a number, and a
 * consumer that wanted the operand read a field; neither parsed anything.
 * Text belongs to whatever draws a screen, and drawing is not what this
 * layer is for.
 *
 * WHAT A DECODER PROMISES. `op` is never left at KDIS_OTHER when the class
 * is one the vocabulary has, `len` is the real length, `wmask` names EVERY
 * register the instruction writes including the ones it does not spell, and
 * an operand that is absent is KDIS_O_NONE rather than zeroed. A decoder
 * that cannot answer says so by returning 0 - it does not guess a length.
 */
#ifndef KOFENG_DISASM_DECODE_H
#define KOFENG_DISASM_DECODE_H

#include <stdint.h>

#include <kofmod/kdis.h>

/*
 * REGISTERS ARE AN INDEX AND THE ARCHITECTURE SAYS WHAT IT MEANS.
 *
 * x86-64 uses 0..15 in the decoder's own order - see gpr.h, which is where
 * the sweep's per-register arrays are sized from. ARM uses r0..r15, MIPS
 * $0..$31. The number is only ever used to index those arrays and to
 * compare two operands, so what matters is that one decoder is consistent
 * with itself, not that two architectures agree.
 */
#define KDIS_NREG 32u

/* Which special register a KDIS_MOV_SPECIAL touches, carried in `cond`. */
#define KDIS_SR_CR 0u
#define KDIS_SR_DR 1u
#define KDIS_SR_TR 2u

/*
 * THE LAST FEW INSTRUCTIONS, KEPT.
 *
 * A call's arguments are set by the instructions just before it, and the
 * sweep answers "what is in this register" from a model it has been
 * carrying since the body started - which is the right answer when the
 * model is right and nothing at all when the model lost the value. It
 * loses them constantly and for good reasons: a join it cannot merge, a
 * register an unmodelled instruction wrote, a branch it did not follow.
 *
 * So the instructions themselves are kept. At a call, "which of the last
 * few wrote rdi" is a question about the BYTES and cannot be wrong; the
 * model stays the first answer, and this is what is left when the model
 * has none. MEASURED on the shape it exists for: `mov $0x40f90f,%edi ;
 * call open` is two instructions apart and the model carried it, while
 * `xor %ebp,%ebp ; mov %ebp,%eax ; syscall` lost the number entirely
 * until the move was taught to copy constants.
 *
 * EIGHT, and the number is a window not a budget: a longer one costs a
 * linear walk per call and buys the arguments of a call whose setup is
 * further away than any compiler puts it. The sweep fills it as it goes,
 * so nothing is decoded twice.
 */
#define KDIS_WINDOW 8u

struct kdis_window {
	struct kdis_insn in[KDIS_WINDOW];
	uint32_t n;             /* how many are valid, at most KDIS_WINDOW */
	uint32_t head;          /* where the NEXT one goes */
};

static inline void kdis_window_put(struct kdis_window *w,
				   const struct kdis_insn *ins)
{
	w->in[w->head] = *ins;
	w->head = (w->head + 1u) % KDIS_WINDOW;
	if (w->n < KDIS_WINDOW)
		w->n++;
}

/* The i-th most recent, 0 being the one just put in. NULL past the end. */
static inline const struct kdis_insn *kdis_window_back(
			const struct kdis_window *w, uint32_t i)
{
	if (i >= w->n)
		return NULL;
	return &w->in[(w->head + KDIS_WINDOW - 1u - i) % KDIS_WINDOW];
}

/*
 * THE MOST RECENT INSTRUCTION THAT WROTE `reg`, or NULL.
 *
 * What a call's argument was set by, asked of the bytes. The caller still
 * has to read the answer: a `mov reg, imm` gives the value outright, a
 * `mov reg, reg` only moves the question along.
 */
static inline const struct kdis_insn *kdis_window_wrote(
			const struct kdis_window *w, uint32_t reg)
{
	uint32_t i;

	if (reg >= 64u)
		return NULL;
	for (i = 0; i < w->n; i++) {
		const struct kdis_insn *k = kdis_window_back(w, i);

		if (k->wmask & (1ull << reg))
			return k;
	}
	return NULL;
}

/*
 * ONE INSTRUCTION, DECODED - or 0 when these bytes are not one.
 *
 * `va` is the address the instruction would run at, which the decoder needs
 * for a relative branch and for rip-relative addressing.
 */
uint32_t kof_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			unsigned bits, struct kdis_insn *out);

/* `be` is big-endian; MIPS ships both ways and bots use both. */
uint32_t kof_decode_mips(const uint8_t *p, uint32_t n, uint64_t va,
			 int be, struct kdis_insn *out);

#endif /* KOFENG_DISASM_DECODE_H */
