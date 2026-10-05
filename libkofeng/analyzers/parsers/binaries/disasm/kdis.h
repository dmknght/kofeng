/*
 * kdis.h - the engine side of the module-facing code reader.
 *
 * The vocabulary a module sees is kofmod/kdis.h; this is only the cursor's
 * state and the three entry points that move it. It lives in the scanner, one
 * per object being scanned, because a module walks one run of code at a time
 * and an allocation per walk would be a handle in the module ABI for no gain.
 */
#ifndef KOFENG_KDIS_ENGINE_H
#define KOFENG_KDIS_ENGINE_H

#include <stdint.h>

struct kof_obj_ctx;
struct kdis_insn;

#define KDIS_STACK 16u

struct kof_kdis {
	uint64_t at;            /* the cursor, a file offset */
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
	uint64_t stk[KDIS_STACK];
	uint16_t stk_known;     /* bit i: stk[i] is a derived constant */
	uint8_t  stk_n;
	uint8_t  open;
	uint8_t  map_ok;        /* the window below has been established */
	uint8_t  _pad[3];
	/*
	 * THE MAPPING WINDOW THE CURSOR IS CURRENTLY INSIDE.
	 *
	 * Every instruction needs its own address, because that is what a
	 * relative branch is computed from - so the offset-to-address
	 * conversion runs once per instruction, and in the segment table it
	 * is a linear walk. MEASURED over a 12 MB subset: 1.3 million walks
	 * for 1.3 million instructions, all but a handful of them finding
	 * the same segment as the walk before.
	 *
	 * A segment is contiguous in both spaces, so inside one the
	 * conversion is a single addition. `map_lo`/`map_hi` are the file
	 * offsets the window covers and `map_delta` is address minus offset
	 * across it; the walk only runs when the cursor leaves the window,
	 * which for a sweep is once per segment.
	 *
	 * INVALIDATED BY kof_kdis_seek AND NOT BY COMPARING THE CONTEXT.
	 * A kof_obj_ctx is a local in scan_object, so the NEXT object's
	 * context is very often at the same address as this one's - a
	 * pointer compare would say "same object" about a different file.
	 * Every walk starts with a seek, so clearing it there is both
	 * sufficient and impossible to get wrong.
	 */
	uint64_t map_lo, map_hi;
	int64_t  map_delta;
};

int kof_kdis_seek(struct kof_kdis *k, uint64_t off, int keep);
int kof_kdis_next(struct kof_kdis *k, const struct kof_obj_ctx *ctx,
		  const uint8_t *base, uint64_t size, struct kdis_insn *out);
int kof_kdis_reg(const struct kof_kdis *k, uint8_t r, uint64_t *out);

#endif /* KOFENG_KDIS_ENGINE_H */
