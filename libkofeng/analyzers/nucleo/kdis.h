/*
 * kdis.h - the engine side of the module-facing code reader.
 *
 * The vocabulary a module sees is kofmod/kdis.h; this is the cursor, the
 * offset/address mapping that needs the object, and the entry points that move
 * it. What registers hold is genotype's (kdis_state.h). It lives in the scanner, one
 * per object being scanned, because a module walks one run of code at a time
 * and an allocation per walk would be a handle in the module ABI for no gain.
 */
#ifndef KOFENG_KDIS_ENGINE_H
#define KOFENG_KDIS_ENGINE_H

#include <stdint.h>

#include "../../../libgenome/genotype/analysis/kdis_state.h"

struct kof_obj_ctx;
struct kdis_insn;

struct kof_kdis {
	uint64_t at;            /* the cursor, a file offset */
	struct kdis_state st;   /* what the walk knows: see kdis_state.h */
	uint8_t  open;
	uint8_t  map_ok;        /* the window below has been established */
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
