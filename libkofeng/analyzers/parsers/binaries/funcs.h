#ifndef KOFENG_BINARIES_FUNCS_H
#define KOFENG_BINARIES_FUNCS_H

/*
 * funcs.h - the engine's door onto the function extents.
 *
 * The extent set (struct kgenome_func_set, kgenome_funcs_build, kgenome_funcs_remap...) is
 * the genome's: <image/funcs.h>, included here so every caller keeps working.
 * What stays is the KSYM block builder, kof_syms_build_grow (the single-shot
 * kof_syms_build, declared in kofmod/kofsym.h, and the static kof_syms_build_with
 * are in sym_any.c).
 */

#include <genotype/image/funcs.h>

/* The PE import table a caller may already hold for this object. */
struct kgenome_pe_imptab;

/*
 * The block for an object, in a buffer that is sized by the table and grown until
 * the block was not cut - see the definition. `*buf` and `*cap` are kept by the
 * caller and only grow.
 */
uint32_t kof_syms_build_grow(uint32_t format, const uint8_t *data, uint64_t data_n,
			     const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t **buf, uint32_t *cap, uint32_t *passes);

#endif /* KOFENG_BINARIES_FUNCS_H */
