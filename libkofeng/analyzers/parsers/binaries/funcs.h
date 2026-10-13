#ifndef KOFENG_BINARIES_FUNCS_H
#define KOFENG_BINARIES_FUNCS_H

/*
 * funcs.h - the engine's door onto the function extents.
 *
 * The extent set (struct kgenome_func_set, kgenome_funcs_build, kgenome_funcs_remap...) is
 * the genome's: <image/funcs.h>, included here so every caller keeps working.
 * What stays is kof_syms_build_with, which is a KSYM block builder.
 */

#include <genotype/image/funcs.h>

/*
 * kof_syms_build, for a caller that already holds the PE import table of this
 * object - see kgenome_pe_imptab. NULL, and any format but PE, behave exactly as
 * kof_syms_build does.
 */
struct kgenome_pe_imptab;
uint32_t kof_syms_build_with(uint32_t format, const uint8_t *data,
			     uint64_t data_n, const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t *out, uint32_t cap);

/*
 * HOW MANY RECORDS THIS OBJECT'S SYMBOL TABLE DECLARES, so the caller sizes the
 * block by the table it has instead of by a constant (KOF_SYM_ABS_MAX_RECS
 * bounds it). ELF: the table's own count. Any other format: 0, which means
 * "not known up front" - the caller grows the block until the builder says it
 * was not cut.
 */
uint32_t kof_syms_declared(uint32_t format, const uint8_t *data, uint64_t data_n,
			   const void *info);

/*
 * The block for an object, in a buffer that is sized by the table and grown until
 * the block was not cut - see the definition. `*buf` and `*cap` are kept by the
 * caller and only grow.
 */
uint32_t kof_syms_build_grow(uint32_t format, const uint8_t *data, uint64_t data_n,
			     const void *info,
			     const struct kgenome_pe_imptab *imports,
			     uint8_t **buf, uint32_t *cap);

#endif /* KOFENG_BINARIES_FUNCS_H */
