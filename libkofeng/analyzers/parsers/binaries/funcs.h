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

#include "../scripts/script_sym.h"

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
/* The same block, grown the same way, for a script whose names the engine took from a scan it made (script_sym.h: kof_script_syms_with). */
uint32_t kof_syms_build_grow_script(kof_script_names_fn feed, void *feed_user, uint8_t **buf, uint32_t *cap, uint32_t *passes);

/*
 * THE NAME OF THE SYMBOL AT AN ADDRESS, read out of a symbol block. `shndx` of -1 matches any section; a relocatable object's values are
 * section-relative, so there the section is part of the answer. `out` is empty when no record matches.
 */
void kof_sym_name_at(const uint8_t *blk, uint32_t n, uint64_t value, int shndx, char *out, size_t cap);

/*
 * THE NAME OF A FUNCTION, in ONE place: its symbol when the block has one, else `fcn_<offset>` - the function's own file offset as 8 hex digits
 * (`fcn_000020ab`), a name MADE from where it is and never a guess at what it is. The blocks table's row, the CFG dialog's title and the callee
 * names of the CFG all say a function this way, so a stripped function is the same word in each. Returns 1 when a symbol named it, 0 when the name is
 * the made-up one. `out` is always NUL-ended (cap >= 1).
 */
int kof_func_name(const struct kgenome_func *f, const uint8_t *blk, uint32_t n, char *out, size_t cap);
/* The made-up name alone, for an address that is a call target and not an entry of the function table. */
void kof_fcn_name(uint64_t off, char *out, size_t cap);

#endif /* KOFENG_BINARIES_FUNCS_H */
