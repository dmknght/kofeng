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
 * THE NAME OF THE SYMBOL AT AN ADDRESS, read out of a symbol block. `value` is NULL when the caller has no
 * address to look up (not a sentinel of 0 - a real symbol can sit at value 0, e.g. -ffunction-sections or a
 * .ko shape). `shndx` of -1 matches any section; a relocatable object's values are section-relative, so there
 * the section is part of the answer. `out` is empty when no record matches.
 */
void kof_sym_name_at(const uint8_t *blk, uint32_t n, const uint64_t *value, int shndx, char *out, size_t cap);

/*
 * THE NAME OF A FUNCTION, in ONE place: its symbol when the block has one, else - for a script
 * (kind KGENOME_FN_SCRIPT) - the identifier its own declaration shape named (name_off/name_len,
 * image/funcs.h, read out of `data`/`data_n`, the object's own bytes); a script entry with NO
 * declared name (an anonymous closure, or a caller's own throwaway entry for a mutation cut's
 * "remainder" piece between real functions) is `block_<line>` - the 1-based source line its `off`
 * sits on (sym_any.c's kof_script_line_of) - because a script has no "function" word for a bare
 * file offset to imply; an ELF/PE entry (kind != KGENOME_FN_SCRIPT) nothing names is `fcn_<offset>` -
 * its own file offset as 8 hex digits (`fcn_000020ab`), a name MADE from where it is and never a
 * guess at what it is. The blocks table's row, the CFG dialog's title and the callee names of the
 * CFG all say a function this way, so the same unnamed place reads the same word everywhere.
 * Returns 1 when a real name was found (a symbol or a script's own identifier), 0 when the name is
 * a made-up one (`block_<line>` or `fcn_<offset>`). `data`/`data_n` may be NULL/0 when the caller
 * has no script function to name (an ELF/PE function never reads them). `out` is always NUL-ended
 * (cap >= 1).
 */
int kof_func_name(const struct kgenome_func *f, const uint8_t *blk, uint32_t n,
		  const uint8_t *data, uint64_t data_n, char *out, size_t cap);
/* The made-up name alone, for an address that is a call target and not an entry of the function table. */
void kof_fcn_name(uint64_t off, char *out, size_t cap);

#endif /* KOFENG_BINARIES_FUNCS_H */
