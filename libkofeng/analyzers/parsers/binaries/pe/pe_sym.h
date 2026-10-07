/*
 * pe_sym.h - building a KSYM block from a PE's imports and exports.
 *
 * INTERNAL, for the reason elf_sym.h is: the layout and the readers are in
 * kofmod/kofsym.h and published to modules, while this half needs the file's
 * bytes and the parsed directories and stays inside the engine. A module
 * reaches the result through kof_syms().
 */

#ifndef KOF_PE_SYM_H
#define KOF_PE_SYM_H

#include <kofcore.h>
#include <kofmod/kofsym.h>

struct kof_pe_info;

/*
 * Write the block for `file` into `out`, returning the bytes written - at
 * least KOF_SYM_HDRLEN, so a PE with neither directory still yields a
 * well-formed empty block. Zero only if `cap` cannot hold the header.
 */
uint32_t kof_pe_syms(kof_buf file, const struct kof_pe_info *p,
		     uint8_t *out, uint32_t cap);

/*
 * Insert imports the program resolved for itself, after the last import and
 * before the exports. Returns the new length in bytes. See the definition for
 * the rules; `dll` and `name` are `n` parallel strings.
 */
uint32_t kof_pe_syms_add_imports(uint8_t *blk, uint32_t n_bytes, uint32_t cap,
				 const char *const *dll, const char *const *name,
				 uint32_t n);

#endif /* KOF_PE_SYM_H */
