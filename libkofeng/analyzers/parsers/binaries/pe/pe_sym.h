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
/* kgenome_pe_funcs_build moved to the genome (RUNTIME_FUNCTION table); still
 * reachable from here for the callers that came through this header. */
#include <genotype/image/funcs.h>

struct kgenome_pe_info;
struct kgenome_pe_imptab;

/*
 * Write the block for `file` into `out`, returning the bytes written - at
 * least KOF_SYM_HDRLEN, so a PE with neither directory still yields a
 * well-formed empty block. Zero only if `cap` cannot hold the header.
 */
uint32_t kof_pe_syms(kof_buf file, const struct kgenome_pe_info *p,
		     uint8_t *out, uint32_t cap);

/*
 * The same, reading the imports from a table the caller already built from
 * `file` - see kgenome_pe_imptab in pe_parse.h - instead of walking the directory
 * again. NULL builds one for this call, which is what kof_pe_syms is.
 */
uint32_t kof_pe_syms_with(kof_buf file, const struct kgenome_pe_info *p,
			  const struct kgenome_pe_imptab *tab,
			  uint8_t *out, uint32_t cap);

/*
 * Insert imports the program resolved for itself, after the last import and
 * before the exports. Returns the new length in bytes. See the definition for
 * the rules; `dll` and `name` are `n` parallel strings.
 */
uint32_t kof_pe_syms_add_imports(uint8_t *blk, uint32_t n_bytes, uint32_t cap,
				 const char *const *dll, const char *const *name,
				 uint32_t n);

/* The bytes inserting these `n` imports can add - the room to make in `cap` first.
 * A block that cannot hold them is left as it was, with its truncated byte set. */
uint32_t kof_pe_syms_add_room(const char *const *dll, const char *const *name,
			      uint32_t n);

#endif /* KOF_PE_SYM_H */
