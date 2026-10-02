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

#endif /* KOF_PE_SYM_H */
