/*
 * elf_sym.h - building a KSYM block from an ELF.
 *
 * INTERNAL. The layout and the readers are in kofmod/kofsym.h, which is
 * published to modules; this is the half that needs the file's bytes and the
 * parsed section table, and it stays inside the engine. A module reaches the
 * result through kof_syms() instead - see kofmod/kofsig.h.
 */

#ifndef KOF_ELF_SYM_H
#define KOF_ELF_SYM_H

#include <kofcore.h>
#include <kofmod/kofsym.h>

struct kof_elf_info;

/*
 * Write the block for `file` into `out`, returning the bytes written - at
 * least KOF_SYM_HDRLEN, so an object with no symbols still yields a
 * well-formed empty block rather than nothing. Zero only if `cap` cannot hold
 * even the header.
 */
struct kof_func_set;
void kof_elf_funcs_build(kof_buf file, const struct kof_elf_info *e,
			 struct kof_func_set *out);
void kof_elf_funcs_from_entries(kof_buf file, const struct kof_elf_info *e,
				uint64_t entry_off, const uint64_t *ent,
				uint32_t n_ent, struct kof_func_set *out);
uint32_t kof_elf_syms(kof_buf file, const struct kof_elf_info *e,
		      uint8_t *out, uint32_t cap);

#endif /* KOF_ELF_SYM_H */
