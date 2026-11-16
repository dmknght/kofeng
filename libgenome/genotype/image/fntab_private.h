#ifndef KGENOME_IMAGE_FNTAB_PRIVATE_H
#define KGENOME_IMAGE_FNTAB_PRIVATE_H

/* fntab_private.h - what the parts of the function table (fntab_*.c) share. Not part of the lib's surface. */

#include "fntab.h"

/* Where the unwind table of an ELF is: the section named .eh_frame (PROGBITS or the x86-64 unwind type, ALLOC), or the
 * PT_GNU_EH_FRAME segment (the search header, which names .eh_frame and works with no section table). 1 and the index, or 0. */
int kgenome_fntab_eh_section(const struct kgenome_elf_info *e, uint32_t *idx);
int kgenome_fntab_eh_segment(const struct kgenome_elf_info *e, uint32_t *idx);

/* An entry whose END a source established: a symbol's size, an unwind length, the Go table's next row, the one decoded instruction of an import stub (DISABLED source). The merge and the GAPS step read it. */
static inline int kgenome_fntab_exact(const struct kgenome_func *f)
{
	return (f->end_source == KGENOME_FN_E_SYMBOL || f->end_source == KGENOME_FN_E_UNWIND || f->end_source == KGENOME_FN_E_INSN || f->end_source == KGENOME_FN_E_PCTAB) &&
	       !(f->flags & KGENOME_FN_F_NOTYPE);      /* PMA-3: a NOTYPE symbol's size is not a function's end */
}

/* Does the file offset lie in a section of stubs (kgenome_elf_sec_is_stub: the executable sections that are not the one the entry point is in - .plt, .plt.got, .plt.sec, .init, .fini)? The
 * linker's and the loader's code. Since round 3 (audit PMA-1) the function table no longer refuses it: an FDE or a loader-table start there is a function; only the disabled entry walk asks. */
struct kgenome_fntab_meta;
struct kgenome_fntab_plan;
/* The PE half of kgenome_fntab_probe / kgenome_fntab_select (fntab_pe_select.c), called by the format. */
void kgenome_pe_probe(kof_buf file, const void *info, struct kgenome_fntab_meta *m);
struct kgenome_fntab_plan kgenome_pe_select(const struct kgenome_fntab_meta *m);

struct kgenome_elf_info;
int kgenome_fntab_in_stub_section(const struct kgenome_elf_info *e, uint64_t off);

/* THE ELF'S CODE, ONE DEFINITION FOR THE START-ONLY ELF STRATEGIES (fntab_select.c): the file offset of address `va` when it lies in the file half of a loadable segment that is
 * executable and in no section of stubs - the rule the unwind strategy applies to an FDE's start. 0 otherwise. */
int kgenome_fntab_elf_code_va(const struct kgenome_elf_info *e, uint64_t va, uint64_t *off);

/* The section of an ELF whose type is `type` (and, when `name` is not NULL, whose name is `name`), with file bytes: 1 and its index, or 0. */
int kgenome_fntab_elf_section(const struct kgenome_elf_info *e, uint32_t type, const char *name, uint32_t *idx);

/* THE PE'S CODE, ONE DEFINITION FOR THE PE STRATEGIES (fntab_pe_common.c). The executable section (kgenome_pe_sec_is_code: IMAGE_SCN_MEM_EXECUTE, what the loader acts on) whose
 * RAW bytes hold RVA `rva`: its file offset in `*off` and the file offset where that section's bytes end (clipped to the file) in `*end`. 0 when the RVA is in no section, in a section
 * that is not executable, or in the part of one that the file does not hold. The same sections kgenome_diag_extent offers the walk, so a start made here is a start the walk's code covers. */
struct kgenome_pe_info;
int kgenome_fntab_pe_code_rva(const struct kgenome_pe_info *p, kof_buf file, uint64_t rva, uint64_t *off, uint64_t *end);

#endif
