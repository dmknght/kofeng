#ifndef KGENOME_IMAGE_FNTAB_PRIVATE_H
#define KGENOME_IMAGE_FNTAB_PRIVATE_H

/* fntab_private.h - what the parts of the function table (fntab_*.c) share. Not part of the lib's surface. */

#include "fntab.h"

/* Where the unwind table of an ELF is: the section named .eh_frame (PROGBITS or the x86-64 unwind type, ALLOC), or the
 * PT_GNU_EH_FRAME segment (the search header, which names .eh_frame and works with no section table). 1 and the index, or 0. */
int kgenome_fntab_eh_section(const struct kgenome_elf_info *e, uint32_t *idx);
int kgenome_fntab_eh_segment(const struct kgenome_elf_info *e, uint32_t *idx);

/* An entry whose END a source established: a symbol's size, an unwind length, the one decoded instruction of an import stub. The merge and the GAPS step read it. */
static inline int kgenome_fntab_exact(const struct kgenome_func *f)
{
	return f->end_source == KGENOME_FN_E_SYMBOL || f->end_source == KGENOME_FN_E_UNWIND || f->end_source == KGENOME_FN_E_INSN;
}

/* Does the file offset lie in a section of stubs (kgenome_elf_sec_is_stub: the executable sections that are not the one the entry point is in - .plt, .plt.got, .plt.sec, .init, .fini)? The
 * linker's and the loader's code is not the program's: no function of the table starts or is named there (the unwind strategy and the entry walk ask; FNTAB-COV-3). */
struct kgenome_fntab_meta;
struct kgenome_fntab_plan;
/* The PE half of kgenome_fntab_probe / kgenome_fntab_select (fntab_pe_select.c), called by the format. */
void kgenome_pe_probe(kof_buf file, const void *info, struct kgenome_fntab_meta *m);
struct kgenome_fntab_plan kgenome_pe_select(const struct kgenome_fntab_meta *m);

struct kgenome_elf_info;
int kgenome_fntab_in_stub_section(const struct kgenome_elf_info *e, uint64_t off);

/* THE PE'S CODE, ONE DEFINITION FOR THE PE STRATEGIES (fntab_pe_common.c). The executable section (kgenome_pe_sec_is_code: IMAGE_SCN_MEM_EXECUTE, what the loader acts on) whose
 * RAW bytes hold RVA `rva`: its file offset in `*off` and the file offset where that section's bytes end (clipped to the file) in `*end`. 0 when the RVA is in no section, in a section
 * that is not executable, or in the part of one that the file does not hold. The same sections kgenome_diag_extent offers the walk, so a start made here is a start the walk's code covers. */
struct kgenome_pe_info;
int kgenome_fntab_pe_code_rva(const struct kgenome_pe_info *p, kof_buf file, uint64_t rva, uint64_t *off, uint64_t *end);

#endif
