/*
 * obj.h - the object kgenome analyses, as kgenome defines it.
 *
 * The lib defines what it reads; the engine's HEAD functions (the ones that
 * take the engine's `struct kof_obj_ctx`) fill this and call the lib. Nothing
 * in libgenome includes the engine's object: every function that used to take
 * a context takes a `const struct kgenome_obj *`, and the one place that knows
 * both is the engine's adapter (kof_genome_obj, libkofeng/analyzers/genome_obj.h).
 *
 * It is plain data: no callback into the engine, no pointer to engine state.
 * It sits in genotype/image because it names the structure of an executable
 * (format, architecture, the parsed header) and celllysis and phenotype already
 * include this directory, never the other way round.
 *
 * `file_header` is the parsed view - a `struct kgenome_elf_info` for
 * KGENOME_FMT_ELF, a `struct kgenome_pe_info` for KGENOME_FMT_PE - and the two
 * accessors below are the only place that cast is made. A plain cast, not a
 * checked one, as the engine's kof_elf()/kof_pe() are.
 *
 * The descriptor is BORROWED by whatever walks the object (a kgenome_cell_space keeps a
 * pointer to it): it must outlive the call that was handed it.
 */
#ifndef KGENOME_IMAGE_OBJ_H
#define KGENOME_IMAGE_OBJ_H

#include <stdint.h>

#include <celllysis/arch.h>          /* KGENOME_NA, KGENOME_BROKEN, enum kgenome_arch */
#include <genotype/image/elf_types.h>
#include <genotype/image/pe_types.h>

/*
 * The formats kgenome analyses. The values are the engine's `enum kof_format`
 * values for the same formats (kofsig.h asserts it), so a descriptor field and
 * an engine format are the same number.
 */
enum kgenome_fmt {
	KGENOME_FMT_NONE = 0,
	KGENOME_FMT_ELF  = 1,
	KGENOME_FMT_PE   = 2
};

struct kgenome_obj {
	uint8_t  format;        /* enum kgenome_fmt */
	uint8_t  arch;          /* enum kgenome_arch */
	uint8_t  subtype;       /* ELF: e_type verbatim; PE: KGENOME_PE_DLL/SYS/... */
	uint8_t  reserved;
	uint64_t obj_size;
	uint64_t entry_off;     /* KGENOME_NA if not applicable, KGENOME_BROKEN if unresolved */
	const void *file_header; /* the parsed view, see above; NULL if none */
};

static inline const struct kgenome_elf_info *
kgenome_obj_elf(const struct kgenome_obj *obj)
{
	return (const struct kgenome_elf_info *)obj->file_header;
}

static inline const struct kgenome_pe_info *
kgenome_obj_pe(const struct kgenome_obj *obj)
{
	return (const struct kgenome_pe_info *)obj->file_header;
}

#endif /* KGENOME_IMAGE_OBJ_H */
