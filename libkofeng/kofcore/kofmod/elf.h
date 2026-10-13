/*
 * elf.h - the ELF view of an object.
 *
 * THE ABI RE-EXPORTS kgenome's TYPE: the structures, constants and region
 * bits are defined once in libgenome/genotype/image/elf_types.h. What stays here is
 * what only a module needs - the accessor and the subtype-name resolver.
 *
 * Including this header declares that the module targets ELF, and a module may
 * include exactly one format header. The build script enforces that, and the
 * reason is the accessor below: kof_elf() casts ctx->fmt, and the cast is sound
 * only because the host does not call a module for a format the module did not
 * declare. Making the module check at runtime would move the guarantee from one
 * place that can be tested to N places that can each forget.
 *
 * So the prefilter is not a performance feature here. It is what makes the cast
 * safe. A detection that spans formats - "ELF with X, or PE with Y" - is written
 * as two modules with two targets and joined at the record layer, which also
 * prefilters better than one module that runs on both.
 */

#ifndef KOFENG_ELF_H
#define KOFENG_ELF_H

#include <stdint.h>
#include <kofmod/kofsig.h>
#include <genotype/image/elf_types.h>

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define KOF_ELFDATA_BE                     KGENOME_ELFDATA_BE
#define KOF_ELF_ANOM_SECTAB_MISSING        KGENOME_ELF_ANOM_SECTAB_MISSING
#define KOF_ELF_ANOM_SEC_PAST_EOF          KGENOME_ELF_ANOM_SEC_PAST_EOF
#define KOF_ELF_ANOM_SHOFF_PAST_EOF        KGENOME_ELF_ANOM_SHOFF_PAST_EOF
#define KOF_ELF_CORE                       KGENOME_ELF_CORE
#define KOF_ELF_DYN                        KGENOME_ELF_DYN
#define KOF_ELF_EXEC                       KGENOME_ELF_EXEC
#define KOF_ELF_MAX_SECTIONS               KGENOME_ELF_MAX_SECTIONS
#define KOF_ELF_MAX_SEGMENTS               KGENOME_ELF_MAX_SEGMENTS
#define KOF_ELF_NONE                       KGENOME_ELF_NONE
#define KOF_ELF_REL                        KGENOME_ELF_REL
#define KOF_ELF_TYPE_LIST(X) KGENOME_ELF_TYPE_LIST_(KOF_, X)   /* entries spelled KOF_*: #name is the word */
#define KOF_PERM_R                         KGENOME_PERM_R
#define KOF_PERM_W                         KGENOME_PERM_W
#define KOF_PERM_X                         KGENOME_PERM_X
#define KOF_SCAN_ELF_CLAIMED               KGENOME_SCAN_ELF_CLAIMED
#define KOF_SCAN_ELF_CODE                  KGENOME_SCAN_ELF_CODE
#define KOF_SCAN_ELF_DATA                  KGENOME_SCAN_ELF_DATA
#define KOF_SCAN_ELF_HEADERS               KGENOME_SCAN_ELF_HEADERS
#define KOF_SCAN_ELF_NOLOAD                KGENOME_SCAN_ELF_NOLOAD
#define KOF_SCAN_ELF_SLIB_CODE             KGENOME_SCAN_ELF_SLIB_CODE
#define KOF_SCAN_ELF_SLIB_DATA             KGENOME_SCAN_ELF_SLIB_DATA
#define KOF_SCAN_ELF_UNCLAIMED             KGENOME_SCAN_ELF_UNCLAIMED
#define kof_elf_info                       kgenome_elf_info
#define kof_elf_seg                        kgenome_elf_seg
#define kof_elf_write_hdr                  kgenome_elf_write_hdr

/* The identifier a signature source writes, to its value - the same direction
 * kof_arch_from_name goes, so a tool that resolves a ELF subtype asks this
 * header instead of matching the enum with a regex. */
static inline int kof_elf_type_from_name(const char *s, uint32_t *out)
{
#define KOF_SUB_X_FROM(name, val)                                            \
	if (kof_streq_(s, #name)) { *out = (uint32_t)(val); return 1; }
	KOF_ELF_TYPE_LIST(KOF_SUB_X_FROM)
#undef KOF_SUB_X_FROM
	return 0;
}

/*
 * The ELF view of a context.
 *
 * A plain cast, not a checked one. Returning NULL on mismatch would only move
 * the fault: a module that forgot to check would dereference NULL instead of
 * reading the wrong struct. The guarantee comes from two things that can be
 * verified once rather than per module - the build script rejects a module that
 * includes more than one format header, and the host does not invoke a module
 * whose declared target does not cover the object in hand.
 */
static inline const struct kof_elf_info *
kof_elf(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_elf_info *)ctx->file_header;
}

#endif /* KOFENG_ELF_H */
