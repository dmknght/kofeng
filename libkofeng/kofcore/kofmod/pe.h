/*
 * pe.h - the PE view of an object.
 *
 * Including this header declares that the module targets PE, and a module may
 * include exactly one format header. The build script enforces that, and the
 * reason is the accessor below: kof_pe() casts ctx->file_header, and the cast is
 * sound only because the host does not call a module for a format the module did
 * not declare.
 *
 * THE ABI RE-EXPORTS kgenome's TYPE: the structures, constants and region
 * bits are defined once in libgenome/genotype/image/pe_types.h (with the notes on how
 * the PE view differs from the ELF one). What stays here is what only a module
 * needs.
 */

#ifndef KOFENG_PE_H
#define KOFENG_PE_H

#include <stdint.h>
#include <kofmod/kofsig.h>
#include <genotype/image/pe_types.h>

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define KOF_PE_DIR_IAT                     KGENOME_PE_DIR_IAT
#define KOF_PE_DIR_IMPORT                  KGENOME_PE_DIR_IMPORT
#define KOF_PE_DIR_RESOURCE                KGENOME_PE_DIR_RESOURCE
#define KOF_PE_DLL                         KGENOME_PE_DLL
#define KOF_PE_EXE                         KGENOME_PE_EXE
#define KOF_PE_IMAGE_LIST(X) KGENOME_PE_IMAGE_LIST_(KOF_, X)   /* entries spelled KOF_*: #name is the word */
#define KOF_PE_MAX_SECTIONS                KGENOME_PE_MAX_SECTIONS
#define KOF_PE_ORIGIN_DELETED              KGENOME_PE_ORIGIN_DELETED
#define KOF_PE_ORIGIN_MANUAL               KGENOME_PE_ORIGIN_MANUAL
#define KOF_PE_PERM_R                      KGENOME_PE_PERM_R
#define KOF_PE_PERM_W                      KGENOME_PE_PERM_W
#define KOF_PE_PERM_X                      KGENOME_PE_PERM_X
#define KOF_PE_SECNAME_MAX                 KGENOME_PE_SECNAME_MAX
#define KOF_PE_SYS                         KGENOME_PE_SYS
#define KOF_SCAN_PE_CLAIMED                KGENOME_SCAN_PE_CLAIMED
#define KOF_SCAN_PE_CODE                   KGENOME_SCAN_PE_CODE
#define KOF_SCAN_PE_DATA                   KGENOME_SCAN_PE_DATA
#define KOF_SCAN_PE_HEADERS                KGENOME_SCAN_PE_HEADERS
#define KOF_SCAN_PE_OVERLAY                KGENOME_SCAN_PE_OVERLAY
#define KOF_SCAN_PE_RESOURCE               KGENOME_SCAN_PE_RESOURCE
#define KOF_SCAN_PE_SIGNATURE              KGENOME_SCAN_PE_SIGNATURE
#define KOF_SCAN_PE_UNCLAIMED              KGENOME_SCAN_PE_UNCLAIMED
#define kof_pe_info                        kgenome_pe_info
#define kof_pe_is_mapped                   kgenome_pe_is_mapped
#define kof_pe_rva_to_off                  kgenome_pe_rva_to_off
#define kof_pe_sec                         kgenome_pe_sec

/* The identifier a signature source writes, to its value - the same direction
 * kof_arch_from_name goes, so a tool that resolves a PE subtype asks this
 * header instead of matching the enum with a regex. */
static inline int kof_pe_image_from_name(const char *s, uint32_t *out)
{
#define KOF_SUB_X_FROM(name, val)                                            \
	if (kof_streq_(s, #name)) { *out = (uint32_t)(val); return 1; }
	KOF_PE_IMAGE_LIST(KOF_SUB_X_FROM)
#undef KOF_SUB_X_FROM
	return 0;
}

/*
 * The PE view of the object under scan.
 *
 * Sound because the module declared KOF_FMT_PE and the host does not run a module
 * against a format its target does not cover.
 */
static inline const struct kof_pe_info *kof_pe(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_pe_info *)ctx->file_header;
}

/*
 * A SECTION'S PERMISSIONS, IN THE VOCABULARY A DECLARATION USES.
 *
 * The parser reports KOF_PE_PERM_*, which is this format's word for them.
 * kunp_rcstruct_section takes KUNP_PERM_*, which is format-neutral because a
 * module may target more than one format and must not have to know which
 * format's constants it is holding.
 *
 * The two families happen to have the same three values, and every module here
 * was passing the parser's word straight through on that coincidence - which
 * is the exact confusion KUNP_PERM_* was introduced to remove. Said once, so
 * that nothing relies on the numbers agreeing and a module that names the
 * wrong family is a compile error rather than a silent success.
 */
static inline uint32_t kof_pe_perm_decl(uint32_t pe_perm)
{
	uint32_t p = 0;

	if (pe_perm & KOF_PE_PERM_X)
		p |= KUNP_PERM_X;
	if (pe_perm & KOF_PE_PERM_W)
		p |= KUNP_PERM_W;
	if (pe_perm & KOF_PE_PERM_R)
		p |= KUNP_PERM_R;
	return p;
}

#endif /* KOFENG_PE_H */
