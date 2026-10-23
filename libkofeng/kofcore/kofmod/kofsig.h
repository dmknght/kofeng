/*
 * kofsig.h - the ABI between the host and a signature module.
 *
 * Including this header declares the translation unit to be a signature module.
 * A module:
 *
 *   - exports exactly one entry point, kof_scan()
 *   - reaches the engine only through the scan context it is handed
 *   - never refers to anything outside its own blob by symbol
 *   - has no writable data (.data / .bss)
 *   - is position independent
 *
 * No external symbols means nothing to resolve at load time, so loading is a copy
 * and an mprotect. No writable data means one mapped copy serves every thread.
 * ksigbuilder enforces all of it on the object.
 *
 * A consequence to know before writing a module: string literals are fine, arrays
 * of pointers to them are not - those land in .data.rel.ro with relocations against
 * them. Where a list is needed, use one NUL separated literal.
 *
 * Format specific facts come from a format header (elf.h, later pe.h), and a module
 * may include exactly one: see kof_elf() in elf.h.
 *
 * THIS FILE IS THE UMBRELLA. A module includes it and nothing under it; the
 * parts are split by what they are for, and the docs sit with their code:
 *
 *   kofabi.h       ABI version
 *   kofobjfmt.h    object format, target axis, format and arch names
 *   kofname.h      what a family name and a comment may hold
 *   kofregion.h    region masks, extent bound, measured region shape
 *   kofcontent.h   struct kof_content, the vtable behind ctx->content
 *   kofentry.h     decoder ids, entry kinds, struct kof_entry
 *   kofctx.h       struct kof_obj_ctx, the context a module is handed
 *   kofdefine.h    kof_scan / kof_unpack and the macros defining them
 *   kofsearch.h    kof_find_str and its folds, offset forms, anchors
 *   kofmeasure.h   kof_mutation_score and the similarity measures
 *   kofdiagnose.h  kof_diag, diagnose ids, node sharing
 *   kofread.h      scalar reads, records, cross references, region measures
 *   kofchild.h     producing a child: declare, fill, decode, decrypt
 *   kofmodemu.h    driving the interpreter, reading the machine and the code
 *   kofverdict.h   engine, verdict and malware type lists
 *   kofdeclare.h   declarations the build reads: targets, names, strings
 *   kofhit.h       marking, noting
 */

#ifndef KOFENG_KOFSIG_H
#define KOFENG_KOFSIG_H

#include <stdint.h>
/* The capability vocabulary - see nucleo.c. No rule names one yet. */
#include <kofmod/kofcap.h>

/* The sentinels, and the architecture list - small enough to need no format
 * header, and shared with the code reader. */
#include "basic.h"
/* The format limits a method id carries; defined by kuncoat, which is what
 * checks them. Re-exported so a module reads them where it always did. */
#include <decompressors/format_limits.h>

/* module-facing names: the lib defines KUNCOAT_*, the ABI keeps the old spelling */
#define KOF_LZMA_MAX_LC  KUNCOAT_LZMA_MAX_LC
#define KOF_LZMA_MAX_LP  KUNCOAT_LZMA_MAX_LP
#define KOF_LZMA_MAX_PB  KUNCOAT_LZMA_MAX_PB
#define KOF_LZX_MAX_BITS KUNCOAT_LZX_MAX_BITS
#define KOF_LZX_MIN_BITS KUNCOAT_LZX_MIN_BITS

/* The code reader's vocabulary - see cell.h for what it is for. */
#include "cell.h"
#include <range.h>   /* struct kof_range - core */
#include <celllysis/xref.h>   /* KOF_XREF_*, what code does to an address */
#include <genotype/image/section_flags.h>   /* KOF_SECF_*, what a declared section is */

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define DIAG_MAX_NODE                      KGENOME_DIAG_MAX_NODE
#define KOF_SECF_CIPHERTEXT                KGENOME_SECF_CIPHERTEXT
#define KOF_SECF_CODE                      KGENOME_SECF_CODE
#define KOF_SECF_DATA                      KGENOME_SECF_DATA
#define KOF_SECF_HOLLOW                    KGENOME_SECF_HOLLOW
#define KOF_SECF_PAD                       KGENOME_SECF_PAD
#define KOF_SECF_READ                      KGENOME_SECF_READ
#define KOF_SECF_REBUILT                   KGENOME_SECF_REBUILT
#define KOF_SECF_SYNTHETIC                 KGENOME_SECF_SYNTHETIC
#define KOF_XREF_ARG                       KGENOME_XREF_ARG
#define KOF_XREF_CALL                      KGENOME_XREF_CALL
#define KOF_XREF_JUMP                      KGENOME_XREF_JUMP
#define KOF_XREF_PARTIAL                   KGENOME_XREF_PARTIAL
#define kof_diag_kind                      kgenome_diag_kind
#define kof_diag_role_of_arg               kgenome_diag_role_of_arg
#define kof_diag_str                       kgenome_diag_str
#define kof_diag_str_add                   kgenome_diag_str_add
#define kof_emu_get_reg                    kgenome_emu_get_reg
#define kof_emu_read                       kgenome_emu_read
#define kof_emu_watch                      kgenome_emu_watch
#define kof_flow_name_arg                  kgenome_nucleo_name_arg
#define kof_true_find                      kgenome_true_find
#define kof_xref_in                        kgenome_xref_in

/* The two kinds of range kof_mark_infected takes. */
#include "infected.h"
#include "disease.h"      /* KOF_DECLARE_DISEASE, what a detector finds */
#include "kofdecode.h"    /* struct kof_capsid, what a module asks the host to decrypt with */

#include "kofabi.h"
#include "kofobjfmt.h"
#include "kofname.h"
#include "kofregion.h"
#include "kofcontent.h"
#include "kofentry.h"
#include "kofctx.h"
#include "kofdefine.h"
#include "kofsearch.h"
#include "kofmeasure.h"
#include "kofdiagnose.h"
#include "kofread.h"
#include "kofchild.h"
#include "kofmodemu.h"
#include "kofverdict.h"
#include "kofdeclare.h"
#include "kofhit.h"

#endif /* KOFENG_KOFSIG_H */
