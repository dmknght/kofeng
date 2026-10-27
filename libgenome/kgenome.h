#ifndef KGENOME_H
#define KGENOME_H

/*
 * kgenome.h - the one public header of kgenome, the analysis of executables.
 *
 * Like <uncoat.h> for kuncoat: the SURFACE of the lib is this header and the part
 * headers it lists below, and nothing else. A caller outside the lib includes
 * either this, or - when it uses one part - that part's header by its part path
 * (<celllysis/nucleo.h>); it never includes a header this one does not name, and
 * never a `_private.h`. tools/check_layers.py enforces that (LIB PUBLIC HEADERS),
 * and tests/unit/kgenome_header.c compiles a unit that includes only this.
 *
 * FIVE PARTS and the two headers they share:
 *
 *   kgenome_status.h  enum kgenome_status - whether an answer is complete. Every
 *                     limit in the lib sets it; none is silent (CLAUDE.md rule 4).
 *   kgenome_budget.h  struct kgenome_budget - what a call may cost, supplied by
 *                     the caller - and the ledger the lib charges its big products
 *                     to. The lib never reads engine state to find a limit.
 *
 *   genotype/         which instruction: the decoders (x86, arm32, arm64) and the
 *                     structure of the file - image/ (PE, ELF, CLR layout, the
 *                     function table, the rebuild writers).
 *   celllysis/        the analysis of code without running it: the decoder front
 *                     end (cell), the capability vocabulary (nucleo), address
 *                     spaces, cross-references, the library-span lines.
 *   textual/          the analysis of text with a grammar: the lexer, one directory a
 *                     language (php/), the API in the files beside them.
 *   phenotype/        the analysis that runs it: the emulator, the unpacking run,
 *                     the diagnose walk and its products (the diagnose graph).
 *
 * WHAT EVERY CALL FOLLOWS (CLAUDE.md section 12, "Rules every lib follows"):
 *   - names carry kgenome_ / KGENOME_;
 *   - the caller supplies the budget; limits scale with the input and the
 *     caller's budget is the DoS bound;
 *   - a limit that fires sets a kgenome_status, and the answer is "cannot say";
 *   - the big products are charged to budget.max_bytes by the lib's ledger.
 *
 * THREAD SAFETY. There is no writable global state: a scan, an emulator, a
 * walk and a ledger are the caller's objects and a lib call touches only what it
 * is handed. Audited by listing every writable data symbol of the built lib
 * (objdump -t, sections .data and .bss): the only ones left are the write-once
 * tables of the ARM decoders - the index of the arm32/thumb rows and the
 * first-level index of the arm64 tree - which are built on first use under an
 * atomic claim (arm32_index.c claim(), arm64.c g_l1_state): the first thread
 * builds, every other waits on the release store and reads them read-only after
 * it. Everything else the audit found was a const table that the dynamic linker
 * relocates (so it sits in .data) or a one-element cache of a build-time
 * constant in the emulator, which is gone (see win_trace in emu_interp.c).
 */

#include "kgenome_status.h"
#include "kgenome_budget.h"

/* genotype: the decoders and the structure of a file */
#include "genotype/genotype.h"
#include "genotype/image/obj.h"
#include "genotype/image/image_addr.h"
#include "genotype/image/section_flags.h"
#include "genotype/image/offmap.h"
#include "genotype/image/elf_types.h"
#include "genotype/image/elf_image.h"
#include "genotype/image/elf_rebuild.h"
#include "genotype/image/pe_types.h"
#include "genotype/image/pe_image.h"
#include "genotype/image/pe_rebuild.h"
#include "genotype/image/pe_unmap.h"
#include "genotype/image/infect.h"
#include "genotype/image/clr_types.h"
#include "genotype/image/clr_image.h"
#include "genotype/image/funcs.h"
#include "genotype/image/endian.h"

/* textual: text that has a grammar - the lexer of a script */
#include "textual/textual.h"

/* celllysis: reading code without running it */
#include "celllysis/arch.h"
#include "celllysis/capability.h"
#include "celllysis/cell.h"
#include "celllysis/decode.h"
#include "celllysis/space.h"
#include "celllysis/celllysis.h"
#include "celllysis/nucleo.h"
#include "celllysis/xref.h"
#include "celllysis/range_facts.h"
#include "celllysis/trueline.h"
#include "celllysis/mutation.h"
#include "celllysis/mutation_window.h"
#include "celllysis/fnprint.h"

/* phenotype: the emulator and what it produces */
#include "phenotype/emu.h"
#include "phenotype/emu_unpack.h"
#include "phenotype/diag_vocab.h"
#include "phenotype/diag_scan.h"
#include "phenotype/diag_text_names.h"
#include "phenotype/diag_scan_state.h"
#include "phenotype/diag_lineage.h"
#include "phenotype/codemap.h"

#endif /* KGENOME_H */
