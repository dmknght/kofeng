/*
 * scan_types.h - the constants, enums and small types the scan state is built from.
 *
 * Split out of scan.h with the includes those types need. The state itself is
 * scan_state.h (struct kof_scanner and the sub-structs it is made of); the
 * functions are scan.h. Include scan.h, not this file.
 */

#ifndef KOFENG_SCAN_TYPES_H
#define KOFENG_SCAN_TYPES_H

#include "objsrc.h"
#include "objprod.h"
#include "../analyzers/parsers/binaries/funcs.h"
#include <celllysis/celllysis.h>
#include "../analyzers/parsers/binaries/elf/elf_parse.h"
#include <genotype/image/pe_rebuild.h>
#include "../kofcore/koftypes.h"
#include "../kofcore/kofhash.h"   /* KOF_ERR_*, SHA-256 */
/* KGENOME_EMU_EXEC_WATCH bounds the per-object list below; the interpreter owns
 * the number because it owns the list it is copied into. */
#include <phenotype/emu.h>
#include <phenotype/emu_unpack.h>
#include "../databases/dbloader.h"
#include "../detectors/pattern/kofmatch.h"
#include "../detectors/mutations/kofmutation.h"
#include "../analyzers/parsers/binaries/pe/pe_parse.h"
#include "../analyzers/parsers/containers/gzip_parse.h"
#include "../analyzers/parsers/containers/docole_parse.h"
#include "../analyzers/parsers/containers/zip_parse.h"
#include "../analyzers/parsers/containers/tar_parse.h"
#include "../analyzers/parsers/containers/sevenzip_parse.h"
#include "../analyzers/parsers/containers/rar_parse.h"
#include "../analyzers/parsers/containers/xz_parse.h"
#include "../analyzers/parsers/containers/rtf_parse.h"
#include "../analyzers/parsers/containers/pdf_parse.h"
#include <uncoat.h>

/*
 * THE SWEPT CALL CHAINS OF ONE OBJECT STOOD HERE, and the set that held
 * them, and the sweep that filled it. All of it is gone - see the note on
 * the removed macros in kofmod/kofsig.h for why a chain could not hold a
 * producer with several consumers, a step joined by control, or a rule that
 * an inserted instruction cannot shift.
 *
 * TWO THINGS THE SET GOT WRONG ARE WORTH KEEPING, because the replacement
 * has to not repeat them. It capped the RESULT at eight chains and evicted
 * the weakest by a count of distinct words - MEASURED on one bot, the chain
 * joining `pipe` to the `dup2` on it, the whole of a redirected shell, was
 * stored and then thrown away for a longer chain that listed more words and
 * joined none of them. And choosing between shapes at all is a selection the
 * engine has no business making: what replaces this stores NODES AND TYPED
 * EDGES and offers all of them.
 */

/*
 * "This child is raw, and I mean it" - see pend_fmt below. Out of the range of
 * enum kof_format on purpose: it is a declaration, not a format, and identify
 * turns it back into KOF_FMT_UNKNOWN once it has skipped the sniff.
 */
#define KOF_FMT_DECLARED_RAW 0xffu

/* Room for a module's own name - "VMProtect.PE" and the like. */
#define KOF_MOD_TAG 48

/* How many regions one run may report, and what each one is. */
/*
 * How many interpreter runs one scan will spend, whatever asks (the rule's ask for the emulator).
 *
 * A number and not a fraction of the tree, because the thing being bounded is
 * wall time on a tree of any size. 512 is what the measured population supports
 * with room to spare: the rule that asks today fires on 18 of 4398 malware
 * objects and on none of 5252 clean ones, so a scan that reaches this ceiling
 * is looking at something no measured corpus resembles - and the honest thing
 * then is to stop interpreting, not to keep going.
 */
#define KOF_SCAN_EMU_MAX 512u

#define KOF_EMU_RGN_MAX 64u
/* KOF_EMU_RGN_IMAGE / _EXEC / _WRITTEN, the kinds of a region, are defined once
 * in the module ABI (kofmod/kofmodemu.h) and come in with kofsig.h. */

/*
 * ---- WHAT IS COMPUTED AT MOST ONCE FOR ONE OBJECT -------------------------
 *
 * Each is a result the scanner derives from the object's bytes the first time
 * something asks and then keeps, so a second rule asking the same question does
 * not pay for it twice. They used to be nine fields, each with its own spelling
 * (`_done`, `_ready`) and each cleared at a place of its own; one was never
 * cleared at all (the serialised graph, so every object after the first read the
 * FIRST object's graph block). One array, one `memset` in obj_begin, and a new
 * latch that is not listed here cannot exist - which is the point.
 *
 * A latch says "has been computed for THIS object". What it guards - a buffer, a
 * table - is released by obj_begin as well, and that is the only place.
 */
enum kof_obj_latch {
	KOF_OL_SYM,             /* the symbol block                         */
	KOF_OL_FUNCS,           /* the functions those symbols name         */
	KOF_OL_USE,             /* the address-use map of the code          */
	KOF_OL_DIAG_GATE,       /* which diagnoses' signs are present       */
	KOF_OL_DIAG,            /* the diagnose walk has run                */
	KOF_OL_RELOCS,          /* the relocation table                     */
	KOF_OL_APIHASH,         /* what a PE resolves for itself            */
	KOF_OL_PE_IMPORTS,      /* the PE's import directory, walked        */
	KOF_OL_GRAPH_BLOCK,     /* the graph serialised for a rule          */
	KOF_OL_MULTI,           /* the multi-pattern set is bound           */
	KOF_OL_MUTATION,          /* the similarity set is bound              */
	KOF_OL_COUNT
};

/*
 * WHAT A STEP SAYS ABOUT THE EVIDENCE, read off the declared step and kept
 * nowhere else: an UNPACK or DECRYPT module took a wrapper off a program that
 * was hidden, which is a layer of packing a heuristic may weigh. A container's
 * members, and what a carve found, are not.
 */
static inline int kof_step_hides_program(uint32_t step)
{
	return step == KOF_ANALYZE_UNPACK || step == KOF_ANALYZE_DECRYPT;
}

/*
 * What the interpreter may do on the object in front of the unpack stage. The
 * values are ORDERED BY WHAT THEY PERMIT and the question each one answers is
 * the one oc_emu_run asks:
 *
 *   BANNED       --emu never, or this is a payload of a payload (the packer-depth
 *                ceiling). No vouch talks past it and it is not a budget.
 *   NOBODY       not banned, and nobody spoke for the run: only a module that
 *                vouches may start it. What --heur 1 leaves behind.
 *   GUESS        the generic receiver may try an object nothing recognised:
 *                emu_use above NEVER.
 *   ASKED        a rule that fired on this object, or the producer that made it,
 *                asked for the interpreter. The run is forced - the entropy gate
 *                is an estimate about objects nobody spoke for.
 *   ONLY         --emu only: the interpreter stands in for the packer modules, so
 *                a static unpacker having opened the object is not a refusal.
 *   ONLY_ASKED   both.
 */
enum kof_emu_stance {
	KOF_EMU_STANCE_BANNED = 0,
	KOF_EMU_STANCE_NOBODY,
	KOF_EMU_STANCE_GUESS,
	KOF_EMU_STANCE_ASKED,
	KOF_EMU_STANCE_ONLY,
	KOF_EMU_STANCE_ONLY_ASKED
};

static inline int kof_emu_stance_asked(enum kof_emu_stance s)
{
	return s == KOF_EMU_STANCE_ASKED || s == KOF_EMU_STANCE_ONLY_ASKED;
}

static inline int kof_emu_stance_only(enum kof_emu_stance s)
{
	return s == KOF_EMU_STANCE_ONLY || s == KOF_EMU_STANCE_ONLY_ASKED;
}

/* One import a module reported: both strings owned by the scanner. */
struct kof_sym_decl {
	char *dll;
	char *fn;
};

#endif
