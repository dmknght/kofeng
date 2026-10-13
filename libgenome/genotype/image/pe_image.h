/*
 * pe_image.h - the structure of a PE, as libgenome reads it.
 *
 * The body of what pe_parse.h declared: the parse, the import walk and the
 * import table. The scan-region partition and the names for tools stay with
 * the engine (pe_parse.h), which includes this header, so every name below is
 * still reachable from there. The original notes follow, with the
 * declarations they describe.
 */

#ifndef KGENOME_IMAGE_PE_IMAGE_H
#define KGENOME_IMAGE_PE_IMAGE_H

#include <genotype/image/pe_types.h>
#include <genotype/image/obj.h>
#include <kofcore.h>
#include "../../kgenome_status.h"

/*
 * The parse itself: the body of kof_pe_parse (pe_parse.h), which calls this
 * and then attaches the engine's region resolver. Same contract - see there.
 * It sets obj->obj_size, entry_off, arch, subtype, format and file_header,
 * and does not touch the engine's region resolver (the adapter owns it).
 */
int kgenome_pe_image_parse(kof_buf file, struct kgenome_pe_info *info,
		       struct kgenome_obj *obj);

/*
 * THE IMPORT DIRECTORY, walked on demand - see the note in elf_parse.h for
 * why this is pulled rather than carried in the view, why it reports to a
 * visitor rather than filling an array, and why it answers with names rather
 * than with meanings.
 *
 * `slot` is the address a call goes THROUGH, taken from FirstThunk, because
 * that is the one the loader writes and the one an indirect call names. The
 * NAME comes from OriginalFirstThunk where there is one: a file on disk has
 * both tables, a memory image dumped to disk has only the first, and the
 * original is the one that still holds names after the loader has written
 * addresses over the other.
 *
 * `nameoff` IS WHERE THE NAME IS IN THE FILE, and zero when there is none. The
 * `name` pointer is a copy - the walk reads it into a buffer of its own - so it
 * cannot be turned into a position, and a node that has to say which import it
 * stands for needs one. A position and not the string, as kgenome_elf_relocs
 * reports it, because the string is already in the buffer the caller handed in.
 *
 * AN IMPORT BY ORDINAL has no name. It is still reported, with `name` NULL
 * and `ordinal` set - the slot is real and a caller that only matches names
 * can ignore it, which is not the same as not being told.
 */
typedef void (*kgenome_pe_import_fn)(void *user, uint64_t slot, const char *dll,
				 const char *name, uint32_t ordinal,
				 uint64_t nameoff);

/*
 * Returns how many imports were reported. `status`, when not NULL, says whether
 * that is all of them: KGENOME_OK, or KGENOME_TRUNCATED when the TOTAL THUNK
 * BUDGET ran out - (file bytes / pointer width) thunks in all, which is what the
 * file can hold if no two descriptors share a table, so an honest import
 * directory never reaches it and a directory built to make the walk quadratic
 * (256 descriptors pointing at one 4096-entry table, say) does. It replaced two
 * per-library constants, 256 DLLs and 4096 thunks each, which dropped the 257th
 * library's imports and the 4097th import of one library - VirtualAlloc among
 * them - without a word.
 */
uint32_t kgenome_pe_imports(kof_buf f, const struct kgenome_pe_info *p,
			kgenome_pe_import_fn fn, void *user,
			enum kgenome_status *status);

/*
 * THE NAMED EXPORTS, one call of `fn` each, in directory order.
 *
 * `nameoff` is where the name is in the file (the caller reads it: its own bound
 * and its own sanitising) and `rva` the exported function's RVA, 0 when the
 * ordinal or function table is missing - a value of zero would read as "at the
 * image base", so it is left out rather than guessed. Exports BY ORDINAL with no
 * name are not reported: the record's identity is its name. `fn` returns 0 to
 * stop. Returns how many were handed over; `status`, when not NULL, is
 * KGENOME_TRUNCATED when NumberOfNames was cut at the walk's bound.
 */
typedef int (*kgenome_pe_export_fn)(void *user, uint64_t nameoff, uint32_t rva);
uint32_t kgenome_pe_exports(kof_buf f, const struct kgenome_pe_info *p,
			kgenome_pe_export_fn fn, void *user,
			enum kgenome_status *status);

/*
 * THE IMPORT DIRECTORY, WALKED ONCE AND KEPT - for the readers that share one
 * object. The symbol block spells the imports as records and the PE diagnose
 * matches call sites against their slots; two walks of one directory, because
 * the record carries no slot. This is the single product both read.
 *
 * One entry per import, in directory order. The NAME is not copied: `nameoff`
 * says where it is in the buffer the table was built from (zero for an import
 * by ordinal), and kgenome_pe_imp_name reads it back. A table that held 256 x 4096
 * names would be 130 MB of copies of bytes the caller already has. The
 * LIBRARY is kept, once per run of entries that share it, and `dll` indexes it.
 *
 * Bounded by the walk's own limit on the INPUT - the total thunk budget, see
 * kgenome_pe_imports. Nothing is dropped below that; `status` says so when it or memory ran
 * out, because "short for want of memory" is not "that is all there was".
 */
#define KGENOME_PE_IMP_DLLLEN 64u
struct kgenome_pe_imp {
	uint64_t slot;          /* the address a call goes through            */
	uint64_t nameoff;       /* the name in the buffer; 0 = by ordinal     */
	uint32_t ordinal;
	uint32_t dll;           /* index into kgenome_pe_imptab.dll               */
};
struct kgenome_pe_imptab {
	struct kgenome_pe_imp *v;
	uint32_t n, cap;
	char (*dll)[KGENOME_PE_IMP_DLLLEN];
	uint32_t n_dll, cap_dll;
	/* KGENOME_OK; KGENOME_TRUNCATED when the thunk budget ran out (the list is
	 * partial); KGENOME_NOMEM when memory did. */
	enum kgenome_status status;
	/* The buffer the walk read, which is also the one `nameoff` indexes. A
	 * reader holding a different buffer (the emulator is handed the object's
	 * bytes and a table separately) asks kgenome_pe_imptab_is_of before trusting
	 * an offset it would read from the wrong bytes. */
	kof_buf from;
};
void kgenome_pe_imptab_build(kof_buf f, const struct kgenome_pe_info *p,
			 struct kgenome_pe_imptab *t);
void kgenome_pe_imptab_free(struct kgenome_pe_imptab *t);
/* Was `t` built from exactly this buffer? */
int  kgenome_pe_imptab_is_of(const struct kgenome_pe_imptab *t, kof_buf f);
/* The i-th entry's name, read from `f` (the buffer the table was built from)
 * into dst, truncated to dstn - 1. Returns its length, 0 for an ordinal. */
uint32_t kgenome_pe_imp_name(kof_buf f, const struct kgenome_pe_imp *e, char *dst,
			 uint32_t dstn);

/*
 * Does this object look like PE at all?
 *
 * MZ plus a PE signature where e_lfanew points, because MZ alone is a DOS
 * executable and claiming one would hand a module an empty view. Magic only, and
 * separate from the parse for the reason given in elf_parse.h: identifying must
 * not need the view buffer.
 */
int kgenome_pe_sniff(kof_buf file);

#endif /* KGENOME_IMAGE_PE_IMAGE_H */
