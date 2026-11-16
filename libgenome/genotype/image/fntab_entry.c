/*
 * fntab_entry.c - the entry-point strategy of the function table: the start the header declares (ELF e_entry, PE AddressOfEntryPoint), already placed in the file by the
 * parse (kgenome_obj.entry_off). A start only (source ENTRY). It was part of the entry walk (fntab_walk.c, DISABLED by the owner 2026-11-16): the start is metadata and
 * stays, the call targets the walk decoded do not.
 *
 * The orchestrator asks it only when another source named a function: an object whose only fact is its entry point has NO function metadata, and the entry alone does
 * not split it (design_partition_meta.md 5: one unpartitioned entry per code extent, trust NONE).
 */
#include <string.h>

#include <kofcore.h>
#include "funcs.h"
#include "fntab_private.h"

void kgenome_fntab_entry(uint64_t entry_off, int thumb, struct kgenome_fntab_list *out)
{
	struct kgenome_func f;

	if (!out || entry_off >= (uint64_t)-2)          /* KGENOME_NA, KGENOME_BROKEN: no entry */
		return;
	memset(&f, 0, sizeof f);
	/* PMA-7 (audit, round 3): an ARM e_entry with bit 0 set is Thumb code at the even address (the parse placed the odd one) */
	if (thumb) {
		entry_off &= ~(uint64_t)1u;
		f.isa_mode = KGENOME_FN_ISA_THUMB;
	}
	f.off = entry_off;
	f.source = KGENOME_FN_S_ENTRY;
	(void)kgenome_fntab_list_add(out, &f);
}
