/*
 * fntab_walk.c - the ENTRY-WALK strategy of the function table (fntab.h): starts from the one decode of the code.
 *
 * Evidence taken: the DIRECT call targets and the `jmp X` thunk at a function's start (the walk's `tgt`, from pass_a: decoded, not found by bytes) and the
 * object's entry point. What it cannot see (CN-5): what is called through a register, address-taken functions, Thumb. Entries only: it gives no end (the ends step
 * of the table does: the next start less the padding the decode saw). It decodes nothing itself: the walk is built by the caller, once.
 */
#include "diag_scan_private.h"
#include <genotype/image/fntab.h>
#include <genotype/image/fntab_private.h>

void kgenome_fntab_walk(const struct kgenome_obj *obj, const struct kgenome_diag_walk *walk, struct kgenome_fntab_list *out)
{
	struct kgenome_func f;
	const struct kgenome_elf_info *elf = obj->format == KGENOME_FMT_ELF ? kgenome_obj_elf(obj) : NULL;
	const uint64_t *ent;
	uint32_t n, i;

	memset(&f, 0, sizeof f);
	ent = kgenome_diag_walk_entries(walk, &n);
	for (i = 0; i < n; i++) {
		/* a call target in a section of stubs (.plt) is the linker's thunk, not a function of the program (FNTAB-COV-3: the unwind strategy refuses the same bytes) */
		if (elf && kgenome_fntab_in_stub_section(elf, ent[i]))
			continue;
		f.off = ent[i];
		f.source = KGENOME_FN_S_WALK;
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
	if (obj->entry_off < (uint64_t)-2) {            /* not NA, not BROKEN */
		f.off = obj->entry_off;
		f.source = KGENOME_FN_S_ENTRY;
		(void)kgenome_fntab_list_add(out, &f);
	}
}
