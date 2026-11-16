/*
 * fntab_build_elf.c - THE STRATEGIES OF AN ELF CASE, run in the order the selector's row says (genotype/image/fntab_select.c: the decision table of the ELF rows).
 *
 * The symbol table (or .dynsym) first: it is exact where it exists, and a table that was READ and held no function is the NEXT row (the meta says so; at most one retry
 * for each of the two tables, so the loop is bounded by them). Then the unwind table, the Go function table and the start-only loader tables (init/fini arrays, .ARM.exidx).
 * No strategy here decodes code (owner 2026-11-16; the entry walk this ran is DISABLED, see fntab_build.c). The entry point is the orchestrator's (fntab_build.c).
 */
#include "fntab_build_private.h"

void kgenome_fntab_collect_elf(struct kgenome_fntab_run *r)
{
	const struct kgenome_elf_info *e = r->obj->file_header;
	uint32_t tries;

	for (tries = 0; tries < 3u; tries++) {
		r->plan = kgenome_fntab_select(&r->meta);
		if (r->plan.run & KGENOME_FNTAB_X_SYMTAB) {
			kgenome_fntab_symtab(r->file, e, 0, &r->l);
			if (!r->l.n && r->l.status == KGENOME_OK) {
				r->meta.symtab_empty = 1;
				continue;
			}
		} else if (r->plan.run & KGENOME_FNTAB_X_DYNSYM) {
			kgenome_fntab_symtab(r->file, e, 1, &r->l);
			if (!r->l.n && r->l.status == KGENOME_OK) {
				r->meta.dynsym_empty = 1;
				continue;
			}
		}
		break;
	}
	if (r->plan.run & KGENOME_FNTAB_X_FDE)
		kgenome_fntab_fde(r->file, e, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_GOPCLN)
		kgenome_fntab_gopcln(r->file, e, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_INITARR)
		kgenome_fntab_initarr(r->file, e, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_EXIDX)
		kgenome_fntab_exidx(r->file, e, &r->l);
	/* the tables of these cases do not name every function (.dynsym the exported ones, .eh_frame what the toolchain gave an FDE, the loader tables a few): said */
	if (r->plan.ccase == KGENOME_FNTAB_C_ELF_DYNSYM || r->plan.ccase == KGENOME_FNTAB_C_ELF_FDE || r->plan.ccase == KGENOME_FNTAB_C_ELF_META)
		r->add_partial |= KGENOME_FNTAB_P_STARTS;
}
