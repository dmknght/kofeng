/*
 * fntab_build_elf.c - THE STRATEGIES OF AN ELF CASE, run in the order the selector's row says (genotype/image/fntab_select.c: the decision table of the ELF rows).
 *
 * The symbol table (or .dynsym) first: it is exact where it exists, and a table that was READ and held no function is the NEXT row (the meta says so; at most one retry
 * for each of the two tables, so the loop is bounded by them). Then the unwind table, then the entry walk (the one decode of the code, with the trace).
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
	if (r->plan.run & KGENOME_FNTAB_X_WALK)
		(void)kgenome_fntab_run_walk(r);
}
