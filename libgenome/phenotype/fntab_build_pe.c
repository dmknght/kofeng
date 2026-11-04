/*
 * fntab_build_pe.c - THE STRATEGIES OF A PE CASE, run in the order the selector's row says (genotype/image/fntab_select.c: the decision table of the PE rows).
 *
 * The exact tables first (the exception table of an x64 image, the COFF symbols), each with its one retry (a table that was READ and held no function is the next row, the
 * meta says so); then the sources that name starts without ends (the COFF symbols beside the exception table, the export address table, the TLS callbacks, the load
 * configuration's call-target lists); then the entry walk and, in the same decode, the import stubs. What the case says about the table that the merge cannot know is
 * kept in `add_partial` (a leaf function has no unwind entry; no table at all; managed code).
 */
#include "fntab_build_private.h"

void kgenome_fntab_collect_pe(struct kgenome_fntab_run *r)
{
	const struct kgenome_pe_info *pe = r->obj->file_header;
	uint32_t tries;

	for (tries = 0; tries < 3u; tries++) {
		r->plan = kgenome_fntab_select(&r->meta);
		if (r->plan.run & KGENOME_FNTAB_X_PDATA) {
			kgenome_fntab_pdata(r->file, pe, &r->l);
			if (!r->l.n && r->l.status == KGENOME_OK) {      /* read, and no entry held (or none validated): the next row; the refusals stay counted */
				r->meta.pdata_empty = 1;
				continue;
			}
		} else if ((r->plan.run & KGENOME_FNTAB_X_PE_COFF) && r->plan.ccase == KGENOME_FNTAB_C_PE_COFF) {
			kgenome_fntab_pe_coff(r->file, pe, &r->l);
			if (!r->l.n && r->l.status == KGENOME_OK) {
				r->meta.coff_empty = 1;
				continue;
			}
		}
		break;
	}
	if ((r->plan.run & KGENOME_FNTAB_X_PE_COFF) && r->plan.ccase == KGENOME_FNTAB_C_PE_PDATA)   /* beside the exception table: names the leaves (the PE_COFF row ran it in the loop) */
		kgenome_fntab_pe_coff(r->file, pe, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_PE_ARMPDATA)
		kgenome_fntab_pdata_arm(r->file, pe, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_PE_EXPORT)
		kgenome_fntab_pe_export(r->file, pe, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_PE_TLS)
		kgenome_fntab_pe_tls(r->file, pe, &r->l);
	if (r->plan.run & KGENOME_FNTAB_X_PE_CFG)
		kgenome_fntab_pe_cfg(r->file, pe, &r->l);
	if ((r->plan.run & KGENOME_FNTAB_X_WALK) && kgenome_fntab_run_walk(r) && (r->plan.run & KGENOME_FNTAB_X_PE_THUNK))
		kgenome_fntab_pe_thunk(r->walk, &r->l);
	if (r->plan.ccase == KGENOME_FNTAB_C_PE_PDATA)
		r->add_partial |= KGENOME_FNTAB_P_STARTS;        /* a leaf function has no unwind entry */
	if (r->plan.ccase == KGENOME_FNTAB_C_PE_NONE)
		r->add_partial |= KGENOME_FNTAB_P_NO_TABLE;
	if (r->plan.ccase == KGENOME_FNTAB_C_PE_ARM)
		r->add_partial |= KGENOME_FNTAB_P_STARTS;        /* no walk decodes this machine: a function with no unwind entry that nothing names is missing */
	if (r->plan.ccase == KGENOME_FNTAB_C_PE_NOCODE)
		r->add_partial |= KGENOME_FNTAB_P_NO_CODE;       /* the code is not in the file: an empty table that says why */
	if (r->plan.ccase == KGENOME_FNTAB_C_PE_CLR)
		r->add_partial |= KGENOME_FNTAB_P_MANAGED;
}
