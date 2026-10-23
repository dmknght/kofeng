/*
 * objctx_diag_route.c - which routines of the diagnose scan a diagnose may run on an object: what it declared, where the
 * object offers it. Moved whole out of objctx_diag.c (which was at its size ceiling) and not changed: the one
 * statement the gate, the symbol block's selection and the run all ask.
 */

#define _GNU_SOURCE

#include <kofmod/elf.h>
#include <phenotype/diag_scan.h>

#include "objctx_int.h"

/*
 * WHICH ANALYSES THIS FILE CAN SERVE, read off the file.
 *
 * The analyses differ by an order of cost and by what each can see. A diagnose
 * says which it is written for (KOF_DIAG_ANALYSIS) and the route that runs is the
 * INTERSECTION of what it declared and what the object can serve - what the
 * object's format and content make possible, never an exclusive class chosen by
 * what evidence the file happens to carry:
 *
 *   an object file (a kernel module)  its names - SYMBOL. No program entry, no
 *                                     system call to find.
 *   an ELF with PT_INTERP             SYMBOL. The loader's own test for "this
 *                                     needs a dynamic linker": its calls are
 *                                     imports, and it contains no system call.
 *   any other ELF (static)            SYMBOL and SYSCALL. A static program says
 *                                     what it calls by name when it has symbols,
 *                                     and enters the kernel by an instruction in
 *                                     its own code whether it has them or not -
 *                                     a section table and a .symtab are
 *                                     evidence of how it was LINKED, not a
 *                                     reason the sweep has nothing to find. The
 *                                     old selection switched SYSCALL off for any
 *                                     static ELF with a section table or a
 *                                     symbol, so a diagnose that declared SYSCALL
 *                                     only (rwx_exec, the botnet net diagnoses)
 *                                     was NO_ROUTE on a stripped static bot that
 *                                     still had section headers
 *                                     (tests/unit/view_equiv.c route matrix).
 *   a PE                              its names, and what it resolves for itself
 *                                     - APIHASH
 *
 * THE COST IS NOT DECIDED HERE. The sweep was MEASURED to be 90% of the scan on
 * 254 ELF files when every static one was offered it, and what keeps it from being
 * that again is the gate (diag_gates): a diagnose whose file-shape conditions or
 * imports are unmet asks for no route, and a diagnose no rule reads is not run.
 * The route runs when a diagnose that passed its gate declared it.
 *
 * Anything else serves none, so no diagnose is asked.
 */
static unsigned diag_servable(const struct kof_obj_ctx *ctx)
{
	if (oc_text_served(ctx))                /* a script whose language has a table of names */
		return KGENOME_DIAG_RUN_TEXT;
	if (ctx->format == KOF_FMT_PE)
		return KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_APIHASH;
	if (ctx->format == KOF_FMT_ELF) {
		const struct kgenome_elf_info *ei = kof_elf(ctx);
		uint32_t i;

		if (!ei || !ei->valid)
			return 0;
		if (ei->e_type == KGENOME_ELF_REL)
			return KGENOME_DIAG_RUN_SYMBOL;
		for (i = 0; i < ei->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			if (ei->seg[i].type == 3u)
				return KGENOME_DIAG_RUN_SYMBOL;
		return KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_SYSCALL;
	}
	return 0;
}

/* The analyses a diagnose DECLARED, as the routines the scan runs. */
static unsigned analysis_runs(unsigned analysis)
{
	unsigned r = 0;

	if (analysis & KOF_DIAG_ANALYSIS_SYSCALL)
		r |= KGENOME_DIAG_RUN_SYSCALL;
	if (analysis & KOF_DIAG_ANALYSIS_SYMBOL)
		r |= KGENOME_DIAG_RUN_SYMBOL;
	if (analysis & KOF_DIAG_ANALYSIS_APIHASH)
		r |= KGENOME_DIAG_RUN_APIHASH;
	if (analysis & KOF_DIAG_ANALYSIS_TEXT)
		r |= KGENOME_DIAG_RUN_TEXT;
	return r;
}

/* The routines to run for diagnose `d` on this file: what it declared, where the
 * file offers it. Zero means the file has nothing for this diagnose. */
unsigned oc_diag_routes(const struct kof_diag *d, const struct kof_obj_ctx *ctx)
{
	return analysis_runs(d->analysis) & diag_servable(ctx);
}
