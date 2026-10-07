#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * rootkit_diamorphine_00.c - Diamorphine and what is built from it: a
 * loadable kernel module that hides itself from the kernel's module list and
 * then either resolves a kernel symbol it is not given or gives root.
 *
 * No behaviour is a verdict alone, and that is deliberate:
 *
 *   DIAG_LKM_SELFHIDE         removes itself from the list of loaded modules
 *                             by taking the address of a field of its own
 *                             struct module. 0 of 900 clean kernel modules.
 *   DIAG_LKM_KPROBERESOLVE    calls register_kprobe, with unregister_kprobe
 *                             imported. 0 of 900 clean kernel modules.
 *   the name                  the probe is placed on kallsyms_lookup_name,
 *                             which is what the probe is FOR: it makes the
 *                             kernel resolve a symbol the module cannot link
 *                             against, and hands the address back. Read out
 *                             of the emulator's memory, kept in the engine,
 *                             asked with kof_diag_has_str. It separates a
 *                             probe used to RESOLVE from one used to hook:
 *                             the same call, placed on do_exit, is a
 *                             different statement.
 *   DIAG_LKM_GIVEROOT         prepare_creds, a zero written into the new
 *                             creds, commit_creds. The route for a build on
 *                             a kernel without kprobes (3.10 measured), where
 *                             there is nothing to resolve through.
 *
 * Selfhide, AND either way of reaching the kernel's internals.
 *
 *
 * ---- THE FORM ----------------------------------------------------------
 *
 * ONE CONDITION, AND ONLY CALLS IN IT. No local, no early return, no helper:
 * a rule written as `if (A && (B || C)) KOF_SCAN_INFECT(...)` is the shape
 * the rule editor generates, and each predicate is one block it can show.
 *
 *
 * ---- WHAT IT DOES NOT CLAIM ---------------------------------------------
 *
 * hcrootkit - two builds in this tree - is NOT this family and is not named
 * by it. Measured: both builds match SELFHIDE and KPROBERESOLVE and neither
 * matches GIVEROOT; the name is never read, because its register_kprobe sits
 * behind a 50-iteration initialisation loop the span runner will not execute.
 * They keep their own HCRootkit signatures. That the name is missing is a
 * limit of the run and not a statement about the module, which is why
 * kof_diag_has_str documents false as "not found".
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);
KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, "Diamorphine");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_diag(DIAG_LKM_SELFHIDE) &&
	    (kof_diag_has_str(DIAG_LKM_KPROBERESOLVE, "kallsyms_lookup_name") ||
	     kof_diag(DIAG_LKM_GIVEROOT)))
		KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
