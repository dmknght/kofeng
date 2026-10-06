#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * rootkit_lkm_00.c - a loadable kernel module that hides itself from the
 * kernel's module list and resolves a kernel symbol it is not given.
 *
 * Two behaviours, and a name. Neither behaviour is a verdict alone, and that
 * is deliberate:
 *
 *   DIAG_LKM_SELFHIDE         removes itself from the list of loaded modules
 *                             by taking the address of a field of its own
 *                             struct module. 0 of 900 clean kernel modules.
 *   DIAG_LKM_KPROBERESOLVE    calls register_kprobe, with unregister_kprobe
 *                             imported. 0 of 900 clean kernel modules.
 *   the name                  the probe is placed on kallsyms_lookup_name,
 *                             which is what the probe is FOR: it makes the
 *                             kernel resolve a symbol the module cannot link
 *                             against, and hands the address back.
 *
 * The third is read out of the emulator's memory and kept in the engine, and
 * is asked here with kof_diag_has_str. It is what separates a probe used to
 * RESOLVE from a probe used to hook: the same call, placed on do_exit, is a
 * different statement.
 *
 *
 * ---- THE FORM ----------------------------------------------------------
 *
 * ONE CONDITION, AND ONLY CALLS IN IT. No local, no early return, no helper:
 * a rule written as `if (A && B && C) KOF_SCAN_INFECT(...)` is the shape the
 * rule editor generates, and each predicate is one block it can show. A
 * verdict that needed a loop or a count would be one the editor could not
 * hold - which is a reason to write that as something else, and it is why this
 * one asks for three things to be true and not for how many of something.
 *
 *
 * ---- WHAT IT DOES NOT CLAIM ---------------------------------------------
 *
 * hcrootkit - two builds in this tree - is NOT detected by this. Its
 * register_kprobe sits behind a 50-iteration initialisation loop the span
 * runner will not execute, so the name is never read and the third condition
 * is false for it. The two diagnoses both match it; the name is what is
 * missing. That is a limit of the run, not a statement about the module, and
 * it is the reason kof_diag_has_str documents false as "not found".
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);
KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, "Lkm");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_diag(DIAG_LKM_SELFHIDE) &&
	    kof_diag_has_str(DIAG_LKM_KPROBERESOLVE, "kallsyms_lookup_name"))
		KOF_SCAN_INFECT(KOF_MALVAR_GENERIC);
}
