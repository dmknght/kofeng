#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * rootkit_diamorphine_00.c - Diamorphine and what is built from it: a
 * loadable kernel module that removes itself from the kernel's list of loaded
 * modules and gives root.
 *
 *   DIAG_LKM_SELFHIDE         takes the address of a field of its own struct
 *                             module and unlinks it. 0 of 900 clean modules.
 *   DIAG_LKM_GIVEROOT         prepare_creds, a zero written into the new
 *                             creds, commit_creds.
 *
 * Neither is a verdict alone; the two together are. Measured on three builds
 * - kernel 3.10, 6.x and 7.x - and none of them needed anything else, which
 * is why how the module reaches the kernel's internals (a kprobe on newer
 * kernels, a direct lookup on older) is NOT asked: it varies with the kernel
 * build and is not what makes this module what it is. See rootkit_lkm_00.c
 * for the newer-kernel behaviour, and for why it is a different verdict.
 *
 * ONE CONDITION, AND ONLY CALLS IN IT, in the shape the rule editor
 * generates.
 *
 * hcrootkit - two builds in this tree - is a different family and is not
 * named by this. Measured: both builds match SELFHIDE and neither matches
 * GIVEROOT. They keep their own HCRootkit signatures.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);
KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, "Diamorphine");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_diag(DIAG_LKM_SELFHIDE) && kof_diag(DIAG_LKM_GIVEROOT))
		KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
}
