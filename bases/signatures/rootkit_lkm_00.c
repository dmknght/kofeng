#include <kofmod/kofsig.h>
#include <kofmod/kofcap.h>
#include <kofmod/kofpathogen.h>

/*
 * rootkit_lkm_00.c - a loadable kernel module that hides itself from the
 * kernel's module list and resolves the system call table through a kprobe.
 * Generic: it names a behaviour, not a family.
 *
 * FOR KERNELS NEWER THAN 4.4.0. The Diamorphine source says so itself:
 *
 *     #if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
 *         syscall_table = (unsigned long *)resolve_sym("sys_call_table");
 *
 * and resolve_sym plants a kprobe, reads back where the probe landed, and
 * calls that address with the name of what it wants. On 4.4.0 and earlier it
 * finds the table another way - a scan of memory, no kprobe, no name -
 * which is how the 3.10 build in this tree gets there, and
 * rootkit_diamorphine_00 covers it by the other behaviour. This verdict will
 * not match those builds. That is the behaviour differing with the kernel
 * build, not a gap.
 *
 * The 4.4.0 line is the SOURCE's. It is not measured here: the builds in this
 * tree are 3.10 (no kprobe), and 6.x and 7.x (kprobe); none sits between.
 *
 *   DIAG_LKM_SELFHIDE         removes itself from the list of loaded modules.
 *                             0 of 900 clean kernel modules.
 *   DIAG_LKM_KPROBE_RESOLVE    the resolver call, with register_kprobe and
 *                             unregister_kprobe imported. 0 of 900 clean.
 *   the name                  what the resolver is asked for - the evidence
 *                             about what is being reached, read from the
 *                             emulator's memory and kept in the engine. Not
 *                             `kallsyms_lookup_name`, which is only the
 *                             probe's own symbol_name. WHICH names depends on
 *                             the architecture and the kernel, so the verdict
 *                             lists them and asks for any:
 *
 *       sys_call_table        every build; what a rootkit patches
 *       x64_sys_call          x86 on 6.9.0 and later (source guard)
 *       update_mapping_prot   arm64: to make the table writable
 *
 *                             The arm64 source also resolves __start_rodata
 *                             and __init_begin, in the same block as
 *                             update_mapping_prot; one of the three is
 *                             enough to say the module is on that path, so
 *                             only this one is asked.
 *
 *                             Measured: sys_call_table on every x86 build in
 *                             this tree, x64_sys_call on the one that is 6.9+.
 *                             The arm64 names come from the source and NOT
 *                             from a sample - none is on disk - so they are
 *                             unmeasured.
 *
 * ONE CONDITION, AND ONLY CALLS IN IT, in the shape the rule editor
 * generates.
 *
 * "false" from kof_diag_str_any means NOT FOUND, never "not there": the run
 * reads names only at calls it reaches, and a loop it will not execute can
 * stand in front of one. hcrootkit's 50-iteration init loop is exactly that,
 * and it is also a different family; it keeps its HCRootkit signatures.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);
KOF_TARGET_NAME(KOF_MALTYPE_ROOTKIT, "LKM");

void kof_scan(const struct kof_obj_ctx *ctx)
{
	if (kof_diag(DIAG_LKM_SELFHIDE) &&
	    kof_diag_str_any(DIAG_LKM_KPROBE_RESOLVE, "sys_call_table",
			     "x64_sys_call", "update_mapping_prot"))
		KOF_SCAN_INFECT(KOF_MALVAR_GENERIC);
}
