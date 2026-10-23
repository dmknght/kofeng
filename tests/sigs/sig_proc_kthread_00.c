/*
 * sig_proc_kthread_00.c - a fixture: a bracketed name the kernel did not give.
 *
 * "[kworker/0:9]" is what ps shows for a kernel thread. A user process can set its own
 * comm to look like one, and then it has an executable on disk and the kernel's PF_KTHREAD
 * bit is clear. tests/unit/proc_rule.c asserts the negative cases as hard as the
 * positive one: a real kernel thread (the bit agrees with the name) and a name with no
 * resolvable executable (a failed readlink, not a masquerade) are silent.
 */

#include <kofmod/kofsig.h>
#include <kofmod/proc.h>

KOF_TARGET_EVENT(KOF_EVT_PROC);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "KThreadMasq");

KOF_DEFINE_SCAN
{
	const struct kof_proc_info *p = kof_proc(ctx);

	if (!p || !p->valid)
		return;
	if (!p->comm_bracketed)
		return;
	/* The kernel's own bit. If it agrees, this IS a kernel thread. */
	if (p->flags & KOF_PROC_F_KTHREAD)
		return;
	if (!(p->flags & KOF_PROC_F_EXE_ON_DISK))
		return;
	kof_debug("KThreadMasq#00", 0);
}
