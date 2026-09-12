/*
 * proc_kthread_00.c - a userland process wearing a kernel thread's name.
 *
 * ps renders kernel threads in brackets, so a process that names ITSELF
 * "[kworker/0:2]" disappears into a list of forty real ones. It costs an
 * attacker one prctl call and it is a standard trick.
 *
 * IT IS DETECTABLE BY CONSTRUCTION, and that is worth saying because it falls
 * out of a decision made for another reason. libkofantarc classifies kernel
 * threads from PF_KTHREAD - field 9 of /proc/<pid>/stat, the kernel's own bit
 * - and never from the name, because a name was never trustworthy for
 * anything. So the disagreement between what a process CALLS itself and what
 * the kernel SAYS it is arrives as two independent facts, and there is no way
 * to spell the name that avoids the comparison.
 *
 * AND IT REQUIRES AN EXECUTABLE ON DISK. A real kernel thread has no exe link
 * at all; without this test a readlink that merely FAILED - refused, or the
 * process gone between two reads - could reach here and be called a masquerade
 * on the strength of a name and a missing answer. With it, the rule is about
 * two things that were both observed: it claims to be a kernel thread, and
 * here is the file it is actually running.
 *
 * THE FALSE POSITIVE LEFT is a program that legitimately brackets its own
 * name. Those exist and are rare enough to read.
 */
#include <kofmod/heur.h>
#include <kofmod/proc.h>

KOF_TARGET_EVENT(KOF_EVT_PROC);

KOF_HEUR_PHASE(KOF_HEUR_VERDICT);
KOF_HEUR_NAME("KThreadMasq");

KOF_DEFINE_HEUR
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

	KOF_HEUR_HIT();
}
