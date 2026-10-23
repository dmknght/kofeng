/*
 * sig_proc_revshell_00.c - a fixture: a process whose descriptors are all one socket.
 *
 * tests/unit/proc_rule.c hands the engine synthetic process records and watches what a
 * module reading them says. This is the shape measured on a controlled `bash -i >&
 * /dev/tcp/...`: stdin and stdout are the same socket, and every descriptor the process
 * holds names that socket. It says it with a note, and nothing else - a module names no
 * object.
 */

#include <kofmod/kofsig.h>
#include <kofmod/proc.h>

KOF_TARGET_EVENT(KOF_EVT_PROC);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "RevShell");

KOF_DEFINE_SCAN
{
	const struct kof_proc_info *p = kof_proc(ctx);

	if (!p || !p->valid)
		return;
	/* The descriptor walk has to have RUN. Without it every count below is zero,
	 * and zero would satisfy the third test by accident. */
	if (!(p->flags & KOF_PROC_F_FDS_READ) || !p->n_fd)
		return;
	if (!p->fd0_socket || !p->fd_same_01)
		return;
	if (p->n_like_stdin != p->n_fd)
		return;
	kof_debug("RevShell#00", 0);
}
