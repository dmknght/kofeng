#include <kofmod/kofpathogen.h>

/*
 * net_cncnonblock_00.c - a stream socket that is made non-blocking and then
 * connected: the way a bot dials its controller.
 *
 *     fd = socket(AF_INET, SOCK_STREAM, 0);
 *     fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
 *     connect(fd, &peer, sizeof peer);        <- returns EINPROGRESS
 *
 * The connect is completed later with select and getsockopt, so a bot never
 * stalls on a controller that is down. A tool that connects once and waits has
 * no reason to do this; a program that keeps many connections or retries on a
 * timer does. Not a verdict by itself: browsers and servers use O_NONBLOCK too.
 *
 * BOTH NODES HANG OFF THE SAME DESCRIPTOR. The non-blocking flag set on a log
 * file and a connect on an unrelated socket do not satisfy it.
 */

KOF_DIAG_NAME(DIAG_NET_CNCNONBLOCK);

/*
 * SYSCALL: the nodes of a static binary are found by sweeping its code for system
 * calls, because it carries its libc and nothing in it names them.
 */
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL);
KOF_DIAG_USE_EMU();

/*
 * NO CONDITION ON THE INTERPRETER. A dynamically linked program contains no
 * system call - it reaches the kernel through the import table and a library
 * this file does not carry - so the sweep this diagnose declared has nothing to
 * find in it. The engine reads that off the file (diag_evidence): a diagnose
 * whose analysis the file does not offer is not run, and nothing here has to be
 * kept in step with what the file is. It is not a sign either: that the file is
 * static is no reason to analyse it, so this diagnose still does not ask - see
 * kof_scan_diag_sign_asks.
 */

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_OPEN, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_FD_NONBLOCK);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_CONNECT);
