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

KOF_DIAG_VIA(KOF_DIAG_VIA_SYSCALL | KOF_DIAG_VIA_EMULATE);

/*
 * THE GATE: A STATIC ELF. The route is a sweep of the code for system calls, and
 * a binary linked against a shared libc has none to find - it reaches the kernel
 * through the import table and a library this file does not carry. Without this
 * the route ran on every ELF a rule reached, and was most of the cost of the
 * whole scan. It narrows where the route runs and is NOT a sign that the object
 * is worth analysing, so it does not make this diagnose ask - see
 * kof_scan_diag_sign_asks.
 */
KOF_DIAG_WHEN(KOF_FACT_INTERP, 0);

KOF_DIAG_ANCHOR(s, KOF_NUCLEO_NET_OPEN, 0);
KOF_DIAG_FROM(n, s, KOF_NUCLEO_FD_NONBLOCK, KOF_DIAG_ROLE_FD);
KOF_DIAG_FROM(c, s, KOF_NUCLEO_NET_CONNECT, KOF_DIAG_ROLE_FD);
