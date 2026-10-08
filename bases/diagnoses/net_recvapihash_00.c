#include <kofmod/kofpathogen.h>

/*
 * net_recvapihash_00.c - a Windows program that opens a socket, connects it, and
 * reads from it.
 *
 *     s = WSASocketA(...);
 *     connect(s, ...);
 *     recv(s, buf, n, 0);
 *
 * THE SAME SHAPE AS net_recvsyscall_00 ON LINUX, and for the same reason it is
 * a separate diagnose from mem_execapihash_00: each is ordinary alone (a downloader
 * is this, a self-unpacking loader is the other) and a verdict joins them at the
 * read - see kof_diag_share.
 *
 * ONLY THE APIHASH ROUTE, as mem_execapihash_00 and gated the same way: the calls of
 * a stager are not in its import table, and the W+X section is what keeps the
 * analysis off the programs that have nothing like one.
 */

KOF_DIAG_NAME(DIAG_NET_RECVAPIHASH);

KOF_DIAG_VIA(KOF_DIAG_VIA_APIHASH);

KOF_DIAG_WHEN(KOF_FACT_FORMAT, KOF_FMT_PE);
KOF_DIAG_WHEN(KOF_FACT_MAP_PERM, KOF_PE_PERM_W | KOF_PE_PERM_X);

KOF_DIAG_ANCHOR(s, KOF_NUCLEO_NET_OPEN, 0);
KOF_DIAG_FROM(c, s, KOF_NUCLEO_NET_CONNECT, KOF_DIAG_ROLE_FD);
KOF_DIAG_FROM(r, s, KOF_NUCLEO_MEM_READ, KOF_DIAG_ROLE_FD);
