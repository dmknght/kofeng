#include <kofmod/kofpathogen.h>

/*
 * net_sendrawheader_00.c - a raw socket that is told the program writes the IP
 * header itself, and then sends on it: the way a flooder spoofs a packet.
 *
 *     fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
 *     setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);
 *     sendto(fd, packet, len, ...);           <- source address is the author's
 *
 * IP_HDRINCL is what makes the source address a choice. Without it the kernel
 * builds the header and the source is the host's; with it the program can send
 * as anyone, which is the point of a SYN/UDP/ACK flood. A ping tool opens a raw
 * socket too and does not set it - that is the difference this keeps.
 *
 * THE SEND IS ON THE SAME DESCRIPTOR as the option. A raw socket configured in
 * one place and a different socket written in another is not this.
 */

KOF_DIAG_NAME(DIAG_NET_SENDRAWHEADER);

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

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_RAW, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_HDRINCL);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_WRITE);
