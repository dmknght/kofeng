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

KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_EMULATE);

/*
 * THE GATE: A STATIC ELF. The route is a sweep of the code for system calls, and
 * a binary linked against a shared libc has none to find - it reaches the kernel
 * through the import table and a library this file does not carry. Without this
 * the route ran on every ELF a rule reached, and was most of the cost of the
 * whole scan. It narrows where the route runs and is NOT a sign that the object
 * is worth analysing, so it does not make this diagnose ask - see
 * kof_scan_diag_sign_asks.
 */
KOF_DIAG_HAS_ATTRB(KOF_FACT_INTERP, 0);

KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_NET_RAW, 0);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_HDRINCL);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_NET_WRITE);
