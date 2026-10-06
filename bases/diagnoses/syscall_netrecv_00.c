#include <kofmod/kofpathogen.h>

/*
 * syscall_netrecv_00.c - the other half of a stager: where the bytes come
 * from.
 *
 * TWO DIAGNOSES, ONE SHAPE. trojan_meterp_00 states the loader half - a
 * region asked for with W+X, filled by a read, and jumped into - which a
 * self-decrypting packer does as well. This states the network half, and
 * what makes the pair a STAGER rather than either of them is that both
 * meet at the SAME read: the descriptor it reads from came off a socket
 * and the buffer it reads into is the executable region.
 *
 * WHY NOT ONE DIAGNOSE. A diagnose is a tree with one root, and this shape
 * has two: the allocation and the socket. The read has a parent in each.
 * That is not a limitation to work around - a value with two origins is
 * exactly what a join is, and kof_diag_share is how a verdict asks for one.
 *
 * MEASURED, after the engine learned to read i386's socketcall arguments:
 * all four stagers checked - meter1, meter1_x86, meter3_encoded and the
 * shikata-encoded x86_poly - match this and DIAG_SYSCALL_MEMEXEC together,
 * on both architectures. Before that fix the i386 ones had every node and
 * none of these edges, because socketcall keeps its arguments in a
 * structure on the stack rather than in registers.
 */

KOF_DIAG_NAME(DIAG_SYSCALL_NETRECV);

/*
 * SYSCALL ONLY, like the loader half: a stager has no imports and no symbol
 * table - it is a block of shellcode that enters the kernel directly.
 */
/*
 * BOTH ROUTES, because neither contains the other. MEASURED on the stagers
 * here: meter3_encoded yields 0 nodes to the syscall sweep and 5 to the
 * span runner; the elf255 sample 4b060ab4 yields 5 to the sweep and 0 to
 * the runner. A diagnose naming one route is a diagnose that misses
 * whichever samples the other one sees.
 */
KOF_DIAG_VIA(KOF_DIAG_VIA_SYSCALL | KOF_DIAG_VIA_EMULATE);

/*
 * ---- AND THE ATTRIBUTES THAT SAY THIS FILE IS WORTH THE ANALYSIS -------
 *
 * The engine publishes what it read out of the header; this is where the
 * diagnose says what it wants those to be - see KOF_DIAG_WHEN.
 *
 * A MAPPING THAT IS WRITABLE AND EXECUTABLE, and no section table. A
 * stager has nothing else to recognise it by - no imports, no symbols, a
 * few hundred bytes of shellcode - and this is the shape its loader was
 * handed. Counted on this machine: 0 of 1056 binaries under /usr/bin
 * declare a W+X mapping of any kind; 9 of 254 malware objects do.
 *
 * SOME mapping and not the one holding the entry, which is the narrower
 * question and the wrong one here: a payload does not have to START in the
 * region it will write code into.
 *
 * WITHOUT A CONDITION THE RULE TURNS THE ANALYSIS ON FOR EVERY ELF -
 * measured, those 954 binaries went from 1.94 s to 3.45 s for a question
 * none of them could have answered yes to.
 *
 * NOT "one program header", which an earlier version also demanded. That
 * is not about what the file may DO: it is the msfvenom RAW template
 * having exactly one, and the same payload written into a full ELF
 * template carries six - x64_rev_http_clear here is that build. A
 * CONDITION HERE DECIDES WHAT GETS LOOKED AT, so one narrower than it
 * needs to be is a detection in disguise whose misses nobody can see.
 *
 * THE MISSING SECTION TABLE STAYS, because the W+X population is the one
 * that will grow: as more malware ships such a mapping that attribute
 * alone stops separating, and having stripped the section table as well is
 * the half that still does.
 */
KOF_DIAG_WHEN(KOF_FACT_MAP_PERM, KOF_PERM_W | KOF_PERM_X);
KOF_DIAG_WHEN(KOF_FACT_SECTIONS, 0);

/*
 * THE SOCKET IS THE ROOT. It is what the descriptor comes from, and a
 * descriptor is the only thing that ties a read to where it reads from.
 */
KOF_DIAG_ANCHOR(s, KOF_NUCLEO_NET_OPEN, 0);

/* The connect proves the socket is an outbound one rather than a listener. */
KOF_DIAG_FROM(c, s, KOF_NUCLEO_NET_CONNECT, KOF_DIAG_ROLE_FD);

/*
 * AND THE READ TAKES ITS DESCRIPTOR FROM THAT SOCKET.
 *
 * This is the node that matters: it is also a node of DIAG_SYSCALL_MEMEXEC,
 * whose read fills the executable region. Two diagnoses naming one node is
 * the whole statement - the bytes that were executed are the bytes that came
 * off the wire - and kof_diag_share is how a verdict asks it.
 *
 * KOF_NUCLEO_MEM_READ AND NOT the net-recv group: the engine names a read by
 * what it is, and whether it was a socket read is said by THIS edge rather
 * than by the word.
 */
KOF_DIAG_FROM(r, s, KOF_NUCLEO_MEM_READ, KOF_DIAG_ROLE_FD);
