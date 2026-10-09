#include <kofmod/kofpathogen.h>

/*
 * tests/sigs/diagnoses/rwx_exec.c
 *
 * A region allocated writable AND executable in ONE call, something filling
 * it, and control going into it.
 *
 * IT IS HERE AND NOT IN bases/ BECAUSE IT IS THE TEST FIXTURE, not a shipped
 * diagnose. It is the shape every part of the diagnose chain is exercised
 * against - the builder that reads these macros, the .kdig the loader reads
 * back, the matcher, and the reporting path out to a tool. A database the
 * product ships should carry diagnoses that were WRITTEN as product, after a
 * survey; this one was written to make the machinery run, and a fixture in
 * the release database is a fixture nobody will ever delete.
 *
 * IT SAYS NOTHING about the network, about files, or about order, and that is
 * why it holds up: a stager reading from a socket, a loader reading from a
 * file and a packer unpacking itself are all this shape. What separates them
 * is a DIFFERENT diagnose, and the point where the two meet - see
 * kof_diag_share.
 *
 * IT IS NOT A JIT. A well-behaved JIT allocates RW, writes, then mprotects to
 * RX. `KOF_FLOWF_WX` demands both permissions IN ONE ALLOCATION, and that is
 * the whole of the line between them.
 */

KOF_DIAG_NAME(rwx_exec);
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYSCALL | KOF_DIAG_ANALYSIS_SYMBOL);

/*
 * WHICH ANALYSIS ROUTINE CAN SATISFY THIS, as a set.
 *
 * Two routes, two entirely different routines, an order of magnitude apart in
 * cost:
 *
 *   SYMBOL   read the imports. NOT ONE INSTRUCTION is decoded.
 *   SYSCALL  a syscall is in no symbol table. The code has to be searched for
 *            the bytes `0f 05` / `cd 80`, then decoded, then the number
 *            resolved out of a register.
 *
 * NOT DERIVABLE from the capabilities: ALLOC_EXEC is reachable BOTH ways -
 * `mmap` on a static ELF, `VirtualAlloc` on a PE - while a diagnose about
 * LoadLibrary then GetProcAddress has only the symbol route and one about raw
 * shellcode has only the syscall route. Declaring it bounds the work without
 * running any, and states what the diagnose is about.
 *
 * A SET AND NOT A VALUE. This shape lives in both worlds.
 */

/*
 * THE ROOT IS RARE AND UNAVOIDABLE. Rare because no clean program allocates
 * W+X in one call - measured, 0 of 846 in /usr/bin. Unavoidable because code
 * that was just fetched has to run somewhere executable, and there is no way
 * around that.
 */
KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);

/*
 * THE HEAD IS THE PARENT OF BOTH. The read is not the parent of the exec.
 *
 * This is a PROVENANCE tree and not an order of execution: both take their
 * pointer from the head. Read as a sequence, a node inserted between the two would
 * break the match, and it must not.
 */
/*
 * "mem-read" AND NOT "net-recv", though this sample's read is on a socket.
 * The diagnose is true of a loader filling the region from a file and of a
 * stager filling it from the network; naming the specific word would fit this
 * one sample and refuse the other. The matcher accepts anything more specific
 * - see kof_flow_cap_generic.
 */
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_MEM_READ);
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_EXEC_REG);
