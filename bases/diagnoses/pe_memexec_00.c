#include <kofmod/kofpathogen.h>

/*
 * pe_memexec_00.c - a Windows program that allocates memory it can write and
 * run, fills it, and jumps into it.
 *
 *     p = VirtualAlloc(0, n, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
 *     recv(s, p, n, 0);                  <- what fills it
 *     ((void (*)())p)();                 <- and the jump
 *
 * THE SAME SHAPE AS syscall_memexec_00 ON LINUX, with the Windows words: the
 * allocation is VirtualAlloc with a protection that is both writable and
 * executable (the vocabulary refines it from the argument - see
 * kof_flow_cap_of_call), the read is whatever fills it, the jump is a branch
 * into what the allocation returned.
 *
 * A SEPARATE DIAGNOSE AND NOT THE ELF ONE WITH A WIDER WHEN, because it asks
 * for a different analysis: the calls of a program that finds its own APIs are
 * named by the apihash route (diag_apihash.c), which the ELF diagnoses have no
 * business running, and it is gated by a W+X section, which is where a stager
 * PE keeps what it decodes into.
 *
 * THE GATE IS A MEASURED ONE. A diagnose a verdict reads ASKS, and an ask makes
 * the engine interpret the object - on every PE that was the whole corpus going
 * through the emulating unpackers, 10.9 s to 26.6 s. A writable-and-executable
 * section is what a stager's template has and an ordinary program's does not.
 */

KOF_DIAG_NAME(DIAG_PE_MEMEXEC);

KOF_DIAG_VIA(KOF_DIAG_VIA_APIHASH);

KOF_DIAG_WHEN(KOF_FACT_FORMAT, KOF_FMT_PE);
KOF_DIAG_WHEN(KOF_FACT_MAP_PERM, KOF_PE_PERM_W | KOF_PE_PERM_X);

KOF_DIAG_ANCHOR(a, KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);
KOF_DIAG_FROM(r, a, KOF_NUCLEO_MEM_READ, KOF_DIAG_ROLE_BUFFER);
KOF_DIAG_FROM(x, a, KOF_NUCLEO_EXEC_REG, KOF_DIAG_ROLE_TARGET);
