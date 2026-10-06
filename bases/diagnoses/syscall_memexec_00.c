#include <kofmod/kofpathogen.h>

/*
 * syscall_memexec_00.c - memory asked for as executable, filled, and entered.
 *
 * IT NAMES NO FAMILY, and the name it used to carry was a mistake: this file
 * was trojan_meterp_00 and described a shape that is not Meterpreter's. A
 * diagnose says what the code DOES; the family is a signature's to name, and
 * the same shape is a stager, a packer and a JIT depending on where the bytes
 * came from - which is a different diagnose.
 *
 * WHY THIS IS NOT A PATTERN RULE. The family already has pattern rules and
 * they work on the DECODED body - the scan reaches it, because the encoder's
 * own loop is run by the interpreter and the child comes out. What they match
 * is bytes, and the encoder exists precisely to change those: shikata_ga_nai
 * builds a different decoder and a different key per build. This matches the
 * part the encoder cannot touch, which is what the payload does once it is
 * decoded - allocate executable memory, fill it, jump into it.
 *
 * MEASURED on samples/msfvenom-encr/x86_poly, 572 bytes, i386. The pipeline
 * that reaches it is the ordinary one and this diagnose adds nothing to it:
 * scan -> the encoded body is interpreted -> child object -> the syscall
 * sweep finds six nodes in the child, and three of them are this shape.
 *
 *     net-open        0x1c5
 *     net-connect     0x1de
 *     sleep           0x1f5
 *     mem-alloc-exec  0x20e   W+X
 *     mem-read        0x21c   <- the region mem-alloc-exec established
 *     exec-memory     0x222   <- the same region
 */

KOF_DIAG_NAME(DIAG_SYSCALL_MEMEXEC);

/*
 * SYSCALL ONLY, AND THAT IS A STATEMENT ABOUT THE OBJECT.
 *
 * This payload has no imports and no symbol table - it IS a block of
 * shellcode that enters the kernel directly, so the symbol route has nothing
 * to read and the emulate route has nothing to resolve. MEASURED on the child
 * above: syscall 6 nodes, emulate 0.
 *
 * Declaring it is not a hint. A route that no loaded diagnose asks for is a
 * route the scan does not pay for, and on this object the symbol route would
 * walk a relocation table that does not exist.
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
 * ---- AND THE SIGN THAT SAYS THIS FILE IS WORTH THE ANALYSIS ------------
 *
 * One region, writable and executable, holding the entry point. A stager
 * has nothing else to recognise it by - no imports, no symbols, a few
 * hundred bytes of shellcode - and this is the shape its loader was handed.
 *
 * WITHOUT IT THE RULE ABOVE TURNS THE ANALYSIS ON FOR EVERY ELF: measured,
 * 954 binaries from /usr/bin went from 1.94 s to 3.45 s for a question none
 * of them could have answered yes to. Not one of them has an RWE PT_LOAD;
 * every msfvenom stager here has exactly one.
 */
KOF_DIAG_SHAPE(KOF_DIAG_SH_ENTRY_WX | KOF_DIAG_SH_NO_SECTIONS);
KOF_DIAG_SHAPE(KOF_DIAG_SH_ONE_LOAD);

/*
 * THE ROOT IS RARE AND UNAVOIDABLE. Rare: no clean program asks for W+X in
 * one call - 0 of 846 in /usr/bin. Unavoidable: code that was just fetched
 * has to run somewhere executable.
 */
KOF_DIAG_ANCHOR(a, KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);

/*
 * BOTH TAKE THEIR POINTER FROM `a`, and this is a provenance tree rather than
 * an order of execution - a node inserted between the two must not break it.
 *
 * ON i386 NEITHER LINK IS A RETURNED VALUE. mmap2 answers in a register on
 * x86-64, but this build establishes the region and names it in an argument,
 * so both edges arrive as REGION links against the stack - index 0xfffe, not
 * a node. The matcher accepts either, which is why one diagnose covers both
 * architectures instead of two copies.
 *
 * "mem-read" AND NOT "net-recv", although this sample's read is on a socket:
 * the statement is true of a loader filling the region from a file as well,
 * and the matcher accepts anything more specific.
 */
KOF_DIAG_FROM(r, a, KOF_NUCLEO_MEM_READ, KOF_DIAG_ROLE_BUFFER);
KOF_DIAG_FROM(x, a, KOF_NUCLEO_EXEC_REG, KOF_DIAG_ROLE_TARGET);
