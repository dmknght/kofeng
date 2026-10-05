#include <kofmod/kofdiag.h>

/*
 * trojan_meterp_00.c - the Metasploit stager, by what its code DOES.
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

KOF_DIAG_NAME(trojan_meterp_00);

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
KOF_DIAG_VIA(KOF_DIAG_VIA_SYSCALL);

/*
 * THE ROOT IS RARE AND UNAVOIDABLE. Rare: no clean program asks for W+X in
 * one call - 0 of 846 in /usr/bin. Unavoidable: code that was just fetched
 * has to run somewhere executable.
 */
KOF_DIAG_ANCHOR(a, "mem-alloc-exec", KOF_FLOWF_WX);

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
KOF_DIAG_FROM(r, a, "mem-read", KOF_DIAG_ROLE_BUFFER);
KOF_DIAG_FROM(x, a, "exec-memory", KOF_DIAG_ROLE_TARGET);

/*
 * THE READ IS OFFERED AS A JOIN POINT, so a rule can ask that this node BE
 * the net-read of another diagnose - at which point it is a stager pulling
 * its payload down a socket rather than something unpacking itself.
 */
KOF_DIAG_TOUCH(r);
