/*
 * celllysis/capability_flags.h - WHAT A NODE CARRIES BESIDES ITS CAPABILITY: the
 * KGENOME_NUCLEO_F_* bits of a node's `flags`, and what each one claims.
 *
 */
#ifndef KGENOME_CAPABILITY_FLAGS_H
#define KGENOME_CAPABILITY_FLAGS_H

#include <stdint.h>

/* The selector was known only in its low 8 bits - "mov al, 3" with the rest of
 * eax never set in this sweep. Accepted because a syscall number under 256 is
 * fully determined by it, and flagged because the claim is weaker. */
#define KGENOME_NUCLEO_F_LOW8   (1u << 0)
/*
 * The node sits inside a backward branch's span.
 *
 * "Sends TCP" and "sends TCP in a loop" are different claims and the second is
 * the one worth a rule - a bot's beacon, a scanner's probe, a stager's retry.
 * APPROXIMATED BY AN INTERVAL, not by a dominator: a backward direct branch
 * from S to T marks everything in [T, S]. That over-reports when two unrelated
 * loops nest and under-reports a loop built out of indirect branches, and both
 * are stated here rather than discovered later.
 */
#define KGENOME_NUCLEO_F_LOOP   (1u << 1)
/*
 * WHAT THIS NODE PRODUCED WAS LATER USED AS A BRANCH TARGET.
 *
 * This is the edge the whole file exists for. "Allocated something executable"
 * is a fact about a JIT as much as about a stager; "allocated something
 * executable AND JUMPED INTO IT" is a different claim, and it is the one a
 * rule wants. The pointer is followed from the register the call returned it
 * in to the operand of an indirect call or jump.
 *
 * REGISTER TO REGISTER ONLY. A pointer spilled to the stack and reloaded is
 * lost - that needs the slot model xref.c has and this does not. Losing it
 * costs a detection; inventing it would cost a false one, so the sweep loses.
 */
#define KGENOME_NUCLEO_F_EXECUTED (1u << 2)
/*
 * THE IMPORT WAS CALLED THROUGH A REGISTER, not through its slot.
 *
 * `call [VirtualAlloc]` is what a compiler emits and what a reader of the
 * import table can see at the call site. `mov edi,[VirtualAlloc] ; ... ; call
 * edi` reaches the same function while leaving nothing at the call site that
 * names it - which is the point: it is one of the cheapest ways to make a
 * static reader lose the reference.
 *
 * NOT A VERDICT. A compiler does this too when the same import is called in a
 * loop, so on its own it says very little. It is a fact about HOW the call was
 * written, and what it is worth is measured beside the others.
 */
#define KGENOME_NUCLEO_F_VIA_REG  (1u << 3)
/*
 * THE PAGE IS WRITABLE AND EXECUTABLE AT THE SAME TIME.
 *
 * WHY THIS IS NOT THE SAME FACT AS ALLOC_EXEC, and keeping it separate is the
 * difference between a rule and a false positive.
 *
 *     a JIT:     allocate READ|WRITE, emit into it, THEN flip it to
 *                READ|EXEC. The page is never both at once - W^X, which
 *                every serious runtime has followed for twenty years.
 *
 *     a loader:  allocate READ|WRITE|EXEC in one call, copy, jump. One call,
 *                and the page is both for its whole life.
 *
 * Both reach this file as "allocated something executable", because the
 * capability vocabulary deliberately does not name the API. That is right for
 * telling mmap from VirtualAlloc and WRONG here: these two are different
 * SHAPES, and normalising them together would put every JIT in the same bucket
 * as every stager. So the shape is kept, as a bit on the node.
 *
 * POSIX spells it PROT_WRITE|PROT_EXEC; Windows spells it
 * PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY.
 */
#define KGENOME_NUCLEO_F_WX       (1u << 4)

/*
 * THE SOCKET IS A DATAGRAM ONE - socket(.., SOCK_DGRAM, ..).
 *
 * "Opened a socket" is one claim and "opened a socket it will not connect"
 * is another. A C2 is a stream: connect, read a command, write a reply. A UDP
 * FLOOD is a datagram socket and sendto in a loop, with no connect anywhere -
 * so without this the two shapes differ only by the absence of a step, which
 * is the weakest thing a rule can be built on.
 */
#define KGENOME_NUCLEO_F_DGRAM    (1u << 5)
/*
 * THE SOCKET IS LOCAL - socket(AF_UNIX, ..) - AND THAT IS A CLEAN SIGNAL.
 *
 * Desktop IPC is sockets: language servers, extension hosts, session buses.
 * bases/heur/proc_revshell_00.c measured eight such processes on an ordinary
 * desktop, every one of them legitimate. A rule that says "talks on a socket"
 * and means the network is wrong on all eight of them, and the domain
 * argument is what separates them - not the protocol, not the port.
 *
 * It is kept as a POSITIVE fact rather than as "not AF_INET", because an
 * argument the sweep could not follow is a third state and must not read as
 * either answer.
 */
#define KGENOME_NUCLEO_F_LOCAL    (1u << 6)
/*
 * THE CAPABILITY WAS READ FROM A NAME, not from a number or an instruction.
 *
 * Every word in this vocabulary comes from something the AUTHOR did not
 * choose - a syscall number the kernel ABI fixes, an instruction the ISA
 * fixes, a symbol the kernel or Windows owns and a program cannot rename and
 * still link. None of it is content in the sense mutation means.
 *
 * But the three are not equally hard to AVOID, and that difference is worth
 * carrying. A number is in the instruction stream of anything that asks the
 * kernel for something; a `mov cr0` is there or it is not. A NAME can be
 * sidestepped: resolve the address at run time and call through a register
 * and there is no name left - diamorphine does precisely that to find the
 * syscall table, and 926 Go binaries here do it for every Windows API they
 * use.
 *
 * So this bit says "this step is the avoidable kind". A rule that wants to
 * stand up to an author who tried can require steps without it; one written
 * for triage can take them as they come. The engine states the difference
 * rather than deciding it.
 */
#define KGENOME_NUCLEO_F_BY_NAME  (1u << 7)

#endif /* KGENOME_CAPABILITY_FLAGS_H */
