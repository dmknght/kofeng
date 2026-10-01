/*
 * infected.h - the two kinds of range a module may mark.
 *
 * A SHARED HEADER FOR TWO CONSTANTS, which is worth a file because both sides
 * need them and neither may include the other: `kofeng.h` is the host's API
 * and `kofmod/kofsig.h` is the module's, and the whole point of keeping them
 * apart is that a module cannot reach the engine's internals. A duplicated
 * pair of numbers would be two places to change and one to forget.
 *
 * See `struct kof_infected` in kofeng.h for what the marks are for.
 */
#ifndef KOFENG_INFECTED_H
#define KOFENG_INFECTED_H

/*
 * THEY CALL FOR OPPOSITE ACTIONS, which is why there are two and not a flag.
 * BODY is the malware's own bytes - what a removal cuts out. DAMAGE is the
 * host's own bytes that were overwritten - what a repair puts back. A reader
 * that treated them alike would offer to delete the program's entry point.
 */
#define KOF_INF_BODY   0u
#define KOF_INF_DAMAGE 1u

#endif /* KOFENG_INFECTED_H */
