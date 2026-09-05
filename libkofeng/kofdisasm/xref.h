/* SPDX-License-Identifier: Apache-2.0 */
/*
 * xref.h - which code refers to a data address, and how.
 *
 * THE QUESTION THIS ANSWERS, and why it is not the one asked before.
 *
 * A rule looking for a payload used to ask what the BYTES look like: how many
 * are unprintable, whether one value owns too much of the blob, whether a
 * syscall instruction is in there. Every one of those is defeated by encoding
 * the payload, which is the first thing anyone does to it.
 *
 * An ordinary variable is READ. A payload variable is EXECUTED. That difference
 * is in the code, not in the data, and it survives any encoding of the data:
 *
 *     mov  rax, [rip+0x2ee8]   # shellcode      <- read: passed to strlen below
 *     mov  rdi, rax
 *     call strlen                                  a DIRECT call - not this
 *     ...
 *     mov  rax, [rip+0x2ebb]   # shellcode      <- and now
 *     call rax                                  <- EXECUTED
 *
 * Both instructions name the same variable. Only the second one calls it, and
 * only through a register - a direct call names a code address and never a
 * variable. That is the whole discriminator.
 *
 * WHAT THIS IS NOT. It is not dataflow analysis and does not try to be: one
 * linear sweep, a shadow map of sixteen registers, and no notion of a basic
 * block. A payload copied into a fresh mapping and called there is NOT seen -
 * the call targets the mapping, not the variable. That is a real limit and it
 * is stated rather than papered over; what is here catches the shape the
 * loaders in the sample set actually use, at a cost bounded by the code size.
 */
#ifndef KOFENG_XREF_H
#define KOFENG_XREF_H

#include <stdint.h>

/*
 * WHAT KIND OF REFERENCE, AND NOTHING ABOUT WHAT IT MEANS.
 *
 * Five mechanical facts. Not one of them says "payload", "loader" or anything
 * else about intent, and that is deliberate: the meaning is assembled where the
 * vocabulary of malware lives, in bases/, and a rule that wants a different
 * shape composes these differently without a line changing here.
 *
 * It was two flags, and the second of them was called CALLED and meant "this is
 * executed" - a conclusion, sitting in the engine, which every future question
 * would have had to be added alongside.
 */
#define KOF_XREF_READ   (1u << 0)  /* code forms this address, or loads from it */
#define KOF_XREF_WRITE  (1u << 1)  /* code stores to it */
#define KOF_XREF_CALL   (1u << 2)  /* it is the target of a CALL */
#define KOF_XREF_JUMP   (1u << 3)  /* it is the target of a JMP */
/*
 * It is in a register at a CALL - an argument, as far as a sweep with no
 * knowledge of the ABI can tell. The weakest of the five and the one that
 * carries the shape nothing else here can: a payload handed to mprotect or
 * memcpy and executed somewhere else entirely is an argument and never a call
 * target.
 */
#define KOF_XREF_ARG    (1u << 4)

/*
 * THE MOST CODE ONE SWEEP WILL READ.
 *
 * A bound in bytes rather than in instructions because that is what a caller
 * can check before committing: the rule that asks already refuses an object
 * whose code is larger than this, so in practice the sweep never reaches it and
 * this is the guard for every other caller.
 */
#define KOF_XREF_MAX 8192u

struct kof_xref;

/* An empty map. NULL when there is no memory. The caller frees. */
struct kof_xref *kof_xref_new(void);

/*
 * Sweep one run of code into the map, and record what it does with the
 * addresses it names.
 *
 * `code_va` is where the first byte is mapped, which is what makes a
 * rip-relative displacement resolvable. `bits` is 32 or 64.
 *
 * ONE CALL PER EXECUTABLE SECTION, and the caller is expected to make all of
 * them. Sweeping only the first was tried and was wrong in a way worth
 * recording: the first executable section of an ordinary ELF is .init, which is
 * twenty three bytes of prologue and names no variable at all. The comment
 * justifying the shortcut said .text came first. It does not.
 */
void kof_xref_add(struct kof_xref *u, const uint8_t *code, uint32_t code_n,
		     uint64_t code_va, unsigned bits);

/* KOF_USE_* for one address, or 0 for an address the sweep never named. */
uint32_t kof_xref_of(const struct kof_xref *u, uint64_t va);

/* Non-zero when the sweep ran out of room and stopped recording. A caller that
 * needs "definitely not used" rather than "used" has to treat that as unknown. */
int kof_xref_full(const struct kof_xref *u);

void kof_xref_free(struct kof_xref *u);

#endif /* KOFENG_XREF_H */
