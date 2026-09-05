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
 * THE FLAGS ARE NOT DEFINED HERE.
 *
 * They are the module ABI's, in kofmod/kofsig.h, and there is exactly one
 * definition of them because there was briefly two. This header had
 * KOF_XREF_RGN_ICALL at bit 5 while the ABI had KOF_XREF_PARTIAL there, so a
 * rule asking "is this address referred to by code that calls it" read a region
 * fact as "this build cannot analyse the object" and fell through to accept
 * every candidate. Eighteen X11 utilities came back carrying shellcode.
 *
 * The engine writes these values and a module reads them; one side owning the
 * numbers and the other repeating them is the same mistake in a smaller space.
 */
#include "../core/kofmod/kofsig.h"


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

/*
 * KOF_XREF_* for everything the sweep named in [va, va + n).
 *
 * A RANGE AND NOT AN ADDRESS, because a blob is not referred to at its first
 * byte. Measured on gcc -O0 output for a memcpy of a 23 byte array:
 *
 *     mov 0x2eab(%rip),%rax   # 4020 <pay>
 *     mov 0x2eac(%rip),%rdx   # 4028 <pay+0x8>
 *     mov 0x2ea5(%rip),%rax   # 402f <pay+0xf>
 *
 * Three references, two of them into the middle of the variable. Asking about
 * the first byte alone found one of the three, and would have found none at all
 * had the compiler started anywhere but the front.
 *
 * `n` of 0 or 1 asks about the single address.
 */
uint32_t kof_xref_in(const struct kof_xref *u, uint64_t va, uint64_t n);


/* Non-zero when the sweep ran out of room and stopped recording. A caller that
 * needs "definitely not referred to" rather than "referred to" has to treat
 * that as unknown. */
int kof_xref_full(const struct kof_xref *u);

/*
 * "This address holds startup code" - the entry point, an .init_array entry,
 * whatever the entry stub hands to __libc_start_main. Call it for each, in any
 * order, before the first query; the region each lands in is resolved once the
 * sweep has seen them all.
 *
 * Anything a startup region calls DIRECTLY and nothing else calls is startup
 * too - which is how register_tm_clones and its siblings are found, since
 * nothing points at them from outside.
 */
void kof_xref_startup(struct kof_xref *u, uint64_t va);

void kof_xref_free(struct kof_xref *u);

#endif /* KOFENG_XREF_H */
