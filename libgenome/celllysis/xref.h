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
#ifndef KGENOME_XREF_H
#define KGENOME_XREF_H

#include <stdint.h>

/*
 * THE FLAGS ARE DEFINED HERE, ONCE, AND THE ABI RE-EXPORTS THEM.
 *
 * They are what the sweep computes, so they live with it; <kofmod/kofsig.h>
 * includes this header and a module reads them where it always did
 * (kof_data_xref). There is exactly one definition of them because there was
 * briefly two. This header had KGENOME_XREF_RGN_ICALL at bit 5 while the ABI
 * had KGENOME_XREF_PARTIAL there, so a rule asking "is this address referred to by
 * code that calls it" read a region fact as "this build cannot analyse the
 * object" and fell through to accept every candidate. Eighteen X11 utilities
 * came back carrying shellcode.
 *
 * The engine writes these values and a module reads them; one side owning the
 * numbers and the other repeating them is the same mistake in a smaller space.
 */

/* Code forms this address, or loads from it. */
#define KGENOME_XREF_READ    (1u << 0)
/* Code stores to it. */
#define KGENOME_XREF_WRITE   (1u << 1)
/* It is the target of a CALL - direct or through a register. A direct call
 * usually names code, and names a variable exactly when a compiler could prove
 * the target constant, which is what -O2 does to a called function pointer. */
#define KGENOME_XREF_CALL    (1u << 2)
/* The same, for a JMP. */
#define KGENOME_XREF_JUMP    (1u << 3)
/* It was in a register when a CALL happened - an argument, as far as a sweep
 * that knows no calling convention can tell. */
#define KGENOME_XREF_ARG     (1u << 4)
/*
 * The sweep gave up before it had seen everything - too many distinct
 * addresses, or code it could not decode. A rule may still trust a bit that IS
 * set; it may not read the absence of one as "not referred to".
 */
#define KGENOME_XREF_PARTIAL (1u << 5)
/*
 * A REGION THAT REFERS TO IT ALSO MAKES AN INDIRECT CALL.
 *
 * Evidence about the neighbourhood rather than about the address, and it exists
 * because the address facts miss the shape that matters most: a payload copied
 * into a fresh mapping and called there is never called, jumped to, or even
 * passed anywhere - and yet one region of code reads it and transfers control.
 *
 * A REGION, not a function: the boundaries come from RET, because the files
 * this has to work on are stripped and have no function table to read.
 *
 * MEASURED 11.6% ON CLEAN BINARIES, which is why no rule gates on it alone.
 */
#define KGENOME_XREF_RGN_ICALL (1u << 6)
/* ...or the region directly calls a region that does. One level. Measured 3.3%
 * on clean binaries, and it fires on programs that only read a lookup table:
 * every dynamically linked binary calls __libc_start_main through the GOT, from
 * the region its entry point is in. */
#define KGENOME_XREF_RGN_NEAR  (1u << 7)
/*
 * SOMETHING OTHER THAN STARTUP CODE REFERS TO IT.
 *
 * Every ELF carries code nobody wrote - the entry stub, the PLT thunks, .init
 * and .fini, and whatever .init_array registers - and all of it references data
 * that no rule about a person's program is looking for. The startup set is
 * found from the ELF's own structure, not from symbols: 4 of 400 binaries in
 * /usr/bin still carry `_start` as a symbol, and every one of them has an entry
 * point and an .init_array.
 *
 * Absent means the only code that ever mentions it is code the compiler wrote.
 * Measured: 87% of sized variables in clean binaries are in that position.
 */
#define KGENOME_XREF_USER      (1u << 8)




/*
 * THE MOST CODE ONE SWEEP WILL READ.
 *
 * A bound in bytes rather than in instructions because that is what a caller
 * can check before committing: the rule that asks already refuses an object
 * whose code is larger than this, so in practice the sweep never reaches it and
 * this is the guard for every other caller.
 */
#define KGENOME_XREF_MAX 8192u

struct kgenome_xref;

/* An empty map. NULL when there is no memory. The caller frees. */
struct kgenome_xref *kgenome_xref_new(void);

struct kgenome_cell_insn;

/*
 * THE SWEEP IS FED INSTRUCTIONS, IT DOES NOT READ BYTES.
 *
 * It used to take a buffer and decode it, which made it a second decoder of the
 * same code the diagnose walks decode - and the diagnose walks keep what they
 * decoded (libgenome/phenotype/diag_wrapper_walk.c, "THE DECODE,
 * ONCE"). Now the caller owns where the instructions come from, and this owns
 * only what they mean: kgenome_xref_feed is the callback a reader of instructions
 * calls (the kgenome_cell_insn_fn of celllysis.h), so the one decode of an object's code
 * can serve it. Nothing in this library changed about which instructions are
 * "x86": the sweep tracks x86 registers and rip-relative operands, and a run
 * begun for any other architecture records nothing - "nothing known", which
 * the caller says itself (KGENOME_XREF_PARTIAL).
 *
 * ONE RUN PER EXECUTABLE SECTION, and the caller is expected to make all of
 * them. A run is where the register map starts empty and a region starts, so
 * the answers depend on where the caller cuts the code into runs - which is
 * why the cut is the caller's. Sweeping only the first was tried and was wrong
 * in a way worth recording: the first executable section of an ordinary ELF is
 * .init, which is twenty three bytes of prologue and names no variable at all.
 * The comment justifying the shortcut said .text came first. It does not.
 *
 *   kgenome_xref_begin   a new run: an empty register map, a new region.
 *   kgenome_xref_feed    the next instruction of the run, in address order; NULL
 *                    for a byte that did not decode (the sweep forgets what the
 *                    registers held - data between functions is not a reason
 *                    to stop, and not a reason to trust what came before it).
 *                    The instruction's at_va is where it runs, which is what
 *                    makes a rip-relative displacement resolvable.
 */
void kgenome_xref_begin(struct kgenome_xref *u, unsigned arch);
void kgenome_xref_feed(void *u, const struct kgenome_cell_insn *in);

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
 *
 * Not const: the first query sorts the entries into a searchable index, so the
 * map a caller passes is finished by asking it a question.
 */
uint32_t kgenome_xref_in(struct kgenome_xref *u, uint64_t va, uint64_t n);


/*
 * HOW MANY TIMES, by kind, the sweep saw code name an address of [va, va + n): the counts behind the flags of
 * kgenome_xref_in. `read` is a load or an address taken (lea, rip-relative), `write` a store, `call` and `jump` a
 * transfer of control through it, `arg` it in a register when a call happened. Each address keeps its counts to 65535;
 * the map keeps 512 distinct addresses, so a caller reads kgenome_xref_full beside it ("none" is only "none seen").
 */
struct kgenome_xref_refs {
	uint32_t read, write, call, jump, arg;
};
void kgenome_xref_refs(struct kgenome_xref *u, uint64_t va, uint64_t n, struct kgenome_xref_refs *out);

/* Non-zero when the sweep ran out of room and stopped recording. A caller that
 * needs "definitely not referred to" rather than "referred to" has to treat
 * that as unknown. */
int kgenome_xref_full(const struct kgenome_xref *u);

/*
 * "This address holds startup code" - the entry point, an .init_array entry,
 * whatever the entry stub hands to __libc_start_main. Call it for each, in any
 * order, before the first query; the region each lands in is resolved once the
 * sweep has seen them all.
 *
 * Anything a startup region calls DIRECTLY and nothing else calls is startup
 * too - which is how register_tm_clones and its siblings are found, since
 * nothing points at them from outside.
 *
 * ANSWERS WHETHER THERE WAS ROOM, because the table is small and fixed and a
 * caller reading addresses OUT OF THE OBJECT has no other way to learn that it
 * is full. An .init_array is a length the file declares, so "keep going until
 * the section ends" is a loop an object chooses the length of - and past this
 * table every turn of it records nothing. A caller that feeds a declared run
 * stops on a zero; one feeding a handful of addresses it enumerated itself can
 * ignore the answer.
 */
int kgenome_xref_startup(struct kgenome_xref *u, uint64_t va);

void kgenome_xref_free(struct kgenome_xref *u);

#endif /* KGENOME_XREF_H */
