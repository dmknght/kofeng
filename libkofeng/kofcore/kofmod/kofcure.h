/*
 * kofcure.h - what a rule writes when it knows how to undo an infection.
 *
 * kofsig.h has named this file since the entry points were first written -
 * "kof_unpack() from kofunp.h, kof_cure() from kofcure.h" - and the macros
 * lived there in the meantime. They are here now, with the arithmetic the
 * disinfect stage answers, because a cure is a role and a role gets a header.
 *
 *
 * A CURE DESCRIBES; THE HOST DECIDES.
 *
 * Every macro below states a request and returns whether it was accepted.
 * Nothing here writes to a file: the host records the requests, bounds-checks
 * each one against the object - see c_cure_patch in objctx.c - and a host that
 * wants to SHOW a repair before carrying it out reads the same description
 * the one that carries it out does. A cure that is refused has still said what
 * it would have done.
 *
 *
 * AND IT NEVER GUESSES A NUMBER.
 *
 * Measured over 1312 cure objects in Kaspersky's own bases, 82% of them call
 * five engine primitives or fewer: a cure is a formula whose terms are all
 * read out of the host. The entry the virus saved, the length it recorded,
 * the end of the last region the parse claims. A size derived from alignment
 * arithmetic, or an entry recovered by disassembling until something looks
 * like a prologue, is a guess - and a guess that truncates a file is how a
 * repair destroys one. What is below exists so the terms can be READ.
 */
#ifndef KOFENG_KOFCURE_H
#define KOFENG_KOFCURE_H

/*
 * This header is included from inside kofsig.h, after struct kof_content is
 * defined - every macro reaches through it, and `ctx` is in scope because
 * KOF_DEFINE_SCAN put it there.
 */

/*
 * WHERE THE HOST'S OWN BYTES END.
 *
 * The largest end offset any region the parse claims reaches, which is the
 * truncation point for an appender: its body is past all of them. KOF_BROKEN
 * when the object has no regions, and a cure that gets that answer must not
 * truncate - it has been told the parse cannot say where the file ends.
 */
#define kof_cure_clean_end()                                               \
	((ctx)->content->pz_clean_end                                      \
	 ? (ctx)->content->pz_clean_end((ctx)) : (uint64_t)KOF_BROKEN)

/*
 * DOES THIS OFFSET HOLD INSTRUCTIONS.
 *
 * The test a restored entry point has to pass. A value read out of a stub is
 * only an entry if it lands where code lives; measured over 127 files sharing
 * one entry stub, the saved value equalled the host's own .text address in
 * 125 of them, so this is what separates a recovered entry from a number that
 * merely parsed.
 */
#define kof_cure_is_code(off)                                              \
	((ctx)->content->pz_is_code                                        \
	 ? (ctx)->content->pz_is_code((ctx), (uint64_t)(off)) : 0)

/*
 * AN ADDRESS THE FILE USES, AS AN OFFSET INTO IT.
 *
 * A saved entry point is an address and every request below takes an offset.
 * PE answers from its section table and ELF from its program headers, so a
 * rule that asks this does not dispatch on format. KOF_BROKEN when nothing
 * maps there.
 */
#define kof_cure_addr(addr)                                                \
	((ctx)->content->pz_addr_to_off                                    \
	 ? (ctx)->content->pz_addr_to_off((ctx), (uint64_t)(addr))         \
	 : (uint64_t)KOF_BROKEN)

/*
 * TAKE THE MASK OFF BYTES THE VIRUS SAVED.
 *
 * The header a parasitic infector keeps so it can put it back is often kept
 * encrypted, and the shapes are a closed set - byte xor, word xor, add,
 * rotate - because a mask whose key must be RECOVERED is not a mask, it is an
 * unpacker's problem. See enum kof_pz_mask.
 *
 * Reads `n` bytes at `off` in this object and writes them to a buffer the
 * rule owns. Returns the bytes written, 0 when the request is out of bounds
 * or the mask is not one of the four.
 */
#define KOF_CURE_MASK_NONE  0u
#define KOF_CURE_MASK_XOR8  1u
#define KOF_CURE_MASK_XOR16 2u
#define KOF_CURE_MASK_ADD8  3u
#define KOF_CURE_MASK_ROL8  4u

#define kof_cure_unmask(off, n, mask, key, out, cap)                       \
	((ctx)->content->pz_unmask                                         \
	 ? (ctx)->content->pz_unmask((ctx), (uint64_t)(off), (uint32_t)(n),\
				     (uint32_t)(mask), (uint32_t)(key),    \
				     (out), (uint32_t)(cap)) : 0u)

#endif /* KOFENG_KOFCURE_H */
