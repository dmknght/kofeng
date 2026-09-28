/*
 * bcj.h - undo the branch rewriting that 7z and xz apply before compressing.
 *
 * Not compression. A BCJ filter changes bytes into other bytes of the same length
 * so that what follows compresses better, and the change has to be undone in the
 * opposite order afterwards. It sits between the decompressor and the file:
 *
 *     packed bytes -> LZMA2 -> BCJ undo -> the original
 *
 * What it rewrites is the address in a CALL or JMP. In x86 those are stored
 * RELATIVE to the instruction, so the same call from two places is two different
 * byte sequences; converting them to absolute makes them identical and the
 * compressor then has something to work with. Undoing it is the same arithmetic
 * with the sign the other way.
 *
 *
 * WHY THIS EARNS ITS PLACE
 *
 * Measured over the 7z archives on this machine, folders that chain a filter in
 * front of the coder:
 *
 *     76   LZMA2 + BCJ x86
 *      8   LZMA + LZMA + LZMA2 + BCJ2 x86
 *
 * So one filter covers 90% of them, and it is the only one worth having: the
 * others in the family - PowerPC, ARM, SPARC, IA64 - do not appear here at all,
 * and BCJ2 is a different shape entirely, four input streams rather than one.
 *
 * Without this the engine has the decompressor and still cannot read the archive,
 * which is the worst of the three possible states: the work is done and the answer
 * is thrown away.
 *
 *
 * WHY IT IS NOT ALLOWED TO BE APPROXIMATE
 *
 * A wrong BCJ undo produces bytes that are the right LENGTH and mostly the right
 * VALUES - only the addresses are wrong - so the result looks like a program and
 * is not one. Nothing downstream would notice. That is why this is checked against
 * a reference implementation on real archives rather than eyeballed.
 *
 * Written from the transform's description. The state machine below - which
 * decides whether a 0xE8 or 0xE9 byte is really an instruction rather than part of
 * some other datum - is what the format specifies; the shape of the code is its own.
 */

#ifndef KOFENG_BCJ_H
#define KOFENG_BCJ_H

#include <stdint.h>

/*
 * Undo the x86 branch conversion, in place.
 *
 * `start` is where this buffer sits in the whole decoded stream, which the
 * transform needs because the addresses it rewrites are relative to a position.
 * For a buffer holding the whole thing it is zero.
 *
 * Returns how many bytes were processed, which is up to four short of `n`: the
 * transform will not touch an instruction whose address would run past the end.
 * Those bytes are left exactly as they were, which is correct - a partial
 * instruction was never rewritten in the first place.
 */
uint64_t kof_bcj_x86_decode(uint8_t *buf, uint64_t n, uint32_t start);

/*
 * ---- MPRESS'S CALL TARGET CONVERSION, WHICH IS A DIFFERENT TRANSFORM -------
 *
 * The same idea as BCJ and not the same rule, which is why it is a second
 * function rather than a flag on the first. Both rewrite the displacement of a
 * call so that identical calls compress alike; they disagree about which bytes
 * are a call, about what the stored value means, and about how far into the
 * buffer to look. Sharing code between them would mean a parameter for every
 * one of those.
 *
 * Read off the stub's own undo loop rather than from a description - see
 * bases/unp/mpress_pe.c for where the container is documented. What the loop
 * does, in order:
 *
 *   - a byte 0xE8 or 0xE9 is a candidate;
 *   - ON 64 BIT ONLY, so is 0xFF followed by a byte whose 0xFD bits are 0x15
 *     (call/jmp through rip), and 0x8D followed by one whose 0xC7 bits are
 *     0x05 (lea from rip). The 32 bit stub does not test for either, and
 *     applying the wider rule to a 32 bit image rewrites bytes the packer
 *     never touched.
 *   - the four bytes after it hold an ABSOLUTE offset from the start of the
 *     buffer, and become the relative displacement they were;
 *   - a stored value at or past `scan` is left alone, and so is a negative one
 *     that stays negative after the position is added back.
 *
 * `n` is the whole buffer. The scan stops at `n - 0x1000`, which is the stub's
 * own bound and not a safety margin invented here: the packer filtered exactly
 * that range, so undoing more would corrupt bytes and undoing less would leave
 * some filtered. A buffer shorter than that is left untouched.
 *
 * `bits` is 32 or 64 and anything else is refused. Returns how many
 * displacements were rewritten, which is a number a caller can report and a
 * test can check - zero is a legitimate answer for a buffer with no calls in
 * it, so it is not an error code.
 */
uint64_t kof_mpress_cto_decode(uint8_t *buf, uint64_t n, unsigned bits);

#endif /* KOFENG_BCJ_H */
