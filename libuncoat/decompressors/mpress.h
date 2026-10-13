#ifndef KUNCOAT_MPRESS_H
#define KUNCOAT_MPRESS_H

/*
 * mpress.h - MPRESS's call target conversion, which is a different transform from the BCJ
 * filter of bcj.h and is an algorithm of its own - the packer-specific algorithm a lib
 * runs on bytes; what interprets MPRESS's container stays in bases/unp/mpress_pe.c.
 */

#include <stdint.h>

/*
 * ---- THE CONVERSION ------------------------------------------------------
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
uint64_t kuncoat_mpress_cto_decode(uint8_t *buf, uint64_t n, unsigned bits);

#endif /* KUNCOAT_MPRESS_H */
