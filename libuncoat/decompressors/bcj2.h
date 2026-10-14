/*
 * bcj2.h - undo the four stream branch transform 7z uses on x86 code.
 *
 * BCJ2 is not a bigger BCJ. The x86 filter in bcj.h rewrites addresses in place -
 * same bytes in, same bytes out, one stream - and the compressor then has an easier
 * job. BCJ2 goes further: it PULLS THE ADDRESSES OUT of the instruction stream
 * entirely and sends them down channels of their own, so that what is left
 * compresses as ordinary code and the addresses compress as ordinary numbers.
 *
 * That is why it takes four inputs and why it cannot be expressed as a filter over
 * one:
 *
 *     main   the code, with the four address bytes of converted branches removed
 *     call   the absolute targets of CALL instructions, big endian
 *     jump   the absolute targets of JMP instructions, big endian
 *     rc     a range coder that says, for each candidate opcode, whether it was
 *            converted at all
 *
 * The fourth is the interesting one. bcj.c has to GUESS whether a 0xE8 byte begins
 * a real instruction, and carries a state machine to make that guess less wrong.
 * BCJ2 does not guess: the encoder knew, and it wrote the answer down one bit at a
 * time. So this decoder is exact where the single stream one is heuristic - and it
 * has to be, because a wrong bit here does not corrupt an address, it desynchronises
 * every stream at once and everything after it is noise.
 *
 *
 * WHAT DECIDES A CANDIDATE
 *
 * A byte is a candidate when it is 0xE8 (CALL), 0xE9 (JMP), or the second byte of a
 * two byte conditional jump - 0x0F followed by 0x80..0x8F. Only then is a bit read.
 * The probability model is indexed so that the common case is cheap: 0xE8 gets one
 * slot per preceding byte, because what precedes a call is highly repetitive in real
 * code; 0xE9 and the conditionals get one slot each.
 *
 *
 * THE ADDRESS IS BIG ENDIAN AND THE OUTPUT IS NOT
 *
 * The channels store targets most significant byte first, which is what makes them
 * compress - the high bytes of addresses in one binary are nearly all the same. The
 * instruction wants a little endian RELATIVE displacement. So each address is read
 * big endian, turned into a displacement from the END of the instruction, and
 * written back little endian. Getting either end of that backwards produces a file
 * of the right length whose every branch is wrong, which nothing downstream would
 * notice.
 */

#ifndef KUNCOAT_BCJ2_H
#define KUNCOAT_BCJ2_H

#include <stdint.h>

#include "../uncoat_io.h"

/*
 * The four streams and the buffer the code goes into: one request, since none
 * of them means anything without the others. This decoder writes to a buffer
 * rather than a sink, so it takes the same `struct kuncoat_span` as the rest of
 * the family but not `struct kuncoat_io`.
 */
struct kuncoat_bcj2_io {
	struct kuncoat_span main_s;     /* the code, branch operands removed */
	struct kuncoat_span call_s;     /* CALL targets, big endian */
	struct kuncoat_span jump_s;     /* JMP targets, big endian */
	struct kuncoat_span rc_s;       /* the range coder's bit stream */
	uint8_t            *out;
	uint64_t            out_cap;
};

/*
 * Decode `io->out_cap` bytes from the four streams into `io->out`.
 *
 * Returns the number of bytes produced. Short of out_cap means a stream ran out -
 * a truncated archive, or a size the header stated and the streams cannot supply -
 * and the caller decides whether that is damage or a limit. Zero means nothing could
 * be produced at all - which is also the answer to a NULL `io`, a NULL stream or
 * output, or an out_cap of 0 (this entry point returns a count, not a status).
 *
 * No stream is optional. An archive whose call or jump channel is empty is legal -
 * code with no branches of that kind - but the pointer must still be valid, because
 * the decoder cannot know it will not be asked until it is.
 */
uint64_t kuncoat_bcj2_decode(const struct kuncoat_bcj2_io *io);

#endif /* KUNCOAT_BCJ2_H */
