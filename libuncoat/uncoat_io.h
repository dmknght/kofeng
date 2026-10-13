/*
 * uncoat_io.h - the decoder convention, written down as a type.
 *
 * Every kuncoat decoder that hands its output to a sink took the same six things:
 * the input and its length, the sink and its user pointer, and two counters it
 * always set - how much input it used and how much output it made. They were
 * repeated as a parameter list in each header, and a list repeated is a list that
 * drifts. Here they are one concept: a stream, in and out of a decoder.
 *
 *   in         the input window. Read only; the decoder never keeps it past the call.
 *   sink,user  where output goes. The sink returns non-zero to continue and zero to
 *              stop, which the decoder reports as KUNCOAT_STOPPED.
 *   consumed   OUT. Input bytes the stream really used. Always set, whatever the
 *              status, because a caller that stopped or was truncated still needs
 *              to know how far it got. A decoder that cannot tell leaves it 0 and
 *              says so in its header.
 *   produced   OUT. Bytes handed to the sink by this call. Always set.
 *
 * It is passed by pointer and is not copied: the decoder reads `in`, `sink` and
 * `user` from it once at entry and writes the two counters once at exit, so none
 * of this is on a per-byte path.
 */

#ifndef KUNCOAT_UNCOAT_IO_H
#define KUNCOAT_UNCOAT_IO_H

#include <stdint.h>

/* A read-only run of bytes: the one shape of "a buffer and its length". */
struct kuncoat_span {
	const uint8_t *p;
	uint64_t       n;
};

/*
 * Where output goes. Returns non-zero to continue, zero to stop. Zero is not an
 * error and not corruption - the receiver has enough - so decoders report it as
 * their own status, never as a failure of the stream.
 */
typedef int (*kuncoat_sink_fn)(void *user, const uint8_t *p, uint32_t n);

struct kuncoat_io {
	struct kuncoat_span in;
	kuncoat_sink_fn     sink;
	void               *user;
	uint64_t            consumed;   /* OUT */
	uint64_t            produced;   /* OUT */
};

#endif /* KUNCOAT_UNCOAT_IO_H */
