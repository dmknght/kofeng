/*
 * inflate.h - DEFLATE (RFC 1951), streaming, with a fixed memory cost.
 *
 * The first decompressor, and the one most others are built on: gzip, zlib, zip
 * method 8 and PNG are all a DEFLATE stream with a different wrapper around it.
 *
 * Two properties are what this exists for, and neither is "fast":
 *
 *   - IT COSTS 32KB, whatever the stream is. DEFLATE's back references reach at
 *     most 32768 bytes, so a sliding window of exactly that is all the state a
 *     decoder needs; output leaves through a sink as it is produced and is never
 *     accumulated here. A stream that expands to a terabyte runs in the same
 *     memory as one that expands to nothing, which is what makes decompression
 *     affordable under a scanner's memory ceiling at all.
 *
 *   - THE SINK CAN SAY STOP. Every limit the engine has - the object cap, the
 *     total budget, the resident ceiling - is enforced by the thing receiving the
 *     bytes rather than by anything here, and the decoder stops on the spot when
 *     it is refused. A decompression bomb is not a special case that has to be
 *     recognised; it is a stream whose sink stops accepting.
 *
 * Written rather than linked because the input is hostile. zlib is correct, but
 * correct against corrupt input means "returns an error", and what is wanted here
 * is a decoder whose every read of a length, a distance and a code came from a
 * bounded buffer, that distinguishes truncation from corruption because a
 * truncated archive inside malware is ordinary rather than exceptional, and that
 * can be fuzzed as a unit with no allocator underneath it. It is checked against
 * zlib on every stream the differential test can generate.
 */

#ifndef KOFENG_INFLATE_H
#define KOFENG_INFLATE_H

#include <stdint.h>

#include "../core/kofcore.h"
#include "decomp.h"

/* DEFLATE's maximum back reference, and therefore the whole of the decoder's
 * state. Not a tuning parameter: RFC 1951 fixes it. */
#define KOF_INF_WINDOW 32768u

/*
 * Where output goes. Returns non-zero to continue, zero to stop.
 *
 * Zero is not an error and is not corruption - it is the receiver saying it has
 * enough - so the decoder reports it as its own status rather than as a failure of
 * the stream. Getting that distinction wrong would report every object that hit a
 * budget as a broken archive.
 */
typedef int (*kof_inflate_sink)(void *user, const uint8_t *p, uint32_t n);

/*
 * How many bits the lookup table below covers. 512 entries of two bytes.
 *
 * Nine because that is where DEFLATE's own fixed code sits: its literal codes are
 * seven, eight and nine bits, so nine resolves every symbol of a fixed block and
 * the overwhelming majority of a dynamic one in a single indexed read. Ten would
 * add a kilobyte per table to catch the tail; measured, it was not worth it.
 */
#define KOF_HUFF_FAST_BITS 9u
#define KOF_HUFF_FAST_SIZE (1u << KOF_HUFF_FAST_BITS)

/*
 * One canonical Huffman code: the count-and-symbol form, plus a table over the
 * short codes.
 *
 * The count-and-symbol form alone is how this was first written, and it is correct
 * and short - fifteen iterations at worst, one bit at a time. It was also the whole
 * cost of a scan. Measured on a container-heavy corpus: decompression was 75% of the
 * total scan time, and this decoder ran at 127MB/s against zlib's 342MB/s on the
 * same data. Removing every bounds check in the decoder changed that number by
 * nothing at all - the gap was the per-bit walk, not the safety.
 *
 * So `fast` resolves any code of nine bits or fewer in one read, and anything longer
 * falls back to the walk, which is kept because it is the thing that is obviously
 * right and because near the end of the input there may not be nine bits left to
 * look at.
 *
 * The table is indexed by the next nine bits AS THEY SIT IN THE BIT BUFFER, which is
 * the reverse of the code: DEFLATE packs bits least-significant-first while canonical
 * Huffman codes are read most-significant-first. Reversing at build time rather than
 * at decode time is the entire point of the table.
 */
struct kof_huff {
	int16_t  count[16];    /* how many codes of each length */
	int16_t  symbol[288];  /* symbols ordered by code */
	/* (length << 12) | symbol, or zero where no code of nine bits or fewer
	 * begins with these bits. Zero is unambiguous because a real entry always
	 * has a length of at least one. */
	uint16_t fast[KOF_HUFF_FAST_SIZE];
};

struct kof_inflate {
	/*
	 * The sliding window, and the reason it is zeroed for every stream.
	 *
	 * A back reference names a distance behind the current position. One that
	 * reaches further back than the stream has written is corrupt, and it is
	 * refused as such - but if it were not, it would return whatever the window
	 * happened to hold, which is the tail of the LAST object decompressed. That
	 * turns a malformed archive into a way of reading bytes from an unrelated
	 * file into a produced object. The distance check is the real defence; the
	 * zeroing is there so that being wrong about the check is not a disclosure.
	 */
	uint8_t  win[KOF_INF_WINDOW];
	uint32_t wpos;      /* next write position within the window */
	uint32_t wpend;     /* bytes in the window not yet handed to the sink */

	const uint8_t *in;
	uint64_t in_len, in_pos;
	uint32_t bitbuf, bitcnt;

	uint64_t produced;

	struct kof_huff lit, dist;
};

/*
 * Decode a DEFLATE stream at `in`, handing output to `sink`.
 *
 * `st` is caller-owned and needs no initialisation: everything is set here. It is
 * 32KB and is meant to be allocated once per thread and reused, not per stream.
 *
 * `consumed` and `produced` are always set, whatever the status, because a caller
 * that stopped or was truncated still needs to know how far it got - the gzip
 * trailer is at the end of the compressed data, not at the end of the file, and
 * only the decoder knows where that is.
 */
int kof_inflate(struct kof_inflate *st, const uint8_t *in, uint64_t in_len,
		kof_inflate_sink sink, void *user,
		uint64_t *consumed, uint64_t *produced);

#endif /* KOFENG_INFLATE_H */
