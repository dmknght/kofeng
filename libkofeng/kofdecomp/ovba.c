/*
 * ovba.c - MS-OVBA 2.4.1 decompression.
 *
 * A container is a signature byte followed by chunks. A chunk is a two byte header
 * and then either 4096 raw bytes or a sequence of tokens; a token sequence is a flag
 * byte whose eight bits say, for the eight tokens after it, whether each is one
 * literal byte or a two byte back reference.
 *
 * The whole of the difficulty is in the back reference, and it is that the SPLIT
 * between its offset field and its length field MOVES: it depends on how many bytes
 * the current chunk has produced so far. Early in a chunk few bits are needed to
 * name an offset, so more are left for the length; later the split shifts the other
 * way. A decoder that used a fixed split would decode the first tokens of every
 * chunk correctly and then drift, which is the failure worth knowing about because
 * the output stays plausible while being wrong.
 */

#include "ovba.h"

/* ---- the chunk header --------------------------------------------------------- */

/*
 * Bits 0..11 hold the chunk's total size less three, bits 12..14 a fixed signature,
 * bit 15 whether the chunk is compressed at all.
 */
#define HDR_SIZE_MASK  0x0fffu
#define HDR_SIG_SHIFT  12u
#define HDR_SIG_MASK   0x07u
#define HDR_SIG_VALUE  0x03u          /* 0b011 */
#define HDR_COMPRESSED 0x8000u

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

/*
 * How many bits of a CopyToken name the offset.
 *
 * The specification writes it as ceil(log2(difference)), floored at four. This is
 * that, counted rather than computed: the position of the highest set bit of
 * difference-1, which is the same number for every value the field can hold.
 */
static uint32_t offset_bits(uint32_t difference)
{
	uint32_t bits = 4u, span = 16u;

	while (span < difference && bits < 12u) {
		bits++;
		span <<= 1;
	}
	return bits;
}

/* ---- the sink ----------------------------------------------------------------- */

/*
 * A chunk's output, held until the chunk ends.
 *
 * It has to be held rather than passed straight through, because a back reference
 * reads what this chunk already produced. 4096 bytes is the whole window - see the
 * header for why nothing reaches further.
 */
struct out {
	uint8_t buf[KOF_OVBA_CHUNK];
	uint32_t n;
};

static int flush(struct out *o, kof_ovba_sink sink, void *user, uint64_t *produced)
{
	int cont = 1;

	if (o->n) {
		*produced += o->n;
		cont = sink(user, o->buf, o->n);
	}
	o->n = 0;
	return cont;
}

int kof_ovba_decode(const uint8_t *in, uint64_t in_len, kof_ovba_sink sink,
		    void *user, uint64_t *produced)
{
	struct out o;
	uint64_t at;
	int st = KOF_DEC_OK;

	*produced = 0;
	if (!in || !sink || in_len < 1u || in[0] != KOF_OVBA_SIGNATURE)
		return KOF_DEC_CORRUPT;

	at = 1u;
	while (at + 2u <= in_len) {
		uint16_t hdr = rd16(in + at);
		uint64_t end, q;
		uint32_t total = (uint32_t)(hdr & HDR_SIZE_MASK) + 3u;

		if (((hdr >> HDR_SIG_SHIFT) & HDR_SIG_MASK) != HDR_SIG_VALUE)
			return KOF_DEC_CORRUPT;

		end = at + total;
		if (end > in_len) {
			/* The last chunk claims more than the container holds.
			 * Decode what is there and say the input ran out. */
			end = in_len;
			st = KOF_DEC_TRUNCATED;
		}
		q = at + 2u;
		o.n = 0;

		if (!(hdr & HDR_COMPRESSED)) {
			/*
			 * A raw chunk is exactly 4096 bytes by the specification.
			 * What is honoured here is the chunk's own declared extent,
			 * because that is what says where the NEXT chunk begins - a
			 * file that disagrees with itself gets its own answer used
			 * consistently rather than a mixture of the two.
			 */
			uint32_t k = 0;

			while (q < end && k < KOF_OVBA_CHUNK)
				o.buf[k++] = in[q++];
			o.n = k;
			if (!flush(&o, sink, user, produced))
				return KOF_DEC_STOPPED;
			if (st == KOF_DEC_TRUNCATED)
				return st;
			at = end;
			continue;
		}

		while (q < end) {
			uint32_t flags = in[q++];
			uint32_t i;

			for (i = 0; i < 8u; i++) {
				uint32_t bits, length, offset;
				uint16_t token;
				uint32_t src;

				if (q >= end)
					break;

				if (!((flags >> i) & 1u)) {
					if (o.n >= KOF_OVBA_CHUNK) {
						/* More literals than a chunk can
						 * hold: the header lied about the
						 * size, and continuing would write
						 * past the window. */
						st = KOF_DEC_CORRUPT;
						goto done;
					}
					o.buf[o.n++] = in[q++];
					continue;
				}

				if (q + 2u > end) {
					st = KOF_DEC_TRUNCATED;
					goto done;
				}
				token = rd16(in + q);
				q += 2u;

				/*
				 * A copy at the very start of a chunk has nothing
				 * to copy from. Well formed input never writes
				 * one; refusing it here is what keeps the offset
				 * check below working on a positive quantity.
				 */
				if (o.n == 0) {
					st = KOF_DEC_CORRUPT;
					goto done;
				}

				bits = offset_bits(o.n);
				length = (uint32_t)(token & (0xffffu >> bits)) + 3u;
				offset = (uint32_t)((token & (uint16_t)~(0xffffu >> bits))
						    >> (16u - bits)) + 1u;

				/*
				 * The field is wide enough to name an offset up
				 * to twice what the chunk has produced, so this
				 * is where a hostile container tries to read the
				 * window left over from the chunk before it.
				 */
				if (offset > o.n) {
					st = KOF_DEC_CORRUPT;
					goto done;
				}
				if (o.n + length > KOF_OVBA_CHUNK) {
					st = KOF_DEC_CORRUPT;
					goto done;
				}

				/*
				 * Byte at a time, and not a block move: the
				 * ranges are allowed to overlap, and an overlap
				 * is how the coding expresses a run.
				 */
				src = o.n - offset;
				while (length--)
					o.buf[o.n++] = o.buf[src++];
			}
		}
done:
		if (!flush(&o, sink, user, produced))
			return KOF_DEC_STOPPED;
		if (st != KOF_DEC_OK)
			return st;
		at = end;
	}

	return st;
}

int kof_ovba_plausible(const uint8_t *in, uint64_t in_len)
{
	uint16_t hdr;

	if (!in || in_len < 3u || in[0] != KOF_OVBA_SIGNATURE)
		return 0;
	hdr = rd16(in + 1);
	return ((hdr >> HDR_SIG_SHIFT) & HDR_SIG_MASK) == HDR_SIG_VALUE;
}
