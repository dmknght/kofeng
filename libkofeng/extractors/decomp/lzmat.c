/*
 * LZMAT. See lzmat.h for what it is and where the algorithm was read.
 *
 * THE NIBBLE STREAM IS THE WHOLE DIFFICULTY. Positions here are byte offsets
 * and `odd` says whether the next item begins four bits into that byte. A
 * reader that is odd takes the high nibble of its byte and the low nibble of
 * the next, so every read may touch one byte past its position - which is why
 * every bound below is written against `in_len` with that extra byte counted.
 */

#include <string.h>

#include "lzmat.h"

/*
 * EVERY READ CLAMPS, AND THAT IS NOT LAZINESS.
 *
 * A dword read by an odd reader touches five bytes, so a loop that guarded
 * itself with "five bytes left" stopped five bytes early - measured, 97781 of
 * 98304 bytes, and the tail of the stream never decoded. The end of the input
 * is not an error here: the last items are real and what lies past the end
 * reads as zero, exactly as it would in a buffer the packer had padded. The
 * stop condition that matters is the OUTPUT reaching the size the container
 * declared, which the caller passes as out_cap.
 */
static uint32_t lz_at(const uint8_t *in, uint64_t n, uint64_t at)
{
	return at < n ? in[at] : 0u;
}

static uint32_t lz_u8(const uint8_t *in, uint64_t n, uint64_t at, int odd)
{
	if (!odd)
		return lz_at(in, n, at);
	return ((lz_at(in, n, at) >> 4) | (lz_at(in, n, at + 1u) << 4)) & 0xffu;
}

static uint32_t lz_u16(const uint8_t *in, uint64_t n, uint64_t at, int odd)
{
	uint32_t v = lz_at(in, n, at) | (lz_at(in, n, at + 1u) << 8) |
		     (lz_at(in, n, at + 2u) << 16) |
		     (lz_at(in, n, at + 3u) << 24);

	if (odd)
		v >>= 4;
	return v & 0xffffu;
}

/* A nibble, which is the one read that MOVES the position. */
static uint32_t lz_u4(const uint8_t *in, uint64_t n, uint64_t *at, int *odd)
{
	uint32_t v = lz_at(in, n, *at);

	if (!*odd) {
		v &= 0xfu;
	} else {
		v >>= 4;
		(*at)++;
	}
	*odd = !*odd;
	return v;
}

enum kof_decomp_status kof_lzmat_decode(const uint8_t *in, uint64_t in_len,
					uint8_t *out, uint64_t out_cap,
					uint64_t *produced)
{
	uint64_t ip = 1, op = 1;
	int odd = 0;

	if (produced)
		*produced = 0;
	if (!in || !out || in_len < 2u || out_cap < 1u)
		return KOF_DEC_CORRUPT;

	/* The first byte is literal and is never part of the coding. */
	out[0] = in[0];

	/*
	 * Four bytes of slack, because the widest read is a dword and an odd
	 * reader takes a nibble past it. Checked once per item rather than per
	 * read: the loop below never advances more than that between checks.
	 */
	while (ip < in_len && op < out_cap) {
		uint32_t ctl = lz_u8(in, in_len, ip, odd);
		unsigned i;

		ip++;
		for (i = 0; i < 8u && ip < in_len && op < out_cap;
		     i++, ctl = (ctl << 1) & 0xffu) {
			uint32_t dist, len, tag;
			uint64_t from;

			if (!(ctl & 0x80u)) {
				/* A literal. */
				if (op >= out_cap)
					goto full;
				out[op++] = (uint8_t)lz_u8(in, in_len, ip, odd);
				ip++;
				continue;
			}

			tag = lz_u16(in, in_len, ip, odd);
			ip++;

			/*
			 * THE DISTANCE WIDENS WITH THE OUTPUT. Under 0x881
			 * bytes produced there are only two shapes; past it
			 * there are four, and the widest of them reaches a
			 * nibble further into the stream.
			 */
			if (op < 0x881u) {
				dist = tag >> 1;
				if (tag & 1u) {
					dist = (dist & 0x7ffu) + 0x81u;
					ip += (uint64_t)(odd != 0);
					odd = !odd;
				} else {
					dist = (dist & 0x7fu) + 1u;
				}
			} else {
				dist = tag >> 2;
				switch (tag & 3u) {
				case 0:
					dist = (dist & 0x3fu) + 1u;
					break;
				case 1:
					dist = (dist & 0x3ffu) + 0x41u;
					ip += (uint64_t)(odd != 0);
					odd = !odd;
					break;
				case 2:
					dist = dist + 0x441u;
					ip++;
					break;
				default:
					ip++;
					dist = dist + (lz_u4(in, in_len, &ip, &odd) << 14)
					     + 0x4441u;
					break;
				}
			}

			/* And the length, in the same widening shape. */
			len = lz_u4(in, in_len, &ip, &odd);
			if (len != 0xfu) {
				len += 3u;
			} else {
				len = lz_u8(in, in_len, ip, odd);
				ip++;
				if (len != 0xffu) {
					len += 0x12u;
				} else {
					len = lz_u16(in, in_len, ip, odd) + 0x111u;
					ip += 2u;
					if (len == 0x10110u) {
						/*
						 * THE LONG RUN, which is not a
						 * back reference at all: it
						 * copies dwords straight out of
						 * the stream. Its count is read
						 * from BEHIND the position, out
						 * of bytes already consumed,
						 * which is why this case is
						 * written separately rather
						 * than folded into the one
						 * above.
						 */
						uint32_t n;

						if (odd) {
							if (ip < 4u)
								goto cut;
							n = (lz_u8(in, in_len, ip - 4u, 0)
							     & 0xfcu) << 5;
							ip++;
							odd = 0;
						} else {
							if (ip < 5u)
								goto cut;
							n = (lz_u16(in, in_len, ip - 5u, 0)
							     & 0xfc0u) << 1;
						}
						n = (n + (ctl & 0x7fu) + 4u) << 1;
						if (n > out_cap / 4u ||
						    op + (uint64_t)n * 4u > out_cap)
							goto full;
						while (n--) {
							uint32_t q;

							for (q = 0; q < 4u; q++)
								out[op + q] =
								  (uint8_t)lz_at(
								    in, in_len,
								    ip + q);
							op += 4u;
							ip += 4u;
						}
						/*
						 * OUT OF THE EIGHT, NOT ON TO
						 * THE NEXT ONE. A long run
						 * ends the control byte it
						 * was under: the remaining
						 * bits are not items. Taking
						 * them as items desynchronises
						 * the stream - measured, a
						 * sample then decoded 5618 of
						 * 98304 bytes and asked for a
						 * distance of 252736 from an
						 * output that short.
						 */
						break;
					}
				}
			}

			/* A distance past what exists is not a stream this
			 * decoder can be reading. */
			if ((uint64_t)dist > op)
				goto bad;
			if (op + len > out_cap)
				goto full;
			from = op - dist;
			while (len--)
				out[op++] = out[from++];
		}
	}

	if (produced)
		*produced = op;
	return KOF_DEC_OK;
full:
	if (produced)
		*produced = op;
	return KOF_DEC_STOPPED;
cut:
	if (produced)
		*produced = op;
	return KOF_DEC_TRUNCATED;
bad:
	if (produced)
		*produced = op;
	return KOF_DEC_CORRUPT;
}
