/*
 * nrv2.c - NRV2B, NRV2D and NRV2E, decoded into a caller-owned buffer.
 *
 * The three are one algorithm with two substitutions, which is why this is one
 * function and not three. A stream is a sequence of items, each either a literal
 * byte or a match; the item type, the match distance and the match length are all
 * read from a bit stream that runs alongside whole bytes taken from the same input.
 * Where the variants differ is exactly two places, both marked below:
 *
 *   - how the distance prefix is accumulated (NRV2B takes two bits per round,
 *     NRV2D and NRV2E take three and subtract one in the middle)
 *   - how the match length is coded once the distance is known
 *
 * Three copies of the surrounding loop would be three places for a bounds check to
 * be fixed in two of them. Everything else - the bit reader, the end marker, every
 * bound - is written once.
 *
 *
 * THE BIT READER
 *
 * A 32 bit buffer refilled four bytes at a time, little endian, consumed from the
 * top. It carries a sentinel: on refill the loaded word is shifted left one and a 1
 * put in the bottom, so "the buffer holds nothing but the sentinel" is a test on the
 * value rather than a separate counter. That is UPX's stub arrangement and it has to
 * be reproduced exactly, because the refill boundary decides which bits belong to
 * which item - a decoder that refills one bit early decodes a different file.
 *
 *
 * WHAT HOSTILE INPUT CAN REACH, AND WHERE EACH IS STOPPED
 *
 * Every value here is attacker controlled and this format gives none of them a
 * bound of its own, so each is bounded against the buffers rather than against a
 * constant:
 *
 *   - the distance and length prefixes are accumulated as "v = v*2 + bit" with no
 *     terminator the format guarantees. Checked BEFORE each doubling against the
 *     value that would overflow, so no accumulator can wrap. A stream whose bits
 *     say "keep doubling" is refused, not run until it wraps to something small.
 *   - a match distance may name any byte already produced and nothing else. It is
 *     checked as "1 <= dist <= produced" against the OUTPUT SO FAR, not against the
 *     buffer size: a distance inside the allocation but ahead of what has been
 *     written would copy uninitialised memory into the object being scanned.
 *   - a match length is checked against the room left before the copy, so the copy
 *     itself needs no test per byte.
 *   - every bit and every byte read is refused past the end of the input, and that
 *     is truncation rather than corruption because a cut-short UPX section is what
 *     a damaged sample looks like.
 *
 * The copy is a byte at a time on purpose: a length greater than the distance is
 * how this format writes a run, and it reads bytes the same loop is writing.
 */

#include "nrv2.h"

#include <string.h>

/* ---- bits -------------------------------------------------------------------- */

struct nrv_in {
	const uint8_t *p;
	uint64_t n, at;
	uint32_t buf;

	/* The bit reader's shape, from the method's width suffix. See the note on
	 * enum kof_nrv2_bits: this is what _8 and _LE32 actually name. */
	uint32_t left;    /* bits still in buf, as a mask over all but the top one */
	unsigned top;     /* which bit of a freshly loaded word comes out first */
	unsigned width;   /* bytes per refill */
};

/*
 * One bit, taken from the top of the buffer. -1 when the input ran out.
 *
 * The buffer carries a sentinel: on refill the loaded word is shifted up one and a
 * 1 put in the bottom, so "nothing but the sentinel is left" is a test on the value
 * and needs no counter. That is UPX's stub arrangement and it has to be reproduced
 * exactly - the refill boundary decides which bits belong to which item, so a
 * decoder that refills a round early decodes a different file rather than failing.
 */
static int nrv_bit(struct nrv_in *s)
{
	uint32_t old = s->buf;

	s->buf = old << 1;
	if ((old & s->left) == 0) {
		unsigned i;

		if (s->at + s->width > s->n)
			return -1;
		old = 0;
		for (i = 0; i < s->width; i++)
			old |= (uint32_t)s->p[s->at + i] << (8u * i);
		s->at += s->width;
		s->buf = (old << 1) | 1u;
	}
	return (int)((old >> s->top) & 1u);
}

/* One whole byte, from the same input the bits come from. */
static int nrv_byte(struct nrv_in *s, uint32_t *out)
{
	if (s->at >= s->n)
		return 0;
	*out = s->p[s->at++];
	return 1;
}

/*
 * The accumulator every prefix in this format is built with.
 *
 * "v = v*2 + bit", with the overflow refused before it can happen rather than
 * detected after. UINT32_MAX/2 is the largest value that can be doubled and still
 * take a carry, so anything above it is a stream asking to wrap.
 */
static int nrv_shift_in(uint32_t *v, int bit)
{
	if (*v > (UINT32_MAX - 1u) / 2u)
		return 0;
	*v = *v * 2u + (uint32_t)bit;
	return 1;
}

/*
 * Arithmetic shift right by one, on a 32 bit two's complement pattern.
 *
 * Spelled out rather than written as ">> 1" on a signed value, which C leaves
 * implementation defined for negatives until C23. It matters more than that here:
 * the value being shifted IS a negative offset, and a logical shift turns a
 * distance of one into a distance of two billion - which the bounds check would
 * then refuse, so the failure would look like "this file is corrupt" on every
 * NRV2D and NRV2E stream rather than like a bug.
 */
static uint32_t nrv_sar1(uint32_t v)
{
	return (v >> 1) | (v & 0x80000000u);
}

/* The tail shared by every length code: bits in pairs until a set one, then +2. */
static int nrv_len_tail(struct nrv_in *s, uint32_t *len)
{
	int bit;

	do {
		if ((bit = nrv_bit(s)) < 0)
			return KOF_DEC_TRUNCATED;
		if (!nrv_shift_in(len, bit))
			return KOF_DEC_CORRUPT;
		if ((bit = nrv_bit(s)) < 0)
			return KOF_DEC_TRUNCATED;
	} while (bit == 0);
	if (*len > UINT32_MAX - 2u)
		return KOF_DEC_CORRUPT;
	*len += 2u;
	return KOF_DEC_OK;
}

/* ---- the decoder --------------------------------------------------------------- */

int kof_nrv2_decode(int variant, int bits, const uint8_t *in, uint64_t in_len,
		    uint8_t *out, uint64_t out_cap, uint64_t *produced)
{
	struct nrv_in s;
	uint64_t at = 0;
	/* One, because that is what UPX's stub starts with: the register holding the
	 * offset is initialised to -1. A stream that reuses the offset before setting
	 * one is malformed either way, but it is refused by the bounds check below
	 * rather than by a rule of our own that real files might trip on. */
	uint32_t last_dist = 1;
	int status = KOF_DEC_OK;

	if (bits != 8 && bits != 16 && bits != 32) {
		if (produced)
			*produced = 0;
		return KOF_DEC_CORRUPT;
	}
	s.p = in;
	s.n = in ? in_len : 0;
	s.at = 0;
	s.buf = 0;
	s.width = (unsigned)bits / 8u;
	s.top = (unsigned)bits - 1u;
	s.left = (1u << s.top) - 1u;

	if (!out || out_cap == 0) {
		if (produced)
			*produced = 0;
		return KOF_DEC_STOPPED;
	}

	for (;;) {
		uint32_t prefix = 1, dist, len, carry = 0;
		int bit;

		/* Literals, until the bit stream says otherwise. */
		for (;;) {
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			if (!bit)
				break;
			if (s.at >= s.n) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			if (at >= out_cap) {
				status = KOF_DEC_STOPPED;
				goto done;
			}
			out[at++] = s.p[s.at++];
		}

		/*
		 * The distance prefix. FIRST OF THE TWO DIFFERENCES.
		 *
		 * NRV2B reads a bit into the accumulator and a second bit that says
		 * whether to stop. NRV2D and NRV2E read a third bit each round and
		 * decrement in between, which is what lets them reach the same
		 * distances in fewer bits on the data UPX sees.
		 */
		for (;;) {
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			if (!nrv_shift_in(&prefix, bit)) {
				status = KOF_DEC_CORRUPT;
				goto done;
			}
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			if (bit)
				break;
			if (variant == KOF_NRV2B)
				continue;
			if (prefix == 0) {
				status = KOF_DEC_CORRUPT;
				goto done;
			}
			prefix--;
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			if (!nrv_shift_in(&prefix, bit)) {
				status = KOF_DEC_CORRUPT;
				goto done;
			}
		}

		/*
		 * A prefix below 3 means "the previous distance again"; at or above
		 * it, a whole byte follows and the two together are the distance.
		 *
		 * The stored form is the complement of the distance, and a complement
		 * of zero is the end of the stream - which is the only terminator this
		 * format has. Reaching the end of the input without seeing it is
		 * truncation, and that is the ordinary state of a damaged sample.
		 */
		if (prefix >= 3u) {
			uint32_t low, packed, neg;

			prefix -= 3u;
			if (prefix > 0x00ffffffu) {
				status = KOF_DEC_CORRUPT;
				goto done;
			}
			if (!nrv_byte(&s, &low)) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			packed = (prefix << 8) | low;

			/*
			 * Held as the NEGATIVE offset the format stores, not as a
			 * distance, until the very last step.
			 *
			 * Converting early would be wrong for two of the three
			 * variants: NRV2D and NRV2E shift this value right, and the
			 * shift has to keep the sign. Carrying it in the form the
			 * format uses means the shift is the format's shift.
			 */
			neg = ~packed;
			if (neg == 0)
				goto done;          /* the end marker: a clean stream */

			/* NRV2D and NRV2E carry the low bit out as the first bit of
			 * the length. SECOND OF THE TWO DIFFERENCES. */
			if (variant != KOF_NRV2B) {
				carry = neg & 1u;
				neg = nrv_sar1(neg);
			}
			/* A non-negative offset would be a forward reference, which
			 * this format cannot express and a hostile stream can ask
			 * for. */
			if ((neg & 0x80000000u) == 0) {
				status = KOF_DEC_CORRUPT;
				goto done;
			}
			last_dist = 0u - neg;
		} else if (variant != KOF_NRV2B) {
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			carry = (uint32_t)bit;
		}
		dist = last_dist;

		/* The length. Where the three part company for the last time. */
		if (variant == KOF_NRV2B) {
			len = 0;
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			len = (uint32_t)bit;
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			len = len * 2u + (uint32_t)bit;
			if (len == 0) {
				len = 1;
				status = nrv_len_tail(&s, &len);
				if (status != KOF_DEC_OK)
					goto done;
			}
			if (dist > 0xd00u)
				len++;
			len++;
		} else if (variant == KOF_NRV2D) {
			len = carry;
			if ((bit = nrv_bit(&s)) < 0) {
				status = KOF_DEC_TRUNCATED;
				goto done;
			}
			len = len * 2u + (uint32_t)bit;
			if (len == 0) {
				len = 1;
				status = nrv_len_tail(&s, &len);
				if (status != KOF_DEC_OK)
					goto done;
			}
			if (dist > 0x500u)
				len++;
			len++;
		} else {
			if (carry) {
				if ((bit = nrv_bit(&s)) < 0) {
					status = KOF_DEC_TRUNCATED;
					goto done;
				}
				len = (uint32_t)bit;
			} else {
				if ((bit = nrv_bit(&s)) < 0) {
					status = KOF_DEC_TRUNCATED;
					goto done;
				}
				if (bit) {
					if ((bit = nrv_bit(&s)) < 0) {
						status = KOF_DEC_TRUNCATED;
						goto done;
					}
					len = 2u + (uint32_t)bit;
				} else {
					len = 1;
					status = nrv_len_tail(&s, &len);
					if (status != KOF_DEC_OK)
						goto done;
				}
			}
			if (dist > 0x500u)
				len++;
			if (len > UINT32_MAX - 2u) {
				status = KOF_DEC_CORRUPT;
				goto done;
			}
			len += 2u;
		}

		/*
		 * The two checks that make the copy safe, and they check different
		 * things.
		 *
		 * The distance is checked against WHAT HAS BEEN PRODUCED, not against
		 * the size of the buffer: a distance that is inside the allocation but
		 * ahead of the write cursor would copy bytes this stream never wrote -
		 * whatever the allocator last left there - straight into an object
		 * about to be scanned. The length is checked against the room left, so
		 * that the copy below needs no test of its own.
		 */
		if (dist == 0 || (uint64_t)dist > at) {
			status = KOF_DEC_CORRUPT;
			goto done;
		}
		if ((uint64_t)len > out_cap - at) {
			status = KOF_DEC_STOPPED;
			goto done;
		}
		/*
		 * Non-overlapping matches are a straight copy.
		 *
		 * A match whose distance is at least its length reads bytes that are
		 * all already written and cannot reach the ones this copy is
		 * producing, so the two ranges are disjoint and memcpy applies -
		 * which on the data these formats carry is most matches. Where the
		 * distance is shorter the overlap is the POINT: the format writes a
		 * run that way, and it has to stay a byte at a time because each
		 * byte read is one this loop just wrote.
		 */
		if ((uint64_t)dist >= (uint64_t)len) {
			memcpy(out + at, out + at - dist, (size_t)len);
			at += len;
		} else {
			while (len--) {
				out[at] = out[at - dist];
				at++;
			}
		}
	}

done:
	if (produced)
		*produced = at;
	return status;
}
