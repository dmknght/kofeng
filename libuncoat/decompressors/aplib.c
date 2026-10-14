/*
 * aplib.c - the aPLib coding. See aplib.h for the format and where it is met.
 */

#include "aplib.h"
#include "inbyte.h"

/*
 * The bit reader and the input cursor share one struct because every read of
 * either can run off the end, and a decoder that carries "did I run out" in two
 * places gets it wrong in one of them.
 */
struct ap {
	const uint8_t *in;
	uint64_t       n, at;
	uint32_t       tag;
	uint32_t       bits;    /* bits left in tag */
	int            eof;     /* the input ended; every further read is 0 */
};

static uint8_t ap_byte(struct ap *s)
{
	return kuncoat_in_byte(s->in, s->n, &s->at, &s->eof);
}

/*
 * THE BIT READER IS SPLIT THE WAY inflate.c SPLITS ITS REFILL, and for the
 * same measured reason.
 *
 * A bit read is a shift and a test nine times out of ten and a byte fetch the
 * tenth, so writing it as one function makes the common case pay for the rare
 * one: the compiler will not inline a body that contains the fetch, and every
 * bit then costs a call. Measured on a Themida sample - 5.1 MB of aPLib output
 * - the one-function form spent 163 million instructions, 32 a byte, with
 * ap_gamma alone accounting for 71,787,365 of them as an out-of-line call.
 *
 * So the test is inline and the refill is not, and ap_gamma becomes small
 * enough to inline in turn.
 */
static void ap_fill(struct ap *s)
{
	s->tag = ap_byte(s);
	s->bits = 8;
}

static inline uint32_t ap_bit(struct ap *s)
{
	uint32_t b;

	if (s->bits == 0)
		ap_fill(s);
	s->bits--;
	b = (s->tag >> 7) & 1u;
	s->tag = (s->tag << 1) & 0xffu;
	return b;
}

/*
 * The gamma code: pairs of bits, a value bit then a continue bit.
 *
 * BOUNDED, and the bound is not decoration. Every bit of a truncated stream
 * reads as zero, and a continue bit that is always zero would end the loop -
 * but a corrupt stream can hold a run of ones, and without a ceiling this
 * shifts until the result wraps and the caller then indexes with it. 32
 * iterations is past anything a real offset or length needs, since the value is
 * used against a buffer the caller sized.
 */
#define AP_GAMMA_MAX 32u

static inline uint64_t ap_gamma(struct ap *s)
{
	uint64_t v = 1;
	uint32_t i;

	for (i = 0; i < AP_GAMMA_MAX; i++) {
		v = (v << 1) + ap_bit(s);
		if (!ap_bit(s))
			return v;
		if (s->eof)
			return v;
	}
	s->eof = 1;
	return v;
}

/*
 * Copy `len` bytes from `dist` back in the output, one at a time.
 *
 * ONE AT A TIME AND NOT memcpy, because aPLib uses overlapping copies as a run
 * encoder: a distance of 1 and a length of 200 means "repeat the last byte 200
 * times", and memcpy of an overlapping range is undefined. The same reason
 * inflate.c gives where it does this.
 */
static int ap_copy(uint8_t *out, uint64_t *have, uint64_t cap,
		   uint64_t dist, uint64_t len)
{
	uint64_t i;

	if (dist == 0 || dist > *have)
		return 0;                       /* reaches before the output */
	for (i = 0; i < len; i++) {
		if (*have >= cap)
			return 2;               /* the caller's ceiling, with the match unfinished */
		out[*have] = out[*have - dist];
		(*have)++;
	}
	return 1;
}

/* Is what follows the end marker (`110` and a zero byte)? Asked when the output is
 * full, to tell a stream that ends exactly there from one that has more to say. */
static int ap_at_end(struct ap *s)
{
	if (!ap_bit(s) || !ap_bit(s) || ap_bit(s))
		return 0;
	return (ap_byte(s) >> 1) == 0;
}

/*
 * NOTHING IS WRITTEN FROM BYTES THAT ARE NOT THERE. Past the end the reader gives
 * zeros and sets `eof`, so every item is decoded and then `eof` is looked at BEFORE
 * the item is written: a literal, a length or a distance that came from the fill
 * is dropped and the stream is TRUNCATED. A complete stream never reads past its
 * end (the marker is inside it), so this loses nothing a stream said.
 */
enum kuncoat_status kuncoat_aplib_decode(const uint8_t *in, uint64_t in_len,
				        uint8_t *out, uint64_t out_cap,
				        uint64_t *produced)
{
	struct ap s;
	uint64_t have = 0, r0 = 0;
	int lwm = 0, ended = 0, cut = 0, cp;
	enum kuncoat_status status = KUNCOAT_OK;

	if (produced)
		*produced = 0;
	if ((!in && in_len) || (!out && out_cap))
		return KUNCOAT_BAD_ARG;
	if (!in_len || !out_cap)
		return KUNCOAT_CORRUPT;         /* no stream, or no room for its first byte */

	s.in = in;
	s.n = in_len;
	s.at = 0;
	s.tag = 0;
	s.bits = 0;
	s.eof = 0;

	/* The first byte is a literal and no bit is read for it. */
	out[have++] = ap_byte(&s);

	while (!ended && have < out_cap && !s.eof) {
		uint32_t b1 = ap_bit(&s);

		if (s.eof)
			break;
		if (!b1) {
			uint8_t lit = ap_byte(&s);

			if (s.eof)
				break;
			out[have++] = lit;
			lwm = 0;
			continue;
		}
		if (!ap_bit(&s)) {
			uint64_t dist = ap_gamma(&s), len;

			if (!lwm && dist == 2u) {
				/* The previous offset again. */
				dist = r0;
				len = ap_gamma(&s);
			} else {
				dist = lwm ? dist - 2u : dist - 3u;
				dist = (dist << 8) + ap_byte(&s);
				len = ap_gamma(&s);
				/*
				 * The length adjustments, which are the
				 * encoder's way of spending fewer bits on the
				 * distances it uses most. Order matters: the
				 * 1280 test is an `if` after the 32000 one and
				 * the 128 test is its `else`, so a distance
				 * over 32000 gains two and never three.
				 */
				if (dist >= 32000u)
					len++;
				if (dist >= 1280u)
					len++;
				else if (dist < 128u)
					len += 2u;
				r0 = dist;
			}
			if (s.eof)
				break;
			cp = ap_copy(out, &have, out_cap, dist, len);
			if (!cp) {
				status = KUNCOAT_CORRUPT;
				goto done;
			}
			cut |= cp == 2;
			lwm = 1;
			continue;
		}
		if (!ap_bit(&s)) {
			uint32_t b = ap_byte(&s);
			uint64_t dist = b >> 1, len = 2u + (b & 1u);

			if (s.eof)
				break;
			if (dist == 0) {
				ended = 1;      /* the end of the stream */
				break;
			}
			cp = ap_copy(out, &have, out_cap, dist, len);
			if (!cp) {
				status = KUNCOAT_CORRUPT;
				goto done;
			}
			cut |= cp == 2;
			r0 = dist;
			lwm = 1;
			continue;
		}
		{
			uint64_t dist = 0;
			uint32_t i;

			for (i = 0; i < 4u; i++)
				dist = (dist << 1) + ap_bit(&s);
			if (s.eof)
				break;
			if (dist) {
				if (dist > have) {
					status = KUNCOAT_CORRUPT;
					goto done;
				}
				out[have] = out[have - dist];
				have++;
			} else {
				out[have++] = 0;
			}
			lwm = 0;
		}
	}

	if (ended)
		status = KUNCOAT_OK;
	else if (s.eof)
		status = KUNCOAT_TRUNCATED;
	else if (cut)
		status = KUNCOAT_STOPPED;       /* the room ended inside a match */
	else if (have >= out_cap)       /* full: the end of the stream, or more of it? */
		status = ap_at_end(&s) ? KUNCOAT_OK : s.eof ? KUNCOAT_TRUNCATED : KUNCOAT_STOPPED;
done:
	if (produced)
		*produced = have;
	return status;
}
