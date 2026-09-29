/*
 * aplib.c - the aPLib coding. See aplib.h for the format and where it is met.
 */

#include "aplib.h"

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
	if (s->at >= s->n) {
		s->eof = 1;
		return 0;
	}
	return s->in[s->at++];
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
			return 1;               /* the caller's ceiling */
		out[*have] = out[*have - dist];
		(*have)++;
	}
	return 1;
}

enum kof_decomp_status kof_aplib_decode(const uint8_t *in, uint64_t in_len,
				        uint8_t *out, uint64_t out_cap,
				        uint64_t *produced)
{
	struct ap s;
	uint64_t have = 0, r0 = 0;
	int lwm = 0, ended = 0;

	if (produced)
		*produced = 0;
	if (!in || !out || !out_cap || !in_len)
		return KOF_DEC_CORRUPT;

	s.in = in;
	s.n = in_len;
	s.at = 0;
	s.tag = 0;
	s.bits = 0;
	s.eof = 0;

	/* The first byte is a literal and no bit is read for it. */
	out[have++] = ap_byte(&s);

	while (!ended && have < out_cap && !s.eof) {
		if (!ap_bit(&s)) {
			out[have++] = ap_byte(&s);
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
			if (!ap_copy(out, &have, out_cap, dist, len))
				return KOF_DEC_CORRUPT;
			lwm = 1;
			continue;
		}
		if (!ap_bit(&s)) {
			uint32_t b = ap_byte(&s);
			uint64_t dist = b >> 1, len = 2u + (b & 1u);

			if (dist == 0) {
				ended = 1;      /* the end of the stream */
				break;
			}
			if (!ap_copy(out, &have, out_cap, dist, len))
				return KOF_DEC_CORRUPT;
			r0 = dist;
			lwm = 1;
			continue;
		}
		{
			uint64_t dist = 0;
			uint32_t i;

			for (i = 0; i < 4u; i++)
				dist = (dist << 1) + ap_bit(&s);
			if (dist) {
				if (dist > have)
					return KOF_DEC_CORRUPT;
				out[have] = out[have - dist];
				have++;
			} else {
				out[have++] = 0;
			}
			lwm = 0;
		}
	}

	if (produced)
		*produced = have;
	if (ended)
		return KOF_DEC_OK;
	if (have >= out_cap)
		return KOF_DEC_STOPPED;
	return KOF_DEC_TRUNCATED;
}
