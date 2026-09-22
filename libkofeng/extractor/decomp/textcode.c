/*
 * textcode.c - see textcode.h.
 */

#include "textcode.h"

/* One flush's worth for the streaming coding. Small on purpose: the receiver
 * charges a budget per call, so a huge buffer would let a bomb produce a lot
 * between two chances to refuse. */
#define RLE_CHUNK 512u

enum kof_decomp_status kof_a85_decode(const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap,
				      uint64_t *produced)
{
	uint64_t i, w = 0;
	uint32_t acc = 0, have = 0;

	*produced = 0;
	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
		    c == '\f' || c == 0)
			continue;
		if (c == '~')
			break;                 /* "~>", and only the ~ matters */
		if (c == 'z' && have == 0) {
			if (w + 4u > cap)
				break;
			out[w] = out[w + 1u] = out[w + 2u] = out[w + 3u] = 0;
			w += 4u;
			continue;
		}
		if (c < '!' || c > 'u') {
			*produced = w;
			return KOF_DEC_CORRUPT;
		}
		/*
		 * acc * 85 + digit, and the overflow test is the format's own
		 * bound rather than a guess: a group of five encodes a 32-bit
		 * value, so a fifth digit that would carry past 2^32 is a group
		 * that cannot have come from four bytes.
		 */
		if (acc > (UINT32_MAX - (uint32_t)(c - '!')) / 85u) {
			*produced = w;
			return KOF_DEC_CORRUPT;
		}
		acc = acc * 85u + (uint32_t)(c - '!');
		if (++have < 5u)
			continue;
		if (w + 4u > cap)
			break;
		out[w++] = (uint8_t)(acc >> 24);
		out[w++] = (uint8_t)(acc >> 16);
		out[w++] = (uint8_t)(acc >> 8);
		out[w++] = (uint8_t)acc;
		acc = 0;
		have = 0;
	}
	/*
	 * A PARTIAL GROUP IS THE ORDINARY ENDING, not damage: the encoding pads
	 * the last group with the highest digit and the decoder drops the bytes
	 * that padding invented. One character alone cannot be a group - four
	 * bytes need at least two - and that IS malformed.
	 */
	if (have == 1u) {
		*produced = w;
		return KOF_DEC_CORRUPT;
	}
	if (have > 1u) {
		uint32_t j;

		for (j = have; j < 5u; j++)
			acc = acc * 85u + 84u;      /* 'u', the pad digit */
		for (j = 0; j + 1u < have && w < cap; j++)
			out[w++] = (uint8_t)(acc >> (24u - 8u * j));
	}
	*produced = w;
	return KOF_DEC_OK;
}

/* A hex digit's value, or -1. Written out rather than reached for isxdigit,
 * which is locale-sensitive and takes an int. */
static int hexval(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

enum kof_decomp_status kof_ahx_decode(const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap,
				      uint64_t *produced)
{
	uint64_t i, w = 0;
	int hi = -1;

	*produced = 0;
	for (i = 0; i < n; i++) {
		uint8_t c = in[i];
		int v;

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
		    c == '\f' || c == 0)
			continue;
		if (c == '>')
			break;
		v = hexval(c);
		if (v < 0) {
			*produced = w;
			return KOF_DEC_CORRUPT;
		}
		if (hi < 0) {
			hi = v;
			continue;
		}
		if (w >= cap)
			break;
		out[w++] = (uint8_t)((hi << 4) | v);
		hi = -1;
	}
	/*
	 * A LAST LONE DIGIT IS PAIRED WITH A ZERO, and that is the format
	 * speaking rather than this code being lenient: 7.4.2 says so in as
	 * many words. Treating it as damage would reject files that are correct.
	 */
	if (hi >= 0 && w < cap)
		out[w++] = (uint8_t)(hi << 4);
	*produced = w;
	return KOF_DEC_OK;
}

enum kof_decomp_status kof_rle_decode(const uint8_t *in, uint64_t n,
				      kof_textcode_sink sink, void *user,
				      uint64_t *produced)
{
	uint8_t buf[RLE_CHUNK];
	uint32_t held = 0;
	uint64_t at = 0, out = 0;
	int ended = 0;

	*produced = 0;
	while (at < n) {
		uint32_t len = in[at++];
		uint32_t k;

		if (len == 128u) {
			ended = 1;
			break;
		}
		if (len < 128u) {
			/*
			 * n+1 literal bytes. Truncated input is not damage -
			 * the bytes before it are real - so what is there is
			 * copied and the walk ends.
			 */
			uint32_t want = len + 1u;
			uint32_t have = (uint64_t)want <= n - at
				      ? want : (uint32_t)(n - at);

			for (k = 0; k < have; k++) {
				buf[held++] = in[at + k];
				if (held == RLE_CHUNK) {
					if (!sink(user, buf, held)) {
						*produced = out + held;
						return KOF_DEC_STOPPED;
					}
					out += held;
					held = 0;
				}
			}
			at += have;
			if (have < want)
				break;          /* input ended mid-literal */
			continue;
		}
		/* 129..255: the next byte repeats 257-len times, so 2..128. */
		if (at >= n)
			break;                  /* the byte to repeat is missing */
		{
			uint32_t run = 257u - len;
			uint8_t c = in[at++];

			for (k = 0; k < run; k++) {
				buf[held++] = c;
				if (held == RLE_CHUNK) {
					if (!sink(user, buf, held)) {
						*produced = out + held;
						return KOF_DEC_STOPPED;
					}
					out += held;
					held = 0;
				}
			}
		}
	}
	if (held) {
		if (!sink(user, buf, held)) {
			*produced = out + held;
			return KOF_DEC_STOPPED;
		}
		out += held;
	}
	*produced = out;
	/*
	 * No 128 means the data ran out before the end marker. Truncated rather
	 * than corrupt, for the same reason a half-copied literal is: every byte
	 * decoded before the end is output the scan wants.
	 */
	return ended ? KOF_DEC_OK : KOF_DEC_TRUNCATED;
}
