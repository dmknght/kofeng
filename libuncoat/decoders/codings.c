/*
 * codings.c - the text codings behind kuncoat_transform: base64, hex, url, add,
 * caesar, reverse, escape, both directions. See codings.h, and transform.h for the
 * contract.
 */

#include <stddef.h>
#include <kofcore.h>            /* kof_hex_val, kof_b64_val: the digit tables */

#include "codings.h"
#include "../transform_private.h"

/* Upper case digits (kof_hex_digit, core's one writer table), for hex_write, url_write and esc_write alike. */
#define HEXD(v) kof_hex_digit((v), 1)

static int b64_skip(uint8_t c)
{
	return c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t';
}

static int hex_skip(uint8_t c)
{
	return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' || c == ',';
}

static kuncoat_st_t b64_read(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
		     uint8_t *out, uint64_t cap, uint64_t *w)
{
	int lax = (s->flags & KUNCOAT_F_LAX) != 0;
	uint32_t acc = 0, have = 0;
	uint64_t i;

	for (i = 0; i < n && *w < cap; i++) {
		int v = kof_b64_val(in[i]);

		if (v < 0) {
			/* Padding, and the wrapping a 76-column encoder puts in -
			 * both belong to the text and neither is data. */
			if (b64_skip(in[i]) || lax)
				continue;
			return KUNCOAT_CORRUPT;         /* not base64 at all */
		}
		acc = (acc << 6) | (uint32_t)v;
		have += 6u;
		if (have >= 8u) {
			have -= 8u;
			out[(*w)++] = (uint8_t)(acc >> have);
		}
	}
	/* The room filled: complete only if what is left is nothing but the text's
	 * own padding and wrapping. */
	for (; i < n; i++)
		if (!b64_skip(in[i]) && !(lax && kof_b64_val(in[i]) < 0))
			return KUNCOAT_OVER_BUDGET;
	return KUNCOAT_OK;
}

/*
 * kuncoat_ahx_decode (textcode.c) is the same digit-pairing walk under the PDF
 * ASCIIHexDecode policy, and the two are NOT one function with a flag, because
 * they differ in five places that decide the status and the byte count:
 *   - separators: here space, CR, LF, tab, ':' and ','; there also FF and NUL,
 *     and neither ':' nor ',' (so "de:ad" is data here and CORRUPT there);
 *   - terminator: there '>' ends the input, here it is not a digit and so is
 *     CORRUPT;
 *   - a last lone digit: there paired with a zero (the format says so), here
 *     TRUNCATED and the digit dropped;
 *   - a full output: here the walk stops BEFORE reading the next byte whether or
 *     not it is mid-pair, there only when a pair completes, so the byte count
 *     and the status differ at the cap;
 *   - on CORRUPT: there the bytes so far are reported through `produced`.
 * Merging would need a policy argument carrying all five, which is longer than
 * either function and puts a branch on every digit.
 */
static kuncoat_st_t hex_read(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap,
		     uint64_t *w, int strict)
{
	uint32_t acc = 0, have = 0;
	uint64_t i;

	for (i = 0; i < n && *w < cap; i++) {
		int v = kof_hex_val(in[i]);

		if (v < 0) {
			if (!strict && hex_skip(in[i]))
				continue;
			return KUNCOAT_CORRUPT;
		}
		acc = (acc << 4) | (uint32_t)v;
		have += 4u;
		if (have >= 8u) {
			have -= 8u;
			out[(*w)++] = (uint8_t)acc;
		}
	}
	if (have)
		return KUNCOAT_TRUNCATED;       /* an odd digit is not a byte string */
	for (; i < n; i++)
		if (strict || !hex_skip(in[i]))
			return KUNCOAT_OVER_BUDGET;
	return KUNCOAT_OK;
}

/*
 * `<s>xHH` repeated, the whole input and nothing else. The separator is the caller's (a backslash
 * for a C or Python literal, a slash for what one dropper writes), and it is one byte for the whole
 * run: an escape with another separator in the middle is not this text.
 *
 * Not hex_read with a prefix: that one skips what is between the digits, and the point here is the
 * reverse - a byte that is not part of an escape means the text is not this coding, so it is
 * CORRUPT, which a reader that was told the run is escapes (the normaliser, after it has found the
 * run) uses to refuse a run it found wrongly. The digits are read in either case; 'x' is the one
 * lower case letter, as in C.
 */
static int esc_sep(const struct kuncoat_step *s)
{
	uint32_t c = s->k32 ? s->k32 : (uint32_t)'\\';

	if (c > 0xffu || c == 'x' || kof_hex_val((uint8_t)c) >= 0 ||
	    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
		return -1;
	return (int)c;
}

static kuncoat_st_t esc_read(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			     uint8_t *out, uint64_t cap, uint64_t *w)
{
	int sep = esc_sep(s);
	uint64_t i = 0;

	if (sep < 0)
		return KUNCOAT_BAD_ARG;
	while (i < n && *w < cap) {
		int hi, lo;

		if (in[i] != (uint8_t)sep)
			return KUNCOAT_CORRUPT;
		if (n - i < 4u)
			return KUNCOAT_TRUNCATED;       /* an escape cut short */
		hi = kof_hex_val(in[i + 2u]);
		lo = kof_hex_val(in[i + 3u]);
		if (in[i + 1u] != 'x' || hi < 0 || lo < 0)
			return KUNCOAT_CORRUPT;
		out[(*w)++] = (uint8_t)(hi << 4 | lo);
		i += 4u;
	}
	return i < n ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

static kuncoat_st_t esc_write(const struct kuncoat_step *s, const uint8_t *p, uint64_t len,
			      uint8_t *out, uint64_t cap, uint64_t *w)
{
	int sep = esc_sep(s);
	uint64_t i;

	if (sep < 0)
		return KUNCOAT_BAD_ARG;
	for (i = 0; i < len && *w + 4u <= cap; i++) {
		out[(*w)++] = (uint8_t)sep;
		out[(*w)++] = 'x';
		out[(*w)++] = HEXD(p[i] >> 4);
		out[(*w)++] = HEXD(p[i] & 15u);
	}
	return i < len ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

static kuncoat_st_t url_read(const struct kuncoat_step *s, const uint8_t *p, uint64_t len,
		     uint8_t *out, uint64_t cap, uint64_t *w)
{
	int lax = (s->flags & KUNCOAT_F_LAX) != 0;
	uint64_t i, esc = 0;

	for (i = 0; i < len && *w < cap; i++) {
		if (p[i] == '%') {
			int b = len - i < 3u ? -1 : kof_hex_byte(p + i + 1u);

			if (b >= 0) {
				out[(*w)++] = (uint8_t)b;
				i += 2u;
				esc++;
				continue;
			}
			/* A `%` that is not an escape means the text was never
			 * written this way - a printf format, a literal per cent -
			 * unless the caller reads text that may carry one. */
			if (!lax)
				return len - i < 3u ? KUNCOAT_TRUNCATED   /* a cut escape */
						    : KUNCOAT_CORRUPT;
		}
		out[(*w)++] = p[i] == '+' && !(s->flags & KUNCOAT_F_RAW) ? (uint8_t)' ' : p[i];
	}
	/* Text carrying no escape at all is not encoded text. */
	if (!esc && !lax)
		return KUNCOAT_CORRUPT;
	return i < len ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

static kuncoat_st_t add_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
		    uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint8_t k = (uint8_t)s->k32;
	uint64_t i;

	for (i = 0; i < n && *w < cap; i++)
		out[(*w)++] = s->dir == KUNCOAT_ENCODE ? (uint8_t)(in[i] - k)
						       : (uint8_t)(in[i] + k);
	return kuncoat_room_end(*w, n);
}

static kuncoat_st_t caesar(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
		   uint8_t *out, uint64_t cap, uint64_t *w)
{
	/* The key is how far the text was shifted, so decoding shifts BACK by it - a
	 * reader who knows a sample was rot-7 types 7, not 19. Nothing but letters
	 * moves, which is what makes a shifted command still look like a command. */
	uint32_t key = s->k32 % 26u;
	uint32_t by;
	uint64_t i;

	by = s->dir == KUNCOAT_ENCODE ? key : 26u - key;
	for (i = 0; i < n && *w < cap; i++) {
		uint8_t c = in[i];

		if (c >= 'a' && c <= 'z')
			c = (uint8_t)('a' + (c - 'a' + by) % 26u);
		else if (c >= 'A' && c <= 'Z')
			c = (uint8_t)('A' + (c - 'A' + by) % 26u);
		out[(*w)++] = c;
	}
	return kuncoat_room_end(*w, n);
}

static kuncoat_st_t reverse(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap,
		    uint64_t *w)
{
	uint64_t i;

	for (i = 0; i < n && *w < cap; i++)
		out[(*w)++] = in[n - 1u - i];
	return kuncoat_room_end(*w, n);
}

static kuncoat_st_t b64_write(const uint8_t *p, uint64_t len, uint8_t *out, uint64_t cap,
		      uint64_t *w)
{
	static const char b64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint64_t i;

	for (i = 0; i < len && *w + 4u <= cap; i += 3u) {
		uint64_t n = len - i < 3u ? len - i : 3u;
		uint32_t acc = (uint32_t)p[i] << 16;

		if (n > 1u)
			acc |= (uint32_t)p[i + 1u] << 8;
		if (n > 2u)
			acc |= p[i + 2u];
		out[(*w)++] = (uint8_t)b64[(acc >> 18) & 63u];
		out[(*w)++] = (uint8_t)b64[(acc >> 12) & 63u];
		/* Padded, because a decoder that counts on it is the common case and
		 * one that ignores it reads this anyway. */
		out[(*w)++] = n > 1u ? (uint8_t)b64[(acc >> 6) & 63u] : (uint8_t)'=';
		out[(*w)++] = n > 2u ? (uint8_t)b64[acc & 63u] : (uint8_t)'=';
	}
	return i < len ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

static kuncoat_st_t hex_write(const uint8_t *p, uint64_t len, uint8_t *out, uint64_t cap,
		      uint64_t *w)
{
	uint64_t i;

	/* UPPER CASE AND NO SEPARATOR, the form a pattern is written in. */
	for (i = 0; i < len && *w + 2u <= cap; i++) {
		out[(*w)++] = HEXD(p[i] >> 4);
		out[(*w)++] = HEXD(p[i] & 15u);
	}
	return i < len ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

static kuncoat_st_t url_write(const uint8_t *p, uint64_t len, uint8_t *out, uint64_t cap,
		      uint64_t *w)
{
	uint64_t i;

	/* RFC 3986's unreserved set stays and everything else is escaped - `+` among
	 * it, so that a `+` a reader typed comes back a `+` and not the space the
	 * reading pass turns one into. Upper case digits. */
	for (i = 0; i < len; i++) {
		uint8_t ch = p[i];

		if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		    (ch >= '0' && ch <= '9') ||
		    ch == '-' || ch == '_' || ch == '.' || ch == '~') {
			if (*w + 1u > cap)
				break;
			out[(*w)++] = ch;
			continue;
		}
		if (*w + 3u > cap)
			break;
		out[(*w)++] = '%';
		out[(*w)++] = HEXD(ch >> 4);
		out[(*w)++] = HEXD(ch & 15u);
	}
	return i < len ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

static enum kuncoat_status coding_run(const struct kuncoat_step *s,
				      const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap, uint64_t *w)
{
	switch (s->algo) {
	case KUNCOAT_ALGO_B64:
		return s->dir == KUNCOAT_ENCODE ? b64_write(in, n, out, cap, w)
						: b64_read(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_HEX:
		return s->dir == KUNCOAT_ENCODE ? hex_write(in, n, out, cap, w)
						: hex_read(in, n, out, cap, w, (s->flags & KUNCOAT_F_STRICT) != 0);
	case KUNCOAT_ALGO_URL:
		return s->dir == KUNCOAT_ENCODE ? url_write(in, n, out, cap, w)
						: url_read(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_ADD:
		return add_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_CAESAR:
		return caesar(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_REVERSE:
		return reverse(in, n, out, cap, w);
	case KUNCOAT_ALGO_ESCAPE:
		return s->dir == KUNCOAT_ENCODE ? esc_write(s, in, n, out, cap, w)
						: esc_read(s, in, n, out, cap, w);
	default:
		return KUNCOAT_UNSUPPORTED;
	}
}

/* Appends at out[*w]; see kuncoat_cipher for why the routines get the tail. */
enum kuncoat_status kuncoat_coding(const struct kuncoat_step *s,
				   const uint8_t *in, uint64_t n,
				   uint8_t *out, uint64_t cap, uint64_t *w)
{
	const uint64_t w0 = *w;
	uint64_t mine = 0;
	enum kuncoat_status r = coding_run(s, in, n, out + w0, cap > w0 ? cap - w0 : 0, &mine);

	*w = w0 + mine;
	return r;
}
