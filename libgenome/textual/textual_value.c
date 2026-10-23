/*
 * textual_value.c - the value of a string literal: kgenome_textual_value, and the table-driven reader of
 * escapes that the languages' value hooks share.
 *
 * ONE READER, A ROW PER LANGUAGE. What differs between languages is data - which letters mean which byte,
 * how many hex digits "\x" takes (two in js and python, one to four in c#), whether an unknown escape keeps its
 * backslash (php, python) or loses it (js) or is an error (java, c#), whether "\<newline>" is a continuation
 * (js, python) - and a function per language would be the same loop written five times.
 *
 * WHAT IS NEVER GUESSED: an escape the table does not know and the language makes an error, or whose value
 * needs a table the lib does not have (python's "\N{name}"), makes the literal valueless - the caller keeps
 * the text as it was typed - and never a value with a hole in it.
 */

#include <kofcore.h>

#include "textual_lang.h"

uint32_t kgenome_textual_utf8_put(uint8_t *out, uint32_t x)
{
	uint8_t buf[8];
	uint32_t n = 1, mfb = 0x3fu, k;

	if (x < 0x80u) {
		out[0] = (uint8_t)x;
		return 1;
	}
	do {
		buf[8u - n++] = (uint8_t)(0x80u | (x & 0x3fu));
		x >>= 6;
		mfb >>= 1;
	} while (x > mfb);
	buf[8u - n] = (uint8_t)(((~mfb << 1) | x) & 0xffu);
	for (k = 0; k < n; k++)
		out[k] = buf[8u - n + k];
	return n;
}

/* A code point as utf-8. Answers how many bytes (1 to 4), 0 for a value past U+10FFFF or a surrogate. */
static uint32_t put_utf8(uint8_t *out, uint32_t cp)
{
	if ((cp >= 0xd800u && cp <= 0xdfffu) || cp > 0x10ffffu)
		return 0;
	return kgenome_textual_utf8_put(out, cp);
}

/* A character or byte `v` written as `chars` says: a character above 0x7f is utf-8, a byte is itself. */
static uint32_t put_value(uint8_t *out, uint32_t v, int chars)
{
	if (chars && v >= 0x80u)
		return put_utf8(out, v);
	out[0] = (uint8_t)v;
	return 1;
}

/*
 * Exactly or at most `max` hex digits at p (n bytes left), at least `min`. The count read, or 0 when fewer than min. A value
 * past U+10FFFF stays one past it however many digits follow (a zero-padded "\u{0000041}" is still 0x41), so that the count
 * of digits is not what a value is judged by.
 */
static uint32_t hex_run(const uint8_t *p, uint32_t n, uint32_t min, uint32_t max, uint32_t *v)
{
	uint32_t k = 0;

	*v = 0;
	while (k < max && k < n && kof_hex_val(p[k]) >= 0) {
		*v = *v * 16u + (uint32_t)kof_hex_val(p[k++]);
		if (*v > 0x10ffffu)
			*v = 0x110000u;
	}
	return k >= min ? k : 0;
}

uint32_t kgenome_textual_lf_value(const uint8_t *p, uint32_t n, uint8_t *out)
{
	uint32_t i, w = 0;

	for (i = 0; i < n; i++) {
		if (p[i] == '\r') {
			if (i + 1u < n && p[i + 1u] == '\n')
				i++;
			out[w++] = '\n';
		} else {
			out[w++] = p[i];
		}
	}
	return w;
}

uint32_t kgenome_textual_esc_scan(const struct kgenome_textual_esc *r, const uint8_t *p, uint32_t n, uint32_t i,
				  struct kgenome_textual_esc_at *h)
{
	uint8_t e = p[i + 1u];
	uint32_t k;

	h->v = 0;
	h->digits = 0;
	h->kind = 0;
	if (r->xmax && e == 'x' && (k = hex_run(p + i + 2u, n - i - 2u, r->xmin, r->xmax, &h->v)) != 0) {
		h->kind = KGENOME_ESC_AT_X;
		h->digits = k;
		return 2u + k;
	}
	if (r->octal && (uint8_t)(e - '0') < 8u) {
		uint32_t max = r->octal == 4u && e > '3' ? 2u : 3u;

		for (k = 0; k < max && i + 1u + k < n && (uint8_t)(p[i + 1u + k] - '0') < 8u; k++)
			h->v = h->v * 8u + (uint32_t)(p[i + 1u + k] - '0');
		h->kind = KGENOME_ESC_AT_OCT;
		h->digits = k;
		return 1u + k;
	}
	if (e == 'u' && r->ubrace && i + 2u < n && p[i + 2u] == '{') {
		k = hex_run(p + i + 3u, n - i - 3u, 1u, r->ubrace == KGENOME_ESC_ANY ? n : r->ubrace, &h->v);
		if (!k || i + 3u + k >= n || p[i + 3u + k] != '}')
			return 0;
		h->kind = KGENOME_ESC_AT_UBRACE;
		h->digits = k;
		return 4u + k;
	}
	if ((e == 'u' && r->u4) || (e == 'U' && r->u8)) {
		k = hex_run(p + i + 2u, n - i - 2u, e == 'u' ? 4u : 8u, e == 'u' ? 4u : 8u, &h->v);
		if (!k)
			return 0;
		h->kind = e == 'u' ? KGENOME_ESC_AT_U4 : KGENOME_ESC_AT_U8;
		h->digits = k;
		return 2u + k;
	}
	return 0;
}

int kgenome_textual_esc_value(const struct kgenome_textual_esc *r, const uint8_t *p, uint32_t n, uint8_t *out,
			      uint32_t *n_out)
{
	uint32_t i = 0, w = 0;

	while (i < n) {
		uint8_t c = p[i], e;
		uint8_t sv;
		struct kgenome_textual_esc_at h;
		uint32_t l;

		if (c != '\\' || i + 1u >= n) {
			out[w++] = c;
			i++;
			continue;
		}
		e = p[i + 1u];
		if (r->refuse && e && strchr(r->refuse, e))
			return 0;
		if (r->simple && kgenome_textual_pair_get(r->simple, e, &sv)) {
			out[w++] = sv;
			i += 2u;
			continue;
		}
		if (r->zero && e == '0' && !(i + 2u < n && kof_is_digit(p[i + 2u]))) {
			out[w++] = 0;
			i += 2u;
			continue;
		}
		if (r->cont && (e == '\n' || e == '\r')) {
			i += 2u;
			if (e == '\r' && i < n && p[i] == '\n')
				i++;
			continue;
		}
		l = kgenome_textual_esc_scan(r, p, n, i, &h);
		if (l && (h.kind == KGENOME_ESC_AT_X || h.kind == KGENOME_ESC_AT_OCT)) {
			w += put_value(out + w, h.kind == KGENOME_ESC_AT_OCT && r->octal != 5u ? h.v & 0xffu : h.v, r->chars);
			i += l;
			continue;
		}
		if (l) {
			uint32_t b, lo, used = l, v = h.v;

			/* a high surrogate and a low one that follows it are one character */
			if (h.kind != KGENOME_ESC_AT_UBRACE && r->pairs && v >= 0xd800u && v < 0xdc00u && i + used + 5u < n + 0u &&
			    p[i + used] == '\\' && p[i + used + 1u] == 'u' &&
			    hex_run(p + i + used + 2u, n - i - used - 2u, 4u, 4u, &lo) && lo >= 0xdc00u && lo < 0xe000u) {
				v = 0x10000u + ((v - 0xd800u) << 10) + (lo - 0xdc00u);
				used += 6u;
			}
			b = put_utf8(out + w, v);
			if (!b)
				return 0;
			w += b;
			i += used;
			continue;
		}
		if (r->unknown == KGENOME_ESC_REFUSE)
			return 0;
		if (r->unknown == KGENOME_ESC_KEEP)
			out[w++] = '\\';
		out[w++] = e;
		i += 2u;
	}
	*n_out = w;
	return 1;
}

int kgenome_textual_value_verbatim(const uint8_t *c, uint32_t cn, uint8_t *out, uint32_t *n)
{
	memmove(out, c, cn);
	*n = cn;
	return 1;
}

int kgenome_textual_brace_value(const uint8_t *c, uint32_t cn, uint8_t *out, uint32_t *n)
{
	uint32_t i = 0, w = 0;

	while (i < cn) {
		uint8_t b = c[i];

		if (b == '{' || b == '}') {
			if (i + 1u >= cn || c[i + 1u] != b)
				return 0;
			i++;
		}
		out[w++] = b;
		i++;
	}
	*n = w;
	return 1;
}

int kgenome_textual_undouble(const uint8_t *c, uint32_t cn, const char *set, int refuse, uint8_t *out, uint32_t *n)
{
	uint32_t i = 0, w = 0;

	while (i < cn) {
		uint8_t b = c[i++];

		if (kof_byte_in_set(b, set)) {
			if (i < cn && c[i] == b)
				i++;
			else if (refuse)
				return 0;
		}
		out[w++] = b;
	}
	*n = w;
	return 1;
}

enum kgenome_textual_status kgenome_textual_value(const struct kgenome_textual_value_req *rq,
						  struct kgenome_textual_value_res *res)
{
	const struct kgenome_textual_lang *lang = kgenome_textual_lang_find(rq->lang);
	uint32_t n = 0, content;

	res->n_out = 0;
	if (!lang)
		return KGENOME_TEXTUAL_NO_LANG;
	if (!lang->value || rq->open_len > rq->len || rq->close_len > rq->len - rq->open_len)
		return KGENOME_TEXTUAL_NO_VALUE;
	content = rq->len - rq->open_len - rq->close_len;
	if (rq->cap < content)
		return KGENOME_TEXTUAL_SMALL;
	if (!lang->value(rq->lit, rq->len, rq->open_len, rq->close_len, rq->flags, rq->out, &n))
		return KGENOME_TEXTUAL_NO_VALUE;
	res->n_out = n;
	return KGENOME_TEXTUAL_OK;
}
