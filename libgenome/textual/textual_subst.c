/*
 * textual_subst.c - a computed value written where it was computed: kgenome_textual_subst. See textual.h for what it promises.
 *
 * The one thing it knows about a language is how that language writes a literal (the row's `quote`, data: textual_lang.h). Everything else
 * about the ranges - that they are a right side, that the value is a constant - is the caller's reading, and nothing here checks it.
 */

#include <stdlib.h>

#include "textual_lang.h"

/* The byte `b` as the letter a row's pairs ("n", NL, "r", CR ...) give it, or 0 when there is none: the escape that reads back as `b`. */
static uint8_t letter_of(const char *pairs, uint8_t b)
{
	for (; pairs && pairs[0]; pairs += 2)
		if ((uint8_t)pairs[1] == b)
			return (uint8_t)pairs[0];
	return 0;
}

/* Is `b` in the row's set (NULL is the empty set; a NUL is never in one). */
static int in_set(uint8_t b, const char *set)
{
	return set && kof_byte_in_set(b, set);
}

/* Does `v` (n bytes) hold one of the sequences of `list` (NUL-separated, ended by an empty one). */
static int holds_seq(const uint8_t *v, uint32_t n, const char *list)
{
	for (; list && *list; list += strlen(list) + 1u) {
		uint32_t l = (uint32_t)strlen(list), i;

		for (i = 0; i + l <= n; i++)
			if (v[i] == (uint8_t)list[0] && memcmp(v + i, list, l) == 0)
				return 1;
	}
	return 0;
}

/* One byte at out[w] when there is an `out` (a NULL one only counts), and the new length. */
static uint32_t put(uint8_t *out, uint32_t w, uint8_t b)
{
	if (out)
		out[w] = b;
	return w + 1u;
}

/* The byte `c` in the spelling `form` names after a backslash: 'x' two hex digits, 'u' four, 'o' three octal digits, 'd' three decimal. */
static uint32_t put_code(uint8_t *out, uint32_t w, uint8_t form, uint8_t c)
{
	w = put(out, w, '\\');
	if (form == 'x' || form == 'u') {
		w = put(out, w, form);
		if (form == 'u') {
			w = put(out, w, '0');
			w = put(out, w, '0');
		}
		w = put(out, w, kof_hex_digit(c >> 4, 0));            /* lower case: core's one writer table */
		return put(out, w, kof_hex_digit(c & 15u, 0));
	}
	if (form == 'o') {
		w = put(out, w, (uint8_t)('0' + (c >> 6)));
		w = put(out, w, (uint8_t)('0' + ((c >> 3) & 7u)));
		return put(out, w, (uint8_t)('0' + (c & 7u)));
	}
	w = put(out, w, (uint8_t)('0' + c / 100u));
	w = put(out, w, (uint8_t)('0' + (c / 10u) % 10u));
	return put(out, w, (uint8_t)('0' + c % 10u));
}

uint64_t kgenome_textual_quote_max(const struct kgenome_textual_quote *r, uint32_t n)
{
	if (r->plain)
		return n;
	/* a byte is itself, or a backslash and one byte (a letter, an escaped quote), or - for the control bytes - the spelling `ctl` names */
	uint32_t per = r->ctl == 'u' ? 6u : r->ctl ? 4u : 2u;

	return (uint64_t)per * n + 2u;
}

uint32_t kgenome_textual_quote_write(const struct kgenome_textual_quote *r, const uint8_t *v, uint32_t n, uint8_t *out)
{
	uint32_t i, w = 0;

	if (r->plain) {                 /* no literal: the bytes themselves, when every one is of the set the text may hold, and there is one */
		for (i = 0; i < n; i++)
			if (!in_set(v[i], r->plain))
				return 0;
		if (!n)
			return 0;
		for (i = 0; i < n; i++)
			w = put(out, w, v[i]);
		return w;
	}
	for (i = 0; i < n; i++) {
		uint8_t b = v[i];

		if (in_set(b, r->refuse) || (r->refuse_ctl && ((b < 0x20u && b != '\t') || b == 0x7fu)))
			return 0;
	}
	if (holds_seq(v, n, r->seq))
		return 0;
	w = put(out, w, r->q);
	for (i = 0; i < n; i++) {
		uint8_t b = v[i], l;

		if (r->dbl && (b == r->q || in_set(b, r->twice))) {
			w = put(out, put(out, w, b), b);
		} else if (b == r->q || in_set(b, r->bs)) {
			w = put(out, put(out, w, '\\'), b);
		} else if ((l = letter_of(r->letters, b)) != 0) {
			w = put(out, put(out, w, '\\'), l);
		} else if (r->ctl && (b < 0x20u || b == 0x7fu)) {
			w = put_code(out, w, r->ctl, b);
		} else {
			w = put(out, w, b);
		}
	}
	return put(out, w, r->q);
}

int kgenome_textual_subst_can(uint32_t lang, const uint8_t *v, uint32_t n)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);

	return l && l->quote && (n == 0 || v) && kgenome_textual_quote_write(l->quote, v, n, NULL) != 0;
}

static int range_before(const void *x, const void *y)
{
	const struct kgenome_textual_subst *a = x, *b = y;

	return a->off < b->off ? -1 : a->off > b->off;
}

uint32_t kgenome_textual_subst_order(struct kgenome_textual_subst *s, uint32_t ns)
{
	uint32_t i, keep = 0;
	uint64_t last_end = 0;

	if (ns > 1u)
		qsort(s, ns, sizeof *s, range_before);
	for (i = 0; i < ns; i++) {
		if (keep && s[i].off < last_end)
			continue;
		s[keep++] = s[i];
		last_end = (uint64_t)s[i].off + s[i].len;
	}
	return keep;
}

int kgenome_textual_name_ok(const uint8_t *v, uint32_t n)
{
	uint32_t i;

	if (!n || !v || kof_is_digit(v[0]))
		return 0;
	for (i = 0; i < n; i++)
		if (!kgenome_textual_ident(v[i]) && v[i] != '\\')
			return 0;
	return 1;
}

uint64_t kgenome_textual_subst_cap(uint32_t lang, const uint8_t *in, uint32_t n, const struct kgenome_textual_subst *s, uint32_t ns)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);
	uint64_t cap = n;
	uint32_t i;

	(void)in;
	for (i = 0; i < ns; i++) {
		uint32_t q = s[i].bare ? s[i].n : l && l->quote ? kgenome_textual_quote_write(l->quote, s[i].value, s[i].n, NULL) : 0;

		cap += q ? q : l && l->quote ? kgenome_textual_quote_max(l->quote, s[i].n) : 0u;    /* a refused value makes the call answer 0 whatever the cap */
	}
	return cap;
}

uint32_t kgenome_textual_subst(uint32_t lang, const uint8_t *in, uint32_t n, const struct kgenome_textual_subst *s, uint32_t ns,
			       uint8_t *out, uint32_t cap)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);
	uint64_t w = 0;
	uint32_t i, at = 0;

	if (!l || !l->quote || !in || !out)
		return 0;
	for (i = 0; i < ns; i++) {
		uint32_t gap, q;

		/* `off > n` first: n - off wraps for it and the next test then passes (L8 of the lexer audit) */
		if (s[i].off < at || s[i].off > n || s[i].len > n - s[i].off || (s[i].n && !s[i].value))
			return 0;
		gap = s[i].off - at;
		if (s[i].bare && !kgenome_textual_name_ok(s[i].value, s[i].n))
			return 0;
		q = s[i].bare ? s[i].n : kgenome_textual_quote_write(l->quote, s[i].value, s[i].n, NULL);
		if (!q || w + gap + q > cap)    /* no q: a value this language cannot write as one literal (kgenome_textual_subst_can says so first) */
			return 0;
		memcpy(out + w, in + at, gap);
		w += gap;
		if (s[i].bare) {
			memcpy(out + w, s[i].value, s[i].n);
			w += s[i].n;
		} else {
			w += kgenome_textual_quote_write(l->quote, s[i].value, s[i].n, out + w);
		}
		at = s[i].off + s[i].len;
	}
	if (w + (n - at) > cap)
		return 0;
	memcpy(out + w, in + at, n - at);
	return (uint32_t)(w + (n - at));
}
