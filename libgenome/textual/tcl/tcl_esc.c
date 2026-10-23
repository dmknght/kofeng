/*
 * tcl_esc.c - what a backslash in a tcl word reads as, and a double-quoted word with its spelled-out bytes written as
 * themselves, for the form.
 *
 * What tcl 8.6 reads after a backslash (checked one case each on this machine's tclsh 8.6.16 - the digit counts are the part
 * that differs between releases, and the one that matters here):
 *   - \a \b \f \n \r \t \v and \\ : one byte; \<line break> and the blanks after it : ONE space;
 *   - \xH, \xHH : one or two hex digits ("\x414" is "A" and "4": 8.5 took them all and 9 takes two); "\x" with none is "x";
 *   - \o to \ooo : octal, the third digit only when the first is 0-3 ("\777" is "?" and "7", "\18" is U+0001 and "8");
 *   - \uH to \uHHHH and \UH to \UHHHHHHHH : up to four and eight hex digits; a lone surrogate stays one, and a character past U+FFFF
 *     is U+FFFD (this build keeps three bytes of UTF-8 for a character: "\U0010FFFF" is U+FFFD, and "\U00110000" is U+FFFD and
 *     "0", the digit that would take the value past U+10FFFF being left alone);
 *   - anything else is the byte itself, the backslash gone ("\q" is "q", "\8" is "8", "\$" is "$").
 *
 * A BYTE IS WRITTEN AS ITSELF ONLY WHEN IT IS PRINTABLE ASCII AND NOT ONE OF  " \ $ [ ( ) { }  - the quote ends the word (and ")" the
 * index of an index span), the backslash begins an escape, "$" and "[" substitute, "(" after a variable name opens its index and
 * the braces open a ${name} -
 * so what is written can never begin a substitution or end the word, and the form of the form is itself. A word with a "["
 * in it is never given to this (the lexer does not flag it): what is inside the brackets is code, with braces in it where
 * nothing is an escape.
 *
 * FIVE NEIGHBOURS CAN STILL CHANGE WHAT A WRITTEN BYTE MEANS, and all are tracked:
 *   - "$a\x62" written as "$ab" is another variable, and "$\x41" as "$A" is one where "$" was a letter: after a "$" and the
 *     name bytes that follow it, no name byte (letters, digits, "_", ":") is written;
 *   - "\x4\x61" (not a program, but a text) written as "\x4a" would complete the escape: after a \x, \u or \U that was kept, no
 *     hex digit is written. A \x is written only when no hex digit follows it, so that 8.5's "all the digits" reads it as 8.6 does;
 *   - "\1\x31" written as "\11" is another byte: after a kept octal escape of fewer than three digits, no octal digit is written;
 *   - "\<newline>" eats the blanks after it, so after one no space is written until a byte that is not a blank.
 */

#include <kofcore.h>

#include "tcl.h"

/*
 * At most `max` hex digits from p[k..]: how many, and their value. A digit that would take the value past `top` is not read: "\U" is
 * read that way (tcl stops before the digit that makes the value larger than U+10FFFF, so "\U00110000" is a character and the digit 0).
 */
static uint32_t hex_run(const uint8_t *p, uint32_t n, uint32_t k, uint32_t max, uint32_t top, uint32_t *v)
{
	uint32_t d = 0;

	*v = 0;
	while (d < max && k + d < n && kof_hex_val(p[k + d]) >= 0 && ((*v << 4) | (uint32_t)kof_hex_val(p[k + d])) <= top)
		*v = (*v << 4) | (uint32_t)kof_hex_val(p[k + d++]);
	return d;
}

uint32_t kgenome_textual_tcl_esc_at(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *v, uint32_t *digits, uint32_t *max)
{
	uint8_t c;
	uint32_t d;

	if (i + 1u >= n)
		return 0;
	c = p[i + 1u];
	if (c == 'x' || c == 'u' || c == 'U') {
		*max = c == 'x' ? 2u : c == 'u' ? 4u : 8u;
		*digits = d = hex_run(p, n, i + 2u, *max, c == 'U' ? 0x10ffffu : 0xffffu, v);
		if (*v > 0xffffu)
			*v = 0xfffdu;
		return d ? 2u + d : 0u;
	}
	if ((uint8_t)(c - '0') < 8u) {
		*max = c <= '3' ? 3u : 2u;
		*v = 0;
		for (d = 0; d < *max && i + 1u + d < n && (uint8_t)(p[i + 1u + d] - '0') < 8u; d++)
			*v = *v * 8u + (uint32_t)(p[i + 1u + d] - '0');
		*digits = d;
		return 1u + d;
	}
	return 0;
}

/*
 * The escape at `i` for the form: tcl_esc_at above, which the value reads too. "\x41" is "A" in 8.6 whatever follows; where a hex
 * digit follows, 8.5 read it as part of the escape, so that one is kept. What a kept escape leaves: the hex guard after a \x, \u
 * or \U, the octal one after one of fewer than three digits, the blank one after a backslash and a line break.
 */
static uint32_t tcl_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	const uint8_t *s = u->s;
	uint32_t n = u->len, digits = 0, max, l, nl = 0;
	uint8_t c = s[i + 1u];

	h->v = 0;
	l = kgenome_textual_tcl_esc_at(s, n, i, &h->v, &digits, &max);
	h->write = (uint8_t)(l && !(c == 'x' && i + l < n && kof_hex_val(s[i + l]) >= 0));
	if (!l)
		nl = kgenome_textual_eol_at(s, n, i + 1u);
	h->guard = (uint8_t)((c == 'x' || c == 'u' || c == 'U' ? KGENOME_UNESC_HEX : 0u) |
			     ((uint8_t)(c - '0') < 8u && digits < 3u ? KGENOME_UNESC_OCT : 0u) | (nl ? KGENOME_UNESC_BLANK : 0u));
	return l ? l : 2u;
}

uint32_t kgenome_textual_tcl_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;

	(void)open_len;
	kgenome_textual_unesc_init(&u, s, len, tcl_at, NULL);
	kgenome_textual_unesc_ban(&u, "\"\\$[(){}");
	u.ws_ctl = 1u << '\t';
	u.name_after = '$';             /* "$a\x62" written as "$ab" is another variable */
	return kgenome_textual_unesc_run(&u, 0, out);
}
