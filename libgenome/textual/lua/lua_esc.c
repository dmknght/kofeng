/*
 * lua_esc.c - what a backslash in a lua string reads as, and a short string with its spelled-out bytes written as
 * themselves, for the form.
 *
 * What lua 5.4 reads after a backslash in a '...' or "..." string (llex.c read_string; one case each is in
 * tests/lib/genome/textual_lua.c, and the value of every closed string of 2000 generated programs and of all 1070 .lua files of the
 * machine it was written on is the one `load` gives under lua 5.4.7):
 *   - \a \b \f \n \r \t \v \\ \" \' : one byte;
 *   - \<line break> : a "\n", whichever of the four breaks it is (a CR LF or LF CR pair is ONE break);
 *   - \z : skips the white space that follows, line breaks included;
 *   - \xHH : EXACTLY two hex digits;
 *   - \ddd : one to three DECIMAL digits, at most 255 ("\256" is an error, "\0123" is "\012" and the text 3);
 *   - \u{H...} : one or more hex digits up to 0x7FFFFFFF, written as utf-8 (the long form up to six bytes), no check for
 *     surrogates;
 *   - anything else is an error ("invalid escape sequence"), which 5.1 does not have: 5.1 keeps the byte and drops the
 *     backslash and has no \x, \z or \u. This reader is 5.4's: where it says "an error" the literal has no value.
 *
 * A BYTE IS WRITTEN AS ITSELF ONLY WHEN IT IS PRINTABLE ASCII AND NOT ONE OF  " ' \ }  : both quotes (one more test
 * costs less than being wrong), the backslash, and "}" for the reason below. What is written can therefore never begin
 * an escape or end the string, so the form of the form is itself.
 *
 * THREE NEIGHBOURS CAN STILL CHANGE WHAT A WRITTEN BYTE MEANS, and all are tracked:
 *   - "\0\x31" written as "\01" is the byte 1, not NUL and "1": after a decimal escape of one or two digits that was
 *     kept, no digit is written;
 *   - "\x4\x61" (not a program, but a text) written as "\x4a" would complete the escape, and so would "\u{4\x31}" written
 *     as "\u{41}" - which is why "}" is never written: after a \x, or a \u{ with its digits, that did not become a valid
 *     escape, no hex digit is written until a byte that is not one;
 *   - "\z\x20" written as "\z " would be skipped by the \z: after a \z no white space is written.
 */

#include <kofcore.h>

#include "lua.h"

uint32_t kgenome_textual_lua_nl(const uint8_t *p, uint32_t n, uint32_t i)
{
	if (i >= n || (p[i] != '\n' && p[i] != '\r'))
		return 0;
	return i + 1u < n && (p[i + 1u] == '\n' || p[i + 1u] == '\r') && p[i + 1u] != p[i] ? 2u : 1u;
}

uint32_t kgenome_textual_lua_esc_at(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *v)
{
	uint8_t c;
	uint32_t k, acc = 0;

	if (i + 1u >= n)
		return 0;
	c = p[i + 1u];
	if (c == 'x') {
		if (n - i < 4u || kof_hex_val(p[i + 2u]) < 0 || kof_hex_val(p[i + 3u]) < 0)
			return 0;
		*v = (uint32_t)(kof_hex_val(p[i + 2u]) * 16 + kof_hex_val(p[i + 3u]));
		return 4u;
	}
	if (kof_is_digit(c)) {
		for (k = i + 1u; k < n && k < i + 4u && kof_is_digit(p[k]); k++)
			acc = acc * 10u + (uint32_t)(p[k] - '0');
		if (acc > 255u)
			return 0;
		*v = acc;
		return k - i;
	}
	if (c == 'u' && i + 2u < n && p[i + 2u] == '{') {
		for (k = i + 3u; k < n && kof_hex_val(p[k]) >= 0; k++) {
			if (acc > (0x7fffffffu >> 4))
				return 0;
			acc = acc * 16u + (uint32_t)kof_hex_val(p[k]);
		}
		if (k == i + 3u || k >= n || p[k] != '}')
			return 0;
		*v = acc;
		return k + 1u - i;
	}
	return 0;
}

/*
 * The escape at `i` for the form: lua_esc_at above, which the value reads too. A \x or \u{ that is not a whole escape leaves the
 * hex guard, and goes with its brace; a \z the blank one; a decimal escape of one or two digits that stays the decimal one.
 */
static uint32_t lua_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	const uint8_t *s = u->s;
	uint8_t c = s[i + 1u];
	uint32_t l;

	h->v = 0;
	l = kgenome_textual_lua_esc_at(s, u->len, i, &h->v);
	h->write = (uint8_t)(l != 0);
	h->guard = 0;
	if (l) {
		h->guard = (uint8_t)((uint8_t)(c - '0') < 10u && l < 4u ? KGENOME_UNESC_DEC : 0u);
		return l;
	}
	h->guard = (uint8_t)((c == 'x' || c == 'u' ? KGENOME_UNESC_HEX : 0u) | (c == 'z' ? KGENOME_UNESC_BLANK : 0u));
	return c == 'u' && i + 2u < u->len && s[i + 2u] == '{' ? 3u : 2u;
}

uint32_t kgenome_textual_lua_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;

	(void)open_len;
	kgenome_textual_unesc_init(&u, s, len, lua_at, NULL);
	kgenome_textual_unesc_ban(&u, "\"'\\}");
	u.ws_ctl = 0x3e00u;             /* \t \n \v \f \r: what \z skips along with the space */
	return kgenome_textual_unesc_run(&u, 0, out);
}
