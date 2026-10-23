/*
 * perl_value.c - the value of a perl string literal, for the form's decoders.
 *
 * WHAT HAS A VALUE: 'x', q(x) and "x", qq(x) with nothing to interpolate. In single quotes only a backslash and the
 * delimiter are escapes ("\\" and "\'", and with q{} also "\{" and "\}"); every other backslash stays, as perl
 * reads it. In double quotes the escapes are n t r f b a e, a hex escape of one or two digits, an octal one up to
 * \377, and a backslash before any other byte is that byte ("\$" "\@" "\"" "\\"); that is `unknown = DROP`, perl's
 * own rule (perlop: "an unrecognized escape that is a letter or digit is a warning, and the backslash goes").
 *
 * WHAT HAS NONE, and the literal is then left as typed, never given a value with a hole in it:
 *   - an unescaped "$" or "@" in a double-quoted text: it interpolates, and the value is the program's. ("a@b" is an
 *     error under strict, so a decoder's payload never has one.)
 *   - the escapes whose value needs a table or a context this lib has not: "\x{...}" (a character, not a byte),
 *     "\x" with no digit (a NUL, which perl says with a warning), an octal above \377, "\N{...}", "\o{...}", "\cX",
 *     and the case changes "\l \u \L \U \Q \E \F" that act on what follows (the lower-case u was missing from the list, and "a\ub", which perl reads as "aB",
 *     had the value "aub": L13 of the lexer audit).
 *   - a backtick or qx: its value is what the command printed. The pattern operators (m qr s tr y) and qw (a list).
 *   - a here-document or the data after __END__ (open_len 0): the span does not say whether it was "<<~" (indented), and
 *     a heredoc body is never the argument of a call the form reads, because its operator is on the line before it.
 *
 * [Unverified] A "\r\n" in a literal from a CRLF file: perl may read it as "\n" before it lexes (it does for the
 * body of a here-document), and the value here is the bytes as typed.
 */

#include <kofcore.h>

#include "perl.h"

const struct kgenome_textual_esc kgenome_textual_perl_dq_esc = {
	.simple = "n\nt\tr\rf\fb\ba\ae\x1b",
	.xmin = 1, .xmax = 2, .octal = 3, .unknown = KGENOME_ESC_DROP,
};

/* Is there a "$" or "@" that is not escaped in c, and an escape in it that has no value here. */
static int has_sigil_or_unknown(const uint8_t *c, uint32_t n)
{
	uint32_t i = 0;

	while (i < n) {
		uint8_t b = c[i];

		if (b == '$' || b == '@')
			return 1;
		if (b != '\\') {
			i++;
			continue;
		}
		if (i + 1u >= n)
			return 0;
		b = c[i + 1u];
		if (b == 'x') {
			if (i + 2u >= n || kof_hex_val(c[i + 2u]) < 0)
				return 1;           /* "\x{41}" and a bare "\x" */
		} else if ((uint8_t)(b - '0') < 8u) {
			uint32_t k = i + 1u, v = 0;

			while (k < n && k < i + 4u && (uint8_t)(c[k] - '0') < 8u)
				v = v * 8u + (uint32_t)(c[k++] - '0');
			if (v > 0xffu)
				return 1;
		} else if (kof_byte_in_set(b, "cNoluULQEF")) {
			return 1;
		}
		i += 2u;
	}
	return 0;
}

int kgenome_textual_perl_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			       uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len, wl = 0;
	uint8_t od, cd;
	int single;

	(void)flags;
	if (!open_len)
		return 0;
	while (wl < open_len && kof_is_alpha(lit[wl]))
		wl++;
	od = lit[open_len - 1u];
	if (wl == 0)
		single = od == '\'';
	else if (wl == 1u && lit[0] == 'q')
		single = 1;
	else if (wl == 2u && lit[0] == 'q' && lit[1] == 'q')
		single = 0;
	else
		return 0;
	if (wl == 0 && od != '\'' && od != '"')
		return 0;
	if (single) {
		struct kgenome_textual_esc sq = { .unknown = KGENOME_ESC_KEEP };
		char simple[7];

		cd = kgenome_textual_close_of(od);
		simple[0] = '\\';
		simple[1] = '\\';
		simple[2] = (char)od;
		simple[3] = (char)od;
		simple[4] = (char)cd;
		simple[5] = (char)cd;
		simple[6] = 0;
		/* a delimiter that is a NUL or the backslash itself would end the table or repeat a pair: keep it as typed */
		if (od == 0 || od == '\\')
			return 0;
		sq.simple = simple;
		return kgenome_textual_esc_value(&sq, c, cn, out, n);
	}
	if (has_sigil_or_unknown(c, cn))
		return 0;
	return kgenome_textual_esc_value(&kgenome_textual_perl_dq_esc, c, cn, out, n);
}
