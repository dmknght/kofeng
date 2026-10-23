/*
 * perl_esc.c - a perl string with its spelled-out bytes written as themselves, for the form.
 *
 * "\x65\x76\x61\x6c" and "eval" are one string, and a script that spells its names the first way does it so that
 * no marker finds them. What perl reads as an escape (perlop, and a run for each case in the test):
 *   - \xH and \xHH: one or two hex digits ("\x4" is the byte 4; "\x" with no digit is a NUL, and is left alone);
 *   - \ooo: one to three octal digits, "\0" included, a value above \377 is a wide character and is left alone;
 *   - \x{...}, \o{...}, \N{...}, \cX and the others stay as typed: they are character names, wide characters or
 *     a different kind of byte. A backslash and the byte after it are one thing, so "\\x41" is a backslash and
 *     the text x41 ("\c" takes three, as "\cX").
 *
 * A BYTE IS WRITTEN AS ITSELF ONLY WHEN IT IS PRINTABLE ASCII AND NOT ONE OF  \  $  @  or either delimiter of the
 * string. The delimiter is read off the opening bytes: "qq{...}" cannot hold a "{" or a "}" that was not there, because
 * the brackets nest. A string whose delimiter is a word byte or a backslash is not rewritten at all: its
 * closing delimiter could be taken for a digit of the escape before it ("qq a\x4a" is "J" and not "\x4" and the end).
 * A here-document (open_len 0) is not rewritten either: a line of its body written as the terminator would end it.
 *
 * AN INTERPOLATED NAME CAN BE EXTENDED BY WHAT FOLLOWS IT. "$x\x41" is $x and "A"; written "$xA" it is the variable
 * $xA, "$h\x7b..." and "$a\x5b0]" would become subscripts, "$x\x2d>[0]" a dereference, "$x\x3a\x3ay" a package name,
 * "$x\x27y" the old separator. So in a string that has an unescaped "$" or "@" in it no byte of a name or of those
 * is written as itself (letters, digits, "_", ":", "[", "{", "-", ">", "'"): the escape stays. This looks at the whole string
 * and not at the place, because a place needs perl's interpolation grammar and the whole needs one scan; the price
 * is that "\x65\x76\x61\x6c $x" keeps its escapes. A string with nothing to interpolate loses all of them.
 *
 * TWO NEIGHBOURS CAN STILL CHANGE WHAT A WRITTEN BYTE MEANS, as in python's, and both are tracked:
 *   - "\0\x31" written as "\01" is the byte 1: after an octal escape of one or two digits that was kept, no octal
 *     digit is written;
 *   - "\x4\x61" written as "\x4a" completes the escape: after a \x that did not take two digits and was kept, no hex
 *     digit is written.
 * Both are cleared by the next byte that is not what could be absorbed. What is written can never begin an
 * escape, end the string or open an interpolation, so the form of the form is itself.
 */

#include <kofcore.h>

#include "perl.h"

/*
 * The escape at `i`: the row's scan (perl_value.c), but an octal one above \377 is a wide character and is read as no escape. A
 * "\cX" is one thing of three bytes, any other escape that stays is two. What a kept \x leaves is the hex guard when it took
 * fewer than two digits, an octal one of one or two digits the octal guard.
 */
static uint32_t perl_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	uint8_t c = u->s[i + 1u];
	struct kgenome_textual_esc_at a;
	uint32_t l = kgenome_textual_unesc_scan(u, i, &a);

	h->v = a.v;
	h->guard = (uint8_t)((c == 'x' && a.digits < 2u ? KGENOME_UNESC_HEX : 0u) |
			     ((uint8_t)(c - '0') < 8u && a.digits && a.digits < 3u ? KGENOME_UNESC_OCT : 0u));
	if (l && a.kind == KGENOME_ESC_AT_OCT && a.v > 0xffu)
		l = 0;
	h->write = (uint8_t)(l != 0);
	return l ? l : c == 'c' && i + 2u < u->len ? 3u : 2u;
}

/* Is there a "$" or "@" in the text that a backslash does not take. */
static int interpolates(const uint8_t *s, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (s[i] == '\\')
			i++;
		else if (s[i] == '$' || s[i] == '@')
			return 1;
	}
	return 0;
}

uint32_t kgenome_textual_perl_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;
	uint8_t od;

	if (!open_len || kgenome_textual_ident(s[open_len - 1u]) || s[open_len - 1u] == '\\') {
		memcpy(out, s, len);
		return len;
	}
	od = s[open_len - 1u];
	kgenome_textual_unesc_init(&u, s, len, perl_at, &kgenome_textual_perl_dq_esc);
	kgenome_textual_unesc_ban(&u, "\\$@");
	kgenome_textual_unesc_ban_byte(&u, od);
	kgenome_textual_unesc_ban_byte(&u, kgenome_textual_close_of(od));
	if (interpolates(s + open_len, len - open_len)) {
		kgenome_textual_unesc_ban_ident(&u);
		kgenome_textual_unesc_ban(&u, ":[{->'");
	}
	return kgenome_textual_unesc_run(&u, open_len, out);
}
