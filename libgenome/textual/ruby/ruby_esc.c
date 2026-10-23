/*
 * ruby_esc.c - a ruby string with its spelled-out bytes written as themselves, for the form.
 *
 * "\x65\x76\x61\x6c" and "eval" are one string, and a script that spells its names the first way does it so that
 * no marker finds them. What ruby reads as an escape in a string that interpolates, and so what this reads (ruby
 * 3.3, `Ripper` and `eval` on one case each in the test):
 *   - \xH or \xHH: ONE or two hex digits ("\x4" is the byte 4, which python refuses);
 *   - \o, \oo, \ooo: one to three octal digits, "\0" included, the value kept to a byte;
 *   - \uHHHH: four hex digits; \u{H...}: one to six hex digits in braces - and a brace with several characters
 *     ("\u{41 42}") is left alone, it is two characters and one escape;
 *   - \c \C- \M- and the named ones (\n \t \s \e ...) are left alone: what they say is a control character, which
 *     is not written as itself.
 * A backslash and the byte after it are one thing, so "\\x41" is a backslash and the text x41.
 *
 * A BYTE IS WRITTEN AS ITSELF ONLY WHEN IT IS PRINTABLE ASCII AND CANNOT CHANGE THE LITERAL: not a quote of either
 * kind or a backtick (the literal's own closer may be any of them), not a backslash, not "#", "@" or "$" (a "#"
 * before "{", "@" or "$" interpolates, and "\x23{" written as "#{" would open code), not a brace, not the literal's
 * own opening or closing delimiter (%Q(...) and %(...): a ")" written would end it). What is written can therefore never
 * begin an escape, end the literal or open an interpolation, and so the form of the form is itself.
 *
 * A HEREDOC BODY IS COPIED AS IT IS. Its end is a line that is the identifier, which this does not know (it is in the
 * operator, which is code), and "\x41" on a line of its own written as "A" would be that line: the body would end there and
 * the lines after it would be code (found by asking that the form of a form be itself on fragments of the language).
 *
 * TWO NEIGHBOURS CAN STILL CHANGE WHAT A WRITTEN BYTE MEANS and are tracked as in python's: "\0\x31" written as
 * "\01" is the byte 1, and "\x4\x61" written as "\x4a" would complete the escape. After an octal escape of one or two
 * digits that was kept no octal digit is written, after a \x or \u that did not take all its digits no hex digit.
 */

#include <kofcore.h>

#include "ruby.h"

/*
 * The escape at `i`: the row's scan (ruby_value.c, the same one the value reads), kept when its value is past a byte. A \x with
 * one digit, a \x or \u that is not an escape, leaves the hex guard; an octal escape of one or two digits the octal one.
 */
static uint32_t ruby_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	uint8_t c = u->s[i + 1u];
	struct kgenome_textual_esc_at a;
	uint32_t l = kgenome_textual_unesc_scan(u, i, &a);
	int short_ = a.kind == KGENOME_ESC_AT_X && a.digits == 1u;

	h->v = a.v;
	h->write = (uint8_t)(l && a.v <= 0xffu);
	h->guard = (uint8_t)((short_ || (!l && (c == 'x' || c == 'u')) ? KGENOME_UNESC_HEX : 0u) |
			     (a.kind == KGENOME_ESC_AT_OCT && a.digits < 3u ? KGENOME_UNESC_OCT : 0u));
	return l ? l : 2u;
}

uint32_t kgenome_textual_ruby_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;
	uint8_t o = open_len ? s[open_len - 1u] : 0u;

	if (!open_len) {
		memcpy(out, s, len);
		return len;
	}
	kgenome_textual_unesc_init(&u, s, len, ruby_at, &kgenome_textual_ruby_dq_esc);
	kgenome_textual_unesc_ban(&u, "\"'`\\#@${}");
	kgenome_textual_unesc_ban_byte(&u, o);
	kgenome_textual_unesc_ban_byte(&u, kgenome_textual_close_of(o));
	/* the opening delimiter as typed is copied with what is before it: it may itself be a backslash (%\ab\) */
	return kgenome_textual_unesc_run(&u, open_len, out);
}
