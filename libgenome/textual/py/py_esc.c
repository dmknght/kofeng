/*
 * py_esc.c - a python string with its spelled-out bytes written as themselves, for the form.
 *
 * "\x65\x76\x61\x6c" and "eval" are one string, and a script that spells its names the first way does it so
 * that no marker finds them: the escape is how it was typed, which is what the form takes out. What python
 * reads as an escape, and so what this reads (python 3.13 `compile`, one case each in the test):
 *   - \xHH: EXACTLY two hex digits ("\x4" is a syntax error, not the byte 4);
 *   - \ooo: one to three octal digits, and "\501" is U+0141 in a str, so a value above \377 is not a byte
 *     and is left alone;
 *   - \uHHHH and \UHHHHHHHH: four and eight hex digits, in a str only - b"A" is six bytes;
 *   - \N{name}: a table lookup the lib does not have, so it is left alone.
 * A backslash and the byte after it are one thing, so "\\x41" is a backslash and the text x41.
 *
 * A BYTE IS WRITTEN AS ITSELF ONLY WHEN IT IS PRINTABLE ASCII AND NOT ONE OF  " ' \ { }  . Both quotes, not
 * the one the string uses: one more test would cost less than being wrong, and "\x27" in '...' would end the
 * string. Both braces: the span may be an f-string with no field in it, where "\x7b" written as "{" would
 * open one. (An f-string WITH a field is never given to this: the lexer does not flag it, because there are
 * strings inside the field - r'\x41' - whose escapes are not escapes.) What is written can therefore never
 * begin an escape, end the string or open a field, and so the form of the form is itself.
 *
 * TWO NEIGHBOURS CAN STILL CHANGE WHAT A WRITTEN BYTE MEANS, and both are tracked (the guards of textual_unescape.c):
 *   - "\0\x31" written as "\01" is the byte 1, not NUL and "1": after an octal escape of one or two digits
 *     that was kept, no octal digit is written;
 *   - "\x4\x61" (not a program, but a text) written as "\x4a" would complete the escape: after a \x, \u or \U
 *     that did not take all its digits, no hex digit is written.
 * Both are cleared by the next byte that is not what could be absorbed, so "\0\x41\x31" is "\0A1".
 */

#include <kofcore.h>

#include "py.h"

/*
 * The escape at `i`. What it is comes from the row (py_value.c: the same scan the value reads it with); what is not a byte
 * is read here as no escape at all: an octal one above \377 ("\501" is U+0141), a \U past U+10FFFF. A \x, \u or \U that is
 * short of digits (or a \u that bytes has not) leaves the hex guard; an octal escape of one or two digits the octal one.
 */
static uint32_t py_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	uint8_t c = u->s[i + 1u];
	struct kgenome_textual_esc_at a;
	uint32_t l = kgenome_textual_unesc_scan(u, i, &a);

	if (l && ((a.kind == KGENOME_ESC_AT_U8 && a.v > 0x10ffffu) || (a.kind == KGENOME_ESC_AT_OCT && a.v > 0xffu)))
		l = 0;
	h->v = a.v;
	h->write = (uint8_t)(l != 0);
	h->guard = 0;
	if (!l) {
		h->guard = (uint8_t)(c == 'x' || c == 'u' || c == 'U' ? KGENOME_UNESC_HEX : 0u);
		return 2u;
	}
	if (a.kind == KGENOME_ESC_AT_OCT && a.digits < 3u)
		h->guard = KGENOME_UNESC_OCT;
	return l;
}

uint32_t kgenome_textual_py_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;

	kgenome_textual_unesc_init(&u, s, len, py_at, kgenome_textual_py_esc_row(s, open_len));
	/* both quotes, not the one the string uses; both braces, for an f-string with no field in it */
	kgenome_textual_unesc_ban(&u, "\"'\\{}");
	return kgenome_textual_unesc_run(&u, 0, out);
}
