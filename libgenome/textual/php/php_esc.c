/*
 * php_esc.c - a php double quoted string (and a jscript island of asp, which reads the same) with its spelled-out bytes
 * written as themselves, for the form.
 *
 * "\x53\x43\x52" and "SCR" are one string, and a script that spells its names the first way does it so that no marker
 * matches them - the escape is how it was typed, which is what the form takes out. A hex escape (one or two digits) or an
 * octal one (one to three, wrapped to a byte) becomes its byte when that byte is printable and is not one the string would
 * treat as something else: a double quote, a backslash, a dollar, a brace, a backtick. Those stay escaped, which is also what
 * keeps the result meaning what it meant - and means a byte this writes can never start an escape of its own, so the form of
 * the form is itself. A backslash and what follows it are read as a pair, so "\\x41" is a backslash and the text "x41".
 * The single quote is not reserved: in a double quoted string it is a byte like another. A kept escape that a digit would lengthen - "\x4"
 * with one hex digit, "\1" or "\12" with fewer than three octal ones - holds a guard, so the byte written after it is not a digit that
 * joins it: "\x4\101" is "\x4" and "A", the bytes 0x04 and 0x41, and written as "\x4A" it was the byte 0x4a. A "\x" with no digit (php keeps it
 * as the two bytes) holds the same guard: "\x\x32\x61" is `\x` then 2 and a, and written "\x2a" it was a "*". (This loop once wrote it that way, and
 * that was kept for the sake of an unchanged output; it changed what the string held, and the form of the form was not the form. The
 * hostile-text test found it.)
 *
 * The escapes are read with the row the value reads (php_value.c); "\u{...}" is one of that row's but not one this writes.
 * Not for a string that does not interpolate: '\x41' is those four characters.
 *
 * IN A HEREDOC an escape at the start of a line - with nothing but blanks in front of it - is not written. The closing label is a line that begins
 * (after blanks, since php 7.3) with the label and a byte that is not a name, and the closer's own indentation is taken off every line: "\x41BC" as a
 * line of a heredoc that ends in ABC is text, and written as ABC it ends the heredoc; "\x20abc" under a closer indented by one is " abc", and
 * written with its blank it is "abc". A byte that comes after a first one on its line can do neither.
 */

#include <kofcore.h>

#include "php.h"

static uint32_t php_at(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_unesc_hit *h)
{
	struct kgenome_textual_esc_at a;
	uint32_t l = kgenome_textual_unesc_scan(u, i, &a);

	h->guard = 0;
	h->v = a.v & 0xffu;
	h->write = (uint8_t)(l && (a.kind == KGENOME_ESC_AT_X || a.kind == KGENOME_ESC_AT_OCT));
	if (h->write && u->s[0] == '<') {               /* the span of a heredoc begins "<<<": its lines are what a closer is looked for in */
		uint32_t j = i;

		while (j && (u->s[j - 1u] == ' ' || u->s[j - 1u] == '\t'))
			j--;
		if (!j || u->s[j - 1u] == '\n' || u->s[j - 1u] == '\r')
			h->write = 0;
	}
	/* what is kept (the driver writes `h->guard` when it keeps the escape) can still be lengthened by the next digit */
	if (!l && u->s[i + 1u] == 'x')                  /* "\x" with no digit is not an escape (php keeps both bytes), and "\x" then a written "2a" is one */
		h->guard = KGENOME_UNESC_HEX;
	else if (h->write && a.kind == KGENOME_ESC_AT_X && a.digits < 2u)
		h->guard = KGENOME_UNESC_HEX;
	else if (h->write && a.kind == KGENOME_ESC_AT_OCT && a.digits < 3u)
		h->guard = KGENOME_UNESC_OCT;
	return h->write ? l : 2u;
}

/* An interpolation, `{$...}` or `${...}`: the program's code and not the string's text - an escape in it is no escape (a quote in it that was
 * spelt "\x27" is a quote, once written, that closes what the lexer reads there). The same reading the lexer has of where it ends. */
static uint32_t php_skip(const struct kgenome_textual_unesc *u, uint32_t i)
{
	if (u->s[i] == '{' && u->s[i + 1u] == '$')
		return kgenome_textual_php_skip_braces(u->s, u->len, i);
	if (u->s[i] == '$' && u->s[i + 1u] == '{')
		return kgenome_textual_php_skip_braces(u->s, u->len, i + 1u);
	return 0;
}

uint32_t kgenome_textual_php_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out)
{
	struct kgenome_textual_unesc u;

	(void)open_len;
	kgenome_textual_unesc_init(&u, s, len, php_at, &kgenome_textual_php_dq);
	u.skip = php_skip;
	kgenome_textual_unesc_ban(&u, "\"\\${`");
	return kgenome_textual_unesc_run(&u, 0, out);
}
