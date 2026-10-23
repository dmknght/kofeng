/*
 * jsp_value.c - the value of a java string literal (in a scriptlet).
 *
 * The escapes are java's: n t r b f s, \\ \' \", the octal \0 to \377 (three digits only when the first is 0 to 3),
 * and \uHHHH. Anything else after a backslash is an error in java and gives no value. A text block (three quotes) is
 * not read: its value comes from stripping the indentation common to its lines, which is a rule this lib does not
 * apply, so it has none - and a decoder over a text block is a program that hides what it is in a place most
 * shells do not use.
 */

#include "jsp.h"

static const struct kgenome_textual_esc java = {
	.simple = KGENOME_TEXTUAL_JAVA_CTL "s \\\\''\"\"",
	.octal = 4, .u4 = 1, .pairs = 1, .unknown = KGENOME_ESC_REFUSE, .chars = 1,
};

int kgenome_textual_jsp_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			      uint8_t flags, uint8_t *out, uint32_t *n)
{
	(void)flags;
	if (open_len >= 3u && lit[0] == '"' && lit[1] == '"' && lit[2] == '"')
		return 0;
	return kgenome_textual_esc_value(&java, lit + open_len, len - open_len - close_len, out, n);
}
