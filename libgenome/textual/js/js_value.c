/*
 * js_value.c - the value of a javascript string literal.
 *
 * A quoted string and a template without a ${ } have one; a regular expression has not (it is not a string) and a
 * template with a substitution has not (it depends on the program). The escapes are javascript's: n r t b f v and
 * \0, \xHH (exactly two digits), \uHHHH and \u{H...}, the legacy octal \101, a backslash and a line break (which
 * vanish) and - for any other byte - the byte itself, the backslash dropped: "\/" is "/", "\q" is "q". What the
 * hex and unicode escapes name are CHARACTERS, so a value above 0x7f is written as utf-8. An unpaired surrogate
 * (\uD83D alone, or both halves of a pair) has no utf-8 form here, and the literal has no value.
 */

#include "js.h"

const struct kgenome_textual_esc kgenome_textual_js_esc = {
	.simple = KGENOME_TEXTUAL_JS_CTL,
	.xmin = 2, .xmax = 2, .octal = 4, .u4 = 1, .pairs = 1, .ubrace = KGENOME_ESC_ANY, .cont = 1,
	.unknown = KGENOME_ESC_DROP, .chars = 1,
};

int kgenome_textual_js_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			     uint8_t flags, uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len, i;

	(void)flags;
	if (lit[0] != '"' && lit[0] != '\'' && lit[0] != '`')
		return 0;
	if (lit[0] == '`')
		for (i = 0; i + 1u < cn; i++) {
			if (c[i] == '\\')
				i++;
			else if (c[i] == '$' && c[i + 1u] == '{')
				return 0;
		}
	return kgenome_textual_esc_value(&kgenome_textual_js_esc, c, cn, out, n);
}
