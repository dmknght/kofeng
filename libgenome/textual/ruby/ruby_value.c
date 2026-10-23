/*
 * ruby_value.c - the value of a ruby string literal.
 *
 * The delimiters, which are part of the span, say how it is read:
 *   '...' and %q(...): a backslash before another backslash or before the literal's delimiter is that byte, any other
 *       backslash is itself ('\n' is two characters);
 *   "..." and %Q(...) and %(...): the escapes n t s r a b f v e, \xH and \xHH, one to three octal digits, \uHHHH and
 *       \u{H}, a backslash before a line break vanishes, and a backslash before any other byte is that byte ("\q" is
 *       "q"). Not given a value: one with "#{", "#@x" or "#$x" in it (it interpolates), \c \C- \M- (a control or
 *       meta character), \u{41 42} (one escape, two characters), and an escape the interpreter refuses (\x with no
 *       digit, a short \u, a surrogate);
 *   __END__ and what follows it: the text after the marker's line, as typed (DATA.read); not what follows a NUL, ^D or ^Z;
 *   `...`, %x, %w %W %i %I %r %s, /.../ and a heredoc body have none: a command, an array, a pattern and a symbol are
 *       not strings, and a heredoc's <<~ takes the indentation out, which is on the operator's side of the span.
 * The interpreter reads "\r\n" in the source as "\n", inside a literal too, and so does this.
 */

#include <kofcore.h>

#include "ruby.h"

const struct kgenome_textual_esc kgenome_textual_ruby_dq_esc = {
	.simple = "n\nt\ts r\ra\ab\bf\fv\ve\033", .refuse = "cCM",
	.xmin = 1, .xmax = 2, .octal = 3, .u4 = 1, .ubrace = 6, .cont = 1, .unknown = KGENOME_ESC_DROP,
};

/* Does the text interpolate, or hold an escape the interpreter refuses or this reader would misread. */
static int unreadable(const uint8_t *c, uint32_t n)
{
	uint32_t i = 0, k;

	while (i < n) {
		if (c[i] == '#' && i + 1u < n && (c[i + 1u] == '{' || kgenome_ruby_dvar_len(c, n, i)))
			return 1;
		if (c[i] != '\\' || i + 1u >= n) {
			i++;
			continue;
		}
		if (c[i + 1u] == 'x' && (i + 2u >= n || kof_hex_val(c[i + 2u]) < 0))
			return 1;
		if (c[i + 1u] == 'u') {
			if (i + 2u < n && c[i + 2u] == '{') {
				for (k = i + 3u; k < n && k < i + 9u && kof_hex_val(c[k]) >= 0; k++)
					;
				if (k == i + 3u || k >= n || c[k] != '}')
					return 1;
			} else {
				for (k = i + 2u; k < n && k < i + 6u && kof_hex_val(c[k]) >= 0; k++)
					;
				if (k != i + 6u)
					return 1;
			}
		}
		i += 2u;
	}
	return 0;
}

/* The text of a single quoted literal: only "\\" and "\<delimiter>" are escapes. */
static uint32_t single_value(const uint8_t *c, uint32_t n, uint8_t o, uint8_t cl, uint8_t *out)
{
	uint32_t i = 0, w = 0;

	while (i < n) {
		if (c[i] == '\\' && i + 1u < n && (c[i + 1u] == '\\' || c[i + 1u] == o || c[i + 1u] == cl))
			i++;
		out[w++] = c[i++];
	}
	return w;
}

int kgenome_textual_ruby_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			       uint8_t flags, uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len;
	uint8_t o, cl, type;

	(void)flags;
	if (open_len == 0)
		return 0;
	if (lit[0] == 0 || lit[0] == 4 || lit[0] == 26)
		return 0;               /* what follows a NUL, ^D or ^Z is not a value the program reads */
	if (lit[0] == '_')              /* the data after __END__ */
		return kgenome_textual_value_verbatim(c, cn, out, n);
	o = lit[open_len - 1u];
	cl = kgenome_textual_close_of(o);
	type = lit[0] == '%' ? (open_len == 3u ? lit[1] : 'Q') : lit[0];
	if (type != '\'' && type != '"' && type != 'q' && type != 'Q')
		return 0;
	cn = kgenome_textual_lf_value(c, cn, out);
	c = out;
	if (type == '\'' || type == 'q') {
		*n = single_value(c, cn, o, cl, out);
		return 1;
	}
	if (unreadable(c, cn))
		return 0;
	return kgenome_textual_esc_value(&kgenome_textual_ruby_dq_esc, c, cn, out, n);
}
