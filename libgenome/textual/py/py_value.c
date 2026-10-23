/*
 * py_value.c - the value of a python string literal.
 *
 * The prefix, which is part of the span, says how: r (raw: the text is the value, a backslash included), b (bytes:
 * \x and octal are bytes, \u \U \N are not escapes), f (an f-string: "{{" and "}}" are braces and a single one
 * opens or closes a field, which depends on the program: no value). The escapes are n t r a b f v \\ \' \",
 * \xHH (exactly two digits), \ooo (up to three), \uHHHH and \UHHHHHHHH in a str, and a backslash and a line break
 * vanish. A \N{name} needs the table of unicode names, which the lib has not: no value. An unknown escape keeps
 * its backslash, as python does ("\q" is two characters). In a str what \x and octal name are characters, so a value
 * above 0x7f is written as utf-8.
 */

#include "py.h"

const struct kgenome_textual_esc kgenome_textual_py_str_esc = {
	.simple = KGENOME_TEXTUAL_PY_CTL "\\\\''\"\"", .refuse = "N",
	.xmin = 2, .xmax = 2, .octal = 5, .u4 = 1, .u8 = 1, .cont = 1,
	.unknown = KGENOME_ESC_KEEP, .chars = 1,
};

const struct kgenome_textual_esc kgenome_textual_py_bytes_esc = {
	.simple = KGENOME_TEXTUAL_PY_CTL "\\\\''\"\"",
	.xmin = 2, .xmax = 2, .octal = 3, .cont = 1, .unknown = KGENOME_ESC_KEEP,
};

/* A b in the prefix makes a bytes literal: \u \U \N are not escapes in one, and an octal one is a byte. */
const struct kgenome_textual_esc *kgenome_textual_py_esc_row(const uint8_t *lit, uint32_t open_len)
{
	uint32_t k;

	for (k = 0; k < open_len; k++)
		if ((lit[k] | 0x20u) == 'b')
			return &kgenome_textual_py_bytes_esc;
	return &kgenome_textual_py_str_esc;
}

int kgenome_textual_py_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			     uint8_t flags, uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len, w = 0, p = 0;
	const struct kgenome_textual_esc *row = kgenome_textual_py_esc_row(lit, open_len);
	int raw = 0, fstr = 0;

	(void)flags;
	/* the tokenizer reads a source with "\n" for every line break, a raw one inside a literal too */
	cn = kgenome_textual_lf_value(c, cn, out);
	c = out;
	while (p < open_len && kof_is_alpha(lit[p])) {
		uint8_t l = (uint8_t)(lit[p++] | 0x20u);

		raw |= l == 'r';
		fstr |= l == 'f';
	}
	if (fstr) {
		/* "{{" and "}}" are braces; a single brace is a field: the value is not in the text */
		if (!kgenome_textual_brace_value(c, cn, out, &w))
			return 0;
		if (raw) {
			*n = w;
			return 1;
		}
		return kgenome_textual_esc_value(row, out, w, out, n);
	}
	if (raw) {
		*n = cn;
		return 1;
	}
	return kgenome_textual_esc_value(row, c, cn, out, n);
}
