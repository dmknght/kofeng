/*
 * php_value.c - the value of a php string literal.
 *
 * Three kinds, told apart by the span: 'single quoted' (the escapes are a backslash and a quote, nothing else - "\n"
 * in one is a backslash and an n), "double quoted" and heredoc (the full set, and a $name or {$expr} in it makes
 * the value depend on the program: no value), and a nowdoc (the text, as it is). A heredoc's value ends before the
 * line break that precedes its closing line, and - since php 7.3 - loses the closer's indentation from the start of
 * every line: `    abc` under a closer indented four is `abc`, in a nowdoc as in a heredoc, before any escape is read. An
 * unknown escape stays as it is, backslash and all: php keeps "\q" two bytes long.
 */

#include "php.h"

/* \\ and \' : nothing else is an escape in single quotes. */
static const struct kgenome_textual_esc sq = { .simple = "\\\\''", .unknown = KGENOME_ESC_KEEP };

/* n r t v e f, \\ \$ \" ; \x with one or two digits; \ooo, wrapped to a byte; \u{...}. Bytes, not characters. */
const struct kgenome_textual_esc kgenome_textual_php_dq = {
	.simple = "n\nr\rt\tv\ve\033f\f\\\\$$\"\"",
	.xmin = 1, .xmax = 2, .octal = 3, .ubrace = 8, .unknown = KGENOME_ESC_KEEP,
};

/* A "$" before a name or "{", or a "{$": the text carries something the program fills in. */
static int interpolates(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i + 1u < n; i++) {
		if (p[i] == '\\')
			i++;
		else if (p[i] == '$' && (kgenome_textual_ident_start(p[i + 1u]) || p[i + 1u] == '{'))
			return 1;
		else if (p[i] == '{' && p[i + 1u] == '$')
			return 1;
	}
	return 0;
}

/* `ind` blanks off the start of every line of c[0..cn) (a line break is "\n", "\r\n" or "\r"), into `out`; a line with fewer loses what it has. The length. */
static uint32_t dedent(const uint8_t *c, uint32_t cn, uint32_t ind, uint8_t *out)
{
	uint32_t i = 0, w = 0, skip = ind;

	while (i < cn) {
		uint8_t b = c[i++];

		if (skip && (b == ' ' || b == '\t')) {
			skip--;
			continue;
		}
		skip = b == '\n' || b == '\r' ? ind : 0u;
		out[w++] = b;
	}
	return w;
}

int kgenome_textual_php_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			      uint8_t flags, uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len;

	if (flags & KGENOME_TEXTUAL_F_HERE) {
		uint32_t ind = 0;

		/* the line break in front of the closer is the text's end, not its content */
		if (cn && c[cn - 1u] == '\n')
			cn -= cn > 1u && c[cn - 2u] == '\r' ? 2u : 1u;
		else if (cn && c[cn - 1u] == '\r')
			cn--;
		/* the closer's own indentation is taken off every line (php 7.3): the closer is what the span's close_len holds, blanks first */
		while (ind < close_len && (lit[len - close_len + ind] == ' ' || lit[len - close_len + ind] == '\t'))
			ind++;
		if (ind && cn) {
			cn = dedent(c, cn, ind, out);
			c = out;
		}
	}
	if (lit[0] == '\'')
		return kgenome_textual_esc_value(&sq, c, cn, out, n);
	if (!(flags & KGENOME_TEXTUAL_F_INTERP))                /* a nowdoc */
		return kgenome_textual_value_verbatim(c, cn, out, n);
	if (interpolates(c, cn))
		return 0;
	return kgenome_textual_esc_value(&kgenome_textual_php_dq, c, cn, out, n);
}
