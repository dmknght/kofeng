/*
 * tcl_value.c - the value of a tcl braced or double-quoted word.
 *
 * A BRACED WORD, {...}: the bytes between the braces, with nothing substituted but "\<line break><blanks>", which is one space
 * (the other backslashes stay, "\{" and "\}" included: they only keep the brace from being counted).
 * A DOUBLE-QUOTED WORD, "...": the escapes of tcl_esc.c; and "$name", "${name}", "$name(index)" and "[command]" are the program's
 * - the word has no value, as a php string with a "$name" has none. A "$" that is not followed by a name (a letter, digit, "_", "::"
 * or "{" or "(") is a "$", and the byte after a backslash that is none of the escapes is itself.
 * A line break in either is "\n" - a file is read by `source` with every line ending translated, a "\r\n" and a lone "\r" included.
 * A word that was not closed has no value.
 */

#include "tcl.h"

/* Is the "$" at `i` a substitution: a name, a braced name or an index follows. */
static int subst_at(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint8_t c;

	if (i + 1u >= n)
		return 0;
	c = p[i + 1u];
	return kof_is_digit(c) || kof_is_alpha(c) || c == '_' || c == '{' || c == '(' ||
	       (c == ':' && i + 2u < n && p[i + 2u] == ':');
}

/* The content of a word: `braced` says which. 0 when it has no value. (Also the value of a stretch of a word that holds substitutions, between them: tcl_cmd.c.) */
int kgenome_textual_tcl_text_value(const uint8_t *p, uint32_t n, int braced, uint8_t *out, uint32_t *w_out)
{
	uint32_t i = 0, w = 0, l, v, digits, max, nl;

	while (i < n) {
		uint8_t c = p[i];

		if ((nl = kgenome_textual_eol_at(p, n, i)) != 0) {
			out[w++] = '\n';
			i += nl;
		} else if (c == '\\' && i + 1u < n && (nl = kgenome_textual_eol_at(p, n, i + 1u)) != 0) {
			for (i += 1u + nl; i < n && kgenome_textual_hblank(p[i]); i++)
				;
			out[w++] = ' ';
		} else if (braced && c == '\\' && i + 1u < n) {
			out[w++] = c;               /* a backslash and the byte after it are a pair: "\\" then a line break is not a continuation */
			out[w++] = p[i + 1u];
			i += 2u;
		} else if (braced || (c != '\\' && c != '$' && c != '[')) {
			out[w++] = c;
			i++;
		} else if (c == '[' || (c == '$' && subst_at(p, n, i))) {
			return 0;
		} else if (c == '$' || i + 1u >= n) {
			out[w++] = c;
			i++;
		} else if ((l = kgenome_textual_tcl_esc_at(p, n, i, &v, &digits, &max)) != 0) {
			w += kgenome_textual_utf8_put(out + w, v);
			i += l;
		} else {
			uint8_t b;

			if (!kgenome_textual_pair_get(KGENOME_TEXTUAL_TCL_CTL, p[i + 1u], &b))
				b = p[i + 1u];
			out[w++] = b;
			i += 2u;
		}
	}
	*w_out = w;
	return 1;
}

int kgenome_textual_tcl_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n)
{
	if (flags & KGENOME_TEXTUAL_F_OPEN)
		return 0;
	return kgenome_textual_tcl_text_value(lit + open_len, len - open_len - close_len, lit[0] == '{', out, n);
}
