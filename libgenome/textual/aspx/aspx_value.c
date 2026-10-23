/*
 * aspx_value.c - the value of a c# string literal (in a page's code).
 *
 * A regular "string": n t r a b f v \\0 \\\\ \\' \\", \\xH to \\xHHHH (one to four digits - not two), \\uHHHH and \\UHHHHHHHH;
 * anything else after a backslash is an error and gives no value. A verbatim @"..." has no escapes and a doubled
 * quote is a quote. An interpolated string ($"..." or $@"...") has {{ and }} for braces and a single one opens a
 * field: no value. A raw string literal (three quotes or more, C# 11) takes its value from stripping indentation,
 * which this lib does not apply: no value.
 *
 * The page may be VB.NET: its literals double the quote and have no escapes, which this reading leaves as typed
 * ("a""b" keeps both quotes) - a base64 or hex payload has no quote in it, so the difference does not reach a decoder.
 */

#include "aspx.h"

static const struct kgenome_textual_esc cs = {
	.simple = KGENOME_TEXTUAL_CS_CTL "\\\\''\"\"",
	.xmin = 1, .xmax = 4, .u4 = 1, .u8 = 1, .pairs = 1, .zero = 1, .unknown = KGENOME_ESC_REFUSE, .chars = 1,
};

int kgenome_textual_aspx_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len,
			       uint8_t flags, uint8_t *out, uint32_t *n)
{
	const uint8_t *c = lit + open_len;
	uint32_t cn = len - open_len - close_len, p = 0;
	int verbatim = 0, interp = 0;

	(void)flags;
	while (p < open_len && (lit[p] == '@' || lit[p] == '$')) {
		verbatim |= lit[p] == '@';
		interp |= lit[p] == '$';
		p++;
	}
	if (open_len - p >= 3u)                         /* """ ... """ */
		return 0;
	/* interpolated: the braces first (a single one is a field); verbatim: a doubled quote is a quote and there are no escapes */
	if (interp) {
		if (!kgenome_textual_brace_value(c, cn, out, &cn))
			return 0;
		c = out;
	}
	if (verbatim)
		return kgenome_textual_undouble(c, cn, "\"", 0, out, n);
	return kgenome_textual_esc_value(&cs, c, cn, out, n);
}
