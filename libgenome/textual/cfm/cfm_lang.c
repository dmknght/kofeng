/*
 * cfm_lang.c - the row for coldfusion (cfml tags and cfscript): the name, the id, the lexer and what the form needs to know.
 * The page is cfm_lex.c, the code (strings, comments, "#...#") cfm_code.c, the value and the decoders cfm_value.c.
 */

#include "cfm.h"

static int wordish(uint8_t c)
{
	return kgenome_textual_ident(c) || c == '"' || c == '\'' || c == '#';
}

/*
 * WOULD CLOSING THESE TWO UP MAKE SOMETHING ELSE. Two words, of course; and the quotes and "#" count as word bytes, which is
 * what keeps `"a" "b"` from becoming "a""b" (one string with a quote in it), `eq "x"` from `eq"x"` and `a #b#` from `a#b#`
 * - white space is what separates the attributes of a tag, so it stays wherever two such bytes meet. Then the operators
 * that are longer when closed up: ++ -- == && || // :: .. (the same byte twice), "<" "!" "-" "-" "-" (a comment opens),
 * "/" "*" (a script comment), "= >" "- >" (arrows), and any of "!<>+-*%&|^=:/" in front of "=" (a compound or a
 * comparison), "?:" and "?." and "<>". Last, what would make "</cfscript>" or a "<cf" tag out of code that held none:
 * "<" or "/" in front of "c" or "C" and "<" in front of "/" keep their gap. That costs "a / count" its normal form
 * ("a/ count"); it was found by the generator, in which the script atom "</ cfscript>" was closed up into the tag
 * that ends the block.
 */
static int cfm_glue(uint8_t a, uint8_t b)
{
	return (wordish(a) && wordish(b)) || kgenome_textual_glue_twice(a, b, "+-*/=!<>&|.:?^~%") ||
	       (a == '/' && b == '*') || (a == '<' && kof_byte_in_set(b, "!>")) || (a == '!' && b == '-') ||
	       (a == '=' && b == '>') || (a == '-' && b == '>') ||
	       kgenome_textual_glue_assign(a, b, "!<>+-*%&|^=:/") ||
	       (a == '?' && kof_byte_in_set(b, ":.")) ||
	       ((a == '<' || a == '/') && (b | 0x20u) == 'c') || (a == '<' && b == '/');
}

/*
 * A "{" alone on a line joins the line above (script is C-shaped), except after a word that ends a statement where a
 * line break may: `return` and `throw` and `break` and `continue` in front of "{" on the next line [Unverified: whether
 * cfscript ends a statement at a line break is not known here, so the break stays].
 */
static int cfm_join_ok(const uint8_t *out, uint32_t n)
{
	static const char *const stop[] = { "return", "throw", "break", "continue" };
	uint32_t s = n, k;

	while (s && kgenome_textual_ident(out[s - 1u]))
		s--;
	for (k = 0; k < sizeof stop / sizeof stop[0]; k++)
		if (strlen(stop[k]) == n - s && kgenome_textual_ci_eq(out + s, stop[k], n - s))
			return 0;
	return 1;
}

/*
 * islands stays 0: an island with nothing in it goes whole, and a tag with nothing in it - "<cfelse>", "</cfif>",
 * "<cfabort>" - is the program. open_tail: a block comment or a string that runs to "</cfscript>" gets no line break
 * in front of the tag. unescape_str stays NULL: CFML has no "\x41" (cfm_value.c).
 */
/* A string: the quote and the "#" written twice, and no escape (cfm_value.c). */
static const struct kgenome_textual_quote quote = { .q = '"', .dbl = 1, .twice = "#" };

const struct kgenome_textual_lang kgenome_textual_lang_cfm = {
	.name = "cfm",
	.id = KGENOME_TEXTUAL_LANG_CFM,
	.gap_comments = KGENOME_TEXTUAL_GAP_LINE | KGENOME_TEXTUAL_GAP_BLOCK,
	.lex = kgenome_textual_cfm_lex,
	.glue = cfm_glue,
	.join_brace = 1,
	.join_ok = cfm_join_ok,
	.open_tail = 1,
	.concat = '&',
	.calls = &kgenome_textual_cfm_calls,
	.value = kgenome_textual_cfm_value,
	.quote = &quote,
};
