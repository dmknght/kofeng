/*
 * php_lang.c - the row for php: the name, the id, the lexer and what the form needs to know.
 */

#include "php.h"

/*
 * WOULD CLOSING THESE TWO UP MAKE A LONGER TOKEN.
 *
 * "$a + +$b" must not become "$a++$b" and "$a / /x" must not become a comment. Both are pairs
 * of non-name bytes, and so is "= $", which closes up perfectly well, so "both non-name" is too
 * blunt and refused far more than it had to.
 *
 * What glues is an OPERATOR byte followed by itself - ++ -- // ** << >> && || :: .. == !! $$ -
 * and the pairs that open a comment or a tag. A bracket, a brace, a comma or a semicolon
 * followed by itself is two tokens, so "isset($a) )" and "isset($a))" are one program and
 * come out as one text; the pass this replaces kept the space in the first, so two copies of a
 * file that differed in that spacing formed to two different texts.
 *
 * kgenome_textual_glue_twice, like every other row, and not strchr: strchr finds the set's own
 * terminator for a NUL, so this row alone kept the space in "\0 \0" (measured: `$a=1; \0 \0 $b` formed
 * to `\0 \0`, where js, lua and every other row give `\0\0`). NUL is not an operator, so closing
 * two of them up makes no longer token and the space was an accident of the library call. No file of
 * the php lists (formhash, 71 files, and the engine over them) has a NUL between two tokens, so
 * nothing they hold changes; tests/lib/genome/textual_glue_nul.c pins it.
 */
static int php_glue(uint8_t a, uint8_t b)
{
	return kgenome_textual_glue_twice(a, b, "+-*/%=!<>&|.:?^~$") || (a == '/' && b == '*') ||
	       (a == '?' && b == '>') || (a == '<' && b == '?');
}

/* A single quoted literal: the quote and the backslash are the only bytes that single quotes read, and every other byte, a line break too, is itself. */
static const struct kgenome_textual_quote quote = { .q = '\'', .bs = "\\" };

const struct kgenome_textual_lang kgenome_textual_lang_php = {
	.name = "php",
	.id = KGENOME_TEXTUAL_LANG_PHP,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH | KGENOME_TEXTUAL_GAP_LINE | KGENOME_TEXTUAL_GAP_BLOCK,
	.lex = kgenome_textual_php_lex,
	.tag_own = kgenome_textual_php_tag_own,
	.glue = php_glue,
	/* A brace on its own line is Allman style, which is K&R with the brace moved. */
	.join_brace = 1,
	.unescape_str = kgenome_textual_php_unescape,
	.islands = 1,
	.calls = &kgenome_textual_php_calls,
	.value = kgenome_textual_php_value,
	.quote = &quote,
	.concat = '.',
	.echo_call = 1,
	.norm_quote = 1,
	.heredoc_eol = 1,
	.fn_table = &kgenome_textual_php_fn_table,
	.fn_fold = 1,
};
