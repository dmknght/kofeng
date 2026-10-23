/*
 * textual_gap - the gap the form skips before it looks for a join or a call: white space, a continuation and the three spellings of a comment
 * (kgenome_tform_skip_gap). The comments are read by the lexer's own readers (kgenome_textual_c_block_end, kgenome_textual_line_end), and what is pinned
 * is what that decided where the function once carried loops of its own:
 *   - a block comment between a literal and its join is a gap, closed or not (an unclosed one has nothing after it, so no join - and no read past the end);
 *   - a line comment ends at the first CR or LF, not at the first LF: in javascript, vbscript and tcl a lone CR is a line break, so the "+" on the
 *     next line joins ("a" // c <CR> + "b" is "ab"; the loop that ran to the LF skipped it and left the join as typed). In python a lone CR ends the
 *     statement, and the join does not happen across it.
 */

#include "textual_check.h"

int main(void)
{
	/* a comment of each spelling between the two literals */
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" /* c */ + \"b\";\n", "var x=\"ab\";");
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" // c\n + \"b\";\n", "var x=\"ab\";");
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" /* a */ /* b */ // c\n + \"b\";\n", "var x=\"ab\";");
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $x = 'a' # c\n . 'b';\n", "<?php $x='ab';");
	/* an unclosed block comment: nothing follows it, so no join, and the text is kept as typed from the comment on */
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" /* c + \"b\";\n", "var x=\"a\"/* c + \"b\";\n");
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" /*", "var x=\"a\"/*");
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" /", "var x=\"a\"/");
	/* a lone CR ends a line comment where the language says it is a line break: the join on the next line is read */
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" // c\r+ \"b\";\nvar y = 1;\n", "var x=\"ab\";\nvar y=1;");
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" // c\r\n+ \"b\";\n", "var x=\"ab\";");
	/* ... and the line after the lone CR is not skipped: a literal that is not a join stays */
	form_lang(KGENOME_TEXTUAL_LANG_JS, "var x = \"a\" // c\rvar y = \"b\";\n", "var x=\"a\"\nvar y=\"b\";");
	/* python: a line break ends the statement, so the "+" on the next line is a new statement's and nothing is joined */
	form_lang(KGENOME_TEXTUAL_LANG_PY, "x = \"a\" # c\r+ \"b\"\ny = 1\n", "x=\"a\"\n+\"b\"\ny=1");
	printf("textual gap: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
