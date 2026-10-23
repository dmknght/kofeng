/*
 * vbs_lang.c - the row for vbscript (a .vbs run by wscript or cscript): its lexer, and what the form
 * needs to know.
 *
 *  glue            kgenome_textual_vb_glue: the pairs closing up would change (see it, textual_vb.c).
 *  ws_significant  0. White space between tokens is not syntax, except in the places `glue` keeps a space:
 *                  "a (1)" and "a(1)" are NOT closed up onto each other, because "Call a (1)", "a (1), 2" and
 *                  "a(1), 2" are not the same statement and no interpreter is on this machine to say which
 *                  spellings are; a space before "(" after a name or ")" is therefore kept.
 *  vb_lines        the continuation "_" + line break is kept as a break the form does not collapse, and a
 *                  lone CR is a line break.
 *  join_brace      0: there is no brace.
 *  unescape_str    NULL: a vbscript string has no escape; a backslash in it is a backslash.
 *  call_chain      NULL, deliberately. VBScript has no builtin function that decodes a literal the way
 *                  php's base64_decode or gzinflate do: Chr(), Asc(), StrReverse(), Replace() and
 *                  "&" build strings from pieces, and what a script decodes with it is its own code, which
 *                  it then hands to Execute, Eval or ExecuteGlobal (just code to the lexer). An
 *                  invented table here would be a decoder that does not exist in the language.
 *  islands         0: a .vbs has no tags (an asp island is the asp row's).
 *  concat          '&': "a" & "b" is one string, the join of its two literals (the doubled quote of one is the one value of the other); like php's ".". The row is
 *                  not the asp row's: a page's island may be jscript, whose join is "+".
 */

#include "vbs.h"

static const struct kgenome_textual_script_lang whole = { .lexer = KGENOME_TEXTUAL_PAGE_VB };

/* A string: the quote written twice, and no escape. A control byte is not written: a line break cannot be in one, and the page language
 * (asp) shares the others. */
static const struct kgenome_textual_quote quote = { .q = '"', .dbl = 1, .refuse_ctl = 1 };

const struct kgenome_textual_lang kgenome_textual_lang_vbs = {
	.name = "vbs",
	.id = KGENOME_TEXTUAL_LANG_VBS,
	.whole = &whole,
	.glue = kgenome_textual_vb_glue,
	.vb_lines = 1,
	.fn_table = &kgenome_textual_vbs_fn_table,
	.fn_fold = 1,
	.member_dot = 1,
	.concat = '&',
	.value = kgenome_textual_vbs_value,
	.quote = &quote,
};
