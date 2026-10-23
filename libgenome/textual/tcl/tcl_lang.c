/*
 * tcl_lang.c - the row for tcl: its lexer and what the form needs to know.
 *
 * WHAT THE ROW SAYS, AND WHY.
 *   - ws_significant: white space separates words ("puts a" is not "putsa"), so it is kept as one space wherever there was
 *     any, and `glue` is not asked (kgenome_textual_glue_always, as sh's).
 *   - continuation: a backslash and the line break after it are one thing - outside braces and quotes they are a gap between
 *     words - and a backslash and the byte after it are a pair, so an escaped blank is a letter of its word ("a\ b" is one word).
 *   - universal_eol: a file is read by `source` with "-translation auto" ("\n", "\r\n" and a lone "\r" are each ONE line break),
 *     which this lexer reads the same way. [Unverified: from the documentation of fconfigure; checked on this machine's tclsh
 *     8.6.16 by sourcing a CR-only file, and by a CRLF file whose comment ends in a backslash.]
 *   - keep_hashbang: a first line "#!" names the interpreter, and is a comment to tcl.
 *   - unescape_str / value: the escapes of a double-quoted word, tcl 8.6's, which are not php's or python's (tcl_esc.c, tcl_value.c).
 *   - NO call_chain, NO concat. Tcl has decoders - binary decode base64|hex|uuencode and zlib decompress|gunzip|inflate - and they
 *     are called as `[binary decode base64 "..."]`: a command in brackets, with no "(" and no ")" and a space-separated subcommand.
 *     The form's decode machinery reads "name(" backwards from the literal, asks the hook only when the byte after the literal is
 *     ")" or "," (textual_form.c resolve_held) and renames a call by the "(" it finds in the tail (calls_rewrite), so none of the
 *     three can be said by a row: it needs a change in textual_form.c, which this row does not make. Left out, and the hook is
 *     never asked. Strings are not joined either: tcl has no operator for it ("a" "b" is two words).
 */

#include "tcl.h"

/* A double-quoted word: the quote, the backslash and the two bytes a word substitutes ("$" and "[") escaped, a control byte as its letter or \ooo. */
static const struct kgenome_textual_quote quote = { .q = '"', .bs = "\\$[", .letters = KGENOME_TEXTUAL_TCL_CTL, .ctl = 'o' };

const struct kgenome_textual_lang kgenome_textual_lang_tcl = {
	.name = "tcl",
	.id = KGENOME_TEXTUAL_LANG_TCL,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH,
	.lex = kgenome_textual_tcl_lex,
	.glue = kgenome_textual_glue_always,
	.ws_significant = 1,
	.continuation = 1,
	.universal_eol = 1,
	.keep_hashbang = 1,
	.unescape_str = kgenome_textual_tcl_unescape,
	.value = kgenome_textual_tcl_value,
	.quote = &quote,
	.cmd = &kgenome_textual_tcl_syntax,
	.fn_table = &kgenome_textual_tcl_fn_table,
};
