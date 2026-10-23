/*
 * sh_lang.c - the row for posix shell: the name, the id, the lexer and what the form needs to know.
 */

#include "sh.h"

/* A double-quoted word: the quote, the backslash, the dollar and the backtick escaped; every other byte, a line break and a control byte included, is itself. A NUL cannot be in a shell word. */
static const struct kgenome_textual_quote quote = { .q = '"', .bs = "\\$`" };

const struct kgenome_textual_lang kgenome_textual_lang_sh = {
	.name = "sh",
	.id = KGENOME_TEXTUAL_LANG_SH,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH,
	.word_vt_ff = 1,
	.lex = kgenome_textual_sh_lex,
	.glue = kgenome_textual_glue_always,
	.ws_significant = 1,
	.continuation = 1,
	.cmd = &kgenome_textual_sh_syntax,
	.value = kgenome_textual_sh_value,
	.fn_table = &kgenome_textual_sh_fn_table,
	.quote = &quote,
};
