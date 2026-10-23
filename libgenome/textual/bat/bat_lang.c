/*
 * bat_lang.c - the row for windows batch (.bat, .cmd): the name, the id, the lexer and what the form needs to know.
 *
 * WHITE SPACE IS KEPT AS ONE SPACE where there was any (`ws_significant`, as in sh): batch has no token rule that
 * tells "a b" from "ab" except the blank itself. A line break ends a command and stays one; the indentation, blank
 * lines and every comment go. `continuation` is NOT set: it is the backslash and its line break, and a backslash
 * at the end of a line in batch is a path ("cd c:\\x\\"); the caret that joins lines is read by the lexer and is
 * code to the form, which keeps its line break as it keeps every one. The form does not know that the line
 * after a caret is the same command, so it collapses a blank line there (a blank line after "^" is
 * [Unverified] a command end in cmd). No "\r" alone is a break (`universal_eol` is 0): the lexer reads it as a blank.
 *
 * NO DECODERS BY NAME (`call_chain` is NULL). Batch has no function that is called over a literal. The tool that
 * is used to decode in a batch file - `certutil -decode in out`, `certutil -urlcache`, `expand`, `powershell -enc` - is a
 * command with FILE arguments: the encoded text lives in a file (or, for -enc, in an argument that is the other
 * language's), not in a call over a literal, so there is nothing for the chain to read in front of a string.
 * Nothing was done for it, on purpose.
 */

#include "bat.h"

/*
 * THE VALUE OF A BATCH STRING is the bytes between its quotes, as they are: there is no escape in a quoted run. Only
 * where nothing expands it - a "%1", "%var%", "%%i" or "!var!" in it is the program's, and the lexer says so with
 * INTERP - and where it was closed.
 */
int kgenome_textual_bat_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n)
{
	uint32_t k = len - open_len - close_len;

	if (flags & (KGENOME_TEXTUAL_F_INTERP | KGENOME_TEXTUAL_F_OPEN))
		return 0;
	return kgenome_textual_value_verbatim(lit + open_len, k, out, n);
}

/* No literal: a value is written into the text as it is, so it may hold only bytes that no part of the line can read as something else (no blank, no & | < > ^ ( ) % ! " , ; =). */
static const struct kgenome_textual_quote quote = { .plain = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-:\\/+@#$" };

const struct kgenome_textual_lang kgenome_textual_lang_bat = {
	.name = "bat",
	.id = KGENOME_TEXTUAL_LANG_BAT,
	.lex = kgenome_textual_bat_lex,
	.glue = kgenome_textual_glue_always,
	.ws_significant = 1,
	.value = kgenome_textual_bat_value,
	.cmd = &kgenome_textual_bat_syntax,
	.fn_table = &kgenome_textual_bat_fn_table,
	.fn_fold = 1,
	.quote = &quote,
};
