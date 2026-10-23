/*
 * cfm_value.c - the value of a coldfusion string literal, and the calls that decode one.
 *
 * VALUE. The text between the quotes with its two escapes applied: the quote written twice is one quote, "##" is one "#".
 * There is no backslash escape in CFML. A "#" that is not doubled opens an expression, so the text has no value without
 * running the program and none is given - which is what keeps `"#form.x#"` from being handed to a decoder as if it were
 * base64. A lone quote cannot be in a closed literal (the lexer would have ended it), so one is refused too.
 *
 * CALLS. By name, case-insensitive, over a literal that is the whole argument (the form checks the byte after it):
 *   toBinary("...")      base64 text to binary; toString(toBinary("...")) is the usual spelling and toString is no
 *                        decoder, so the chain is toBinary and "toString(" stays
 *   urlDecode("...")     percent decoding, "+" a space, as php's urldecode does
 *   reverse("...")       the string reversed (a way to keep a name from a scan)
 * LEFT OUT, and why: binaryDecode("...", "base64"|"hex"|"uu") - the encoding is the SECOND argument, which the reader of
 * the code in front of a literal never sees, and base64 read as hex (or the other way) is a wrong decode, not a missed one;
 * charsetEncode / toString - they turn binary into text and do not change the bytes; decrypt - it needs a key; evaluate
 * and iif - they RUN the text, they do not decode it. [Unverified: the function names and their semantics are from the
 * CFML reference, not from a run.]
 */

#include "cfm.h"

int kgenome_textual_cfm_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n)
{
	const char set[3] = { (char)lit[0], '#', 0 };

	(void)flags;
	if (open_len != 1u)
		return 0;
	return kgenome_textual_undouble(lit + open_len, len - open_len - close_len, set, 1, out, n);
}

static const struct kgenome_textual_decoder_row rows[] = {
	{ "tobinary",  KGENOME_TEXTUAL_DEC_B64 },
	{ "urldecode", KGENOME_TEXTUAL_DEC_URL },
	{ "reverse",   KGENOME_TEXTUAL_DEC_REVERSE },
};

const struct kgenome_textual_call_style kgenome_textual_cfm_calls = {
	.rows = rows, .n_rows = sizeof rows / sizeof rows[0], .fold = 1,
};
