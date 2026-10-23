/*
 * py_lang.c - the row for python: its lexer, what closing up two tokens would change, the decoders a script
 * calls on its own literals, and what the form needs to know.
 *
 * INDENTATION IS SYNTAX IN PYTHON AND THE FORM REMOVES IT ALL THE SAME, as it always has for this language:
 * what comes out is for a marker to match, not for an interpreter to run. A line break stays one (a
 * statement ends at it), so the lines of a program are still there; their depth is not. Blank lines, comments
 * and the white space inside a line go. A backslash continuation keeps its break, and "\r\n" and a lone "\r"
 * are the same line break as "\n" (`universal_eol`, as the interpreter reads them).
 */

#include "py.h"

/*
 * WOULD CLOSING THESE TWO UP CHANGE THE TOKENS. Python's white space between tokens means nothing to the
 * parser (indentation aside), so the question is only whether the pair makes a longer token:
 *   - an operator byte then "=": += -= *= /= %= @= &= |= ^= <= >= == != :=  (and "= =" is "==");
 *   - "* *" is "**", "/ /" is "//", "< <" is "<<", "> >" is ">>", "- >" is "->";
 *   - a digit then ".": "1 .real" is a call on 1 and "1.real" is not python, and a name that ends in a
 *     digit keeps the space too, which costs one byte and cannot be told apart from a number here;
 *   - a quote then the same quote: "" "x" is two strings and """x" opens a triple one. The byte before
 *     the gap may close any string, so this keeps the space after every string that is followed by one with
 *     the same quote ("a" "b" stays) - one byte, against reading a different program.
 *   - a prefix letter (r b u f t, either case) then a quote: "t 'x'" is a name and a string and "t'x'" is one
 *     template string. The byte before the gap may end any name, not only a lone "t", so the space stays after
 *     "print", "if", "or" and "not" too - one byte, and the price of the form of a form being itself on text
 *     that is not a program (found on random text: a lone "t", a form feed, a quote). Not needed for a
 *     program: no valid python has a prefix-sized name in front of a string.
 * Not here, on purpose: "+ +", "- -" and "< -" are two tokens either way ("- -x" is "--x", two minuses, and
 * python has no "--"), and ". ." is two dots - so those close up.
 */
static int py_glue(uint8_t a, uint8_t b)
{
	if (kgenome_textual_glue_assign(a, b, "+-*/%@&|^<>=!:") || kgenome_textual_glue_twice(a, b, "*/<>\"'"))
		return 1;
	if ((b == '"' || b == '\'') && kof_byte_in_set(a, "rRbBuUfFtT"))
		return 1;
	return (a == '-' && b == '>') || (kof_is_digit(a) && b == '.');
}

/*
 * THE DECODERS, as they are written - "base64.b64decode(" or "b64decode(" after a from-import, "zlib.decompress("
 * - read by the name and, where the module changes what it is, by the module: the first row that ends the
 * written name wins, so the qualified ones come first. A row with no decoder says "this is not one" and ends
 * the chain: bz2 and lzma have a decompress too, and the hook would be asked for a coding it was never told.
 *   - base64: b64decode, standard_b64decode, decodebytes (and python 2's decodestring), binascii.a2b_base64;
 *   - hex: binascii.unhexlify, a2b_hex, bytes.fromhex, bytearray.fromhex, base64.b16decode (not a bare
 *     "fromhex": float.fromhex is a hexadecimal FLOAT);
 *   - zlib.decompress, and a bare "decompress", which is the zlib one more often than not and, when it is not,
 *     is refused by the hook ("0 refuses: the value is not what the first decoder reads"); gzip.decompress;
 *   - urllib's unquote, unquote_plus, unquote_to_bytes (and python 2's urllib.unquote).
 * NOT EXPRESSIBLE, and so not here: codecs.decode(x, 'hex' | 'base64' | 'rot13') names its coding in a SECOND
 * argument that comes after the literal, which the chain - read from the code BEFORE the literal - cannot
 * see, and the hook is given a coding, not an argument; x.decode('hex'), x.decode('base64') and 'x'[::-1]
 * are postfix, so there is no call in front of the literal at all; reversed(x) is an iterator, not a str, so
 * it is not "reverse" until a join, which is not the call before the literal; urlsafe_b64decode reads a
 * different alphabet than the base64 decoder the hook runs, [Unverified] whether that decoder would refuse or
 * mis-decode a "-" or "_"; bz2, lzma, base64.b32decode and marshal have no decoder id.
 */
static const struct kgenome_textual_decoder_row decoder_row[] = {
	{ "bz2.decompress",          KGENOME_TEXTUAL_DEC_NONE },
	{ "lzma.decompress",         KGENOME_TEXTUAL_DEC_NONE },
	{ "gzip.decompress",         KGENOME_TEXTUAL_DEC_GZIP },
	{ "zlib.decompress",         KGENOME_TEXTUAL_DEC_ZLIB },
	{ "decompress",              KGENOME_TEXTUAL_DEC_ZLIB },
	{ "b64decode",               KGENOME_TEXTUAL_DEC_B64 },
	{ "standard_b64decode",      KGENOME_TEXTUAL_DEC_B64 },
	{ "decodebytes",             KGENOME_TEXTUAL_DEC_B64 },
	{ "decodestring",            KGENOME_TEXTUAL_DEC_B64 },
	{ "a2b_base64",              KGENOME_TEXTUAL_DEC_B64 },
	{ "unhexlify",               KGENOME_TEXTUAL_DEC_HEX },
	{ "a2b_hex",                 KGENOME_TEXTUAL_DEC_HEX },
	{ "bytes.fromhex",           KGENOME_TEXTUAL_DEC_HEX },
	{ "bytearray.fromhex",       KGENOME_TEXTUAL_DEC_HEX },
	{ "b16decode",               KGENOME_TEXTUAL_DEC_HEX },
	{ "unquote",                 KGENOME_TEXTUAL_DEC_RAWURL },     /* keeps "+": verified with python 3, unquote("a+b") is "a+b" */
	{ "unquote_plus",            KGENOME_TEXTUAL_DEC_URL },        /* the one that reads "+" as a space */
	{ "unquote_to_bytes",        KGENOME_TEXTUAL_DEC_RAWURL },
};

/* Names are case sensitive, there is no "@" and no leading "\"; "module.name" is how a call is qualified. */
static const struct kgenome_textual_call_style style = {
	.rows = decoder_row, .n_rows = sizeof decoder_row / sizeof decoder_row[0], .qualify = '.',
};

/* A single quoted str: the backslash and the quote escaped, a control byte as its letter or \xHH (a raw CR or NUL does not belong in a source line). */
static const struct kgenome_textual_quote quote = { .q = '\'', .bs = "\\", .letters = KGENOME_TEXTUAL_PY_CTL, .ctl = 'x' };

const struct kgenome_textual_lang kgenome_textual_lang_py = {
	.name = "py",
	.id = KGENOME_TEXTUAL_LANG_PY,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH,
	.lex = kgenome_textual_py_lex,
	.glue = py_glue,
	.continuation = 1,
	.universal_eol = 1,
	.keep_hashbang = 1,
	.unescape_str = kgenome_textual_py_unescape,
	.calls = &style,
	.fn_table = &kgenome_textual_py_fn_table,
	.member_dot = 1,
	.value = kgenome_textual_py_value,
	.concat = '+',
	.concat_adjacent = 1,
	.quote = &quote,
};
