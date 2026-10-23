/*
 * py_fn.c - the functions python builds a value with, as the table kgenome_textual_fn_find reads: chr(n), the character with the code point n (0..0x10FFFF, a
 * ValueError outside it; a surrogate has no utf-8 form here and is refused). A character above 0x7f is written as its utf-8 bytes, which is what the value of a
 * str literal holding it is (py_value.c writes \xE9 the same way). Checked against python 3.13: tests/lib/genome/textual_fn_chr.c reads every number of
 * the range back through the interpreter.
 *
 * AND THE METHODS, the operator and the suffix a str is changed with, which the evaluator reads (textual.h, enum kgenome_textual_shape). Each runs the op php's
 * str_replace, strtolower, trim and strrev run, with what python does that the op does not:
 *   - ".replace(old, new)": an empty `old` inserts between every character (NOEMPTY refuses it), and a third argument (a count) is not in max: that call is not read.
 *   - ".lower" and ".upper": a str is mapped by Unicode, so the subject is ASCII. ".strip", ".lstrip", ".rstrip" take off the white space of a str, whose ASCII members are
 *     `py_ws` (the four of the C0 separators included: str.isspace says so), and with an argument (a set of characters) are not read.
 *   - ".split(sep)" with a string `sep` (no maxsplit): an empty one is a ValueError, and the op refuses an empty separator. ".join(list)": the separator is the receiver and the list the one argument; a str
 *     argument is an iterable of its characters, which is not a list here and is not read.
 *   - "[::-1]" reverses the characters: ASCII, where a character is one byte.
 *   - "s * n": a str times an int, and an int below 0 gives "" (no NONNEG: python says so); the right side must be a number of the program, not a str that spells one
 *     (NUMTYPED), and the left a str (the row's receiver).
 * NOT here: bytes.fromhex and bytes.decode. bytes.fromhex is a DECODER row (py_lang.c): what it decodes is shown by the decode hook with the call kept. Reading
 * `.decode('utf-8')` of its answer needs the evaluator to know a value is bytes and not a str, which it does not (a value has a "string" flag and nothing else).
 * Checked against python 3.13: tests/unit/script_methods.c runs every case a row accepts through the interpreter.
 */

#include "py.h"

#define NO KGENOME_TEXTUAL_FN_NO
#define ASCII KGENOME_TEXTUAL_FN_ASCII

static const char py_ws[] = " \t\n\r\v\f\x1c\x1d\x1e\x1f";

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_FN_CHR("chr", 1, KGENOME_TEXTUAL_CHR_UTF8),
	KGENOME_TEXTUAL_ROW(".replace", REPLACE, 3, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".lower", LOWER, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".upper", UPPER, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".strip", TRIM, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD, .set = py_ws),
	KGENOME_TEXTUAL_ROW(".lstrip", LTRIM, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD, .set = py_ws),
	KGENOME_TEXTUAL_ROW(".rstrip", RTRIM, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD, .set = py_ws),
	KGENOME_TEXTUAL_ROW(".split", SPLIT, 2, 2, 0, 1, NO, 0, 0, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".join", JOIN, 2, 2, 0, 1, NO, 0, 0, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW("[::-1]", REVERSE, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_SUFFIX),
	KGENOME_TEXTUAL_ROW("*", REPEAT, 2, 2, 0, 1, NO, 1, KGENOME_TEXTUAL_FN_NUMTYPED, KGENOME_TEXTUAL_K_OP(1)),
};

const struct kgenome_textual_fn_table kgenome_textual_py_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
