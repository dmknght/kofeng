/*
 * js_fn.c - the functions javascript builds a value with, as the table kgenome_textual_fn_find reads: String.fromCharCode and String.fromCodePoint, a character
 * from each number it is given (the dropper's `String.fromCharCode(104, 116, 116, 112)`, and the same with one call a character joined by "+"), and the METHODS
 * a string is changed with, which the evaluator reads (textual.h, enum kgenome_textual_shape): `"abc".replace("a", "b")` is the row ".replace" with the receiver as
 * argument 0 and runs the same op as php's str_replace.
 *
 * The row is spelled WITH its receiver, because that is how the function is written and the only way a name that is no other object's method is told: a "." in
 * front of a name is member access in javascript (kgenome_textual_lang.member_dot), so `x.fromCharCode(1)` is not this.
 *   - fromCharCode takes each number as a UTF-16 unit, modulo 65536 (a negative number wraps); a unit that is half of a surrogate pair has no utf-8 form here and
 *     refuses the call; above 0x7f the character is written as its utf-8 bytes, which is what the value of a literal holding it is.
 *   - fromCodePoint takes 0..0x10FFFF (the language throws outside it) and no surrogate.
 *
 * THE METHODS, each with what the language does that the op does not:
 *   - replace(search, replacement) with two strings changes the FIRST match; replaceAll the rest (the op, with FIRST for the first). An empty search inserts at every
 *     position, which the op does not (NOEMPTY refuses it), and "$" in the replacement is a pattern ("$&", "$1", "$$": it is refused).
 *   - split(sep) cuts at a string separator; an empty one cuts into characters, and the op refuses an empty separator (BAD_ARG), so the row needs no flag for it. join(sep) is the one method of a list: an argument of "," is the language's
 *     default when there is none, so a join with no separator is not read (the row says two arguments). `"a,b".split(",").join("")` is the idiom this exists for.
 *   - substring, slice and substr cut. All three count UTF-16 units, so the subject is ASCII (a byte above 0x7f is more than one unit of a str in some cases and the
 *     op counts bytes); a negative number counts from the end in slice and substr and is zero in substring, none of which the op does - the row refuses a number below 0.
 *     substring swaps its two numbers when the first is the larger; slice does not (and cuts nothing then); substr's second number is a length.
 *   - toLowerCase, toUpperCase map by Unicode where ASCII maps by ASCII: the subject is ASCII. trim, trimStart and trimEnd take off the white space of ECMAScript, whose ASCII
 *     members are the six of `js_ws` (U+000B and U+000C included, NUL not); the others are not ASCII.
 *   - repeat(n) writes the subject n times; a negative n is a RangeError (NONNEG refuses it).
 * atob is a decoder row (js_lang.c): the decode hook shows what it decodes, so it is not here.
 * [Unverified] against node: this tree has no javascript interpreter; the rules are the language's (ECMA-262, string methods).
 */

#include "js.h"

#define NO KGENOME_TEXTUAL_FN_NO
#define ASCII  KGENOME_TEXTUAL_FN_ASCII
#define NONNEG KGENOME_TEXTUAL_FN_NONNEG
#define NOEMPTY KGENOME_TEXTUAL_FN_NOEMPTY

static const char js_ws[] = " \t\n\v\f\r";

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_FN_CHR("String.fromCharCode", 16, KGENOME_TEXTUAL_CHR_UTF16),
	KGENOME_TEXTUAL_FN_CHR("String.fromCodePoint", 16, KGENOME_TEXTUAL_CHR_UTF8),
	KGENOME_TEXTUAL_ROW(".replace", REPLACE, 3, 3, 0, 1, 2, 0, NOEMPTY | KGENOME_TEXTUAL_FN_FIRST, KGENOME_TEXTUAL_K_METHOD, .bad = { NULL, NULL, "$" }),
	KGENOME_TEXTUAL_ROW(".replaceAll", REPLACE, 3, 3, 0, 1, 2, 0, NOEMPTY, KGENOME_TEXTUAL_K_METHOD, .bad = { NULL, NULL, "$" }),
	KGENOME_TEXTUAL_ROW(".split", SPLIT, 2, 2, 0, 1, NO, 0, 0, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".join", JOIN, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_LIST_RECV, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".substring", SLICE, 2, 3, 0, 1, 2, 3, ASCII | NONNEG | KGENOME_TEXTUAL_FN_ENDIDX | KGENOME_TEXTUAL_FN_SWAP, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".slice", SLICE, 2, 3, 0, 1, 2, 3, ASCII | NONNEG | KGENOME_TEXTUAL_FN_ENDIDX, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".substr", SLICE, 2, 3, 0, 1, 2, 3, ASCII | NONNEG, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".toLowerCase", LOWER, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".toUpperCase", UPPER, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".trim", TRIM, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD, .set = js_ws),
	KGENOME_TEXTUAL_ROW(".trimStart", LTRIM, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD, .set = js_ws),
	KGENOME_TEXTUAL_ROW(".trimEnd", RTRIM, 1, 1, 0, NO, NO, 0, ASCII, KGENOME_TEXTUAL_K_METHOD, .set = js_ws),
	KGENOME_TEXTUAL_ROW(".repeat", REPEAT, 2, 2, 0, 1, NO, 1, NONNEG, KGENOME_TEXTUAL_K_METHOD),
};

const struct kgenome_textual_fn_table kgenome_textual_js_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
