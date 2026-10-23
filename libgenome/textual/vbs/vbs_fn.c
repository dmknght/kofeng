/*
 * vbs_fn.c - the functions vbscript builds a value with, as the table kgenome_textual_fn_find reads: Chr and ChrW (a character from a number: how a dropper
 * keeps a class name out of the text), LCase and UCase, Replace, Mid, Left, Right, Trim, LTrim, RTrim, StrReverse and String. The names are lower case because the
 * language folds them (the row says `fn_fold`).
 *
 * WHAT EACH IS, with the rule that decides what is left out:
 *   - Chr is taken for 0..127: above it the byte is the ANSI code page's, which this lib does not know; ChrW (0..65535, no surrogate) is a utf-8 character.
 *   - LCase and UCase map letters by locale, so a subject with a byte above 0x7f is refused (KGENOME_TEXTUAL_FN_ASCII); on ASCII they are the two case maps.
 *   - Replace is the three-argument form (replace all, binary compare); its optional start, count and compare arguments are not in max, so a call that uses one is
 *     not this function. A search of nothing leaves the subject as it is, as the language says.
 *   - Mid, Left and Right count characters, so the subject is ASCII (the op counts bytes). Mid counts from 1 (KGENOME_TEXTUAL_FN_BASE1) and refuses a start or a length
 *     below its range, where php's substr counts from the end. Left(s, n) is the first n and Right(s, n) the last n (KGENOME_TEXTUAL_FN_FROMEND); n below 0 is an error
 *     (NONNEG), and above the length is the whole string.
 *   - Trim, LTrim and RTrim take off the SPACE and nothing else (a tab is not white space to them): the row's `set`.
 *   - StrReverse reverses characters, so the subject is ASCII.
 *   - String(n, c) is the character c written n times; c is one character (a longer string is cut to its first, and a number is a character code: both refused), and a count
 *     below 0 is an error. The evaluator's only (a row the form does not rewrite): `String(40, "-")` is the line of an ordinary banner.
 * [Unverified] against vbscript: this tree has no interpreter (no wscript, no wine); the rules are the language reference's.
 */

#include "vbs.h"

#define ASCII KGENOME_TEXTUAL_FN_ASCII

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_FN_CHR("chr", 1, KGENOME_TEXTUAL_CHR_ASCII),
	KGENOME_TEXTUAL_FN_CHR("chrw", 1, KGENOME_TEXTUAL_CHR_UCS2),
	KGENOME_TEXTUAL_FN_STR1("lcase", LOWER, ASCII),
	KGENOME_TEXTUAL_FN_STR1("ucase", UPPER, ASCII),
	/* Replace(expression, find, replacement) */
	KGENOME_TEXTUAL_FN("replace", REPLACE, 3, 3, 0, 1, 2, 0, 0),
	/* Mid(string, start, length = to the end) */
	KGENOME_TEXTUAL_FN("mid", SLICE, 2, 3, 0, 1, 2, 3, ASCII | KGENOME_TEXTUAL_FN_BASE1 | KGENOME_TEXTUAL_FN_NONNEG),
	/* Left(string, length), Right(string, length): the count is the one parameter (the second slot), the start is 0 or the end */
	KGENOME_TEXTUAL_ROW("left", SLICE, 2, 2, 0, KGENOME_TEXTUAL_FN_NO, 1, 2, ASCII | KGENOME_TEXTUAL_FN_NONNEG, KGENOME_TEXTUAL_K_CALL),
	KGENOME_TEXTUAL_ROW("right", SLICE, 2, 2, 0, KGENOME_TEXTUAL_FN_NO, 1, 2, ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_FROMEND, KGENOME_TEXTUAL_K_CALL),
	KGENOME_TEXTUAL_ROW("trim", TRIM, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_CALL, .set = " "),
	KGENOME_TEXTUAL_ROW("ltrim", LTRIM, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_CALL, .set = " "),
	KGENOME_TEXTUAL_ROW("rtrim", RTRIM, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_CALL, .set = " "),
	KGENOME_TEXTUAL_ROW("strreverse", REVERSE, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, ASCII, KGENOME_TEXTUAL_K_CALL),
	/* String(count, character): the subject is the second argument */
	KGENOME_TEXTUAL_ROW("string", REPEAT, 2, 2, 1, 0, KGENOME_TEXTUAL_FN_NO, 1, KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_ONECHAR | KGENOME_TEXTUAL_FN_NUMTYPED,
			    KGENOME_TEXTUAL_K_EVAL),
};

const struct kgenome_textual_fn_table kgenome_textual_vbs_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
