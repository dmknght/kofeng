/*
 * ruby_fn.c - the methods ruby changes a string with, as the table kgenome_textual_fn_find reads and the evaluator uses (textual.h, enum kgenome_textual_shape): the
 * method ".gsub" is the row with the receiver as argument 0, and it runs the op php's str_replace runs. What ruby does that the op does not is said in the row:
 *   - gsub(pattern, replacement) and sub(...): a STRING pattern is the text itself (a regular expression is a literal between slashes, and is not a string of the lexer,
 *     so a call with one has no string argument and is not read). The replacement reads a backslash ("\1", "\0", "\\&", "\k<n>"), so one with a backslash is refused.
 *     An empty pattern matches between every character (NOEMPTY). sub changes the first match, gsub all (FIRST).
 *   - reverse, upcase, downcase: a character is a code point and the case is Unicode's, so the subject is ASCII.
 *   - tr(from, to): `from` and `to` are SETS, with ranges ("a-z"), a negation ("^") and escapes; a set with "-", "^" or a backslash is refused. A byte of `from` twice
 *     is refused (which pair wins is ruby's own), and the lists must be as long as each other (ruby pads the shorter, which the op does not).
 *   - join and split are the two methods that work on a list. join with no argument joins with nothing; split(sep) drops the empty strings at the END of the list and
 *     a separator that is a single space is "awk mode" (any white space): refused.
 *   - reverse, upcase, downcase and join are often written with no brackets (`"abc".reverse`): NOPAREN says so, and only these rows take no argument.
 *   - "s * n": a string times a non-negative integer (a negative one is an ArgumentError: NONNEG).
 * NOT here: strip and its kin (a leading NUL is white space to one and not to the other in the versions this was read from), capitalize, swapcase, center.
 * [Unverified] against ruby: this tree has no interpreter; the rules are the language's (String, ruby 3.3).
 */

#include "ruby.h"

#define NO KGENOME_TEXTUAL_FN_NO
#define ASCII KGENOME_TEXTUAL_FN_ASCII

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_ROW(".gsub", REPLACE, 3, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY, KGENOME_TEXTUAL_K_METHOD, .bad = { NULL, NULL, "\\" }),
	KGENOME_TEXTUAL_ROW(".sub", REPLACE, 3, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY | KGENOME_TEXTUAL_FN_FIRST, KGENOME_TEXTUAL_K_METHOD, .bad = { NULL, NULL, "\\" }),
	KGENOME_TEXTUAL_ROW(".reverse", REVERSE, 1, 1, 0, NO, NO, 0, ASCII | KGENOME_TEXTUAL_FN_NOPAREN, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".upcase", UPPER, 1, 1, 0, NO, NO, 0, ASCII | KGENOME_TEXTUAL_FN_NOPAREN, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".downcase", LOWER, 1, 1, 0, NO, NO, 0, ASCII | KGENOME_TEXTUAL_FN_NOPAREN, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".tr", TRANSLATE, 3, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_UNIQUE, KGENOME_TEXTUAL_K_METHOD, .bad = { NULL, "-^\\", "-\\" }),
	KGENOME_TEXTUAL_ROW(".join", JOIN, 1, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_LIST_RECV | KGENOME_TEXTUAL_FN_NOPAREN, KGENOME_TEXTUAL_K_METHOD),
	KGENOME_TEXTUAL_ROW(".split", SPLIT, 2, 2, 0, 1, NO, 0, 0, KGENOME_TEXTUAL_K_METHOD, .list = KGENOME_TEXTUAL_LIST_DROP_TRAILING,
			    .bad = { NULL, " ", NULL }),
	KGENOME_TEXTUAL_ROW("*", REPEAT, 2, 2, 0, 1, NO, 1, KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_NUMTYPED, KGENOME_TEXTUAL_K_OP(1)),
};

const struct kgenome_textual_fn_table kgenome_textual_ruby_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
