/*
 * lua_fn.c - the functions lua builds a value with, as the table kgenome_textual_fn_find reads: string.char(n, ...), a byte from each number (0..255: lua raises
 * "value out of range" outside it), and the string functions a program changes a name with. The row is spelt with its receiver, as a "." in front of a name is a field of
 * something else in lua (kgenome_textual_lang.member_dot). The method syntax (`("x"):rep(3)`) is not read.
 *   - string.rep(s, n): n times, and a count below 1 gives "" (no NONNEG: the manual says so). A third argument (the separator) is not in max. The evaluator's only: a
 *     separator line `string.rep("-", 40)` is ordinary code, and the form would move the view of every file that has one.
 *   - string.reverse(s) is bytes. string.lower and string.upper map by the C locale's tolower, which is ASCII until a program calls os.setlocale: the subject is ASCII.
 *   - string.sub(s, i, j): counts from 1, j is INCLUSIVE (j = 0 cuts nothing; that is an exclusive end counted from 0, the one number, so BASE1 and ENDIDX say it), and a missing j is "to the end"; a negative number counts from the end in lua, which the op does
 *     not, so a number below 0 is refused, and i = 0 (which lua reads as 1) is refused with it (BASE1).
 *   - string.gsub(s, pattern, repl): the pattern is a lua PATTERN, so only one without a magic character ("^$()%.[]*+-?") is the plain text it matches, and the replacement reads
 *     "%" ("%1", "%%"). An empty pattern matches between every character (NOEMPTY). It answers TWO values (the text and the count), so it is read where the call is bracketed or
 *     joined (MULTI: see ev_single_value) and the form never rewrites it - `print(string.gsub(s, a, b))` would print one value less.
 * [Unverified] against lua: this machine has no interpreter; the rules are the manual's (5.4).
 */

#include "lua.h"

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_FN_CHR("string.char", 16, KGENOME_TEXTUAL_CHR_BYTE),
	KGENOME_TEXTUAL_ROW("string.rep", REPEAT, 2, 2, 0, 1, KGENOME_TEXTUAL_FN_NO, 1, 0, KGENOME_TEXTUAL_K_EVAL),
	KGENOME_TEXTUAL_ROW("string.reverse", REVERSE, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_CALL),
	KGENOME_TEXTUAL_ROW("string.lower", LOWER, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, KGENOME_TEXTUAL_FN_ASCII, KGENOME_TEXTUAL_K_CALL),
	KGENOME_TEXTUAL_ROW("string.upper", UPPER, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, KGENOME_TEXTUAL_FN_ASCII, KGENOME_TEXTUAL_K_CALL),
	KGENOME_TEXTUAL_ROW("string.sub", SLICE, 2, 3, 0, 1, 2, 3, KGENOME_TEXTUAL_FN_BASE1 | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_ENDIDX,
			    KGENOME_TEXTUAL_K_CALL),
	KGENOME_TEXTUAL_ROW("string.gsub", REPLACE, 3, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY | KGENOME_TEXTUAL_FN_MULTI, KGENOME_TEXTUAL_K_EVAL,
			    .bad = { NULL, "^$()%.[]*+-?", "%" }),
};

const struct kgenome_textual_fn_table kgenome_textual_lua_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
