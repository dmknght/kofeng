/*
 * psh_fn.c - what powershell changes a string with, as the table kgenome_textual_fn_find reads and the evaluator uses (textual.h, enum kgenome_textual_shape): methods of
 * .NET's String (`$s.Replace('a', 'b')`), the operators -replace -split -join, the cast [char]65, and the static [string]::Join. Each is a row of the op php's str_replace,
 * explode/implode, strtolower and trim run, with what the language does that the op does not. The names are lower case because powershell does not tell cases apart.
 *
 *   - .Replace(a, b) is ordinal and replaces every match; an empty `a` is an ArgumentException (NOEMPTY). .Split(c) with ONE character (a longer string is a set of
 *     characters in Windows PowerShell and a string in PowerShell 7). .Substring(start, length) is an exception - not a clamp - for a start or a length past the end
 *     (STRICT) and below 0 (NONNEG); a character is a UTF-16 unit, so the subject is ASCII.
 *   - .ToLower() and .ToUpper() use the CURRENT CULTURE: in Turkish "I" lowers to a dotless "i" and "i" uppers to a dotted "I". A subject with the letter the Turkish
 *     and Azeri cultures map differently is refused (`bad`); the Invariant forms have no such letter. .Trim() takes off the white space of Char.IsWhiteSpace, whose ASCII
 *     members are `ps_ws`; .TrimStart() and .TrimEnd() the same on one side. All of them with no argument (an argument is a set of characters) and an ASCII subject.
 *   - -replace is a REGULAR EXPRESSION, case-INsensitive; -creplace is case-sensitive. A pattern holding a metacharacter is refused, and one without is the text it matches
 *     (`re_meta`), a replacement holding "$" is refused (it reads "$1" and "${name}"), the case-insensitive ones need an ASCII subject (the language's folding is Unicode's,
 *     where the Kelvin sign matches "k"), and an empty pattern matches everywhere. `-replace 'a'` with no replacement removes the match. The right side is a comma list:
 *     `-replace 'a', 'b'` binds tighter than a join and looser than a method, so it is the array ('a', 'b').
 *   - -split is a regular expression too, with the same rules, and answers a LIST: the pieces between, empty ones kept. -join joins a list: `('a', 'b') -join ''`; with no left
 *     side it is the unary `-join ('a', 'b')`, which joins with nothing; both bind looser than a join of strings.
 *   - [char]N is the character of the number N (0..65535 and no surrogate: a number outside it is an error, where javascript wraps; a string that spells a number is an error, so the operand must be a number: NUMTYPED). A character is not
 *     a string (see ev_join_level): `'a' + [char]66` is "aB" and `[char]65 + [char]66` is the number 131.
 *   - [string]::Join(sep, a, b, ...) and [string]::Join(sep, list): the separator, then the elements.
 * [Unverified] against powershell: this machine has no pwsh; the rules are .NET's (String, Regex) and about_Operators.
 */

#include "psh.h"

#define NO KGENOME_TEXTUAL_FN_NO
#define ASCII KGENOME_TEXTUAL_FN_ASCII
#define NOEMPTY KGENOME_TEXTUAL_FN_NOEMPTY
#define M KGENOME_TEXTUAL_K_METHOD
#define OPLOW KGENOME_TEXTUAL_K_OP(0)

static const char ps_ws[] = " \t\n\v\f\r";
static const char re_meta[] = "\\^$.|?*+()[]{}";

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_ROW(".replace", REPLACE, 3, 3, 0, 1, 2, 0, NOEMPTY, M),
	KGENOME_TEXTUAL_ROW(".split", SPLIT, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_ONESEP, M),
	KGENOME_TEXTUAL_ROW(".substring", SLICE, 2, 3, 0, 1, 2, 3, ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_STRICT, M),
	KGENOME_TEXTUAL_ROW(".tolower", LOWER, 1, 1, 0, NO, NO, 0, ASCII, M, .bad = { "I", NULL, NULL }),
	KGENOME_TEXTUAL_ROW(".toupper", UPPER, 1, 1, 0, NO, NO, 0, ASCII, M, .bad = { "i", NULL, NULL }),
	KGENOME_TEXTUAL_ROW(".tolowerinvariant", LOWER, 1, 1, 0, NO, NO, 0, ASCII, M),
	KGENOME_TEXTUAL_ROW(".toupperinvariant", UPPER, 1, 1, 0, NO, NO, 0, ASCII, M),
	KGENOME_TEXTUAL_ROW(".trim", TRIM, 1, 1, 0, NO, NO, 0, ASCII, M, .set = ps_ws),
	KGENOME_TEXTUAL_ROW(".trimstart", LTRIM, 1, 1, 0, NO, NO, 0, ASCII, M, .set = ps_ws),
	KGENOME_TEXTUAL_ROW(".trimend", RTRIM, 1, 1, 0, NO, NO, 0, ASCII, M, .set = ps_ws),
	KGENOME_TEXTUAL_ROW("-replace", REPLACE, 2, 3, 0, 1, 2, 0, NOEMPTY | KGENOME_TEXTUAL_FN_ICASE, OPLOW, .list = KGENOME_TEXTUAL_LIST_RIGHT, .bad = { NULL, re_meta, "$" }),
	KGENOME_TEXTUAL_ROW("-ireplace", REPLACE, 2, 3, 0, 1, 2, 0, NOEMPTY | KGENOME_TEXTUAL_FN_ICASE, OPLOW, .list = KGENOME_TEXTUAL_LIST_RIGHT, .bad = { NULL, re_meta, "$" }),
	KGENOME_TEXTUAL_ROW("-creplace", REPLACE, 2, 3, 0, 1, 2, 0, NOEMPTY, OPLOW, .list = KGENOME_TEXTUAL_LIST_RIGHT, .bad = { NULL, re_meta, "$" }),
	KGENOME_TEXTUAL_ROW("-split", SPLIT, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_ICASE, OPLOW, .bad = { NULL, re_meta, NULL }),
	KGENOME_TEXTUAL_ROW("-isplit", SPLIT, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_ICASE, OPLOW, .bad = { NULL, re_meta, NULL }),
	KGENOME_TEXTUAL_ROW("-csplit", SPLIT, 2, 2, 0, 1, NO, 0, 0, OPLOW, .bad = { NULL, re_meta, NULL }),
	KGENOME_TEXTUAL_ROW("-join", JOIN, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_LIST_RECV, OPLOW),
	KGENOME_TEXTUAL_ROW("-join", JOIN, 1, 1, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_LIST_RECV, KGENOME_TEXTUAL_K_CAST),
	KGENOME_TEXTUAL_ROW("[char]", CHR, 1, 1, NO, 0, NO, 1, KGENOME_TEXTUAL_FN_NUMTYPED, KGENOME_TEXTUAL_K_CAST, .chr = KGENOME_TEXTUAL_CHR_UCS2),
	KGENOME_TEXTUAL_ROW("[string]::join", JOIN, 2, 2, 0, 1, NO, 0, 0, KGENOME_TEXTUAL_K_EVAL, .list = KGENOME_TEXTUAL_LIST_VARIADIC),
	KGENOME_TEXTUAL_ROW("[system.string]::join", JOIN, 2, 2, 0, 1, NO, 0, 0, KGENOME_TEXTUAL_K_EVAL, .list = KGENOME_TEXTUAL_LIST_VARIADIC),
};

const struct kgenome_textual_fn_table kgenome_textual_psh_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
