/*
 * bat_fn.c - what batch changes a value with, as the table the reader of bat_cmd.c uses (textual.h, shape EXPAND, spelled by the operator after the name in `%name:...%`). [Unverified]
 * against cmd.exe: this machine has none; the rules are the documented ones (`set /?`).
 *
 *   %v:a=b%    every "a" replaced by "b", CASE-INSENSITIVELY (cmd compares without regard to case: REPLACE with ICASE, which needs an ASCII subject). The search starts at the first
 *              byte after the colon: a "*" there makes it match up to the first "a", which this refuses, and a search of nothing is refused. The replacement may be empty (`%v:a=%`); `%v:a%` is
 *              no expansion.
 *   %v:~o,l%   the characters from o for l: a negative o counts from the end, a negative l stops that many from the end, a start past the end gives nothing - the same cut as
 *              php's substr, which is the op (SLICE). Characters are bytes only for ASCII, so the subject is ASCII.
 * The operands are text with no further `%` (the first one closes the expansion).
 */

#include "bat.h"

#define X KGENOME_TEXTUAL_K_EXPAND

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_ROW(":~", SLICE, 2, 3, 0, 1, 2, 3, KGENOME_TEXTUAL_FN_ASCII, X, .sep = ','),
	KGENOME_TEXTUAL_ROW(":", REPLACE, 2, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY | KGENOME_TEXTUAL_FN_ICASE, X, .sep = '=', .bad = { NULL, "*", NULL }),
};

const struct kgenome_textual_fn_table kgenome_textual_bat_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
