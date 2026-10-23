/*
 * diag_text_lang_ruby.c - the profile row of ruby, for the calls written with a bracket.
 *
 * `@ivar` and `$gvar` are variables (`ident_pre`: the sigil is part of the name, so `@cmd` and `cmd` are two). A block ends at `end`, and a `def` is
 * the scope: the words that open one are the row's, `if`/`unless`/`while`/`until` only as the first word of a line (after another word they are
 * the modifier of a statement and open nothing). A line break ends a statement. `A::B.c` joins to "A.B.c".
 * A command without a bracket is a call (`stmt_words`), and a backtick or `%x()` runs one (`cmd_str`, told as the row `system`, which the table has for it).
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "alias", "and", "begin", "break", "case", "class", "def", "do", "else", "elsif", "end", "ensure", "for", "if",
	"in", "module", "next", "not", "or", "redo", "rescue", "retry", "return", "super", "then", "undef", "unless", "until", "when", "while", "yield",
	NULL };
static const char *const concat[] = { "+", NULL };
static const char *const joins[] = { ".", "::", "&.", NULL };
static const char *const loads[] = { "require", "require_relative", NULL };
static const char *const open_[] = { "def", "class", "module", "case", "begin", "do", "if", "unless", "while", "until", "for", NULL };
static const char *const open_first[] = { "if", "unless", "while", "until", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "Integer", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Float", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

static const char *const cmd_str[] = { "`", "%x", NULL };
/* `system "id"`, `exec "sh"`, `eval code`: calls without a bracket. A block after one (`eval do`, `{`) is a block. */
static const char *const stmt_words[] = { "system", "exec", "spawn", "eval", "load", NULL };
static const char *const stmt_block[] = { "{", "do", NULL };

const struct kgenome_dtx_lang kgenome_dtx_lang_ruby = {
	.id = KGENOME_TEXTUAL_LANG_RUBY,
	.typed = 1, .target = KGENOME_NUCLEO_T_RUBY,
	.stmt_words = stmt_words, .stmt_block = stmt_block, .cmd_str = cmd_str, .cmd_row = "system", .interp = 2, .interp_all = 1,
	.ident_pre = "@$", .keywords = keywords, .load_names = loads,
	.append = "+=", .concat = concat, .list_bracket = 1, .joins = joins, .chain = 1, .data_call = 1,
	.eol_term = 1,
	.ret_kw = "return",
	.fn_opaque = 1, .blocks = KGENOME_DTX_BLK_END, .fn_kw = "def", .blk_open = open_, .blk_open_first = open_first, .blk_close = "end",
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
