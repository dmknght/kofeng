/*
 * diag_text_lang_lua.c - the profile row of lua.
 *
 * Variables are bare names; `local` is a keyword in front of one and needs no hook of its own (the name after it is read as any assignment's).
 * ".." joins, ":" is a method's join (`f:read()`), a block ends at `end` and the words that open one are function, if and do (a `for` or a `while`
 * carries its `do`). `_G[n](...)` is a call by a value. `require('socket')` names a module.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "and", "break", "do", "else", "elseif", "end", "for", "function", "goto", "if", "in", "local", "not", "or",
	"repeat", "return", "then", "until", "while", NULL };
static const char *const concat[] = { "..", NULL };
static const char *const joins[] = { ".", ":", NULL };
static const char *const scope_objs[] = { "_G", "_ENV", NULL };
static const char *const loads[] = { "require", NULL };
static const char *const open_[] = { "function", "if", "do", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "tonumber", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_lua = {
	.id = KGENOME_TEXTUAL_LANG_LUA,
	.typed = 1, .target = KGENOME_NUCLEO_T_LUA,
	.keywords = keywords,
	.concat = concat, .joins = joins, .chain = 1, .data_call = 1,
	.scope_objs = scope_objs, .module_fn = "require", .load_names = loads,
	.eol_term = 1,
	.ret_kw = "return",
	.lexical = 1, .fn_opaque = 1, .blocks = KGENOME_DTX_BLK_END, .fn_kw = "function", .blk_open = open_, .blk_close = "end",
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
