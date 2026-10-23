/*
 * diag_text_lang_py.c - the profile row of python.
 *
 * Indentation is the block structure, so the scopes are the lines under a `def` (`blocks`), and a line break ends a statement (`eol_term`). `f(name=v)`
 * is a keyword argument, not an assignment (`kwargs`). Two literals side by side are one. `globals()[n](...)` is a call by a value; `__import__('os')`
 * names a module, and `__import__(x)` with a value loads one the program does not name ("(load)"). No string functions of its own yet: see the report
 * (str.join, bytes.fromhex, "%" and format, chr, [::-1], bytes.decode).
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except",
	"finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
	"with", "yield", NULL };
static const char *const concat[] = { "+", NULL };
static const char *const joins[] = { ".", NULL };
static const char *const scope_objs[] = { "globals", "locals", "vars", NULL };
static const char *const loads[] = { "__import__", "importlib.import_module", "import_module", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "int", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "float", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "bool", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "len", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "ord", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "abs", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "isinstance", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_py = {
	.id = KGENOME_TEXTUAL_LANG_PY,
	.typed = 1, .target = KGENOME_NUCLEO_T_PY,
	.keywords = keywords,
	.append = "+=", .concat = concat, .adjacent = 1, .list_bracket = 1, .list_paren = 1, .joins = joins, .chain = 1, .data_call = 1,
	.scope_objs = scope_objs, .load_names = loads, .module_fn = "__import__",
	.eol_term = 1, .kwargs = 1,
	.ret_kw = "return",
	.lexical = 1, .fn_opaque = 1, .blocks = KGENOME_DTX_BLK_INDENT, .fn_kw = "def", .global_kw = "global",
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
