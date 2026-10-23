/*
 * diag_text_lang_js.c - the profile row of javascript (node, the browser, wsh's jscript).
 *
 * A name is a bare identifier ("$" is a letter), so a variable is a name that is no call, member or keyword. Calls are qualified ("child_process.exec"),
 * `require('m')` names a module, and a call by a value is `window[n](...)`. A line break ends a statement (automatic semicolon) unless the line
 * goes on. `new ActiveXObject("ProgID")` makes a COM object, whose members are the VBS table's rows (`classfns`). Functions: `function`, and `name(...) {` / `=> {` by shape. No string functions: the evaluator follows literals, "+", variables and
 * the module a require names - see the report for the list js would need (String.fromCharCode, atob, unescape, split/reverse/join, replace).
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else",
	"export", "extends", "finally", "for", "function", "if", "import", "in", "instanceof", "let", "new", "of", "return", "super", "switch",
	"throw", "try", "typeof", "var", "void", "while", "with", "yield", "await", "async", NULL };
static const char *const concat[] = { "+", NULL };
static const char *const joins[] = { ".", "?.", NULL };
static const char *const scope_objs[] = { "window", "self", "globalThis", "top", "this", NULL };
static const char *const loads[] = { "require", NULL };
static const char *const ctl[] = { "if", "for", "while", "switch", "catch", "with", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "parseInt", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "parseFloat", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Number", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Boolean", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "isNaN", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "isFinite", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

/* wsh's jscript makes COM objects: their members are rows of the VBS table (nucleo.h: COM is written once). */
static const struct kgenome_dtx_classfn classfns[] = {
	{ .name = "ActiveXObject", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
	{ .name = "WScript.CreateObject", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_js = {
	.id = KGENOME_TEXTUAL_LANG_JS,
	.typed = 1, .target = KGENOME_NUCLEO_T_JS,
	.ident_extra = "$", .keywords = keywords,
	.append = "+=", .concat = concat, .list_bracket = 1, .joins = joins, .chain = 1, .data_call = 1,
	.scope_objs = scope_objs, .module_fn = "require", .load_names = loads,
	.eol_term = 1,
	.ret_kw = "return",
	.lexical = 1, .fn_opaque = 1, .blocks = KGENOME_DTX_BLK_BRACE, .fn_kw = "function", .arrow = "=>", .shape = 1, .ctl_words = ctl,
	.classfns = classfns, .n_classfns = sizeof classfns / sizeof classfns[0],
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
