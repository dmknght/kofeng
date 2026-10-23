/*
 * diag_text_lang_aspx.c - the profile row of asp.net: c# and vb.net, one table (the class library), names that do not care about case (`fold`).
 *
 * c# ends a statement with ";" and vb.net with the line, so the row has both (a line break after a c# statement is an empty statement); vb's "_"
 * continues a line (`cont_us`). The page's islands each end one. "+" and vb's "&" join. A fully qualified name ("System.Diagnostics.Process.Start") is
 * looked up without its namespace (`ns_drop`). The scope is the shape `name(...) {` - c#'s; vb's `Sub`/`Function ... End` blocks are NOT read, so
 * in a vb.net page every variable is at the top level. The request is also read through an index or a call (`req_obj`) and through a server control's text (`ctl_row`).
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked", "class", "const",
	"continue", "decimal", "default", "delegate", "do", "double", "else", "enum", "event", "explicit", "extern", "finally", "fixed", "float",
	"for", "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock", "long", "namespace", "new", "object",
	"operator", "out", "override", "params", "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof",
	"static", "struct", "switch", "this", "throw", "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual", "void",
	"volatile", "while", "dim", "end", "then", "next", "sub", "function", "set", "let", "byval", "byref", "imports", "inherits", "elseif",
	"select", "with", "not", "and", "or", "mod", "each", NULL };
static const char *const concat[] = { "+", "&", NULL };
static const char *const joins[] = { ".", NULL };
static const char *const ctl[] = { "if", "for", "foreach", "while", "switch", "catch", "using", "lock", "fixed", "checked", "unchecked", NULL };
static const char *const casts[] = { "int", "long", "double", "float", "short", "byte", "bool", "decimal", NULL };

/* A server control's text (`txtArg.Text`) is what the sender posted. 335 benign pages hold the word Request, so the table has no row for it alone; read through an index or a call it is the
 * request's default collection (`Request["x"]`, vb's `Request("x")`: the row "Request.Item"). */
static const char *const ctl_members[] = { "text", "value", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "int.Parse", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Convert.ToInt32", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "CInt", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_aspx = {
	.id = KGENOME_TEXTUAL_LANG_ASPX,
	.typed = 1, .target = KGENOME_NUCLEO_T_DOTNET, .fold = 1,
	.keywords = keywords,
	.append = "+=", .concat = concat, .joins = joins, .chain = 1, .data_call = 1, .ns_drop = 1, .typed_decl = 1,
	.eol_term = 1, .island_term = 1, .cont_us = 1, .num_casts = casts,
	.ret_kw = "return",
	.lexical = 1, .fn_opaque = 1, .blocks = KGENOME_DTX_BLK_BRACE, .arrow = "=>", .shape = 1, .ctl_words = ctl,
	.req_obj = "request", .req_row = "Request.Item", .ctl_row = "Request.Form", .ctl_members = ctl_members,
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
