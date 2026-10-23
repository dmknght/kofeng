/*
 * diag_text_lang_vbs.c - the profile rows of vbscript (a .vbs run by wscript) and of classic asp (a page whose <% %> islands are vbscript, or jscript): ONE table
 * (T_VBS) and one reading, so the two rows share every field but the lexer's id and the island's end (`island_term`).
 *
 * VBScript calls with or without a bracket: `Execute x`, `ExecuteGlobal x` (statements: `stmt_words`), `o.Run cmd, 0, True` (a member that is a row, at the head of a
 * statement: `bare_members`), `Call o.Run(cmd, 0, True)` and `x = o.Run(cmd)` (the bracket forms, read as every call). A name that is a call and a member that is a read are
 * the same row (`x.nodeTypedValue`, `Request.Form`). The line break ends a statement and so does ":" (`sep`), and `Then`/`Else` begin one (`stmt_lead`); "_" continues a line.
 * "&" and "+" join. An object is a COM object made by `CreateObject("ProgID")` (also `Server.CreateObject`, `WScript.CreateObject`, and `new ActiveXObject(..)` of a jscript
 * page) and its members are the rows "ProgID.Member" of this table.
 *
 * `Sub`/`Function ... End Function` is a scope (BLK_PAIR): its parameters and the names it `Dim`s are its own and any other name is the top level's (`global_default`: vbscript's
 * undeclared variable is a global), and a function returns by assigning its own name (`ret_name`). A call of one with a bracket is read by the summaries (diag_text_sum.c); calling it is
 * no call of a value (`data_call` is not set: vb has no variable that holds a callable but through GetRef).
 *
 * NOT READ: a call of a Sub or Function without a bracket (`Run cmd`); `Class` members' own scope; a comparison `If a = b Then` reads as an assignment until `Then` ends it; `With o ... .Run x` (the object of a leading dot).
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "and", "as", "byref", "byval", "call", "case", "class", "const", "dim", "do", "each", "else", "elseif", "empty",
	"end", "eqv", "erase", "error", "exit", "explicit", "false", "for", "function", "get", "goto", "if", "imp", "in", "is", "let", "loop", "mod", "new",
	"next", "not", "nothing", "null", "on", "option", "or", "preserve", "private", "property", "public", "redim", "rem", "resume", "select", "set",
	"step", "sub", "then", "to", "true", "until", "wend", "while", "with", "xor",
	/* jscript, in an asp page */ "var", "return", "typeof", "break", "continue", "throw", "try", "catch", "finally", "switch", "default", NULL };
static const char *const stmt_words[] = { "execute", "executeglobal", NULL };
static const char *const stmt_lead[] = { "then", "else", "call", NULL };
static const char *const concat[] = { "&", "+", NULL };
static const char *const joins[] = { ".", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "CInt", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "CLng", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "CDbl", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "CSng", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "CByte", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "CBool", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Len", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Asc", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "IsNumeric", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "IsEmpty", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "IsNull", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "UBound", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

/* The calls that make a COM object out of a ProgID: a vbscript or asp page, and the jscript that an asp page may be written in. */
static const struct kgenome_dtx_classfn classfns[] = {
	{ .name = "CreateObject", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
	{ .name = "Server.CreateObject", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
	{ .name = "WScript.CreateObject", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
	{ .name = "ActiveXObject", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
};

#define VB_ROW(lang_id, lit, island) \
	.id = (lang_id), .typed = 1, .lit_lang = (lit), .target = KGENOME_NUCLEO_T_VBS, .fold = 1, .fold_vars = 1, .keywords = keywords, \
	.append = "+=", .concat = concat, .joins = joins, .chain = 1, .bare_members = 1, \
	.eol_term = 1, .island_term = (island), .cont_us = 1, .sep = ':', \
	.stmt_words = stmt_words, .stmt_lead = stmt_lead, \
	.classfns = classfns, .n_classfns = sizeof classfns / sizeof classfns[0], \
	.blocks = KGENOME_DTX_BLK_PAIR, .fn_kw = "function", .fn_kw2 = "sub", .local_kw = "dim", .global_default = 1, .ret_name = 1, \
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0]

const struct kgenome_dtx_lang kgenome_dtx_lang_vbs = { VB_ROW(KGENOME_TEXTUAL_LANG_VBS, 0, 0) };
const struct kgenome_dtx_lang kgenome_dtx_lang_asp = { VB_ROW(KGENOME_TEXTUAL_LANG_ASP, KGENOME_TEXTUAL_LANG_VBS, 1) };
