/*
 * diag_text_lang_php.c - the profile row of php: exactly what the walk assumed before the route read a row (the lists of the corpus did not move when
 * the assumptions became these fields). A variable is "$name"; a call is the one name in front of its bracket (`$o->system(` is a call of
 * system, which a table of php says is a node), so there is no `chain`; `.` joins, `.=` appends, `;` ends; `$$k`, `${...}`, `$GLOBALS` and
 * extract() make a variable of a name that is a value (`dyn_var`); `include` is a statement with no bracket; php://input is the request's body.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const struct kgenome_dtx_callsem callsems[] = {
	{ "preg_match", KGENOME_DTX_CS_OUT, 1u << 1, 2, 0 },
	{ "preg_match_all", KGENOME_DTX_CS_OUT, 1u << 1, 2, 0 },
	{ "parse_str", KGENOME_DTX_CS_OUT, 1u << 0, 1, 0 },
	{ "extract", KGENOME_DTX_CS_OUT, 1u << 0, KGENOME_DTX_CS_NO_DST, 0 },
	{ "create_function", 0, 0, 0, 1 },
	{ "intval", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "floatval", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "doubleval", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "boolval", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "absint", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "md5", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "sha1", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "crc32", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "hash", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "strlen", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "count", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "sizeof", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "isset", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "empty", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "is_numeric", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "is_string", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "is_array", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "ctype_digit", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "ctype_alnum", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

static const char *const concat[] = { ".", NULL };
static const char *const joins[] = { "->", NULL };         /* only to know a member when a "[" follows it: see kgenome_dtx_lang.chain */
static const char *const casts[] = { "int", "integer", "float", "double", "bool", "boolean", NULL };
static const char *const cmd_str[] = { "`", NULL };
static const char *const includes[] = { "include", "include_once", "require", "require_once", NULL };

const struct kgenome_dtx_lang kgenome_dtx_lang_php = {
	.id = KGENOME_TEXTUAL_LANG_PHP, .target = KGENOME_NUCLEO_T_PHP, .fold = 1,
	.sigil = '$', .string_call = 1, .ident_bs = 1, .reads_view = 1,
	.append = ".=", .concat = concat, .list_bracket = 1, .list_call = "array", .joins = joins,
	.num_casts = casts, .stmt_words = includes, .cmd_str = cmd_str, .cmd_row = "shell_exec", .interp = 1, .body_stream = "php://input",
	.blocks = KGENOME_DTX_BLK_BRACE, .fn_kw = "function", .global_kw = "global", .use_kw = "use",
	.dyn_var = 1, .ret_kw = "return",
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
