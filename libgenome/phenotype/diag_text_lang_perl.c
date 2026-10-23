/*
 * diag_text_lang_perl.c - the profile row of perl, for the calls written with a bracket.
 *
 * A variable is "$name" as in php; a module's function is "Pkg::name" or "Pkg->name" and joins to the table's "Pkg.name". `$ENV{KEY}` is the
 * member "ENV.KEY" (`hash_key`, the one thing a "{" after a variable says that no other language here does). A sub has no bracket for its
 * parameters (`fn_noparen`). `eval {...}` is a block and has no bracket: it is not a call, so it is no node.
 * A command without a bracket is a call (`stmt_words`: `system "id"`, `unlink $f`), and a backtick or `qx{}` runs one (`cmd_str`: the interpolated variables are its arguments).
 * NOT YET: `$q->param(...)` (the object's class is not read for a sigil variable).
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const concat[] = { ".", NULL };
static const char *const joins[] = { "::", "->", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "int", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "length", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "hex", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "oct", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "abs", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

static const char *const cmd_str[] = { "`", "qx", NULL };
/* the builtins and imports the table has a row for that are written without a bracket: `system "id"`, `unlink $f`, `eval $code`, `socket SOCK, ...`. `eval {` is a block, not a call. */
static const char *const stmt_words[] = { "system", "exec", "readpipe", "eval", "unlink", "rename", "chmod", "chown", "utime", "socket", "connect", "bind", "listen", "accept", "recv",
	"send", "inet_aton", "inet_ntoa", "gethostbyname", "gethostbyaddr", "decode_base64", "uri_unescape", "uncompress", "memGunzip", "getstore", NULL };
static const char *const stmt_block[] = { "{", NULL };

const struct kgenome_dtx_lang kgenome_dtx_lang_perl = {
	.id = KGENOME_TEXTUAL_LANG_PERL,
	.typed = 1, .target = KGENOME_NUCLEO_T_PERL,
	.sigil = '$', .stmt_words = stmt_words, .stmt_block = stmt_block, .cmd_str = cmd_str, .cmd_row = "readpipe", .interp = 1, .interp_all = 1,
	.append = ".=", .concat = concat, .joins = joins, .chain = 1, .data_call = 1, .hash_key = 1,
	.ret_kw = "return",
	.lexical = 1, .fn_opaque = 1, .blocks = KGENOME_DTX_BLK_BRACE, .fn_kw = "sub", .fn_noparen = 1,
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
