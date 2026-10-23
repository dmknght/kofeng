/*
 * diag_text_lang_tcl.c - the profile row of tcl: a command line, read by diag_text_cmd.c.
 *
 * A command is the first word of a segment (`;` and the line break end one, `[` begins one inside a word and `]` ends it). The ensemble commands take their subcommand into the
 * name (`file delete` is "file.delete", `binary decode`, `zlib inflate`, `interp eval`: `cmd_sub`), and a package's procedure is written with "::" and spelled with "." in the table
 * (`http::geturl`: `cmd_ns`).
 * WHAT IT CANNOT READ, and no row can say: a braced body is a string to the lexer (`catch {exec $x}`, `proc f {} { ... }`, `if 1 { ... }`), so a command inside one is not seen: only the
 * top level of a file and the `[commands]` substituted into it are. `set` and the variables it makes are not followed.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const sub[] = { "file", "binary", "zlib", "interp", NULL };

const struct kgenome_dtx_lang kgenome_dtx_lang_tcl = {
	.id = KGENOME_TEXTUAL_LANG_TCL,
	.typed = 1, .target = KGENOME_NUCLEO_T_TCL,
	.sigil = '$', .eol_term = 1, .blocks = KGENOME_DTX_BLK_BRACE,
	.cmd = 2, .cmd_ends = ";[]", .cmd_bytes = ":", .cmd_sub = sub, .cmd_ns = 1, .cmd_var = 0, .cmd_vals = 1,
};
