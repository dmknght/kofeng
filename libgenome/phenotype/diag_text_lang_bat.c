/*
 * diag_text_lang_bat.c - the profile row of windows batch (.bat, .cmd): a command line, read by diag_text_cmd.c.
 *
 * A command is the first word of a segment (`&` `&&` `|` `||` `(` `)` and the line break end one; ";" is a blank in cmd, not an end), of what follows `start` and `call`, and
 * of what follows `do` and `else` wherever they stand (`cmd_rearm`: they follow a ")"); a leading "@" is no part of it, and `/b` and the like after `start` are skipped. A word holds what a path and a variable do (`%SystemRoot%\system32\cmd.exe`), and the
 * command is the last piece of the path without .exe .com .bat .cmd; names do not care about case. The text of `echo` is arguments like any other.
 * The command after the condition of an `if` is read (`cond`: `if exist f cmd`, `if not "%a%"=="b" cmd`, `if a neq b cmd`).
 * NOT READ: `for` sets, `set` variables, and what a quoted command line holds
 * (`cmd /c "curl u | sh"`): a string.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const lead[] = { "start", "call", NULL };
static const char *const rearm[] = { "do", "else", NULL };
static const char *const if_head[] = { "if", NULL };
static const char *const if_mods[] = { "not", NULL };
static const char *const if_unary[] = { "exist", "defined", "errorlevel", "cmdextversion", NULL, NULL };
static const char *const if_binary[] = { "equ", "neq", "lss", "leq", "gtr", "geq", NULL };
static const struct kgenome_dtx_cond cond = { if_head, if_mods, if_unary, if_binary };
static const char *const exts[] = { ".exe", ".com", ".bat", ".cmd", NULL };

/* What a command takes as a file where a bare name does not say so (diag_text_ident.c): curl's `-o`, or with `-O` the last piece of the URL. */
static const struct kgenome_dtx_pathsem pathsem[] = {
	{ "curl", "-o --output", 0, 1, "-O", NULL },
};

/* KNOWN DEFECT D15b (2026-10-24, R) [sev M]: the bat row reads neither `set` assignments nor the sets of a `for`, so `set c=powershell` / `for %i in (cmd) do %i` give no value to the command that follows.
 * Trigger: a batch file that builds the command word with set or for. Effect: the command is an unknown word, the node has no capability and no link (documented at the head of this file as NOT READ).
 * Reproducer: none yet. Fix: a batch assignment reader beside the sh one in diag_text_cmdval.c (set NAME=value, set /a read as unknown) and `for ... in (list) do` binding the variable per word. */
const struct kgenome_dtx_lang kgenome_dtx_lang_bat = {
	.id = KGENOME_TEXTUAL_LANG_BAT,
	.typed = 1, .target = KGENOME_NUCLEO_T_BAT, .fold = 1,
	.eol_term = 1, .blocks = KGENOME_DTX_BLK_BRACE,
	.cmd = 2, .cmd_ends = "&|()", .cmd_start = "/.~%-:\\*?", .cmd_bytes = "/.~%-:\\*?+,", .cmd_opt = "/", .cmd_pass = "@",
	.cmd_lead = lead, .cmd_rearm = rearm, .cmd_exts = exts, .cmd_var = 1, .cond = &cond, .cmd_vals = 1,
	.pathsem = pathsem, .n_pathsem = sizeof pathsem / sizeof pathsem[0],
};
