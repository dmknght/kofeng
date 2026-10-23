/*
 * diag_text_lang_sh.c - the profile row of the posix shell (sh, bash, busybox ash): a command line, read by diag_text_cmd.c.
 *
 * A command is the first word of a segment (`;` `&` `|` `(` `)` `{` `}` and the line break end one) and of what follows the words that hand it on (`sudo nohup exec
 * time env xargs command setsid busybox`, and the keywords `then do else elif if while until`); a "!" and a "$" in front of it are no part of it. A word is made of what the
 * shell lets a word hold ("-/.~:%+,@?*^"), so `/bin/sh`, `-c` and `./x` are words, and the command is the last piece of its path. `name=value` at the head is an assignment
 * (`cmd_assign`), `$cmd args` runs a value (`cmd_var`), and a word that begins with bash's `/dev/tcp` is a connect wherever it stands (`cmd_paths`). A "$(" is a command inside
 * the line, and `${name}` a variable.
 * NOT READ: what a quoted string holds (`sh -c 'x'`, `eval "$x"`) unless it interpolates, a function's own scope (every variable is the top level's), the options that take an
 * argument (`sudo -u root cmd` takes `root` for the command), `case` patterns beyond their ")".
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const lead[] = { "sudo", "nohup", "exec", "time", "env", "xargs", "command", "setsid", "busybox", "then", "do", "else", "elif", "if", "while", "until", NULL };
static const char *const paths[] = { "/dev/tcp", "/dev/udp", NULL };

/* What a command takes as a file where a bare name does not say so (diag_text_ident.c). wget and curl: the file of `-O`/`-o`, or - with no such option, and with curl's `-O` - the last piece of the URL (the tools' own
 * defaults); chmod, chown and chgrp: their last word; an interpreter: the script it runs. */
static const struct kgenome_dtx_pathsem pathsem[] = {
	{ "wget", "-O", 0, 1, NULL, NULL },
	{ "curl", "-o --output", 0, 1, "-O", NULL },
	{ "chmod", NULL, 2, 0, NULL, NULL }, { "chown", NULL, 2, 0, NULL, NULL }, { "chgrp", NULL, 2, 0, NULL, NULL },
	{ "sh", NULL, 1, 0, NULL, "-c" }, { "bash", NULL, 1, 0, NULL, "-c" }, { "python", NULL, 1, 0, NULL, "-c" }, { "python3", NULL, 1, 0, NULL, "-c" }, { "perl", NULL, 1, 0, NULL, "-e" },
	{ "php", NULL, 1, 0, NULL, "-r" }, { "ruby", NULL, 1, 0, NULL, "-e" }, { "node", NULL, 1, 0, NULL, "-e" },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_sh = {
	.id = KGENOME_TEXTUAL_LANG_SH,
	.typed = 1, .target = KGENOME_NUCLEO_T_SH,
	.sigil = '$', .eol_term = 1, .blocks = KGENOME_DTX_BLK_BRACE,
.interp_all = 1, .interp = 3,
	.cmd = 2, .cmd_ends = ";&|(){}", .cmd_start = "-/.~%+@*?", .cmd_bytes = "-/.~:%+,@?*^", .cmd_opt = "-", .cmd_pass = "$!",
	.cmd_lead = lead, .cmd_paths = paths, .cmd_assign = 1, .cmd_var = 1, .cmd_vals = 1, .cmd_strip = 1, .cmd_split = 1,
	.pathsem = pathsem, .n_pathsem = sizeof pathsem / sizeof pathsem[0],
};
