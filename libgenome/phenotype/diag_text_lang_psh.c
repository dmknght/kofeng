/*
 * diag_text_lang_psh.c - the profile row of powershell: a command line (cmdlets, the pipeline, `& $x`) and the calls on objects (`$wc.DownloadString(..)`,
 * `[Convert]::FromBase64String(..)`), both read by the one walk.
 *
 * A command is the first word of a segment (`;` `|` `(` `)` `{` `}` and the line break end one; "=" begins a value a command may be: `$x = Invoke-Expression $y`), and a cmdlet's
 * name holds "-" (`Invoke-Expression`), so a word holds "-.:\\" besides name bytes. `& $x` and `. $x` run a value (`cmd_pass`), a variable at the head is not a command (`$wc.Foo()`
 * is a statement). Qualifiers join with "." and "::", and a type written in brackets is the receiver of its static member (`type_lit`: `[Net.WebClient]::new()`); the table
 * drops "System." (`ns_drop`). The object a variable holds is the class its `New-Object` named - `-ComObject X` is a COM object, a row of the VBS table, otherwise a .NET type of
 * this one (`classfns`) - and so is the receiver `(New-Object Net.WebClient).DownloadString(..)`. Variables do not care about case.
 * NOT READ: what a double quoted string holds (`"$(iex $x)"`), a pipeline's `ForEach-Object { iex $_ }` input ($_), splatting, a function's own scope, and `$env:NAME`.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const concat[] = { "+", NULL };
static const char *const joins[] = { ".", "::", NULL };

static const struct kgenome_dtx_classfn classfns[] = {
	{ .name = "New-Object", .target = KGENOME_NUCLEO_T_VBS, .versions = 1, .bare = 1, .flag = "-ComObject" },
};

/* The parameters of a cmdlet whose value is a file (diag_text_ident.c): a bare name given to one is a path (`-Path out.exe`), anywhere else only what has a path's shape is. */
static const struct kgenome_dtx_pathsem pathsem[] = {
	{ "Start-Process", "-FilePath", 0, 0, NULL, NULL },
	{ "Out-File", "-FilePath -Path", 0, 0, NULL, NULL },
	{ "Set-Content", "-Path -LiteralPath", 0, 0, NULL, NULL },
	{ "Add-Content", "-Path -LiteralPath", 0, 0, NULL, NULL },
	{ "Invoke-WebRequest", "-OutFile", 0, 0, NULL, NULL },
	{ "Copy-Item", "-Destination", 0, 0, NULL, NULL },
	{ "Move-Item", "-Destination", 0, 0, NULL, NULL },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_psh = {
	.id = KGENOME_TEXTUAL_LANG_PSH,
	.typed = 1, .target = KGENOME_NUCLEO_T_PSH, .fold = 1, .fold_vars = 1,
	.sigil = '$', .append = "+=", .list_paren = 1, .list_at = 1, .concat = concat, .joins = joins, .chain = 1, .ns_drop = 1, .type_lit = "[",
	.eol_term = 1, .blocks = KGENOME_DTX_BLK_BRACE,
	.classfns = classfns, .n_classfns = sizeof classfns / sizeof classfns[0],
.interp_all = 1, .interp = 1,
	.cmd = 1, .cmd_ends = ";|(){}=", .cmd_start = "-", .cmd_bytes = "-.:\\", .cmd_pass = "&.",
	.pathsem = pathsem, .n_pathsem = sizeof pathsem / sizeof pathsem[0],
};
