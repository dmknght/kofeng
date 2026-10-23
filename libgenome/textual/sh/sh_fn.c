/*
 * sh_fn.c - what the shell changes a word with, as the table kgenome_textual_fn_find and the readers of sh_cmd.c use (textual.h, enum kgenome_textual_shape): the EXPANSIONS of a
 * variable (`${x//a/b}`: shape EXPAND, spelled by its operator) and the COMMANDS that are pure functions of their words (`echo`, `printf`, `rev`, `tr`: shape CMD). Each runs one of kuncoat's
 * ops - REPLACE, CUTHEAD, CUTTAIL, SLICE, CASE, LENGTH, JOIN, FORMAT, REVERSE, TRANSLATE - the ones php's str_replace, substr, strtoupper and strrev run, with what the shell does that
 * the op does not as data in the row. Checked against bash 5.3 on this machine: tests/unit/script_cmds.c runs every accepted case through it. dash has no `//` and `^^`: a script that
 * uses them runs under bash, which is what these rows say.
 *
 * EXPANSIONS (the variable's value is argument 0, the operands follow):
 *   - ${x//p/r} and ${x/p/r}: every match, or the first. The pattern is a GLOB, so one holding * ? [ or a backslash is refused (the plain text is the pattern only without them), and so is
 *     one with # or % (they anchor); an empty pattern is refused. bash 5.2 added `patsub_replacement`, on by default: "&" in the replacement is the match, so "&" and a backslash are refused there.
 *   - ${x#p} ${x##p} ${x%p} ${x%%p}: the pattern without a glob character is plain text, and the shortest and the longest match are the same (CUTHEAD, CUTTAIL).
 *   - ${x:o:l}: offset and length are DIGITS (an arithmetic expression, a sign - `${x:-0}` is a default value, not an offset - are refused); bash counts characters, so the subject is ASCII.
 *   - ${x^^} ${x^} ${x,,} ${x,}: the case maps, ASCII (the locale maps the rest), with no pattern. ${#x}: the number of characters, ASCII.
 * COMMANDS (their output is the value, the trailing line breaks which `$(..)` takes off included):
 *   - echo words..: the words joined by a blank; a leading -n changes nothing about the value, -e and -E are refused (echo reads backslashes then).
 *   - printf format words..: only "%s", "%%" and \n \t \\ in the format, run again over the arguments left over (the shell's rule), a "-" first is an option (NODASH).
 *   - rev and tr read what a pipe brings: rev reverses each LINE, so a subject with a line break is refused, and the subject is ASCII (it reverses characters); tr takes two sets with ranges
 *     (a-z) and no class, escape or option, of as many bytes each (tr pads the shorter: refused).
 * base64 -d and the decoders are the decode hook's, not rows.
 */

#include "sh.h"

#define NO KGENOME_TEXTUAL_FN_NO
#define ASCII KGENOME_TEXTUAL_FN_ASCII
#define X KGENOME_TEXTUAL_K_EXPAND
#define GLOB "*?[\\"

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_ROW("//", REPLACE, 2, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY, X, .sep = '/', .bad = { NULL, GLOB "#%", "&\\" }),
	KGENOME_TEXTUAL_ROW("/", REPLACE, 2, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_NOEMPTY | KGENOME_TEXTUAL_FN_FIRST, X, .sep = '/', .bad = { NULL, GLOB "#%", "&\\" }),
	KGENOME_TEXTUAL_ROW("#", CUTHEAD, 2, 2, 0, 1, NO, 0, 0, X, .bad = { NULL, GLOB, NULL }),
	KGENOME_TEXTUAL_ROW("##", CUTHEAD, 2, 2, 0, 1, NO, 0, 0, X, .bad = { NULL, GLOB, NULL }),
	KGENOME_TEXTUAL_ROW("%", CUTTAIL, 2, 2, 0, 1, NO, 0, 0, X, .bad = { NULL, GLOB, NULL }),
	KGENOME_TEXTUAL_ROW("%%", CUTTAIL, 2, 2, 0, 1, NO, 0, 0, X, .bad = { NULL, GLOB, NULL }),
	KGENOME_TEXTUAL_ROW(":", SLICE, 2, 3, 0, 1, 2, 3, ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_PLAINNUM | KGENOME_TEXTUAL_FN_BASHSLICE, X, .sep = ':'),
	KGENOME_TEXTUAL_ROW("^^", UPPER, 1, 1, 0, NO, NO, 0, ASCII, X),
	KGENOME_TEXTUAL_ROW("^", UCFIRST, 1, 1, 0, NO, NO, 0, ASCII, X),
	KGENOME_TEXTUAL_ROW(",,", LOWER, 1, 1, 0, NO, NO, 0, ASCII, X),
	KGENOME_TEXTUAL_ROW(",", LCFIRST, 1, 1, 0, NO, NO, 0, ASCII, X),
	KGENOME_TEXTUAL_ROW("#", LENGTH, 1, 1, 0, NO, NO, 0, ASCII | KGENOME_TEXTUAL_FN_PREFIXOP, X),
	KGENOME_TEXTUAL_ROW("echo", JOIN, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_COLLECT_ALL | KGENOME_TEXTUAL_FN_ECHOOPT, KGENOME_TEXTUAL_K_CMD, .set = " "),
	KGENOME_TEXTUAL_ROW("printf", FORMAT, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_COLLECT_REST | KGENOME_TEXTUAL_FN_NODASH, KGENOME_TEXTUAL_K_CMD,
			    .opflags = KGENOME_TEXTUAL_CALL_REUSE | KGENOME_TEXTUAL_CALL_ESC),
	KGENOME_TEXTUAL_ROW("rev", REVERSE, 1, 1, 0, NO, NO, 0, KGENOME_TEXTUAL_FN_STDIN | ASCII, KGENOME_TEXTUAL_K_CMD, .bad = { "\n", NULL, NULL }),
	KGENOME_TEXTUAL_ROW("tr", TRANSLATE, 3, 3, 0, 1, 2, 0, KGENOME_TEXTUAL_FN_STDIN | KGENOME_TEXTUAL_FN_NODASH, KGENOME_TEXTUAL_K_CMD, .opflags = KGENOME_TEXTUAL_CALL_RANGES,
			    .bad = { NULL, "[\\", "[\\" }),
};

const struct kgenome_textual_fn_table kgenome_textual_sh_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
