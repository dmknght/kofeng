/*
 * tcl_fn.c - the commands of tcl that are pure functions of their words, as the table the reader of tcl_cmd.c and the evaluator of command substitutions (`[string map ...]`) use
 * (textual.h, shape CMD: the name is the words that name the command, "string map"). Each runs a kuncoat op. [Unverified] against tclsh: none is on this machine; the rules are the
 * manual's (string(n), join(n), split(n), format(n), concat(n)).
 *
 *   string map mapping s       the mapping is a LIST of pairs written as text; at each place the first pair of the list wins and the scan goes on after the key. A mapping whose elements need
 *                              quoting (a brace, a quote, a backslash), an odd one, and -nocase are refused.
 *   string reverse s, tolower, toupper, length, range, repeat    characters, so the subject is ASCII; range counts from 0, includes the last, takes `end` and `end-N`, and a negative
 *                              number is refused (tcl clamps it, which no row says); repeat takes a count of nothing below 0.
 *   string trim s ?chars?, trimleft, trimright    the set to take off is the second word, or white space; the default is four bytes in the manual - space, tab, line break, carriage
 *                              return - while the implementation takes more (the vertical tab and the form feed among them), so a subject holding either is refused.
 *   string cat words.. / concat words..     the words joined by nothing / by a blank. concat TRIMS each word and drops an empty one, so a word with white space at either end or none is refused.
 *   join list sep, split s sep          the list is a tcl list written as text (elements by white space; an element needing quoting is refused) or the list another command made; split
 *                              takes one byte of separator (the argument is a SET of separators in tcl) and answers a list.
 *   format fmt args..          "%s" and "%%" only, exactly as many arguments as "%s" (tcl errors on too few and on too many).
 */

#include "tcl.h"

#define NO KGENOME_TEXTUAL_FN_NO
#define ASCII KGENOME_TEXTUAL_FN_ASCII
#define C KGENOME_TEXTUAL_K_CMD

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_ROW("string map", MAP, 2, 2, 1, 0, NO, 0, 0, C),
	KGENOME_TEXTUAL_ROW("string reverse", REVERSE, 1, 1, 0, NO, NO, 0, ASCII, C),
	KGENOME_TEXTUAL_ROW("string tolower", LOWER, 1, 1, 0, NO, NO, 0, ASCII, C),
	KGENOME_TEXTUAL_ROW("string toupper", UPPER, 1, 1, 0, NO, NO, 0, ASCII, C),
	KGENOME_TEXTUAL_ROW("string length", LENGTH, 1, 1, 0, NO, NO, 0, ASCII, C),
	KGENOME_TEXTUAL_ROW("string range", SLICE, 3, 3, 0, 1, 2, 3,
			    ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_ENDIDX | KGENOME_TEXTUAL_FN_INCL | KGENOME_TEXTUAL_FN_ENDWORD, C),
	KGENOME_TEXTUAL_ROW("string repeat", REPEAT, 2, 2, 0, 1, NO, 1, KGENOME_TEXTUAL_FN_NONNEG, C),
	KGENOME_TEXTUAL_ROW("string trim", TRIM, 1, 2, 0, 1, NO, 0, ASCII | KGENOME_TEXTUAL_FN_SETARG, C, .set = " \t\n\r", .bad = { "\v\f", NULL, NULL }),
	KGENOME_TEXTUAL_ROW("string trimleft", LTRIM, 1, 2, 0, 1, NO, 0, ASCII | KGENOME_TEXTUAL_FN_SETARG, C, .set = " \t\n\r", .bad = { "\v\f", NULL, NULL }),
	KGENOME_TEXTUAL_ROW("string trimright", RTRIM, 1, 2, 0, 1, NO, 0, ASCII | KGENOME_TEXTUAL_FN_SETARG, C, .set = " \t\n\r", .bad = { "\v\f", NULL, NULL }),
	KGENOME_TEXTUAL_ROW("string cat", JOIN, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_COLLECT_ALL, C, .set = ""),
	KGENOME_TEXTUAL_ROW("concat", JOIN, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_COLLECT_ALL | KGENOME_TEXTUAL_FN_NOEDGE, C, .set = " "),
	KGENOME_TEXTUAL_ROW("join", JOIN, 2, 2, 0, 1, NO, 0, 0, C, .opflags = KGENOME_TEXTUAL_CALL_WSLIST),
	KGENOME_TEXTUAL_ROW("split", SPLIT, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_ONESEP, C),
	KGENOME_TEXTUAL_ROW("format", FORMAT, 2, 2, 0, 1, NO, 0, KGENOME_TEXTUAL_FN_COLLECT_REST, C),
};

const struct kgenome_textual_fn_table kgenome_textual_tcl_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
