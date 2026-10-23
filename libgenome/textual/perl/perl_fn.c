/*
 * perl_fn.c - the functions perl builds a value with, as the table kgenome_textual_fn_find reads: chr(n), the byte n (0..255: above it chr makes a wide
 * character, which is not a byte), and lcfirst and ucfirst (the ASCII case of the first byte; a byte above 0x7f is left alone in a string that is not utf-8, which
 * is what a literal of this lib is). Checked against perl 5.44: tests/lib/genome/textual_fn_chr.c and tests/unit/script_fn_rows.c run every value through the
 * interpreter.
 *
 * lc and uc are rows of the EVALUATOR only (form EVAL: a name of two letters would switch the form's call stage off, its table being read by a hash of the first three
 * bytes), and run the case maps on an ASCII subject: perl's lc of a string with a byte above 0x7f depends on `use utf8`, `use locale` and the feature unicode_strings.
 * join(sep, a, b, ...) is the list operation (every argument after the separator is an element), and "x" is the operator that repeats a string: `"ab" x 3`. A negative count
 * gives "" in perl, and one that is not an integer is not read. The left side of "x" is a term as written, never a bracket: `("ab") x 3` is a LIST repetition in list context.
 *
 * NOT here: reverse (its answer depends on the context it is called in: `print reverse "ab"` is "ab", `$x = reverse "ab"` is "ba", and the row cannot see the context),
 * pack, sprintf and tr///.
 */

#include "perl.h"

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_FN_CHR("chr", 1, KGENOME_TEXTUAL_CHR_BYTE),
	KGENOME_TEXTUAL_FN_STR1("lcfirst", LCFIRST, 0),
	KGENOME_TEXTUAL_FN_STR1("ucfirst", UCFIRST, 0),
	KGENOME_TEXTUAL_ROW("lc", LOWER, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, KGENOME_TEXTUAL_FN_ASCII, KGENOME_TEXTUAL_K_EVAL),
	KGENOME_TEXTUAL_ROW("uc", UPPER, 1, 1, 0, KGENOME_TEXTUAL_FN_NO, KGENOME_TEXTUAL_FN_NO, 0, KGENOME_TEXTUAL_FN_ASCII, KGENOME_TEXTUAL_K_EVAL),
	KGENOME_TEXTUAL_ROW("join", JOIN, 2, 2, 0, 1, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_EVAL, .list = KGENOME_TEXTUAL_LIST_VARIADIC),
	KGENOME_TEXTUAL_ROW("x", REPEAT, 2, 2, 0, 1, KGENOME_TEXTUAL_FN_NO, 1, KGENOME_TEXTUAL_FN_NOGROUP, KGENOME_TEXTUAL_K_OP(1)),
};

const struct kgenome_textual_fn_table kgenome_textual_perl_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
