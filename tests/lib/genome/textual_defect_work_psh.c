/*
 * genome / textual_defect_work_psh - the lexer of psh (psh/psh_lex.c), one of the ones the lexer audit did not read in full, attacked by WORK (textual_work.h): every
 * text of 1 to 3 bytes of the language's own syntax, repeated to 2 KiB and to 8 KiB, must cost work that grows linearly (at most x6 for x4 the bytes, and 100 blocks
 * a byte). No quadratic shape was found in it; this keeps it so.
 *
 * Why there was no test: (a) no test counted a lexer's work; they check the spans of texts a person would write.
 *
 * usage: textual_defect_work_psh   (built with -fsanitize-coverage=trace-pc: UNIT_LIBS_textual_defect_work_psh in mk/tests.mk)
 */

#include <textual/psh/psh_lex.c>

#include "textual_work.h"

int main(void)
{
	int bad;

	if (!work_selfcheck())
		return 1;
	bad = work_alphabet_shapes(KGENOME_TEXTUAL_LANG_PSH, "psh", "", "a \"'`@<>$#()\n", 3, 2048, 400);
	printf(bad ? "textual_defect_work_psh: %d FAILED\n" : "textual_defect_work_psh: ok\n", bad);
	return bad != 0;
}
