/*
 * genome / textual_defect_work_vb - L4 of the lexer audit: textual_vb.c vb_bracket_end. Every "[" asked for its "]" by walking to the end of the line, so a line of
 * n brackets cost n^2/2 (a minified .vbs or a page's island is one line). The answer for a "[" that has no "]" before the line ends is the same for every later "["
 * of that line, and is given once.
 *
 * Asserted by WORK (textual_work.h) for vbscript and for classic asp, at 4 KiB and 16 KiB.
 *
 * Why the old tests missed it: (b) the vbs cases hold a handful of brackets in short lines; a line of brackets is no case.
 *
 * usage: textual_defect_work_vb   (built with -fsanitize-coverage=trace-pc)
 */

#include <textual/textual_vb.c>

#include "textual_work.h"

static int fails;

int main(void)
{
	static const char *const unit[] = { "[", "[a", "[a ", "x[", "[[", "[a\"", "[#" };
	uint32_t k;

	if (!work_selfcheck())
		return 1;
	for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
		char what[64];

		snprintf(what, sizeof what, "vbs `%s` repeated", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_VBS, what, "", unit[k], "", 4096, 400);
		snprintf(what, sizeof what, "asp `<%% %s` repeated", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_ASP, what, "<% ", unit[k], "", 4096, 400);
	}
	fails += work_alphabet_shapes(KGENOME_TEXTUAL_LANG_VBS, "vbs", "", "a \"'[]_&#:\n", 3, 2048, 400);
	fails += work_alphabet_shapes(KGENOME_TEXTUAL_LANG_ASP, "asp", "<% ", "a \"'[]_&#:%>\n", 3, 2048, 400);
	printf(fails ? "textual_defect_work_vb: %d FAILED\n" : "textual_defect_work_vb: ok\n", fails);
	return fails != 0;
}
