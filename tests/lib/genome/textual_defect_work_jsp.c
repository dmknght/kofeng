/*
 * genome / textual_defect_work_jsp - the work bound of jsp_lex.c's EL reader (kgenome_textual_jsp_markup -> el -> el_end),
 * never pinned by a test although the fix is already in the tree and its own comment names the shape by hand: "a text of
 * n/3 '${'' would otherwise scan to the end n/3 times" (jsp_lex.c, el()). Every sibling page/script lexer that got the
 * same kind of fix in the lexer audit round (L3, L5, L21: sh's "((", a c# interpolated string's "{", a run of "$"/"@")
 * has its own textual_defect_work_<lang>.c; jsp's did not, so a regression here would have gone unnoticed by `make -k unit`.
 *
 * THE SHAPE: a "${" (or "#{") that never finds its closing "}" before the end of the text, or before the next "<%", makes
 * el_end() walk to the end once; el() then sets lx->aux and every later "$"/"#" in the text is a single `if (lx->aux)
 * return 0` - O(1) - instead of one more O(n) walk. Without that flag a text of k such opens costs O(k*n): this asserts
 * the walk is linear in the text length at both n1 and 4*n1 bytes (work_grows_linearly, tests/lib/work_count.h).
 *
 * Asserted by WORK (textual_work.h) at 4 KiB and 16 KiB, the same scale as the sibling tests.
 *
 * usage: textual_defect_work_jsp   (built with -fsanitize-coverage=trace-pc; see mk/tests.mk's UNIT_LIBS_textual_defect_work_jsp)
 */

#include <textual/jsp/jsp_lex.c>

#include "textual_work.h"

static int fails;

int main(void)
{
	static const char *const unit[] = { "${", "#{", "${'", "${\"", "${a" };
	uint32_t k;

	if (!work_selfcheck())
		return 1;

	/* an EL open that never closes, repeated: each one used to scan to the end of the text looking for "}" */
	for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
		char what[64];

		snprintf(what, sizeof what, "jsp `%s` repeated, unclosed", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_JSP, what, "", unit[k], "", 4096, 400);
	}
	/* the general sweep: every short text of the construct's own alphabet, including "<%" (which must still end an
	 * EL scan that has not given up, and must still open an island after one that has) */
	fails += work_alphabet_shapes(KGENOME_TEXTUAL_LANG_JSP, "jsp", "", "${}#\"'\\<%>\n", 3, 2048, 400);

	printf(fails ? "textual_defect_work_jsp: %d FAILED\n" : "textual_defect_work_jsp: ok\n", fails);
	return fails != 0;
}
