/*
 * genome / textual_defect_work_clike - L5 of the lexer audit: textual_clike.c cs_scan -> skip_braces. In a C# interpolated string every "{" that is not "{{" asks
 * skip_braces for its "}", and one that never closes walks to the end of the text: `$"` followed by n "{ " cost n^2/2 (an aspx or a jsp page is one text). An
 * unclosed hole makes the rest of the string text; the later braces are not asked again.
 *
 * A second one, found by the same shapes (an aspx island of "$" or "@" repeated): cs_open reads the run of "$" and "@" in front of a quote to find out whether a string
 * opens, from every byte of the run, so a run of n bytes cost n^2/2 (L21 of this round). A run that ends in anything but a quote opens nothing from any byte in it.
 *
 * Asserted by WORK (textual_work.h) at 4 KiB and 16 KiB.
 *
 * Why the old tests missed it: (b) the c# cases close their holes or have one; a string of unclosed holes is no case.
 *
 * usage: textual_defect_work_clike   (built with -fsanitize-coverage=trace-pc)
 */

#include <textual/textual_clike.c>

#include "textual_work.h"

static int fails;

int main(void)
{
	static const char *const unit[] = { "{ ", "{a", "{{ {", "{\"", "{'", "{ \"a\" ", "{@" };
	static const char *const head[] = { "<% var s = $\"", "<% var s = $@\"", "<% var s = @$\"" };
	uint32_t k, h;

	if (!work_selfcheck())
		return 1;
	for (h = 0; h < sizeof head / sizeof head[0]; h++)
		for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
			char what[96];

			snprintf(what, sizeof what, "aspx `%s` + `%s` repeated", head[h], unit[k]);
			fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_ASPX, what, head[h], unit[k], "", 4096, 400);
		}
	/* the openers: a run of "$" and "@" that does not end in a quote, in an island */
	{
		static const char *const run[] = { "$", "@", "$@", "@$", "$$@", "@@$", "$ ", "@ ", "$a", "$\n" };

		for (k = 0; k < sizeof run / sizeof run[0]; k++) {
			char what[96];

			snprintf(what, sizeof what, "aspx `<%% ` + `%s` repeated", run[k]);
			fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_ASPX, what, "<% ", run[k], "", 4096, 400);
		}
	}
	fails += work_alphabet_shapes(KGENOME_TEXTUAL_LANG_ASPX, "aspx", "<% ", "a \"'{}$@\n/*", 3, 2048, 400);
	{
		uint32_t len;
		uint8_t *t = work_text("<% var s = $\"", "{ ", 4096, "", &len);

		(void)work_lex(KGENOME_TEXTUAL_LANG_ASPX, t, len);
		if (work_bound_seen < 1u) {
			printf("  FAIL a string of 4096 unclosed holes says no bound fired\n");
			fails++;
		}
		free(t);
		t = work_text("<% var s = $\"", "{ ", 2, "\"; %>", &len);
		(void)work_lex(KGENOME_TEXTUAL_LANG_ASPX, t, len);
		if (work_bound_seen) {
			printf("  FAIL a string of two unclosed holes says a bound fired\n");
			fails++;
		}
		free(t);
	}
	printf(fails ? "textual_defect_work_clike: %d FAILED\n" : "textual_defect_work_clike: ok\n", fails);
	return fails != 0;
}
