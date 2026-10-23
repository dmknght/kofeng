/*
 * genome / textual_defect_work_sh_lex - L3 of the lexer audit: sh_lex.c skip_group. An unclosed "((" was retried from the next byte, and every retry walked to
 * the end of the text: "(" written n times cost n^2/2 steps. The shell lexer answers once per text what a "((" that does not close is.
 *
 * Asserted by WORK, not time (textual_work.h): the same shape at 4 KiB and 16 KiB, work growing by at most 6 and at most 400 blocks a byte (the allowance of the failed groups is a page and the text: at -O0 a step is several blocks).
 *
 * Why the old tests missed it: (b) textual_sh_groups.c-style cases are lines; no test gives the lexer a text whose every byte is an opener that does not close, and no
 * test counted anything but spans.
 *
 * usage: textual_defect_work_sh_lex   (built with -fsanitize-coverage=trace-pc: UNIT_LIBS_textual_defect_work_sh_lex)
 */

#include <textual/sh/sh_lex.c>

#include "textual_work.h"

static int fails;

int main(void)
{
	uint32_t k;
	/* the shapes that make the retry run: openers, openers with strings and comments in the way, the arithmetic forms, and the same behind a command */
	static const char *const unit[] = { "(", "((", "$((", "( ", "(a", "(\"", "('", "(#", "(`", "((a)" };

	if (!work_selfcheck())
		return 1;
	for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
		char what[64];

		snprintf(what, sizeof what, "sh lex `%s` repeated", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_SH, what, "", unit[k], "", 4096, 400);
		snprintf(what, sizeof what, "sh lex echo; `%s` repeated", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_SH, what, "echo x\n", unit[k], "\n", 4096, 400);
	}
	fails += work_alphabet_shapes(KGENOME_TEXTUAL_LANG_SH, "sh", "", "a \"'$(){}`\\\n;<#", 3, 2048, 400);
	/* the bound SAYS it fired (kgenome_textual_lex_res.n_bound, kgenome_textual_form_res.n_bound), and does not when nothing failed that much */
	{
		uint32_t len;
		uint8_t *t = work_text("", "(", 4096, "", &len);
		struct kgenome_textual_form_req fq;
		struct kgenome_textual_form_res fr;
		uint8_t *o = malloc((size_t)KGENOME_TEXTUAL_FORM_CAP(len));

		(void)work_lex(KGENOME_TEXTUAL_LANG_SH, t, len);
		if (work_bound_seen < 1u) {
			printf("  FAIL a text of 4096 \"(\" says no bound fired\n");
			fails++;
		}
		fq = (struct kgenome_textual_form_req){ .in = t, .n = len, .lang = KGENOME_TEXTUAL_LANG_SH, .out = o, .cap = KGENOME_TEXTUAL_FORM_CAP(len) };
		(void)kgenome_textual_form(&fq, &fr);
		if (fr.n_bound < 1u) {
			printf("  FAIL the form of a text of 4096 \"(\" says no bound fired\n");
			fails++;
		}
		free(o);
		free(t);
		t = work_text("echo ((1+2))\n", "(( x\n", 3, "((", &len);
		(void)work_lex(KGENOME_TEXTUAL_LANG_SH, t, len);
		if (work_bound_seen) {
			printf("  FAIL a text of a few unclosed \"((\" says a bound fired\n");
			fails++;
		}
		free(t);
	}
	printf(fails ? "textual_defect_work_sh_lex: %d FAILED\n" : "textual_defect_work_sh_lex: ok\n", fails);
	return fails != 0;
}
