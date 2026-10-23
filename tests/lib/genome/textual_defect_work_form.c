/*
 * genome / textual_defect_work_form - L7 of the lexer audit: textual_form.c kgenome_tform_skip_gap, which fold_ahead (after every literal) and call_name_at
 * (after every name that begins a call) ask for the next byte that is not white space or a comment. It read "#" as the start of a line comment, and "//" and
 * the slash-star opener as the start of a comment, in EVERY language: in javascript, vbscript, java, c#, coldfusion "#" is code, and in python the two slash openers are operators. A line
 * of n literals each followed by a "#" therefore walked to the end of the line n times (n^2/2), and what the form did after the false comment - no join, no call
 * taken - was a wrong answer as well as a slow one. Each language row now says which comment spellings it has, and the gap reads those.
 *
 * Asserted by WORK (textual_work.h): bytes the comment readers are asked to skip, at 4 KiB and 16 KiB, growth at most 6 and at most 100 a byte. textual_form.c is
 * #included (its skip_gap and the inlined line reader are what is counted) and kgenome_textual_c_block_end, in textual_clike.o, is wrapped
 * (-Wl,--wrap=kgenome_textual_c_block_end) and adds the bytes it passes over.
 *
 * Why the old tests missed it: (b) textual_gap.c pins the gap rule on php-shaped text (where all three are comments); no case puts a "#" after a literal in a language
 * that has none, and (c) the form tests compare the output, which a false comment only changes when a join follows it.
 *
 * usage: textual_defect_work_form   (built with -fsanitize-coverage=trace-pc and --wrap=kgenome_textual_c_block_end)
 */

#include <textual/textual_form.c>

#include "textual_work.h"

static int fails;

uint32_t __real_kgenome_textual_c_block_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed);
uint32_t __wrap_kgenome_textual_c_block_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed);
uint32_t __wrap_kgenome_textual_c_block_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed)
{
	uint32_t r = __real_kgenome_textual_c_block_end(p, end, i, closed);

	if (work_on)
		work_n += r - i;
	return r;
}

/* a hook that runs nothing: with it the form looks for calls to rewrite (call_name_at), and every call it finds stays as typed */
static int apply_none(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	(void)u;
	(void)c;
	(void)in;
	(void)len;
	(void)out;
	(void)cap;
	(void)n_out;
	return 0;
}

static uint64_t work_form(uint32_t lang, const uint8_t *in, uint32_t n, int calls)
{
	uint8_t *out = malloc((size_t)KGENOME_TEXTUAL_FORM_CAP(n));
	struct kgenome_textual_form_req rq = { .in = in, .n = n, .lang = lang, .out = out, .cap = KGENOME_TEXTUAL_FORM_CAP(n),
					       .apply = calls ? apply_none : NULL };
	struct kgenome_textual_form_res rs;

	if (!out)
		abort();
	WORK_BEGIN();
	(void)kgenome_textual_form(&rq, &rs);
	free(out);
	return work_end();
}

static void shape(uint32_t lang, const char *name, const char *head, const char *unit, int calls)
{
	uint32_t rep1 = (uint32_t)(4096u / strlen(unit)), l1, l2;
	uint8_t *a = work_text(head, unit, rep1, "", &l1), *b = work_text(head, unit, rep1 * 4u, "", &l2);
	char what[128];
	uint64_t w1 = work_form(lang, a, l1, calls), w2 = work_form(lang, b, l2, calls);

	snprintf(what, sizeof what, "form of %s `%s` + `%s` repeated", name, head, unit);
	fails += !work_grows_linearly(what, w1, l1, w2, l2, 400);
	free(a);
	free(b);
}

int main(void)
{
	/* a literal and then a spelling that is a comment in some other language but not in this one: the join test (fold_ahead) */
	static const char *const js[] = { "\"a\"#", "\"a\" #", "'a' #x" };
	static const char *const py[] = { "\"a\"//", "\"a\" //", "\"a\"/*", "\"a\" /*" };
	static const char *const vb[] = { "\"a\"#", "\"a\"//", "\"a\"/*" };
	/* a decoder's name and then the spelling: the call test (call_name_at) */
	static const char *const call_js[] = { "String.fromCharCode#", "String.fromCharCode #", "String.fromCharCode//" };
	static const char *const call_py[] = { "chr//", "chr/*", "chr#" };
	uint32_t k;

	if (!work_selfcheck())
		return 1;
	for (k = 0; k < sizeof js / sizeof js[0]; k++) {
		shape(KGENOME_TEXTUAL_LANG_JS, "js", "", js[k], 0);
		shape(KGENOME_TEXTUAL_LANG_JSP, "jsp", "<% ", js[k], 0);
		shape(KGENOME_TEXTUAL_LANG_CFM, "cfm", "<cfscript>", js[k], 0);
	}
	for (k = 0; k < sizeof py / sizeof py[0]; k++)
		shape(KGENOME_TEXTUAL_LANG_PY, "py", "", py[k], 0);
	for (k = 0; k < sizeof vb / sizeof vb[0]; k++)
		shape(KGENOME_TEXTUAL_LANG_VBS, "vbs", "", vb[k], 0);
	for (k = 0; k < sizeof call_js / sizeof call_js[0]; k++)
		shape(KGENOME_TEXTUAL_LANG_JS, "js", "", call_js[k], 1);
	for (k = 0; k < sizeof call_py / sizeof call_py[0]; k++)
		shape(KGENOME_TEXTUAL_LANG_PY, "py", "", call_py[k], 1);
	printf(fails ? "textual_defect_work_form: %d FAILED\n" : "textual_defect_work_form: ok\n", fails);
	return fails != 0;
}
