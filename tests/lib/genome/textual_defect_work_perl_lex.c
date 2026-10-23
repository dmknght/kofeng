/*
 * genome / textual_defect_work_perl_lex - L6 of the lexer audit: perl_lex.c tok_less. Every "<" where a term is expected looked for the end of its line first
 * (memchr for the line break) and then for its ">", so `<a>,<a>,<a>,...` on one line cost n^2/2: the line's end was found again for every glob. The ">" is looked
 * for up to the line's end in one pass, and a line that has none is remembered.
 *
 * Asserted by WORK (textual_work.h) at 4 KiB and 16 KiB. libc's memchr is not instrumented, so the test also wraps it (-Wl,--wrap=memchr in
 * UNIT_LIBS_textual_defect_work_perl_lex) and counts the bytes it is asked to search: that is where the old code spent its time.
 *
 * Why the old tests missed it: (b) textual_perl.c has `<STDIN>` and `<$fh>` lines; no case is a long line of globs.
 *
 * usage: textual_defect_work_perl_lex   (built with -fsanitize-coverage=trace-pc and --wrap=memchr)
 */

#include <textual/perl/perl_lex.c>

#include "textual_work.h"

static int fails;

/* the bytes memchr actually passes over while the counter is on: up to the byte it finds, or all it was given (an eighth of them is a block of work) */
void *__real_memchr(const void *s, int c, size_t n);
void *__wrap_memchr(const void *s, int c, size_t n);
void *__wrap_memchr(const void *s, int c, size_t n)
{
	void *r = __real_memchr(s, c, n);

	if (work_on)
		work_n += (r ? (size_t)((const char *)r - (const char *)s) + 1u : n) / 8u;
	return r;
}

int main(void)
{
	static const char *const unit[] = { "<a>,", "<a> ,", "(<a>,", "= <a>;", "<$a>,", "<a>\n<", "<,", "x ? <a> : <b>," };
	uint32_t k;

	if (!work_selfcheck())
		return 1;
	for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
		char what[64];

		snprintf(what, sizeof what, "perl `%s` repeated", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_PERL, what, "", unit[k], "", 4096, 400);
		snprintf(what, sizeof what, "perl my @a = `%s` repeated", unit[k]);
		fails += !work_lex_shape(KGENOME_TEXTUAL_LANG_PERL, what, "my @a = (", unit[k], ");", 4096, 400);
	}
	fails += work_alphabet_shapes(KGENOME_TEXTUAL_LANG_PERL, "perl", "", "a <>$,;()=\"'#\n", 3, 2048, 400);
	printf(fails ? "textual_defect_work_perl_lex: %d FAILED\n" : "textual_defect_work_perl_lex: ok\n", fails);
	return fails != 0;
}
