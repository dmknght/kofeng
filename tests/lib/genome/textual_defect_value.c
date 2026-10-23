/*
 * genome / textual_defect_value - L13 of the lexer audit: the value of a perl double-quoted literal (textual/perl/perl_value.c). Its refusal list for the escapes
 * that act on what follows - "\l \u \L \U \Q \E \F" - lacked the lower-case u: perl reads "a\ub" as "aB" (\u upper-cases the next character) and the value reader
 * answered "aub", which the form then wrote into the view as a constant (598 of 60061 perl literals of the audit's corpus differ). A literal whose value needs the
 * program's rules has no value here, and "\u" is one.
 *
 * Asserted, over ALL 256 bytes after a backslash in "a\<byte>Z": the escapes perl gives a meaning that depends on more than the byte itself are refused (NO_VALUE),
 * the simple escapes and the octal ones give their byte, and every other byte is itself (the backslash goes). The expected value is written from perlop, not
 * from the reader: the table below is the check.
 *
 * Why the old tests missed it: (b) textual_perl.c and textual_value.c list the escapes the author remembered (l, L, U, Q, E, F were in the list, u was not); no test
 * ran every byte after a backslash.
 *
 * usage: textual_defect_value
 */

#include "textual_check.h"

int main(void)
{
	uint32_t b;

	for (b = 0; b < 256; b++) {
		uint8_t lit[8] = { '"', 'a', '\\', (uint8_t)b, 'Z', '"', 0, 0 }, out[16];
		struct kgenome_textual_value_req rq = { .lang = KGENOME_TEXTUAL_LANG_PERL, .lit = lit, .len = 6, .open_len = 1, .close_len = 1, .out = out, .cap = sizeof out };
		struct kgenome_textual_value_res rs;
		enum kgenome_textual_status st = kgenome_textual_value(&rq, &rs);
		uint8_t want[4];
		uint32_t wn = 0;
		int refuse = b == 'x' || (b != 0 && strchr("cNoluULQEF$@", (int)b) != NULL);   /* $ and @ after a backslash are themselves: see below */
		const char *simple = "n\nt\tr\rf\fb\ba\ae\x1b";

		if (b == '$' || b == '@')
			refuse = 0;
		want[wn++] = 'a';
		if (b >= '0' && b <= '7') {
			want[wn++] = (uint8_t)(b - '0');
		} else {
			const char *p = b ? strchr(simple, (int)b) : NULL;

			if (p && (p - simple) % 2 == 0)
				want[wn++] = (uint8_t)p[1];
			else
				want[wn++] = (uint8_t)b;
		}
		want[wn++] = 'Z';
		if (refuse) {
			if (st != KGENOME_TEXTUAL_NO_VALUE) {
				printf("  FAIL \"a\\%c\" (byte 0x%02x): value of %u bytes, status %d - perl gives this escape a meaning that depends on more than its byte, so there is no value\n",
				       b >= 0x20 && b < 0x7f ? (int)b : '?', b, rs.n_out, (int)st);
				fails++;
			}
		} else if (st != KGENOME_TEXTUAL_OK || rs.n_out != wn || memcmp(out, want, wn)) {
			printf("  FAIL \"a\\%c\" (byte 0x%02x): status %d, %u bytes, wanted %u\n", b >= 0x20 && b < 0x7f ? (int)b : '?', b, (int)st, rs.n_out, wn);
			fails++;
		}
	}
	/* the same through qq with another delimiter, which is the same reader */
	{
		uint8_t lit[16] = "qq(a\\ub)", out[8];
		struct kgenome_textual_value_req rq = { .lang = KGENOME_TEXTUAL_LANG_PERL, .lit = lit, .len = 8, .open_len = 3, .close_len = 1, .out = out, .cap = sizeof out };
		struct kgenome_textual_value_res rs;

		CK(kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_NO_VALUE);
	}
	printf(fails ? "textual_defect_value: %d FAILED\n" : "textual_defect_value: ok\n", fails);
	return fails != 0;
}
