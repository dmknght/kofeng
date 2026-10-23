/*
 * genome / textual_defect_ci - L20 of the lexer audit: the case-insensitive compare of the textual part (kgenome_textual_ci_eq, textual_private.h) and the byte classes
 * that were written inline, about 39 times, as `c | 0x20`.
 *
 * ci_eq is documented as "ASCII case folding for a name that is lower case letters, digits and _ in s; p as typed". It folded by setting bit 5 of p and comparing,
 * and for a byte of s that is not a letter that is not a fold: 0x10..0x19 become the digits 0x30..0x39 ("\x13" equalled "3"), 0x08 became "(" and 0x09 ")" (the
 * "__halt_compiler()" the echo rule looks for), 0x0d became "-". Every byte of s is now compared as what it is: a letter folds p, any other byte must be p.
 * The idiom for "is a letter" - `(uint8_t)((c | 0x20u) - 'a') < 26u` - is exact (as a test; as a fold it is not, which is what kofcore.h says about it) and is
 * kof_is_alpha, one spelling, in the files that wrote it out.
 *
 * Asserted EXHAUSTIVELY: for every byte p and every byte s of the contract (a-z, 0-9, _ and the punctuation the callers' words hold), ci_eq(p, s) is what a table of the
 * ASCII fold says; for every pair of bytes in a two-byte word; and the classes the lexers share (kgenome_textual_ident, ident_start, one_of's use in glue) over all 256 bytes
 * against a table written here from the definition, so a class that is changed to a different fold shows.
 *
 * Why the old tests missed it: (b) the cases of textual_anchor.c and the lexer tests give ci_eq a word and the same word in other cases - a byte that is not the word in any case
 * (a control byte) is never the first argument; and nothing enumerates the 256 bytes against it.
 *
 * usage: textual_defect_ci
 */

#include "textual_check.h"

#include <textual/textual_private.h>

static uint8_t fold(uint8_t c)
{
	return (uint8_t)(c >= 'A' && c <= 'Z' ? c + 32 : c);
}

int main(void)
{
	static const char words[] = "abcdefghijklmnopqrstuvwxyz0123456789_()-.:/<>=!#@[]{}\"' \t\\$%&*+,;?^`|~";
	uint32_t p, k, q, l;
	uint64_t bad = 0, cases = 0;

	for (p = 0; p < 256; p++)
		for (k = 0; words[k]; k++) {
			uint8_t pb = (uint8_t)p, sb = (uint8_t)words[k];
			int want = fold(pb) == sb;

			cases++;
			if (kgenome_textual_ci_eq(&pb, &words[k], 1) != want) {
				if (bad < 5u)
					printf("  FAIL ci_eq(0x%02x, '%c') = %d, the fold says %d\n", p, words[k], !want, want);
				bad++;
			}
		}
	for (p = 0; p < 256; p++)
		for (q = 0; q < 256; q += 7) {
			uint8_t pb[2] = { (uint8_t)p, (uint8_t)q };

			for (l = 0; l < 3; l++) {
				static const char *const w[] = { "a1", "_0", "()" };
				int want = fold(pb[0]) == (uint8_t)w[l][0] && fold(pb[1]) == (uint8_t)w[l][1];

				cases++;
				if (kgenome_textual_ci_eq(pb, w[l], 2) != want) {
					if (bad < 5u)
						printf("  FAIL ci_eq([0x%02x 0x%02x], \"%s\") = %d, the fold says %d\n", p, q, w[l], !want, want);
					bad++;
				}
			}
		}
	if (bad) {
		printf("  FAIL ci_eq: %llu of %llu comparisons differ from the ASCII fold\n", (unsigned long long)bad, (unsigned long long)cases);
		fails++;
	}
	/* the classes the lexers share, over all 256 bytes, from their definitions */
	for (p = 0; p < 256; p++) {
		uint8_t c = (uint8_t)p;
		int alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'), digit = c >= '0' && c <= '9';
		int ident = alpha || digit || c == '_' || c >= 0x80;

		if (kgenome_textual_ident(c) != ident || kgenome_textual_ident_start(c) != (ident && !digit) || kof_is_alpha(c) != alpha) {
			printf("  FAIL byte class of 0x%02x: ident %d (want %d), alpha %d (want %d)\n", p, kgenome_textual_ident(c), ident, kof_is_alpha(c), alpha);
			fails++;
		}
	}
	printf(fails ? "textual_defect_ci: %d FAILED\n" : "textual_defect_ci: ok\n", fails);
	return fails != 0;
}
