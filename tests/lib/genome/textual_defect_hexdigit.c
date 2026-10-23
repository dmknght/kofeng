/*
 * genome / textual_defect_hexdigit - the hex digit WRITERS had no table of their own: textual_subst.c (put_code, lower case: the \x and \u escapes of a literal),
 * libuncoat/decoders/codings.c (hexd, upper case: the hex and url and escape encoders) and kofcore/kofhash.c (lower case: a digest) each spelled
 * "0123456789abcdef" or "...ABCDEF", beside core's kof_hex_val for the READ side. One digit table is core's kof_hex_digit(v, upper), and the three call it.
 *
 * This is the lib side: every byte of every escape the literal writer makes (both spellings, \x and \u, all 256 values) is the digits kof_hex_digit(.,0) names, and
 * kof_hex_digit is the inverse of kof_hex_val for all 16 values in both cases. The uncoat side is tests/lib/uncoat/hex_alphabet.c (the encoders write kof_hex_digit(.,1)).
 *
 * Why the old tests missed it: (a) the duplicate has no wrong behaviour to fail on - both tables were right - so a result test cannot be red on it; the red here is that
 * the one function does not exist (the test does not compile against the unfixed tree) and, once it does, that the three writers agree with it byte for byte (mutants.out:
 * a table with one digit changed in any of the three places is caught).
 *
 * usage: textual_defect_hexdigit
 */

#include <stdio.h>
#include <string.h>

#include <kofcore.h>
#include <textual/textual_lang.h>
#include <textual/textual_private.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

int main(void)
{
	unsigned v, ctl;

	for (v = 0; v < 16u; v++) {
		CK(kof_hex_val(kof_hex_digit(v, 0)) == (int)v, "lower digit of %u reads back", v);
		CK(kof_hex_val(kof_hex_digit(v, 1)) == (int)v, "upper digit of %u reads back", v);
		CK(kof_hex_digit(v, 0) == (uint8_t)"0123456789abcdef"[v], "lower digit of %u is %c", v, "0123456789abcdef"[v]);
		CK(kof_hex_digit(v, 1) == (uint8_t)"0123456789ABCDEF"[v], "upper digit of %u is %c", v, "0123456789ABCDEF"[v]);
	}
	for (v = 16; v < 256u; v++)     /* only the low four bits are a digit */
		CK(kof_hex_digit(v, 0) == kof_hex_digit(v & 15u, 0) && kof_hex_digit(v, 1) == kof_hex_digit(v & 15u, 1), "kof_hex_digit(%u) reads the low nibble", v);
	for (ctl = 0; ctl < 2u; ctl++) {
		struct kgenome_textual_quote q = { .q = '"', .ctl = (uint8_t)(ctl ? 'u' : 'x') };

		for (v = 0; v < 256u; v++) {
			uint8_t b = (uint8_t)v, out[16];
			char want[16];
			uint32_t n = kgenome_textual_quote_write(&q, &b, 1, out);

			if (v < 0x20u || v == 0x7fu)
				snprintf(want, sizeof want, "\"\\%s%c%c\"", ctl ? "u00" : "x", kof_hex_digit(v >> 4, 0), kof_hex_digit(v & 15u, 0));
			else if (v == '"')
				snprintf(want, sizeof want, "\"\\\"\"");              /* the quote is escaped by a backslash */
			else
				snprintf(want, sizeof want, "\"%c\"", (int)v);
			CK(n == strlen(want) && memcmp(out, want, n) == 0, "literal writer, %c form, byte 0x%02x: [%.*s] wanted [%s]", ctl ? 'u' : 'x', v, (int)n, out, want);
		}
	}
	printf("textual_defect_hexdigit: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
