/*
 * hex_alphabet - the one hex digit table, and what each reader of it accepts.
 *
 * The hex readers are the lib's decoder (kuncoat_transform, KUNCOAT_ALGO_HEX,
 * libuncoat/decoders/codings.c), its URL decoder and its encoder, and the
 * normaliser's run-finder (analyzers/normalize/executables.c), which asks core's
 * kof_hex_val for the digit, kof_hex_byte for the pair, and then calls the lib to
 * decode. This pins what the table says and that the lib agrees with it for every
 * byte, as b64_alphabet.c does for base64:
 *
 *   - kof_hex_val is 0-9, a-f and A-F and nothing else (-1 for every other byte);
 *   - kof_hex_byte is the pair of digits, for all 65536 pairs, and -1 when either is
 *     not a digit;
 *   - the strict decoder takes the digits in pairs, skips exactly ' ' CR LF tab ':'
 *     and ',', and calls any other byte CORRUPT; an odd digit is TRUNCATED;
 *   - what the encoder writes is upper case digits and decode inverts encode;
 *   - the URL decoder reads %XX through the same pairing: strict refuses a `%` that
 *     is not an escape, LAX (the normaliser's reading) keeps it as the byte it is.
 */

#include <stdio.h>
#include <string.h>

#include <kofcore.h>
#include <uncoat.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static enum kuncoat_status run(uint32_t algo, uint32_t dir, uint32_t flags, const uint8_t *in,
			       uint64_t n, uint8_t *out, uint64_t cap, uint64_t *got)
{
	struct kuncoat_step s;

	memset(&s, 0, sizeof s);
	s.algo = algo;
	s.dir = dir;
	s.flags = flags;
	return kuncoat_transform(&s, in, n, out, cap, got);
}

int main(void)
{
	static const char digits[] = "0123456789abcdef";
	unsigned c, i, j;
	uint8_t out[16], enc[16];
	uint64_t got;

	for (c = 0; c < 256u; c++) {
		const char *lo = c ? strchr(digits, (int)c) : NULL;
		int v = lo ? (int)(lo - digits) : -1;
		int skip = c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' || c == ',';
		uint8_t in[2] = { 'a', (uint8_t)c };

		if (v < 0 && c >= 'A' && c <= 'F')
			v = (int)(c - 'A') + 10;
		CK(kof_hex_val((uint8_t)c) == v);
		got = 0;
		/* "a" then c: a digit completes the pair, a separator leaves the
		 * lone digit TRUNCATED, anything else is CORRUPT. */
		CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, 0, in, 2, out, sizeof out, &got) ==
		   (v >= 0 ? KUNCOAT_OK : skip ? KUNCOAT_TRUNCATED : KUNCOAT_CORRUPT));
	}

	for (i = 0; i < 256u; i++) {
		for (j = 0; j < 256u; j++) {
			uint8_t pair[2] = { (uint8_t)i, (uint8_t)j };
			int hi = kof_hex_val((uint8_t)i), lo = kof_hex_val((uint8_t)j);

			CK(kof_hex_byte(pair) == ((hi < 0 || lo < 0) ? -1 : (hi << 4) | lo));
		}
	}

	for (i = 0; i < 256u; i++) {
		uint8_t src[1] = { (uint8_t)i };
		uint64_t en = 0, dn = 0;
		unsigned k;

		CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_ENCODE, 0, src, 1, enc, sizeof enc, &en) == KUNCOAT_OK &&
		   en == 2u);
		for (k = 0; k < en; k++)
			CK(kof_hex_val(enc[k]) >= 0 && !(enc[k] >= 'a' && enc[k] <= 'f'));
		CK(run(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, 0, enc, en, out, sizeof out, &dn) == KUNCOAT_OK &&
		   dn == 1u && out[0] == (uint8_t)i);
		CK(kof_hex_byte(enc) == (int)i);
	}

	{
		static const uint8_t bad[] = "a%zzb+c";   /* a stray % and a plus */
		static const uint8_t good[] = "a%41b+c";

		got = 0;
		CK(run(KUNCOAT_ALGO_URL, KUNCOAT_DECODE, 0, bad, 7, out, sizeof out, &got) == KUNCOAT_CORRUPT);
		got = 0;
		CK(run(KUNCOAT_ALGO_URL, KUNCOAT_DECODE, KUNCOAT_F_LAX, bad, 7, out, sizeof out, &got) ==
		   KUNCOAT_OK && got == 7u && !memcmp(out, "a%zzb c", 7));
		got = 0;
		CK(run(KUNCOAT_ALGO_URL, KUNCOAT_DECODE, 0, good, 7, out, sizeof out, &got) == KUNCOAT_OK &&
		   got == 5u && !memcmp(out, "aAb c", 5));
		got = 0;
		CK(run(KUNCOAT_ALGO_URL, KUNCOAT_DECODE, 0, (const uint8_t *)"ab%4", 4, out, sizeof out, &got) ==
		   KUNCOAT_TRUNCATED);
	}
	printf("hex alphabet: one table, decoder, encoder and the URL pairing agree with it - %s\n",
	       fails ? "FAILED" : "ok");
	return fails ? 1 : 0;
}
