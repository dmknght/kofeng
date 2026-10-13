/*
 * b64_alphabet - the one base64 alphabet, and what each reader of it accepts.
 *
 * There are three readers of base64 text: the lib's decoder (kuncoat_transform,
 * libuncoat/decoders/codings.c), its encoder, and the normaliser's run-finder
 * (analyzers/normalize/executables.c), which asks core's kof_b64_val for the digit and
 * then calls the lib to decode. They share ONE digit table (kof_b64_val). This pins
 * what the table says and that the lib's decoder agrees with it for every byte:
 *
 *   - kof_b64_val is the standard alphabet and nothing else (no URL-safe - and _);
 *   - the strict decoder takes exactly the digits plus the text's own padding and
 *     wrapping ('=', CR, LF, space, tab) and calls any other byte CORRUPT;
 *   - the lax decoder (KUNCOAT_F_LAX, what the normaliser passes) skips every
 *     other byte instead;
 *   - everything the encoder writes is a digit, and decode inverts encode.
 *
 * What differs between the decoder's skip set and the run-finder's character set
 * is a decision and not drift: a run in a file may not contain a space (it is where
 * a payload ENDS), and the decoder must tolerate one (a wrapped line). The run set
 * is a subset of what the decoder takes, which is the property the normaliser's
 * decode-in-place relies on and is checked below as: every digit decodes.
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

static enum kuncoat_status b64(uint32_t dir, uint32_t flags, const uint8_t *in, uint64_t n,
			       uint8_t *out, uint64_t cap, uint64_t *got)
{
	struct kuncoat_step s;

	memset(&s, 0, sizeof s);
	s.algo = KUNCOAT_ALGO_B64;
	s.dir = dir;
	s.flags = flags;
	return kuncoat_transform(&s, in, n, out, cap, got);
}

int main(void)
{
	static const char alpha[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned c, i;
	uint8_t out[16], enc[16];
	uint64_t got;

	for (c = 0; c < 256u; c++) {
		const char *at = c ? strchr(alpha, (int)c) : NULL;
		int digit = at != NULL;
		int skip = c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t';
		uint8_t in[4] = { 'A', 'A', 'A', (uint8_t)c };

		CK(kof_b64_val((uint8_t)c) == (digit ? (int)(at - alpha) : -1));
		got = 0;
		CK((b64(KUNCOAT_DECODE, 0, in, 4, out, sizeof out, &got) == KUNCOAT_OK) ==
		   (digit || skip));
		got = 0;
		CK(b64(KUNCOAT_DECODE, KUNCOAT_F_LAX, in, 4, out, sizeof out, &got) == KUNCOAT_OK);
		if (digit)
			CK(got == 3u);
	}

	for (i = 0; i < 256u; i++) {
		uint8_t src[3] = { (uint8_t)i, (uint8_t)(i * 7u), (uint8_t)(255u - i) };
		uint64_t en = 0, dn = 0;
		unsigned k;

		CK(b64(KUNCOAT_ENCODE, 0, src, 3, enc, sizeof enc, &en) == KUNCOAT_OK && en == 4u);
		for (k = 0; k < en; k++)
			CK(kof_b64_val(enc[k]) >= 0);
		CK(b64(KUNCOAT_DECODE, 0, enc, en, out, sizeof out, &dn) == KUNCOAT_OK &&
		   dn == 3u && !memcmp(out, src, 3));
	}
	printf("base64 alphabet: one table, decoder and encoder agree with it - %s\n",
	       fails ? "FAILED" : "ok");
	return fails ? 1 : 0;
}
