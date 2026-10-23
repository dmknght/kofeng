/*
 * uncoat / textcode_defect - L12 of the lexer audit, through <uncoat.h> alone: ASCII85. A partial last group is padded with the highest digit before it is read,
 * `acc * 85 + 84` once for each missing digit, unchecked: two or three digits that name a value past 2^32 once padded ("uu", "uuu") wrapped and gave bytes. A full
 * group that carries past 2^32 is CORRUPT; a padded one is the same group and is CORRUPT too. Asserted by a MODEL over every text of 1 to 7 characters of an alphabet
 * that holds the edge digits, and on the encoder's own output (every 1 and 2 byte string, a spread of 3 and 4, so the padded groups the format really makes still decode).
 *
 * Why the old tests missed it: (b) hostile_text.c decodes partial groups of valid encodings; the encoder never makes a group past the format's bound, so no test had one.
 *
 * usage: textcode_defect
 */

#include <uncoat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* the model of ASCII85 over a text of no whitespace: the decoder's contract written from the format (a group of five digits is a 32-bit value, a partial group of
 * 2 to 4 digits is padded with "u" and gives n - 1 bytes, one digit alone is damage, "z" stands for four zero bytes where a group begins, "~" ends the data) */
static enum kuncoat_status a85_model(const uint8_t *in, uint32_t n, uint8_t *out, uint32_t *w)
{
	uint64_t acc = 0;
	uint32_t i, have = 0;

	*w = 0;
	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if (c == '~')
			break;
		if (c == 'z' && have == 0) {
			memset(out + *w, 0, 4);
			*w += 4;
			continue;
		}
		if (c < '!' || c > 'u')
			return KUNCOAT_CORRUPT;
		acc = acc * 85u + (uint32_t)(c - '!');
		if (acc > 0xffffffffu)
			return KUNCOAT_CORRUPT;
		if (++have < 5u)
			continue;
		out[(*w)++] = (uint8_t)(acc >> 24);
		out[(*w)++] = (uint8_t)(acc >> 16);
		out[(*w)++] = (uint8_t)(acc >> 8);
		out[(*w)++] = (uint8_t)acc;
		acc = 0;
		have = 0;
	}
	if (have == 1u)
		return KUNCOAT_CORRUPT;
	if (have > 1u) {
		uint32_t j;

		for (j = have; j < 5u; j++)
			acc = acc * 85u + 84u;
		if (acc > 0xffffffffu)
			return KUNCOAT_CORRUPT;
		for (j = 0; j + 1u < have; j++)
			out[(*w)++] = (uint8_t)(acc >> (24u - 8u * j));
	}
	return KUNCOAT_OK;
}

static unsigned a85_bad;

static void a85_compare(const uint8_t *in, uint32_t n)
{
	uint8_t got[64], want[64];
	uint64_t pg = 0;
	uint32_t pw = 0, i;
	enum kuncoat_status sg = kuncoat_a85_decode(in, n, got, sizeof got, &pg), sw = a85_model(in, n, want, &pw);

	if (sg != sw || (sw == KUNCOAT_OK && (pg != pw || memcmp(got, want, pw)))) {
		if (a85_bad++ < 5u) {
			printf("  FAIL a85 [");
			for (i = 0; i < n; i++)
				putchar(in[i]);
			printf("]: status %d (%llu bytes), the format says %d (%u bytes)\n", (int)sg, (unsigned long long)pg, (int)sw, pw);
		}
		fails++;
	}
}

/* the encoder: the bytes of `in` as ASCII85, partial last group written with n + 1 digits */
static uint32_t a85_encode(const uint8_t *in, uint32_t n, uint8_t *out)
{
	uint32_t i, w = 0;

	for (i = 0; i < n; i += 4) {
		uint32_t take = n - i < 4u ? n - i : 4u, v = 0, k;
		uint8_t d[5];

		for (k = 0; k < 4u; k++)
			v = v << 8 | (k < take ? in[i + k] : 0u);
		for (k = 5; k-- > 0;) {
			d[k] = (uint8_t)('!' + v % 85u);
			v /= 85u;
		}
		for (k = 0; k < take + 1u; k++)
			out[w++] = d[k];
	}
	return w;
}

static void l12(void)
{
	static const char alpha[] = "!rstuz~";
	uint32_t na = (uint32_t)strlen(alpha), len, k, idx[8];
	uint8_t b[8];

	for (len = 1; len <= 7; len++) {
		for (k = 0; k < len; k++)
			idx[k] = 0;
		for (;;) {
			for (k = 0; k < len; k++)
				b[k] = (uint8_t)alpha[idx[k]];
			a85_compare(b, len);
			for (k = 0; k < len && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == len)
				break;
		}
	}
	CK(1);
	/* the encoder's own output decodes to what was encoded, for every 1 and 2 byte string and a spread of 3 and 4 byte ones */
	{
		uint32_t v;

		for (v = 0; v < 65536u * 4u; v++) {
			uint8_t in[4], enc[16], got[16];
			uint64_t pg = 0;
			uint32_t n = v < 256u ? 1u : v < 65536u ? 2u : v < 65536u * 2u ? 3u : 4u, e;

			in[0] = (uint8_t)v;
			in[1] = (uint8_t)(v >> 8);
			in[2] = (uint8_t)(v >> 13 ^ v >> 3);
			in[3] = (uint8_t)(v * 2654435761u >> 24);
			if (n == 1u)
				in[0] = (uint8_t)v;
			e = a85_encode(in, n, enc);
			if (kuncoat_a85_decode(enc, e, got, sizeof got, &pg) != KUNCOAT_OK || pg != n || memcmp(got, in, n)) {
				printf("  FAIL a85 round trip of %u bytes (v = %u)\n", n, v);
				fails++;
				break;
			}
		}
	}
	/* the three the audit names */
	{
		uint8_t out[8];
		uint64_t n;

		CK(kuncoat_a85_decode((const uint8_t *)"uu", 2, out, sizeof out, &n) == KUNCOAT_CORRUPT);
		CK(kuncoat_a85_decode((const uint8_t *)"uuu", 3, out, sizeof out, &n) == KUNCOAT_CORRUPT);
		CK(kuncoat_a85_decode((const uint8_t *)"uuuu", 4, out, sizeof out, &n) == KUNCOAT_CORRUPT);
		CK(kuncoat_a85_decode((const uint8_t *)"rr", 2, out, sizeof out, &n) == KUNCOAT_OK && n == 1u && out[0] == 0xffu);   /* "rr" is the one byte 0xff: padded, 4278804204 */
	}
}

int main(void)
{
	l12();
	if (a85_bad)
		printf("  FAIL a85: %u texts of the sweep decode differently from the format's rule\n", a85_bad);
	printf(fails ? "textcode_defect: %d FAILED\n" : "textcode_defect: ok\n", fails);
	return fails != 0;
}
