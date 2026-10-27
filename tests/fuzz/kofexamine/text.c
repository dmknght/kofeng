/*
 * kofexamine/text - what a person TYPES or what a document's string holds, as the examiner reads it: the Go-to offset
 * (goto_parse.h), the typed key and the coding step (codec_ui.c, run through kuncoat_transform), hex respacing, the PDF text line
 * and the region label (kofinspect.c). Every row is a string driver: the bytes are the text.
 *
 *   kofexamine/goto_parse   an exact-size copy plus the terminator, against an oracle that cannot wrap (128-bit);
 *   kofexamine/codec        byte 0 picks a coding (0..9: 7 real, 3 not), byte 1 the direction, the rest is the key text (up to
 *                           the first 0) and the data; encode then decode gives the data back; every status is in the enum;
 *   kofexamine/hex_respace  the text and a room (byte 0): never a byte past the room, always terminated, non-hex text copied;
 *                           the known defect EX-3 (the tail cut) is COUNTED in the digest, not held;
 *   kofexamine/pdf_text     both modes, against the model of the rules in the source, any room;
 *   kofexamine/region_label an enum name taken from the bytes: always a suffix of the input;
 *   kofexamine/names        the vocabulary functions of kofinspect.c with a value from the bytes: a name is NULL (ELF types: "no name, print
 *                           the number") or a non-empty word, and the symbol-block names are never NULL.
 * (kof_goto_parse is a static function of a header; the surface reader of tools/check_layers.py does not list it, so its row has no .covers.)
 * Held for all: no read past the terminator, no write past the room (the output is a heap block of exactly the room, so
 * AddressSanitizer's redzone is the guard).
 */
#include <stdlib.h>
#include <string.h>

#include "../../../kofexamine/codec_ui.h"
#include "../../../kofexamine/goto_parse.h"
#include "../../../kofexamine/kofinspect.h"
#include "../../lib/fuzz_drv.h"

/* ------------------------------------------------------------------------------------- goto_parse */

static void goto_seeds(struct fz_corpus *c)
{
	static const char *const s[] = { "10", "0x10", "0n10", "ff", "ffffffffffffffe", "fffffffffffffffe", "ffffffffffffffff",
		"0n18446744073709551614", "0n18446744073709551615", "  20", "12g4", "0x", "-1", "10000000000000000" };
	unsigned i;

	for (i = 0; i < sizeof s / sizeof s[0]; i++)
		fz_corpus_add(c, s[i], s[i], strlen(s[i]));
}

static const char *const goto_dict[] = { "0x", "0n", "0X", "0N", "ffffffff", "9999999999", NULL };

static uint64_t goto_oracle(const char *s)
{
	unsigned __int128 n = 0;
	unsigned base = 16, digits = 0;

	while (*s == ' ' || *s == '\t')
		s++;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	else if (s[0] == '0' && (s[1] == 'n' || s[1] == 'N')) {
		s += 2;
		base = 10;
	}
	for (; *s; s++) {
		int d = -1;

		if (*s >= '0' && *s <= '9')
			d = *s - '0';
		else if (base == 16 && *s >= 'a' && *s <= 'f')
			d = *s - 'a' + 10;
		else if (base == 16 && *s >= 'A' && *s <= 'F')
			d = *s - 'A' + 10;
		if (d < 0 || d >= (int)base)
			return KOF_GOTO_BAD;
		n = n * base + (unsigned)d;
		if (n >= (unsigned __int128)KOF_GOTO_BAD)
			return KOF_GOTO_BAD;
		digits++;
	}
	return digits ? (uint64_t)n : KOF_GOTO_BAD;
}

static int goto_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char *t = malloc(n + 1u);
	uint64_t got, want;

	if (!t)
		return 0;
	memcpy(t, in, n);
	t[n] = 0;
	got = kof_goto_parse(t);
	want = goto_oracle(t);
	FZ_CHECK(c, got == want, "kof_goto_parse and the 128-bit oracle disagree");
	fz_digest(c, got);
	free(t);
	return got != KOF_GOTO_BAD;
}

FZ_ADAPTER(kx_goto, .name = "kofexamine/goto_parse", .shape = FZ_REQ, .seeds = goto_seeds,
	   .dict = goto_dict, .run = goto_run);

/* ----------------------------------------------------------------------------------------- codec */

static void codec_seeds(struct fz_corpus *c)
{
	uint8_t b[64];
	unsigned codec;

	for (codec = 0; codec < 9; codec++) {
		b[0] = (uint8_t)codec;
		b[1] = 0;
		memcpy(b + 2, "7\0Hello, world", 14);
		fz_corpus_add(c, "decode", b, 16);
		b[1] = 1;
		fz_corpus_add(c, "encode", b, 16);
	}
	{
		static const struct { uint8_t codec; const char *text; } r[] = { { 0, "SGVsbG8sIHdvcmxk" }, { 2, "%41%42+%2f" }, { 1, "414243" } };
		unsigned i;

		for (i = 0; i < 3; i++) {
			b[0] = r[i].codec;
			b[1] = 0;
			b[2] = 0;
			memcpy(b + 3, r[i].text, strlen(r[i].text));
			fz_corpus_add(c, "text", b, 3 + strlen(r[i].text));
		}
	}
}

static int codec_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint32_t codec, key;
	int encode, keyed, ok;
	uint8_t keybyte[1], kb2[1];
	struct kuncoat_step st, st2;
	const uint8_t *data;
	size_t klen, dn, cap, i;
	char keytxt[40];
	uint8_t *out, *back;
	uint64_t got = 0, got2 = 0;
	enum kuncoat_status s1, s2 = KUNCOAT_OK;

	if (n < 2)
		return 0;
	codec = in[0] % 9u;
	encode = in[1] & 1;
	for (klen = 0; 2 + klen < n && in[2 + klen] && klen < sizeof keytxt - 1u; klen++)
		keytxt[klen] = (char)in[2 + klen];
	keytxt[klen] = 0;
	data = in + 2 + klen + (2 + klen < n && !in[2 + klen] ? 1u : 0u);
	dn = n - (size_t)(data - in);
	key = kof_codec_key(keytxt);
	{
		/* the key of a text, restated: an optional 0x, then hex digits to the first byte that is not one, 32 bits kept */
		const char *q = keytxt;
		uint32_t want = 0;

		if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X'))
			q += 2;
		for (; *q; q++) {
			int d = *q >= '0' && *q <= '9' ? *q - '0' : *q >= 'a' && *q <= 'f' ? *q - 'a' + 10 : *q >= 'A' && *q <= 'F' ? *q - 'A' + 10 : -1;

			if (d < 0)
				break;
			want = (want << 4) | (uint32_t)d;
		}
		FZ_CHECK(c, key == want, "kof_codec_key: not the hex prefix of its text");
	}
	/* the key of a text is what its hex prefix says: never more than 32 bits, 0 for no digits */
	FZ_CHECK(c, klen > 0 || key == 0, "a key from no text is not zero");
	FZ_CHECK(c, strcmp(kof_codec_name(codec), "?") != 0 || codec >= KOF_CODEC_COUNT, "a real coding has no name");
	FZ_CHECK(c, strcmp(kof_codec_name(codec), "?") == 0 || codec < KOF_CODEC_COUNT, "a coding that does not exist has a name");
	keyed = kof_codec_keyed(codec);
	FZ_CHECK(c, !keyed || codec < KOF_CODEC_COUNT, "a coding that does not exist takes a key");
	ok = kof_codec_step(codec, key, encode, keybyte, &st);
	FZ_CHECK(c, ok == (codec < KOF_CODEC_COUNT), "kof_codec_step accepts what is not a coding, or refuses what is");
	if (!ok)
		return 0;
	cap = dn * 4u + 16u;
	out = malloc(cap);
	back = malloc(dn + 16u);
	if (!out || !back) {
		free(out);
		free(back);
		return 0;
	}
	s1 = kuncoat_transform(&st, data, dn, out, cap, &got);
	FZ_CHECK(c, (unsigned)s1 <= (unsigned)KUNCOAT_BAD_ARG, "transform status outside the enum");
	FZ_CHECK(c, got <= cap, "transform produced more than its room");
	fz_digest(c, (uint64_t)s1 ^ got << 4);
	for (i = 0; i < got && i < 64; i++)
		fz_digest(c, out[i]);
	/* URL text with no escape in it is not URL-coded text: its reading is CORRUPT by design (measured: decode("d") is KUNCOAT_CORRUPT),
	 * so only a written text that holds a '%' is held to read back */
	if (encode && s1 == KUNCOAT_OK && (codec != KOF_CODEC_URL || memchr(out, '%', (size_t)got))) {
		/* what was written one way reads back the other: the coding is a bijection on what it wrote */
		kof_codec_step(codec, key, 0, kb2, &st2);
		s2 = kuncoat_transform(&st2, out, got, back, dn + 16u, &got2);
		FZ_CHECK(c, s2 == KUNCOAT_OK, "what a coding wrote does not read back");
		FZ_CHECK(c, got2 == dn && !memcmp(back, data, dn), "decode(encode(x)) is not x");
	}
	free(out);
	free(back);
	return (int)s1;
}

FZ_ADAPTER(kx_codec, .name = "kofexamine/codec", .covers = "kof_codec_name kof_codec_keyed kof_codec_key kof_codec_step",
	   .shape = FZ_REQ, .seeds = codec_seeds, .run = codec_run);

/* ---------------------------------------------------------------------------------- hex_respace */

static void respace_seeds(struct fz_corpus *c)
{
	static const char *const s[] = { "aabbcc", "a a b b", "4d5a9000", "zz", "", "0 1 2 3 4 5 6 7 8 9", "ABCDEF" };
	uint8_t b[64];
	unsigned i;

	for (i = 0; i < sizeof s / sizeof s[0]; i++) {
		b[0] = (uint8_t)(8 + 7 * i);
		memcpy(b + 1, s[i], strlen(s[i]));
		fz_corpus_add(c, s[i], b, 1 + strlen(s[i]));
	}
}

static int respace_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	size_t cap, tl, i, digits = 0;
	char *text, *out;
	int hexonly = 1;
	size_t len;

	if (n < 1)
		return 0;
	cap = 1u + in[0] % 80u;
	tl = n - 1u;
	text = malloc(tl + 1u);
	out = malloc(cap);
	if (!text || !out) {
		free(text);
		free(out);
		return 0;
	}
	/* the text is the rest of the bytes up to the first 0: a C string */
	for (i = 0; i < tl && in[1 + i]; i++)
		text[i] = (char)in[1 + i];
	text[i] = 0;
	for (i = 0; text[i]; i++) {
		unsigned char ch = (unsigned char)text[i];
		int hx = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');

		if (!hx && ch != ' ' && ch != '\t')
			hexonly = 0;
		digits += (size_t)hx;
	}
	kof_hex_respace(text, out, cap);
	len = strnlen(out, cap);
	FZ_CHECK(c, len < cap, "kof_hex_respace left the output unterminated inside its room");
	if (!hexonly) {
		char *want = malloc(cap);

		if (want) {
			snprintf(want, cap, "%s", text);
			FZ_CHECK(c, !strcmp(out, want), "text with a non-hex byte was not copied as it is");
			free(want);
		}
	} else {
		/* what comes out holds the digits in order and nothing else but spaces: the digits are a prefix of the input's */
		size_t k = 0;

		for (i = 0; i < len; i++) {
			unsigned char ch = (unsigned char)out[i];

			if (ch == ' ' || ch == '\t')
				continue;
			FZ_CHECK(c, ch < 0x80 && ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')),
				 "a respaced pattern holds a byte that is not a hex digit");
			k++;
		}
		FZ_CHECK(c, k <= digits, "a respaced pattern holds more digits than the input");
		/* EX-3: fewer digits than the input AND not the input as it was is the cut tail. Counted, not held. */
		fz_digest(c, k < digits && strncmp(out, text, len) != 0);
	}
	fz_digest(c, len);
	for (i = 0; i < len; i++)
		fz_digest(c, (unsigned char)out[i]);
	free(text);
	free(out);
	return (int)len;
}

FZ_ADAPTER(kx_respace, .name = "kofexamine/hex_respace", .covers = "kof_hex_respace", .shape = FZ_REQ, .seeds = respace_seeds,
	   .run = respace_run);

/* -------------------------------------------------------------------------------------- pdf_text */

static void pdf_seeds(struct fz_corpus *c)
{
	static const uint8_t lit[] = { 0, 40, 'H', 'e', 'l', 'l', 'o', '\\', 'n', '\\', '(', 'x' };
	static const uint8_t hex[] = { 1, 40, '4', '8', '6', '5', ' ', '6', 'C', '6', 'C', '6' };
	static const uint8_t wide[] = { 0, 40, 0xfe, 0xff, 0, 'A', 0, 'B', 0, 'C' };
	static const uint8_t hexwide[] = { 1, 40, 'F', 'E', 'F', 'F', '0', '0', '4', '1', '0', '0', '4', '2' };

	fz_corpus_add(c, "literal", lit, sizeof lit);
	fz_corpus_add(c, "hex", hex, sizeof hex);
	fz_corpus_add(c, "utf16", wide, sizeof wide);
	fz_corpus_add(c, "hex-utf16", hexwide, sizeof hexwide);
}

/* The model of the rules the source comment states, written as a plain pass (not a copy of the code's buffer handling). */
static uint32_t pdf_model(const uint8_t *p, size_t n, int hex, char *out, uint32_t cap)
{
	uint8_t b[512];
	size_t have = 0, i;
	uint32_t w = 0;
	int hi = -1, wide;

	out[0] = 0;
	for (i = 0; i < n && have < 512; i++) {
		if (hex) {
			int v = p[i] >= '0' && p[i] <= '9' ? p[i] - '0' : p[i] >= 'a' && p[i] <= 'f' ? p[i] - 'a' + 10
			      : p[i] >= 'A' && p[i] <= 'F' ? p[i] - 'A' + 10 : -1;

			if (v < 0)
				continue;
			if (hi < 0)
				hi = v;
			else {
				b[have++] = (uint8_t)(hi * 16 + v);
				hi = -1;
			}
		} else if (p[i] == '\\' && i + 1 < n) {
			uint8_t e = p[++i];

			b[have++] = e == 'n' ? '\n' : e == 'r' ? '\r' : e == 't' ? '\t' : e == 'b' ? '\b' : e == 'f' ? '\f' : e;
		} else
			b[have++] = p[i];
	}
	if (hex && hi >= 0 && have < 512)
		b[have++] = (uint8_t)(hi * 16);
	wide = have >= 2 && b[0] == 0xfe && b[1] == 0xff;
	for (i = wide ? 3u : 0u; i < have && w + 1u < cap; i += wide ? 2u : 1u)
		out[w++] = b[i] >= 0x20 && b[i] < 0x7f ? (char)b[i] : '.';
	out[w] = 0;
	return w;
}

static int pdf_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint32_t cap, r, w;
	char *out, *want;
	int hex;

	if (n < 2)
		return 0;
	hex = in[0] & 1;
	cap = 1u + in[1] % 90u;
	out = malloc(cap);
	want = malloc(cap);
	if (!out || !want) {
		free(out);
		free(want);
		return 0;
	}
	r = kof_pdf_text(in + 2, n - 2u, hex, out, cap);
	w = pdf_model(in + 2, n - 2u, hex, want, cap);
	FZ_CHECK(c, r < cap && out[r] == 0, "kof_pdf_text: the count is not the length of a terminated string inside the room");
	FZ_CHECK(c, r == w && !memcmp(out, want, w + 1u), "kof_pdf_text and the model of its rules disagree");
	fz_digest(c, r);
	free(out);
	free(want);
	return (int)r;
}

FZ_ADAPTER(kx_pdftext, .name = "kofexamine/pdf_text", .covers = "kof_pdf_text", .shape = FZ_REQ, .seeds = pdf_seeds, .run = pdf_run);

/* ------------------------------------------------------------------------------- region_label */

static void label_seeds(struct fz_corpus *c)
{
	static const char *const s[] = { "KOF_SCAN_ELF_CODE", "KOF_SCAN_ALL", "KOF_SCAN_SYM_IMP", "A_B_C", "x" };
	unsigned i;

	for (i = 0; i < sizeof s / sizeof s[0]; i++)
		fz_corpus_add(c, s[i], s[i], strlen(s[i]));
}

static int label_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char *t = malloc(n + 1u);
	const char *r;
	size_t i, us = 0;

	if (!t)
		return 0;
	for (i = 0; i < n && in[i]; i++)
		t[i] = (char)in[i];
	t[i] = 0;
	r = kof_region_label(t);
	FZ_CHECK(c, r >= t && r <= t + strlen(t), "kof_region_label returned something that is not a suffix of its input");
	for (i = 0; t[i]; i++)
		us += t[i] == '_';
	/* fewer than two separators: the whole name; otherwise the part after the third (or the second) */
	FZ_CHECK(c, us >= 2 || r == t, "a name with fewer than two underscores was cut");
	fz_digest(c, (uint64_t)(r - t));
	free(t);
	return 0;
}

FZ_ADAPTER(kx_label, .name = "kofexamine/region_label", .covers = "kof_region_label", .shape = FZ_REQ, .seeds = label_seeds,
	   .run = label_run);

/* ------------------------------------------------------------------------------------------ names */

static void names_seeds(struct fz_corpus *c)
{
	static const uint8_t b[] = { 0, 1, 0, 0, 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };

	fz_corpus_add(c, "names", b, sizeof b);
}

static int names_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint32_t v = 0;
	uint8_t blk[24];
	const char *s;
	size_t bn;

	if (n < 8)
		return 0;
	memcpy(&v, in + 1, 4);
	memset(blk, 0, sizeof blk);
	bn = n - 5 < sizeof blk ? n - 5 : sizeof blk;
	memcpy(blk, in + 5, bn);
	s = kof_inspect_ptype_name(v);
	FZ_CHECK(c, !s || (s[0] && !strncmp(s, "PT_", 3)), "a program header type name that is empty or not a PT_ word");
	fz_digest(c, s ? strlen(s) : 0);
	s = kof_inspect_shtype_name(v);
	FZ_CHECK(c, !s || (s[0] && !strncmp(s, "SHT_", 4)), "a section type name that is empty or not an SHT_ word");
	fz_digest(c, s ? strlen(s) : 0);
	s = kof_inspect_subtype_name(in[5], in[6]);
	FZ_CHECK(c, !s || s[0], "a subtype name that is the empty string");
	fz_digest(c, s ? strlen(s) : 0);
	s = kof_sym_type_name(in[5]);
	FZ_CHECK(c, s && s[0], "a symbol type with no name");
	s = kof_sym_bind_name(in[6]);
	FZ_CHECK(c, s && s[0], "a symbol binding with no name");
	s = kof_sym_vis_name(in[7]);
	FZ_CHECK(c, s && s[0], "a symbol visibility with no name");
	s = kof_sym_origin_name(in[0] & 1 ? blk : NULL, (uint32_t)bn);
	FZ_CHECK(c, s && s[0], "a symbol origin with no name");
	FZ_CHECK(c, (in[0] & 1) || !strcmp(s, "none"), "an origin of no block is not none");
	fz_digest(c, strlen(s));
	return 0;
}

FZ_ADAPTER(kx_names, .name = "kofexamine/names",
	   .covers = "kof_inspect_ptype_name kof_inspect_shtype_name kof_inspect_subtype_name kof_sym_type_name kof_sym_bind_name "
		     "kof_sym_vis_name kof_sym_origin_name",
	   .shape = FZ_REQ, .seeds = names_seeds, .run = names_run);
