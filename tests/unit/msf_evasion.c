/*
 * msf_evasion - the RC4 layer of metasploit's Windows evasion EXE, through the whole
 * engine.
 *
 * A PE32 is built from bytes: the template's marker, a push of the payload size, a
 * 40 letter key as text followed by a NUL, and the payload encrypted with that key
 * by an RC4 written out here the textbook way. The module finds the key by trying
 * every run of letters and checking whether the keystream turns the bytes under some
 * position into the payload's opening - so what is asserted is the whole of it: the
 * key was found, the keystream was the right one, and the plaintext came out.
 *
 * The RC4 is the host's now (kofmod/kofdecode.h), and the module only chooses the
 * key and the range; this pins that choice. The reference below is independent of
 * the engine's, so a mistake in both would have to be the same mistake.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

static void rc4_ref(const uint8_t *key, unsigned kl, const uint8_t *in, unsigned n,
		    uint8_t *out)
{
	uint8_t s[256], t;
	unsigned i, j = 0, x = 0, y = 0;

	for (i = 0; i < 256; i++)
		s[i] = (uint8_t)i;
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % kl]) & 255u;
		t = s[i]; s[i] = s[j]; s[j] = t;
	}
	for (i = 0; i < n; i++) {
		x = (x + 1u) & 255u;
		y = (y + s[x]) & 255u;
		t = s[x]; s[x] = s[y]; s[y] = t;
		out[i] = (uint8_t)(in[i] ^ s[(uint8_t)(s[x] + s[y])]);
	}
}

static void w16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *p, unsigned long v)
{
	w16(p, (unsigned)(v & 0xffffu));
	w16(p + 2, (unsigned)(v >> 16));
}

#define TEXT_OFF  0x200u
#define TEXT_RVA  0x1000u

/* A PE32 whose one section holds `body`. */
static uint64_t build_pe(uint8_t *f, const uint8_t *body, uint32_t n)
{
	uint8_t *nt = f + 0x40, *o = nt + 24, *sec = nt + 24 + 0xe0;
	uint32_t raw = (n + 0x1ffu) & ~0x1ffu;

	memset(f, 0, TEXT_OFF + raw);
	f[0] = 'M';
	f[1] = 'Z';
	w32(f + 0x3c, 0x40);
	memcpy(nt, "PE\0\0", 4);
	w16(nt + 4, 0x14c);                 /* i386            */
	w16(nt + 6, 1);
	w16(nt + 20, 0xe0);
	w16(nt + 22, 0x0102);               /* EXECUTABLE | 32BIT */
	w16(o, 0x10b);                      /* PE32            */
	w32(o + 16, TEXT_RVA);              /* entry           */
	w32(o + 28, 0x400000);              /* ImageBase       */
	w32(o + 32, 0x1000);
	w32(o + 36, 0x200);
	w32(o + 56, TEXT_RVA + ((raw + 0xfffu) & ~0xfffu));
	w32(o + 60, TEXT_OFF);
	w16(o + 68, 3);
	w32(o + 92, 16);
	memcpy(sec, ".text\0\0", 8);
	w32(sec + 8, raw);
	w32(sec + 12, TEXT_RVA);
	w32(sec + 16, raw);
	w32(sec + 20, TEXT_OFF);
	w32(sec + 36, 0x60000020ul);
	memcpy(f + TEXT_OFF, body, n);
	return TEXT_OFF + raw;
}

static uint64_t n_kids;
static uint8_t  last[8192];
static uint64_t last_n;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)res; (void)user;
	if (!strstr(name, "//"))
		return 0;
	n_kids++;
	last_n = len < sizeof last ? len : sizeof last;
	if (bytes)
		memcpy(last, bytes, (size_t)last_n);
	return 0;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *path = "build/test/msf_evasion.tmp";
	/* The payload's opening is what the module recognises: fc e8 ?? 00 00 00 60 89 e5. */
	uint8_t plain[96] = { 0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5 };
	static uint8_t body[1024], pe[4096], file_cipher[96];
	static const char keytext[] = "qKzXpLmNvBtRgHjWcYdFsAeUoIxZnMkTbQwEr";
	uint8_t key[40];
	struct kof_scan_option opt;
	kof_engine *eng;
	kof_scanner *sc;
	unsigned i, at = 0;
	uint64_t pn;
	FILE *fp;

	for (i = 9; i < sizeof plain; i++)
		plain[i] = (uint8_t)(0x31 + i * 7u);
	memset(key, 0, sizeof key);
	memcpy(key, keytext, strlen(keytext));
	for (i = strlen(keytext); i < sizeof key; i++)
		key[i] = (uint8_t)('a' + i % 26u);
	rc4_ref(key, sizeof key, plain, sizeof plain, file_cipher);

	/* the template's own marker, the push of the size, the key as text, the cipher */
	{
		static const uint8_t tmpl[9] = { 0x6a,0x04,0x6a,0x00,0x68,0xff,0x0f,0x1f,0x00 };

		memcpy(body + at, tmpl, sizeof tmpl);
		at += 16;
		body[at++] = 0x68;
		w32(body + at, sizeof plain);               /* push size   */
		at += 4;
		body[at++] = 0xff;
		body[at++] = 0x75;
		at += 8;
		memcpy(body + at, key, sizeof key);
		at += sizeof key;
		body[at++] = 0;                             /* NUL: the key is a C string */
		at += 4;
		memcpy(body + at, file_cipher, sizeof file_cipher);
		at += sizeof file_cipher;
	}
	pn = build_pe(pe, body, at);

	eng = keng_open(db);
	if (!eng) {
		printf("msf evasion: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	fp = fopen(path, "wb");
	if (!sc || !fp || fwrite(pe, 1, (size_t)pn, fp) != (size_t)pn) {
		printf("msf evasion: cannot write the sample\n");
		return 2;
	}
	fclose(fp);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1u << 20;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;
	kscan_path(sc, path, &opt, on_object, NULL);

	if (n_kids < 1)
		fail("the RC4 layer produced no child");
	else if (last_n < sizeof plain || memcmp(last, "MZ", 2) != 0)
		fail("the child is not a PE of the right length");
	else if (memcmp(last + last_n - sizeof plain, plain, sizeof plain) != 0)
		fail("the plaintext is wrong: the key or the keystream was not the one used");
	else
		printf("  RC4 layer -> %llu child(ren), PE header + %u bytes, plaintext exact\n",
		       (unsigned long long)n_kids, (unsigned)sizeof plain);

	remove(path);
	kscan_free(sc);
	keng_close(eng);
	printf("msf evasion: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
