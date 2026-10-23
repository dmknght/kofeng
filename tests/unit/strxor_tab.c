/*
 * strxor_tab - the string table of the 111.exe family, through the whole engine.
 *
 * The module reads the table the way the program reads it: from the call sites of the one routine that
 * decrypts a string. Its arguments are two pointers and a length - `push len`, `mov edx, key`,
 * `mov ecx, payload`, `call` - and the plaintext is `payload[i] ^ key[i % strlen(key)]`, with neither
 * the length nor the key length in the data. So the test builds exactly that: a PE32 whose code calls
 * one routine forty-eight times and whose data is forty-eight records, each a key (sixteen hex digits), four
 * zeros, the ciphertext and four zeros.
 *
 * WHAT IS ASSERTED
 *
 *   PLAINTEXT   the child is the parent with every payload replaced by what it says, byte for byte,
 *               and every key blanked - the keys are a different sixteen digits in every build and
 *               would otherwise sit between every pair of recovered strings. A module that read a
 *               length from the wrong place would cut a string or run into its neighbour, and the
 *               comparison is on every byte of the child.
 *   BOTH FORMS  some sites put the length push in front of both movs and some between them, as the
 *               real ones do, and the child is right for both.
 *   NOT A TABLE a PE with the same code and fewer than SX_NEED records yields nothing, and so does one
 *               whose data holds a single hex constant followed by padding. The gate that dismisses a
 *               file is what made the module cheap enough to run on every PE: it costs about one
 *               instruction in a hundred on a clean one.
 *   NOT TWICE   a derived object is not offered back to the module that derived it, so the child is
 *               one object and not a chain.
 *
 * The images are built in memory and written to one file beside the build output, because a scan needs
 * a path.
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

#define BASE      0x400000u
#define TEXT_RVA  0x1000u
#define DATA_RVA  0x2000u
#define TEXT_OFF  0x400u
#define DATA_OFF  0x1400u
#define TEXT_LEN  0x1000u
#define DATA_LEN  0x1000u
#define FILE_LEN  (DATA_OFF + DATA_LEN + 0x2000u)   /* and an overlay: see build() */
#define ROUTINE   0xff0u            /* offset of the routine in the code */
#define SITE_LEN  80u               /* a site is 17 bytes; the rest is filler. See build() */
#define KEY_LEN   16u
#define N_REC     48u

static void p16(uint8_t *b, uint32_t at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}

static void p32(uint8_t *b, uint32_t at, uint32_t v)
{
	p16(b, at, (uint16_t)v);
	p16(b, at + 2u, (uint16_t)(v >> 16));
}

/* A PE32 with a code section (read, execute) and a data section (read, write). */
static void pe32(uint8_t *f)
{
	const uint32_t o = 0x98u, sec = o + 0xe0u;

	memset(f, 0, FILE_LEN);
	f[0] = 'M';
	f[1] = 'Z';
	p32(f, 0x3c, 0x80);
	memcpy(f + 0x80, "PE\0\0", 4);
	p16(f, 0x84, 0x014c);
	p16(f, 0x86, 2);
	p16(f, 0x94, 0xe0);
	p16(f, 0x96, 0x0102);
	p16(f, o, 0x010b);
	p32(f, o + 16, TEXT_RVA);
	p32(f, o + 20, TEXT_RVA);
	p32(f, o + 24, DATA_RVA);
	p32(f, o + 28, BASE);
	p32(f, o + 32, 0x200);
	p32(f, o + 36, 0x200);
	p16(f, o + 40, 6);
	p16(f, o + 48, 6);
	p32(f, o + 56, 0x3000);
	p32(f, o + 60, 0x400);
	p16(f, o + 68, 3);
	p32(f, o + 92, 16);
	memcpy(f + sec, ".text\0\0\0", 8);
	p32(f, sec + 8, TEXT_LEN);
	p32(f, sec + 12, TEXT_RVA);
	p32(f, sec + 16, TEXT_LEN);
	p32(f, sec + 20, TEXT_OFF);
	p32(f, sec + 36, 0x60000020u);
	memcpy(f + sec + 40u, ".data\0\0\0", 8);
	p32(f, sec + 40u + 8, DATA_LEN);
	p32(f, sec + 40u + 12, DATA_RVA);
	p32(f, sec + 40u + 16, DATA_LEN);
	p32(f, sec + 40u + 20, DATA_OFF);
	p32(f, sec + 40u + 36, 0xc0000040u);
}

/* The plain text of record `i`: distinct, printable, and of varying length. */
static size_t plain(unsigned i, char *out)
{
	static const char *const w[] = {
		"kernel32.dll", "LoadLibraryW", "GetProcAddress", "CreateToolhelp32Snapshot",
		"CryptUnprotectData", "sqlite3_open16", "SELECT host_key, path, name FROM cookies",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "wallet.dat", "logins.json",
		"formhistory.sqlite", "http://185.181.10.208/", "Content-Disposition: form-data; name=\"file\"",
		"\\ffcookies.txt", "\\CC.txt", "webextension@metamask.io", "%s\r\n", "\t- Login Data",
		"expires_utc", "encrypted_value"
	};

	return (size_t)sprintf(out, "%s", w[i % (sizeof w / sizeof w[0])]);
}

/* Sixteen lower case hex digits from the record number, a different set each. */
static void key_of(unsigned i, char *key)
{
	uint32_t s = 0x9e3779b9u * (i + 1u);
	unsigned k;

	for (k = 0; k < KEY_LEN; k++) {
		s = s * 1103515245u + 12345u;
		key[k] = "0123456789abcdef"[(s >> 16) & 15u];
	}
}

/*
 * SITES ARE SPREAD OUT, as they are in the family's code where the obfuscator puts junk between them:
 * the module reads a length from the pushes in the 64 bytes before a call, so sites packed 17 bytes
 * apart would put the neighbours' pushes in each other's window and a payload would be read a few
 * bytes long. That is a property of the module's window, not something this test is about.
 *
 * The module takes an immediate for an address when `immediate - image base` is below the object's size
 * (it is the module's test, and a real image is far larger than its table's rva). The image here is
 * padded by an overlay so that the data section's rva is inside it.
 *
 * `n` records into the data section, and the call sites into the code: returns where each record's
 * payload is, so the expected child can be built from the same numbers. A site's length push comes first
 * for two records in three and between the two movs for the rest.
 */
static void build(uint8_t *f, unsigned n, uint32_t rec_off[], uint16_t rec_len[], uint32_t key_off[])
{
	uint32_t d = 0;
	unsigned i;

	pe32(f);
	for (i = 0; i < n; i++) {
		char text[96], key[KEY_LEN + 1u];
		size_t l = plain(i, text), k;
		uint32_t c = TEXT_OFF + i * SITE_LEN, site = c;
		uint32_t key_va = BASE + DATA_RVA + d;
		uint32_t dat_va = BASE + DATA_RVA + d + KEY_LEN + 4u;

		key_of(i, key);
		memcpy(f + DATA_OFF + d, key, KEY_LEN);
		key_off[i] = DATA_OFF + d;
		d += KEY_LEN + 4u;
		rec_off[i] = DATA_OFF + d;
		rec_len[i] = (uint16_t)l;
		for (k = 0; k < l; k++)
			f[DATA_OFF + d + k] = (uint8_t)text[k] ^ (uint8_t)key[k % KEY_LEN];
		d += (uint32_t)l + 4u;
		if (i % 3u != 2u) {
			f[c++] = 0x6a;
			f[c++] = (uint8_t)l;
			f[c++] = 0xba;
			p32(f, c, key_va);
			c += 4u;
		} else {
			f[c++] = 0xba;
			p32(f, c, key_va);
			c += 4u;
			f[c++] = 0x6a;
			f[c++] = (uint8_t)l;
		}
		f[c++] = 0xb9;
		p32(f, c, dat_va);
		c += 4u;
		f[c++] = 0xe8;
		p32(f, c, (TEXT_OFF + ROUTINE) - (c + 4u));
		c += 4u;
		memset(f + c, 0xcc, site + SITE_LEN - c);
	}
	f[TEXT_OFF + ROUTINE] = 0xc3;
}

static uint8_t kid[FILE_LEN + 16u];
static uint64_t kid_n, n_kids;

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res,
		     void *user)
{
	(void)res;
	(void)user;
	if (!strstr(name, "//") || strstr(name, ":norm"))
		return 0;
	n_kids++;
	if (!kid_n && bytes && len <= sizeof kid) {
		memcpy(kid, bytes, (size_t)len);
		kid_n = len;
	}
	return 0;
}

static int scan(kof_scanner *sc, const char *path, const uint8_t *f, uint64_t n)
{
	struct kof_scan_option opt;
	FILE *fp = fopen(path, "wb");

	if (!fp || fwrite(f, 1, (size_t)n, fp) != (size_t)n) {
		if (fp)
			fclose(fp);
		return 0;
	}
	fclose(fp);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 8u << 20;
	opt.max_resident_bytes = 64u << 20;
	opt.max_object_bytes = 8u << 20;
	n_kids = 0;
	kid_n = 0;
	return kscan_path(sc, path, &opt, on_object, NULL) >= 0;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *path = "build/test/strxor_tab.tmp";
	static uint8_t f[FILE_LEN], want[FILE_LEN];
	uint32_t rec_off[N_REC], key_off[N_REC];
	uint16_t rec_len[N_REC];
	kof_engine *eng;
	kof_scanner *sc;
	unsigned i, bad;

	eng = keng_open(db);
	if (!eng) {
		printf("strxor tab: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		return 2;
	}

	/* A table of forty-eight: one child, and it is the parent with its strings readable. */
	build(f, N_REC, rec_off, rec_len, key_off);
	memcpy(want, f, FILE_LEN);
	for (i = 0; i < N_REC; i++) {
		char text[96];

		plain(i, text);
		memcpy(want + rec_off[i], text, rec_len[i]);
		memset(want + key_off[i], 0, KEY_LEN);
	}
	if (!scan(sc, path, f, FILE_LEN)) {
		fail("the scan could not run");
	} else {
		printf("  bảng %u record -> %llu object con\n", N_REC, (unsigned long long)n_kids);
		if (n_kids != 1)
			fail("a table of forty-eight records did not give exactly one child");
		else if (kid_n != FILE_LEN)
			fail("the child is not the parent's length");
		else {
			for (i = 0, bad = 0; i < FILE_LEN; i++)
				bad += kid[i] != want[i];
			if (bad)
				printf("  %u byte của con khác bản mong đợi\n", bad);
			if (bad)
				fail("the child differs from the parent with its strings readable");
		}
	}

	/* Under the floor: the same code and the same data, ten records. */
	build(f, 10u, rec_off, rec_len, key_off);
	if (!scan(sc, path, f, FILE_LEN))
		fail("the short table's scan could not run");
	else {
		printf("  bảng 10 record -> %llu object con\n", (unsigned long long)n_kids);
		if (n_kids != 0)
			fail("ten records were read as a table");
	}

	/* Not a table: the code of the table and a data section that holds one hex constant and padding. */
	build(f, N_REC, rec_off, rec_len, key_off);
	memset(f + DATA_OFF, 0, DATA_LEN);
	memcpy(f + DATA_OFF, "0123456789abcdef", 16);
	if (!scan(sc, path, f, FILE_LEN))
		fail("the code-only scan could not run");
	else {
		printf("  mã có call site, dữ liệu không phải bảng -> %llu object con\n",
		       (unsigned long long)n_kids);
		if (n_kids != 0)
			fail("call sites with no table behind them were read");
	}

	remove(path);
	kscan_free(sc);
	keng_close(eng);
	printf("strxor tab: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
