/*
 * msf_xor - the self-describing XOR wrapper, through the whole engine.
 *
 * The module reads three things out of the stub - the key terminator, the two
 * byte end marker, and the key - and every one of them is chosen per sample by
 * msfvenom. A test that built one wrapper would pass on a module that hard coded
 * any of them, which is exactly the bug this file exists to catch: the first
 * version of the module spelled one sample's end marker as a constant, opened
 * the sample it was written against, and read the other three past their real
 * end.
 *
 * So the wrappers here are built with DIFFERENT terminators, markers and key
 * lengths on each layer, and the assertion is on the bytes that come out.
 *
 *
 * WHAT IS ASSERTED
 *
 *   NESTING    Three layers are wrapped and three children come back. The module
 *              peels one layer and hands the rest to the engine, so this is also
 *              a test that a formatless child is offered back to the unpackers -
 *              which it was not until the module dropped its ELF-only target.
 *
 *   PLAINTEXT  The innermost child is the payload, byte for byte. Counting
 *              children alone would pass on a module that decrypted against the
 *              wrong key and produced three objects of noise.
 *
 *   SILENCE    An ELF whose entry point is ordinary code yields nothing. The
 *              stub's prologue is common instructions - a jump, two pops, a mov -
 *              and a module matching a prefix of it would claim half of /usr/bin.
 *
 * The wrappers are built in memory and written to one temporary file, because a
 * scan needs a path.
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

/* The payload every layer eventually reveals: the opening of the msfvenom x64
 * stager, which is what the measured samples decrypt to. */
static const uint8_t payload[] = {
	0x31,0xff,0x6a,0x09,0x58,0x99,0xb6,0x10,0x48,0x89,0xd6,0x4d,0x31,0xc9,
	0x6a,0x22,0x41,0x5a,0x6a,0x07,0x5a,0x0f,0x05,0x48,0x85,0xc0,0x78,0x51,
	0x6a,0x0a,0x41,0x59,0x50,0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,
	0x5e,0x0f,0x05,0x48,0x85,0xc0,0x78,0x3b,0x48,0x97,0x48,0xb9,0x02,0x00,
	0x11,0x5c,0x7f,0x00,0x00,0x01,0x51,0x48,0x89,0xe6,0x6a,0x10,0x5a,0x6a,
	0x2a,0x58,0x0f,0x05,0x59,0x48,0x85,0xc0,0x79,0x25,0x49,0xff,0xc9,0x74,
	0x18,0x57,0x6a,0x23,0x58,0x6a,0x00,0x6a,0x05,0x48,0x89,0xde,0x48,0xf7
};

#define STUB_LEN 46u

/*
 * Wrap `n` bytes at `in` in one layer, into `out`. Returns the wrapped length.
 *
 * The layout is the module's own listing read backwards: the fixed stub with
 * this layer's terminator patched into its two places, then the key, the
 * terminator, the ciphertext, and the marker.
 */
static uint64_t wrap(uint8_t *out, const uint8_t *in, uint64_t n,
		     uint8_t term, uint8_t m0, uint8_t m1,
		     const uint8_t *key, uint32_t keylen)
{
	static const uint8_t stub[STUB_LEN] = {
		0xeb,0x27,
		0x5b,0x53,0x5f,
		0xb0,0x00,                     /* [6]  = term          */
		0xfc,
		0xae,0x75,0xfd,
		0x57,0x59,
		0x53,0x5e,
		0x8a,0x06,
		0x30,0x07,
		0x48,0xff,0xc7,
		0x48,0xff,0xc6,
		0x66,0x81,0x3f,0x00,0x00,      /* [28],[29] = marker   */
		0x74,0x07,
		0x80,0x3e,0x00,                /* [34] = term          */
		0x75,0xea,
		0xeb,0xe6,
		0xff,0xe1,
		0xe8,0xd4,0xff,0xff,0xff
	};
	uint64_t at = 0, i;

	memcpy(out, stub, STUB_LEN);
	out[6]  = term;
	out[28] = m0;
	out[29] = m1;
	out[34] = term;
	at = STUB_LEN;
	memcpy(out + at, key, keylen);
	at += keylen;
	out[at++] = term;
	for (i = 0; i < n; i++)
		out[at + i] = (uint8_t)(in[i] ^ key[i % keylen]);
	at += n;
	out[at++] = m0;
	out[at++] = m1;
	return at;
}

/* An ELF64 with one executable PT_LOAD covering the file, entry at `body`. */
static uint64_t build_elf(uint8_t *f, const uint8_t *body, uint64_t n)
{
	const uint64_t base = 0x400000, off = 0x78;   /* msfvenom's own layout */
	uint64_t len = off + n;
	uint8_t *ph = f + 64;
	unsigned i;

	memset(f, 0, (size_t)len);
	memcpy(f, "\177ELF\2\1\1", 7);
	f[0x10] = 2;                                  /* ET_EXEC   */
	f[0x12] = 0x3e;                               /* EM_X86_64 */
	f[0x14] = 1;
	for (i = 0; i < 8; i++)
		f[0x18 + i] = (uint8_t)((base + off) >> (i * 8));
	f[0x20] = 64;                                 /* e_phoff   */
	f[0x34] = 64;                                 /* ehsize    */
	f[0x36] = 56;                                 /* phentsize */
	f[0x38] = 1;                                  /* phnum     */
	ph[0] = 1;                                    /* PT_LOAD   */
	ph[4] = 5;                                    /* R|X       */
	for (i = 0; i < 8; i++) {
		ph[0x10 + i] = (uint8_t)(base >> (i * 8));
		ph[0x18 + i] = (uint8_t)(base >> (i * 8));
		ph[0x20 + i] = (uint8_t)(len >> (i * 8));
		ph[0x28 + i] = (uint8_t)(len >> (i * 8));
	}
	ph[0x30] = 0x10;                              /* align 0x1000 */
	memcpy(f + off, body, (size_t)n);
	return len;
}

static uint64_t n_kids;
static uint8_t  last[4096];
static uint64_t last_n;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)res; (void)user;
	/* The root is announced too; only children have "//" in their name. */
	if (!strstr(name, "//"))
		return 0;
	n_kids++;
	last_n = len < sizeof last ? len : sizeof last;
	if (bytes)
		memcpy(last, bytes, (size_t)last_n);
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
	opt.max_produced_bytes = 1u << 20;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;
	n_kids = 0;
	last_n = 0;
	return kof_scan_path(sc, path, &opt, on_object, NULL) >= 0;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *path = "build/test/msf_xor.tmp";
	static uint8_t l1[4096], l2[4096], l3[4096], elf[8192];
	static const uint8_t k1[1] = { 0x10 };
	static const uint8_t k2[3] = { 0xa5, 0x3c, 0x01 };
	static const uint8_t k3[7] = { 0x77, 0x12, 0xfe, 0x08, 0x9a, 0x44, 0x20 };
	kof_engine *eng;
	kof_scanner *sc;
	uint64_t n1, n2, n3, ne;

	eng = kof_engine_open(db);
	if (!eng) {
		printf("msf xor: cannot open %s\n", db);
		return 2;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		return 2;
	}

	/*
	 * Three layers, innermost first, each with its own terminator, marker
	 * and key length. None of the three shares a value with another, so a
	 * module reading any of them from the wrong layer produces the wrong
	 * bytes and the plaintext assertion fails.
	 */
	n1 = wrap(l1, payload, sizeof payload, 0xcf, 0xe0, 0x22, k1, 1);
	n2 = wrap(l2, l1, n1, 0x71, 0xa8, 0xe4, k2, 3);
	n3 = wrap(l3, l2, n2, 0x95, 0x24, 0x45, k3, 7);
	ne = build_elf(elf, l3, n3);

	if (!scan(sc, path, elf, ne)) {
		fail("the scan could not run");
	} else {
		printf("  ba lớp bọc -> %llu object con\n",
		       (unsigned long long)n_kids);
		if (n_kids != 3)
			fail("three wrapped layers did not yield three children");
		if (last_n != sizeof payload ||
		    memcmp(last, payload, sizeof payload) != 0)
			fail("the innermost child is not the payload");
		else
			printf("  lớp trong cùng khớp payload %u byte\n",
			       (unsigned)sizeof payload);
	}

	/*
	 * The negative: an ELF whose entry is ordinary code. The bytes chosen
	 * are the payload itself, which is real amd64 and shares nothing with
	 * the stub past its first instruction.
	 */
	ne = build_elf(elf, payload, sizeof payload);
	if (!scan(sc, path, elf, ne)) {
		fail("the negative scan could not run");
	} else {
		printf("  ELF mã thường          -> %llu object con\n",
		       (unsigned long long)n_kids);
		if (n_kids != 0)
			fail("an unwrapped ELF was claimed by the module");
	}

	remove(path);
	kof_scanner_free(sc);
	kof_engine_close(eng);
	printf("msf xor: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
