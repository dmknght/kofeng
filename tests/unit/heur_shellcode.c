/*
 * heur_shellcode - the shape that says "this file is nothing but code".
 *
 * The term this exercises is the one number in the heuristic table that was
 * CHOSEN rather than measured - it is set so the shape reaches the bar with the
 * missing section table it implies, and nothing else. That makes it the term
 * most likely to stop working silently: a parser that starts reporting one more
 * anomaly on these files, or a table whose other weights move, changes the sum
 * without changing anything a reader would look at. So the assertion here is on
 * the REPORT, through the public scan API, and not on the predicate.
 *
 *
 * WHAT IS ASSERTED
 *
 *   FIRES        A single-segment executable ELF with no section table is
 *                reported as Heur:Shellcode. This is the whole point of the
 *                term, and it is the assertion that fails if the sum drifts
 *                below the bar by one centinat.
 *
 *   NOT A SIZE   A four kilobyte object of the same shape fires too. Size was
 *                tried as the discriminator and rejected on the measurement -
 *                the largest malware object with this shape is 1266 bytes and
 *                the smallest clean ELF on the machine is 1192 - so a size bound
 *                creeping back in has to fail something.
 *
 *   TWO SEGMENTS An ELF with a data segment beside its code is silent, section
 *                table or not. Every binary a toolchain produces has one, so
 *                this is the case that decides whether the term can be let near
 *                a real filesystem.
 *
 *   SECTION TAB  An ELF that keeps its section header table is silent. Stripping
 *                is common in clean software and worth 2.75 nats on its own;
 *                what is rare is stripping AND having nothing but one code
 *                segment.
 *
 * The ELFs are built in memory and written to one temporary file, because a scan
 * needs a path.
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

/* Real amd64, so the object is code by any reading of it: the opening of the
 * msfvenom stager. Its content is not what the term looks at - the shape is -
 * but a file of zeroes would leave the reader wondering. */
static const uint8_t code[] = {
	0x31,0xff,0x6a,0x09,0x58,0x99,0xb6,0x10,0x48,0x89,0xd6,0x4d,0x31,0xc9,
	0x6a,0x22,0x41,0x5a,0x6a,0x07,0x5a,0x0f,0x05,0x48,0x85,0xc0,0x78,0x51,
	0x6a,0x0a,0x41,0x59,0x50,0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,
	0x5e,0x0f,0x05,0x48,0x85,0xc0,0x78,0x3b,0x48,0x97,0x48,0xb9,0x02,0x00
};

#define SEC_N 1u

/*
 * One ELF64, in the shapes the assertions need.
 *
 *   segs    1 or 2 PT_LOADs; the second is read-write, where a toolchain puts
 *           the data a program has.
 *   sectab  non-zero to append a one-entry section header table, which is what
 *           an unstripped binary carries.
 *   body_n  how many bytes of code to lay down, `code` repeating, so the same
 *           shape can be built at two sizes.
 */
static uint64_t build(uint8_t *f, unsigned segs, int sectab, uint64_t body_n)
{
	const uint64_t base = 0x400000, off = 0x78;
	uint64_t len = off + body_n, shoff = 0;
	uint8_t *ph = f + 64;
	unsigned i, s;

	memset(f, 0, (size_t)(len + 64 * 4));
	memcpy(f, "\177ELF\2\1\1", 7);
	f[0x10] = 2;                                  /* ET_EXEC   */
	f[0x12] = 0x3e;                               /* EM_X86_64 */
	f[0x14] = 1;
	for (i = 0; i < 8; i++)
		f[0x18 + i] = (uint8_t)((base + off) >> (i * 8));
	f[0x20] = 64;                                 /* e_phoff   */
	f[0x34] = 64;                                 /* ehsize    */
	f[0x36] = 56;                                 /* phentsize */
	f[0x38] = (uint8_t)segs;                      /* phnum     */
	f[0x3a] = 64;                                 /* shentsize */

	for (s = 0; s < segs; s++) {
		uint8_t *p = ph + s * 56;
		uint64_t va = base + s * 0x200000;

		p[0] = 1;                             /* PT_LOAD   */
		p[4] = s == 0 ? 5 : 6;                /* R|X, then R|W */
		for (i = 0; i < 8; i++) {
			p[0x10 + i] = (uint8_t)(va >> (i * 8));
			p[0x18 + i] = (uint8_t)(va >> (i * 8));
			p[0x20 + i] = (uint8_t)(len >> (i * 8));
			p[0x28 + i] = (uint8_t)(len >> (i * 8));
		}
		p[0x30] = 0x10;
	}
	for (i = 0; i < body_n; i++)
		f[off + i] = code[i % (sizeof code)];

	if (sectab) {
		shoff = len;
		/* One entry, SHT_PROGBITS, so the parser has a usable table. */
		f[shoff + 4] = 1;
		len = shoff + 64;
		f[0x3c] = (uint8_t)SEC_N;             /* e_shnum */
		for (i = 0; i < 8; i++)
			f[0x28 + i] = (uint8_t)(shoff >> (i * 8));
	}
	return len;
}

static char seen[256];

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	uint32_t k;

	(void)name; (void)bytes; (void)len; (void)user;
	seen[0] = '\0';
	if (!res)
		return 0;
	for (k = 0; k < res->n; k++)
		if (res->v[k].level == KOF_LEVEL_HEUR) {
			snprintf(seen, sizeof seen, "%s", res->v[k].name);
			break;
		}
	return 0;
}

/*
 * Returns non-zero when the object was reported as a heuristic whose SHAPE is
 * Shellcode. A rule names itself Heur:<predicted-family>#<variant>?<shape>, so
 * the shape "Shellcode" sits after the "?" when there is a prediction (there is
 * one here, Meterp) and right after "Heur:" when there is not. Both are a Heur
 * finding carrying the word Shellcode, which is what this asks.
 */
static int shellcode_said(kof_scanner *sc, const char *path,
			  const uint8_t *f, uint64_t n)
{
	struct kof_scan_option opt;
	FILE *fp = fopen(path, "wb");

	if (!fp || fwrite(f, 1, (size_t)n, fp) != (size_t)n) {
		if (fp)
			fclose(fp);
		fail("could not write the temporary object");
		return 0;
	}
	fclose(fp);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1u << 20;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;
	seen[0] = '\0';
	if (kof_scan_path(sc, path, &opt, on_object, NULL) < 0) {
		fail("the scan could not run");
		return 0;
	}
	return strstr(seen, "Heur:") != NULL && strstr(seen, "Shellcode") != NULL;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	const char *path = "build/test/heur_shellcode.tmp";
	static uint8_t f[16384];
	kof_engine *eng;
	kof_scanner *sc;
	uint64_t n;

	eng = kof_engine_open(db);
	if (!eng) {
		printf("heur shellcode: cannot open %s\n", db);
		return 2;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		return 2;
	}

	n = build(f, 1, 0, sizeof code);
	printf("  1 segment, không section table, %llu B -> %s\n",
	       (unsigned long long)n, shellcode_said(sc, path, f, n)
	       ? "Heur:Shellcode" : "IM LẶNG");
	if (!shellcode_said(sc, path, f, n))
		fail("the shape the term exists for was not reported");

	n = build(f, 1, 0, 4096);
	printf("  cùng shape nhưng %llu B      -> %s\n",
	       (unsigned long long)n, shellcode_said(sc, path, f, n)
	       ? "Heur:Shellcode" : "IM LẶNG");
	if (!shellcode_said(sc, path, f, n))
		fail("a size bound has crept back into the term");

	n = build(f, 2, 0, sizeof code);
	printf("  2 segment, không section table -> %s\n",
	       shellcode_said(sc, path, f, n) ? "Heur:Shellcode" : "im lặng");
	if (shellcode_said(sc, path, f, n))
		fail("an ELF with a data segment was reported");

	n = build(f, 1, 1, sizeof code);
	printf("  1 segment, CÓ section table    -> %s\n",
	       shellcode_said(sc, path, f, n) ? "Heur:Shellcode" : "im lặng");
	if (shellcode_said(sc, path, f, n))
		fail("an ELF that kept its section table was reported");

	remove(path);
	kof_scanner_free(sc);
	kof_engine_close(eng);
	printf("heur shellcode: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
