/*
 * cab_mszip - a cabinet whose folder is MSZIP, decoded back into its files.
 *
 * THE ORACLE IS zlib, the way inflate_diff's is: the fixture is COMPRESSED
 * here, with a real deflate, so what the engine hands back can be compared
 * against the bytes that went in rather than against another copy of this
 * code's opinion.
 *
 * THE CASE THAT MATTERS IS THE SECOND BLOCK. MSZIP is one deflate stream per
 * block, and every block after the first may reference up to 32KB of the
 * PREVIOUS block's output. A decoder that starts each block from an empty
 * window still produces output of the right length - matches resolve against
 * zeros - so the failure is silent and the file is simply wrong. The second
 * block below is built to reference the first: it is compressed with the first
 * block's content as a preset dictionary, which is exactly what a cabinet
 * writer does.
 *
 * So this test fails on any build whose inflate is not seeded, and passes only
 * if the history is carried block to block.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/cab.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/*
 * The folder's content: two blocks, and the second is mostly a repeat of the
 * first so that a compressor WILL reach back into it. Plain text on purpose -
 * a wrong decode of it is visible rather than a hash mismatch.
 */
#define B0 "MZ kofeng cabinet block zero: the quick brown fox jumps over the " \
	   "lazy dog, and then jumps over it again and again and again.\n"
#define B1 "the quick brown fox jumps over the lazy dog, and then jumps over " \
	   "it again and again and again. block one adds only this tail.\n"

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * One MSZIP block: "CK" and a RAW deflate stream, compressed with `dict` as the
 * preset dictionary when there is one. That dictionary is the previous block's
 * output, which is what makes the second block unreadable without the history.
 */
static uint32_t mszip_block(uint8_t *out, uint32_t cap, const uint8_t *data,
			    uint32_t n, const uint8_t *dict, uint32_t dict_len)
{
	z_stream z;
	uint32_t got;

	memset(&z, 0, sizeof z);
	if (deflateInit2(&z, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 8,
			 Z_DEFAULT_STRATEGY) != Z_OK)
		return 0;
	if (dict_len && deflateSetDictionary(&z, dict, dict_len) != Z_OK) {
		deflateEnd(&z);
		return 0;
	}
	out[0] = 'C';
	out[1] = 'K';
	z.next_in = (Bytef *)(uintptr_t)data;
	z.avail_in = n;
	z.next_out = out + 2;
	z.avail_out = cap - 2u;
	if (deflate(&z, Z_FINISH) != Z_STREAM_END) {
		deflateEnd(&z);
		return 0;
	}
	got = (uint32_t)(cap - 2u - z.avail_out);
	deflateEnd(&z);
	return got + 2u;
}

#define CAB_HDR 36u
#define FOLD_AT CAB_HDR
#define FILES_AT (FOLD_AT + 8u)

/*
 * A cabinet with one MSZIP folder of two blocks and two files: the first
 * entirely inside block zero, the second starting inside block one - so
 * reaching it needs the first block decoded and thrown away, which is the other
 * half of what the host has to get right.
 */
static size_t build(uint8_t *f, size_t cap, uint32_t *f2_off, uint32_t *f2_len)
{
	static const char *n1 = "first.txt";
	static const char *n2 = "second.txt";
	uint32_t at, blk, b0 = (uint32_t)(sizeof B0 - 1u);
	uint32_t b1 = (uint32_t)(sizeof B1 - 1u);

	memcpy(f, "MSCF", 4);
	wr16(f + 24, 0x0301u);
	wr16(f + 26, 1);                     /* one folder */
	wr16(f + 28, 2);                     /* two files */
	wr32(f + 16, FILES_AT);

	at = FILES_AT;
	/* first.txt: the whole of block zero. */
	wr32(f + at, b0);
	wr32(f + at + 4, 0);
	wr16(f + at + 8, 0);
	wr16(f + at + 14, 0x20u);
	memcpy(f + at + 16, n1, strlen(n1) + 1u);
	at += (uint32_t)(16u + strlen(n1) + 1u);

	/* second.txt: block one, which begins where block zero ended. */
	wr32(f + at, b1);
	wr32(f + at + 4, b0);
	wr16(f + at + 8, 0);
	wr16(f + at + 14, 0x20u);
	memcpy(f + at + 16, n2, strlen(n2) + 1u);
	at += (uint32_t)(16u + strlen(n2) + 1u);
	*f2_off = b0;
	*f2_len = b1;

	wr32(f + FOLD_AT, at);
	wr16(f + FOLD_AT + 4, 2);            /* two CFDATA blocks */
	wr16(f + FOLD_AT + 6, KOF_CAB_C_MSZIP);

	/* block zero */
	blk = mszip_block(f + at + 8u, (uint32_t)(cap - at - 8u),
			  (const uint8_t *)B0, b0, NULL, 0);
	if (!blk)
		return 0;
	wr32(f + at, 0);
	wr16(f + at + 4, (uint16_t)blk);
	wr16(f + at + 6, (uint16_t)b0);
	at += 8u + blk;

	/* block one, compressed against block zero's output */
	blk = mszip_block(f + at + 8u, (uint32_t)(cap - at - 8u),
			  (const uint8_t *)B1, b1,
			  (const uint8_t *)B0, b0);
	if (!blk)
		return 0;
	wr32(f + at, 0);
	wr16(f + at + 4, (uint16_t)blk);
	wr16(f + at + 6, (uint16_t)b1);
	at += 8u + blk;

	wr32(f + 8, at);
	return at;
}

struct seen {
	int objects;
	int first_ok, second_ok, wrong;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)res;
	s->objects++;
	if (!bytes || !name)
		return 0;
	if (strstr(name, "first.txt")) {
		if (len == sizeof B0 - 1u && memcmp(bytes, B0, (size_t)len) == 0)
			s->first_ok = 1;
		else
			s->wrong++;
	} else if (strstr(name, "second.txt")) {
		if (len == sizeof B1 - 1u && memcmp(bytes, B1, (size_t)len) == 0)
			s->second_ok = 1;
		else
			s->wrong++;
	}
	return 0;
}

int main(void)
{
	static const char *db = "build/release/databases";
	struct kof_scan_option opt;
	struct kof_engine *eng;
	struct kof_scanner *sc;
	struct seen s;
	uint8_t *f = calloc(1, 4096);
	uint32_t f2_off = 0, f2_len = 0;
	size_t n;

	if (!f) {
		printf("cab mszip: out of memory\n");
		return 1;
	}
	n = build(f, 4096, &f2_off, &f2_len);
	if (!n) {
		free(f);
		printf("cab mszip: the fixture could not be compressed - "
		       "nothing tested\n");
		return 0;
	}

	eng = kof_engine_open(db);
	if (!eng) {
		free(f);
		printf("cab mszip: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		free(f);
		printf("cab mszip: could not make a scanner\n");
		return 1;
	}

	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	if (kof_scan_bytes(sc, f, n, "fixture.cab", &opt, on_object, &s) <= 0)
		fail("scan", "the cabinet was not scanned");

	if (!s.first_ok)
		fail("block zero", "the first file did not come back as the "
		     "bytes that were compressed");
	/*
	 * THE ONE THAT CATCHES AN UNSEEDED DECODER: the second file is in the
	 * second block, which was compressed against the first block's output.
	 */
	if (!s.second_ok)
		fail("block one", "the second file is wrong - the block's "
		     "history was not carried, or the skip past the first file "
		     "is off");
	if (s.wrong)
		fail("content", "a child came back under the right name with "
		     "the wrong bytes");

	kof_scanner_free(sc);
	kof_engine_close(eng);
	free(f);

	if (failures) {
		printf("cab mszip: %d check(s) failed\n", failures);
		return 1;
	}
	printf("cab mszip: two blocks, a preset dictionary between them, both "
	       "files back byte for byte - %d object(s) - ok\n", s.objects);
	return 0;
}
