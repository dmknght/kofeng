/* SPDX-License-Identifier: Apache-2.0 */
/*
 * view_reuse.c - a parse must not report the PREVIOUS file's entries.
 *
 * WHAT THIS GUARDS, AND WHY IT NEEDS GUARDING NOW.
 *
 * A format view - struct kof_zip_info and its siblings - is allocated ONCE per
 * scanner and reused for every object of that format. It is 608KB for ZIP and
 * 800KB for PDF, almost all of it two arrays sized for the worst case, and the
 * parsers used to begin with `memset(view, 0, sizeof *view)`.
 *
 * That was 9.1us of memset per ZIP object and 13.7us per PDF one, measured, to
 * zero four thousand entry slots that a two-entry archive cannot reach. The
 * parsers now clear the HEADER and leave the arrays dirty, which is sound for
 * exactly one reason: nothing reads past the count, and the count is in the
 * header. A parse that stops early leaves the tail holding the last file's
 * entries and the count at zero, so it reads as "no entries".
 *
 * THE FAILURE THAT REASONING ALLOWS is the one this file exists to catch: a
 * parser that sets its count BEFORE filling the slots, or that leaves the count
 * from a previous object, hands a consumer somebody else's data. Nothing about
 * that looks wrong - no crash, no overflow, no sanitizer report - and the
 * result is a scanner reporting entry names that belong to a file it finished
 * with. A _Static_assert catches a field added after the arrays; only a run
 * catches this.
 *
 * SO THE SHAPE OF EVERY CASE IS THE SAME: parse a BIG object, then a SMALL one
 * through the SAME view, and demand that the small one's answers are its own.
 * The big one goes first on purpose - it is what leaves the tail dirty.
 *
 * AND ONE CASE PARSES RUBBISH between the two, because the interesting failure
 * is not "the second parse is wrong" but "the second parse gave up early and
 * kept what it found last time". A parse that refuses must leave a count of
 * zero, not the previous count.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofparsers/containers/zip_parse.h"
#include "../../libkofeng/kofparsers/containers/tar_parse.h"

static int fails;

static void ok(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		fails++;
	}
}

/* ---------------------------------------------------------------- zip ---- */

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

/*
 * A STORED zip with `n` entries named "eNNNN". Hand built rather than shelled
 * out to `zip`, so the test runs on a machine that has no archiver and cannot
 * be made to pass or fail by one that behaves differently.
 */
static uint64_t make_zip(uint8_t *out, size_t cap, uint32_t n, char tag)
{
	uint64_t at = 0, cd_at;
	uint32_t i;
	uint64_t loc[512];

	if (n > 512)
		n = 512;
	for (i = 0; i < n; i++) {
		char nm[16];
		int  nl = snprintf(nm, sizeof nm, "%c%04u", tag, i);

		if (at + 30u + (uint64_t)nl + 4u > cap)
			return 0;
		loc[i] = at;
		put32(out + at, 0x04034b50u);        /* local header       */
		put16(out + at + 4, 20);             /* version            */
		put16(out + at + 6, 0);              /* flags              */
		put16(out + at + 8, 0);              /* STORED             */
		put16(out + at + 10, 0);
		put16(out + at + 12, 0);
		put32(out + at + 14, 0);             /* crc                */
		put32(out + at + 18, 4);             /* compressed size    */
		put32(out + at + 22, 4);             /* uncompressed size  */
		put16(out + at + 26, (uint16_t)nl);
		put16(out + at + 28, 0);
		memcpy(out + at + 30, nm, (size_t)nl);
		at += 30u + (uint64_t)nl;
		memcpy(out + at, "DATA", 4);
		at += 4;
	}
	cd_at = at;
	for (i = 0; i < n; i++) {
		char nm[16];
		int  nl = snprintf(nm, sizeof nm, "%c%04u", tag, i);

		if (at + 46u + (uint64_t)nl > cap)
			return 0;
		put32(out + at, 0x02014b50u);        /* central directory  */
		put16(out + at + 4, 20);
		put16(out + at + 6, 20);
		put16(out + at + 8, 0);
		put16(out + at + 10, 0);
		put16(out + at + 12, 0);
		put16(out + at + 14, 0);
		put32(out + at + 16, 0);
		put32(out + at + 20, 4);
		put32(out + at + 24, 4);
		put16(out + at + 28, (uint16_t)nl);
		put16(out + at + 30, 0);
		put16(out + at + 32, 0);
		put16(out + at + 34, 0);
		put16(out + at + 36, 0);
		put32(out + at + 38, 0);
		put32(out + at + 42, (uint32_t)loc[i]);
		memcpy(out + at + 46, nm, (size_t)nl);
		at += 46u + (uint64_t)nl;
	}
	if (at + 22u > cap)
		return 0;
	put32(out + at, 0x06054b50u);                /* end of central dir */
	put16(out + at + 4, 0);
	put16(out + at + 6, 0);
	put16(out + at + 8, (uint16_t)n);
	put16(out + at + 10, (uint16_t)n);
	put32(out + at + 12, (uint32_t)(cd_at ? at - cd_at : 0));
	put32(out + at + 16, (uint32_t)cd_at);
	put16(out + at + 20, 0);
	return at + 22u;
}

static void zip_case(void)
{
	static uint8_t big[1u << 20], small[4096], junk[512];
	struct kof_zip_info *view = malloc(sizeof *view);
	struct kof_obj_ctx ctx;
	uint64_t nbig, nsmall;
	uint32_t i;

	if (!view) {
		printf("  FAIL out of memory\n");
		fails++;
		return;
	}
	/*
	 * A DELIBERATELY DIRTY VIEW, so a parser that clears nothing at all is
	 * caught as surely as one that clears too little. Without this the
	 * malloc could hand back zeroed pages and the test would pass on a
	 * parser that never writes the count.
	 */
	memset(view, 0xAB, sizeof *view);

	nbig = make_zip(big, sizeof big, 300u, 'B');
	nsmall = make_zip(small, sizeof small, 2u, 'S');
	ok(nbig > 0 && nsmall > 0, "zip fixtures built");
	if (!nbig || !nsmall) {
		free(view);
		return;
	}

	memset(&ctx, 0, sizeof ctx);
	ok(kof_zip_parse(kof_buf_make(big, nbig), view, &ctx) != 0,
	   "zip: the 300-entry archive parses");
	ok(view->n_entries == 300u, "zip: 300 entries found");

	/* The same view, a much smaller archive. */
	memset(&ctx, 0, sizeof ctx);
	ok(kof_zip_parse(kof_buf_make(small, nsmall), view, &ctx) != 0,
	   "zip: the 2-entry archive parses");
	ok(view->n_entries == 2u,
	   "zip: 2 entries, NOT the 300 left in the tail");

	/*
	 * And the two it reports are ITS OWN. A count that was reset while the
	 * slots were not would pass the check above and fail this one.
	 */
	for (i = 0; i < view->n_entries && i < 2u; i++) {
		const char *nm = (const char *)small + view->entry[i].name_off;

		ok(view->entry[i].name_len == 5u && nm[0] == 'S',
		   "zip: the entry names belong to the second archive");
	}

	/*
	 * RUBBISH BETWEEN TWO GOOD PARSES. A parse that refuses must leave the
	 * count at zero rather than whatever the last good one set, or a
	 * consumer reads 2 entries out of a file that has none.
	 */
	memset(junk, 0x5A, sizeof junk);
	memset(&ctx, 0, sizeof ctx);
	(void)kof_zip_parse(kof_buf_make(junk, sizeof junk), view, &ctx);
	ok(view->n_entries == 0u,
	   "zip: a refused parse reports no entries, not the last file's");

	free(view);
}

/* ---------------------------------------------------------------- tar ---- */

/* A ustar archive of `n` empty members. Same reasoning as make_zip: built here
 * so no external tool decides whether this test passes. */
static uint64_t make_tar(uint8_t *out, size_t cap, uint32_t n, char tag)
{
	uint64_t at = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint8_t *h = out + at;
		unsigned sum = 0;
		uint32_t k;

		if (at + 512u * 2u > cap)
			return 0;
		memset(h, 0, 512);
		snprintf((char *)h, 100, "%c%04u.txt", tag, i);
		memcpy(h + 100, "0000644", 8);       /* mode  */
		memcpy(h + 108, "0000000", 8);       /* uid   */
		memcpy(h + 116, "0000000", 8);       /* gid   */
		memcpy(h + 124, "00000000000", 12);  /* size 0 */
		memcpy(h + 136, "00000000000", 12);  /* mtime */
		memset(h + 148, ' ', 8);             /* checksum field */
		h[156] = '0';                        /* regular file   */
		memcpy(h + 257, "ustar", 6);
		memcpy(h + 263, "00", 2);
		for (k = 0; k < 512u; k++)
			sum += h[k];
		snprintf((char *)h + 148, 8, "%06o", sum);
		h[154] = '\0';
		h[155] = ' ';
		at += 512;
	}
	if (at + 1024u > cap)
		return 0;
	memset(out + at, 0, 1024);               /* two empty blocks = end */
	return at + 1024u;
}

static void tar_case(void)
{
	static uint8_t big[1u << 19], small[8192];
	struct kof_tar_info *view = malloc(sizeof *view);
	struct kof_obj_ctx ctx;
	uint64_t nbig, nsmall;

	if (!view) {
		printf("  FAIL out of memory\n");
		fails++;
		return;
	}
	memset(view, 0xAB, sizeof *view);

	nbig = make_tar(big, sizeof big, 200u, 'B');
	nsmall = make_tar(small, sizeof small, 1u, 'S');
	ok(nbig > 0 && nsmall > 0, "tar fixtures built");
	if (!nbig || !nsmall) {
		free(view);
		return;
	}

	memset(&ctx, 0, sizeof ctx);
	ok(kof_tar_parse(kof_buf_make(big, nbig), view, &ctx) != 0,
	   "tar: the 200-member archive parses");
	ok(view->n_entries == 200u, "tar: 200 entries found");

	memset(&ctx, 0, sizeof ctx);
	ok(kof_tar_parse(kof_buf_make(small, nsmall), view, &ctx) != 0,
	   "tar: the 1-member archive parses");
	ok(view->n_entries == 1u,
	   "tar: 1 entry, NOT the 200 left in the tail");

	free(view);
}

int main(void)
{
	printf("== view reuse: a parse must not report the previous file's "
	       "entries\n");
	zip_case();
	tar_case();
	if (fails) {
		printf("view_reuse: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("view reuse: zip, tar - ok\n");
	return 0;
}
