/*
 * cab_walk - the cabinet's three tables, and the arithmetic that turns a file
 * into a range.
 *
 * THE FIXTURE IS BUILT HERE for the reason chm_walk's is: nothing on a Linux
 * build host writes a cabinet. It is also the only way to build the cases that
 * matter, which are not "a cabinet parses" but the four shapes a parser gets
 * wrong:
 *
 *   - a file INSIDE one uncompressed block: a plain range, and a child
 *   - a file that CROSSES a block boundary: not one range at all, because the
 *     next block's header sits in the middle of it. Described as contiguous, it
 *     would hand a rule a file with eight bytes of header spliced into it
 *   - a file in a COMPRESSED folder: no mapping exists, and pretending one does
 *     points at the coded bytes under the file's name
 *   - a header whose optional part moves the folder table: get the reserve
 *     sizes or the spanning names wrong and the folder walk lands on the wrong
 *     bytes, which then parse as folders and point anywhere
 *
 * Every one of those produces a plausible wrong answer rather than an error,
 * which is why each is a case below.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofparsers/containers/cab_parse.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

static void ok_(int cond, const char *what)
{
	if (!cond)
		fail(what, "the answer was the wrong one");
}

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
 * A cabinet with two folders and three files:
 *
 *   folder 0  uncompressed, two blocks of 16 bytes
 *             "small.txt"  8 bytes at offset 0   - inside block 0
 *             "split.bin" 16 bytes at offset 8   - crosses into block 1
 *   folder 1  MSZIP, one block
 *             "coded.bin" 10 bytes               - no mapping exists
 */
#define BLK 16u
#define HDR 36u
#define FOLD_AT  HDR
#define FILES_AT (FOLD_AT + 16u)          /* two folders of eight bytes */

struct built {
	uint8_t *p;
	size_t   n;
	uint64_t files_at, data0, data1;
};

static uint32_t put_file(uint8_t *p, uint32_t size, uint32_t off,
			 uint16_t folder, const char *name)
{
	size_t nl = strlen(name) + 1u;

	wr32(p, size);
	wr32(p + 4, off);
	wr16(p + 8, folder);
	wr16(p + 10, 0);      /* date */
	wr16(p + 12, 0);      /* time */
	wr16(p + 14, 0x20u);  /* attribs */
	memcpy(p + 16, name, nl);
	return (uint32_t)(16u + nl);
}

static uint32_t put_block(uint8_t *p, const uint8_t *data, uint16_t n)
{
	wr32(p, 0);           /* checksum, which nothing here verifies */
	wr16(p + 4, n);       /* cbData */
	wr16(p + 6, n);       /* cbUncomp - equal, the folder is stored */
	memcpy(p + 8, data, n);
	return 8u + n;
}

static int build(struct built *b)
{
	uint8_t *f = calloc(1, 1024);
	uint8_t blk0[BLK], blk1[BLK];
	uint32_t at;
	uint32_t i;

	if (!f)
		return 0;
	for (i = 0; i < BLK; i++) {
		blk0[i] = (uint8_t)('A' + i);
		blk1[i] = (uint8_t)('a' + i);
	}

	memcpy(f, "MSCF", 4);
	wr16(f + 24, 0x0301u);      /* versionMinor 3, versionMajor 1 */
	wr16(f + 26, 2);            /* cFolders */
	wr16(f + 28, 3);            /* cFiles */

	at = FILES_AT;
	at += put_file(f + at, 8u, 0u, 0, "small.txt");
	at += put_file(f + at, 16u, 8u, 0, "split.bin");
	at += put_file(f + at, 10u, 0u, 1, "coded.bin");
	wr32(f + 16, FILES_AT);     /* coffFiles */

	/* folder 0: two stored blocks, beginning here */
	b->data0 = at;
	wr32(f + FOLD_AT, (uint32_t)at);
	wr16(f + FOLD_AT + 4, 2);                  /* cCFData */
	wr16(f + FOLD_AT + 6, KOF_CAB_C_NONE);
	at += put_block(f + at, blk0, BLK);
	at += put_block(f + at, blk1, BLK);

	/* folder 1: one block, MSZIP */
	b->data1 = at;
	wr32(f + FOLD_AT + 8, (uint32_t)at);
	wr16(f + FOLD_AT + 12, 1);
	wr16(f + FOLD_AT + 14, KOF_CAB_C_MSZIP);
	at += put_block(f + at, blk0, 10u);

	wr32(f + 8, at);            /* cbCabinet: the real length */
	b->p = f;
	b->n = at;
	b->files_at = FILES_AT;
	return 1;
}

static kof_buf buf_of(const uint8_t *p, size_t n)
{
	kof_buf b;

	b.p = p;
	b.n = n;
	return b;
}

int main(void)
{
	struct kof_cab_info *c = malloc(sizeof *c);
	struct kof_obj_ctx ctx;
	struct built b;

	if (!c) {
		printf("cab walk: out of memory\n");
		return 1;
	}
	if (!build(&b)) {
		free(c);
		printf("cab walk: out of memory\n");
		return 1;
	}

	memset(&ctx, 0, sizeof ctx);
	if (!kof_cab_sniff(buf_of(b.p, b.n)))
		fail("sniff", "MSCF was not recognised");
	if (!kof_cab_parse(buf_of(b.p, b.n), c, &ctx)) {
		fail("parse", "a well formed cabinet would not parse");
	} else {
		ok_(c->n_folders == 2u && c->n_files == 3u,
		    "the counts are read");
		ok_((c->anomalies & KOF_CAB_ANOM_SIZE_MISMATCH) == 0,
		    "cbCabinet agrees with the object");
		ok_((c->anomalies & KOF_CAB_ANOM_CODED) != 0,
		    "a coded folder is said");

		/*
		 * ALL THREE ARE ENTRIES, in three different shapes:
		 *
		 *   small.txt  inside one block of a stored folder: one range
		 *   split.bin  across two blocks of it: SCATTERED, and its
		 *              pieces come from resolve_entry
		 *   coded.bin  in an MSZIP folder: SCATTERED over the folder's
		 *              BLOCKS, with where it sits in the decoded stream
		 *              in out_hint - see KOF_UNP_MSZIP
		 *
		 * n_coded counts the third whether or not this build can open
		 * it, because it answers "how much of this cabinet is behind a
		 * coding" and not "how much was opened".
		 */
		ok_(c->n_entries == 3u, "all three files are entries");
		ok_(c->n_split == 1u, "the one crossing a block is counted");
		ok_(c->n_coded == 1u, "the one in a coded folder is counted");
		if (c->n_entries == 3u) {
			const struct kof_entry *e = &c->entry[2];

			ok_((e->flags & KOF_ENT_F_SCATTERED) != 0 &&
			    e->coding[0] == KOF_UNP_MSZIP &&
			    (e->out_hint & 0xffffffffu) == 10u,
			    "the coded one carries its place in the folder");
		}

		if (c->n_entries >= 2u) {
			const struct kof_entry *e = &c->entry[0];

			ok_(!(e->flags & KOF_ENT_F_SCATTERED),
			    "a file inside one block is one range");
			ok_(e->off == b.data0 + 8u && e->len == 8u,
			    "the entry points past the block header");
			ok_(memcmp(b.p + e->off, "ABCDEFGH", 8) == 0,
			    "and at the bytes the file actually holds");
			ok_(e->name_len == 9u &&
			    memcmp(b.p + e->name_off, "small.txt", 9) == 0,
			    "the name is a range in the object");
		}

		/*
		 * AND THE PIECES OF THE SPLIT ONE JOIN BACK INTO THE FILE.
		 *
		 * split.bin is sixteen bytes at folder offset eight: the last
		 * eight of block 0 and the first eight of block 1. Asserted by
		 * CONTENT rather than by counting ranges - two ranges of the
		 * right lengths holding the wrong bytes is the failure this
		 * exists to catch, and it is what an off-by-one in the block
		 * walk produces.
		 */
		if (c->n_entries >= 2u) {
			const struct kof_entry *e = &c->entry[1];
			struct kof_range r[8];
			uint8_t joined[32];
			uint32_t nr, i, at = 0;

			ok_((e->flags & KOF_ENT_F_SCATTERED) != 0,
			    "a file crossing a block is scattered");
			nr = ctx.resolve_entry ?
			     ctx.resolve_entry(&ctx, e->index, r, 8u) : 0;
			ok_(nr == 2u, "it is in two pieces");
			for (i = 0; i < nr && at + r[i].len <= sizeof joined; i++) {
				memcpy(joined + at, b.p + r[i].off,
				       (size_t)r[i].len);
				at += (uint32_t)r[i].len;
			}
			ok_(at == 16u &&
			    memcmp(joined, "IJKLMNOP", 8) == 0 &&
			    memcmp(joined + 8, "abcdefgh", 8) == 0,
			    "and the pieces are the file, in order");
		}

		/* The regions partition the object. */
		{
			struct kof_range r[16];
			uint32_t n, i;
			uint64_t total = 0;

			n = ctx.resolve_scan(&ctx, KOF_SCAN_CAB_HEADERS |
						   KOF_SCAN_CAB_FOLDERS |
						   KOF_SCAN_CAB_NAMES |
						   KOF_SCAN_CAB_DATA |
						   KOF_SCAN_CAB_UNCLAIMED,
					     r, 16u);
			for (i = 0; i < n; i++)
				total += r[i].len;
			ok_(total == b.n, "the regions cover the object once");
		}
	}

	/* ---- something appended to a cabinet --------------------------- */
	{
		uint8_t *g = realloc(b.p, b.n + 64u);

		if (g) {
			b.p = g;
			memset(g + b.n, 'Z', 64u);
			memset(&ctx, 0, sizeof ctx);
			kof_cab_parse(buf_of(g, b.n + 64u), c, &ctx);
			ok_((c->anomalies & KOF_CAB_ANOM_SIZE_MISMATCH) != 0,
			    "a cabinet longer than it says it is, is said");
		}
	}

	/* ---- a spanning cabinet ---------------------------------------- */
	{
		/* Set the NEXT flag without the name behind it: the walk must
		 * stop rather than read the folder table out of a name. */
		wr16(b.p + 30, KOF_CAB_F_NEXT_CABINET);
		memset(&ctx, 0, sizeof ctx);
		kof_cab_parse(buf_of(b.p, b.n), c, &ctx);
		ok_((c->anomalies & KOF_CAB_ANOM_SPANNED) != 0,
		    "a cabinet that continues elsewhere is said");
		wr16(b.p + 30, 0);
	}

	/* ---- a folder count larger than the file ----------------------- */
	{
		wr16(b.p + 26, 0xffffu);
		memset(&ctx, 0, sizeof ctx);
		kof_cab_parse(buf_of(b.p, b.n), c, &ctx);
		ok_((c->anomalies & KOF_CAB_ANOM_TRUNCATED) != 0 &&
		    (uint64_t)c->n_folders * 8u <= b.n,
		    "a folder count past the end is clamped and said");
		wr16(b.p + 26, 2);
	}

	/* ---- a file naming a folder that does not exist ---------------- */
	{
		uint8_t *at = b.p + FILES_AT;

		wr16(at + 8, 9u);           /* small.txt -> folder 9 */
		memset(&ctx, 0, sizeof ctx);
		kof_cab_parse(buf_of(b.p, b.n), c, &ctx);
		/* The OTHER stored file still becomes an entry: one bad row is
		 * a fact about that row, not a reason to stop describing the
		 * archive. */
		/* The other two files still become entries: one bad row is a
		 * fact about that row, not a reason to stop describing the
		 * archive. */
		ok_((c->anomalies & KOF_CAB_ANOM_BAD_FOLDER) != 0 &&
		    c->n_entries == 2u,
		    "a file in a folder that is not there is dropped and said");
		wr16(at + 8, 0);
	}

	/*
	 * ---- a name with no terminator ---------------------------------
	 *
	 * EVERY BYTE TO THE END OF THE OBJECT, not a handful: a name is read
	 * until a NUL or until the object stops, and the zeros in the NEXT file
	 * record are a terminator like any other. The first attempt at this
	 * case overwrote sixteen bytes, found the following record's date field
	 * and passed while proving nothing.
	 */
	{
		uint8_t *g = malloc(b.n);

		if (g) {
			memcpy(g, b.p, b.n);
			memset(g + FILES_AT + 16u, 'A',
			       b.n - (FILES_AT + 16u));
			memset(&ctx, 0, sizeof ctx);
			kof_cab_parse(buf_of(g, b.n), c, &ctx);
			ok_((c->anomalies & KOF_CAB_ANOM_TRUNCATED) != 0 &&
			    c->n_entries == 0u,
			    "a name that never ends stops the file walk");
			free(g);
		}
	}

	free(b.p);
	free(c);

	if (failures) {
		printf("cab walk: %d check(s) failed\n", failures);
		return 1;
	}
	printf("cab walk: header, folders, files, block mapping, a split file, "
	       "a coded folder, regions, appended bytes, spanning, a huge "
	       "count, a bad folder, an unterminated name - ok\n");
	return 0;
}
