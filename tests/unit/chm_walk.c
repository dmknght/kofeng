/*
 * chm_walk - the ITSS directory, walked and bounded.
 *
 * THE FIXTURE IS BUILT HERE, byte by byte, because there is no CHM writer on a
 * Linux build host - hhc.exe is the only tool that makes one. Written out
 * rather than committed as a blob for the reason mkfixtures.sh gives about
 * every other fixture: a blob in a source tree is opaque, and what makes this
 * one interesting is exactly the fields the code below sets.
 *
 * WHAT IS UNDER TEST is not "a good CHM parses" - it is that every count in the
 * file is bounded before it is used. A CHM's directory is a chunk COUNT, a
 * chunk SIZE, a name LENGTH and an entry OFFSET, all of them written by whoever
 * made the file, and all of them multiplied or added by the walk. So each case
 * breaks exactly one of them and the parse must come back with anomalies rather
 * than with entries, a hang, or a read outside the buffer - which is what the
 * sanitised build of this test is checking while it does so.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/analyzer/parsers/containers/chm_parse.h"
#include "chmgen.h"

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

/* ---- building one ---------------------------------------------------------- */

#define CHUNK 4096u
#define ITSF_LEN 0x60u
#define ITSP_LEN 0x54u
#define DIR_AT   (ITSF_LEN + ITSP_LEN)
#define CONTENT_AT (DIR_AT + CHUNK)

/*
 * THE CONTENT AREA, laid out so the compressed half is describable.
 *
 * A help file's pages are in an LZX stream, and reaching one takes three of the
 * format's own entries: ControlData for the window, the reset table for where
 * the stream restarts, and Content for the stream itself. The fixture carries
 * all three - the stream's BYTES are not LZX and nothing here decodes them, but
 * every number the placement works from is real, which is what is under test.
 */
#define PAGE_AT      0u
#define PAGE_LEN     32u
#define NAMELIST_AT  32u
#define NAMELIST_LEN 16u
#define CTRL_AT      48u
#define CTRL_LEN     24u        /* six words */
#define RESET_AT     80u
#define RESET_LEN    (0x28u + 8u)   /* the header and one row */
#define LZX_AT       128u
#define LZX_LEN      200u
#define CONTENT_LEN  (LZX_AT + LZX_LEN)

/* What the reset table declares, and what the coded entry asks for inside it. */
#define FRAME_LEN    32768u
#define RESET_EVERY  2u         /* frames between restarts */
#define UNCOMP_LEN   100u
#define HIDDEN_LEN   99u

#define FILE_LEN (CONTENT_AT + CONTENT_LEN)

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t *p, uint64_t v)
{
	wr32(p, (uint32_t)v);
	wr32(p + 4, (uint32_t)(v >> 32));
}

/* An ENCINT: seven bits a byte, most significant group first. */


/*
 * A CHM holding three entries: one ordinary file in the uncompressed section,
 * one in the compressed section, and one of the format's own - which is the
 * mix every real help file has.
 */
static uint8_t *build(size_t *len_out)
{
	uint8_t *f = calloc(1, FILE_LEN);
	uint8_t *dir, *at;

	if (!f)
		return NULL;
	memcpy(f, "ITSF", 4);
	wr32(f + 4, 3);                    /* version */
	wr32(f + 8, ITSF_LEN);             /* header length */
	wr32(f + 16, 0x5f000000u);         /* timestamp */
	wr32(f + 20, 0x409u);              /* language: en-US */
	wr64(f + 56, ITSF_LEN);            /* header section 0 */
	wr64(f + 64, 0x18u);
	wr64(f + 72, ITSF_LEN);            /* header section 1: the directory */
	wr64(f + 80, ITSP_LEN);
	wr64(f + 88, CONTENT_AT);          /* content area, v3 */

	memcpy(f + ITSF_LEN, "ITSP", 4);
	wr32(f + ITSF_LEN + 4, 1);
	wr32(f + ITSF_LEN + 8, ITSP_LEN);  /* directory header length */
	wr32(f + ITSF_LEN + 16, CHUNK);    /* chunk size */
	wr32(f + ITSF_LEN + 44, 1);        /* one chunk */

	dir = f + DIR_AT;
	memcpy(dir, "PMGL", 4);
	at = dir + 0x14u;
	at += put_entry(at, "/page.htm", 0, PAGE_AT, PAGE_LEN);
	at += put_entry(at, "/hidden.htm", 1, 0, HIDDEN_LEN);
	at += put_entry(at, "::DataSpace/NameList", 0, NAMELIST_AT, NAMELIST_LEN);
	/*
	 * The three the compressed section is read through. Matched on the tail
	 * of the name, which is why the reset table's real path - it sits under
	 * a GUID no two writers agree on - can be shortened here.
	 */
	at += put_entry(at, "::DataSpace/Storage/MSCompressed/ControlData",
			0, CTRL_AT, CTRL_LEN);
	at += put_entry(at, "::DataSpace/Storage/MSCompressed/Transform/"
			"{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/"
			"InstanceData/ResetTable", 0, RESET_AT, RESET_LEN);
	at += put_entry(at, "::DataSpace/Storage/MSCompressed/Content",
			0, LZX_AT, LZX_LEN);
	/* Everything after the entries is the chunk's free space, which is what
	 * the header's second field states - get this wrong and the walk reads
	 * the quickref area as if it were entries. */
	wr32(dir + 4, (uint32_t)(CHUNK - (uint32_t)(at - dir)));

	memcpy(f + CONTENT_AT + PAGE_AT, "kofeng-chm-fixture-page-bytes-32",
	       PAGE_LEN);

	/*
	 * ControlData: a length in words, "LZXC", a version, the reset
	 * interval, the window and a cache size. Version 2 counts the interval
	 * in frames; the window is in frames too, so one frame is 2^15.
	 */
	wr32(f + CONTENT_AT + CTRL_AT + 0, 6);
	memcpy(f + CONTENT_AT + CTRL_AT + 4, "LZXC", 4);
	wr32(f + CONTENT_AT + CTRL_AT + 8, 2);
	wr32(f + CONTENT_AT + CTRL_AT + 12, RESET_EVERY);
	wr32(f + CONTENT_AT + CTRL_AT + 16, 1);
	wr32(f + CONTENT_AT + CTRL_AT + 20, 0x8000u);

	/* The reset table: one row, so the whole stream is one interval. */
	wr32(f + CONTENT_AT + RESET_AT + 0, 2);            /* version */
	wr32(f + CONTENT_AT + RESET_AT + 4, 1);            /* rows */
	wr32(f + CONTENT_AT + RESET_AT + 8, 8);            /* bytes a row */
	wr32(f + CONTENT_AT + RESET_AT + 12, 0x28u);       /* where they start */
	wr64(f + CONTENT_AT + RESET_AT + 0x10, UNCOMP_LEN);
	wr64(f + CONTENT_AT + RESET_AT + 0x18, LZX_LEN);
	wr64(f + CONTENT_AT + RESET_AT + 0x20, FRAME_LEN);
	wr64(f + CONTENT_AT + RESET_AT + 0x28, 0);         /* frame 0 */

	*len_out = FILE_LEN;
	return f;
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
	struct kof_chm_info *c = malloc(sizeof *c);
	struct kof_obj_ctx ctx;
	uint8_t *f;
	size_t len = 0;

	if (!c) {
		printf("chm walk: out of memory\n");
		return 1;
	}
	f = build(&len);
	if (!f) {
		free(c);
		printf("chm walk: out of memory\n");
		return 1;
	}

	/* ---- the ordinary file ---------------------------------------- */
	memset(&ctx, 0, sizeof ctx);
	if (!kof_chm_sniff(buf_of(f, len)))
		fail("sniff", "ITSF was not recognised");
	if (!kof_chm_parse(buf_of(f, len), c, &ctx)) {
		fail("parse", "a well formed CHM would not parse");
	} else {
		ok_(c->valid && !c->anomalies, "a clean file has no anomalies");
		ok_(c->itsf_version == 3u, "the version is read");
		ok_(c->lang_id == 0x409u, "the language id is read");
		ok_(c->chunk_size == CHUNK && c->n_chunks == 1u,
		    "the directory header is read");
		/*
		 * TWO entries: the page, which is a range, and the one in the
		 * compressed section, which is not - it is the intervals of the
		 * stream it sits in. The four ::DataSpace rows are the format's
		 * own bookkeeping and are not offered as files.
		 */
		ok_(c->n_entries == 2u, "both entries are offered");
		ok_(c->n_compressed == 1u, "the compressed one is counted");
		ok_(c->n_unreachable == 0u,
		    "and the reset table placed it");
		ok_(c->n_special == 4u, "the format's own entries are counted");
		ok_(c->lzx_window_bits == 15u &&
		    c->lzx_reset_interval == RESET_EVERY,
		    "ControlData says the window and the interval");
		ok_(c->lzx_uncomp_len == UNCOMP_LEN &&
		    c->lzx_frame == FRAME_LEN && c->n_reset == 1u,
		    "the reset table says what the stream comes to");
		if (c->n_entries == 2u) {
			const struct kof_entry *e = &c->entry[0];

			ok_(e->kind == KOF_ENT_EMBEDDED,
			    "an entry is a carried file");
			ok_(e->off == CONTENT_AT + PAGE_AT &&
			    e->len == PAGE_LEN,
			    "the entry points at its bytes");
			ok_(e->name_len == 9u &&
			    memcmp(f + e->name_off, "/page.htm", 9) == 0,
			    "the name is a range in the object");
			ok_(memcmp(f + e->off, "kofeng-chm", 10) == 0,
			    "and the bytes are the ones it named");

			/*
			 * AND THE CODED ONE IS NOT A RANGE. Its pieces come
			 * from resolve_entry and its out_hint says where in
			 * the decoded stream it starts and how long it is -
			 * which is the whole of what a decoder is told.
			 */
			e = &c->entry[1];
			ok_((e->flags & KOF_ENT_F_SCATTERED) != 0 &&
			    e->coding[0] == KOF_UNP_LZX_RESET(15u),
			    "the compressed entry is not a range of the file, "
			    "and it names the coding and the window");
			ok_(e->len == HIDDEN_LEN &&
			    e->out_hint == HIDDEN_LEN,
			    "it begins at the restart, so nothing is skipped");
			{
				struct kof_range r[4];
				uint32_t n;

				n = ctx.resolve_entry(&ctx, e->index, r, 4u);
				ok_(n == 1u &&
				    r[0].off == CONTENT_AT + LZX_AT &&
				    r[0].len == LZX_LEN,
				    "and its one piece is the stream from that "
				    "restart");
			}
		}
		/* The regions partition the object - the property every
		 * collector here owes. */
		{
			struct kof_range r[16];
			uint32_t n, i;
			uint64_t total = 0;

			n = ctx.resolve_scan(&ctx, KOF_SCAN_CHM_HEADERS |
						   KOF_SCAN_CHM_DIRECTORY |
						   KOF_SCAN_CHM_CONTENT |
						   KOF_SCAN_CHM_UNCLAIMED,
					     r, 16u);
			for (i = 0; i < n; i++)
				total += r[i].len;
			ok_(total == len, "the regions cover the object once");
		}
	}

	/* ---- a chunk count larger than the file ------------------------ */
	{
		uint8_t save[4];

		memcpy(save, f + ITSF_LEN + 44, 4);
		wr32(f + ITSF_LEN + 44, 0xffffffffu);
		memset(&ctx, 0, sizeof ctx);
		kof_chm_parse(buf_of(f, len), c, &ctx);
		ok_((c->anomalies & KOF_CHM_ANOM_TRUNCATED) != 0,
		    "a chunk count past the end of the file is refused");
		ok_(c->n_chunks * (uint64_t)c->chunk_size <= len,
		    "and clamped to what the object holds");
		memcpy(f + ITSF_LEN + 44, save, 4);
	}

	/* ---- a chunk size that is not one ------------------------------ */
	{
		uint8_t save[4];

		memcpy(save, f + ITSF_LEN + 16, 4);
		wr32(f + ITSF_LEN + 16, 4097u);   /* not a power of two */
		memset(&ctx, 0, sizeof ctx);
		kof_chm_parse(buf_of(f, len), c, &ctx);
		ok_((c->anomalies & KOF_CHM_ANOM_BAD_DIRECTORY) != 0 &&
		    c->n_entries == 0u,
		    "a chunk size no writer produces stops the walk");
		memcpy(f + ITSF_LEN + 16, save, 4);
	}

	/* ---- a name longer than the chunk ------------------------------ */
	{
		uint8_t *at = f + DIR_AT + 0x14u;
		uint8_t save[2];

		memcpy(save, at, 2);
		/*
		 * The first entry's name length, made larger than the entries
		 * area it sits in - 512 as a two byte encint. The walk must
		 * stop at the chunk rather than read the rest of the object.
		 *
		 * Not the largest single byte value, which is what this said
		 * first: 127 fits inside a chunk once the fixture carries the
		 * compressed section's entries, so the case stopped being one.
		 */
		at[0] = 0x84u;
		at[1] = 0x00u;
		memset(&ctx, 0, sizeof ctx);
		kof_chm_parse(buf_of(f, len), c, &ctx);
		ok_(c->n_entries == 0u,
		    "a name that does not fit its chunk ends the walk");
		memcpy(at, save, 2);
	}

	/* ---- an entry pointing past the end ---------------------------- */
	{
		/* Rebuild with the page's length set past the object, which is
		 * the row the host would otherwise be handed. */
		uint8_t *g = calloc(1, FILE_LEN);
		size_t glen = 0;
		uint8_t *gd, *gat;

		if (g) {
			free(g);
			g = build(&glen);
		}
		if (g) {
			gd = g + DIR_AT;
			gat = gd + 0x14u;
			gat += put_entry(gat, "/page.htm", 0, 0, 0xffffu);
			wr32(gd + 4, (uint32_t)(CHUNK - (uint32_t)(gat - gd)));
			memset(&ctx, 0, sizeof ctx);
			kof_chm_parse(buf_of(g, glen), c, &ctx);
			ok_((c->anomalies & KOF_CHM_ANOM_ENTRY_PAST_EOF) != 0,
			    "an entry running past the object is dropped and "
			    "said");
			free(g);
		}
	}

	/* ---- a path that means to escape ------------------------------- */
	{
		uint8_t *g = build(&len);

		if (g) {
			uint8_t *gd = g + DIR_AT;
			uint8_t *gat = gd + 0x14u;

			gat += put_entry(gat, "/../../evil.htm", 0, 0, 16);
			wr32(gd + 4, (uint32_t)(CHUNK - (uint32_t)(gat - gd)));
			memset(&ctx, 0, sizeof ctx);
			kof_chm_parse(buf_of(g, len), c, &ctx);
			ok_((c->anomalies & KOF_CHM_ANOM_TRAVERSAL) != 0,
			    "a traversal in a name is recorded");
			free(g);
		}
	}

	free(f);
	free(c);

	if (failures) {
		printf("chm walk: %d check(s) failed\n", failures);
		return 1;
	}
	printf("chm walk: header, directory, entries, the coded section's three "
	       "structures and where they place a page, regions, a huge count, "
	       "a bad chunk size, a huge name, a past-the-end entry, traversal "
	       "- ok\n");
	return 0;
}
