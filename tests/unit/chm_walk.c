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

#include "../../libkofeng/kofparsers/containers/chm_parse.h"

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
#define FILE_LEN (CONTENT_AT + 64u)

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
static uint32_t enc(uint8_t *p, uint64_t v)
{
	uint8_t tmp[5];
	uint32_t n = 0, i;

	do {
		tmp[n++] = (uint8_t)(v & 0x7fu);
		v >>= 7;
	} while (v && n < 5u);
	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(tmp[n - 1u - i] | (i + 1u < n ? 0x80u : 0u));
	return n;
}

static uint32_t put_entry(uint8_t *p, const char *name, uint64_t sect,
			  uint64_t off, uint64_t len)
{
	uint32_t n = 0;
	size_t nl = strlen(name);

	n += enc(p + n, nl);
	memcpy(p + n, name, nl);
	n += (uint32_t)nl;
	n += enc(p + n, sect);
	n += enc(p + n, off);
	n += enc(p + n, len);
	return n;
}

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
	at += put_entry(at, "/page.htm", 0, 0, 32);
	at += put_entry(at, "/hidden.htm", 1, 0, 99);
	at += put_entry(at, "::DataSpace/NameList", 0, 32, 16);
	/* Everything after the entries is the chunk's free space, which is what
	 * the header's second field states - get this wrong and the walk reads
	 * the quickref area as if it were entries. */
	wr32(dir + 4, (uint32_t)(CHUNK - (uint32_t)(at - dir)));

	memcpy(f + CONTENT_AT, "kofeng-chm-fixture-page-bytes-32", 32);
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
		 * ONE entry: the page. The compressed one is counted and not
		 * offered - this build has no LZX, and an entry it cannot point
		 * at must not become a child of the wrong bytes. The NameList
		 * is the format's own bookkeeping.
		 */
		ok_(c->n_entries == 1u, "one openable entry");
		ok_(c->n_compressed == 1u, "the compressed one is counted");
		ok_(c->n_special == 1u, "the format's own entry is counted");
		if (c->n_entries == 1u) {
			const struct kof_entry *e = &c->entry[0];

			ok_(e->kind == KOF_ENT_EMBEDDED,
			    "an entry is a carried file");
			ok_(e->off == CONTENT_AT && e->len == 32u,
			    "the entry points at its bytes");
			ok_(e->name_len == 9u &&
			    memcmp(f + e->name_off, "/page.htm", 9) == 0,
			    "the name is a range in the object");
			ok_(memcmp(f + e->off, "kofeng-chm", 10) == 0,
			    "and the bytes are the ones it named");
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
		uint8_t save = at[0];

		/* The first entry's name length, made huge. The walk must stop
		 * at the chunk rather than read the rest of the object. */
		at[0] = 0x7fu;
		memset(&ctx, 0, sizeof ctx);
		kof_chm_parse(buf_of(f, len), c, &ctx);
		ok_(c->n_entries == 0u,
		    "a name that does not fit its chunk ends the walk");
		at[0] = save;
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
	printf("chm walk: header, directory, entries, regions, a huge count, a "
	       "bad chunk size, a huge name, a past-the-end entry, traversal - "
	       "ok\n");
	return 0;
}
