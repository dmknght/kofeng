/*
 * lha_walk - the header chain, and where it must refuse to keep going.
 *
 * An LHA archive has no directory: the next header is at the end of this one's
 * body, so a length is not a field to be checked against something else - it IS
 * the walk. That makes the interesting cases the ones where a length is wrong,
 * and the property under test is that the walk STOPS and says so rather than
 * landing on whatever follows and parsing it as a header.
 *
 * The fixture is built here for the reason chm_walk's and cab_walk's are: the
 * shapes worth testing are not the ones a real archiver produces.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofparsers/containers/lha_parse.h"

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

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * One level 0 header and its body.
 *
 * The size byte counts from offset two, and the checksum is the sum of exactly
 * those bytes - so both are computed here rather than written down, which is
 * also what makes the "bad checksum" case below a real mutation.
 */
static uint32_t put_entry(uint8_t *p, const char *method, const char *name,
			  const uint8_t *body, uint32_t blen)
{
	uint32_t nl = (uint32_t)strlen(name);
	uint32_t hsize = 20u + nl + 2u;   /* offset 2 .. name .. crc16 */
	uint32_t sum = 0, i;

	p[0] = (uint8_t)hsize;
	memcpy(p + 2, method, 5);
	wr32(p + 7, blen);                /* compressed size */
	wr32(p + 11, blen);               /* original size */
	wr32(p + 15, 0);                  /* timestamp */
	p[19] = 0x20u;                    /* attribute */
	p[20] = 0;                        /* level 0 */
	p[21] = (uint8_t)nl;
	memcpy(p + 22, name, nl);
	p[22 + nl] = 0;                   /* crc16, which nothing here checks */
	p[23 + nl] = 0;

	for (i = 0; i < hsize; i++)
		sum += p[2 + i];
	p[1] = (uint8_t)sum;

	if (blen)
		memcpy(p + 2 + hsize, body, blen);
	return 2u + hsize + blen;
}

static kof_buf buf_of(const uint8_t *p, size_t n)
{
	kof_buf b;

	b.p = p;
	b.n = n;
	return b;
}

#define BODY "kofeng-lha-fixture-body"

int main(void)
{
	struct kof_lha_info *l = malloc(sizeof *l);
	struct kof_obj_ctx ctx;
	uint8_t *f = calloc(1, 512);
	uint32_t at = 0, first_len;
	size_t len;

	if (!l || !f) {
		free(l);
		free(f);
		printf("lha walk: out of memory\n");
		return 1;
	}

	/* A stored entry, a compressed one, and the end mark. */
	first_len = put_entry(f, "-lh0-", "stored.txt",
			      (const uint8_t *)BODY, (uint32_t)sizeof BODY - 1u);
	at = first_len;
	at += put_entry(f + at, "-lh5-", "coded.bin",
			(const uint8_t *)BODY, 8u);
	f[at++] = 0;                      /* the end mark */
	len = at;

	memset(&ctx, 0, sizeof ctx);
	if (!kof_lha_sniff(buf_of(f, len)))
		fail("sniff", "an LHA header was not recognised");
	if (!kof_lha_parse(buf_of(f, len), l, &ctx)) {
		fail("parse", "a well formed archive would not parse");
	} else {
		ok_((l->anomalies & KOF_LHA_ANOM_NO_END) == 0,
		    "the end mark is found");
		/*
		 * BOTH are entries: "-lh0-" is the file itself and "-lh5-" is
		 * a coding the engine has - it becomes an entry that NAMES the
		 * coding and carries the original size, which for this one is
		 * what ends the stream rather than a guess at its output.
		 */
		ok_(l->n_entries == 2u, "both files are entries");
		ok_(l->n_coded == 1u, "the coded one is counted as coded");
		ok_((l->anomalies & KOF_LHA_ANOM_CODED) != 0,
		    "and said");
		if (l->n_entries == 2u) {
			const struct kof_entry *e = &l->entry[0];

			ok_(e->len == sizeof BODY - 1u &&
			    memcmp(f + e->off, BODY, e->len) == 0,
			    "the entry points at its body");
			ok_(e->name_len == 10u &&
			    memcmp(f + e->name_off, "stored.txt", 10) == 0,
			    "the name is a range in the object");
			ok_(e->coding[0] == 0,
			    "a stored entry names no coding");

			e = &l->entry[1];
			ok_(e->coding[0] == KOF_UNP_LZHUF_LH5 &&
			    e->out_hint == 8u,
			    "the coded one names its coding and the size that "
			    "ends its stream");
		}
		{
			struct kof_range r[16];
			uint32_t n, i;
			uint64_t total = 0;

			n = ctx.resolve_scan(&ctx, KOF_SCAN_LHA_HEADERS |
						   KOF_SCAN_LHA_NAMES |
						   KOF_SCAN_LHA_DATA |
						   KOF_SCAN_LHA_UNCLAIMED,
					     r, 16u);
			for (i = 0; i < n; i++)
				total += r[i].len;
			ok_(total == len, "the regions cover the object once");
		}
	}

	/* ---- a body longer than the object ----------------------------- */
	{
		uint8_t save[4];

		memcpy(save, f + 7, 4);
		wr32(f + 7, 0xffffffu);
		memset(&ctx, 0, sizeof ctx);
		kof_lha_parse(buf_of(f, len), l, &ctx);
		ok_((l->anomalies & KOF_LHA_ANOM_TRUNCATED) != 0 &&
		    l->n_entries == 0u,
		    "a body running past the object ends the walk");
		memcpy(f + 7, save, 4);
	}

	/* ---- a header level that does not exist ------------------------ */
	{
		uint8_t save = f[20];

		f[20] = 7u;
		memset(&ctx, 0, sizeof ctx);
		kof_lha_parse(buf_of(f, len), l, &ctx);
		ok_((l->anomalies & KOF_LHA_ANOM_BAD_LEVEL) != 0,
		    "a level outside 0..2 ends the walk");
		f[20] = save;
	}

	/* ---- a name that does not fit its own header -------------------- */
	{
		uint8_t save = f[21];

		f[21] = 200u;             /* longer than the header says it is */
		memset(&ctx, 0, sizeof ctx);
		kof_lha_parse(buf_of(f, len), l, &ctx);
		ok_((l->anomalies & KOF_LHA_ANOM_TRUNCATED) != 0 &&
		    l->n_entries == 0u,
		    "a name past the end of its header ends the walk");
		f[21] = save;
	}

	/* ---- an edited header ------------------------------------------ */
	{
		uint8_t save = f[22];

		f[22] = 'X';              /* the first byte of the name */
		memset(&ctx, 0, sizeof ctx);
		kof_lha_parse(buf_of(f, len), l, &ctx);
		ok_((l->anomalies & KOF_LHA_ANOM_BAD_CHECKSUM) != 0,
		    "a header that does not match its checksum is said");
		f[22] = save;
	}

	/* ---- no end mark ------------------------------------------------ */
	{
		memset(&ctx, 0, sizeof ctx);
		kof_lha_parse(buf_of(f, len - 1u), l, &ctx);
		ok_((l->anomalies & KOF_LHA_ANOM_NO_END) != 0,
		    "an archive that just stops is said");
	}

	/* ---- a traversal in a name -------------------------------------- */
	{
		uint8_t *g = calloc(1, 512);

		if (g) {
			uint32_t n = put_entry(g, "-lh0-", "../../evil",
					       (const uint8_t *)BODY, 4u);

			g[n] = 0;
			memset(&ctx, 0, sizeof ctx);
			kof_lha_parse(buf_of(g, n + 1u), l, &ctx);
			ok_((l->anomalies & KOF_LHA_ANOM_TRAVERSAL) != 0,
			    "a traversal in a name is recorded");
			free(g);
		}
	}

	free(f);
	free(l);

	if (failures) {
		printf("lha walk: %d check(s) failed\n", failures);
		return 1;
	}
	printf("lha walk: chain, stored entry, coded entry, regions, a huge "
	       "body, a bad level, a name past its header, a bad checksum, no "
	       "end mark, traversal - ok\n");
	return 0;
}
