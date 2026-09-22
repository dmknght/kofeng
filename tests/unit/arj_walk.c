/*
 * arj_walk - the framed header chain, and the frames that do not add up.
 *
 * ARJ frames every header with a magic and a length, which is one more check
 * than LHA has - and the cases below are about what the walk does when the
 * frame and the contents disagree. The fixture is built here, like the other
 * archive tests', because the shapes worth testing are not the ones an archiver
 * produces.
 *
 * The first header of an ARJ is the archive's own and carries no data, so a
 * parser that treats it as a file invents an entry out of the archive's name -
 * which is the first case below.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/analyzer/parsers/containers/arj_parse.h"

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

#define FIRST_SIZE 30u

/*
 * One header: magic, length, the fixed part, a name, a comment, a CRC, and the
 * empty extension list. `body` is written after it when there is one.
 */
static uint32_t put_hdr(uint8_t *p, uint8_t method, uint8_t ftype,
			uint8_t flags, const char *name,
			const uint8_t *body, uint32_t blen)
{
	uint32_t nl = (uint32_t)strlen(name) + 1u;
	uint32_t basic = FIRST_SIZE + nl + 1u;   /* + the empty comment */
	uint32_t at;

	p[0] = 0x60u;
	p[1] = 0xeau;
	wr16(p + 2, (uint16_t)basic);
	p[4] = FIRST_SIZE;          /* first_hdr_size */
	p[5] = 11;                  /* archiver version */
	p[6] = 1;                   /* minimum version */
	p[7] = 2;                   /* host os */
	p[8] = flags;
	p[9] = method;
	p[10] = ftype;
	wr32(p + 16, blen);         /* compressed size */
	wr32(p + 20, blen);         /* original size */
	memcpy(p + 4 + FIRST_SIZE, name, nl);
	p[4 + FIRST_SIZE + nl] = 0; /* the comment: empty */

	at = 4u + basic;
	wr32(p + at, 0);            /* the basic header's CRC */
	at += 4u;
	wr16(p + at, 0);            /* no extension headers */
	at += 2u;
	if (blen) {
		memcpy(p + at, body, blen);
		at += blen;
	}
	return at;
}

static kof_buf buf_of(const uint8_t *p, size_t n)
{
	kof_buf b;

	b.p = p;
	b.n = n;
	return b;
}

#define BODY "kofeng-arj-fixture-body"

int main(void)
{
	struct kof_arj_info *a = malloc(sizeof *a);
	struct kof_obj_ctx ctx;
	uint8_t *f = calloc(1, 512);
	uint32_t at = 0, second;
	size_t len;

	if (!a || !f) {
		free(a);
		free(f);
		printf("arj walk: out of memory\n");
		return 1;
	}

	/* The archive header, a stored file, a coded one, and the end. */
	at = put_hdr(f, 0, 2, 0, "archive.arj", NULL, 0);
	second = at;
	at += put_hdr(f + at, 0, 0, 0, "stored.txt",
		      (const uint8_t *)BODY, (uint32_t)sizeof BODY - 1u);
	at += put_hdr(f + at, 1, 0, 0, "coded.bin",
		      (const uint8_t *)BODY, 8u);
	wr16(f + at, 0x0000u);      /* magic ... */
	f[at] = 0x60u;
	f[at + 1u] = 0xeau;
	wr16(f + at + 2u, 0);       /* ... and a zero length: the end */
	at += 4u;
	len = at;

	memset(&ctx, 0, sizeof ctx);
	if (!kof_arj_sniff(buf_of(f, len)))
		fail("sniff", "an ARJ header was not recognised");
	if (!kof_arj_parse(buf_of(f, len), a, &ctx)) {
		fail("parse", "a well formed archive would not parse");
	} else {
		ok_((a->anomalies & KOF_ARJ_ANOM_NO_END) == 0,
		    "the end of the chain is found");
		ok_(a->archiver_ver == 11u && a->host_os == 2u,
		    "the archive header's own fields are read");
		/*
		 * TWO entries and not three. The archive header is not a file -
		 * a parser that counts it invents one out of the archive's own
		 * name - and the other two are: one stored, one coded with the
		 * method ARJ's -m1 uses.
		 *
		 * The coded one is an entry rather than a count because the
		 * engine has that coding. It carries the coding in the entry
		 * and the original size in out_hint, which for this coding is
		 * what ENDS the stream rather than a guess at its output.
		 */
		ok_(a->n_entries == 2u, "both files are entries");
		ok_(a->n_coded == 1u, "the coded one is counted as coded");
		if (a->n_entries == 2u) {
			const struct kof_entry *e = &a->entry[0];

			ok_(e->len == sizeof BODY - 1u &&
			    memcmp(f + e->off, BODY, e->len) == 0,
			    "the entry points at its body");
			ok_(e->name_len == 10u &&
			    memcmp(f + e->name_off, "stored.txt", 10) == 0,
			    "the name is a range in the object");
			ok_(e->coding[0] == 0,
			    "a stored entry names no coding");

			e = &a->entry[1];
			ok_(e->coding[0] == KOF_UNP_LZHUF_ARJ &&
			    e->out_hint == 8u,
			    "the coded one names its coding and the size that "
			    "ends its stream");
		}
		{
			struct kof_range r[16];
			uint32_t n, i;
			uint64_t total = 0;

			n = ctx.resolve_scan(&ctx, KOF_SCAN_ARJ_HEADERS |
						   KOF_SCAN_ARJ_NAMES |
						   KOF_SCAN_ARJ_DATA |
						   KOF_SCAN_ARJ_UNCLAIMED,
					     r, 16u);
			for (i = 0; i < n; i++)
				total += r[i].len;
			ok_(total == len, "the regions cover the object once");
		}
	}

	/* ---- a body longer than the object ----------------------------- */
	{
		uint8_t save[4];

		memcpy(save, f + second + 16u, 4);
		wr32(f + second + 16u, 0xffffffu);
		memset(&ctx, 0, sizeof ctx);
		kof_arj_parse(buf_of(f, len), a, &ctx);
		ok_((a->anomalies & KOF_ARJ_ANOM_TRUNCATED) != 0 &&
		    a->n_entries == 0u,
		    "a body running past the object ends the walk");
		memcpy(f + second + 16u, save, 4);
	}

	/* ---- a basic header length the header cannot hold --------------- */
	{
		uint8_t save[2];

		memcpy(save, f + second + 2u, 2);
		wr16(f + second + 2u, 8u);      /* below the fixed part */
		memset(&ctx, 0, sizeof ctx);
		kof_arj_parse(buf_of(f, len), a, &ctx);
		ok_((a->anomalies & KOF_ARJ_ANOM_BAD_HEADER) != 0,
		    "a basic header too short for its own fields is said");
		memcpy(f + second + 2u, save, 2);
	}

	/* ---- the magic gone from the second header ---------------------- */
	{
		uint8_t save = f[second];

		f[second] = 0x61u;
		memset(&ctx, 0, sizeof ctx);
		kof_arj_parse(buf_of(f, len), a, &ctx);
		ok_((a->anomalies & KOF_ARJ_ANOM_TRUNCATED) != 0 &&
		    a->n_entries == 0u,
		    "a chain that loses the magic stops rather than hunting");
		f[second] = save;
	}

	/* ---- an encrypted archive --------------------------------------- */
	{
		uint8_t save = f[second + 8u];

		f[second + 8u] = 0x01u;         /* GARBLED */
		memset(&ctx, 0, sizeof ctx);
		kof_arj_parse(buf_of(f, len), a, &ctx);
		/* The coded one is still offered - it is not the encrypted
		 * one - so what this asks is that the ENCRYPTED entry is gone,
		 * which is the stored one and the only entry with no coding. */
		ok_((a->anomalies & KOF_ARJ_ANOM_ENCRYPTED) != 0 &&
		    a->n_entries == 1u && a->entry[0].coding[0] != 0,
		    "an encrypted entry is said and not pointed at");
		f[second + 8u] = save;
	}

	/* ---- a traversal in a name -------------------------------------- */
	{
		uint8_t *g = calloc(1, 512);

		if (g) {
			uint32_t n = put_hdr(g, 0, 2, 0, "archive.arj", NULL, 0);

			n += put_hdr(g + n, 0, 0, 0, "../../evil",
				     (const uint8_t *)BODY, 4u);
			g[n] = 0x60u;
			g[n + 1u] = 0xeau;
			wr16(g + n + 2u, 0);
			memset(&ctx, 0, sizeof ctx);
			kof_arj_parse(buf_of(g, n + 4u), a, &ctx);
			ok_((a->anomalies & KOF_ARJ_ANOM_TRAVERSAL) != 0,
			    "a traversal in a name is recorded");
			free(g);
		}
	}

	free(f);
	free(a);

	if (failures) {
		printf("arj walk: %d check(s) failed\n", failures);
		return 1;
	}
	printf("arj walk: chain, the archive header is not a file, stored "
	       "entry, coded entry, regions, a huge body, a short header, a "
	       "lost magic, encryption, traversal - ok\n");
	return 0;
}
