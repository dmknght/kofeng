/*
 * entry_child - every container that fills an entry table gets children out of
 * it, and the children are the right bytes under the right names.
 *
 * WHY ONE TEST FOR THREE FORMATS. The walk tests beside this one - cab_walk,
 * lha_walk, arj_walk - link the parser alone and assert what it recorded. That
 * leaves the step after it untested, and it is a step none of those parsers can
 * see: the host opens carried files GENERICALLY from the entry table (see
 * kof_objtree_declared), so a parser that fills the table correctly needs no
 * module, and one that fills it wrongly produces nothing.
 *
 * Nothing about that failure is visible in a scan. The archive is opened, the
 * names are parsed, no child is made, nothing matches - and the file is
 * reported clean, quickly. So the assertion here is a CHILD with the entry's
 * exact bytes and a name that came from the archive's own directory.
 *
 * The fixtures are built in memory, for the reason each walk test gives: no
 * Linux build host writes a cabinet, an LHA or an ARJ.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/core/kofmod/cab.h"
#include "../../libkofeng/core/kofmod/lha.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* What every fixture below stores, and what the child must turn out to be. */
static const char body[] = "kofeng-entry-child-fixture-body";
#define BODY_LEN (sizeof body - 1u)

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

/* ---- a cabinet with one stored file ----------------------------------------- */

#define CAB_HDR 36u
#define CAB_FOLD_AT CAB_HDR
#define CAB_FILES_AT (CAB_FOLD_AT + 8u)

static size_t build_cab(uint8_t *f, const char *name)
{
	size_t nl = strlen(name) + 1u;
	uint32_t at;

	memcpy(f, "MSCF", 4);
	wr16(f + 24, 0x0301u);
	wr16(f + 26, 1);                    /* one folder */
	wr16(f + 28, 1);                    /* one file */
	wr32(f + 16, CAB_FILES_AT);

	at = CAB_FILES_AT;
	wr32(f + at, (uint32_t)BODY_LEN);   /* cbFile */
	wr32(f + at + 4, 0);                /* uoffFolderStart */
	wr16(f + at + 8, 0);                /* iFolder */
	wr16(f + at + 14, 0x20u);
	memcpy(f + at + 16, name, nl);
	at += (uint32_t)(16u + nl);

	wr32(f + CAB_FOLD_AT, at);          /* coffCabStart */
	wr16(f + CAB_FOLD_AT + 4, 1);       /* one CFDATA */
	wr16(f + CAB_FOLD_AT + 6, KOF_CAB_C_NONE);

	wr32(f + at, 0);                    /* checksum */
	wr16(f + at + 4, (uint16_t)BODY_LEN);
	wr16(f + at + 6, (uint16_t)BODY_LEN);
	memcpy(f + at + 8, body, BODY_LEN);
	at += (uint32_t)(8u + BODY_LEN);

	wr32(f + 8, at);                    /* cbCabinet */
	return at;
}

/*
 * The same cabinet, with the file cut across two CFDATA blocks.
 *
 * The body is written in two halves with a block header between them, which is
 * exactly what a stored file over 32KB looks like in a real cabinet - only
 * smaller, so the fixture stays readable.
 */
static size_t build_cab_split(uint8_t *f, const char *name)
{
	size_t nl = strlen(name) + 1u;
	uint32_t at, half = (uint32_t)(BODY_LEN / 2u);

	memcpy(f, "MSCF", 4);
	wr16(f + 24, 0x0301u);
	wr16(f + 26, 1);
	wr16(f + 28, 1);
	wr32(f + 16, CAB_FILES_AT);

	at = CAB_FILES_AT;
	wr32(f + at, (uint32_t)BODY_LEN);
	wr32(f + at + 4, 0);
	wr16(f + at + 8, 0);
	wr16(f + at + 14, 0x20u);
	memcpy(f + at + 16, name, nl);
	at += (uint32_t)(16u + nl);

	wr32(f + CAB_FOLD_AT, at);
	wr16(f + CAB_FOLD_AT + 4, 2);       /* two CFDATA blocks */
	wr16(f + CAB_FOLD_AT + 6, KOF_CAB_C_NONE);

	wr32(f + at, 0);
	wr16(f + at + 4, (uint16_t)half);
	wr16(f + at + 6, (uint16_t)half);
	memcpy(f + at + 8, body, half);
	at += 8u + half;

	wr32(f + at, 0);
	wr16(f + at + 4, (uint16_t)(BODY_LEN - half));
	wr16(f + at + 6, (uint16_t)(BODY_LEN - half));
	memcpy(f + at + 8, body + half, BODY_LEN - half);
	at += (uint32_t)(8u + BODY_LEN - half);

	wr32(f + 8, at);
	return at;
}

/* ---- an LHA with one stored entry ------------------------------------------- */

static size_t build_lha(uint8_t *f, const char *name)
{
	uint32_t nl = (uint32_t)strlen(name);
	uint32_t hsize = 20u + nl + 2u;
	uint32_t sum = 0, i;

	f[0] = (uint8_t)hsize;
	memcpy(f + 2, "-lh0-", 5);
	wr32(f + 7, (uint32_t)BODY_LEN);
	wr32(f + 11, (uint32_t)BODY_LEN);
	f[19] = 0x20u;
	f[20] = 0;                          /* level 0 */
	f[21] = (uint8_t)nl;
	memcpy(f + 22, name, nl);
	for (i = 0; i < hsize; i++)
		sum += f[2 + i];
	f[1] = (uint8_t)sum;
	memcpy(f + 2 + hsize, body, BODY_LEN);
	f[2 + hsize + BODY_LEN] = 0;        /* the end mark */
	return 2u + hsize + BODY_LEN + 1u;
}

/* ---- an ARJ with its archive header and one stored entry -------------------- */

#define ARJ_FIRST 30u

static uint32_t arj_hdr(uint8_t *p, uint8_t method, uint8_t ftype,
			const char *name, uint32_t blen)
{
	uint32_t nl = (uint32_t)strlen(name) + 1u;
	uint32_t basic = ARJ_FIRST + nl + 1u;
	uint32_t at;

	p[0] = 0x60u;
	p[1] = 0xeau;
	wr16(p + 2, (uint16_t)basic);
	p[4] = ARJ_FIRST;
	p[5] = 11;
	p[6] = 1;
	p[7] = 2;
	p[4 + 5] = method;                  /* base + 5 */
	p[4 + 6] = ftype;                   /* base + 6 */
	wr32(p + 4 + 12, blen);             /* base + 12: compressed size */
	wr32(p + 4 + 16, blen);             /* base + 16: original size */
	memcpy(p + 4 + ARJ_FIRST, name, nl);
	p[4 + ARJ_FIRST + nl] = 0;          /* empty comment */

	at = 4u + basic;
	wr32(p + at, 0);                    /* header CRC */
	at += 4u;
	wr16(p + at, 0);                    /* no extension headers */
	at += 2u;
	if (blen) {
		memcpy(p + at, body, blen);
		at += blen;
	}
	return at;
}

static size_t build_arj(uint8_t *f, const char *name)
{
	uint32_t at = arj_hdr(f, 0, 2, "archive.arj", 0);

	at += arj_hdr(f + at, 0, 0, name, (uint32_t)BODY_LEN);
	f[at] = 0x60u;
	f[at + 1u] = 0xeau;
	wr16(f + at + 2u, 0);               /* the end of the chain */
	return at + 4u;
}

/* ---- the scan ---------------------------------------------------------------- */

struct seen {
	const char *want_name;
	int objects, matched, named;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)res;
	s->objects++;
	if (bytes && len == BODY_LEN && memcmp(bytes, body, (size_t)len) == 0) {
		s->matched++;
		if (name && strstr(name, s->want_name))
			s->named++;
	}
	return 0;
}

static void one(struct kof_scanner *sc, const char *what, const uint8_t *f,
		size_t n, const char *want_name)
{
	struct kof_scan_option opt;
	struct seen s;
	int rc;

	memset(&s, 0, sizeof s);
	s.want_name = want_name;
	memset(&opt, 0, sizeof opt);
	rc = kof_scan_bytes(sc, f, n, what, &opt, on_object, &s);

	if (rc <= 0)
		fail(what, "the archive was not scanned at all");
	else if (s.objects < 2)
		fail(what, "the entry table named a file and no child was made "
		     "of it");
	else if (!s.matched)
		fail(what, "a child was made and it is not the entry's bytes");
	else if (!s.named)
		fail(what, "the child carries no name, though the archive has "
		     "one for it");
}

/*
 * The same assertion, for a child that had to be JOINED rather than windowed.
 *
 * Its bytes and its name are the same - which is the point: a reader of the
 * result cannot tell that one file was in one piece and the other in two, and
 * that is the only acceptable difference between them.
 */
static void one_split(struct kof_scanner *sc, const char *what,
		      const uint8_t *f, size_t n, const char *want_name)
{
	one(sc, what, f, n, want_name);
}

int main(void)
{
	static const char *db = "build/release/databases";
	struct kof_engine *eng;
	struct kof_scanner *sc;
	uint8_t *f = calloc(1, 1024);
	size_t n;

	if (!f) {
		printf("entry child: out of memory\n");
		return 1;
	}
	eng = kof_engine_open(db);
	if (!eng) {
		free(f);
		printf("entry child: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		free(f);
		printf("entry child: could not make a scanner\n");
		return 1;
	}

	memset(f, 0, 1024);
	n = build_cab(f, "payload.exe");
	one(sc, "cab", f, n, "payload.exe");

	/*
	 * AND A CABINET WHOSE FILE IS IN PIECES.
	 *
	 * The case the generic step cannot do: a stored file crossing a block
	 * boundary, which every stored file over 32KB is. It reaches a child
	 * only through resolve_entry and the join, so this is what says that
	 * path is wired up - see bases/decomp/cab.c.
	 */
	{
		uint8_t *g = calloc(1, 4096);

		if (g) {
			size_t gn = build_cab_split(g, "big.bin");

			one_split(sc, "cab split", g, gn, "big.bin");
			free(g);
		}
	}

	memset(f, 0, 1024);
	n = build_lha(f, "payload.bin");
	one(sc, "lha", f, n, "payload.bin");

	memset(f, 0, 1024);
	n = build_arj(f, "payload.dat");
	one(sc, "arj", f, n, "payload.dat");

	kof_scanner_free(sc);
	kof_engine_close(eng);
	free(f);

	if (failures) {
		printf("entry child: %d check(s) failed\n", failures);
		return 1;
	}
	printf("entry child: cab, lha, arj - each entry is a named child of "
	       "the right bytes - ok\n");
	return 0;
}
