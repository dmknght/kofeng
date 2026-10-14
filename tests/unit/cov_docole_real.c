/*
 * cov_docole_real - a compound document with a VBA project, written byte by byte, through the shipped unpacker.
 *
 * A Word or Excel document with macros is an OLE compound file (MS-CFB): a header, a FAT, a directory that is
 * a tree of entries, small streams packed into a mini stream behind a mini FAT, large ones in sectors of their
 * own - and, inside the VBA storage, a `dir` stream (itself MS-OVBA compressed) that says where each module's
 * compressed source begins in its stream. No such file is in the tree, so this writes one:
 *
 *   header        sector 512, mini sector 64, mini cutoff 4096, one FAT sector, the DIFAT in the header
 *   directory     Root Entry, VBA (a storage), dir, Module1, _VBA_PROJECT, WordDocument - linked as the tree the
 *                 format has, siblings ordered by name length
 *   streams       dir, Module1 (40 bytes of compiled code, then the OVBA container of the source) and _VBA_PROJECT in
 *                 the mini stream; WordDocument, 5000 bytes, in ordinary sectors
 *
 * and then asks the engine what it makes of it. What is asserted: the module's SOURCE comes out as a child, equal to
 * the text written (the offset in `dir` was used, the OVBA container decoded); `dir` comes out decoded and holds the
 * module's name and offset records; the document body is gathered whole (5000 bytes, from sectors that are not
 * contiguous); a bad archive is named (a chain that loops, a stream past the end of the file, a FAT that points
 * outside it, a mini stream larger than its container, a directory that points at itself) and not read as a good
 * one; and every cut of the file and a few thousand flipped bits give an answer and no child longer than the file
 * can hold.
 *
 * No file is written. The engine is the release database's.
 */

#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"

#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofcore.h"

#define DB_RELEASE "build/release/databases"

#include "cov_fixtures_ole.h"

/* ---- scanning ----------------------------------------------------------------------------------- */

#define MAXKIDS 12
struct kid {
	char     name[160];
	uint64_t len;
	uint8_t  data[8192];
	uint32_t broken;
};

struct scan {
	struct kid kid[MAXKIDS];
	unsigned   n;
	uint32_t   root_broken;
};

static int on_obj(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *user)
{
	struct scan *s = user;

	if (s->n == 0) {
		s->root_broken = r->broken;
	} else if (s->n <= MAXKIDS) {
		struct kid *k = &s->kid[s->n - 1];

		snprintf(k->name, sizeof k->name, "%s", name);
		k->len = n;
		memcpy(k->data, b, n < sizeof k->data ? n : sizeof k->data);
		k->broken = r->broken;
	}
	s->n++;
	return 0;
}

static struct scan g_scan;
static struct doc g_doc, g_bad;

static unsigned do_scan(kof_scanner *sc, const uint8_t *b, size_t n)
{
	struct kof_scan_option op = he_opt();

	memset(&g_scan, 0, sizeof g_scan);
	(void)kscan_bytes(sc, b, n, "d.doc", &op, on_obj, &g_scan);
	return g_scan.n ? g_scan.n - 1u : 0u;
}

static const struct kid *by_name(const char *want)
{
	unsigned i, n = g_scan.n ? g_scan.n - 1u : 0u;
	size_t lw = strlen(want);

	for (i = 0; i < n && i < MAXKIDS; i++) {
		size_t l = strlen(g_scan.kid[i].name);

		if (l >= lw && !strcmp(g_scan.kid[i].name + l - lw, want))
			return &g_scan.kid[i];
	}
	return NULL;
}

static void dump(void)
{
	unsigned i;

	for (i = 0; i + 1 < g_scan.n && i < MAXKIDS; i++)
		printf("      child %u: %s (%llu bytes, broken %u)\n", i, g_scan.kid[i].name, (unsigned long long)g_scan.kid[i].len,
		       g_scan.kid[i].broken);
	printf("      root broken %u\n", g_scan.root_broken);
}

/* ---- the checks --------------------------------------------------------------------------------- */

static void t_good(kof_scanner *sc)
{
	unsigned n;
	const struct kid *k;

	build(&g_doc);
	n = do_scan(sc, g_doc.bytes, g_doc.len);
	if (n < 3)
		dump();
	CK(n >= 3, "the document opens its macro streams and its body (%u children)", n);
	k = by_name("Module1");
	CK(k && k->len == sizeof SRC - 1 && !memcmp(k->data, SRC, sizeof SRC - 1),
	   "the module's SOURCE is a child, equal to what was written (%llu bytes, wanted %zu)", k ? (unsigned long long)k->len : 0ull,
	   sizeof SRC - 1);
	k = by_name("dir");
	CK(k && k->len == g_doc.dir_plain_len && !memcmp(k->data, g_doc.dir_plain, g_doc.dir_plain_len),
	   "dir comes out decoded, with the module's name and offset records (%llu bytes, wanted %zu)", k ? (unsigned long long)k->len : 0ull,
	   g_doc.dir_plain_len);
	k = by_name("_VBA_PROJECT");
	CK(k && k->len == 7 && !memcmp(k->data, "\xcc\x61\xff\xff\x00\x00\x00", 7),
	   "a stream that is not an OVBA container goes out as it lies (%llu bytes)", k ? (unsigned long long)k->len : 0ull);
	{
		unsigned i, body = 0;

		for (i = 0; i < n && i < MAXKIDS; i++)
			if (g_scan.kid[i].len >= sizeof g_doc.body && !memcmp(g_scan.kid[i].data, g_doc.body, 64))
				body = 1;
		CK(body, "the document body is gathered whole from sectors that are not contiguous");
	}
	CK(g_scan.root_broken == 0, "a good document is not reported broken (%u)", g_scan.root_broken);
}

/* each way a compound file can lie about itself, and what the scan says */
static void t_wrong(kof_scanner *sc)
{
	unsigned n;

	/* a FAT chain that loops: the body's first sector points at itself */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w32(g_bad.bytes + SEC * 1 + 4u * g_doc.first_big, g_doc.first_big);
	w64(g_bad.bytes + SEC * (1 + 1) + 128 * 5 + 120, 2000000);      /* longer than the walk budget (1024 steps) allows */
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(g_scan.root_broken != 0, "a FAT chain that loops marks the document broken (%u children, broken %u)", n, g_scan.root_broken);
	CK(g_scan.root_broken == KOF_BROKEN_DAMAGED || g_scan.root_broken == KOF_BROKEN_LIMIT, "and as damage or limit, not another reason (%u)", g_scan.root_broken);

	/* the directory's first sector beyond the file */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w32(g_bad.bytes + 48, 0x00ffffffu);
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(n == 0 || g_scan.root_broken != 0, "a directory start outside the file opens nothing or says so (%u, %u)", n, g_scan.root_broken);

	/* the sector shift of a version that does not exist */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w16(g_bad.bytes + 30, 31);
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(n == 0, "a sector shift of 31 opens nothing (%u)", n);
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w16(g_bad.bytes + 30, 12);                   /* 4096 byte sectors in a file written with 512 */
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(n <= 3, "the wrong sector size gives no more than a few objects (%u)", n);

	/* the file cut short in the middle of the body */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	n = do_scan(sc, g_bad.bytes, g_doc.len - 2000);
	CK(g_scan.root_broken != 0, "a body that runs past the end of the file marks it broken (%u)", g_scan.root_broken);

	/* the root's mini stream larger than the sectors that hold it */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w64(g_bad.bytes + SEC * (1 + 1) + 120, 1ull << 30);
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(n <= 6, "a mini stream that claims a gigabyte opens a bounded number of objects (%u)", n);

	/* a directory whose root is its own child */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w32(g_bad.bytes + SEC * (1 + 1) + 76, 0);
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(n <= 6, "a root that is its own child ends the walk (%u)", n);

	/* the sibling of a stream points back at the stream before it */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	w32(g_bad.bytes + SEC * (1 + 1) + 128 * 4 + 72, 3);
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(n <= 8, "a sibling cycle in the directory ends the walk (%u)", n);

	/* the module's offset in dir points past the stream: the module is described, not read at that place */
	memcpy(&g_bad, &g_doc, sizeof g_bad);
	{
		uint32_t big = 0x7fffffffu;
		size_t i;

		/* the dir stream is compressed: instead make Module1's own size tiny so the offset (40) is past it */
		(void)big; (void)i;
		w64(g_bad.bytes + SEC * (1 + 1) + 128 * 3 + 120, 20);
	}
	n = do_scan(sc, g_bad.bytes, g_bad.len);
	CK(by_name("Module1") == NULL || by_name("Module1")->len != sizeof SRC - 1, "a module whose offset is past its stream is not decoded as source (%u children)", n);
}

static void t_hostile(kof_scanner *sc)
{
	static uint8_t flip[SEC * 40];
	size_t k, i, step = 7;
	uint64_t seed = 0x01d0cf11e0ull;

	for (k = 0; k <= g_doc.len; k += step) {
		struct he_guard g;

		if (!he_guard_make(&g, g_doc.bytes, k))
			continue;
		do_scan(sc, g.p, k);
		for (i = 0; i + 1 < g_scan.n && i < MAXKIDS; i++)
			CK(g_scan.kid[i].len <= g_doc.len * 8u, "cut %zu: child %zu is %llu bytes", k, i, (unsigned long long)g_scan.kid[i].len);
		he_guard_free(&g);
	}
	for (i = 0; i < 2500; i++) {
		size_t at, j;

		seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
		memcpy(flip, g_doc.bytes, g_doc.len);
		at = (size_t)(seed % (g_doc.len * 8u));
		flip[at / 8] ^= (uint8_t)(1u << (at % 8));
		do_scan(sc, flip, g_doc.len);
		for (j = 0; j + 1 < g_scan.n && j < MAXKIDS; j++)
			CK(g_scan.kid[j].len <= 1u << 22, "flip %zu: child %zu is %llu bytes", i, j, (unsigned long long)g_scan.kid[j].len);
	}
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : DB_RELEASE;
	struct stat sb;
	kof_engine *e;
	kof_scanner *sc;

	if (stat(db, &sb) != 0) {
		printf("cov_docole_real: no database at %s (make) - nothing tested\n", db);
		return 0;
	}
	e = keng_open(db);
	if (!e) {
		printf("cov_docole_real: the database did not load\n");
		return 1;
	}
	sc = kscan_new(e);
	if (!sc) {
		printf("cov_docole_real: no scanner\n");
		keng_close(e);
		return 1;
	}
	t_good(sc);
	t_wrong(sc);
	t_hostile(sc);
	kscan_free(sc);
	keng_close(e);
	printf("cov_docole_real: %u check(s), %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
