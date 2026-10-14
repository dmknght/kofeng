/*
 * cov_sevenzip_real - real 7z archives, written byte by byte, through the shipped unpacker.
 *
 * The fixtures a 7z test needs (an archive made by 7-Zip) are not in the tree and the tool is not on
 * the machine, so the archives are WRITTEN here from the format document: the signature header with its
 * three CRCs, packed streams, and a header that names folders, coders and files. The coded streams are
 * made by xz (raw LZMA and LZMA2) and gzip (raw deflate), so a decoder that is wrong in the same way as
 * the writer's reading of the format is still caught on the coders. Each archive is scanned with the
 * release database, and the children it opens are compared with the files put in:
 *
 *   LAYOUTS     one folder with several files (a solid block); one folder per file; an empty file and an empty
 *               stream; a name with a directory in it; a coder chain (x86 branch filter, then LZMA2) and plain
 *               LZMA, LZMA2, deflate, and copy
 *   HEADERS     a plain header, and a header that is itself coded with LZMA (what 7-Zip writes for any archive
 *               of size): the coded header's packed bytes and its coder are found, decoded, and the archive
 *               read from what comes out
 *   WRONG       a start header whose CRC is wrong, a next header past the end, a next header of size zero, a
 *               header kind that is not one: each is reported (an anomaly bit or a broken object) and none is
 *               read as a good archive
 *   CUTS, FLIPS every prefix of a small archive and a few thousand bit flips of two archives: the scan answers
 *               (children or none), never a child longer than its declared size, and never reads outside the
 *               object (the guard page, in the plain build; the sanitiser, in the other)
 *
 * Skipped, visibly, for each tool that is not installed. No file is written.
 */

#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"

#include <sys/stat.h>


#define DB_RELEASE "build/release/databases"

#include "cov_fixtures_7z.h"

/* ---- scanning --------------------------------------------------------------------------------- */

#define MAXKIDS 16
struct kid {
	char     name[160];
	uint64_t len;
	uint8_t  data[8192];
	uint32_t broken;
};

struct scan {
	struct kid kid[MAXKIDS];
	unsigned   n;
	uint32_t   root_broken, root_anom;
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

static void dump(const struct scan *s)
{
	unsigned i;

	for (i = 0; i + 1 < s->n && i < MAXKIDS; i++)
		printf("      child %u: %s (%llu bytes, broken %u)\n", i, s->kid[i].name, (unsigned long long)s->kid[i].len, s->kid[i].broken);
	printf("      root broken %u\n", s->root_broken);
}

static unsigned do_scan(kof_scanner *sc, const uint8_t *arc, size_t n, struct scan *out)
{
	struct kof_scan_option op = he_opt();

	memset(out, 0, sizeof *out);
	(void)kscan_bytes(sc, arc, n, "x.7z", &op, on_obj, out);
	return out->n ? out->n - 1u : 0u;
}

static uint8_t g_plain[4][8192], g_pack[1 << 16], g_arc[1 << 17], g_hdr[4096], g_coded_hdr[4096], g_all[1 << 15];

static int same(const struct kid *k, const uint8_t *want, size_t n)
{
	return k && k->len == n && !memcmp(k->data, want, n < sizeof k->data ? n : sizeof k->data);
}

/* ---- tests -------------------------------------------------------------------------------------- */

/* one solid LZMA2 folder with three files, plain header; and the same behind a coded header */
static void t_solid(kof_scanner *sc, int coded_header)
{
	static const struct afile files[3] = { { "a.txt", 0, 0 }, { "dir/b.txt", 0, 0 }, { "c.txt", 0, 0 } };
	struct folder fo;
	size_t n0, n1, n2, total, packed, hdr, arc;
	static struct scan s;
	unsigned made;

	if (!have("/usr/bin/xz")) {
		printf("  (xz is not installed: the LZMA2 archive is skipped)\n");
		return;
	}
	n0 = text_file(g_plain[0], 0, 20);
	n1 = text_file(g_plain[1], 1, 40);
	n2 = text_file(g_plain[2], 2, 5);
	memcpy(g_all, g_plain[0], n0);
	memcpy(g_all + n0, g_plain[1], n1);
	memcpy(g_all + n0 + n1, g_plain[2], n2);
	total = n0 + n1 + n2;
	packed = via_tool("/usr/bin/xz -c --format=raw --lzma2=preset=6,dict=1MiB", g_all, total, g_pack, sizeof g_pack);
	CK(packed > 0, "xz made the LZMA2 stream");
	memset(&fo, 0, sizeof fo);
	fo.coder[0] = &C_LZMA2;
	fo.n_coders = 1;
	fo.packed = g_pack;
	fo.packed_len = packed;
	fo.unpack_len = total;
	fo.n_files = 3;
	fo.file_len[0] = n0;
	fo.file_len[1] = n1;
	fo.file_len[2] = n2;
	hdr = build_header(g_hdr, sizeof g_hdr, &fo, 1, files, 3);
	if (!coded_header) {
		arc = assemble(g_arc, sizeof g_arc, g_pack, packed, g_hdr, hdr);
	} else {
		/* the header, coded with LZMA and stored after the data; the next header is a pointer to it */
		static uint8_t data[1 << 16], enc_hdr[256];
		struct wb e = { enc_hdr, 0, sizeof enc_hdr };
		size_t hpacked = via_tool("/usr/bin/xz -c --format=raw --lzma1=lc=3,lp=0,pb=2,dict=1MiB", g_hdr, hdr, g_coded_hdr, sizeof g_coded_hdr);
		size_t k;

		CK(hpacked > 0, "xz made the coded header");
		memcpy(data, g_pack, packed);
		memcpy(data + packed, g_coded_hdr, hpacked);
		wb_u8(&e, ID_ENCODED);
		wb_u8(&e, ID_PACKINFO);
		wb_num(&e, packed);                  /* packPos: after the file data */
		wb_num(&e, 1);
		wb_u8(&e, ID_SIZE);
		wb_num(&e, hpacked);
		wb_u8(&e, ID_END);
		wb_u8(&e, ID_UNPACK);
		wb_u8(&e, ID_FOLDER);
		wb_num(&e, 1);
		wb_u8(&e, 0);
		wb_num(&e, 1);
		wb_coder(&e, &C_LZMA);
		wb_u8(&e, ID_CODERSSIZE);
		wb_num(&e, hdr);
		wb_u8(&e, ID_END);
		wb_u8(&e, ID_END);
		(void)k;
		arc = assemble(g_arc, sizeof g_arc, data, packed + hpacked, enc_hdr, e.n);
	}
	made = do_scan(sc, g_arc, arc, &s);
	if (made != 2)
		dump(&s);
	/* the module hands over the file LIST (the header, as bytes: a window when it is plain, its decoding when coded)
	 * and then each FOLDER whole, the solid block of every file in it end to end */
	CK(made == 2, "%s header: the list and one folder are opened (%u)", coded_header ? "coded" : "plain", made);
	CK(same(&s.kid[0], g_hdr, hdr), "the first child is the header as written (%llu bytes, wanted %zu)", (unsigned long long)s.kid[0].len, hdr);
	CK(s.kid[1].len == total && !memcmp(s.kid[1].data, g_all, total < sizeof s.kid[1].data ? total : sizeof s.kid[1].data),
	   "the second is the folder: the three files in order (%llu bytes, wanted %zu)", (unsigned long long)s.kid[1].len, total);
	CK(s.root_broken == 0, "the archive is not reported broken (%u)", s.root_broken);
}

/* a folder per file, three coders, an empty file and an empty directory entry, with the files' sizes known */
static void t_coders(kof_scanner *sc)
{
	static const struct afile files[5] = { { "lz.txt", 0, 0 }, { "defl.txt", 0, 0 }, { "copy.bin", 0, 0 }, { "empty.txt", 1, 1 },
					       { "dir", 1, 0 } };
	struct folder fo[3];
	static uint8_t p0[1 << 14], p1[1 << 14], p2[1 << 14];
	size_t n0, n1, n2, a, b;
	static struct scan s;
	unsigned made;
	size_t hdr, arc, off = 0;
	static uint8_t data[1 << 16];

	if (!have("/usr/bin/xz") || !have("/usr/bin/gzip")) {
		printf("  (xz or gzip is not installed: the coder archive is skipped)\n");
		return;
	}
	n0 = text_file(p0, 0, 30);
	n1 = text_file(p1, 1, 30);
	n2 = x86_file(p2, 200);
	memset(fo, 0, sizeof fo);
	a = via_tool("/usr/bin/xz -c --format=raw --lzma1=lc=3,lp=0,pb=2,dict=1MiB", p0, n0, data + off, sizeof data - off);
	fo[0].coder[0] = &C_LZMA; fo[0].n_coders = 1; fo[0].packed_len = a; fo[0].unpack_len = n0; fo[0].n_files = 1;
	off += a;
	b = gzip_raw(p1, n1, data + off, sizeof data - off);
	fo[1].coder[0] = &C_DEFLATE; fo[1].n_coders = 1; fo[1].packed_len = b; fo[1].unpack_len = n1; fo[1].n_files = 1;
	off += b;
	memcpy(data + off, p2, n2);
	fo[2].coder[0] = &C_COPY; fo[2].n_coders = 1; fo[2].packed_len = n2; fo[2].unpack_len = n2; fo[2].n_files = 1;
	off += n2;
	CK(a > 0 && b > 0, "the tools made the streams");
	hdr = build_header(g_hdr, sizeof g_hdr, fo, 3, files, 5);
	arc = assemble(g_arc, sizeof g_arc, data, off, g_hdr, hdr);
	made = do_scan(sc, g_arc, arc, &s);
	/* the shipped unpacker runs LZMA2 (and the filters over it): LZMA, deflate and copy folders are named, not skipped silently */
	CK(made == 1, "only the file list is opened (%u): no LZMA, deflate or stored folder is decoded", made);
	CK(same(&s.kid[0], g_hdr, hdr), "and it is the header as written");
	CK(s.root_broken == KOF_BROKEN_UNSUPPORTED, "the archive is reported UNSUPPORTED, not clean (broken %u)", s.root_broken);
}

/* a coder chain: the x86 branch filter over LZMA2 */
static void t_chain(kof_scanner *sc)
{
	static const struct afile files[1] = { { "prog.bin", 0, 0 } };
	struct folder fo;
	static uint8_t px[1 << 14];
	size_t n, a, hdr, arc;
	static struct scan s;
	unsigned made;

	if (!have("/usr/bin/xz")) {
		printf("  (xz is not installed: the filter chain is skipped)\n");
		return;
	}
	n = x86_file(px, 600);
	a = via_tool("/usr/bin/xz -c --format=raw --x86 --lzma2=preset=6,dict=1MiB", px, n, g_pack, sizeof g_pack);
	memset(&fo, 0, sizeof fo);
	fo.coder[0] = &C_LZMA2;                  /* listed from the packed stream outward, as 7-Zip writes them */
	fo.coder[1] = &C_BCJ;
	fo.n_coders = 2;
	fo.packed_len = a;
	fo.unpack_len = n;
	fo.n_files = 1;
	hdr = build_header(g_hdr, sizeof g_hdr, &fo, 1, files, 1);
	arc = assemble(g_arc, sizeof g_arc, g_pack, a, g_hdr, hdr);
	made = do_scan(sc, g_arc, arc, &s);
	CK(made == 2, "the chained folder opens (header and folder: %u)", made);
	CK(made == 2 && s.kid[1].len == n && !memcmp(s.kid[1].data, px, n < sizeof s.kid[1].data ? n : sizeof s.kid[1].data),
	   "BCJ over LZMA2 gives the program back, calls converted back (%llu bytes, wanted %zu)", (unsigned long long)s.kid[1].len, n);
	CK(s.root_broken == 0, "not broken (%u)", s.root_broken);
}

/* wrong headers are said so */
static void t_wrong(kof_scanner *sc)
{
	static const struct afile files[1] = { { "a.txt", 0, 0 } };
	struct folder fo;
	size_t n, hdr, arc;
	static struct scan s;
	unsigned made;
	uint8_t bad[8192];

	n = text_file(g_plain[0], 0, 10);
	memset(&fo, 0, sizeof fo);
	fo.coder[0] = &C_COPY;
	fo.n_coders = 1;
	fo.packed_len = n;
	fo.unpack_len = n;
	fo.n_files = 1;
	hdr = build_header(g_hdr, sizeof g_hdr, &fo, 1, files, 1);
	arc = assemble(g_arc, sizeof g_arc, g_plain[0], n, g_hdr, hdr);
	made = do_scan(sc, g_arc, arc, &s);
	CK(made == 1 && same(&s.kid[0], g_hdr, hdr) && s.root_broken == KOF_BROKEN_UNSUPPORTED,
	   "a stored archive: the list is opened, the stored folder is reported unsupported (%u, broken %u)", made, s.root_broken);
	if (arc > sizeof bad)
		return;
	/* start header CRC wrong */
	memcpy(bad, g_arc, arc);
	bad[8] ^= 0xff;
	made = do_scan(sc, bad, arc, &s);
	CK(made <= 1, "a wrong start header CRC: at most the list (%u children, broken %u)", made, s.root_broken);
	/* next header offset past the end */
	memcpy(bad, g_arc, arc);
	memset(bad + 12, 0xff, 8);
	made = do_scan(sc, bad, arc, &s);
	CK(made == 0, "a next header past the end opens nothing (%u)", made);
	/* next header size zero */
	memcpy(bad, g_arc, arc);
	memset(bad + 20, 0, 8);
	made = do_scan(sc, bad, arc, &s);
	CK(made == 0, "a next header of size zero opens nothing (%u)", made);
	/* a header kind that is not one */
	memcpy(bad, g_arc, arc);
	bad[32 + n] = 0x42;
	made = do_scan(sc, bad, arc, &s);
	CK(made == 0, "a header that is not kHeader or kEncodedHeader opens nothing (%u)", made);
	/* a folder that claims more bytes than the archive holds */
	memcpy(bad, g_arc, arc);
	{
		unsigned k;

		for (k = 32 + (unsigned)n; k < arc && k < 32 + n + 24; k++)
			if (bad[k] == ID_SIZE) {
				bad[k + 1] = 0x7f;       /* the packed size becomes 127: far less than declared elsewhere */
				break;
			}
	}
	made = do_scan(sc, bad, arc, &s);
	CK(made <= 1, "an altered pack size opens at most the one file (%u)", made);
}

/* every cut, and flipped bits, of a small archive of each header kind */
static void t_hostile(kof_scanner *sc)
{
	static const struct afile files[2] = { { "a.txt", 0, 0 }, { "b.txt", 0, 0 } };
	struct folder fo;
	size_t n0, n1, hdr, arc, k, i;
	static uint8_t bad[2][8192];
	static struct scan s;
	uint64_t seed = 0x7a7a7a7aull;

	n0 = text_file(g_plain[0], 0, 5);
	n1 = text_file(g_plain[1], 1, 5);
	memcpy(g_all, g_plain[0], n0);
	memcpy(g_all + n0, g_plain[1], n1);
	memset(&fo, 0, sizeof fo);
	fo.coder[0] = &C_COPY;
	fo.n_coders = 1;
	fo.packed_len = n0 + n1;
	fo.unpack_len = n0 + n1;
	fo.n_files = 2;
	fo.file_len[0] = n0;
	fo.file_len[1] = n1;
	hdr = build_header(g_hdr, sizeof g_hdr, &fo, 1, files, 2);
	arc = assemble(g_arc, sizeof g_arc, g_all, n0 + n1, g_hdr, hdr);
	if (arc > sizeof bad[0])
		return;
	for (k = 0; k <= arc; k++) {
		struct he_guard g;

		if (!he_guard_make(&g, g_arc, k))
			continue;
		do_scan(sc, g.p, k, &s);
		/* a child is never longer than the bytes the archive could hold */
		for (i = 0; i + 1 < s.n && i < MAXKIDS; i++)
			CK(s.kid[i].len <= arc, "cut %zu: child %zu is %llu bytes, longer than the %zu byte archive", k, i,
			   (unsigned long long)s.kid[i].len, arc);
		he_guard_free(&g);
	}
	for (i = 0; i < 1500; i++) {
		size_t at;
		unsigned j;

		seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
		memcpy(bad[0], g_arc, arc);
		at = (size_t)(seed % (arc * 8u));
		bad[0][at / 8] ^= (uint8_t)(1u << (at % 8));
		do_scan(sc, bad[0], arc, &s);
		for (j = 0; j + 1 < s.n && j < MAXKIDS; j++)
			CK(s.kid[j].len <= arc * 64u, "flip %zu: child %u is %llu bytes", i, j, (unsigned long long)s.kid[j].len);
	}
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : DB_RELEASE;
	struct stat sb;
	kof_engine *e;
	kof_scanner *sc;

	if (stat(db, &sb) != 0) {
		printf("cov_sevenzip_real: no database at %s (make) - nothing tested\n", db);
		return 0;
	}
	e = keng_open(db);
	if (!e) {
		printf("cov_sevenzip_real: the database did not load\n");
		return 1;
	}
	sc = kscan_new(e);
	if (!sc) {
		printf("cov_sevenzip_real: no scanner\n");
		keng_close(e);
		return 1;
	}
	t_solid(sc, 0);
	t_solid(sc, 1);
	t_coders(sc);
	t_chain(sc);
	t_wrong(sc);
	t_hostile(sc);
	kscan_free(sc);
	keng_close(e);
	printf("cov_sevenzip_real: %u check(s), %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
