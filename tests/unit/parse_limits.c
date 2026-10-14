/*
 * parse_limits - the numbers the container parsers bound themselves by, each against what the parser does AT that number.
 *
 *   WINDOWS     KOF_ZIP_EOCD_SEARCH: an end record is looked for in the last 22 + 65535 bytes, so a zip with a
 *               comment/trailer of 65535 bytes is a zip and one of 65536 is not found (NO_EOCD, said);
 *               KOF_PDF_HEADER_SEARCH: `%PDF-` within the first 1024 bytes and not after; KOF_TAR_MAGIC_AT /
 *               KOF_TAR_BLOCK: "ustar" at 257 and nowhere near it
 *   RATIOS      KOF_ZIP_RATIO_ABSURD, KOF_GZIP_RATIO_ABSURD: a declared expansion of 5000 is flagged and 4999 is not
 *   TABLES      the arrays a parser fills are the size its limit says (an index bounded by 4096 into an array of
 *               2048 was how QUALITY_AUDIT II.5 found the first of these): RAR entries and runs, XZ blocks and
 *               runs, ZIP and TAR runs, 7z pack streams
 *   MAGIC       the layout constants of the fixed headers against the seeds that carry them: XZ's magic, header
 *               and footer, 7z's signature header
 *   ALIASES     KOF_ELF_MAX_* are the lib's limits under the module-facing name
 */

#include "hostile_engine.h"
#pragma GCC diagnostic ignored "-Wunused-function"      /* the seeds header carries builders this file does not need */
#include "hostile_engine_seeds.h"

#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/pdf_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/rar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/xz_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/sevenzip_parse.h"
#include <kofmod/zip.h>
#include <kofmod/gzip.h>
#include <kofmod/tar.h>
#include <kofmod/pdf.h>
#include <kofmod/rar.h>
#include <kofmod/xz.h>
#include <kofmod/sevenzip.h>
#include <kofmod/elf.h>

#define ELEMS(a) (sizeof(a) / sizeof((a)[0]))

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* one stored-looking member whose header declares csize and usize; `tail` bytes follow the end record */
static size_t zip1(uint8_t *f, uint32_t csize, uint32_t usize, size_t tail)
{
	size_t at = 0, cd;

	le32(f + at, 0x04034b50u); le16(f + at + 4, 10); le32(f + at + 18, csize); le32(f + at + 22, usize); le16(f + at + 26, 1);
	f[at + 30] = 'a';
	memset(f + at + 31, 'x', csize);
	at += 31u + csize;
	cd = at;
	le32(f + at, 0x02014b50u); le16(f + at + 4, 20); le16(f + at + 6, 10); le32(f + at + 20, csize); le32(f + at + 24, usize);
	le16(f + at + 28, 1); le32(f + at + 42, 0);
	f[at + 46] = 'a';
	at += 47;
	le32(f + at, 0x06054b50u); le16(f + at + 8, 1); le16(f + at + 10, 1);
	le32(f + at + 12, (uint32_t)(at - cd)); le32(f + at + 16, (uint32_t)cd);
	at += 22;
	memset(f + at, 0, tail);
	return at + tail;
}

static uint64_t zip_anoms(const uint8_t *b, size_t n, int *ok)
{
	struct kof_zip_info *z = calloc(1, sizeof *z);
	struct kof_obj_ctx ctx;
	uint64_t a;

	memset(&ctx, 0, sizeof ctx);
	if (!z) {
		*ok = 0;
		return 0;
	}
	*ok = kof_zip_parse(kof_buf_make(b, n), z, &ctx);
	a = z->anomalies;
	kof_zip_release(z);
	free(z);
	return a;
}

static void zip_limits(void)
{
	static uint8_t f[KOF_ZIP_EOCD_SEARCH + 4096u];
	int ok;
	uint64_t a;
	size_t n;

	n = zip1(f, 1, KOF_ZIP_RATIO_ABSURD, 0);
	a = zip_anoms(f, n, &ok);
	CK(ok && (a & KOF_ZIP_ANOM_RATIO_ABSURD), "a declared expansion of %u: flagged absurd", KOF_ZIP_RATIO_ABSURD);
	n = zip1(f, 1, KOF_ZIP_RATIO_ABSURD - 1u, 0);
	a = zip_anoms(f, n, &ok);
	CK(ok && !(a & KOF_ZIP_ANOM_RATIO_ABSURD), "and %u is not", KOF_ZIP_RATIO_ABSURD - 1u);
	n = zip1(f, 3, 3u * KOF_ZIP_RATIO_ABSURD, 0);
	CK((zip_anoms(f, n, &ok) & KOF_ZIP_ANOM_RATIO_ABSURD) != 0, "the ratio is usize over csize, not usize alone");

	n = zip1(f, 1, 1, 0);
	a = zip_anoms(f, n, &ok);
	CK(ok && !(a & KOF_ZIP_ANOM_NO_EOCD), "an ordinary one-member zip has its end record");
	n = zip1(f, 1, 1, KOF_ZIP_EOCD_SEARCH - 22u);
	a = zip_anoms(f, n, &ok);
	CK(!(a & KOF_ZIP_ANOM_NO_EOCD), "the end record 22 + 65535 bytes from the end is found (the whole search window)");
	n = zip1(f, 1, 1, KOF_ZIP_EOCD_SEARCH - 22u + 1u);
	a = zip_anoms(f, n, &ok);
	CK(!ok || (a & KOF_ZIP_ANOM_NO_EOCD), "one byte further it is not, and the parse says NO_EOCD instead of guessing (ok %d)", ok);
}

static void gzip_limits(void)
{
	const struct seed *sd = NULL;
	unsigned i;
	uint8_t *c;
	struct kof_gzip_info *g = calloc(1, sizeof *g);
	struct kof_obj_ctx ctx;
	uint64_t dl;

	for (i = 0; i < n_seeds; i++)
		if (seeds[i].fmt == KOF_FMT_GZIP)
			sd = &seeds[i];
	CK(sd && g, "a gzip seed");
	if (!sd || !g) {
		free(g);
		return;
	}
	c = malloc(sd->n);
	memcpy(c, sd->p, sd->n);
	memset(&ctx, 0, sizeof ctx);
	CK(kof_gzip_parse(kof_buf_make(c, sd->n), g, &ctx) == 1, "the seed parses");
	dl = g->data_len;
	CK(dl > 0 && dl * KOF_GZIP_RATIO_ABSURD < 0xffffffffu, "it has data to take a ratio of (%llu)", (unsigned long long)dl);
	le32(c + sd->n - 4u, (uint32_t)(dl * KOF_GZIP_RATIO_ABSURD));
	memset(g, 0, sizeof *g);
	CK(kof_gzip_parse(kof_buf_make(c, sd->n), g, &ctx) == 1 && (g->anomalies & KOF_GZIP_ANOM_RATIO_ABSURD),
	   "ISIZE of %u times the data is flagged absurd", KOF_GZIP_RATIO_ABSURD);
	le32(c + sd->n - 4u, (uint32_t)(dl * (KOF_GZIP_RATIO_ABSURD - 1u)));
	memset(g, 0, sizeof *g);
	CK(kof_gzip_parse(kof_buf_make(c, sd->n), g, &ctx) == 1 && !(g->anomalies & KOF_GZIP_ANOM_RATIO_ABSURD), "and one less is not");
	free(c);
	free(g);
}

static void tar_pdf_limits(void)
{
	static uint8_t t[1024], p[2048];
	static const char pdf[] = "%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";
	unsigned k;

	CK(KOF_TAR_MAGIC_AT + 5u <= KOF_TAR_BLOCK && KOF_TAR_BLOCK == 512u, "the magic lies inside the first block (257 + 5 of 512)");
	memset(t, 0, sizeof t);
	memcpy(t + KOF_TAR_MAGIC_AT, "ustar", 5);
	CK(kof_tar_sniff(kof_buf_make(t, KOF_TAR_MAGIC_AT + 5u)) == 1 && kof_tar_sniff(kof_buf_make(t, KOF_TAR_BLOCK)) == 1,
	   "ustar at KOF_TAR_MAGIC_AT is a tar, from the byte it ends on");
	CK(kof_tar_sniff(kof_buf_make(t, KOF_TAR_MAGIC_AT + 4u)) == 0, "one byte short of the magic's end is not");
	memset(t, 0, sizeof t);
	memcpy(t + KOF_TAR_MAGIC_AT - 1u, "ustar", 5);
	CK(kof_tar_sniff(kof_buf_make(t, KOF_TAR_BLOCK)) == 0, "the magic one byte early is not a tar");
	memset(t, 0, sizeof t);
	memcpy(t + KOF_TAR_MAGIC_AT + 1u, "ustar", 5);
	CK(kof_tar_sniff(kof_buf_make(t, KOF_TAR_BLOCK)) == 0, "and one byte late is not either");

	for (k = KOF_PDF_HEADER_SEARCH - 6u; k <= KOF_PDF_HEADER_SEARCH - 4u; k++) {
		memset(p, ' ', sizeof p);
		memcpy(p + k, pdf, sizeof pdf - 1u);
		/* the 5 bytes of `%PDF-` must END inside the window: they start at k, the window is KOF_PDF_HEADER_SEARCH long */
		CK(kof_pdf_sniff(kof_buf_make(p, k + sizeof pdf - 1u)) == (k + 5u <= KOF_PDF_HEADER_SEARCH),
		   "%%PDF- starting at byte %u (the window is %u): %s", k, KOF_PDF_HEADER_SEARCH, k + 5u <= KOF_PDF_HEADER_SEARCH ? "found" : "not found");
	}
}

static void tables(void)
{
	struct kof_rar_info r;
	struct kof_xz_info x;
	struct kof_zip_info z;
	struct kof_tar_info t;
	struct kof_7z_info s;

	/* rar likewise: a file block is at least KOF_RAR_ENTRY_MIN bytes and makes at most five runs */
	memset(&r, 0, sizeof r);
	CK(KOF_RAR_ENTRY_MIN == 12u && KOF_RAR_RUNS_PER_ENTRY == 5u && r.run == NULL && r.entry == NULL,
	   "rar: the tables are allocated to the file, bounded by its length over the smallest block");
	CK(ELEMS(x.block) == KOF_XZ_MAX_BLOCKS && ELEMS(x.run) == KOF_XZ_MAX_EXTENTS, "xz: the block and run tables are");
	/* zip has no table of a size chosen in advance: what bounds it is the file (record size) and the ledger */
	memset(&z, 0, sizeof z);
	CK(KOF_ZIP_CENTRAL_MIN == 46u && KOF_ZIP_RUNS_PER_ENTRY == 8u && z.run == NULL && z.entry == NULL,
	   "zip: the tables are allocated to the file, bounded by its length over the smallest record");
	/* tar likewise: an entry costs one header block, and makes at most two runs */
	memset(&t, 0, sizeof t);
	CK(KOF_TAR_BLOCK == 512u && KOF_TAR_RUNS_PER_ENTRY == 2u && t.run == NULL && t.entry == NULL,
	   "tar: the tables are allocated to the file, bounded by its length over one header block");
	/* 7z likewise: a folder is at least three bytes of the header, a packed stream's size one */
	memset(&s, 0, sizeof s);
	CK(KOF_7Z_FOLDER_MIN == 3u && s.folder == NULL && s.pack == NULL,
	   "7z: the folder and pack tables are allocated to the header, bounded by its length");
	CK(KOF_ELF_MAX_SECTIONS == KGENOME_ELF_MAX_SECTIONS && KOF_ELF_MAX_SEGMENTS == KGENOME_ELF_MAX_SEGMENTS && KOF_ELF_MAX_SECTIONS > 0 &&
	   KOF_ELF_MAX_SEGMENTS > 0, "the ELF limits of the module ABI are the lib's");
	CK(KOF_ZIP_RATIO_ABSURD == 5000u && KOF_GZIP_RATIO_ABSURD == 5000u && KOF_RAR_RATIO_ABSURD == 5000u && KOF_XZ_RATIO_ABSURD == 5000u,
	   "one ratio, 5000, in every format that declares a size: the measured real-world ceiling is far under it (QUALITY_AUDIT II.1)");
}

static void magic(void)
{
	static const uint8_t xzm[KOF_XZ_MAGIC_LEN] = { 0xfd, '7', 'z', 'X', 'Z', 0x00 };
	static const uint8_t szm[6] = { '7', 'z', 0xbc, 0xaf, 0x27, 0x1c };
	unsigned i;

	for (i = 0; i < n_seeds; i++) {
		const struct seed *sd = &seeds[i];

		if (sd->fmt == KOF_FMT_XZ) {
			CK(sd->n >= KOF_XZ_HEADER_LEN + KOF_XZ_FOOTER_LEN && !memcmp(sd->p, xzm, KOF_XZ_MAGIC_LEN) &&
			   sd->p[sd->n - 2u] == 'Y' && sd->p[sd->n - 1u] == 'Z', "the xz seed: magic of %u bytes, a header and a footer of %u each, ends YZ",
			   KOF_XZ_MAGIC_LEN, KOF_XZ_HEADER_LEN);
			CK(kof_xz_sniff(kof_buf_make(sd->p, sd->n)) == 1, "and is sniffed");
			CK(kof_xz_sniff(kof_buf_make(sd->p, KOF_XZ_MAGIC_LEN)) == 1 && kof_xz_sniff(kof_buf_make(sd->p, KOF_XZ_MAGIC_LEN - 1u)) == 0,
			   "sniffing an xz is the magic and nothing more: six bytes are enough, five are not");
		}
		if (sd->fmt == KOF_FMT_7Z) {
			CK(sd->n >= KOF_7Z_SIG_LEN && !memcmp(sd->p, szm, sizeof szm), "the 7z seed: the %u byte signature header starts with the six byte magic", KOF_7Z_SIG_LEN);
			CK(kof_7z_sniff(kof_buf_make(sd->p, sd->n)) == 1 && kof_7z_sniff(kof_buf_make(sd->p, sizeof szm)) == 1 &&
			   kof_7z_sniff(kof_buf_make(sd->p, sizeof szm - 1u)) == 0, "and the sniff is the six byte magic alone");
		}
	}
}

int main(void)
{
	build_seeds();
	zip_limits();
	gzip_limits();
	tar_pdf_limits();
	tables();
	magic();
	printf("parse_limits: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
