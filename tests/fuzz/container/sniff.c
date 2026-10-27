/*
 * container/sniff - every container format's recogniser on inputs of EVERY length from 0 to 64 bytes, and on the prefix of
 * each seed. A sniff is the first code that sees a hostile file and the only one that must decide from what it has: it reads
 * a header at an offset (a tar's magic is at 257, a zip's end record is searched from the tail, a CHM's from byte 0, a PDF's
 * anywhere in the first kilobyte), so the failure it can have is reading past the end of a short object.
 *
 * The lengths are 0..64, 250..270 (a tar's magic is at 257) and the tail rules (n, n-1, n-4, n-21..n-23).
 * Each prefix is copied into a heap block of EXACTLY its length (AddressSanitizer's redzone is the guard: one byte read past
 * the length is a report), then every sniff is called on it. Held: a sniff answers, the answer is 0 or 1, and two sniffs of one
 * prefix agree (a recogniser reads nothing but its bytes). A format whose sniff accepts a prefix must also accept the
 * seed it was cut from only where the rule is a prefix rule; that is not asserted (zip's is a tail rule), what is: the
 * recognisers claim a SMALL number of formats for any one input (at most 5 of the 16, a polyglot is two or three).
 *
 * The walk's sniff chain (kof_parser_list order) is run on the same prefix: the first format that accepts is the
 * format the engine would parse as, and it must be the same twice.
 */
#include <kofmod/kofsig.h>
#include "../../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/rar_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/lha_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/arj_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/cab_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/chm_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/sevenzip_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/docole_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/pdf_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/bz2_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/xz_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/rtf_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/lnk_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/reg_parse.h"

#include "ctr_seeds.h"

static void seeds(struct fz_corpus *c)
{
	unsigned f;

	for (f = 0; f < CW_NFORMATS; f++) {
		struct cw w;
		static uint8_t d[200];
		struct cw_ent e;

		memset(&w, 0, sizeof w);
		memset(d, 'q', sizeof d);
		memset(&e, 0, sizeof e);
		e.name = "x";
		e.data = d;
		e.len = sizeof d;
		cw_formats[f].write(&w, &e, 1, NULL, NULL);
		csd_add(c, cw_formats[f].name, "sniff", &w, NULL);
		cw_free(&w);
	}
	fz_corpus_add(c, "bz2", "BZh9\x17\x72\x45\x38\x50\x90\0\0\0\0", 14);
	fz_corpus_add(c, "rtf", "{\\rtf1\\ansi}", 12);
	fz_corpus_add(c, "reg", "Windows Registry Editor Version 5.00\r\n", 38);
	fz_corpus_add(c, "xz", "\xfd" "7zXZ\0\0\0\0", 9);
	fz_corpus_add(c, "lnk", "\x4c\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0\x46", 20);
}

static unsigned sniff_all(kof_buf f, uint32_t *bits)
{
	unsigned n = 0, b = 0;
	int r;

#define S(call) do { r = (call); n += r != 0; b = (b << 1) | (r != 0); } while (0)
	S(kof_zip_sniff(f)); S(kof_tar_sniff(f)); S(kof_rar_sniff(f)); S(kof_lha_sniff(f)); S(kof_arj_sniff(f)); S(kof_cab_sniff(f)); S(kof_chm_sniff(f));
	S(kof_7z_sniff(f)); S(kof_docole_sniff(f)); S(kof_pdf_sniff(f)); S(kof_gzip_sniff(f)); S(kof_bz2_sniff(f)); S(kof_xz_sniff(f)); S(kof_rtf_sniff(f));
	S(kof_lnk_sniff(f)); S(kof_reg_sniff(f));
#undef S
	*bits = b;
	return n;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	/* every length 0..64 (the magics at the start), 250..270 (a tar's "ustar" is at 257), and the tail rules: a zip's end record is
	 * searched from the last 22 + 65535 bytes, so n, n-1, n-4, n-21, n-22, n-23 */
	size_t lens[96 + 8], nl = 0, k, take;
	uint64_t acc = 0;

	for (k = 0; k <= 64; k++)
		lens[nl++] = k;
	for (k = 250; k <= 270; k++)
		lens[nl++] = k;
	lens[nl++] = n;
	lens[nl++] = n > 0 ? n - 1u : 0;
	lens[nl++] = n > 3 ? n - 4u : 0;
	lens[nl++] = n > 20 ? n - 21u : 0;
	lens[nl++] = n > 21 ? n - 22u : 0;
	lens[nl++] = n > 22 ? n - 23u : 0;
	for (k = 0; k < nl; k++) {
		uint8_t *exact;
		uint32_t b1, b2;
		unsigned n1, n2;
		uint32_t np, i;
		const struct kof_parser *pl;

		take = lens[k];
		if (take > n)
			take = n;
		exact = (uint8_t *)malloc(take ? take : 1u);
		if (!exact)
			continue;
		if (take)
			memcpy(exact, in, take);
		n1 = sniff_all(kof_buf_make(exact, take), &b1);
		n2 = sniff_all(kof_buf_make(exact, take), &b2);
		FZ_CHECK(c, b1 == b2 && n1 == n2, "two sniffs of one prefix disagree");
		FZ_CHECK(c, n1 <= 5u, "more than five container formats claim one input");
		pl = kof_parser_list(&np);
		for (i = 0; i < np; i++)
			if (pl[i].sniff && pl[i].sniff(kof_buf_make(exact, take)))
				break;
		acc = acc * 31u + b1 + ((uint64_t)i << 40);
		free(exact);
	}
	fz_digest(c, acc);
	return 0;
}

FZ_ADAPTER(cw_sniff, .name = "container/sniff", .shape = FZ_REQ,
	   .covers = "kof_zip_sniff kof_tar_sniff kof_rar_sniff kof_lha_sniff kof_arj_sniff kof_cab_sniff kof_chm_sniff kof_7z_sniff kof_docole_sniff kof_pdf_sniff kof_gzip_sniff kof_bz2_sniff kof_xz_sniff kof_rtf_sniff kof_lnk_sniff kof_reg_sniff",
	   .seeds = seeds, .run = run, .backstop_s = 600);   /* ~100 prefixes x 16 sniffs a case: 200000 cases take about a minute */
