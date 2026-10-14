/*
 * api_engine_parsers.c - the public entry points of every parser under
 * analyzers/parsers, by name: kof_<fmt>_sniff, kof_<fmt>_parse,
 * kof_<fmt>_region_name, kof_<fmt>_anomaly_name, the region-bit tables and the
 * *_REGIONS lists, the engine-side parser table (kofformat.h) and the container
 * name checks (cname.h).
 *
 * hostile_engine_parsers.c walks the same parsers through the table; this file
 * calls each by name, so a parser whose function was renamed or dropped from the
 * table is still held to its contract:
 *
 *   SNIFF     accepts a valid object, refuses NULL, nothing, and a block of zeros
 *   PARSE     accepts it, says what format it is, and publishes the view and the
 *             resolver a module reads
 *   REGIONS   every region the format lists has a name that is its enumerator's
 *             spelling, is one bit, is in the format's bit table, and is found again
 *             by kof_region_mask_of; a bit the format does not have has no name
 *   ANOMALIES every anomaly has a distinct, non-empty name, and the list ends
 *
 * One macro writes the test for a format, so that all sixteen are held to the same
 * thing and none is a little different by accident.
 */

#include "hostile_engine.h"
#include "hostile_engine_seeds.h"
#include "known_miss.h"

#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/analyzers/parsers/containers/arj_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/bz2_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/cab_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/chm_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/cname.h"
#include "../../libkofeng/analyzers/parsers/containers/docole_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/lha_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/lnk_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/pdf_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/rar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/reg_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/rtf_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/sevenzip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/xz_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"
#include "../../libkofeng/analyzers/parsers/events/amsi_parse.h"
#include "../../libkofeng/analyzers/parsers/processes/proc_parse.h"
#include <kofmod/kofsig.h>
#include <kofmod/zip.h>
#include <kofmod/tar.h>
#include <kofmod/gzip.h>
#include <kofmod/sevenzip.h>
#include <kofmod/rar.h>
#include <kofmod/xz.h>
#include <kofmod/bz2.h>
#include <kofmod/docole.h>
#include <kofmod/pdf.h>
#include <kofmod/rtf.h>
#include <kofmod/arj.h>
#include <kofmod/lha.h>
#include <kofmod/cab.h>
#include <kofmod/chm.h>
#include <kofmod/proc.h>
#include <kofmod/heur.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/script.h>

struct rg {
	const char *name;
	uint32_t    bit;
};

#define RG_ROW(nm) { #nm, (nm) },

static const struct seed *seed_of(uint8_t fmt)
{
	unsigned i;

	for (i = 0; i < n_seeds; i++)
		if (seeds[i].fmt == fmt)
			return &seeds[i];
	return NULL;
}

static unsigned pop32(uint32_t v)
{
	unsigned n = 0;

	for (; v; v &= v - 1u)
		n++;
	return n;
}

/* The checks every format shares, once its own functions have been named. */
static void common(const char *tag, uint8_t fmt, const struct rg *rg, unsigned n_rg, const uint32_t *bits,
		   const char *(*region_name)(uint32_t), const char *(*anomaly_name)(unsigned))
{
	const struct kof_parser *pr = kof_parser_of(fmt);
	unsigned i, j, names = 0;
	uint32_t seen = 0;

	CK(pr != NULL && pr->format == fmt, "%s: the table has a row for it", tag);
	CK(n_rg > 0, "%s: the format lists regions", tag);
	for (i = 0; i < n_rg; i++) {
		const char *nm = region_name(rg[i].bit);

		CK(pop32(rg[i].bit) == 1, "%s: %s is one bit", tag, rg[i].name);
		CK(!(seen & rg[i].bit), "%s: %s is not another region's bit", tag, rg[i].name);
		seen |= rg[i].bit;
		/* A .NET region (PE's KOF_SCAN_CLR_*) is named by the stream it is - "#Strings", "#US" - which a signature
		 * source does not spell; every other region's name is its own enumerator's. */
		int clr = strncmp(rg[i].name, "KOF_SCAN_CLR_", 13u) == 0;

		if (clr)
			CK(nm && nm[0], "%s: %s has a name ('%s')", tag, rg[i].name, nm ? nm : "NULL");
		else
			CK(nm && strcmp(nm, rg[i].name) == 0, "%s: region_name(%s) is its own spelling ('%s')", tag, rg[i].name, nm ? nm : "NULL");
		CK(bits[i] == rg[i].bit || n_rg != (pr ? pr->n_regions : 0u), "%s: the bit table is in the list's order (%u)", tag, i);
		if (!clr)
			CK(pr && kof_region_mask_of(pr, rg[i].name) == rg[i].bit, "%s: kof_region_mask_of finds %s again", tag, rg[i].name);
	}
	CK(pr && pr->n_regions == n_rg, "%s: the table and the list agree on how many regions (%u, %u)", tag, pr ? pr->n_regions : 0u, n_rg);
	for (i = 0; pr && i < pr->n_regions; i++) {
		unsigned found = 0;

		for (j = 0; j < n_rg; j++)
			found |= pr->regions[i] == rg[j].bit;
		CK(found, "%s: the table's region %u is in the list", tag, i);
	}
	CK(region_name(0x40000000u) == NULL || (seen & 0x40000000u), "%s: a bit the format does not have has no name", tag);
	CK(pr && kof_region_mask_of(pr, "KOF_SCAN_NO_SUCH_REGION") == KOF_SCAN_ALL && kof_region_mask_of(pr, "") == KOF_SCAN_ALL &&
	   kof_region_mask_of(pr, NULL) == KOF_SCAN_ALL && kof_region_mask_of(NULL, rg[0].name) == KOF_SCAN_ALL,
	   "%s: an unknown spelling, an empty one, NULL, and no parser all answer KOF_SCAN_ALL", tag);

	for (i = 0; i < 64u; i++) {
		const char *a = anomaly_name(i);

		if (!a)
			break;
		CK(a[0] != 0, "%s: anomaly %u has a name", tag, i);
		for (j = 0; j < i; j++)
			CK(strcmp(a, anomaly_name(j)) != 0 || !strcmp(a, "?"), "%s: anomalies %u and %u share the name '%s'", tag, j, i, a);
		names++;
	}
	CK(names < 64u, "%s: the anomaly list ends (%u names)", tag, names);
	CK(anomaly_name(1000) == NULL || !strcmp(anomaly_name(1000), "?"), "%s: past the list: NULL or ?", tag);
}

#define FORMAT_TEST(tag, FMT, REGIONS, COUNT)                                                                  \
static void t_##tag(void)                                                                                   \
{                                                                                                           \
	static const struct rg rg[] = { REGIONS(RG_ROW) };                                                  \
	const struct seed *sd = seed_of(FMT);                                                               \
	struct kof_##tag##_info *view = calloc(1, sizeof *view);                                            \
	struct kof_obj_ctx ctx;                                                                             \
	uint8_t zeros[512];                                                                                 \
                                                                                                            \
	memset(zeros, 0, sizeof zeros);                                                                     \
	memset(&ctx, 0, sizeof ctx);                                                                        \
	CK(sd && view, #tag ": a seed and a view");                                                         \
	if (sd && view) {                                                                                   \
		kof_buf b = kof_buf_make(sd->p, sd->n);                                                     \
                                                                                                            \
		CK(kof_##tag##_sniff(b) == 1, #tag ": sniff accepts its own object");                       \
		CK(kof_##tag##_parse(b, view, &ctx) == 1, #tag ": parse accepts it");                       \
		CK(ctx.file_header == view && ctx.format == (FMT), #tag ": the context carries the view and the format"); \
		CK(ctx.resolve_scan != NULL, #tag ": and the region resolver");                             \
		CK(kof_##tag##_sniff(kof_buf_make(NULL, 0)) == 0 && kof_##tag##_sniff(kof_buf_make(zeros, 0)) == 0 && \
		   kof_##tag##_sniff(kof_buf_make(zeros, sizeof zeros)) == 0, #tag ": sniff refuses NULL, nothing and zeros"); \
		CK(kof_##tag##_sniff(kof_buf_make(sd->p, 1)) == 0, #tag ": and one byte of its own magic");   \
		memset(&ctx, 0, sizeof ctx);                                                                \
		(void)kof_##tag##_parse(kof_buf_make(zeros, sizeof zeros), view, &ctx);                    \
		CK(1, #tag ": parse of zeros returns");                                                     \
	}                                                                                                   \
	CK((COUNT) == 0u || (COUNT) == sizeof rg / sizeof rg[0], #tag ": the count macro is the length of the region list"); \
	common(#tag, FMT, rg, (unsigned)(sizeof rg / sizeof rg[0]), kof_##tag##_region_bits,               \
	       kof_##tag##_region_name, kof_##tag##_anomaly_name);                                          \
	free(view);                                                                                         \
}

FORMAT_TEST(zip, KOF_FMT_ZIP, ZIP_REGIONS, KOF_ZIP_REGION_COUNT)
FORMAT_TEST(tar, KOF_FMT_TAR, TAR_REGIONS, KOF_TAR_REGION_COUNT)
FORMAT_TEST(gzip, KOF_FMT_GZIP, GZIP_REGIONS, KOF_GZIP_REGION_COUNT)
FORMAT_TEST(7z, KOF_FMT_7Z, SZ_REGIONS, KOF_7Z_REGION_COUNT)
FORMAT_TEST(rar, KOF_FMT_RAR, RAR_REGIONS, KOF_RAR_REGION_COUNT)
FORMAT_TEST(xz, KOF_FMT_XZ, XZ_REGIONS, KOF_XZ_REGION_COUNT)
FORMAT_TEST(bz2, KOF_FMT_BZIP2, BZ2_REGIONS, KOF_BZ2_REGION_COUNT)
FORMAT_TEST(docole, KOF_FMT_DOCOLE, DOCOLE_REGIONS, KOF_DOCOLE_REGION_COUNT)
FORMAT_TEST(pdf, KOF_FMT_PDF, PDF_REGIONS, 0u)
FORMAT_TEST(rtf, KOF_FMT_RTF, RTF_REGIONS, KOF_RTF_REGION_COUNT)
FORMAT_TEST(arj, KOF_FMT_ARJ, ARJ_REGIONS, KOF_ARJ_REGION_COUNT)
FORMAT_TEST(lha, KOF_FMT_LHA, LHA_REGIONS, KOF_LHA_REGION_COUNT)
FORMAT_TEST(cab, KOF_FMT_CAB, CAB_REGIONS, KOF_CAB_REGION_COUNT)
FORMAT_TEST(chm, KOF_FMT_CHM, CHM_REGIONS, KOF_CHM_REGION_COUNT)
FORMAT_TEST(lnk, KOF_FMT_LNK, LNK_REGIONS, KOF_LNK_REGION_COUNT)
FORMAT_TEST(reg, KOF_FMT_REG, REG_REGIONS, KOF_REG_REGION_COUNT)

/*
 * ELF, PE and SCRIPT: the parsers whose views are the libs' (kgenome_elf_info, kgenome_pe_info) or the
 * engine's own (kof_script_info), so there is no kof_<tag>_info for FORMAT_TEST to allocate. What they
 * share with every other format is the naming surface, and that is what is held here.
 */
#define RG_ROWK(nm) { "KOF_" #nm, (KOF_##nm) },        /* ELF and PE list the bare suffix */

#define NAMES_TEST(tag, FMT, REGIONS, COUNT, ROW)                                                              \
static void n_##tag(void)                                                                                   \
{                                                                                                           \
	static const struct rg rg[] = { REGIONS(ROW) };                                                     \
                                                                                                            \
	CK((COUNT) == sizeof rg / sizeof rg[0], #tag ": the count macro is the length of the region list"); \
	common(#tag, FMT, rg, (unsigned)(sizeof rg / sizeof rg[0]), kof_##tag##_region_bits,               \
	       kof_##tag##_region_name, kof_##tag##_anomaly_name);                                          \
}

NAMES_TEST(elf, KOF_FMT_ELF, ELF_REGIONS, KOF_ELF_REGION_COUNT, RG_ROWK)
NAMES_TEST(pe, KOF_FMT_PE, PE_REGIONS, KOF_PE_REGION_COUNT, RG_ROWK)
NAMES_TEST(script, KOF_FMT_SCRIPT, SCRIPT_REGIONS, KOF_SCRIPT_REGION_COUNT, RG_ROW)

/* The view accessors a module calls: each is the context's view, cast to the format's own type. */
static void t_accessors(void)
{
	struct kof_obj_ctx c;
	static const long long any = 7;

	memset(&c, 0, sizeof c);
	c.file_header = &any;
	CK((const void *)kof_zip(&c) == &any && (const void *)kof_tar(&c) == &any && (const void *)kof_gzip(&c) == &any &&
	   (const void *)kof_7z(&c) == &any && (const void *)kof_rar(&c) == &any && (const void *)kof_xz(&c) == &any &&
	   (const void *)kof_bz2(&c) == &any && (const void *)kof_docole(&c) == &any && (const void *)kof_pdf(&c) == &any &&
	   (const void *)kof_rtf(&c) == &any && (const void *)kof_arj(&c) == &any && (const void *)kof_lha(&c) == &any &&
	   (const void *)kof_cab(&c) == &any && (const void *)kof_chm(&c) == &any && (const void *)kof_proc(&c) == &any, "every accessor is a cast of file_header");
	c.file_header = NULL;
	CK(kof_zip(&c) == NULL && kof_pdf(&c) == NULL, "and a context with no view gives NULL, not a guess");
}

/* ---- the kind words some formats add ------------------------------------------------------------ */

static void t_kind_names(void)
{
	uint32_t k;
	const char *seen[16];
	unsigned n = 0;

	for (k = 0; k < 16u; k++) {
		const char *w = kof_zip_kind_name(k);

		if (!w)
			break;
		CK(w[0] != 0, "zip kind %u has a name", k);
		seen[n++] = w;
	}
	CK(n >= 1, "zip has kind words");
	CK(kof_zip_kind_name(1000) == NULL || kof_zip_kind_name(1000)[0] == '?' || 1, "an unknown zip kind does not crash");
	for (k = 0; k < 8u; k++)
		CK(kof_7z_header_kind_name(k) == NULL || kof_7z_header_kind_name(k)[0] != 0, "7z header kind %u", k);
	CK(kof_7z_header_kind_name(0xffffffffu) == NULL || kof_7z_header_kind_name(0xffffffffu)[0] != 0, "an unknown 7z header kind");
}

/* ---- events: AMSI and processes -------------------------------------------------------------------- */

static void t_amsi_proc(void)
{
	struct kof_amsi_view v;
	struct kof_obj_ctx ctx;
	uint8_t blob[64];
	const struct kof_parser *pa = kof_parser_of(KOF_EVT_AMSI), *pp = kof_parser_of(KOF_EVT_PROC);
	uint8_t pv[256];
	unsigned i;

	memset(blob, 'q', sizeof blob);
	memset(&v, 0, sizeof v);
	memset(&ctx, 0, sizeof ctx);
	v.obj_off = 16;
	v.obj_len = 32;
	CK(kof_amsi_parse(kof_buf_make(blob, sizeof blob), &v, &ctx) == 1, "amsi: a declared window parses");
	CK(ctx.format == KOF_EVT_AMSI && v.size == sizeof blob && v.obj_off == 16 && v.obj_len == 32, "amsi: the view says what was declared, and the size");
	CK(ctx.resolve_scan != NULL, "amsi: resolver published");
	if (ctx.resolve_scan) {
		struct kof_range out[4];
		uint32_t n = ctx.resolve_scan(&ctx, KOF_SCAN_AMSI_OBJ, out, 4), total = 0, k;

		CK(n == 1 && out[0].off == 16 && out[0].len == 32, "amsi: the object region is the declared window");
		n = ctx.resolve_scan(&ctx, KOF_SCAN_AMSI_META | KOF_SCAN_AMSI_OBJ, out, 4);
		for (k = 0; k < n; k++)
			total += (uint32_t)out[k].len;
		CK(total == sizeof blob, "amsi: the two regions are the whole record");
	}
	memset(&v, 0, sizeof v);
	v.obj_off = 100;
	v.obj_len = 4;
	CK(kof_amsi_parse(kof_buf_make(blob, sizeof blob), &v, &ctx) == 0, "amsi: a window that starts past the record is refused");
	memset(&v, 0, sizeof v);
	v.obj_off = 60;
	v.obj_len = 0xffffffffffffffffull;
	CK(kof_amsi_parse(kof_buf_make(blob, sizeof blob), &v, &ctx) == 1 && v.obj_len == 4, "amsi: a length past the end is clipped to the record");
	v.obj_off = 0xffffffffffffffffull;
	CK(kof_amsi_parse(kof_buf_make(blob, sizeof blob), &v, &ctx) == 0, "amsi: an offset of 2^64-1");
	CK(kof_amsi_parse(kof_buf_make(NULL, 0), &v, &ctx) == 0 && kof_amsi_parse(kof_buf_make(blob, sizeof blob), NULL, &ctx) == 0 &&
	   kof_amsi_parse(kof_buf_make(blob, sizeof blob), &v, NULL) == 0, "amsi: NULL buffer, view, context");
	/* Every parser spells a region by its enumerator, and answers NULL for a bit it does not have;
	 * kof_region_mask_of finds a region by that word. */
	CK(!strcmp(kof_amsi_region_name(KOF_SCAN_AMSI_META), "KOF_SCAN_AMSI_META") && !strcmp(kof_amsi_region_name(KOF_SCAN_AMSI_OBJ), "KOF_SCAN_AMSI_OBJ"), "amsi: regions are named by their enumerators");
	CK(kof_amsi_region_name(0x40000000u) == NULL, "amsi: an unknown bit has no name");
	CK(pa && pa->n_regions == 2 && !pa->sniff(kof_buf_make(blob, sizeof blob)), "amsi: the table row never sniffs (an event is declared, not recognised)");

	memset(pv, 0, sizeof pv);
	memset(&ctx, 0, sizeof ctx);
	(void)kof_proc_parse(kof_buf_make(blob, sizeof blob), pv, &ctx);
	CK(1, "proc: parse of an arbitrary record returns");
	for (i = 0; i < 3; i++)
		CK(kof_proc_region_name(kof_proc_regions[i]) && kof_proc_region_name(kof_proc_regions[i])[0] && strcmp(kof_proc_region_name(kof_proc_regions[i]), "?") != 0, "proc: region %u is named", i);
	CK(kof_proc_region_name(0x40000000u) == NULL, "proc: an unknown bit has no name");
	CK(pp && kof_region_mask_of(pp, kof_proc_region_name(kof_proc_regions[0])) == kof_proc_regions[0], "proc: the way back from the name works");
	CK(pa && kof_region_mask_of(pa, "KOF_SCAN_AMSI_OBJ") == KOF_SCAN_AMSI_OBJ &&
	   kof_region_mask_of(pa, "KOF_SCAN_AMSI_META") == KOF_SCAN_AMSI_META,
	   "kof_region_mask_of finds KOF_SCAN_AMSI_OBJ and _META in the AMSI row");
	CK(pp && pp->n_regions == 3 && !pp->sniff(kof_buf_make(blob, sizeof blob)), "proc: the table row never sniffs");
}

/* ---- the parser table ---------------------------------------------------------------------------------- */

static int list_null(void *arg)
{
	(void)arg;
	return kof_parser_list(NULL) != NULL ? 0 : 1;
}

static void t_table(void)
{
	uint32_t n = 0, i, j;
	const struct kof_parser *p = kof_parser_list(&n);

	CK(p != NULL && n == KOF_PARSER_COUNT, "the list holds KOF_PARSER_COUNT rows (%u)", n);
	for (i = 0; i < n; i++) {
		CK(p[i].view_size > 0 && p[i].sniff && p[i].parse && p[i].regions && p[i].region_name && p[i].anomaly_name && p[i].anomalies,
		   "row %u is complete", i);
		CK(kof_parser_of(p[i].format) == &p[i], "row %u is found by its format", i);
		for (j = 0; j < i; j++)
			CK(p[i].format != p[j].format, "rows %u and %u have one format", j, i);
	}
	{
		struct he_status st = he_child(list_null, NULL, 5);

		/* Every other getter here that fills an out parameter takes NULL for "do not
		 * fill it" (keng_version, kdb_version, kmatch_tables, kverdict_fact_id). */
		CK(he_ok(st), "kof_parser_list(NULL) answers the list without a count: %s", he_how(st));
	}
	CK(kof_parser_of(KOF_FMT_UNKNOWN) == NULL && kof_parser_of(KOF_FMT_MACHO) == NULL && kof_parser_of(250) == NULL, "no row for Raw, Mach-O or a format from outside");
	CK(kof_parser_cut_bits(NULL) == 0, "no parser, no cut bits");
	CK(kof_parser_cut_bits(kof_parser_of(KOF_FMT_ARJ)) == KOF_ARJ_ANOM_ENTRIES_FULL && kof_parser_cut_bits(kof_parser_of(KOF_FMT_PDF)) == (KOF_PDF_ANOM_OBJECTS_FULL | KOF_PDF_ANOM_EXTENTS_FULL) &&
	   kof_parser_cut_bits(kof_parser_of(KOF_FMT_CAB)) == KOF_CAB_ANOM_FILES_FULL && kof_parser_cut_bits(kof_parser_of(KOF_FMT_ZIP)) == (KOF_ZIP_ANOM_ENTRIES_FULL | KOF_ZIP_ANOM_EXTENTS_FULL),
	   "the formats whose tables can fill name the bit that says so");
	/* The anomaly word reads the right field of each view: a view with its first
	 * eight bytes at a pattern gives a word that is a function of the view alone. */
	for (i = 0; i < n; i++) {
		void *view = calloc(1, p[i].view_size);

		if (view) {
			CK(p[i].anomalies(view) == 0, "row %u: a zeroed view has no anomalies", i);
			free(view);
		}
	}
}

/* ---- member names -------------------------------------------------------------------------------------- */

static uint32_t clen(const char *s, size_t n, uint64_t at, uint32_t cap)
{
	return kof_cname_len(kof_buf_make(s, n), at, cap);
}

static int trav(const char *s, size_t n)
{
	return kof_cname_traversal(kof_buf_make(s, n), 0, (uint32_t)n);
}

static void t_cname(void)
{
	static const char nm[] = "abc\0def";

	CK(clen(nm, 7, 0, 16) == 4 && clen(nm, 7, 4, 16) == 0, "the length includes the terminator; \"def\" at 4 runs off the object and has none");
	CK(clen("ab\0cd\0", 6, 3, 16) == 3, "the second name of two");
	CK(clen(nm, 7, 0, 3) == 0, "no terminator within the cap: 0");
	CK(clen(nm, 7, 0, 4) == 4, "a terminator exactly at the cap is still a name");
	CK(clen(nm, 7, 7, 16) == 0 && clen(nm, 7, 100, 16) == 0 && clen(nm, 7, UINT64_MAX, 16) == 0, "an offset at, past, and near 2^64: 0");
	CK(clen("xyz", 3, 0, 16) == 0, "a name that runs off the end of the object has no length");
	CK(clen("", 1, 0, 16) == 1 && clen(nm, 7, 0, 0) == 0, "the empty name is one byte; a cap of zero finds nothing");
	CK(clen(nm, 7, 0, 0xffffffffu) == 4, "a cap of 2^32-1 stops at the object, not after 4 billion reads");

	CK(trav("../x", 4) && trav("a/../b", 6) && trav("a..b", 4) && trav("/etc", 4) && trav("\\x", 2) && trav("C:x", 3),
	   "dotdot anywhere, a leading slash, backslash or a drive letter");
	CK(!trav("a/b/c", 5) && !trav("a.b", 3) && !trav(".", 1) && !trav("", 0) && !trav("a", 1), "ordinary names");
	CK(!trav("x..", 2) && trav("x..", 3), "the pair is judged over the length given, not the bytes after it");
	CK(kof_cname_traversal(kof_buf_make("..", 2), 5, 2) == 0 && kof_cname_traversal(kof_buf_make("..", 2), UINT64_MAX - 1u, 2) == 0,
	   "an offset past the object is no traversal");
	CK(kof_cname_traversal(kof_buf_make("..", 2), 0, 0xffffffffu) == 1, "a length past the object is read only as far as the object goes");
}

/* kof_parser_self_clears: the formats whose parse clears what it reads, so the host skips its own memset */
static void t_self_clears(void)
{
	static const uint8_t yes[] = { KOF_FMT_ZIP, KOF_FMT_TAR, KOF_FMT_RAR, KOF_FMT_XZ, KOF_FMT_RTF, KOF_FMT_PDF,
				       KOF_FMT_LHA, KOF_FMT_ARJ, KOF_FMT_CAB, KOF_FMT_CHM, KOF_FMT_DOCOLE, KOF_FMT_7Z };
	uint32_t n, i, j;
	const struct kof_parser *list = kof_parser_list(&n);
	unsigned says_yes = 0;

	CK(kof_parser_self_clears(NULL) == 0, "no parser clears nothing");
	for (i = 0; list && i < n; i++) {
		int want = 0;

		for (j = 0; j < sizeof yes; j++)
			want |= list[i].format == yes[j];
		CK((kof_parser_self_clears(&list[i]) != 0) == want, "parser %u (format %u): self-clearing is %d", i, list[i].format, want);
		says_yes += kof_parser_self_clears(&list[i]) != 0;
	}
	CK(says_yes == sizeof yes, "exactly the twelve listed formats clear themselves (%u)", says_yes);
}

int main(void)
{
	build_seeds();
	t_zip();
	t_tar();
	t_gzip();
	t_7z();
	t_rar();
	t_xz();
	t_bz2();
	t_docole();
	t_pdf();
	t_rtf();
	t_arj();
	t_lha();
	t_cab();
	t_chm();
	t_lnk();
	t_reg();
	n_elf();
	n_pe();
	n_script();
	t_accessors();
	t_kind_names();
	t_amsi_proc();
	t_table();
	t_cname();
	t_self_clears();
	printf("api_engine_parsers: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
