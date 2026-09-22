/* The parser list. See kofformat.h for why there is only one of it. */

#include "kofformat.h"
#include "binaries/elf_parse.h"
#include "binaries/pe_parse.h"
#include "containers/gzip_parse.h"
#include "containers/docole_parse.h"
#include "containers/zip_parse.h"
#include "containers/tar_parse.h"
#include "containers/sevenzip_parse.h"
#include "containers/rar_parse.h"
#include "containers/xz_parse.h"
#include "containers/bz2_parse.h"
#include "containers/chm_parse.h"
#include "containers/cab_parse.h"
#include "containers/lha_parse.h"
#include "containers/arj_parse.h"
#include "containers/lnk_parse.h"
#include "containers/reg_parse.h"
#include "containers/reg_parse.h"
#include "containers/rtf_parse.h"
#include "containers/pdf_parse.h"
#include "scripts/script_parse.h"
#include "events/amsi_parse.h"
#include "processes/proc_parse.h"

/*
 * Each parser takes its own view type; the table takes one signature. The casts
 * live here, in one line each, rather than at every call site.
 */
static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kof_elf_info *)v, c);
}

static int pe_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pe_parse(b, (struct kof_pe_info *)v, c);
}

static int gzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_gzip_parse(b, (struct kof_gzip_info *)v, c);
}

static int arj_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_arj_parse(b, (struct kof_arj_info *)v, c);
}

static int lnk_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_lnk_parse(b, (struct kof_lnk_info *)v, c);
}

static int reg_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_reg_parse(b, (struct kof_reg_info *)v, c);
}

static int lha_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_lha_parse(b, (struct kof_lha_info *)v, c);
}

static int cab_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_cab_parse(b, (struct kof_cab_info *)v, c);
}

static int chm_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_chm_parse(b, (struct kof_chm_info *)v, c);
}

static int bz2_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_bz2_parse(b, (struct kof_bz2_info *)v, c);
}

static int docole_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_docole_parse(b, (struct kof_docole_info *)v, c);
}

static int zip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_zip_parse(b, (struct kof_zip_info *)v, c);
}

static int tar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_tar_parse(b, (struct kof_tar_info *)v, c);
}

static int sevenzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_7z_parse(b, (struct kof_7z_info *)v, c);
}

static int rar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rar_parse(b, (struct kof_rar_info *)v, c);
}

static int xz_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_xz_parse(b, (struct kof_xz_info *)v, c);
}

static int script_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_script_parse(b, (struct kof_script_info *)v, c);
}

static int rtf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rtf_parse(b, (struct kof_rtf_info *)v, c);
}

static int pdf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pdf_parse(b, (struct kof_pdf_info *)v, c);
}

static int proc_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_proc_parse(b, v, c);
}

static int amsi_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_amsi_parse(b, v, c);
}

/*
 * The anomaly word, read through the view's own type. One line each, all of
 * them here, so no caller ever casts a view it did not allocate.
 */
static uint64_t anom_elf(const void *v)
{
	return ((const struct kof_elf_info *)v)->anomalies;
}

static uint64_t anom_pe(const void *v)
{
	return ((const struct kof_pe_info *)v)->anomalies;
}

static uint64_t anom_gzip(const void *v)
{
	return ((const struct kof_gzip_info *)v)->anomalies;
}

static uint64_t anom_docole(const void *v)
{
	return ((const struct kof_docole_info *)v)->anomalies;
}

static uint64_t anom_zip(const void *v)
{
	return ((const struct kof_zip_info *)v)->anomalies;
}

static uint64_t anom_tar(const void *v)
{
	return ((const struct kof_tar_info *)v)->anomalies;
}

static uint64_t anom_7z(const void *v)
{
	return ((const struct kof_7z_info *)v)->anomalies;
}

static uint64_t anom_rar(const void *v)
{
	return ((const struct kof_rar_info *)v)->anomalies;
}

static uint64_t anom_xz(const void *v)
{
	return ((const struct kof_xz_info *)v)->anomalies;
}

static uint64_t anom_pdf(const void *v)
{
	return ((const struct kof_pdf_info *)v)->anomalies;
}

/* Required, not optional: both readers call it without a null check, so a row
 * that left it out segfaulted on the first object it claimed. None are defined
 * for a script yet; the word is there so the row can answer. */
static uint64_t anom_script(const void *v)
{
	return ((const struct kof_script_info *)v)->anomalies;
}

static uint64_t anom_arj(const void *v)
{
	return ((const struct kof_arj_info *)v)->anomalies;
}

static uint64_t anom_lnk(const void *v)
{
	return ((const struct kof_lnk_info *)v)->anomalies;
}

static uint64_t anom_reg(const void *v)
{
	return ((const struct kof_reg_info *)v)->anomalies;
}

static uint64_t anom_lha(const void *v)
{
	return ((const struct kof_lha_info *)v)->anomalies;
}

static uint64_t anom_cab(const void *v)
{
	return ((const struct kof_cab_info *)v)->anomalies;
}

static uint64_t anom_chm(const void *v)
{
	return ((const struct kof_chm_info *)v)->anomalies;
}

static uint64_t anom_bz2(const void *v)
{
	return ((const struct kof_bz2_info *)v)->anomalies;
}

static uint64_t anom_rtf(const void *v)
{
	return ((const struct kof_rtf_info *)v)->anomalies;
}

static const struct kof_parser formats[] = {
	{ KOF_FMT_ELF, (uint32_t)sizeof(struct kof_elf_info),
	  kof_elf_sniff, elf_parse_thunk,
	  kof_elf_region_bits, KOF_ELF_REGION_COUNT,
	  kof_elf_region_name, kof_elf_anomaly_name, anom_elf },
	{ KOF_FMT_PE, (uint32_t)sizeof(struct kof_pe_info),
	  kof_pe_sniff, pe_parse_thunk,
	  kof_pe_region_bits, KOF_PE_REGION_COUNT,
	  kof_pe_region_name, kof_pe_anomaly_name, anom_pe },
	{ KOF_FMT_GZIP, (uint32_t)sizeof(struct kof_gzip_info),
	  kof_gzip_sniff, gzip_parse_thunk,
	  kof_gzip_region_bits, KOF_GZIP_REGION_COUNT,
	  kof_gzip_region_name, kof_gzip_anomaly_name, anom_gzip },
	{ KOF_FMT_DOCOLE, (uint32_t)sizeof(struct kof_docole_info),
	  kof_docole_sniff, docole_parse_thunk,
	  kof_docole_region_bits, KOF_DOCOLE_REGION_COUNT,
	  kof_docole_region_name, kof_docole_anomaly_name, anom_docole },
	/*
	 * One row, two formats. The parse decides between ZIP and DOCZIP from the
	 * entry names and sets ctx->format itself, so the format named here is only
	 * which VIEW to allocate - and both share one.
	 */
	{ KOF_FMT_ZIP, (uint32_t)sizeof(struct kof_zip_info),
	  kof_zip_sniff, zip_parse_thunk,
	  kof_zip_region_bits, KOF_ZIP_REGION_COUNT,
	  kof_zip_region_name, kof_zip_anomaly_name, anom_zip },
	{ KOF_FMT_TAR, (uint32_t)sizeof(struct kof_tar_info),
	  kof_tar_sniff, tar_parse_thunk,
	  kof_tar_region_bits, KOF_TAR_REGION_COUNT,
	  kof_tar_region_name, kof_tar_anomaly_name, anom_tar },
	{ KOF_FMT_7Z, (uint32_t)sizeof(struct kof_7z_info),
	  kof_7z_sniff, sevenzip_parse_thunk,
	  kof_7z_region_bits, KOF_7Z_REGION_COUNT,
	  kof_7z_region_name, kof_7z_anomaly_name, anom_7z },
	{ KOF_FMT_RAR, (uint32_t)sizeof(struct kof_rar_info),
	  kof_rar_sniff, rar_parse_thunk,
	  kof_rar_region_bits, KOF_RAR_REGION_COUNT,
	  kof_rar_region_name, kof_rar_anomaly_name, anom_rar },
	{ KOF_FMT_XZ, (uint32_t)sizeof(struct kof_xz_info),
	  kof_xz_sniff, xz_parse_thunk,
	  kof_xz_region_bits, KOF_XZ_REGION_COUNT,
	  kof_xz_region_name, kof_xz_anomaly_name, anom_xz },
	{ KOF_FMT_ARJ, (uint32_t)sizeof(struct kof_arj_info),
	  kof_arj_sniff, arj_parse_thunk,
	  kof_arj_region_bits, KOF_ARJ_REGION_COUNT,
	  kof_arj_region_name, kof_arj_anomaly_name, anom_arj },
	{ KOF_FMT_LHA, (uint32_t)sizeof(struct kof_lha_info),
	  kof_lha_sniff, lha_parse_thunk,
	  kof_lha_region_bits, KOF_LHA_REGION_COUNT,
	  kof_lha_region_name, kof_lha_anomaly_name, anom_lha },
	{ KOF_FMT_CAB, (uint32_t)sizeof(struct kof_cab_info),
	  kof_cab_sniff, cab_parse_thunk,
	  kof_cab_region_bits, KOF_CAB_REGION_COUNT,
	  kof_cab_region_name, kof_cab_anomaly_name, anom_cab },
	{ KOF_FMT_CHM, (uint32_t)sizeof(struct kof_chm_info),
	  kof_chm_sniff, chm_parse_thunk,
	  kof_chm_region_bits, KOF_CHM_REGION_COUNT,
	  kof_chm_region_name, kof_chm_anomaly_name, anom_chm },
	{ KOF_FMT_BZIP2, (uint32_t)sizeof(struct kof_bz2_info),
	  kof_bz2_sniff, bz2_parse_thunk,
	  kof_bz2_region_bits, KOF_BZ2_REGION_COUNT,
	  kof_bz2_region_name, kof_bz2_anomaly_name, anom_bz2 },
	{ KOF_FMT_RTF, (uint32_t)sizeof(struct kof_rtf_info),
	  kof_rtf_sniff, rtf_parse_thunk,
	  kof_rtf_region_bits, KOF_RTF_REGION_COUNT,
	  kof_rtf_region_name, kof_rtf_anomaly_name, anom_rtf },
	{ KOF_FMT_PDF, (uint32_t)sizeof(struct kof_pdf_info),
	  kof_pdf_sniff, pdf_parse_thunk,
	  kof_pdf_region_bits, KOF_PDF_REGION_COUNT,
	  kof_pdf_region_name, kof_pdf_anomaly_name, anom_pdf },

	/*
	 * ABOVE THE SCRIPT ROW, because a shell link HAS a magic and the rule
	 * of this table is that the formats which can prove what they are go
	 * first. Its sniff is stricter than most: a fixed size field AND the
	 * one CLSID, which is twenty bytes that have to agree.
	 */
	{ KOF_FMT_LNK, (uint32_t)sizeof(struct kof_lnk_info),
	  kof_lnk_sniff, lnk_parse_thunk,
	  kof_lnk_region_bits, KOF_LNK_REGION_COUNT,
	  kof_lnk_region_name, kof_lnk_anomaly_name, anom_lnk },

	/*
	 * ALSO ABOVE THE SCRIPT ROW, and for a reason the script sniff makes
	 * necessary rather than merely tidy: a .reg is text, and the tagless
	 * rules below read text looking for a language. "Windows Registry
	 * Editor Version 5.00" is a whole line that only this format has, so
	 * asking for it first settles the file before anything has to guess.
	 */
	{ KOF_FMT_REG, (uint32_t)sizeof(struct kof_reg_info),
	  kof_reg_sniff, reg_parse_thunk,
	  kof_reg_region_bits, KOF_REG_REGION_COUNT,
	  kof_reg_region_name, kof_reg_anomaly_name, anom_reg },

	/*
	 * AFTER EVERY FORMAT WITH A MAGIC NUMBER, which is what makes its sniff
	 * safe to write loosely. A script has no magic - "#!" is two bytes that
	 * occur in plenty of binaries - so it only gets to look at what nothing
	 * structured has claimed. Moving this row up would let a shebang beat a
	 * real header, which is the one mistake the order of this table exists
	 * to prevent. See script_parse.h.
	 */
	{ KOF_FMT_SCRIPT, (uint32_t)sizeof(struct kof_script_info),
	  kof_script_sniff, script_parse_thunk,
	  kof_script_region_bits, KOF_SCRIPT_REGION_COUNT,
	  kof_script_region_name, kof_script_anomaly_name, anom_script },

	/*
	 * LAST, AND ITS SNIFF NEVER ACCEPTS.
	 *
	 * Order is part of this table's contract - the first sniff that accepts
	 * wins - and this row opts out of that race entirely: an event record
	 * has no magic, so any sniff would be a guess about whose bytes these
	 * are. It is reached only through kof_parser_of(KOF_EVT_AMSI), by a
	 * caller that already knows what it is holding. See amsi_parse.h.
	 */
	{ KOF_EVT_AMSI, (uint32_t)sizeof(struct kof_amsi_view),
	  kof_amsi_sniff, amsi_parse_thunk,
	  kof_amsi_regions, 2u,
	  kof_amsi_region_name, kof_amsi_anomaly_name, kof_amsi_anomalies },

	/*
	 * A PROCESS SNAPSHOT. Like the row above it this never sniffs and is
	 * reached only through kof_parser_of(KOF_EVT_PROC), by a caller that
	 * built the record. See processes/proc_parse.h.
	 */
	{ KOF_EVT_PROC, (uint32_t)sizeof(struct kof_proc_info),
	  kof_proc_sniff, proc_parse_thunk,
	  kof_proc_regions, 3u,
	  kof_proc_region_name, kof_proc_anomaly_name, kof_proc_anomalies }
};


_Static_assert(sizeof formats / sizeof formats[0] == KOF_PARSER_COUNT,
	       "KOF_PARSER_COUNT no longer matches the table");


const struct kof_parser *kof_parser_list(uint32_t *n)
{
	*n = (uint32_t)(sizeof formats / sizeof formats[0]);
	return formats;
}

const struct kof_parser *kof_parser_of(uint8_t format)
{
	uint32_t i;

	for (i = 0; i < sizeof formats / sizeof formats[0]; i++)
		if (formats[i].format == format)
			return &formats[i];
	return NULL;
}

uint32_t kof_region_mask_of(const struct kof_parser *fp, const char *enum_name)
{
	uint32_t i;

	if (!enum_name || !enum_name[0] || !fp || !fp->regions ||
	    !fp->region_name)
		return (uint32_t)KOF_SCAN_ALL;
	for (i = 0; i < fp->n_regions; i++) {
		const char *rn = fp->region_name(fp->regions[i]);

		if (rn && !strcmp(rn, enum_name))
			return fp->regions[i];
	}
	/* Not a region of this format - see the note on the declaration. */
	return (uint32_t)KOF_SCAN_ALL;
}
