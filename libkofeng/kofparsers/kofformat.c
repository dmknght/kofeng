/* SPDX-License-Identifier: Apache-2.0 */
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
#include "containers/rtf_parse.h"
#include "containers/pdf_parse.h"

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

static int rtf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rtf_parse(b, (struct kof_rtf_info *)v, c);
}

static int pdf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pdf_parse(b, (struct kof_pdf_info *)v, c);
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
	{ KOF_FMT_RTF, (uint32_t)sizeof(struct kof_rtf_info),
	  kof_rtf_sniff, rtf_parse_thunk,
	  kof_rtf_region_bits, KOF_RTF_REGION_COUNT,
	  kof_rtf_region_name, kof_rtf_anomaly_name, anom_rtf },
	{ KOF_FMT_PDF, (uint32_t)sizeof(struct kof_pdf_info),
	  kof_pdf_sniff, pdf_parse_thunk,
	  kof_pdf_region_bits, KOF_PDF_REGION_COUNT,
	  kof_pdf_region_name, kof_pdf_anomaly_name, anom_pdf }
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
