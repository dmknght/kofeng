/* The parser list. See kofformat.h for why there is only one of it. */

#include "kofformat.h"
#include "binaries/elf/elf_parse.h"
#include "binaries/pe/pe_parse.h"
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
#include "containers/rtf_parse.h"
#include "containers/pdf_parse.h"
#include "scripts/script_parse.h"
#include "events/amsi_parse.h"
#include "processes/proc_parse.h"

static uint64_t kof_parser_no_anomalies(const void *view);

static const char *kof_parser_no_anomaly_name(unsigned index);

static int kof_parser_never_sniffs(kof_buf b);

/*
 * Each parser takes its own view type; the table takes one signature. The casts
 * live here, in one line each, rather than at every call site.
 */
static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kgenome_elf_info *)v, c);
}

static int pe_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pe_parse(b, (struct kgenome_pe_info *)v, c);
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

static int script_parse_keep_thunk(kof_buf b, void *v, struct kof_obj_ctx *c,
				   const void *keep)
{
	return kof_script_parse_keep(b, (struct kof_script_info *)v, c, keep);
}

_Static_assert(sizeof(struct kof_script_found) <= KOF_PARSER_KEEP,
	       "the script sniff's answer must fit what the host keeps for it");

const struct kof_parser_keep *kof_parser_keep_of(uint8_t format)
{
	static const struct kof_parser_keep script = {
		kof_script_sniff_keep, script_parse_keep_thunk
	};

	return format == KOF_FMT_SCRIPT ? &script : NULL;
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
	return ((const struct kgenome_elf_info *)v)->anomalies;
}

static uint64_t anom_pe(const void *v)
{
	return ((const struct kgenome_pe_info *)v)->anomalies;
}

static void zip_release_thunk(void *v)
{
	kof_zip_release((struct kof_zip_info *)v);
}

static void pdf_release_thunk(void *v)
{
	kof_pdf_release((struct kof_pdf_info *)v);
}

static void tar_release_thunk(void *v)
{
	kof_tar_release((struct kof_tar_info *)v);
}

static void lha_release_thunk(void *v)
{
	kof_lha_release((struct kof_lha_info *)v);
}

static void arj_release_thunk(void *v)
{
	kof_arj_release((struct kof_arj_info *)v);
}

static void cab_release_thunk(void *v)
{
	kof_cab_release((struct kof_cab_info *)v);
}

static void chm_release_thunk(void *v)
{
	kof_chm_release((struct kof_chm_info *)v);
}

static void docole_release_thunk(void *v)
{
	kof_docole_release((struct kof_docole_info *)v);
}

static void rar_release_thunk(void *v)
{
	kof_rar_release((struct kof_rar_info *)v);
}

static void sevenzip_release_thunk(void *v)
{
	kof_7z_release((struct kof_7z_info *)v);
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

/*
 * THE ANOMALY BITS THAT MEAN "A TABLE OF THE PARSER WAS FULL, AND WHAT IS PAST IT
 * WAS NOT READ".
 *
 * A parse's table that cannot grow (the file's own bound, or the engine's ledger: see tabgrow.h)
 * records it as an anomaly. Reading that word is not the module's business: the engine reads it,
 * once, after the parse (sx_facts), and the object says it was cut (KOF_BROKEN_LIMIT) - one place,
 * so no module has to remember, and none does. Every "full" bit a parser sets is here, because a bit
 * nothing reads is a member that is gone with no word anywhere. (The 7z coded-header walk is listed
 * too: a header that cannot be decoded within the account is a folder list not read.)
 */
uint64_t kof_parser_cut_bits(const struct kof_parser *p)
{
	if (!p)
		return 0;
	switch (p->format) {
	case KOF_FMT_ARJ: return KOF_ARJ_ANOM_ENTRIES_FULL;
	case KOF_FMT_LHA: return KOF_LHA_ANOM_ENTRIES_FULL;
	case KOF_FMT_CAB: return KOF_CAB_ANOM_FILES_FULL;
	case KOF_FMT_CHM: return KOF_CHM_ANOM_ENTRIES_FULL;
	case KOF_FMT_PDF: return KOF_PDF_ANOM_OBJECTS_FULL | KOF_PDF_ANOM_EXTENTS_FULL;
	case KOF_FMT_REG: return KOF_REG_ANOM_EXTENTS_FULL;
	case KOF_FMT_RAR: return KOF_RAR_ANOM_ENTRIES_FULL | KOF_RAR_ANOM_EXTENTS_FULL;
	case KOF_FMT_DOCOLE:
		return KOF_DOCOLE_ANOM_ENT_RUNS_FULL | KOF_DOCOLE_ANOM_DIR_OVERFLOW |
		       KOF_DOCOLE_ANOM_EXTENTS_FULL | KOF_DOCOLE_ANOM_ENTRIES_FULL |
		       KOF_DOCOLE_ANOM_WORK_FULL;
	case KOF_FMT_ZIP: return KOF_ZIP_ANOM_ENTRIES_FULL | KOF_ZIP_ANOM_EXTENTS_FULL;
	case KOF_FMT_TAR: return KOF_TAR_ANOM_ENTRIES_FULL | KOF_TAR_ANOM_EXTENTS_FULL;
	case KOF_FMT_7Z:  return KOF_7Z_ANOM_FOLDERS_FULL;
	case KOF_FMT_SCRIPT: return KOF_SCRIPT_ANOM_ISLANDS_FULL;
	default:          return 0;
	}
}

/*
 * The handles of the views that own memory. DOCZIP is the same row as ZIP - the parse
 * chooses between them - so both name the one view; asked for a format without such a
 * view the answer is NULL and the caller has nothing to arm, charge or release.
 */
const struct kof_view_ops *kof_view_ops_of(uint8_t format)
{
	static const struct kof_view_ops zip = { kof_zip_mem, zip_release_thunk, kof_zip_row };
	static const struct kof_view_ops pdf = { kof_pdf_mem, pdf_release_thunk, kof_pdf_row };
	static const struct kof_view_ops tar = { kof_tar_mem, tar_release_thunk, kof_tar_row };
	static const struct kof_view_ops lha = { kof_lha_mem, lha_release_thunk, kof_lha_row };
	static const struct kof_view_ops arj = { kof_arj_mem, arj_release_thunk, kof_arj_row };
	static const struct kof_view_ops cab = { kof_cab_mem, cab_release_thunk, kof_cab_row };
	static const struct kof_view_ops chm = { kof_chm_mem, chm_release_thunk, kof_chm_row };
	static const struct kof_view_ops docole = { kof_docole_mem, docole_release_thunk,
						    kof_docole_row };
	static const struct kof_view_ops rar = { kof_rar_mem, rar_release_thunk, kof_rar_row };
	static const struct kof_view_ops sz = { kof_7z_mem, sevenzip_release_thunk, kof_7z_row };

	switch (format) {
	case KOF_FMT_ZIP: case KOF_FMT_DOCZIP: return &zip;
	case KOF_FMT_PDF:                      return &pdf;
	case KOF_FMT_TAR:                      return &tar;
	case KOF_FMT_LHA:                      return &lha;
	case KOF_FMT_ARJ:                      return &arj;
	case KOF_FMT_CAB:                      return &cab;
	case KOF_FMT_CHM:                      return &chm;
	case KOF_FMT_DOCOLE:                   return &docole;
	case KOF_FMT_RAR:                      return &rar;
	case KOF_FMT_7Z:                       return &sz;
	default:                               return NULL;
	}
}

/* The header region of each format, by its own enumerator: the one place the
 * "a header is not offered" decision names a bit (kof_parser_region_unoffered). */
uint32_t kof_parser_region_unoffered(const struct kof_parser *p)
{
	uint32_t m = KOF_SCAN_SYM;      /* built by the host, not in the file */

	if (!p)
		return m;
	switch (p->format) {
	case KOF_FMT_ELF:    return m | KGENOME_SCAN_ELF_HEADERS | KGENOME_SCAN_ELF_SLIB_CODE |
				    KGENOME_SCAN_ELF_SLIB_DATA;
	case KOF_FMT_PE:     return m | KGENOME_SCAN_PE_HEADERS;
	case KOF_FMT_GZIP:   return m | KOF_SCAN_GZIP_HEADER;
	case KOF_FMT_DOCOLE: return m | KOF_SCAN_DOCOLE_HEADERS;
	case KOF_FMT_ZIP:    return m | KOF_SCAN_ZIP_HEADERS;
	case KOF_FMT_TAR:    return m | KOF_SCAN_TAR_HEADERS;
	case KOF_FMT_7Z:     return m | KOF_SCAN_7Z_HEADERS;
	case KOF_FMT_RAR:    return m | KOF_SCAN_RAR_HEADERS;
	case KOF_FMT_XZ:     return m | KOF_SCAN_XZ_HEADERS;
	case KOF_FMT_ARJ:    return m | KOF_SCAN_ARJ_HEADERS;
	case KOF_FMT_LHA:    return m | KOF_SCAN_LHA_HEADERS;
	case KOF_FMT_CAB:    return m | KOF_SCAN_CAB_HEADERS;
	case KOF_FMT_CHM:    return m | KOF_SCAN_CHM_HEADERS;
	case KOF_FMT_BZIP2:  return m | KOF_SCAN_BZ2_HEADER;
	case KOF_FMT_PDF:    return m | KOF_SCAN_PDF_HEADERS;
	case KOF_FMT_LNK:    return m | KOF_SCAN_LNK_HEADER;
	case KOF_FMT_REG:    return m | KOF_SCAN_REG_HEADER;
	case KOF_FMT_SCRIPT: return m | KOF_SCAN_SCRIPT_HEADER;
	default:             return m;
	}
}

/*
 * Whether the format's parse clears what it will read by itself - its header, and each array
 * slot as it claims it ("nothing reads past a count", pinned by tests/unit/view_reuse.c) - so the
 * host need not zero the whole view first. That memset was 819 KB per PDF, 623 KB per zip,
 * 311 KB per RAR, redundant, and it made every page of a view resident for the life of the
 * scanner. Not listed: a format whose parse keeps a field the CALLER fills, or does not clear
 * its own; the host clears those as it always did.
 *
 * ZIP AND PDF CLEAR THE WHOLE OF THEIR VIEW NOW (it is a few hundred bytes: the arrays are
 * tables the parse allocates) and let go of what the last parse held first, which is also why
 * the host must never memset such a view itself - the pointers in it are the only way to free
 * the tables. The caller's `mem.room` is the one field the parse reads before it clears.
 */
int kof_parser_self_clears(const struct kof_parser *p)
{
	if (!p)
		return 0;
	switch (p->format) {
	case KOF_FMT_ZIP: case KOF_FMT_TAR: case KOF_FMT_RAR:
	case KOF_FMT_XZ:  case KOF_FMT_RTF: case KOF_FMT_PDF:
	case KOF_FMT_LHA: case KOF_FMT_ARJ: case KOF_FMT_CAB: case KOF_FMT_CHM:
	case KOF_FMT_DOCOLE: case KOF_FMT_7Z:
		return 1;
	default:
		return 0;
	}
}

static const struct kof_parser formats[] = {
	{ KOF_FMT_ELF, (uint32_t)sizeof(struct kgenome_elf_info),
	  kgenome_elf_sniff, elf_parse_thunk,
	  kof_elf_region_bits, KOF_ELF_REGION_COUNT,
	  kof_elf_region_name, kof_elf_anomaly_name, anom_elf },
	{ KOF_FMT_PE, (uint32_t)sizeof(struct kgenome_pe_info),
	  kgenome_pe_sniff, pe_parse_thunk,
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
	  kof_parser_never_sniffs, amsi_parse_thunk,
	  kof_amsi_regions, 2u,
	  kof_amsi_region_name, kof_parser_no_anomaly_name,
	  kof_parser_no_anomalies },

	/*
	 * A PROCESS SNAPSHOT. Like the row above it this never sniffs and is
	 * reached only through kof_parser_of(KOF_EVT_PROC), by a caller that
	 * built the record. See processes/proc_parse.h.
	 */
	{ KOF_EVT_PROC, (uint32_t)sizeof(struct kof_proc_info),
	  kof_parser_never_sniffs, proc_parse_thunk,
	  kof_proc_regions, 3u,
	  kof_proc_region_name, kof_parser_no_anomaly_name,
	  kof_parser_no_anomalies }
};


/*
 * The three entries of a parser row for a format that has nothing to say: an
 * event record (AMSI, a process snapshot) has no magic, so its sniff never
 * accepts - any test would be a guess about whose bytes these are - and it
 * keeps no anomaly word. Reached only through kof_parser_of(), by a caller that
 * already knows what it holds.
 */
static int kof_parser_never_sniffs(kof_buf b)
{
	(void)b;
	return 0;
}

static const char *kof_parser_no_anomaly_name(unsigned index)
{
	(void)index;
	return "?";
}

static uint64_t kof_parser_no_anomalies(const void *view)
{
	(void)view;
	return 0;
}

_Static_assert(sizeof formats / sizeof formats[0] == KOF_PARSER_COUNT,
	       "KOF_PARSER_COUNT no longer matches the table");


const struct kof_parser *kof_parser_list(uint32_t *n)
{
	/* NULL means "do not tell me how many", as for every other getter that fills an
	 * out parameter (keng_version, kdb_version, kmatch_tables). */
	if (n)
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
