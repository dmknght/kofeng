/*
 * kofheur.c - see kofheur.h.
 *
 * THE VALUES IN THIS FILE WERE MEASURED, AND THE MEASUREMENT IS WHY THEY LOOK
 * UNEVEN.
 *
 * Each is log(P(trace | malware) / P(trace | clean)) over a population of that
 * format: 6523 malware ELF against 13638 clean, and 899 malware PE against
 * 25267 clean. The ELF paragraph below is about the ELF numbers; the PE ones
 * carry their own note beside them, including what their population is missing.
 *
 * FOR THE ELF SIDE: The clean set was chosen adversarially: it holds
 * 1482 legitimate system binaries packed with UPX, Ezuri, gzexe, ward, midgetpack
 * and pakkero, because a clean corpus with no packed files makes "is it packed"
 * look like a perfect detector and it is not.
 *
 * Two results decided the shape of everything here:
 *
 *   - SECTAB_MISSING is worth 2.75 nats in the file itself and 5.71 nats in an
 *     image recovered from inside a packer. Packing a clean binary yields a clean
 *     image; packing malware yields an image that is itself malformed. That is
 *     why depth is part of the score and not a footnote.
 *
 *   - "an unpacker recognised its format and could not finish" appeared in 0 of
 *     13638 clean objects. Legitimate packing unpacks cleanly. A tampered stub
 *     does not.
 */

#include <string.h>

#include "kofheur.h"
#include "../../kofcore/kofmod/kofsig.h"
#include "../../kofcore/kofmod/elf.h"
#include "../../kofcore/kofmod/pe.h"
#include "../../kofcore/kofmod/gzip.h"
#include "../../kofcore/kofmod/docole.h"
#include "../../kofcore/kofmod/zip.h"
#include "../../kofcore/kofmod/tar.h"
#include "../../kofcore/kofmod/sevenzip.h"
#include "../../kofcore/kofmod/rar.h"
#include "../../kofcore/kofmod/xz.h"
#include "../../kofcore/kofmod/bz2.h"
#include "../../kofcore/kofmod/chm.h"
#include "../../kofcore/kofmod/cab.h"
#include "../../kofcore/kofmod/lha.h"
#include "../../kofcore/kofmod/arj.h"
#include "../../kofcore/kofmod/rtf.h"
#include "../../kofcore/kofmod/pdf.h"

uint64_t kof_heur_anomalies(const struct kof_obj_ctx *ctx)
{
	if (!ctx || !ctx->file_header)
		return 0;
	switch (ctx->format) {
	case KOF_FMT_ELF:    return kof_elf(ctx)->anomalies;
	case KOF_FMT_PE:     return kof_pe(ctx)->anomalies;
	case KOF_FMT_GZIP:   return kof_gzip(ctx)->anomalies;
	case KOF_FMT_DOCOLE: return kof_docole(ctx)->anomalies;
	case KOF_FMT_ZIP:
	case KOF_FMT_DOCZIP: return kof_zip(ctx)->anomalies;
	case KOF_FMT_TAR:    return kof_tar(ctx)->anomalies;
	case KOF_FMT_7Z:     return kof_7z(ctx)->anomalies;
	case KOF_FMT_RAR:    return kof_rar(ctx)->anomalies;
	case KOF_FMT_XZ:     return kof_xz(ctx)->anomalies;
	case KOF_FMT_BZIP2:  return kof_bz2(ctx)->anomalies;
	case KOF_FMT_CHM:    return kof_chm(ctx)->anomalies;
	case KOF_FMT_CAB:    return kof_cab(ctx)->anomalies;
	case KOF_FMT_LHA:    return kof_lha(ctx)->anomalies;
	case KOF_FMT_ARJ:    return kof_arj(ctx)->anomalies;
	case KOF_FMT_RTF:    return kof_rtf(ctx)->anomalies;
	case KOF_FMT_PDF:    return kof_pdf(ctx)->anomalies;
	default:             return 0;
	}
}

/*
 * TWO FORMATS NOW, AND THE MASK BELOW SAYS WHICH.
 *
 * Every term names the format it was measured on and nothing borrows a number
 * from another: bit 3 is one thing in an ELF and another in a PE, and the clean
 * populations have nothing in common either. A doczip is still not covered -
 * a document container that is malformed is usually just a document written by
 * something old - and the model reports that rather than scoring it with
 * numbers from somewhere else.
 */
#define CN(x) ((int32_t)((x) * 100))

static const struct kof_heur_anom_term default_anom[] = {
	/*
	 * --- PE -----------------------------------------------------------
	 *
	 * Measured the same way and on this machine's own populations: 899
	 * malware PE from the sample collection against 25267 clean PE - the
	 * Windows system DLLs of a Wine prefix, .NET assemblies, and game and
	 * editor binaries. Every term below fires on ZERO of the clean set.
	 *
	 * WHAT THIS POPULATION IS NOT. It is not a Windows install and it has
	 * no legitimately packed members, which is the gap the ELF numbers were
	 * careful to close - 1482 of the clean ELF are system binaries wrapped
	 * in UPX, Ezuri and four others, because a clean corpus with no packed
	 * files makes "is it packed" look like a perfect detector. The PE side
	 * has no equivalent yet, so the terms here are deliberately ones that
	 * packing does not produce: a packer writes a well formed header.
	 *
	 * AND ONE FILE HAD TO BE THROWN OUT, which is worth recording because
	 * it is how a clean corpus goes wrong. The first pass found exactly one
	 * "clean" file with SEC_WRITE_EXEC and it was
	 * RetDec-v5.0/bin/samples/111.exe - a malware sample shipped with a
	 * tool. A clean set gathered by path is only as clean as the paths.
	 *
	 * WHAT IS LEFT OUT, AND WHY. SEC_OVERLAP, ENTRY_NOT_EXEC and
	 * ENTRY_UNMAPPED are absent from the clean set too, but appear on 3, 3
	 * and 2 malware files - too few to be a measurement. SEC_ZERO_RAW
	 * (+0.14) and ENTRY_ZERO (+0.12) are worth nothing. STUB_NONSTANDARD
	 * (-1.21) and SECNAME_OBJFORM (-2.49) point the OTHER way on this
	 * population: 10262 and 6608 of the clean files carry them, because a
	 * .NET assembly has neither a DOS stub nor image section names. A
	 * negative term is a thing this model has no shape for, so they are
	 * left out rather than clamped to zero and forgotten.
	 *
	 * The bar is the ELF one, 747, and it did not have to move: the highest
	 * any of the 25267 clean PE reaches is 110. At that bar these terms
	 * detect 113 of 899 malware PE - 12.6%, against 11.0% for the ELF side.
	 *
	 * Confirmed end to end rather than on the arithmetic alone: a full scan
	 * of all 25779 clean PE at --heur 1 reports zero heuristic verdicts.
	 * The sum is not the whole score - the flag terms and the depth of the
	 * object add to it - so a table that computes clean on paper can still
	 * fire in a scan.
	 */
	{ KOF_FMT_PE,  KOF_PE_ANOM_SEC_WRITE_EXEC,     CN(8.64), "WriteExec" },
	{ KOF_FMT_PE,  KOF_PE_ANOM_SUMMARY_MISMATCH,   CN(7.93), "HdrMismatch" },
	{ KOF_FMT_PE,  KOF_PE_ANOM_ENTRY_ZEROFILL,     CN(6.55), "EntryUnwritten" },
	{ KOF_FMT_PE,  KOF_PE_ANOM_DIR_COUNT_ODD,      CN(6.28), "DirCount"  },
	{ KOF_FMT_PE,  KOF_PE_ANOM_CERT_PAST_EOF,      CN(6.17), "CertCut"   },
	{ KOF_FMT_PE,  KOF_PE_ANOM_SEC_PAST_EOF,       CN(1.10), "Truncated" },

	/* --- the file's own structure ----------------------------------- */
	{ KOF_FMT_ELF, KOF_ELF_ANOM_SECTAB_MISSING,    CN(2.75), "Stripped"  },
	{ KOF_FMT_ELF, KOF_ELF_ANOM_SEG_PAST_EOF,      CN(5.15), "Truncated" },
	{ KOF_FMT_ELF, KOF_ELF_ANOM_SHOFF_PAST_EOF,    CN(4.84), "Truncated" },
	{ KOF_FMT_ELF, KOF_ELF_ANOM_SEC_PAST_EOF,      CN(4.50), "Truncated" },
	{ KOF_FMT_ELF, KOF_ELF_ANOM_SEG_OVERLAP,       CN(2.96), "Overlap"   },
	{ KOF_FMT_ELF, KOF_ELF_ANOM_ENTRY_NOT_EXEC,    CN(2.63), "BadEntry"  },
	{ KOF_FMT_ELF, KOF_ELF_ANOM_NO_LOAD_SEGMENT,   CN(1.35), "NoLoad"    }
};

static const struct kof_heur_flag_term default_flag[] = {
	/* --- how it was reached ------------------------------------------ */
	{ KOF_HEUR_F_PACKED,          CN(1.11), "Packed"     },
	{ KOF_HEUR_F_UNPACK_PARTIAL,  CN(3.24), "PackTamper" }
	/*
	 * THERE WAS A TERM HERE FOR "the file is nothing but code", AND IT IS
	 * NOW A RULE.
	 *
	 * It was the one value in this table that was chosen rather than
	 * measured - set at the bar so a single trace could report on its own,
	 * which is not what a sum of log-likelihood ratios is for. That is the
	 * shape of a rule, so it is written as one:
	 * bases/heur/shellcode_00.c, where it also carries the measurement and
	 * asks for the emulator. Nothing here has to pretend to score it.
	 */
	/*
	 * There were two more here - StrayMarker and PartFamily, both measured -
	 * for evidence the database notices without firing. Nothing ever
	 * gathered those facts, so the weights sat in the table describing a
	 * question no code asked. A measured weight for a fact that is never
	 * collected reads as a working feature, so it is out until the
	 * collector arrives with it.
	 */
};

/*
 * The bar.
 *
 * 747 centinats, and it is not a round number because it is not a choice: the
 * highest score reached by any of the 13638 clean objects was 386, and the next
 * score any object of either kind takes is 747. Sitting on that step is what
 * makes the measured false-positive count zero rather than small.
 *
 * Detection at this bar was 11.0% of the malware the signature database missed.
 * Lowering it to 386 buys 14.9% and costs 1.47% false positives - which on a
 * desktop's ten thousand ELF files is a hundred and fifty wrong answers, so it is
 * not offered.
 */
static const struct kof_heur_model default_model = {
	default_anom, (uint32_t)(sizeof default_anom / sizeof default_anom[0]),
	default_flag, (uint32_t)(sizeof default_flag / sizeof default_flag[0]),
	(1u << KOF_FMT_ELF) | (1u << KOF_FMT_PE),
	747
	/*
	 * THERE WAS A TERM HERE FOR PACKER DEPTH, AND IT WAS WRONG.
	 *
	 * 400 centinats per layer, so two layers scored 800 against a bar of
	 * 747 - a verdict out of packing alone, with no other evidence. What it
	 * actually caught, measured over the corpus: four malware files, and
	 * three clean ones. The three were bunzip2, kill and zipinfo wrapped in
	 * Ezuri, each scoring exactly 800 - the whole verdict being the term
	 * itself. "Nothing legitimate is wrapped twice" was the argument, and it
	 * is false: a packed bunzip2 is a packed bunzip2.
	 *
	 * The measured step is 0 to 1 layer, not 1 to 2: the corpus holds 979
	 * objects one layer deep and 7 at two. A term shaped to reward the
	 * second layer was reaching for a population that is not there.
	 *
	 * Depth is still REPORTED - kof_result.heur_depth, the d1/d2 an examiner
	 * prints - because where an object sat is worth knowing. It is not
	 * scored.
	 */
};

const struct kof_heur_model *kof_heur_default(void)
{
	return &default_model;
}

int kof_heur_score(const struct kof_heur_model *m,
		   const struct kof_heur_facts *f, int32_t *out,
		   const char **guess)
{
	int64_t s = 0;
	int32_t best = 0;
	uint32_t i;

	if (!m || !f || !out)
		return 0;
	if (guess)
		*guess = "Unknown";
	if (f->format >= 32 || !(m->formats & (1u << f->format)))
		return 0;               /* no model for this population */

	for (i = 0; i < m->n_anom; i++)
		if (m->anom[i].format == f->format &&
		    (f->anomalies & m->anom[i].mask)) {
			s += m->anom[i].centinats;
			/* The word comes from the trace that carried the most
			 * weight - the one a reader should look at first. */
			if (guess && m->anom[i].centinats > best) {
				best = m->anom[i].centinats;
				*guess = m->anom[i].guess;
			}
		}
	for (i = 0; i < m->n_flag; i++)
		if (f->flags & KOF_HEUR_FL(m->flag[i].fact)) {
			s += m->flag[i].centinats;
			if (guess && m->flag[i].centinats > best) {
				best = m->flag[i].centinats;
				*guess = m->flag[i].guess;
			}
		}

	if (s >  0x7fffffff) s =  0x7fffffff;
	if (s < -0x7fffffff) s = -0x7fffffff;
	*out = (int32_t)s;
	return 1;
}
