/*
 * kofheur.c - see kofheur.h.
 *
 * THE VALUES IN THIS FILE WERE MEASURED, AND THE MEASUREMENT IS WHY THEY LOOK
 * UNEVEN.
 *
 * Each is log(P(trace | malware) / P(trace | clean)) over 6523 malware ELF
 * objects and 13638 clean ones. The clean set was chosen adversarially: it holds
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
#include "../core/kofmod/kofsig.h"
#include "../core/kofmod/elf.h"
#include "../core/kofmod/pe.h"
#include "../core/kofmod/gzip.h"
#include "../core/kofmod/docole.h"
#include "../core/kofmod/zip.h"
#include "../core/kofmod/tar.h"
#include "../core/kofmod/sevenzip.h"
#include "../core/kofmod/rar.h"
#include "../core/kofmod/xz.h"
#include "../core/kofmod/rtf.h"
#include "../core/kofmod/pdf.h"

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
	case KOF_FMT_RTF:    return kof_rtf(ctx)->anomalies;
	case KOF_FMT_PDF:    return kof_pdf(ctx)->anomalies;
	default:             return 0;
	}
}

/*
 * ELF ONLY, AND THE MASK BELOW SAYS SO.
 *
 * These numbers came from an ELF population. A PE has a different anomaly
 * vocabulary and a different clean population; a doczip has fewer traces of this
 * kind at all, because a document container that is malformed is usually just a
 * document written by something old. Neither is covered, and the model reports
 * that rather than scoring them with borrowed numbers.
 */
#define CN(x) ((int32_t)((x) * 100))

static const struct kof_heur_anom_term default_anom[] = {
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
	{ KOF_HEUR_F_UNPACK_PARTIAL,  CN(3.24), "PackTamper" },
	/* --- what the database noticed without firing --------------------- */
	{ KOF_HEUR_F_MARKER_OUTSIDE,  CN(3.66), "StrayMarker"},
	{ KOF_HEUR_F_FAMILY_PARTIAL,  CN(0.84), "PartFamily" }
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
	1u << KOF_FMT_ELF,
	747,
	100                     /* no depth gain: see kof_heur_model.depth_gain_pct */
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

	/*
	 * Depth multiplies what was found INSIDE, which is the whole reason the
	 * depth is carried. One layer at 100% leaves it alone, which is what this
	 * build ships - the corpus had six objects two layers deep and that is
	 * not enough to justify a number.
	 */
	if (f->packer_depth && m->depth_gain_pct != 100u) {
		uint32_t d = f->packer_depth > 4u ? 4u : f->packer_depth;

		while (d--)
			s = s * (int64_t)m->depth_gain_pct / 100;
	}
	if (s >  0x7fffffff) s =  0x7fffffff;
	if (s < -0x7fffffff) s = -0x7fffffff;
	*out = (int32_t)s;
	return 1;
}
