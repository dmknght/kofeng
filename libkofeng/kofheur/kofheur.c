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

/*
 * IS THIS FILE NOTHING BUT CODE?
 *
 * See the note in the header for what the shape is and why a toolchain cannot
 * reach it. What follows is how it was measured, because the value in the table
 * below is only worth what the measurement is.
 *
 *   0 of 3252   x86-64 ELF files under /usr/{bin,sbin,lib,libexec}. Not one of
 *               them reaches the shape, and the smallest is 1192 bytes.
 *   0 of 1000   CLEAN binaries packed with upx, ezuri, pakkero, midgetpack and
 *               ward, 200 each. This is the adversarial half: a packed clean
 *               binary is the thing most likely to look hand-built, and none of
 *               the five packers produces a single-segment file - they carry
 *               three, six or seven program headers.
 *  18 of 4398   malware ELF objects. 7 of the 18 the signature database already
 *               names; the other 11 it misses, and they are what this term is
 *               for: two encoder-wrapped meterpreter stagers, eight small
 *               droppers, and one 1266-byte Mirai loader.
 *   7 of 7      the msfvenom samples on hand, including the 618-byte one that a
 *               size bound of 500 would have missed. SIZE IS NOT THE
 *               DISCRIMINATOR and was tried as one: the largest object with the
 *               shape is 1266 bytes and the smallest clean ELF is 1192, so the
 *               two populations overlap on size and separate on structure.
 *
 * WHY THE VALUE IS NOT THE MEASURED RATIO, AND THAT IS SAID PLAINLY.
 *
 * The likelihood ratio these counts support is ln((18.5/4399)/(0.5/4253)) = 3.58
 * nats, and the ceiling on it is the size of the clean corpus rather than the
 * strength of the trace: for the ratio to reach the bar on its own the clean
 * side would have to be measured at better than one in twenty-seven thousand,
 * and 4252 objects cannot say that.
 *
 * The value shipped is 4.72 nats. It is chosen, not measured, and it is chosen
 * so that the shape - together with the missing section table it NECESSARILY
 * implies, worth 2.75 - lands exactly on the bar. The consequence of the choice
 * is what was measured: zero false positives in the 4252 clean objects above,
 * and eleven malware objects reported that the database does not name. Lower it
 * to 358 and the term still contributes; it just stops being sufficient by
 * itself.
 */
int kof_heur_code_blob(const struct kof_obj_ctx *ctx)
{
	const struct kof_elf_info *e;
	const struct kof_elf_seg *x = NULL;
	uint32_t i, loads = 0;

	if (!ctx || !ctx->file_header || ctx->format != KOF_FMT_ELF)
		return 0;
	e = kof_elf(ctx);
	if (!e || !e->valid)
		return 0;
	/* No section table at all, and one program header: the two numbers a
	 * template has because it was written by hand. */
	if (e->shoff != 0 || e->phnum != 1)
		return 0;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		if (e->seg[i].type != 1u)               /* PT_LOAD */
			continue;
		loads++;
		if (e->seg[i].perm & KOF_PERM_X)
			x = &e->seg[i];
	}
	if (loads != 1 || !x)
		return 0;
	/*
	 * The segment IS the file: it starts at zero and its file image is at
	 * least as long as the object. Checked rather than assumed, because a
	 * single segment that maps only part of the file leaves the rest
	 * unaccounted for and that is a different object.
	 */
	if (x->file_off != 0 || x->file_size < ctx->obj_size)
		return 0;
	return e->entry_addr >= x->mem_addr &&
	       e->entry_addr <  x->mem_addr + x->mem_size;
}

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
	/* --- what the file is, rather than how it was reached ------------ */
	/* See kof_heur_code_blob() for the measurement AND for why this one
	 * number in the table is chosen rather than measured. */
	{ KOF_HEUR_F_CODE_BLOB,       CN(4.72), "Shellcode"  }
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
	1u << KOF_FMT_ELF,
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
