#ifndef KOFENG_DATABASES_SYNDSRC_H
#define KOFENG_DATABASES_SYNDSRC_H

/*
 * syndsrc.h - one verified sample, read from its source.
 *
 * A SYNDROME IS EVIDENCE, NOT A RULE: the diseases that fired on a sample
 * somebody verified, and the types that sample was - see
 * detectors/pathogen/syndromes/kofsyndrome.h for what is done with them. It is written as
 * the other bases are, a source file with one declaration to a line between
 * paragraphs of comment, because the comments are where the sample is named
 * (which file, how it was checked):
 *
 *     KOF_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);
 *     KOF_SYNDROME_TYPE(KOF_MALTYPE_EXPLOIT);        // a bot that carries an exploit
 *     KOF_SYNDROME_HAS("cnc/recv-syscall");
 *     KOF_SYNDROME_HAS("flood-network/raw-header");
 *
 * More than one type is a sample that was both, which is what a single-label
 * name hides: a botnet with a root exploit is named by whichever signature hit.
 *
 * ONE READER FOR THE BUILD AND THE TOOLS, as diagsrc.h is for a diagnose.
 */

#include <stddef.h>
#include <stdint.h>
#include "diagsrc.h"
#include <kofmod/kofpathogen.h>

/* A bound on COST: no sample is described by this many behaviours. A source
 * over it is an error, not truncated. */
#define KOF_SSRC_MAX_DIS 64u

struct kof_ssrc {
	uint32_t type_mask;     /* 1u << kof_maltype, for each KOF_SYNDROME_TYPE */
	uint32_t n_dis;
	char     dis[KOF_SSRC_MAX_DIS][KOF_DIAG_DISEASE_LEN + 1u];
};

/* Returns the number of errors; `p` is only meaningful at 0. */
int kof_ssrc_parse(const char *text, size_t n, struct kof_ssrc *p,
		   const struct kof_dsrc_report *r);

#endif /* KOFENG_DATABASES_SYNDSRC_H */
