/*
 * arm32_private.h - what only the table builders and the unit test of the ARM
 * state and Thumb state decoders need: the canonical rows and the statistics of
 * the index build. What the inline decode reads is arm32_table.h, which arm32.h and
 * thumb.h include; this header is not part of the surface.
 */
#ifndef KGENOME_GENOTYPE_ARM32_PRIVATE_H
#define KGENOME_GENOTYPE_ARM32_PRIVATE_H

#include "arm32_table.h"

/* THE CANONICAL ROWS: hand-written, in priority order. */
extern const struct kgenome_arm32_row kgenome_arm32_src_cond[], kgenome_arm32_src_unc[];
extern const unsigned kgenome_arm32_src_cond_n, kgenome_arm32_src_unc_n;
extern const struct kgenome_arm32_row kgenome_thumb_src_narrow[], kgenome_thumb_src_wide[];
extern const unsigned kgenome_thumb_src_narrow_n, kgenome_thumb_src_wide_n;

/* What the builders found, for the unit test: rows no key reaches (shadowed by an
 * earlier row: a mistake in the order), and the room used in the list pools. */
struct kgenome_arm32_stats {
	unsigned shadowed_arm32, shadowed_thumb;
	unsigned lists_arm32, lists_thumb;      /* rows used in the pools */
	unsigned cap_arm32, cap_thumb;          /* and the pools' size */
};
void kgenome_arm32_stats(struct kgenome_arm32_stats *out);

#endif /* KGENOME_GENOTYPE_ARM32_PRIVATE_H */
