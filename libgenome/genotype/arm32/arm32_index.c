/*
 * arm32_index.c - the statistics of the first-level index of the ARM state and Thumb
 * state decoders. The index itself is const data, arm32_index_tab.c, written from the
 * hand-written rows (arm32_rows.c, thumb_rows.c) by tools/genotype/arm_index_gen.c;
 * see arm32_table.h for what it is. tests/lib/genome/arm_index.c checks the checked-in
 * tables against the rows.
 */
#include "arm32_private.h"

void kgenome_arm32_stats(struct kgenome_arm32_stats *out)
{
	*out = kgenome_arm32_index_stats;
}
