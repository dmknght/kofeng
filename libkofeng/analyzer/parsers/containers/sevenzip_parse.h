/*
 * sevenzip_parse.h - the 7z collector.
 *
 * Same shape as the others: a sniff that needs no view buffer, and a parse that
 * never fails - hostile or truncated input yields what was recovered plus anomaly
 * bits.
 *
 * What is different is how little it can establish. A 7z compresses its own file
 * list, so this describes the container and says whether the list is readable at
 * all; it does not enumerate anything. See sevenzip.h for why that is a statement
 * about the format rather than a gap in this file.
 */

#ifndef KOFENG_SEVENZIP_PARSE_H
#define KOFENG_SEVENZIP_PARSE_H

#include <kofmod/sevenzip.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

int kof_7z_parse(kof_buf file, struct kof_7z_info *info, struct kof_obj_ctx *ctx);

/* The six byte magic. Unlike a tar there is nothing else to confirm it with at
 * offset zero, and unlike a zip there is no second copy of the structure to check
 * against - so the magic is the whole test and the parse records what it finds. */
int kof_7z_sniff(kof_buf file);

const char *kof_7z_region_name(uint32_t bit);
const char *kof_7z_anomaly_name(unsigned index);
const char *kof_7z_header_kind_name(uint32_t kind);

/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define SZ_REGIONS(X)          \
	X(KOF_SCAN_7Z_HEADERS)   \
	X(KOF_SCAN_7Z_PACKED)    \
	X(KOF_SCAN_7Z_UNCLAIMED)

extern const uint32_t kof_7z_region_bits[];
#define KOF_7Z_REGION_COUNT 3u   /* asserted against the array in the .c */

#endif /* KOFENG_SEVENZIP_PARSE_H */
