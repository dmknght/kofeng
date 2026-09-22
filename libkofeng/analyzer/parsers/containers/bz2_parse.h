/*
 * bz2_parse.h - bzip2 collector entry point.
 *
 * Same shape as the gzip collector and for the same reasons: a sniff that needs
 * no view buffer, a parse that fills both the common context and the format
 * view, and a parse that never fails - hostile or truncated input yields what
 * was recovered plus anomaly bits.
 *
 * The wrapper only. Nothing here decodes the stream: that is
 * extractor/decomp/bzip2.c, reached by an unpacker through the host, and it is
 * deliberately not reachable from a collector. Identifying an object must not
 * cost the decompression of it, and for this format that matters more than
 * most - a bzip2 block cannot be partly decoded, so the cheapest question
 * "what is inside" would cost a megabyte of work.
 */

#ifndef KOFENG_BZ2_PARSE_H
#define KOFENG_BZ2_PARSE_H

#include <kofmod/bz2.h>
#include <kofmod/kofsig.h>
#include "../../../kofcore/kofcore.h"

/*
 * Returns non-zero if the object is bzip2.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_BZIP2. A non-zero return does not mean the stream is well formed -
 * check info->anomalies. On a zero return info is zeroed and safe to read and
 * ctx->format is left for whoever identifies the object next.
 */
int kof_bz2_parse(kof_buf file, struct kof_bz2_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like bzip2?
 *
 * "BZh", a level digit, and the six byte marker of the first block behind it.
 * The header alone is four bytes of which three are letters, which is weak
 * enough to claim ordinary text - and the marker is the one thing in this
 * format that is byte aligned, so requiring it costs nothing and settles it.
 */
int kof_bz2_sniff(kof_buf file);

/* Names for the region and anomaly bits, for tools that describe a file to a
 * person. See kof_pe_region_name for why these live with the collector. */
const char *kof_bz2_region_name(uint32_t bit);
const char *kof_bz2_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it - see
 * GZIP_REGIONS for what a second hand copy of this cost. */
#define BZ2_REGIONS(X)          \
	X(KOF_SCAN_BZ2_HEADER)    \
	X(KOF_SCAN_BZ2_DATA)      \
	X(KOF_SCAN_BZ2_UNCLAIMED)

extern const uint32_t kof_bz2_region_bits[];
#define KOF_BZ2_REGION_COUNT 3u   /* asserted against the array in the .c */

#endif /* KOFENG_BZ2_PARSE_H */
