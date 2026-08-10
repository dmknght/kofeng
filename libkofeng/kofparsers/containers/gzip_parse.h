/*
 * gzip_parse.h - gzip collector entry point.
 *
 * Same shape as the ELF and PE collectors and for the same reasons: a sniff that
 * needs no view buffer, a parse that fills both the common context and the format
 * view, and a parse that never fails - hostile or truncated input yields what was
 * recovered plus anomaly bits.
 *
 * The wrapper only. Nothing here decodes the stream: that is kofdecomp/inflate.c,
 * reached by an unpacker through the host, and it is deliberately not reachable
 * from a collector. Identifying an object must not cost the decompression of it,
 * or every file in a scan pays a decoder to find out what it is.
 */

#ifndef KOFENG_GZIP_PARSE_H
#define KOFENG_GZIP_PARSE_H

#include <kofmod/gzip.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is gzip.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_GZIP. A non-zero return does not mean the wrapper is well formed -
 * check info->anomalies. On a zero return info is zeroed and safe to read and
 * ctx->format is left for whoever identifies the object next.
 */
int kof_gzip_parse(kof_buf file, struct kof_gzip_info *info,
		   struct kof_obj_ctx *ctx);

/*
 * Does this object look like gzip?
 *
 * The two magic bytes and the compression method, which is three bytes of the ten
 * byte header. Magic alone would claim any file starting 1f 8b, and CM is the only
 * other field with one legal value - everything else in a gzip header is free.
 *
 * Not enough on its own to be sure, and it does not need to be: a false claim
 * costs a parse that finds nothing and sets anomalies, and the object is still
 * scanned by every module whose target covers it.
 */
int kof_gzip_sniff(kof_buf file);

/* Names for the region and anomaly bits, for tools that describe a file to a
 * person. See kof_pe_region_name for why these live with the collector. */
const char *kof_gzip_region_name(uint32_t bit);
const char *kof_gzip_anomaly_name(unsigned index);

extern const uint32_t kof_gzip_region_bits[];
#define KOF_GZIP_REGION_COUNT 5u   /* asserted against the array in the .c */

#endif /* KOFENG_GZIP_PARSE_H */
