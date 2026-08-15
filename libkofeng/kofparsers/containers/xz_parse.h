/*
 * xz_parse.h - the xz collector.
 *
 * Same shape as every other collector: a sniff that needs no view buffer, a parse
 * that fills both the common context and the format view, and a parse that never
 * fails - hostile or truncated input yields what was recovered plus anomaly bits.
 *
 * Unlike the other containers this one reads BACKWARDS first: the footer says
 * where the index is and the index says where the blocks are, because a block
 * header is allowed to omit its own sizes. See xz.h.
 */

#ifndef KOFENG_XZ_PARSE_H
#define KOFENG_XZ_PARSE_H

#include <kofmod/xz.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is an xz stream.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_XZ. A non-zero return does not mean the stream is well formed - check
 * info->anomalies.
 */
int kof_xz_parse(kof_buf file, struct kof_xz_info *info, struct kof_obj_ctx *ctx);

/* "\xfd7zXZ\0", which is the whole of the identification: six bytes chosen so that
 * no text file and no other container begins with them. */
int kof_xz_sniff(kof_buf file);

const char *kof_xz_region_name(uint32_t bit);
const char *kof_xz_anomaly_name(unsigned index);

extern const uint32_t kof_xz_region_bits[];
#define KOF_XZ_REGION_COUNT 3u   /* asserted against the array in the .c */

#endif /* KOFENG_XZ_PARSE_H */
