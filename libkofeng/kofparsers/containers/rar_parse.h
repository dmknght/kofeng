/*
 * rar_parse.h - the RAR collector.
 *
 * Same shape as every other collector: a sniff that needs no view buffer, a parse
 * that fills both the common context and the format view, and a parse that never
 * fails - hostile or truncated input yields what was recovered plus anomaly bits.
 *
 * RAR3 and RAR5 are both walked, and the two share nothing but a signature prefix -
 * RAR3 blocks are fixed width little endian fields, RAR5 blocks are variable length
 * integers - so there are two walks behind one entry point, and ctx->subtype says
 * which one ran. An archive whose entries are compressed by a method this build has
 * no decoder for is left with KOF_RAR_ANOM_UNSUPPORTED, so it is reported as a gap
 * rather than as an archive that turned out to be empty.
 */

#ifndef KOFENG_RAR_PARSE_H
#define KOFENG_RAR_PARSE_H

#include <kofmod/rar.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is a RAR.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_RAR. A non-zero return does not mean the archive is well formed - check
 * info->anomalies.
 */
int kof_rar_parse(kof_buf file, struct kof_rar_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like a RAR?
 *
 * "Rar!\x1a\x07" then a version byte: 0x00 for RAR3, 0x01 0x00 for RAR5. Both are
 * accepted here; which one it turned out to be is in info->rar_version.
 */
int kof_rar_sniff(kof_buf file);

const char *kof_rar_region_name(uint32_t bit);
const char *kof_rar_anomaly_name(unsigned index);

extern const uint32_t kof_rar_region_bits[];
#define KOF_RAR_REGION_COUNT 5u   /* asserted against the array in the .c */

#endif /* KOFENG_RAR_PARSE_H */
