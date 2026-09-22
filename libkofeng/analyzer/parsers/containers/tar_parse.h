/*
 * tar_parse.h - the tar collector.
 *
 * Same shape as every other collector: a sniff that needs no view buffer, a parse
 * that fills both the common context and the format view, and a parse that never
 * fails - hostile or truncated input yields what was recovered plus anomaly bits.
 *
 * Unlike the other containers there is nothing here that a decoder would follow.
 * tar does not compress; the parse is the whole job.
 */

#ifndef KOFENG_TAR_PARSE_H
#define KOFENG_TAR_PARSE_H

#include <kofmod/tar.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is a tar.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_TAR. A non-zero return does not mean the archive is well formed - check
 * info->anomalies.
 */
int kof_tar_parse(kof_buf file, struct kof_tar_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like a tar?
 *
 * "ustar" at offset 257, which is the only thing in the format that identifies it -
 * a tar has no magic at offset zero and its first 100 bytes are a filename.
 *
 * That means the original V7 tar, which has no magic at all, is not recognised.
 * Deliberate: the alternative is to accept any file whose first block happens to
 * carry six plausible octal fields, and the cost of being wrong is claiming an
 * arbitrary file as an archive and reading its bytes as sizes. Measured over 28316
 * entries in this collection, every one carried the magic.
 */
int kof_tar_sniff(kof_buf file);

const char *kof_tar_region_name(uint32_t bit);
const char *kof_tar_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define TAR_REGIONS(X)          \
	X(KOF_SCAN_TAR_HEADERS)   \
	X(KOF_SCAN_TAR_DATA)      \
	X(KOF_SCAN_TAR_UNCLAIMED)

extern const uint32_t kof_tar_region_bits[];
#define KOF_TAR_REGION_COUNT 3u   /* asserted against the array in the .c */

#endif /* KOFENG_TAR_PARSE_H */
