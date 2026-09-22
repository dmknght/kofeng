/*
 * zip_parse.h - the zip collector, for both formats that share the view.
 *
 * Same shape as every other collector: a sniff that needs no view buffer, a parse
 * that fills both the common context and the format view, and a parse that never
 * fails - hostile or truncated input yields what was recovered plus anomaly bits.
 *
 * The structure only. Nothing here inflates an entry: that costs budget and is an
 * unpacker's business, reached through the host. What this produces for free is
 * every entry's name, where its bytes are, and whether they can be searched where
 * they lie - which on a document is most of the answer.
 */

#ifndef KOFENG_ZIP_PARSE_H
#define KOFENG_ZIP_PARSE_H

#include <kofmod/zip.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is a zip.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_ZIP or KOF_FMT_DOCZIP - the parse decides which from the entry names,
 * which is why the caller cannot know it in advance and must not assume it.
 */
int kof_zip_parse(kof_buf file, struct kof_zip_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like a zip?
 *
 * A local header or an end record at offset zero, and nothing else. In particular
 * this does NOT search the tail for an end record, which would find the zip inside
 * every self-extracting archive - and finding it here would be the wrong place. An
 * SFX is an executable that happens to carry an archive: it should be identified as
 * the executable it is, parsed as one, and the archive reached as its overlay. One
 * object, one format, and the layering does the rest.
 */
int kof_zip_sniff(kof_buf file);

const char *kof_zip_region_name(uint32_t bit);
const char *kof_zip_anomaly_name(unsigned index);
const char *kof_zip_kind_name(uint32_t kind);

/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define ZIP_REGIONS(X)            \
	X(KOF_SCAN_ZIP_HEADERS)     \
	X(KOF_SCAN_ZIP_NAMES)       \
	X(KOF_SCAN_ZIP_STORED)      \
	X(KOF_SCAN_ZIP_PACKED)      \
	X(KOF_SCAN_ZIP_UNCLAIMED)

extern const uint32_t kof_zip_region_bits[];
#define KOF_ZIP_REGION_COUNT 5u   /* asserted against the array in the .c */

#endif /* KOFENG_ZIP_PARSE_H */
