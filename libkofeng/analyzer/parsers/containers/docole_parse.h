/*
 * docole_parse.h - the OLE document collector.
 *
 * Same shape as the ELF, PE and gzip collectors: a sniff that needs no view
 * buffer, a parse that fills both the common context and the format view, and a
 * parse that never fails - hostile or truncated input yields what was recovered
 * plus anomaly bits.
 *
 * The structure only. Nothing here joins a stream's sectors together or decodes a
 * VBA module: the first costs memory and is reached through kof_gather() from an
 * unpacker, and the second is a decompressor. Identifying an object must not cost
 * the reconstruction of it, or every file in a scan pays for the ones that turn out
 * to be documents.
 */

#ifndef KOFENG_DOCOLE_PARSE_H
#define KOFENG_DOCOLE_PARSE_H

#include <kofmod/docole.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is a compound file.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_DOCOLE. A non-zero return does not mean the file is well formed - check
 * info->anomalies. On a zero return info is zeroed and safe to read.
 */
int kof_docole_parse(kof_buf file, struct kof_docole_info *info,
		     struct kof_obj_ctx *ctx);

/*
 * Does this object look like a compound file?
 *
 * The eight byte signature alone. Unlike gzip there is no second field with a
 * single legal value to confirm it with - the version, the shifts and the byte
 * order are all checked by the parse and all recorded as anomalies rather than
 * used to reject, because a document with a wrong shift is still a document and
 * refusing it here would leave it scanned as an unidentified blob.
 */
int kof_docole_sniff(kof_buf file);

/* Names for the region and anomaly bits, for tools that describe a file to a
 * person. See kof_pe_region_name for why these live with the collector. */
const char *kof_docole_region_name(uint32_t bit);
const char *kof_docole_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define DOCOLE_REGIONS(X)                       \
	X(KOF_SCAN_DOCOLE_HEADERS)                \
	X(KOF_SCAN_DOCOLE_DIRECTORY)              \
	X(KOF_SCAN_DOCOLE_CONTENT_DATA)           \
	X(KOF_SCAN_DOCOLE_CONTENT_MACROS)         \
	X(KOF_SCAN_DOCOLE_CONTENT_METADATA)       \
	X(KOF_SCAN_DOCOLE_RESOURCES)              \
	X(KOF_SCAN_DOCOLE_UNCLAIMED)

extern const uint32_t kof_docole_region_bits[];
#define KOF_DOCOLE_REGION_COUNT 7u   /* asserted against the array in the .c */

#endif /* KOFENG_DOCOLE_PARSE_H */
