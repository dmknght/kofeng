/*
 * arj_parse.h - ARJ collector entry point.
 *
 * Same shape as the other container collectors: a sniff that needs no view
 * buffer, a parse that fills both the common context and the format view, and
 * a parse that never fails. The structure only; nothing here decodes. See
 * arj.h.
 */

#ifndef KOFENG_ARJ_PARSE_H
#define KOFENG_ARJ_PARSE_H

#include <kofmod/arj.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is an ARJ archive.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_ARJ. A non-zero return does not mean the archive is well formed -
 * check info->anomalies.
 */
int kof_arj_parse(kof_buf file, struct kof_arj_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like an ARJ archive?
 *
 * TWO BYTES OF MAGIC IS NOT ENOUGH ON ITS OWN - 0x60 0xEA occurs in ordinary
 * binaries often enough to matter - so this also requires the basic header
 * length behind it to be one the format permits and the first header's own
 * size byte to be sane. That is three fields, which is what separates an
 * archive from a coincidence.
 */
int kof_arj_sniff(kof_buf file);

/* Names for the region and anomaly bits - see kof_pe_region_name. */
const char *kof_arj_region_name(uint32_t bit);
const char *kof_arj_anomaly_name(unsigned index);

#define ARJ_REGIONS(X)            \
	X(KOF_SCAN_ARJ_HEADERS)     \
	X(KOF_SCAN_ARJ_NAMES)       \
	X(KOF_SCAN_ARJ_DATA)        \
	X(KOF_SCAN_ARJ_UNCLAIMED)

extern const uint32_t kof_arj_region_bits[];
#define KOF_ARJ_REGION_COUNT 4u   /* asserted against the array in the .c */

#endif /* KOFENG_ARJ_PARSE_H */
