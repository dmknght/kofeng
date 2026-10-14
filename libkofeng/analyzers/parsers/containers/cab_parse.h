/*
 * cab_parse.h - CAB collector entry point.
 *
 * Same shape as the other container collectors and for the same reasons: a
 * sniff that needs no view buffer, a parse that fills both the common context
 * and the format view, and a parse that never fails - hostile or truncated
 * input yields what was recovered plus anomaly bits.
 *
 * The structure only. No folder is decoded here: what a folder is coded with
 * and why this build leaves it alone is written down in cab.h, where a rule
 * author can read it.
 */

#ifndef KOFENG_CAB_PARSE_H
#define KOFENG_CAB_PARSE_H

#include <kofmod/cab.h>
#include <kofmod/kofsig.h>
#include "../../../kofcore/kofcore.h"

/*
 * Returns non-zero if the object is a cabinet.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_CAB. A non-zero return does not mean the cabinet is well formed -
 * check info->anomalies. On a zero return info is zeroed and safe to read and
 * ctx->format is left for whoever identifies the object next.
 */
int kof_cab_parse(kof_buf file, struct kof_cab_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * THE VIEW'S TABLES ARE THE FILE'S SIZE, so a view owns memory - zip_parse.h has the contract, which
 * is the same here: `info->mem.room` is the caller's before the parse, `info->mem.held` is what the
 * tables hold after it, and kof_cab_release gives it all back. A table that cannot grow is not a
 * failed parse: the rows read so far are whole and KOF_CAB_ANOM_FILES_FULL says the rest was not.
 */
void kof_cab_release(struct kof_cab_info *info);

/* The host's handles on the view - see struct kof_view_ops in kofformat.h. */
struct kof_view_mem *kof_cab_mem(void *view);
const void *kof_cab_row(void *view, uint32_t *cursor);

/*
 * Does this object look like a cabinet?
 *
 * "MSCF" and the four reserved bytes behind it, which the format says are
 * zero. Four bytes of magic is what every container here is recognised by; the
 * reserved word is free and costs nothing, and it is what separates a cabinet
 * from a file that happens to begin with those letters.
 */
int kof_cab_sniff(kof_buf file);

/* Names for the region and anomaly bits, for tools that describe a file to a
 * person. See kof_pe_region_name for why these live with the collector. */
const char *kof_cab_region_name(uint32_t bit);
const char *kof_cab_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it - see
 * GZIP_REGIONS for what a second hand copy of this cost. */
#define CAB_REGIONS(X)            \
	X(KOF_SCAN_CAB_HEADERS)     \
	X(KOF_SCAN_CAB_FOLDERS)     \
	X(KOF_SCAN_CAB_NAMES)       \
	X(KOF_SCAN_CAB_DATA)        \
	X(KOF_SCAN_CAB_UNCLAIMED)

extern const uint32_t kof_cab_region_bits[];
#define KOF_CAB_REGION_COUNT 5u   /* asserted against the array in the .c */

#endif /* KOFENG_CAB_PARSE_H */
