/*
 * lha_parse.h - LHA/LZH collector entry point.
 *
 * Same shape as the other container collectors: a sniff that needs no view
 * buffer, a parse that fills both the common context and the format view, and
 * a parse that never fails - hostile or truncated input yields what was
 * recovered plus anomaly bits.
 *
 * The structure only; nothing here decodes an entry. See lha.h.
 */

#ifndef KOFENG_LHA_PARSE_H
#define KOFENG_LHA_PARSE_H

#include <kofmod/lha.h>
#include <kofmod/kofsig.h>
#include "../../../kofcore/kofcore.h"

/*
 * Returns non-zero if the object is an LHA archive.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_LHA. A non-zero return does not mean the archive is well formed -
 * check info->anomalies.
 */
int kof_lha_parse(kof_buf file, struct kof_lha_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * THE VIEW'S TABLE IS THE FILE'S SIZE, so a view owns memory - zip_parse.h has the contract, which
 * is the same here: `info->mem.room` is the caller's before the parse, `info->mem.held` is what the
 * table holds after it, and kof_lha_release gives it back. A table that cannot grow is not a failed
 * parse: the rows read so far are whole and KOF_LHA_ANOM_ENTRIES_FULL says the rest was not.
 */
void kof_lha_release(struct kof_lha_info *info);

/* The host's handles on the view - see struct kof_view_ops in kofformat.h. */
struct kof_view_mem *kof_lha_mem(void *view);
const void *kof_lha_row(void *view, uint32_t *cursor);

/*
 * Does this object look like an LHA archive?
 *
 * THE MAGIC IS NOT AT OFFSET ZERO, which is the whole difficulty with this
 * format: the five bytes "-lh5-" sit at offset two, behind a size and a
 * checksum that can be anything. Five bytes with fixed ends and one digit is
 * weak on its own, so the header LEVEL at offset twenty has to be one of the
 * three that exist - which is what stops this claiming arbitrary data that
 * happens to contain "-lh" three bytes in.
 */
int kof_lha_sniff(kof_buf file);

/* Names for the region and anomaly bits - see kof_pe_region_name. */
const char *kof_lha_region_name(uint32_t bit);
const char *kof_lha_anomaly_name(unsigned index);

#define LHA_REGIONS(X)            \
	X(KOF_SCAN_LHA_HEADERS)     \
	X(KOF_SCAN_LHA_NAMES)       \
	X(KOF_SCAN_LHA_DATA)        \
	X(KOF_SCAN_LHA_UNCLAIMED)

extern const uint32_t kof_lha_region_bits[];
#define KOF_LHA_REGION_COUNT 4u   /* asserted against the array in the .c */

#endif /* KOFENG_LHA_PARSE_H */
