/*
 * chm_parse.h - CHM collector entry point.
 *
 * Same shape as the other container collectors and for the same reasons: a
 * sniff that needs no view buffer, a parse that fills both the common context
 * and the format view, and a parse that never fails - hostile or truncated
 * input yields what was recovered plus anomaly bits.
 *
 * THE STRUCTURE ONLY, AND THAT IS NOT THE SAME AS "the content is out of
 * reach" - which is what this comment used to say, from when it was true.
 * Nothing in this file decodes LZX. It locates: an entry in the compressed
 * section becomes a scattered child carrying the intervals it spans, and
 * bases/decomp/chm.c decodes those. Pointing at bytes and decoding them are
 * different operations and the host only does the first, the same split a
 * cabinet's coded folders use.
 *
 * Measured over the 25 CHMs on a stock Windows install: every entry of every
 * one of them openable, none unreachable. What is still not reached is named
 * in chm.h and counted in n_unreachable.
 */

#ifndef KOFENG_CHM_PARSE_H
#define KOFENG_CHM_PARSE_H

#include <kofmod/chm.h>
#include <kofmod/kofsig.h>
#include "../../../kofcore/kofcore.h"

/*
 * Returns non-zero if the object is a CHM.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_CHM. A non-zero return does not mean the file is well formed - check
 * info->anomalies. On a zero return info is zeroed and safe to read and
 * ctx->format is left for whoever identifies the object next.
 */
int kof_chm_parse(kof_buf file, struct kof_chm_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like a CHM?
 *
 * "ITSF" and a version this build will walk. Four bytes of magic with a
 * version behind them is what every other container here is recognised by, and
 * it is enough: the cost of a false claim is a parse that finds nothing and
 * sets anomalies.
 */
int kof_chm_sniff(kof_buf file);

/* Names for the region and anomaly bits, for tools that describe a file to a
 * person. See kof_pe_region_name for why these live with the collector. */
const char *kof_chm_region_name(uint32_t bit);
const char *kof_chm_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it - see
 * GZIP_REGIONS for what a second hand copy of this cost. */
#define CHM_REGIONS(X)            \
	X(KOF_SCAN_CHM_HEADERS)     \
	X(KOF_SCAN_CHM_DIRECTORY)   \
	X(KOF_SCAN_CHM_CONTENT)     \
	X(KOF_SCAN_CHM_UNCLAIMED)

extern const uint32_t kof_chm_region_bits[];
#define KOF_CHM_REGION_COUNT 4u   /* asserted against the array in the .c */

#endif /* KOFENG_CHM_PARSE_H */
