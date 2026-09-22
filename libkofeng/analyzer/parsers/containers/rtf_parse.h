/*
 * rtf_parse.h - the RTF collector.
 *
 * Same shape as every other collector: a sniff that needs no view buffer, a parse
 * that fills both the common context and the format view, and a parse that never
 * fails - hostile or truncated input yields what was recovered plus anomaly bits.
 *
 * Unlike the others this one READS FORWARD through syntax rather than following
 * offsets, because RTF has no offsets. See rtf.h.
 */

#ifndef KOFENG_RTF_PARSE_H
#define KOFENG_RTF_PARSE_H

#include <kofmod/rtf.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is RTF.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_RTF. A non-zero return does not mean the document is well formed - check
 * info->anomalies.
 */
int kof_rtf_parse(kof_buf file, struct kof_rtf_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * "{\rt" and then a letter, which is as much as can be relied on.
 *
 * The specification says "{\rtf1" and real readers accept less: a version other
 * than 1, whitespace after the brace, and a truncated word. Matching only the
 * strict spelling would refuse files that Word opens, which is the wrong side to
 * err on for a scanner.
 */
int kof_rtf_sniff(kof_buf file);

const char *kof_rtf_region_name(uint32_t bit);
const char *kof_rtf_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define RTF_REGIONS(X)          \
	X(KOF_SCAN_RTF_BODY)      \
	X(KOF_SCAN_RTF_OBJDATA)   \
	X(KOF_SCAN_RTF_BINARY)    \
	X(KOF_SCAN_RTF_UNCLAIMED)

extern const uint32_t kof_rtf_region_bits[];
#define KOF_RTF_REGION_COUNT 4u   /* asserted against the array in the .c */

#endif /* KOFENG_RTF_PARSE_H */
