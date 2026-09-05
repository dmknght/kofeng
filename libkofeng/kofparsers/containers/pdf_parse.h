/*
 * pdf_parse.h - locate a PDF's objects and classify its bytes.
 *
 * See kofmod/pdf.h for what the regions mean and why the objects are found by
 * scanning rather than by trusting the cross reference table.
 */

#ifndef KOFENG_PDF_PARSE_H
#define KOFENG_PDF_PARSE_H

#include <kofmod/pdf.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

int kof_pdf_parse(kof_buf file, struct kof_pdf_info *info,
		  struct kof_obj_ctx *ctx);

int kof_pdf_sniff(kof_buf file);

const char *kof_pdf_region_name(uint32_t bit);
const char *kof_pdf_anomaly_name(unsigned index);
/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define PDF_REGIONS(X)                 \
	X(KOF_SCAN_PDF_HEADER)           \
	X(KOF_SCAN_PDF_OBJECTS)          \
	X(KOF_SCAN_PDF_STREAM_PLAIN)     \
	X(KOF_SCAN_PDF_STREAM_PACKED)    \
	X(KOF_SCAN_PDF_UNCLAIMED)

extern const uint32_t kof_pdf_region_bits[];

#endif /* KOFENG_PDF_PARSE_H */
