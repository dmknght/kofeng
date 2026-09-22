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
/*
 * THE REGION NAME LIST, where everything that needs it can see it.
 *
 * It lived in the .c, so ksigbuilder - which has to turn the name a signature
 * writes back into a bit - kept a hand copy in rgn_names[] with, in its own
 * words, no build-time check that it had not fallen behind. Now there is one
 * list, and kof_pdf_region_bits[], kof_pdf_region_name() and ksigbuilder's
 * table are all it.
 *
 * ONE ENTRY PER ARGUMENT, because every format's list is called with the same
 * one-argument macro from the same table in ksigbuilder. So this is the one
 * list that is not generated from KOF_PDF_CLASSES, and pdf_parse.c asserts the
 * two name the same bits - by their union and by their count, which together
 * leave no way to add a region to one and not the other.
 *
 * THE ORDER IS WHAT A READER SEES: structure, then content, then resources,
 * then the passengers, then what nothing claimed. kofexamine and kofviewer
 * walk this to print a per-region byte count, so it reads top to bottom like
 * the document does.
 */
#define PDF_REGIONS(X)                 \
	X(KOF_SCAN_PDF_HEADERS)          \
	X(KOF_SCAN_PDF_XREF)             \
	X(KOF_SCAN_PDF_OBJ_TABLE)        \
	X(KOF_SCAN_PDF_CONTENT)          \
	X(KOF_SCAN_PDF_CONTENT_SCRIPT)   \
	X(KOF_SCAN_PDF_CONTENT_METADATA) \
	X(KOF_SCAN_PDF_RESOURCE_IMAGE)   \
	X(KOF_SCAN_PDF_RESOURCE_FONT)    \
	X(KOF_SCAN_EMBEDDED)             \
	X(KOF_SCAN_PDF_UNCLAIMED)

extern const uint32_t kof_pdf_region_bits[];

#endif /* KOFENG_PDF_PARSE_H */
