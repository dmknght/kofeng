/* SPDX-License-Identifier: Apache-2.0 */
/*
 * amsi_parse.h - one collected AMSI event, presented as a scannable object.
 *
 * WHY THIS PARSER NEVER SNIFFS.
 *
 * Every other row in kofformat.c recognises its format from the bytes. A
 * struct kof_evt has no magic - it is a header of integers and a text arena -
 * so a sniff would have to accept a buffer on the strength of fields that look
 * plausible, and plausible is exactly what arbitrary data is. It would claim
 * other people's objects as events.
 *
 * It does not need to. An event is DECLARED: the client that read the record
 * off the channel knows what it holds, and so does the viewer that opened the
 * log. So the sniff refuses everything and the row is reached only through
 * kof_parser_of(KOF_FMT_AMSI) - by a caller that already knows.
 *
 * The parse still VALIDATES. Being told is not the same as being right, and a
 * record whose offsets point outside itself would otherwise resolve to ranges
 * outside the buffer.
 */
#ifndef KOF_AMSI_PARSE_H
#define KOF_AMSI_PARSE_H

#include "../../core/kofcore.h"
#include "../../core/kofmod/kofsig.h"
#include "../../core/kofmod/amsi.h"

/*
 * What the parse worked out, which is only where the two regions are.
 *
 * A view exists per format because most parsers have tables to keep. This one
 * has two offsets; it is still a view because the region resolver is handed
 * nothing else, and recomputing them from the record on every resolve would be
 * reading the same four fields to reach the same two answers.
 */
struct kof_amsi_view {
	/*
	 * WHERE THE SUBMITTED CONTENT IS - FILLED BY THE CALLER, BEFORE THE
	 * PARSE.
	 *
	 * This is input, not output, and that is the whole reason the engine
	 * can host this parser at all. The offsets live in a collected-event
	 * record, and that record's layout belongs to libkoforbit - which sits
	 * OUTSIDE the engine and must stay there: orbit may know the engine's
	 * types, the engine must never know orbit's. Reading the record here
	 * would have turned that arrow round, and did until it was noticed.
	 *
	 * The caller already has both numbers. It is the client that took the
	 * record off a channel, or the viewer that opened a log; it declared
	 * this format in the first place, so it is not being asked for anything
	 * it had to work out.
	 *
	 * The parse VALIDATES them against the buffer. Being told is not being
	 * right, and an offset past the end would otherwise resolve to a range
	 * that is not there.
	 */
	uint64_t obj_off;
	uint64_t obj_len;

	uint64_t size;      /* the object as a whole; filled by the parse */
};

int  kof_amsi_sniff(kof_buf b);
int  kof_amsi_parse(kof_buf b, void *view, struct kof_obj_ctx *ctx);

const char *kof_amsi_region_name(uint32_t bit);
const char *kof_amsi_anomaly_name(unsigned index);
uint64_t    kof_amsi_anomalies(const void *view);

extern const uint32_t kof_amsi_regions[2];



#endif /* KOF_AMSI_PARSE_H */
