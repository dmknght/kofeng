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
	uint64_t obj_off;   /* where the submitted content starts */
	uint64_t obj_len;   /* and how much of it there is */
	uint64_t size;      /* the object as a whole */
};

int  kof_amsi_sniff(kof_buf b);
int  kof_amsi_parse(kof_buf b, void *view, struct kof_obj_ctx *ctx);

const char *kof_amsi_region_name(uint32_t bit);
const char *kof_amsi_anomaly_name(unsigned index);
uint64_t    kof_amsi_anomalies(const void *view);

extern const uint32_t kof_amsi_regions[2];

/*
 * WHICH SIGNATURE TARGET A VERB ROUTES TO, or KOF_FMT_UNKNOWN.
 *
 * The verb is the byte a client filters records on: it decides which rules are
 * even offered a record. This is that decision, in one place.
 *
 * HERE AND NOT IN kofevt.h, which is deliberately standalone - it is compiled
 * into the Windows collector, which must not start pulling in the engine's
 * headers. The mapping is about SIGNATURE TARGETS, so it belongs on the side
 * that knows what a target is.
 */
uint8_t kof_evt_target_of(uint16_t verb);

#endif /* KOF_AMSI_PARSE_H */
