/* SPDX-License-Identifier: Apache-2.0 */
/*
 * proc_parse.h - one collected process snapshot, presented as a scannable
 * object.
 *
 * IT NEVER SNIFFS, for the reason amsi_parse.h gives: the record is integers
 * and strings with no structure a sniff could trust, so accepting a buffer on
 * the strength of plausible-looking fields would claim other people's objects.
 * It is reached only through kof_parser_of(KOF_EVT_PROC), by a caller that
 * built the record and therefore knows what it is holding.
 *
 * IT STILL VALIDATES. Being told is not the same as being right, and a record
 * whose offsets point outside itself would otherwise resolve regions to ranges
 * outside the buffer.
 */
#ifndef KOF_PROC_PARSE_H
#define KOF_PROC_PARSE_H

#include "../../core/kofcore.h"
#include "../../core/kofmod/kofsig.h"
#include "../../core/kofmod/proc.h"

extern const uint32_t kof_proc_regions[1];

int         kof_proc_sniff(kof_buf b);
int         kof_proc_parse(kof_buf b, void *view, struct kof_obj_ctx *ctx);
const char *kof_proc_region_name(uint32_t bit);
const char *kof_proc_anomaly_name(unsigned index);
uint64_t    kof_proc_anomalies(const void *view);

#endif /* KOF_PROC_PARSE_H */
