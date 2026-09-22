/*
 * proc_parse.h - one collected process snapshot, presented as a scannable
 * object.
 *
 * WHAT THIS PARSES: a struct kof_proc_rec. Not memory, not /proc, not a live
 * process - the RECORD, which is a fixed head of integers (pid, ppid,
 * start_time, the descriptor counts, the flags, the per-platform pair) and an
 * arena of strings behind it (exe, comm, command line, environment, connection
 * list, the three standard descriptor links). Bytes in, a kof_proc_info view
 * out, plus the extents of MEM_CMDLINE, MEM_ENV and MEM_NET so a signature
 * scoped to one of them searches those bytes and no others.
 *
 * NOT IN events/, which is where it used to sit beside the AMSI parser. The two
 * look alike - both take a record somebody else built, neither sniffs - and
 * they are not the same kind of thing. An AMSI record is an EVENT: something
 * happened, a callback fired, the bytes exist because of it. A process record
 * is what a SCAN asked for: nothing happened, somebody pointed at a pid, and
 * the walk read /proc to answer. One is real time and one is not, and filing
 * this under events said the wrong thing about when it runs and why.
 *
 * IT IS A PARSER AND SO IT IS IN THE ENGINE, which is the other half of the
 * question. Three steps, three places:
 *
 *   libkofantarc (or libkofgrille)  reads /proc, fills struct kofa_proc
 *   libkoforbit/kofproc             normalises it into the record's bytes
 *   THIS                            reads those bytes back as a scannable view
 *
 * The normalising is already in orbit; this is the step after it, and it is
 * the same shape as elf_parse and zip_parse - which is why it lives beside
 * them. Putting it in the collector would make libkofeng depend on a platform,
 * and a record that arrived off a channel or out of a recorded log - neither of
 * which involves a collector at all - would have no parser.
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

extern const uint32_t kof_proc_regions[3];

int         kof_proc_sniff(kof_buf b);
int         kof_proc_parse(kof_buf b, void *view, struct kof_obj_ctx *ctx);
const char *kof_proc_region_name(uint32_t bit);
const char *kof_proc_anomaly_name(unsigned index);
uint64_t    kof_proc_anomalies(const void *view);

#endif /* KOF_PROC_PARSE_H */
