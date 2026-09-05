/* SPDX-License-Identifier: Apache-2.0 */
/*
 * WHICH PARSERS EXIST, AND IN WHAT ORDER THEY GET ASKED.
 *
 * One list, because the answer to "what is this object" must not depend on who
 * asked. The scanner and the examine tools both walk it; before this file each
 * kept its own copy, and the copies had already drifted - a parse that failed
 * mid-way made the scanner try the next format and made the viewer give up.
 *
 * What this file does NOT decide is that policy. It hands out the list and the
 * three facts about each entry that everyone needs - which format, how big its
 * view is, how to sniff and how to parse - and each caller keeps its own rules
 * about allocation lifetime and what a failed parse means. Those differ for
 * good reasons: the scanner reuses one view per format across a whole directory
 * walk, the viewer allocates one and frees it with the file.
 *
 * ORDER IS PART OF THE CONTRACT. Sniffs are not mutually exclusive - a self
 * extracting archive is a PE and a ZIP both - so the first row whose sniff
 * accepts wins. Adding a row in the middle changes what such an object is
 * called, so add at the end unless that change is the point.
 */
#ifndef KOFFORMAT_H
#define KOFFORMAT_H

#include "../core/kofcore.h"
#include "../core/kofmod/kofsig.h"

/*
 * One parser, as everything outside the parser needs to see it.
 *
 * The last four fields are the format's own vocabulary - which regions it can
 * name, what it calls them, what its anomaly bits mean. Each format already
 * publishes those next to its parse (kof_elf_region_name and friends); what was
 * missing was anywhere to ask for them WITHOUT naming a format, and every tool
 * and test that wanted to walk all formats grew its own copy of this join.
 * There were five of those copies.
 *
 * `anomalies` is here because the anomaly word sits at a different place in
 * every view struct, so reading it needs the cast that only the engine should
 * be making.
 */
struct kof_parser {
	uint8_t  format;                       /* enum kof_format */
	uint32_t view_size;                    /* bytes to allocate for the view */
	int (*sniff)(kof_buf);
	int (*parse)(kof_buf, void *view, struct kof_obj_ctx *);

	const uint32_t *regions;               /* every region bit, in order */
	uint32_t    n_regions;
	const char *(*region_name)(uint32_t bit);
	const char *(*anomaly_name)(unsigned index);
	uint64_t  (*anomalies)(const void *view);
};

/* How many rows. Public so a caller that keeps a table of its own, one row per
 * format, can check its length against this and fail to build rather than fall
 * quietly behind. */
#define KOF_PARSER_COUNT 11u

/*
 * The list, in sniff order. Sets *n and returns a pointer that stays valid for
 * the life of the process - the table is static const, so a caller may hold it.
 */
const struct kof_parser *kof_parser_list(uint32_t *n);

/* The row for one KOF_FMT_*, or NULL. For a caller that has a format in hand
 * and wants its parser rather than a sniff. */
const struct kof_parser *kof_parser_of(uint8_t format);

#endif /* KOFFORMAT_H */
