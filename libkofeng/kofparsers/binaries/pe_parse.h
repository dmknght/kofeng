/*
 * pe_parse.h - PE collector entry point.
 *
 * Fills both tiers in one call: the common scan context and the PE specific view.
 * Keeping it in one function means one place knows how a PE fact maps onto a
 * common one - Machine to kof_arch, AddressOfEntryPoint to entry_off - instead of
 * that mapping being duplicated by every caller.
 *
 * Handles PE32 and PE32+, and never fails: on hostile or truncated input it
 * reports what it recovered plus an anomaly bitmask.
 */

#ifndef KOFENG_PE_PARSE_H
#define KOFENG_PE_PARSE_H

#include <kofmod/pe.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is PE at all - MZ and PE\0\0 both matched.
 *
 * On a non-zero return, ctx->file_header points at info and ctx->format is
 * KOF_FMT_PE. A non-zero return does not mean the facts are complete: check
 * info->anomalies. On a zero return both structs are zeroed and safe to read,
 * ctx->file_header is NULL, and ctx->format is left for whoever identifies the
 * object next.
 *
 * An MZ with no usable PE header is not PE: it is a DOS executable, and claiming
 * it would hand a module a view with nothing in it.
 */
int kof_pe_parse(kof_buf file, struct kof_pe_info *info,
		 struct kof_obj_ctx *ctx);

/*
 * Does this object look like PE at all?
 *
 * MZ plus a PE signature where e_lfanew points, because MZ alone is a DOS
 * executable and claiming one would hand a module an empty view. Magic only, and
 * separate from the parse for the reason given in elf_parse.h: identifying must
 * not need the view buffer.
 */
int kof_pe_sniff(kof_buf file);

/*
 * Names for the region bits and the anomaly bits.
 *
 * A region's name is its enum identifier, spelled out. It ends up as a filename
 * when a tool dumps regions, and a name somebody can paste straight into grep
 * finds the enum, the CLAIMED mask and the resolver branch at once. A shortened
 * form would read better in a column and would cost a mental step exactly when
 * somebody is trying to find out where a byte came from.
 *
 * Here rather than in kofmod/pe.h because a module cannot print: it has no libc
 * and no output. These exist for tools that describe a file to a person, so they
 * live with the collector, on the internal side.
 *
 * NULL for a bit with no name, which is the failure mode to want. A tool printing
 * "bit19" for an anomaly somebody added and did not name is a tool that shows the
 * omission; a table silently one entry short would print the wrong name for every
 * bit above the gap.
 */
const char *kof_pe_region_name(uint32_t bit);
const char *kof_pe_anomaly_name(unsigned index);

/* Every region bit the format defines, in bit order. See the note on
 * kof_elf_region_bits: one list, so a region added here cannot go untested. */
/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
/* The regions, once: bit list and names generated from the same line each. */
#define PE_REGIONS(X)           \
	X(KOF_SCAN_PE_HEADERS)    \
	X(KOF_SCAN_PE_CODE)       \
	X(KOF_SCAN_PE_DATA)       \
	X(KOF_SCAN_PE_RESOURCE)   \
	X(KOF_SCAN_PE_SIGNATURE)  \
	X(KOF_SCAN_PE_OVERLAY)    \
	X(KOF_SCAN_PE_UNCLAIMED)

extern const uint32_t kof_pe_region_bits[];
#define KOF_PE_REGION_COUNT 7u   /* asserted against the array in the .c */

#endif /* KOFENG_PE_PARSE_H */