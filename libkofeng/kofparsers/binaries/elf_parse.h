/*
 * elf_parse.h - ELF collector entry point.
 *
 * Fills both tiers in one call: the common scan context and the ELF specific
 * view. Keeping it in one function means one place knows how an ELF fact maps
 * onto a common one - e_machine to kof_arch, e_entry to entry_off - instead of
 * that mapping being duplicated by every caller.
 *
 * Handles ELF32 and ELF64, little and big endian, and never fails: on hostile
 * or truncated input it reports what it recovered plus an anomaly bitmask.
 */

#ifndef KOFENG_ELF_PARSE_H
#define KOFENG_ELF_PARSE_H

#include <kofmod/elf.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if the object is ELF at all (magic matched), zero otherwise.
 *
 * On a non-zero return, ctx->fmt points at info and ctx->format is
 * KOF_FMT_ELF. A non-zero return does not mean the facts are complete: check
 * info->anomalies. On a zero return both structs are zeroed and safe to read,
 * ctx->fmt is NULL, and ctx->format is left KOF_FMT_UNKNOWN for whoever
 * identifies the object next.
 *
 * ctx->src_type is not set here: only the caller knows where the bytes came
 * from.
 */
int kof_elf_parse(kof_buf file, struct kof_elf_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * Does this object look like ELF at all?
 *
 * Magic only, and deliberately separate from the parse: identifying an object
 * must not need the view buffer, because the view is what gets allocated once the
 * format is known. Reading four bytes to decide is what keeps a scanner that only
 * ever sees one format from carrying every other format's view.
 */
int kof_elf_sniff(kof_buf file);

/* Names for the region and anomaly bits. See the note in pe_parse.h: a module
 * cannot print, so these are for tools and live on the internal side. */
const char *kof_elf_region_name(uint32_t bit);
const char *kof_elf_anomaly_name(unsigned index);

/*
 * Every region bit the format defines, in bit order.
 *
 * Exported because three separate callers had each written this list out by hand -
 * the examiner, the partition test and the fuzzer - and a list written three times
 * is a list where adding a region silently stops it being dumped and stops it being
 * checked. The same shape of copy in the signature compiler once made every PE
 * signature fail to compile. Here it is defined once, beside the name function, and
 * both are generated from the same list.
 */
extern const uint32_t kof_elf_region_bits[];
#define KOF_ELF_REGION_COUNT 5u   /* asserted against the array in the .c */

#endif /* KOFENG_ELF_PARSE_H */
