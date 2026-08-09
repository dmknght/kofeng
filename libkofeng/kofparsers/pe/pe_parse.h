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

#endif /* KOFENG_PE_PARSE_H */