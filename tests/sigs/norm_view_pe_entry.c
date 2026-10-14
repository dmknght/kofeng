/*
 * norm_view_pe_entry.c - twelve bytes at the entry point.
 *
 * kof_find_str_at takes an offset the module computed, and the one it computes
 * here is ctx->entry_off. In the view that offset is the parent's carried through
 * the collapse; a collapse before the code moves the code and the entry has to
 * move with it, or these twelve bytes are not where the rule looks.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "NormViewEntryPe");

KOF_DEFINE_HEXSTR(entry_sig, "90 90 4E 6F 72 6D 45 6E 74 72 79 90");

KOF_DEFINE_SCAN
{
	if (ctx->entry_off != KOF_NA && ctx->entry_off != KOF_BROKEN &&
	    kof_find_str_at(ctx->entry_off, entry_sig))
		KOF_SCAN_INFECT("NormViewEntryPe");
}
