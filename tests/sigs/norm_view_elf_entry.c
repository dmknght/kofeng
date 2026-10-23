/*
 * norm_view_elf_entry.c - twelve bytes at the entry point.
 *
 * kof_find_str_at takes an offset the module computed, and the one it computes
 * here is ctx->entry_off. In the view that offset is the parent's carried through
 * the collapse; a collapse before the code moves the code and the entry has to
 * move with it, or these twelve bytes are not where the rule looks.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "NormViewEntry");

KOF_DEFINE_HEXSTR(entry_sig, "90 90 4E 6F 72 6D 45 6E 74 72 79 90");

KOF_DEFINE_SCAN
{
	if (ctx->entry_off != KOF_NA && ctx->entry_off != KOF_BROKEN &&
	    kof_find_str_at(ctx->entry_off, entry_sig))
		{ kof_debug("NormViewEntry#NormViewEntry", 0); return; }
}
