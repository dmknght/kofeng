/*
 * infect_mark_00.c - a module that says WHERE an infection is, for the Infection dialog's test (tests/tui/t_dashtabs.py).
 *
 * Fires on twelve bytes at the entry point ("InfMark" and five nops) and marks the damage there (KOF_INF_DAMAGE, the host's
 * bytes that were overwritten) and four bytes of the ELF header as the body (KOF_INF_BODY), a place no region of the dialog's
 * list covers, so the dialog has to show it as a row of its own. It makes no verdict and offers no repair: a mark is a fact
 * about a place (kofhit.h).
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "InfectMark");

KOF_DEFINE_HEXSTR(entry_sig, "49 6E 66 4D 61 72 6B 90 90 90 90 90");

KOF_DEFINE_SCAN
{
	if (ctx->entry_off != KOF_NA && ctx->entry_off != KOF_BROKEN &&
	    kof_find_str_at(ctx->entry_off, entry_sig)) {
		kof_mark_infected(ctx->entry_off, 12, KOF_INF_DAMAGE);
		kof_mark_infected(4, 4, KOF_INF_BODY);
		kof_debug("InfectMark#InfectMark", 0);
	}
}
