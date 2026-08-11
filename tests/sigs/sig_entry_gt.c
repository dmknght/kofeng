/*
 * sig_entry_gt.c - first end to end signature module.
 *
 * Deliberately trivial: report a match when the entry point sits above a
 * threshold. The logic is not the point. What this proves is the whole chain -
 * a freestanding blob with no relocations, loaded at an arbitrary address,
 * reading host owned facts through the context it was handed, returning a
 * verdict the host understands.
 *
 * Note what is absent: no include but the ABI headers, no string literals, no
 * static state, no call to any external symbol. Those absences are what the
 * build script checks, and they are what keep the blob loadable by a copy and
 * an mprotect rather than by a linker.
 *
 * Also absent, and more importantly: any precondition check. The module does not
 * verify the ABI version, does not test whether the object is ELF, and does not
 * test whether the facts are valid. All of that is settled before it is called,
 * because a precondition belongs to whoever decides to make the call:
 *
 *   - the ABI version is checked once when the module is loaded. It is a
 *     constant; re-testing it per object per module produces nothing.
 *   - format is what the target mask is for. The host does not invoke a module
 *     whose declared target does not cover the object in hand, which is also
 *     what makes kof_elf()'s cast sound.
 *   - a malformed object is not this module's problem. It is the subject of a
 *     different module, one written against the anomaly facts.
 *
 * entry_off is read from the common tier rather than from the ELF view, because
 * "offset of the entry point, or a sentinel saying there is none" means the same
 * thing for every executable format. Reading it here means this module needs no
 * change when the same threshold check is wanted for PE.
 */

#include <kofmod/kofsig.h>

/* entry_off is a common tier fact, meaningful for every executable format, so
 * this needs no format view and can apply to more than one format. */
KOF_SIG_TARGET(KOF_FMT_ELF | KOF_FMT_PE);

#define ENTRY_THRESHOLD 0x1234u

KOF_DEFINE_SCAN
{
	/* An entry point that is declared but unresolvable is itself the finding;
	 * a file that simply has none is unremarkable. The two sentinels exist so
	 * this distinction can be made. */
	if (ctx->entry_off == KOF_BROKEN)
		KOF_SIG_MATCH("Suspect.EntryUnresolved", KOF_LVL_SUSPECT);
	if (ctx->entry_off == KOF_NA)
		return;

	if (ctx->entry_off > ENTRY_THRESHOLD)
		KOF_SIG_MATCH("Test.EntryAboveThreshold", KOF_LVL_INFECT);

}
