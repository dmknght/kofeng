/*
 * memdeleted_00.c - a module still running out of a file somebody removed.
 *
 * WHAT IT IS, AND WHAT IT IS CAREFULLY NOT.
 *
 * The loader lists this module, so it was loaded the ordinary way. Its file has
 * since been UNLINKED, and nothing is at the path it came from. The bytes are
 * still in the process because the mapping keeps the file alive, and reading
 * them out of memory is now the only way anyone can see them at all.
 *
 * That is a dropper finishing its work: load the payload, delete the evidence.
 *
 * WHAT IT IS NOT is an update. A package upgrade, an installer replacing its
 * own runtime, Office updating itself - all of them unlink a mapped file too,
 * and every one of them puts a NEW file at the same path. That case is
 * KOF_PE_ORIGIN_REPLACED and this rule does not fire on it.
 *
 * THE DISTINCTION IS THE WHOLE RULE, and it was not there until it was
 * measured. Before it, "the file behind this module is gone" was three findings
 * on an ordinary desktop - VCRUNTIME140, VCRUNTIME140_1 and MSVCP140, inside
 * Office ClickToRun, all mapped out of NTFS's \$Extend\$Deleted, all three with
 * a newer file sitting at their original path. Office updating itself, on every
 * machine that has Office.
 *
 * With updates separated out, the same machine measures:
 *
 *     4778 modules:  DELETED 0,  REPLACED 3,  UNNAMED 0
 *
 * Zero is what makes this worth reporting. The Linux half of this codebase
 * reached the opposite conclusion about the same observation - aproc.h calls
 * KOFA_RGF_DELETED "a fact and not a finding", measured at 94 mappings - and it
 * was right, because it was counting updates and deletions together.
 *
 *
 * HEURISTIC, NOT A DETECTION. It says how these bytes came to have no file. It
 * says nothing about what they are, and an installer that cleans up after
 * itself does look like this. What it buys is that the bytes get SCANNED and
 * REPORTED at all: without it a payload whose file is gone is invisible to
 * anything that works from the disk.
 */

#include <kofmod/heur.h>
#include <kofmod/pe.h>

KOF_TARGET_FORMAT(KOF_FMT_PE);

/* Nothing to collect: the fact was established by the walker and arrives in
 * the view. See memmapped_00.c, which is this rule's sibling. */
KOF_HEUR_PHASE(KOF_HEUR_VERDICT);
KOF_HEUR_NAME("MemDeleted");

KOF_DEFINE_HEUR
{
	const struct kof_pe_info *pe = kof_pe(ctx);

	if (!pe || !pe->valid)
		return;

	/*
	 * BOTH TESTS, AND THE SECOND IS NOT REDUNDANT.
	 *
	 * `layout` says these bytes were read out of memory rather than off a
	 * disk; `mem_origin` says which of four things put them there. A file
	 * scan sets neither, so a rule reading only the second would fire on
	 * whatever stale value a view happened to hold - which is the bug the
	 * sniff path's memset was added to close, and is not a thing to rely on
	 * being closed.
	 */
	if (!kof_pe_is_mapped(pe) || pe->mem_origin != KOF_PE_ORIGIN_DELETED)
		return;

	KOF_HEUR_HIT();
}
