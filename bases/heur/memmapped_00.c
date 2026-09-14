/*
 * memmapped_00.c - a PE laid out in memory that no file on disk accounts for.
 *
 * WHAT IT IS ACTUALLY SAYING, which is narrower than "there is a PE here".
 *
 * A module the loader mapped is read from its FILE, and a file is parsed at
 * FILE layout - sections at their raw offsets. This fires only on a PE the
 * caller declared as MAPPED, and the only bytes that reach the engine that way
 * are bytes read out of a process's memory that no file explains:
 *
 *   MEM_MANUALMAP  a PE header in executable memory that is not an image
 *                  section and has no mapped file behind it. That is
 *                  reflective loading, described: VirtualAlloc, copy the
 *                  image, fix the relocations, resolve the imports, call
 *                  DllMain. The loader is never asked, so there is no image
 *                  section and no module list entry.
 *
 *   MEM_DELETED    a module the loader DOES list whose file is gone - deleted
 *                  or renamed after the load. A dropper's own payload, after
 *                  it tidied up.
 *
 *   MEM_UNNAMED    the same with no path at all.
 *
 * WHY THIS IS A HEURISTIC AND NOT A SIGNATURE. It matches no bytes. What it
 * recognises is a RELATIONSHIP - memory that is executable, holds a PE, and has
 * nothing on disk to point at - and that relationship is established by the
 * walker before the engine ever sees the bytes. See kof_walk_item.as_format.
 *
 *
 * THE NOISE FLOOR, MEASURED BEFORE THIS WAS WRITTEN, because a heuristic
 * without one is a guess.
 *
 * Across 83 processes and 51573 regions on an ordinary desktop:
 *
 *   executable, nothing on disk behind it   447
 *   ... of those, holding a PE header         0
 *
 * The first number is why "unbacked executable memory" is NOT this rule: every
 * JIT on the machine allocates exactly that, all day - .NET, every JavaScript
 * engine, every managed runtime. A payload copied into it is indistinguishable
 * from a compiled method by that test alone.
 *
 * The second number is why a PE HEADER is the discriminator. A JIT emits
 * machine code; it has no reason to write "MZ" and a section table in front of
 * it. A reflective loader has every reason - it is mapping an image, and the
 * image's own headers are what it copies first.
 *
 *
 * SUSPECT AND NOT INFECT, and the distinction is the honest one.
 *
 * This says HOW the memory got there, never WHAT it is. A packer that unpacks
 * itself into private memory does this. So does an installer with an embedded
 * module, and so does at least one legitimate anti-cheat. The finding is worth
 * a person's attention and is not worth a quarantine, which is exactly what
 * KOF_LVL_SUSPECT means - see kofmod/heur.h on why a heuristic never claims a
 * family.
 */

#include <kofmod/heur.h>
#include <kofmod/pe.h>

KOF_TARGET_FORMAT(KOF_FMT_PE);

/*
 * VERDICT PHASE. There is nothing to collect and nothing to score - the fact
 * this rule needs was established by the walker and travels in the view, so
 * there is no evidence-gathering pass for it to take part in.
 */
KOF_HEUR_PHASE(KOF_HEUR_VERDICT);
KOF_HEUR_NAME("MemMapped");

KOF_DEFINE_HEUR
{
	const struct kof_pe_info *pe = kof_pe(ctx);

	if (!pe || !pe->valid)
		return;

	/*
	 * MAPPED, AND SPECIFICALLY A MANUAL ONE.
	 *
	 * `layout` says the bytes were read out of memory. `mem_origin` says
	 * which of three things put them there, and this rule wants exactly one
	 * of them - see enum kof_pe_origin.
	 *
	 * IT USED TO TEST ONLY `layout`, AND THE DIFFERENCE IS THE WHOLE
	 * USEFULNESS OF THE RULE. That version fired on three modules of
	 * AppVShNotify.exe - Office ClickToRun - whose files had been
	 * POSIX-deleted into NTFS's \$Extend\$Deleted while still mapped. Every
	 * one of those was a TRUE positive: the file really was gone. They were
	 * also Office doing its job, on every machine that has Office.
	 *
	 * A deleted file after a load is a real dropper move and deserves a
	 * rule. It does not deserve THIS one, because the two have base rates
	 * orders of magnitude apart and one verdict cannot serve both: measured
	 * on an ordinary desktop, manual maps 0 and deleted files 3.
	 */
	if (!kof_pe_is_mapped(pe) || pe->mem_origin != KOF_PE_ORIGIN_MANUAL)
		return;

	KOF_HEUR_HIT();
}
