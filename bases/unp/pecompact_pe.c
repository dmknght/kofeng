/*
 * pecompact_pe.c - recognise a PECompact 2 packed PE and say it was not read.
 *
 * PRODUCES NOTHING, AND THAT IS THE POINT.
 *
 * PECompact 2 compresses the whole image into the section its entry point is
 * in and states the two sizes in a header - so the container is plain, and a
 * module could be written the moment the coding were known. It is not: the
 * codec is a plugin the builder chooses, and on the sample this was written
 * for it is none of the ones this engine has. Measured over the compressed
 * stream: not aPLib at any offset in the first 16 KB, and not zlib, raw
 * DEFLATE, bzip2, xz or LZMA1 at any of lc 0-8 x pb 0-4 over the same range.
 *
 * So the codec is a gap in this engine, and the module used to stop at saying
 * so - KOF_UNP_UNSUPPORTED, and nothing produced.
 *
 *
 * IT DRIVES THE INTERPRETER ITSELF NOW, and that is what an unpack module is
 * for: the abstraction over HOW a family comes apart. Statically it comes apart
 * not at all, and this module is the one thing in the engine that knows that
 * for certain rather than guessing it - so it VOUCHES for a run and folds what
 * the run leaves into an object, through the same emu_harvest.h every other
 * driver uses.
 *
 * Leaving it to the generic receiver was nearly the same thing and worse in
 * two ways. The generic one asks unvouched, so the object has to pass a density
 * gate that knows nothing about PECompact; and it only ever ran when the host
 * had already decided to interpret things - `kofexaminer`, which sets no emu
 * mode at all, got no child out of 007 Spy.exe while this module sat beside it
 * holding the proof that nothing else would work.
 *
 * VOUCHED AT LEVEL 2, NOT UNCONDITIONALLY. What the run costs is measured:
 * 168,558,592 instructions, 17.3 seconds, the whole ceiling. The stub
 * deliberately faults at a null pointer and continues through its own exception
 * handler - the interpreter's SEH dispatch handles that correctly, raised=1
 * taken=1 - and then decompresses eight megabytes with a codec nothing here can
 * follow. That is the right price for a caller who asked for the expensive
 * level and the wrong price for a default sweep, so the level rides with the
 * vouch and the host compares it - see vouch_level in kofsig.h.
 *
 * AND IT STILL SAYS UNSUPPORTED WHEN THE RUN GIVES NOTHING. A build whose codec
 * this engine cannot follow AND whose run was refused or empty is a file this
 * engine did not read, and that is worth reporting as a gap rather than as
 * clean.
 *
 *
 * THE SHAPE
 *
 *   - "PEC2" in the headers, before the first section's data. PECompact writes
 *     it there and the bound keeps the search off the rest of the file, for
 *     the reason upx_pe.c gives about its own marker.
 *   - the entry point's section has a VirtualSize far larger than its raw size
 *     - the image decompresses into it. Four times is well under what a packer
 *     produces and well over what alignment padding explains.
 *
 * Both, because "PEC2" alone is four bytes that could be anywhere.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>
#include <kofunpack/emu_harvest.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_PE);

KOF_DEFINE_STR(pec_magic, "PEC2", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);


#define PEC_GROWTH 4u        /* VirtualSize this many times the raw size */
/* The --heur level from which the run is worth its 17 seconds. */
#define PEC_VOUCH_LEVEL 2u

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_sec *e;
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint64_t at;

	if (!pe->valid || pe->entry_sec >= pe->sec_count)
		return;
	e = &pe->sec[pe->entry_sec];
	if (!e->file_size || !e->file_off)
		return;
	if (e->mem_size < (uint64_t)e->file_size * PEC_GROWTH)
		return;

	at = kof_find_str_where(0, e->file_off, pec_magic);
	if (at == KOF_BROKEN)
		return;

	/*
	 * WHICH PECOMPACT, AS FAR AS THE FILE SUPPORTS SAYING.
	 *
	 * "PEC2" in the headers is the 2.x marker - 1.x writes "PEC1" - and
	 * nothing after it is a version: measured on 007 Spy.exe the four bytes
	 * following are zero. The minor release is told apart by the SHAPE of
	 * the stub, which is what DIE's scripts and XVolkolak's per-packer
	 * unpackers do, and this build has one sample; a table with one row in
	 * it would be a table of that sample.
	 *
	 * So the honest answer is the major version, which the marker proves,
	 * and it is enough for the thing a build is FOR - the layout this
	 * module reads the object with is 2.x's.
	 */
	kunp_rcstruct_build("PE:PECompact 2.x");

	kof_debug("PECompact.PE.raw", (uint32_t)(e->file_size >> 10));
	kof_debug("PECompact.PE.virt", (uint32_t)(e->mem_size >> 10));

	/*
	 * NO HANDOVER RANGE, AND THAT IS A PROPERTY OF THIS PACKER RATHER THAN
	 * A GAP IN THE MECHANISM. Three ways of naming one were tried and
	 * measured on 007 Spy.exe; all three are wrong, and they are recorded
	 * because each is the obvious next idea after the one before it.
	 *
	 *   - THE ENTRY SECTION, which is the one that grows and therefore the
	 *     one the image decompresses into. A watch ends the run when
	 *     execution crosses INTO the range, and the loader crosses back in
	 *     at instruction 17 - it runs partly in .text and partly in .rsrc,
	 *     so re-entry means nothing here. (Before the watch counted the
	 *     edge rather than the address it was worse: instruction 0.)
	 *   - EVERY OTHER SECTION, on the guess that the stub lives where the
	 *     run starts. It does not: PECompact leaves a jump at the entry
	 *     point and its loader in .rsrc, so the run ends at instruction 6.
	 *   - THE STUB'S OWN LAST INSTRUCTION, which is exact and which the
	 *     public OllyDbg scripts break on: `8B C6 5A 5E 5F 59 5B 5D FF E0`
	 *     - mov eax,esi; pop edx; pop esi; pop edi; pop ecx; pop ebx;
	 *     pop ebp; jmp eax - one match in this file, at 0x504e9. Declared
	 *     at its rva, 0x8428f1, the run went the full 207,329,920
	 *     instructions without ever fetching it. The reason is in how those
	 *     scripts work and not in the pattern: they search it in MEMORY,
	 *     because the loader COPIES ITSELF to 0x20000000 and runs the rest
	 *     of the unpacking there. The bytes in the file are never executed.
	 *
	 * So the address of the handover is not a fact about the file. What
	 * would find it is a search of memory as the run makes it executable,
	 * which is what those scripts do and what this engine has no mechanism
	 * for - see DESIGN-object-pipeline.md. Until then nothing is declared,
	 * the run stops the usual ways, and what is harvested is what the
	 * auto-snapshot caught.
	 */
	{
		uint32_t made = eh_fold(ctx, kunp_emu_run(PEC_VOUCH_LEVEL));

		kof_debug("PECompact.PE.emu", made);
		if (made)
			return;
	}

	KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
}
