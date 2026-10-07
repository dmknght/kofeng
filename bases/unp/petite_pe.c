/*
 * petite_pe.c - recognise a Petite packed PE, say which build, and run it.
 *
 * WHY THIS ONE IS NOT STATIC WHILE aspack_pe.c BESIDE IT IS, because that is
 * the interesting part and it is a fact about Petite rather than about effort.
 *
 * Petite's container is statically readable: the loader carries an OP TABLE -
 * a list of {source rva, size, destination rva} - and an LZ decoder whose bit
 * reader is aPLib's `doubledl`. XVolkolak's xpetite.cpp implements exactly that
 * and this module was written against it. Two things stopped it here:
 *
 *   - THE NEWER BUILDS CARRY THEIR OWN DECODER. Petite embeds a per-file
 *     decompression routine and passes it five loader-local helper addresses,
 *     and XVolkolak's answer is to RUN that routine under its emulator -
 *     petRunEmbeddedDecoder - because the routine is what differs per file.
 *     The static path is the fallback there, not the main road.
 *   - ONE SAMPLE. The survey over 23,138 Bazaar files and 14,204 MalwareLab
 *     files found a single Petite binary. A decoder with a hundred bounds in
 *     it, tested on one file, is a decoder that has been shown to decode one
 *     file. See /mnt/games/kofsurvey/packer-coverage.md.
 *
 * And the price of running it is small in a way ASPack's was not: measured on
 * the sample here, 1,635,140 instructions and 0.15 seconds, against ASPack's
 * 19 to 58 million and up to 5.4 seconds. That is what makes the vouch worth
 * paying at the DEFAULT level rather than at --heur 2 - see PET_VOUCH_LEVEL.
 *
 * So this module does the half that is certain - which packer, which build -
 * and drives the interpreter for the half that is not, through the same
 * emu_harvest.h every other driver uses. If more samples turn up, the static
 * path belongs here and the shape of this file does not have to change: an
 * unpack module is the abstraction over HOW a family comes apart, and both
 * ways are inside it.
 *
 *
 * THE SHAPE
 *
 *   - the entry point, against the table below. Necessary, never sufficient -
 *     see ep_shape.h.
 *   - and a section Petite wrote: `.petite`, or the entry point in the LAST
 *     section. Either, not both: the name is the builder's default and can be
 *     changed, and a build that changed it still puts its loader last.
 *
 * The decoys the survey turned up are what the pair is for. Two samples declare
 * 27 one-byte sections named after every packer at once - `.petite` among them
 * - and match six packers by section name alone. Neither has a Petite entry
 * point.
 *
 * Version tables from XVolkolak's nfd_pe.cpp (MIT) - see THIRD-PARTY.md.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>
#include <kofunpack/ep_shape.h>
#include <kofunpack/emu_harvest.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);

KOF_TARGET_FORMAT(KOF_FMT_PE);

/*
 * 0.15 seconds and 1.6 million instructions, so it is worth paying on an
 * ordinary sweep. pecompact_pe.c vouches at 2 because its run costs 17
 * seconds; the level is the price and not the confidence.
 */
#define PET_VOUCH_LEVEL 1u

/*
 * WHICH PETITE, BY THE FIRST BYTES OF ITS LOADER.
 *
 * Longest first: every row but the last begins `B8 imm32`, and `2.4`'s six
 * bytes are a prefix of all of them. A table ordered the other way would call
 * every Petite 2.4.
 *
 * Only `2.2-2.3` is measured here - the one sample matches the second row,
 * which is the form with a single `push imm32` rather than `push 0; push
 * imm32`. The rest are XVolkolak's.
 *
 * THE OTHER HALF OF THE VERSION IS THE COMPRESSION LEVEL, and it is not in
 * this table - see pet_level below. The two are independent: the entry-point
 * shape says which BUILD wrote the file, the level says which of that build's
 * two loaders is in it, and the level is the one the unpack logic branches on.
 *
 * WHAT IS NOT DONE: telling 2.2 from 2.3. XVolkolak does it by the IMPORT
 * LIST - four to six kernel32 names in a fixed order, with the count deciding
 * - and that rule does not fire on the one sample here: its kernel32
 * descriptor holds ExitProcess, LoadLibraryA, GetProcAddress, VirtualProtect,
 * ReadFile, which is 2.2's first four followed by one of the PROGRAM's own
 * imports rather than 2.2's fifth. So this build merges the loader's imports
 * into the original table instead of replacing it, and an exact-count rule
 * cannot see through that. A prefix rule would fire, and would be a rule
 * invented here rather than measured; the range stays honest until a sample
 * exists that a real rule can be checked against.
 */
static const struct eps_row pet_rows[] = {
	/* B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00
	 * 64 89 25 00 00 00 00 66 9C 60 */
	{ { 0xb8,0,0,0,0, 0x6a,0x00, 0x68,0,0,0,0,
	    0x64,0xff,0x35,0x00,0x00,0x00,0x00,
	    0x64,0x89,0x25,0x00,0x00,0x00,0x00, 0x66,0x9c,0x60 },
	  0x00000f1eu, 29, "PE:Petite 2.2-2.3" },
	/* B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ??
	 * 64 89 25 ?? ?? ?? ?? 66 9C 60 */
	{ { 0xb8,0,0,0,0, 0x68,0,0,0,0,
	    0x64,0xff,0x35,0,0,0,0,
	    0x64,0x89,0x25,0,0,0,0, 0x66,0x9c,0x60 },
	  0x00f1e3deu, 27, "PE:Petite 2.2-2.3" },
	/* B8 ?? ?? ?? ?? 66 9C 60 */
	{ { 0xb8,0,0,0,0, 0x66,0x9c,0x60 }, 0x0000001eu, 8,
	  "PE:Petite 1.3-1.4" },
	/* B8 ?? ?? ?? ?? 60 */
	{ { 0xb8,0,0,0,0, 0x60 }, 0x0000001eu, 6, "PE:Petite 2.4" },
	/* 66 9C 60 */
	{ { 0x66,0x9c,0x60 }, 0u, 3, "PE:Petite 1.2" }
};

#define PET_ROWS (sizeof pet_rows / sizeof pet_rows[0])

/*
 * WHICH OF THE BUILD'S TWO LOADERS IS IN THE FILE - "the compression level".
 *
 * The entry point is `mov eax, imm32` and the immediate is the address the
 * loader was placed at: imageBase plus the VirtualAddress of the section
 * holding it. Petite puts that section LAST at its higher level and
 * SECOND-TO-LAST at the lower one, so comparing the immediate against those
 * two addresses says which, with no table and nothing to keep up to date. It
 * is XVolkolak's own detection for its static unpacker - `_detect` in
 * xpetite.cpp - and this is a plain restatement of it.
 *
 * IT IS A VERSION AND NOT A DETAIL, which is why it is read even though this
 * module currently interprets rather than decodes. Three constants in the
 * static path are chosen by it: how much loader tail to strip (0x355 against
 * 0x323), the skew that tail may sit at (0x35 against 0x34), and where the op
 * table is when the loader cannot be read for it (0x1b8 against 0x178). A
 * static Petite path that did not branch here would strip the wrong number of
 * bytes off the last section of every file at the other level.
 *
 * AND IT IS A THIRD STRUCTURAL CHECK. The immediate has to equal an address
 * computed from this file's own header; a forgery that copied Petite's entry
 * bytes carries whatever address the file it was copied from had.
 *
 * Returns 2, 1, or 0 for neither.
 */
static uint32_t pet_level(const struct kof_obj_ctx *ctx,
			  const struct kof_pe_info *pe, uint64_t ep)
{
	uint64_t imm;
	uint32_t n = pe->sec_count;

	if (!kof_in_obj(ep, 5u) || kof_u8(ep) != 0xb8u)
		return 0;
	imm = kof_u32(ep + 1u);
	if (n >= 1u && imm == pe->image_base + pe->sec[n - 1u].mem_rva)
		return 2;
	if (n >= 2u && imm == pe->image_base + pe->sec[n - 2u].mem_rva)
		return 1;
	return 0;
}

/*
 * LEVEL ZERO - stored, not compressed - which XVolkolak refuses outright
 * because there is nothing for its decoder to do.
 *
 * Recorded rather than refused here, because this module does not decode: a
 * run interprets the loader whatever it was built to do, and the level only
 * decides which way the static path would have gone. So it is a fact about
 * the file and not a reason to stop.
 */
#define PET_L0_AT   0x80u
#define PET_L0_MARK 0x163c988du

/* A section Petite wrote, by the name its builder gives one by default. */
static int pet_named(const struct kof_pe_info *pe)
{
	uint32_t i;

	for (i = 0; i < pe->sec_count; i++) {
		const char *n = pe->sec[i].name;

		if (n[0] == '.')
			n++;
		if (n[0] == 'p' && n[1] == 'e' && n[2] == 't' && n[3] == 'i' &&
		    n[4] == 't' && n[5] == 'e' && n[6] == 0)
			return 1;
	}
	return 0;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint64_t ep;
	uint32_t level;
	int r;

	if (!pe->valid || pe->pe32_plus || pe->entry_sec >= pe->sec_count)
		return;
	if (!pet_named(pe) && pe->entry_sec != (uint32_t)pe->sec_count - 1u)
		return;

	ep = kof_pe_rva_to_off(pe, pe->entry_rva);
	if (ep == KOF_BROKEN)
		return;
	r = eps_match(ctx, ep, pet_rows, PET_ROWS);
	if (r < 0)
		return;
	level = pet_level(ctx, pe, ep);

	/*
	 * THE BUILD AND THE LEVEL, IN ONE STRING, because packer_build is one
	 * answer and not two - see the note in objctx.c about a tool given two
	 * engine answers having to choose between them. "PE:Petite 2.2-2.3 L2".
	 *
	 * Composed here rather than held in the table: the table has one row
	 * per entry-point shape and every shape can carry either level, so
	 * rows for the pairs would be the table twice over.
	 */
	{
		char b[sizeof pet_rows[0].name + 4u];
		uint32_t k = 0;

		for (; k + 1u < sizeof b && pet_rows[r].name[k]; k++)
			b[k] = pet_rows[r].name[k];
		if (level && k + 3u < sizeof b) {
			b[k++] = ' ';
			b[k++] = 'L';
			b[k++] = (char)('0' + level);
		}
		b[k] = 0;
		kunp_rcstruct_build(b);
	}
	kof_debug("Petite.PE.build", (uint32_t)r);
	kof_debug("Petite.PE.level", level);
	if (kof_in_obj(ep + PET_L0_AT, 4u) &&
	    kof_u32(ep + PET_L0_AT) == PET_L0_MARK)
		kof_debug("Petite.PE.stored", 1);

	/*
	 * NO HANDOVER RANGE DECLARED, and unlike PECompact that is not because
	 * one cannot exist. The public OllyDbg script for this family breaks on
	 * `9D 5F F3 AA 61 66 9D 83 C4 08` - popfd; pop edi; rep stosb; popad;
	 * popfw; add esp,8 - and steps ten bytes past it, which is the loader
	 * restoring the context it saved at the entry point and therefore
	 * exactly the hand-over. It searches that pattern IN MEMORY, and this
	 * engine has no mechanism for a watch on bytes rather than on an
	 * address; see DESIGN-object-pipeline.md. The run stops the usual ways
	 * instead, which on the sample here it does with the payload written.
	 */
	{
		uint32_t made = eh_fold(ctx, kunp_emu_run(PET_VOUCH_LEVEL));

		kof_debug("Petite.PE.emu", made);
		if (made)
			return;
	}

	KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
}
