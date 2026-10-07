/*
 * kkrunchy_pe.c - recognise a kkrunchy packed PE, say which build, and run it.
 *
 * NO STATIC PATH EXISTS ANYWHERE, and that is worth recording because it is the
 * opposite of the two modules beside it. kkrunchy's coding is a RANGE CODER
 * WITH CONTEXT MODELLING - the entry point's first act is `rep stosd` over
 * 0x400 dwords, which is the probability table being initialised - and a range
 * coder's model is the decompressor itself rather than a table a reader can
 * lift out. RetDec identifies kkrunchy and stops; XVolkolak, which carries
 * static unpackers for ASPack, Petite, UPX, MEW, FSG, NsPack and six others,
 * puts kkrunchy under XEmulUnpacker instead. There is nothing to port.
 *
 * WHAT MADE IT WORK WAS ONE INSTRUCTION. Before this module existed the
 * interpreter already had everything it needed and stopped 4111 instructions
 * in: `[emu] why=0 stop=4 insn=4111 entry=0x3f29d5 images=1 written=3
 * detail=JECXZ 0x3f2a3a`. kkrunchy's inner decode loop is built on JECXZ -
 * branch on the counter being zero WITHOUT decrementing it, the one member of
 * the LOOP family that reads RCX and leaves it alone - and every one of the
 * five samples here produced nothing at all. With it added to libkofemu, all
 * five hand over with the stack balanced:
 *
 *     00, 04  8,191,416 insn   handover 0x3e4184
 *     01, 02  2,912,096 insn   handover 0x3fccb0
 *     03      3,828,214 insn   handover 0x3facf4
 *
 * So what this module adds over the generic receiver is what the generic
 * receiver cannot have: the NAME and the BUILD, and a vouch, so the run happens
 * because a module recognised the family rather than because an object looked
 * dense enough to be worth guessing at.
 *
 *
 * THE SHAPE, and kkrunchy is unusually easy to be sure about.
 *
 *   - THE DOS AND PE HEADERS ARE ONE. kkrunchy overlaps them to save bytes and
 *     signs the result: the file begins "MZfarbrausch" or "MZconspiracy" and
 *     then "PE\0\0" at offset 12. That is a fourteen-byte marker at offset
 *     zero which no forgery has a reason to carry.
 *   - one section, named `kkrunchy` by default.
 *   - and the entry point against the table below.
 *
 * Either of the first two with the third, for the reason petite_pe.c gives:
 * the section name is the builder's default and the header signature is the
 * packer's own, so requiring both would refuse a build that changed either.
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
 * 0.73 seconds and 8.2 million instructions on the largest sample here, which
 * is more than Petite's 0.15 and far less than PECompact's 17. Level 2: the
 * run is cheap enough to be worth asking for and dear enough that a default
 * sweep of a directory should not pay it on every file that reaches here.
 */
#define KKR_VOUCH_LEVEL 2u

/*
 * WHICH kkrunchy, BY THE PROBABILITY TABLE SET-UP AT THE ENTRY POINT.
 *
 * Every row begins `BD imm32` - mov ebp, <the stub's own data> - and then
 * writes the table's first entry. What differs between the alphas is what the
 * stub does with EBP next, and the three rows are ordered longest first so
 * alpha 1's shorter pattern cannot swallow the other two.
 *
 * All five samples here are alpha 1. The other two rows are XVolkolak's.
 */
static const struct eps_row kkr_rows[] = {
	/* BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? ?? B8 ?? ?? ?? ??
	 * 89 45 04 89 45 54 50 C7 45 10 */
	{ { 0xbd,0,0,0,0, 0xc7,0x45,0x00, 0,0,0,0, 0xb8,0,0,0,0,
	    0x89,0x45,0x04, 0x89,0x45,0x54, 0x50, 0xc7,0x45,0x10 },
	  0x0001ef1eu, 28, "PE:kkrunchy 0.23 alpha 2" },
	/* the same with 89 45 58 */
	{ { 0xbd,0,0,0,0, 0xc7,0x45,0x00, 0,0,0,0, 0xb8,0,0,0,0,
	    0x89,0x45,0x04, 0x89,0x45,0x58, 0x50, 0xc7,0x45,0x10 },
	  0x0001ef1eu, 28, "PE:kkrunchy 0.23 alpha 3-4" },
	/* BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 */
	{ { 0xbd,0,0,0,0, 0xc7,0x45,0x00, 0,0,0,0,
	    0xff,0x4d,0x08, 0xc6,0x45,0x0c,0x05 },
	  0x00000f1eu, 19, "PE:kkrunchy 0.23 alpha 1" }
};

#define KKR_ROWS (sizeof kkr_rows / sizeof kkr_rows[0])

/*
 * The fused DOS/PE header, which is the packer's signature on its own output.
 *
 * "PE\0\0" at offset 12 is checked as well as the name, because the name alone
 * is twelve bytes of text that a builder could have been told to change and the
 * OVERLAP is the structural fact - a normal PE has e_lfanew at 0x3c pointing
 * somewhere past the stub, and this one has the NT headers where the DOS
 * header's own fields would be.
 */
static int kkr_header(const struct kof_obj_ctx *ctx)
{
	static const char farb[] = "MZfarbrausch";
	static const char consp[] = "MZconspiracy";
	uint32_t k;
	int a = 1, b = 1;

	if (!kof_in_obj(0, 16u))
		return 0;
	for (k = 0; k < 12u; k++) {
		uint8_t c = kof_u8(k);

		if (c != (uint8_t)farb[k])
			a = 0;
		if (c != (uint8_t)consp[k])
			b = 0;
	}
	if (!a && !b)
		return 0;
	return kof_u8(12) == 'P' && kof_u8(13) == 'E' &&
	       kof_u8(14) == 0 && kof_u8(15) == 0;
}

static int kkr_named(const struct kof_pe_info *pe)
{
	static const char want[] = "kkrunchy";
	uint32_t i, k;

	for (i = 0; i < pe->sec_count; i++) {
		for (k = 0; k < 8u; k++)
			if (pe->sec[i].name[k] != want[k])
				break;
		if (k == 8u && pe->sec[i].name[8] == 0)
			return 1;
	}
	return 0;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint64_t ep;
	int r;

	if (!pe->valid || pe->pe32_plus || !pe->entry_rva)
		return;
	if (!kkr_header(ctx) && !kkr_named(pe))
		return;

	ep = kof_pe_rva_to_off(pe, pe->entry_rva);
	if (ep == KOF_BROKEN)
		return;
	r = eps_match(ctx, ep, kkr_rows, KKR_ROWS);
	if (r < 0)
		return;

	kunp_rcstruct_build(kkr_rows[r].name);
	kof_debug("kkrunchy.PE.build", (uint32_t)r);

	/*
	 * NO HANDOVER RANGE. kkrunchy decompresses into a region it allocates
	 * and jumps there, so the address is not in the file and a watch would
	 * have nothing to name. The run stops on its own - measured, with the
	 * stack balanced at the hand-over, which is the condition XVolkolak's
	 * OEP_CONTEXT uses and the one this engine took from it.
	 */
	{
		uint32_t made = eh_fold(ctx, kunp_emu_run(KKR_VOUCH_LEVEL));

		kof_debug("kkrunchy.PE.emu", made);
		if (made)
			return;
	}

	KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
}
