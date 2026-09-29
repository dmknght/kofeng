/*
 * VMPROTECT, RECOGNISED SO THE INTERPRETER IS GIVEN TIME.
 *
 * This rule unpacks nothing and says nothing about whether a file is malicious.
 * What it does is name a shape whose payload only an interpreter can reach, and
 * ask for one - the same thing bases/heur/shellcode_00.c does for a msfvenom
 * stub.
 *
 * WHY IT IS A RULE AND NOT AN UNPACKER. There is nothing to decode: VMProtect
 * compresses and encrypts its sections and rebuilds them at run time, so a
 * module in bases/unp would have no child to produce and no want to attach one
 * to. A rule asks about the object in front of it, which is exactly the shape
 * of this request.
 *
 * HOW IT IS RECOGNISED, and neither half is a signature:
 *
 *   - THE ENTRY IS `push imm32` FOLLOWED BY A NEAR CALL OR JUMP. RetDec's
 *     cpdetect lists that pair as VMProtect's entry - see THIRD-PARTY.md - and
 *     accepts it alongside a `.vmp0` section name. The name is not required
 *     here and often cannot be: measured, the sample that prompted this is a
 *     VMProtect image that was then packed with MPRESS, so by the time it is
 *     an object the original section names are gone and only the shape is left.
 *
 *   - THE ENTRY SECTION IS DENSE. A `push`/`call` pair is two instructions
 *     anyone might write; it means something only over code that is not
 *     ordinary code. Seven bits per byte is the threshold the rest of this
 *     engine uses for "packed".
 *
 * WHAT IT IS WORTH. The run needs the time: measured on that sample, the stub
 * executes four million instructions before it has written a new page, which is
 * the ceiling an unasked-for run gets. It also runs straight into VMProtect's
 * anti-emulation - a 16 bit SHRD with a count past the operand width, whose
 * result is architecturally undefined - which is handled in libkofemu and is
 * the reason this shape is worth naming at all.
 */

#include <kofmod/kofsig.h>
#include <kofmod/heur.h>
#include <kofmod/pe.h>

KOF_HEUR_NAME("VMProtect");

KOF_TARGET_FORMAT(KOF_FMT_PE);

/* EXAMINE: everything below is a field of the parse plus one entropy window,
 * and both are ready by then. */
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);

/*
 * LEVEL 1, WHICH IS THE DEFAULT AND IS WHY IT IS NOT DECLARED.
 *
 * It was 2, back when the only thing this rule could ask for was the
 * interpreter. What it does now is name the family, and the family is what
 * routes bases/unp/vmprotect_pe.c ahead of the general pass - so gating it
 * behind --heur 2 would mean an ordinary scan never reaches the module that
 * unpacks the file, and hollow_pe.c would answer UNSUPPORTED instead.
 *
 * NO KOF_HEUR_WANT. It asked for KOF_ENG_USE_EMU, from before there was a
 * static unpacker for this. There is one now, and it produces the image
 * without running anything - so the interpreter was being started on a file
 * already opened, which on 111.exe cost the whole run and hung.
 */

/*
 * The family, so the unpacker that knows this layout is entered BEFORE the
 * general pass. It matters here and not as a nicety: hollow_pe.c recognises
 * the same shape and answers UNSUPPORTED, and the first reason recorded is the
 * one kept - so without this routing the module never runs at all.
 */
KOF_HEUR_PREDICT("VMProtect");

#define VMP_MIN_SEC     3u
/* Seven bits per byte. kof_entropy_at answers in EIGHTHS of a bit, not
 * tenths - measured here at 62, which is 7.75 bits and would have failed a
 * threshold written on the wrong scale. */
#define VMP_DENSE_EIGHTHS 56u

KOF_DEFINE_HEUR
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	const struct kof_pe_sec *e;
	uint64_t at;
	uint32_t dense;

	if (!pe || !pe->valid || pe->sec_count < VMP_MIN_SEC)
		return;
	if (pe->entry_sec >= pe->sec_count)
		return;
	e = &pe->sec[pe->entry_sec];
	if (!e->file_size || !e->file_off || pe->entry_rva < e->mem_rva)
		return;

	at = e->file_off + (pe->entry_rva - e->mem_rva);
	if (!kof_in_obj(at, 6u))
		return;
	/* push imm32, then a near call or a near jump. */
	if (kof_u8(at) != 0x68u)
		return;
	if (kof_u8(at + 5u) != 0xe8u && kof_u8(at + 5u) != 0xe9u)
		return;

	/*
	 * And the section it sits in is not ordinary code. Measured over the
	 * whole section rather than a window at the entry: a stub's own first
	 * page is hand written and reads low, and what says "packed" is the
	 * body behind it.
	 */
	/*
	 * NO kof_debug HERE, AND THAT IS DELIBERATE.
	 *
	 * Both tools infer WHICH MODULE produced a recovered object from the
	 * prefix of the last debug note anybody emitted - kofexaminer says so
	 * in on_debug, where it is written down as a known defect. This is a
	 * heuristic rule, not a producer, and it runs after the unpacker that
	 * did the work: on 111.exe it made MPRESS's child report "via
	 * VMProtect.PE", so a reader saw two children both labelled VMProtect,
	 * one of which is the MPRESS image with the VMProtect blocks still
	 * undecrypted. The entropy was a diagnostic and is not worth that.
	 */
	dense = kof_entropy_at(e->file_off, e->file_size);
	if (dense < VMP_DENSE_EIGHTHS)
		return;

	KOF_HEUR_HIT();
}
