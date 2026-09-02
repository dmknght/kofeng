/*
 * shellcode_00.c - an ELF that is nothing but a blob of executable code.
 *
 * A COMPILER AND LINKER CANNOT PRODUCE THIS, which is the whole of the rule.
 * Anything a toolchain builds has a second segment for the data a program has,
 * and usually a PT_PHDR, a PT_GNU_STACK and a dynamic section besides. This
 * shape is what a tool that pastes shellcode into a fixed ELF template
 * produces, and msfvenom is such a tool.
 *
 *
 * WHAT WAS MEASURED
 *
 *   0 of 3252   x86-64 ELF files under /usr/{bin,sbin,lib,libexec}. Not one
 *               reaches the shape, and the smallest is 1192 bytes.
 *   0 of 2000   objects from CLEAN binaries packed with upx, ezuri, pakkero,
 *               midgetpack, ward and gzexe - children included, so the images
 *               recovered from inside them are in that count. This is the
 *               adversarial half: a packed clean binary is the thing most
 *               likely to look hand-built, and none of the six emits a
 *               single-segment file.
 *  18 of 4398   malware ELF objects. Seven the database already names; the
 *               other eleven it misses, and they are what this rule is for.
 *   7 of 7      the msfvenom samples on hand.
 *
 * SIZE IS NOT THE DISCRIMINATOR and was tried as one. The largest object with
 * this shape is 1266 bytes and the smallest clean ELF is 1192, so the two
 * populations overlap on size and separate on structure. A size bound also lost
 * one of the seven samples.
 *
 *
 * WHY IT ASKS FOR THE EMULATOR
 *
 * The shape says "this file is a payload". It does not say what the payload
 * does, and on six of the seven samples it cannot: the bytes are encrypted, and
 * what is in front of them is a decryptor. Running it is what turns the object
 * into something a signature can read - and the measurement above is what makes
 * the ask affordable, because it says how rarely this fires.
 *
 * The ask reaches exactly this object. See kofmod/heur.h.
 */

#include <kofmod/heur.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/*
 * EXAMINE, because the ask has to arrive before the object is opened - and
 * because everything the rule reads is a field of the parse, which is finished
 * by then.
 */
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
KOF_HEUR_NAME("Shellcode");

/*
 * The shape is the shape of a msfvenom payload, and the family it most often
 * carries is meterpreter - so the rule guesses "Meterp" and the engine both
 * reports it (Heur:Shellcode?Meterp) and tries the Meterp decoder first. The
 * guess never becomes a verdict: if a decoder recovers the payload and a
 * signature names it, that name wins; if nothing does, the question mark stands.
 */
KOF_HEUR_PREDICT("Meterp");
KOF_HEUR_WANT(KOF_ENG_USE_EMU);

/*
 * No architecture is declared. The shape is a property of the ELF layout and
 * not of the machine code inside it: the measurement above holds on the x86
 * samples as well as the amd64 ones, and three of the eleven the database
 * misses are 32-bit.
 */

KOF_DEFINE_HEUR
{
	const struct kof_elf_info *e = kof_elf(ctx);
	const struct kof_elf_seg *x = 0;
	uint32_t i, loads = 0;

	if (!e || !e->valid)
		return;
	/* No section table at all, and one program header: the two numbers a
	 * template has because it was written by hand. */
	if (e->shoff != 0 || e->phnum != 1)
		return;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		if (e->seg[i].type != 1u)               /* PT_LOAD */
			continue;
		loads++;
		if (e->seg[i].perm & KOF_PERM_X)
			x = &e->seg[i];
	}
	if (loads != 1 || !x)
		return;
	/*
	 * The segment IS the file: it starts at zero and its file image is at
	 * least as long as the object. Checked rather than assumed, because a
	 * single segment that maps only part of the file leaves the rest
	 * unaccounted for, and that is a different object.
	 */
	if (x->file_off != 0 || x->file_size < ctx->obj_size)
		return;
	if (e->entry_addr >= x->mem_addr &&
	    e->entry_addr <  x->mem_addr + x->mem_size)
		KOF_HEUR_HIT();
}
