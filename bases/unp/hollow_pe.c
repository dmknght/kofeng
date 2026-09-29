/*
 * hollow_pe.c - a PE whose sections are not in the file, and the honest
 * verdict that follows.
 *
 * WHAT THIS RECOGNISES, AND WHY IT PRODUCES NOTHING.
 *
 * A packer that compresses a whole image has two ways to write the result. It
 * can keep the original section table and add its own section, which is what
 * MPRESS and Themida do and which leaves a container this engine can open. Or
 * it can HOLLOW the table: every original section keeps its name, its address
 * and its VirtualSize, and its SizeOfRawData is set to zero - so the file
 * carries no bytes for .text, .rdata or .data at all, and one high-entropy
 * section at the end holds everything.
 *
 * There is nothing to unpack, because there is no algorithm to implement. The
 * stub that rebuilds the image is itself virtualised: measured on three such
 * samples, every entry point is the same two instructions -
 *
 *     68 <imm32>     push  a key
 *     e8 <rel32>     call  an interpreter
 *
 * followed by bytecode. The decompressor is not code this engine could
 * reimplement; it is data for a virtual machine that differs per build.
 *
 * SO THIS EXISTS TO STOP THE FILE BEING CALLED CLEAN. Measured before it: of
 * 893 PE files, the ten that have this shape were scanned in 10 to 59
 * milliseconds and every one came back "clean 1 file(s)" - a true statement
 * about the bytes that are there and a false impression about the program,
 * whose code the engine never saw a byte of. A verdict of "not examined" is
 * the whole point: see KOF_UNP_UNSUPPORTED in kofsig.h, where it is spelled
 * out that a coding this build lacks is a gap in the engine and must never be
 * reported as a clean file.
 *
 *
 * THE SHAPE, AND WHY EACH PART OF IT IS THERE
 *
 * Not the section names. The ten matches are named .vmp0/.vmp1, .text0/.text1,
 * .data0/.data1, qq0 through qq3, and three that are random bytes - ".$5x",
 * ".Ais", ".\"4}". A rule keyed on the names would have caught four of ten and
 * would be defeated by a checkbox. The arrangement is not.
 *
 *   - THREE OR MORE SECTIONS with a real VirtualSize and NO raw data, other
 *     than the one holding the entry point. One is ordinary: .bss is exactly
 *     this and so is any uninitialised region. Three is not something a linker
 *     produces.
 *   - THE ENTRY SECTION HOLDS ALMOST ALL THE FILE'S RAW BYTES - at least
 *     nineteen twentieths. That is what says the image was moved into it
 *     rather than merely accompanied by it, and it is what lets a sample keep
 *     a small .rsrc or .reloc with real bytes without being missed.
 *   - AND IT IS DENSE. Seven bits per byte over the whole section. The image
 *     is in there compressed; a section this large that is not dense is not
 *     holding one.
 *
 * Measured over 893 PE files: ten match, and all ten are packed images. The
 * fourteen PE files in a non-malware set to hand match none, which is far too
 * small a set to mean anything and is said here so that nobody mistakes it for
 * a false positive measurement. That measurement is what this file is waiting
 * for.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_PE);

#define HP_MIN_HOLLOW   3u          /* sections with a size and no bytes */
#define HP_MIN_VSZ      0x1000u     /* below this a VirtualSize says little */
#define HP_MIN_RAW      0x1000u     /* and the entry section has to hold some */
#define HP_SHARE        20u         /* the entry section holds 19/20 of the raw */
#define HP_EIGHTHS      56u         /* 7.0 bits per byte */

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	const struct kof_pe_sec *e;
	uint64_t raw_other = 0;
	uint32_t i, hollow = 0;

	if (!pe->valid || pe->sec_count < 3u ||
	    pe->entry_sec >= pe->sec_count)
		return;

	e = &pe->sec[pe->entry_sec];
	if (e->file_size < HP_MIN_RAW || !e->file_off)
		return;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];

		if (i == pe->entry_sec)
			continue;
		raw_other += s->file_size;
		if (s->mem_size >= HP_MIN_VSZ && s->file_size == 0)
			hollow++;
	}
	if (hollow < HP_MIN_HOLLOW)
		return;
	/*
	 * Multiplied rather than divided, so a file with no raw bytes outside
	 * the entry section does not have to be a special case and nothing
	 * rounds.
	 */
	if (raw_other * HP_SHARE > e->file_size)
		return;
	if (!kof_in_obj(e->file_off, e->file_size))
		return;
	if (kof_entropy_at(e->file_off, e->file_size) < HP_EIGHTHS)
		return;

	kof_debug("Hollow.PE.hollow", hollow);
	kof_debug("Hollow.PE.eighths",
		  kof_entropy_at(e->file_off, e->file_size));

	/*
	 * NOTHING IS PRODUCED AND THAT IS THE FINDING.
	 *
	 * The module has established what the object is - an image this build
	 * cannot rebuild - and the only thing it can do about it is refuse to
	 * let the scan end in silence. UNSUPPORTED and not DAMAGED: the file is
	 * intact and well formed, and it is this engine that falls short.
	 */
	KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
}
