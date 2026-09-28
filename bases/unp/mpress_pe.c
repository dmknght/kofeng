/*
 * mpress_pe.c - unpack an MPRESS packed PE.
 *
 * Written because the emulator was doing this job and failing at it. On one
 * sample - a 2,770,432 byte PE32+ - kof_emu_unp_gate_pe answered DENSE, the
 * interpreter spent its entire 268,435,456 instruction ceiling and produced
 * nothing, and the scan cost 21.35 seconds against 0.015 with the emulator off.
 * Nothing was recovered for the 21 seconds; the object was reported exactly as
 * it is reported when no emulator runs at all.
 *
 * There is no anti-emulation in that stub and this is not a workaround for one.
 * Its 918 decoded instructions contain no rdtsc, no cpuid, no PEB read, no
 * indirect call and no syscall: it is a straight LZMA decompressor, which is
 * precisely the shape emu_unpack.h says an interpreter reaches. It fails on
 * SIZE alone. The stub must decode 8,183,808 bytes, and LZMA costs on the order
 * of a hundred guest instructions per output byte, so the work is around a
 * billion instructions against a ceiling of 268 million. The gate could have
 * known that before starting: the number is the section's VirtualSize, which is
 * in the header.
 *
 * So this module exists for the ordinary reason a static unpacker exists - it
 * reads the header and calls the decoder, and on that sample it produced all
 * 8,183,808 bytes in milliseconds.
 *
 *
 * THE CONTAINER
 *
 * MPRESS writes two sections: the payload, and a stub. The payload section
 * begins with six bytes of header followed by two bytes of LZMA properties and
 * then the stream:
 *
 *     +0  u16   the uncompressed size, in 4096 byte units
 *     +2  u32   the compressed size, counting the two property bytes
 *     +6  u8    pb in the high nibble, lp in the low nibble
 *     +7  u8    lc
 *     +8        a raw LZMA1 stream, standard five byte range coder init
 *
 * Read off the stub's own entry code rather than from a specification: the
 * entry reads the word, shifts it left by twelve and keeps it as the output
 * length; reads the dword and uses it as a copy length; then takes the two
 * property bytes apart with `shr $4` and `and $0xf` and sizes a probability
 * array of 0x300 << (lc + lp) entries on the stack, which is LZMA's and only
 * LZMA's.
 *
 * Confirmed by decoding, on the seven files in one collection that carry this
 * container. FIVE decode to exactly the length the section declares, not
 * approximately and not in part:
 *
 *     PE32+  lc=5 lp=0 pb=2   0x7ce000 of 0x7ce000
 *     PE32   lc=5 lp=0 pb=2   0x4f1000 of 0x4f1000
 *     PE32   lc=5 lp=0 pb=2   0x592000 of 0x592000
 *     PE32   lc=7 lp=0 pb=2   0xda8000 of 0xda8000
 *     PE32   lc=4 lp=0 pb=2   0x0b4000 of 0x0b4000
 *
 * Both widths, three values of lc, and the width is not what varies with it -
 * a PE32 and a PE32+ share lc=5. So nothing here branches on pe32_plus: the
 * parameters are in the file because the packer put them there.
 *
 * Note lc + lp = 5 on four of those. liblzma refuses that combination - LZMA1
 * in xz requires lc + lp <= 4 - which is why a decode through the system
 * library reports an internal error on these files and this engine's decoder
 * does not. KOF_LZMA_MAX_LC is 8 because the specification says 8.
 *
 *
 * THE OTHER TWO, WHICH ARE NOT LZMA AT ALL
 *
 * The remaining two carry the same six byte size header - the word still times
 * 4096 to exactly the section's VirtualSize - and then something else. Their
 * property bytes are 0x6a 0x00, which would be pb=6 and lp=10, and both are
 * outside what LZMA allows; the range check below is what notices.
 *
 * It is not a corrupt file and the disassembly says so. Their stub reads the
 * same word and the same dword, performs the same backward copy, and then
 * calls its decoder with nothing but a source and a destination - no property
 * bytes read, no probability array sized, none of the `shr $4` / `and $0xf`
 * the LZMA stub does. An earlier MPRESS with a different coding, and the two
 * bytes this reads as properties are the first two bytes of its stream.
 *
 * So they are reported KOF_UNP_UNSUPPORTED, which is what they are: a version
 * this build lacks. Adding that coding is a separate piece of work with its own
 * measurement, and until it happens these two objects are honestly described
 * rather than quietly declared clean.
 *
 * A stream of that older kind whose first two bytes happened to parse as valid
 * properties would be decoded as LZMA and produce garbage - and then `got`
 * falls short of what the section declared, the comparison at the end notices,
 * and the object is reported not fully examined. Wrong in the same safe
 * direction the rest of this directory is wrong in.
 *
 *
 * FINDING THE PAYLOAD SECTION WITHOUT ITS NAME
 *
 * The sections are called .MPRESS1 and .MPRESS2 and this does not look at the
 * names, for the reason upx_pe.c gives about UPX1: a name is a string whoever
 * built the file chose, and renaming one is free.
 *
 * What cannot be renamed is that the header's size field and the section's
 * VirtualSize are the same number written twice. The stub reads the word at the
 * payload's first byte, shifts it left by twelve, and decompresses that many
 * bytes into the section - so a section whose VirtualSize is not exactly
 * (u16 << 12) is not one MPRESS wrote, and one whose VirtualSize is cannot be a
 * coincidence in any file that also passes the three checks below. Two
 * independent numbers agreeing, at a cost of eight bytes read per section.
 *
 * The entry section is excluded because it is the stub, and a section is
 * required to be at least two pages so the agreement is a statement rather than
 * arithmetic on a small number.
 *
 * MEASURED, because an invariant that costs nothing is still worth nothing if
 * it fires on ordinary files: over 7909 PE files from one malware collection,
 * this matches 0. All seven matches in the other collection are MPRESS, by the
 * section name this deliberately does not read.
 *
 *
 * WHAT THIS DOES NOT DO
 *
 * It does not rebuild the PE, and cannot: what comes out is the image from
 * VirtualAddress 0x1000 upward, and the original headers are not in it - MPRESS
 * wrote its own. So the child is handed over as KOF_FORM_RAW and identifies as
 * nothing in particular, which is what it is. Whether the file's own headers
 * are close enough to the original's to splice on is a question for
 * measurement, not for assumption.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_PE);

#define MP_HDR       8u         /* six bytes of sizes, two of properties */
#define MP_UNIT      12u        /* the uncompressed size is in 4096s */
#define MP_MIN_MEM   0x2000u    /* two pages, below which the match is noise */

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint64_t stream, u_len, got;
	uint32_t c_len, i, found;
	unsigned lc, lp, pb;

	if (!pe->valid || pe->sec_count < 2u ||
	    pe->entry_sec >= pe->sec_count)
		return;
	found = pe->sec_count;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];

		if (i == pe->entry_sec)
			continue;               /* that one holds the stub */
		if (s->mem_size < MP_MIN_MEM || !s->file_off)
			continue;
		if (!kof_in_obj(s->file_off, MP_HDR))
			continue;
		/*
		 * The agreement. Both sides are read as written - the header's
		 * word from the file and VirtualSize from the section table -
		 * and a mismatch ends this section here, before anything else
		 * is read.
		 */
		if (((uint64_t)kof_u16(s->file_off) << MP_UNIT) != s->mem_size)
			continue;
		/*
		 * And the compressed stream has to fit in the bytes the section
		 * actually owns. c_len counts from the property bytes, so the
		 * six header bytes ahead of them are added back.
		 */
		c_len = kof_u32(s->file_off + 2);
		if (c_len <= 2u || (uint64_t)c_len + 6u > s->file_size)
			continue;
		found = i;
		break;
	}
	if (found >= pe->sec_count)
		return;                         /* not this packer */

	stream = pe->sec[found].file_off;
	u_len  = pe->sec[found].mem_size;
	c_len  = kof_u32(stream + 2);
	pb     = kof_u8(stream + 6) >> 4;
	lp     = kof_u8(stream + 6) & 0xfu;
	lc     = kof_u8(stream + 7);

	/*
	 * What was recognised, before anything is decided about it - the three
	 * numbers that decide whether a sample is one this module handles, so
	 * they are reported whatever happens next.
	 */
	kof_debug("MPRESS.PE.lc", lc);
	kof_debug("MPRESS.PE.lp", lp);
	kof_debug("MPRESS.PE.pb", pb);

	if (lc > KOF_LZMA_MAX_LC || lp > KOF_LZMA_MAX_LP ||
	    pb > KOF_LZMA_MAX_PB) {
		/*
		 * The agreement held and the parameters did not, which is the
		 * earlier MPRESS described at the top: the same size header
		 * over a coding this engine does not have. UNSUPPORTED and not
		 * DAMAGED - the file is intact and it is this build that falls
		 * short, and kofsig.h reserves each word for exactly that.
		 */
		KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);
	}

	/*
	 * u_len sizes the buffer and bounds nothing: it is a number out of the
	 * file, so the host clamps it to what the memory ceiling allows and the
	 * comparison at the end is what notices a stream that did not hold what
	 * the section said it held.
	 */
	/*
	 * THE CALL FILTER IS PART OF THE CODING, not an extra this module
	 * could leave off.
	 *
	 * MPRESS rewrites the displacement of every E8 and E9 - and on 64 bit
	 * also every FF15/FF17 and 8D05 - from relative to absolute before
	 * compressing, and its stub converts them back before jumping. Bytes
	 * handed over without that step are the right length and the wrong
	 * program: measured on the PE32+ sample, 8649 displacements differ, so
	 * a hex pattern written over any code containing a call does not match
	 * what a scan would see.
	 *
	 * Asked for through the method id because the transform needs the
	 * whole decoded output and a module has no buffer to hold it - the
	 * host does the decode, so the host does the undo, exactly as it
	 * already does for KOF_UNP_LZMA2_BCJ_X86.
	 *
	 * THE WIDTH COMES FROM THE FILE, and it has to: the two stubs convert
	 * different opcodes, and the wide rule applied to a 32 bit image
	 * rewrites four bytes after every 0x8D the packer never touched.
	 */
	got = kof_unpack_form(KOF_UNP_LZMA_MPRESS_PROPS(lc, lp, pb,
							pe->pe32_plus ? 64u
								      : 32u),
			      stream + MP_HDR, c_len - 2u, u_len,
			      KOF_FORM_RAW);
	if (got == 0)
		KOF_UNP_BROKEN(KOF_UNP_DAMAGED);

	/*
	 * The handover is checked, like every container in this directory
	 * checks it: refused by the host and not reported, the module would be
	 * saying it unpacked the object while having produced nothing.
	 */
	if (!kof_child())
		kof_unp_broken(KOF_UNP_LIMIT);

	if (got < u_len)
		kof_unp_broken(KOF_UNP_DAMAGED);
}
