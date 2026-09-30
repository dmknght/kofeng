/*
 * pe_reassemble.h - hand back the PE a packer decompressed INTO, not a new one.
 *
 * TWO KINDS OF RECONSTRUCTION, AND THIS IS THE OTHER ONE.
 *
 * msf_pe.h beside this builds a PE that never existed: a decoder produces a
 * payload with no structure at all, and the honest expression of it is one
 * section holding those bytes with the entry point at their start. Nothing is
 * copied because there is nothing to copy from.
 *
 * This is for the packer that decompresses into an image it already describes.
 * MPRESS and Themida both write a section with a VirtualSize and no file bytes
 * and fill it at run time; what the file becomes once the stub has run is the
 * SAME image, with that section's contents supplied. So the reconstruction
 * copies the parent's own header - machine, image base, subsystem, the whole
 * section table - and nothing in it is invented.
 *
 * WHY IT MATTERS THAT IT IS A FILE AND NOT A BLOB. Measured on an MPRESS
 * child before this existed: kofexaminer reported "format unrecognised,
 * 8183808 bytes" over 8 MB of real x86-64 code. Unrecognised means no region
 * partition, no PE-scoped rule, no import table, and - because
 * kof_scan_emu_unpack returns at its first line for an object whose format is
 * not PE - no emulator either, on the one object the emulator is the only way
 * into.
 *
 * THE LAYOUT IS THE IMAGE'S. FileAlignment is set to SectionAlignment so the
 * file and the image have the same shape and each section sits at its own
 * virtual address. That is what the bytes actually are once a stub has run, so
 * describing them any other way would need a translation step that exists only
 * to undo itself.
 *
 * WHAT A CALLER SUPPLIES. The entry point, because only the caller knows where
 * its packer hands control over, and the section walk, because only the caller
 * knows which section it filled and how. Everything mechanical is here.
 */

#ifndef KOF_PE_REASSEMBLE_H
#define KOF_PE_REASSEMBLE_H

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

/* How much is emitted at a time, and the image's alignment. Both are the
 * loader's own units: a page is what SectionAlignment is set to, and the
 * chunk is a convenient piece of one. */
#define PEI_CHUNK   0x200u
#define PEI_PAGE 0x1000u

/*
 * THE BYTE POKERS THAT USED TO BE HERE ARE GONE - pei_put16, pei_put32 and
 * pei_put64. They existed so a module could assemble PE structures: a header
 * first, and after that stopped, an import directory. Both are declarations
 * now - see kof_pe_write_hdr and `import` in kofsig.h - and nothing in this
 * tree builds a PE structure by hand any more.
 *
 * Removed rather than left for the next caller, which is the point: a header
 * that still offered them would be an invitation to encode something, and the
 * one rule the object pipeline has is that a module says what it found and the
 * engine writes the file.
 */

/* How many bytes a section occupies in the reassembled image. */
static uint64_t __attribute__((unused)) pei_span(const struct kof_pe_sec *s)
{
	return (s->mem_size + PEI_PAGE - 1u) & ~(uint64_t)(PEI_PAGE - 1u);
}

/*
 * WHERE THE SECTIONS START, which is not always one page in.
 *
 * MPRESS puts its first section at rva 0x1000 and Themida puts its at 0x2000,
 * and a walk that assumed the first is what the second silently produced
 * nothing from: the first section's address did not match where the walk
 * thought it was, so the walk stopped before it began. The file says where its
 * own sections start, so this asks it.
 *
 * The lowest section address, which is also what SizeOfHeaders has to be for
 * the header area and the first section not to overlap.
 */
static uint64_t __attribute__((unused)) pei_hdr_span(const struct kof_pe_info *pe)
{
	uint64_t lo = 0;
	uint32_t i;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++)
		if (!lo || pe->sec[i].mem_rva < lo)
			lo = pe->sec[i].mem_rva;
	if (lo < PEI_PAGE)
		lo = PEI_PAGE;
	return lo & ~(uint64_t)(PEI_PAGE - 1u);
}

/*
 * The header the image never had.
 *
 * MPRESS wrote its own, so the original is not in the file and not in the
 * stream - unlike UPX, which keeps a copy inside what it compresses and which
 * is why kof_pe_rebuild works by looking for one. There is nothing to look
 * for here, so this builds one, and every field is either read from the file
 * or describes what this module actually produced:
 *
 *     machine, magic, image base, subsystem      from the parent's own header,
 *                                                which the loader used and
 *                                                MPRESS therefore left alone
 *     entry point                                from the stub, above
 *     one section at rva 0x1000, of exactly      what was decompressed
 *     the declared size
 *
 * ONE SECTION, AND IT IS NOT A FREE CHOICE. The original section table is
 * gone - names, boundaries and permissions with it - so anything with more
 * than one section in it would be a division this module invented. The cost is
 * that the whole image reads as CODE, so a rule scoped to DATA cannot fire on
 * it; the alternative is the object identifying as nothing at all, which is
 * what it did before and which costs every PE-scoped rule instead of some.
 *
 * FileAlignment IS SectionAlignment, so the file this describes has the same
 * layout as the image and no rebuild step is needed: the header page, then the
 * decompressed bytes exactly as they come out.
 */

/*
 * EVERY SECTION, NOT JUST THE ONE THAT WAS COMPRESSED - and the reason is
 * measured rather than tidy.
 *
 * With only the payload section in it, the child is a valid PE and the
 * emulator starts on it at the right address and dies fifteen instructions
 * later, reading 0xbcf028. That address is the stub's own import thunk, which
 * lives in the SECOND section: the code MPRESS decompresses does not stand
 * alone, it calls back into the loader through the parent's import table. A
 * child missing that section is a program missing its imports.
 *
 * So the child is the whole image: the header, then every section at its
 * virtual address, with the compressed one replaced by what it decompresses to
 * and the others copied as they are. FileAlignment is set to SectionAlignment
 * so the file and the image have the same layout and the sections follow one
 * another with no translation.
 *
 * THE IMPORT DIRECTORY IS CARRIED OVER TOO. It is the parent's, it points into
 * a section the child now has, and the host fills those thunks before the run -
 * see fill_iat_pe in emu_unpack.c. Left out, the thunks stay as the file wrote
 * them and the first call through one goes to an RVA.
 */
static int __attribute__((unused)) pei_pad(const struct kof_obj_ctx *ctx, uint64_t n)
{
	uint8_t z[PEI_CHUNK];
	unsigned k;

	for (k = 0; k < PEI_CHUNK; k++)
		z[k] = 0;
	while (n) {
		unsigned c = n > PEI_CHUNK ? PEI_CHUNK : (unsigned)n;

		if (!kunp_rcstruct_write(z, c))
			return 0;
		n -= c;
	}
	return 1;
}

/*
 * Copy a range of the parent into the child being built.
 *
 * THROUGH kunp_rcstruct_write AND NOT kunp_rcstruct_window, which is the obvious call and the
 * wrong one: a window is a child in its own right - c_window pushes it
 * immediately - so mixing the two does not append a range to what is being
 * assembled, it ends the assembly and starts something else. Measured, the
 * child came back as the 3072 bytes of the last window and nothing before it.
 */
static int __attribute__((unused)) pei_copy(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	uint8_t b[PEI_CHUNK];

	while (len) {
		unsigned c = len > PEI_CHUNK ? PEI_CHUNK : (unsigned)len, k = 0;

		/*
		 * EIGHT BYTES A CALL, NOT ONE.
		 *
		 * The accessors are indirect calls through the content table
		 * and each one bounds-checks its own read, so the per-byte form
		 * cost sixteen instructions a byte: measured on a Themida
		 * sample, which copies about four megabytes of sections it did
		 * not decompress, c_rd8 alone was 67,004,168 instructions -
		 * 8.4% of the whole scan, to move bytes from one place to
		 * another.
		 *
		 * kof_u64 checks the same bounds once for eight, and the tail
		 * is whatever is left. Nothing else changes: the same bytes in
		 * the same order.
		 */
		while (k + 8u <= c) {
			uint64_t v = kof_u64(off + k);
			unsigned j;

			for (j = 0; j < 8u; j++)
				b[k + j] = (uint8_t)(v >> (8u * j));
			k += 8u;
		}
		for (; k < c; k++)
			b[k] = (uint8_t)kof_u8(off + k);
		if (!kunp_rcstruct_write(b, c))
			return 0;
		off += c;
		len -= c;
	}
	return 1;
}




/*
 * How long the reassembled image is: the highest section end, rounded up.
 * The same number the header's SizeOfImage carries, computed once so a caller
 * and the header cannot disagree about it.
 */
static uint64_t __attribute__((unused)) pei_image_end(const struct kof_pe_info *pe)
{
	uint64_t end = 0;
	uint32_t i;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		uint64_t e2 = (pe->sec[i].mem_rva + pe->sec[i].mem_size +
			       PEI_PAGE - 1u) & ~(uint64_t)(PEI_PAGE - 1u);

		if (e2 > end)
			end = e2;
	}
	return end;
}


#endif /* KOF_PE_REASSEMBLE_H */
