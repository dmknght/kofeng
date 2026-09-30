/*
 * msf_elf64.h - put msfvenom's x86-64 ELF header back in front of a payload.
 *
 * The 64-bit counterpart of msf_elf32.h. Split into a header of its own rather
 * than a `bits` argument on that one, because the two share no constant: the
 * templates are linked at different addresses, their headers are different
 * lengths, and their payload sections are given different permissions. A
 * function taking a width would be two functions with a switch in front.
 *
 * It lived inside bases/unp/msf_xor_00.c as `emit_elf_hdr`, which is why the
 * split is worth stating. That copy assembled 0x78 bytes of ELF header and
 * program header field by field and handed them over with
 * kunp_rcstruct_write - the round trip the declaration mechanism exists to
 * end, and the last one left in this tree. Nothing in the engine knew those
 * bytes were a header, so the child's first 0x78 bytes were content like the
 * rest and the layout the module knew exactly had to be parsed back out of
 * what the module had just written.
 *
 * WHAT IS NOT CLAIMED: that a file like this was ever on disk. msfvenom pastes
 * the payload into a fixed template; the reconstruction is what the loader
 * would have run, expressed as the ELF64 its outermost layer is. See msf_pe.h,
 * which says it first and says it well.
 */

#ifndef MSF_ELF64_H
#define MSF_ELF64_H

#include <kofmod/kofsig.h>

/*
 * The template's own numbers, read off the cleartext sample:
 *   base   0x400000   where msfvenom links these
 *   header 0x78       64-byte ELF64 header + one 56-byte program header,
 *                     which is exactly KUNP_HDR_ELF64 - the room the engine
 *                     needs in front of the first section
 */
#define MSF_ELF64_BASE  0x400000ull
#define MSF_ELF64_HDR   KUNP_HDR_ELF64

/*
 * DECLARE the ELF a payload of `payload_n` bytes is to become. Returns 0 when
 * the host refused, so a caller stops.
 *
 * Call this, then write the payload, then kunp_rcstruct_done().
 *
 * RWX, because that is what the template's own PT_LOAD asks for and because
 * the payload writes to itself. The engine ORs the permissions of the declared
 * sections into the one PT_LOAD it writes - see kof_elf_write_hdr - so one
 * section carrying all three is the same segment the module used to write.
 *
 * WHAT CHANGES AGAINST THE HAND-WRITTEN COPY, measured rather than assumed:
 * p_memsz. The old copy set it equal to p_filesz and said in a comment that
 * the template pads it - 680 bytes of image for 250 of file - and that copying
 * the number would be inventing one. The engine's writer sets both to the
 * image end, which is the same value for a single section with no bss. So the
 * bytes are unchanged; only who writes them moves.
 */
static int msf_decl_elf64(const struct kof_obj_ctx *ctx, uint64_t payload_n)
{
	if (!payload_n)
		return 0;
	if (kunp_rcstruct_section(".text", MSF_ELF64_HDR, payload_n,
				  KUNP_PERM_R | KUNP_PERM_W | KUNP_PERM_X,
				  KOF_SECF_CODE | KOF_SECF_REBUILT) < 0)
		return 0;
	kunp_rcstruct_as(KOF_FMT_ELF, KOF_ARCH_X86_64, MSF_ELF64_BASE);
	if (!kunp_rcstruct_image())
		return 0;
	kunp_rcstruct_entry(MSF_ELF64_HDR);
	return kunp_rcstruct_at(MSF_ELF64_HDR);
}

#endif /* MSF_ELF64_H */
