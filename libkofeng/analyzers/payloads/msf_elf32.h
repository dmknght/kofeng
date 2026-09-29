/*
 * msf_elf32.h - put msfvenom's x86 ELF header back in front of a decoded payload.
 *
 * The 32-bit counterpart of emit_elf_hdr in msf_xor_00.c, and shared by the
 * three x86 static decoders because it is byte for byte the same for all of
 * them - the payload they recover is the same x86 stager, and msfvenom wraps it
 * in one fixed template. A header rather than three copies of it: the modules
 * differ in how they decrypt, not in what a decrypted x86 payload is.
 *
 * WHY RECONSTRUCT AT ALL. A decoder that emits the payload alone hands back a
 * formatless blob - real machine code, but with no ELF header, so it is not a
 * file and no signature scoped to an ELF region can run on it. msfvenom does not
 * compile these; it pastes the payload into a fixed template, so the honest
 * reconstruction is that template with the payload in it. `x86_clear` in the
 * sample set is the reference: a payload built with no encoder is byte for byte
 * this layout.
 *
 * WHAT IS NOT CLAIMED: that a file like this was ever on disk. It was not - the
 * encoder's output was. The reconstruction is what the loader would have run,
 * expressed as the ELF32 its outermost layer is, and the viewer shows it as a
 * child of that layer.
 */

#ifndef MSF_ELF32_H
#define MSF_ELF32_H

#include <kofmod/kofsig.h>

/* The template's own numbers, read off x86_clear:
 *   base   0x08048000   the load address msfvenom links these at
 *   header 0x54         52-byte ELF32 header + one 32-byte program header
 *   entry  base + 0x54  the payload, right after the header
 */
#define MSF_ELF32_BASE  0x08048000u
#define MSF_ELF32_HDR   0x54u


/*
 * DECLARE the ELF a payload of `payload_n` bytes is to become. Returns 0 when
 * the host refused, so a caller stops.
 *
 * Call this, then write the payload, then kunp_rcstruct_done().
 *
 * IT USED TO WRITE THE HEADER ITSELF - fifty-two bytes of ELF header and
 * thirty-two of program header, assembled field by field right here and handed
 * over with kunp_rcstruct_write like any other content. That is the round trip
 * the declaration mechanism exists to end, and it had the failure the argument
 * for that mechanism predicts: nothing in the engine knew those bytes were a
 * header, so the child's first fifty-two bytes were content like the rest, and
 * the layout the module knew exactly had to be recovered by parsing back what
 * the module had just written.
 *
 * WHAT IS DECLARED. One section holding the payload, at MSF_ELF32_HDR so the
 * header fits in front of it, readable-writable-executable because that is what
 * msfvenom's own template asks for, and REBUILT because these bytes were
 * recovered rather than read. The entry point is the payload's first byte. The
 * engine writes the rest - see kof_elf_write_hdr.
 *
 * The 0x1000 alignment, the ET_EXEC, the single PT_LOAD covering the whole file
 * are all still what they were; they are simply no longer this file's business.
 */
static int msf_decl_elf32(const struct kof_obj_ctx *ctx, uint32_t payload_n)
{
	if (!payload_n)
		return 0;
	if (kunp_rcstruct_section(".text", MSF_ELF32_HDR, payload_n,
				  KUNP_PERM_R | KUNP_PERM_W | KUNP_PERM_X,
				  KOF_SECF_CODE | KOF_SECF_REBUILT) < 0)
		return 0;
	kunp_rcstruct_as(KOF_FMT_ELF, KOF_ARCH_X86, MSF_ELF32_BASE);
	if (!kunp_rcstruct_image())
		return 0;
	kunp_rcstruct_entry(MSF_ELF32_HDR);
	return kunp_rcstruct_at(MSF_ELF32_HDR);
}

/*
 * WHICH header a decoded payload gets, in one place.
 *
 * Every x86 decoder faces the same question and the answer is a property of the
 * object, not of the decoder: a payload peeled out of a PE is Windows shellcode
 * and belongs in a PE, one peeled out of an ELF is Linux shellcode and belongs
 * in an ELF. A formatless intermediate layer keeps the ELF answer, which is
 * what the ELF chain has always done.
 */
#include <kofanalyze/msf_pe.h>

static int msf_emit_hdr(const struct kof_obj_ctx *ctx, uint32_t payload_n)
{
	return MSF_RECON_PE(ctx) ? msf_emit_pe(ctx, payload_n, 32)
				 : msf_decl_elf32(ctx, payload_n);
}

#endif /* MSF_ELF32_H */
