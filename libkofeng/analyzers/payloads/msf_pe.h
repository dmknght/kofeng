/*
 * msf_pe.h - say what PE a decoded Windows payload is, and let the engine write it.
 *
 * The Windows counterpart of msf_elf32.h, and it exists for the same reason: a
 * decoder that emits the payload alone hands back a formatless blob - real
 * machine code, but not a file, so no signature scoped to a PE region can run
 * on it. msfvenom does not compile these either; it injects the payload into a
 * fixed template EXE and points the entry point at it, so the honest
 * reconstruction is a PE whose one executable section IS the payload and whose
 * entry point is its first byte. `win_x86_clear` in the sample set is the
 * reference: the payload built with no encoder sits in a random-named RWX
 * section at RVA 0x5000, and the entry point is that RVA.
 *
 * WHAT IS NOT CLAIMED: that a file like this was ever on disk. It was not - the
 * template with the encoded payload in it was. The reconstruction is what the
 * loader would have jumped to, expressed as the PE its outermost layer is.
 *
 * WHY NOT REPRODUCE THE TEMPLATE. The template is 7KB of unrelated import
 * tables, .rdata and .reloc that say nothing about the payload, and copying
 * bytes this module never read would be inventing them. One section holding
 * exactly what was decoded is the whole of what is known.
 *
 *
 * IT USED TO WRITE THE HEADER ITSELF - a hundred and thirty lines assembling
 * 0x200 bytes of DOS header, COFF header, optional header and one section
 * header field by field, handed over with kunp_rcstruct_write like any other
 * content. msf_elf32.h beside it stopped doing that and this did not, and the
 * round trip is exactly what the declaration mechanism exists to end: nothing
 * in the engine knew those 0x200 bytes were a header, so the child's first
 * page was content like the rest and the layout this file knew exactly had to
 * be recovered by parsing back what this file had just written. Every loss
 * `section` in kofsig.h lists applied - the section was REBUILT and said
 * READ, and the fact that the engine had reconstructed it was gone.
 *
 * WHAT HELD IT UP, because it is worth knowing that the obstacle was real and
 * where it was: the engine's PE header writer took machine, width and image
 * base from the PARENT's parse and ignored what a module declared with
 * kunp_rcstruct_as - the ELF arm read them and the PE arm did not. msfvenom's
 * 64-bit Windows payload is routinely carried by a PE32 template, so declaring
 * would have described an x64 payload as i386, which is worse than the round
 * trip: the architecture is a precondition every signature is filtered by. The
 * engine now honours the declaration; see the note beside it in objctx.c.
 */

#ifndef MSF_PE_H
#define MSF_PE_H

#include <kofmod/kofsig.h>

/*
 * The layout. Only two numbers are this file's to choose now - where the
 * payload sits and what it is loaded at - because the rest is the writer's:
 *
 *   0x000  the header, whatever the engine needs for it
 *   0x1000 the payload, at RVA 0x1000, file offset equal to RVA
 *
 * FILE OFFSET EQUALS RVA, which is what declaring a section at MSF_PE_RVA and
 * writing there means. The engine's writer sets FileAlignment to
 * SectionAlignment for exactly this reason - see kof_pe_write_hdr - so the
 * file and the image have one shape and no translation step exists to undo
 * itself.
 */
#define MSF_PE_RVA      0x1000u         /* the payload's RVA, and its offset */
#define MSF_PE_BASE32   0x400000u
#define MSF_PE_BASE64   0x140000000ull

/*
 * DECLARE the PE a payload of `payload_n` bytes is to become. Returns 0 when
 * the host refused, so a caller stops.
 *
 * Call this, then write the payload, then kunp_rcstruct_done().
 *
 * `bits` is 32 or 64 and is the PAYLOAD's width, not the parent's - see the
 * note at the top about why that distinction cost this file its conversion.
 *
 * WHAT IS DECLARED. One section holding the payload at MSF_PE_RVA,
 * readable-writable-executable because that is what msfvenom's own template
 * gives its payload section and what a self-modifying decoder needs, and
 * REBUILT because these bytes were recovered rather than read. The entry point
 * is the payload's first byte.
 *
 * ".text", not the template's random eight letters. The name msfvenom
 * generates is different in every sample - .yvgw, .srmp, .icdn in the three
 * read here - so it carries no information, and a reconstruction that invented
 * one of them would look like a fact. ".text" says what the section IS.
 */
static int msf_decl_pe(const struct kof_obj_ctx *ctx, uint32_t payload_n,
		       unsigned bits)
{
	if (!payload_n)
		return 0;
	if (kunp_rcstruct_section(".text", MSF_PE_RVA, payload_n,
				  KUNP_PERM_R | KUNP_PERM_W | KUNP_PERM_X,
				  KOF_SECF_CODE | KOF_SECF_REBUILT) < 0)
		return 0;
	kunp_rcstruct_as(KOF_FMT_PE,
			 bits == 64 ? KOF_ARCH_X86_64 : KOF_ARCH_X86,
			 bits == 64 ? MSF_PE_BASE64 : MSF_PE_BASE32);
	if (!kunp_rcstruct_image())
		return 0;
	kunp_rcstruct_entry(MSF_PE_RVA);
	return kunp_rcstruct_at(MSF_PE_RVA);
}

/*
 * Which reconstruction this object's payload wants, decided by what the object
 * IS rather than by a flag each decoder would have to be told.
 *
 * One place, because every decoder faces the same question and the answer is
 * the same: a payload peeled out of a PE is Windows shellcode and belongs in a
 * PE, one peeled out of an ELF is Linux shellcode and belongs in an ELF. A
 * formatless intermediate layer keeps the ELF answer, which is what the ELF
 * chain has always done - see the note on stub_in_buf about only the LAST layer
 * being reconstructed at all.
 */
#define MSF_RECON_PE(ctx) ((ctx)->format == KOF_FMT_PE)

#endif /* MSF_PE_H */
