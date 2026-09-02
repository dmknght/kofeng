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

static void msf_elf32_put(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * Emit the 0x54-byte header for a payload of `payload_n` bytes. Returns what
 * kof_emit returns, so a caller stops if the host has stopped taking bytes.
 * Emit this, then the payload, then kof_child().
 */
static int msf_emit_elf32(const struct kof_obj_ctx *ctx, uint32_t payload_n)
{
	uint8_t h[MSF_ELF32_HDR];
	uint8_t *ph = h + 0x34;              /* the program header */
	uint32_t total = MSF_ELF32_HDR + payload_n;
	unsigned k;

	(void)ctx;                           /* kof_emit reads it through the macro */
	for (k = 0; k < MSF_ELF32_HDR; k++)
		h[k] = 0;
	h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
	h[4] = 1;                            /* ELFCLASS32                       */
	h[5] = 1;                            /* ELFDATA2LSB                      */
	h[6] = 1;                            /* EV_CURRENT                       */
	h[0x10] = 2;                         /* ET_EXEC                          */
	h[0x12] = 3;                         /* EM_386                           */
	h[0x14] = 1;                         /* e_version                        */
	msf_elf32_put(h + 0x18, MSF_ELF32_BASE + MSF_ELF32_HDR); /* e_entry      */
	msf_elf32_put(h + 0x1c, 0x34);       /* e_phoff                          */
	/* e_shoff stays zero: the template carries no section table. */
	h[0x28] = 0x34;                      /* e_ehsize   (52)                  */
	h[0x2a] = 0x20;                      /* e_phentsize (32)                 */
	h[0x2c] = 1;                         /* e_phnum                          */

	ph[0x00] = 1;                        /* p_type  = PT_LOAD                */
	msf_elf32_put(ph + 0x04, 0);         /* p_offset                         */
	msf_elf32_put(ph + 0x08, MSF_ELF32_BASE);  /* p_vaddr                    */
	msf_elf32_put(ph + 0x0c, MSF_ELF32_BASE);  /* p_paddr                    */
	msf_elf32_put(ph + 0x10, total);     /* p_filesz                         */
	/*
	 * p_memsz = p_filesz. The template pads memsz past filesz - x86_clear
	 * asks for 0x14a of image for 0xcf of file - and the padding is a
	 * constant of the template, not anything derived from the payload, so
	 * copying it would be inventing a number. Against x86_clear this
	 * reconstruction differs in these four bytes and in nothing else.
	 */
	msf_elf32_put(ph + 0x14, total);     /* p_memsz                          */
	ph[0x18] = 7;                        /* p_flags = RWX                    */
	msf_elf32_put(ph + 0x1c, 0x1000);    /* p_align                          */
	return kof_emit(h, MSF_ELF32_HDR);
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
#include "msf_pe.h"

static int msf_emit_hdr(const struct kof_obj_ctx *ctx, uint32_t payload_n)
{
	return MSF_RECON_PE(ctx) ? msf_emit_pe(ctx, payload_n, 32)
				 : msf_emit_elf32(ctx, payload_n);
}

#endif /* MSF_ELF32_H */
