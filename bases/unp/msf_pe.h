/*
 * msf_pe.h - put a PE header back in front of a decoded Windows payload.
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
 */

#ifndef MSF_PE_H
#define MSF_PE_H

#include <kofmod/kofsig.h>

/*
 * The layout, chosen so every offset below is a constant a reader can check:
 *
 *   0x000  DOS header, e_lfanew = 0x40
 *   0x040  "PE\0\0"
 *   0x044  COFF header, 20 bytes
 *   0x058  optional header, 0xe0 (PE32) or 0xf0 (PE32+)
 *   0x138  one section header, 40 bytes            (PE32; 0x148 for PE32+)
 *   0x200  the payload, at RVA 0x1000
 *
 * SizeOfHeaders is rounded to FileAlignment, which is what puts the payload at
 * 0x200 in both widths and keeps the two layouts identical from there on.
 */
#define MSF_PE_FALIGN   0x200u
#define MSF_PE_SALIGN   0x1000u
#define MSF_PE_HDR      0x200u          /* file offset of the payload      */
#define MSF_PE_RVA      0x1000u         /* and its RVA                     */
#define MSF_PE_BASE32   0x400000u
#define MSF_PE_BASE64   0x140000000ull

static void msf_pe_put16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void msf_pe_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void msf_pe_put64(uint8_t *p, uint64_t v)
{
	msf_pe_put32(p, (uint32_t)v);
	msf_pe_put32(p + 4, (uint32_t)(v >> 32));
}

/*
 * Emit the 0x200-byte header for a payload of `payload_n` bytes. `bits` is 32
 * or 64 and decides PE32 against PE32+ - which is not cosmetic, because the
 * collector reads the magic to set the object's architecture, and an x64
 * payload described as PE32 would be disassembled and prefiltered as i386.
 *
 * Returns what kof_emit returns, so a caller stops if the host has stopped
 * taking bytes. Emit this, then the payload, then kof_child().
 */
static int msf_emit_pe(const struct kof_obj_ctx *ctx, uint32_t payload_n,
		       unsigned bits)
{
	uint8_t h[MSF_PE_HDR];
	uint8_t *pe, *coff, *opt, *sec;
	uint32_t optsz = bits == 64 ? 0xf0u : 0xe0u;
	uint32_t vsz = (payload_n + MSF_PE_SALIGN - 1u) & ~(MSF_PE_SALIGN - 1u);
	uint32_t rsz = (payload_n + MSF_PE_FALIGN - 1u) & ~(MSF_PE_FALIGN - 1u);
	unsigned k;

	(void)ctx;                           /* kof_emit reads it through the macro */
	for (k = 0; k < MSF_PE_HDR; k++)
		h[k] = 0;

	/* The DOS stub is not reproduced: nothing reads it, and a made-up one
	 * would be bytes this module never saw. The two fields a PE loader and
	 * every parser actually use are the magic and e_lfanew. */
	h[0] = 'M'; h[1] = 'Z';
	msf_pe_put32(h + 0x3c, 0x40);

	pe = h + 0x40;
	pe[0] = 'P'; pe[1] = 'E'; pe[2] = 0; pe[3] = 0;

	coff = pe + 4;
	msf_pe_put16(coff + 0, bits == 64 ? 0x8664u : 0x014cu);  /* Machine   */
	msf_pe_put16(coff + 2, 1);                               /* sections  */
	msf_pe_put16(coff + 16, (uint32_t)optsz);                /* opt size  */
	/* EXECUTABLE_IMAGE, plus 32BIT_MACHINE for PE32 - the pair a loader
	 * checks before it maps anything. */
	msf_pe_put16(coff + 18, bits == 64 ? 0x0022u : 0x0102u);

	opt = coff + 20;
	msf_pe_put16(opt + 0x00, bits == 64 ? 0x020bu : 0x010bu);  /* Magic     */
	msf_pe_put32(opt + 0x04, rsz);                             /* SizeOfCode */
	msf_pe_put32(opt + 0x10, MSF_PE_RVA);                      /* entry     */
	msf_pe_put32(opt + 0x14, MSF_PE_RVA);                      /* BaseOfCode */
	if (bits == 64) {
		msf_pe_put64(opt + 0x18, MSF_PE_BASE64);
		msf_pe_put32(opt + 0x20, MSF_PE_SALIGN);
		msf_pe_put32(opt + 0x24, MSF_PE_FALIGN);
		msf_pe_put16(opt + 0x30, 5);           /* MajorSubsystemVersion */
		msf_pe_put32(opt + 0x38, MSF_PE_RVA + vsz);   /* SizeOfImage    */
		msf_pe_put32(opt + 0x3c, MSF_PE_HDR);         /* SizeOfHeaders  */
		msf_pe_put16(opt + 0x44, 3);           /* Subsystem = CONSOLE   */
		msf_pe_put32(opt + 0x6c, 16);          /* NumberOfRvaAndSizes   */
	} else {
		/* PE32 keeps BaseOfData where PE32+ has none, so every field
		 * from ImageBase on sits four bytes later. */
		msf_pe_put32(opt + 0x18, MSF_PE_RVA + vsz);   /* BaseOfData     */
		msf_pe_put32(opt + 0x1c, MSF_PE_BASE32);
		msf_pe_put32(opt + 0x20, MSF_PE_SALIGN);
		msf_pe_put32(opt + 0x24, MSF_PE_FALIGN);
		msf_pe_put16(opt + 0x30, 5);
		msf_pe_put32(opt + 0x38, MSF_PE_RVA + vsz);
		msf_pe_put32(opt + 0x3c, MSF_PE_HDR);
		msf_pe_put16(opt + 0x44, 3);
		msf_pe_put32(opt + 0x5c, 16);
	}

	sec = opt + optsz;
	/*
	 * ".text", not the template's random eight letters. The name msfvenom
	 * generates is different in every sample - .yvgw, .srmp, .icdn in the
	 * three read here - so it carries no information, and a reconstruction
	 * that invented one of them would look like a fact. ".text" says what
	 * the section IS.
	 */
	sec[0] = '.'; sec[1] = 't'; sec[2] = 'e'; sec[3] = 'x'; sec[4] = 't';
	msf_pe_put32(sec + 0x08, vsz);            /* VirtualSize             */
	msf_pe_put32(sec + 0x0c, MSF_PE_RVA);     /* VirtualAddress          */
	msf_pe_put32(sec + 0x10, rsz);            /* SizeOfRawData           */
	msf_pe_put32(sec + 0x14, MSF_PE_HDR);     /* PointerToRawData        */
	/* CODE | EXECUTE | READ | WRITE - the RWX the template's own payload
	 * section carries, and what a self-modifying decoder needs. */
	msf_pe_put32(sec + 0x24, 0xe0000020u);

	return kof_emit(h, MSF_PE_HDR);
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
