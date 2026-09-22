/*
 * wrap.h - make a formatless blob into something a rule can be scoped to.
 *
 * A module that recovers raw machine code - a decoder's output, a payload lifted
 * out of a loader's variable - hands back bytes that are not a file. Every rule
 * declares a format and scopes itself to a region, so a blob is offered to no
 * module at all and the scan reports "no module targets this format". The
 * reconstruction is what makes it reachable.
 *
 * This is the GENERIC one: a minimal container built around bytes whose origin
 * is unknown. bases/unp/msf_elf32.h and msf_pe.h are the other kind - they put
 * back a SPECIFIC template that a known builder produced, and where one of those
 * applies it is the better answer, because it is a reconstruction of something
 * that existed rather than a container invented to hold something.
 *
 * Neither claims the file was ever on disk. See the note in msf_pe.h, which says
 * it first and says it well.
 *
 * IT LIVED IN kofviewer.c. A tool built the header so its own pane could show
 * the payload as an object, which meant the SCANNER never saw that object at
 * all: the engine located the payload, reported its offset as a debug fact, and
 * stopped. The bytes were never scanned by anything. Here, an unpacker emits it
 * and every front end gets the same object for free.
 */
#ifndef KOFENG_WRAP_H
#define KOFENG_WRAP_H

#include "kofsig.h"

/*
 * A PSEUDO ELF HEADER IN FRONT OF THE PAYLOAD.
 *
 * WHY. Without one the payload is a formatless blob, and the scanner says so:
 * "SKIPPED - no module targets this format". Every rule declares a format and
 * scopes itself to a region, so a blob matches nothing and is not even offered
 * to a module. A header is what makes the payload reachable - it is not a
 * claim that a file like this ever existed, exactly as bases/unp/msf_pe.h says
 * of its own reconstruction.
 *
 * THE PAYLOAD GOES IN A WRITABLE, NON-EXECUTABLE SEGMENT, so it lands in region
 * DATA. Three measured reasons, and the first is the one that matters:
 *
 *  - In the PARENT the payload is in .data, so region DATA. One DATA-scoped
 *    rule then reaches both: the un-encoded payload sitting in the loader's
 *    variable, and the decoded payload here. Nine of twelve samples measured
 *    are already matchable in the parent that way, with no reconstruction.
 *  - An entry point inside a non-executable segment raises
 *    KOF_ELF_ANOM_ENTRY_NOT_EXEC, which kof_emu_unp_gate reads as "unloadable"
 *    and would hand every reconstructed child to the interpreter for nothing.
 *    ET_DYN with e_entry 0 raises nothing: an image with no entry point is what
 *    a blob lifted out of a variable IS.
 *  - An RWX segment with the entry on it lands the payload in CODE and is
 *    byte-for-byte the shape bases/heur/shellcode_00.c looks for - no section
 *    table, one program header, one executable PT_LOAD that is the whole file.
 *    Measured: the engine flags its own reconstruction as an msfvenom template.
 *
 * p_filesz MUST NOT EXCEED WHAT IS WRITTEN, or KOF_ELF_ANOM_SEG_PAST_EOF fires
 * and kofheur scores it "Truncated" - the engine detecting its own output.
 * p_memsz may be larger; that is what .bss is. Measured both ways.
 *
 * The width follows the PAYLOAD, not the parent - a 64-bit loader routinely
 * carries 32-bit Windows shellcode - so the caller passes what it read off the
 * payload itself.
 */
/* The most header bytes kof_wrap_elf can write, so a caller can size a buffer
 * without knowing which class it will pick. */
#define KOF_WRAP_ELF_MAX 120u

#define KOF_WRAP_EH64 64u
#define KOF_WRAP_PH64 56u
#define KOF_WRAP_EH32 52u
#define KOF_WRAP_PH32 32u

static void kof_wrap_put(uint8_t *p, uint64_t v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

/*
 * Write the header for `n` payload bytes into `out` (at least 120 bytes) and
 * return its length. `bits` is 32 or 64 and decides ELF32 against ELF64 - not
 * cosmetic, because the collector reads the class to set the object's
 * architecture, and an x86 payload described as ELF64 would be disassembled as
 * amd64.
 */
static uint32_t kof_wrap_elf(uint8_t *out, uint32_t n, unsigned bits)
{
	int b64 = bits != 32;
	uint32_t eh = b64 ? KOF_WRAP_EH64 : KOF_WRAP_EH32;
	uint32_t ph = b64 ? KOF_WRAP_PH64 : KOF_WRAP_PH32;
	uint32_t hdrs = eh + ph;
	uint8_t *p;
	uint32_t k;

	for (k = 0; k < hdrs; k++)
		out[k] = 0;
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = b64 ? 2u : 1u;         /* ELFCLASS64 / ELFCLASS32 */
	out[5] = 1;                     /* ELFDATA2LSB             */
	out[6] = 1;                     /* EV_CURRENT              */
	kof_wrap_put(out + 16, 3, 2);       /* ET_DYN - see the note   */
	kof_wrap_put(out + 18, b64 ? 0x3eu : 3u, 2);   /* x86-64 / i386 */
	kof_wrap_put(out + 20, 1, 4);       /* EV_CURRENT              */
	/* e_entry stays 0. e_shoff and e_shnum stay 0: there is no section
	 * table, and inventing one would be inventing bytes. */
	/*
	 * The offsets, and they are worth spelling out because getting them
	 * wrong is silent. Written two bytes late at first - 54/56/58 for
	 * ELF64 instead of 52/54/56 - so the parser read e_phentsize as 64 and
	 * e_phnum as 56: fifty-six program headers of sixty-four bytes, far
	 * past the end of a 203-byte file. It still identified as ELF-x64, and
	 * the whole object came back as one HEADERS region with no DATA at all.
	 *
	 *   ELF64  e_phoff 32(8)  e_ehsize 52(2)  e_phentsize 54(2)  e_phnum 56(2)
	 *   ELF32  e_phoff 28(4)  e_ehsize 40(2)  e_phentsize 42(2)  e_phnum 44(2)
	 */
	kof_wrap_put(out + (b64 ? 32u : 28u), eh, b64 ? 8u : 4u);   /* e_phoff */
	kof_wrap_put(out + (b64 ? 52u : 40u), eh, 2);               /* e_ehsize */
	kof_wrap_put(out + (b64 ? 54u : 42u), ph, 2);               /* e_phentsize */
	kof_wrap_put(out + (b64 ? 56u : 44u), 1, 2);                /* e_phnum */

	p = out + eh;
	kof_wrap_put(p + 0, 1, 4);                  /* PT_LOAD */
	if (b64) {
		kof_wrap_put(p + 4,  6, 4);         /* p_flags = RW */
		kof_wrap_put(p + 8,  0, 8);         /* p_offset */
		kof_wrap_put(p + 16, 0, 8);         /* p_vaddr  */
		kof_wrap_put(p + 24, 0, 8);         /* p_paddr  */
		kof_wrap_put(p + 32, hdrs + n, 8);  /* p_filesz - exactly the file */
		kof_wrap_put(p + 40, hdrs + n, 8);  /* p_memsz  */
		kof_wrap_put(p + 48, 0x1000, 8);    /* p_align  */
	} else {
		kof_wrap_put(p + 4,  0, 4);         /* p_offset */
		kof_wrap_put(p + 8,  0, 4);         /* p_vaddr  */
		kof_wrap_put(p + 12, 0, 4);         /* p_paddr  */
		kof_wrap_put(p + 16, hdrs + n, 4);  /* p_filesz */
		kof_wrap_put(p + 20, hdrs + n, 4);  /* p_memsz  */
		kof_wrap_put(p + 24, 6, 4);         /* p_flags = RW */
		kof_wrap_put(p + 28, 0x1000, 4);    /* p_align  */
	}
	return hdrs;
}

#endif /* KOFENG_WRAP_H */
