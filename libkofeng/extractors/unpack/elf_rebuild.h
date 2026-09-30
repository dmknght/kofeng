/*
 * elf_rebuild.h - turn an unpacked ELF image back into an ELF file.
 *
 * The same job pe_rebuild.h does, arrived at from the other direction and for
 * the same reason: what a run of a packed program leaves behind is the IMAGE -
 * segments sitting at their virtual addresses, scattered across whatever the
 * stub happened to map - and an image is not a file. Measured on one sample the
 * emulator unpacks correctly: six separate memory regions came back, the parser
 * recognised ELF in the one holding the header and reported "sections 0 of 25"
 * because the section table is in a different region, and the 2.1 MB region
 * that holds the actual code identified as nothing at all. Raw bytes are enough
 * for a literal string and enough for nothing else - no format, no region
 * partition, so no signature scoped to CODE or DATA can ever run on it.
 *
 * The static unpacker for the same file hands back one 2 854 912-byte file that
 * partitions into HEADERS, CODE, DATA and NOLOAD. That is the difference this
 * closes, and it is why an emulator that recovers the right bytes can still be
 * worth less to a scanner than a static unpacker that recovers the same ones.
 *
 * WHAT IT IS GIVEN
 *
 * Not a buffer - an address space, through a read callback. That is the honest
 * interface for this producer: the segments are not contiguous and the gaps
 * between them are not part of the file, so handing over "the image" would mean
 * inventing a buffer that never existed. The caller says where the ELF header
 * is and answers reads by virtual address; everything else is read out of the
 * program headers the guest itself built.
 *
 * Every field read here is attacker controlled. The rebuilt file is bounded by
 * what could actually be read rather than by what the header claims, and a
 * header that does not describe something loadable is refused rather than
 * repaired.
 */

#ifndef KOFENG_ELF_REBUILD_H
#define KOFENG_ELF_REBUILD_H

#include <stdint.h>

#include "pe_rebuild.h"   /* struct kof_sec_decl - the declaration both writers take */

/*
 * Answer a read of `n` bytes at virtual address `va`. Non-zero on success; a
 * short or unmapped read must return zero rather than a partial buffer.
 */
typedef int (*kof_elf_rebuild_rd)(void *user, uint64_t va, void *dst,
				  uint32_t n);

/*
 * Rebuild the ELF whose header sits at `base` into a file.
 *
 * On success *out is a malloc'd file the caller owns and *out_len its length.
 * Returns zero and touches neither when there is nothing rebuildable at `base`,
 * which is the ordinary answer for a region that merely happens to start with
 * the magic.
 *
 * `cap` bounds the file produced; zero takes a built-in ceiling.
 *
 * `covered_lo`/`covered_hi`, when not NULL, come back holding the span of
 * virtual addresses the rebuilt file accounts for, so a caller emitting several
 * images can tell which of them this one has already spoken for.
 */
int kof_elf_rebuild(uint64_t base, kof_elf_rebuild_rd rd, void *user,
		    uint64_t cap, uint8_t **out, uint64_t *out_len,
		    uint64_t *covered_lo, uint64_t *covered_hi);

/*
 * ---- THE OTHER DIRECTION: A HEADER FROM A DECLARED LAYOUT -------------------
 *
 * kof_elf_rebuild above reads structure out of what a run left behind. This is
 * what a module needs when there is no structure to read: a decoder hands back
 * SHELLCODE - machine code with nothing in front of it - and shellcode is not a
 * file. Nothing identifies it, no region partition is possible, and every rule
 * scoped to CODE is silently inapplicable to it.
 *
 * WHY THE ENGINE WRITES IT AND NOT THE MODULE. Three msfvenom decoders used to
 * assemble these fifty-two bytes themselves, byte by byte, out of a header file
 * they shared - which is the round trip `section` in kofsig.h exists to end: the
 * module knows its layout exactly and had one way to say it, by synthesising a
 * header for the engine to parse back. A module declares now, and the engine
 * writes; the same split pe_rebuild.h has.
 *
 * ONE PT_LOAD OVER THE WHOLE FILE, and that is not a simplification of what a
 * real ELF does - it is what msfvenom's own template does, and it is the only
 * honest answer for a payload whose internal structure nobody knows. The
 * permissions are the OR of the declared sections'.
 *
 * `base` is where the image is to be loaded; `entry_rva` is relative to it, as
 * every declared address is. Returns the bytes written, or 0 - which includes
 * the case of a header that will not fit in front of the first section, because
 * a caller that laid its content out too tightly must be told rather than
 * allowed to overwrite it.
 */
/*
 * `has_entry` is whether the producer DECLARED an entry point, and it decides
 * e_type: ET_EXEC with the entry in it when one was declared, ET_DYN with
 * e_entry 0 when none was. A blob lifted out of a variable has no entry point,
 * and saying ET_EXEC of it would be a claim the parser correctly objects to.
 */
uint64_t kof_elf_write_hdr(uint8_t *out, uint64_t cap, int is64,
			   uint16_t machine, uint64_t base,
			   const struct kof_sec_decl *sec, uint32_t n,
			   uint64_t entry_rva, int has_entry,
			   uint64_t image_end);

#endif /* KOFENG_ELF_REBUILD_H */
