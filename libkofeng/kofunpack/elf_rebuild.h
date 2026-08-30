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

#endif /* KOFENG_ELF_REBUILD_H */
