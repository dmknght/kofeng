/*
 * pe_unmap.h - turn an image the LOADER mapped back into a PE file.
 *
 * NOT THE SAME JOB AS pe_rebuild.h, and the difference is why this is a second
 * entry point rather than a flag on the first.
 *
 * pe_rebuild is given what a PACKER left behind: a buffer that begins at the
 * first section's virtual address, with no MZ at the front and the original
 * header hidden somewhere inside. Nothing about that layout is known, so it
 * searches for a signature and takes the lowest section address as the origin.
 *
 * This is given what the WINDOWS LOADER produced, read back out of a process.
 * Everything about that layout is known exactly: the MZ is at offset 0, the PE
 * header is at e_lfanew, and buffer[x] is what is at RVA x. There is nothing to
 * search for and nothing to guess - and running pe_rebuild over one of these
 * gets every section wrong by the first section's RVA, silently, because its
 * origin assumption is the one thing that does not hold here.
 *
 *
 * WHY UN-MAPPING AT ALL, WHEN THE REGIONS ALREADY RESOLVE.
 *
 * enum kof_pe_layout made a mapped image's scan regions correct, so a rule that
 * names CODE reaches the code. That fixes WHERE and not WHAT: the loader also
 * CHANGED bytes on its way in. It applied base relocations, so every absolute
 * pointer in the image differs from the file by the load delta, and it filled
 * the import address table with addresses that exist only in that process.
 *
 * A signature whose literal crosses a relocated pointer therefore matches the
 * file and not the image - and there is no way to tell from the miss. Undoing
 * the relocations puts those bytes back to what the file had, which is what
 * makes the file corpus apply to memory rather than nearly apply.
 *
 * THE IAT IS LEFT AS THE LOADER WROTE IT. Restoring it means walking the import
 * descriptors and putting each thunk back to the name RVA it came from, which
 * is a rebuild rather than an undo, and the addresses it would remove are in a
 * small region that signatures do not target. Said here so the omission is a
 * decision rather than a gap somebody finds later.
 *
 *
 * WHAT IT IS FOR, since a loaded module's file is usually right there on disk.
 *
 * The cases where it is not: a reflectively loaded DLL that was never written
 * anywhere, a hollowed image whose file on disk is the innocent original, a
 * payload unpacked in place. In every one of those the mapped copy is the ONLY
 * copy, and this is what turns it into something the rest of the engine - the
 * unpackers, the format modules, a dump somebody wants to keep - can treat as
 * an ordinary file.
 */

#ifndef KOFENG_PE_UNMAP_H
#define KOFENG_PE_UNMAP_H

#include <stdint.h>

#include "../core/kofcore.h"

/*
 * What the un-map did, for a caller that reports rather than only scans.
 *
 * `relocs_undone` of zero with a non-zero `delta` means the image carries no
 * relocation table - which is true of most main executables - and the bytes were
 * copied as they were. That is a different thing from a delta of zero, where
 * there was nothing to undo, and the two are told apart here rather than left
 * to be inferred from a count.
 */
struct kof_pe_unmap_info {
	uint64_t image_base;      /* the preferred base that was USED */
	uint64_t hdr_image_base;  /* what the buffer's own header asks for */
	uint64_t mapped_at;       /* where it actually is, as the caller said */
	int64_t  delta;           /* mapped_at - image_base */
	uint32_t relocs_undone;
	uint32_t relocs_skipped;  /* a type this does not handle, or out of range */
	uint32_t sections;
	uint32_t sections_short;  /* fewer bytes in the buffer than declared */

	/* The caller supplied `preferred_base` and it is what `delta` rests on.
	 * Zero means the buffer's own header was the only source. */
	uint8_t  base_told;

	/*
	 * THE DELTA CAME OUT ZERO AND THAT MAY BE WRONG.
	 *
	 * Set when no preferred base was supplied, the header's base equals
	 * `mapped_at`, and the image DOES carry a relocation table. Those three
	 * together have two possible causes and this cannot tell them apart:
	 * the image loaded exactly where it asked to, or something rewrote the
	 * header's base to the address it ended up at - which is what the
	 * Windows loader does to every image it maps.
	 *
	 * In the first case nothing needed undoing. In the second every
	 * relocated pointer is still relocated and no count says so. A caller
	 * comparing this output against a file on disk must treat the
	 * difference as unexplained rather than as evidence: see
	 * kofmemscan's diff_module, which refuses to call it a patch.
	 */
	uint8_t  base_ambiguous;
	uint8_t  reserved[6];
};

/*
 * Un-map `img` into a PE file.
 *
 * `img` is the image as the loader laid it out, starting at the image base.
 * `mapped_at` is the address it was mapped at; pass 0 to copy the bytes without
 * touching relocations, which is the right answer when the address is not known
 * - a wrong delta would corrupt every relocated pointer, and a corrupted pointer
 * is worse than a relocated one because nothing downstream can tell.
 *
 *
 * `preferred_base` IS THE BASE THE FILE ASKS FOR, AND IT IS NOT OPTIONAL
 * INFORMATION FOR A LOADER-MAPPED IMAGE.
 *
 * Pass 0 and the buffer's own header is used, which is correct for an image
 * somebody mapped BY HAND - a reflective loader applies the relocations and
 * almost never bothers to rewrite the header - and silently wrong for anything
 * the WINDOWS LOADER mapped, because the loader writes the actual load address
 * into the mapped copy's ImageBase. Measured on this tree's build host, every
 * module in a live process:
 *
 *     module          loaded at        ImageBase in mem   ImageBase in file
 *     ntdll.dll       0x7ffdd22b0000   0x7ffdd22b0000     0x180000000
 *     KERNEL32.DLL    0x7ffdce760000   0x7ffdce760000     0x180000000
 *
 * So `mapped_at - hdr_image_base` is zero for all of them, the relocations are
 * never undone, and `relocs_undone` reports 0 while looking like the innocent
 * "this image carries no relocation table". That was the bug, and it is why
 * this argument exists rather than being derived: a caller holding the file -
 * which is every caller that is about to compare against it - already has the
 * one number that makes the delta right.
 *
 * When it cannot be known, `info->base_ambiguous` says so.
 *
 * On success *out is a malloc'd file the caller owns and *out_len its length.
 * Returns zero and touches neither when `img` does not hold a mapped PE, which
 * is the ordinary answer for a region that merely began with an MZ.
 *
 * `cap` bounds the file it will build, for the reason kof_pe_rebuild has one: a
 * section table can describe a file far larger than the image it came from, and
 * those numbers are attacker controlled.
 *
 * `info` may be NULL.
 */
int kof_pe_unmap(kof_buf img, uint64_t mapped_at, uint64_t preferred_base,
		 uint64_t cap, uint8_t **out, uint64_t *out_len,
		 struct kof_pe_unmap_info *info);

/*
 * The ImageBase a PE FILE asks for, read out of its header. 0 when `file` does
 * not hold a readable PE header.
 *
 * Here rather than in each caller because it is the companion to the argument
 * above: whoever has the file needs exactly this one field out of it, and every
 * caller working it out from its own header walk is another place to get the
 * PE32 versus PE32+ offset wrong.
 */
uint64_t kof_pe_file_image_base(kof_buf file);

#endif /* KOFENG_PE_UNMAP_H */
