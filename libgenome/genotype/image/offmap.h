/*
 * offmap.h - carrying an image's description through a transform that moves
 * bytes.
 *
 * A DERIVED OBJECT IS THE SAME IMAGE WITH SOME OF ITS BYTES TAKEN OUT (a
 * normalised view collapses zero runs, narrows wide text, cuts a library).
 * Everything the parse found is still TRUE of the program - where the entry is,
 * what the sections are, which functions there are - but every FILE OFFSET in
 * that description now points at the wrong place. Parsing the derived bytes
 * again cannot fix it: their header is the parent's header, byte for byte, and
 * it still says where things WERE. The description is carried instead: each file
 * offset in it goes through the transform's own boundary table.
 *
 * Two things here, and neither knows what the transform was:
 *
 *   the table      kgenome_offmap: sorted parent offsets and the offsets the
 *                  transform put them at. The transform fills `to` by walking
 *                  its own copy loop once, with `from` as the list of places it
 *                  was asked to report.
 *   the visitor    kgenome_{pe,elf}_info_offsets: hands every file offset the
 *                  description holds to a callback, as (offset, length) where
 *                  the field is an extent and with a NULL length where it is a
 *                  single position. ONE walk serves both halves - the caller
 *                  collects the places to ask about with it, and remaps with it
 *                  afterwards - so the two cannot disagree about which fields
 *                  are offsets. A new offset field is added in one place.
 *
 * RVAs, virtual addresses, sizes of the loaded image and flags are NOT file
 * offsets and are not visited: the view is not a loadable image, and nothing
 * that reads the carried description may pretend it is one. What needs a
 * loadable image is answered from the parent's analysis, not re-run on bytes
 * whose layout the transform changed.
 */
#ifndef KGENOME_IMAGE_OFFMAP_H
#define KGENOME_IMAGE_OFFMAP_H

#include <stdint.h>

struct kgenome_pe_info;
struct kgenome_elf_info;

struct kgenome_offmap {
	const uint64_t *from;   /* sorted, ascending, no duplicates             */
	const uint64_t *to;     /* what the transform made of each, same length */
	uint32_t        n;
	uint64_t        from_end;   /* size of the original                      */
	uint64_t        to_end;     /* size of the result                        */
};

/*
 * The offset in the result for an offset in the original. An offset that is
 * one of `from` answers exactly; one between two answers the nearer lower mark
 * plus the distance, held below the next mark; past the end answers to_end.
 */
uint64_t kgenome_offmap_at(const struct kgenome_offmap *m, uint64_t off);

/* One file offset (len == NULL) or one extent (off, len) of a description. */
typedef void (*kgenome_off_fn)(void *user, uint64_t *off, uint64_t *len);

void kgenome_pe_info_offsets(struct kgenome_pe_info *info, kgenome_off_fn fn, void *user);
void kgenome_elf_info_offsets(struct kgenome_elf_info *info, kgenome_off_fn fn, void *user);

/* The description, with every file offset carried through `m` in place. An
 * extent keeps its meaning: its new length is what lies between the two new
 * ends. */
void kgenome_pe_info_remap(struct kgenome_pe_info *info, const struct kgenome_offmap *m);
void kgenome_elf_info_remap(struct kgenome_elf_info *info, const struct kgenome_offmap *m);

#endif /* KGENOME_IMAGE_OFFMAP_H */
