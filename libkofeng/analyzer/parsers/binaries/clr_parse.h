/*
 * clr_parse.h - read the CLI metadata of an assembly, whoever is carrying it.
 *
 * HOST-AGNOSTIC ON PURPOSE, and that is the whole reason it is a file of its
 * own rather than thirty lines inside pe_parse.c.
 *
 * A managed assembly is a PE - ECMA-335 says so, and that holds for Mono on
 * Linux as much as for Windows. But the PE is not always the outermost thing:
 * an ELF single-file bundle carries assemblies, mkbundle embeds them, an AMSI
 * submission hands one over, and a byte array in somebody's heap holds one that
 * was never a file. The metadata is byte-identical in every one of those.
 *
 * So this takes a buffer, one offset, and a way to translate an RVA. PE finds
 * the offset in its COM descriptor directory and calls in; anything else that
 * learns to find it calls the same function and gets the same answer, and there
 * is no second implementation to drift.
 *
 *
 * IT DOES NOT WALK THE TABLES, and that is a boundary rather than a gap.
 *
 * "#~" holds the rows - types, methods, the RVA of every method body - and
 * indexing one needs the heap-size flags plus the row count of every table
 * present before it, because the row WIDTH depends on them. That is the pass an
 * eventual look at IL will need. Naming where the heaps are does not need it,
 * and what a rule usually wants - a type name, a literal, an embedded blob - is
 * in the heaps rather than in the rows.
 */
#ifndef KOF_CLR_PARSE_H
#define KOF_CLR_PARSE_H

#include "../../core/kofcore.h"
#include "../../core/kofmod/clr.h"
/* For struct kof_rlist and struct kof_range: the two shapes a host already
 * speaks when it settles ownership and resolves regions. */
#include "../rangelist.h"

/*
 * Turn an RVA into an offset in the object, or KOF_BROKEN.
 *
 * The ONE thing this file cannot do for itself: it depends on the host's
 * section table, and a file on disk and an image the loader mapped answer it
 * differently - see enum kof_pe_layout. A field whose RVA resolves nowhere is
 * left empty rather than guessed at.
 */
typedef uint64_t (*kof_clr_rva)(const void *user, uint64_t rva);

/*
 * Read the metadata that the CLI header at `clr_off` describes.
 *
 * `obj` is the whole object and `clr_off` is object-relative - the first byte
 * of the 72-byte CLI header, the one holding `cb`. Everything in *out comes
 * back object-relative too, and already clipped to `obj`.
 *
 * Returns non-zero when a metadata root was found. Zero leaves *out zeroed,
 * which reads as "not a managed image" through kof_clr_present.
 */
int kof_clr_read(kof_buf obj, uint64_t clr_off, kof_clr_rva rva,
		 const void *user, struct kof_clr_meta *out);

/*
 * Append the CLI ranges `mask` names to `l`.
 *
 * Separate from the read because a host has to settle OWNERSHIP before it
 * resolves: the heaps sit inside one of its sections, so whoever owns the
 * object must rank them above that section or the same offset lands in two
 * regions and the partition is gone.
 */
void kof_clr_add_ranges(const struct kof_clr_meta *m, uint32_t mask,
			struct kof_rlist *l, uint64_t obj_size);

/*
 * Every byte the metadata claims, as one list, for a host settling ownership.
 *
 * Returns how many entries were written, at most KOF_CLR_CLAIM_MAX.
 */
#define KOF_CLR_CLAIM_MAX 7u

uint32_t kof_clr_claims(const struct kof_clr_meta *m, struct kof_range *out,
			uint32_t cap);

#endif /* KOF_CLR_PARSE_H */
