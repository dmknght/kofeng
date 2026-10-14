/*
 * kofregion.h - which part of an object a module searches: the region masks,
 * the extent bound, and the measured shape of a region.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFREGION_H
#define KOFENG_KOFREGION_H

#include <stdint.h>

/*
 * Which part of the object to search.
 *
 * A module names a region and never computes a range, which removes the class of bug
 * where an expression like "sec->file_size - 0x40" underflows on a small section.
 *
 * Only KOF_SCAN_ALL is defined here: it is the only region that means the same thing
 * for every input. The rest are named by the format header, because the parts of an
 * object are a property of its format - ELF has three header structures at both ends
 * of the file, a PE has a DOS stub and NT headers, and one shared "header" name
 * would have to be re-read as something different per format.
 *
 * Each format numbers its own bits from 1, so values collide between formats. Safe
 * for the same reason the kof_elf() cast is safe: naming KOF_SCAN_ELF_* requires
 * including elf.h, and the build rejects a module that includes a format header
 * without declaring that format as its target.
 *
 * Region ids are bits, so they compose: KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA is the
 * union. The host resolves a mask to ranges sorted and coalesced, so a pattern lying
 * across the join between two adjacent regions is found. A format should define its
 * regions as a partition of the object; then OR-ing any set of bits scans no byte
 * twice and leaves none unreachable. Bits with no region behind them are ignored,
 * because the mask reaches the host as bytes out of a database.
 *
 * The ranges are filled by whichever parser identified the object, since working out
 * where the code is is format specific work and the parser already has the tables.
 */

/* A resolved range: struct kof_range, defined in core (<range.h>, included at
 * the top of this file). */

/*
 * Resolving a mask produces a list of ranges, not one range: a single bounding range
 * was measured at 89% of the file for data on a modern four-load layout, which made
 * it a superset of code.
 *
 * Nothing is stored. Ranges are computed from the parsed segment and section tables
 * on each call - those are already resident and hold every fact needed, so a stored
 * copy would be a cache able to disagree with its source. Computing also lets the
 * buffer be sized to the format's worst case, so extents are never merged to fit.
 *
 * This is the bound on that buffer. A resolver that would exceed it must coalesce,
 * never drop: overshooting a range loses precision, dropping one loses a detection.
 */
/*
 * How many extents a region resolve starts with room for.
 *
 * NOT A LIMIT ON WHAT A REGION MAY HOLD, any more. It was: 256, which is ample for an
 * executable - an ELF's CODE is a handful of ranges - and nowhere near enough for an archive,
 * so it became 4096, and a zip of 2100 entries still did not fit it (a zip stores each name
 * between two pieces of header, twice over, so its NAMES region is two extents an entry: 4200)
 * and lost every member to the report that said so. How many extents a region has is a
 * property of the FILE.
 *
 * So this is the size of the buffers the scanner owns (see kof_scan_cache; they live in the
 * scanner and not on the stack, which is what makes a number this large affordable) and of
 * the resolves that cannot grow - a tool's, which has no ledger. The scanner's own buffer is
 * grown when a resolve fills it (scanners/scan_ext.c), up to one extent a byte of the
 * object, charged to the per-object ledger and given back with the object; a region the
 * ledger cannot afford is cut, the object is reported cut, and nothing is searched in part
 * without saying so.
 */
#define KOF_SCAN_MAX_EXTENTS 4096

/* The whole object. The host answers this without a parser, so a module naming only
 * this region works on input nothing has identified. */
#define KOF_SCAN_ALL (1u << 0)

/*
 * THE SYMBOL RECORDS, IN TWO HALVES - and unlike every region above, these are
 * not bytes of the file.
 *
 * kof_syms() hands back a block the host BUILT while parsing and cached for the
 * object (see kof_scanner). Naming it here is what lets a signature match a
 * symbol rather than match some bytes that happen to spell one, which is the
 * whole reason the KSYM layout exists: "inflateEnd" searched in DATA is any
 * occurrence of that string anywhere in the data, and searched in SYM_EXP it is
 * the claim that this file EXPORTS inflateEnd. The second is a far narrower
 * statement about the same ten bytes, and narrower is what a signature is for.
 *
 * Shared like KOF_SCAN_ALL rather than named per format, and for the same
 * reason: the block means the same thing for every input that has one. Both
 * builders fill one layout, so a rule scoped to SYM_IMP reads an ELF undefined
 * symbol and a PE import as the one claim they both are.
 *
 * FROM THE TOP, because format regions number upward from bit 1 and these must
 * never collide with a region a format adds later. The highest bit a format
 * uses today is 9 - PDF, whose stream regions are split by what the bytes ARE
 * rather than by how they are coded. It was 7 when this was written, so the
 * number is worth re-reading rather than trusting.
 *
 * The split is on KOF_SYM_F_UNDEFINED, and the extents cover the symbols' POOL
 * ENTRIES only (the four attribute bytes, the whole name, its NUL - see
 * KOF_SYM_KEYLEN) - the block's own header and the record table are not searched.
 * The count and `_start` index change with the file, and the numeric fields with
 * every build, so a pattern over them would be matching the host's bookkeeping
 * or one binary's addresses rather than anything the object says.
 */
/*
 * A FILE THIS OBJECT CARRIES AS A FILE - SHARED, BECAUSE IT IS NOT ONE
 * FORMAT'S IDEA.
 *
 * A PDF attaches an executable through /EF. A doczip IS a zip and every entry
 * in it is a carried file. An ELF can hold another ELF that a compiler put
 * there. The containers have nothing in common and the question does: "is this
 * a passenger rather than part of the document", and a rule that wants
 * passengers should not have to name one region per format to ask.
 *
 * Shared like KOF_SCAN_ALL and KOF_SCAN_SYM_*, and for the reason those give:
 * it means the same thing for every input that has one.
 *
 * INSIDE THE PARTITION, WHICH IS THE DIFFERENCE FROM SYM. The symbol halves
 * are an overlay - the host BUILT that block and its bytes are not the
 * object's, so nothing double counts when a mask names them beside a region.
 * A carried file's bytes ARE the object's, and they are already in one of its
 * regions. So this is not an overlay on top of those: it is the bit a format
 * assigns to its OWN carried-file class, through the same *_cls_bit[] table
 * that maps every other class to a region. One bit, one class per format, no
 * byte in two regions - which is the property every mask in this engine rests
 * on and an overlay would have quietly broken.
 *
 * FROM THE TOP for the same reason the symbol halves are: format regions
 * number upward from bit 1 and this must never collide with one a format adds
 * later.
 */
#define KOF_SCAN_EMBEDDED (1u << 29)

#define KOF_SCAN_SYM_IMP (1u << 30)
#define KOF_SCAN_SYM_EXP (1u << 31)
#define KOF_SCAN_SYM     (KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP)

/*
 * A region measured rather than read. See `region_shape` below.
 *
 * `widest` and `widest_off` describe ONE contiguous run and not the region: a
 * region is usually several, and the difference between "60% of this file is
 * unclaimed" and "60% of this file is unclaimed IN ONE PIECE" is the whole
 * signal. The first is true of ordinary binaries full of alignment padding; the
 * second is not true of any of them.
 */
struct kof_region_shape {
	uint64_t bytes;       /* every byte the region covers */
	uint64_t widest;      /* the longest single run in it */
	uint64_t widest_off;  /* where that run starts, in the object */
	uint32_t runs;        /* how many runs the region is */
	uint32_t reserved;
};

#endif /* KOFENG_KOFREGION_H */
