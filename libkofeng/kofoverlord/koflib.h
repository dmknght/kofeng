/*
 * koflib.h - which bytes of an object belong to the STATIC LIBRARY, and not to
 * whoever wrote the program.
 *
 * WHY THE ENGINE NEEDS THIS AT ALL, and not just the similarity matcher: two
 * unrelated statically linked binaries share their libc, and that shared half
 * is most of the file. Measured here, two CLEAN binaries reach a median
 * string-set Jaccard of 0.25 and a 90th percentile of 0.99 purely through what
 * the linker pulled in - nothing either author wrote. Any matcher that hashes
 * those bytes is measuring the toolchain and calling it identity.
 *
 * So the library is not a nuisance to be thresholded away. It is a REGION THAT
 * WAS NEVER THE AUTHOR'S, and the honest thing is to stop hashing it.
 *
 * MARKERS, AND NOTHING ELSE. A symbol tier would be exact where symbols
 * survive, and it is not here because it has not been measured: the numbers
 * this and kofoverlord are built on came from the marker span alone, and a
 * second source of spans would make them numbers about something else. The
 * measured coverage of this tier is in the note beside the marker table.
 *
 * DELIBERATELY BIASED TOWARDS CUTTING TOO MUCH. The two ways to be wrong are
 * not worth the same: subtracting a little user code loses a detection, while
 * leaving library code in admits a false positive on every binary that links
 * the same libc. The first fails quietly and the second fails loudly.
 */

#ifndef KOFENG_KOFLIB_H
#define KOFENG_KOFLIB_H

#include <stdint.h>
#include <kofcore.h>
#include <kofmod/kofsig.h>

struct kof_elf_info;

/*
 * The most spans one object can yield: at most one per loadable segment, since
 * the span runs from a segment's first marker to its last.
 */
#define KOF_LIB_MAX_SPANS 16u

struct kof_lib_result {
	struct kof_range span[KOF_LIB_MAX_SPANS];
	uint32_t n;
};

/*
 * Find the library spans of an ELF. Offsets are FILE offsets, so a caller can
 * subtract them from a resolved range without translating anything.
 *
 * Never fails: an object it cannot read yields n = 0, which a caller must treat
 * as "cut nothing" and not as "there is nothing to cut". That difference is
 * real and common - measured over 514 IoT-botnet ELFs, 86% yielded no span at
 * all, because a stripped static uclibc build carries none of the text this
 * recognises.
 */
void kof_lib_find(kof_buf file, const struct kof_elf_info *e,
		  struct kof_lib_result *out);

#endif /* KOFENG_KOFLIB_H */
