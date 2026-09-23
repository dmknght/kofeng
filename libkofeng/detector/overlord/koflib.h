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
 * The most spans one object can yield, per tier.
 *
 * SIXTEEN IS THE MARKER TIER'S NUMBER - one per loadable segment, since that
 * span runs from a segment's first marker to its last - and it is not the
 * symbol tier's. That one produces a range per library FUNC or OBJECT, which is
 * over a thousand before they are merged, and a list that fills silently drops
 * the rest: measured on a 3.2MB static build, a cap of 16 cut 3.9KB of library
 * code where the symbols named half a megabyte of it, and a cap of 512 reached
 * half.
 *
 * TWO TYPES AND NOT ONE BIG ONE, so a caller that only ever wants the marker
 * span - kofoverlord, the block builder - is not made to carry 32KB of array it
 * cannot fill.
 */
#define KOF_LIB_MAX_SPANS     16u
#define KOF_LIB_MAX_SPANS_ALL 2048u

struct kof_lib_result {
	struct kof_range span[KOF_LIB_MAX_SPANS];
	uint32_t n;
};

struct kof_lib_all {
	struct kof_range span[KOF_LIB_MAX_SPANS_ALL];
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

/*
 * The same, plus the symbol tier: every byte the file's own symbols attribute
 * to the implementation, exactly, in whatever region it lies.
 *
 * TWO ENTRY POINTS AND NOT A COMPLETER kof_lib_find, WHICH IS A MEASUREMENT
 * DECISION RATHER THAN A TASTE ONE.
 *
 * The similarity matcher and kofoverlord were calibrated against the marker
 * span - the note at the top of this file says so - and the thresholds they
 * carry are numbers about THAT set of bytes. Switching them to a wider cut does
 * not improve them, it makes their numbers about something else: measured when
 * kof_lib_find itself was widened, a malware corpus moved 57 files from
 * infected to suspected, because the blocks those verdicts rest on no longer
 * covered the same bytes.
 *
 * So the wider cut goes where it was asked for and where nothing is calibrated
 * against it - the normalised view, whose whole purpose is to be the object's
 * own content and nobody else's. Moving the other two across is a
 * re-measurement, not an edit.
 */
void kof_lib_find_all(kof_buf file, const struct kof_elf_info *e,
		      struct kof_lib_all *out);

/*
 * The symbol tier ALONE, for an object where the marker span cannot be trusted.
 *
 * The marker span runs from a segment's first library string to its last and
 * takes everything between, which is right for a static build - the library is
 * one run - and wrong for a DYNAMIC one, where there is no static library at
 * all and the strings it finds are the program's own. Measured: an 8MB miner
 * with a PT_INTERP yielded a 7MB "library" span across its CODE, which is the
 * program.
 *
 * The symbol tier has no such failure mode: it claims exactly what a symbol
 * covers and nothing between symbols, so it is as true of a dynamic object -
 * where it finds the handful of crt and loader pieces the linker put in - as of
 * a static one.
 */
void kof_lib_find_syms(kof_buf file, const struct kof_elf_info *e,
		       struct kof_lib_all *out);

/*
 * Whether the [va, va+size) a SYMBOL covers falls in what was found.
 *
 * For a caller holding symbols rather than file offsets, so that translating an
 * address through the segments happens in one place and cannot drift from the
 * translation the spans themselves were built with. What the segments cannot
 * place is not the library's - see the note on the definition.
 */
int kof_lib_has_addr(const struct kof_elf_info *e,
		     const struct kof_lib_all *lib, uint64_t va, uint64_t size);

#endif /* KOFENG_KOFLIB_H */
