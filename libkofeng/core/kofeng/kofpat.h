/*
 * kofpat.h - compiled pattern format, and the macro that uses a declared string.
 *
 * The format is the contract between the generator (tools/kofpat) and the matcher
 * (libkofeng/kofmatch). It describes the record beside the blob, not an array inside
 * it: strings are declared, the host owns them, so a module holds an index.
 *
 * Nothing in a compiled set is a pointer - fragments refer to their bytes by offset
 * from the start of the array. Today's generator emits only the simplest case; the
 * rest is defined now because hex patterns with wildcards and gaps need somewhere to
 * live and changing a format later means changing every built blob.
 */

#ifndef KOFENG_KOFPAT_H
#define KOFENG_KOFPAT_H

#include <stdint.h>

#define KOF_PAT_FORMAT_VERSION 1

/* A module declares at most this many strings, because the answers arrive as a
 * bitmask in a uint64_t. */
#define KOF_PAT_MAX_IN_SET 64

/* Per-pattern flags. */
enum {
	KOF_PATF_IGNORE_CASE = 1u << 0, /* fold ASCII case on both sides */
	KOF_PATF_HAS_MASK    = 1u << 1, /* fragment data is val[] then mask[] */
	KOF_PATF_NEGATE      = 1u << 2, /* reserved: see note below */
	KOF_PATF_FULLWORD    = 1u << 3  /* neighbours must not be [A-Za-z0-9_] */
};

/*
 * KOF_PATF_NEGATE is reserved, not implemented. Declaring a pattern as must-not-match
 * lets the matcher stop the moment it finds one, which "!kof_find_str(...)" cannot
 * express - that has to scan the whole region to prove absence. Reserved now so
 * adding it later is not a format change.
 */

/*
 * Layout, all little endian, offsets from the start of the array:
 *
 *   0   u8    version        KOF_PAT_FORMAT_VERSION
 *   1   u8    npat           1 .. KOF_PAT_MAX_IN_SET
 *   2   u16   total_len      size of the whole array, for a self-check
 *   4   struct kof_pat_desc[npat]
 *   ..  struct kof_pat_frag[sum of nfrag]
 *   ..  fragment bytes
 *
 * Both tables are fixed size records so the matcher can index them without
 * walking, and a truncated or forged array fails the bounds check rather than
 * being followed.
 */
struct kof_pat_hdr {
	uint8_t  version;
	uint8_t  npat;
	uint16_t total_len;
};

struct kof_pat_desc {
	uint8_t  flags;      /* KOF_PATF_* */
	uint8_t  nfrag;
	uint16_t frag_off;   /* offset of this pattern's first kof_pat_frag */
};

/*
 * gap_min/gap_max are the distance allowed between the end of the previous
 * fragment and the start of this one. Both zero for the first fragment, and for
 * a plain literal, which is one fragment with no gap.
 */
struct kof_pat_frag {
	uint16_t gap_min;
	uint16_t gap_max;
	uint16_t data_off;   /* offset of this fragment's bytes */
	uint16_t data_len;   /* bytes of val; doubled on disk if HAS_MASK */
};

/*
 * Look for a declared string in a declared range.
 *
 *     if (kof_find_str(ctx, busybox, loaded)) ...
 *
 * Both names resolve through identifiers the generator defines from the
 * KOF_DEFINE_STR and KOF_DEFINE_RANGE declarations. A name that was never declared
 * is an undefined identifier at compile time rather than a lookup that quietly
 * returns false.
 */
#define KOF_PASTE2(a, b) a##b
#define KOF_PASTE(a, b)  KOF_PASTE2(a, b)

#define kof_find_str(ctx, str_name, range_name)                    \
	((ctx)->content->find_str((ctx),                           \
		KOF_PASTE(kof_strid_, str_name),                   \
		KOF_PASTE(kof_rangeid_, range_name)))

#endif /* KOFENG_KOFPAT_H */
