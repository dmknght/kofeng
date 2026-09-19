/*
 * kofoverlord.h - "is this the same thing as that", asked of two whole objects.
 *
 * NOT A SIGNATURE AND NOT PLAGUE. A signature says "these bytes are that
 * family" and plague says "this block came from that family's code". Both are
 * claims about CONTENT, and both go quiet on the object whose content has been
 * encrypted - which, for the corpus this was built against, is most of it.
 *
 * Overlord asks a different question: given a reference object somebody already
 * identified, is the object in hand the same program? That question has an
 * answer even when every byte of the payload is ciphertext, because what a
 * builder produces has a SHAPE - how many loadable regions, how big each is
 * relative to the others, how the file sizes compare, what the segment table
 * looks like - and encrypting a payload changes none of it.
 *
 *
 * TWO TRACKS, AND THEY ARE NOT A FALLBACK FOR EACH OTHER
 *
 *   STRUCTURE   shape only, not one byte of content read. Measured on 925
 *               deduplicated IoT-botnet ELFs against 3870 clean objects: 71.5%
 *               of the malware matched some other sample, at zero false
 *               positives. This is the track that survives encryption.
 *
 *   STRINGS     the printable runs of each region, after the static library is
 *               subtracted. 84.3% at zero false positives on the same corpora.
 *               This is the track that recognises a mutation.
 *
 * They overlap but neither contains the other: across independent collections,
 * 41 objects were caught only by strings and 9 only by structure. So the
 * verdict is their union, and which track fired is reported - "the shape is
 * identical and the content is not" is a different fact from "the content
 * matches", and an analyst wants to be told which one happened.
 *
 * WHY STRINGS AND NOT ROLLING-HASH BLOCKS. Both were tried. Block hashing is
 * sensitive to LAYOUT - two builds holding the same table of strings in a
 * different order share no window - and it measured 0.000 on every
 * cross-architecture pair, every time. The string SET is layout-free, and the
 * same pairs measured 0.4 to 0.94, because a botnet's table is the same table
 * on every target it was cross-compiled for. Plague keeps the block hashes,
 * which is the right tool for the question plague asks; this one needs the set.
 *
 *
 * THE LIBRARY IS SUBTRACTED BEFORE ANYTHING IS COLLECTED
 *
 * Two unrelated statically linked binaries share their libc, and that shared
 * half is most of the file: clean-to-clean string similarity has a median of
 * 0.25 and a 90th percentile of 0.99 through the toolchain alone. Collecting
 * those strings measures the linker and calls it identity. See koflib.h, and
 * note the hole recorded there - on stripped static uclibc builds the cut
 * currently finds nothing.
 *
 *
 * WHAT DOES NOT APPLY IS NOT THE SAME AS WHAT FAILED
 *
 * A region with no strings on either side did not fail to match; there was
 * nothing to match. Scoring it zero would drag the mean down for a pair that
 * agrees everywhere it can. So every dimension carries a bit saying whether it
 * applied, and a rule reads only the dimensions that did.
 */

#ifndef KOFENG_KOFOVERLORD_H
#define KOFENG_KOFOVERLORD_H

#include <stdint.h>
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofoverlord.h>
#include "koflib.h"

struct kof_elf_info;

/*
 * Loadable regions one descriptor keeps. An ELF the linker produced has two to
 * four; the objects with more are not programs, and one that fills this says so
 * rather than silently comparing a prefix.
 */
#define KOF_OVL_MAX_REGIONS 8u

/*
 * Strings one descriptor keeps, across all its regions.
 *
 * Four thousand against a measured median of 74 for a botnet sample and 128 for
 * a clean one, with a 75th percentile of 327. Generous, and fixed, so building
 * a descriptor needs no allocation.
 */
#define KOF_OVL_MAX_STRINGS 4096u

/* The shortest printable run that counts as a string. Six, as measured. */
#define KOF_OVL_MIN_STRING 6u

struct kof_ovl_region {
	uint64_t fsz;        /* the region's bytes on disk, before subtraction */
	uint32_t str_off;    /* slice of the descriptor's string pool          */
	uint32_t str_n;
	uint8_t  x;          /* executable: what the pairing keys on           */
	uint8_t  pad[3];
};

struct kof_ovl_desc {
	uint64_t fsize;
	uint64_t anomalies;       /* the parse's complaints: shared damage is an
				   * anchor, not noise - broken headers are 18
				   * times more common in this malware corpus
				   * than in clean objects (18% against 1%)     */
	uint32_t ptypes;          /* bitmask over the low p_type values         */
	uint32_t machine;
	uint16_t etype;
	uint8_t  cls;             /* KOF_ELFCLASS_*                             */
	uint8_t  end;             /* KOF_ELFDATA_*                              */
	uint8_t  n_region;
	uint8_t  truncated;       /* a cap stopped the build                    */
	uint8_t  pad[2];
	struct kof_ovl_region region[KOF_OVL_MAX_REGIONS];
	uint32_t n_str;
	uint64_t str[KOF_OVL_MAX_STRINGS];   /* sorted, deduplicated, per region */
};

/* Which dimensions of a comparison had an answer. */
enum kof_ovl_dim {
	KOF_OVL_D_SIZE    = 1u << 0,
	KOF_OVL_D_PTYPE   = 1u << 1,
	KOF_OVL_D_REGSIZE = 1u << 2,
	KOF_OVL_D_STRINGS = 1u << 3,
	KOF_OVL_D_ANOM    = 1u << 4
};

/*
 * The comparison, as the vector it is. Per mille, because the engine has no
 * floating point on its hot paths and a thousandth is finer than any threshold
 * these measurements support.
 *
 * NOT REDUCED TO A SCORE, and that is the point. Summing these would map two
 * unrelated shapes onto the same number as one real match - the projection
 * throws away exactly what separates them - and no threshold recovers what the
 * sum destroyed. A rule is a conjunction over the fields.
 */
struct kof_ovl_vec {
	uint16_t size_ratio;   /* min/max of file sizes                        */
	uint16_t ptype_jac;
	uint16_t reg_size;     /* the WORST paired region, not the mean: one
				* region that does not fit means a different
				* program, however well the others agree      */
	uint16_t str_mean;     /* mean over paired regions - measured to beat
				* the max, because agreement in every region
				* is what a rebuild preserves and a
				* coincidence does not                        */
	uint16_t str_max;
	uint16_t anom_jac;
	uint16_t applied;      /* enum kof_ovl_dim bits that had an answer     */
	uint8_t  cls_match;    /* class and endianness together                */
	uint8_t  etype_match;
	uint8_t  same_arch;
	uint8_t  nload_match;
	uint8_t  anom_both;
	uint8_t  pad[3];
};

/*
 * Build a descriptor. Returns 0 when the object is not one this can describe -
 * not ELF, no loadable region - and the descriptor is zeroed and safe to read.
 */
int kof_ovl_build(struct kof_ovl_desc *d, kof_buf file,
		  const struct kof_elf_info *e);

/* Compare two descriptors. Symmetric; neither argument is privileged. */
void kof_ovl_compare(const struct kof_ovl_desc *a, const struct kof_ovl_desc *b,
		     struct kof_ovl_vec *v);

/*
 * Which track, if any, fires.
 *
 * The thresholds are the ones that measured zero false positives on 3870 clean
 * objects - 1000 of them adversarially packed - with the clean corpus split so
 * that the half used to choose them was never the half they were tested on.
 */
enum kof_ovl_track {
	KOF_OVL_NONE      = 0,
	KOF_OVL_STRINGS   = 1u << 0,   /* content matched: a mutation           */
	KOF_OVL_STRUCTURE = 1u << 1,   /* shape matched, content need not       */
	KOF_OVL_ANCHOR    = 1u << 2    /* shared header damage plus shape       */
};

uint32_t kof_ovl_verdict(const struct kof_ovl_vec *v);
const char *kof_ovl_track_name(uint32_t track);

/*
 * A SHAPE A RULE CAN DECLARE, and the one number it is asked about.
 *
 * The structure track compares facts a rule can write down - how big the file
 * is, how many loadable regions and how big each, which program header types
 * are present - and none of them need the object's bytes. So a rule carries a
 * shape rather than a whole descriptor: no string pool, a hundred-odd bytes,
 * and the comparison costs a handful of divisions.
 *
 * ONE PERCENTAGE, AND IT IS STILL A CONJUNCTION. kof_ovl_shape_pct answers with
 * the WORST-agreeing dimension, not an average of them, so `>= 70` means every
 * dimension agrees to at least seventy percent - which is exactly the rule that
 * measured zero false positives on 3870 clean objects. An average would let a
 * perfect match on one dimension pay for a total disagreement on another, which
 * is the projection this file refuses everywhere else.
 */


#endif /* KOFENG_KOFOVERLORD_H */
