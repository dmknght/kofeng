/*
 * kofmultimatch.h - answering every marker of one region in one pass.
 *
 * WHAT THIS IS FOR
 *
 * The lazy path searches once per (marker, region): a clean object is asked
 * about nearly every marker in the database and answers "no" to nearly all of
 * them, so the same bytes are read once per marker. Measured on
 * /usr/lib/x86_64-linux-gnu with the shipping base: 324306 searches reading
 * 77038 MB over 1704 MB of data - every byte read about forty-five times.
 *
 * That number is set by the size of the database, not by the object, so it
 * grows with every signature written. This reads each region ONCE for all of
 * its markers and writes the answers into the memo the lazy path already
 * consults, which makes the cost of a region a property of the region rather
 * than of the base.
 *
 * It is semantically invisible. A memo cell means "is this marker in this
 * region mask of this object", and that question has one answer whoever fills
 * it in; kof_match_lookup reads the cell before doing anything else. The module
 * ABI already sanctions this - see find_str in kofmod/kofsig.h: "the host is
 * free to answer from a table it filled in one batched pass or to search on the
 * spot and remember. The module cannot tell."
 *
 * WHY THERE IS MORE THAN ONE ROUTINE
 *
 * Because no single one wins everywhere, and which one wins is decided by two
 * numbers the build already knows. Measured over 14300 region rows - clean
 * /usr/lib, /usr/bin and /usr/sbin, three malware corpora, objects recovered by
 * the unpackers, and synthetic sets up to a million markers:
 *
 *   K < 8                 per-marker search. A region with a handful of live
 *                         markers is cheaper read a handful of times than read
 *                         once by a routine with a slower inner loop. PE today
 *                         is K=2 and K=3, and per-marker beats batching there
 *                         by 151% and 222%.
 *
 *   shortest marker >= 8  Wu-Manber. Its skip is bounded by the SHORTEST marker
 *                         declared for the region, so a region whose markers
 *                         are all long steps over most of the bytes. ELF NOLOAD
 *                         (shortest 12) and PE CODE (shortest 14) are the two
 *                         that qualify today, and it wins them by 65% and 112%.
 *
 *   otherwise             the 4-gram table. A short marker caps Wu-Manber's
 *                         skip at nothing, and then reading every position with
 *                         a cheap test is the better trade. ELF CODE (shortest
 *                         6), ELF DATA (7) and text bodies (5).
 *
 * AND WHY THE COUNT OVERRIDES THE SHAPE
 *
 * Past roughly two hundred thousand markers on one region, Wu-Manber's skip
 * table saturates - every block hashes to a bucket some marker needs, so the
 * shift is zero everywhere and the skip stops existing. Measured: at 100k the
 * long-marker set runs 4.12 ms/MB against the gram table's 11.70, at 300k it is
 * 29.95 against 14.13. So the count is tested before the shape, not after.
 *
 * THE TABLES ARE SIZED FROM THE COUNT, AND THAT IS NOT A DETAIL
 *
 * A fixed table is a measurement of the fixed size. Wu-Manber with a 2^16 shift
 * table against a million markers reads as an algorithm that collapses (905
 * ms/MB); given a table scaled to the set it is 110. Both numbers are real and
 * only one of them is about Wu-Manber.
 *
 * HEX PROGRAMS ARE IN, AND THEY ENTER BY THEIR ANCHOR RUN
 *
 * A hex pattern is a program with gaps and alternatives, so it cannot be keyed
 * on its first four bytes - but it always carries one concrete run, and the
 * compiler records where that run sits and how far a match can begin before it.
 * hex_search already does exactly three things: find the run, step back over
 * the window it can begin in, walk the program. Only the FIRST of those is a
 * search, so only the first moves here; the other two are the same code,
 * reached through kof_hex_walk.
 *
 * That also removes a cost hex_search could not avoid: it re-entered find_lit
 * from scratch after every rejected anchor hit, re-paying memmem's needle
 * preprocessing per hit. A shared pass has no "search again" step.
 *
 * WHAT IS STILL DELIBERATELY LEFT TO THE LAZY PATH
 *
 * Markers shorter than the key, hex programs whose anchor run is shorter than
 * it, and any mask naming the symbol halves - the last because those bytes are
 * not the object's and are searched by a second matcher over a buffer this one
 * has never seen. Their cells are simply not filled, and an unfilled cell reads
 * as unknown, which is exactly what it is. A batch that guessed at them would
 * be a batch that could be wrong; leaving them costs one search each.
 *
 * WHAT THIS REPLACED, AND BY HOW MUCH
 *
 * Medians of five against a 1.1 build of the same tree, and against the first
 * version of this file, which keyed on region MASKS instead of regions:
 *
 *                             v1.1        keyed on masks   keyed on regions
 *   /usr/lib (--jobs 1)      8.77 s      4.93 s  1.78x     3.23 s  2.72x
 *   /usr/bin (--jobs 1)      1.60 s      0.90 s  1.78x     0.60 s  2.67x
 *   MalwareLab (--jobs 8)    5.86 s      4.96 s  1.18x     4.50 s  1.30x
 *
 *   searches left to the per-marker path, /usr/lib:  324306 -> 10322 -> 6
 *                                         /usr/bin:  153174 ->  4662 -> 0
 *
 * The mask-keyed version swept 2972 MB of a 1704 MB corpus. Keyed on regions it
 * sweeps 1499 MB, and /usr/bin is answered with NO per-marker search at all.
 * MalwareLab moves least because it is unpack-bound, not match-bound.
 *
 * APPROACHES MEASURED AND REJECTED - DO NOT REDO THEM
 *
 * Each of these looked right and was tried; the number after it is why it is
 * not here. The harness that produced them is gone, so this is the record.
 *
 *   Tuning the presence filter. It lowers the line and never the slope: the
 *   per-marker path, the 24-bit stamp table and a bitset sized to the object
 *   are all LINEAR in marker count (33/294/2938/14614 ms at 116/1k/10k/50k
 *   markers, against 5.3/5.5/7.5/17.2 for the gram table). A filter cannot
 *   flatten a curve, only lower it.
 *
 *   Predicting cost as candidates x table occupancy. Not correlated: measured
 *   occupancy 9.4% against a 33.6% admit rate, 2.4% against 27.3%, and on a
 *   crafted file 0.0% occupancy with a 100% admit rate. Occupancy is the false
 *   positive rate for a RANDOM query and a marker is not one - markers are
 *   ASCII and real binaries are full of ASCII.
 *
 *   Sizing the presence table to the object. On a 30 MB object it needs 28
 *   bits, costs 100 ms to stamp and 32 MB, and the total (134 ms) beat nothing:
 *   the per-marker path was 143 ms. Build cost scales with the object.
 *
 *   Routing on what the FILE looks like. The crossover does not move: measured
 *   invariant in size from 64 KB to 6.3 MB and in content across a real binary,
 *   /dev/urandom and all zeros. A perfect per-file oracle gains 0.0%. Random
 *   data is in fact the filter's BEST case, not its worst - random bytes
 *   contain almost no ASCII 4-grams.
 *
 *   Routing on the format's NAME. "text -> per-marker" costs +253% against a
 *   per-region oracle and "binary -> per-marker" +442%. "PE -> per-marker" is
 *   true today and is a fact about K=2, not about PE: it flips at K=8.
 *
 *   Aho-Corasick as the default. Flat in time and LINEAR IN RAM - 1.2 MB at 116
 *   markers, 106 MB at 10k, 17.7 GB projected at a million, where it simply
 *   cannot be built. +125% against the oracle. It is the one routine immune to
 *   the shared-prefix case below, which is the only reason to keep it in mind.
 *
 * THE SHAPE THAT WOULD BREAK THE GRAM TABLE, AND WHAT HOLDS IT
 *
 * Markers sharing a four-byte head, in a file full of those bytes: every
 * position walks that one bucket. Measured in the harness at its extreme -
 * every marker sharing - it goes quadratic, up to 1157750 ms per MB at a
 * million markers.
 *
 * IT IS THE LITERAL PATH, NOT THE HEX PATH. The deepest bucket in the shipping
 * base is `sys_`, four markers: "sys_call_table", "sys_mmap", "sys_munmap",
 * "sys_write", from hcrootkit_00, hcrootkit_01 and diamorphine_01. Every hex
 * anchor sits in a bucket of its own. So this grows as STRING markers are
 * added, which is the direction a signature base grows.
 *
 * WHAT HOLDS IT IS `tag`, ONE BYTE PAST THE KEY, PER CHAIN ENTRY. Those four
 * markers share four bytes and part at the fifth, which is the ordinary case: a
 * bucket is deep because of a common prefix, and a common prefix is common
 * precisely because what follows it differs. Comparing that byte first turns a
 * chain step into a load and a compare instead of a call.
 *
 * MEASURED, on an ELF whose 3.6 MB .text is filled with `sys_`, forty copies,
 * 247 MB, medians of three, against a 1.1 build of this tree:
 *
 *                          v1.1     no tag    with tag   with tag, by region
 *   ordinary libcrypto    1.30 s    1.74x     1.70x      2.55x
 *   .text all `sys_`      1.10 s    0.80x     1.28x      1.77x
 *
 * Without the tag the crafted file made this engine SLOWER than the one it
 * replaced - the per-marker path gets faster on uniform data, because memmem
 * skips it. With it the worst input measured is comfortably faster than 1.1.
 *
 * IT IS NOT A THRESHOLD AND CANNOT BE WRONG. There is no budget to fit, no
 * fallback to arm and no input that behaves differently in kind:
 * KOF_MULTIMATCH_NOTAG is what a marker exactly as long as the key gets and is
 * always tried, the same value is used where the extent ends before that byte,
 * and every candidate that survives is still verified in full. That is why this
 * is here and a work budget on `max_chain` is not - a budget would have needed a
 * constant fitted against one synthetic file, and would have refused to batch a
 * mask for a worst case that may never occur.
 *
 * WHAT IS STILL NOT COVERED: markers sharing FIVE bytes or more. `max_chain` is
 * reported by kof_engine_multimatch (four, on this base) so the depth is
 * readable without constructing the file, and the same trick extends - a wider
 * tag, or a second one further along - if a base ever makes it necessary. It is
 * not necessary now, and a wider tag fitted against nothing would be a guess.
 */

#ifndef KOFENG_KOFMULTIMATCH_H
#define KOFENG_KOFMULTIMATCH_H

#include <stdint.h>
#include <kofmod/kofsig.h>   /* struct kof_range */
#include "../core/kofcore.h"
#include "kofmatch.h"

struct kof_engine;
struct kof_module;

/*
 * How one region mask is to be answered.
 *
 * LAZY is not a routine, it is the absence of one: nothing is swept and the
 * module's own calls do the searching, exactly as they did before this file
 * existed. It is the answer for a region with too few live markers to pay for a
 * pass, and it is the fallback whenever a table could not be built.
 */
enum kof_multimatch_kind {
	KOF_MULTIMATCH_NONE = 0,
	KOF_MULTIMATCH_HASH4,        /* 4-gram buckets, every position tested */
	KOF_MULTIMATCH_WUMANBER      /* block hash with a skip, long markers only */
};

/*
 * The thresholds, named because they were measured and will have to be
 * measured again when the base changes shape. tests/tmp_performance holds the
 * harness that produced them.
 */
#define KOF_MULTIMATCH_MIN_LIVE   8u        /* K below this: per-marker */
#define KOF_MULTIMATCH_LONG_MIN   8u        /* shortest marker at or above: skip pays */
#define KOF_MULTIMATCH_WM_MAX     200000u   /* markers above this: the skip saturates */

/* Key width of the gram table, and Wu-Manber's block. Both are the width the
 * measurements were taken at; neither is free to change without redoing them. */
#define KOF_MULTIMATCH_KEY        4u
#define KOF_MULTIMATCH_WM_BLOCK   3u

/*
 * HOW LONG A HEX ANCHOR HAS TO BE BEFORE IT IS WORTH BATCHING.
 *
 * A bucket hit is only a claim about the first KOF_MULTIMATCH_KEY bytes; what
 * rejects the rest is the memcmp of the whole anchor before the walk. An anchor
 * exactly as long as the key rejects NOTHING - every hit runs a walk - and a
 * short run of code bytes is common by construction. bases/ has one:
 * `48 85 F6 75`, which is `test rsi,rsi; jne` and appears all over any x86-64
 * text section.
 *
 * THIS IS A GUARD, NOT A MEASURED WIN, AND THE DIFFERENCE MATTERS. On the
 * shipping base the threshold changes nothing that can be told from noise -
 * medians of five over /usr/lib: 4 -> 5.46 s, 8 -> 5.40 s, 12 -> 5.53 s, with
 * 4, 6 and 8 all reporting the identical 10322 searches, because the two short
 * anchors it excludes are ones the lazy path never reaches either. An earlier
 * reading of 7.20 s that appeared to condemn them was a cold-cache run and is
 * not evidence of anything.
 *
 * What justifies it is the shape, which the harness DID measure: a key with no
 * verify behind it is the `prefix` case in tests/tmp_performance, and that goes
 * quadratic - up to 1157750 ms per MB at a million markers. A four-byte anchor
 * is that case with one pattern instead of many. Eight is the smallest length
 * at which the memcmp is doing real work; below it, the lazy path's memmem skip
 * does the rejecting instead, which is what it is good at.
 */
#define KOF_MULTIMATCH_HEX_MIN    8u

/* Bucket counts are derived from the marker count and then bounded. The floor
 * keeps a tiny set from thrashing one cache line; the ceiling is the memory
 * this is allowed to want at a million markers - 4M buckets is 4MB of heads
 * plus 512KB of bitmap. */
/* No byte past the key to hold, so the entry is always tried. Outside a byte's
 * range on purpose: any real value would be a marker this could wrongly skip. */
#define KOF_MULTIMATCH_NOTAG      0x1ffu

#define KOF_MULTIMATCH_BITS_MIN   12u
#define KOF_MULTIMATCH_BITS_MAX   22u

/*
 * One REGION's plan and, when it has one, its table.
 *
 * A region and not a region MASK, and the difference is the whole cost of the
 * pass. Regions partition the object exactly (tests/unit/region_partition.c),
 * so one table per region means the sweep reads every byte once; one table per
 * mask means CODE is read again for CODE|DATA and DATA a third time for
 * DATA|NOLOAD. Measured on the mask-keyed version: 2972 MB swept over a 1704 MB
 * corpus, 1.74x, for nothing.
 *
 * What a MASK is owed - "is this marker anywhere in CODE|DATA" - is then an OR
 * over the regions it names, which is arithmetic on a word rather than another
 * pass over the bytes.
 *
 * Built once when the database is loaded and read-only afterwards, which is
 * what lets every scanner thread share one copy. Per-object state lives in the
 * matcher and in the caller's `found` array, not here.
 */
struct kof_multimatch {
	/* What the base says about this region. All static. */
	uint32_t  mask;          /* the single region bit, for resolving */
	uint32_t  n_pat;         /* distinct markers reaching this region */
	uint16_t  min_len;       /* shortest of them; 0 when there are none */
	uint8_t   fold;          /* any of them case-insensitive */
	uint8_t   kind;          /* enum kof_multimatch_kind, before K is known */

	/* The table. NULL when route came out LAZY or a build failed. */
	uint8_t  *seen;          /* 1 bit a bucket, consulted first */
	uint32_t *head;          /* bucket -> first chain index, 0 = none */
	uint32_t *ids;           /* chain: marker index into `pat` */
	uint32_t *next;
	/*
	 * ONE BYTE PAST THE KEY, PER CHAIN ENTRY.
	 *
	 * A bucket only claims the first KOF_MULTIMATCH_KEY bytes, so every
	 * marker on a chain gets a full compare even when they differ at the
	 * very next byte. The four deepest markers in the shipping base are
	 * "sys_call_table", "sys_mmap", "sys_munmap" and "sys_write" - one
	 * bucket, and they part at byte four.
	 *
	 * Holding that byte beside the chain turns each step into a load and a
	 * compare instead of a call. It is not a filter that can be wrong:
	 * KOF_MULTIMATCH_NOTAG means "no such byte, try it" and is what a marker
	 * exactly as long as the key gets, and every surviving candidate is still
	 * verified in full.
	 */
	uint16_t *tag;
	uint8_t  *shift;         /* Wu-Manber only: bytes the next block may skip */
	uint32_t  nb, bits;
	uint32_t  max_chain;     /* longest bucket - what bounds the worst case */

	/*
	 * Which markers, as indices into the set's one shared array.
	 *
	 * Indices and not copies: a marker reachable from CODE and from DATA is
	 * one marker, and the per-object record of where it was found has to be
	 * one slot or the OR below would be reading two halves of an answer.
	 */
	uint32_t *idx;
	size_t    bytes;         /* what this table cost, for the stats */
};

/*
 * One marker as the table sees it.
 *
 * A literal is its own bytes. A hex program is its ANCHOR RUN - the table finds
 * that, and `prog` is what finishes the job. Keeping both in one array means
 * one pass answers both kinds, which is the whole point; the alternative is a
 * second sweep over the same bytes for a minority of the markers.
 */
struct kof_multimatch_pat {
	const uint8_t *b;        /* literal: the bytes. hex: the anchor run */
	uint16_t       len;      /* literal: its length. hex: anchor_len */
	uint8_t        flags;    /* KOF_STR_ICASE | KOF_STR_FULLWORD; zero for hex */
	uint8_t        is_hex;

	/*
	 * Where a match may BEGIN, relative to a hit on the anchor run.
	 *
	 * A window and not a point: a gap or an alternation of unequal lengths
	 * ahead of the anchor makes the distance vary. One wide when the
	 * concrete bytes come first. The loader bounds the width, so the walk
	 * this drives cannot be entered an unbounded number of times per hit.
	 */
	const uint8_t *prog;     /* hex only: the compiled program */
	uint32_t       before_min, before_max;
	uint32_t       min_span; /* shortest a match can be, for a cheap reject */

	uint32_t       uid;      /* database-wide marker id, for the memo slot */
};

/*
 * Every mask's plan, one array indexed by rng_uid.
 *
 * Owned by the engine because the marker set is the database's and not the
 * scanner's: building it per scanner would duplicate a table sized by the base
 * once per thread, which is the same mistake the memo already refuses to make
 * for the symbol block.
 */
/*
 * Region bits live in the low half of a mask word; KOF_SCAN_ALL is bit 0 and
 * the two symbol halves are bits 30 and 31, which this never sweeps because
 * those bytes are not the object's.
 */
#define KOF_MULTIMATCH_BITS       30u

struct kof_multimatch_set {
	/*
	 * Every keyable marker in the database, once, deduplicated by the id the
	 * build gave it. The region tables index this, and so does the caller's
	 * per-object `found` array - which is what lets a marker met in CODE and
	 * a marker met in DATA be the same marker.
	 */
	struct kof_multimatch_pat *pat;
	uint32_t                   n_pat;

	struct kof_multimatch tab[KOF_MULTIMATCH_BITS];   /* one per region bit */

	/* The raw bits behind each dense mask id, so a fold knows which regions
	 * a mask is asking about. */
	uint32_t             *mask_bits;
	uint32_t              n_masks;

	size_t                bytes;
};

/*
 * Build every mask's table from the loaded database. Returns NULL only when
 * there is nothing to build or memory ran out - and a NULL set is not an error
 * anywhere, it means every mask is answered the way it always was.
 */
struct kof_multimatch_set *kof_multimatch_build(const struct kof_engine *);
void                  kof_multimatch_free(struct kof_multimatch_set *);

/*
 * Which routine for this mask, now that the live marker count is known.
 *
 * `n_live` is what the precondition sweep left: the markers of the modules that
 * survived it. Separate from the table's own n_pat because the table is the
 * base's and n_live is this object's - the same region is worth sweeping on an
 * ELF and not worth it on something where every ELF module was ruled out.
 */
enum kof_multimatch_kind kof_multimatch_pick(const struct kof_multimatch *, uint32_t n_live);

/*
 * Sweep one region's extents, recording WHERE each marker was found rather than
 * answering anything.
 *
 * `found` is one word per marker in the set, owned by the caller and cleared
 * per object: bit b is set when that marker was seen in region bit b. Nothing
 * is written to the memo here, because a region on its own cannot answer a mask
 * that names two of them - only the fold below knows the question.
 *
 * Returns the bytes walked.
 */
uint64_t kof_multimatch_sweep(const struct kof_multimatch_set *, uint32_t bit,
			      enum kof_multimatch_kind, struct kof_match_ctx *,
			      const struct kof_range *ext, uint32_t n_ext,
			      uint32_t *found);

/*
 * Turn what the sweeps found into one mask's answers.
 *
 * PRESENT when the marker was seen in any region the mask names, ABSENT when it
 * was seen in none - and ABSENT is only sound because the caller swept every
 * region of the mask that this object actually has. That condition is the
 * caller's to check, and `kof_multimatch_sweep` returning nothing for a region
 * is exactly the case where it does not hold.
 *
 * Returns how many cells were written.
 */
uint64_t kof_multimatch_fold(const struct kof_multimatch_set *,
			     struct kof_match_ctx *, uint32_t mask_uid,
			     uint32_t mask_bits, const uint32_t *found,
			     uint32_t n_masks);

#endif /* KOFENG_KOFMULTIMATCH_H */
