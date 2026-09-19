/*
 * kofplague.h - the similarity matcher: an index over rule blocks, and the
 * per-thread state that scores one object against all of them.
 *
 * THE SPLIT IS THE ENGINE'S OWN. `kof_plague_set` is built once, is immutable,
 * and is shared by every thread; `kof_plague_ctx` is the counters, one per
 * scanner. That is the same division kof_engine and kof_scanner already have,
 * and it is what keeps a few megabytes of index out of the per-thread cost.
 *
 * COST, because this runs on every eligible object:
 *
 *   - one linear pass per (region, normalizer) a rule asked for. About two
 *     operations a byte: a rolling hash update and a multiply.
 *   - one bitmap test per window. Most windows are not selected at all, and of
 *     those that are, most are in no rule; both are rejected without touching
 *     the index.
 *   - a binary search only for the few that survive.
 *
 * So the cost is linear in the bytes and INDEPENDENT OF THE NUMBER OF RULES.
 * That is the whole reason the index is inverted rather than the rules being
 * walked - ten thousand rules walked per object would be a million set
 * intersections and is not a design that ships.
 */

#ifndef KOFENG_KOFPLAGUE_MATCH_H
#define KOFENG_KOFPLAGUE_MATCH_H

#include <stdint.h>
#include <kofmod/kofsig.h>   /* struct kof_range, for the library spans */
#include <kofmod/kofplague.h>

/*
 * The immutable side: the rules, their blocks, the hash pool, and the index
 * built over it.
 *
 * Built from the arrays a pack loaded, and it does not own them - a pack is
 * mapped or read once and outlives every set built from it.
 */
struct kof_plague_set;

/*
 * Build the index. Returns NULL if the inputs do not describe a consistent set
 * - a block whose hash slice runs past the pool - because a matcher that
 * indexed those would read out of bounds on an object nobody could predict.
 */
struct kof_plague_set *kof_plague_build(const struct kof_plague_block *blocks,
					uint32_t n_blocks,
					const uint32_t *pool, uint32_t n_pool);
void kof_plague_set_free(struct kof_plague_set *set);

/* What the index cost, for whoever reports engine size. */
uint64_t kof_plague_set_bytes(const struct kof_plague_set *set);
uint32_t kof_plague_set_blocks(const struct kof_plague_set *set);

/*
 * Which normalizers any block of this set uses, as a bit per enum value.
 *
 * A caller feeds a region once per normalizer in use; asking first is what
 * keeps a pack that only ever hashes raw bytes from paying for two extra
 * passes over every object.
 */
uint32_t kof_plague_set_norms(const struct kof_plague_set *set, uint32_t scan_mask);

/*
 * ONE BLOCK'S HASHES, so a caller can recognise the block by its content.
 *
 * A block has no name in the database - the source calls it blk_<something>
 * and the pack keeps only the numbers - so the way to tell that a span of a
 * file IS a block the database already has is to hash the span and compare the
 * sets. The viewer does exactly that: it carves a sample, and a carved block
 * whose hashes fold to the same value as a declared one is that declared one.
 *
 * NULL and *n_hash = 0 for an index the set does not have.
 */
/* The block's name: the fold of its hashes, as the verdict spells it. */
uint32_t kof_plague_block_id(const struct kof_plague_set *set, uint32_t block);

const uint32_t *kof_plague_block_hashes(const struct kof_plague_set *set,
					uint32_t block, uint32_t *n_hash);

/*
 * How many selected windows one call may hold before it starts discarding
 * them. A span is at most a few tens of kilobytes and one window in
 * 2^KOF_PLAGUE_SEL_BITS is kept, so this is generous; it exists so the working
 * array is a fixed size and the call needs no allocation.
 */
#define KOF_PLAGUE_SPAN_MAX (1u << 14)

uint32_t kof_plague_hash_span(const uint8_t *p, uint64_t n, uint32_t norm,
			      uint32_t *out, uint32_t max_out);

/* The mutable side: one per scanner thread. */
struct kof_plague_ctx {
	const struct kof_plague_set *set;
	/*
	 * Per block: how many of its hashes have been seen for THIS object, and
	 * which object that was.
	 *
	 * The stamp is what removes the clear: an object bumps a generation
	 * counter and every stale count reads as zero without anything being
	 * written. At ten thousand blocks a memset per object is forty kilobytes
	 * of pointless stores on the overwhelmingly common path where nothing
	 * matches at all.
	 */
	uint32_t *seen;
	uint32_t *stamp;
	/*
	 * One byte per hash in the set: has THIS hash of this block been seen
	 * for this object. It is what makes `seen` a count of distinct hashes
	 * rather than of arrivals - see the note where it is set. Cleared a
	 * block at a time, lazily, by the same stamp that resets the count.
	 */
	uint8_t  *hit;
	/*
	 * Credit a block whatever region the bytes came from - see
	 * kof_plague_any_region. Per object, because it is a property of the
	 * OBJECT and not of the set: cleared by kof_plague_begin so it cannot
	 * leak from one object into the next.
	 */
	int       any_region;
	/*
	 * THE STATIC LIBRARY OF THIS OBJECT, which is not hashed.
	 *
	 * See kof_plague_object. Per object and cleared by kof_plague_begin,
	 * for the same reason any_region is: a span list belongs to the bytes it
	 * was computed from and carrying it into the next object would cut holes
	 * in a file it says nothing about.
	 */
	const uint8_t      *obj_base;
	const struct kof_range *lib;
	uint32_t            n_lib;
	uint32_t  gen;
	uint32_t  n_block;
};

int  kof_plague_ctx_init(struct kof_plague_ctx *c, const struct kof_plague_set *s);
void kof_plague_ctx_done(struct kof_plague_ctx *c);

/* Start a new object. Cheap - it bumps a counter. */
void kof_plague_begin(struct kof_plague_ctx *c);

/*
 * DROP THE REGION ANCHOR FOR THIS OBJECT.
 *
 * A block records the region it was cut from and is credited only from that
 * region, which is the anchoring a rule is written with - see the note in
 * kofplague.h on a block being a place as much as a content.
 *
 * That anchor is meaningless on an object an UNPACKER PRODUCED. What comes out
 * of a packer is a reconstructed image, and which region of it a given blob
 * lands in is a property of the packer and of the rebuild, not of the malware:
 * the same code sits in CODE in one build, in DATA after a repack, and in a
 * single unnamed run of bytes when nothing parses the output at all. Anchored,
 * every block scores zero on exactly the object the unpacker was run to
 * produce.
 *
 * Set after kof_plague_begin and before the feeds, and cleared by the next
 * begin.
 */
void kof_plague_any_region(struct kof_plague_ctx *c, int on);

/*
 * DO NOT HASH THE STATIC LIBRARY.
 *
 * Two unrelated statically linked binaries share their libc, and that shared
 * half is most of the file - clean against clean reaches a median similarity of
 * 0.25 and a 90th percentile of 0.99 through the toolchain alone. A block cut
 * from those bytes matches every program the same linker ever built, so it is
 * not a signature of anything; hashing them at scan time is the same mistake
 * from the other end.
 *
 * `base` is the first byte of the OBJECT, so that a feed of a region can be
 * placed back in the file - the spans koflib produces are file offsets, and the
 * feeds are interior pointers. `lib` must outlive the object's feeds; it is not
 * copied.
 *
 * Set after kof_plague_begin and before the feeds, and cleared by the next
 * begin. Passing n_lib = 0 - or not calling this at all - hashes everything,
 * which is the right behaviour for an object with no library to find and for a
 * caller that has not looked.
 *
 * COSTS NOTHING ON THE HOT PATH. The test runs only for a window that already
 * passed selection, which is one in a few thousand, so an object with no
 * library in it pays a comparison against zero.
 */
void kof_plague_object(struct kof_plague_ctx *c, const uint8_t *base,
		       const struct kof_range *lib, uint32_t n_lib);

/*
 * Feed one region's bytes, hashed with one normalizer.
 *
 * `scan_mask` is the region bit these bytes are; only blocks taken from that
 * region are credited, so the same byte in the wrong region cannot score. That
 * is the anchor a rule relies on - see the note in kofplague.h about a block
 * being a place as much as a content.
 */
void kof_plague_feed(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		     const uint8_t *p, uint64_t n);

/*
 * How much of block `b` was found in what was fed, as a percentage.
 *
 * Named `pct` and not `score` because the RULE-facing spelling of this is
 * kof_plague_score in kofsig.h, and that one takes a declared block name rather
 * than an engine-wide index. Two names for two layers: a module never sees this
 * one, and the host never sees a block name.
 *
 * This is the whole interface a rule sees, through that macro. What the number means is the rule's
 * to decide - see the note in kofmod/kofplague.h about why the thresholds are
 * not here.
 *
 * Zero for a block nothing fed could reach, which is the same answer as "none
 * of it was there": a rule cannot tell the two apart and must not try, because
 * a region that was never resolved and a region with nothing in it are the same
 * fact about this object.
 */
uint32_t kof_plague_pct(const struct kof_plague_ctx *c, uint32_t b);
/* The same measurement unreduced, for a caller combining several blocks. */
int kof_plague_counts(const struct kof_plague_ctx *c, uint32_t b,
		      uint32_t *seen, uint32_t *n_hash);

/*
 * The count the percentage was computed from.
 *
 * Not for a rule - a rule wants the percentage and nothing else - but for a
 * tool showing an author why a block scored what it did. Seven of twenty and
 * seven of twenty-one are both thirty-five percent, and which one it is decides
 * whether a threshold of forty is reachable at all.
 */
uint32_t kof_plague_matched(const struct kof_plague_ctx *c, uint32_t b);

#endif /* KOFENG_KOFPLAGUE_MATCH_H */
