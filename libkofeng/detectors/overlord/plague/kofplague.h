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
#include "../../../analyzers/parsers/binaries/funcs.h"
#include "../../../analyzers/trueline/trueline.h"

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
 * HOW A BLOCK'S HASHES ARE CHOSEN - one generator, one definition of a window.
 *
 * The POOL of a span is every distinct window hash it has (not flat, see
 * kof_plague_flat), ascending. A block is NOT the pool - that would be thousands
 * of values - it is a sample of it: the smallest KOF_PLAGUE_MINHASH_K of the
 * windows worth keeping. For one sample "worth keeping" is every window, which
 * is kof_plague_minhash: the bottom-k sketch every block so far was made with.
 *
 * WITH MORE THAN ONE SAMPLE it is a choice, and it is the one that matters.
 * Measured on 149 files that carry one exploit request (research notes in
 * /mnt/games/kofscratch/blkcut/PROPOSAL.md): a block cut from the span a unit
 * gives hit 3 of them; the same data cut by hand as 1200 bytes, 129; and a block
 * of the windows that EVERY sample shares and NO background file holds, 142 -
 * with the same 32 hashes for any span that contains the request, shifted,
 * grown or shrunk. The variable material of a span is inside it, so no choice
 * of where to cut removes it; what removes it is asking more than one sample
 * which windows are the data's and which the sample's. kof_plague_member is that
 * question and kof_plague_core is the answer.
 */
#define KOF_PLAGUE_MINHASH_K 32u

/* Every distinct non-flat window hash of the span, ascending, malloc'd; NULL
 * (and *n_out 0) when the span has none. The CALLER bounds the span: a block's
 * input is a function or a cluster, never a file. */
uint32_t *kof_plague_pool(const uint8_t *p, uint64_t n, uint32_t norm,
			  uint32_t *n_out);

/* The smallest K of the pool; ascending, distinct. */
uint32_t kof_plague_minhash(const uint8_t *p, uint64_t n, uint32_t norm,
			    uint32_t *out);

/*
 * Which of `pool`'s windows does this sample hold? Bit i of `bits` (n_pool bits,
 * zeroed by the caller; set, never cleared) is set when the sample has window
 * pool[i] anywhere. One pass over the sample, a bit table first.
 */
void kof_plague_member(const uint32_t *pool, uint32_t n_pool, const uint8_t *p,
		       uint64_t n, uint32_t norm, uint8_t *bits);

/*
 * The block of a pool, given how many positive samples held each window
 * (`pos`, against `pos_need`) and how many background samples did (`bg`, at most
 * `bg_max`; NULL for no background). The smallest `k` windows that pass, ascending
 * - the pool is ascending, so they are the first k. Returns 0 when fewer than
 * KOF_PLAGUE_MIN_HASH pass: there is no invariant, informative material in this
 * span, and saying so is the answer - the alternative is a block made of the
 * sample's own accidents.
 */
uint32_t kof_plague_core(const uint32_t *pool, uint32_t n_pool,
			 const uint16_t *pos, uint32_t pos_need,
			 const uint16_t *bg, uint32_t bg_max, uint32_t k,
			 uint32_t *out);

/*
 * WHERE TO CUT A SPAN OF BYTES THAT HAS NO FUNCTIONS - the other half of how
 * blocks are offered.
 *
 * Content-defined: a cut falls where the window hash of the bytes has its low
 * bits clear, so the same bytes are cut in the same places whatever was inserted
 * before them, and a block cut from one sample is recognisable in the next.
 * `avg` is the mean piece (a power of two), `min` and `max` bound it.
 *
 * Here, beside the hash it uses, and not in the panel that wants the pieces: a
 * second copy of the rolling loop is a second definition of what a window is.
 * `fn` is called for each piece in order with its [from, to) offsets inside the
 * span, and stops the walk by returning non-zero. A span of kof_plague_ng bytes
 * or fewer is one piece.
 */
typedef int (*kof_plague_cut_fn)(void *user, uint64_t from, uint64_t to);
void kof_plague_cut(const uint8_t *p, uint64_t len, uint32_t avg, uint32_t min,
		    uint32_t max, kof_plague_cut_fn fn, void *user);

/*
 * HOW AN OBJECT IS CUT INTO UNITS - the same cut for the tool that makes a block
 * and the scanner that finds it, so it is made here and nowhere else.
 *
 * `ext` are the extents of ONE region, resolved by the caller. A region that is
 * offered a function at a time (kof_plague_by_function) yields the functions of
 * `funcs` that lie in it - grouped when small, dropped when they are stubs or
 * the library's - and, from the bytes alone, the clusters of
 * strings that such a region holds when .rodata shares its segment (by_string in
 * kofplague_units.c). With `funcs` empty only the clusters remain. Any other region is cut by kof_plague_cut at the fixed target
 * KOF_PLAGUE_SEG_AVG, split where it crosses a library boundary so that no unit
 * spans one. `lib` may be NULL.
 *
 * `fn` gets each unit's file offset, length and side, in order, and stops the
 * walk by returning non-zero. A unit that is functions also gets the largest of
 * them - the one the unit is mostly made of, for a tool that names it; a piece of
 * bytes gets NULL.
 */
#define KOF_PLAGUE_SEG_AVG 8192u        /* the mean carved piece, a power of two */

typedef int (*kof_plague_unit_fn)(void *user, uint64_t off, uint64_t len,
				  uint32_t side, const struct kof_func *first);

int kof_plague_by_function(uint32_t format, uint32_t mask);

void kof_plague_units(const uint8_t *p, uint64_t n_obj, uint32_t format,
		      uint32_t mask, const struct kof_range *ext, uint32_t n_ext,
		      const struct kof_func_set *funcs,
		      const struct kof_true_all *lib,
		      kof_plague_unit_fn fn, void *user);

/* The mutable side: one per scanner thread. */
struct kof_plague_ctx {
	const struct kof_plague_set *set;
	/*
	 * Per block: the best count of its hashes that ONE unit of this object
	 * held, and which object that was.
	 *
	 * The stamp is what removes the clear: an object bumps a generation
	 * counter and every stale count reads as zero without anything being
	 * written.
	 */
	uint32_t *seen;
	uint32_t *stamp;
	/*
	 * Per block, for the unit being credited: how many of its hashes this
	 * unit holds, and which unit that was. Same device, one level in.
	 */
	/* Per (block, hash) pair, same device: a hash that many windows of one
	 * object produce is one hash of the block, counted once - see pl_credit. */
	uint32_t *pstamp;
	/*
	 * Credit a block whatever region the bytes came from - see
	 * kof_plague_any_region. Per object, because it is a property of the
	 * OBJECT and not of the set: cleared by kof_plague_begin so it cannot
	 * leak from one object into the next.
	 */
	int       any_region;
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
 * Credit one UNIT of the object - a function, a run of small ones, or a piece of
 * a region cut by kof_plague_cut; see kof_plague_units, which makes the same
 * cuts a block was made from. The unit is sketched with one normalizer and each
 * hash of its sketch is credited to the blocks that hold it.
 *
 * `scan_mask` is the region bit the bytes are in; only blocks taken from that
 * region are credited, so the same bytes in the wrong region cannot score. That
 * is the anchor a rule relies on. `side` is which half of the object the unit
 * is on - see enum kof_plague_side - and only blocks from the same side count.
 *
 * A block's score is the BEST single unit's: how much of its sketch that unit
 * holds, not what several units hold between them.
 */
void kof_plague_unit(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		     uint32_t side, const uint8_t *p, uint64_t n);

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
