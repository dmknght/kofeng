/*
 * kofmutation.h - the similarity matcher: an index over rule blocks, and the
 * per-thread state that scores one object against all of them.
 *
 * THE SPLIT IS THE ENGINE'S OWN. `kof_mutation_set` is built once, is immutable,
 * and is shared by every thread; `kof_mutation_ctx` is the counters, one per
 * scanner. That is the same division kof_engine and kof_scanner already have,
 * and it is what keeps a few megabytes of index out of the per-thread cost.
 *
 * COST, because this runs on every eligible object:
 *
 *   - one linear pass per (region, normalizer) a rule asked for. About two
 *     operations a byte: a rolling hash update and a multiply.
 *   - one filter test per window. Most windows are in no rule; they are rejected
 *     by one cache line of a filter whose size comes from the engine's memory
 *     ledger, not from the number of rules.
 *   - for the windows that pass: ONE batch. They are sorted, and the bucket of the
 *     index each one falls in is read from the pack (pread, a verified 64 KiB slice at
 *     a time) and searched. A value is credited once per object however often the
 *     object repeats it.
 *
 * So the cost is linear in the bytes and INDEPENDENT OF THE NUMBER OF RULES, and
 * so is the memory: a database of 8,000,000 hashes resides in the same few
 * megabytes as one of 80 (databases/pack/dbkix.h says where the rest is). There
 * is ONE path: the stream that probed each window as it came is gone, because it
 * needed the whole index in memory and a second path left both to keep correct.
 */

#ifndef KOFENG_KOFMUTATION_MATCH_H
#define KOFENG_KOFMUTATION_MATCH_H

#include <stdint.h>
#include <kofmod/kofsig.h>   /* struct kof_range, for the library spans */
#include <kofmod/kofmutation.h>
#include <celllysis/mutation.h>
#include "../../databases/pack/dbkix.h"   /* the block index container: struct kof_kix */
#include "../../kofcore/kofbudget.h"        /* struct kof_budget: where the filter's size comes from */
#include "kofmutflt.h"                       /* the pre-built filter a pack may carry */

/*
 * The immutable side: the index over the blocks of every pack that has any, and the filter
 * that goes in front of it. Built once, shared by every thread, read-only after.
 *
 * A pack that carries the index trailer (databases/pack/dbkix.h) is used where it
 * lies: its directory and slice CRCs are in memory, its body is read on demand. A pack
 * that does not (built before the trailer existed) has the same structure built in memory
 * under the ledger's allowance, or the set is refused and says so - never a silent
 * skip. The set does not own the arrays it was built from.
 */
struct kof_mutation_set;

/* One pack's blocks. Exactly one of the two forms: an opened trailer (`kix`, taken over
 * by the build, success or not) or the arrays to build one from. `base` is the global
 * number of this pack's block 0 (the loader numbers blocks pack after pack). */
struct kof_mutation_src {
	struct kof_kix                  *kix;
	const struct kof_mutation_block *blocks;
	uint32_t                         n_blocks;
	const uint32_t                  *pool;
	uint32_t                         n_pool;
	uint32_t                         base;
	/* A pre-built filter for this pack's keys (kofmutflt.h): `xf.read` reads its region, `xf_crc` is the CRC
	 * the region must have, and `xf.ctx` must stay valid until the set is freed (the trailer handle does).
	 * With it the set holds the filter at the width the ledger grants and builds nothing; `xf.read` NULL is
	 * a pack whose filter is the trailer's bloom filter, or one built in memory. Only with `kix`. */
	struct kof_mflt_io               xf;
	uint32_t                         xf_crc;
};

/*
 * Build the index over arrays, in memory. Returns NULL if the inputs do not describe a
 * consistent set - a block whose hash slice runs past the pool - because a matcher that
 * indexed those would read out of bounds on an object nobody could predict.
 */
struct kof_mutation_set *kof_mutation_build(const struct kof_mutation_block *blocks,
					uint32_t n_blocks,
					const uint32_t *pool, uint32_t n_pool);
void kof_mutation_set_free(struct kof_mutation_set *set);

/*
 * THE INDEX, ITS ALLOWANCE AND WHAT IT SAYS ABOUT ITSELF.
 *
 * `budget` is the engine's ledger (kofbudget.h) and is where every size comes from. THE FILTER HAS NO FLAT
 * CAP: its ceiling is a share of what the ledger has left after the index's own tables and the
 * scanners' fixed costs (kof_mflt_ceiling: `scanners` of them at `scan_fixed` each, 0 for the defaults),
 * and it is the default for the number of hashes, taken down the ladder until it fits - a pre-built
 * fuse filter by keeping fewer bits of every fingerprint, a bloom filter by halving - and KOF_MTN_B_FILTER_DEGRADED
 * says that it went below what a bloom filter of 12 bits a key does (`bloom_bits` against `n_key`, and
 * `flt_w` / `flt_res`, say how far). And the
 * resident part of the index - directories, the filter, and the bodies of packs built in
 * memory - may take at most half of what the ledger has left, the other half being what the
 * scanners will need. `max_bytes` lowers that further (0: no more than the ledger). A set
 * that does not fit is REFUSED - NULL, with KOF_MTN_B_OVER_BUDGET - rather than half built.
 * With no ledger the default cap (KOF_ENGINE_MEM_CAP) is the ledger.
 * `max_visit` is the most entries one object may walk in shared lists (0: the larger
 * of four times the entries and 4M): a DoS bound, and when it is reached the object says so
 * (kof_mutation_stat) - it never drops quietly.
 */
struct kof_mutation_build_res;
struct kof_mutation_build_req {
	const struct kof_mutation_src *src;     /* one per pack ... */
	uint32_t        n_src;
	const struct kof_mutation_block *blocks; /* ... or, with n_src 0, one set of arrays */
	uint32_t        n_blocks;
	const uint32_t *pool;
	uint32_t        n_pool;
	const struct kof_budget *budget;
	uint64_t        max_bytes;
	uint64_t        max_visit;
	uint32_t        bloom_bpk;     /* 0: KOF_KIX_FILTER_BPK; the bloom filter's bits a distinct hash */
	uint32_t        scanners;      /* live scanners the filter's ceiling leaves room for; 0: KOF_MFLT_SCANNERS */
	uint64_t        scan_fixed;    /* the fixed cost of one of them; 0: KOF_MFLT_SCAN_FIXED */
	uint32_t        flags;         /* KOF_MTN_BUILD_* */
	struct kof_mutation_build_res *res;   /* the caller's, or NULL */
};
struct kof_mutation_build_res {
	uint32_t status;               /* KOF_MTN_B_* */
	uint32_t n_block, n_pair, n_key, max_mult;
	uint64_t bytes;                /* resident: also set when refused (what was reached) */
	uint64_t bloom_bits;
	uint64_t max_visit;
	uint32_t n_part, n_part_mem;   /* packs indexed; of those, built in memory */
	uint32_t flt_kind;             /* KOF_MTN_FLT_*: what filters the windows */
	uint32_t flt_w;                /* fuse: bits kept of each fingerprint (0: no fuse filter) */
	uint32_t flt_parts, flt_res;   /* fuse: partitions it has, and how many are resident */
	uint64_t flt_ceiling;          /* what the ledger's rule allowed the filter, bytes */
};
#define KOF_MTN_FLT_NONE   0u
#define KOF_MTN_FLT_BLOOM  1u
#define KOF_MTN_FLT_FUSE   2u
struct kof_mutation_set *kof_mutation_build_req(const struct kof_mutation_build_req *rq);
/* For tests and measurement: bit 0 the filter lets `v` through (or there is none), bit 1 `v` is in the index. */
uint32_t kof_mutation_probe(const struct kof_mutation_set *set, uint32_t v);
void kof_mutation_set_info(const struct kof_mutation_set *set, struct kof_mutation_build_res *res);

/* Build status. A set with only FILTER_DEGRADED (or NO_FILTER) is built and correct. */
#define KOF_MTN_B_FILTER_DEGRADED  0x01u  /* the filter is below what 12 bloom bits a distinct hash give (about 1% false passes): a bloom filter under them, a fuse filter at under 8 bits a fingerprint or with partitions left out; the ledger said so */
#define KOF_MTN_B_NO_FILTER        0x02u  /* none at all: every window reaches the index */
#define KOF_MTN_B_OVER_BUDGET      0x04u  /* refused: the index does not fit the allowance */
#define KOF_MTN_B_TOO_MANY_BLOCKS  0x08u  /* refused: more than 16,777,215 blocks */
#define KOF_MTN_B_BAD_BLOCK        0x10u  /* refused: a slice, count or normalizer that does not fit */
#define KOF_MTN_B_NOMEM            0x20u  /* refused: an allocation failed */
#define KOF_MTN_B_TOO_BIG          0x40u  /* refused: more entries than 32-bit offsets address */
#define KOF_MTN_B_IN_RAM           0x80u  /* a pack with no index trailer: built in memory under the allowance (repack to avoid) */
#define KOF_MTN_B_TOO_MANY_CLASSES 0x100u /* refused: more than 256 distinct (region, normalizer, side) */
#define KOF_MTN_B_REFUSED (KOF_MTN_B_OVER_BUDGET | KOF_MTN_B_TOO_MANY_BLOCKS | \
			   KOF_MTN_B_BAD_BLOCK | KOF_MTN_B_NOMEM | KOF_MTN_B_TOO_BIG | \
			   KOF_MTN_B_TOO_MANY_CLASSES)
#define KOF_MTN_BUILD_NO_FILTER    0x01u  /* measurement: a filter that passes everything */

/*
 * What one object may ask of the pack's index file. A DoS bound: the cost of a read is its bytes
 * or a page, and the allowance is a fixed part plus a part that follows the bytes the object fed
 * (kofmutation.c says what the second is made of). Reaching it is REPORTED (KOF_MTN_S_IO_BUDGET)
 * and only lowers counts.
 */
#define KOF_MTN_IO_BASE            ((uint64_t)256u << 20)
/* Survivors collected before a batch is probed (4 MB, and the same again to sort in). */
#define KOF_MUTATION_CHUNK         (1u << 20)
/* What a scanner's matcher state may hold when its host does not say. */
#define KOF_MUTATION_STATE_CAP     ((uint64_t)64u << 20)

/* One object's status, kof_mutation_stat. */
#define KOF_MTN_S_WALK_TRUNCATED 0x01u  /* a walk was refused for the visit budget: counts are LOWER BOUNDS */
#define KOF_MTN_S_STATE_NOMEM    0x02u  /* the state would not grow within the allowance: same effect */
#define KOF_MTN_S_IO_BUDGET      0x04u  /* the object's reads of the index file were spent: same effect */
#define KOF_MTN_S_IO_ERROR       0x08u  /* a read failed (a truncated or vanished pack file): same effect */
#define KOF_MTN_S_SLICE_CRC      0x10u  /* a 64 KiB slice of the index does not match its checksum: same effect */
struct kof_mutation_stat {
	uint32_t status;
	uint32_t n_chunks, touched;
	uint64_t visits, walks, trunc_walks, trunc_pairs, probes;
	uint64_t state_bytes;          /* what this scanner holds for the matcher */
	uint64_t life_visits;
	uint32_t life_trunc_objects;
	uint64_t io_bytes, io_reads;   /* this object's reads of the index file */
	uint64_t life_io_bytes;        /* over every object this scanner has seen, this one excluded */
	uint32_t life_io_objects;      /* objects that ended with IO_BUDGET, IO_ERROR or SLICE_CRC */
};
struct kof_mutation_ctx;
void kof_mutation_stat(const struct kof_mutation_ctx *c, struct kof_mutation_stat *out);

/*
 * Which normalizers any block of this set uses, as a bit per enum value.
 *
 * A caller feeds a region once per normalizer in use; asking first is what
 * keeps a pack that only ever hashes raw bytes from paying for two extra
 * passes over every object.
 */
uint32_t kof_mutation_set_norms(const struct kof_mutation_set *set, uint32_t scan_mask);

/*
 * A BLOCK'S NAME AND ITS HASHES.
 *
 * A block has no name in the database - the source calls it blk_<something>
 * and the pack keeps only the numbers - so the way to tell that a span of a
 * file IS a block the database already has is to hash the span and compare the
 * sets. The viewer does exactly that: it carves a sample, and a carved block
 * whose hashes fold to the same value as a declared one is that declared one.
 */
/* The block's name: the fold of its hashes, as the verdict spells it. 0 for a block the
 * set does not have, or when the pack cannot be read. */
uint32_t kof_mutation_block_id(const struct kof_mutation_set *set, uint32_t block);

/* A pointer to the block's hashes, for a set built in memory over the caller's arrays; NULL
 * and *n_hash = 0 for a block the set does not have and for a set whose body is in the pack
 * (a pointer would need the hashes held, which is what the set is not): use
 * kof_mutation_block_copy. */
const uint32_t *kof_mutation_block_hashes(const struct kof_mutation_set *set,
					uint32_t block, uint32_t *n_hash);
/* The block's hashes copied into `out` (room for KOF_MUTATION_MAX_HASH); 1 on success. */
int kof_mutation_block_copy(const struct kof_mutation_set *set, uint32_t block,
			    uint32_t *out, uint32_t *n_hash);


/* The mutable side: one per scanner thread. */
struct kof_mutation_ctx {
	const struct kof_mutation_set *set;
	/*
	 * Credit a block whatever region the bytes came from - see
	 * kof_mutation_any_region. Per object, because it is a property of the
	 * OBJECT and not of the set: cleared by kof_mutation_begin so it cannot
	 * leak from one object into the next.
	 */
	int       any_region;
	uint32_t  gen;
	uint32_t  n_block;
	/*
	 * What this scanner holds for the object in hand, sized by what the object TOUCHED
	 * and not by the database (kofmutation.c, struct mtn_blk and mtn_ent): `bs` the blocks
	 * credited and which of their hashes, `tmap` the hot values already walked, `sv` the
	 * survivors waiting for a batch (and `sv2` to sort them in), `span` the bytes of the
	 * index file one batch reads. `held` is their total and `cap` what the host allows
	 * (kof_mutation_limit); an allocation past it is not made and the object says so.
	 */
	struct mtn_blk *bs;
	struct mtn_ent *tmap;
	uint32_t *sv, *sv2;
	uint8_t  *span;
	uint32_t  bcap, bn, tcap, tn, scap;
	/*
	 * THE BATCH SPANS UNITS. Survivors are collected across consecutive units that ask the same
	 * thing (region, normalizer, side, any-region) and probed together when the batch fills, the
	 * call changes, or anything asks for a count: a function is a few thousand windows, and the
	 * index is read in order only when enough of them wait together (measured: a unit at a time
	 * read 6.8 GB for an object that matches half the database, a batch of a million read 224 MB).
	 * `nsv` of them wait now, for the call `pk_*`.
	 */
	uint32_t  nsv, pk_norm, pk_side, pk_mask;
	int       pk_any;
	uint64_t  span_cap;
	uint64_t  held, cap;
	uint64_t  ledgered;             /* what the host has charged to its ledger for `held`: the host's own bookkeeping */
	uint64_t  fed;                  /* bytes this object has fed: the reads' allowance follows it */
	/* Tests and measurement only: a lower batch size (0: KOF_MUTATION_CHUNK) and a replacement
	 * for the whole reads' allowance (0: KOF_MTN_IO_BASE plus a share of the bytes fed). Set
	 * after ctx_init. */
	uint32_t  chunk_max;
	uint64_t  io_budget;
	struct kof_kix_io io;
	uint32_t  status;               /* KOF_MTN_S_* for this object */
	uint32_t  trunc_walks, walks, n_chunks;
	uint64_t  visits, trunc_pairs, probes;
	uint64_t  life_visits;          /* over every object this scanner has seen */
	uint32_t  life_trunc_objects, life_io_objects;
	uint64_t  life_io_bytes;
};

int  kof_mutation_ctx_init(struct kof_mutation_ctx *c, const struct kof_mutation_set *s);
void kof_mutation_ctx_done(struct kof_mutation_ctx *c);

/* Start a new object. Cheap - it bumps a counter. */
void kof_mutation_begin(struct kof_mutation_ctx *c);

/*
 * What the matcher's state may hold for the object in hand, from the host's ledger. Read by
 * kof_mutation_held, which the host charges to the ledger once the feed has run. A cap the
 * state would pass is not exceeded: the allocation is refused, KOF_MTN_S_STATE_NOMEM is
 * set, and the counts that follow are lower bounds.
 */
void kof_mutation_limit(struct kof_mutation_ctx *c, uint64_t cap);
/* Free what the state holds (kscan_trim); the next object allocates again. */
void kof_mutation_trim(struct kof_mutation_ctx *c);
uint64_t kof_mutation_held(const struct kof_mutation_ctx *c);

/*
 * DROP THE REGION ANCHOR FOR THIS OBJECT.
 *
 * A block records the region it was cut from and is credited only from that
 * region, which is the anchoring a rule is written with - see the note in
 * kofmutation.h on a block being a place as much as a content.
 *
 * That anchor is meaningless on an object an UNPACKER PRODUCED. What comes out
 * of a packer is a reconstructed image, and which region of it a given blob
 * lands in is a property of the packer and of the rebuild, not of the malware:
 * the same code sits in CODE in one build, in DATA after a repack, and in a
 * single unnamed run of bytes when nothing parses the output at all. Anchored,
 * every block scores zero on exactly the object the unpacker was run to
 * produce.
 *
 * Set after kof_mutation_begin and before the feeds, and cleared by the next
 * begin.
 */
void kof_mutation_any_region(struct kof_mutation_ctx *c, int on);

/*
 * Credit one UNIT of the object - a function, a run of small ones, or a piece of
 * a region cut by kgenome_mutation_cut; see kgenome_mutation_units, which makes the same
 * cuts a block was made from. The unit is sketched with one normalizer and each
 * hash of its sketch is credited to the blocks that hold it.
 *
 * `scan_mask` is the region bit the bytes are in; only blocks taken from that
 * region are credited, so the same bytes in the wrong region cannot score. That
 * is the anchor a rule relies on. `side` is which half of the object the unit
 * is on - see enum kgenome_mutation_side - and only blocks from the same side count.
 *
 * A block's score is the number of its hashes the object held, each counted once
 * (a hash a block names twice counts twice, and the count is clamped at the block's n_hash).
 */
void kof_mutation_unit(struct kof_mutation_ctx *c, uint32_t scan_mask, uint32_t norm,
		     uint32_t side, const uint8_t *p, uint64_t n);

/*
 * How much of block `b` was found in what was fed, as a percentage.
 *
 * Named `pct` and not `score` because the RULE-facing spelling of this is
 * kof_mutation_score in kofsig.h, and that one takes a declared block name rather
 * than an engine-wide index. Two names for two layers: a module never sees this
 * one, and the host never sees a block name.
 *
 * This is the whole interface a rule sees, through that macro. What the number means is the rule's
 * to decide - see the note in kofmod/kofmutation.h about why the thresholds are
 * not here.
 *
 * Zero for a block nothing fed could reach, which is the same answer as "none
 * of it was there": a rule cannot tell the two apart and must not try, because
 * a region that was never resolved and a region with nothing in it are the same
 * fact about this object.
 */
uint32_t kof_mutation_pct(const struct kof_mutation_ctx *c, uint32_t b);
/* The same measurement unreduced, for a caller combining several blocks. */
int kof_mutation_counts(const struct kof_mutation_ctx *c, uint32_t b,
		      uint32_t *seen, uint32_t *n_hash);

/*
 * The count the percentage was computed from.
 *
 * Not for a rule - a rule wants the percentage and nothing else - but for a
 * tool showing an author why a block scored what it did. Seven of twenty and
 * seven of twenty-one are both thirty-five percent, and which one it is decides
 * whether a threshold of forty is reachable at all.
 */
uint32_t kof_mutation_matched(const struct kof_mutation_ctx *c, uint32_t b);

#endif /* KOFENG_KOFMUTATION_MATCH_H */
