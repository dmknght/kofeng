/*
 * kofpix.h - the pattern table that stays in the pack.
 *
 * WHAT IT REPLACED, AND WHY
 *
 * The engine used to answer a region from tables built from the database when it was loaded: five shapes
 * (4-gram chain, Wu-Manber, bisect, rekey, and a router), 40 bytes of marker, 10 of chain, 4 of index and the
 * bucket heads for every marker, plus - per scanner - one word per marker and one memo cell per (marker, mask).
 * Measured on a synthetic base of real strings, load plus matcher was 484 B a rule (1e6 rules: 486 MB of
 * heap, 4e6: 1.85 GB) and a scanner added 9 B a rule on top. The engine's cap is 512 MiB for everything, so
 * the cap was spent by the pattern side alone at about a million rules. Those tables are gone (the
 * verification they ended in is kofmultimatch.h); this is the only way a region is swept.
 *
 * What a sweep NEEDS resident is not the markers. It is an answer to "can any marker start at this
 * position", asked once per byte. Everything after the answer is yes is rare, and can be read from the pack.
 *
 *   resident   per region: a bit table (one probe a byte, sized from the engine's ledger and only an
 *              accelerator), the EXACT SET of the region's keys (2 bytes a distinct key: a directory over
 *              the top sixteen bits of the hash and the low sixteen of each key; below 8192 keys the
 *              sorted hashes themselves), and a directory over the records. The bit table is what the sweep
 *              tests at every byte; the exact set is tested only where the bit table said yes, so a bit table
 *              that is small and cache-sized costs a few percent of positions more, never a wrong answer.
 *              Nothing resident is a marker: the rule count moves the size of the key set (about 0.4
 *              distinct keys a rule here) and nothing else.
 *   in the pack, per region: 24-byte records sorted by the hash of the key. A record carries the key's
 *              hash (exact: the hash is a bijection of the four bytes), the four bytes after the key, the
 *              marker's id and where its bytes are in the string pool.
 *
 * THE SWEEP. Hash the four bytes, test one bit; a position that passes the bit and the exact set is written
 * to a buffer instead of walked. The buffer is resolved when it fills and at the end of the extent: sorted
 * by directory bucket, one read per bucket, binary search inside it, the four bytes after the key compared
 * in the record, and only a candidate that still stands is verified by reading the marker from the pool
 * and handing it to kof_multimatch_pat_at.
 *
 * WHERE IT LIVES. A pack with a table big enough to be worth it (KOFPIX_EMBED_MIN, about 7000 markers) carries
 * it as a PART of its tail, beside the block index (databases/pack/dbkix.h: one container, two parts, one
 * footer, one sliced reader with a checksum a 64 KiB), and the loader opens it where it lies: pread, never
 * mapped. A pack without one - a smaller table, or a pack from before the part existed - gets the same table
 * built in memory from the pack's own sections (kofpix_build_pack) when it fits what the ledger leaves, and
 * the engine says so when it does not (KOF_PIX_B_*). One algorithm, two residencies.
 *
 * THE SET. The packs of a database are swept together (kofpix_set): a region is usually in several
 * packs, and sweeping each by itself read every byte once per pack (1.7 times the bytes the single table
 * it replaced read, on the shipping base). The set merges the packs' filters into one, so a region is read
 * once, and asks each pack's exact key set only where the merged filter said yes.
 *
 * THE BIT TABLE'S BUDGET. 8 MiB over every region of every pack by default, the knee of the measurement:
 * at 8e6 markers and a clean random 3.8 MB object, 1 / 2 / 4 / 8 MB of filter took 199 / 130 / 95 / 58 ms
 * with 9.2 / 9.9 / 11.4 / 14.4 MB resident in all. The ledger may grant less (a quarter of what it has
 * left); a grant below the default's level is reported as KOF_PIX_B_DEGRADED and costs time, not answers.
 *
 * WHERE A MARKER IS KEYED is the packer's choice and moves no answer (every position of a marker is a valid
 * key): the four bytes the fewest other markers of the region contain, and, when the packer is given what
 * ordinary files contain (kofpix_build_opt), not a gram that ordinary files are full of. Measured on a clean
 * ELF against a million markers, keying every hex program on the start of its run let 36% of positions
 * through the filter; keying it inside the run, 8%; and with the second rule, 6%.
 *
 * EXACT. The filter can only add work: a bit set for a hash no marker has costs one directory test.
 * Nothing the filter or the directory rejects can be a marker, because a marker's own key set its bit and
 * its directory slot. The record check compares bytes the marker really has. What is refused is refused by
 * the comparison the lazy path makes.
 *
 * THE BOUNDS. A hostile object can make every position pass the filter, can make every candidate need a
 * read, and - with a base whose markers share their key - can make every survivor walk a long run of
 * records already in memory. The reads of one object are bounded (KOFPIX_IO_FLOOR + 1/2 per byte swept),
 * so are the record visits (KOFPIX_WORK_FLOOR + KOFPIX_WORK_PER_BYTE per byte), and the table of what was
 * found is capped by the object's ledger share. Past a bound the sweep STOPS and REPORTS it
 * (KOFPIX_S_BUDGET / _WORK / _FOUND) and the caller must treat the region as not swept - its masks are then
 * answered by the lazy path, which is exact. A read that fails (a truncated pack) reports KOFPIX_S_IO, a
 * slice that fails its checksum KOFPIX_S_CRC, and both are the same thing. Never a silent "not found",
 * never a signal: the table is read with pread and its status is checked. The marker bytes of a table
 * built in memory are the one read that is not (they are in the pack's mapping, as the loader's own
 * string reads are).
 *
 * COLD CACHE. A table read from a cold pack costs a random read a bucket. The loader asks the system to
 * read the part in the background when it opens it (kof_prefetch: posix_fadvise WILLNEED where the system
 * has it, nothing elsewhere): page cache, not resident memory, and a hint nothing waits on.
 */
#ifndef KOFENG_KOFPIX_H
#define KOFENG_KOFPIX_H

#include <stdint.h>
#include <stddef.h>
#include "kofmatch.h"
#include "kofmultimatch.h"
#include "../../databases/pack/dbkix.h"   /* the tail container: struct kof_slices, struct kof_kix_io */
#include <kofmod/kofsig.h>   /* struct kof_range */

#define KOFPIX_MAGIC      0x3158504bu     /* "KPX1" */
#define KOFPIX_MAX_REG    30u             /* one table per region bit, like KOF_MULTIMATCH_BITS */
#define KOFPIX_REC_SIZE   24u
#define KOFPIX_DIR_BITS_MAX 16u
#define KOFPIX_FILTER_MIN_BITS 16u
#define KOFPIX_PAGE       4096u         /* what one read costs at least: kof_slices_read's unit */
#define KOFPIX_IO_FLOOR   4096u         /* reads an object may make before it has swept a byte */
/* One read per 2 bytes swept. A read costs a page, so a hostile megabyte may cost up to 2 GB of page-cache reads: about a
 * second, a floor near 1 MB/s (the tables this replaced: 1.2 MB/s at 4e6 markers on the same kind of object). Measured on
 * a clean 2 MB ELF swept over 0.5 MB of code: it needs 25,000 reads at 8e5 markers, 68,000 at 4e6 and 174,000 at
 * 8e6 (0.33 a byte; the base has 12% of its markers from system libraries, as a real one has). One per 8 was a bound
 * the object reached at 4e6 (98%) and passed at 8e6; one per 4 passed it too. A legitimate object that loses its
 * sweep makes every module search for itself - the per-marker cost the sweep exists to avoid - so the bound is set
 * where clean objects have 1.5 times the room at 8e6, not where a hostile one is cheap. */
#define KOFPIX_IO_SHIFT   1u
#define KOFPIX_WORK_FLOOR    ((uint64_t)1u << 20)   /* record visits an object may make before it has swept a byte */
#define KOFPIX_WORK_PER_BYTE 16u                    /* + this many per byte swept */
/* The filter budget over every region of every pack when the ledger is not asked (a test, a
 * table built outside an engine), and the most the loader asks it for: 8 MiB, the knee of the
 * measurement (kofpix.h, "THE BIT TABLE'S BUDGET"). */
#define KOFPIX_FILTER_DEFAULT ((uint64_t)8u << 20)

enum kofpix_status {
	KOFPIX_OK = 0,
	KOFPIX_E_FORMAT,       /* the section does not hold together */
	KOFPIX_E_IO,           /* a read failed or came back short: truncated pack */
	KOFPIX_E_CRC,          /* a slice of the table does not match its checksum */
	KOFPIX_E_NOMEM
};

/* What a sweep could not do. Zero is a complete answer for the region. */
#define KOFPIX_S_IO       0x1u    /* a read failed: the region is NOT swept */
#define KOFPIX_S_BUDGET   0x2u    /* the object's read bound was reached */
#define KOFPIX_S_FOUND    0x4u    /* the table of what was found is full */
#define KOFPIX_S_FORMAT   0x8u    /* a record contradicted the directory */
#define KOFPIX_S_NOMEM    0x10u   /* a buffer could not be made */
#define KOFPIX_S_WORK     0x40u   /* the object's allowance of record visits was spent (a run of equal keys): NOT swept */
#define KOFPIX_S_CRC      0x20u   /* a slice of the table failed its checksum: the region is NOT swept */

/* What loading the tables said: kdb_pattern_status. Zero is clean. None of these loses a marker: the
 * markers a missing or unusable table would have found are answered one at a time instead (exact). */
#define KOF_PIX_B_DEGRADED     0x01u  /* a filter coarser than the default: the ledger gave less (slower, as exact) */
#define KOF_PIX_B_IN_RAM       0x02u  /* a pack with a big table and no part: built in memory (repack) */
#define KOF_PIX_B_OVER_BUDGET  0x04u  /* a table did not fit the ledger: that pack's markers are searched one at a time */
#define KOF_PIX_B_OPEN_FAILED  0x08u  /* a table in a pack did not open (format, checksum, truncated): same */
#define KOF_PIX_B_NOMEM        0x10u  /* an allocation failed building a table: same */

/* ---- the builder (packer side) ------------------------------------------- */

/*
 * One marker as the packer holds it. `bytes` is the literal, or the compiled hex
 * program; `off`/`len` say where those bytes are in the pack's string pool (the
 * record carries them so a verify can read them). `regs` is the set of region
 * bits the marker can be asked about. The marker is NOT copied.
 */
struct kofpix_marker {
	const uint8_t *bytes;
	uint32_t       uid;        /* pack-local, as the string descriptor holds it */
	uint32_t       off;
	uint32_t       regs;
	uint16_t       len;
	uint8_t        kind;       /* KOF_STR_LITERAL / KOF_STR_HEX */
	uint8_t        flags;
};

struct kofpix_build_stat {
	uint64_t n_rec;            /* records, over every region */
	uint32_t n_reg;
	uint32_t n_skipped;        /* markers the sweep cannot key (left to the lazy path) */
	uint64_t max_run;          /* longest run of records sharing a hash */
};

/*
 * What the packer knows about ordinary files, to choose each marker's key by:
 * `common[hash >> (32 - common_bits)]` is how many clean files contain the
 * (lowercased) gram, and a gram at or above `common_thr` is "common". Optional;
 * without it keys are chosen by their rarity among the markers alone.
 */
struct kofpix_build_opt {
	const uint16_t *common;
	uint32_t        common_bits;
	uint32_t        common_thr;
};

/* The section, malloc'd, or NULL. The packer writes it at the tail of the pack. */
uint8_t *kofpix_build(const struct kofpix_marker *mk, uint32_t n, uint64_t *len,
		      struct kofpix_build_stat *st, const struct kofpix_build_opt *opt);

/*
 * THE TABLE OF ONE PACK, from the pack's own sections: the modules' records, the string
 * descriptors, the range masks and the string pool. One marker per pattern id, its regions the
 * union of the range masks of every module that declares it (the pairing of marker to range is
 * decided by the module's code at run time, so what the build can know is a superset, and a
 * superset only costs a probe that finds nothing). A marker that cannot be keyed (shorter than the
 * key, a hex program with a short concrete run, a program kof_hex_prog_valid refuses) is left out
 * and is answered by the exact per-marker path. The packer calls it with the arrays it just built
 * and the loader with the pack's mapping, so the two cannot disagree about what a table holds.
 * NULL with *len 0 when there is nothing to key; NULL with *len ~0 when memory ran out.
 */
struct kof_pack_mod;
struct kof_pack_str;
struct kofpix_pack_view {
	const struct kof_pack_mod *mod;
	uint32_t                   n_mod;
	const struct kof_pack_str *str;
	uint32_t                   n_str;
	const uint32_t            *rng;      /* the range masks, indexed by a module's rng_first */
	uint32_t                   n_rng;
	const uint8_t             *pool;
	uint64_t                   pool_len;
};
uint8_t *kofpix_build_pack(const struct kofpix_pack_view *v, uint64_t *len,
			   struct kofpix_build_stat *st);
/* A table smaller than this is not written into a pack: the loader builds it in memory in less time
 * than opening a part takes (measured in the report), and a pack of a few kilobytes does not grow
 * by tens. 256 KiB is about 7000 markers. */
#define KOFPIX_EMBED_MIN  ((uint64_t)256u << 10)

/* ---- the table (engine side) --------------------------------------------- */

/*
 * Where the table and the string pool are. The table is either a part of the pack read with pread
 * through the sliced reader (`sec`, borrowed: it must outlive the table) or, with `mem` set, the
 * whole table in memory (an old pack's table built at load, a test) and reads are copies. The
 * pool is read with pread from `fd` at `pool_off`, or from `pool_mem` (the pack's mapping, for a
 * table built at load: the same exposure the loader's own string reads have; a table read from
 * the pack never touches it). A record whose bytes lie outside `pool_len` is refused.
 */
struct kofpix_src {
	const struct kof_slices *sec;
	const uint8_t  *mem;
	uint64_t        sec_len;
	int             fd;
	uint64_t        pool_off, pool_len;
	const uint8_t  *pool_mem;
};

struct kofpix_open_req {
	struct kofpix_src src;
	uint64_t       filter_budget;    /* bytes the ledger granted for every region's filter */
	uint64_t       filter_default;   /* what it would have been without pressure: the filter
					  * is DEGRADED when the grant buys a coarser level */
	uint32_t       uid_base;
	int            own_mem;          /* `src.mem` is freed with the table (success only) */
};

struct kofpix_open_res {
	enum kofpix_status status;
	uint32_t       degraded;         /* regions whose filter is coarser than the default's */
	uint32_t       n_reg, max_run;
	uint64_t       n_ent;
	uint64_t       resident;         /* what the open table holds in memory */
};

struct kofpix;
struct kofpix_set;

struct kofpix *kofpix_open(const struct kofpix_open_req *rq, struct kofpix_open_res *res);
void           kofpix_close(struct kofpix *);
/* What the table holds resident: directories and filters, not the records. */
uint64_t       kofpix_resident(const struct kofpix *);
uint32_t       kofpix_region_n(const struct kofpix *, uint32_t bit);

/* ---- the set: every pack's table, swept together ------------------------- */

/*
 * The tables of every pack, ready to sweep. A region is usually in several packs (the detector
 * pack, the heuristic pack and the unpack pack of one format) and sweeping each table by itself
 * reads every byte of the region once per pack - 1.7 times the bytes the single table this
 * replaced read, measured on the shipping base. The set reads a region once for all of them: one hash
 * a position and one probe of a filter that is the OR of every table's; only a position that
 * passes is asked of each table's exact key set. Regions whose tables fold case differently are two
 * groups, so a region is read at most twice.
 *
 * kofpix_set_make TAKES THE FILTERS of the tables it merges (it frees theirs and leaves a view of
 * the merged one), so the tables are swept through the set from then on. The set borrows the
 * tables: free it first. NULL when memory ran out.
 */
struct kofpix_set *kofpix_set_make(struct kofpix **px, uint32_t n);
void               kofpix_set_free(struct kofpix_set *);
uint32_t           kofpix_set_regions(const struct kofpix_set *);   /* bit set: regions with a table */
uint64_t           kofpix_set_resident(const struct kofpix_set *);  /* what merging added */
int                kofpix_set_reads_file(const struct kofpix_set *); /* some table is read with pread (NULL: assumed) */

/* ---- one scanner's state ------------------------------------------------- */

struct kofpix_surv { uint64_t pos; uint32_t g; uint32_t pad; };

struct kofpix_found {
	uint32_t *key;             /* uid + 1, 0 = empty */
	uint32_t *bits;
	uint32_t  cap, n, cap_max;
	uint8_t   full;
};

struct kofpix_ctx {
	struct kofpix_surv *surv, *tmp;
	uint32_t   surv_cap;
	uint8_t   *slice;          /* one bucket of records, read once per flush */
	uint32_t   slice_cap;
	uint8_t   *pool_buf;       /* the marker cache: KOFPIX_POOL_SLOTS slots */
	uint64_t  *pool_key;       /* (off + 1) << 20 | len, 0 = empty */
	const struct kofpix **pool_own;  /* whose pool the slot came from: two packs share one context */
	uint32_t  *tab_cnt;        /* survivors per table, when a region has several */
	uint32_t   tab_cap;
	uint8_t   *big;            /* the one marker too long for a slot */
	size_t     big_cap;
	struct kofpix_found found;
	struct kof_kix_io io;      /* this object's reads: what they cost, what is allowed, why one failed */
	uint64_t   work_left;      /* record visits this object may still make (kofpix.c: work_take) */
	uint64_t   io_floor;       /* the bound, settable so a test can raise or lower it */
	uint32_t   io_shift;
	/* what the sweeps of this object did, for the stats and the tests */
	uint64_t   n_survivors, n_slice_reads, n_pool_reads, n_pool_hits, n_cand, n_verify, n_flush;
	uint32_t   status;         /* every sweep of this object, ORed */
	uint32_t   last;           /* the sweep just made: nonzero = that region is NOT swept */
};

#define KOFPIX_POOL_SLOTS 4096u
#define KOFPIX_POOL_SLOT  256u

int  kofpix_ctx_init(struct kofpix_ctx *, const struct kofpix_set *, uint64_t found_max_bytes);
void kofpix_ctx_free(struct kofpix_ctx *);
uint64_t kofpix_ctx_fixed(const struct kofpix_set *);
uint64_t kofpix_ctx_held(const struct kofpix_ctx *);
void     kofpix_ctx_limit(struct kofpix_ctx *, uint64_t room);
/* Per object: forget what was found. */
void kofpix_ctx_begin(struct kofpix_ctx *);

/*
 * Sweep one region's extents. Returns the bytes walked. After it, c->last says
 * whether the answer for the region is complete (0) or the caller must not treat
 * "not found" as absent; c->status is the OR over the object's sweeps.
 */
uint64_t kofpix_sweep(const struct kofpix_set *, struct kofpix_ctx *, uint32_t bit,
		      struct kof_match_ctx *m, const struct kof_range *ext, uint32_t n_ext);

/* Region bits in which this marker was found (global uid = uid_base + pack uid). */
uint32_t kofpix_found_get(const struct kofpix_ctx *, uint32_t uid);

#endif /* KOFENG_KOFPIX_H */
