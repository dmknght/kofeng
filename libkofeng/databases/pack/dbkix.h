/*
 * dbkix.h - THE BLOCK INDEX AS A CONTAINER: sorted entries in the pack, a small
 * directory and a filter in memory.
 *
 * WHY IT EXISTS. The similarity matcher answers "which blocks hold this window hash?" for
 * every window of every object. It used to build a hash table over every block hash at
 * load: 27 bytes a hash resident, so a database of 8,000,000 hashes cost 209 MB and one of
 * 32,000,000 cost 870 MB - past the engine's 512 MiB cap (kofbudget.h) by itself. The cost
 * has to follow the OBJECT, not the database.
 *
 * WHAT IT IS. A trailer appended to a pack, after the last section and inside the length
 * the header states:
 *
 *   hdr       256 B + a table of up to 256 CLASSES {region mask, normaliser, side}: what a
 *             block has to match for a window of some call to credit it. An entry names its
 *             class in one byte, so a credit is decided without reading the block table.
 *   dir       65,537 x u32: where the entries of bucket b start. A bucket is the top 16 bits
 *             of the hash multiplied by an odd constant (below). 257 KB, in memory.
 *   crc       one CRC-32 per 64 KiB of body.
 *   body      7 bytes an entry, grouped by bucket and in each bucket three columns:
 *                lo16[n] (u16) | ref[n] (u32, block << 8 | slot) | cls[n] (u8)
 *             sorted by (lo16, ref). Read with pread, never mapped: a file that is shorter
 *             than it said is a short read and an error status; a mapping would be a signal.
 *   filter    a blocked bloom filter (64-byte lines, K bits in a line) over the same keys.
 *             The stored size is the DEFAULT; the loader may fold it smaller to fit the
 *             engine's memory ledger (kof_kix_filter_or), and a false pass only costs a read.
 *   footer    64 B at the end of the file: where the trailer starts, how long its parts
 *             are, the CRC of the old part of the pack, the CRC of everything above `body`.
 *
 * WHY THE KEY IS MULTIPLIED. A block holds the SMALLEST hashes of its span (celllysis/
 * mutation.h), so the values in a database crowd towards zero; bucketing by the top 16 bits
 * of those would put 66 to 400 times the mean in the busiest bucket (simulated). v * KOF_KIX_MULT
 * (odd, so a bijection of 32-bit values: no two hashes merge) spreads them. It is exact.
 *
 * NO FORMAT BUMP. A pack header carries file_len and a CRC of everything after itself; the
 * packer writes both for the pack WITH the trailer, so an engine that does not know it
 * loads the pack as one with a long tail. Every record keeps its layout. The footer is how
 * a newer engine tells: it checks the CRC of the OLD part, then the trailer's own parts as
 * it uses them, and does not read the body at load.
 *
 * ONE CONTAINER, TWO PARTS. A pack's tail is a chain of parts, each ending in the same 64-byte
 * footer (struct kof_kix_footer; the magic says which part it is) and each read with pread through
 * the same sliced reader (struct kof_slices: one CRC per 64 KiB of body, checked the first time a
 * slice is read, the answer shared). The parts, in file order:
 *
 *   [old pack] [pattern table, footer "KPXF"] [block index, footer "KIXF"]
 *
 * Either may be absent; the LAST part's footer is the last 64 bytes of the file, and the footer
 * of the part before it ends where the last part starts. Both footers carry where the old pack
 * ends and its CRC, so an engine that knows only the block index (an older build) finds the old
 * part and the block index and treats the pattern table as a gap it does not read. Nothing in
 * the reading half knows what a block or a marker is except kof_kix_block* and kofpix.c.
 *
 * Not for a module: the module ABI does not see this.
 */

#ifndef KOFENG_DBKIX_H
#define KOFENG_DBKIX_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#include <kofmod/kofmutation.h>   /* struct kof_mutation_block */

#define KOF_KIX_MAGIC_HDR   0x3158494bu      /* "KIX1" */
#define KOF_KIX_MAGIC_FOOT  0x4658494bu      /* "KIXF": the block index's footer */
#define KOF_PIX_MAGIC_FOOT  0x4658504bu      /* "KPXF": the pattern table's footer */
#define KOF_KIX_VERSION     1u
/* A trailer with an extension region (the pre-built filter the packer stores, kof_kix_make's `xf`): the
 * same layout with the region where the bloom filter was, and a version an engine that does not know it
 * refuses by the footer, so it loads the pack as one without a trailer instead of misreading the tail. */
#define KOF_KIX_VERSION_XF  2u
#define KOF_KIX_XF_FUSE     1u               /* the extension is a detectors/mutations/kofmutflt.h region */

#define KOF_KIX_DIR_BITS    16u
#define KOF_KIX_N_DIR       (1u << KOF_KIX_DIR_BITS)
#define KOF_KIX_SLICE_SHIFT 16u              /* one CRC per 64 KiB of body */
#define KOF_KIX_SLICE       (1u << KOF_KIX_SLICE_SHIFT)
#define KOF_KIX_ENTRY       7u               /* body bytes an entry: lo16 + ref + cls */
#define KOF_KIX_MAX_CLASS   256u
#define KOF_KIX_ALIGN       64u

/* The key mix. Odd: v -> v * MULT (mod 2^32) is a bijection. */
#define KOF_KIX_MULT        0x9E3779B1u

/* Probes in a 64-byte filter line. One constant, because a merged filter (several packs, or
 * a folded one) is only valid if every part used the same. Chosen by the measurement in the
 * header of dbkix.c. */
#define KOF_KIX_FILTER_K    4u
#define KOF_KIX_FILTER_MIN  4096u            /* bytes: 64 lines */

/* The classes: what a block has to say about itself for a call to credit it. */
struct kof_kix_class {
	uint32_t mask;            /* the block's scan_mask */
	uint8_t  norm;
	uint8_t  side;
	uint16_t pad;
};

/* On disk, native byte order like the rest of a pack (a pack is built for its machine). */
struct kof_kix_hdr {
	uint32_t magic, version;
	uint32_t n_block, n_class;
	uint64_t n_pair;
	uint32_t n_key;           /* distinct hash values */
	uint32_t max_mult;        /* most entries one value has */
	uint32_t top;             /* the largest RAW hash: a window above it is in no block */
	uint32_t mult;            /* KOF_KIX_MULT at build time: read, not assumed */
	uint32_t dir_bits, slice_shift;
	uint32_t filter_k, entry; /* entry: KOF_KIX_ENTRY */
	uint64_t filter_bytes;
	uint32_t filter_crc;
	uint32_t n_slice;
	/* Offsets from the start of the trailer. */
	uint64_t off_class, off_dir, off_crc, off_body, body_len, off_filter;
	/* Version 2 only (zero in version 1): the extension region, where the filter would be. The bloom
	 * filter is then absent (filter_bytes 0): the extension is the filter. */
	uint64_t off_xf, xf_bytes;
	uint32_t xf_crc, xf_kind;
	uint8_t  reserved[112];
};

/*
 * The footer both parts end with. Fields as the block index ("KIXF") uses them; the pattern
 * table ("KPXF") reads them this way: trailer_off is where the part starts (its first byte is
 * the table's header), body_len is the length of the table, meta_len the length of the slice
 * CRC table that follows the table (padded to 64), filter_off where that CRC table starts
 * (from trailer_off), meta_crc the CRC of that table, n_item the markers in it.
 */
struct kof_kix_footer {
	uint32_t magic, version;
	uint64_t trailer_off;     /* the file offset of the header */
	uint64_t meta_len;        /* header .. crc table, which meta_crc covers; the body starts here */
	uint64_t body_len;
	uint64_t filter_off;      /* from trailer_off */
	uint64_t old_len;         /* where the pack as an older engine knows it ends */
	uint32_t old_crc;         /* CRC-32 of [KOF_PACK_CRC_FROM, old_len) */
	uint32_t meta_crc;
	uint32_t n_item;          /* blocks (KIXF) or markers (KPXF) */
	uint32_t footer_crc;      /* of the 60 bytes before it */
};

_Static_assert(sizeof(struct kof_kix_hdr) == 256u, "kix header is 256 bytes");
_Static_assert(sizeof(struct kof_kix_class) == 8u, "kix class is 8 bytes");
_Static_assert(sizeof(struct kof_kix_footer) == 64u, "kix footer is 64 bytes");

/* Why a build or an open said no. A set bit is a reason; none is success. */
#define KOF_KIX_B_NOMEM          0x01u
#define KOF_KIX_B_TOO_BIG        0x02u   /* more entries than 32-bit offsets address */
#define KOF_KIX_B_TOO_MANY_BLOCKS 0x04u
#define KOF_KIX_B_BAD_BLOCK      0x08u
#define KOF_KIX_B_TOO_MANY_CLASSES 0x10u /* more than KOF_KIX_MAX_CLASS distinct (mask, norm, side) */
#define KOF_KIX_B_OVER_BUDGET    0x20u   /* the image would pass max_bytes */

/* Reasons a READ failed, ORed into kof_kix_io.err. Never silent: the matcher turns them into
 * a status of the object, and counts only fall. */
#define KOF_KIX_E_IO             0x01u   /* short read or an error: a truncated or vanished file */
#define KOF_KIX_E_CRC            0x02u   /* a 64 KiB slice does not match its CRC */
#define KOF_KIX_E_BUDGET         0x04u   /* the object's I/O allowance is spent */

struct kof_kix_build_in {
	const struct kof_mutation_block *blk;
	uint32_t        n_blk;
	const uint32_t *pool;
	uint32_t        n_pool;
	/* Stored filter: `filter_bytes` (0: derived from the distinct keys at `filter_bpk` bits
	 * each, 0: KOF_KIX_FILTER_BPK; a power of two, at least KOF_KIX_FILTER_MIN, at most
	 * KOF_KIX_FILTER_CAP). */
	uint32_t        filter_bpk;
	uint64_t        filter_bytes;
	uint64_t        max_bytes;      /* 0: none. The image, charged before it is allocated. */
	/* An extension region to store instead of the bloom filter (version 2; filter_* are then ignored):
	 * kind KOF_KIX_XF_FUSE, built by the caller from the distinct multiplied keys. Copied. */
	const uint8_t  *xf;
	uint64_t        xf_bytes;
	uint32_t        xf_kind;
};

struct kof_kix_build_res {
	uint32_t status;                /* KOF_KIX_B_* */
	uint32_t n_pair, n_key, max_mult, n_class;
	uint64_t filter_bytes;
	uint64_t xf_bytes;              /* the extension region stored instead (0: none) */
	uint64_t bytes;                 /* the image; also what was asked for when refused */
};

/* Bits a key gets in the stored filter by default, and the most bytes it may take. Chosen by the
 * measurement in the header of dbkix.c (false passes against time and memory). */
#define KOF_KIX_FILTER_BPK  16u
#define KOF_KIX_FILTER_CAP  ((uint64_t)16u << 20)
/* A filter that holds fewer bits than this a distinct key is DEGRADED (the ledger, or the cap, gave it less
 * than the default sizing, which never goes below it); the matcher says so and the false-pass rate follows. */
#define KOF_KIX_FILTER_FLOOR_BPK 12u

/* The filter's default size for `n_keys` at `bpk` bits each (0: KOF_KIX_FILTER_BPK): a power of two
 * of at least KOF_KIX_FILTER_MIN and at most KOF_KIX_FILTER_CAP, rounded UP unless that would give a key
 * more than a third more bits than asked (so 12 to 24 bits a key, not 16 to 32). The one place this
 * is decided: the packer writes it and the matcher asks the ledger for it. */
uint64_t kof_kix_filter_default(uint64_t n_keys, uint32_t bpk);

/* What the image of `n_pair` entries with a filter of `filter_bytes` costs (the trailer: header, directory,
 * slice table, body, filter, footer), and the transient scratch a build also needs besides the sort's:
 * the directory's counters. A caller deciding what fits asks here, so that its answer and the
 * writer's check cannot differ. */
uint64_t kof_kix_image_bytes(uint64_t n_pair, uint64_t filter_bytes);
#define KOF_KIX_SCRATCH (2ull * 4u * (KOF_KIX_N_DIR + 1u))

/*
 * BUILD the trailer image for `in`, ready to be appended to a pack at file offset
 * `trailer_off` whose old part ends at `old_len` with CRC `old_crc` - the footer carries
 * all three. Returns a malloc'd image of *len bytes (footer included) or NULL with
 * res->status set. A set that is not a valid description (a block that slices past the
 * pool, an n_hash outside the limits, a normaliser the engine does not have) is refused
 * the way the matcher refuses it.
 */
uint8_t *kof_kix_make(const struct kof_kix_build_in *in, uint64_t trailer_off,
		      uint64_t old_len, uint32_t old_crc, uint64_t *len,
		      struct kof_kix_build_res *res);

/* Put the CRC of the old part into a finished image's footer (and the footer's own CRC). The
 * packer cannot know it when it builds the trailer: the old part includes the header, whose
 * file_len is the length WITH the trailer. */
void kof_kix_seal(uint8_t *image, uint64_t len, uint32_t old_crc);

/* ---- reading ------------------------------------------------------------------ */

struct kof_kix;

/* Where the old part of the pack that the index needs lives: its block table and hash pool,
 * as ABSOLUTE file offsets, and the descriptor everything is read through (borrowed; it
 * must stay open until kof_kix_close). */
struct kof_kix_loc {
	int      fd;
	uint64_t file_size;
	uint64_t blk_off, pool_off;
	uint32_t n_blk, n_pool;
};

/* Is there a trailer? 0: no, nothing to say (an old pack, or a footer this build cannot read:
 * both load as a pack without one, and the whole-file CRC then decides). 1: yes, `*ft` is the
 * footer, its own CRC and its offsets checked against `size`. A descriptor that cannot be
 * read answers 0, which the full CRC then reports as it always did. */
int kof_kix_probe(int fd, uint64_t size, struct kof_kix_footer *ft);

/*
 * OPEN what kof_kix_probe found. Reads the header, the class table, the directory and the
 * slice CRCs, checks them against the footer's CRC, streams the filter through its CRC,
 * and validates every number it will use without a further check: a directory that does
 * not climb to n_pair, offsets that leave the file, counts that disagree with the pack's.
 * It does not read the body. NULL with `why` filled (and nothing leaked) on any failure -
 * the loader refuses that pack on its own.
 */
struct kof_kix *kof_kix_open_file(const struct kof_kix_loc *loc,
				  const struct kof_kix_footer *ft,
				  char *why, size_t why_len);

/* The same reading over an image in memory (kof_kix_make's), taken over: freed by
 * kof_kix_close. `blk` and `pool` are borrowed and must outlive it. Used for a pack that
 * has no trailer (built under the ledger) and for tests. */
struct kof_kix *kof_kix_open_mem(uint8_t *image, uint64_t len,
				 const struct kof_mutation_block *blk, uint32_t n_blk,
				 const uint32_t *pool, uint32_t n_pool,
				 char *why, size_t why_len);

void kof_kix_close(struct kof_kix *k);

struct kof_kix_info {
	uint32_t n_block, n_key, max_mult, top, mult, n_class, filter_k;
	uint64_t n_pair, body_len, filter_bytes;
	uint64_t xf_bytes;              /* the extension region (0: none), its CRC and kind */
	uint32_t xf_crc, xf_kind;
	uint64_t resident;              /* what the handle holds in memory */
	int      in_memory;
};
void kof_kix_info(const struct kof_kix *k, struct kof_kix_info *out);

/* The directory: n_dir + 1 offsets, in entries. Valid while the handle is. */
const uint32_t *kof_kix_dir(const struct kof_kix *k);
const struct kof_kix_class *kof_kix_class(const struct kof_kix *k, uint32_t *n);

/*
 * One scanner's reading account: what it has asked for this object, what it may ask for,
 * and why a read failed. A read costs its bytes or one page, whichever is more, because a
 * thousand reads of two bytes are not free.
 */
struct kof_kix_io {
	uint64_t bytes, reads;          /* actually read, slice checks included */
	uint64_t spent, budget;         /* cost units used / allowed; budget 0: none allowed */
	uint32_t err;                   /* KOF_KIX_E_* */
};

/* Read body bytes [off, off + n). Every 64 KiB slice the range touches is checked against
 * its CRC the first time it is read (by any scanner; the answer is shared). 1 on success;
 * on failure 0 and io->err says why - a slice that failed stays failed, so every later
 * read of it says so too. Safe from many threads. */
int kof_kix_body(const struct kof_kix *k, uint64_t off, void *out, size_t n,
		 struct kof_kix_io *io);

/* Block `b` (local to this pack): its record, and its hashes (at most KOF_MUTATION_MAX_HASH).
 * Read through the descriptor, checked again against the pool length: the file may have
 * changed since it was validated. 0 on failure, with io->err (io may be NULL). */
int kof_kix_block(const struct kof_kix *k, uint32_t b, struct kof_mutation_block *out,
		  struct kof_kix_io *io);
int kof_kix_block_hashes(const struct kof_kix *k, uint32_t b, uint32_t *out,
			 uint32_t *n_out, struct kof_kix_io *io);

/* Read `n` bytes at `off` of the extension region (0 when that would pass its end). The region's CRC (kof_kix_info:
 * xf_crc) is the reader's to check as it streams the region: open does not read it. */
int kof_kix_xf_read(const struct kof_kix *k, uint64_t off, void *out, size_t n);

/*
 * OR this index's stored filter into `dst` (`dst_bytes`, a power of two, at least
 * KOF_KIX_FILTER_MIN), whatever size it was stored at: a larger stored filter is folded (lines
 * that share their high bits are ORed together - a window that passed still passes) and a smaller
 * one is repeated. 1 on success, 0 on a read error. `dst` must be zeroed by the caller once;
 * several indexes are ORed into the same one.
 */
int kof_kix_filter_or(const struct kof_kix *k, uint8_t *dst, uint64_t dst_bytes);

/* ---- the sliced reader, shared by both parts ----------------------------------- */

/*
 * A body of bytes in a file (read with pread, never mapped) or in memory, with one CRC-32 per
 * 64 KiB. A slice is checked against its CRC the first time any read touches it, by whoever
 * reads it; the verdict (good or bad) is stored and shared, so a slice that failed fails every
 * later read too. Safe from many threads. A file shorter than it was measured is a short read
 * and KOF_KIX_E_IO, a wrong byte is KOF_KIX_E_CRC: never a signal and never a wrong answer.
 */
struct kof_slices {
	int              fd;
	const uint8_t   *mem;          /* non-NULL: read from this buffer, not the descriptor */
	uint64_t         base;         /* where the bytes the body lies in start, in the file or buffer */
	uint64_t         src_len;      /* how many bytes from `base` may be read */
	uint64_t         body_off;     /* the body, from `base` */
	uint64_t         body_len;
	uint32_t         n_slice;
	uint32_t        *crc;          /* owned: n_slice words */
	_Atomic uint8_t *ok;           /* owned: 0 unchecked, 1 good, 2 bad */
};

struct kof_slices_req {
	int             fd;
	const uint8_t  *mem;
	uint64_t        base, src_len, body_off, body_len;
	const uint32_t *crc;           /* n_slice words, copied */
	int             verified;      /* the bytes are known good (just built): no per-slice check */
};

/* 1 on success; 0 when memory ran out or the request does not hold together (nothing left allocated). */
int  kof_slices_init(struct kof_slices *s, const struct kof_slices_req *rq);
void kof_slices_done(struct kof_slices *s);
/*
 * Read body bytes [off, off + n) into `out`. With `io`: the read costs its bytes or one page,
 * whichever is more, against io->budget (KOF_KIX_E_BUDGET when spent), and the bytes and reads
 * are counted; without it the read is free (an open, a build). 1 on success, 0 with io->err set.
 */
int  kof_slices_read(const struct kof_slices *s, uint64_t off, void *out, size_t n,
		     struct kof_kix_io *io);

/* ---- the tail of a pack: which parts it has ------------------------------------- */

struct kof_tail {
	int                   has_kix, has_pix;
	struct kof_kix_footer kix, pix;     /* valid when the part is there */
	uint64_t              old_len;      /* the pack as an older engine reads it, and its CRC */
	uint32_t              old_crc;
};

/*
 * What the end of the file says. 0: no part (an old pack, or a footer this build cannot read;
 * both load as a pack with no tail and the whole-file CRC then decides). 1: at least one part, `*t`
 * filled, every footer's own CRC and offsets checked against `size`. The pattern part counts only
 * when it agrees with the block index about where the old pack ends (a pack that says two things is
 * read as the one an older engine would read: without the pattern part). A descriptor that cannot be
 * read answers 0, which the full CRC then reports as it always did.
 */
int kof_tail_probe(int fd, uint64_t size, struct kof_tail *t);

/*
 * THE PATTERN PART's image: `sec` (the table kofpix_build made, `sec_len` bytes) at file offset
 * `at`, padded, followed by the slice CRC table and the footer. Returns a malloc'd image of *len
 * bytes whose first byte is file offset `at` (64-aligned), or NULL. The footer carries `old_len`
 * and `old_crc` as the block index's does; the caller seals the CRC afterwards (kof_kix_seal) when
 * it cannot know it yet.
 */
uint8_t *kof_pix_make(const uint8_t *sec, uint64_t sec_len, uint32_t n_item, uint64_t at,
		      uint64_t old_len, uint32_t old_crc, uint64_t *len);

/*
 * OPEN what kof_tail_probe found for the pattern part: reads the slice CRC table, checks it
 * against the footer's CRC, and initialises `*sl` over the table's bytes. The descriptor is
 * borrowed. 0 with `why` filled and nothing left allocated.
 */
int kof_pix_open_file(int fd, uint64_t file_size, const struct kof_kix_footer *ft,
		      struct kof_slices *sl, char *why, size_t why_len);

/* ---- the filter itself, shared by the builder, the folder and the matcher ------- */

/* `vp` is the MULTIPLIED key. `lbits` is log2(lines). */
static inline uint32_t kof_kix_flt_line(uint32_t vp, uint32_t lbits)
{
	return (vp * 0x85EBCA6Bu) >> (32u - lbits);
}

static inline uint64_t kof_kix_flt_bits(uint32_t vp)
{
	return (uint64_t)vp * 0x9E3779B97F4A7C15ull;
}

/* Does the filter hold `vp`? One 64-byte line, KOF_KIX_FILTER_K bits in it. */
static inline int kof_kix_flt_test(const uint8_t *flt, uint32_t lbits, uint32_t vp)
{
	const uint64_t *line = (const uint64_t *)(const void *)(flt + ((uint64_t)kof_kix_flt_line(vp, lbits) << 6));
	uint64_t y = kof_kix_flt_bits(vp);
	uint32_t i;

	for (i = 0; i < KOF_KIX_FILTER_K; i++) {
		uint32_t bit = (uint32_t)(y >> (64u - 9u * (i + 1u))) & 511u;

		if (!((line[bit >> 6] >> (bit & 63u)) & 1u))
			return 0;
	}
	return 1;
}

static inline void kof_kix_flt_add(uint8_t *flt, uint32_t lbits, uint32_t vp)
{
	uint64_t *line = (uint64_t *)(void *)(flt + ((uint64_t)kof_kix_flt_line(vp, lbits) << 6));
	uint64_t y = kof_kix_flt_bits(vp);
	uint32_t i;

	for (i = 0; i < KOF_KIX_FILTER_K; i++) {
		uint32_t bit = (uint32_t)(y >> (64u - 9u * (i + 1u))) & 511u;

		line[bit >> 6] |= (uint64_t)1 << (bit & 63u);
	}
}

/* log2 of a power of two (a filter's byte size >> 6 is its line count). */
static inline uint32_t kof_kix_flt_lbits(uint64_t bytes)
{
	uint32_t l = 0;

	bytes >>= 6;
	while (bytes > 1u) {
		bytes >>= 1;
		l++;
	}
	return l;
}

#endif /* KOFENG_DBKIX_H */
