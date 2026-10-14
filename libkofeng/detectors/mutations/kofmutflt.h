/*
 * kofmutflt.h - THE BLOCK FILTER THAT FOLLOWS THE LEDGER: a partitioned binary fuse filter that the
 * packer builds, the pack stores, and the loader reads without building anything, plus the one
 * rule that sizes it from the engine's memory ledger.
 *
 * WHAT IT ANSWERS. "Can this 32-bit window hash be in any block?" - no false rejects (a key that
 * was added always passes), a false pass costs one read of the index and never a wrong credit.
 * The key is the MULTIPLIED hash (KOF_KIX_MULT), the same one the index is bucketed by.
 *
 * WHY NOT THE BLOOM FILTER OF dbkix.h. A blocked bloom filter needs ~16 bits a key for a 0.2% false
 * pass rate and cannot be shrunk without raising it fast (measured: dbmem_algorithms.md). A binary
 * fuse filter holds a fingerprint of r bits in 1.125 r bits a key (r = 8: 9.1 bits, 0.39% false
 * pass). It is built once, offline, from the distinct keys; the loader only copies it.
 *
 * WHY THE SIZE IS A LADDER AND NOT A CAP. The fingerprints are XORs, and the low w bits of an XOR are
 * the XOR of the low w bits, so a filter stored at r bits is also a valid filter at w < r bits by
 * truncating every entry while it is read: the false-pass rate goes from 2^-r to 2^-w and the
 * memory from 1.125 r to 1.125 w bits a key, with nothing rebuilt. That is the "halve until the
 * ledger grants it" step, exact: w = 16, 8, 4, 2, 1. Below one bit the filter covers fewer
 * partitions: a partition that is not resident passes every window (a cost, never a loss).
 *
 * PARTITIONS. The keys are cut by their top bits into parts of at most 2^21 keys, each its own
 * filter with its own seed. The packer's memory is one part, a part builds in a fraction of a
 * second, and a part is the unit the loader may leave out.
 *
 * ON DISK (native byte order like the rest of a pack), the "xf region" of a dbkix trailer:
 *
 *   header   64 B   magic, version, r, part_bits, n_part, n_key, region length
 *   table    32 B x n_part    seed, offset of the entries, key count, segment shape
 *   entries  per part (seg_count + 2) * seg_len entries of r bits (8 or 16: bytes, or u16)
 *
 * The region is covered by the CRC the dbkix header keeps for it, and every number the matcher
 * will use is checked when it is opened.
 */

#ifndef KOFENG_KOFMUTFLT_H
#define KOFENG_KOFMUTFLT_H

#include <stdint.h>
#include <stddef.h>

#include "../../databases/pack/dbkix.h"   /* the bloom filter's inline test, and struct kof_kix */

#define KOF_MFLT_MAGIC       0x544c464du      /* "MFLT" */
#define KOF_MFLT_VERSION     1u
#define KOF_MFLT_HDR_LEN     64u
#define KOF_MFLT_PART_LEN    32u
#define KOF_MFLT_PART_KEYS   (1u << 21)       /* most keys a part is cut to */
#define KOF_MFLT_MAX_PART_BITS 16u
#define KOF_MFLT_MAX_SEG_LOG 18u

/* Fingerprint widths the packer may store, and the narrowest the loader keeps. */
#define KOF_MFLT_R_DEFAULT   8u
#define KOF_MFLT_R_MAX       16u
/* A resident width below this has a false-pass rate above 1%: the matcher reports it as degraded. */
#define KOF_MFLT_W_FLOOR     8u

/* Build reasons, ORed. None is success. */
#define KOF_MFLT_B_NOMEM     0x01u
#define KOF_MFLT_B_BAD_ARG   0x02u            /* r not 8 or 16, keys not ascending and distinct */
#define KOF_MFLT_B_NO_SEED   0x04u            /* a part would not peel in the attempts allowed (never seen) */

/* ---- the packer's half ------------------------------------------------------- */

/* How many bytes the region of `n_key` keys at `r` bits takes (an upper bound the build never passes). */
uint64_t kof_mflt_region_bytes(uint64_t n_key, uint32_t r);

/*
 * BUILD the region for `keys[0, n)`: MULTIPLIED keys, strictly ascending. Returns a malloc'd
 * region of *len bytes, or NULL with *status set. Peak memory: the region and about 14 bytes a key of
 * the largest part (<= 2^21 keys: 30 MB), whatever the size of the set.
 */
uint8_t *kof_mflt_build(const uint32_t *keys, uint64_t n, uint32_t r, uint64_t *len,
			uint32_t *status);

/* ---- the loader's half ------------------------------------------------------- */

struct kof_mflt;

/* Reads `n` bytes at `off` of the region into `buf`: 1 on success. */
typedef int (*kof_mflt_read_fn)(void *ctx, uint64_t off, void *buf, size_t n);

struct kof_mflt_io {
	kof_mflt_read_fn read;
	void            *ctx;
	uint64_t         len;          /* the region's length: the read never asks past it */
};

struct kof_mflt_info {
	uint32_t r, part_bits, n_part;
	uint64_t n_key;
	uint64_t entries;              /* sum of the parts' entries */
	uint64_t max_entries;          /* the largest part's */
	uint64_t bytes_w[5];           /* resident bytes, handle included, all parts, at w = 1, 2, 4, 8, 16 */
};

/* Read and check the header and the table (not the entries). 1 on success, else 0 and `why`. */
int kof_mflt_probe(const struct kof_mflt_io *io, struct kof_mflt_info *info,
		   char *why, size_t why_len);

/* What the resident filter costs at width `w` (1, 2, 4, 8 or 16, at most info->r) with `n_res`
 * of its parts resident (0: all): the figure kof_mflt_open will charge, handle included. */
uint64_t kof_mflt_bytes(const struct kof_mflt_info *info, uint32_t w, uint32_t n_res);

/*
 * OPEN: read the entries through `io` in slices, keep the low `w` bits of each, and for the first
 * `n_res` parts only (0: all of them; a part that is left out passes every key). The CRC of
 * the whole region is computed on the way and must equal `crc` (a damaged byte is a NULL here, never a
 * wrong answer later). Nothing is built.
 */
struct kof_mflt *kof_mflt_open(const struct kof_mflt_io *io, uint32_t w, uint32_t n_res,
			       uint32_t crc, char *why, size_t why_len);
void kof_mflt_close(struct kof_mflt *f);

struct kof_mflt_stat {
	uint32_t w, n_part, n_res;
	uint64_t resident;
	uint64_t n_key;
};
void kof_mflt_stat(const struct kof_mflt *f, struct kof_mflt_stat *out);

/* Is `vp` (a MULTIPLIED key) possibly in the set? 1: maybe, 0: no. */
int kof_mflt_test(const struct kof_mflt *f, uint32_t vp);

/*
 * THE SAME QUESTION IN TWO STEPS, for a loop that has many windows to ask about: `kof_mflt_pre` hashes the key,
 * works out its three slots and PREFETCHES them; `kof_mflt_post` reads them. A caller that runs the first for
 * 16 windows and then the second for the same 16 has the three cache misses of every window in flight together
 * (measured: 22 ns a window becomes 7 at 32,000,000 keys, where the filter is 34 MB). Same answer as kof_mflt_test.
 */
struct kof_mflt_pre {
	const uint8_t *arr;            /* NULL: decided already, `fp` is the answer */
	uint32_t h0, h1, h2, fp;
};
void kof_mflt_pre(const struct kof_mflt *f, uint32_t vp, struct kof_mflt_pre *p);
int kof_mflt_post(const struct kof_mflt *f, const struct kof_mflt_pre *p);

/* ---- the size rule ------------------------------------------------------------ */

/*
 * THE CEILING, from the ledger (CLAUDE.md, Memory). `room` is what the ledger has left when the matcher
 * builds, after the database's tables; the scanners are not made yet, so `scanners` of them
 * (the engine's expected live scanners; 0: KOF_MFLT_SCANNERS) are reserved at `scan_fixed` each
 * (0: KOF_MFLT_SCAN_FIXED), and the filter may take 1 / KOF_MFLT_SHARE_DEN of what is left of that. No flat figure
 * anywhere: 1,000 hashes and 1,000,000,000 differ only in how far down the ladder the answer falls.
 */
#define KOF_MFLT_SCANNERS        8u
#define KOF_MFLT_SCAN_FIXED      ((uint64_t)12u << 20)
#define KOF_MFLT_SHARE_DEN       4u
/*
 * THE HARD MAXIMUM, whatever the room: a filter never takes more than 1 / KOF_MFLT_CAP_DEN of the ENGINE'S CAP (`cap`), so a
 * host that sets a huge cap, or an engine with a lone scanner, cannot let it eat the budget. The second bound is in
 * bits a key and not in bytes: a stored filter is KOF_MFLT_R_DEFAULT (8) bits an entry, so the ladder never goes above 9.05
 * bits a distinct hash; a bloom filter is 16 bits. Why there: measured at 3.2e7 keys, 16-bit entries (18 bits, 65 MB)
 * against 8 (9 bits, 32.5 MB) gain 0.4 ns a window (11.7 against 11.2) for a false-pass rate of 0.0017% against
 * 0.39%: past 8 bits the false passes are already not the cost.
 */
#define KOF_MFLT_CAP_DEN         5u
uint64_t kof_mflt_ceiling(uint64_t room, uint64_t cap, uint32_t scanners, uint64_t scan_fixed);

/* ---- the bank: every filter a block set has, behind one question --------------------------- */

/*
 * A set of blocks is made of packs, and each pack's keys are filtered by one of two things: a pre-built fuse
 * filter the pack stores (one each, they cannot be merged), or a bloom filter - the packs' stored ones ORed
 * into one, or one built in memory for a pack that has none. The bank holds them together and answers for
 * the lot: a window passes when the bloom filter or any fuse filter lets it through, and passes unconditionally
 * when a pack ended up with no filter at all (`filtered` 0), because that pack's keys could be anywhere.
 */
struct kof_fbank_xf;

struct kof_fbank {
	uint8_t         *flt;          /* the merged bloom filter, 64-byte aligned, or NULL */
	uint8_t         *flt_mem;      /* what it was allocated as */
	uint64_t         flt_bytes;
	uint32_t         flt_lbits;
	struct kof_mflt **fx;          /* the fuse filters that are resident */
	uint32_t         nfx;
	int              filtered;     /* 0: something has no filter, every window passes */
	/* Planning and what came of it. */
	struct kof_fbank_xf *xf;       /* the packs that have a pre-built filter, until it is opened */
	uint32_t         n_xf, xf_ok;
	uint64_t         xf_pairs, fx_bytes;
	uint32_t         w, parts, res;   /* the width kept, partitions in all, partitions resident */
};

struct kof_fbank *kof_fbank_new(uint32_t max_xf);
void kof_fbank_free(struct kof_fbank *b);

/* Add a pack's pre-built filter (probed now: its header and table). `pairs` weighs its share of the ceiling. */
int kof_fbank_add_xf(struct kof_fbank *b, const struct kof_mflt_io *io, uint32_t crc, uint64_t pairs);

/* The bloom filter: its default size for `n_keys` at `bpk` bits each (a power of two, rounded UP unless that
 * gives a key more than a third more bits than asked; at most `stored_max` when the filters it is made of are
 * stored, since a stored filter can be folded smaller and not made larger; 0: no limit), allocated, and a
 * pack's stored filter ORed into it. */
uint64_t kof_fbank_bloom_default(uint64_t n_keys, uint32_t bpk, uint64_t stored_max);
int kof_fbank_bloom_alloc(struct kof_fbank *b, uint64_t bytes);
int kof_fbank_bloom_or(struct kof_fbank *b, const struct kof_kix *k);

/* Choose the width (and, below one bit, the partitions) of the pre-built filters so that they fit `grant`, and open
 * them. 0 on a filter that cannot be read or does not match its checksum (never a wrong answer later).
 * A pack none of whose partitions fits leaves xf_ok 0. */
int kof_fbank_open_xf(struct kof_fbank *b, uint64_t grant);

static inline int kof_fbank_pass(const struct kof_fbank *b, uint32_t vp)
{
	uint32_t i;

	if (!b->filtered)
		return 1;
	if (b->flt && kof_kix_flt_test(b->flt, b->flt_lbits, vp))
		return 1;
	for (i = 0; i < b->nfx; i++)
		if (kof_mflt_test(b->fx[i], vp))
			return 1;
	return 0;
}

/*
 * The same question for a BATCH of windows, which is how the matcher's loop asks it: the windows' values do not depend on
 * what the filter said about the ones before, so up to KOF_FBANK_BATCH of them are collected, the memory each one will
 * touch is prefetched, and then they are tested - the cache misses of the batch overlap instead of queueing (measured:
 * a filter of 34 MB, 22 ns a window one at a time, 14 in batches of 16). Writes to `out` the multiplied hashes
 * of the windows that pass and are not flat (`flat[i]` != 0); returns how many.
 */
#define KOF_FBANK_BATCH 16u
#define KOF_FBANK_CACHE ((uint64_t)12u << 20)   /* resident filter bytes up to which the batch is not worth its loop (a share of the cache: host dependent) */
uint32_t kof_fbank_pass_n(const struct kof_fbank *b, const uint32_t *vp, const uint8_t *flat, uint32_t n,
			  uint32_t *out);

/* ---- measurement ---------------------------------------------------------------- */

/* The same filter over memory, for tests and benchmarks. */
struct kof_mflt *kof_mflt_open_mem(const uint8_t *region, uint64_t len, uint32_t w, uint32_t n_res,
				   char *why, size_t why_len);

#endif /* KOFENG_KOFMUTFLT_H */
