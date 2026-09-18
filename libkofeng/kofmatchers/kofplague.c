/*
 * kofplague.c - the similarity matcher.
 *
 * See kofplague.h for what it costs and why the index is inverted. What
 * follows is the three pieces that make that cost real:
 *
 *   THE BITMAP, which answers "is this hash in any rule at all" in one memory
 *   touch. About one window in thirty-two is even selected, and of those nearly
 *   all are in no rule, so this is where the overwhelming majority of the work
 *   ends.
 *
 *   THE SORTED PAIR ARRAY, searched only for what the bitmap let through. Pairs
 *   rather than a hash table because a hash can belong to several blocks and
 *   the equal range is then contiguous - one search, then a walk.
 *
 *   THE GENERATION STAMP, which is what removes the per-object clear. See the
 *   note on `seen` in the header.
 */

#include <stdlib.h>
#include <string.h>

#include "kofplague.h"

/*
 * The bitmap is sized from the number of indexed pairs so its load factor stays
 * low whatever the pack holds: a bitmap that is too small stops rejecting and
 * every window falls through to the search.
 *
 * Eight bits of table per pair keeps occupancy near an eighth, which is where
 * the test earns its keep. Bounded at both ends: below the floor a tiny pack
 * would allocate a table larger than its index, and above the ceiling a large
 * one would spend memory on a test that is already almost free.
 */
#define PL_BM_MIN_BITS 12u
#define PL_BM_MAX_BITS 24u

/*
 * One hash of one block, and WHICH of that block's hashes it is.
 *
 * The slot is what makes the count a count of DISTINCT hashes: without it a
 * hit says only "some hash of block b arrived", and a file that repeats two of
 * a block's hashes sixty times is indistinguishable from one that contains all
 * of them. It is packed beside the block index rather than given a word of its
 * own because there is one pair per hash in the database and a third word on
 * each is half as much index again; a block holds at most
 * KOF_PLAGUE_MAX_HASH of them, which is 128, so eight bits is room to spare.
 */
struct pl_pair {
	uint32_t hash;
	uint32_t bs;                /* block << 8 | slot */
};

#define PL_BS(b, sl)  (((b) << 8) | (sl))
#define PL_BLOCK(bs)  ((bs) >> 8)
#define PL_SLOT(bs)   ((bs) & 0xffu)
/* What the packing costs: a set may hold this many blocks and no more. Checked
 * where a set is built, so an oversized pack is refused rather than indexed
 * into the wrong block. */
#define PL_MAX_BLOCK  0x00ffffffu

struct kof_plague_set {
	const struct kof_plague_block *block;
	const uint32_t                *pool;
	uint32_t n_block, n_pool;

	struct pl_pair *pair;       /* sorted by hash */
	uint32_t        n_pair;

	uint8_t  *bm;
	uint32_t  bm_bits;          /* the table is 1 << bm_bits bits */
	uint32_t  bm_mask;

	uint64_t bytes;
};

/* ---- building ---------------------------------------------------------- */

static int pl_cmp(const void *a, const void *b)
{
	uint32_t x = ((const struct pl_pair *)a)->hash;
	uint32_t y = ((const struct pl_pair *)b)->hash;

	if (x != y)
		return x < y ? -1 : 1;
	/* Ties by block and then by slot, so the equal range is deterministic -
	 * a set built twice from the same pack must index identically or two
	 * engines disagree. */
	x = ((const struct pl_pair *)a)->bs;
	y = ((const struct pl_pair *)b)->bs;
	return x < y ? -1 : x > y ? 1 : 0;
}

static uint32_t pl_bm_bits(uint32_t n_pair)
{
	uint32_t b = PL_BM_MIN_BITS;

	while (b < PL_BM_MAX_BITS && (1u << b) < n_pair * 8u)
		b++;
	return b;
}

struct kof_plague_set *kof_plague_build(const struct kof_plague_block *blocks,
					uint32_t n_blocks,
					const uint32_t *pool, uint32_t n_pool)
{
	struct kof_plague_set *s;
	uint32_t i, j, np = 0;

	if ((n_blocks && !blocks) || (n_pool && !pool))
		return NULL;

	/*
	 * VALIDATE BEFORE ALLOCATING ANYTHING. Every slice below is used as an
	 * index later, on an object chosen by whoever wrote the file the pack
	 * came from - so a row that does not fit is refused here rather than
	 * read out of bounds there.
	 */
	if (n_blocks > PL_MAX_BLOCK)
		return NULL;
	for (i = 0; i < n_blocks; i++) {
		if (blocks[i].n_hash < KOF_PLAGUE_MIN_HASH ||
		    blocks[i].n_hash > KOF_PLAGUE_MAX_HASH)
			return NULL;
		if (blocks[i].first_hash > n_pool ||
		    blocks[i].n_hash > n_pool - blocks[i].first_hash)
			return NULL;
		if (blocks[i].norm >= KOF_PLAGUE_NORM_COUNT)
			return NULL;
		np += blocks[i].n_hash;
	}

	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;
	s->block = blocks; s->n_block = n_blocks;
	s->pool = pool; s->n_pool = n_pool;

	s->pair = np ? malloc((size_t)np * sizeof *s->pair) : NULL;
	if (np && !s->pair) {
		free(s);
		return NULL;
	}
	for (i = 0; i < n_blocks; i++)
		for (j = 0; j < blocks[i].n_hash; j++) {
			s->pair[s->n_pair].hash = pool[blocks[i].first_hash + j];
			s->pair[s->n_pair].bs = PL_BS(i, j);
			s->n_pair++;
		}
	if (s->n_pair)
		qsort(s->pair, s->n_pair, sizeof *s->pair, pl_cmp);

	s->bm_bits = pl_bm_bits(s->n_pair);
	s->bm_mask = (1u << s->bm_bits) - 1u;
	s->bm = calloc((size_t)1 << (s->bm_bits - 3u), 1);
	if (!s->bm) {
		free(s->pair);
		free(s);
		return NULL;
	}
	for (i = 0; i < s->n_pair; i++) {
		uint32_t k = s->pair[i].hash & s->bm_mask;

		s->bm[k >> 3] |= (uint8_t)(1u << (k & 7u));
	}
	s->bytes = (uint64_t)s->n_pair * sizeof *s->pair +
		   ((uint64_t)1 << (s->bm_bits - 3u)) + sizeof *s;
	return s;
}

void kof_plague_set_free(struct kof_plague_set *s)
{
	if (!s)
		return;
	free(s->pair);
	free(s->bm);
	free(s);
}

uint64_t kof_plague_set_bytes(const struct kof_plague_set *s)
{
	return s ? s->bytes : 0;
}

uint32_t kof_plague_set_blocks(const struct kof_plague_set *s)
{
	return s ? s->n_block : 0;
}

const uint32_t *kof_plague_block_hashes(const struct kof_plague_set *s,
					uint32_t block, uint32_t *n_hash)
{
	if (n_hash)
		*n_hash = 0;
	if (!s || block >= s->n_block)
		return NULL;
	if (n_hash)
		*n_hash = s->block[block].n_hash;
	return s->pool + s->block[block].first_hash;
}

uint32_t kof_plague_set_norms(const struct kof_plague_set *s, uint32_t scan_mask)
{
	uint32_t i, m = 0;

	if (!s)
		return 0;
	for (i = 0; i < s->n_block; i++)
		if (!scan_mask || (s->block[i].scan_mask & scan_mask))
			m |= 1u << s->block[i].norm;
	return m;
}

/* ---- per scanner ------------------------------------------------------- */

int kof_plague_ctx_init(struct kof_plague_ctx *c, const struct kof_plague_set *s)
{
	if (!c || !s)
		return 0;
	memset(c, 0, sizeof *c);
	c->set = s;
	c->n_block = s->n_block;
	if (c->n_block) {
		c->seen = calloc(c->n_block, sizeof *c->seen);
		c->stamp = calloc(c->n_block, sizeof *c->stamp);
		c->hit = calloc(s->n_pool ? s->n_pool : 1u, 1);
		if (!c->seen || !c->stamp || !c->hit) {
			free(c->seen); free(c->stamp); free(c->hit);
			memset(c, 0, sizeof *c);
			return 0;
		}
	}
	/*
	 * Generations start at one, so a stamp array that calloc left at zero
	 * cannot be mistaken for "counted during this object".
	 */
	c->gen = 1;
	return 1;
}

void kof_plague_ctx_done(struct kof_plague_ctx *c)
{
	if (!c)
		return;
	free(c->seen);
	free(c->stamp);
	free(c->hit);
	memset(c, 0, sizeof *c);
}

void kof_plague_begin(struct kof_plague_ctx *c)
{
	if (!c)
		return;
	c->gen++;
	c->any_region = 0;
	/*
	 * Wrapping would make a stale stamp look current. It takes four billion
	 * objects on one thread to get here and the clear is a millisecond, so
	 * the honest fix is the cheap one.
	 */
	if (c->gen == 0) {
		if (c->n_block) {
			memset(c->stamp, 0, (size_t)c->n_block * sizeof *c->stamp);
			memset(c->seen, 0, (size_t)c->n_block * sizeof *c->seen);
		}
		c->gen = 1;
	}
}

void kof_plague_any_region(struct kof_plague_ctx *c, int on)
{
	if (c)
		c->any_region = on != 0;
}

/* Credit one hash to every block that holds it. */
static void pl_credit(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		      uint32_t h)
{
	const struct kof_plague_set *s = c->set;
	uint32_t lo = 0, hi = s->n_pair, mid;

	while (lo < hi) {
		mid = lo + (hi - lo) / 2u;
		if (s->pair[mid].hash < h)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (; lo < s->n_pair && s->pair[lo].hash == h; lo++) {
		uint32_t b = PL_BLOCK(s->pair[lo].bs);
		uint32_t sl = PL_SLOT(s->pair[lo].bs);
		const struct kof_plague_block *blk = &s->block[b];

		/*
		 * THE REGION AND THE NORMALIZER ARE PART OF THE MATCH, not a
		 * filter applied afterwards. The same eight bytes in another
		 * region, or hashed another way, is a different fact - and a
		 * matcher that credited it would quietly undo the anchoring the
		 * rule was written with.
		 */
		if (blk->norm != norm ||
		    (!c->any_region && !(blk->scan_mask & scan_mask)))
			continue;
		if (c->stamp[b] != c->gen) {
			c->stamp[b] = c->gen;
			c->seen[b] = 0;
			/* And the block's slice of the hit marks, which is the
			 * only thing that has to be cleared per object - at
			 * most KOF_PLAGUE_MAX_HASH bytes, and only for a block
			 * something actually matched. */
			memset(c->hit + blk->first_hash, 0, blk->n_hash);
		}
		/*
		 * COUNTED ONCE PER DISTINCT HASH, not per occurrence.
		 *
		 * A block repeated twice in a file is still that one block, and
		 * a run of padding that happens to carry one of a rule's hashes
		 * must not be able to score the rule on its own.
		 *
		 * Bounding an occurrence counter by the block's size was NOT
		 * this, though it was written as though it were: it let any
		 * file that repeated a handful of a block's hashes often enough
		 * saturate the count and read as a hundred per cent. Measured
		 * on a sample and a two per cent variant of it, every carried
		 * block scored 100 where the true containment was 93.
		 */
		if (!c->hit[blk->first_hash + sl]) {
			c->hit[blk->first_hash + sl] = 1;
			c->seen[b]++;
		}
	}
}

void kof_plague_feed(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		     const uint8_t *p, uint64_t n)
{
	const struct kof_plague_set *s;
	uint32_t h = 0, drop, i;
	uint64_t at;

	if (!c || !c->set || !p || norm >= KOF_PLAGUE_NORM_COUNT)
		return;
	s = c->set;
	if (!s->n_pair)
		return;

	/*
	 * The normalized stream is one shorter than the bytes, because a
	 * difference needs two of them. Written as a bound on the loop rather
	 * than a copy of the buffer: a region is up to a megabyte and the point
	 * of a rolling hash is not to touch it twice.
	 */
	if (norm != KOF_PLAGUE_RAW) {
		if (n < 2u)
			return;
		n -= 1u;
	}
	if (n < KOF_PLAGUE_NG)
		return;

	drop = kof_plague_drop_weight();

#define PL_BYTE(k) ((uint32_t)(norm == KOF_PLAGUE_RAW ? p[(k)]                 \
		    : norm == KOF_PLAGUE_XOR ? (uint8_t)(p[(k)] ^ p[(k) + 1u])  \
		    : (uint8_t)(p[(k) + 1u] - p[(k)])))

	for (i = 0; i < KOF_PLAGUE_NG; i++)
		h = h * KOF_PLAGUE_BASE + PL_BYTE(i);

	for (at = 0;; at++) {
		uint32_t mixed = kof_plague_mix(h);

		if (kof_plague_selects(mixed) &&
		    !kof_plague_flat(p, at, norm)) {
			uint32_t k = mixed & s->bm_mask;

			if (s->bm[k >> 3] & (1u << (k & 7u)))
				pl_credit(c, scan_mask, norm, mixed);
		}
		if (at + KOF_PLAGUE_NG >= n)
			break;
		h -= PL_BYTE(at) * drop;
		h = h * KOF_PLAGUE_BASE + PL_BYTE(at + KOF_PLAGUE_NG);
	}
#undef PL_BYTE
}

/* ---- scoring ------------------------------------------------------------ */

uint32_t kof_plague_matched(const struct kof_plague_ctx *c, uint32_t b)
{
	if (!c || !c->set || b >= c->n_block)
		return 0;
	return (c->stamp[b] == c->gen) ? c->seen[b] : 0u;
}

uint32_t kof_plague_pct(const struct kof_plague_ctx *c, uint32_t b)
{
	const struct kof_plague_block *blk;
	uint32_t seen;

	if (!c || !c->set || b >= c->n_block)
		return 0;
	blk = &c->set->block[b];
	if (!blk->n_hash)
		return 0;
	seen = (c->stamp[b] == c->gen) ? c->seen[b] : 0u;
	return seen * 100u / blk->n_hash;
}
