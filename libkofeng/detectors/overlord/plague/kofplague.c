/*
 * kofplague.c - the similarity matcher.
 *
 * A block is the MinHash sketch of one unit of code or data; the scanner
 * sketches the units of the object it is looking at - see kofplague_units.c for
 * how an object is cut, the same way a block was cut - and counts how much of a
 * block's sketch a unit's holds. There is no scan of every window: the cost is
 * one rolling pass over each unit and a lookup per kept hash.
 *
 *   THE SORTED PAIR ARRAY, searched once per kept hash. Pairs rather than a
 *   hash table because a hash can belong to several blocks and the equal range
 *   is then contiguous - one search, then a walk.
 *
 *   THE GENERATION STAMPS, which remove the per-object and per-unit clears.
 */

#include <stdlib.h>
#include <string.h>

#include "kofplague.h"

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

/*
 * "Room to spare" above is the whole safety argument, so it is made to the
 * compiler too. A slot of 256 does not overflow - it sets bit 8, PL_BLOCK
 * reads that as part of the block number, and the pair is filed against the
 * block next door. No crash and no bounds violation: just two blocks whose
 * coverage is quietly wrong. Both entry points already refuse n_hash above the
 * cap (dbloader.c and pl_build below), so this pins the constant they check.
 */
_Static_assert(KOF_PLAGUE_MAX_HASH <= 256u,
	       "PL_BS packs the slot into 8 bits below the block number");
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

	/*
	 * WHAT EVERY BLOCK FOLDS TO, AND WHICH NORMALIZERS EXIST - both fixed
	 * the moment the set is built, and both were being recomputed per
	 * object.
	 *
	 * kof_plague_block_id folds a block's whole hash list, which is up to
	 * KOF_PLAGUE_MAX_HASH of them, and objctx.c calls it every time a
	 * module asks about a block - to compare against a list of ids already
	 * counted. kof_plague_set_norms walks every block in the set, and
	 * scan.c calls it once per object per mask.
	 *
	 * Neither answer depends on the object. Measured with 200 000 plague
	 * blocks over the small target: block_id 14,007,787,059 instructions
	 * (36.4% of the scan) and set_norms 2,131,669,108 (5.5%), both spent
	 * recomputing constants.
	 *
	 * norm_bit[b] is the union of normalizers over blocks whose scan_mask
	 * names region b, and norm_all over every block - so set_norms becomes
	 * an OR across at most 32 entries instead of a walk of the set.
	 *
	 * NULL on allocation failure, and both functions then compute as they
	 * always did.
	 */
	uint32_t *block_id;         /* [n_block]; 0 means "not precomputed" */
	uint32_t  norm_bit[32];
	uint32_t  norm_all;
	uint8_t   norm_ready;

	uint64_t bytes;
};

/* ---- building ---------------------------------------------------------- */

/*
 * SORTING THE PAIRS BY HASH, IN FOUR LINEAR PASSES RATHER THAN n log n.
 *
 * The key is a uint32 and there are one per declared hash in the whole
 * database, so at scale this is the single most expensive thing a load does:
 * measured with 200 000 plague blocks (25.6 million pairs), qsort and pl_cmp
 * together came to 12.7 billion instructions - 56% of everything the run did.
 * A least-significant-digit radix sort touches each pair four times and
 * compares nothing.
 *
 * IDENTICAL OUTPUT, not merely sorted. pl_cmp breaks ties by `bs` so that a
 * set built twice indexes identically, and a radix sort gives that for free:
 * the pairs are appended in (block, slot) order, so `bs` ascends in the input,
 * and an LSD radix is STABLE - equal hashes keep the order they arrived in,
 * which is ascending bs. Every pass must be stable for that to hold, which is
 * why the counts are turned into offsets and the pairs copied forward.
 *
 * Answers 0 when the scratch cannot be allocated; the caller then sorts the
 * way it always did.
 */
static int pl_radix(struct pl_pair *a, uint32_t n)
{
	struct pl_pair *tmp;
	uint32_t pass;

	if (n < 2u)
		return 1;
	tmp = malloc((size_t)n * sizeof *tmp);
	if (!tmp)
		return 0;

	for (pass = 0; pass < 4u; pass++) {
		uint32_t count[257];
		uint32_t i, sh = pass * 8u;

		memset(count, 0, sizeof count);
		for (i = 0; i < n; i++)
			count[((a[i].hash >> sh) & 0xffu) + 1u]++;
		/* A pass whose digit is the same everywhere would only copy the
		 * array onto itself. */
		for (i = 0; i < 256u; i++)
			if (count[i + 1u] == n)
				break;
		if (i < 256u)
			continue;
		for (i = 0; i < 256u; i++)
			count[i + 1u] += count[i];
		for (i = 0; i < n; i++)
			tmp[count[(a[i].hash >> sh) & 0xffu]++] = a[i];
		memcpy(a, tmp, (size_t)n * sizeof *a);
	}
	free(tmp);
	return 1;
}

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
		if (!pl_radix(s->pair, s->n_pair))
			qsort(s->pair, s->n_pair, sizeof *s->pair, pl_cmp);

	s->bytes = (uint64_t)s->n_pair * sizeof *s->pair + sizeof *s;

	/* The two constants - see block_id and norm_bit in the struct. */
	s->block_id = calloc(s->n_block ? s->n_block : 1u,
			     sizeof *s->block_id);
	if (s->block_id) {
		for (i = 0; i < s->n_block; i++) {
			uint32_t nh = 0;
			const uint32_t *h = kof_plague_block_hashes(s, i, &nh);

			s->block_id[i] = h ? kof_plague_fold(h, nh) : 0u;
		}
		s->bytes += (uint64_t)s->n_block * sizeof *s->block_id;
	}
	for (i = 0; i < s->n_block; i++) {
		uint32_t bit, m = 1u << s->block[i].norm;

		s->norm_all |= m;
		for (bit = 0; bit < 32u; bit++)
			if (s->block[i].scan_mask & (1u << bit))
				s->norm_bit[bit] |= m;
	}
	s->norm_ready = 1;
	return s;
}

void kof_plague_set_free(struct kof_plague_set *s)
{
	if (!s)
		return;
	free(s->pair);
	free(s->block_id);
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

/*
 * THE NAME OF A BLOCK, and the only place it is decided.
 *
 * A block has no stored name - it is the fold of its own hashes, so the same
 * bytes carry the same name whoever carved them and whichever pack they were
 * loaded into. Both the verdict the scanner writes and anyone later asking
 * which rule a verdict came from must read it from here, or the two spellings
 * drift and the answer is wrong in a way nothing reports.
 */
uint32_t kof_plague_block_id(const struct kof_plague_set *s, uint32_t block)
{
	uint32_t nh = 0;
	const uint32_t *h;

	/* Folded once when the set was built - see block_id. */
	if (s && s->block_id && block < s->n_block)
		return s->block_id[block];

	h = kof_plague_block_hashes(s, block, &nh);
	return h ? kof_plague_fold(h, nh) : 0u;
}

uint32_t kof_plague_set_norms(const struct kof_plague_set *s, uint32_t scan_mask)
{
	uint32_t i, m = 0;

	if (!s)
		return 0;
	/* Unioned per region when the set was built - see norm_bit. */
	if (s->norm_ready) {
		if (!scan_mask)
			return s->norm_all;
		for (i = 0; i < 32u; i++)
			if (scan_mask & (1u << i))
				m |= s->norm_bit[i];
		return m;
	}
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
		c->seen   = calloc(c->n_block, sizeof *c->seen);
		c->stamp  = calloc(c->n_block, sizeof *c->stamp);
		c->ucnt   = calloc(c->n_block, sizeof *c->ucnt);
		c->ustamp = calloc(c->n_block, sizeof *c->ustamp);
		if (!c->seen || !c->stamp || !c->ucnt || !c->ustamp) {
			free(c->seen); free(c->stamp);
			free(c->ucnt); free(c->ustamp);
			memset(c, 0, sizeof *c);
			return 0;
		}
	}
	/*
	 * Generations start at one, so a stamp array that calloc left at zero
	 * cannot be mistaken for "counted during this object".
	 */
	c->gen = 1;
	c->ugen = 1;
	return 1;
}

void kof_plague_ctx_done(struct kof_plague_ctx *c)
{
	if (!c)
		return;
	free(c->seen);
	free(c->stamp);
	free(c->ucnt);
	free(c->ustamp);
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

/*
 * THE GENERATOR SIDE: hash one span the way the matcher will read it.
 *
 * Here rather than in whoever is carving because there is one right answer and
 * several callers - the panel that offers blocks, anything that wants to
 * recognise a block it has been handed, a test. A generator that derived a
 * value differently from kof_plague_unit would produce a rule that matches
 * nothing and reports no error, and the way to make that impossible is for
 * there to be one of it.
 *
 * The k smallest DISTINCT values, which is the cut the matcher expects: a block
 * and a file both keep their smallest, so the two subsets overlap wherever the
 * content does. Windows of one repeated byte are left out on both sides - see
 * kof_plague_flat.
 *
 * KEPT IN A SORTED ARRAY OF k, NOT COLLECTED AND SORTED. What this wants out is
 * the k smallest, and a window larger than the array's largest is rejected by
 * one compare - which is nearly all of them once k values are held. The
 * collecting version needed a working array of every selected window, capped at
 * KOF_PLAGUE_SPAN_MAX, and a window past the cap was dropped without a word: a
 * span long enough to need it lost the tail of itself. Nothing is capped now.
 */
uint32_t kof_plague_minhash(const uint8_t *p, uint64_t n, uint32_t norm,
			    uint32_t *out)
{
	const uint32_t max_out = KOF_PLAGUE_MINHASH_K;
	uint32_t h = 0, drop = kof_plague_drop_weight(), i, got = 0;
	uint64_t at;

	if (norm != KOF_PLAGUE_RAW) {
		if (n < 2u)
			return 0;
		n -= 1u;
	}
	if (n < KOF_PLAGUE_NG)
		return 0;

	/* One definition of what a normalizer presents - see kofplague.h. */
#define PB(k) ((uint32_t)kof_plague_byte(p, (k), norm))
	for (i = 0; i < KOF_PLAGUE_NG; i++)
		h = h * KOF_PLAGUE_BASE + PB(i);
	for (at = 0;; at++) {
		uint32_t v = kof_plague_mix(h);

		/* THE CHEAP TEST FIRST. Once k values are held a window larger
		 * than the largest is rejected by this compare, which is nearly
		 * all of them; the flat test is eight comparisons and is paid
		 * only by a window that would have been kept. The answer is the
		 * same - a flat window is refused either way. */
		if ((got < max_out || v < out[got - 1u]) &&
		    !kof_plague_flat(p, at, norm)) {
			uint32_t lo = 0, hi = got;

			while (lo < hi) {
				uint32_t mid = lo + (hi - lo) / 2u;

				if (out[mid] < v)
					lo = mid + 1u;
				else
					hi = mid;
			}
			if (lo == got || out[lo] != v) {
				uint32_t last = got < max_out ? got : max_out - 1u;

				memmove(out + lo + 1u, out + lo,
					(last - lo) * sizeof *out);
				out[lo] = v;
				if (got < max_out)
					got++;
			}
		}
		if (at + KOF_PLAGUE_NG >= n)
			break;
		/* The normalizer is decided once per window, not twice. */
		if (norm == KOF_PLAGUE_RAW) {
			h -= (uint32_t)p[at] * drop;
			h = h * KOF_PLAGUE_BASE + (uint32_t)p[at + KOF_PLAGUE_NG];
		} else {
			h -= PB(at) * drop;
			h = h * KOF_PLAGUE_BASE + PB(at + KOF_PLAGUE_NG);
		}
	}
#undef PB
	return got;
}

void kof_plague_cut(const uint8_t *p, uint64_t len, uint32_t avg, uint32_t min,
		    uint32_t max, kof_plague_cut_fn fn, void *user)
{
	uint32_t h = 0, drop = kof_plague_drop_weight(), w;
	uint64_t at, cut = 0;

	for (w = 0; w < KOF_PLAGUE_NG && w < len; w++)
		h = h * KOF_PLAGUE_BASE + p[w];
	for (at = KOF_PLAGUE_NG; at < len; at++) {
		int here = (kof_plague_mix(h) & (avg - 1u)) == 0u;

		if ((here && at - cut >= min) || at - cut >= max) {
			if (fn(user, cut, at))
				return;
			cut = at;
		}
		h -= (uint32_t)p[at - KOF_PLAGUE_NG] * drop;
		h = h * KOF_PLAGUE_BASE + p[at];
	}
	/* And the tail, whatever is left of the span. */
	if (cut < len)
		(void)fn(user, cut, len);
}

/* Credit one hash of a unit's sketch to every block that holds it. */
static void pl_credit(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		      uint32_t h, uint32_t side)
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
		const struct kof_plague_block *blk = &s->block[b];

		/*
		 * THE REGION, THE NORMALIZER AND THE SIDE ARE PART OF THE MATCH,
		 * not a filter applied afterwards. The same bytes in another
		 * region, hashed another way, or on the other side of the static
		 * library are a different fact - see enum kof_plague_side.
		 */
		if (blk->norm != norm || blk->side != side ||
		    (!c->any_region && !(blk->scan_mask & scan_mask)))
			continue;
		if (c->ustamp[b] != c->ugen) {
			c->ustamp[b] = c->ugen;
			c->ucnt[b] = 0;
		}
		c->ucnt[b]++;
		if (c->stamp[b] != c->gen) {
			c->stamp[b] = c->gen;
			c->seen[b] = 0;
		}
		/*
		 * THE BEST UNIT, not the sum over units. A sketch's hashes are
		 * distinct and so are a block's, so one unit counts each hash of
		 * the block once; and two unrelated units that each hold a few
		 * of a block's hashes must not add up to a match.
		 */
		if (c->ucnt[b] > c->seen[b])
			c->seen[b] = c->ucnt[b];
	}
}

void kof_plague_unit(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		     uint32_t side, const uint8_t *p, uint64_t n)
{
	uint32_t sk[KOF_PLAGUE_MINHASH_K], got, i;

	if (!c || !c->set || !p || norm >= KOF_PLAGUE_NORM_COUNT ||
	    !c->set->n_pair)
		return;
	got = kof_plague_minhash(p, n, norm, sk);
	if (!got)
		return;
	/* A new unit: the counts of the last say nothing about this one. */
	if (++c->ugen == 0u) {
		memset(c->ustamp, 0, (size_t)c->n_block * sizeof *c->ustamp);
		c->ugen = 1u;
	}
	for (i = 0; i < got; i++)
		pl_credit(c, scan_mask, norm, sk[i], side);
}

/* ---- scoring ------------------------------------------------------------ */

uint32_t kof_plague_matched(const struct kof_plague_ctx *c, uint32_t b)
{
	if (!c || !c->set || b >= c->n_block)
		return 0;
	return (c->stamp[b] == c->gen) ? c->seen[b] : 0u;
}

/*
 * THE TWO NUMBERS THE SCORE IS A RATIO OF.
 *
 * Asked for separately because a rule that names SEVERAL blocks has one score
 * and it is not an average of theirs: the question is how much of what the rule
 * is made of is in this object, which is matched hashes over declared hashes
 * across the whole set. Averaging percentages would let a 200-byte block and a
 * 20KB one weigh the same.
 */
int kof_plague_counts(const struct kof_plague_ctx *c, uint32_t b,
		      uint32_t *seen, uint32_t *n_hash)
{
	const struct kof_plague_block *blk;

	if (seen)
		*seen = 0;
	if (n_hash)
		*n_hash = 0;
	if (!c || !c->set || b >= c->n_block)
		return 0;
	blk = &c->set->block[b];
	if (!blk->n_hash)
		return 0;
	if (seen) {
		*seen = (c->stamp[b] == c->gen) ? c->seen[b] : 0u;
		/* A block that names one hash twice must not read past a
		 * hundred per cent. */
		if (*seen > blk->n_hash)
			*seen = blk->n_hash;
	}
	if (n_hash)
		*n_hash = blk->n_hash;
	return 1;
}

uint32_t kof_plague_pct(const struct kof_plague_ctx *c, uint32_t b)
{
	uint32_t seen, n_hash;

	/* One division, defined once - see kof_plague_counts. */
	if (!kof_plague_counts(c, b, &seen, &n_hash) || !n_hash)
		return 0;
	return seen * 100u / n_hash;
}
