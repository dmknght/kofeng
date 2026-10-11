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

	/*
	 * THE BIT PREFILTER, built once with the index and shared like it.
	 *
	 * One bit per hash of the set, in a table sized from the number of them,
	 * indexed by the low bits of a window's value. A window whose bit is clear
	 * is in no block and never reaches the search. `top` alone could not do
	 * this once a block carried large values: a block's hashes are the
	 * smallest of ITS span, so a block cut from a span of few windows, or one
	 * made of the windows its samples share, has a high `top`, and that one
	 * block then lets every window of the database through to the binary
	 * search (measured by the research agent: 58 / 113 / 207 ns/byte at 1k /
	 * 50k / 200k such blocks, against 2-35 with small-valued blocks).
	 */
	uint64_t *bloom;
	uint32_t  bloom_mask;       /* bits - 1 */

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

	/* 32 bits of table per hash keeps a window that is in no block from
	 * passing about three times in a hundred; clamped so a tiny set does not
	 * pay a page and a huge one does not pay more than 32 MB. */
	{
		uint64_t bits = 1u << 12, w;

		while (bits < (uint64_t)s->n_pair * 32u && bits < (1u << 28))
			bits <<= 1;
		w = bits / 64u;
		s->bloom = calloc((size_t)w, sizeof *s->bloom);
		if (s->bloom) {
			uint32_t k;

			s->bloom_mask = (uint32_t)(bits - 1u);
			for (k = 0; k < s->n_pair; k++) {
				uint32_t ix = s->pair[k].hash & s->bloom_mask;

				s->bloom[ix >> 6] |= (uint64_t)1 << (ix & 63u);
			}
			s->bytes += w * sizeof *s->bloom;
		}
	}

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
	free(s->bloom);
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
		c->pstamp = calloc(s->n_pair ? s->n_pair : 1u, sizeof *c->pstamp);
		if (!c->seen || !c->stamp || !c->pstamp) {
			free(c->seen); free(c->stamp); free(c->pstamp);
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
	free(c->pstamp);
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
			memset(c->pstamp, 0,
			       (size_t)c->set->n_pair * sizeof *c->pstamp);
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
 * ONE DEFINITION OF A WINDOW, three readers. The iterator below is what a window
 * IS - eight bytes as the normalizer presents them, rolled, mixed - and the pool
 * (the generator), the membership pass (the authoring tool asking whether a
 * sample holds a pool's windows) and the scan (kof_plague_unit) all walk it.
 * Windows of one repeated byte are left out on every side - see
 * kof_plague_flat. The loop was written out three times before it was one.
 */
struct pl_win {
	const uint8_t *p;
	uint64_t       n, at;
	uint32_t       norm, h, drop;
};

/* Position on the first window; 0 when the span has none. */
static inline int pl_win_begin(struct pl_win *w, const uint8_t *p, uint64_t n,
			       uint32_t norm)
{
	uint32_t i;

	if (norm != KOF_PLAGUE_RAW) {
		if (n < 2u)
			return 0;
		n -= 1u;
	}
	if (n < KOF_PLAGUE_NG)
		return 0;
	w->p = p; w->n = n; w->at = 0; w->norm = norm;
	w->drop = kof_plague_drop_weight();
	w->h = 0;
	for (i = 0; i < KOF_PLAGUE_NG; i++)
		w->h = w->h * KOF_PLAGUE_BASE +
		       (uint32_t)kof_plague_byte(p, i, norm);
	return 1;
}

static inline uint32_t pl_win_value(const struct pl_win *w)
{
	return kof_plague_mix(w->h);
}

static inline int pl_win_flat(const struct pl_win *w)
{
	return kof_plague_flat(w->p, w->at, w->norm);
}

/* Roll to the next window; 0 once the last has been given. */
static inline int pl_win_next(struct pl_win *w)
{
	if (w->at + KOF_PLAGUE_NG >= w->n)
		return 0;
	if (w->norm == KOF_PLAGUE_RAW) {
		w->h -= (uint32_t)w->p[w->at] * w->drop;
		w->h = w->h * KOF_PLAGUE_BASE +
		       (uint32_t)w->p[w->at + KOF_PLAGUE_NG];
	} else {
		w->h -= (uint32_t)kof_plague_byte(w->p, w->at, w->norm) * w->drop;
		w->h = w->h * KOF_PLAGUE_BASE +
		       (uint32_t)kof_plague_byte(w->p, w->at + KOF_PLAGUE_NG,
					       w->norm);
	}
	w->at++;
	return 1;
}

static int pl_u32_cmp(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

uint32_t *kof_plague_pool(const uint8_t *p, uint64_t n, uint32_t norm,
			  uint32_t *n_out)
{
	struct pl_win w;
	uint32_t *v, got = 0, k = 0;
	uint64_t room;

	if (n_out)
		*n_out = 0;
	if (!p || norm >= KOF_PLAGUE_NORM_COUNT || !pl_win_begin(&w, p, n, norm))
		return NULL;
	room = w.n - KOF_PLAGUE_NG + 1u;
	/* A span this size is not a block's input; refuse rather than wrap. */
	if (room > 0x3fffffffu)
		return NULL;
	v = malloc((size_t)room * sizeof *v);
	if (!v)
		return NULL;
	do {
		if (!pl_win_flat(&w))
			v[got++] = pl_win_value(&w);
	} while (pl_win_next(&w));
	if (!got) {
		free(v);
		return NULL;
	}
	qsort(v, got, sizeof *v, pl_u32_cmp);
	for (k = 1, room = 1; room < got; room++)
		if (v[room] != v[k - 1u])
			v[k++] = v[room];
	if (n_out)
		*n_out = k;
	return v;
}

/*
 * THE k SMALLEST OF THE POOL - what a block of one sample is, and the generator
 * every older block was made with, now spelled as what it always was. Returns
 * the values ascending and distinct, never more than K.
 */
uint32_t kof_plague_minhash(const uint8_t *p, uint64_t n, uint32_t norm,
			    uint32_t *out)
{
	uint32_t np = 0, got, *pool = kof_plague_pool(p, n, norm, &np);

	if (!pool)
		return 0;
	got = np < KOF_PLAGUE_MINHASH_K ? np : KOF_PLAGUE_MINHASH_K;
	memcpy(out, pool, got * sizeof *out);
	free(pool);
	return got;
}

void kof_plague_member(const uint32_t *pool, uint32_t n_pool, const uint8_t *p,
		       uint64_t n, uint32_t norm, uint8_t *bits)
{
	struct pl_win w;
	uint64_t *bloom = NULL, nb = 1u << 12;
	uint32_t mask = 0;

	if (!pool || !n_pool || !p || !bits || norm >= KOF_PLAGUE_NORM_COUNT ||
	    !pl_win_begin(&w, p, n, norm))
		return;
	/* Most windows of a sample are in no pool: a bit table says so without a
	 * search. Without room for it the search is simply done every time. */
	while (nb < (uint64_t)n_pool * 32u && nb < (1u << 24))
		nb <<= 1;
	bloom = calloc((size_t)(nb / 64u), sizeof *bloom);
	if (bloom) {
		uint32_t i;

		mask = (uint32_t)(nb - 1u);
		for (i = 0; i < n_pool; i++)
			bloom[(pool[i] & mask) >> 6] |=
				(uint64_t)1 << (pool[i] & 63u);
	}
	do {
		uint32_t v = pl_win_value(&w), lo = 0, hi = n_pool;

		if (v < pool[0] || v > pool[n_pool - 1u])
			continue;
		if (bloom &&
		    !((bloom[(v & mask) >> 6] >> (v & 63u)) & 1u))
			continue;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (pool[mid] < v)
				lo = mid + 1u;
			else
				hi = mid;
		}
		if (lo < n_pool && pool[lo] == v && !pl_win_flat(&w))
			bits[lo >> 3] |= (uint8_t)(1u << (lo & 7u));
	} while (pl_win_next(&w));
	free(bloom);
}

uint32_t kof_plague_core(const uint32_t *pool, uint32_t n_pool,
			 const uint16_t *pos, uint32_t pos_need,
			 const uint16_t *bg, uint32_t bg_max, uint32_t k,
			 uint32_t *out)
{
	uint32_t i, got = 0;

	if (!pool || !pos || !out)
		return 0;
	/* The pool is ascending, so the first k that qualify are the k smallest. */
	for (i = 0; i < n_pool && got < k; i++)
		if (pos[i] >= pos_need && (!bg || bg[i] <= bg_max))
			out[got++] = pool[i];
	return got >= KOF_PLAGUE_MIN_HASH ? got : 0u;
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

/*
 * Credit one window hash to every block that holds it, once per OBJECT.
 *
 * A pair is a block's hash, and an object holds it or does not: how many units
 * it sits in is the scanner's cut and not a fact about the object. Counted per
 * unit, a block spanning two units - two grouped functions, a cluster the
 * cutter split - needed both in one, and the same data scored differently
 * depending on where a gap fell. The stamp is keyed by the object's generation,
 * so the first unit to hold a hash counts it and no other does.
 */
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

		if (c->pstamp[lo] == c->gen)
			continue;

		/*
		 * THE REGION, THE NORMALIZER AND THE SIDE ARE PART OF THE MATCH,
		 * not a filter applied afterwards. The same bytes in another
		 * region, hashed another way, or on the other side of the static
		 * library are a different fact - see enum kof_plague_side.
		 */
		if (blk->norm != norm || blk->side != side ||
		    (!c->any_region && !(blk->scan_mask & scan_mask)))
			continue;
		c->pstamp[lo] = c->gen;
		if (c->stamp[b] != c->gen) {
			c->stamp[b] = c->gen;
			c->seen[b] = 0;
		}
		c->seen[b]++;
	}
}

/*
 * A UNIT IS HELD AGAINST A BLOCK BY CONTAINMENT: every window of the unit is
 * asked whether it is one of the block's hashes. Not by comparing two sketches.
 *
 * A block is the smallest window hashes of the span it was cut from, so it is a
 * sample of that span - and a unit is the same sample taken of a different
 * span. When the unit is bigger than the block (a variant with more strings
 * round the same exploit, a function body with something added) its own
 * smallest are a different set, the block's fall out of them, and the score
 * drops though every one of them is still in the bytes. Measured: a 1200-byte
 * block of the exploit strings, cut from one bot, scored 0 of 83 on the 83
 * Bazaar files that carry the same request (sketch 28%), and 67 of 83 at 70%
 * or more asked this way.
 *
 * TWO REJECTS BEFORE THE SEARCH, both one load: `top`, the largest hash of the
 * whole set (the blocks of an old rule are all small), then the bit table. A
 * window that passes neither is in no block.
 */
void kof_plague_unit(struct kof_plague_ctx *c, uint32_t scan_mask, uint32_t norm,
		     uint32_t side, const uint8_t *p, uint64_t n)
{
	const struct kof_plague_set *s;
	struct pl_win w;
	uint32_t top;

	if (!c || !c->set || !p || norm >= KOF_PLAGUE_NORM_COUNT ||
	    !c->set->n_pair || !pl_win_begin(&w, p, n, norm))
		return;
	s = c->set;
	top = s->pair[s->n_pair - 1u].hash;
	do {
		uint32_t v = pl_win_value(&w);

		if (v > top)
			continue;
		if (s->bloom) {
			uint32_t ix = v & s->bloom_mask;

			if (!((s->bloom[ix >> 6] >> (ix & 63u)) & 1u))
				continue;
		}
		if (!pl_win_flat(&w))
			pl_credit(c, scan_mask, norm, v, side);
	} while (pl_win_next(&w));
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
