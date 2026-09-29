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

	uint8_t  *bm;
	uint32_t  bm_bits;          /* the table is 1 << bm_bits bits */
	uint32_t  bm_mask;

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
		if (!pl_radix(s->pair, s->n_pair))
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
	free(s->bm);
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
	c->obj_base = 0;
	c->lib = 0;
	c->n_lib = 0;
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

void kof_plague_object(struct kof_plague_ctx *c, const uint8_t *base,
		       const struct kof_range *lib, uint32_t n_lib)
{
	if (!c)
		return;
	c->obj_base = base;
	c->lib      = (base && n_lib) ? lib : 0;
	c->n_lib    = (base && lib) ? n_lib : 0;
}

/*
 * Does the window at file offset `off` touch the library?
 *
 * Linear over the spans, which number a few tens at most, and reached only by a
 * window that already passed selection - so this runs on roughly one window in
 * a few thousand and an object with no library never reaches it at all.
 *
 * ANY OVERLAP DISQUALIFIES, not majority overlap. A window straddling the
 * boundary is part library, and a hash of part of the library is still a hash
 * every binary built against that library can produce.
 */
static int pl_in_lib(const struct kof_plague_ctx *c, uint64_t off, uint64_t len)
{
	uint32_t i;

	for (i = 0; i < c->n_lib; i++) {
		uint64_t s = c->lib[i].off;
		uint64_t e = s + c->lib[i].len;

		if (off < e && s < off + len)
			return 1;
	}
	return 0;
}

/*
 * THE GENERATOR SIDE: hash one span the way the matcher will read it.
 *
 * Here rather than in whoever is carving because there is one right answer and
 * several callers - the panel that offers blocks, anything that wants to
 * recognise a block it has been handed, a test. A generator that derived a
 * value differently from kof_plague_feed would produce a rule that matches
 * nothing and reports no error, and the way to make that impossible is for
 * there to be one of it.
 *
 * The k smallest DISTINCT values, which is the cut the matcher expects: a block
 * and a file both keep their smallest, so the two subsets overlap wherever the
 * content does. Windows of one repeated byte are left out on both sides - see
 * kof_plague_flat.
 *
 * Returns how many were written, never more than max_out.
 */
/*
 * ASCENDING, IN PLACE, AND NOT AN INSERTION SORT.
 *
 * What the caller wants out of this is a sorted, de-duplicated list, and any
 * correct sort produces the same one - so the choice is only about what it
 * costs. An insertion sort was here, and the values being sorted are hashes:
 * they arrive in no order at all, which is the input that makes it quadratic
 * rather than the nearly-sorted one that makes it fast.
 *
 * The array is up to KOF_PLAGUE_SPAN_MAX entries. At the cap that is 268
 * million moves against 229 thousand comparisons for an n log n sort, and the
 * span this runs over is a whole region of a file - kofviewer carves one every
 * time a researcher moves the selection.
 *
 * HEAPSORT, WHICH IS THE ONE THAT FITS. `tmp` is already 64 KB of frame and
 * the build refuses a frame past 128 KB, so a merge or a radix pass has
 * nowhere to put its second buffer; heapsort needs none, recurses nowhere, and
 * has no input that degrades it.
 */
static void pl_sift(uint32_t *a, uint32_t root, uint32_t n)
{
	for (;;) {
		uint32_t c = 2u * root + 1u, big = root, t;

		if (c < n && a[c] > a[big])
			big = c;
		if (c + 1u < n && a[c + 1u] > a[big])
			big = c + 1u;
		if (big == root)
			return;
		t = a[root]; a[root] = a[big]; a[big] = t;
		root = big;
	}
}

static void pl_sort(uint32_t *a, uint32_t n)
{
	uint32_t i;

	if (n < 2u)
		return;
	for (i = n / 2u; i-- > 0u; )
		pl_sift(a, i, n);
	for (i = n; i-- > 1u; ) {
		uint32_t t = a[0];

		a[0] = a[i];
		a[i] = t;
		pl_sift(a, 0, i);
	}
}

uint32_t kof_plague_hash_span(const uint8_t *p, uint64_t n, uint32_t norm,
			      uint32_t *out, uint32_t max_out)
{
	uint32_t h = 0, drop = kof_plague_drop_weight(), i, got = 0;
	uint64_t at;
	uint32_t tmp[KOF_PLAGUE_SPAN_MAX];
	uint32_t nt = 0;

	if (norm != KOF_PLAGUE_RAW) {
		if (n < 2u)
			return 0;
		n -= 1u;
	}
	if (n < KOF_PLAGUE_NG)
		return 0;

	/* One definition of what a normalizer presents - see kofplague.h. The
	 * macro that used to be here was a second copy of it, and a generator
	 * that derived a byte differently from the matcher is a rule that
	 * matches nothing and reports no error. */
#define PB(k) ((uint32_t)kof_plague_byte(p, (k), norm))
	for (i = 0; i < KOF_PLAGUE_NG; i++)
		h = h * KOF_PLAGUE_BASE + PB(i);
	for (at = 0;; at++) {
		/* The multiply decides selection on its own - see
		 * kof_plague_premix. The xor-shift is paid only by the one
		 * window in 2^SEL_BITS that is going to be stored. */
		uint32_t pre = kof_plague_premix(h);

		if (kof_plague_selects_pre(pre) &&
		    !kof_plague_flat(p, at, norm) &&
		    nt < KOF_PLAGUE_SPAN_MAX)
			tmp[nt++] = kof_plague_mix_from(pre);
		if (at + KOF_PLAGUE_NG >= n)
			break;
		h -= PB(at) * drop;
		h = h * KOF_PLAGUE_BASE + PB(at + KOF_PLAGUE_NG);
	}
#undef PB
	pl_sort(tmp, nt);
	for (i = 0; i < nt && got < max_out; i++)
		if (!i || tmp[i] != tmp[i - 1u])
			out[got++] = tmp[i];
	return got;
}


/* Credit one hash to every block that holds it. */
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
		/*
		 * AND THE SIDE, for the reason the two above are here: a block
		 * cut from the static library and a block cut from the author's
		 * own code are answers to different questions, and one must not
		 * be able to score the other. See enum kof_plague_side.
		 */
		if (blk->side != side)
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

	/* One definition of what a normalizer presents - see kofplague.h. The
	 * macro that used to be here was a third copy of it. */
#define kof_plague_byte_of(k) ((uint32_t)kof_plague_byte(p, (k), norm))
	for (i = 0; i < KOF_PLAGUE_NG; i++)
		h = h * KOF_PLAGUE_BASE + kof_plague_byte_of(i);

	for (at = 0;; at++) {
		/* The multiply decides selection on its own - see
		 * kof_plague_premix. This is the hottest loop in the matcher
		 * and the xor-shift was being run on every byte of every
		 * region to produce a value that thirty-one windows in
		 * thirty-two never read. */
		uint32_t pre = kof_plague_premix(h);

		if (kof_plague_selects_pre(pre) &&
		    !kof_plague_flat(p, at, norm)) {
			uint32_t mixed = kof_plague_mix_from(pre);
			uint32_t k = mixed & s->bm_mask;

			/*
			 * WHICH SIDE THIS WINDOW IS ON - see enum
			 * kof_plague_side. It used to be a refusal: a window
			 * inside the library credited nothing at all. Now it
			 * chooses which blocks it may credit, so the library is
			 * still unable to score a rule written on author code
			 * and has become able to score one written on itself.
			 *
			 * Per window, and after selection because that is what
			 * makes it free: one object in a thousand windows gets
			 * this far.
			 */
			/*
			 * NG BYTES RAW AND NG+1 DIFFERENCED, because that is
			 * what the window actually READ - see kof_plague_byte,
			 * which takes p[k] and p[k+1] for XOR and SUB. Asked
			 * about NG either way, a window whose last differenced
			 * byte was the library's first would have been called
			 * the author's, and the rule this states is that ANY
			 * overlap disqualifies.
			 */
			/*
			 * THE BITMAP FIRST, AND THE SIDE ONLY IF IT PASSES.
			 *
			 * Both values below are read by pl_credit and by
			 * nothing else, so computing them before the index
			 * test is work thrown away for every window the index
			 * does not hold - which is nearly all of them. The cost
			 * model at the top of kofplague.h says exactly that:
			 * "most windows are not selected at all, and of those
			 * that are, most are in no rule; both are rejected
			 * without touching the index."
			 *
			 * pl_in_lib walks the library spans, and the symbol
			 * tier produces one per library function - up to
			 * KOF_LIB_MAX_SPANS_ALL of them. Paid per selected
			 * window on a three-megabyte object that is ninety
			 * thousand walks of a list answering nothing the
			 * verdict uses.
			 *
			 * The answer is identical either way: the index test
			 * reads nothing these compute, and they read nothing
			 * the index test changes.
			 */
			if (s->bm[k >> 3] & (1u << (k & 7u))) {
				uint64_t wlen = norm == KOF_PLAGUE_RAW
					      ? (uint64_t)KOF_PLAGUE_NG
					      : (uint64_t)KOF_PLAGUE_NG + 1u;
				uint32_t side = (c->n_lib && p >= c->obj_base &&
						 pl_in_lib(c,
							   (uint64_t)(p - c->obj_base) + at,
							   wlen))
					      ? (uint32_t)KOF_PLAGUE_SIDE_LIB
					      : (uint32_t)KOF_PLAGUE_SIDE_USER;

				pl_credit(c, scan_mask, norm, mixed, side);
			}
		}
		/* The `next:` label that was here is gone with the refusal it
		 * existed for: a library window no longer skips the crediting
		 * step, it credits a different set of blocks. */
		if (at + KOF_PLAGUE_NG >= n)
			break;
		/*
		 * THE NORMALIZER IS DECIDED ONCE PER WINDOW, NOT TWICE.
		 *
		 * kof_plague_byte is a two-branch chain on `norm`, and the two
		 * calls below run it for every byte of every region fed - so
		 * the rolling update asked a question that cannot change for
		 * the whole walk, four times a window.
		 *
		 * GCC does not lift it: loop unswitching is an -O3 pass and
		 * this tree builds at -O2, so the invariant test stays inside
		 * the loop however obvious it is. Lifted by hand, it becomes
		 * one branch the predictor gets right every time, and the two
		 * accessors become plain loads.
		 *
		 * The three arms are kof_plague_byte's three cases, spelled the
		 * same way and in the same order - see kofplague.h, which is
		 * still the one definition of what a normalizer presents.
		 */
		if (norm == KOF_PLAGUE_RAW) {
			h -= (uint32_t)p[at] * drop;
			h = h * KOF_PLAGUE_BASE +
			    (uint32_t)p[at + KOF_PLAGUE_NG];
		} else if (norm == KOF_PLAGUE_XOR) {
			h -= (uint32_t)(uint8_t)(p[at] ^ p[at + 1u]) * drop;
			h = h * KOF_PLAGUE_BASE +
			    (uint32_t)(uint8_t)(p[at + KOF_PLAGUE_NG] ^
						p[at + KOF_PLAGUE_NG + 1u]);
		} else {
			h -= (uint32_t)(uint8_t)(p[at + 1u] - p[at]) * drop;
			h = h * KOF_PLAGUE_BASE +
			    (uint32_t)(uint8_t)(p[at + KOF_PLAGUE_NG + 1u] -
						p[at + KOF_PLAGUE_NG]);
		}
	}
#undef kof_plague_byte_of
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
	if (seen)
		*seen = (c->stamp[b] == c->gen) ? c->seen[b] : 0u;
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
