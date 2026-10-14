/*
 * kofmutation.c - the similarity matcher.
 *
 * A block is the MinHash sketch of one unit of code or data; the scanner
 * sketches the units of the object it is looking at - see libgenome/celllysis/mutation_units.c for
 * how an object is cut, the same way a block was cut - and counts how much of a
 * block's sketch a unit's holds. There is no scan of every window: the cost is
 * one rolling pass over each unit and a lookup per window that survives the filter.
 *
 * WHAT THIS FILE IS, in one paragraph, because the structure is not the obvious one.
 *
 * The index is the pack's own (databases/pack/dbkix.h): every (hash, block, slot) of every
 * block, sorted, grouped by the top 16 bits of the hash times an odd constant, with a
 * directory and a class table in memory and the entries read from the file on demand. A
 * window is looked up in three steps, each one an exact test or a cheaper stand-in for one:
 *
 *   `top`        the largest hash of the whole set. A window above it is in no block.
 *   FILTER       a blocked bloom filter, one 64-byte line a window, over every key. It is
 *                what keeps most windows from touching the file at all, and its size is
 *                what the engine's ledger grants - so a false pass costs a read and never
 *                a wrong answer, and a filter that is too small makes the scan slower and
 *                not different. (The stream path of the earlier matcher probed each window
 *                that passed, one at a time, against a hash table that was ALL in memory:
 *                27 bytes a hash. It is gone: one path, one memory model.)
 *   BATCH        the windows that pass are collected (a chunk of KOF_MUTATION_CHUNK, or a
 *                unit), sorted, and probed bucket by bucket in ascending order, so a
 *                bucket is read once per chunk and neighbouring buckets in one read.
 *
 * WHY CREDIT IS A SET BIT. A block's count is the number of its (block, slot) entries whose
 * hash the object held, each counted once per object. A window adds to a count only through
 * the entries of its value that match the CALL - normalizer, side and region (or any region)
 * - so crediting is idempotent: a second window with the same value in the same context finds
 * every entry it matches already credited. The state keeps one bit per (block, slot) and the
 * count is how many are set. Because it is idempotent the order of the windows does not
 * matter, which is what lets a batch be sorted and the same value met in two chunks, or two
 * units, be credited twice without effect. tests/unit/mutation_index.c keeps the previous
 * in-memory matcher as an oracle and holds this one to it entry for entry.
 *
 * WHAT STILL BOUNDS THE COST OF AN OBJECT, because the DoS bounds did not go with the
 * stream. A value held by more than MTN_HOT blocks is "hot": it is walked once per object
 * per context however often the object repeats it (a small table, struct mtn_ent), and
 * every walk spends from a visit budget (max_visit) that, when it runs out, refuses the
 * walk whole and says so. The pack file is read through a per-object allowance
 * (KOF_MTN_IO_BASE plus a share of the bytes fed). A bucket larger than the read buffer -
 * only a pack built to skew, since the key is multiplied - is searched through small reads
 * instead of read whole. Every one of these only LOWERS a count and is reported in the
 * object's status; none is a silent loss.
 */

#include <stdlib.h>
#include <string.h>

#include "kofmutation.h"

/* The slot is 8 bits below the block number in an entry's reference. */
_Static_assert(KOF_MUTATION_MAX_HASH <= 128u,
	       "the per-block credit bits are four words of 32");
/* A set may hold this many blocks and no more: the block id is 24 bits of the reference. */
#define PL_MAX_BLOCK  0x00ffffffu

#define MTN_HOT        64u                 /* a value in more blocks than this is walked once per object */
#define MTN_WIN        (1u << 20)          /* bytes of index one read may cover */
#define MTN_GAP        (8u << 10)          /* buckets this near are read together */
#define MTN_SV_MIN     4096u
#define MTN_BIG_STEP   256u                /* entries read at a time when a bucket is searched by small reads */
#define MTN_PIECE      4096u

struct mtn_part {
	struct kof_kix *kix;
	const uint32_t *dir;
	const struct kof_kix_class *cls;
	uint32_t        n_class;
	uint32_t        base, n_block;
	uint64_t        n_pair;
	/* Borrowed arrays of a part built in memory (kof_mutation_block_hashes). */
	const struct kof_mutation_block *mem_blk;
	const uint32_t *mem_pool;
	int             in_mem;
	int             has_xf;       /* its filter is pre-built (kofmutflt.h), not a share of the merged bloom filter */
};

struct kof_mutation_set {
	struct mtn_part *part;
	uint32_t        n_part;
	uint32_t        n_block;
	uint32_t        top;         /* the largest raw hash of any part */
	struct kof_fbank *fb;        /* the filters in front of the index (kofmutflt.h) */
	uint64_t        flt_ceiling; /* what the ledger's rule allowed them, bytes */
	uint64_t        max_visit;   /* per object: entries one object may walk */
	uint64_t        io_per_byte; /* per byte fed: what an object's reads of the index file may cost, see kof_mutation_build_req */
	uint32_t        status;      /* KOF_MTN_B_* */
	uint32_t        n_key, max_mult;
	uint64_t        n_pair;
	uint32_t        norm_bit[32];
	uint32_t        norm_all;
	uint64_t        bytes;
};

/*
 * One entry per block this object credited: which of its hashes (slot s is bit s of four
 * words) and how many. Valid when `gen` is the object's generation; the table holds only
 * what was touched and doubles when three quarters full: 32 bytes an entry, so the cost
 * follows the OBJECT and never the database.
 */
struct mtn_blk {
	uint32_t block, gen, cnt, pad;
	uint32_t w[4];
};

/*
 * One entry per (hot value, normalizer+side) this object has walked: the union of the
 * region masks walked, whether an any-region walk happened, and whether the walk was
 * refused for the budget.
 */
struct mtn_ent {
	uint32_t key, mask, meta, gen;
};
#define MTN_M_CLS     0x0fffffffu
#define MTN_M_ANY     0x40000000u
#define MTN_M_REFUSED 0x80000000u

/* ---- helpers ------------------------------------------------------------------ */

static inline uint32_t mtn_mix(uint32_t k, uint32_t salt)
{
	uint32_t h = (k ^ salt) * 0x9E3779B1u;

	h ^= h >> 15;
	h *= 0x85EBCA77u;
	h ^= h >> 13;
	return h;
}

static inline uint32_t ld32(const uint8_t *p)
{
	uint32_t x;

	memcpy(&x, p, 4);
	return x;
}

static inline uint32_t ld16(const uint8_t *p)
{
	uint16_t x;

	memcpy(&x, p, 2);
	return x;
}

/* ---- building ----------------------------------------------------------------- */

static void mtn_fill(struct kof_mutation_build_res *r, const struct kof_mutation_set *s,
		     uint32_t status)
{
	uint32_t i;

	memset(r, 0, sizeof *r);
	r->status = status;
	if (!s)
		return;
	r->bytes = s->bytes;
	r->n_block = s->n_block;
	r->n_pair = (uint32_t)s->n_pair;
	r->n_key = s->n_key;
	r->max_mult = s->max_mult;
	r->bloom_bits = (s->fb->flt_bytes + s->fb->fx_bytes) * 8u;
	r->flt_kind = (s->fb->flt ? KOF_MTN_FLT_BLOOM : 0u) | (s->fb->nfx ? KOF_MTN_FLT_FUSE : 0u);
	r->flt_w = s->fb->nfx ? s->fb->w : 0u;
	r->flt_parts = s->fb->parts;
	r->flt_res = s->fb->res;
	r->flt_ceiling = s->flt_ceiling;
	r->max_visit = s->max_visit;
	r->n_part = s->n_part;
	for (i = 0; i < s->n_part; i++)
		r->n_part_mem += s->part[i].in_mem != 0;
}

static void mtn_res(const struct kof_mutation_build_req *rq, const struct kof_mutation_set *s,
		    uint32_t status)
{
	if (rq->res)
		mtn_fill(rq->res, s, status);
}

static void mtn_set_free_parts(struct kof_mutation_set *s)
{
	uint32_t i;

	for (i = 0; i < s->n_part; i++)
		kof_kix_close(s->part[i].kix);
	free(s->part);
	kof_fbank_free(s->fb);
	free(s);
}

static uint32_t mtn_status_of_kix(uint32_t b)
{
	uint32_t st = 0;

	if (b & KOF_KIX_B_NOMEM)
		st |= KOF_MTN_B_NOMEM;
	if (b & KOF_KIX_B_TOO_BIG)
		st |= KOF_MTN_B_TOO_BIG;
	if (b & KOF_KIX_B_TOO_MANY_BLOCKS)
		st |= KOF_MTN_B_TOO_MANY_BLOCKS;
	if (b & KOF_KIX_B_BAD_BLOCK)
		st |= KOF_MTN_B_BAD_BLOCK;
	if (b & KOF_KIX_B_TOO_MANY_CLASSES)
		st |= KOF_MTN_B_TOO_MANY_CLASSES;
	if (b & KOF_KIX_B_OVER_BUDGET)
		st |= KOF_MTN_B_OVER_BUDGET;
	return st;
}

/* The caller's arrays as one source, when it gave arrays and not sources. */
static uint32_t mtn_collect(const struct kof_mutation_build_req *rq,
			    struct kof_mutation_src *one, const struct kof_mutation_src **out)
{
	if (rq->n_src) {
		*out = rq->src;
		return rq->n_src;
	}
	memset(one, 0, sizeof *one);
	one->blocks = rq->blocks;
	one->n_blocks = rq->n_blocks;
	one->pool = rq->pool;
	one->n_pool = rq->n_pool;
	*out = one;
	return 1;
}

/*
 * THE ALLOWANCE. The index is charged to the engine's ledger first, at load, and may take at
 * most half of what is left - the scanners need the rest. With no ledger the default cap is
 * the ledger. `max_bytes` lowers it further. Returns what the resident part of the index
 * may take.
 */
static uint64_t mtn_allowance(const struct kof_mutation_build_req *rq)
{
	uint64_t room, allow;

	if (rq->budget)
		room = kof_budget_room(rq->budget);
	else
		room = KOF_ENGINE_MEM_CAP;
	allow = room / 2u;
	if (rq->max_bytes && rq->max_bytes < allow)
		allow = rq->max_bytes;
	return allow;
}

struct kof_mutation_set *kof_mutation_build_req(const struct kof_mutation_build_req *rq)
{
	struct kof_mutation_src one;
	const struct kof_mutation_src *src;
	struct kof_mutation_set *s = NULL;
	uint32_t n_src = mtn_collect(rq, &one, &src), i, j, st = 0, bit;
	uint64_t allow, used = 0, k_bloom = 0, mem_est = 0, fb, scratch, fixed_now, room, ceiling, ceil_x, ceil_b;
	uint64_t stored_max = 0, n_key_bloom = 0;
	uint32_t n_mem = 0, bpk, no_filter;
	uint64_t total_blk = 0, body = 0;

	/* Sources are taken over whatever happens: close the ones a refusal leaves unused. */
#define REFUSE_ALL(bits)                                                     \
	do {                                                                 \
		st |= (bits);                                                \
		goto refuse;                                                 \
	} while (0)

	s = calloc(1, sizeof *s);
	if (!s) {
		for (i = 0; i < n_src; i++)
			kof_kix_close(src[i].kix);
		mtn_res(rq, NULL, KOF_MTN_B_NOMEM);
		return NULL;
	}
	s->part = calloc(n_src ? n_src : 1u, sizeof *s->part);
	s->fb = kof_fbank_new(n_src);
	if (!s->part || !s->fb)
		REFUSE_ALL(KOF_MTN_B_NOMEM);
	/* A part holds its source's kix from now on, so the free path closes it. Parts built in
	 * memory are filled in below, after the filter's size is known. */
	for (i = 0; i < n_src; i++) {
		s->part[i].kix = src[i].kix;
		s->part[i].base = src[i].base;
		s->part[i].n_block = src[i].kix ? 0u : src[i].n_blocks;
	}
	s->n_part = n_src;

	allow = mtn_allowance(rq);
	s->max_visit = 0;

	/* Pass 1: what each source holds, to size the filter before anything is built. */
	for (i = 0; i < n_src; i++) {
		struct mtn_part *p = &s->part[i];

		if (src[i].kix) {
			struct kof_kix_info in;

			kof_kix_info(src[i].kix, &in);
			p->n_block = in.n_block;
			p->n_pair = in.n_pair;
			used += in.resident;
			if (src[i].xf.read || in.xf_bytes) {   /* a trailer with no bloom filter must come with its reader */
				if (!src[i].xf.read || !kof_fbank_add_xf(s->fb, &src[i].xf, src[i].xf_crc, in.n_key))
					REFUSE_ALL(KOF_MTN_B_BAD_BLOCK);
				p->has_xf = 1;
			} else {
				k_bloom += in.n_key;     /* distinct hashes: what a filter holds, not the entries (real code repeats: 2.5 each) */
				stored_max = in.filter_bytes > stored_max ? in.filter_bytes : stored_max;
			}
		} else {
			uint64_t np = 0;

			if (src[i].n_blocks > PL_MAX_BLOCK)
				REFUSE_ALL(KOF_MTN_B_TOO_MANY_BLOCKS);
			if ((src[i].n_blocks && !src[i].blocks) || (src[i].n_pool && !src[i].pool))
				REFUSE_ALL(KOF_MTN_B_BAD_BLOCK);
			for (j = 0; j < src[i].n_blocks; j++)
				np += src[i].blocks[j].n_hash > KOF_MUTATION_MAX_HASH
				      ? KOF_MUTATION_MAX_HASH : src[i].blocks[j].n_hash;
			p->n_pair = np;
			k_bloom += np;
			/* The image without its filter, as the builder will charge it. */
			mem_est += kof_kix_image_bytes(np, 0);
			n_mem++;
		}
		total_blk += p->n_block;
	}
	if (total_blk > PL_MAX_BLOCK)
		REFUSE_ALL(KOF_MTN_B_TOO_MANY_BLOCKS);
	s->n_block = (uint32_t)total_blk;

	/*
	 * THE FILTERS, from the ledger, with no flat cap. What they may take is a share of what the ledger has
	 * left once the index's own tables are counted and `scanners` scanners' fixed costs are set aside
	 * (kof_mflt_ceiling), and never more than the allowance's half; the pre-built filters and the bloom filter
	 * (kofmutflt.h) each get their packs' share of the keys. A pre-built one is taken down the ladder until it
	 * fits - fewer bits of every fingerprint, below one bit fewer partitions - and a bloom filter is halved,
	 * as before (the stored ones of a pack cannot be made larger than they were written). Both are a COST, not a
	 * loss of evidence: a window a filter lets through is read against the index, and the status says how far
	 * down it went.
	 */
	bpk = rq->bloom_bpk ? rq->bloom_bpk : KOF_KIX_FILTER_BPK;
	scratch = n_mem ? KOF_KIX_SCRATCH : 0;          /* transient: freed when the part is built */
	fixed_now = used + mem_est + scratch;
	if (fixed_now > allow)
		REFUSE_ALL(KOF_MTN_B_OVER_BUDGET);
	room = rq->budget ? kof_budget_room(rq->budget) : KOF_ENGINE_MEM_CAP;
	ceiling = kof_mflt_ceiling(room > fixed_now ? room - fixed_now : 0u, rq->budget ? rq->budget->cap : KOF_ENGINE_MEM_CAP,
				   rq->scanners, rq->scan_fixed);
	if (ceiling > allow - fixed_now)
		ceiling = allow - fixed_now;
	s->flt_ceiling = ceiling;
	no_filter = (rq->flags & KOF_MTN_BUILD_NO_FILTER) != 0;
	ceil_x = k_bloom + s->fb->xf_pairs ? ceiling / (k_bloom + s->fb->xf_pairs) * s->fb->xf_pairs +
		 ceiling % (k_bloom + s->fb->xf_pairs) * s->fb->xf_pairs / (k_bloom + s->fb->xf_pairs) : 0u;
	ceil_b = ceiling - ceil_x;
	fb = no_filter || !k_bloom ? 0u : kof_fbank_bloom_default(k_bloom, bpk, n_mem ? 0u : stored_max);
	/* Ask the ledger for it (kof_budget_ask: how much of `fb` may be used now), and keep the allowance's
	 * half-rule and the ceiling besides: the filter is halved until all say yes. */
	while (fb > KOF_KIX_FILTER_MIN &&
	       (fixed_now + fb * (1u + n_mem) > allow || fb * (1u + n_mem) > ceil_b ||
		(rq->budget && kof_budget_ask(rq->budget, fb * (1u + n_mem)) < fb * (1u + n_mem))))
		fb >>= 1;
	if (fb && fixed_now + fb * (1u + n_mem) > allow)
		REFUSE_ALL(KOF_MTN_B_OVER_BUDGET);

	/* Pass 2: the sources without a trailer, built in memory. */
	for (i = 0; i < n_src; i++) {
		struct mtn_part *p = &s->part[i];
		struct kof_kix_build_in bi;
		struct kof_kix_build_res br;
		struct kof_kix *k;
		uint8_t *img;
		uint64_t len;
		char why[160];

		if (src[i].kix)
			continue;
		memset(&bi, 0, sizeof bi);
		bi.blk = src[i].blocks; bi.n_blk = src[i].n_blocks;
		bi.pool = src[i].pool; bi.n_pool = src[i].n_pool;
		bi.filter_bytes = fb ? fb : KOF_KIX_FILTER_MIN;
		bi.max_bytes = allow - used;
		img = kof_kix_make(&bi, 0, 0, 0, &len, &br);
		if (!img) {
			st |= mtn_status_of_kix(br.status);
			if (!(st & KOF_MTN_B_REFUSED))
				st |= KOF_MTN_B_BAD_BLOCK;
			goto refuse;
		}
		k = kof_kix_open_mem(img, len, src[i].blocks, src[i].n_blocks,
				     src[i].pool, src[i].n_pool, why, sizeof why);
		if (!k)
			REFUSE_ALL(KOF_MTN_B_NOMEM);
		p->kix = k;
		p->in_mem = 1;
		p->mem_blk = src[i].blocks;
		p->mem_pool = src[i].pool;
		p->n_pair = br.n_pair;
		{
			struct kof_kix_info in;

			kof_kix_info(k, &in);
			used += in.resident;
		}
		st |= KOF_MTN_B_IN_RAM;
	}

	/* The parts' numbers, and what the whole set says about itself. */
	for (i = 0; i < n_src; i++) {
		struct mtn_part *p = &s->part[i];
		struct kof_kix_info in;
		uint32_t c;

		kof_kix_info(p->kix, &in);
		p->dir = kof_kix_dir(p->kix);
		p->cls = kof_kix_class(p->kix, &p->n_class);
		p->n_pair = in.n_pair;
		s->n_pair += in.n_pair;
		s->n_key += in.n_key;
		body += in.body_len;
		if (in.max_mult > s->max_mult)
			s->max_mult = in.max_mult;
		if (in.n_pair && in.top > s->top)
			s->top = in.top;
		for (c = 0; c < p->n_class; c++) {
			uint32_t m = 1u << p->cls[c].norm;

			s->norm_all |= m;
			for (bit = 0; bit < 32u; bit++)
				if (p->cls[c].mask & (1u << bit))
					s->norm_bit[bit] |= m;
		}
	}
	/* Blocks are numbered pack after pack: the parts must be in that order. */
	for (i = 1; i < n_src; i++)
		if (s->part[i].base < s->part[i - 1u].base + s->part[i - 1u].n_block)
			REFUSE_ALL(KOF_MTN_B_BAD_BLOCK);

	/* The filters themselves. A window is refused only by filters that cover every part: one part with
	 * none makes the whole set unfiltered. */
	if (!no_filter && fb) {
		if (!kof_fbank_bloom_alloc(s->fb, fb))
			REFUSE_ALL(KOF_MTN_B_NOMEM);
		for (i = 0; i < n_src; i++) {
			struct kof_kix_info in;

			if (s->part[i].has_xf)
				continue;
			/* A filter that cannot be read is an index that cannot be trusted. */
			if (!kof_fbank_bloom_or(s->fb, s->part[i].kix))
				REFUSE_ALL(KOF_MTN_B_BAD_BLOCK);
			kof_kix_info(s->part[i].kix, &in);
			n_key_bloom += in.n_key;
		}
		used += fb;
	}
	if (!no_filter && !kof_fbank_open_xf(s->fb, ceil_x))
		REFUSE_ALL(KOF_MTN_B_BAD_BLOCK);
	used += s->fb->fx_bytes;
	s->fb->filtered = !no_filter && (!k_bloom || fb) && s->fb->xf_ok;
	if (!s->fb->filtered) {
		st |= KOF_MTN_B_NO_FILTER;
		if (!no_filter)
			st |= KOF_MTN_B_FILTER_DEGRADED;
	} else if ((fb && fb * 8u < n_key_bloom * KOF_KIX_FILTER_FLOOR_BPK) ||
		   (s->fb->nfx && (s->fb->w < KOF_MFLT_W_FLOOR || s->fb->res < s->fb->parts))) {
		st |= KOF_MTN_B_FILTER_DEGRADED;
	}
	/*
	 * WHAT AN OBJECT MAY READ. A window that survives the filter costs at most one read, and
	 * a read costs a page at the least, so a page a byte fed is what an object whose every
	 * window survives could ask for; and each batch (KOF_MUTATION_CHUNK survivors) may read
	 * the whole body once, which is a share of it a byte. Past that the object has asked for
	 * more than its own size explains: it is stopped, and says so (KOF_MTN_S_IO_BUDGET).
	 * Measured against the real traffic of an object at every filter size, never reached
	 * (see the stage report); a bound on what a hostile object or index may cost, and a
	 * function of the object and not of how many hashes the database holds in any other way
	 * than the body the passes cover.
	 */
	s->io_per_byte = 4096u + 2u * ((body + KOF_MUTATION_CHUNK - 1u) / KOF_MUTATION_CHUNK);
	s->max_visit = rq->max_visit ? rq->max_visit
		     : (4u * s->n_pair > (1u << 22) ? 4u * s->n_pair : (1u << 22));
	s->bytes = used + sizeof *s;
	s->status = st;
	mtn_res(rq, s, st);
	return s;

refuse:
	mtn_res(rq, NULL, st);
	if (rq->res)
		rq->res->bytes = used;
	if (s) {
		/* Sources not yet adopted are closed here; adopted ones by the free. */
		if (s->part) {
			for (i = s->n_part; i < n_src; i++)
				kof_kix_close(src[i].kix);
			mtn_set_free_parts(s);
		} else {
			for (i = 0; i < n_src; i++)
				kof_kix_close(src[i].kix);
			free(s);
		}
	}
	return NULL;
#undef REFUSE_ALL
}

struct kof_mutation_set *kof_mutation_build(const struct kof_mutation_block *blocks,
					uint32_t n_blocks,
					const uint32_t *pool, uint32_t n_pool)
{
	struct kof_mutation_build_req rq;

	memset(&rq, 0, sizeof rq);
	rq.blocks = blocks; rq.n_blocks = n_blocks;
	rq.pool = pool; rq.n_pool = n_pool;
	return kof_mutation_build_req(&rq);
}

void kof_mutation_set_free(struct kof_mutation_set *s)
{
	if (!s)
		return;
	mtn_set_free_parts(s);
}

void kof_mutation_set_info(const struct kof_mutation_set *s, struct kof_mutation_build_res *r)
{
	mtn_fill(r, s, s ? s->status : 0u);
}

static const struct mtn_part *mtn_part_of(const struct kof_mutation_set *s, uint32_t b,
					  uint32_t *local)
{
	uint32_t lo = 0, hi;

	if (!s || b >= s->n_block || !s->n_part)
		return NULL;
	hi = s->n_part;
	while (hi - lo > 1u) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (s->part[mid].base <= b)
			lo = mid;
		else
			hi = mid;
	}
	if (b < s->part[lo].base || b - s->part[lo].base >= s->part[lo].n_block)
		return NULL;
	*local = b - s->part[lo].base;
	return &s->part[lo];
}

int kof_mutation_block_copy(const struct kof_mutation_set *s, uint32_t block,
			    uint32_t *out, uint32_t *n_hash)
{
	uint32_t local, n = 0;
	const struct mtn_part *p = mtn_part_of(s, block, &local);

	if (n_hash)
		*n_hash = 0;
	if (!p || !kof_kix_block_hashes(p->kix, local, out, &n, NULL))
		return 0;
	if (n_hash)
		*n_hash = n;
	return 1;
}

const uint32_t *kof_mutation_block_hashes(const struct kof_mutation_set *s,
					uint32_t block, uint32_t *n_hash)
{
	uint32_t local;
	const struct mtn_part *p = mtn_part_of(s, block, &local);

	if (n_hash)
		*n_hash = 0;
	if (!p || !p->in_mem || !p->mem_blk || !p->mem_pool)
		return NULL;
	if (n_hash)
		*n_hash = p->mem_blk[local].n_hash;
	return p->mem_pool + p->mem_blk[local].first_hash;
}

/*
 * THE NAME OF A BLOCK, and the only place it is decided.
 *
 * A block has no stored name - it is the fold of its own hashes, so the same
 * bytes carry the same name whoever carved them and whichever pack they were
 * loaded into. Both the verdict the scanner writes and anyone later asking
 * which rule a verdict came from must read it from here, or the two spellings
 * drift and the answer is wrong in a way nothing reports. The hashes are read from the
 * pack when asked (a verdict names a handful of blocks), so no table of names is held.
 */
uint32_t kof_mutation_block_id(const struct kof_mutation_set *s, uint32_t block)
{
	uint32_t h[KOF_MUTATION_MAX_HASH], n = 0;

	if (!kof_mutation_block_copy(s, block, h, &n))
		return 0u;
	return kof_mutation_fold(h, n);
}

uint32_t kof_mutation_set_norms(const struct kof_mutation_set *s, uint32_t scan_mask)
{
	uint32_t i, m = 0;

	if (!s)
		return 0;
	/* Unioned per region when the set was built - see norm_bit. */
	if (!scan_mask)
		return s->norm_all;
	for (i = 0; i < 32u; i++)
		if (scan_mask & (1u << i))
			m |= s->norm_bit[i];
	return m;
}

uint32_t kof_mutation_probe(const struct kof_mutation_set *s, uint32_t v)
{
	uint32_t r = 0, vp = v * KOF_KIX_MULT, i;

	if (!s || !s->n_pair)
		return 0;
	if (kof_fbank_pass(s->fb, vp))
		r |= 1u;
	for (i = 0; i < s->n_part && !(r & 2u); i++) {
		const struct mtn_part *p = &s->part[i];
		uint32_t b = vp >> (32u - KOF_KIX_DIR_BITS), n = p->dir[b + 1u] - p->dir[b], x;
		struct kof_kix_io io;
		uint8_t *col;

		if (!n)
			continue;
		memset(&io, 0, sizeof io);
		io.budget = (uint64_t)n * KOF_KIX_ENTRY + KOF_MTN_IO_BASE;
		col = malloc((size_t)n * KOF_KIX_ENTRY);
		if (!col)
			continue;
		if (kof_kix_body(p->kix, (uint64_t)p->dir[b] * KOF_KIX_ENTRY, col,
				 (size_t)n * KOF_KIX_ENTRY, &io))
			for (x = 0; x < n; x++)
				if (ld16(col + 2u * x) == (vp & 0xffffu))
					r |= 2u;
		free(col);
	}
	return r;
}

/* ---- per scanner -------------------------------------------------------------- */

static void mtn_settle(const struct kof_mutation_ctx *c);

int kof_mutation_ctx_init(struct kof_mutation_ctx *c, const struct kof_mutation_set *s)
{
	if (!c || !s)
		return 0;
	memset(c, 0, sizeof *c);
	c->set = s;
	c->n_block = s->n_block;
	c->cap = KOF_MUTATION_STATE_CAP;
	/*
	 * Generations start at one, so a table that calloc left at zero cannot be mistaken for
	 * "counted during this object". Nothing is allocated here: the tables follow what an
	 * object touches, and a database with no similarity rules never reaches the first.
	 */
	c->gen = 1;
	return 1;
}

void kof_mutation_ctx_done(struct kof_mutation_ctx *c)
{
	if (!c)
		return;
	free(c->bs);
	free(c->tmap);
	free(c->sv);
	free(c->sv2);
	free(c->span);
	memset(c, 0, sizeof *c);
}

/*
 * Give back everything the state holds. What the last object credited is gone with it (its counts
 * read as zero), so the host trims between objects, never during one.
 */
void kof_mutation_trim(struct kof_mutation_ctx *c)
{
	if (!c)
		return;
	free(c->bs);
	free(c->tmap);
	free(c->sv);
	free(c->sv2);
	free(c->span);
	c->bs = NULL; c->tmap = NULL; c->sv = c->sv2 = NULL; c->span = NULL;
	c->bcap = c->bn = c->tcap = c->tn = c->scap = c->nsv = 0;
	c->span_cap = 0;
	c->held = 0;
}

void kof_mutation_limit(struct kof_mutation_ctx *c, uint64_t cap)
{
	if (c)
		c->cap = cap;
}

uint64_t kof_mutation_held(const struct kof_mutation_ctx *c)
{
	if (!c)
		return 0;
	mtn_settle(c);          /* what waits is credited first: it is part of what the state holds */
	return c->held;
}

static uint32_t mtn_io_status(uint32_t err)
{
	uint32_t st = 0;

	if (err & KOF_KIX_E_BUDGET)
		st |= KOF_MTN_S_IO_BUDGET;
	if (err & KOF_KIX_E_IO)
		st |= KOF_MTN_S_IO_ERROR;
	if (err & KOF_KIX_E_CRC)
		st |= KOF_MTN_S_SLICE_CRC;
	return st;
}

void kof_mutation_begin(struct kof_mutation_ctx *c)
{
	if (!c)
		return;
	mtn_settle(c);          /* the last object's waiting survivors are its own: credited, counted, then dropped */
	/* What the object that just ended did, folded into the life counters. */
	c->life_visits += c->visits;
	c->life_io_bytes += c->io.bytes;
	if (c->status & KOF_MTN_S_WALK_TRUNCATED)
		c->life_trunc_objects++;
	if ((c->status | mtn_io_status(c->io.err)) &
	    (KOF_MTN_S_IO_BUDGET | KOF_MTN_S_IO_ERROR | KOF_MTN_S_SLICE_CRC))
		c->life_io_objects++;
	/* The tables follow what an object touches, so a big one is let go when the last
	 * object needed an eighth of it. */
	if (c->bcap > 4096u && (uint64_t)c->bn * 8u < c->bcap) {
		c->held -= (uint64_t)c->bcap * sizeof *c->bs;
		free(c->bs);
		c->bs = NULL;
		c->bcap = 0;
	}
	if (c->tcap > 4096u && (uint64_t)c->tn * 8u < c->tcap) {
		c->held -= (uint64_t)c->tcap * sizeof *c->tmap;
		free(c->tmap);
		c->tmap = NULL;
		c->tcap = 0;
	}
	c->bn = c->tn = 0;
	c->visits = c->trunc_pairs = c->probes = 0;
	c->trunc_walks = c->walks = c->n_chunks = 0;
	c->status = 0;
	c->fed = 0;
	memset(&c->io, 0, sizeof c->io);
	c->gen++;
	c->any_region = 0;
	/*
	 * Wrapping would make a stale stamp look current. It takes four billion objects on one
	 * thread to get here and the clear is a millisecond, so the honest fix is the cheap one.
	 */
	if (c->gen == 0) {
		if (c->bs)
			memset(c->bs, 0, (size_t)c->bcap * sizeof *c->bs);
		if (c->tmap)
			memset(c->tmap, 0, (size_t)c->tcap * sizeof *c->tmap);
		c->gen = 1;
	}
}

void kof_mutation_any_region(struct kof_mutation_ctx *c, int on)
{
	if (!c)
		return;
	if ((on != 0) != c->any_region)
		mtn_settle(c);          /* what waits was collected under the other setting */
	c->any_region = on != 0;
}

void kof_mutation_stat(const struct kof_mutation_ctx *c, struct kof_mutation_stat *o)
{
	memset(o, 0, sizeof *o);
	if (!c)
		return;
	mtn_settle(c);
	o->status = c->status | mtn_io_status(c->io.err);
	o->visits = c->visits;
	o->walks = c->walks;
	o->probes = c->probes;
	o->trunc_walks = c->trunc_walks;
	o->trunc_pairs = c->trunc_pairs;
	o->n_chunks = c->n_chunks;
	o->touched = c->bn;
	o->state_bytes = c->held;
	o->io_bytes = c->io.bytes;
	o->io_reads = c->io.reads;
	o->life_io_bytes = c->life_io_bytes;
	o->life_visits = c->life_visits;
	o->life_trunc_objects = c->life_trunc_objects + ((c->status & KOF_MTN_S_WALK_TRUNCATED) != 0);
	o->life_io_objects = c->life_io_objects +
		((o->status & (KOF_MTN_S_IO_BUDGET | KOF_MTN_S_IO_ERROR | KOF_MTN_S_SLICE_CRC)) != 0);
}

/* ---- the state ---------------------------------------------------------------- */

/* A table grows only within what the host allows; the new one and the old one exist together
 * for the rehash, so the check is for both. */
static int mtn_room(const struct kof_mutation_ctx *c, uint64_t add)
{
	return c->held <= c->cap && add <= c->cap - c->held;
}

static struct mtn_blk *bs_find(const struct kof_mutation_ctx *c, uint32_t block)
{
	uint32_t i;

	if (!c->bcap)
		return NULL;
	i = mtn_mix(block, 0) & (c->bcap - 1u);
	for (;;) {
		struct mtn_blk *e = &c->bs[i];

		if (e->gen != c->gen)
			return NULL;
		if (e->block == block)
			return e;
		i = (i + 1u) & (c->bcap - 1u);
	}
}

static struct mtn_blk *bs_get(struct kof_mutation_ctx *c, uint32_t block)
{
	uint32_t i;
	struct mtn_blk *e;

	if ((uint64_t)(c->bn + 1u) * 4u > (uint64_t)c->bcap * 3u) {
		uint32_t nc = c->bcap ? c->bcap * 2u : 256u, x;
		uint64_t nb = (uint64_t)nc * sizeof *c->bs;
		struct mtn_blk *nt;

		if (nc < c->bcap || !mtn_room(c, nb))
			return NULL;
		nt = calloc(nc, sizeof *nt);
		if (!nt)
			return NULL;
		for (x = 0; x < c->bcap; x++) {
			const struct mtn_blk *o = &c->bs[x];

			if (o->gen != c->gen)
				continue;
			i = mtn_mix(o->block, 0) & (nc - 1u);
			while (nt[i].gen)
				i = (i + 1u) & (nc - 1u);
			nt[i] = *o;
		}
		c->held -= (uint64_t)c->bcap * sizeof *c->bs;
		free(c->bs);
		c->bs = nt;
		c->bcap = nc;
		c->held += nb;
	}
	i = mtn_mix(block, 0) & (c->bcap - 1u);
	while (c->bs[i].gen == c->gen) {
		if (c->bs[i].block == block)
			return &c->bs[i];
		i = (i + 1u) & (c->bcap - 1u);
	}
	e = &c->bs[i];
	memset(e, 0, sizeof *e);
	e->block = block;
	e->gen = c->gen;
	c->bn++;
	return e;
}

static struct mtn_ent *tm_find(const struct kof_mutation_ctx *c, uint32_t key, uint32_t cls)
{
	uint32_t i;

	if (!c->tcap)
		return NULL;
	i = mtn_mix(key, cls * 0x2545F491u) & (c->tcap - 1u);
	for (;;) {
		struct mtn_ent *e = &c->tmap[i];

		if (e->gen != c->gen)
			return NULL;
		if (e->key == key && (e->meta & MTN_M_CLS) == cls)
			return e;
		i = (i + 1u) & (c->tcap - 1u);
	}
}

static struct mtn_ent *tm_insert(struct kof_mutation_ctx *c, uint32_t key, uint32_t cls)
{
	uint32_t i;
	struct mtn_ent *e;

	if ((uint64_t)(c->tn + 1u) * 4u > (uint64_t)c->tcap * 3u) {
		uint32_t nc = c->tcap ? c->tcap * 2u : 256u, x;
		uint64_t nb = (uint64_t)nc * sizeof *c->tmap;
		struct mtn_ent *nt;

		if (nc < c->tcap || !mtn_room(c, nb))
			return NULL;
		nt = calloc(nc, sizeof *nt);
		if (!nt)
			return NULL;
		for (x = 0; x < c->tcap; x++) {
			const struct mtn_ent *o = &c->tmap[x];

			if (o->gen != c->gen)
				continue;
			i = mtn_mix(o->key, (o->meta & MTN_M_CLS) * 0x2545F491u) & (nc - 1u);
			while (nt[i].gen)
				i = (i + 1u) & (nc - 1u);
			nt[i] = *o;
		}
		c->held -= (uint64_t)c->tcap * sizeof *c->tmap;
		free(c->tmap);
		c->tmap = nt;
		c->tcap = nc;
		c->held += nb;
	}
	i = mtn_mix(key, cls * 0x2545F491u) & (c->tcap - 1u);
	while (c->tmap[i].gen == c->gen)
		i = (i + 1u) & (c->tcap - 1u);
	e = &c->tmap[i];
	e->key = key; e->mask = 0; e->meta = cls; e->gen = c->gen;
	c->tn++;
	return e;
}

/* Survivors a batch may hold: the constant, or what a test lowered it to. */
static uint32_t chunk_limit(const struct kof_mutation_ctx *c)
{
	return c->chunk_max && c->chunk_max < KOF_MUTATION_CHUNK ? c->chunk_max : KOF_MUTATION_CHUNK;
}

/* The survivors' buffers: `sv` to collect in, `sv2` to sort into, grown together. */
static int sv_grow(struct kof_mutation_ctx *c, uint32_t want)
{
	uint32_t lim = chunk_limit(c);
	uint32_t nc = c->scap ? c->scap : (MTN_SV_MIN < lim ? MTN_SV_MIN : lim);
	uint64_t add;
	uint32_t *a, *b;

	while (nc < want && nc < lim)
		nc *= 2u;
	if (nc > lim)
		nc = lim;
	if (nc <= c->scap)
		return c->scap >= want;
	add = (uint64_t)(nc - c->scap) * 2u * sizeof *a;
	if (!mtn_room(c, add))
		return 0;
	a = realloc(c->sv, (size_t)nc * sizeof *a);
	if (!a)
		return 0;
	c->sv = a;
	b = realloc(c->sv2, (size_t)nc * sizeof *b);
	if (!b)
		return 0;
	c->sv2 = b;
	c->held += add;
	c->scap = nc;
	return 1;
}

static int span_ensure(struct kof_mutation_ctx *c)
{
	if (c->span)
		return 1;
	if (!mtn_room(c, MTN_WIN))
		return 0;
	c->span = malloc(MTN_WIN);
	if (!c->span)
		return 0;
	c->span_cap = MTN_WIN;
	c->held += MTN_WIN;
	return 1;
}

/* ---- crediting ---------------------------------------------------------------- */

/* What one kof_mutation_unit call asks, fixed for all its windows. */
struct mtn_call {
	uint32_t norm, side, mask, cls;
	int any;
};

static void mtn_credit_bit(struct kof_mutation_ctx *c, uint32_t block, uint32_t slot)
{
	struct mtn_blk *e = bs_get(c, block);
	uint32_t bit = 1u << (slot & 31u);

	if (!e) {
		c->status |= KOF_MTN_S_STATE_NOMEM | KOF_MTN_S_WALK_TRUNCATED;
		c->trunc_pairs++;
		return;
	}
	if (!(e->w[slot >> 5] & bit)) {
		e->w[slot >> 5] |= bit;
		e->cnt++;
	}
}

/* Credit the entries of one run. `refs` and `cl` are the run's two columns, `n` entries. */
static void mtn_credit_run(struct kof_mutation_ctx *c, const struct mtn_call *k,
			   const struct mtn_part *p, const uint8_t *refs, const uint8_t *cl,
			   uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint32_t ref = ld32(refs + 4ull * i), ci = cl[i];
		uint32_t blk = ref >> 8, slot = ref & 0xffu;
		const struct kof_kix_class *q;

		/* A reference the directory of this pack cannot have made: reported. */
		if (ci >= p->n_class || blk >= p->n_block || slot >= KOF_MUTATION_MAX_HASH) {
			c->status |= KOF_MTN_S_IO_ERROR;
			continue;
		}
		q = &p->cls[ci];
		/*
		 * THE REGION, THE NORMALIZER AND THE SIDE ARE PART OF THE MATCH, not a filter
		 * applied afterwards. The same bytes in another region, hashed another way, or on
		 * the other side of the static library are a different fact - see enum
		 * kgenome_mutation_side.
		 */
		if (q->norm != k->norm || q->side != k->side ||
		    (!k->any && !(q->mask & k->mask)))
			continue;
		mtn_credit_bit(c, p->base + blk, slot);
	}
}

/*
 * The decision before a run is walked: 0 to skip it. A value in more blocks than MTN_HOT is
 * remembered per object (struct mtn_ent) so that meeting it again in the same context walks
 * nothing; any value spends the visit budget, and a walk that would pass it is refused
 * whole, flagged, and counted - it can only LOWER a count.
 */
static int walk_begin(struct kof_mutation_ctx *c, const struct mtn_call *k, uint32_t vp,
		      uint32_t run, struct mtn_ent **eo)
{
	const struct kof_mutation_set *s = c->set;
	struct mtn_ent *e = NULL;

	*eo = NULL;
	if (run > MTN_HOT) {
		e = tm_find(c, vp, k->cls);
		if (e && ((e->meta & (MTN_M_REFUSED | MTN_M_ANY)) ||
			  (!k->any && !(k->mask & ~e->mask))))
			return 0;
	}
	if (run > s->max_visit - (c->visits < s->max_visit ? c->visits : s->max_visit)) {
		if (run > MTN_HOT) {
			if (!e)
				e = tm_insert(c, vp, k->cls);
			if (e)
				e->meta |= MTN_M_REFUSED;
		}
		c->status |= KOF_MTN_S_WALK_TRUNCATED;
		c->trunc_walks++;
		c->trunc_pairs += run;
		return 0;
	}
	if (run > MTN_HOT && !e) {
		e = tm_insert(c, vp, k->cls);
		if (!e)
			c->status |= KOF_MTN_S_STATE_NOMEM;   /* walked anyway; the budget bounds it */
	}
	c->visits += run;
	c->walks++;
	*eo = e;
	return 1;
}

static void walk_end(const struct mtn_call *k, struct mtn_ent *e)
{
	if (!e)
		return;
	if (k->any)
		e->meta |= MTN_M_ANY;
	else
		e->mask |= k->mask;
}

/* The bucket's three columns in a buffer holding the whole bucket. */
static void mtn_find_in(struct kof_mutation_ctx *c, const struct mtn_call *k,
			const struct mtn_part *p, uint32_t vp, const uint8_t *col, uint32_t n)
{
	uint32_t x = vp & 0xffffu, lo = 0, hi = n, r0, r1;
	struct mtn_ent *e;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (ld16(col + 2ull * mid) < x)
			lo = mid + 1u;
		else
			hi = mid;
	}
	r0 = lo;
	if (r0 == n || ld16(col + 2ull * r0) != x)
		return;
	hi = n;
	lo = r0 + 1u;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (ld16(col + 2ull * mid) <= x)
			lo = mid + 1u;
		else
			hi = mid;
	}
	r1 = lo;
	if (!walk_begin(c, k, vp, r1 - r0, &e))
		return;
	mtn_credit_run(c, k, p, col + 2ull * n + 4ull * r0, col + 6ull * n + r0, r1 - r0);
	walk_end(k, e);
}

/* A bucket too big for the read buffer, searched by reads of MTN_BIG_STEP entries. Only a
 * pack made to skew has one (the key is multiplied); the cost is bounded by the object's
 * read allowance. Returns the first entry whose lo16 is >= x, or n when there is none;
 * *ok is 0 when a read failed. */
static uint32_t big_lower(struct kof_mutation_ctx *c, const struct mtn_part *p, uint64_t base,
			  uint32_t n, uint32_t x, int *ok)
{
	uint32_t lo = 0, hi = n, i;
	uint8_t buf[2u * MTN_BIG_STEP];

	*ok = 1;
	if (x > 0xffffu)
		return n;
	while (hi - lo > MTN_BIG_STEP) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (!kof_kix_body(p->kix, base + 2ull * mid, buf, 2u, &c->io)) {
			*ok = 0;
			return n;
		}
		if (ld16(buf) < x)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (hi > lo && !kof_kix_body(p->kix, base + 2ull * lo, buf, 2ull * (hi - lo), &c->io)) {
		*ok = 0;
		return n;
	}
	for (i = lo; i < hi; i++)
		if (ld16(buf + 2ull * (i - lo)) >= x)
			return i;
	return hi;
}

static void mtn_find_big(struct kof_mutation_ctx *c, const struct mtn_call *k,
			 const struct mtn_part *p, uint32_t vp, uint64_t base, uint32_t n)
{
	uint32_t x = vp & 0xffffu, r0, r1, at;
	int ok;
	uint8_t chk[2];
	struct mtn_ent *e;

	r0 = big_lower(c, p, base, n, x, &ok);
	if (!ok || r0 >= n)
		return;
	if (!kof_kix_body(p->kix, base + 2ull * r0, chk, 2u, &c->io) || ld16(chk) != x)
		return;
	r1 = big_lower(c, p, base, n, x + 1u, &ok);
	if (!ok)
		return;
	if (!walk_begin(c, k, vp, r1 - r0, &e))
		return;
	for (at = r0; at < r1; at += MTN_PIECE) {
		uint32_t m = r1 - at < MTN_PIECE ? r1 - at : MTN_PIECE;
		uint8_t refs[4u * MTN_PIECE], cl[MTN_PIECE];

		if (!kof_kix_body(p->kix, base + 2ull * n + 4ull * at, refs, 4ull * m, &c->io) ||
		    !kof_kix_body(p->kix, base + 6ull * n + at, cl, m, &c->io))
			return;
		mtn_credit_run(c, k, p, refs, cl, m);
	}
	walk_end(k, e);
}

/* ---- the batch ---------------------------------------------------------------- */

/* Sort `a` (n values) with `t` as scratch; the result is in the returned array. Three passes of
 * 11, 11 and 10 bits, which is what a 32-bit key needs, and an insertion sort when it is short. */
static uint32_t *mtn_sort(uint32_t *a, uint32_t *t, uint32_t n)
{
	uint32_t cnt[3][2048], i, pass;
	uint32_t *src = a, *dst = t;

	if (n < 64u) {
		for (i = 1; i < n; i++) {
			uint32_t x = a[i], j = i;

			while (j && a[j - 1u] > x) {
				a[j] = a[j - 1u];
				j--;
			}
			a[j] = x;
		}
		return a;
	}
	memset(cnt, 0, sizeof cnt);
	for (i = 0; i < n; i++) {
		cnt[0][a[i] & 2047u]++;
		cnt[1][(a[i] >> 11) & 2047u]++;
		cnt[2][a[i] >> 22]++;
	}
	for (pass = 0; pass < 3; pass++) {
		uint32_t sum = 0, sh = pass * 11u, b;

		for (b = 0; b < 2048u; b++) {
			uint32_t x = cnt[pass][b];

			cnt[pass][b] = sum;
			sum += x;
		}
		for (i = 0; i < n; i++)
			dst[cnt[pass][(src[i] >> sh) & 2047u]++] = src[i];
		{
			uint32_t *sw = src;

			src = dst;
			dst = sw;
		}
	}
	return src;
}

/* The first survivor at or after `i` that is in another bucket than `b`. */
static uint32_t skip_bucket(const uint32_t *v, uint32_t i, uint32_t m, uint32_t b)
{
	while (i < m && (v[i] >> (32u - KOF_KIX_DIR_BITS)) == b)
		i++;
	return i;
}

/* One part against the sorted, distinct survivors. */
static void mtn_part_run(struct kof_mutation_ctx *c, const struct mtn_call *k,
			 const struct mtn_part *p, const uint32_t *v, uint32_t m)
{
	const uint32_t *dir = p->dir;
	uint32_t i = 0;

	while (i < m) {
		uint32_t b = v[i] >> (32u - KOF_KIX_DIR_BITS), j, n = dir[b + 1u] - dir[b];
		uint64_t a = (uint64_t)KOF_KIX_ENTRY * dir[b], e = (uint64_t)KOF_KIX_ENTRY * dir[b + 1u];
		uint64_t sa, se;

		if (c->io.err & KOF_KIX_E_BUDGET)
			return;                        /* the object's reads are spent: reported, and counts only fall */
		if (!n) {
			i = skip_bucket(v, i, m, b);
			continue;
		}
		if (e - a > MTN_WIN) {
			for (j = i; j < m && (v[j] >> (32u - KOF_KIX_DIR_BITS)) == b; j++)
				mtn_find_big(c, k, p, v[j], a, n);
			i = j;
			continue;
		}
		/* A span: this bucket and the next ones that are near enough to read together. */
		j = skip_bucket(v, i, m, b);
		sa = a;
		se = e;
		while (j < m) {
			uint32_t b2 = v[j] >> (32u - KOF_KIX_DIR_BITS);
			uint64_t a2 = (uint64_t)KOF_KIX_ENTRY * dir[b2], e2 = (uint64_t)KOF_KIX_ENTRY * dir[b2 + 1u];

			if (a2 == e2) {
				j = skip_bucket(v, j, m, b2);
				continue;
			}
			if (a2 - se > MTN_GAP || e2 - sa > MTN_WIN)
				break;
			se = e2;
			j = skip_bucket(v, j, m, b2);
		}
		if (!span_ensure(c)) {
			c->status |= KOF_MTN_S_STATE_NOMEM | KOF_MTN_S_WALK_TRUNCATED;
			c->trunc_pairs += j - i;
			return;
		}
		if (kof_kix_body(p->kix, sa, c->span, (size_t)(se - sa), &c->io)) {
			uint32_t q;

			for (q = i; q < j; q++) {
				uint32_t bq = v[q] >> (32u - KOF_KIX_DIR_BITS), nq = dir[bq + 1u] - dir[bq];

				if (nq)
					mtn_find_in(c, k, p, v[q],
						    c->span + ((uint64_t)KOF_KIX_ENTRY * dir[bq] - sa), nq);
			}
		}
		i = j;
	}
}

static void mtn_flush(struct kof_mutation_ctx *c, const struct mtn_call *k, uint32_t nb)
{
	const struct kof_mutation_set *s = c->set;
	uint32_t *v = mtn_sort(c->sv, c->sv2, nb), m = 0, i, pi;

	c->n_chunks++;
	/* Distinct values: the same window met twice in a batch is credited once, which is
	 * exact because credit is a set bit. */
	for (i = 0; i < nb; i++)
		if (!m || v[i] != v[m - 1u])
			v[m++] = v[i];
	c->io.budget = c->io_budget ? c->io_budget : KOF_MTN_IO_BASE + s->io_per_byte * c->fed;
	/* A probe is a distinct window that passed the filter, against one part of the index. */
	c->probes += (uint64_t)m * s->n_part;
	for (pi = 0; pi < s->n_part; pi++)
		mtn_part_run(c, k, &s->part[pi], v, m);
	c->status |= mtn_io_status(c->io.err);
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
 * THREE REJECTS BEFORE THE INDEX, all of them in memory: `top`, the largest hash of the
 * whole set (the blocks of an old rule are all small), the filter, and the flat test (a
 * window of one repeated byte is in no block). What passes is collected and probed as a batch.
 */
void kof_mutation_unit(struct kof_mutation_ctx *c, uint32_t scan_mask, uint32_t norm,
		     uint32_t side, const uint8_t *p, uint64_t n)
{
	const struct kof_mutation_set *s;
	struct kgenome_mtn_win w;
	struct mtn_call k;
	uint32_t top, lim, nb = 0;
	int more;

	if (!c || !c->set || !p || norm >= KGENOME_MUTATION_NORM_COUNT ||
	    !c->set->n_pair || !kgenome_mtn_win_begin(&w, p, n, norm))
		return;
	/* A block's side is a byte and its region a mask: no block matches
	 * anything else, so there is nothing to credit. */
	if (side > 255u || (!c->any_region && !scan_mask))
		return;
	s = c->set;
	c->fed += n;
	/* What waits was collected for one call; when this unit asks another, it is probed first. */
	if (c->nsv && (c->pk_norm != norm || c->pk_side != side || c->pk_mask != scan_mask ||
		       c->pk_any != c->any_region))
		mtn_settle(c);
	c->pk_norm = norm; c->pk_side = side; c->pk_mask = scan_mask; c->pk_any = c->any_region;
	k.norm = norm; k.side = side; k.mask = scan_mask; k.any = c->any_region;
	k.cls = norm | (side << 2);
	lim = chunk_limit(c);
	top = s->top;
	nb = c->nsv;
	if (!c->scap && !sv_grow(c, 1u)) {
		c->status |= KOF_MTN_S_STATE_NOMEM | KOF_MTN_S_WALK_TRUNCATED;
		return;
	}
	/* The windows are taken KOF_FBANK_BATCH at a time and asked of the filters together (kof_fbank_pass_n). */
	for (more = 1; more;) {
		uint32_t cand[KOF_FBANK_BATCH], keep[KOF_FBANK_BATCH], m = 0, j, np;
		uint8_t flat[KOF_FBANK_BATCH];

		do {
			uint32_t v = kgenome_mtn_win_value(&w);

			if (v <= top) {
				cand[m] = v * KOF_KIX_MULT;
				flat[m++] = (uint8_t)kgenome_mtn_win_flat(&w);
			}
			more = kgenome_mtn_win_next(&w);
		} while (more && m < KOF_FBANK_BATCH);
		np = kof_fbank_pass_n(s->fb, cand, flat, m, keep);
		for (j = 0; j < np; j++) {
			if (nb == c->scap || nb >= lim) {
				if (nb >= lim || !sv_grow(c, nb + 1u)) {
					/* A full batch is probed and the scan goes on; one the allowance will
					 * not let grow is probed early, which costs reads and says so. */
					if (nb < lim)
						c->status |= KOF_MTN_S_STATE_NOMEM;
					mtn_flush(c, &k, nb);
					nb = 0;
				}
			}
			c->sv[nb++] = keep[j];
		}
	}
	c->nsv = nb;
}

/*
 * Probe what waits. Called by anything that reads the state - a count, the stats, the held bytes, the
 * start of the next object - and by a call that changes. The context is the ctx's own, and the const on the
 * readers is a promise about what they return and not about when the work behind it was done, which is why
 * it is taken off here.
 */
static void mtn_settle(const struct kof_mutation_ctx *cc)
{
	struct kof_mutation_ctx *c = (struct kof_mutation_ctx *)(uintptr_t)cc;
	struct mtn_call k;
	uint32_t nb = c->nsv;

	if (!nb)
		return;
	k.norm = c->pk_norm; k.side = c->pk_side; k.mask = c->pk_mask; k.any = c->pk_any;
	k.cls = k.norm | (k.side << 2);
	c->nsv = 0;
	mtn_flush(c, &k, nb);
}

/* ---- scoring ------------------------------------------------------------------ */

static uint32_t mtn_count(const struct kof_mutation_ctx *c, uint32_t b)
{
	const struct mtn_blk *e = bs_find(c, b);

	return e ? e->cnt : 0u;
}

uint32_t kof_mutation_matched(const struct kof_mutation_ctx *c, uint32_t b)
{
	if (!c || !c->set || b >= c->n_block)
		return 0;
	mtn_settle(c);
	return mtn_count(c, b);
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
int kof_mutation_counts(const struct kof_mutation_ctx *c, uint32_t b,
		      uint32_t *seen, uint32_t *n_hash)
{
	struct kof_mutation_block blk;
	uint32_t local;
	const struct mtn_part *p;

	if (seen)
		*seen = 0;
	if (n_hash)
		*n_hash = 0;
	if (!c || !c->set || b >= c->n_block)
		return 0;
	mtn_settle(c);
	p = mtn_part_of(c->set, b, &local);
	if (!p || !kof_kix_block(p->kix, local, &blk, NULL) || !blk.n_hash)
		return 0;
	if (seen) {
		*seen = mtn_count(c, b);
		/* A block that names one hash twice must not read past a
		 * hundred per cent. */
		if (*seen > blk.n_hash)
			*seen = blk.n_hash;
	}
	if (n_hash)
		*n_hash = blk.n_hash;
	return 1;
}

uint32_t kof_mutation_pct(const struct kof_mutation_ctx *c, uint32_t b)
{
	uint32_t seen, n_hash;

	/* One division, defined once - see kof_mutation_counts. */
	if (!kof_mutation_counts(c, b, &seen, &n_hash) || !n_hash)
		return 0;
	return seen * 100u / n_hash;
}
