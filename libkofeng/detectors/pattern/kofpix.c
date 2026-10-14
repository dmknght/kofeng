/*
 * kofpix.c - the pattern table that stays in the pack. See kofpix.h for what it is
 * for and what it promises; this file is the arithmetic.
 */
#define _GNU_SOURCE
#include "kofpix_private.h"
#include "../../databases/pack/hexprog.h"
#include "../../databases/pack/dbcore.h"
#include "../../kofcore/kofplatform.h"

#include <stdlib.h>
#include <string.h>

/* ---- reading -------------------------------------------------------------- */

struct kofpix_reg {
	uint32_t        bit, fold, n_ent, dbits, cbits;
	uint32_t       *dir;        /* (1 << dbits) + 1 */
	uint32_t       *kdir;       /* 65537: first key of each top-16-bit bucket */
	uint16_t       *klow;       /* the low sixteen bits of each distinct key, sorted within a bucket */
	uint32_t       *kfull;      /* a small table: the distinct hashes, sorted (then kdir and klow are NULL) */
	uint32_t        n_keys;
	int             own_keys;
	uint8_t        *filt;       /* 1 << cbits bits */
	uint64_t        rec_off;    /* section-relative */
	const uint8_t  *recs;       /* resident mode: the records in memory */
	int             own_dir, own_filt;
};

struct kofpix {
	struct kofpix_src src;
	struct kofpix_reg reg[KOFPIX_MAX_REG];
	uint32_t          n_reg, uid_base, max_run;
	uint64_t          n_ent;
	uint64_t          resident;
	uint8_t          *own_mem;     /* the table, when this handle owns it (built at load) */
};

/*
 * A read of the table. 1 = all of it. A short read is a truncated pack and a wrong byte is a
 * slice that fails its checksum: both are an error and say which (io->err), never a smaller
 * answer. From memory (a table built at load, a test) it is a copy.
 */
static int sec_rd(const struct kofpix *px, uint64_t off, void *buf, size_t n, struct kof_kix_io *io)
{
	const struct kofpix_src *s = &px->src;

	if (s->mem) {
		if (off > s->sec_len || n > s->sec_len - off) {
			if (io)
				io->err |= KOF_KIX_E_IO;
			return 0;
		}
		memcpy(buf, s->mem + off, n);
		return 1;
	}
	return kof_slices_read(s->sec, off, buf, n, io);
}

/* One cost unit's worth of the object's allowance: the same arithmetic as the sliced reader's
 * (a read costs its bytes or a page), so the pool reads and the record reads spend one budget. */
static int io_take(struct kof_kix_io *io, uint64_t n)
{
	uint64_t cost = n < KOFPIX_PAGE ? KOFPIX_PAGE : n;

	if (io->spent > io->budget || cost > io->budget - io->spent) {
		io->err |= KOF_KIX_E_BUDGET;
		return 0;
	}
	io->spent += cost;
	return 1;
}

/* The marker's bytes, from the pool of the pack the table belongs to. */
static int pool_rd(const struct kofpix *px, uint64_t off, void *buf, size_t n, struct kof_kix_io *io)
{
	const struct kofpix_src *s = &px->src;

	if (off > s->pool_len || n > s->pool_len - off) {
		io->err |= KOF_KIX_E_IO;
		return 0;
	}
	if (s->pool_mem) {
		memcpy(buf, s->pool_mem + off, n);
		return 1;
	}
	if (!io_take(io, n))
		return 0;
	io->reads++;
	io->bytes += n;
	if (kof_pread(s->fd, buf, n, s->pool_off + off) != n) {
		io->err |= KOF_KIX_E_IO;
		return 0;
	}
	return 1;
}

void kofpix_close(struct kofpix *px)
{
	uint32_t b;

	if (!px)
		return;
	for (b = 0; b < KOFPIX_MAX_REG; b++) {
		if (px->reg[b].own_dir) free(px->reg[b].dir);
		if (px->reg[b].own_filt) free(px->reg[b].filt);
		if (px->reg[b].own_keys) { free(px->reg[b].kdir); free(px->reg[b].klow); free(px->reg[b].kfull); }
	}
	free(px->own_mem);
	free(px);
}

static int reg_check(const struct kofpix_regtab *rt, const struct kofpix_hdr *h)
{
	uint64_t dir_bytes, lvl_bytes = 0, k;

	if (rt->dbits < 4u || rt->dbits > KOFPIX_DIR_BITS_MAX ||
	    rt->fb < KOFPIX_FILTER_MIN_BITS || rt->fb > 30u ||
	    rt->n_lvl != rt->fb - KOFPIX_FILTER_MIN_BITS + 1u)
		return 0;
	dir_bytes = (((uint64_t)1 << rt->dbits) + 1u) * 4u;
	for (k = 0; k < rt->n_lvl; k++)
		lvl_bytes += (uint64_t)1 << (rt->fb - (uint32_t)k - 3u);
	if (rt->n_keys > rt->n_ent || (rt->n_keys > KOFPIX_KEYS_SMALL) != (rt->kdir_off != 0))
		return 0;
	return (rt->kdir_off == 0 || (rt->kdir_off <= h->sec_len && ((uint64_t)65537u * 4u) <= h->sec_len - rt->kdir_off)) &&
	       rt->klow_off <= h->sec_len && (uint64_t)rt->n_keys * (rt->kdir_off ? 2u : 4u) <= h->sec_len - rt->klow_off &&
	       rt->dir_off <= h->sec_len && dir_bytes <= h->sec_len - rt->dir_off &&
	       rt->flt_off <= h->sec_len && lvl_bytes <= h->sec_len - rt->flt_off &&
	       rt->rec_off <= h->sec_len && (uint64_t)rt->n_ent * KOFPIX_REC_SIZE <= h->sec_len - rt->rec_off;
}

/* The filter level a share of the budget buys: the largest not above it, never below the smallest
 * stored. Level 0 is the stored size, `n_lvl - 1` the smallest. */
static uint32_t pick_level(const struct kofpix_regtab *rt, uint64_t share)
{
	uint64_t k;

	for (k = 0; k < rt->n_lvl; k++)
		if (((uint64_t)1 << (rt->fb - (uint32_t)k - 3u)) <= share)
			return (uint32_t)k;
	return rt->n_lvl - 1u;
}

static uint64_t region_share(uint64_t budget, uint32_t n_ent, uint64_t total)
{
	return total ? budget / 8u * n_ent / total * 8u : budget;
}

struct kofpix *kofpix_open(const struct kofpix_open_req *rq, struct kofpix_open_res *res)
{
	const struct kofpix_src *src = &rq->src;
	enum kofpix_status st = KOFPIX_E_FORMAT;
	struct kofpix_hdr *h = malloc(sizeof *h);
	struct kofpix *px = calloc(1, sizeof *px);
	struct kof_kix_io io;
	uint64_t total = 0;
	uint32_t b;

	memset(&io, 0, sizeof io);
	io.budget = ~(uint64_t)0 >> 1;           /* an open is not metered, only reported */
	if (res)
		memset(res, 0, sizeof *res);
	if (!h || !px || (!src->mem && !src->sec) || (src->mem && src->sec)) {
		st = (!h || !px) ? KOFPIX_E_NOMEM : KOFPIX_E_FORMAT;
		goto fail;
	}
	px->src = *src;
	px->uid_base = rq->uid_base;
	if (!sec_rd(px, 0, h, sizeof *h, &io)) {
		st = (io.err & KOF_KIX_E_CRC) ? KOFPIX_E_CRC : KOFPIX_E_IO;
		goto fail;
	}
	if (h->magic != KOFPIX_MAGIC || h->version != 1 || h->rec_size != KOFPIX_REC_SIZE ||
	    h->sec_len != src->sec_len || h->pool_len > src->pool_len)
		goto fail;
	for (b = 0; b < KOFPIX_MAX_REG; b++)
		if (h->reg[b].n_ent) {
			if (h->reg[b].bit != b || !reg_check(&h->reg[b], h))
				goto fail;
			total += h->reg[b].n_ent;
		}
	for (b = 0; b < KOFPIX_MAX_REG; b++) {
		const struct kofpix_regtab *rt = &h->reg[b];
		struct kofpix_reg *r = &px->reg[b];
		uint64_t dir_bytes, nb, off, k;
		uint32_t cb, j, lvl, lvl_default;

		if (!rt->n_ent)
			continue;
		r->bit = b; r->fold = rt->fold; r->n_ent = rt->n_ent; r->dbits = rt->dbits;
		r->rec_off = rt->rec_off;
		dir_bytes = (((uint64_t)1 << rt->dbits) + 1u) * 4u;
		if (src->mem) {
			r->dir = (uint32_t *)(uintptr_t)(src->mem + rt->dir_off);
			r->recs = src->mem + rt->rec_off;
		} else {
			r->dir = malloc((size_t)dir_bytes);
			r->own_dir = 1;
			if (!r->dir) { st = KOFPIX_E_NOMEM; goto fail; }
			if (!sec_rd(px, rt->dir_off, r->dir, (size_t)dir_bytes, &io)) { st = (io.err & KOF_KIX_E_CRC) ? KOFPIX_E_CRC : KOFPIX_E_IO; goto fail; }
			px->resident += dir_bytes;
		}
		r->n_keys = rt->n_keys;
		if (rt->kdir_off) {
			if (src->mem) {
				r->kdir = (uint32_t *)(uintptr_t)(src->mem + rt->kdir_off);
				r->klow = (uint16_t *)(uintptr_t)(src->mem + rt->klow_off);
			} else {
				r->kdir = malloc(65537u * 4u);
				r->klow = malloc((size_t)rt->n_keys * 2u + 2u);
				r->own_keys = 1;
				if (!r->kdir || !r->klow) { st = KOFPIX_E_NOMEM; goto fail; }
				if (!sec_rd(px, rt->kdir_off, r->kdir, 65537u * 4u, &io) ||
				    !sec_rd(px, rt->klow_off, r->klow, (size_t)rt->n_keys * 2u, &io)) { st = (io.err & KOF_KIX_E_CRC) ? KOFPIX_E_CRC : KOFPIX_E_IO; goto fail; }
				px->resident += 65537u * 4u + (uint64_t)rt->n_keys * 2u;
			}
			if (r->kdir[0] != 0 || r->kdir[65536] != rt->n_keys)
				goto fail;
			for (j = 0; j < 65536u; j++)
				if (r->kdir[j] > r->kdir[j + 1u])
					goto fail;
		} else {
			if (src->mem) {
				r->kfull = (uint32_t *)(uintptr_t)(src->mem + rt->klow_off);
			} else {
				r->kfull = malloc((size_t)rt->n_keys * 4u + 4u);
				r->own_keys = 1;
				if (!r->kfull) { st = KOFPIX_E_NOMEM; goto fail; }
				if (!sec_rd(px, rt->klow_off, r->kfull, (size_t)rt->n_keys * 4u, &io)) { st = (io.err & KOF_KIX_E_CRC) ? KOFPIX_E_CRC : KOFPIX_E_IO; goto fail; }
				px->resident += (uint64_t)rt->n_keys * 4u;
			}
			for (j = 1; j < rt->n_keys; j++)
				if (r->kfull[j - 1u] >= r->kfull[j])
					goto fail;
		}
		/* the directory is the one structure every lookup trusts: monotone and ending
		 * at n_ent, or the section is refused */
		if (r->dir[0] != 0 || r->dir[(size_t)1 << rt->dbits] != rt->n_ent)
			goto fail;
		for (j = 0; j < ((uint32_t)1 << rt->dbits); j++)
			if (r->dir[j] > r->dir[j + 1u])
				goto fail;
		/* The filter level that fits this region's share of what the ledger granted. A level
		 * coarser than the one the DEFAULT budget would have chosen is a degraded filter: slower
		 * (more positions reach the key set), never less exact - and said so. */
		lvl = pick_level(rt, region_share(rq->filter_budget, rt->n_ent, total));
		lvl_default = pick_level(rt, region_share(rq->filter_default, rt->n_ent, total));
		if (lvl < lvl_default)
			lvl = lvl_default;           /* a grant above the default buys nothing the packer meant */
		if (lvl > lvl_default && res)
			res->degraded++;
		cb = rt->fb - lvl;
		off = rt->flt_off;
		for (k = 0; k < lvl; k++)
			off += (uint64_t)1 << (rt->fb - (uint32_t)k - 3u);
		nb = (uint64_t)1 << (cb - 3u);
		r->cbits = cb;
		if (src->mem) {
			r->filt = (uint8_t *)(uintptr_t)(src->mem + off);
		} else {
			r->filt = malloc((size_t)nb);
			r->own_filt = 1;
			if (!r->filt) { st = KOFPIX_E_NOMEM; goto fail; }
			if (!sec_rd(px, off, r->filt, (size_t)nb, &io)) { st = (io.err & KOF_KIX_E_CRC) ? KOFPIX_E_CRC : KOFPIX_E_IO; goto fail; }
			px->resident += nb;
		}
		px->n_reg++;
		px->n_ent += rt->n_ent;
		if (rt->max_run > px->max_run)
			px->max_run = rt->max_run;
	}
	if (rq->own_mem) {
		px->own_mem = (uint8_t *)(uintptr_t)src->mem;      /* ownership passes on success only */
		px->resident += src->sec_len;                       /* and the table is what is resident */
	}
	free(h);
	if (res) {
		res->status = KOFPIX_OK;
		res->resident = px->resident + sizeof *px;
		res->n_ent = px->n_ent;
		res->max_run = px->max_run;
		res->n_reg = px->n_reg;
	}
	return px;
fail:
	free(h);
	kofpix_close(px);
	if (res)
		res->status = st;
	return NULL;
}

uint64_t kofpix_resident(const struct kofpix *px) { return px ? px->resident + sizeof *px : 0; }

uint32_t kofpix_region_n(const struct kofpix *px, uint32_t bit)
{
	return px && bit < KOFPIX_MAX_REG ? px->reg[bit].n_ent : 0;
}

/* ---- the set: every pack's table, swept together ---------------------------------- */

/*
 * The tables of one region that hash their four bytes the same way. A pack has a table of its own,
 * and a region is usually in several packs (the detector pack, the heuristic pack and the unpack
 * pack of one format): sweeping each separately reads every byte of the region once PER PACK, and
 * measured on the shipping base that was 1.7 times the bytes the one table of the old design read.
 * So a region is read once for all of them: one hash a position, one probe of a filter that is the
 * OR of every table's, and only a position that passes is asked of each table's exact key set.
 * The two ways to hash (folded for a region that has a case-insensitive marker, exact for the rest)
 * are two groups, so a region is read at most twice however many packs there are.
 */
struct kofpix_grp {
	uint32_t             bit, fold, cbits, n_tab;
	struct kofpix      **px;       /* the tables, each with a region `bit` */
	uint8_t             *filt;     /* a table's own filter (one table) or the OR of all of them */
	int                  own_filt;
};

struct kofpix_set {
	uint32_t           regions, n_grp;
	int                reads_file;  /* some table is read from a file: the scanner needs buffers for it */
	struct kofpix_grp *grp;
	uint64_t           resident;   /* what the merged filters hold; the tables' own are in them */
};

/* Set every bit of the filter `dst` (2^dbits bits) that `src` (2^sbits bits, sbits <= dbits) says
 * is set, widened: a bit of the coarser filter stands for 2^(dbits - sbits) of the finer one. */
static void filter_or_up(uint8_t *dst, uint32_t dbits, const uint8_t *src, uint32_t sbits)
{
	uint64_t q, n = (uint64_t)1 << sbits;
	uint32_t d = dbits - sbits;

	for (q = 0; q < n; q++) {
		uint64_t from, to, x;

		if (!((src[q >> 3] >> (q & 7u)) & 1u))
			continue;
		from = q << d;
		to = (q + 1u) << d;
		if (d >= 3u) {
			memset(dst + (from >> 3), 0xff, (size_t)((to - from) >> 3));
		} else {
			for (x = from; x < to; x++)
				dst[x >> 3] |= (uint8_t)(1u << (x & 7u));
		}
	}
}

void kofpix_set_free(struct kofpix_set *set)
{
	uint32_t i;

	if (!set)
		return;
	for (i = 0; i < set->n_grp; i++) {
		if (set->grp[i].own_filt)
			free(set->grp[i].filt);
		free(set->grp[i].px);
	}
	free(set->grp);
	free(set);
}

struct kofpix_set *kofpix_set_make(struct kofpix **px, uint32_t n)
{
	struct kofpix_set *set = calloc(1, sizeof *set);
	uint32_t bit, fold, t;

	if (!set)
		return NULL;
	for (t = 0; t < n; t++)
		if (px[t] && (!px[t]->src.mem || !px[t]->src.pool_mem))
			set->reads_file = 1;
	set->grp = calloc(2u * KOFPIX_MAX_REG, sizeof *set->grp);
	if (!set->grp)
		goto fail;
	for (bit = 0; bit < KOFPIX_MAX_REG; bit++)
		for (fold = 0; fold < 2u; fold++) {
			struct kofpix_grp *g = &set->grp[set->n_grp];
			uint32_t cnt = 0, cb = 0;

			for (t = 0; t < n; t++) {
				const struct kofpix_reg *r = px[t] ? &px[t]->reg[bit] : NULL;

				if (r && r->n_ent && r->fold == fold) {
					cnt++;
					if (r->cbits > cb)
						cb = r->cbits;
				}
			}
			if (!cnt)
				continue;
			g->px = calloc(cnt, sizeof *g->px);
			if (!g->px)
				goto fail;
			g->bit = bit; g->fold = fold; g->cbits = cb;
			set->n_grp++;
			for (t = 0; t < n; t++) {
				const struct kofpix_reg *r = px[t] ? &px[t]->reg[bit] : NULL;

				if (r && r->n_ent && r->fold == fold)
					g->px[g->n_tab++] = px[t];
			}
			set->regions |= 1u << bit;
			if (cnt == 1u) {
				g->filt = g->px[0]->reg[bit].filt;
			} else {
				uint64_t nb = (uint64_t)1 << (cb - 3u);

				g->filt = calloc(1, (size_t)nb);
				if (!g->filt)
					goto fail;
				g->own_filt = 1;
				set->resident += nb;
				for (t = 0; t < g->n_tab; t++) {
					struct kofpix *own = g->px[t];

					filter_or_up(g->filt, cb, own->reg[bit].filt, own->reg[bit].cbits);
					/* the merged filter has it now: the table's own is given back */
					if (own->reg[bit].own_filt) {
						free(own->reg[bit].filt);
						own->resident -= (uint64_t)1 << (own->reg[bit].cbits - 3u);
					}
					own->reg[bit].filt = g->filt;     /* a view, not owned */
					own->reg[bit].own_filt = 0;
					own->reg[bit].cbits = cb;
				}
			}
		}
	return set;
fail:
	kofpix_set_free(set);
	return NULL;
}

int kofpix_set_reads_file(const struct kofpix_set *set)
{
	return !set || set->reads_file;      /* no set: assume the worst, which is the full buffers */
}

uint32_t kofpix_set_regions(const struct kofpix_set *set)
{
	return set ? set->regions : 0;
}

uint64_t kofpix_set_resident(const struct kofpix_set *set)
{
	return set ? set->resident + sizeof *set + (uint64_t)2u * KOFPIX_MAX_REG * sizeof *set->grp : 0;
}

/* ---- one scanner's state --------------------------------------------------- */

#define SURV_CAP      (1u << 15)
#define SLICE_CAP     (1u << 20)
#define FOUND_START   1024u

/* A set that reads nothing from a file (every table in memory) needs no slice buffer and no marker
 * cache, and its survivors are resolved without a read, so a small buffer does: the scanner of a
 * small database holds a few hundred kilobytes, not three megabytes. */
#define SURV_CAP_MEM  (1u << 12)

int kofpix_ctx_init(struct kofpix_ctx *c, const struct kofpix_set *set, uint64_t found_max_bytes)
{
	uint64_t cap_max = found_max_bytes / 8u, cm = FOUND_START;
	const int file = kofpix_set_reads_file(set);
	const uint32_t sc = file ? SURV_CAP : SURV_CAP_MEM;

	memset(c, 0, sizeof *c);
	while (cm * 2u <= cap_max)
		cm *= 2u;
	c->io_floor = KOFPIX_IO_FLOOR;
	c->io_shift = KOFPIX_IO_SHIFT;
	c->surv_cap = sc;
	c->surv = malloc((size_t)sc * sizeof *c->surv);
	c->tmp = malloc((size_t)sc * sizeof *c->tmp);
	if (file) {
		c->slice_cap = SLICE_CAP;
		c->slice = malloc(SLICE_CAP);
		c->pool_buf = malloc((size_t)KOFPIX_POOL_SLOTS * KOFPIX_POOL_SLOT);
	}
	c->pool_key = calloc(KOFPIX_POOL_SLOTS, sizeof *c->pool_key);
	c->pool_own = calloc(KOFPIX_POOL_SLOTS, sizeof *c->pool_own);
	c->found.cap = FOUND_START;
	c->found.cap_max = (uint32_t)cm;
	c->found.key = calloc(FOUND_START, sizeof *c->found.key);
	c->found.bits = calloc(FOUND_START, sizeof *c->found.bits);
	if (!c->surv || !c->tmp || (file && (!c->slice || !c->pool_buf)) || !c->pool_key || !c->pool_own ||
	    !c->found.key || !c->found.bits) {
		kofpix_ctx_free(c);
		return 0;
	}
	return 1;
}

void kofpix_ctx_free(struct kofpix_ctx *c)
{
	free(c->surv); free(c->tmp); free(c->slice); free(c->pool_buf); free(c->pool_key); free(c->pool_own);
	free(c->found.key); free(c->found.bits); free(c->big); free(c->tab_cnt);
	memset(c, 0, sizeof *c);
}

/* What a context costs before it has held a single found marker: charged once, when the scanner
 * is made. The buffers are allocated whole but a page of them costs nothing until it is written,
 * so this is the ceiling the scanner reserves, not what an idle one holds. */
uint64_t kofpix_ctx_fixed(const struct kofpix_set *set)
{
	const int file = kofpix_set_reads_file(set);

	return (uint64_t)(file ? SURV_CAP : SURV_CAP_MEM) * sizeof(struct kofpix_surv) * 2u +
	       (file ? (uint64_t)SLICE_CAP + (uint64_t)KOFPIX_POOL_SLOTS * KOFPIX_POOL_SLOT : 0u) +
	       (uint64_t)KOFPIX_POOL_SLOTS * (sizeof(uint64_t) + sizeof(void *)) +
	       (uint64_t)FOUND_START * 8u + sizeof(struct kofpix_ctx);
}

/* What the table of what was found holds beyond its starting size: what an object that found a
 * great many has to be charged for, and gives back with the object. */
uint64_t kofpix_ctx_held(const struct kofpix_ctx *c)
{
	return c->found.cap > FOUND_START ? (uint64_t)(c->found.cap - FOUND_START) * 8u : 0u;
}

/* The most the table of what was found may hold beyond its starting size, from what the object's
 * ledger has left: it may take half, never less than it already has. A table that cannot grow past
 * this is full, and a full table is a region not swept (KOFPIX_S_FOUND): reported, answered one
 * marker at a time. */
void kofpix_ctx_limit(struct kofpix_ctx *c, uint64_t room)
{
	uint64_t cm = FOUND_START, want = kofpix_ctx_held(c) + room / 2u;

	while ((cm * 2u - FOUND_START) * 8u <= want && cm < ((uint64_t)1 << 30))
		cm *= 2u;
	if (cm < c->found.cap)
		cm = c->found.cap;
	c->found.cap_max = (uint32_t)cm;
}

void kofpix_ctx_begin(struct kofpix_ctx *c)
{
	/* an object that found a great many leaves a big table behind; clearing it for
	 * every small object after it would cost more than the objects */
	if (c->found.cap > FOUND_START * 64u && c->found.n < c->found.cap / 16u) {
		uint32_t *nk = calloc(FOUND_START, sizeof *nk), *nb = calloc(FOUND_START, sizeof *nb);

		if (nk && nb) {
			free(c->found.key); free(c->found.bits);
			c->found.key = nk; c->found.bits = nb; c->found.cap = FOUND_START;
		} else {
			free(nk); free(nb);
		}
	}
	memset(c->found.key, 0, (size_t)c->found.cap * sizeof *c->found.key);
	c->found.n = 0;
	c->found.full = 0;
	memset(&c->io, 0, sizeof c->io);
	c->work_left = 0;
	c->n_survivors = c->n_slice_reads = c->n_pool_reads = c->n_pool_hits = 0;
	c->n_cand = c->n_verify = c->n_flush = 0;
	c->status = 0;
	memset(c->pool_key, 0, KOFPIX_POOL_SLOTS * sizeof *c->pool_key);
	memset(c->pool_own, 0, KOFPIX_POOL_SLOTS * sizeof *c->pool_own);
}

static uint32_t found_slot(uint32_t cap, uint32_t uid)
{
	return (uid * 2654435761u) & (cap - 1u);
}

uint32_t kofpix_found_get(const struct kofpix_ctx *c, uint32_t uid)
{
	const struct kofpix_found *f = &c->found;
	uint32_t i = found_slot(f->cap, uid);

	while (f->key[i]) {
		if (f->key[i] == uid + 1u)
			return f->bits[i];
		i = (i + 1u) & (f->cap - 1u);
	}
	return 0;
}

static int found_or(struct kofpix_ctx *c, uint32_t uid, uint32_t bits)
{
	struct kofpix_found *f = &c->found;
	uint32_t i;

	if ((uint64_t)(f->n + 1u) * 2u > f->cap) {
		uint32_t nc = f->cap * 2u, j;
		uint32_t *nk, *nb;

		if (nc > f->cap_max || nc < f->cap) {
			f->full = 1;
			c->status |= KOFPIX_S_FOUND;
			return 0;
		}
		nk = calloc(nc, sizeof *nk);
		nb = calloc(nc, sizeof *nb);
		if (!nk || !nb) {
			free(nk); free(nb);
			f->full = 1;
			c->status |= KOFPIX_S_FOUND;
			return 0;
		}
		for (j = 0; j < f->cap; j++)
			if (f->key[j]) {
				uint32_t k = found_slot(nc, f->key[j] - 1u);

				while (nk[k])
					k = (k + 1u) & (nc - 1u);
				nk[k] = f->key[j]; nb[k] = f->bits[j];
			}
		free(f->key); free(f->bits);
		f->key = nk; f->bits = nb; f->cap = nc;
	}
	i = found_slot(f->cap, uid);
	while (f->key[i] && f->key[i] != uid + 1u)
		i = (i + 1u) & (f->cap - 1u);
	if (!f->key[i]) {
		/* assigned, not OR'd: begin clears the keys and not the words, and a
		 * stale word in a slot a new key takes would be read as found */
		f->key[i] = uid + 1u;
		f->bits[i] = bits;
		f->n++;
	} else {
		f->bits[i] |= bits;
	}
	return 1;
}

/* ---- resolving survivors --------------------------------------------------- */

struct fl {                      /* one flush */
	const struct kofpix *px;
	const struct kofpix_reg *r;
	struct kofpix_ctx *c;
	const struct kof_match_ctx *m;
	uint64_t base, span, end;
	uint32_t bitmask;
	int stop;
};

/* The marker's bytes, from the cache or the pool. NULL = could not (status set). */
static const uint8_t *marker_bytes(struct fl *f, uint32_t off, uint32_t len, int hex)
{
	struct kofpix_ctx *c = f->c;
	uint64_t key = ((uint64_t)off + 1u) << 20 | (len & 0xfffffu);
	uint32_t slot = (uint32_t)((off * 2654435761u) >> 24) & (KOFPIX_POOL_SLOTS - 1u);
	uint8_t *dst;

	/* A program is read as a struct: it has to be aligned and it has to be one. The packer
	 * and the loader's check guarantee both, and a table in memory may still have been
	 * handed a record they did not write. */
	if (hex && ((off % KOF_HEX_PROG_ALIGN) || len > KOF_HEX_MAX_PROG)) {
		c->status |= KOFPIX_S_FORMAT;
		return NULL;
	}
	if (f->px->src.pool_mem) {
		const uint8_t *p = f->px->src.pool_mem + off;

		if ((uint64_t)off + len > f->px->src.pool_len)
			return NULL;
		if (!hex)
			return p;
		/* validated once per program: the cache holds the offsets that passed */
		if (c->pool_key[slot] == key && c->pool_own[slot] == f->px)
			return p;
		if (!kof_hex_prog_valid(p, len)) {
			c->status |= KOFPIX_S_FORMAT;
			return NULL;
		}
		c->pool_key[slot] = key;
		c->pool_own[slot] = f->px;
		return p;
	}
	if (len > KOFPIX_POOL_SLOT) {
		/* too big for a slot (a long literal): read into the context's one spare
		 * buffer, which the next such marker replaces. The slice is live, so it
		 * cannot be borrowed. */
		if (len > c->big_cap) {
			uint8_t *nb = realloc(c->big, len);

			if (!nb) { c->status |= KOFPIX_S_NOMEM; return NULL; }
			c->big = nb; c->big_cap = len;
		}
		c->n_pool_reads++;
		if (!pool_rd(f->px, off, c->big, len, &c->io)) { f->stop = 1; return NULL; }
		if (hex && !kof_hex_prog_valid(c->big, len)) { c->status |= KOFPIX_S_FORMAT; return NULL; }
		return c->big;
	}
	dst = c->pool_buf + (size_t)slot * KOFPIX_POOL_SLOT;
	if (c->pool_key[slot] == key && c->pool_own[slot] == f->px) {
		c->n_pool_hits++;
		return dst;
	}
	c->n_pool_reads++;
	if (!pool_rd(f->px, off, dst, len, &c->io)) {
		f->stop = 1;
		return NULL;
	}
	/* A program is checked ONCE, on its way into the cache: the walk trusts it, and a
	 * file can change under an open descriptor. What is in the cache has passed. */
	if (hex && !kof_hex_prog_valid(dst, len)) {
		c->status |= KOFPIX_S_FORMAT;
		return NULL;
	}
	c->pool_key[slot] = key;
	c->pool_own[slot] = f->px;
	return dst;
}

static void candidate(struct fl *f, const struct kofpix_rec *r, uint64_t pos)
{
	struct kofpix_ctx *c = f->c;
	const struct kof_match_ctx *m = f->m;
	struct kof_multimatch_pat p;
	const uint8_t *bytes;
	uint32_t uid = f->px->uid_base + r->uid;

	if (r->koff > pos - f->base)
		return;
	/* the four bytes after the key, compared where the record sits */
	{
		uint32_t nv = r->nvh & 7u, w = 0, j;

		if (nv > 4u) {          /* a record the builder did not write */
			c->status |= KOFPIX_S_FORMAT;
			return;
		}
		if (nv) {
			uint32_t mask = nv == 4u ? 0xffffffffu : ((1u << (8u * nv)) - 1u);

			if (pos + 4u + nv > f->end)
				return;
			if (pos + 8u <= m->data.n)
				w = kof_ld_le32(m->data.p + pos + 4u);
			else
				for (j = 0; j < nv; j++)
					w |= (uint32_t)m->data.p[pos + 4u + j] << (8u * j);
			if (f->r->fold)
				w = kof_mm_swar_lower(w);
			if ((w ^ r->c) & mask)
				return;
		}
	}
	c->n_cand++;
	if (kofpix_found_get(c, uid) & f->bitmask)
		return;
	bytes = marker_bytes(f, r->off, r->len, (r->nvh & KOFPIX_HEX) != 0);
	if (!bytes)
		return;
	memset(&p, 0, sizeof p);
	p.flags = r->flags;
	p.uid = uid;
	if (r->nvh & KOFPIX_HEX) {
		const struct kof_hex_hdr *h = (const void *)bytes;
		uint32_t alen;

		p.b = kof_multimatch_hex_anchor(bytes, &alen);
		p.len = (uint16_t)alen;
		p.is_hex = 1;
		p.prog = bytes;
		p.before_min = h->anchor_before_min;
		p.before_max = h->anchor_before_max;
		p.min_span = h->min_span;
	} else {
		p.b = bytes;
		p.len = r->len;
	}
	c->n_verify++;
	if (kof_multimatch_pat_at(m, &p, pos - r->koff, f->base, f->span) &&
	    !found_or(c, uid, f->bitmask))
		f->stop = 1;            /* nowhere to record it: the region is not swept */
}

/*
 * THE BOUND ON WHAT A RUN OF EQUAL KEYS COSTS. The read bound counts reads of the pack; a bucket that is
 * already in memory is walked for every survivor that lands in it, and a base whose markers share their
 * rarest four bytes (a family of hex programs on one anchor) makes that walk as long as the run, for every
 * position of an object that is full of those bytes. That is CPU the read bound cannot see. So each record
 * visited spends one unit of an allowance of KOFPIX_WORK_FLOOR and KOFPIX_WORK_PER_BYTE a byte swept: a clean
 * object visits a handful, the bound is two orders of magnitude above that, and past it the sweep STOPS and
 * REPORTS KOFPIX_S_WORK like the read bound does - the region is not swept and its masks are answered by
 * the exact per-marker path.
 */
static inline int work_take(struct fl *f)
{
	if (f->c->work_left == 0) {
		f->c->status |= KOFPIX_S_WORK;
		f->stop = 1;
		return 0;
	}
	f->c->work_left--;
	return 1;
}

/* The records of g within [recs, recs + n): the first one and how many, by binary search. */
static uint32_t lower_bound(const struct kofpix_rec *recs, uint32_t n, uint32_t g)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (recs[mid].g < g) lo = mid + 1u; else hi = mid;
	}
	return lo;
}

static uint32_t bucket_of(const struct kofpix_reg *r, uint32_t g)
{
	return g >> (32u - r->dbits);
}

/* A bucket larger than the slice buffer (a run of equal hashes this long is a hostile
 * base, not a hostile object): find the run by probing single records and read it in
 * pieces. */
static void resolve_big(struct fl *f, const struct kofpix_surv *s, uint32_t lo, uint32_t hi)
{
	const struct kofpix_reg *r = f->r;
	struct kofpix_ctx *c = f->c;
	uint32_t a = lo, b = hi, first, pos;
	struct kofpix_rec one;
	uint32_t per = c->slice_cap / KOFPIX_REC_SIZE;

	while (a < b) {
		uint32_t mid = a + (b - a) / 2u;

		c->n_slice_reads++;
		if (!sec_rd(f->px, r->rec_off + (uint64_t)mid * KOFPIX_REC_SIZE, &one, sizeof one, &c->io)) {
			f->stop = 1; return;
		}
		if (one.g < s->g) a = mid + 1u; else b = mid;
	}
	first = a;
	for (pos = first; pos < hi && !f->stop; ) {
		uint32_t n = hi - pos, j;
		const struct kofpix_rec *recs;

		if (n > per)
			n = per;
		c->n_slice_reads++;
		if (!sec_rd(f->px, r->rec_off + (uint64_t)pos * KOFPIX_REC_SIZE, c->slice, (size_t)n * KOFPIX_REC_SIZE, &c->io)) {
			f->stop = 1; return;
		}
		recs = (const void *)c->slice;
		for (j = 0; j < n; j++) {
			if (recs[j].g != s->g)
				return;
			if (!work_take(f))
				return;
			candidate(f, &recs[j], s->pos);
			if (f->stop)
				return;
		}
		pos += n;
	}
}

/* Sort `n` survivors by directory bucket (LSD radix on the top `bits` bits of the hash), in `a`
 * with `b` as scratch; returns whichever of the two holds the result. */
static struct kofpix_surv *sort_surv(struct kofpix_surv *a, struct kofpix_surv *b, uint32_t n,
				     uint32_t bits)
{
	uint32_t pass, i;
	uint32_t cnt[256];

	for (pass = 0; pass * 8u < bits; pass++) {
		uint32_t sh = 32u - bits + pass * 8u, pos = 0;
		uint32_t w = bits - pass * 8u > 8u ? 8u : bits - pass * 8u, k = 1u << w;
		struct kofpix_surv *t;

		memset(cnt, 0, k * sizeof *cnt);
		for (i = 0; i < n; i++)
			cnt[(a[i].g >> sh) & (k - 1u)]++;
		for (i = 0; i < k; i++) { uint32_t q = cnt[i]; cnt[i] = pos; pos += q; }
		for (i = 0; i < n; i++)
			b[cnt[(a[i].g >> sh) & (k - 1u)]++] = a[i];
		t = a; a = b; b = t;
	}
	return a;
}

/* The survivors of ONE table, `sv[0..n)`: resolved bucket by bucket, one read of the records a
 * bucket has, binary search inside it. `scratch` is room for n entries to sort in. */
static void flush_table(struct fl *f, struct kofpix_surv *sv, struct kofpix_surv *scratch, uint32_t n)
{
	const struct kofpix_reg *r = f->r;
	struct kofpix_ctx *c = f->c;
	uint32_t i = 0;

	c->n_flush++;
	if (!r->recs && n > 1u)
		sv = sort_surv(sv, scratch, n, r->dbits);
	while (i < n && !f->stop) {
		uint32_t b = bucket_of(r, sv[i].g), lo = r->dir[b], hi = r->dir[b + 1u], j = i;
		const struct kofpix_rec *recs = NULL;

		while (j < n && bucket_of(r, sv[j].g) == b)
			j++;
		if (lo == hi) { i = j; continue; }        /* a filter false positive: no read */
		if (r->recs) {
			recs = (const void *)(r->recs + (uint64_t)lo * KOFPIX_REC_SIZE);
		} else if ((uint64_t)(hi - lo) * KOFPIX_REC_SIZE <= c->slice_cap) {
			c->n_slice_reads++;
			if (!sec_rd(f->px, r->rec_off + (uint64_t)lo * KOFPIX_REC_SIZE, c->slice,
				    (size_t)(hi - lo) * KOFPIX_REC_SIZE, &c->io)) {
				f->stop = 1; return;
			}
			recs = (const void *)c->slice;
		}
		for (; i < j && !f->stop; i++) {
			const struct kofpix_surv *s = &sv[i];

			if (!recs) {
				resolve_big(f, s, lo, hi);
				continue;
			} else {
				uint32_t q = lower_bound(recs, hi - lo, s->g);

				for (; q < hi - lo && recs[q].g == s->g; q++) {
					if (bucket_of(r, recs[q].g) != b) { c->status |= KOFPIX_S_FORMAT; break; }
					if (!work_take(f))
						break;
					candidate(f, &recs[q], s->pos);
					if (f->stop)
						break;
				}
			}
		}
	}
}

/* The buffer of survivors, resolved. With one table it is that table's; with several each survivor
 * carries the table that keyed it (`pad`), and the buffer is split by table first, stably, so each
 * table is resolved over its own positions in order. */
static void flush(struct fl *f, const struct kofpix_grp *g, uint32_t n)
{
	struct kofpix_ctx *c = f->c;
	uint32_t t, i, m = 0;
	uint32_t *cnt;

	if (g->n_tab == 1u) {
		f->px = g->px[0];
		f->r = &f->px->reg[g->bit];
		flush_table(f, c->surv, c->tmp, n);
		return;
	}
	if (c->tab_cap < 2u * g->n_tab) {
		uint32_t *nc = realloc(c->tab_cnt, (size_t)2u * g->n_tab * sizeof *nc);

		if (!nc) {
			c->status |= KOFPIX_S_NOMEM;
			f->stop = 1;
			return;
		}
		c->tab_cnt = nc;
		c->tab_cap = 2u * g->n_tab;
	}
	cnt = c->tab_cnt;                  /* counts, then where each table's survivors start */
	memset(cnt, 0, (size_t)g->n_tab * sizeof *cnt);
	for (i = 0; i < n; i++)
		cnt[c->surv[i].pad]++;
	for (t = 0; t < g->n_tab; t++) { cnt[g->n_tab + t] = m; m += cnt[t]; }
	for (i = 0; i < n; i++)
		c->tmp[cnt[g->n_tab + c->surv[i].pad]++] = c->surv[i];
	/* c->tmp[0..n) holds the survivors grouped by table, each group in position order; c->surv is
	 * free to sort in. cnt[g->n_tab + t] is now the END of group t. */
	for (t = 0, m = 0; t < g->n_tab && !f->stop; t++) {
		uint32_t cn = cnt[g->n_tab + t] - m;

		if (cn) {
			f->px = g->px[t];
			f->r = &f->px->reg[g->bit];
			flush_table(f, c->tmp + m, c->surv + m, cn);
		}
		m = cnt[g->n_tab + t];
	}
}

/* ---- the sweep ---------------------------------------------------------------- */

#define KOFPIX_SWEEP_BODY(HASH)                                                      \
	for (i = base; i < last; i++) {                                              \
		uint32_t h = HASH(dp + i);                                           \
		uint32_t k = h >> shift;                                             \
                                                                                     \
		if (!(((uint32_t)filt[k >> 3] >> (k & 7u)) & 1u))                    \
			continue;                                                    \
		for (t = 0; t < g->n_tab; t++) {                                     \
			if (!key_present(&g->px[t]->reg[g->bit], h))                 \
				continue;                                            \
			surv[ns].pos = i;                                            \
			surv[ns].g = h;                                              \
			surv[ns].pad = t;                                            \
			if (++ns == cap) {                                           \
				c->n_survivors += ns;                                \
				flush(&f, g, ns);                                    \
				ns = 0;                                              \
				if (f.stop)                                          \
					return;                                      \
			}                                                            \
		}                                                                    \
	}

/* Is this hash the key of some marker of the region. Exact. Runs only for a position the
 * filter let through, which is a few percent. */
static inline int key_present(const struct kofpix_reg *r, uint32_t h)
{
	if (r->kdir) {
		uint32_t lo = r->kdir[h >> 16], hi = r->kdir[(h >> 16) + 1u], end = hi;
		uint16_t v = (uint16_t)(h & 0xffffu);

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (r->klow[mid] < v) lo = mid + 1u; else hi = mid;
		}
		return lo < end && r->klow[lo] == v;
	} else {
		uint32_t lo = 0, hi = r->n_keys;

		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (r->kfull[mid] < h) lo = mid + 1u; else hi = mid;
		}
		return lo < r->n_keys && r->kfull[lo] == h;
	}
}

static inline uint32_t hash_exact(const uint8_t *p) { return kof_ld_le32(p) * KOF_MM_MUL; }
static inline uint32_t hash_fold(const uint8_t *p)  { return kof_mm_swar_lower(kof_ld_le32(p)) * KOF_MM_MUL; }

static void sweep_extent(const struct kofpix_grp *g, struct kofpix_ctx *c,
			 struct kof_match_ctx *m, uint64_t base, uint64_t span)
{
	struct fl f;
	const uint8_t *dp = m->data.p, *filt = g->filt;
	struct kofpix_surv *surv = c->surv;
	const uint32_t shift = 32u - g->cbits, cap = c->surv_cap;
	uint64_t i, end = base + span, last;
	uint32_t ns = 0, t;

	f.px = g->px[0]; f.r = &g->px[0]->reg[g->bit]; f.c = c; f.m = m;
	f.base = base; f.span = span; f.end = end;
	f.bitmask = 1u << g->bit; f.stop = 0;
	if (span < 4u)
		return;
	last = end - 3u;           /* positions with four bytes left: span >= 4, so no wrap */
	if (g->fold)
		KOFPIX_SWEEP_BODY(hash_fold)
	else
		KOFPIX_SWEEP_BODY(hash_exact)
	if (ns) {
		c->n_survivors += ns;
		flush(&f, g, ns);
	}
}

uint64_t kofpix_sweep(const struct kofpix_set *set, struct kofpix_ctx *c, uint32_t bit,
		      struct kof_match_ctx *m, const struct kof_range *ext, uint32_t n_ext)
{
	uint64_t walked = 0;
	uint32_t gi, i, before = c->status;

	c->last = 0;
	if (!set || bit >= KOFPIX_MAX_REG || !(set->regions & (1u << bit)))
		return 0;
	c->status = 0;
	c->io.err = 0;
	for (gi = 0; gi < set->n_grp && !c->status; gi++) {
		const struct kofpix_grp *g = &set->grp[gi];

		if (g->bit != bit)
			continue;
		for (i = 0; i < n_ext; i++) {
			uint64_t off = ext[i].off, len = kof_clip_len(m->data.n, off, ext[i].len);

			if (!len)
				continue;
			walked += len;
			/* the bound on what this object may make the pack read: a floor, and a share
			 * of the bytes swept. Past it the sweep stops and says so. */
			c->io.budget += ((uint64_t)c->io_floor + (len >> c->io_shift)) * KOFPIX_PAGE;
			c->work_left += KOFPIX_WORK_FLOOR + len * KOFPIX_WORK_PER_BYTE;
			sweep_extent(g, c, m, off, len);
			if (c->io.err & KOF_KIX_E_IO)
				c->status |= KOFPIX_S_IO;
			if (c->io.err & KOF_KIX_E_CRC)
				c->status |= KOFPIX_S_CRC;
			if (c->io.err & KOF_KIX_E_BUDGET)
				c->status |= KOFPIX_S_BUDGET;
			if (c->status)
				break;      /* any status means the region is not swept; the caller reads it */
		}
	}
	c->last = c->status;    /* this region's, apart from what earlier regions of the object said */
	c->status |= before;
	return walked;
}
