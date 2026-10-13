/*
 * fnprint_db.h - a database of blocks built the way the generator builds them
 * (the smallest 32 window hashes of a unit, kgenome_mutation_minhash), loaded
 * into the real matcher (kof_mutation_build), and the units fed to it.
 */
#ifndef KOFENG_TESTS_FNPRINT_DB_H
#define KOFENG_TESTS_FNPRINT_DB_H

#include "../lib/genome/fnprint_kit.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"

#define FD_MAX 64

struct fd_db {
	struct kof_mutation_block blk[FD_MAX];
	uint32_t pool[FD_MAX * 32];
	uint32_t n_blk, n_pool;
	struct kof_mutation_set *set;
};

/* A block from bytes [off, off+len) of an object, on `side`. Returns its index, or -1. */
static int fd_block(struct fd_db *d, const uint8_t *p, uint64_t off, uint64_t len, uint32_t side) HK_UNUSED;
static int fd_block(struct fd_db *d, const uint8_t *p, uint64_t off, uint64_t len, uint32_t side)
{
	uint32_t n;

	if (d->n_blk >= FD_MAX)
		return -1;
	n = kgenome_mutation_minhash(p + off, len, KGENOME_MUTATION_RAW, d->pool + d->n_pool);
	if (n < 8)
		return -1;
	d->blk[d->n_blk].first_hash = d->n_pool;
	d->blk[d->n_blk].n_hash = n;
	d->blk[d->n_blk].scan_mask = 1u;
	d->blk[d->n_blk].norm = KGENOME_MUTATION_RAW;
	d->blk[d->n_blk].side = (uint8_t)side;
	d->n_pool += n;
	return (int)d->n_blk++;
}

static void fd_build(struct fd_db *d) HK_UNUSED;
static void fd_build(struct fd_db *d)
{
	d->set = kof_mutation_build(d->blk, d->n_blk, d->pool, d->n_pool);
}

static void fd_free(struct fd_db *d) HK_UNUSED;
static void fd_free(struct fd_db *d)
{
	kof_mutation_set_free(d->set);
	d->set = NULL;
}

/* The unit sink that credits at once: the streaming shape. */
struct fd_feed {
	struct kof_mutation_ctx *c;
	struct kof_mutation_ctx *c2;      /* when set, the unit is offered to it on BOTH sides: the credit without the side */
	const uint8_t *p;
	uint32_t n_units;
	uint64_t bytes;
};

static int fd_unit(void *user, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first) HK_UNUSED;
static int fd_unit(void *user, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct fd_feed *f = user;

	(void)first;
	kof_mutation_unit(f->c, 1u, KGENOME_MUTATION_RAW, side, f->p + off, len);
	if (f->c2) {
		kof_mutation_unit(f->c2, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_USER, f->p + off, len);
		kof_mutation_unit(f->c2, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_LIB, f->p + off, len);
	}
	f->n_units++;
	f->bytes += len;
	return 0;
}

/* Walk an object with the given pick and credit into ctx. */
static void fd_credit(const struct fk_obj *o, enum kgenome_fnprint_link link, uint64_t entry, uint32_t pick,
		      const uint64_t *nodes, uint32_t n_nodes, struct kof_mutation_ctx *c, struct kof_mutation_ctx *c2,
		      struct kgenome_fnprint_stat *st) HK_UNUSED;
static void fd_credit(const struct fk_obj *o, enum kgenome_fnprint_link link, uint64_t entry, uint32_t pick,
		      const uint64_t *nodes, uint32_t n_nodes, struct kof_mutation_ctx *c, struct kof_mutation_ctx *c2,
		      struct kgenome_fnprint_stat *st)
{
	struct kgenome_fnprint_req rq;
	struct kgenome_func_set fs;
	struct fd_feed f;

	fk_req(&rq, o, link, st, &fs);
	rq.entry_off = entry;
	rq.hint.node_at = nodes;
	rq.hint.n_node = n_nodes;
	f.c = c; f.c2 = c2; f.p = o->b; f.n_units = 0; f.bytes = 0;
	rq.units.fn = fd_unit;
	rq.units.user = &f;
	rq.units.pick = pick;
	rq.units.lo = 0;
	rq.units.hi = o->n;
	kgenome_fnprint_walk(&rq);
}

#endif
