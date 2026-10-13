/*
 * diag_wrapper_trace.c - the decode trace, read side: the packed records that serve a later read of an offset, and the
 * one source of instructions over them.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"

static int64_t get_vz(const uint8_t **pp)
{
	const uint8_t *p = *pp;
	uint64_t z = 0;
	unsigned sh = 0;

	for (;;) {
		uint8_t b = *p++;

		z |= (uint64_t)(b & 0x7fu) << sh;
		if (!(b & 0x80u))
			break;
		sh += 7u;
	}
	*pp = p;
	return (int64_t)(z >> 1) ^ -(int64_t)(z & 1u);
}

void kgenome_diag_wrapper_trace_get(struct kgenome_diag_wrapper_reader *r, struct kgenome_diag_wrapper_insn *w)
{
	const uint8_t *p = r->p, *q = p + 7;
	unsigned ctl = p[1], n = (ctl >> KGENOME_DIAG_WRAPPER_TRACE_NOP_SHIFT) & 3u, i;

	w->op = p[2];
	w->len = p[3];
	w->flags = p[4];
	w->wmask = kof_ld_le16(p + 5);
	if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_AT) {
		uint32_t a;

		memcpy(&a, q, 4);
		r->at = a;
		q += 4;
	}
	if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_DELTA) {
		memcpy(&r->delta, q, 8);
		q += 8;
	}
	w->at = r->at;
	w->at_va = r->at + r->delta;
	if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_TGT) {
		uint32_t t;

		memcpy(&t, q, 4);
		w->target = t;
		q += 4;
	} else {
		w->target = KGENOME_BROKEN;
	}
	w->n_op = (uint8_t)n;
	for (i = 0; i < n; i++) {
		struct kgenome_diag_wrapper_op *o = &w->o[i];

		o->kind = q[0]; o->reg = q[1]; o->index = q[2]; o->scale = q[3];
		o->size = q[4]; o->flags = q[5]; o->seg = q[6];
		q += 7;
		o->v = get_vz(&q);
	}
	for (; i < 3u; i++) {
		struct kgenome_diag_wrapper_op *o = &w->o[i];

		o->kind = KGENOME_CELL_O_NONE;
		o->reg = o->index = o->seg = KGENOME_CELL_REG_NONE;
		o->scale = o->size = o->flags = 0;
		o->v = 0;
	}
	r->at += w->len;
	r->p = p + p[0];
}

/* The first record of the trace of segment `g` at or after `off`, if it holds one.
 * The index gets within W_TRACE_EVERY records of it and the rest is a walk over
 * record headers, which carry their own length. A `off` before the segment's
 * first record starts at that record. */
int kgenome_diag_wrapper_trace_lower(const struct kgenome_diag_walk *wk, const struct kgenome_diag_wrapper_seg *g,
		       uint64_t off, struct kgenome_diag_wrapper_reader *r)
{
	uint32_t lo = 0, hi = g->n_ix;
	const uint8_t *p, *pend = wk->tr + g->end;
	uint64_t at = 0, delta = 0;

	if (off >= g->hi || !g->n_ix)
		return 0;
	if (off >= g->lo) {
		while (lo < hi) {               /* the last entry at or before `off` */
			uint32_t mid = lo + (hi - lo) / 2u;

			if (wk->ix[g->ix + mid].at <= off)
				lo = mid + 1u;
			else
				hi = mid;
		}
	}
	p = wk->tr + (lo ? wk->ix[g->ix + lo - 1u].pos : g->pos);
	while (p < pend) {
		unsigned ctl = p[1];
		const uint8_t *q = p + 7;

		if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_AT) {
			uint32_t a;

			memcpy(&a, q, 4);
			at = a;
			q += 4;
		}
		if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_DELTA)
			memcpy(&delta, q, 8);
		if (at >= off) {
			r->p = p;
			r->at = at;
			r->delta = delta;
			return 1;
		}
		at += p[3];
		p += p[0];
	}
	return 0;
}

/* The record the trace of segment `g` holds AT `off`, if it holds one. */
static int trace_find(const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_diag_wrapper_seg *g, uint64_t off,
		      struct kgenome_diag_wrapper_reader *r)
{
	struct kgenome_diag_wrapper_reader t;

	if (off < g->lo || off >= g->hi || !kgenome_diag_wrapper_trace_lower(c->wk, g, off, &t) ||
	    t.at != off)
		return 0;
	*r = t;
	return 1;
}

void kgenome_diag_wrapper_isrc_scan(struct kgenome_diag_wrapper_isrc *it, struct kgenome_diag_wrapper_ctx *c, unsigned seg,
		      uint64_t off, uint64_t n)
{
	const struct kgenome_diag_wrapper_seg *g = &c->wk->tseg[seg];

	memset(it, 0, sizeof *it);
	it->c = c;
	it->at = off;
	it->end = off + n;
	it->scan = 1;
	if (g->n) {
		it->rd.p = c->wk->tr + g->pos;
		it->rend = c->wk->tr + g->end;
		it->whole = g->complete;
	}
}

void kgenome_diag_wrapper_isrc_seek(struct kgenome_diag_wrapper_isrc *it, uint64_t off)
{
	struct kgenome_diag_wrapper_ctx *c = it->c;
	unsigned i;

	it->at = off;
	it->kat = 0;
	it->rend = NULL;
	for (i = 0; i < KGENOME_ELF_MAX_SEGMENTS; i++)
		if (trace_find(c, &c->wk->tseg[i], off, &it->rd)) {
			it->rend = c->wk->tr + c->wk->tseg[i].end;
			return;
		}
}

void kgenome_diag_wrapper_isrc_walk(struct kgenome_diag_wrapper_isrc *it, struct kgenome_diag_wrapper_ctx *c, uint64_t off)
{
	memset(it, 0, sizeof *it);
	it->c = c;
	it->end = UINT64_MAX;
	kgenome_diag_wrapper_isrc_seek(it, off);
}

int kgenome_diag_wrapper_isrc_next(struct kgenome_diag_wrapper_isrc *it, struct kgenome_diag_wrapper_insn *w)
{
	if (it->rend) {
		if (it->rd.p < it->rend) {
			struct kgenome_diag_wrapper_reader t = it->rd;

			kgenome_diag_wrapper_trace_get(&t, w);
			/* A scan takes the next record wherever it is - the bytes
			 * before it did not decode. A walk takes it only where it
			 * is. */
			if (it->scan || w->at == it->at) {
				it->rd = t;
				it->at = w->at + w->len;
				return 1;
			}
		} else if (it->whole) {
			return 0;
		} else {
			it->at = it->rd.at;     /* where the prefix ends */
		}
		it->rend = NULL;
		it->kat = 0;
	}
	for (;;) {
		if (it->at >= it->end)
			return 0;
		if (!it->kat) {
			kgenome_cell_seek(&it->k, it->at, 0);
			it->kat = 1;
		}
		if (kgenome_diag_wrapper_decode(it->c, &it->k, w)) {
			it->at = it->k.at;
			return 1;
		}
		if (!it->scan)
			return 0;
		it->k.at++;                     /* data in the code: step over it */
		it->at = it->k.at;
	}
}
