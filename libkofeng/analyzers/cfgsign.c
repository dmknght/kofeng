/*
 * cfgsign.c - kof_cfgsign_function. See cfgsign.h for what it decides.
 *
 * ORDER OF WORK: ONE decode of the function through kgenome_diag_code_run, the engine's reader, which for a little-endian object is
 * the explicit little-endian decode -> kgenome_cfg_build -> kgenome_cfg_sign -> the floor (kgenome_cfg_anchor). Nothing is decoded
 * twice and no block is found twice: the instruction array is what build and sign both read.
 */
#include <stdlib.h>
#include <string.h>

#include <genotype/image/image_addr.h>
#include <phenotype/diag_scan.h>

#include "cfgsign.h"
#include "genome_obj.h"

#define DEFAULT_MAX_BYTES (64ull << 20)

const char *kof_cfgsign_state_name(enum kof_cfgsign_state s)
{
	switch (s) {
	case KOF_CFGSIGN_SIGNED: return "signed";
	case KOF_CFGSIGN_BELOW_FLOOR: return "below the floor";
	case KOF_CFGSIGN_UNDECODABLE: return "no instruction decodes";
	case KOF_CFGSIGN_UNSUPPORTED: return "no control-flow rules for this architecture";
	case KOF_CFGSIGN_OVER_BUDGET: return "over the allowance of one call";
	case KOF_CFGSIGN_NOMEM: return "no memory";
	}
	return "?";
}

static void *m_alloc(const struct kgenome_cfg_mem *m, size_t n)
{
	return m && m->alloc ? m->alloc(m->user, n) : malloc(n);
}

static void m_release(const struct kgenome_cfg_mem *m, void *p, size_t n)
{
	if (!p)
		return;
	if (m && m->release)
		m->release(m->user, p, n);
	else
		free(p);
}

/* The decoded instructions, in an array that grows by doubling inside the call's allowance. */
struct col {
	struct kgenome_cell_insn *v;
	uint32_t n, cap;
	uint64_t max_bytes, skipped;
	const struct kgenome_cfg_mem *mem;
	int over, nomem;
};

static void collect(void *user, const struct kgenome_cell_insn *in)
{
	struct col *c = user;

	if (!in) {
		c->skipped++;
		return;
	}
	if (c->over || c->nomem)
		return;
	if (c->n == c->cap) {
		const uint32_t nc = c->cap ? c->cap * 2u : 256u;
		struct kgenome_cell_insn *nv;

		if (nc < c->cap || (uint64_t)nc * sizeof *nv > c->max_bytes) {
			c->over = 1;
			return;
		}
		nv = m_alloc(c->mem, (size_t)nc * sizeof *nv);
		if (!nv) {
			c->nomem = 1;
			return;
		}
		if (c->n)
			memcpy(nv, c->v, (size_t)c->n * sizeof *nv);
		m_release(c->mem, c->v, (size_t)c->cap * sizeof *nv);
		c->v = nv;
		c->cap = nc;
	}
	c->v[c->n++] = *in;
}

void kof_cfgsign_release(struct kof_cfgsign *r, const struct kgenome_cfg_mem *mem)
{
	if (!r)
		return;
	m_release(mem, r->in, r->in_bytes_);
	m_release(mem, r->label, r->label_bytes_);
	kgenome_cfg_free(&r->g, mem);
	r->in = NULL;
	r->label = NULL;
	r->in_bytes_ = r->label_bytes_ = 0;
	memset(&r->g, 0, sizeof r->g);
}

static enum kof_cfgsign_state finish(struct kof_cfgsign *out, enum kof_cfgsign_state s)
{
	out->state = s;
	return s;
}

enum kof_cfgsign_state kof_cfgsign_function(const struct kof_cfgsign_req *rq, struct kof_cfgsign *out)
{
	const struct kof_cfgsign_host *h = rq ? rq->host : NULL;
	const struct kgenome_cfg_mem *mem = h ? &h->mem : NULL;
	struct kgenome_obj gobj;
	struct col col;
	struct kgenome_cfg_req cq;
	struct kgenome_cfg g;
	struct kgenome_cfg_sign_req sq;
	struct kgenome_budget bud;
	struct kgenome_cfg_anchor_req aq;
	uint64_t *label = NULL, va;
	size_t label_bytes = 0;
	enum kgenome_status st;

	memset(out, 0, sizeof *out);
	memset(&g, 0, sizeof g);
	memset(&col, 0, sizeof col);
	if (!rq || !rq->ctx || !rq->data.p || !rq->len || rq->off >= rq->data.n || rq->len > rq->data.n - rq->off)
		return finish(out, KOF_CFGSIGN_UNDECODABLE);
	kof_genome_obj(rq->ctx, &gobj);
	out->be = kgenome_obj_big_endian(&gobj) && !kgenome_obj_code_little_endian(&gobj);
	va = kgenome_image_off_to_addr(&gobj, rq->off);
	out->mapped = va != KGENOME_BROKEN;
	out->func_va = out->mapped ? va : rq->off;
	memset(&bud, 0, sizeof bud);
	bud.max_bytes = h && h->max_bytes ? h->max_bytes : DEFAULT_MAX_BYTES;
	col.max_bytes = bud.max_bytes;
	col.mem = mem;
	/* THE ONE DECODE. */
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
		.obj = &gobj, .base = rq->data.p, .size = rq->data.n, .off = rq->off, .n = rq->len, .va = out->func_va,
		.fn = collect, .user = &col });
	out->n_insn = col.n;
	out->n_skip = col.skipped;
	if (col.nomem || col.over || !col.n) {
		enum kof_cfgsign_state s = col.nomem ? KOF_CFGSIGN_NOMEM : col.over ? KOF_CFGSIGN_OVER_BUDGET : KOF_CFGSIGN_UNDECODABLE;

		if (s == KOF_CFGSIGN_UNDECODABLE) {
			/* nothing decoded: either the architecture has no rules (the lib says so on an empty request) or the bytes are not code */
			struct kgenome_cfg_req probe;
			struct kgenome_cfg none;

			memset(&probe, 0, sizeof probe);
			memset(&none, 0, sizeof none);
			probe.arch = rq->ctx->arch;
			if (kgenome_cfg_build(&probe, &none) == KGENOME_UNSUPPORTED)
				s = KOF_CFGSIGN_UNSUPPORTED;
			kgenome_cfg_free(&none, NULL);
		}

		out->status = col.nomem ? KGENOME_NOMEM : col.over ? KGENOME_OVER_BUDGET : KGENOME_BAD_INPUT;
		m_release(mem, col.v, (size_t)col.cap * sizeof *col.v);
		return finish(out, s);
	}
	memset(&cq, 0, sizeof cq);
	cq.in = col.v;
	cq.n_in = col.n;
	cq.arch = rq->ctx->arch;
	cq.be = out->be;
	cq.va_lo = out->func_va;
	cq.va_hi = out->func_va + rq->len;
	cq.bytes = rq->data.p;
	cq.bytes_len = rq->data.n;
	cq.cut = col.skipped != 0;
	cq.budget = &bud;
	cq.mem = h ? h->mem : (struct kgenome_cfg_mem){0};
	st = kgenome_cfg_build(&cq, &g);
	if (!g.n_all) {
		out->status = st == KGENOME_OK ? KGENOME_BAD_INPUT : st;
		m_release(mem, col.v, (size_t)col.cap * sizeof *col.v);
		return finish(out, st == KGENOME_UNSUPPORTED ? KOF_CFGSIGN_UNSUPPORTED :
			      st == KGENOME_NOMEM ? KOF_CFGSIGN_NOMEM :
			      st == KGENOME_OVER_BUDGET ? KOF_CFGSIGN_OVER_BUDGET : KOF_CFGSIGN_UNDECODABLE);
	}
	if (rq->keep) {
		label_bytes = (size_t)g.n_all * sizeof *label;
		label = m_alloc(mem, label_bytes);
		if (!label) {
			kgenome_cfg_free(&g, mem);
			m_release(mem, col.v, (size_t)col.cap * sizeof *col.v);
			out->status = KGENOME_NOMEM;
			return finish(out, KOF_CFGSIGN_NOMEM);
		}
	}
	memset(&sq, 0, sizeof sq);
	sq.g = &g;
	sq.label = label;
	sq.budget = &bud;
	sq.mem = cq.mem;
	st = kgenome_cfg_sign(&sq, &out->sign);
	out->status = kgenome_status_merge(st, g.status);
	if (st == KGENOME_NOMEM || st == KGENOME_OVER_BUDGET) {
		const enum kof_cfgsign_state s = st == KGENOME_NOMEM ? KOF_CFGSIGN_NOMEM : KOF_CFGSIGN_OVER_BUDGET;

		m_release(mem, label, label_bytes);
		kgenome_cfg_free(&g, mem);
		m_release(mem, col.v, (size_t)col.cap * sizeof *col.v);
		memset(&out->sign, 0, sizeof out->sign);
		return finish(out, s);
	}
	memset(&aq, 0, sizeof aq);
	aq.min_blk = rq->floor ? rq->floor : KGENOME_CFG_ANCHOR_MIN;
	if (rq->keep) {
		out->in = col.v;
		out->in_bytes_ = (size_t)col.cap * sizeof *col.v;
		out->g = g;
		out->label = label;
		out->label_bytes_ = label_bytes;
	}
	{
		const int pass = kgenome_cfg_anchor(&g, &aq);

		if (!rq->keep) {
			kgenome_cfg_free(&g, mem);
			m_release(mem, col.v, (size_t)col.cap * sizeof *col.v);
		}
		return finish(out, pass ? KOF_CFGSIGN_SIGNED : KOF_CFGSIGN_BELOW_FLOOR);
	}
}
