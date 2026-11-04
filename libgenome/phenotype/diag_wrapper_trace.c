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

/* The record at `r`, the whole instruction as the decoder returned it (every field but the padding is written; an absent operand arrives as the decoder leaves it). */
void kgenome_diag_wrapper_trace_get_cell(struct kgenome_diag_wrapper_reader *r, struct kgenome_cell_insn *ci)
{
	const uint8_t *p = r->p, *q = p + 7;
	const unsigned ctl = p[1], n = (ctl >> KGENOME_DIAG_WRAPPER_TRACE_NOP_SHIFT) & 3u;
	unsigned i;

	ci->op = p[2];
	ci->len = p[3];
	ci->flags = p[4] & 0x0fu;
	ci->cond = (uint8_t)(p[4] >> 4);
	ci->wmask = kof_ld_le16(p + 5);
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
	ci->at = r->at;
	ci->at_va = r->at + r->delta;
	ci->target = KGENOME_BROKEN;
	if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_TGT) {
		uint32_t t;

		memcpy(&t, q, 4);
		ci->target = t;
		q += 4;
	}
	if (ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_WHI)
		ci->wmask |= (uint64_t)get_vz(&q) << 16;
	ci->target_va = ctl & KGENOME_DIAG_WRAPPER_TRACE_HAS_TVA ? ci->at_va + (uint64_t)get_vz(&q) : KGENOME_BROKEN;
	ci->n_op = (uint8_t)n;
	ci->_pad[0] = ci->_pad[1] = ci->_pad[2] = 0;
	for (i = 0; i < n; i++) {
		struct kgenome_cell_operand *o = &ci->o[i];
		const unsigned both = q[0] & KGENOME_DIAG_WRAPPER_TRACE_OP_BOTH;

		o->kind = (uint8_t)(q[0] & ~KGENOME_DIAG_WRAPPER_TRACE_OP_BOTH);
		o->reg = q[1]; o->index = q[2]; o->scale = q[3];
		o->size = q[4]; o->flags = q[5]; o->seg = q[6];
		o->_pad = 0;
		q += 7;
		if (both) {
			o->disp = get_vz(&q);
			o->imm = (uint64_t)get_vz(&q);
		} else {
			const int64_t v = get_vz(&q);

			o->disp = o->kind == KGENOME_CELL_O_MEM ? v : 0;
			o->imm = o->kind == KGENOME_CELL_O_IMM || o->kind == KGENOME_CELL_O_REL ? (uint64_t)v : 0;
		}
	}
	for (; i < 3u; i++) {
		struct kgenome_cell_operand *o = &ci->o[i];

		o->kind = KGENOME_CELL_O_NONE;
		o->reg = o->index = o->seg = KGENOME_CELL_REG_NONE;
		o->scale = o->size = o->flags = 0;
		o->_pad = 0;
		o->disp = 0;
		o->imm = 0;
	}
	r->at += ci->len;
	r->p = p + p[0];
}

/* The same record in the narrower form the wrapper analysis reads (kgenome_diag_wrapper_winsn_of: a mask of sixteen registers, one value to an operand). */
void kgenome_diag_wrapper_trace_get(struct kgenome_diag_wrapper_reader *r, struct kgenome_diag_wrapper_insn *w)
{
	struct kgenome_cell_insn ci;

	kgenome_diag_wrapper_trace_get_cell(r, &ci);
	kgenome_diag_wrapper_winsn_of(w, &ci);
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
static int trace_find(const struct kgenome_diag_walk *wk, const struct kgenome_diag_wrapper_seg *g, uint64_t off,
		      struct kgenome_diag_wrapper_reader *r)
{
	struct kgenome_diag_wrapper_reader t;

	if (off < g->lo || off >= g->hi || !kgenome_diag_wrapper_trace_lower(wk, g, off, &t) ||
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
	for (i = 0; i < KGENOME_DIAG_WALK_SEGS; i++)
		if (trace_find(c->wk, &c->wk->tseg[i], off, &it->rd)) {
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

/*
 * ---- THE TRACE AS THE DECODE SOURCE OF A CURSOR -----------------------------------
 *
 * The sweep (diag_sweep.c) reads windows of code through a celllysis cursor and used to
 * decode every instruction of them, though the walk had decoded and kept the same offsets:
 * MEASURED over 254 static ELF, 3.85 M of the 5.08 M decodes the sweep made were offsets
 * the walk held. A cursor given this as its space's `held` answers from the record at the
 * offset it is asked for, and from the decoder when there is none - a window that starts
 * out of step with the walk's alignment, bytes that did not decode, a trace cut at its cap.
 * Nothing is read that decoding would not have returned: the record must be AT the offset, and
 * what is not in it (the address, the branch target computed from it) is made from the address
 * the cursor gives the offset, field for field as decode_x86.c makes it - the bytes are the
 * same under any load address, and the address is not part of what was decoded.
 * (tests/lib/genome/decode_held.c compares every offset of real code and of random bytes.)
 *
 * The cost of an answer is one record read (trace_get, ~125 Ir) and the fill (~140 Ir),
 * against ~420 Ir for the decode and its translation: MEASURED on a 5.9 MB static ELF, 225 k
 * sweep decodes, of which all but about a hundred were answered from the trace. `h_p` is the
 * record after the last answer, so reading on in order costs no search; any other offset is
 * found through the index. A sweep that runs BEFORE the walk exists (an object whose functions
 * came from its symbols, so nothing made the walk first) decodes, and the walk the wrapper
 * resolution makes after it decodes the same offsets once more: 1.22 M of the 55 M decodes of
 * 254 static ELF, left because the sweep cannot tell before it runs whether a wrapper
 * resolution will follow, and a walk made for nothing costs the whole text.
 */
static uint32_t walk_held(void *priv, uint64_t off, uint64_t va, uint32_t left, struct kgenome_cell_insn *out)
{
	struct kgenome_diag_walk *wk = priv;
	struct kgenome_diag_wrapper_reader t;
	unsigned i;

	wk->h_asked++;
	if (wk->h_p && wk->h_p < wk->h_end && wk->h_at == off) {
		t.p = wk->h_p;
		t.at = wk->h_at;
		t.delta = wk->h_delta;
	} else {
		for (i = 0; i < KGENOME_DIAG_WALK_SEGS; i++) {
			if (trace_find(wk, &wk->tseg[i], off, &t)) {
				wk->h_end = wk->tr + wk->tseg[i].end;
				break;
			}
		}
		if (i == KGENOME_DIAG_WALK_SEGS) {
			wk->h_p = NULL;
			return 0;
		}
	}
	kgenome_diag_wrapper_trace_get_cell(&t, out);
	if (out->at != off || out->len > left)
		return 0;
	wk->h_p = t.p;
	wk->h_at = t.at;
	wk->h_delta = t.delta;
	/* The address is the cursor's, not the record's: the bytes decode the same under any load address
	 * and what depends on it (the branch target) is made from the one the cursor gives. */
	if (out->at_va != va) {
		/* a branch's address is relative to the instruction only where the branch is (x86: rel8/rel32, and the same bytes anywhere); a MIPS `j` or a PowerPC `ba` names a
		 * place of the address space, so a record made for another address is not this instruction's */
		if (wk->arch != KGENOME_ARCH_X86 && wk->arch != KGENOME_ARCH_X86_64)
			return 0;
		if (out->target_va != KGENOME_BROKEN)
			out->target_va += va - out->at_va;
	}
	out->at_va = va;
	out->at = va;                   /* as the decoder leaves it; cell_fetch sets the offset */
	out->target = out->target_va;   /* likewise: an address until cell_fetch makes it an offset */
	wk->h_served++;
	return out->len;
}

int kgenome_diag_walk_hold(struct kgenome_cell_space *sp, struct kgenome_diag_walk *wk)
{
	if (!wk || !wk->built || !wk->has_trace || !wk->tr || wk->base != sp->base || wk->size != sp->size ||
	    wk->arch != sp->arch)
		return 0;
	sp->held = walk_held;
	sp->held_priv = wk;
	return 1;
}

uint64_t kgenome_diag_walk_held_count(const struct kgenome_diag_walk *wk, uint64_t *asked)
{
	if (asked)
		*asked = wk ? wk->h_asked : 0;
	return wk ? wk->h_served : 0;
}
