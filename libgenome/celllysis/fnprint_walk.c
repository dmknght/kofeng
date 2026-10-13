/*
 * fnprint_walk.c - the single pass over an object's function set.
 *
 * ONE DECODE PER FUNCTION. What is kept between functions is the scalars of
 * struct kgenome_fnprint_state, the scratch of the function being read (padding
 * and branch targets: it grows with the largest function), and the REGION - the
 * records and edges of the stretch between the entry and the frontier, held until
 * the reachability decision (fnprint_reach.c) and bounded as it says. The entry
 * function is read once more beforehand (entry_probe) because what it hands to the
 * C runtime - `main` - and what it calls last are facts the rest of the walk needs
 * and the function that holds them is usually first in the file but not always. It
 * is one function, and its instructions are counted apart (stat.probe_insn is not in
 * n_insn).
 *
 * The relevance of each function is kgenome_fnprint_decide (fnprint_rel.c); the units the
 * credit reads are built here from the pieces the walk visits, a run at a time.
 */
#include "fnprint_private.h"

#include <stdlib.h>
#include <string.h>

/* Where the function sits in the address space: va = off + delta of its segment. */
static uint64_t va_of(const struct kgenome_fnprint_req *rq, uint64_t off)
{
	struct kgenome_image_seg g;

	if (rq->space && rq->space->seg_at && rq->space->seg_at(rq->space->priv, off, &g))
		return off + (uint64_t)g.delta;
	return off;
}

static uint64_t off_of(const struct kgenome_fnprint_req *rq, uint64_t va)
{
	if (rq->space && rq->space->off_of_va)
		return rq->space->off_of_va(rq->space->priv, va);
	return va;
}

static int is_x64(const struct kgenome_fnprint_req *rq)
{
	return rq->arch == KGENOME_ARCH_X86_64;
}

/* What the entry stub hands over: the last address-of-a-function it loads into
 * the first-argument register (x86-64) or pushes (x86) before its first call. */
struct entry_cand {
	uint64_t va;
	uint64_t call_va;       /* the direct call that ends the stub's set-up: the runtime's start */
	int      have, have_call, done;
};

static void entry_note(const struct kgenome_fnprint_req *rq, const struct kgenome_cell_insn *in,
		       struct entry_cand *c)
{
	if (c->done)
		return;
	if (in->op == KGENOME_CELL_CALL) {
		if (in->n_op >= 1 && in->o[0].kind == KGENOME_CELL_O_REL && in->target_va != KGENOME_BROKEN) {
			c->call_va = in->target_va;
			c->have_call = 1;
		}
		c->done = 1;
		return;
	}
	if (is_x64(rq) && (in->op == KGENOME_CELL_MOV || in->op == KGENOME_CELL_LEA) && in->n_op >= 2 &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == KGENOME_CELL_REG_DI) {
		if (in->o[1].kind == KGENOME_CELL_O_IMM) {
			c->va = in->o[1].imm; c->have = 1;
		} else if (in->op == KGENOME_CELL_LEA && in->o[1].kind == KGENOME_CELL_O_MEM &&
			   (in->o[1].flags & KGENOME_CELL_OF_RIPREL)) {
			c->va = in->at_va + in->len + (uint64_t)in->o[1].disp; c->have = 1;
		}
	} else if (rq->arch == KGENOME_ARCH_X86 && in->op == KGENOME_CELL_PUSH && in->n_op >= 1 &&
		   in->o[0].kind == KGENOME_CELL_O_IMM) {
		c->va = in->o[0].imm; c->have = 1;
	}
}

/* Decode a function once: fingerprint, counters, and (entry only) the main candidate. */
/*
 * WHERE THE BODY ENDS. The function set's extents are not equal across the ways
 * of producing it: a symbol's size is the function's own, an entry walk's extent
 * runs from one entry to the next and holds whatever lies between (measured: 14
 * of 471 extents of one object equal their symbol's). A fingerprint of the
 * extent would be a fingerprint of the discovery method. So the body is read to
 * the first TERMINAL instruction - a return, or a jump that does not go forward
 * inside the extent, an indirect jump included - that is past the furthest
 * forward branch target seen. What follows is the tail: reported, not hashed.
 */
struct body {
	uint64_t reach;
};

/* How a body ended: the kind matters to what may follow it (see split_after). */
enum { TERM_NONE = 0, TERM_RET, TERM_JMP, TERM_IND };

static int body_ends(const struct kgenome_cell_insn *in, uint64_t at, uint64_t flen, struct body *b)
{
	uint64_t after = at + in->len;
	int64_t rel = 0;
	int local = 0;

	if ((in->op == KGENOME_CELL_JCC || in->op == KGENOME_CELL_JMP || in->op == KGENOME_CELL_LOOP) &&
	    in->n_op >= 1 && in->o[0].kind == KGENOME_CELL_O_REL && in->target_va != KGENOME_BROKEN) {
		rel = (int64_t)at + (int64_t)(in->target_va - in->at_va);
		local = rel >= 0 && (uint64_t)rel < flen;
		if (local && (uint64_t)rel > b->reach)
			b->reach = (uint64_t)rel;
	}
	if (in->op == KGENOME_CELL_RET || in->op == KGENOME_CELL_IRET)
		return after > b->reach ? TERM_RET : TERM_NONE;
	if (in->op == KGENOME_CELL_JMP && !(local && (uint64_t)rel >= after) && after > b->reach)
		return (in->n_op >= 1 && in->o[0].kind == KGENOME_CELL_O_REL) ? TERM_JMP : TERM_IND;
	return TERM_NONE;
}

/* What a decode gives besides the function's own numbers. */
struct a_out {
	struct entry_cand *ec;      /* entry stub: main and the runtime's start (NULL: not the entry) */
	int term;                   /* how the body ended */
	struct kgenome_fnprint_reach *edges;   /* collect the edges here (NULL: none) */
	struct kgenome_ledger *led;
};

/* The edges of one instruction: where control or an address leaves for. */
static void note_edges(const struct kgenome_fnprint_req *rq, const struct kgenome_cell_insn *in,
		       uint64_t at, uint64_t flen, struct a_out *out)
{
	uint64_t va = KGENOME_BROKEN;

	if ((in->op == KGENOME_CELL_CALL || in->op == KGENOME_CELL_JMP || in->op == KGENOME_CELL_JCC) &&
	    in->n_op >= 1 && in->o[0].kind == KGENOME_CELL_O_REL && in->target_va != KGENOME_BROKEN) {
		int64_t rel = (int64_t)at + (int64_t)(in->target_va - in->at_va);

		if (rel < 0 || (uint64_t)rel >= flen)
			va = in->target_va;
	} else if (in->op == KGENOME_CELL_LEA && in->n_op >= 2 && in->o[1].kind == KGENOME_CELL_O_MEM &&
		   (in->o[1].flags & KGENOME_CELL_OF_RIPREL)) {
		va = in->at_va + in->len + (uint64_t)in->o[1].disp;
	} else {
		/* mov reg,imm / push imm: an absolute address (a non-PIE handler, a callback) */
		const struct kgenome_cell_operand *src = NULL;

		if (in->op == KGENOME_CELL_MOV && in->n_op >= 2)
			src = &in->o[1];
		else if (in->op == KGENOME_CELL_PUSH && in->n_op >= 1)
			src = &in->o[0];
		if (src && src->kind == KGENOME_CELL_O_IMM)
			va = src->imm;
	}
	if (va != KGENOME_BROKEN) {
		uint64_t to = off_of(rq, va);

		if (to != KGENOME_BROKEN && to < rq->n)
			kgenome_fnprint_reach_edge(out->edges, out->led, to);
	}
}

static int analyse(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_state *st,
		   struct kgenome_fnprint_fn *f, uint64_t max_steps, struct a_out *out)
{
	struct kgenome_fnprint_acc a;
	struct body bd = { 0 };
	int tm = TERM_NONE;
	uint64_t at = 0, va = va_of(rq, f->off);

	kgenome_fnprint_acc_init(&a);
	kgenome_fnprint_pos_reset(&st->pos);
	while (at < f->len) {
		struct kgenome_cell_insn in;
		struct kgenome_fnprint_tok t;
		uint64_t room = f->len - at;
		uint32_t n;
		uint64_t ext = 0;

		if (++st->steps > max_steps)
			return 0;
		n = kgenome_cell_decode(rq->arch, rq->be, rq->p + f->off + at,
					(uint32_t)(room > 16 ? 16 : room), va + at, &in);
		if (!n) {
			kgenome_fnprint_acc_bad(&a);
			at++;
			continue;
		}
		if (rq->hint.ext && in.n_op >= 1 && in.o[0].kind == KGENOME_CELL_O_REL &&
		    in.target_va != KGENOME_BROKEN) {
			int64_t rel = (int64_t)(at + (in.target_va - in.at_va));

			if (rel < 0 || (uint64_t)rel >= f->len) {
				uint64_t to = off_of(rq, in.target_va);

				if (to != KGENOME_BROKEN)
					ext = rq->hint.ext(rq->hint.ext_user, to);
			}
		}
		kgenome_fnprint_tokens(&in, at, f->len, ext, &t);
		if (n == 4 && kgenome_fnprint_is_landing_pad(rq->p + f->off + at, n)) {
			t.ns = 0;
			t.w = 0;
		}
		if (!t.ns) {
			kgenome_fnprint_pos_pad(&st->pos, rq->led, at, n);
		} else {
			uint64_t to;

			if (kgenome_fnprint_local_target(&in, at, f->len, &to))
				kgenome_fnprint_pos_target(&st->pos, rq->led, to);
		}
		kgenome_fnprint_acc_good(&a, &in, &t);
		if (n == 2 && rq->p[f->off + at] == 0 && rq->p[f->off + at + 1] == 0)
			a.n_zero++;
		if (out && out->ec)
			entry_note(rq, &in, out->ec);
		if (out && out->edges)
			note_edges(rq, &in, at, f->len, out);
		at += n;
		tm = body_ends(&in, at - n, f->len, &bd);
		if (tm)
			break;
	}
	if (out)
		out->term = tm;
	f->body_len = at;
	f->fp = kgenome_fnprint_pos_fold(&st->pos, a.fp); f->fw = a.fw;
	f->n_insn = a.n_insn; f->n_bad = a.n_bad; f->n_call = a.n_call;
	f->n_branch = a.n_branch; f->n_syscall = a.n_syscall; f->n_zero = a.n_zero; f->last_op = a.last_op;
	return 1;
}

static uint32_t entry_index(const struct kgenome_fnprint_req *rq)
{
	uint32_t i;

	if (rq->entry_off == KGENOME_BROKEN)
		return UINT32_MAX;
	for (i = 0; i < rq->funcs->n; i++) {
		const struct kgenome_func *g = &rq->funcs->v[i];

		if (g->len && rq->entry_off >= g->off && rq->entry_off - g->off < g->len &&
		    g->off < rq->n && g->len <= rq->n - g->off)
			return i;
	}
	return UINT32_MAX;
}

static void entry_probe(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_state *st,
			uint32_t e, uint64_t max_steps)
{
	struct kgenome_fnprint_fn f;
	struct entry_cand c = { 0, 0, 0, 0, 0 };
	struct a_out ao = { &c, 0, NULL, NULL };
	uint64_t keep = st->steps;
	uint32_t i;

	memset(&f, 0, sizeof f);
	f.off = rq->funcs->v[e].off;
	f.len = rq->funcs->v[e].len;
	if (!analyse(rq, st, &f, max_steps, &ao))
		return;
	st->steps = keep;           /* the probe is not the walk's budget: counted apart */
	if (c.have_call && !(rq->opt.off & KGENOME_FNP_OFF_ENTRY_ORDER)) {
		uint64_t to = off_of(rq, c.call_va);

		for (i = 0; to != KGENOME_BROKEN && i < rq->funcs->n; i++)
			if (to >= rq->funcs->v[i].off && to - rq->funcs->v[i].off < rq->funcs->v[i].len) {
				st->lib0 = rq->funcs->v[i].off;
				break;
			}
	}
	if (!c.have)
		return;
	{
		uint64_t to = off_of(rq, c.va);

		if (to == KGENOME_BROKEN)
			return;
		/* Inside a function of the set, not only AT the start of one: main is
		 * reached by address and never called, so an entry walk does not list it. */
		for (i = 0; i < rq->funcs->n; i++)
			if (i != e && to >= rq->funcs->v[i].off &&
			    to - rq->funcs->v[i].off < rq->funcs->v[i].len) {
				st->main_off = to;
				return;
			}
	}
}

/* ---- the unit being built ----------------------------------------------------- */

static void run_flush(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_state *st,
		      struct kgenome_fnprint_stat *sx)
{
	if (!st->run_open)
		return;
	st->run_open = 0;
	if (st->run_hi <= st->run_lo || !rq->units.fn)
		return;
	sx->n_units++;
	sx->unit_bytes += st->run_hi - st->run_lo;
	if (rq->units.fn(rq->units.user, st->run_lo, st->run_hi - st->run_lo, st->run_side, NULL))
		st->stop = 1;
}

static void run_piece(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_state *st,
		      struct kgenome_fnprint_stat *sx, uint64_t lo, uint64_t hi, uint32_t side)
{
	uint64_t gap = rq->units.gap ? rq->units.gap : 32u;

	if (hi <= lo)
		return;
	if (st->run_open && st->run_side == side && lo <= st->run_hi + gap && lo + gap >= st->run_lo) {
		if (lo < st->run_lo) st->run_lo = lo;
		if (hi > st->run_hi) st->run_hi = hi;
		return;
	}
	run_flush(rq, st, sx);
	st->run_open = 1;
	st->run_lo = lo; st->run_hi = hi; st->run_side = side;
}

static int picked(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_fn *f)
{
	uint32_t pk = rq->units.pick;

	if (f->reason & KGENOME_FNP_R_BAD)
		return 0;
	if (pk & KGENOME_FNP_PICK_SIDED)
		return 1;
	if (pk & KGENOME_FNP_PICK_DIAG)
		return (f->reason & KGENOME_FNP_R_DIAG) && f->cls != KGENOME_FNP_LIB;
	return (f->cls == KGENOME_FNP_AUTHOR && (pk & KGENOME_FNP_PICK_AUTHOR)) ||
	       (f->cls == KGENOME_FNP_UNKNOWN && (pk & KGENOME_FNP_PICK_UNKNOWN));
}

static void units_feed(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_state *st,
		       struct kgenome_fnprint_stat *sx, const struct kgenome_fnprint_fn *f)
{
	int sided = (rq->units.pick & KGENOME_FNP_PICK_SIDED) != 0;

	if (!rq->units.fn || !rq->units.pick)
		return;
	if (sided && !(f->reason & KGENOME_FNP_R_BAD) && f->off >= st->prev_end) {
		uint64_t from = st->have_prev ? st->prev_end : rq->units.lo;

		if (from < rq->units.lo)
			from = rq->units.lo;
		run_piece(rq, st, sx, from, f->off, KGENOME_MUTATION_SIDE_USER);
	}
	if (!picked(rq, f))
		return;
	sx->n_unit_funcs++;
	run_piece(rq, st, sx, f->off, f->off + f->len,
		  sided && f->cls == KGENOME_FNP_LIB ? KGENOME_MUTATION_SIDE_LIB
						     : KGENOME_MUTATION_SIDE_USER);
}

/* ---- the pass ---------------------------------------------------------------- */

static void count(struct kgenome_fnprint_stat *sx, const struct kgenome_fnprint_fn *f)
{
	if (f->reason & KGENOME_FNP_R_SPLIT)
		sx->n_split++;
	else
		sx->n_visited++;
	if (f->cls == KGENOME_FNP_AUTHOR) sx->n_author++;
	else if (f->cls == KGENOME_FNP_LIB) sx->n_lib++;
	else sx->n_unknown++;
	if (f->reason & KGENOME_FNP_R_BAD) sx->n_bad++;
	if (f->reason & KGENOME_FNP_R_OVERLAP) sx->n_overlap++;
	if (f->reason & KGENOME_FNP_R_HUGE) sx->n_huge++;
}

/* One decided piece counted, offered to the unit builder and the visitor. */
static void emit(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_state *st,
		 struct kgenome_fnprint_stat *sx, const struct kgenome_fnprint_fn *f)
{
	count(sx, f);
	units_feed(rq, st, sx, f);
	if (!(f->reason & KGENOME_FNP_R_BAD)) {
		st->prev_off = f->off;
		if (!st->have_prev || f->off + f->len > st->prev_end)
			st->prev_end = f->off + f->len;
		st->have_prev = 1;
	}
	if (rq->visit && rq->visit(rq->user, f))
		st->stop = 1;
}

/* The held region decided and emitted, in address order. */
static void flush_region(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_opts *o,
			 struct kgenome_fnprint_state *st, struct kgenome_fnprint_stat *sx)
{
	struct kgenome_fnprint_reach *r = &st->rc;
	uint32_t i;

	if (!r->n && !r->have_root)
		return;
	kgenome_fnprint_reach_resolve(r, rq, o, sx);
	for (i = 0; i < r->n && !st->stop; i++)
		emit(rq, st, sx, &r->v[i].f);
	kgenome_fnprint_reach_reset(r);
}

/*
 * CODE THE SET DID NOT ENTER. An extent runs from one entry to the next, so it
 * holds whatever lies between them: a function nothing calls directly (main, a
 * callback, a static function whose address is taken), a split-off cold part.
 * After a body's first terminal - a return or a direct jump past every forward
 * branch target - the bytes that follow are alignment padding and then, in code
 * a compiler wrote, the next function; the padding is skipped and the rest is a
 * piece of its own. The last extent of the set is cut at the end of the last code section
 * when the caller knows it (req.code_end); without that, nothing bounds it but the end of
 * the segment and what follows its first return may be data in the same segment
 * (relocation entries, tables): it is not read. NOT after an indirect jump: the blocks behind a switch's
 * `jmp *table(,%reg,8)` are entered through the table only, so they are the
 * same function, and cutting them out would invent functions. The other cut is
 * `main`, whose address the entry stub names: it is an entry whether or not any
 * call enters it.
 */
static uint64_t skip_pad(const struct kgenome_fnprint_req *rq, uint64_t lo, uint64_t hi)
{
	while (lo < hi) {
		struct kgenome_cell_insn in;
		uint64_t room = hi - lo;
		uint32_t n;

		if (rq->p[lo] == 0) {
			lo++;
			continue;
		}
		n = kgenome_cell_decode(rq->arch, rq->be, rq->p + lo, (uint32_t)(room > 16 ? 16 : room), lo, &in);
		if (!n || !(in.op == KGENOME_CELL_NOP ||
			    (in.op == KGENOME_CELL_INT && (in.n_op == 0 || (in.o[0].kind == KGENOME_CELL_O_IMM && in.o[0].imm == 3)))))
			break;
		lo += n;
	}
	return lo;
}

/* Where the next piece of an extent starts after a piece that was cut at `cut`: the code left after the body, else `cut`. */
static uint64_t next_piece(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_fn *f,
			   uint64_t cut, int term, int unbounded_tail)
{
	uint64_t p;

	if (!unbounded_tail && rq->extents == KGENOME_FNP_EXT_ENTRY_WALK && !(rq->opt.off & KGENOME_FNP_OFF_SPLIT_TAILS) &&
	    f->body_len < f->len && (term == TERM_RET || term == TERM_JMP)) {
		p = skip_pad(rq, f->off + f->body_len, cut);
		if (p < cut)
			return p;
	}
	return cut;
}

/* Does the region rule want this piece held (and its edges collected)? */
static int region_wants(const struct kgenome_fnprint_state *st, uint64_t lo)
{
	return st->region && !st->latched && !st->rc.failed && (lo >= st->entry_off || lo == st->main_off);
}

/* A piece decided: held for the region, or emitted now. */
static void settle(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_opts *o,
		   struct kgenome_fnprint_state *st, struct kgenome_fnprint_stat *sx,
		   struct kgenome_fnprint_fn *f, uint32_t e0, int collected)
{
	struct kgenome_fnprint_reach *r = &st->rc;
	uint32_t ne = r->ne - e0;
	int held = 0;

	if (collected && !st->latched && f->off >= st->entry_off && !(f->reason & KGENOME_FNP_R_BAD))
		held = kgenome_fnprint_reach_hold(r, rq->led, f, e0, ne);
	if (held) {
		sx->n_region++;
		if (r->n > sx->region_peak)
			sx->region_peak = r->n;
		return;
	}
	if (collected && r->failed) {
		flush_region(rq, o, st, sx);     /* what was held is decided by the layout alone */
		sx->n_region_over++;
		r->ne = 0;
	} else if (collected && f->off == st->main_off && f->off < st->entry_off) {
		r->have_root = 1;                /* main lies before the entry: its edges are the root's */
		r->root_e0 = e0;
		r->root_ne = ne;
	} else if (collected) {
		if (e0 < r->ne)
			r->ne = e0;              /* not held: its edges are of no use */
	}
	emit(rq, st, sx, f);
}

static void one(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_opts *o,
		struct kgenome_fnprint_state *st, struct kgenome_fnprint_stat *sx, uint32_t i,
		uint32_t entry, uint64_t max_steps)
{
	const struct kgenome_func *g = &rq->funcs->v[i];
	uint64_t lo = g->off, hi = g->off + g->len;
	int first = 1, last = i + 1 == rq->funcs->n, bounded = rq->code_end && rq->code_end != KGENOME_BROKEN;

	if (!g->len || g->off >= rq->n || g->len > rq->n - g->off) {
		struct kgenome_fnprint_fn f;

		memset(&f, 0, sizeof f);
		f.off = g->off; f.len = g->len; f.index = i;
		f.reason |= KGENOME_FNP_R_BAD;
		kgenome_fnprint_decide(rq, o, st, &f, rq->hint.name ? rq->hint.name(rq->hint.name_user, i) : 0, 0, 0);
		emit(rq, st, sx, &f);
		return;
	}
	if (last && bounded && rq->code_end > lo && rq->code_end < hi)
		hi = rq->code_end;               /* what the last extent holds behind the code is not code */
	while (lo < hi && !st->stop) {
		struct kgenome_fnprint_fn f;
		uint64_t cut = hi;
		struct a_out ao = { NULL, TERM_NONE, NULL, NULL };
		uint32_t e0 = st->rc.ne;
		int collected, was_latched = st->latched;
		uint64_t nlo;

		memset(&f, 0, sizeof f);
		f.off = lo; f.index = i;
		if (!(rq->opt.off & KGENOME_FNP_OFF_SPLIT_MAIN) && st->main_off != KGENOME_BROKEN &&
		    st->main_off > lo && st->main_off < hi)
			cut = st->main_off;
		f.len = cut - lo;
		if (!first)
			f.reason |= KGENOME_FNP_R_SPLIT;
		if (first && st->have_prev && g->off < st->prev_off)
			sx->n_unsorted++;
		if (first && i != entry && st->have_prev && g->off < st->prev_end)
			f.reason |= KGENOME_FNP_R_OVERLAP;
		if (g->len > o->huge_len)
			f.reason |= KGENOME_FNP_R_HUGE;
		collected = region_wants(st, lo);
		if (collected) {
			ao.edges = &st->rc;
			ao.led = rq->led;
		}
		if (!analyse(rq, st, &f, max_steps, &ao)) {
			sx->status = kgenome_status_merge(sx->status, KGENOME_OVER_BUDGET);
			st->stop = 1;
			return;
		}
		sx->n_insn += f.n_insn + f.n_bad;
		nlo = next_piece(rq, &f, cut, ao.term, last && !bounded);
		if (nlo < cut)
			f.len = nlo - lo;                /* the piece ends where the next one starts */
		kgenome_fnprint_decide(rq, o, st, &f, first && rq->hint.name ? rq->hint.name(rq->hint.name_user, i) : 0,
				       first && i == entry, kgenome_fnprint_has_node(&rq->hint, f.off, f.len));
		if (!was_latched && st->latched)
			flush_region(rq, o, st, sx);     /* the frontier is here: what lies before it is decided */
		settle(rq, o, st, sx, &f, e0, collected);
		first = 0;
		lo = nlo;
	}
}

void kgenome_fnprint_walk(const struct kgenome_fnprint_req *rq)
{
	struct kgenome_fnprint_stat *sx;
	struct kgenome_fnprint_state st;
	struct kgenome_fnprint_opts o;
	struct kgenome_budget bd;
	uint64_t scratch = sizeof st + sizeof(struct kgenome_fnprint_fn);
	uint32_t i, entry;

	if (!rq || !rq->stat)
		return;
	sx = rq->stat;
	memset(sx, 0, sizeof *sx);
	sx->main_off = sx->frontier_off = KGENOME_BROKEN;
	if (!rq->p || !rq->n || !rq->funcs || (rq->funcs->n && !rq->funcs->v)) {
		sx->status = KGENOME_BAD_INPUT;
		return;
	}
	sx->n_funcs = rq->funcs->n;
	if (rq->led && !kgenome_ledger_charge(rq->led, scratch)) {
		sx->status = KGENOME_OVER_BUDGET;
		sx->n_skipped = sx->n_funcs;
		return;
	}
	sx->scratch_bytes = rq->led ? scratch : 0;
	o = rq->opt;
	kgenome_fnprint_opts_resolve(&o);
	if (rq->budget)
		bd = *rq->budget;
	else
		kgenome_budget_default(&bd, rq->n, 0);
	if (!bd.max_steps)
		kgenome_budget_default(&bd, rq->n, bd.code_bytes);
	memset(&st, 0, sizeof st);
	st.main_off = st.frontier = st.entry_off = st.lib0 = KGENOME_BROKEN;
	st.rc.max = o.region_max;
	{
		struct kgenome_fnprint_req r2 = *rq;     /* the caller's, opts resolved */

		r2.opt = o;
		if (rq->hint.n_node) {
			uint32_t k;

			for (k = 1; k < rq->hint.n_node; k++)
				if (rq->hint.node_at[k] < rq->hint.node_at[k - 1]) {
					sx->status = kgenome_status_merge(sx->status, KGENOME_BAD_INPUT);
					r2.hint.n_node = 0;
					break;
				}
		}
		entry = entry_index(&r2);
		if (entry != UINT32_MAX && r2.link != KGENOME_FNP_LINK_UNKNOWN) {
			st.entry_off = r2.funcs->v[entry].off;
			entry_probe(&r2, &st, entry, bd.max_steps);
		}
		st.region = st.main_off != KGENOME_BROKEN && st.entry_off != KGENOME_BROKEN &&
			    !(o.off & (KGENOME_FNP_OFF_REACH | KGENOME_FNP_OFF_ENTRY_ORDER));
		st.steps = 0;
		for (i = 0; i < r2.funcs->n && !st.stop; i++)
			one(&r2, &o, &st, sx, i, entry, bd.max_steps);
		if (!st.stop)
			flush_region(&r2, &o, &st, sx);
		kgenome_fnprint_reach_free(&st.rc, rq->led);
		kgenome_fnprint_pos_free(&st.pos, rq->led);
		if (st.latched)
			sx->frontier_off = st.frontier;
		sx->main_off = st.main_off;
		if (rq->units.fn && rq->units.pick) {
			if ((rq->units.pick & KGENOME_FNP_PICK_SIDED) && !st.stop) {
				uint64_t from = st.have_prev ? st.prev_end : rq->units.lo;

				if (from < rq->units.lo)
					from = rq->units.lo;
				run_piece(&r2, &st, sx, from, rq->units.hi, KGENOME_MUTATION_SIDE_USER);
			}
			run_flush(&r2, &st, sx);
		}
	}
	sx->n_skipped = sx->n_funcs - sx->n_visited;
	if (sx->n_unsorted || sx->n_region_over)
		sx->status = kgenome_status_merge(sx->status, KGENOME_TRUNCATED);   /* reported, not silent */
	if (sx->n_skipped && sx->status == KGENOME_OK)
		sx->status = KGENOME_TRUNCATED;      /* the visitor or the unit sink stopped it */
	if (rq->led)
		kgenome_ledger_release(rq->led, scratch);
}

/* ---- the collect-everything variant ------------------------------------------ */

struct collect {
	struct kgenome_fnprint_set *s;
	struct kgenome_ledger *led;
	uint32_t cap;
};

static int collect_visit(void *user, const struct kgenome_fnprint_fn *f)
{
	struct collect *c = user;
	struct kgenome_fnprint_set *s = c->s;

	if (s->n == c->cap) {
		uint32_t ncap = c->cap ? c->cap * 2u : 256u;
		uint64_t add = (uint64_t)(ncap - c->cap) * sizeof *s->fn;
		struct kgenome_fnprint_fn *nv;

		if (c->led && !kgenome_ledger_charge(c->led, add)) {
			s->stat.status = kgenome_status_merge(s->stat.status, KGENOME_OVER_BUDGET);
			return 1;
		}
		nv = realloc(s->fn, (size_t)ncap * sizeof *s->fn);
		if (!nv) {
			if (c->led)
				kgenome_ledger_release(c->led, add);
			s->stat.status = kgenome_status_merge(s->stat.status, KGENOME_NOMEM);
			return 1;
		}
		s->fn = nv;
		c->cap = ncap;
		s->bytes += add;
	}
	s->fn[s->n++] = *f;
	return 0;
}

void kgenome_fnprint_collect(const struct kgenome_fnprint_req *rq, struct kgenome_fnprint_set *out)
{
	struct kgenome_fnprint_req r;
	struct collect c;

	memset(out, 0, sizeof *out);
	if (!rq)
		return;
	c.s = out; c.led = rq->led; c.cap = 0;
	r = *rq;
	r.visit = collect_visit;
	r.user = &c;
	r.units.fn = NULL;
	r.stat = &out->stat;
	kgenome_fnprint_walk(&r);
	if (rq->stat)
		*rq->stat = out->stat;
}

void kgenome_fnprint_set_free(struct kgenome_fnprint_set *s, struct kgenome_ledger *led)
{
	if (!s)
		return;
	if (led)
		kgenome_ledger_release(led, s->bytes);
	free(s->fn);
	s->fn = NULL;
	s->n = 0;
	s->bytes = 0;
}
