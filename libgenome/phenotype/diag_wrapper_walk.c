/*
 * diag_wrapper_walk.c - the object's walk (decoded once: call targets,
 * kernel entries), the write side of the decode trace, the walk's life, and the instructions of a run for an observer.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"

/* ---- pass A: call targets and syscall sites -------------------------------- */

int kgenome_diag_wrapper_push_u64(uint64_t **v, uint32_t *n, uint32_t *cap, uint64_t x)
{
	if (*n == *cap) {
		uint32_t nc = *cap ? *cap * 2u : 256u;
		uint64_t *nv = realloc(*v, (size_t)nc * sizeof **v);

		if (!nv)
			return 0;
		*v = nv;
		*cap = nc;
	}
	(*v)[(*n)++] = x;
	return 1;
}

/* The one kernel-entry test is kgenome_diag_kernel_entry (nodes.c). */
int kgenome_diag_wrapper_is_kernel_entry(const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_diag_wrapper_insn *in)
{
	return kgenome_diag_kernel_entry(c->obj, in->op,
				     in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM &&
				     in->o[0].v == 0x80, c->base + in->at);
}

/*
 * ---- THE DECODE, ONCE ------------------------------------------------------
 *
 * A decode is a pure function of the bytes at an offset: the same offset in the
 * same space gives the same instruction however it is reached. pass_a decodes
 * every instruction of every executable segment, kgenome_diag_wrapper_pass_b reads the same ones
 * again (twice, when a global is read before it is written) and `kgenome_diag_wrapper_summarise`
 * walks function bodies that pass_a has already decoded - MEASURED on a 7.2 MB
 * static x86 ELF, 3.25 M + 0.39 M decodes of a ~1.6 M instruction image, and a
 * decode is ~800 Ir against ~100 for reading one back. So the first decode is
 * kept and every later read of an offset the trace holds is served from it.
 *
 * THE TRACE IS A CACHE, NOT A SECOND WALK. Nothing is read from it that decoding
 * would not have returned: a record is a struct kgenome_diag_wrapper_insn - what this file reads of
 * an instruction, and the only form of one it sees - packed, and unpacking gives
 * back that struct field for field. Checked end to end: the node dump of 1119
 * files is byte for byte the one decoding every time, and so it is with the
 * stream cut to 4 KiB, 150 KiB, 2 MiB and 8 MiB, which makes the prefix, the
 * seek-into-the-middle and the decode-after-the-end paths carry most of it. An
 * offset the trace does not hold is decoded exactly as before. The code below has
 * ONE decoder entry, kgenome_diag_wrapper_decode(), for both.
 *
 * WHAT A winsn LEAVES OUT of struct kgenome_cell_insn: `cond` and `target_va`, which
 * nothing here reads, `wmask` above bit 15 (only the sixteen general registers
 * are tracked), and the displacement/immediate that the operand's kind makes
 * meaningless. Leaving them out is what lets it be packed; reading one would
 * not compile.
 *
 * THE BOUND IS ON MEMORY, NOT ON WHAT IS FOUND. The record stream is limited to
 * W_TRACE_BYTES and its index (one entry per W_TRACE_EVERY records, 8 bytes, at
 * most 1/14 of the stream) comes on top. MEASURED on a 7.2 MB static ELF, 1,025,877
 * instructions pack to 22,795,487 bytes - 22.2 each against the 120 of a
 * kgenome_cell_insn - so the same 32 MiB that held 262144 instructions as cell_insns
 * holds about 1.5 M.
 * Past it the stream stops growing and the rest of the image is decoded again:
 * a trace is a prefix of its segment's walk, and the walk continues from where
 * the prefix ends, so nothing is dropped from the analysis, only from the cache.
 * Rule 4.
 */
#define W_TRACE_BYTES  (32u << 20)
#define W_TRACE_EVERY  16u
#define W_REC_MAX      80u

static uint8_t *put_vz(uint8_t *p, int64_t v)
{
	uint64_t z = ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);

	while (z >= 0x80u) {
		*p++ = (uint8_t)(z | 0x80u);
		z >>= 7;
	}
	*p++ = (uint8_t)z;
	return p;
}

/* Charge the trace's growth to the scan's ledger when a scan holds the walk -
 * SOFT (kgenome_ledger_try): the trace is a cache, and a refusal only means the
 * code is decoded again, the answer unchanged. 0 = do not grow it. */
static int wtrace_charge(struct kgenome_diag_walk *wk, uint64_t n)
{
	if (!wk->lg)
		return 1;
	if (!kgenome_ledger_try(wk->lg, n))
		return 0;
	wk->lg_charged += n;
	return 1;
}

static void trace_give_up(struct kgenome_diag_wrapper_seg *g)
{
	g->complete = 0;
	g->given_up = 1;
}

/* Keep what pass_a saw. Once a segment has been given up it stays given up: a
 * trace is a prefix of the walk and never has a hole in it. */
static void trace_put(struct kgenome_diag_wrapper_ctx *c, unsigned seg, const struct kgenome_diag_wrapper_insn *w)
{
	struct kgenome_diag_wrapper_seg *g = &c->wk->tseg[seg];
	uint8_t rec[W_REC_MAX], *p = rec + 7;
	uint64_t delta = w->at_va - w->at;
	unsigned ctl = 0, i;
	int first;

	if (g->given_up)
		return;
	first = !(g->n % W_TRACE_EVERY);
	/* An offset or a target that does not fit 32 bits: the image is not one
	 * this record can hold (size is checked at open, a target is not). */
	if (w->at > 0xffffffffu ||
	    (w->target != KGENOME_BROKEN && w->target > 0xffffffffu)) {
		trace_give_up(g);
		return;
	}
	if (first || w->at != c->wk->pk_end) {
		ctl |= KGENOME_DIAG_WRAPPER_TRACE_HAS_AT;
		memcpy(p, &(uint32_t){ (uint32_t)w->at }, 4);
		p += 4;
	}
	if (first || delta != c->wk->pk_delta) {
		ctl |= KGENOME_DIAG_WRAPPER_TRACE_HAS_DELTA;
		memcpy(p, &delta, 8);
		p += 8;
	}
	if (w->target != KGENOME_BROKEN) {
		ctl |= KGENOME_DIAG_WRAPPER_TRACE_HAS_TGT;
		memcpy(p, &(uint32_t){ (uint32_t)w->target }, 4);
		p += 4;
	}
	ctl |= (unsigned)w->n_op << KGENOME_DIAG_WRAPPER_TRACE_NOP_SHIFT;
	for (i = 0; i < w->n_op; i++) {
		const struct kgenome_diag_wrapper_op *o = &w->o[i];

		p[0] = o->kind; p[1] = o->reg; p[2] = o->index; p[3] = o->scale;
		p[4] = o->size; p[5] = o->flags; p[6] = o->seg;
		p = put_vz(p + 7, o->v);
	}
	rec[0] = (uint8_t)(p - rec);
	rec[1] = (uint8_t)ctl;
	rec[2] = w->op;
	rec[3] = w->len;
	rec[4] = w->flags;
	rec[5] = (uint8_t)w->wmask;
	rec[6] = (uint8_t)(w->wmask >> 8);

	if (c->wk->n_tr + rec[0] > c->wk->cap_tr) {
		size_t nc = c->wk->cap_tr ? (size_t)c->wk->cap_tr * 2u : 1u << 16;
		uint8_t *nt;

		if (nc > W_TRACE_BYTES)
			nc = W_TRACE_BYTES;
		if (c->wk->n_tr + rec[0] > nc ||
		    !wtrace_charge(c->wk, nc - c->wk->cap_tr) ||
		    !(nt = realloc(c->wk->tr, nc))) {
			trace_give_up(g);
			return;
		}
		c->wk->tr = nt;
		c->wk->cap_tr = (uint32_t)nc;
	}
	if (first) {
		if (c->wk->n_ix == c->wk->cap_ix) {
			uint32_t nc = c->wk->cap_ix ? c->wk->cap_ix * 2u : 1024u;
			struct kgenome_diag_wrapper_index *nx;

			if (!wtrace_charge(c->wk, (uint64_t)(nc - c->wk->cap_ix) * sizeof *nx)) {
				trace_give_up(g);
				return;
			}
			nx = realloc(c->wk->ix, (size_t)nc * sizeof *nx);
			if (!nx) {
				trace_give_up(g);
				return;
			}
			c->wk->ix = nx;
			c->wk->cap_ix = nc;
		}
		c->wk->ix[c->wk->n_ix].at = (uint32_t)w->at;
		c->wk->ix[c->wk->n_ix].pos = c->wk->n_tr;
		c->wk->n_ix++;
		g->n_ix++;
	}
	memcpy(c->wk->tr + c->wk->n_tr, rec, rec[0]);
	c->wk->n_tr += rec[0];
	g->end = c->wk->n_tr;
	g->n++;
	c->wk->pk_end = w->at + w->len;
	c->wk->pk_delta = delta;
}

/*
 * ---- THE INSTRUCTIONS OF ONE RUN, FOR AN OBSERVER ----------------------------
 *
 * The xref sweep (libgenome/celllysis/xref.c) asks for the instructions of a
 * range of the file, cut the way ITS answers need (a section: where its register
 * map starts empty), and it used to decode them itself - a second decode of code
 * this walk decodes and keeps. This is the one reader of an object's
 * instructions that hands them over: from the trace where the trace holds the
 * very instruction the sweep would have decoded, from kgenome_cell_decode (the one
 * decoder) otherwise. The observer cannot tell which, and does not need to.
 *
 * WHAT "THE VERY INSTRUCTION" MEANS, because the answer must be identical to
 * decoding the run on its own and a linear sweep is alignment-sensitive. A run
 * starts at `off`, reads on a window that ends at `off + n`, and an instruction
 * that does not fit the window does not decode - so a trace record is taken
 * only when it starts exactly at the position the run has reached, ends inside
 * the window, and was decoded for the same address (at_va, which differs only
 * when a section header claims an address its segment does not give it). Any
 * other position is decoded afresh, one byte on after a failure, exactly as the
 * run alone would, and the next position that coincides with a record goes back
 * to the trace. A run that begins before the walk did (the headers; the bytes
 * before an entry the walk started at) is decoded up to the walk's first
 * record. The trace is a prefix when it was cut at W_TRACE_BYTES: past it every
 * position is decoded afresh. Rule 4: a bound on memory, never on what the
 * sweep sees.
 *
 * WHAT A TRACE RECORD LEAVES OUT of a kgenome_cell_insn is put back here: `cond` is not
 * read by the observer, `target_va` is the one decode_x86.c computes (the
 * relative operand added to the end of the instruction - the trace is x86's, and
 * only x86's), and operands beyond the three a kgenome_cell_insn holds do not exist.
 */
static void cinsn_of(struct kgenome_cell_insn *ci, const struct kgenome_diag_wrapper_insn *w)
{
	unsigned i;

	memset(ci, 0, sizeof *ci);
	ci->op = w->op;
	ci->len = w->len;
	ci->n_op = w->n_op;
	ci->flags = w->flags;
	ci->wmask = w->wmask;
	ci->at = w->at;
	ci->at_va = w->at_va;
	ci->target = w->target;
	ci->target_va = KGENOME_BROKEN;
	for (i = 0; i < w->n_op; i++) {
		const struct kgenome_diag_wrapper_op *o = &w->o[i];
		struct kgenome_cell_operand *d = &ci->o[i];

		d->kind = o->kind;
		d->reg = o->reg;
		d->index = o->index;
		d->scale = o->scale;
		d->size = o->size;
		d->flags = o->flags;
		d->seg = o->seg;
		if (o->kind == KGENOME_CELL_O_MEM)
			d->disp = o->v;
		else if (o->kind == KGENOME_CELL_O_IMM || o->kind == KGENOME_CELL_O_REL)
			d->imm = (uint64_t)o->v;
		if (o->kind == KGENOME_CELL_O_REL)
			ci->target_va = w->at_va + w->len +
					(uint64_t)(int64_t)(int32_t)d->imm;
	}
	for (; i < 3u; i++) {
		ci->o[i].kind = KGENOME_CELL_O_NONE;
		ci->o[i].reg = ci->o[i].index = ci->o[i].seg = KGENOME_CELL_REG_NONE;
	}
}

void kgenome_diag_code_run(const struct kgenome_diag_code_req *rq)
{
	struct kgenome_diag_walk *wk = rq->wk;
	const struct kgenome_obj *obj = rq->obj;
	const uint8_t *base = rq->base;
	const uint64_t size = rq->size, off = rq->off, n = rq->n, va = rq->va;
	const kgenome_cell_insn_fn fn = rq->fn;
	void *user = rq->user;
	struct kgenome_diag_code_run_stats *st = rq->st;
	struct kgenome_cell_insn ci;
	struct kgenome_diag_wrapper_insn pk;                /* the next record the trace holds */
	struct kgenome_diag_wrapper_reader nx;
	const uint8_t *rend = NULL;
	uint64_t at = off, end;
	unsigned i;
	int pk_ok = 0;
	int64_t delta;

	if (!obj || !base || !fn || off >= size)
		return;
	end = n > size - off ? size : off + n;
	delta = (int64_t)(va - off);
	if (wk && wk->built && wk->has_trace && wk->tr && wk->base == base &&
	    wk->size == size) {
		for (i = 0; i < KGENOME_ELF_MAX_SEGMENTS; i++) {
			const struct kgenome_diag_wrapper_seg *g = &wk->tseg[i];

			/* A run that begins before the walk did (the headers, the
			 * bytes before an entry) is decoded up to the first record
			 * and read from the trace from there. */
			if (g->end > g->pos && off < g->hi && end > g->lo &&
			    kgenome_diag_wrapper_trace_lower(wk, g, off, &nx)) {
				rend = wk->tr + g->end;
				kgenome_diag_wrapper_trace_get(&nx, &pk);
				pk_ok = 1;
				break;
			}
		}
	}
	while (at < end) {
		/* `nx` reads on from the record `pk` was taken from. */
		while (pk_ok && pk.at < at) {           /* catch up with the run */
			if (nx.p < rend)
				kgenome_diag_wrapper_trace_get(&nx, &pk);
			else
				pk_ok = 0;
		}
		if (pk_ok && pk.at == at && at + pk.len <= end &&
		    pk.at_va == at + (uint64_t)delta) {
			cinsn_of(&ci, &pk);
			fn(user, &ci);
			at += pk.len;
			if (st)
				st->from_trace++;
			continue;
		}
		/*
		 * THE ONE DECODER, directly: kgenome_cell_decode is what every cursor wraps,
		 * and this run is one segment of one address mapping, so what the
		 * cursor adds (the segment lookup, the target's file offset) is work
		 * the observer would throw away - MEASURED, through kgenome_cell_step it
		 * cost 17% more than the sweep it replaced, which read this window
		 * with kgenome_cell_decode itself. The window is what is left of the run.
		 */
		{
			uint64_t left = end - at;
			uint32_t len = kgenome_cell_decode(obj->arch, 0, base + at,
						   left > UINT32_MAX ? UINT32_MAX
								     : (uint32_t)left,
						   at + (uint64_t)delta, &ci);

			if (len) {
				ci.at = at;
				fn(user, &ci);
				at += len;
				if (st)
					st->decoded++;
			} else {
				fn(user, NULL); /* data in the code: one byte on */
				at++;
				if (st)
					st->skipped++;
			}
		}
	}
}

/*
 * WHY THE WHOLE IMAGE IS DECODED HERE, and not only the windows around syscall
 * sites and around the callers of a wrapper found by searching the bytes for
 * `e8 rel32` that lands on it. Tried, and measured against this pass:
 *
 *   - THE CALL TARGETS a byte search names are not the ones decoding finds. Over
 *     255 ELF files: 299,857 decoded, 304,425 by bytes, 20,166 of the decoded ones
 *     missing (the `jmp` thunks a function starts with, which need to know the
 *     instruction before them is a ret/jmp/nop, and calls behind a prefix) and
 *     24,734 invented (an `e8` inside an immediate or a displacement whose bytes
 *     happen to land in the image). Putting the byte-found set in place of this
 *     pass's changes the node dump of 79 of 1119 files (one lost 218 of 394
 *     nodes) with `e8` alone, and 248 with a heuristic for the `e9` thunks.
 *   - THE SYSCALL SITES a byte search names are a superset (18,915 decoded,
 *     20,649 by bytes, none missing) and the extra ones are harmless: a site only
 *     selects an entry, and kgenome_diag_wrapper_summarise decodes forward from that entry, so a site
 *     in the middle of an instruction is never reached. Replacing this pass's
 *     sites with the byte-found ones changes no file of the 1119.
 *
 * So the sites could come from bytes; the call targets cannot - an entry is a
 * fact about alignment and alignment is a decode. Hence one decode of the image,
 * kept (see THE DECODE, ONCE) and read from there.
 */
static int pass_a(struct kgenome_diag_wrapper_ctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	struct kgenome_cell_cur k;
	struct kgenome_diag_wrapper_insn in;
	struct kgenome_diag_wrapper_seg *g = &c->wk->tseg[seg];

	/* Whether the instruction before ended a function's straight line. */
	int boundary = 1;

	memset(&k, 0, sizeof k);
	g->lo = off;
	g->hi = off + n;
	g->pos = c->wk->n_tr;
	g->end = c->wk->n_tr;
	g->ix = c->wk->n_ix;
	g->complete = c->wk->tr_on != 0;
	g->given_up = !c->wk->tr_on;
	if (!kgenome_cell_seek(&k, off, 0))
		return 1;
	while (k.at < off + n) {
		if (!kgenome_diag_wrapper_decode(c, &k, &in)) {
			k.at++;                 /* data in the code: step over it */
			continue;
		}
		trace_put(c, seg, &in);
		if (in.op == KGENOME_CELL_CALL && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
		    in.target != KGENOME_BROKEN) {
			if (!kgenome_diag_wrapper_push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, in.target))
				return 0;
		} else if (in.op == KGENOME_CELL_JMP && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
			   in.target != KGENOME_BROKEN && boundary) {
			/*
			 * A THUNK: `jmp X` as the first instruction of a function
			 * makes X an entry, though nothing CALLS it. musl keeps its
			 * generic syscall(nr, a1..a6) at X and gives the cancellable
			 * wrappers a one-instruction stub that jumps to it - sendto
			 * and connect both enter there, and with X not an entry the
			 * syscall inside it was attributed to no function and every
			 * socket send of the program was lost. Found by reading the
			 * 79 x86-64 Bazaar files that had a raw socket and no send.
			 */
			if (!kgenome_diag_wrapper_push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, in.target))
				return 0;
		} else if (c->wk->sites && kgenome_diag_wrapper_is_kernel_entry(c, &in)) {
			if (!kgenome_diag_wrapper_push_u64(&c->wk->site, &c->wk->n_site, &c->wk->cap_site, in.at))
				return 0;
		}
		boundary = in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_JMP ||
			   in.op == KGENOME_CELL_NOP;
	}
	return 1;
}

/*
 * THE WALK'S LIFE. One walk per object, made on the first ask and read by every
 * later one - the functions (the entries) and the wrapper resolution (the
 * entries, the kernel-entry sites and, in the same decode, the trace).
 *
 * `want_trace` is the caller saying it will read the code again after this. A
 * walk made without one that is later asked for one is made again (what two
 * walks cost before this existed); one made with it serves both. The trace is
 * bounded by W_TRACE_BYTES exactly as it was. It lives as long as the walk does
 * - to the end of the object - because two readers use it, the wrapper
 * resolution and the xref sweep (kgenome_diag_code_run), and which asks first is
 * the rules' business. It is freed with the walk, or when a walk made without
 * one is made again.
 */
struct kgenome_diag_walk *kgenome_diag_walk_new(void)
{
	return calloc(1, sizeof(struct kgenome_diag_walk));
}

void kgenome_diag_wrapper_walk_drop_trace(struct kgenome_diag_walk *wk)
{
	if (!wk)
		return;
	if (wk->lg)
		kgenome_ledger_release(wk->lg, wk->lg_charged);
	wk->lg_charged = 0;
	free(wk->tr);
	free(wk->ix);
	wk->tr = NULL;
	wk->ix = NULL;
	wk->n_tr = wk->cap_tr = wk->n_ix = wk->cap_ix = 0;
	wk->has_trace = 0;
	memset(wk->tseg, 0, sizeof wk->tseg);
}

static void walk_reset(struct kgenome_diag_walk *wk)
{
	struct kgenome_ledger *lg = wk->lg;

	kgenome_diag_wrapper_walk_drop_trace(wk);
	free(wk->tgt);
	free(wk->site);
	memset(wk, 0, sizeof *wk);
	wk->lg = lg;                    /* who holds the walk is not part of what it holds */
}

/*
 * A SCAN TAKES THE WALK, or lets it go. While bound, the walk's trace is
 * charged to the scan's ledger (what it already holds, now; what it grows by,
 * as it grows); unbound - the scan is freed, and the walk goes on to the next
 * reader in the object's life - nothing refers to a ledger that is gone.
 */
void kgenome_diag_walk_bind(struct kgenome_diag_walk *wk, struct kgenome_ledger *lg)
{
	if (!wk || wk->lg == lg)
		return;
	if (wk->lg)
		kgenome_ledger_release(wk->lg, wk->lg_charged);
	wk->lg = lg;
	wk->lg_charged = 0;
	if (lg) {
		uint64_t have = (uint64_t)wk->cap_tr + (uint64_t)wk->cap_ix * sizeof *wk->ix;

		if (have && kgenome_ledger_try(lg, have))
			wk->lg_charged = have;
	}
}

void kgenome_diag_walk_free(struct kgenome_diag_walk *wk)
{
	if (!wk)
		return;
	walk_reset(wk);
	free(wk);
}

/* The walk of the executable segments of an ELF, through celllysis, whichever
 * architecture it has a decoder for. Kernel-entry sites are x86's and are
 * recorded for x86 only. 1 when it holds the answer. */
int kgenome_diag_walk_ensure(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, int want_trace)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	struct kgenome_diag_wrapper_ctx c;
	uint32_t i;
	int x86 = obj->arch == KGENOME_ARCH_X86 || obj->arch == KGENOME_ARCH_X86_64;

	if (!wk || !e || !e->valid || obj->format != KGENOME_FMT_ELF)
		return 0;
	if (wk->built && wk->base == base && wk->size == size &&
	    (wk->has_trace || !want_trace))
		return 1;
	walk_reset(wk);
	memset(&c, 0, sizeof c);
	c.obj = obj;
	c.base = base;
	kgenome_cell_space_init(&c.sp, obj, base, size);
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;
	c.wk = wk;
	wk->base = base;
	wk->size = size;
	wk->sites = x86;
	wk->has_trace = want_trace && x86;
	wk->tr_on = wk->has_trace && size <= 0xffffffffu;
	for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

		if (have && !pass_a(&c, i, at, have)) {
			walk_reset(wk);
			return 0;
		}
	}
	kgenome_diag_wrapper_tgt_unique(&c);
	wk->built = 1;
	return 1;
}

const uint64_t *kgenome_diag_walk_entries(const struct kgenome_diag_walk *wk, uint32_t *n)
{
	*n = wk->n_tgt;
	return wk->tgt;
}

/* The scan's walk: the one it was given, else one of its own. */
struct kgenome_diag_walk *kgenome_diag_scan_walk(struct kgenome_diag_scan *s)
{
	if (!s->walk) {
		s->own_walk = kgenome_diag_walk_new();
		s->walk = s->own_walk;
		kgenome_diag_walk_bind(s->walk, &s->led);
	}
	return s->walk;
}
