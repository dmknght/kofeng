/*
 * diag_wrapper_walk.c - the object's walk (decoded once: call targets,
 * kernel entries), the write side of the decode trace, the walk's life, and the instructions of a run for an observer.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"
#include <celllysis/cfg_private.h>      /* kgenome_cfg_isa_of: delay slots */

/* ---- pass A: call targets and syscall sites -------------------------------- */

int kgenome_diag_wrapper_push_u64(uint64_t **v, uint32_t *n, uint32_t *cap, uint64_t x)
{
	if (*n == *cap) {
		uint32_t nc = kgenome_grow_cap(*cap, 256u);
		uint64_t *nv = nc ? realloc(*v, (size_t)nc * sizeof **v) : NULL;

		if (!nv)
			return 0;
		*v = nv;
		*cap = nc;
	}
	(*v)[(*n)++] = x;
	return 1;
}

/* The one kernel-entry test is kgenome_diag_kernel_entry (diag_sweep_cand.c); how an instruction is
 * put to it - `int 0x80` is the vector in the first operand - is kgenome_diag_wrapper_entry_test
 * (private header), for the walk's cell instruction and for a trace instruction alike. */
int kgenome_diag_wrapper_is_kernel_entry(const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_diag_wrapper_insn *in)
{
	return kgenome_diag_wrapper_entry_test(c, in->op, in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM &&
					  in->o[0].v == 0x80, in->at);
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
 * ONE decoder, kgenome_cell_step: pass_a takes the instruction it returns and packs it
 * into the record as it stands (trace_put reads a struct kgenome_cell_insn; nothing is
 * converted to another form first), and kgenome_diag_wrapper_decode() is the same
 * call turned into the form the readers use, for an offset the trace does not hold.
 *
 * WHO READS IT. The wrapper resolution (pass_b, summarise: diag_wrapper_trace.c, isrc),
 * the xref sweep (kgenome_diag_code_run) and the syscall sweep (diag_sweep.c), which gets
 * it as the decode source of its own cursor (kgenome_diag_walk_hold). MEASURED over 254
 * static ELF before the sweep read it: 66.6 M decode calls, 59.9 M distinct offsets, and
 * 5.08 M of the repeats were the sweep decoding what this walk held.
 *
 * WHAT A winsn LEAVES OUT of struct kgenome_cell_insn: `target_va`, which nothing here
 * reads (it is the relative operand added to the end of the instruction, and is made
 * again where it is wanted), `wmask` above bit 15 (only the sixteen general registers
 * are tracked) and the displacement/immediate that the operand's kind makes
 * meaningless. Leaving them out is what lets it be packed; reading one would
 * not compile. `cond` is kept (it rides in the record's flags byte) because a record also
 * answers a cursor, which must get the instruction the decoder returns: an instruction
 * whose wmask has a bit above 15, or whose flags or cond do not fit a nibble, is not
 * recorded at all and its segment's trace ends there (trace_put) - none of the x86
 * decoder's outputs is such, and decode_held.c reads every offset of random code to say so.
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
#define W_REC_MAX      128u    /* 7 + at 4 + delta 8 + target 4 + two varints 10 + three operands of 7 + two varints 20 = 124 */

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
static void trace_put(struct kgenome_diag_wrapper_ctx *c, unsigned seg, const struct kgenome_cell_insn *w)
{
	struct kgenome_diag_wrapper_seg *g = &c->wk->tseg[seg];
	uint8_t rec[W_REC_MAX], *p = rec + 7;
	uint64_t delta = w->at_va - w->at;
	unsigned ctl = 0, i;
	int first;

	if (g->given_up)
		return;
	/* The record could not say what was decoded: it is not made, and the segment's trace ends here. (A wider mask, a target_va and the second field of an operand have a place in it:
	 * the record is the whole instruction of any architecture, kgenome_diag_wrapper_trace_get_cell.) */
	if (w->n_op > 3u || w->cond > 15u || w->flags > 15u) {
		trace_give_up(g);
		return;
	}
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
	if (w->wmask >> 16) {
		ctl |= KGENOME_DIAG_WRAPPER_TRACE_HAS_WHI;
		p = put_vz(p, (int64_t)(w->wmask >> 16));
	}
	if (w->target_va != KGENOME_BROKEN) {           /* relative to the instruction: the bytes decode the same under any load address */
		ctl |= KGENOME_DIAG_WRAPPER_TRACE_HAS_TVA;
		p = put_vz(p, (int64_t)(w->target_va - w->at_va));
	}
	ctl |= (unsigned)w->n_op << KGENOME_DIAG_WRAPPER_TRACE_NOP_SHIFT;
	for (i = 0; i < w->n_op; i++) {
		const struct kgenome_cell_operand *o = &w->o[i];
		const int64_t canon_d = o->kind == KGENOME_CELL_O_MEM ? o->disp : 0;
		const uint64_t canon_i = o->kind == KGENOME_CELL_O_IMM || o->kind == KGENOME_CELL_O_REL ? o->imm : 0;
		const int both = o->disp != canon_d || o->imm != canon_i;       /* a field the kind does not name is not zero: both are written */

		p[0] = (uint8_t)(o->kind | (both ? KGENOME_DIAG_WRAPPER_TRACE_OP_BOTH : 0u));
		p[1] = o->reg; p[2] = o->index; p[3] = o->scale;
		p[4] = o->size; p[5] = o->flags; p[6] = o->seg;
		p += 7;
		if (both) {
			p = put_vz(p, o->disp);
			p = put_vz(p, (int64_t)o->imm);
		} else {
			p = put_vz(p, o->kind == KGENOME_CELL_O_MEM ? o->disp : (int64_t)canon_i);
		}
	}
	rec[0] = (uint8_t)(p - rec);
	rec[1] = (uint8_t)ctl;
	rec[2] = w->op;
	rec[3] = w->len;
	rec[4] = (uint8_t)(w->flags | (w->cond << 4));
	rec[5] = (uint8_t)w->wmask;
	rec[6] = (uint8_t)(w->wmask >> 8);

	if (c->wk->n_tr + rec[0] > c->wk->cap_tr) {
		size_t nc = c->wk->cap_tr ? (size_t)c->wk->cap_tr * 2u : 1u << 16;
		uint8_t *nt;

		const size_t lim = c->wk->cap_bytes && c->wk->cap_bytes < W_TRACE_BYTES
				 ? (size_t)c->wk->cap_bytes : (size_t)W_TRACE_BYTES;

		if (nc > lim)
			nc = lim;
		/* KNOWN DEFECT REV-D3 (2026-10-25, Inference) [sev L]: the wrapper walk trace (diag_wrapper_walk.c) stops growing
		 * at W_TRACE_BYTES (32 MiB) and the rest of the image is decoded again; a performance defect, not lost evidence
		 * (`capped` is set). Trigger: a large dynamic ELF whose walk records more than 32 MiB. Effect: up to 33% of the
		 * reads decoded twice (agent-reported, STATUS D12, not re-measured here). Reproducer: none committed (the large
		 * dynamic file runs of fix_gbin). Fix: trace by function so a hot segment fits, pack the record tighter, or size
		 * the cap from the ledger. */
		if (c->wk->n_tr + rec[0] > nc ||
		    !wtrace_charge(c->wk, nc - c->wk->cap_tr) ||
		    !(nt = realloc(c->wk->tr, nc))) {
			c->wk->capped = 1;
			trace_give_up(g);
			return;
		}
		c->wk->tr = nt;
		c->wk->cap_tr = (uint32_t)nc;
	}
	if (first) {
		if (c->wk->n_ix == c->wk->cap_ix) {
			uint32_t nc = kgenome_grow_cap(c->wk->cap_ix, 1024u);
			struct kgenome_diag_wrapper_index *nx;

			if (!nc || !wtrace_charge(c->wk, (uint64_t)(nc - c->wk->cap_ix) * sizeof *nx)) {
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
 * WHAT A TRACE RECORD HOLDS: the whole instruction of ANY architecture (kgenome_diag_wrapper_trace_get_cell; the record's layout is in the private header), so
 * this reader hands over what kgenome_cell_decode writes, field for field, `target` aside: a branch's address is `target_va` (a file offset is the cursor's). The
 * sweep's cursor is answered by the same function (diag_wrapper_trace.c).
 */
/* CONSOLIDATION DEC-1 (2026-10-30, M): KEEP (will be the single reader of instructions in address order, serving the trace where held; 5 callers:
 * codemap, diag_elfimp, objctx xref feed, lineage, callnames, the PE route, the signing of a function). The trace holds every architecture (tests/lib/genome/trace_arch.c).
 * Better logic here than the others: one bounded run with stats (from_trace/decoded/skipped). Prove with: trace_arch.c (trace vs decoder, field for field). */
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
	struct kgenome_cell_insn pk;                        /* the next record the trace holds */
	struct kgenome_diag_wrapper_reader nx;
	const uint8_t *rend = NULL;
	uint64_t at = off, end;
	unsigned i;
	int pk_ok = 0;
	int be;
	int64_t delta;

	if (!obj || !base || !fn || off >= size)
		return;
	end = n > size - off ? size : off + n;
	/* The byte order of the words, as the cursor reads them (cursor.c: sp->be && !sp->code_le). This loop decoded every object little-endian: a MIPS-BE
	 * `sw` (0xafc2000c) was read as a `jal` (CN-1, fixed). */
	be = kgenome_obj_big_endian(obj) && !kgenome_obj_code_little_endian(obj);
	delta = (int64_t)(va - off);
	if (wk && wk->built && wk->has_trace && wk->tr && wk->base == base &&
	    wk->size == size) {
		for (i = 0; i < KGENOME_DIAG_WALK_SEGS; i++) {
			const struct kgenome_diag_wrapper_seg *g = &wk->tseg[i];

			/* A run that begins before the walk did (the headers, the
			 * bytes before an entry) is decoded up to the first record
			 * and read from the trace from there. */
			if (g->end > g->pos && off < g->hi && end > g->lo &&
			    kgenome_diag_wrapper_trace_lower(wk, g, off, &nx)) {
				rend = wk->tr + g->end;
				kgenome_diag_wrapper_trace_get_cell(&nx, &pk);
				pk_ok = 1;
				break;
			}
		}
	}
	/* KNOWN DEFECT CN-6 (2026-11-03, M) [sev M]: a reader that holds no trace still decodes the bytes again. Codemap is ONE read now (2.05 -> 1.01 per offset on Mirai.b, 2.00 -> 1.01 on ARM) and reads the walk's trace when it is given the walk (engine-like run on Mirai.b: 2.01 -> 1.01); what is left is below.
	 * Trigger: (1) a scan with no trace: the syscall sweep runs before the walk exists and a lib-level RUN_ALL decodes 3.19 per offset; (2) kof_codenotes_build builds a codemap of its own (D18b).
	 * Effect: work done twice or more (CLAUDE.md work-once), no wrong result.
	 * Reproducer: tests/unit/codemap_decode_once.c (codemap), /mnt/games/normtest/fix_decode1/h/deccnt2.c rows P3 and P4 (the rest).
	 * Fix: build the walk's trace before the syscall sweep; codenotes adopts the engine's codemap. */
	while (at < end) {
		/* `nx` reads on from the record `pk` was taken from. */
		while (pk_ok && pk.at < at) {           /* catch up with the run */
			if (nx.p < rend)
				kgenome_diag_wrapper_trace_get_cell(&nx, &pk);
			else
				pk_ok = 0;
		}
		if (pk_ok && pk.at == at && at + pk.len <= end &&
		    pk.at_va == at + (uint64_t)delta) {
			pk.target = KGENOME_BROKEN;     /* the one contract of this reader, as on the decode path below: a branch's address is `target_va` (its file offset is the cursor's) */
			fn(user, &pk);
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
			uint32_t len = kgenome_cell_decode(obj->arch, be, base + at,
						   left > UINT32_MAX ? UINT32_MAX
								     : (uint32_t)left,
						   at + (uint64_t)delta, &ci);

			if (len) {
				ci.at = at;
				ci.target = KGENOME_BROKEN;
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
static int stub_cmp(const void *a, const void *b)
{
	const uint64_t x = ((const struct kgenome_diag_stub *)a)->at, y = ((const struct kgenome_diag_stub *)b)->at;

	return x < y ? -1 : x > y ? 1 : 0;
}

/* `lea r,[r+0]` (8d 76 00, 8d b6 00 00 00 00, 8d 74 26 00, 8d b4 26 00 00 00 00, cs-prefixed or not: the assembler's multi-byte pad, which an x86 decoder reports as a LEA and no
 * nop) changes nothing and is padding like a nop (D2: a function's end was left beyond the padding that follows it). A LEA of anything else is a computation. */
static int x86_self_lea(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_LEA && in->n_op == 2u && in->o[0].kind == KGENOME_CELL_O_REG && in->o[1].kind == KGENOME_CELL_O_MEM &&
	       in->o[1].reg == in->o[0].reg && in->o[1].index == KGENOME_CELL_REG_NONE && in->o[1].disp == 0;
}

/* The signal-return trampolines the C library keeps (__restore_rt, __restore): a few bytes that nothing calls - the kernel returns into them - and that follow the function before them
 * with no padding, so the entry walk saw no start there and the stub was merged into the previous function (D3: 602 bytes on a measured file). The ABI fixes the bytes:
 *   x86-64  mov rax,15 ; syscall                     48 c7 c0 0f 00 00 00 0f 05
 *   i386    pop eax ; mov eax,119 ; int 0x80         58 b8 77 00 00 00 cd 80      (sigreturn)
 *           mov eax,173 ; int 0x80                   b8 ad 00 00 00 cd 80         (rt_sigreturn) */
static int x86_sigreturn_stub(const uint8_t *p, uint64_t left, unsigned arch)
{
	static const uint8_t k64[] = { 0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05 };
	static const uint8_t k32a[] = { 0x58, 0xb8, 0x77, 0x00, 0x00, 0x00, 0xcd, 0x80 };
	static const uint8_t k32b[] = { 0xb8, 0xad, 0x00, 0x00, 0x00, 0xcd, 0x80 };

	if (arch == KGENOME_ARCH_X86_64)
		return left >= sizeof k64 && !memcmp(p, k64, sizeof k64);
	return (left >= sizeof k32a && !memcmp(p, k32a, sizeof k32a)) || (left >= sizeof k32b && !memcmp(p, k32b, sizeof k32b));
}

static int pad_cmp(const void *a, const void *b)
{
	const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

/* Ends the padding run in progress at `at`: [from, at) is recorded when it holds a byte. */
static int pad_close(struct kgenome_diag_wrapper_ctx *c, uint64_t *from, uint64_t at)
{
	const uint64_t f = *from;

	*from = UINT64_MAX;
	if (f == UINT64_MAX || at <= f)
		return 1;
	return kgenome_diag_wrapper_push_u64(&c->wk->pad, &c->wk->n_pad, &c->wk->cap_pad, f) &&
	       kgenome_diag_wrapper_push_u64(&c->wk->pad, &c->wk->n_pad, &c->wk->cap_pad, at);
}

/* MIPS o32 PIC registers pass_a reads by number (celllysis/decode_mips.c names none of them: it
 * reports a plain register index like every other decoder). $t9 carries every PIC call's callee
 * (CN-5's Fix); $gp is the base the loader fixes it relative to. */
#define MIPS_REG_T9 25u
#define MIPS_REG_GP 28u

/*
 * CN-5's Fix, part 1: MIPS o32 PIC fixes $gp as a LINK-TIME CONSTANT relative to the GOT -
 * `.got`'s address + 0x7ff0, which centres $gp in the 16-bit signed offset range (the SVR4 MIPS
 * ABI convention, read by the linker and by every PIC-call site alike; it holds for a dynamically
 * linked object and for a purely static one the same way, so no DT_MIPS_* / .dynamic reader is
 * needed - this tree has none today and this does not add one). Read like kgenome_fntab_eh_section
 * reads ".eh_frame": by section name, kept sections only. A sstripped object (no section table) or
 * one with no `.got` answers unknown (0): pass_a then leaves `jalr $t9` exactly as before - rule 4,
 * no guess.
 */
static int mips_gp_of(const struct kgenome_obj *obj, uint64_t *gp)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	uint32_t i;

	if (!e || !e->valid)
		return 0;
	for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if ((s->flags & KGENOME_ELF_SHF_ALLOC) && s->file_size && !strcmp(s->name, ".got")) {
			*gp = s->mem_addr + 0x7ff0u;
			return 1;
		}
	}
	return 0;
}

/*
 * CN-5's Fix, part 2: the callee of a `jalr $t9` whose $t9 came from `lw $t9, t9_off($gp)` (the
 * caller tracked `t9_off` across the straight-line run since that load - see pass_a). The slot at
 * $gp+t9_off is a LOCAL GOT entry: the static linker fills it with the real callee address whether
 * or not the object is dynamically linked at all (no runtime fixup is needed for a local symbol),
 * so the file already holds the answer and reading it is not a relocation walk.
 *
 * Refuses (0) rather than ever reporting a wrong target: the slot must be a whole, in-bounds read
 * of THIS object's own bytes, and the value it holds must land inside one of the object's own
 * EXECUTABLE segments. A global/PLT-style GOT entry - filled only by the dynamic loader at runtime -
 * reads back as zero or an unrelated link-time placeholder here and is correctly turned away by
 * that same check, never guessed at.
 *
 * `gp` is the caller's: part 1's walk-wide one (the object's `.got` + 0x7ff0) for most functions,
 * or part 3's per-function one (the `lui`/`addiu`/`addu` prologue, below) for a function that
 * recomputes its own - the slot read and the two checks are identical either way, so one function
 * serves both rather than each resolving its slot and re-deriving this one's safety check.
 */
static int mips_got_target(const struct kgenome_diag_wrapper_ctx *c, uint64_t gp, uint64_t t9_off, uint64_t *out)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(c->obj);
	uint64_t got_va, slot_off, raw, callee_off;
	uint32_t i;

	if (!e || !c->sp.off_of_va)
		return 0;
	got_va = gp + t9_off;
	slot_off = c->sp.off_of_va(c->sp.priv, got_va);
	if (slot_off == KGENOME_BROKEN || slot_off + 4u > c->size)
		return 0;
	raw = c->sp.be ? ((uint64_t)c->base[slot_off] << 24 | (uint64_t)c->base[slot_off + 1u] << 16 |
			  (uint64_t)c->base[slot_off + 2u] << 8 | (uint64_t)c->base[slot_off + 3u])
		       : ((uint64_t)c->base[slot_off + 3u] << 24 | (uint64_t)c->base[slot_off + 2u] << 16 |
			  (uint64_t)c->base[slot_off + 1u] << 8 | (uint64_t)c->base[slot_off]);
	if (!raw)
		return 0;
	callee_off = c->sp.off_of_va(c->sp.priv, raw);
	if (callee_off == KGENOME_BROKEN || callee_off >= c->size)
		return 0;
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
		if (kgenome_elf_seg_is_code(&e->seg[i]) && raw >= e->seg[i].mem_addr &&
		    raw - e->seg[i].mem_addr < e->seg[i].mem_size) {
			*out = callee_off;
			return 1;
		}
	return 0;
}

/*
 * CN-5's Fix, part 3: MIPS o32 PIC's OTHER convention - merge 135 measured a real Mirai MIPS sample
 * using it ALONGSIDE part 1's walk-wide $gp, in the same binary. A function using it recomputes its
 * OWN $gp from $t9 at entry:
 *
 *     lui   $gp, hi      addiu $gp, $gp, lo      addu  $gp, $gp, $t9
 *
 * This reads the SAME ABI fact part 1's GOT read does, from its other side: the calling convention
 * guarantees $t9 holds the CALLEE's own address at entry (the caller's `jalr $t9` put it there) -
 * so at the exact point this sequence executes, and ONLY there, $t9 equals the function's own start
 * address. Nothing is tracked to know it: pass_a already knows where `lui` sits, so the function's
 * start stands in for $t9 with no register value followed at all. `mips_is_lui_gp` below being true
 * at a function's own (delay-slot-adjusted) start - `mips_fn_bnd` in pass_a - is what makes that
 * substitution sound, not a guess at what $t9 holds generally.
 *
 * ONE AMBIGUITY INHERITED FROM THE DECODER, read and accepted rather than guessed around:
 * decode_mips.c's generic I-type form reports `lui $gp,X` and a LOAD into $gp (`lw`/`lh`/`lb
 * $gp,X(rs)`) as the identical shape - class MOV, three REG/REG/IMM operands - because the decoder
 * does not keep which of MIPS's several I-type opcodes produced one (celllysis's contract: it names
 * what a sweep asks about, not every opcode). `o[1].reg == 0` (a real `lui`'s rs field, which the
 * assembler always sets to the zero register) is the one signal left, and it is not proof by itself
 * - a `lw $gp,X($zero)` would read the same. What keeps a false match harmless rather than wrong: it
 * must ALSO sit at a function's own start (a reload instruction - the real case this could be
 * confused with, `lw $gp,off($sp)` restoring a caller's $gp after a call - runs mid-function, never
 * there), AND it must ALSO be followed, verbatim and straight-line, by a real `addiu $gp,$gp,lo` and
 * a real `addu $gp,$gp,$t9` for anything to be set at all - a combination no load-then-arithmetic
 * sequence in real code produces by coincidence - and even then mips_got_target's own bounds and
 * code-segment check is what actually gates a resolved call, exactly as it does for part 1's $gp.
 */
static int mips_is_lui_gp(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_MOV && in->n_op == 3u &&
	       in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == MIPS_REG_GP &&
	       in->o[1].kind == KGENOME_CELL_O_REG && in->o[1].reg == 0u &&
	       in->o[2].kind == KGENOME_CELL_O_IMM;
}

static int mips_is_addiu_gp_gp(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_ADD && in->n_op == 3u &&
	       in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == MIPS_REG_GP &&
	       in->o[1].kind == KGENOME_CELL_O_REG && in->o[1].reg == MIPS_REG_GP &&
	       in->o[2].kind == KGENOME_CELL_O_IMM;
}

/* Either operand order: `addu` is a plain sum of two registers and the GNU toolchain's own order
 * (`addu $gp,$gp,$t9`) is not a fact a module should have to match exactly to get the same number. */
static int mips_is_addu_gp_t9(const struct kgenome_cell_insn *in)
{
	return in->op == KGENOME_CELL_ADD && in->n_op == 3u &&
	       in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == MIPS_REG_GP &&
	       in->o[1].kind == KGENOME_CELL_O_REG && in->o[2].kind == KGENOME_CELL_O_REG &&
	       ((in->o[1].reg == MIPS_REG_GP && in->o[2].reg == MIPS_REG_T9) ||
		(in->o[1].reg == MIPS_REG_T9 && in->o[2].reg == MIPS_REG_GP));
}

/* CONSOLIDATION FUNC-5 (2026-10-30, R): KEEP (the entry evidence: direct call targets and the `jmp X` thunk at a function start, from the walk's one
 * decode; 1 caller walk_ensure, which has 3). Better logic than byte search and than codemap: thunk targets (the comment above measured 20166 thunks a
 * byte search misses) and a trace shared by later readers. Lacks: indirect calls through a register (cell_step has no register model), lea/adrp address-
 * taken starts. Prove with: tests/lib/genome diag wrapper rows; evmix.c column E vs C (C 62.9% vs E 64.3% on x86-64, consistent with the thunks:
 * Inference). */
static int pass_a(struct kgenome_diag_wrapper_ctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	struct kgenome_diag_wrapper_seg *g = &c->wk->tseg[seg];

	/* Whether the instruction before ended a function's straight line. */
	int boundary = 1;
	int sgboundary = 1;             /* x86: the instruction before ended a function or was padding of any kind (a stub of the C library may start here, D3) */
	/* THE PADDING RUN in progress (the function table cuts it off the end of the function before it): where it began, or UINT64_MAX. A delay
	 * slot belongs to the branch before it, so on an architecture that has one the run begins after it. */
	uint64_t pad_from = UINT64_MAX;
	int prev_cti = 0, prev_call = 0;
	struct kgenome_diag_wrapper_pe pe;      /* the PE rules of this decode (diag_wrapper_pe.c); `pe.pe` is NULL for every other format */
	const struct kgenome_cfg_isa *isa = kgenome_cfg_isa_of(c->wk->arch);
	const int slots = isa && isa->delay_slots;
	const int x86 = c->wk->arch == KGENOME_ARCH_X86 || c->wk->arch == KGENOME_ARCH_X86_64;
	/* The all-zero word is padding where it is a nop or the linker's fill: MIPS (`sll $0,$0,0`, the canonical nop, which the decoder reports as OTHER: it names what the
	 * sweep asks about) and ARM (`andeq r0,r0,r0`, the fill GNU ld puts between objects: 391 of 1876 alignment gaps of at most 15 bytes in the 260 ARM files of the
	 * oracle corpus, agent-reported; the others are `mov r0,r0` and the Thumb nop 0xbf00, which is read as ARM here, CN-5). */
	const int zeronop = c->wk->arch == KGENOME_ARCH_MIPS || c->wk->arch == KGENOME_ARCH_MIPS64 || c->wk->arch == KGENOME_ARCH_ARM;
	/* CN-5's Fix: MIPS32 only (MIPS64's n32/n64 GOT and $gp convention differ and are not read
	 * here - rule 4, stay unresolved rather than guess at a layout this file does not know).
	 * `t9_known` is a single straight-line fact, the same shape as `prev_cti`/`pad_from` above:
	 * set by the one recognised `lw $t9, t9_off($gp)` shape, cleared by anything that could make
	 * it stale before a `jalr $t9` reads it - a control-transfer instruction (mips_got_target is
	 * asked before this read, below) or any other instruction that writes $t9. */
	const int mips = c->wk->arch == KGENOME_ARCH_MIPS;
	uint64_t t9_off = 0;
	int t9_known = 0;
	/*
	 * CN-5's Fix, part 3 (mips_is_lui_gp/_addiu_gp_gp/_addu_gp_t9 above): the pending match of the
	 * `lui`/`addiu`/`addu` sequence (pgp_state: 0 none, 1 saw `lui`, 2 saw `lui`+`addiu`), what it
	 * has accumulated, and the per-function $gp it establishes once complete - the same
	 * one-slot-of-straight-line-fact shape as `t9_known` above, not a second $t9/$gp tracker.
	 */
	uint64_t pgp_hi = 0, pgp_lo = 0;        /* hi<<16 (already shifted by the decoder) and the sign-extended lo, from the `lui`/`addiu` steps */
	uint64_t pgp_entry_va = 0;              /* the `lui`'s own address: $t9's value there, by the ABI, iff pgp_entry_valid */
	int pgp_entry_valid = 0;
	unsigned pgp_state = 0;
	uint64_t pgp = 0;
	int pgp_known = 0;
	/*
	 * `boundary` above, delay-slot adjusted for MIPS: the instruction right after an unconditional
	 * transfer (`jr`/`j`) is that transfer's OWN delay slot, not the next function - so part 3's
	 * `lui` must not be judged against `boundary` itself, which would read the slot as the start. A
	 * `nop`'s boundary needs no such delay (it is not a transfer), and this affects part 3's reading
	 * of pgp_entry_valid only: `boundary` itself (the thunk-entry and padding logic above) is
	 * unchanged. mips_bnd_delay marks that the instruction just read WAS such a slot, so the one
	 * after it is the true boundary.
	 */
	int mips_bnd = 1;
	int mips_bnd_delay = 0;

	memset(&k, 0, sizeof k);
	kgenome_diag_wrapper_pe_start(&pe, c->obj);
	g->lo = off;
	g->hi = off + n;
	g->pos = c->wk->n_tr;
	g->end = c->wk->n_tr;
	g->ix = c->wk->n_ix;
	g->complete = c->wk->tr_on != 0;
	g->given_up = !c->wk->tr_on;
	(void)kgenome_cell_seek(&k, off, 0);            /* (answers 0 only for no cursor) */
	while (k.at < off + n) {
		if (!kgenome_cell_step(&k, &c->sp, &in)) {
			if (!pad_close(c, &pad_from, k.at))
				return 0;
			k.at++;                 /* data in the code: step over it */
			prev_cti = 0;
			prev_call = 0;
			sgboundary = 0;
			t9_known = 0;           /* a decode gap breaks the straight line: do not carry $t9 across it */
			pgp_state = 0;
			pgp_known = 0;          /* likewise for the per-function $gp (part 3) */
			if (pe.pe)
				kgenome_diag_wrapper_pe_data(&pe, c, k.at - 1u);        /* (a lone zero byte, the odd one of a zero tail, does not end the zero run) */
			continue;
		}
		trace_put(c, seg, &in);
		/* the padding runs: nop of any width, int3 (the byte 0xcc decodes as INT) */
		if (in.op == KGENOME_CELL_NOP || (x86 && in.op == KGENOME_CELL_INT && in.at < c->size && c->base[in.at] == 0xccu) || (x86 && x86_self_lea(&in)) ||
		    (zeronop && in.len == 4u && in.at + 4u <= c->size && !(c->base[in.at] | c->base[in.at + 1u] | c->base[in.at + 2u] | c->base[in.at + 3u]))) {
			if (pad_from == UINT64_MAX) {
				pad_from = in.at + (slots && prev_cti ? in.len : 0u);
				if (pe.pe)
					pad_from = kgenome_diag_wrapper_pe_pad_from(&in, prev_call, pad_from);
			}
		} else if (!pad_close(c, &pad_from, in.at)) {
			return 0;
		}
		if (pe.pe)
			kgenome_diag_wrapper_pe_zero(&pe, c, &in);
		prev_cti = in.op == KGENOME_CELL_JMP || in.op == KGENOME_CELL_JCC || in.op == KGENOME_CELL_RET ||
			   in.op == KGENOME_CELL_CALL || in.op == KGENOME_CELL_LOOP;
		prev_call = in.op == KGENOME_CELL_CALL;
		/* $t9 tracking for CN-5's Fix (MIPS only; see mips_got_target above). The one recognised
		 * shape sets it; anything else that writes $t9 (another load, an ALU move into it) makes
		 * it unknown rather than stale - a write this is not the lw-pattern case below is never
		 * also the pattern, so testing it here cannot see this same instruction's own effect. */
		if (mips && in.op == KGENOME_CELL_MOV && in.n_op == 3u &&
		    in.o[0].kind == KGENOME_CELL_O_REG && in.o[0].reg == MIPS_REG_T9 &&
		    in.o[1].kind == KGENOME_CELL_O_REG && in.o[1].reg == MIPS_REG_GP &&
		    in.o[2].kind == KGENOME_CELL_O_IMM) {
			t9_off = in.o[2].imm;
			t9_known = 1;
		} else if (mips && (in.wmask & (1ull << MIPS_REG_T9)) != 0u) {
			t9_known = 0;
		}
		/*
		 * CN-5's Fix, part 3: the per-function $gp prologue. `consumed` says this instruction's
		 * effect on the pending match was already decided by one of the three steps; anything
		 * else either breaks a pending match (pgp_state) or, if it writes $gp some other way,
		 * empties what was already established (pgp_known) - mirroring $t9's own tracking above.
		 */
		if (mips) {
			int consumed = 0;

			if (mips_is_lui_gp(&in)) {
				pgp_hi = in.o[2].imm;
				pgp_entry_va = in.at_va;
				pgp_entry_valid = mips_bnd;
				pgp_state = 1;
				pgp_known = 0;          /* `lui` just wrote $gp: whatever pgp held before does not hold now */
				consumed = 1;
			} else if (pgp_state == 1 && mips_is_addiu_gp_gp(&in)) {
				pgp_lo = in.o[2].imm;
				pgp_state = 2;
				consumed = 1;
			} else if (pgp_state == 2 && mips_is_addu_gp_t9(&in)) {
				if (pgp_entry_valid) {
					pgp = (uint64_t)(uint32_t)((uint32_t)pgp_hi + (uint32_t)pgp_lo + (uint32_t)pgp_entry_va);
					pgp_known = 1;
				}
				pgp_state = 0;
				consumed = 1;
			}
			if (!consumed) {
				pgp_state = 0;          /* not the expected next step: any pending match is abandoned */
				if ((in.wmask & (1ull << MIPS_REG_GP)) != 0u)
					pgp_known = 0;  /* $gp written some other way than the sequence above */
			}
		}
		/* KNOWN DEFECT CN-5 (2026-11-05, M) [sev M]: PARTIAL - fixed for MIPS32's two PIC call conventions (`jalr $t9` preceded, straight-line, by `lw $t9, off($gp)`, with $gp either the walk-wide one fixed from the object's own `.got` section - mips_got_target - or a per-function one recomputed by the `lui`/`addiu`/`addu` prologue - mips_is_lui_gp and the pgp_* tracking above); MIPS64 (a different GOT/$gp convention, n32/n64, not read here) and ARM's Thumb mode (read as ARM, Inference) are still unresolved.
		 * Trigger: a MIPS64 object, a sstripped MIPS32 object with neither a `.got` section nor the recompute prologue in scope, or $t9 set any other way (a true function-pointer call). Effect: every one of these still takes no entry; Thumb code is unaffected by this fix.
		 * Reproducer: /mnt/games/normtest/fix_consol/matrix.md (fix_consol, entry walk vs symtab); tests/lib/genome/fntab.c t_walk_mips_indirect_jalr_got, t_walk_mips_indirect_jalr_prologue_gp (both green - the two conventions) and t_walk_mips_indirect_jalr / _no_lw / _prologue_gp_broken (the fallback cases, still pinned).
		 * Fix: a MIPS64 $gp/GOT reader of the n32/n64 convention; the stronger general evidence is still the unwind table (fntab_fde.c), which the function table reads. */
		if (mips && in.op == KGENOME_CELL_CALL && (in.flags & KGENOME_CELL_F_INDIRECT) &&
		    in.n_op && in.o[0].kind == KGENOME_CELL_O_REG && in.o[0].reg == MIPS_REG_T9 &&
		    t9_known && (pgp_known || c->wk->mips_gp_known)) {
			const uint64_t gp = pgp_known ? pgp : c->wk->mips_gp;  /* this function's own $gp (part 3) wins over the walk-wide one (part 1) when both apply */
			uint64_t mips_tgt;

			if (mips_got_target(c, gp, t9_off, &mips_tgt) &&
			    !kgenome_diag_wrapper_push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, mips_tgt))
				return 0;
		}
		if (pe.pe && !kgenome_diag_wrapper_pe_stub(&pe, c, &in))
			return 0;
		if (x86 && sgboundary && !pe.pe && in.at < c->size && x86_sigreturn_stub(c->base + in.at, c->size - in.at, c->wk->arch) &&
		    !kgenome_diag_wrapper_push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, in.at))
			return 0;
		if (in.op == KGENOME_CELL_CALL && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
		    in.target != KGENOME_BROKEN) {
			if (!kgenome_diag_wrapper_push_u64(&c->wk->tgt, &c->wk->n_tgt, &c->wk->cap_tgt, in.target))
				return 0;
		} else if (in.op == KGENOME_CELL_JMP && !(in.flags & KGENOME_CELL_F_INDIRECT) &&
			   in.target != KGENOME_BROKEN && boundary && !pe.pe) {
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
		} else if (c->wk->sites &&
			   kgenome_diag_wrapper_entry_test(c, in.op, in.n_op && in.o[0].kind == KGENOME_CELL_O_IMM &&
						     in.o[0].imm == 0x80u, in.at)) {
			if (!kgenome_diag_wrapper_push_u64(&c->wk->site, &c->wk->n_site, &c->wk->cap_site, in.at))
				return 0;
		}
		if (mips && prev_cti) {
			t9_known = 0;    /* this instruction crossed control flow: whatever filled $t9 before it may not reach past here */
			pgp_known = 0;   /* likewise for the per-function $gp (part 3): a call may let its callee clobber $gp with nothing here to say it was restored */
		}
		if (mips) {
			/*
			 * mips_bnd is `boundary` delay-slot adjusted: MIPS always runs one more instruction
			 * (the delay slot) after `jr`/`j` before the transfer happens, so the position right
			 * after one is still that instruction's own slot, not a new function - mips_bnd says
			 * so one instruction later than `boundary` itself would. A `nop` has no delay slot
			 * (it is not a transfer), so it sets the true boundary immediately, like `boundary`.
			 */
			if (mips_bnd_delay) {
				mips_bnd = 1;
				mips_bnd_delay = 0;
			} else if (in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_JMP) {
				mips_bnd = 0;
				mips_bnd_delay = 1;
			} else {
				mips_bnd = in.op == KGENOME_CELL_NOP;
			}
		}
		boundary = in.op == KGENOME_CELL_RET || in.op == KGENOME_CELL_JMP ||
			   in.op == KGENOME_CELL_NOP;
		sgboundary = boundary || (x86 && (x86_self_lea(&in) || (in.op == KGENOME_CELL_INT && in.at < c->size && c->base[in.at] == 0xccu)));
		if (pe.pe)
			kgenome_diag_wrapper_pe_boundary(&pe, c, &in, boundary);
	}
	if (!pad_close(c, &pad_from, k.at))
		return 0;
	return !pe.pe || kgenome_diag_wrapper_pe_close(&pe, c, k.at, off + n);
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
	wk->h_p = wk->h_end = NULL;     /* the cursor's place in a stream that is gone */
	memset(wk->tseg, 0, sizeof wk->tseg);
}

static void walk_reset(struct kgenome_diag_walk *wk)
{
	struct kgenome_ledger *lg = wk->lg;
	uint32_t runs = wk->runs;
	const uint64_t cap_bytes = wk->cap_bytes;
	const uint32_t capped = wk->capped;

	kgenome_diag_wrapper_walk_drop_trace(wk);
	free(wk->tgt);
	free(wk->site);
	free(wk->pad);
	free(wk->thk);
	memset(wk, 0, sizeof *wk);
	wk->lg = lg;                    /* who holds the walk is not part of what it holds */
	wk->runs = runs;                /* nor how many times it has been made */
	wk->cap_bytes = cap_bytes;      /* nor what its caller allows it */
	wk->capped = capped;
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

void kgenome_diag_walk_trim(struct kgenome_diag_walk *wk)
{
	kgenome_diag_wrapper_walk_drop_trace(wk);
}

void kgenome_diag_walk_set_cap(struct kgenome_diag_walk *wk, uint64_t trace_bytes)
{
	if (wk)
		wk->cap_bytes = trace_bytes;
}

uint32_t kgenome_diag_walk_capped(const struct kgenome_diag_walk *wk)
{
	return wk ? wk->capped : 0;
}

uint32_t kgenome_diag_walk_runs(const struct kgenome_diag_walk *wk)
{
	return wk ? wk->runs : 0;
}

/* The walk of the executable segments of an ELF, through celllysis, whichever
 * architecture it has a decoder for. Kernel-entry sites are x86's and are
 * recorded for x86 only. 1 when it holds the answer. */
int kgenome_diag_walk_ensure(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, int want_trace)
{
	struct kgenome_diag_wrapper_ctx c;
	uint32_t i;
	int x86 = obj->arch == KGENOME_ARCH_X86 || obj->arch == KGENOME_ARCH_X86_64;

	if (!wk || !obj)
		return 0;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		if (!e || !e->valid)
			return 0;
	} else if (obj->format == KGENOME_FMT_PE) {
		/* A PE is walked as x86 / x64 only (the one decoder with a trace); its kernel-entry sites are an ELF's question. */
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		if (!p || !p->valid || !x86)
			return 0;
	} else {
		return 0;
	}
	if (wk->built && wk->base == base && wk->size == size &&
	    (wk->has_trace || !want_trace))
		return 1;
	walk_reset(wk);
	wk->runs++;
	memset(&c, 0, sizeof c);
	c.obj = obj;
	c.base = base;
	kgenome_cell_space_init(&c.sp, obj, base, size);
	c.sp.raw = 1;                   /* the trace holds what the decoder writes */
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;
	c.wk = wk;
	wk->base = base;
	wk->size = size;
	wk->arch = obj->arch;
	wk->sites = x86 && obj->format == KGENOME_FMT_ELF;
	wk->mips_gp_known = (uint8_t)(wk->arch == KGENOME_ARCH_MIPS && obj->format == KGENOME_FMT_ELF &&
				      mips_gp_of(obj, &wk->mips_gp));
	wk->has_trace = want_trace;
	wk->tr_on = wk->has_trace && size <= 0xffffffffu;
	for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

		if (have && !pass_a(&c, i, at, have)) {
			walk_reset(wk);
			return 0;
		}
	}
	kgenome_diag_wrapper_tgt_unique(&c);
	if (wk->n_pad)
		qsort(wk->pad, wk->n_pad / 2u, 2u * sizeof *wk->pad, pad_cmp);
	if (wk->n_thk)
		qsort(wk->thk, wk->n_thk, sizeof *wk->thk, stub_cmp);
	wk->built = 1;
	return 1;
}

const uint64_t *kgenome_diag_walk_entries(const struct kgenome_diag_walk *wk, uint32_t *n)
{
	*n = wk->n_tgt;
	return wk->tgt;
}

/* The runs of padding instructions the one decode saw: `*n` runs of [from, to), sorted by `from` (the runs are disjoint, so `to` is
 * sorted too). Two u64 a run. */
const uint64_t *kgenome_diag_walk_pads(const struct kgenome_diag_walk *wk, uint32_t *n)
{
	*n = wk->n_pad / 2u;
	return wk->pad;
}

/* The import stubs the one decode met (PE): `*n` stubs, sorted by offset (the extents of a PE need not be in the order of the file). */
const struct kgenome_diag_stub *kgenome_diag_walk_thunks(const struct kgenome_diag_walk *wk, uint32_t *n)
{
	*n = wk->n_thk;
	return wk->thk;
}

uint64_t kgenome_diag_walk_thunk_slot(const struct kgenome_diag_walk *wk, uint64_t at)
{
	uint32_t lo = 0, hi = wk ? wk->n_thk : 0;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (wk->thk[mid].at < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return wk && lo < wk->n_thk && wk->thk[lo].at == at ? wk->thk[lo].slot : KGENOME_BROKEN;
}

/* The scan's walk: the one it was given, else one of its own. */
struct kgenome_diag_walk *kgenome_diag_scan_walk(struct kgenome_diag_scan *s)
{
	if (!s->walk) {
		s->own_walk = kgenome_diag_walk_new();
		s->own |= KGENOME_DIAG_OWN_WALK;
		s->walk = s->own_walk;
		kgenome_diag_walk_bind(s->walk, &s->led);
	}
	return s->walk;
}
