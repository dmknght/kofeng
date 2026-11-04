/*
 * frame.c - kgenome_frame_make and the cache. See frame.h for what a frame holds and why.
 *
 * The decode, the precondition and the graph are what the engine's signing function (analyzers/cfgsign.c) did for each function before this existed;
 * they moved here unchanged (one decode through kgenome_diag_code_run, the one reader, which serves the walk's trace; the build's first work area refused
 * as OVER_BUDGET before anything is allocated; the real byte order). What is new is what the one loop over the instructions also records.
 */
#include <stdlib.h>
#include <string.h>

#include "frame.h"
#include "diag_scan.h"
#include "../genotype/image/image_addr.h"
#include "../genotype/image/obj.h"

#define DEFAULT_MAX_BYTES (64ull << 20)

const char *kgenome_frame_state_name(enum kgenome_frame_state s)
{
	switch (s) {
	case KGENOME_FRAME_OK: return "built";
	case KGENOME_FRAME_UNDECODABLE: return "no instruction decodes at the entry";
	case KGENOME_FRAME_UNSUPPORTED: return "no control-flow rules for this architecture";
	case KGENOME_FRAME_OVER_BUDGET: return "over the allowance of one call";
	case KGENOME_FRAME_NOMEM: return "no memory";
	}
	return "?";
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
		nv = kgenome_cfg_alloc(c->mem, (size_t)nc * sizeof *nv);
		if (!nv) {
			c->nomem = 1;
			return;
		}
		if (c->n)
			memcpy(nv, c->v, (size_t)c->n * sizeof *nv);
		kgenome_cfg_release(c->mem, c->v, (size_t)c->cap * sizeof *nv);
		c->v = nv;
		c->cap = nc;
	}
	c->v[c->n++] = *in;
}

/* ---- what the one loop over the instructions records ---- */

/*
 * IS THE FRAME POINTER ONE? `push rbp; mov rbp, rsp` at the top and no other instruction that writes rbp but the epilogue's (`pop rbp`, and `leave`, which has no
 * operand): then `[rbp+x]` is a slot of the frame, which a value-flow stage follows, and not a cell it would follow. A function that uses rbp for anything else - a
 * pointer into an object, say - has no frame pointer here and every `[rbp+x]` is a place. The test is conservative in the direction that matters: when it is not
 * sure, the operand is a place. It is learned in the one loop, so what the loop sees of `[rbp+x]` before it knows is held apart (the two BP bits below) and joined
 * to the others afterwards.
 */
#define B_BPCELL  0x4000u
#define B_BPSTORE 0x8000u

struct fp_scan {
	int pushed, framed, bad;
};

static void fp_step(struct fp_scan *f, uint32_t i, const struct kgenome_cell_insn *in)
{
	if (!f->framed && i < 4u) {
		if (in->op == KGENOME_CELL_PUSH && in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg == KGENOME_CELL_REG_BP)
			f->pushed = 1;
		else if (f->pushed && in->op == KGENOME_CELL_MOV && in->n_op >= 2u && in->o[0].kind == KGENOME_CELL_O_REG &&
			 in->o[0].reg == KGENOME_CELL_REG_BP && in->o[1].kind == KGENOME_CELL_O_REG && in->o[1].reg == KGENOME_CELL_REG_SP)
			f->framed = 1;
	} else if (f->framed && (in->wmask & (1ull << KGENOME_CELL_REG_BP)) && in->op != KGENOME_CELL_POP && in->n_op) {
		f->bad = 1;
	}
}

/* What the memory operands of one instruction add to the block's bits. */
static uint16_t mem_bits(const struct kgenome_cell_insn *in)
{
	uint16_t pr = 0;
	uint8_t k;

	if (in->op == KGENOME_CELL_LEA)
		return 0;
	for (k = 0; k < in->n_op && k < 2u; k++) {
		const struct kgenome_cell_operand *o = &in->o[k];
		const int bp = o->reg == KGENOME_CELL_REG_BP && o->index == KGENOME_CELL_REG_NONE;
		const int store = (o->flags & KGENOME_CELL_OF_WRITE) && in->op != KGENOME_CELL_CALL && in->op != KGENOME_CELL_JMP &&
				  in->op != KGENOME_CELL_CMP && in->op != KGENOME_CELL_TEST && in->op != KGENOME_CELL_PUSH;

		if (o->kind != KGENOME_CELL_O_MEM || (o->reg == KGENOME_CELL_REG_SP && o->index == KGENOME_CELL_REG_NONE))
			continue;
		/* (a call through a slot names its operand 0 too, and does not write it) */
		pr |= bp ? (uint16_t)(B_BPCELL | (store ? B_BPSTORE : 0u)) : (uint16_t)(KGENOME_FRAME_B_MEMCELL | (store ? KGENOME_FRAME_B_MEMSTORE : 0u));
	}
	return pr;
}

/* Does a jump, conditional jump or loop go out of the extent: through a register or memory, or to a target outside [va, va + len)? (An unknown target,
 * KGENOME_BROKEN, is above every extent, so the range test answers it: a test of its own was a branch no input could tell from the range test.) */
static int leaves(const struct kgenome_frame *f, const struct kgenome_cell_insn *in)
{
	return (in->flags & KGENOME_CELL_F_INDIRECT) || in->target_va < f->va || in->target_va - f->va >= f->len;
}

static void record(struct kgenome_frame *f, const struct kgenome_cell_insn *in)
{
	struct fp_scan fp = { 0, 0, 0 };
	uint32_t b, i;

	for (b = 0; b < f->cfg.n_all; b++) {
		const struct kgenome_cfg_block *k = &f->cfg.b[b];
		uint16_t pr = 0;

		for (i = k->first; i < k->first + k->n_insn; i++) {
			fp_step(&fp, i, &in[i]);
			if (in[i].op == KGENOME_CELL_CALL)
				pr |= KGENOME_FRAME_B_CALL;
			else if (in[i].op == KGENOME_CELL_JMP)
				pr |= KGENOME_FRAME_B_JMP;
			else if (in[i].op == KGENOME_CELL_PUSH)
				pr |= KGENOME_FRAME_B_PUSH;
			else if (in[i].op == KGENOME_CELL_RET)
				pr |= KGENOME_FRAME_B_RET;
			if ((in[i].op == KGENOME_CELL_JMP || in[i].op == KGENOME_CELL_JCC || in[i].op == KGENOME_CELL_LOOP) && leaves(f, &in[i]))
				pr |= KGENOME_FRAME_B_LEAVES;
			pr |= mem_bits(&in[i]);
		}
		/* control runs out of the extent when the last block has no branch to end it: after a call it is the call that does not come back (`call abort` is the last instruction of a function
		 * the compiler knows does not return), after anything else it is the next function's code */
		if (b + 1u == f->cfg.n_all && k->term == KGENOME_CFG_T_FALL && in[k->first + k->n_insn - 1u].op != KGENOME_CELL_CALL &&
		    in[k->first + k->n_insn - 1u].op != KGENOME_CELL_SYSCALL)
			pr |= KGENOME_FRAME_B_RUNS_OUT;
		f->bits[b] = pr;
	}
	/* with no frame pointer, what went through rbp is a place like any other */
	for (b = 0; b < f->cfg.n_all; b++) {
		uint16_t pr = f->bits[b];

		if (!fp.framed || fp.bad)
			pr |= (uint16_t)((pr & B_BPCELL ? KGENOME_FRAME_B_MEMCELL : 0u) | (pr & B_BPSTORE ? KGENOME_FRAME_B_MEMSTORE : 0u));
		f->bits[b] = (uint16_t)(pr & ~(B_BPCELL | B_BPSTORE));
	}
	f->framed = fp.framed && !fp.bad;
}

const uint16_t *kgenome_frame_facts(const struct kgenome_frame *cf, const struct kgenome_cell_insn *in)
{
	struct kgenome_frame *f = (struct kgenome_frame *)(uintptr_t)cf;     /* the memo: see frame.h */

	if (!f || f->state != KGENOME_FRAME_OK || !in)
		return NULL;
	if (!f->bits) {
		f->bits_bytes_ = (size_t)f->cfg.n_all * sizeof *f->bits;
		f->bits = kgenome_cfg_alloc(&f->mem_, f->bits_bytes_);
		if (!f->bits) {
			f->bits_bytes_ = 0;
			return NULL;
		}
		record(f, in);
	}
	return f->bits;
}

const uint16_t *kgenome_frame_facts_of(const struct kgenome_frame *f, const struct kgenome_frame_src *s)
{
	struct col col;
	const uint16_t *r;

	if (!f || !s || f->state != KGENOME_FRAME_OK)
		return NULL;
	if (f->bits)
		return f->bits;
	memset(&col, 0, sizeof col);
	col.max_bytes = s->max_bytes ? s->max_bytes : DEFAULT_MAX_BYTES;
	col.mem = &s->mem;
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
		.obj = s->obj, .base = s->base, .size = s->size, .off = f->off, .n = f->len, .va = f->va,
		.fn = collect, .user = &col, .wk = s->wk });
	/* the same instructions the graph was made from: a count that differs is not this function's frame (the walk's trace was dropped between the two reads) */
	r = !col.over && !col.nomem && col.n == f->n_insn ? kgenome_frame_facts(f, col.v) : NULL;
	if (col.cap)
		kgenome_cfg_release(&s->mem, col.v, (size_t)col.cap * sizeof *col.v);
	return r;
}

/* ---- make ---- */

enum kgenome_frame_state kgenome_frame_make(const struct kgenome_frame_src *s, uint64_t off, uint64_t len, unsigned flags,
					    struct kgenome_frame *out)
{
	const struct kgenome_cfg_mem *mem = s ? &s->mem : NULL;
	struct kgenome_budget bud;
	struct kgenome_cfg_req cq;
	struct col col;
	uint64_t va;
	enum kgenome_status st;

	memset(out, 0, sizeof *out);
	out->fn = KGENOME_FUNCS_NONE;
	out->off = off;
	out->len = len;
	out->state = KGENOME_FRAME_UNDECODABLE;
	out->status = KGENOME_BAD_INPUT;
	if (!s || !s->obj || !s->base || !len || off >= s->size || len > s->size - off)
		return KGENOME_FRAME_UNDECODABLE;
	out->be = (uint8_t)(kgenome_obj_big_endian(s->obj) && !kgenome_obj_code_little_endian(s->obj));
	va = kgenome_image_off_to_addr(s->obj, off);
	out->mapped = va != KGENOME_BROKEN;
	out->va = out->mapped ? va : off;
	memset(&bud, 0, sizeof bud);
	bud.max_bytes = s->max_bytes ? s->max_bytes : DEFAULT_MAX_BYTES;
	memset(&col, 0, sizeof col);
	col.max_bytes = bud.max_bytes;
	col.mem = mem;
	if (s->pre && s->pre->off == off && s->pre->len == len && !(flags & KGENOME_FRAME_KEEP_INSN)) {
		/* the caller's decode, read and not made again (the array stays the caller's: col.v is not owned, col.cap stays 0) */
		col.v = (struct kgenome_cell_insn *)(uintptr_t)s->pre->v;
		col.n = s->pre->n;
		col.skipped = s->pre->skipped;
		if ((uint64_t)col.n * sizeof *col.v > col.max_bytes)
			col.over = 1;
	} else {
		/* THE ONE DECODE (the walk's trace where the object has one). */
		kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
			.obj = s->obj, .base = s->base, .size = s->size, .off = off, .n = len, .va = out->va,
			.fn = collect, .user = &col, .wk = s->wk });
	}
	out->n_insn = col.n;
	out->n_skip = col.skipped;
	out->cut = col.skipped != 0;
	if (col.nomem || col.over) {
		out->status = col.nomem ? KGENOME_NOMEM : KGENOME_OVER_BUDGET;
		out->state = col.nomem ? KGENOME_FRAME_NOMEM : KGENOME_FRAME_OVER_BUDGET;
		goto fail;
	}
	if (!col.n || col.v[0].at != off) {
		/* nothing decoded at the entry: either the architecture has no rules (the lib says so on an empty request) or the bytes are not code */
		struct kgenome_cfg_req probe;
		struct kgenome_cfg none;

		memset(&probe, 0, sizeof probe);
		memset(&none, 0, sizeof none);
		probe.arch = s->obj->arch;
		out->status = KGENOME_BAD_INPUT;
		out->state = kgenome_cfg_build(&probe, &none) == KGENOME_UNSUPPORTED ? KGENOME_FRAME_UNSUPPORTED : KGENOME_FRAME_UNDECODABLE;
		kgenome_cfg_free(&none, NULL);
		goto fail;
	}
	/* (what the graph itself needs is bounded by `bud`, inside kgenome_cfg_build, and said in its status: a check of the instructions' count here asked less than the array of them
	 * had already been held to - an instruction is 120 bytes, the graph asks 9 - and no input could reach it) */
	memset(&cq, 0, sizeof cq);
	cq.in = col.v;
	cq.n_in = col.n;
	cq.arch = s->obj->arch;
	cq.be = out->be;
	cq.va_lo = out->va;
	cq.va_hi = out->va + len;
	cq.bytes = s->base;
	cq.bytes_len = s->size;
	cq.cut = out->cut;
	/* A PE of x86: the int3 (or hlt) after a call is MSVC's mark that the call does not return (the exit of the function): a rule of that toolchain, so ELF code keeps going past one. */
	if (s->obj->format == KGENOME_FMT_PE && (s->obj->arch == KGENOME_ARCH_X86 || s->obj->arch == KGENOME_ARCH_X86_64))
		cq.flags |= KGENOME_CFG_F_TRAP_EXITS;
	cq.budget = &bud;
	cq.mem = s->mem;
	cq.switch_src = s->switch_src;          /* REACH_INDIRECT: plumbing only, see frame.h; NULL read_at (every caller today) changes nothing */
	st = kgenome_cfg_build(&cq, &out->cfg);
	out->status = kgenome_status_merge(st, out->cfg.status);
	if (!out->cfg.n_all) {
		kgenome_cfg_free(&out->cfg, mem);
		out->status = st == KGENOME_OK ? KGENOME_BAD_INPUT : st;
		out->state = st == KGENOME_UNSUPPORTED ? KGENOME_FRAME_UNSUPPORTED : st == KGENOME_NOMEM ? KGENOME_FRAME_NOMEM :
			     st == KGENOME_OVER_BUDGET ? KGENOME_FRAME_OVER_BUDGET : KGENOME_FRAME_UNDECODABLE;
		goto fail;
	}
	out->mem_ = s->mem;
	out->state = KGENOME_FRAME_OK;
	if (s->facts)
		(void)kgenome_frame_facts(out, col.v);        /* a refusal leaves the memo to the first ask */
	if (flags & KGENOME_FRAME_KEEP_INSN) {
		out->in = col.v;
		out->in_bytes_ = (size_t)col.cap * sizeof *col.v;
	} else {
		if (col.cap)
			kgenome_cfg_release(mem, col.v, (size_t)col.cap * sizeof *col.v);     /* (a caller's decode is not ours to give back) */
	}
	return KGENOME_FRAME_OK;
fail:
	if (col.cap)
		kgenome_cfg_release(mem, col.v, (size_t)col.cap * sizeof *col.v);
	return (enum kgenome_frame_state)out->state;
}

void kgenome_frame_release(struct kgenome_frame *f, const struct kgenome_cfg_mem *mem)
{
	if (!f)
		return;
	kgenome_cfg_release(mem, f->in, f->in_bytes_);
	kgenome_cfg_release(mem, f->bits, f->bits_bytes_);
	kgenome_cfg_free(&f->cfg, mem);
	f->in = NULL;
	f->bits = NULL;
	f->in_bytes_ = f->bits_bytes_ = 0;
}

/* ---- the cache ---- */

struct kgenome_frame_cache {
	struct kgenome_frame **slot;    /* per table entry: its frame, or NULL until asked */
	uint32_t n;
	uint32_t built, hits, refused;
	uint64_t bytes, max_bytes;
	struct kgenome_cfg_mem mem;     /* the allocator every frame of the cache is charged to (given at creation: the cache outlives any one caller) */
	size_t slot_bytes;
};

struct kgenome_frame_cache *kgenome_frame_cache_new(const struct kgenome_cfg_mem *mem, uint64_t max_bytes)
{
	struct kgenome_frame_cache *c = calloc(1, sizeof *c);

	if (c && mem)
		c->mem = *mem;
	if (c)
		c->max_bytes = max_bytes ? max_bytes : KGENOME_FRAME_CACHE_MAX;
	return c;
}

static uint64_t frame_bytes(const struct kgenome_frame *f)
{
	return f->self_bytes_ + f->bits_bytes_ + f->in_bytes_ + (uint64_t)f->cfg.n_all * sizeof *f->cfg.b + (uint64_t)f->cfg.call_cap_ * sizeof *f->cfg.call;
}

const struct kgenome_frame *kgenome_frame_get(struct kgenome_frame_cache *c, const struct kgenome_frame_src *s, uint32_t fi)
{
	struct kgenome_frame *f;

	if (!c || !s || !s->fs || fi >= s->fs->n)
		return NULL;
	if (!c->slot) {
		c->slot_bytes = (size_t)s->fs->n * sizeof *c->slot;
		c->slot = kgenome_cfg_alloc(&c->mem, c->slot_bytes);
		if (!c->slot) {
			c->slot_bytes = 0;
			return NULL;
		}
		memset(c->slot, 0, c->slot_bytes);
		c->n = s->fs->n;
	}
	if (c->n != s->fs->n)
		return NULL;            /* a different table than the cache was made for: a caller's mistake, answered with nothing */
	if (c->slot[fi]) {
		c->hits++;
		return c->slot[fi];
	}
	/* the bound: a function of `len` bytes makes a frame of about twice that and a header; at the bound nothing is made here, the caller makes it for the one use */
	if (c->bytes + c->slot_bytes + 2u * s->fs->v[fi].len + sizeof *f > c->max_bytes) {
		c->refused++;
		return NULL;
	}
	f = kgenome_cfg_alloc(&c->mem, sizeof *f);
	if (!f)
		return NULL;
	{
		struct kgenome_frame_src own = *s;

		own.mem = c->mem;     /* the frames of a cache are all charged to the allocator it was made with */
		(void)kgenome_frame_make(&own, s->fs->v[fi].off, s->fs->v[fi].len, 0u, f);
	}
	f->fn = fi;
	f->self_bytes_ = sizeof *f;
	if (f->state == KGENOME_FRAME_NOMEM) {
		/* a refusal of memory is not an answer about the function: nothing is kept, the next ask tries again */
		kgenome_frame_release(f, &c->mem);
		kgenome_cfg_release(&c->mem, f, sizeof *f);
		return NULL;
	}
	c->slot[fi] = f;
	c->built++;
	c->bytes += frame_bytes(f);
	return f;
}

const struct kgenome_frame *kgenome_frame_of_extent(struct kgenome_frame_cache *c, const struct kgenome_frame_src *s, uint64_t off, uint64_t len,
						    struct kgenome_frame *own)
{
	if (c && s && s->fs) {
		const uint32_t fi = kgenome_funcs_start(s->fs, off);

		if (fi != KGENOME_FUNCS_NONE && s->fs->v[fi].len == len) {
			const struct kgenome_frame *f = kgenome_frame_get(c, s, fi);

			if (f)
				return f;               /* at the cache's bound (or a refused allocation) it is made below for the one use */
		}
	}
	(void)kgenome_frame_make(s, off, len, 0u, own);
	return own->state == KGENOME_FRAME_NOMEM ? NULL : own;
}

uint32_t kgenome_frame_cache_built(const struct kgenome_frame_cache *c)
{
	return c ? c->built : 0;
}

uint32_t kgenome_frame_cache_hits(const struct kgenome_frame_cache *c)
{
	return c ? c->hits : 0;
}

uint32_t kgenome_frame_cache_refused(const struct kgenome_frame_cache *c)
{
	return c ? c->refused : 0;
}

uint64_t kgenome_frame_cache_bytes(const struct kgenome_frame_cache *c)
{
	return c ? c->bytes + c->slot_bytes : 0;
}

void kgenome_frame_cache_free(struct kgenome_frame_cache *c)
{
	uint32_t i;

	if (!c)
		return;
	for (i = 0; c->slot && i < c->n; i++)
		if (c->slot[i]) {
			kgenome_frame_release(c->slot[i], &c->mem);
			kgenome_cfg_release(&c->mem, c->slot[i], sizeof *c->slot[i]);
		}
	kgenome_cfg_release(&c->mem, c->slot, c->slot_bytes);
	free(c);
}
