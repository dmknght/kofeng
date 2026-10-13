/*
 * fnprint_kit.h - what the fnprint_*.c tests build their objects from.
 *
 * A function is x86-64 machine code generated from a seed: the same seed is the
 * same sequence of instructions, and the VARIANTS (the displacement of its call,
 * of its RIP-relative load, its large immediate) are the operand fields the
 * fingerprint must not see. An object is functions laid end to end in a flat
 * buffer (virtual address == file offset), so a test places the same function at
 * two positions, pads between functions, collapses a zero run, and adds a static
 * library's worth of identical functions, all in memory.
 */
#ifndef KGENOME_TESTS_FNPRINT_KIT_H
#define KGENOME_TESTS_FNPRINT_KIT_H

#include <kgenome.h>

#include "hk.h"

struct fk_var {
	int32_t  call_disp;     /* rel32 of its `call` */
	int32_t  rip_disp;      /* disp32 of its `lea rdi,[rip+...]` */
	uint32_t big_imm;       /* the immediate of `mov rdi, imm32` that is large */
};

struct fk_obj {
	uint8_t  *b;
	uint64_t  n, cap;
	struct kgenome_func *v;
	uint32_t  nf, capf;
};

static void fk_init(struct fk_obj *o) HK_UNUSED;
static void fk_init(struct fk_obj *o)
{
	memset(o, 0, sizeof *o);
}

static void fk_free(struct fk_obj *o) HK_UNUSED;
static void fk_free(struct fk_obj *o)
{
	free(o->b);
	free(o->v);
	memset(o, 0, sizeof *o);
}

static void fk_room(struct fk_obj *o, uint64_t add)
{
	if (o->n + add > o->cap) {
		uint64_t nc = o->cap ? o->cap : 4096;

		while (nc < o->n + add)
			nc *= 2;
		o->b = realloc(o->b, nc);
		o->cap = nc;
	}
}

/* Append bytes (not a function). */
static void fk_raw(struct fk_obj *o, const void *p, uint64_t n) HK_UNUSED;
static void fk_raw(struct fk_obj *o, const void *p, uint64_t n)
{
	fk_room(o, n);
	memcpy(o->b + o->n, p, n);
	o->n += n;
}

static void fk_fill(struct fk_obj *o, uint8_t byte, uint64_t n) HK_UNUSED;
static void fk_fill(struct fk_obj *o, uint8_t byte, uint64_t n)
{
	fk_room(o, n);
	memset(o->b + o->n, byte, n);
	o->n += n;
}

/* Register the bytes [off, off+len) as a function. */
static void fk_mark(struct fk_obj *o, uint64_t off, uint64_t len) HK_UNUSED;
static void fk_mark(struct fk_obj *o, uint64_t off, uint64_t len)
{
	if (o->nf == o->capf) {
		o->capf = o->capf ? o->capf * 2u : 64u;
		o->v = realloc(o->v, (size_t)o->capf * sizeof *o->v);
	}
	memset(&o->v[o->nf], 0, sizeof o->v[0]);
	o->v[o->nf].off = off;
	o->v[o->nf].len = len;
	o->nf++;
}

/* The code of function `seed`, `nins` template instructions, into out; returns its length. */
static uint32_t fk_code(uint8_t *out, uint32_t seed, uint32_t nins, const struct fk_var *vr) HK_UNUSED;
static uint32_t fk_code(uint8_t *out, uint32_t seed, uint32_t nins, const struct fk_var *vr)
{
	struct hk_rng r = { 0x9e3779b97f4a7c15ull ^ ((uint64_t)seed * 0x100000001b3ull) };
	uint32_t n = 0, k;
	static const uint8_t pro[] = { 0x55, 0x48, 0x89, 0xe5 };

	memcpy(out, pro, 4);
	n = 4;
	for (k = 0; k < nins; k++) {
		uint32_t t = hk_below(&r, 13), a = hk_below(&r, 120) + 1u, w = (uint32_t)hk_next(&r);

		switch (t) {
		case 0: out[n++] = 0xb8; memcpy(out + n, &w, 4); n += 4; break;
		case 11: out[n++] = 0x05; memcpy(out + n, &w, 4); n += 4; break;
		case 12: out[n++] = 0x3d; memcpy(out + n, &w, 4); n += 4; break;
		case 1: out[n++] = 0x83; out[n++] = 0xc0; out[n++] = (uint8_t)a; break;
		case 2: out[n++] = 0x89; out[n++] = 0x7d; out[n++] = (uint8_t)(0x100 - (a & 0x7f) - 1); break;
		case 3: out[n++] = 0x8b; out[n++] = 0x7d; out[n++] = (uint8_t)(0x100 - (a & 0x7f) - 1); break;
		case 4: out[n++] = 0x31; out[n++] = 0xc0; break;
		case 5: out[n++] = 0x83; out[n++] = 0xf8; out[n++] = (uint8_t)a;
			out[n++] = 0x74; out[n++] = 0x03;
			out[n++] = 0x83; out[n++] = 0xc0; out[n++] = 0x01; break;
		case 6: out[n++] = 0xe8; memcpy(out + n, &vr->call_disp, 4); n += 4; break;
		case 7: out[n++] = 0x48; out[n++] = 0x8d; out[n++] = 0x3d;
			memcpy(out + n, &vr->rip_disp, 4); n += 4; break;
		case 8: out[n++] = 0x48; out[n++] = 0xc7; out[n++] = 0xc7;
			memcpy(out + n, &vr->big_imm, 4); n += 4; break;
		case 9: out[n++] = 0x48; out[n++] = 0x83; out[n++] = 0xec; out[n++] = (uint8_t)(a & 0x7f); break;
		default: out[n++] = 0x6b; out[n++] = 0xc0; out[n++] = (uint8_t)a; break;
		}
	}
	out[n++] = 0x5d;
	out[n++] = 0xc3;
	return n;
}

/* Append function `seed` and register it; returns its offset. */
static uint64_t fk_func(struct fk_obj *o, uint32_t seed, uint32_t nins, const struct fk_var *vr) HK_UNUSED;
static uint64_t fk_func(struct fk_obj *o, uint32_t seed, uint32_t nins, const struct fk_var *vr)
{
	uint8_t code[2048];
	uint64_t at = o->n;
	uint32_t n = fk_code(code, seed, nins < 200 ? nins : 200, vr);

	fk_raw(o, code, n);
	fk_mark(o, at, n);
	return at;
}

/*
 * A caller: `n` `call rel32` to places not known yet, then ret. site[i] is the offset of the i-th rel32 and
 * fk_call_to patches it once the target exists. How a test says "main calls these": the program reaches its code.
 */
static uint64_t fk_stub(struct fk_obj *o, uint32_t n, uint64_t *site) HK_UNUSED;
static uint64_t fk_stub(struct fk_obj *o, uint32_t n, uint64_t *site)
{
	uint64_t at = o->n;
	uint32_t i;
	static const uint8_t c[5] = { 0xe8, 0, 0, 0, 0 };

	for (i = 0; i < n; i++) {
		site[i] = o->n + 1;
		fk_raw(o, c, 5);
	}
	fk_fill(o, 0xc3, 1);
	fk_mark(o, at, o->n - at);
	return at;
}

static void fk_call_to(struct fk_obj *o, uint64_t site, uint64_t target) HK_UNUSED;
static void fk_call_to(struct fk_obj *o, uint64_t site, uint64_t target)
{
	int32_t d = (int32_t)((int64_t)target - (int64_t)(site + 4));

	memcpy(o->b + site, &d, 4);
}

/* A syscall wrapper: mov eax, nr; syscall; ret. */
static uint64_t fk_wrapper(struct fk_obj *o, uint32_t nr) HK_UNUSED;
static uint64_t fk_wrapper(struct fk_obj *o, uint32_t nr)
{
	uint8_t c[8] = { 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0xc3 };
	uint64_t at = o->n;

	memcpy(c + 1, &nr, 4);
	fk_raw(o, c, 8);
	fk_mark(o, at, 8);
	return at;
}

/*
 * The entry stub of a static program: it hands `main_off` to the runtime in rdi
 * (RIP-relative LEA) and calls it - the shape the entry probe reads.
 */
static uint64_t fk_entry(struct fk_obj *o, uint64_t main_off) HK_UNUSED;
static uint64_t fk_entry(struct fk_obj *o, uint64_t main_off)
{
	uint8_t c[13] = { 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xf4 };
	uint64_t at = o->n;
	int32_t d = (int32_t)((int64_t)main_off - (int64_t)(at + 7));

	memcpy(c + 3, &d, 4);
	fk_raw(o, c, 13);
	fk_mark(o, at, 13);
	return at;
}

/* The request for an object, with the defaults a test wants. */
static void fk_req(struct kgenome_fnprint_req *rq, const struct fk_obj *o, enum kgenome_fnprint_link link,
		   struct kgenome_fnprint_stat *st, struct kgenome_func_set *fs) HK_UNUSED;
static void fk_req(struct kgenome_fnprint_req *rq, const struct fk_obj *o, enum kgenome_fnprint_link link,
		   struct kgenome_fnprint_stat *st, struct kgenome_func_set *fs)
{
	memset(rq, 0, sizeof *rq);
	fs->v = o->v;
	fs->n = o->nf;
	fs->status = KGENOME_OK;
	rq->p = o->b;
	rq->n = o->n;
	rq->arch = KGENOME_ARCH_X86_64;
	rq->funcs = fs;
	rq->entry_off = KGENOME_BROKEN;
	rq->link = link;
	rq->stat = st;
}

#endif /* KGENOME_TESTS_FNPRINT_KIT_H */
