/*
 * cfg_kit.h - the shared kit of the cfg_*.c tests of libgenome (celllysis/cfg.h).
 *
 * Header only; every helper is static and unused ones are quiet. Nothing here is a stored binary: the functions
 * the tests analyse are ASSEMBLED AT RUN TIME from an abstract program (nops, jumps, conditional branches,
 * calls, ret, indirect jumps, loops, a syscall) into the bytes of each architecture, DECODED by the lib's own
 * decoder (kgenome_cell_decode, once) and handed to kgenome_cfg_build. Inert code; nothing malware-shaped.
 *
 * Three things in here are ORACLES and are written without the lib's cfg code:
 *   ref_build   the blocks of an abstract program by the textbook rule (leader = entry, target, instruction after a
 *               terminator), on the abstract ops, with no decoder in the way
 *   ref_sign    the signature the SLOW way: every label exact (a string, not a hash) for the partition tests, and
 *               the sorted-multiset hash of the survey's harness for the sketch
 *   the objdump parser of cfg_oracle.c (not here) - a third, external one for x86
 */
#ifndef KGENOME_TESTS_CFG_KIT_H
#define KGENOME_TESTS_CFG_KIT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <kgenome.h>
#include <celllysis/cfg_private.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CK_UNUSED __attribute__((unused))

static CK_UNUSED int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define CKM(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

/* ---- a fixed-seed generator ---- */
struct crng { uint64_t s; };
static CK_UNUSED void crng_seed(struct crng *r, uint64_t seed) { r->s = seed * 0x9e3779b97f4a7c15ull + 0x1234567ull; if (!r->s) r->s = 1; }
static CK_UNUSED uint64_t crng_next(struct crng *r)
{
	uint64_t x = r->s;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	r->s = x;
	return x * 0x2545f4914f6cdd1dull;
}
static CK_UNUSED uint32_t crng_below(struct crng *r, uint32_t n) { return n ? (uint32_t)(crng_next(r) >> 33) % n : 0u; }

/* ---- the abstract program ---- */
enum {
	O_NOP, O_JMP, O_JCC, O_CALL, O_RET, O_IJMP, O_UD, O_LOOP, O_SYS,
	O_CRET,         /* ARM: bx lr under a condition */
	O_B,            /* MIPS: beq $0,$0 */
	O_BAL           /* MIPS: bgezal $0, a call that is spelt as a branch */
};
#define OUT 0xffffffffu         /* a target outside the function */

struct op { uint8_t kind; uint32_t tgt; };
struct prog { struct op *op; uint32_t n; };

static CK_UNUSED void prog_add(struct prog *p, uint8_t kind, uint32_t tgt)
{
	p->op = realloc(p->op, (size_t)(p->n + 1u) * sizeof *p->op);
	p->op[p->n].kind = kind;
	p->op[p->n].tgt = tgt;
	p->n++;
}
static CK_UNUSED void prog_free(struct prog *p) { free(p->op); p->op = NULL; p->n = 0; }

struct isa_t { unsigned arch; int be; const char *name; };
static const struct isa_t ISAS[] = {
	{ KGENOME_ARCH_X86_64, 0, "x86-64" }, { KGENOME_ARCH_X86, 0, "i386" },
	{ KGENOME_ARCH_ARM, 0, "arm32" },     { KGENOME_ARCH_ARM64, 0, "aarch64" },
	{ KGENOME_ARCH_MIPS, 0, "mips-le" },  { KGENOME_ARCH_MIPS, 1, "mips-be" },
};
#define N_ISAS (sizeof ISAS / sizeof ISAS[0])

static CK_UNUSED int isa_is_mips(const struct isa_t *i) { return i->arch == KGENOME_ARCH_MIPS || i->arch == KGENOME_ARCH_MIPS64; }
static CK_UNUSED int isa_is_x86(const struct isa_t *i) { return i->arch == KGENOME_ARCH_X86 || i->arch == KGENOME_ARCH_X86_64; }

/* The assembled function. */
struct blob {
	uint8_t *b;
	uint32_t len;
	uint64_t va0;
	uint32_t *va_of_op;     /* n ops: the address of each */
	uint32_t *insn_of_op;   /* the instruction index of each op */
	uint32_t n_insn;
};
static CK_UNUSED void blob_free(struct blob *x) { free(x->b); free(x->va_of_op); free(x->insn_of_op); memset(x, 0, sizeof *x); }

static CK_UNUSED int op_has_slot(const struct isa_t *isa, uint8_t k)
{
	if (!isa_is_mips(isa))
		return 0;
	return k == O_JMP || k == O_JCC || k == O_RET || k == O_IJMP || k == O_LOOP || k == O_B || k == O_BAL;
}

static CK_UNUSED uint32_t op_size(const struct isa_t *isa, uint8_t k)
{
	if (isa_is_x86(isa)) {
		switch (k) {
		case O_JMP: case O_CALL: return 5;
		case O_JCC: return 6;
		case O_IJMP: case O_UD: case O_LOOP: case O_SYS: return 2;
		default: return 1;      /* NOP, RET */
		}
	}
	return 4u + (op_has_slot(isa, k) ? 4u : 0u);
}

static CK_UNUSED void put32(const struct isa_t *isa, uint8_t *p, uint32_t w)
{
	if (isa->be) {
		p[0] = (uint8_t)(w >> 24); p[1] = (uint8_t)(w >> 16); p[2] = (uint8_t)(w >> 8); p[3] = (uint8_t)w;
	} else {
		p[3] = (uint8_t)(w >> 24); p[2] = (uint8_t)(w >> 16); p[1] = (uint8_t)(w >> 8); p[0] = (uint8_t)w;
	}
}

/* An address far outside every function of the tests, for a call and for a jump that leaves. */
#define FAR_VA 0x8000u

/*
 * Assemble `p` for `isa` at `va0`. Returns 0 for a program the architecture cannot spell (UD on ARM...).
 * `slot` is the one-word instruction placed in each delay slot (0 = nop); a test may put something else there.
 */
static CK_UNUSED int blob_make(const struct isa_t *isa, const struct prog *p, uint64_t va0, struct blob *out)
{
	uint32_t i, at = 0;
	uint8_t *q;

	memset(out, 0, sizeof *out);
	out->va_of_op = malloc((size_t)(p->n + 1u) * sizeof(uint32_t));
	out->insn_of_op = malloc((size_t)(p->n + 1u) * sizeof(uint32_t));
	out->va0 = va0;
	for (i = 0; i < p->n; i++) {
		const uint8_t k = p->op[i].kind;

		if (isa_is_x86(isa) ? (k == O_CRET || k == O_B || k == O_BAL) :
		    isa_is_mips(isa) ? (k == O_UD || k == O_LOOP || k == O_CRET) :
		    (k == O_UD || k == O_LOOP || k == O_B || k == O_BAL || (k == O_CRET && isa->arch != KGENOME_ARCH_ARM))) {
			blob_free(out);
			return 0;
		}
		out->va_of_op[i] = at;
		at += op_size(isa, k);
	}
	out->va_of_op[p->n] = at;
	out->len = at;
	out->b = calloc(at ? at : 1u, 1);
	for (i = 0, q = out->b; i < p->n; i++) {
		const uint8_t k = p->op[i].kind;
		const uint64_t va = va0 + out->va_of_op[i];
		const uint64_t tva = p->op[i].tgt == OUT ? FAR_VA + va0 : va0 + out->va_of_op[p->op[i].tgt];
		const int64_t rel = (int64_t)tva - (int64_t)va;
		uint8_t *w = q + out->va_of_op[i];

		if (isa_is_x86(isa)) {
			switch (k) {
			case O_NOP: w[0] = 0x90; break;
			case O_RET: w[0] = 0xc3; break;
			case O_JMP: w[0] = 0xe9; { int32_t d = (int32_t)(rel - 5); memcpy(w + 1, &d, 4); } break;
			case O_CALL: w[0] = 0xe8; { int32_t d = (int32_t)(rel - 5); memcpy(w + 1, &d, 4); } break;
			case O_JCC: w[0] = 0x0f; w[1] = 0x85; { int32_t d = (int32_t)(rel - 6); memcpy(w + 2, &d, 4); } break;
			case O_IJMP: w[0] = 0xff; w[1] = 0xe0; break;
			case O_UD: w[0] = 0x0f; w[1] = 0x0b; break;
			case O_LOOP: w[0] = 0xe2; w[1] = (uint8_t)(int8_t)(rel - 2); break;
			case O_SYS: if (isa->arch == KGENOME_ARCH_X86) { w[0] = 0xcd; w[1] = 0x80; } else { w[0] = 0x0f; w[1] = 0x05; } break;
			}
		} else if (isa->arch == KGENOME_ARCH_ARM) {
			const uint32_t i24 = (uint32_t)((rel - 8) >> 2) & 0xffffffu;

			switch (k) {
			case O_NOP: put32(isa, w, 0xe1a00000u); break;
			case O_JMP: put32(isa, w, 0xea000000u | i24); break;
			case O_JCC: put32(isa, w, 0x1a000000u | i24); break;
			case O_CALL: put32(isa, w, 0xeb000000u | i24); break;
			case O_RET: put32(isa, w, 0xe12fff1eu); break;
			case O_CRET: put32(isa, w, 0x012fff1eu); break;
			case O_IJMP: put32(isa, w, 0xe12fff11u); break;
			case O_SYS: put32(isa, w, 0xef000000u); break;
			}
		} else if (isa->arch == KGENOME_ARCH_ARM64) {
			const uint32_t i26 = (uint32_t)(rel >> 2) & 0x3ffffffu, i19 = (uint32_t)(rel >> 2) & 0x7ffffu;

			switch (k) {
			case O_NOP: put32(isa, w, 0xd503201fu); break;
			case O_JMP: put32(isa, w, 0x14000000u | i26); break;
			case O_JCC: put32(isa, w, 0x54000001u | (i19 << 5)); break;
			case O_CALL: put32(isa, w, 0x94000000u | i26); break;
			case O_RET: put32(isa, w, 0xd65f03c0u); break;
			case O_IJMP: put32(isa, w, 0xd61f0020u); break;
			case O_SYS: put32(isa, w, 0xd4000001u); break;
			}
		} else {
			const uint32_t off = (uint32_t)((rel - 4) >> 2) & 0xffffu;

			switch (k) {
			case O_NOP: put32(isa, w, 0); break;
			case O_JMP: put32(isa, w, 0x08000000u | (uint32_t)((tva >> 2) & 0x3ffffffu)); break;
			case O_JCC: put32(isa, w, 0x14200000u | off); break;
			case O_B: put32(isa, w, 0x10000000u | off); break;
			case O_BAL: put32(isa, w, 0x04110000u | off); break;
			case O_CALL: put32(isa, w, 0x0c000000u | (uint32_t)((tva >> 2) & 0x3ffffffu)); break;
			case O_RET: put32(isa, w, 0x03e00008u); break;
			case O_IJMP: put32(isa, w, 0x03200008u); break;
			case O_SYS: put32(isa, w, 0x0000000cu); break;
			}
			/* the delay slot is left as the nop word the calloc made */
		}
	}
	return 1;
}

/* Decode every instruction of the blob once. Returns the count, or 0 when a byte does not decode. */
static CK_UNUSED uint32_t blob_decode(const struct isa_t *isa, struct blob *x, struct kgenome_cell_insn **out)
{
	uint32_t pos = 0, n = 0, cap = x->len + 1u;
	struct kgenome_cell_insn *v = calloc(cap, sizeof *v);

	while (pos < x->len) {
		const uint32_t l = kgenome_cell_decode(isa->arch, isa->be, x->b + pos, x->len - pos, x->va0 + pos, &v[n]);

		if (!l) {
			free(v);
			*out = NULL;
			return 0;
		}
		v[n].at = pos;          /* the decoder writes the address into `at`; a caller's `at` is the OFFSET in the object */
		n++;
		pos += l;
	}
	*out = v;
	return n;
}

/* op -> instruction index, from the decoded array (both are in address order) */
static CK_UNUSED void blob_map_ops(const struct prog *p, struct blob *x, const struct kgenome_cell_insn *in, uint32_t n)
{
	uint32_t i, k = 0;

	for (i = 0; i < p->n; i++) {
		while (k < n && in[k].at_va < x->va0 + x->va_of_op[i])
			k++;
		x->insn_of_op[i] = k;
	}
	x->insn_of_op[p->n] = n;
	x->n_insn = n;
}

/* One call that builds the graph of a blob; `*in` is the decoded array (free it). */
static CK_UNUSED enum kgenome_status blob_cfg(const struct isa_t *isa, const struct prog *p, struct blob *x,
					      struct kgenome_cell_insn **in, struct kgenome_cfg *g)
{
	uint32_t n = blob_decode(isa, x, in);
	struct kgenome_cfg_req rq;

	memset(&rq, 0, sizeof rq);
	if (!n)
		return KGENOME_BAD_INPUT;
	blob_map_ops(p, x, *in, n);
	rq.in = *in; rq.n_in = n; rq.arch = isa->arch; rq.be = isa->be;
	rq.va_lo = x->va0; rq.va_hi = x->va0 + x->len; rq.bytes = x->b; rq.bytes_len = x->len;
	return kgenome_cfg_build(&rq, g);
}

/* ---- the reference blocks, on the abstract program (no decoder, no lib cfg) ---- */
struct refg {
	uint32_t nb;
	uint32_t *first_op;     /* nb: the first op of each block */
	uint8_t  *term;         /* enum kgenome_cfg_term */
	uint32_t (*succ)[2];
	uint8_t  *reach;
	uint32_t n_blk, n_edge;
};
static CK_UNUSED void refg_free(struct refg *r) { free(r->first_op); free(r->term); free(r->succ); free(r->reach); memset(r, 0, sizeof *r); }

static CK_UNUSED int op_is_term(const struct isa_t *isa, const struct op *o)
{
	(void)isa;
	switch (o->kind) {
	case O_JCC: case O_LOOP: return o->tgt != OUT;  /* a conditional branch out of the function is not a block end */
	case O_JMP: case O_RET: case O_IJMP: case O_UD: case O_CRET: case O_B: return 1;
	default: return 0;
	}
}

static CK_UNUSED void ref_build(const struct isa_t *isa, const struct prog *p, struct refg *r)
{
	uint8_t *lead = calloc(p->n + 1u, 1);
	uint32_t *blk_of = malloc((size_t)(p->n + 1u) * sizeof *blk_of), i, b, n_st = 0, *stk;

	memset(r, 0, sizeof *r);
	if (!p->n) {
		free(lead);
		free(blk_of);
		return;
	}
	lead[0] = 1;
	for (i = 0; i < p->n; i++) {
		const struct op *o = &p->op[i];

		if (op_is_term(isa, o) && i + 1u < p->n)
			lead[i + 1u] = 1;
		if ((o->kind == O_JMP || o->kind == O_JCC || o->kind == O_LOOP || o->kind == O_B) && o->tgt != OUT)
			lead[o->tgt] = 1;
	}
	for (i = 0; i < p->n; i++) {
		if (lead[i])
			r->nb++;
		blk_of[i] = r->nb - 1u;
	}
	r->first_op = malloc((size_t)r->nb * sizeof *r->first_op);
	r->term = calloc(r->nb, 1);
	r->succ = malloc((size_t)r->nb * sizeof *r->succ);
	r->reach = calloc(r->nb, 1);
	for (i = 0, b = 0; i < p->n; i++)
		if (lead[i])
			r->first_op[b++] = i;
	for (b = 0; b < r->nb; b++) {
		const uint32_t last_op = (b + 1u < r->nb ? r->first_op[b + 1u] : p->n) - 1u;
		const struct op *o = &p->op[last_op];
		const uint32_t next = b + 1u < r->nb ? b + 1u : KGENOME_CFG_NONE;

		r->succ[b][0] = r->succ[b][1] = KGENOME_CFG_NONE;
		r->term[b] = KGENOME_CFG_T_FALL;
		if (!op_is_term(isa, o) || o->kind == O_CRET) {
			r->succ[b][0] = next;
			continue;
		}
		switch (o->kind) {
		case O_JCC: case O_LOOP:
			r->term[b] = KGENOME_CFG_T_COND;
			r->succ[b][0] = blk_of[o->tgt];
			r->succ[b][1] = next;
			break;
		case O_JMP: case O_B:
			if (o->tgt == OUT) {
				r->term[b] = KGENOME_CFG_T_EXIT;
			} else {
				r->term[b] = KGENOME_CFG_T_JUMP;
				r->succ[b][0] = blk_of[o->tgt];
			}
			break;
		default:
			r->term[b] = KGENOME_CFG_T_EXIT;
			break;
		}
	}
	stk = malloc((size_t)r->nb * sizeof *stk);
	r->reach[0] = 1;
	stk[n_st++] = 0;
	while (n_st) {
		const uint32_t x = stk[--n_st];
		unsigned e;

		for (e = 0; e < 2u; e++) {
			const uint32_t s = r->succ[x][e];

			if (s == KGENOME_CFG_NONE)
				continue;
			r->n_edge++;
			if (!r->reach[s]) {
				r->reach[s] = 1;
				stk[n_st++] = s;
			}
		}
	}
	for (b = 0; b < r->nb; b++)
		r->n_blk += r->reach[b];
	free(stk);
	free(lead);
	free(blk_of);
}

/* Does the lib's graph equal the reference's? Block by block: instruction index of the first op, terminator, successors, reach. */
static CK_UNUSED int cfg_equals_ref(const struct kgenome_cfg *g, const struct refg *r, const struct blob *x, const char *tag)
{
	uint32_t b;
	int ok = 1;

	if (g->n_all != r->nb || g->n_blk != r->n_blk || g->n_edge != r->n_edge) {
		printf("  %s: n_all %u/%u n_blk %u/%u n_edge %u/%u\n", tag, g->n_all, r->nb, g->n_blk, r->n_blk, g->n_edge, r->n_edge);
		return 0;
	}
	for (b = 0; b < r->nb && ok; b++) {
		const struct kgenome_cfg_block *k = &g->b[b];

		const uint32_t f0 = x->insn_of_op[r->first_op[b]];
		const uint32_t f1 = b + 1u < r->nb ? x->insn_of_op[r->first_op[b + 1u]] : x->n_insn;

		if (k->first != f0 || k->n_insn != f1 - f0 || k->term != r->term[b] || k->succ[0] != r->succ[b][0] ||
		    k->succ[1] != r->succ[b][1] || k->reach != r->reach[b]) {
			printf("  %s: block %u first %u/%u term %u/%u succ %u,%u/%u,%u reach %u/%u\n", tag, b, k->first,
			       x->insn_of_op[r->first_op[b]], k->term, r->term[b], k->succ[0], k->succ[1], r->succ[b][0],
			       r->succ[b][1], k->reach, r->reach[b]);
			ok = 0;
		}
	}
	return ok;
}

/* ---- the reference signature (slow, sorted, exact) ---- */
static CK_UNUSED uint64_t rmix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	h *= 0xff51afd7ed558ccdull;
	return h ^ (h >> 33);
}
static CK_UNUSED int rcmp64(const void *a, const void *b)
{
	const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}
static CK_UNUSED int rcmp32(const void *a, const void *b)
{
	const uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

struct refsig {
	uint64_t canon;                 /* the survey's sorted fold */
	uint32_t n_key, key[KGENOME_CFG_KEYS];
	uint32_t n_el;                  /* elements before the sketch (= reachable blocks) */
	uint32_t *el;                   /* all n_el elements, sorted, with repeats of equal u32 kept */
};

/* The survey harness' algorithm on the reference graph: degrees over reachable edges, label = (in, out, term), `rounds` WL rounds, sort the
 * labels, fold, pair each label with its occurrence index, take the 32 smallest distinct high words. */
static CK_UNUSED void ref_sign(const struct refg *g, unsigned rounds, struct refsig *s)
{
	uint32_t b, i, *indeg = calloc(g->nb, sizeof *indeg), nr = 0, run = 0, m = 0;
	uint64_t *cur = calloc(g->nb, sizeof *cur), *nxt = calloc(g->nb, sizeof *nxt), *sp = calloc(g->nb, sizeof *sp), *ss = calloc(g->nb, sizeof *ss);
	uint64_t *lab, h;

	memset(s, 0, sizeof *s);
	for (b = 0; b < g->nb; b++)
		if (g->reach[b])
			for (i = 0; i < 2; i++)
				if (g->succ[b][i] != KGENOME_CFG_NONE)
					indeg[g->succ[b][i]]++;
	for (b = 0; b < g->nb; b++) {
		unsigned od = (g->succ[b][0] != KGENOME_CFG_NONE) + (g->succ[b][1] != KGENOME_CFG_NONE);

		if (!g->reach[b])
			continue;
		cur[b] = rmix(rmix(rmix(7u, indeg[b]), od), g->term[b]);
	}
	while (rounds--) {
		memset(sp, 0, g->nb * sizeof *sp);
		memset(ss, 0, g->nb * sizeof *ss);
		for (b = 0; b < g->nb; b++)
			if (g->reach[b])
				for (i = 0; i < 2; i++) {
					const uint32_t t = g->succ[b][i];

					if (t == KGENOME_CFG_NONE)
						continue;
					ss[b] += rmix(cur[t], 2u);
					sp[t] += rmix(cur[b], 1u);
				}
		for (b = 0; b < g->nb; b++)
			if (g->reach[b])
				nxt[b] = rmix(rmix(cur[b], sp[b]), ss[b]);
		memcpy(cur, nxt, g->nb * sizeof *cur);
	}
	lab = malloc((size_t)(g->n_blk ? g->n_blk : 1u) * sizeof *lab);
	for (b = 0; b < g->nb; b++)
		if (g->reach[b])
			lab[nr++] = cur[b];
	qsort(lab, nr, sizeof *lab, rcmp64);
	h = rmix(rmix(0x5151u, g->n_blk), g->n_edge);
	for (i = 0; i < nr; i++)
		h = rmix(h, lab[i]);
	s->canon = h;
	s->el = malloc((size_t)(nr ? nr : 1u) * sizeof *s->el);
	for (i = 0; i < nr; i++) {
		run = i && lab[i] == lab[i - 1u] ? run + 1u : 0u;
		s->el[i] = (uint32_t)(rmix(rmix(KGENOME_CFG_KEY_SEED, lab[i]), run) >> 32);   /* the domain-separated element (cfg.h) */
	}
	qsort(s->el, nr, sizeof *s->el, rcmp32);
	s->n_el = nr;
	for (i = 0; i < nr && m < KGENOME_CFG_KEYS; i++)
		if (!i || s->el[i] != s->el[i - 1u])
			s->key[m++] = s->el[i];
	s->n_key = m;
	free(indeg); free(cur); free(nxt); free(sp); free(ss); free(lab);
}
static CK_UNUSED void refsig_free(struct refsig *s) { free(s->el); memset(s, 0, sizeof *s); }

/* The exact Jaccard (in percent, double) of the two multisets of u32 elements, repeats counted as distinct occurrences. */
static CK_UNUSED double ref_jaccard(const struct refsig *a, const struct refsig *b)
{
	uint32_t i = 0, j = 0, in = 0, u;

	while (i < a->n_el && j < b->n_el) {
		if (a->el[i] == b->el[j]) { in++; i++; j++; }
		else if (a->el[i] < b->el[j]) i++;
		else j++;
	}
	u = a->n_el + b->n_el - in;
	return u ? 100.0 * in / u : 100.0;
}

/* ---- helpers to sign a graph ---- */
static CK_UNUSED enum kgenome_status sign_of(const struct kgenome_cfg *g, unsigned rounds, struct kgenome_cfg_sign *s)
{
	struct kgenome_cfg_sign_req rq;

	memset(&rq, 0, sizeof rq);
	rq.g = g;
	rq.rounds = (uint8_t)rounds;
	return kgenome_cfg_sign(&rq, s);
}

static CK_UNUSED int sign_eq(const struct kgenome_cfg_sign *a, const struct kgenome_cfg_sign *b)
{
	return a->canon == b->canon && a->n_key == b->n_key && a->n_blk == b->n_blk &&
	       !memcmp(a->key, b->key, a->n_key * sizeof *a->key);
}

/* A counting allocator that can be told to refuse the Nth allocation. */
struct counting {
	uint32_t n_alloc, n_free, fail_at;      /* fail_at 0 = never; 1 = the first */
	int64_t  live;
	uint64_t peak;
};
static CK_UNUSED void *cnt_alloc(void *u, size_t n)
{
	struct counting *c = u;
	void *p;

	c->n_alloc++;
	if (c->fail_at && c->n_alloc == c->fail_at)
		return NULL;
	p = malloc(n);
	if (p) {
		c->live += (int64_t)n;
		if ((uint64_t)c->live > c->peak)
			c->peak = (uint64_t)c->live;
	}
	return p;
}
static CK_UNUSED void cnt_release(void *u, void *p, size_t n)
{
	struct counting *c = u;

	c->n_free++;
	c->live -= (int64_t)n;
	free(p);
}
#define COUNTING_MEM(c) { cnt_alloc, cnt_release, (c) }

static CK_UNUSED double now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* ---- random abstract programs ---- */
static CK_UNUSED void prog_random(const struct isa_t *isa, struct crng *r, uint32_t n, struct prog *p)
{
	uint32_t i;

	memset(p, 0, sizeof *p);
	for (i = 0; i < n; i++) {
		const uint32_t roll = crng_below(r, 100);
		uint32_t tgt = crng_below(r, 10) == 0 ? OUT : crng_below(r, n);
		uint8_t k;

		if (roll < 40) k = O_NOP;
		else if (roll < 55) k = O_JCC;
		else if (roll < 65) k = O_JMP;
		else if (roll < 75) k = O_CALL;
		else if (roll < 83) k = O_RET;
		else if (roll < 86) k = O_IJMP;
		else if (roll < 88) k = O_SYS;
		else if (roll < 91 && isa_is_mips(isa)) k = O_B;
		else if (roll < 93 && isa->arch == KGENOME_ARCH_ARM) k = O_CRET;
		else if (roll < 95 && isa_is_x86(isa)) k = O_UD;
		else k = O_NOP;
		prog_add(p, k, tgt);
	}
}

/* ---- block-structured programs: the graph IS the test input ---- */
/*
 * A graph of `nb` blocks, layout-valid: block i is [nop] then a terminator chosen by `kind[i]`:
 *   G_EXIT  ret            G_FALL  (nothing: falls into block i+1)
 *   G_JUMP  jmp t          G_COND  jcc t, falling into block i+1
 */
enum { G_EXIT, G_FALL, G_JUMP, G_COND };
struct gspec { uint32_t nb; uint8_t kind[64]; uint32_t t[64]; uint8_t pad[64]; uint8_t calls[64]; };

/* `pad` extra nops and `calls` calls go in front of the terminator: they change addresses and sizes, never the shape. */
static CK_UNUSED void gspec_prog(const struct gspec *g, struct prog *p, uint32_t *first_op)
{
	uint32_t b, i, at = 0, *start = malloc((size_t)(g->nb + 1u) * sizeof *start);

	memset(p, 0, sizeof *p);
	for (b = 0; b < g->nb; b++) {
		start[b] = at;
		at += 1u + g->pad[b] + g->calls[b] + (g->kind[b] == G_FALL ? 0u : 1u);
	}
	start[g->nb] = at;
	for (b = 0; b < g->nb; b++) {
		if (first_op)
			first_op[b] = start[b];
		prog_add(p, O_NOP, 0);
		for (i = 0; i < g->pad[b]; i++)
			prog_add(p, O_NOP, 0);
		for (i = 0; i < g->calls[b]; i++)
			prog_add(p, O_CALL, OUT);
		switch (g->kind[b]) {
		case G_EXIT: prog_add(p, O_RET, 0); break;
		case G_JUMP: prog_add(p, O_JMP, start[g->t[b]]); break;
		case G_COND: prog_add(p, O_JCC, start[g->t[b]]); break;
		default: break;
		}
	}
	free(start);
}


/* ---- the graph spec: build the lib's graph + signature of a gspec through the assembler and the decoder ---- */

/* Assemble `g` for `isa` at `va0`, decode, build, sign. Returns 0 when the architecture cannot spell it. */
static CK_UNUSED int gspec_sign(const struct isa_t *isa, const struct gspec *g, uint64_t va0, unsigned rounds, struct kgenome_cfg_sign *s,
				struct kgenome_cfg *keep)
{
	struct prog p;
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg c;
	enum kgenome_status st;

	gspec_prog(g, &p, NULL);
	if (!blob_make(isa, &p, va0, &x)) {
		prog_free(&p);
		return 0;
	}
	st = blob_cfg(isa, &p, &x, &in, &c);
	if (st != KGENOME_OK) {
		printf("  gspec_sign: build status %d\n", (int)st);
		fails++;
	}
	st = sign_of(&c, rounds, s);
	if (st != KGENOME_OK) {
		printf("  gspec_sign: sign status %d\n", (int)st);
		fails++;
	}
	if (keep)
		*keep = c;
	else
		kgenome_cfg_free(&c, NULL);
	free(in);
	blob_free(&x);
	prog_free(&p);
	return 1;
}

/* The reference graph of a gspec, straight from the spec (no assembler, no decoder). */
static CK_UNUSED void gspec_ref(const struct gspec *g, struct refg *r)
{
	uint32_t b, n_st = 0, stk[64];

	memset(r, 0, sizeof *r);
	r->nb = g->nb;
	r->first_op = calloc(g->nb, sizeof *r->first_op);
	r->term = calloc(g->nb, 1);
	r->succ = calloc(g->nb, sizeof *r->succ);
	r->reach = calloc(g->nb, 1);
	for (b = 0; b < g->nb; b++) {
		const uint32_t next = b + 1u < g->nb ? b + 1u : KGENOME_CFG_NONE;

		r->succ[b][0] = r->succ[b][1] = KGENOME_CFG_NONE;
		switch (g->kind[b]) {
		case G_EXIT: r->term[b] = KGENOME_CFG_T_EXIT; break;
		case G_FALL: r->term[b] = KGENOME_CFG_T_FALL; r->succ[b][0] = next; break;
		case G_JUMP: r->term[b] = KGENOME_CFG_T_JUMP; r->succ[b][0] = g->t[b]; break;
		default: r->term[b] = KGENOME_CFG_T_COND; r->succ[b][0] = g->t[b]; r->succ[b][1] = next; break;
		}
	}
	r->reach[0] = 1;
	stk[n_st++] = 0;
	while (n_st) {
		const uint32_t x = stk[--n_st];
		unsigned e;

		for (e = 0; e < 2u; e++) {
			const uint32_t s = r->succ[x][e];

			if (s == KGENOME_CFG_NONE)
				continue;
			r->n_edge++;
			if (!r->reach[s]) {
				r->reach[s] = 1;
				stk[n_st++] = s;
			}
		}
	}
	for (b = 0; b < g->nb; b++)
		r->n_blk += r->reach[b];
}

#endif /* KGENOME_TESTS_CFG_KIT_H */
