/*
 * x86_equiv - the x86 / x86-64 decode path, new against frozen.
 *
 * A DEV TOOL, NOT A TEST. The reference is the decoder as it was BEFORE the
 * speed work on genotype/x86 and decode_x86.c, copied out of the tree with every
 * external symbol renamed (ref_gt_x86_*, ref_cell_decode_x86; the macros and
 * enums too, so both headers can be included here). The new pipeline is what is
 * in the tree. Both decode the same bytes and the answers are compared:
 *
 *   gt_x86_decode      status, len, id, and what the public accessors say about
 *                      the instruction (nops, cat, cond, nexp, nform, wgpr, osz,
 *                      asz, efop, mand, repeated); and gt_x86_operand for EVERY
 *                      operand, field by field (the emulator and the cross-
 *                      reference pass read those);
 *   cell_decode_x86    the return value and every field of struct cell_insn -
 *                      op, len, n_op, cond, flags, wmask, at, at_va, target,
 *                      target_va, and for each of the three operands kind, reg,
 *                      index, scale, size, flags, seg, disp, imm. The padding is
 *                      not defined and is not compared. The `size` and `scale`
 *                      of an operand whose kind is NONE are not defined either
 *                      (the frozen adapter left them as it found them in the
 *                      caller's struct), so they are compared only when
 *                      -s is given - which is a statement about the
 *                      frozen code's leftovers, not about a result;
 *   gt_x86_format      the text, on one decode in 16 (it is the slow part, and
 *                      it reads every field of the decoded struct).
 *
 * Build by hand (the reference is in the scratch directory, not in the tree).
 * The first four .o are the frozen files compiled once with
 *   gcc -O2 -w -I$K/libgenome -I$K/libgenome/genotype -I$K/libkofeng/kofcore -I. -c
 * in /mnt/games/kofscratch/x86ref:
 *
 *   K=<tree>; R=/mnt/games/kofscratch/x86ref
 *   gcc -O2 -w -std=gnu11 -pthread -I$K/libkofeng/kofcore -I$K/libgenome \
 *       -I$K/libgenome/genotype -I$K/libgenome/celllysis -I/mnt/games/kofscratch \
 *       $K/tools/celllysis/x86_equiv.c $R/x86.o $R/x86_tab.o $R/x86_fmt.o \
 *       $R/decode_x86.o $K/libgenome/genotype/x86/x86.c \
 *       $K/libgenome/genotype/x86/x86_tab.c $K/libgenome/genotype/x86/x86_fmt.c \
 *       $K/libgenome/celllysis/decode_x86.c -o x86_equiv
 *
 *   x86_equiv [-s] [-j N] blobs <va> <blob>...   every byte offset of each file named
 *                                         NNNNN.BITS.bin, at address va+offset
 *   x86_equiv [-j N] rand <millions> [seed]
 *                                         generated encodings (see gen()), both
 *                                         modes, random address
 *   x86_equiv bench <blob>...             ns per decode, frozen and new
 *
 * Exit status 0 only when there were no differences.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kofmod/cell.h"
#include "celllysis/celllysis.h"
#include "celllysis/decode.h"
#include <x86/x86.h>
#include "x86ref/x86.h"
#include "x86ref/ref_cursor.h"

uint32_t ref_cell_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			     unsigned bits, struct cell_insn *out);

static int g_strict, g_walk = 1;

struct stat_ {
	uint64_t n, bad, shown;
	uint64_t ok_dec;
};

static void hex(const uint8_t *p, unsigned n, char *out)
{
	unsigned i;

	for (i = 0; i < n; i++)
		sprintf(out + 3 * i, "%02x ", p[i]);
}

#define D(fmt, ...) do { if (st->shown < 12) { char hb[64]; hex(p, n < 16 ? n : 16, hb); \
	fprintf(stderr, "DIFF %db va=%" PRIx64 " n=%u [%s] " fmt "\n", bits, va, n, hb, __VA_ARGS__); } \
	bad++; } while (0)

static int cmp_op(const struct gt_x86_op *a, const struct ref_gt_x86_op *b)
{
	return a->type != b->type || a->enc != b->enc || a->acc != b->acc || a->flags != b->flags ||
	       a->size != b->size || a->rtype != b->rtype || a->rsize != b->rsize ||
	       a->reg != b->reg || a->high8 != b->high8 || a->seg != b->seg || a->base != b->base ||
	       a->index != b->index || a->scale != b->scale || a->bsz != b->bsz ||
	       a->isz != b->isz || a->rawsize != b->rawsize || a->count != b->count ||
	       a->elem != b->elem || a->mf != b->mf || a->sel != b->sel || a->v != b->v;
}

static int cmp_insn(const struct cell_insn *a, const struct cell_insn *b, const char **what)
{
	unsigned k;

#define C(f) do { if (a->f != b->f) { *what = #f; return 1; } } while (0)
	C(op); C(len); C(n_op); C(cond); C(flags); C(wmask); C(at); C(at_va);
	C(target); C(target_va);
	for (k = 0; k < 3; k++) {
		const struct cell_operand *x = &a->o[k], *y = &b->o[k];

		if (x->kind != y->kind) { *what = "o.kind"; return 1; }
		if (x->reg != y->reg) { *what = "o.reg"; return 1; }
		if (x->index != y->index) { *what = "o.index"; return 1; }
		if (x->flags != y->flags) { *what = "o.flags"; return 1; }
		if (x->seg != y->seg) { *what = "o.seg"; return 1; }
		if (x->disp != y->disp) { *what = "o.disp"; return 1; }
		if (x->imm != y->imm) { *what = "o.imm"; return 1; }
		if (x->kind != CELL_O_NONE || g_strict) {
			if (x->size != y->size) { *what = "o.size"; return 1; }
			if (x->scale != y->scale) { *what = "o.scale"; return 1; }
		}
	}
#undef C
	return 0;
}

/* One decode, everything compared. Returns the number of differences. */
static unsigned one(struct stat_ *st, const uint8_t *p, unsigned n, uint64_t va, unsigned bits,
		    int text)
{
	struct gt_x86_insn nx;
	struct ref_gt_x86_insn rx;
	struct cell_insn a, b;
	uint32_t la, lb;
	enum gt_status sa, sb;
	unsigned bad = 0;

	st->n++;
	sa = gt_x86_decode(&nx, p, n, (int)bits);
	sb = ref_gt_x86_decode(&rx, p, n, (int)bits);
	if (sa != sb) {
		D("status %d vs ref %d", sa, sb);
	} else if (sa == GT_OK) {
		unsigned k, nops;

		st->ok_dec++;
		if (nx.id != rx.id || nx.len != rx.len) {
			D("id/len %u/%u vs ref %u/%u", nx.id, nx.len, rx.id, rx.len);
		} else {
			if (gt_x86_nops(&nx) != ref_gt_x86_nops(&rx) || gt_x86_cat(&nx) != ref_gt_x86_cat(&rx) ||
			    gt_x86_cond(&nx) != ref_gt_x86_cond(&rx) || gt_x86_nexp(&nx) != ref_gt_x86_nexp(&rx) ||
			    gt_x86_nform(&nx) != ref_gt_x86_nform(&rx) || gt_x86_wgpr(&nx) != ref_gt_x86_wgpr(&rx) ||
			    gt_x86_osz(&nx) != ref_gt_x86_osz(&rx) || gt_x86_asz(&nx) != ref_gt_x86_asz(&rx) ||
			    gt_x86_efop(&nx) != ref_gt_x86_efop(&rx) || gt_x86_mand(&nx) != ref_gt_x86_mand(&rx) ||
			    gt_x86_repeated(&nx) != ref_gt_x86_repeated(&rx)) {
				D("accessors id=%u", nx.id);
			} else {
				nops = gt_x86_nops(&nx);
				for (k = 0; k < nops; k++) {
					struct gt_x86_op oa;
					struct ref_gt_x86_op ob;

					gt_x86_operand(&nx, k, &oa);
					ref_gt_x86_operand(&rx, k, &ob);
					if (cmp_op(&oa, &ob)) {
						D("operand %u id=%u", k, nx.id);
						break;
					}
				}
			}
			if (text) {
				char ta[GT_X86_TEXT], tb[REF_GT_X86_TEXT];
				size_t xa = gt_x86_format(&nx, va, ta, sizeof ta);
				size_t xb = ref_gt_x86_format(&rx, va, tb, sizeof tb);

				if (xa != xb || memcmp(ta, tb, xa))
					D("text '%s' vs ref '%s'", ta, tb);
			}
		}
	}

	memset(&a, 0xA5, sizeof a);
	memset(&b, 0xA5, sizeof b);
	la = cell_decode_x86(p, n, va, bits, &a);
	lb = ref_cell_decode_x86(p, n, va, bits, &b);
	if (la != lb) {
		D("cell ret %u vs ref %u", la, lb);
	} else if (la) {
		const char *w = "";

		if (cmp_insn(&a, &b, &w))
			D("cell_insn field %s", w);
	}
	if (bad)
		st->shown++;
	st->bad += bad;
	return bad;
}

/* ---- the cursor ----------------------------------------------------------- */

static int seg_at(void *priv, uint64_t off, struct cell_seg *o)
{
	(void)off;
	o->lo = 0;
	o->hi = (uint64_t)-1;
	o->delta = (int64_t)(uint64_t)(uintptr_t)priv;
	return 1;
}

static uint64_t off_of_va(void *priv, uint64_t va)
{
	return va - (uint64_t)(uintptr_t)priv;
}

/*
 * The whole file walked by kof_cell_next (or kof_cell_step) beside the frozen
 * cursor and frozen constant map, an undecodable byte skipped by one: every
 * instruction, the return value, the cursor and the register/stack state are
 * compared after each step.
 */
static unsigned walk_one(struct stat_ *st, const uint8_t *buf, size_t sz, unsigned bits,
			 uint64_t vabase, int step)
{
	struct cell_space sp = { buf, sz, bits == 64 ? KOF_ARCH_X86_64 : KOF_ARCH_X86, 0,
				 (void *)(uintptr_t)vabase, seg_at, off_of_va };
	struct kof_cell_cur a;
	struct ref_kof_cell_cur b;
	unsigned bad = 0, n = 0;
	const uint8_t *p = buf;

	memset(&a, 0, sizeof a);
	memset(&b, 0, sizeof b);
	kof_cell_seek(&a, 0, 0);
	ref_kof_cell_seek(&b, 0, 0);
	while (a.at < sz) {
		struct cell_insn ia, ib;
		int ra, rb;
		const char *w = "";

		memset(&ia, 0xA5, sizeof ia);
		memset(&ib, 0xA5, sizeof ib);
		ra = step ? kof_cell_step(&a, &sp, &ia) : kof_cell_next(&a, &sp, &ia);
		rb = step ? ref_kof_cell_step(&b, &sp, &ib) : ref_kof_cell_next(&b, &sp, &ib);
		st->n++;
		if (ra != rb || a.at != b.at) {
			if (st->shown++ < 12)
				fprintf(stderr, "WALK DIFF ret %d vs %d at %" PRIu64 "/%" PRIu64 "\n", ra, rb, a.at, b.at);
			st->bad++;
			bad++;
			return bad;
		}
		if (ra) {
			if (cmp_insn(&ia, &ib, &w)) {
				if (st->shown++ < 12)
					fprintf(stderr, "WALK DIFF field %s at %" PRIu64 " bits %u\n", w, a.at, bits);
				st->bad++;
				bad++;
			}
			if (!step && (memcmp(a.st.reg, b.st.reg, sizeof a.st.reg) || a.st.known != b.st.known ||
				      memcmp(a.st.stk, b.st.stk, sizeof a.st.stk) || a.st.stk_known != b.st.stk_known ||
				      a.st.stk_n != b.st.stk_n)) {
				if (st->shown++ < 12)
					fprintf(stderr, "WALK DIFF state at %" PRIu64 " op %u bits %u\n", a.at, ia.op, bits);
				st->bad++;
				bad++;
				/* the states have parted; resynchronise so one cause is one count */
				memcpy(&b.st, &a.st, sizeof a.st);
			}
		} else {
			a.at++;
			b.at++;
		}
		n++;
		(void)p;
	}
	return bad;
}

/* ---- blobs -------------------------------------------------------------- */

static int run_blob(struct stat_ *st, const char *path, uint64_t vabase)
{
	const char *base = strrchr(path, '/');
	unsigned k, bits;
	FILE *f;
	long sz;
	uint8_t *buf;
	size_t i;

	base = base ? base + 1 : path;
	if (sscanf(base, "%u.%u.bin", &k, &bits) != 2 || (bits != 32 && bits != 64))
		return 0;
	f = fopen(path, "rb");
	if (!f)
		return -1;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)sz + 32);
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		free(buf);
		return -1;
	}
	fclose(f);
	for (i = 0; i < (size_t)sz; i++) {
		size_t left = (size_t)sz - i;

		one(st, buf + i, left > 16 ? 16 : (unsigned)left, vabase + i, bits, (i & 15) == 0);
	}
	if (g_walk) {
		walk_one(st, buf, (size_t)sz, bits, vabase, 0);
		walk_one(st, buf, (size_t)sz, bits, vabase, 1);
	}
	free(buf);
	return 1;
}

/* The file list is shared: each thread takes the next unclaimed one. */
static char **g_files;
static int g_nf, g_next;
static uint64_t g_va;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static void *blob_thread(void *arg)
{
	struct stat_ *st = arg;

	for (;;) {
		int i;

		pthread_mutex_lock(&g_mu);
		i = g_next++;
		pthread_mutex_unlock(&g_mu);
		if (i >= g_nf)
			break;
		run_blob(st, g_files[i], g_va);
	}
	return NULL;
}

/* ---- generated encodings ------------------------------------------------- */

struct rng {
	uint64_t s;
};

static uint64_t rnd(struct rng *r)
{
	uint64_t x = r->s;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return r->s = x;
}

static unsigned rn(struct rng *r, unsigned n)
{
	return (unsigned)((rnd(r) >> 11) % n);
}

static const uint8_t PFX[] = { 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3 };

/*
 * What is generated, by a roll: pure random bytes; a prefix soup (legacy prefixes
 * and a REX in any order and number) in front of a one-byte, 0F, 0F 38 or 0F 3A
 * opcode; or an extended-prefix form - VEX2, VEX3, EVEX, XOP, and the stray 8F, D5
 * - with a payload that is random in all its bits (so every map, pp, L, W, vvvv,
 * R'X'B', aaa, z, b is reached) in front of an opcode. The tail is random, with
 * ModRM mod/rm biased to reach disp8, disp32, SIB and the 16-bit forms. Bytes the
 * decoder never reads are random too, so nothing depends on them.
 */
static unsigned gen(struct rng *r, uint8_t *b)
{
	unsigned i = 0, roll = rn(r, 16), n, k;

	memset(b, 0, 32);
	if (roll < 2) {
		for (k = 0; k < 16; k++)
			b[k] = (uint8_t)rnd(r);
	} else {
		unsigned np = rn(r, 4) ? rn(r, 4) : rn(r, 9);

		for (k = 0; k < np; k++) {
			unsigned c = rn(r, 14);

			b[i++] = c < 11 ? PFX[c] : (uint8_t)(0x40 + rn(r, 16));
		}
		if (roll < 9) {
			unsigned m = rn(r, 8);

			if (m == 0) {
				b[i++] = 0x0f;
				b[i++] = (uint8_t)rnd(r);
			} else if (m == 1) {
				b[i++] = 0x0f;
				b[i++] = rn(r, 2) ? 0x38 : 0x3a;
				b[i++] = (uint8_t)rnd(r);
			} else if (m == 2) {
				b[i++] = 0x0f;
				b[i++] = 0x0f;
			} else {
				b[i++] = (uint8_t)rnd(r);
			}
		} else {
			static const uint8_t X[] = { 0xc4, 0xc5, 0x62, 0x8f, 0xd5, 0xc4, 0xc5, 0x62, 0x8f };

			b[i++] = X[rn(r, 9)];
			k = rn(r, 3) + 1;
			while (k--)
				b[i++] = (uint8_t)rnd(r);
			b[i++] = (uint8_t)rnd(r);
		}
		/* ModRM and what follows, with the interesting mods */
		k = rn(r, 4);
		if (k < 3) {
			static const uint8_t MOD[] = { 0x00, 0x40, 0x80, 0xc0, 0x04, 0x44, 0x84, 0x05, 0x06, 0x45, 0x85 };

			b[i] = (uint8_t)(MOD[rn(r, 11)] | (rnd(r) & 0x3b));
			if (rn(r, 4) == 0)
				b[i] = (uint8_t)rnd(r);
			i++;
		}
		while (i < 16)
			b[i++] = (uint8_t)rnd(r);
	}
	/* How many bytes the caller has: all 16 mostly, else any shorter. */
	n = rn(r, 3) ? 16 : 1 + rn(r, 16);
	return n;
}

struct rjob {
	uint64_t count, seed;
	int id;
	struct stat_ st;
};

static void *rand_thread(void *arg)
{
	struct rjob *j = arg;
	struct rng r = { j->seed * 0x9e3779b97f4a7c15ull + 0x1234567ull };
	uint64_t i;

	rnd(&r);
	rnd(&r);
	for (i = 0; i < j->count; i++) {
		uint8_t b[32];
		unsigned n = gen(&r, b), bits = (rnd(&r) & 1) ? 64 : 32;
		uint64_t va = rn(&r, 4) ? rnd(&r) : (rnd(&r) & 0xfffffull) | 0xfffffffffff00000ull;

		one(&j->st, b, n, va, bits, (i & 15) == 0);
	}
	return NULL;
}

/* ---- timing --------------------------------------------------------------- */

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static int bench(int argc, char **argv)
{
	int a;

	for (a = 0; a < argc; a++) {
		const char *base = strrchr(argv[a], '/');
		unsigned k, bits;
		FILE *f;
		long sz;
		uint8_t *buf;
		size_t i;
		double t0, ta, tb;
		uint64_t ni = 0, sink = 0;
		struct cell_insn in;
		int rep;

		base = base ? base + 1 : argv[a];
		if (sscanf(base, "%u.%u.bin", &k, &bits) != 2)
			continue;
		f = fopen(argv[a], "rb");
		if (!f)
			continue;
		fseek(f, 0, SEEK_END);
		sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		buf = malloc((size_t)sz + 32);
		if (fread(buf, 1, (size_t)sz, f) != (size_t)sz)
			return 1;
		fclose(f);
		ta = tb = 1e9;
		for (rep = 0; rep < 3; rep++) {
			t0 = now();
			for (i = 0, ni = 0; i < (size_t)sz; ni++) {
				size_t left = (size_t)sz - i;
				uint32_t l = cell_decode_x86(buf + i, left > 16 ? 16 : (uint32_t)left, 0x400000 + i, bits, &in);

				sink += l;
				i += l ? l : 1;
			}
			if (now() - t0 < ta)
				ta = now() - t0;
			t0 = now();
			for (i = 0; i < (size_t)sz;) {
				size_t left = (size_t)sz - i;
				uint32_t l = ref_cell_decode_x86(buf + i, left > 16 ? 16 : (uint32_t)left, 0x400000 + i, bits, &in);

				sink += l;
				i += l ? l : 1;
			}
			if (now() - t0 < tb)
				tb = now() - t0;
		}
		printf("%s: new %.1f ns/insn, frozen %.1f ns/insn (%" PRIu64 " insn) %" PRIu64 "\n", base,
		       ta * 1e9 / (double)ni, tb * 1e9 / (double)ni, ni, sink & 1);
		free(buf);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int nth = 8, t;
	pthread_t th[64];
	uint64_t n = 0, bad = 0, okd = 0;

	/* options first: -s compares size/scale of absent operands too, -j N threads */
	while (argc > 2 && argv[1][0] == '-') {
		if (!strcmp(argv[1], "-s")) {
			g_strict = 1;
			argc--, argv++;
		} else if (!strcmp(argv[1], "-j") && argc > 3) {
			nth = atoi(argv[2]);
			if (nth < 1 || nth > 64)
				nth = 8;
			argc -= 2, argv += 2;
		} else {
			break;
		}
	}
	if (argc >= 3 && !strcmp(argv[1], "blobs")) {
		struct stat_ st[64];

		memset(st, 0, sizeof st);
		g_files = argv + 3;
		g_nf = argc - 3;
		g_va = strtoull(argv[2], NULL, 0);
		for (t = 0; t < nth; t++)
			pthread_create(&th[t], NULL, blob_thread, &st[t]);
		for (t = 0; t < nth; t++) {
			pthread_join(th[t], NULL);
			n += st[t].n;
			bad += st[t].bad;
			okd += st[t].ok_dec;
		}
		printf("blobs va=%s: %" PRIu64 " offsets (%" PRIu64 " decode), %" PRIu64 " differences\n",
		       argv[2], n, okd, bad);
		return bad != 0;
	}
	if (argc >= 3 && !strcmp(argv[1], "rand")) {
		struct rjob job[64];
		uint64_t millions = strtoull(argv[2], NULL, 0), seed = argc > 3 ? strtoull(argv[3], NULL, 0) : 1;

		for (t = 0; t < nth; t++) {
			job[t] = (struct rjob){ millions * 1000000ull / (uint64_t)nth, seed * 1000 + (uint64_t)t, t, { 0, 0, 0, 0 } };
			pthread_create(&th[t], NULL, rand_thread, &job[t]);
		}
		for (t = 0; t < nth; t++) {
			pthread_join(th[t], NULL);
			n += job[t].st.n;
			bad += job[t].st.bad;
			okd += job[t].st.ok_dec;
		}
		printf("rand seed=%" PRIu64 ": %" PRIu64 " encodings (%" PRIu64 " decode), %" PRIu64 " differences\n",
		       seed, n, okd, bad);
		return bad != 0;
	}
	if (argc >= 3 && !strcmp(argv[1], "bench"))
		return bench(argc - 2, argv + 2);
	fprintf(stderr, "usage: x86_equiv [-s] [-j N] blobs <va> <file>... | rand <millions> [seed] | bench <file>...\n");
	return 2;
}
