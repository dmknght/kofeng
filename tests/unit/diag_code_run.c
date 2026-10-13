/*
 * diag_code_run - the instructions of a run are the same whether they come from
 * the walk's trace or from the decoder.
 *
 * kgenome_diag_code_run is the one reader of an object's instructions that the xref
 * sweep consumes, and its contract is that the observer cannot tell where an
 * instruction came from. A linear sweep is alignment sensitive, so "the same"
 * has to hold where it is easiest to break: a run that starts off the trace's
 * alignment, a run whose window ends inside an instruction, a section whose
 * address is not the one its segment gives it, and bytes that do not decode.
 *
 * Every case reads the same bytes twice - once with no walk (every instruction
 * decoded) and once with a walk that holds a trace - and the two streams must be
 * equal field for field in everything an observer reads.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include <phenotype/diag_private.h>
#include "../../libkofeng/analyzers/genome_obj.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define SZ   0x800u
#define CODE 0x78u

static uint8_t img[SZ];

static void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}

/* An ELF64 header and one RWX PT_LOAD from offset zero, then a deterministic
 * mixture of the shapes the xref sweep reads (an address into a register, an
 * indirect call, a direct call, a store to a local), a syscall, a ret, and
 * bytes that do not decode in 64-bit mode (0x06 is `push es`). */
static void build(void)
{
	static const uint8_t lea[] = { 0x48, 0x8d, 0x05, 0x10, 0x01, 0x00, 0x00 };
	static const uint8_t calr[] = { 0xff, 0xd0 };
	static const uint8_t cal[] = { 0xe8, 0x40, 0x00, 0x00, 0x00 };
	static const uint8_t jmp[] = { 0xe9, 0xf0, 0xff, 0xff, 0xff };
	static const uint8_t st[] = { 0x48, 0x89, 0x45, 0xf8 };
	static const uint8_t ld[] = { 0x48, 0x8b, 0x45, 0xf8 };
	static const uint8_t sys[] = { 0x0f, 0x05 };
	static const uint8_t ret[] = { 0xc3 };
	static const uint8_t bad[] = { 0x06 };
	static const uint8_t mov[] = { 0xb8, 0x39, 0x00, 0x00, 0x00 };
	static const struct { const uint8_t *p; unsigned n; } t[] = {
		{ lea, sizeof lea }, { calr, sizeof calr }, { cal, sizeof cal },
		{ jmp, sizeof jmp }, { st, sizeof st }, { ld, sizeof ld },
		{ sys, sizeof sys }, { ret, sizeof ret }, { bad, sizeof bad },
		{ mov, sizeof mov },
	};
	unsigned at = CODE, seed = 12345u;

	memset(img, 0, sizeof img);
	memcpy(img, "\177ELF\2\1\1", 7);
	img[16] = 2;
	img[18] = 0x3e;
	img[20] = 1;
	put64(img, 24, 0x400000u + CODE);       /* e_entry */
	put64(img, 32, 64);                     /* e_phoff */
	img[52] = 64;
	img[54] = 56;
	img[56] = 1;
	img[64] = 1;                            /* PT_LOAD */
	img[68] = 7;                            /* RWX */
	put64(img, 80, 0x400000u);
	put64(img, 96, SZ);
	put64(img, 104, SZ);
	while (at < SZ - 8u) {
		unsigned k;

		seed = seed * 1103515245u + 12345u;
		k = (seed >> 16) % (sizeof t / sizeof t[0]);
		memcpy(img + at, t[k].p, t[k].n);
		at += t[k].n;
	}
}

struct rec {
	uint64_t at_va, target_va, wmask;
	uint8_t  len, op, n_op, flags;
	uint8_t  kind[3], reg[3], index[3], oflags[3];
	int64_t  v[3];
};

static struct rec out[SZ + 8];
static unsigned n_out;

static void obs(void *user, const struct kgenome_cell_insn *in)
{
	struct rec *r = &out[n_out++];
	unsigned i;

	(void)user;
	memset(r, 0, sizeof *r);
	if (!in)
		return;                         /* len 0 is the marker */
	r->at_va = in->at_va;
	r->target_va = in->target_va;
	r->wmask = in->wmask & 0xffffu;
	r->len = in->len;
	r->op = in->op;
	r->n_op = in->n_op;
	r->flags = in->flags;
	for (i = 0; i < in->n_op && i < 3u; i++) {
		r->kind[i] = in->o[i].kind;
		r->reg[i] = in->o[i].reg;
		r->index[i] = in->o[i].index;
		r->oflags[i] = in->o[i].flags;
		r->v[i] = in->o[i].kind == KGENOME_CELL_O_MEM ? in->o[i].disp
			: (int64_t)in->o[i].imm;
	}
}

static int parse(struct kof_obj_ctx *ctx, void *view)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	buf.p = img;
	buf.n = SZ;
	memset(ctx, 0, sizeof *ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, ctx))
			return 1;
	return 0;
}

static unsigned run(struct kgenome_diag_walk *wk, const struct kof_obj_ctx *ctx,
		    uint64_t off, uint64_t n, uint64_t va,
		    struct kgenome_diag_code_run_stats *st, struct rec *keep)
{
	struct kgenome_obj gobj;

	n_out = 0;
	memset(st, 0, sizeof *st);
	kof_genome_obj(ctx, &gobj);
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
			.wk = wk,
			.obj = &gobj,
			.base = img,
			.size = SZ,
			.off = off,
			.n = n,
			.va = va,
			.fn = obs,
			.user = NULL,
			.st = st,
		});
	if (keep)
		memcpy(keep, out, n_out * sizeof *out);
	return n_out;
}

/* One case: the same run with and without the trace. */
static void same(const char *tag, struct kgenome_diag_walk *wk,
		 const struct kof_obj_ctx *ctx, uint64_t off, uint64_t n,
		 uint64_t va, int want_trace_use)
{
	static struct rec a[SZ + 8];
	struct kgenome_diag_code_run_stats sa, sb;
	unsigned na = run(NULL, ctx, off, n, va, &sa, a);
	unsigned nb = run(wk, ctx, off, n, va, &sb, NULL);
	unsigned i, bad = 0;

	if (na != nb) {
		printf("  FAIL %s: %u observations decoded, %u with a trace\n",
		       tag, na, nb);
		fails++;
		return;
	}
	for (i = 0; i < na; i++)
		if (memcmp(&a[i], &out[i], sizeof a[i]))
			bad++;
	if (bad) {
		printf("  FAIL %s: %u of %u observations differ\n", tag, bad, na);
		fails++;
	}
	if (sa.from_trace || sa.decoded + sa.skipped != na) {
		printf("  FAIL %s: no walk but the counts say %llu/%llu/%llu of %u\n",
		       tag, (unsigned long long)sa.from_trace,
		       (unsigned long long)sa.decoded,
		       (unsigned long long)sa.skipped, na);
		fails++;
	}
	if (want_trace_use && !sb.from_trace) {
		printf("  FAIL %s: the trace served nothing\n", tag);
		fails++;
	}
	if (!want_trace_use && sb.from_trace) {
		printf("  FAIL %s: the trace served %llu instructions it must not\n",
		       tag, (unsigned long long)sb.from_trace);
		fails++;
	}
	if (!na) {
		printf("  FAIL %s: nothing was read\n", tag);
		fails++;
	}
}

int main(void)
{
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kgenome_diag_walk *wk;
	struct kgenome_diag_code_run_stats st;
	struct kgenome_obj gobj;
	uint64_t va0 = 0x400000u + CODE;

	build();
	if (!parse(&ctx, view)) {
		printf("  FAIL the engine did not parse the image\n");
		return 1;
	}
	wk = kgenome_diag_walk_new();
	CK(wk != NULL);
	kof_genome_obj(&ctx, &gobj);
	CK(kgenome_diag_walk_ensure(wk, &gobj, img, SZ, 1));

	/* The whole segment past the headers, aligned with the walk's start. */
	same("aligned", wk, &ctx, CODE, SZ - CODE, va0, 1);
	/* Off the alignment the walk made: decoded afresh until the two coincide. */
	same("misaligned by one", wk, &ctx, CODE + 1u, SZ - CODE - 1u, va0 + 1u, 1);
	same("misaligned by three", wk, &ctx, CODE + 3u, 300, va0 + 3u, 1);
	/* A window that ends inside an instruction: it does not decode there. */
	same("window ends mid-instruction", wk, &ctx, CODE, 301, va0, 1);
	same("window of one byte", wk, &ctx, CODE, 1, va0, 0);
	/* A section that claims an address its segment does not give: the trace
	 * decoded these bytes for another address, so none of it is taken. */
	same("forged address", wk, &ctx, CODE, SZ - CODE, va0 + 0x10u, 0);
	/* A run that starts before the walk did: the header bytes are decoded, the
	 * rest comes from the trace once the alignments meet. */
	same("starts in the headers", wk, &ctx, 0x40, SZ - 0x40, 0x400040u, 1);
	/* A run that starts past the end reads nothing and says nothing. */
	CK(run(wk, &ctx, SZ, 16, 0x400000u + SZ, &st, NULL) == 0);
	/* The observer is told about every byte it stepped over. */
	{
		unsigned i, gaps = 0;

		run(NULL, &ctx, CODE, SZ - CODE, va0, &st, NULL);
		for (i = 0; i < n_out; i++)
			gaps += out[i].len == 0;
		CK(gaps == st.skipped);
		CK(gaps > 0);           /* the image does contain bytes that do not decode */
	}
	kgenome_diag_walk_free(wk);
	if (fails)
		printf("diag code run: %d FAILED\n", fails);
	else
		printf("diag code run: aligned, misaligned, cut window, forged address, headers - ok\n");
	return fails != 0;
}
