/*
 * codemap_decode_once - the codemap reads the object's code ONCE (owner, 2026-11-03: "Chi decode 1 lan ... khong thuc hien duplicate cong viec ke ca decode").
 *
 * kgenome_codemap_build decoded every byte of the code twice (its own read, then a second cursor pass for the syscall numbers: 2.05 decodes per
 * offset on Mirai.b, 2.00 on an ARM object). It now reads once, and asks the register model only over each syscall's straight run; with the object's
 * walk it reads the walk's trace and decodes nothing it holds. The seam is a link-time wrap of kgenome_cell_decode (UNIT_LIBS_codemap_decode_once in
 * mk/tests.mk): no counter in the production code. Why the old tests missed it: (c) api_codemap compares the table with a model and checks
 * no cost.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include <phenotype/diag_private.h>
#include <phenotype/codemap.h>
#include "../../libkofeng/analyzers/genome_obj.h"

uint32_t __real_kgenome_cell_decode(unsigned, int, const uint8_t *, uint32_t, uint64_t, struct kgenome_cell_insn *);

#define SZ   0x800u
#define CODE 0x78u

static uint64_t g_calls;
static uint8_t g_seen[0x800];
static const uint8_t *g_base;

static uint64_t g_ok_code;      /* decodes that produced an instruction at or past the first code byte */

uint32_t __wrap_kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out);

uint32_t __wrap_kgenome_cell_decode(unsigned arch, int be, const uint8_t *p, uint32_t n, uint64_t va, struct kgenome_cell_insn *out)
{
	uint32_t len;

	g_calls++;
	if (g_base && p >= g_base && p < g_base + sizeof g_seen && g_seen[p - g_base] < 255u)
		g_seen[p - g_base]++;
	len = __real_kgenome_cell_decode(arch, be, p, n, va, out);
	if (len && g_base && p >= g_base + CODE && p < g_base + sizeof g_seen)
		g_ok_code++;
	return len;
}

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

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


static void count_reset(void)
{
	g_calls = 0;
	g_ok_code = 0;
	memset(g_seen, 0, sizeof g_seen);
	g_base = img;
}

/* offsets decoded at least once, and the most any one offset was decoded */
static unsigned distinct(unsigned *most)
{
	unsigned i, d = 0;

	*most = 0;
	for (i = 0; i < sizeof g_seen; i++) {
		d += g_seen[i] != 0;
		if (g_seen[i] > *most)
			*most = g_seen[i];
	}
	return d;
}

int main(void)
{
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kgenome_diag_walk *wk;
	struct kgenome_func_set fs;
	struct kgenome_codemap a, b;
	struct kgenome_obj gobj;
	unsigned d, most, i, sys = 0, nr = 0;

	build();
	if (!parse(&ctx, view)) {
		printf("  FAIL the engine did not parse the image\n");
		return 1;
	}
	kof_genome_obj(&ctx, &gobj);

	/* A: no walk. One read of the code; a syscall's straight run is read again for the register model, a few instructions each. */
	count_reset();
	CK(kgenome_codemap_build(&gobj, img, SZ, NULL, NULL, &a) == 1);
	d = distinct(&most);
	printf("  no walk: %llu decodes over %u offsets (max %u at one offset)\n", (unsigned long long)g_calls, d, most);
	CK(d > 200u);
	CK(g_calls * 4u <= (uint64_t)d * 5u);           /* old code: 2.0 per offset */
	for (i = 0; i < a.n; i++)
		if (a.v[i].kind == KGENOME_CM_SYSCALL) {
			sys++;
			nr += (a.v[i].flags & KGENOME_CMF_NR) != 0;
		}
	CK(sys > 10u && nr > 0u);                       /* the fixture has syscalls whose number is known: the window still finds them */

	/* B: with the walk and its trace: the trace serves the read and the windows, nothing is decoded again. */
	wk = kgenome_diag_walk_new();
	memset(&fs, 0, sizeof fs);
	kgenome_diag_funcs_with_walk(&gobj, img, SZ, wk, &fs);
	count_reset();
	CK(kgenome_codemap_build(&gobj, img, SZ, NULL, wk, &b) == 1);
	printf("  with walk: %llu decodes, %llu of them an instruction in the code\n", (unsigned long long)g_calls, (unsigned long long)g_ok_code);
	CK(g_ok_code == 0u);                            /* what the trace holds is not decoded again; bytes that do not decode are tried once */
	CK(a.n == b.n && a.n_to == b.n_to && !memcmp(a.v, b.v, (size_t)a.n * sizeof *a.v));
	kgenome_codemap_free(&a);
	kgenome_codemap_free(&b);
	kgenome_funcs_free(&fs);
	kgenome_diag_walk_free(wk);
	if (fails)
		printf("codemap_decode_once: %d failure(s)\n", fails);
	else
		printf("codemap_decode_once: ok\n");
	return fails != 0;
}
