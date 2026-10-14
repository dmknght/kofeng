/*
 * decode_held - the decode of an object's code is made ONCE and every reader of it is
 * answered from that one decode.
 *
 * THE PRODUCT. The diagnose walk decodes every instruction of the executable segments of an
 * x86 or x86-64 ELF and keeps what it decoded as a packed trace (diag_wrapper_walk.c). The
 * syscall sweep reads windows of the same code through a celllysis cursor, and used to
 * decode every instruction of them again - MEASURED over 254 static ELF, 5.08 M of the
 * 66.6 M decode calls were that. A cursor whose space carries `held`
 * (kgenome_diag_walk_hold) is answered from the trace where the walk decoded that very offset,
 * and by the decoder everywhere else.
 *
 * WHAT IS HELD TO. The answer must be the decoder's, not close to it. So every case below
 * reads the SAME offsets twice, through a space with no `held` and through one with it, and
 * compares every field of the instruction and the result of the call:
 *
 *   - every offset of the object, not only the ones the walk landed on: an offset in the
 *     middle of an instruction (overlapping instructions, a jump into the middle of one)
 *     is not in the trace and must come out as the decoder's reading of those bytes;
 *   - bytes that do not decode, 15-byte prefix soup, an instruction cut by the end of the
 *     object, random bytes (data in code);
 *   - x86 and x86-64: a record is one mode's, and a walk of the other mode is refused;
 *   - an object whose code changed: a walk made of other bytes is refused, so a normalised
 *     view (same size, other bytes, other address) is never answered from its parent's trace;
 *   - a walk made without a trace, and a trace cut at its cap (a 50 MB .text): what is past
 *     the cut is decoded, what is before it is held, and both are exact.
 *
 * And the end result: the diagnose scan's nodes are the same with and without the trace,
 * and the trace answered what the sweep asked (the counter says so). The comparison also runs over every
 * offset of the executable segments of this test's own binary: real compiler output.
 *
 * Linked against libkgenome.a alone; builds its objects in memory.
 */

#include <kgenome.h>
#include <phenotype/diag_private.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* ---- the object: one ELF, one RWX PT_LOAD over the whole file ------------------------------------ */

static void w16(uint8_t *b, unsigned at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *b, unsigned at, uint32_t v) { w16(b, at, (uint16_t)v); w16(b, at + 2, (uint16_t)(v >> 16)); }
static void w64(uint8_t *b, unsigned at, uint64_t v) { w32(b, at, (uint32_t)v); w32(b, at + 4, (uint32_t)(v >> 32)); }

#define BASE  0x400000u

/* The headers of an ELF of `n` bytes; the code is everything past `code`. */
static unsigned elf_head(uint8_t *b, uint64_t n, int is64)
{
	const unsigned code = is64 ? 0x78u : 0x54u;

	memset(b, 0, code);
	memcpy(b, "\177ELF", 4);
	b[4] = is64 ? 2 : 1;
	b[5] = 1;
	b[6] = 1;
	w16(b, 16, 2);
	w16(b, 18, is64 ? 0x3e : 3);
	w32(b, 20, 1);
	if (is64) {
		w64(b, 24, BASE + code);
		w64(b, 32, 64);
		w16(b, 52, 64);
		w16(b, 54, 56);
		w16(b, 56, 1);
		w32(b, 64, 1);                  /* PT_LOAD */
		w32(b, 68, 7);                  /* RWX */
		w64(b, 72, 0);
		w64(b, 80, BASE);
		w64(b, 88, BASE);
		w64(b, 96, n);
		w64(b, 104, n);
		w64(b, 112, 0x1000);
	} else {
		w32(b, 24, BASE + code);
		w32(b, 28, 52);
		w16(b, 40, 52);
		w16(b, 42, 32);
		w16(b, 44, 1);
		w32(b, 52, 1);
		w32(b, 56, 0);
		w32(b, 60, BASE);
		w32(b, 64, BASE);
		w32(b, 68, (uint32_t)n);
		w32(b, 72, (uint32_t)n);
		w32(b, 76, 7);
		w32(b, 80, 0x1000);
	}
	return code;
}

struct obj {
	uint8_t *b;
	uint64_t n;
	int is64;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	unsigned code;
};

static int obj_open(struct obj *x, uint8_t *b, uint64_t n, int is64)
{
	memset(&x->ei, 0, sizeof x->ei);
	x->b = b;
	x->n = n;
	x->is64 = is64;
	x->code = is64 ? 0x78u : 0x54u;
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), &x->ei, &x->o))
		return 0;
	x->o.file_header = &x->ei;
	return x->o.arch == (is64 ? KGENOME_ARCH_X86_64 : KGENOME_ARCH_X86);
}

/* ---- the comparison ---------------------------------------------------------------------------- */

static int same_insn(const struct kgenome_cell_insn *a, const struct kgenome_cell_insn *b)
{
	unsigned i;

	if (a->op != b->op || a->len != b->len || a->n_op != b->n_op || a->cond != b->cond ||
	    a->flags != b->flags || a->wmask != b->wmask || a->at != b->at || a->at_va != b->at_va ||
	    a->target != b->target || a->target_va != b->target_va)
		return 0;
	for (i = 0; i < 3u; i++) {
		const struct kgenome_cell_operand *p = &a->o[i], *q = &b->o[i];

		if (p->kind != q->kind || p->reg != q->reg || p->index != q->index || p->scale != q->scale ||
		    p->size != q->size || p->flags != q->flags || p->seg != q->seg || p->disp != q->disp ||
		    p->imm != q->imm)
			return 0;
	}
	return 1;
}

/* Offsets [lo, hi) stepping by `stride`: through a space with no `held` and through one with it.
 * Returns how many offsets differ; `decoded` counts the ones that decode at all. */
static unsigned compare(const struct obj *x, struct kgenome_diag_walk *wk, uint64_t lo, uint64_t hi,
			uint64_t stride, unsigned *decoded, int *held_on)
{
	struct kgenome_cell_space a, b;
	uint64_t at;
	unsigned bad = 0, dec = 0;

	kgenome_cell_space_init(&a, &x->o, x->b, x->n);
	kgenome_cell_space_init(&b, &x->o, x->b, x->n);
	*held_on = kgenome_diag_walk_hold(&b, wk);
	for (at = lo; at < hi; at += stride) {
		struct kgenome_cell_cur ka, kb;
		struct kgenome_cell_insn ia, ib;
		int ra, rb;

		memset(&ia, 0xa5, sizeof ia);
		memset(&ib, 0x5a, sizeof ib);
		kgenome_cell_seek(&ka, at, 0);
		kgenome_cell_seek(&kb, at, 0);
		ra = kgenome_cell_step(&ka, &a, &ia);
		rb = kgenome_cell_step(&kb, &b, &ib);
		if (ra != rb || ka.at != kb.at || (ra && !same_insn(&ia, &ib))) {
			if (bad < 5)
				printf("  differs at offset %llu: %d/%d len %u/%u\n", (unsigned long long)at, ra, rb,
				       ra ? ia.len : 0u, rb ? ib.len : 0u);
			bad++;
		}
		dec += ra != 0;
	}
	*decoded = dec;
	return bad;
}

/* One image, one mode: the walk with a trace, then every offset compared. */
static void every_offset(struct obj *x, const char *tag, int expect_held)
{
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	unsigned decoded = 0, bad;
	int held_on = 0;
	uint64_t asked = 0, served;

	CK(wk != NULL);
	CK(kgenome_diag_walk_ensure(wk, &x->o, x->b, x->n, 1));
	bad = compare(x, wk, 0, x->n, 1, &decoded, &held_on);
	served = kgenome_diag_walk_held_count(wk, &asked);
	if (bad || held_on != expect_held)
		printf("  FAIL %s: %u offsets differ, held %d (expected %d)\n", tag, bad, held_on, expect_held);
	CK(bad == 0);
	CK(held_on == expect_held);
	CK(decoded > 0);
	if (expect_held) {
		/* one ask per offset; the ones on the walk's alignment are answered from the trace */
		CK(asked == x->n);
		CK(served > 0 && served <= asked);
		/* an offset the walk decoded is one of its records; the rest are other alignments of the same
	 * bytes, which this reads by decoding. 1 offset in 20 is a loose floor for a stream of 10-byte
	 * instructions in which all but one offset in ten is somebody else's alignment. */
	if (served * 20u < decoded)
		printf("  %s: served %llu of %u decoding offsets\n", tag, (unsigned long long)served, decoded);
	CK(served * 20u >= decoded);
	} else {
		CK(asked == 0 && served == 0);
	}
	kgenome_diag_walk_free(wk);
}

/* ---- the images ------------------------------------------------------------------------------- */

static uint64_t rs;
static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 11);
}

/* The shapes a static binary is made of: calls, jumps, conditional jumps, moves with memory
 * operands, a syscall, a ret, an `int 0x80`, a REP string op, padding, and bytes that do not
 * decode in 64-bit mode. */
static void mixture(uint8_t *b, uint64_t n, unsigned code, int is64)
{
	static const uint8_t t64[][12] = {
		{ 3, 0x48, 0x8b, 0x45 }, { 5, 0xe8, 0x40, 0x00, 0x00, 0x00 }, { 5, 0xe9, 0xf0, 0xff, 0xff, 0xff },
		{ 2, 0x74, 0x05 }, { 7, 0x48, 0x8d, 0x05, 0x10, 0x01, 0x00, 0x00 }, { 2, 0x0f, 0x05 },
		{ 1, 0xc3 }, { 5, 0xb8, 0x39, 0x00, 0x00, 0x00 }, { 2, 0xff, 0xd0 }, { 3, 0x48, 0x89, 0xe5 },
		{ 1, 0x55 }, { 4, 0x48, 0x83, 0xec, 0x20 }, { 2, 0x31, 0xc0 }, { 2, 0xf3, 0xa4 }, { 1, 0x06 },
		{ 2, 0xcd, 0x80 }, { 6, 0x0f, 0x84, 0x10, 0x00, 0x00, 0x00 }, { 3, 0x0f, 0x1f, 0x00 },
		{ 4, 0x66, 0x0f, 0x1f, 0x44 }, { 9, 0x48, 0xc7, 0x44, 0x24, 0x08, 0x01, 0x00, 0x00, 0x00 },
	};
	static const uint8_t t32[][12] = {
		{ 3, 0x8b, 0x45, 0xf8 }, { 5, 0xe8, 0x40, 0x00, 0x00, 0x00 }, { 5, 0xe9, 0xf0, 0xff, 0xff, 0xff },
		{ 2, 0x74, 0x05 }, { 2, 0xcd, 0x80 }, { 1, 0xc3 }, { 5, 0xb8, 0x39, 0x00, 0x00, 0x00 },
		{ 2, 0xff, 0xd0 }, { 2, 0x89, 0xe5 }, { 1, 0x55 }, { 3, 0x83, 0xec, 0x20 }, { 2, 0x31, 0xc0 },
		{ 1, 0x06 }, { 6, 0x0f, 0x84, 0x10, 0x00, 0x00, 0x00 }, { 5, 0xb8, 0x04, 0x00, 0x00, 0x00 },
		{ 3, 0x0f, 0x1f, 0x00 }, { 1, 0x60 }, { 2, 0x0f, 0x05 },
	};
	const unsigned nt = is64 ? (unsigned)(sizeof t64 / sizeof t64[0]) : (unsigned)(sizeof t32 / sizeof t32[0]);
	uint64_t at = code;

	while (at < n) {
		const uint8_t *e = is64 ? t64[rnd() % nt] : t32[rnd() % nt];
		unsigned k = e[0];

		if (at + k > n)
			k = (unsigned)(n - at);
		memcpy(b + at, e + 1, k);
		at += k;
	}
}

static uint8_t small[1u << 15];
static uint8_t viewb[1u << 15];

static void t_mixture(int is64)
{
	struct obj x;
	char tag[64];

	rs = UINT64_C(0x9e3779b97f4a7c15) ^ (uint64_t)is64;
	elf_head(small, sizeof small, is64);
	mixture(small, sizeof small, is64 ? 0x78u : 0x54u, is64);
	snprintf(tag, sizeof tag, "mixture, x86%s", is64 ? "-64" : "");
	CK(obj_open(&x, small, sizeof small, is64));
	every_offset(&x, tag, 1);
}

static void t_random(int is64)
{
	struct obj x;
	unsigned seed, i;
	char tag[64];

	for (seed = 1; seed <= 4u; seed++) {
		rs = UINT64_C(0x1234567) * (uint64_t)seed + (uint64_t)is64;
		elf_head(small, sizeof small, is64);
		for (i = is64 ? 0x78u : 0x54u; i < sizeof small; i++)
			small[i] = (uint8_t)rnd();
		snprintf(tag, sizeof tag, "random bytes seed %u, x86%s", seed, is64 ? "-64" : "");
		CK(obj_open(&x, small, sizeof small, is64));
		every_offset(&x, tag, 1);
	}
}

/* 15-byte instruction soup: runs of prefixes of every kind, the longest legal form and the
 * first illegal one, and instructions that end exactly at the end of the object. */
static void t_soup(int is64)
{
	static const uint8_t pfx[] = { 0x66, 0x67, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0xf0, 0xf2, 0xf3, 0x40, 0x48, 0x4f };
	struct obj x;
	uint64_t at = is64 ? 0x78u : 0x54u;
	unsigned k;
	char tag[64];

	rs = UINT64_C(0xabcdef12345) + (uint64_t)is64;
	elf_head(small, 4096, is64);
	memset(small + at, 0x90, 4096 - at);
	while (at + 16 < 4096) {
		unsigned run = rnd() % 16u;

		for (k = 0; k < run; k++)
			small[at + k] = pfx[rnd() % sizeof pfx];
		small[at + run] = (uint8_t)(rnd() % 3u == 0 ? 0x8b : rnd() % 2u ? 0x0f : 0x90);
		small[at + run + 1] = (uint8_t)rnd();
		at += 16;
	}
	/* an instruction that does not fit: `e8` and two bytes of its rel32, then the object ends */
	small[4096 - 3] = 0xe8;
	small[4096 - 2] = 0x01;
	small[4096 - 1] = 0x02;
	snprintf(tag, sizeof tag, "prefix soup and a cut instruction, x86%s", is64 ? "-64" : "");
	CK(obj_open(&x, small, 4096, is64));
	every_offset(&x, tag, 1);
}

/* Overlapping instructions: every byte of a stream of long instructions is also the start of a
 * different, shorter one. The walk keeps its own alignment; the others come from the decoder. */
static void t_overlap(void)
{
	struct obj x;
	unsigned i, at = 0x78u;

	elf_head(small, 4096, 1);
	for (i = 0; at + 10 <= 4096u; i++) {
		static const uint8_t movabs[] = { 0x48, 0xb8, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3 };

		memcpy(small + at, movabs, sizeof movabs);
		at += (unsigned)sizeof movabs;
	}
	CK(obj_open(&x, small, 4096, 1));
	every_offset(&x, "overlapping instructions (a syscall inside an immediate)", 1);
}

/* ---- a walk is only for the bytes it was made of -------------------------------------------------- */

static void t_refused(void)
{
	struct obj x, y, x32;
	struct kgenome_diag_walk *wk, *nt;
	struct kgenome_cell_space sp;
	unsigned decoded, bad;
	int held_on;

	rs = 77;
	elf_head(small, sizeof small, 1);
	mixture(small, sizeof small, 0x78u, 1);
	CK(obj_open(&x, small, sizeof small, 1));
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));

	/* the same bytes elsewhere: a normalised view is another buffer, never this one's trace */
	memcpy(viewb, small, sizeof small);
	viewb[0x80] ^= 0xff;
	viewb[0x1000] ^= 0x55;
	CK(obj_open(&y, viewb, sizeof viewb, 1));
	bad = compare(&y, wk, 0, y.n, 1, &decoded, &held_on);
	CK(held_on == 0);                       /* refused: the buffer is not the one the walk was made of */
	CK(bad == 0);

	/* the same bytes under another load address: the walk is accepted (the bytes are the ones it
	 * was made of) and a relative branch is answered with the target of the address the cursor gives
	 * its offset, not the one the walk had. The header is changed after the walk and is not code. */
	{
		struct obj z;

		w64(small, 80, BASE + 0x1000u);
		CK(obj_open(&z, small, sizeof small, 1));
		bad = compare(&z, wk, 0x78, z.n, 1, &decoded, &held_on);
		CK(held_on == 1);
		CK(bad == 0);
		CK(kgenome_diag_walk_held_count(wk, NULL) > 0);
		w64(small, 80, BASE);
	}

	/* the same buffer under the other mode: refused, and what comes out is that mode's decode */
	elf_head(viewb, sizeof viewb, 0);
	CK(obj_open(&x32, viewb, sizeof viewb, 0));
	kgenome_cell_space_init(&sp, &x32.o, small, sizeof small);
	CK(kgenome_diag_walk_hold(&sp, wk) == 0);
	CK(sp.held == NULL);

	/* the same bytes, one byte shorter */
	kgenome_cell_space_init(&sp, &x.o, small, sizeof small - 1);
	CK(kgenome_diag_walk_hold(&sp, wk) == 0);

	/* a walk made without a trace holds none */
	nt = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(nt, &x.o, x.b, x.n, 0));
	kgenome_cell_space_init(&sp, &x.o, small, sizeof small);
	CK(kgenome_diag_walk_hold(&sp, nt) == 0);
	/* an empty one, and NULL */
	kgenome_diag_walk_free(nt);
	nt = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_hold(&sp, nt) == 0);
	CK(kgenome_diag_walk_hold(&sp, NULL) == 0);
	kgenome_diag_walk_free(nt);

	/* a trimmed walk (the trace given back) holds none either */
	kgenome_diag_walk_trim(wk);
	kgenome_cell_space_init(&sp, &x.o, small, sizeof small);
	CK(kgenome_diag_walk_hold(&sp, wk) == 0);
	kgenome_diag_walk_free(wk);
}

/* ---- a trace cut at its cap ---------------------------------------------------------------------- */

static void t_huge(void)
{
	/* 50 MB of code, five million 10-byte instructions: the trace is cut at its cap (32 MiB, a
	 * record is about 22 bytes) long before the end of the code. */
	const uint64_t n = 50ull << 20;
	uint8_t *b = malloc(n);
	struct obj x;
	struct kgenome_diag_walk *wk;
	uint64_t asked = 0, served, at;
	unsigned decoded, bad = 0, held_on = 0, dec2;
	const unsigned code = 0x78u;
	int on;

	CK(b != NULL);
	if (!b)
		return;
	elf_head(b, n, 1);
	for (at = code; at + 10u <= n; at += 10u) {
		b[at] = 0x48;
		b[at + 1] = 0xb8;                       /* movabs rax, imm64 */
		memset(b + at + 2, (int)(at >> 7), 8);
	}
	memset(b + at, 0x90, n - at);
	CK(obj_open(&x, b, n, 1));
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));
	CK(kgenome_diag_walk_capped(wk) > 0);           /* the cut happened, and was reported */
	/* the head of the code (held), the middle of it, the tail (decoded), and a stride through all */
	bad += compare(&x, wk, code, code + 4096, 1, &decoded, &on);
	held_on = (unsigned)on;
	bad += compare(&x, wk, n / 2, n / 2 + 4096, 1, &dec2, &on);
	bad += compare(&x, wk, n - 8192, n, 1, &dec2, &on);
	bad += compare(&x, wk, code, n, 4099, &dec2, &on);
	served = kgenome_diag_walk_held_count(wk, &asked);
	CK(bad == 0);
	CK(held_on == 1);
	CK(served > 0);                                 /* the head is held ... */
	CK(served < asked);                             /* ... and the tail is not: it was cut */
	kgenome_diag_walk_free(wk);
	free(b);
}

/* ---- the scan's answer ------------------------------------------------------------------------------ */

static int same_hits(struct kgenome_diag_scan *a, struct kgenome_diag_scan *b)
{
	uint32_t i, k, n = kgenome_diag_scan_count(a);

	if (n != kgenome_diag_scan_count(b))
		return 0;
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *p = kgenome_diag_scan_at(a, i), *q = kgenome_diag_scan_at(b, i);

		if (p->at != q->at || p->attr != q->attr || p->val != q->val || p->symref != q->symref ||
		    p->symadd != q->symadd || p->cap != q->cap || p->flags != q->flags || p->bits != q->bits ||
		    p->n_in != q->n_in)
			return 0;
		for (k = 0; k < p->n_in && k < 4u; k++)
			if (p->in[k].from != q->in[k].from || p->in[k].role != q->in[k].role ||
			    p->in[k].how != q->in[k].how || p->in[k].kind != q->in[k].kind)
				return 0;
	}
	return kgenome_diag_scan_status(a) == kgenome_diag_scan_status(b);
}

/* The sweep reads the walk's trace, and what it finds is what it finds by decoding. */
static void t_scan(int is64)
{
	static uint8_t img[1u << 16];
	struct obj x;
	struct kgenome_diag_walk *w1, *w2;
	struct kgenome_diag_inputs in1, in2;
	struct kgenome_diag_scan *s1, *s2;
	uint64_t asked = 0, served;
	unsigned at, i;
	char tag[64];

	for (i = 0; i < 2; i++) {
		/* code with syscalls whose number is set a few instructions before (x86-64: `mov eax,N;
		 * syscall`, x86: `mov eax,N; int 0x80`), calls, and filler the sweep has to read through */
		const unsigned code = is64 ? 0x78u : 0x54u;

		rs = 4242u + i + (uint64_t)is64;
		elf_head(img, sizeof img, is64);
		mixture(img, sizeof img, code, is64);
		for (at = code + 64u; at + 16u < sizeof img; at += 97u + rnd() % 64u) {
			img[at] = 0xb8;
			img[at + 1] = (uint8_t)(i ? 41u + rnd() % 3u : 1u + rnd() % 60u);
			img[at + 2] = img[at + 3] = img[at + 4] = 0;
			if (is64) {
				img[at + 5] = 0x0f;
				img[at + 6] = 0x05;
			} else {
				img[at + 5] = 0xcd;
				img[at + 6] = 0x80;
			}
		}
		snprintf(tag, sizeof tag, "scan %u, x86%s", i, is64 ? "-64" : "");
		CK(obj_open(&x, img, sizeof img, is64));
		w1 = kgenome_diag_walk_new();
		w2 = kgenome_diag_walk_new();
		CK(kgenome_diag_walk_ensure(w1, &x.o, x.b, x.n, 1));    /* held: a trace of these bytes */
		memset(&in1, 0, sizeof in1);
		memset(&in2, 0, sizeof in2);
		in1.walk = w1;
		in2.walk = w2;                                          /* empty: nothing is held */
		s1 = kgenome_diag_scan_with_inputs(&x.o, x.b, x.n, KGENOME_DIAG_RUN_SYSCALL, &in1);
		s2 = kgenome_diag_scan_with_inputs(&x.o, x.b, x.n, KGENOME_DIAG_RUN_SYSCALL, &in2);
		CK(s1 && s2);
		if (s1 && s2) {
			if (!same_hits(s1, s2))
				printf("  FAIL %s: the nodes differ with a held trace\n", tag);
			CK(same_hits(s1, s2));
			CK(kgenome_diag_scan_count(s1) > 0);
		}
		served = kgenome_diag_walk_held_count(w1, &asked);
		CK(asked > 0);
		CK(served > 0);
		/* the sweep reads windows of a stream whose alignment is the walk's, but it stops at a
		 * byte that does not decode and starts again at an arbitrary one, and this image is full of
		 * both: half is the floor here (the real binaries measured give nearly all) */
		CK(served * 2u >= asked);
		CK(kgenome_diag_walk_held_count(w2, &asked) == 0 && asked == 0);
		kgenome_diag_scan_free(s1);
		kgenome_diag_scan_free(s2);
		kgenome_diag_walk_free(w1);
		kgenome_diag_walk_free(w2);
	}
}

/* ---- real code: this very test binary ------------------------------------------------------------ */

/* The executable segment(s) of the program that is running, every offset: compiler output, a
 * PLT, padding, jump tables and constants between functions. The binary is x86-64 where the suite
 * runs on x86-64 and is something else (and the case says so) where it does not. */
static void t_self(const char *exe)
{
	FILE *f = exe ? fopen(exe, "rb") : NULL;
	uint8_t *b;
	long n;
	struct obj x;
	struct kgenome_diag_walk *wk;
	unsigned i, segs = 0, decoded, bad = 0;
	uint64_t span = 0, asked = 0, served;
	int on;

	if (!f) {
		printf("  (no executable to read: the real-code case is not run)\n");
		return;
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = n > 0 ? malloc((size_t)n) : NULL;
	if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
		fclose(f);
		free(b);
		printf("  (the executable could not be read: the real-code case is not run)\n");
		return;
	}
	fclose(f);
	if (!obj_open(&x, b, (uint64_t)n, 1)) {
		printf("  (this executable is not an x86-64 ELF: the real-code case is not run)\n");
		free(b);
		return;
	}
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));
	for (i = 0; i < KGENOME_ELF_MAX_SEGMENTS && i < x.ei.seg_count; i++) {
		const struct kgenome_elf_seg *g = &x.ei.seg[i];

		if (!(g->perm & KGENOME_PERM_X) || g->file_off >= x.n)
			continue;
		bad += compare(&x, wk, g->file_off, g->file_off + (g->file_size < x.n - g->file_off ? g->file_size : x.n - g->file_off),
			       1, &decoded, &on);
		span += g->file_size;
		segs++;
		CK(on == 1);
	}
	served = kgenome_diag_walk_held_count(wk, &asked);
	CK(segs > 0);
	CK(bad == 0);
	CK(served > 0);
	printf("  real code: %llu bytes of executable segments, %llu answered from the trace of %llu asked\n",
	       (unsigned long long)span, (unsigned long long)served, (unsigned long long)asked);
	kgenome_diag_walk_free(wk);
	free(b);
}

int main(int argc, char **argv)
{
	t_mixture(1);
	t_mixture(0);
	t_random(1);
	t_random(0);
	t_soup(1);
	t_soup(0);
	t_overlap();
	t_refused();
	t_scan(1);
	t_scan(0);
	t_self(argc > 0 ? argv[0] : NULL);
	t_huge();
	if (fails)
		printf("decode held: %d FAILED\n", fails);
	else
		printf("decode held: every offset, soup, overlap, both modes, refused walks, cut trace, scan - ok\n");
	return fails != 0;
}
