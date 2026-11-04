/*
 * trace_arch - the diagnose walk keeps the decode of EVERY architecture it has a decoder for, and every reader of the code is answered from that one decode.
 *
 * THE PRODUCT. The walk (diag_wrapper_walk.c) decodes each executable segment once and keeps the packed records. The records are the whole instruction
 * (struct kgenome_cell_insn: the register mask above sixteen registers, the address of a branch, the field of an operand its kind does not name), so
 * a reader of a record is a reader of the decoder. Until now only x86 held a trace; ARM, AArch64, MIPS and PowerPC were decoded again by the xref
 * feed, the code map, the signing of a function and the syscall sweep (measured over the 160 Mirai files: 1.82 to 2.00 decodes an offset).
 *
 * WHAT IS HELD TO. The answer must be the decoder's, field for field, so every case reads the same bytes twice and compares every field:
 *   - ROUND TRIP    kgenome_diag_code_run over each extent through the walk (the records) and without it (the decoder): the same instructions, the same
 *                   count of bytes the decoder could not read, and every instruction of the first run came from a record (the counter says so);
 *   - THE CURSOR    every offset of the object through a space with `held` and through one without: same result, same instruction, same position (the
 *                   offsets of another alignment are the decoder's);
 *   - THE FIELDS    random bytes of each architecture reach the corners a program does not: a mask above bit 15 (AArch64, PowerPC), a branch whose address is
 *                   not relative (MIPS `j`), a field an operand's kind does not name (ARM), an operand slot the instruction does not use;
 *   - ANOTHER ADDRESS  the same buffer under another load address: x86 is answered with the target of the address the cursor gives (a relative branch),
 *                   every other architecture is DECODED (a MIPS `j` names a place of the address space: the record made for another address is not this
 *                   instruction's);
 *   - ARM LITERAL   the cursor still rewrites a literal-pool load as the MOV of the constant (what the constant map reads) and the trace holds what the
 *                   decoder wrote, so a reader of the walk and a reader of the decoder see the same instruction.
 * RED on the base: a walk of anything but x86 held no trace (`from_trace` 0, the cursor never `held`). Why the old tests missed it: (a) decode_held.c and
 * deccnt only ever built an x86 image; (b) no row asked an architecture other than x86 for a trace; (c) the cfg and lineage tests compared graphs, never how many
 * times an offset was decoded.
 *
 * Linked against libkgenome.a alone; every image is built in memory.
 */
#include <kgenome.h>
#include <phenotype/diag_private.h>
#include <phenotype/diag_wrapper_private.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/image_addr.h>

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

static void put(uint8_t *b, unsigned at, uint64_t v, unsigned n, int be)
{
	unsigned i;

	for (i = 0; i < n; i++)
		b[at + i] = (uint8_t)(v >> (8u * (be ? n - 1u - i : i)));
}

#define BASE  0x400000u

struct isa {
	const char *name;
	unsigned machine;
	int is64, be;
	unsigned arch;
};

static const struct isa ISA[] = {
	{ "x86-64", 0x3e, 1, 0, KGENOME_ARCH_X86_64 }, { "i386", 3, 0, 0, KGENOME_ARCH_X86 },
	{ "arm32", 40, 0, 0, KGENOME_ARCH_ARM },       { "aarch64", 183, 1, 0, KGENOME_ARCH_ARM64 },
	{ "mips-le", 8, 0, 0, KGENOME_ARCH_MIPS },     { "mips-be", 8, 0, 1, KGENOME_ARCH_MIPS },
	{ "ppc32", 20, 0, 1, KGENOME_ARCH_PPC },       { "ppc64", 21, 1, 1, KGENOME_ARCH_PPC64 },
};
#define N_ISA (sizeof ISA / sizeof ISA[0])

/* One ELF of `n` bytes, one RWX PT_LOAD over all of it at `base`; the code is everything past the headers. Returns the offset of the code. */
static unsigned elf_head(uint8_t *b, uint64_t n, const struct isa *isa, uint32_t base)
{
	const unsigned code = isa->is64 ? 0x78u : 0x54u;
	const int be = isa->be;

	memset(b, 0, code);
	memcpy(b, "\177ELF", 4);
	b[4] = isa->is64 ? 2 : 1;
	b[5] = be ? 2 : 1;
	b[6] = 1;
	put(b, 16, 2, 2, be);
	put(b, 18, isa->machine, 2, be);
	put(b, 20, 1, 4, be);
	if (isa->is64) {
		put(b, 24, base + code, 8, be);
		put(b, 32, 64, 8, be);
		put(b, 52, 64, 2, be);
		put(b, 54, 56, 2, be);
		put(b, 56, 1, 2, be);
		put(b, 64, 1, 4, be);                   /* PT_LOAD */
		put(b, 68, 7, 4, be);                   /* RWX */
		put(b, 72, 0, 8, be);
		put(b, 80, base, 8, be);
		put(b, 88, base, 8, be);
		put(b, 96, n, 8, be);
		put(b, 104, n, 8, be);
		put(b, 112, 0x1000, 8, be);
	} else {
		put(b, 24, base + code, 4, be);
		put(b, 28, 52, 4, be);
		put(b, 40, 52, 2, be);
		put(b, 42, 32, 2, be);
		put(b, 44, 1, 2, be);
		put(b, 52, 1, 4, be);
		put(b, 56, 0, 4, be);
		put(b, 60, base, 4, be);
		put(b, 64, base, 4, be);
		put(b, 68, n, 4, be);
		put(b, 72, n, 4, be);
		put(b, 76, 7, 4, be);
		put(b, 80, 0x1000, 4, be);
	}
	return code;
}

struct obj {
	uint8_t *b;
	uint64_t n;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
};

static int obj_open(struct obj *x, uint8_t *b, uint64_t n, const struct isa *isa)
{
	memset(&x->ei, 0, sizeof x->ei);
	x->b = b;
	x->n = n;
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), &x->ei, &x->o))
		return 0;
	x->o.file_header = &x->ei;
	return x->o.arch == isa->arch;
}

static int same_insn(const struct kgenome_cell_insn *a, const struct kgenome_cell_insn *b)
{
	unsigned i;

	if (a->op != b->op || a->len != b->len || a->n_op != b->n_op || a->cond != b->cond || a->flags != b->flags || a->wmask != b->wmask || a->at != b->at ||
	    a->at_va != b->at_va || a->target != b->target || a->target_va != b->target_va)
		return 0;
	for (i = 0; i < 3u; i++) {
		const struct kgenome_cell_operand *p = &a->o[i], *q = &b->o[i];

		if (p->kind != q->kind || p->reg != q->reg || p->index != q->index || p->scale != q->scale || p->size != q->size || p->flags != q->flags ||
		    p->seg != q->seg || p->disp != q->disp || p->imm != q->imm)
			return 0;
	}
	return 1;
}

/* ---- ROUND TRIP: code_run through the walk and through the decoder ------------------------------------------------------------------ */

struct col {
	struct kgenome_cell_insn *v;
	uint32_t n, cap, nul;
	uint64_t hi_mask, both_fields;          /* corners met: a mask above bit 15, an operand with the field its kind does not name */
};

static void obs(void *u, const struct kgenome_cell_insn *in)
{
	struct col *c = u;
	unsigned i;

	if (!in) {
		c->nul++;
		return;
	}
	if (c->n == c->cap) {
		c->cap = c->cap ? c->cap * 2u : 4096u;
		c->v = realloc(c->v, (size_t)c->cap * sizeof *c->v);
	}
	c->v[c->n++] = *in;
	c->hi_mask += (in->wmask >> 16) != 0;
	for (i = 0; i < in->n_op; i++) {
		const struct kgenome_cell_operand *o = &in->o[i];

		if ((o->kind == KGENOME_CELL_O_MEM && o->imm) || ((o->kind == KGENOME_CELL_O_IMM || o->kind == KGENOME_CELL_O_REL) && o->disp) ||
		    ((o->kind == KGENOME_CELL_O_REG || o->kind == KGENOME_CELL_O_NONE) && (o->disp || o->imm)))
			c->both_fields++;
	}
}

static uint64_t t_hi, t_both, t_insns;

static uint64_t round_trip(const struct obj *x, struct kgenome_diag_walk *wk, const char *tag)
{
	uint32_t i;
	uint64_t from_trace = 0, total = 0;

	for (i = 0; i < kgenome_diag_extent_count(&x->o); i++) {
		uint64_t at, have = kgenome_diag_extent(&x->o, i, x->n, &at), va;
		struct col c1, c2;
		struct kgenome_diag_code_run_stats st;
		uint32_t k;

		if (!have)
			continue;
		va = kgenome_image_off_to_addr(&x->o, at);
		memset(&c1, 0, sizeof c1);
		memset(&c2, 0, sizeof c2);
		memset(&st, 0, sizeof st);
		kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
			.obj = &x->o, .base = x->b, .size = x->n, .off = at, .n = have, .va = va, .fn = obs, .user = &c1, .wk = wk, .st = &st });
		kgenome_diag_code_run(&(const struct kgenome_diag_code_req){
			.obj = &x->o, .base = x->b, .size = x->n, .off = at, .n = have, .va = va, .fn = obs, .user = &c2 });
		if (c1.n != c2.n || c1.nul != c2.nul) {
			printf("  FAIL %s: %u/%u instructions, %u/%u unreadable\n", tag, c1.n, c2.n, c1.nul, c2.nul);
			fails++;
		} else {
			for (k = 0; k < c1.n; k++)
				if (!same_insn(&c1.v[k], &c2.v[k])) {
					printf("  FAIL %s: instruction %u at %llx differs between the trace and the decoder\n", tag, k, (unsigned long long)c1.v[k].at);
					fails++;
					break;
				}
		}
		from_trace += st.from_trace;
		total += c2.n;
		t_hi += c2.hi_mask;
		t_both += c2.both_fields;
		free(c1.v);
		free(c2.v);
	}
	t_insns += total;
	if (from_trace != total) {
		printf("  FAIL %s: %llu of %llu instructions came from the trace\n", tag, (unsigned long long)from_trace, (unsigned long long)total);
		fails++;
	}
	return total;
}

/* ---- THE CURSOR: every offset, held and not ---------------------------------------------------------------------------------------------- */

static unsigned compare(const struct obj *x, struct kgenome_diag_walk *wk, uint64_t lo, uint64_t hi, int *held_on)
{
	struct kgenome_cell_space a, b;
	uint64_t at;
	unsigned bad = 0;

	kgenome_cell_space_init(&a, &x->o, x->b, x->n);
	kgenome_cell_space_init(&b, &x->o, x->b, x->n);
	*held_on = kgenome_diag_walk_hold(&b, wk);
	for (at = lo; at < hi; at++) {
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
				printf("  differs at offset %llu: %d/%d\n", (unsigned long long)at, ra, rb);
			bad++;
		}
	}
	return bad;
}

static uint64_t rs;
static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 11);
}

static uint8_t img[1u << 14];

/* `kind` 0: random bytes; 1: words of one repeated pattern (every ISA word has a first byte): all zeros; 2: all ones. */
static void fill(const struct isa *isa, unsigned kind, unsigned code)
{
	unsigned i;

	elf_head(img, sizeof img, isa, BASE);
	for (i = code; i < sizeof img; i++)
		img[i] = kind == 0 ? (uint8_t)rnd() : kind == 1 ? 0u : 0xffu;
}

static void t_isa(const struct isa *isa)
{
	const unsigned code = isa->is64 ? 0x78u : 0x54u;
	unsigned kind, seed;

	for (kind = 0; kind < 3u; kind++)
		for (seed = 1; seed <= (kind == 0 ? 6u : 1u); seed++) {
			struct obj x;
			struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
			char tag[96];
			int held_on = 0;
			unsigned bad;
			uint64_t total;

			rs = UINT64_C(0x9e3779b97f4a7c15) * seed + isa->machine + (uint64_t)isa->be;
			fill(isa, kind, code);
			snprintf(tag, sizeof tag, "%s %s %u", isa->name, kind == 0 ? "random" : kind == 1 ? "zeros" : "ones", seed);
			CK(obj_open(&x, img, sizeof img, isa));
			CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));
			total = round_trip(&x, wk, tag);
			bad = compare(&x, wk, 0, x.n, &held_on);
			if (bad || held_on != (total > 0))
				printf("  FAIL %s: %u offsets differ, held %d\n", tag, bad, held_on);
			CK(bad == 0);
			CK(held_on == (total > 0));     /* a walk that decoded nothing holds nothing: bytes no instruction starts with (all ones, on x86) */
			kgenome_diag_walk_free(wk);
		}
}

/* ---- ANOTHER ADDRESS ------------------------------------------------------------------------------------------------------------------------ */

static void t_other_address(const struct isa *isa)
{
	const unsigned code = isa->is64 ? 0x78u : 0x54u;
	struct obj x, y;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint64_t asked = 0, served;
	int held_on = 0;
	unsigned bad;
	char tag[64];

	snprintf(tag, sizeof tag, "%s at another address", isa->name);
	rs = 31337u + isa->machine;
	fill(isa, 0, code);
	CK(obj_open(&x, img, sizeof img, isa));
	CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));
	/* the header says the segment is somewhere else; the bytes of the code are the ones the walk was made of */
	elf_head(img, sizeof img, isa, BASE + 0x10000u);
	CK(obj_open(&y, img, sizeof img, isa));
	bad = compare(&y, wk, code, y.n, &held_on);
	served = kgenome_diag_walk_held_count(wk, &asked);
	if (bad)
		printf("  FAIL %s: %u offsets differ\n", tag, bad);
	CK(bad == 0);
	CK(held_on == 1);
	/* x86 is answered from the record (a relative branch re-aimed at the cursor's address); the others are decoded, never answered with a record made for another address */
	if (isa->arch == KGENOME_ARCH_X86 || isa->arch == KGENOME_ARCH_X86_64)
		CK(served > 0);
	else
		CK(served == 0 && asked > 0);
	kgenome_diag_walk_free(wk);
}

/* ---- the walk's own cases ------------------------------------------------------------------------------------------------------------------- */

/* The edges of the walk's API: an object of a kind it does not read (neither ELF nor PE, a PE of another machine, an ELF/PE that did not parse), no walk at all, a run of nothing, and a run
 * with the counters asked for on the decoder's own path (the trace holds nothing for a walk made without one). */
static void t_walk_edges(void)
{
	struct obj x;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	struct kgenome_obj other;
	struct kgenome_pe_info pi;
	struct kgenome_diag_code_run_stats st;
	struct col c;
	const struct isa *mips = &ISA[4];

	rs = 9;
	fill(mips, 0, 0x54u);
	CK(obj_open(&x, img, sizeof img, mips));
	other = x.o;
	other.format = 0;                                          /* a payload with no header */
	CK(!kgenome_diag_walk_ensure(wk, &other, x.b, x.n, 1));
	memset(&pi, 0, sizeof pi);
	pi.valid = 1;
	other = x.o;
	other.format = KGENOME_FMT_PE;
	other.file_header = &pi;
	other.arch = KGENOME_ARCH_ARM;                             /* a PE is walked as x86 / x64 only */
	CK(!kgenome_diag_walk_ensure(wk, &other, x.b, x.n, 1));
	CK(!kgenome_diag_walk_ensure(NULL, &x.o, x.b, x.n, 1));
	kgenome_diag_wrapper_walk_drop_trace(NULL);
	/* code_run: no observer, no object, no bytes, an offset past the object: nothing happens; and the counters count what the decoder did */
	memset(&c, 0, sizeof c);
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){ .obj = &x.o, .base = x.b, .size = x.n, .off = x.n, .n = 4, .va = BASE, .fn = obs, .user = &c });
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){ .obj = NULL, .base = x.b, .size = x.n, .off = 0, .n = 4, .va = BASE, .fn = obs, .user = &c });
	CK(c.n == 0 && c.nul == 0);
	memset(&st, 0, sizeof st);
	kgenome_diag_code_run(&(const struct kgenome_diag_code_req){ .obj = &x.o, .base = x.b, .size = x.n, .off = 0x54, .n = 256, .va = BASE + 0x54, .fn = obs, .user = &c, .st = &st });
	CK(st.decoded > 0 && st.from_trace == 0);
	free(c.v);
	kgenome_diag_walk_free(wk);
}

static void t_walk(void)
{
	struct obj x;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	struct kgenome_cell_space sp;
	const struct isa *arm = &ISA[2], *mips = &ISA[5];

	rs = 5;
	fill(arm, 0, 0x54u);
	CK(obj_open(&x, img, sizeof img, arm));
	CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 0));
	kgenome_cell_space_init(&sp, &x.o, x.b, x.n);
	CK(kgenome_diag_walk_hold(&sp, wk) == 0);               /* a walk made without a trace holds none, on any architecture */
	CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));    /* asked for the trace later: made again, with it */
	kgenome_cell_space_init(&sp, &x.o, x.b, x.n);
	CK(kgenome_diag_walk_hold(&sp, wk) == 1);
	/* the other architecture's space is refused */
	fill(mips, 0, 0x54u);
	{
		struct obj m;

		CK(obj_open(&m, img, sizeof img, mips));
		kgenome_cell_space_init(&sp, &m.o, x.b, x.n);
		CK(kgenome_diag_walk_hold(&sp, wk) == 0);
	}
	kgenome_diag_walk_free(wk);
}

/* D2: the assembler pads between functions with `lea r,[r+0]` forms (x86 reports them as a LEA, not a nop). The walk takes the ones that change nothing as padding, so a function's end
 * is cut in front of them (the table's ends read the walk's runs). A LEA that computes (`lea eax,[rsi+8]`, a displacement, another register) is code. RED on main: no run for the lea. */
static void t_pad_lea(void)
{
	static const struct { const char *name; int arch64; const uint8_t b[16]; unsigned n; int pad; } row[] = {
		{ "lea esi,[rsi+0] (6)", 1, { 0xc3, 0x8d, 0xb6, 0, 0, 0, 0, 0xc3 }, 8, 1 },
		{ "lea esi,[rsi+0] (3)", 1, { 0xc3, 0x8d, 0x76, 0x00, 0xc3 }, 5, 1 },
		{ "lea rsi,[rsi*1+0] sib (4)", 1, { 0xc3, 0x8d, 0x74, 0x26, 0x00, 0xc3 }, 6, 1 },
		{ "lea esi,[esi+eiz*1+0] (7)", 0, { 0xc3, 0x8d, 0xb4, 0x26, 0, 0, 0, 0, 0xc3 }, 9, 1 },
		{ "lea esi,[esi+0] i386", 0, { 0xc3, 0x8d, 0x76, 0x00, 0xc3 }, 5, 1 },
		{ "lea eax,[rsi+8]", 1, { 0xc3, 0x8d, 0x46, 0x08, 0xc3 }, 5, 0 },
		{ "lea eax,[rax+8]", 1, { 0xc3, 0x8d, 0x40, 0x08, 0xc3 }, 5, 0 },
		{ "lea eax,[rsi+0]", 1, { 0xc3, 0x8d, 0x46, 0x00, 0xc3 }, 5, 0 },
		{ "lea esi,[rsi+rax*1]", 1, { 0xc3, 0x8d, 0x34, 0x06, 0xc3 }, 5, 0 },       /* an index register: a sum, not a pad */
	};
	unsigned r;

	for (r = 0; r < sizeof row / sizeof row[0]; r++) {
		const struct isa *isa = row[r].arch64 ? &ISA[0] : &ISA[1];
		const unsigned code = isa->is64 ? 0x78u : 0x54u;
		struct obj x;
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		const uint64_t *pads;
		uint32_t np = 0;

		memset(img, 0xcc, sizeof img);
		elf_head(img, sizeof img, isa, BASE);
		memset(img + code, 0x90, 64);
		memcpy(img + code, row[r].b, row[r].n);
		CK(obj_open(&x, img, 64u + code, isa));
		CK(kgenome_diag_walk_ensure(wk, &x.o, x.b, x.n, 1));
		pads = kgenome_diag_walk_pads(wk, &np);
		{
			unsigned i, hit = 0;

			for (i = 0; i < np; i++)
				if (pads[2u * i] == code + 1u)
					hit = 1;
			if (hit != (unsigned)row[r].pad)
				printf("  %s: padding run at the lea %s, wanted %s\n", row[r].name, hit ? "found" : "not found", row[r].pad ? "found" : "not found");
			CK(hit == (unsigned)row[r].pad);
		}
		kgenome_diag_walk_free(wk);
	}
}

/* D3: the C library's signal-return trampolines are called by no one (the kernel returns into them) and follow the function before them with no padding: the entry walk saw no start and the
 * stub was merged into the function before it. Their bytes are fixed by the ABI; where they stand after a ret or padding they are a start. The same bytes after an instruction that does not
 * end a function are not. RED on main: no entry for the stub. */
static void t_sigreturn_stub(void)
{
	static const uint8_t k64[] = { 0x48, 0xc7, 0xc0, 0x0f, 0, 0, 0, 0x0f, 0x05 };
	static const uint8_t k32a[] = { 0x58, 0xb8, 0x77, 0, 0, 0, 0xcd, 0x80 };
	static const uint8_t k32b[] = { 0xb8, 0xad, 0, 0, 0, 0xcd, 0x80 };
	static const struct { const char *name; int arch64; const uint8_t *stub; unsigned n; unsigned lead; int start; } row[] = {
		{ "x86-64 mov rax,15; syscall after ret", 1, k64, sizeof k64, 0, 1 },
		{ "x86-64 after int3 padding", 1, k64, sizeof k64, 1, 1 },
		{ "x86-64 after a mov (not a function end)", 1, k64, sizeof k64, 2, 0 },
		{ "i386 pop eax; mov eax,119; int 0x80", 0, k32a, sizeof k32a, 0, 1 },
		{ "i386 mov eax,173; int 0x80", 0, k32b, sizeof k32b, 0, 1 },
		{ "i386 after a mov (not a function end)", 0, k32b, sizeof k32b, 2, 0 },
	};
	unsigned r;

	for (r = 0; r < sizeof row / sizeof row[0]; r++) {
		const struct isa *isa = row[r].arch64 ? &ISA[0] : &ISA[1];
		const unsigned code = isa->is64 ? 0x78u : 0x54u;
		struct obj x;
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		struct kgenome_func_set fs;
		unsigned at, i, found = 0;

		memset(img, 0xcc, sizeof img);
		elf_head(img, sizeof img, isa, BASE);
		memset(img + code, 0x90, 64);
		img[code] = 0x55;                                      /* push rbp */
		img[code + 1] = 0xc3;                                  /* ret */
		if (row[r].lead == 1u) {
			img[code + 2] = 0xcc;
			at = code + 3u;
		} else if (row[r].lead == 2u) {
			img[code + 1] = 0xb8;                          /* mov eax,imm32: it does not end the function */
			img[code + 2] = img[code + 3] = img[code + 4] = img[code + 5] = 0;
			at = code + 6u;                                /* the stub follows the mov at once */
		} else {
			at = code + 2u;
		}
		memcpy(img + at, row[r].stub, row[r].n);
		img[at + row[r].n] = 0xc3;
		CK(obj_open(&x, img, 96u + code, isa));
		memset(&fs, 0, sizeof fs);
		kgenome_diag_funcs_with_walk(&x.o, x.b, x.n, wk, &fs);
		for (i = 0; i < fs.n; i++)
			if (fs.v[i].off == at)
				found = 1;
		if (found != (unsigned)row[r].start)
			printf("  %s: start %s, wanted %s\n", row[r].name, found ? "made" : "not made", row[r].start ? "made" : "not made");
		CK(found == (unsigned)row[r].start);
		kgenome_funcs_free(&fs);
		kgenome_diag_walk_free(wk);
	}
}

int main(void)
{
	unsigned i;

	for (i = 0; i < N_ISA; i++) {
		t_isa(&ISA[i]);
		t_other_address(&ISA[i]);
	}
	t_walk();
	t_walk_edges();
	t_pad_lea();
	t_sigreturn_stub();
	/* the corners exist in the images above, or the rows prove nothing about them */
	CK(t_hi > 0);
	CK(t_both > 0);
	printf("trace_arch: %u architectures, %llu instructions through the trace and the decoder, %llu with a mask above bit 15, %llu with the other field of an operand set, %d failure(s)\n",
	       (unsigned)N_ISA, (unsigned long long)t_insns, (unsigned long long)t_hi, (unsigned long long)t_both, fails);
	return fails != 0;
}
