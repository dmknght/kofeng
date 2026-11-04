/*
 * cfg_switch.c - REACH_INDIRECT: kgenome_cfg_build resolving an indirect jmp against a switch/jump table
 * (cfg.h, KGENOME_CFG_T_SWITCH). Library-only (libgenome alone, no engine symbol): it calls kgenome_cfg_build
 * directly with a hand-filled kgenome_cfg_req and a `switch_src` callback backed by a small in-memory table,
 * exactly the shape fntab_reach.c would supply from the object's own bytes (not wired here: see cfg_build.c's
 * own comment and this work package's report for why that plumbing stops at frame.h/frame.c this round).
 *
 * x86-64 bytes only: the one architecture a jump-table dispatch like this is tested against, decoded by the
 * lib's own decoder (kgenome_cell_decode), never a second disassembler. Two fixtures are the VERIFIED byte-for-
 * byte output of `gcc -O2 -fno-pic -no-pie` resp. plain `gcc -O2` (default PIC) on:
 *
 *     int dispatch(int x) { switch (x) { case 0: return work(10); ... case 7: return work(80); default: return -1; } }
 *
 * (8 cases; M, checked with objdump -dr against sw_nopic.o / sw_pic.o, gcc 14.2.0, 2026-11-04). CASE_A_TEXT below
 * is the -fno-pic -no-pie `.text` bytes verbatim (only the four relocated fields are patched at runtime: the
 * table's own disp32, and the seven tail-call rel32 which are irrelevant to this test and point far outside the
 * function on purpose, as `work` itself does in the real relocatable object). PIC_TEXT is the first 27 bytes of
 * the plain `gcc -O2` output (through `jmp rax`): the REAL position-independent jump-table shape, used as the
 * "genuinely unresolvable" case. CASE_B is NOT something this gcc emits for a plain switch; it is the direct,
 * documented one-instruction variant of CASE_A's own table load (`mov rax,[idx*8+table]` then `jmp rax`,
 * instead of `jmp [idx*8+table]` in one instruction) - case (b) of cfg_build.c's resolve_switches() family
 * comment, hand-assembled from well-known x86-64 encodings and noted as such, not claimed to be gcc's output.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <kgenome.h>
#include <celllysis/decode.h>

#include <stdint.h>
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

#define CKM(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

/* ---- decode a flat buffer, exactly as fntab_reach.c's caller would hand instructions to cfg_build. `arch` is
 * KGENOME_ARCH_X86_64 for every case up to and including (6)/(7); (8)/(9) pass KGENOME_ARCH_X86 for the real
 * 32-bit PE bytes. ---- */
static uint32_t decode_all_arch(const uint8_t *b, uint32_t n, uint64_t va0, enum kgenome_arch arch, struct kgenome_cell_insn **out)
{
	struct kgenome_cell_insn *v = calloc(n ? n : 1u, sizeof *v);
	uint32_t pos = 0, k = 0;

	while (pos < n) {
		const uint32_t l = kgenome_cell_decode(arch, 0, b + pos, n - pos, va0 + pos, &v[k]);

		if (!l) {
			free(v);
			*out = NULL;
			return 0;
		}
		v[k].at = pos;
		k++;
		pos += l;
	}
	*out = v;
	return k;
}

/* ---- a switch_src backed by one in-memory table, at `table_va`, little-endian, `width`-byte entries ---- */
struct fake_table {
	uint64_t va;
	const uint8_t *bytes;
	uint32_t len;
};

static int table_read(void *user, uint64_t va, void *out, uint32_t len)
{
	const struct fake_table *t = user;

	if (va < t->va || len > t->len || va - t->va > (uint64_t)(t->len - len))
		return 0;
	memcpy(out, t->bytes + (va - t->va), len);
	return 1;
}

/* A callback that always answers with ONE fixed, valid 8-byte VA (for the cap test: there is no cmp/sub bound
 * anywhere, so every entry up to KGENOME_CFG_SWITCH_MAX_CASES must be read and must validate). */
struct fixed_target { uint64_t va; };

static int table_read_fixed(void *user, uint64_t va, void *out, uint32_t len)
{
	const struct fixed_target *f = user;
	uint8_t raw[8];
	uint32_t i;

	(void)va;
	for (i = 0; i < 8u; i++)
		raw[i] = (uint8_t)(f->va >> (8u * i));
	if (len > sizeof raw)
		return 0;
	memcpy(out, raw, len);
	return 1;
}

static void put_u32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void put_u64(uint8_t *p, uint64_t v) { uint32_t i; for (i = 0; i < 8u; i++) p[i] = (uint8_t)(v >> (8u * i)); }

/*
 * CASE_A: gcc -O2 -fno-pic -no-pie `dispatch`, verbatim (M, objdump above), 152 bytes. Layout (offsets into the
 * buffer, matching the compiler's own):
 *   0x00  cmp edi,0x7                      (block 0)
 *   0x03  ja  0x92                                      ; bound: edi <= 7, i.e. 8 cases - this IS the predecessor
 *                                                         block of the dispatch block, never the dispatch block itself
 *   0x09  mov edi,edi                      (block 1: the dispatch block)
 *   0x0b  jmp QWORD PTR [rdi*8+TABLE]                   ; disp32 at 0x0e, patched to `table_va`
 *   0x12..0x91  eight case bodies (16 bytes each), each a 6-byte nop + `mov edi,imm32` + `jmp rel32` (tail call,
 *               patched to land far outside the function - irrelevant to this test, exactly as the real
 *               relocatable object leaves `work` unresolved)
 *   0x92  mov eax,0xffffffff ; ret                      (the `ja` target: the default case)
 */
static const uint8_t CASE_A_TEXT[] = {
	0x83, 0xff, 0x07, 0x0f, 0x87, 0x89, 0x00, 0x00, 0x00, 0x89, 0xff, 0xff,
	0x24, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xbf, 0x46, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f,
	0x1f, 0x44, 0x00, 0x00, 0xbf, 0x50, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00,
	0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xbf, 0x0a, 0x00, 0x00,
	0x00, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xbf, 0x14, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f,
	0x1f, 0x44, 0x00, 0x00, 0xbf, 0x1e, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00,
	0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xbf, 0x28, 0x00, 0x00,
	0x00, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xbf, 0x32, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f,
	0x1f, 0x44, 0x00, 0x00, 0xbf, 0x3c, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00,
	0x00, 0x00, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3
};
#define CASE_A_LEN (sizeof CASE_A_TEXT)
#define CASE_A_TABLE_DISP_AT 0x0e
#define CASE_A_TAILJMP_AT_0 0x1e       /* 8 of them, 16 bytes apart: 0x1e, 0x2e, ... 0x8e */
#define CASE_A_DEFAULT_AT 0x92
/* table[i] = CASE_A_TEXT offset of case i's handler (the `mov edi,...` that loads work()'s argument) - read off
 * the real object's .rela.rodata (M, same objdump session). */
static const uint32_t CASE_A_TABLE_OFF[8] = { 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x18, 0x28 };
static const uint32_t CASE_A_CASE_IMM[8]  = { 10, 20, 30, 40, 50, 60, 70, 80 };        /* work()'s argument per case, for a cross-check */

/* Patch the four relocated fields of a CASE_A copy for base VA `va0` and table VA `table_va`; tail calls aim at
 * `va0 - 0x10000` (clearly outside [va0, va0+CASE_A_LEN), so they classify as EXIT exactly as a real tail call to
 * an external symbol would - irrelevant to what this test checks). */
static void case_a_patch(uint8_t *b, uint64_t va0, uint64_t table_va)
{
	uint32_t i;

	put_u32(b + CASE_A_TABLE_DISP_AT, (uint32_t)table_va);
	for (i = 0; i < 8u; i++) {
		const uint32_t at = CASE_A_TAILJMP_AT_0 + i * 16u;
		const uint64_t insn_va = va0 + at - 1u;        /* the jmp rel32 opcode byte is one before its displacement field */
		const int64_t rel = (int64_t)(va0 - 0x10000ull) - (int64_t)(insn_va + 5u);

		put_u32(b + at, (uint32_t)rel);
	}
}

/* The jump table itself: 8 absolute 8-byte pointers, table[i] = va0 + CASE_A_TABLE_OFF[i] + `shift` (CASE_B's case
 * bodies sit `shift` bytes later than CASE_A's own - case_b_build()). */
static void case_a_table(uint8_t *tbl, uint64_t va0, uint32_t shift)
{
	uint32_t i;

	for (i = 0; i < 8u; i++)
		put_u64(tbl + i * 8u, va0 + CASE_A_TABLE_OFF[i] + shift);
}

/*
 * CASE_B: the same dispatch, but the one table-load instruction is split into `mov rax,[rdi*8+TABLE]` (8 bytes:
 * REX.W 48 8b 04 fd + disp32) then `jmp rax` (ff e0) in place of CASE_A's single `jmp [rdi*8+TABLE]` (7 bytes:
 * ff 24 fd + disp32). Everything else byte-identical to CASE_A, shifted by (10 - 7) = 3 bytes from offset 0x12 on
 * (the shift is computed below, not hand-counted twice). NOT gcc's output for a plain switch on this host (verified:
 * -O1 and -O2, with and without -fpic, both stay the single-instruction direct form or the PIC delta form - see the
 * file's top comment); built here as the documented, minimal instance of cfg_build.c's case (b) (`jmp reg` resolved
 * by a one-hop backward scan). Returns the length and, through `*jmp_va_off`, the file offset of `jmp rax` itself.
 */
static uint32_t case_b_build(uint8_t *b, uint64_t va0, uint64_t table_va, uint32_t *jmp_off)
{
	uint32_t at = 0x0b, shift;

	memcpy(b, CASE_A_TEXT, 0x0b);                                  /* cmp; ja; mov edi,edi - identical */
	b[at++] = 0x48; b[at++] = 0x8b; b[at++] = 0x04; b[at++] = 0xfd;        /* mov rax,[rdi*8+disp32] (8 bytes) */
	put_u32(b + at, (uint32_t)table_va);
	at += 4u;
	*jmp_off = at;
	b[at++] = 0xff; b[at++] = 0xe0;                                /* jmp rax (2 bytes) */
	shift = at - 0x12u;                                            /* CASE_A's case bodies started at 0x12 */
	memcpy(b + at, CASE_A_TEXT + 0x12, CASE_A_LEN - 0x12);         /* the 8 case bodies + default, identical */
	at += (uint32_t)(CASE_A_LEN - 0x12);
	/* the `ja` target (CASE_A_DEFAULT_AT) moved by `shift`: patch its rel32 (field at offset 0x5, ja ends at 0x9). */
	put_u32(b + 0x5, (uint32_t)(CASE_A_DEFAULT_AT + shift - 0x9u));
	/* the 8 tail jmps, each moved by `shift` from CASE_A_TAILJMP_AT_0 + i*16. */
	{
		uint32_t i;

		for (i = 0; i < 8u; i++) {
			const uint32_t off = CASE_A_TAILJMP_AT_0 + shift + i * 16u;
			const uint64_t insn_va = va0 + off - 1u;
			const int64_t rel = (int64_t)(va0 - 0x10000ull) - (int64_t)(insn_va + 5u);

			put_u32(b + off, (uint32_t)rel);
		}
	}
	return at;
}

/* ---- build kgenome_cfg from a flat buffer, with an optional switch_src and bytes/bytes_len set (as frame.c does) ---- */
static enum kgenome_status build_of_arch(const uint8_t *buf, uint32_t len, uint64_t va0, enum kgenome_arch arch,
					 const struct kgenome_cfg_switch_src *sw, struct kgenome_cell_insn **in, struct kgenome_cfg *g)
{
	struct kgenome_cfg_req rq;
	uint32_t n = decode_all_arch(buf, len, va0, arch, in);

	memset(&rq, 0, sizeof rq);
	if (!n)
		return KGENOME_BAD_INPUT;
	rq.in = *in;
	rq.n_in = n;
	rq.arch = arch;
	rq.va_lo = va0;
	rq.va_hi = va0 + len;
	rq.bytes = buf;
	rq.bytes_len = len;
	if (sw)
		rq.switch_src = *sw;
	return kgenome_cfg_build(&rq, g);
}

static enum kgenome_status build_of(const uint8_t *buf, uint32_t len, uint64_t va0, const struct kgenome_cfg_switch_src *sw,
				    struct kgenome_cell_insn **in, struct kgenome_cfg *g)
{
	return build_of_arch(buf, len, va0, KGENOME_ARCH_X86_64, sw, in, g);
}

/* Block whose last instruction's at_va == va: linear scan (test-sized graphs only). */
static const struct kgenome_cfg_block *block_ending_at(const struct kgenome_cfg *g, const struct kgenome_cell_insn *in, uint64_t va)
{
	uint32_t k;

	for (k = 0; k < g->n_all; k++) {
		const struct kgenome_cfg_block *b = &g->b[k];

		if (in[b->first + b->n_insn - 1u].at_va == va)
			return b;
	}
	return NULL;
}

/* ---- (1) NULL switch_src: byte-for-byte the pre-feature EXIT behaviour ---- */
static void null_callback_is_unchanged(void)
{
	const uint64_t va0 = 0x401000ull, table_va = 0x403000ull;
	uint8_t buf[CASE_A_LEN], tbl[64];
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;

	memcpy(buf, CASE_A_TEXT, CASE_A_LEN);
	case_a_patch(buf, va0, table_va);
	case_a_table(tbl, va0, 0u);
	(void)tbl;
	st = build_of(buf, CASE_A_LEN, va0, NULL, &in, &g);
	CKM(st == KGENOME_OK, "null_callback: build status %d", (int)st);
	disp = block_ending_at(&g, in, va0 + 0x0b);
	CKM(disp != NULL, "null_callback: no block ends at the jmp");
	if (disp) {
		CK(disp->term == KGENOME_CFG_T_EXIT);
		CK(disp->succ[0] == KGENOME_CFG_NONE && disp->succ[1] == KGENOME_CFG_NONE);
		CK(disp->out_deg == 0);
		CK(disp->n_switch == 0 && disp->switch_first == 0 && disp->switch_capped == 0);
	}
	CK(g.switch_tgt == NULL && g.n_switch_tgt == 0);
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/* ---- (2) CASE_A resolves: direct `jmp [idx*8+table]`, bound found in the (single) predecessor block ---- */
static void case_a_resolves(void)
{
	const uint64_t va0 = 0x401000ull, table_va = 0x403000ull;
	uint8_t buf[CASE_A_LEN], tbl[64];
	struct fake_table ft = { table_va, tbl, sizeof tbl };
	struct kgenome_cfg_switch_src sw = { table_read, &ft };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;
	uint32_t i;

	memcpy(buf, CASE_A_TEXT, CASE_A_LEN);
	case_a_patch(buf, va0, table_va);
	case_a_table(tbl, va0, 0u);
	st = build_of(buf, CASE_A_LEN, va0, &sw, &in, &g);
	CKM(st == KGENOME_OK, "case_a: build status %d", (int)st);
	disp = block_ending_at(&g, in, va0 + 0x0b);
	CKM(disp != NULL, "case_a: no block ends at the jmp");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_SWITCH, "case_a: term %d, want SWITCH", disp->term);
		CKM(disp->n_switch == 8u, "case_a: n_switch %u, want 8 (the cmp edi,0x7 bound)", disp->n_switch);
		CK(disp->switch_capped == 0);                  /* a real bound, not the cap */
		CK(disp->succ[0] == KGENOME_CFG_NONE && disp->succ[1] == KGENOME_CFG_NONE && disp->out_deg == 0);
		for (i = 0; i < disp->n_switch && i < 8u; i++) {
			const uint32_t ii = g.switch_tgt[disp->switch_first + i];
			const uint64_t want_va = va0 + CASE_A_TABLE_OFF[i];

			CKM(in[ii].at_va == want_va, "case_a: target %u at_va 0x%llx, want 0x%llx", i,
			    (unsigned long long)in[ii].at_va, (unsigned long long)want_va);
			/* cross-check against the real compiled body: the `mov edi,imm` right at the target loads the
			 * exact argument `work()` was called with for this case (M: read off the objdump above). The
			 * immediate is found by kind, not by operand index: operand order is the decoder's own and not
			 * part of this test's assumptions. */
			{
				uint32_t kk;
				int found_imm = 0;

				for (kk = 0; kk < in[ii].n_op; kk++)
					if (in[ii].o[kk].kind == KGENOME_CELL_O_IMM && in[ii].o[kk].imm == CASE_A_CASE_IMM[i])
						found_imm = 1;
				CKM(in[ii].op == KGENOME_CELL_MOV && found_imm, "case_a: target %u does not load work()'s real argument", i);
			}
		}
	}
	CK(g.status == KGENOME_OK);
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/* ---- (3) CASE_B resolves: `jmp reg` through a one-hop `mov reg,[idx*8+table]` in the SAME block ---- */
static void case_b_resolves(void)
{
	const uint64_t va0 = 0x401000ull, table_va = 0x403000ull;
	uint8_t buf[CASE_A_LEN + 3u], tbl[64];
	struct fake_table ft = { table_va, tbl, sizeof tbl };
	struct kgenome_cfg_switch_src sw = { table_read, &ft };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;
	uint32_t len, jmp_off = 0;

	len = case_b_build(buf, va0, table_va, &jmp_off);
	case_a_table(tbl, va0, (jmp_off + 2u) - 0x12u);        /* CASE_B's case bodies start `shift` bytes later than CASE_A's own */
	st = build_of(buf, len, va0, &sw, &in, &g);
	CKM(st == KGENOME_OK, "case_b: build status %d", (int)st);
	disp = block_ending_at(&g, in, va0 + jmp_off);
	CKM(disp != NULL, "case_b: no block ends at jmp rax");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_SWITCH, "case_b: term %d, want SWITCH", disp->term);
		CKM(disp->n_switch == 8u, "case_b: n_switch %u, want 8", disp->n_switch);
	}
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/* ---- (4) the backward scan is THIS BLOCK ONLY: a register loaded in a DIFFERENT (predecessor) block must not resolve ---- */
static void cross_block_producer_does_not_resolve(void)
{
	const uint64_t va0 = 0x401000ull, table_va = 0x403000ull;
	/*
	 * block A: mov rax,[rcx*8+table]  (REX.W 48 8b 04 cd + disp32, 8 bytes, offsets 0..7)
	 *          jmp +0                 (eb 00, 2 bytes, offsets 8..9: unconditional, falls straight into block B)
	 * block B: jmp rax                (ff e0, 2 bytes, offsets 10..11)
	 * The producer of rax is in block A; block B's own [first, ji) is empty (one instruction), so the backward
	 * scan (cfg_build.c switch_find_table) must find nothing there, and the jmp must stay a plain EXIT.
	 */
	uint8_t buf[12] = { 0x48, 0x8b, 0x04, 0xcd, 0, 0, 0, 0, 0xeb, 0x00, 0xff, 0xe0 };
	uint8_t tbl[64];
	struct fake_table ft = { table_va, tbl, sizeof tbl };
	struct kgenome_cfg_switch_src sw = { table_read, &ft };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;

	put_u32(buf + 4, (uint32_t)table_va);
	st = build_of(buf, sizeof buf, va0, &sw, &in, &g);
	CKM(st == KGENOME_OK, "cross_block: build status %d", (int)st);
	disp = block_ending_at(&g, in, va0 + 10u);
	CKM(disp != NULL, "cross_block: no block ends at jmp rax");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_EXIT, "cross_block: term %d, want EXIT (must NOT cross into the predecessor block)", disp->term);
		CK(disp->n_switch == 0);
	}
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/* ---- (5) the cap: no cmp/sub bound anywhere, and every entry the callback hands back validates - must stop at
 * KGENOME_CFG_SWITCH_MAX_CASES and say so (switch_capped), never read "forever". ---- */
static void cap_triggers_and_is_reported(void)
{
	const uint64_t va0 = 0x401000ull;
	/* jmp [rdi*8+0] with NO cmp/sub anywhere before it: a direct function of 7 bytes. */
	uint8_t buf[7] = { 0xff, 0x24, 0xfd, 0, 0, 0, 0 };
	struct fixed_target fx = { va0 };               /* every read answers with this function's own entry VA: always valid */
	struct kgenome_cfg_switch_src sw = { table_read_fixed, &fx };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;

	put_u32(buf + 3, 0x9000);               /* an arbitrary table VA; table_read_fixed ignores it */
	st = build_of(buf, sizeof buf, va0, &sw, &in, &g);
	CKM(st == KGENOME_OK, "cap: build status %d", (int)st);
	disp = block_ending_at(&g, in, va0);
	CKM(disp != NULL, "cap: no block");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_SWITCH, "cap: term %d, want SWITCH", disp->term);
		CKM(disp->n_switch == KGENOME_CFG_SWITCH_MAX_CASES, "cap: n_switch %u, want the cap %u", disp->n_switch,
		    KGENOME_CFG_SWITCH_MAX_CASES);
		CKM(disp->switch_capped == 1, "cap: switch_capped not set - a cap that does not say so is the rule-4 defect this test guards");
	}
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/*
 * ---- (6) genuinely unresolvable: the REAL gcc -O2 default-PIC shape
 *          (lea rdx,[rip+table]; mov edi,edi; movsxd rax,[rdx+rdi*4]; add rax,rdx; jmp rax)
 * falls back to the exact prior safe behaviour - EXIT, no switch_tgt - because `jmp rax`'s immediate producer in
 * its own block is `add rax,rdx` (not a MOV/MOVZX/MOVSX/LEA): resolution stops at step 2, one hop, never chasing
 * the chain back through movsxd and lea (cfg_build.c's NAMED LIMITS note). The disp32/imm fields that are never
 * dereferenced (resolution fails before reading the table) are left as the real relocation placeholders (0),
 * exactly as the unlinked .o itself has them.
 */
static void pic_delta_table_stays_unresolved(void)
{
	const uint64_t va0 = 0x401000ull, table_va = 0x403000ull;
	static const uint8_t PIC_TEXT[] = {
		0x83, 0xff, 0x07,                               /* cmp edi,0x7 */
		0x0f, 0x87, 0x11, 0x00, 0x00, 0x00,              /* ja +0x11 (to the `ret` appended below, at offset 0x1c) */
		0x48, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00,        /* lea rdx,[rip+TABLE] */
		0x89, 0xff,                                      /* mov edi,edi */
		0x48, 0x63, 0x04, 0xba,                          /* movsxd rax,[rdx+rdi*4] */
		0x48, 0x01, 0xd0,                                /* add rax,rdx */
		0xff, 0xe0,                                      /* jmp rax */
		0xc3                                             /* ret (the `ja` target: not part of the real function, just a
		                                                  * valid decode target so `ja`'s branch stays local) */
	};
	uint8_t buf[sizeof PIC_TEXT], tbl[64];
	struct fake_table ft = { table_va, tbl, sizeof tbl };
	struct kgenome_cfg_switch_src sw = { table_read, &ft };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;

	memcpy(buf, PIC_TEXT, sizeof buf);
	put_u32(buf + 12, (uint32_t)(table_va - (va0 + 0x10)));        /* the lea's real rip-relative disp32 */
	memset(tbl, 0, sizeof tbl);                                    /* delta entries: 0 is not a valid absolute VA either way */
	st = build_of(buf, sizeof buf, va0, &sw, &in, &g);
	CKM(st == KGENOME_OK, "pic: build status %d", (int)st);
	disp = block_ending_at(&g, in, va0 + 0x19);
	CKM(disp != NULL, "pic: no block ends at jmp rax");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_EXIT, "pic: term %d, want EXIT (must stay unresolved, not misread a delta as a VA)", disp->term);
		CK(disp->n_switch == 0);
	}
	CK(g.n_switch_tgt == 0 && g.switch_tgt == NULL);
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/* ---- (7) a callback that refuses every read behaves exactly like "no table found": EXIT, no crash, no partial state ---- */
/* A non-NULL read_at that refuses every call (distinct from NULL: the pass IS entered and attempts the site). */
static int table_read_refuse(void *user, uint64_t va, void *out, uint32_t len)
{
	(void)user; (void)va; (void)out; (void)len;
	return 0;
}

static void refusing_callback_falls_back_safely(void)
{
	const uint64_t va0 = 0x401000ull;
	uint8_t buf[7] = { 0xff, 0x24, 0xfd, 0, 0, 0, 0 };
	struct kgenome_cfg_switch_src sw = { table_read_refuse, NULL };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	enum kgenome_status st;

	put_u32(buf + 3, 0x9000);
	st = build_of(buf, sizeof buf, va0, &sw, &in, &g);
	CKM(st == KGENOME_OK, "refuse: build status %d", (int)st);
	CKM(g.n_all == 1u && g.b[0].term == KGENOME_CFG_T_EXIT && g.n_switch_tgt == 0,
	    "refuse: a read_at that refuses every call must fall back to plain EXIT, not crash or half-resolve");
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/*
 * ---- (8)/(9) REAL mingw-w64 PE output, not a hand-built mimic - replacing this session's own [Inference] with an M.
 *
 * The open question (STATUS.md, "Full pipeline audit, ELF + PE", finding c): cases (2)/(6) above proved CASE_A
 * (direct `jmp [idx*N+table]`) and the PIC-delta shape only against gcc/ELF/Linux. The audit flagged, as
 * [Inference], that gcc's PIC-delta shape (6) is ALSO believed to be the standard x64 MSVC/mingw PE switch shape -
 * meaning REACH_INDIRECT might resolve close to 0% of real x64 PE switches once wired. Toolchains were not
 * available in that round. They are now (flatpak-spawn --host): confirmed M below.
 *
 * Source (both targets, identical body):
 *   __attribute__((noinline)) int work(int x) { return x * 3 + 1; }
 *   __attribute__((noinline)) int dispatch(int x) { switch (x) { case 0: return work(10); ... case 15: return
 *   work(160); default: return -1; } }   (16 contiguous cases: enough for gcc to always emit a jump table)
 *
 * Commands actually run (M, this session, 2026-11-05), compiling to a REAL loadable PE and linking it (not just
 * emitting a .o), then reading the function and table bytes back out of the linked image at their real file
 * offsets via objdump -d/-h and python:
 *   flatpak-spawn --host x86_64-w64-mingw32-gcc -O2 sw.c main.c -o sw_x64.exe
 *   flatpak-spawn --host i686-w64-mingw32-gcc   -O2 sw.c main.c -o sw_x86.exe
 *   flatpak-spawn --host objdump -d sw_x64.exe / sw_x86.exe   (find dispatch, its length, the table's section)
 *   flatpak-spawn --host objdump -h sw_x64.exe / sw_x86.exe   (section VMA/file-offset to map VA -> file byte)
 * gcc version string (M): "gcc version 14-win32 (GCC)" (Debian's mingw-w64 cross package, win32 threads). -O1,
 * -O2 and -O3 all produce IDENTICAL machine code for `dispatch` on both targets (M, `cmp` on the three .o files);
 * so do -fno-pic and explicit -fPIC on x86_64-w64-mingw32-gcc - all four combinations byte-for-byte identical to
 * plain -O2 (M). mingw-w64's reported defaults (`-Q --help=common`, this host): -fpic enabled, -fPIC/-fPIE/-fPIC
 * disabled; none of it moves this codegen - x86_64-w64-mingw32-gcc ALWAYS lowers this switch to the RIP-relative
 * delta-table shape, x64 PE ships no classic Windows ASLR switch is irrelevant to the compiler's choice here.
 *
 * x64 result (M, objdump -dr sw_x64.exe, dispatch at VA 0x140001460): BYTE-IDENTICAL IN SHAPE to case (6)'s ELF
 * PIC-delta fixture -
 *     cmp ecx,0xf ; ja <default> ; lea rdx,[rip+0x2b90] # -> 0x140004000 (.rdata) ; mov ecx,ecx
 *     movslq rax,[rdx+rcx*4] ; add rax,rdx ; jmp rax
 * (the one visible difference from the ELF fixture is the calling convention's argument register, ecx vs edi -
 * irrelevant to switch_find_table, which reads the jmp's own register and its block-local producer, not a fixed
 * name). The table itself (.rdata, VA 0x140004000) holds 16 SIGNED 32-bit DELTAS from the table's own base (e.g.
 * entry 0 = 0xffffd4a0 = -11104, target = 0x140004000 - 0x2b60 = 0x1400014a0, M, verified against every case body's
 * real address) - never absolute pointers, exactly the shape cfg_build.c's NAMED LIMITS note already names.
 * pe64_real_mingw_pic_delta_stays_unresolved() below feeds the REAL extracted bytes of this dispatch function (not
 * a hand-typed mimic) through kgenome_cfg_build and confirms (M, this patch) it stays a plain EXIT: switch_find_table
 * sees `jmp rax`'s producer is `add rax,rdx` (neither MOV/MOVZX/MOVSX/LEA), stops at step 2, and the table's own
 * bytes are never even read (switch_src.read_at observed 0 calls on this site). This answers the open question: on
 * this host and these three optimisation levels, x64 PE's compiler-emitted switch shape is the SAME unresolved
 * shape as default-PIC ELF, not the already-resolving CASE_A shape; this round's REACH_INDIRECT resolves 0 of the
 * x64 PE cases it was asked about, while staying correctly conservative (no misread address, no crash).
 *
 * x86 (32-bit PE) result (M, objdump -dr sw_x86.exe, dispatch at VA 0x00401500): the audit's OTHER half of the
 * prediction, confirmed -
 *     mov eax,[esp+4] ; cmp eax,0xf ; ja <default> ; jmp DWORD PTR [eax*4+0x404044]
 * - a single-instruction direct `jmp [idx*4+table]` with an ABSOLUTE dir32 base, exactly CASE_A's own shape (2),
 * just scale/entry-size 4 instead of 8 (32-bit pointers). pe32_real_mingw_direct_table_resolves() below feeds the
 * REAL extracted bytes and table through kgenome_cfg_build and confirms (M) it DOES resolve: KGENOME_CFG_T_SWITCH,
 * all 16 targets, each landing exactly on the real case body's first instruction (cross-checked against the
 * table's own real content, read back with objdump -s -j .rdata). Function-level claim only: this proves
 * resolve_switches() CAN resolve this real PE shape; it is not wired to a production caller this round (cfg_build.c's
 * own pass-6 comment, "NULL switch_src (every caller today)") - that remains separate, not-yet-done work.
 */
static const uint8_t PE64_DISPATCH_TEXT[] = {
	0x83, 0xf9, 0x0f, 0x0f, 0x87, 0x11, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x15,
	0x90, 0x2b, 0x00, 0x00, 0x89, 0xc9, 0x48, 0x63, 0x04, 0x8a, 0x48, 0x01,
	0xd0, 0xff, 0xe0, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xb9, 0x96, 0x00, 0x00,
	0x00, 0xeb, 0xc9, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xb9, 0xa0, 0x00, 0x00, 0x00, 0xeb, 0xb9, 0x66, 0x0f, 0x1f, 0x84, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xb9, 0x0a, 0x00, 0x00, 0x00, 0xeb, 0xa9, 0x66,
	0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x14, 0x00, 0x00,
	0x00, 0xeb, 0x99, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xb9, 0x1e, 0x00, 0x00, 0x00, 0xeb, 0x89, 0x66, 0x0f, 0x1f, 0x84, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xb9, 0x28, 0x00, 0x00, 0x00, 0xe9, 0x76, 0xff,
	0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xb9, 0x32, 0x00, 0x00,
	0x00, 0xe9, 0x66, 0xff, 0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xb9, 0x3c, 0x00, 0x00, 0x00, 0xe9, 0x56, 0xff, 0xff, 0xff, 0x66, 0x0f,
	0x1f, 0x44, 0x00, 0x00, 0xb9, 0x46, 0x00, 0x00, 0x00, 0xe9, 0x46, 0xff,
	0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xb9, 0x50, 0x00, 0x00,
	0x00, 0xe9, 0x36, 0xff, 0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xb9, 0x5a, 0x00, 0x00, 0x00, 0xe9, 0x26, 0xff, 0xff, 0xff, 0x66, 0x0f,
	0x1f, 0x44, 0x00, 0x00, 0xb9, 0x64, 0x00, 0x00, 0x00, 0xe9, 0x16, 0xff,
	0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xb9, 0x6e, 0x00, 0x00,
	0x00, 0xe9, 0x06, 0xff, 0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xb9, 0x78, 0x00, 0x00, 0x00, 0xe9, 0xf6, 0xfe, 0xff, 0xff, 0x66, 0x0f,
	0x1f, 0x44, 0x00, 0x00, 0xb9, 0x82, 0x00, 0x00, 0x00, 0xe9, 0xe6, 0xfe,
	0xff, 0xff, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xb9, 0x8c, 0x00, 0x00,
	0x00, 0xe9, 0xd6, 0xfe, 0xff, 0xff, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,
};
#define PE64_DISPATCH_VA 0x140001460ull
#define PE64_TABLE_VA    0x140004000ull

/* .rdata bytes at 0x140004000: 16 little-endian 32-bit SIGNED DELTAS from PE64_TABLE_VA (M, objdump -s -j .rdata);
 * never read by resolve_switches() on this input (it stops at step 2, before any table read), kept verbatim so the
 * fixture is the real image and not a stand-in. */
static const uint8_t PE64_TABLE_RAW[] = {
	0xa0, 0xd4, 0xff, 0xff, 0xb0, 0xd4, 0xff, 0xff, 0xc0, 0xd4, 0xff, 0xff,
	0xd0, 0xd4, 0xff, 0xff, 0xe0, 0xd4, 0xff, 0xff, 0xf0, 0xd4, 0xff, 0xff,
	0x00, 0xd5, 0xff, 0xff, 0x10, 0xd5, 0xff, 0xff, 0x20, 0xd5, 0xff, 0xff,
	0x30, 0xd5, 0xff, 0xff, 0x40, 0xd5, 0xff, 0xff, 0x50, 0xd5, 0xff, 0xff,
	0x60, 0xd5, 0xff, 0xff, 0x70, 0xd5, 0xff, 0xff, 0x80, 0xd4, 0xff, 0xff,
	0x90, 0xd4, 0xff, 0xff,
};

static void pe64_real_mingw_pic_delta_stays_unresolved(void)
{
	uint8_t buf[sizeof PE64_DISPATCH_TEXT];
	struct fake_table ft = { PE64_TABLE_VA, PE64_TABLE_RAW, sizeof PE64_TABLE_RAW };
	struct kgenome_cfg_switch_src sw = { table_read, &ft };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;

	memcpy(buf, PE64_DISPATCH_TEXT, sizeof buf);
	st = build_of_arch(buf, sizeof buf, PE64_DISPATCH_VA, KGENOME_ARCH_X86_64, &sw, &in, &g);
	CKM(st == KGENOME_OK, "pe64_real: build status %d", (int)st);
	disp = block_ending_at(&g, in, PE64_DISPATCH_VA + 0x19u);        /* the real `jmp rax`, at offset 0x19 into dispatch */
	CKM(disp != NULL, "pe64_real: no block ends at the real jmp rax");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_EXIT,
		    "pe64_real: term %d, want EXIT - real mingw x64 PE switch codegen must stay unresolved, matching the ELF PIC-delta case",
		    disp->term);
		CK(disp->n_switch == 0);
	}
	CK(g.n_switch_tgt == 0 && g.switch_tgt == NULL);
	kgenome_cfg_free(&g, NULL);
	free(in);
}

/* Real i686-w64-mingw32-gcc -O2 `dispatch` bytes (M, objdump -dr sw_x86.exe, VA 0x00401500..0x0040161b). */
static const uint8_t PE32_DISPATCH_TEXT[] = {
	0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x0f, 0x0f, 0x87, 0x08, 0x01, 0x00,
	0x00, 0xff, 0x24, 0x85, 0x44, 0x40, 0x40, 0x00, 0x8d, 0x74, 0x26, 0x00,
	0xc7, 0x44, 0x24, 0x04, 0x96, 0x00, 0x00, 0x00, 0xeb, 0xce, 0x8d, 0xb6,
	0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x04, 0xa0, 0x00, 0x00, 0x00,
	0xeb, 0xbe, 0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x04,
	0x0a, 0x00, 0x00, 0x00, 0xeb, 0xae, 0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00,
	0xc7, 0x44, 0x24, 0x04, 0x14, 0x00, 0x00, 0x00, 0xeb, 0x9e, 0x8d, 0xb6,
	0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x04, 0x1e, 0x00, 0x00, 0x00,
	0xeb, 0x8e, 0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x04,
	0x28, 0x00, 0x00, 0x00, 0xe9, 0x7b, 0xff, 0xff, 0xff, 0x8d, 0x76, 0x00,
	0xc7, 0x44, 0x24, 0x04, 0x32, 0x00, 0x00, 0x00, 0xe9, 0x6b, 0xff, 0xff,
	0xff, 0x8d, 0x76, 0x00, 0xc7, 0x44, 0x24, 0x04, 0x3c, 0x00, 0x00, 0x00,
	0xe9, 0x5b, 0xff, 0xff, 0xff, 0x8d, 0x76, 0x00, 0xc7, 0x44, 0x24, 0x04,
	0x46, 0x00, 0x00, 0x00, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x8d, 0x76, 0x00,
	0xc7, 0x44, 0x24, 0x04, 0x50, 0x00, 0x00, 0x00, 0xe9, 0x3b, 0xff, 0xff,
	0xff, 0x8d, 0x76, 0x00, 0xc7, 0x44, 0x24, 0x04, 0x5a, 0x00, 0x00, 0x00,
	0xe9, 0x2b, 0xff, 0xff, 0xff, 0x8d, 0x76, 0x00, 0xc7, 0x44, 0x24, 0x04,
	0x64, 0x00, 0x00, 0x00, 0xe9, 0x1b, 0xff, 0xff, 0xff, 0x8d, 0x76, 0x00,
	0xc7, 0x44, 0x24, 0x04, 0x6e, 0x00, 0x00, 0x00, 0xe9, 0x0b, 0xff, 0xff,
	0xff, 0x8d, 0x76, 0x00, 0xc7, 0x44, 0x24, 0x04, 0x78, 0x00, 0x00, 0x00,
	0xe9, 0xfb, 0xfe, 0xff, 0xff, 0x8d, 0x76, 0x00, 0xc7, 0x44, 0x24, 0x04,
	0x82, 0x00, 0x00, 0x00, 0xe9, 0xeb, 0xfe, 0xff, 0xff, 0x8d, 0x76, 0x00,
	0xc7, 0x44, 0x24, 0x04, 0x8c, 0x00, 0x00, 0x00, 0xe9, 0xdb, 0xfe, 0xff,
	0xff, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3,
};
#define PE32_DISPATCH_VA 0x00401500ull
#define PE32_TABLE_VA    0x00404044ull
/* .rdata bytes at 0x00404044: 16 little-endian 32-bit ABSOLUTE pointers, one per case, each landing exactly on
 * that case's real `mov [esp+4],imm` (M, objdump -s -j .rdata sw_x86.exe, cross-checked below by decoded VA). */
static const uint8_t PE32_TABLE_RAW[] = {
	0x38, 0x15, 0x40, 0x00, 0x48, 0x15, 0x40, 0x00, 0x58, 0x15, 0x40, 0x00,
	0x68, 0x15, 0x40, 0x00, 0x78, 0x15, 0x40, 0x00, 0x88, 0x15, 0x40, 0x00,
	0x98, 0x15, 0x40, 0x00, 0xa8, 0x15, 0x40, 0x00, 0xb8, 0x15, 0x40, 0x00,
	0xc8, 0x15, 0x40, 0x00, 0xd8, 0x15, 0x40, 0x00, 0xe8, 0x15, 0x40, 0x00,
	0xf8, 0x15, 0x40, 0x00, 0x08, 0x16, 0x40, 0x00, 0x18, 0x15, 0x40, 0x00,
	0x28, 0x15, 0x40, 0x00,
};
/* table[i]'s real target VA, read off objdump -s -j .rdata by hand (M) - the cross-check below trusts this, not
 * the other way round. */
static const uint64_t PE32_TABLE_TARGET_VA[16] = {
	0x401538, 0x401548, 0x401558, 0x401568, 0x401578, 0x401588, 0x401598, 0x4015a8,
	0x4015b8, 0x4015c8, 0x4015d8, 0x4015e8, 0x4015f8, 0x401608, 0x401518, 0x401528,
};

static void pe32_real_mingw_direct_table_resolves(void)
{
	uint8_t buf[sizeof PE32_DISPATCH_TEXT];
	struct fake_table ft = { PE32_TABLE_VA, PE32_TABLE_RAW, sizeof PE32_TABLE_RAW };
	struct kgenome_cfg_switch_src sw = { table_read, &ft };
	struct kgenome_cell_insn *in = NULL;
	struct kgenome_cfg g;
	const struct kgenome_cfg_block *disp;
	enum kgenome_status st;
	uint32_t i;

	memcpy(buf, PE32_DISPATCH_TEXT, sizeof buf);
	st = build_of_arch(buf, sizeof buf, PE32_DISPATCH_VA, KGENOME_ARCH_X86, &sw, &in, &g);
	CKM(st == KGENOME_OK, "pe32_real: build status %d", (int)st);
	disp = block_ending_at(&g, in, PE32_DISPATCH_VA + 0x0du);        /* the real `jmp [eax*4+table]`, at offset 0xd */
	CKM(disp != NULL, "pe32_real: no block ends at the real jmp [eax*4+table]");
	if (disp) {
		CKM(disp->term == KGENOME_CFG_T_SWITCH, "pe32_real: term %d, want SWITCH (real mingw x86 PE direct table must resolve)",
		    disp->term);
		CKM(disp->n_switch == 16u, "pe32_real: n_switch %u, want 16 (the cmp eax,0xf / ja bound)", disp->n_switch);
		CK(disp->switch_capped == 0);
		for (i = 0; i < disp->n_switch && i < 16u; i++) {
			const uint32_t ii = g.switch_tgt[disp->switch_first + i];

			CKM(in[ii].at_va == PE32_TABLE_TARGET_VA[i], "pe32_real: target %u at_va 0x%llx, want the real case body 0x%llx",
			    i, (unsigned long long)in[ii].at_va, (unsigned long long)PE32_TABLE_TARGET_VA[i]);
		}
	}
	CK(g.status == KGENOME_OK);
	kgenome_cfg_free(&g, NULL);
	free(in);
}

int main(void)
{
	null_callback_is_unchanged();
	case_a_resolves();
	case_b_resolves();
	cross_block_producer_does_not_resolve();
	cap_triggers_and_is_reported();
	pic_delta_table_stays_unresolved();
	refusing_callback_falls_back_safely();
	pe64_real_mingw_pic_delta_stays_unresolved();
	pe32_real_mingw_direct_table_resolves();
	if (fails) {
		printf("cfg_switch: %d failure(s)\n", fails);
		return 1;
	}
	printf("cfg_switch: ok\n");
	return 0;
}
