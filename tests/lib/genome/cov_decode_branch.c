/*
 * cov_decode_branch - the ARM, Thumb, AArch64 and MIPS decoders, swept over their instruction spaces and held to the
 * architecture manuals' formulas for where a branch goes.
 *
 * WHAT IS ASSERTED, for millions of encodings drawn from a fixed seed (and every first halfword of Thumb):
 *
 *   LENGTH         a word is four bytes; a Thumb instruction is two or four by the top five bits of its first
 *                  halfword and no decoder needs the second one to say so; with too few bytes the answer is 0
 *   ENDIAN         the same instruction written big-endian (a word, or each halfword) decodes to exactly the same
 *                  fields - the byte order is the reader's, the meaning is not
 *   BRANCHES       every direct branch the manuals define has the class and the target their formulas give, from the
 *                  fields of the encoding: ARM B/BL/BLX (imm24, the H bit), Thumb B (T1 imm8, T2 imm11), B.W (T3,
 *                  T4), BL and BLX (the J1/J2 arithmetic) and the aligned PC of BLX, A64 B, BL, B.cond, CBZ/CBNZ and
 *                  TBZ/TBNZ, MIPS J, JAL and the 16 bit branches. The formulas are written in this file from the
 *                  manuals, not read from the decoder.
 *   WRITES         the registers an instruction writes are inside the register file of the architecture (r0-r15,
 *                  x0-x30 and sp, r0-r31)
 *   DETERMINISM    the same bytes decode to the same fields twice
 *
 * No reference decoder is needed: the oracle is a handful of lines per branch form.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <celllysis/cell.h>
#include <celllysis/decode.h>

static unsigned fails, nbranch[4];

#define CK(cond, ...) do { \
	if (!(cond)) { \
		if (fails < 40) { \
			printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
		fails++; \
	} \
} while (0)

static uint64_t rs = 0x9e3779b97f4a7c15ull;

static uint32_t rnd32(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 16);
}

static int64_t sext(uint64_t v, unsigned bits)
{
	uint64_t m = 1ull << (bits - 1u);

	v &= (1ull << bits) - 1ull;
	return (int64_t)((v ^ m) - m);
}

static void put_le32(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8); p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

static void put_be32(uint8_t *p, uint32_t w)
{
	p[3] = (uint8_t)w; p[2] = (uint8_t)(w >> 8); p[1] = (uint8_t)(w >> 16); p[0] = (uint8_t)(w >> 24);
}

/* two decodes of the same instruction agree on everything a consumer reads */
static int same(const struct kgenome_cell_insn *a, const struct kgenome_cell_insn *b)
{
	unsigned k;

	if (a->op != b->op || a->len != b->len || a->n_op != b->n_op || a->cond != b->cond || a->flags != b->flags ||
	    a->wmask != b->wmask || a->at_va != b->at_va || a->target != b->target || a->target_va != b->target_va)
		return 0;
	for (k = 0; k < 3; k++) {
		const struct kgenome_cell_operand *x = &a->o[k], *y = &b->o[k];

		if (x->kind != y->kind || x->reg != y->reg || x->index != y->index || x->scale != y->scale ||
		    x->size != y->size || x->flags != y->flags || x->disp != y->disp || x->imm != y->imm)
			return 0;
	}
	return 1;
}

static int is_branch_class(unsigned op)
{
	return op == KGENOME_CELL_JMP || op == KGENOME_CELL_JCC || op == KGENOME_CELL_CALL;
}

/* ---- ARM state ------------------------------------------------------------------------------ */

static void t_arm32(void)
{
	unsigned i;

	for (i = 0; i < 3000000; i++) {
		uint32_t w = rnd32(), cond = w >> 28;
		uint64_t va = ((uint64_t)(rnd32() & 0x3ffffffcu)) + 0x10000u;
		uint8_t p[4], q[4];
		struct kgenome_cell_insn a, b, c;
		uint32_t r, r2;

		if ((i & 0x3ffu) == 0)
			w = (w & 0xf0ffffffu) | 0x0a000000u | ((i & 0x400u) ? 0x01000000u : 0u);   /* force the branch space */
		cond = w >> 28;
		put_le32(p, w);
		put_be32(q, w);
		r = kgenome_cell_decode_arm32(p, 4, va, 0, &a);
		r2 = kgenome_cell_decode_arm32(q, 4, va, 1, &b);
		CK(r == 4 && a.len == 4, "arm %08x length %u", w, r);
		CK(r2 == 4 && same(&a, &b), "arm %08x big-endian differs", w);
		CK(kgenome_cell_decode_arm32(p, 4, va, 0, &c) == 4 && same(&a, &c), "arm %08x not deterministic", w);
		CK((a.wmask >> 16) == 0, "arm %08x writes a register past r15 (%llx)", w, (unsigned long long)a.wmask);
		CK(a.at_va == va, "arm %08x at_va", w);
		if (((w >> 25) & 7u) == 5u) {
			int64_t off = sext(w & 0xffffffu, 24) * 4;

			nbranch[0]++;
			if (cond != 0xfu) {
				uint64_t want = (va + 8u + (uint64_t)off) & 0xffffffffu;

				CK(a.target_va == want, "arm %08x at %llx: target %llx, want %llx", w, (unsigned long long)va,
				   (unsigned long long)a.target_va, (unsigned long long)want);
				if (w & 0x01000000u)
					CK(a.op == KGENOME_CELL_CALL, "arm bl %08x class %u", w, a.op);
				else
					CK(a.op == (cond == 0xeu ? KGENOME_CELL_JMP : KGENOME_CELL_JCC), "arm b %08x class %u", w, a.op);
				if (a.op == KGENOME_CELL_JCC)
					CK(a.cond == cond, "arm %08x condition %u", w, a.cond);
				CK(a.n_op == 1 && a.o[0].kind == KGENOME_CELL_O_REL, "arm %08x operand", w);
				CK(a.wmask & (1ull << 15), "arm %08x writes pc", w);
			} else {
				/* blx (immediate): to Thumb, the H bit is the halfword; the Thumb bit is not part of the target */
				uint64_t want = (va + 8u + (uint64_t)off + ((w & 0x01000000u) ? 2u : 0u)) & 0xfffffffeu;

				CK(a.op == KGENOME_CELL_CALL && a.target_va == want, "arm blx %08x: class %u target %llx, want %llx", w,
				   a.op, (unsigned long long)a.target_va, (unsigned long long)want);
			}
		}
	}
	for (i = 0; i < 4; i++) {
		uint8_t p[4] = { 0x01, 0x02, 0x03, 0x04 };
		struct kgenome_cell_insn a;

		CK(kgenome_cell_decode_arm32(p, i, 0, 0, &a) == 0, "arm with %u byte(s)", i);
	}
	CK(kgenome_cell_decode_arm32(NULL, 4, 0, 0, &(struct kgenome_cell_insn){ 0 }) == 0, "arm: no bytes");
	CK(nbranch[0] > 100000, "arm: enough branches (%u)", nbranch[0]);
}

/* ---- Thumb --------------------------------------------------------------------------------- */

static void t_thumb(void)
{
	uint32_t h1;
	unsigned k;

	for (h1 = 0; h1 < 65536; h1++) {
		for (k = 0; k < 96; k++) {
			uint32_t h2 = rnd32() & 0xffffu;
			uint64_t va = ((uint64_t)(rnd32() & 0x3ffffffeu)) + 0x10000u;
			int is32 = (h1 >> 11) >= 0x1du;
			uint8_t p[4], q[4], one[2];
			struct kgenome_cell_insn a, b, c;
			uint32_t r, r2;

			if (k && !is32)
				break;                 /* a 16 bit instruction does not depend on what follows: once is enough */
			if (k == 1 && (rnd32() & 3u))
				va &= ~3ull;           /* both alignments of the PC for BLX */
			p[0] = (uint8_t)h1; p[1] = (uint8_t)(h1 >> 8); p[2] = (uint8_t)h2; p[3] = (uint8_t)(h2 >> 8);
			q[0] = (uint8_t)(h1 >> 8); q[1] = (uint8_t)h1; q[2] = (uint8_t)(h2 >> 8); q[3] = (uint8_t)h2;
			r = kgenome_cell_decode_thumb(p, 4, va, 0, &a);
			r2 = kgenome_cell_decode_thumb(q, 4, va, 1, &b);
			CK(r == (is32 ? 4u : 2u) && a.len == r, "thumb %04x %04x: length %u", h1, h2, r);
			CK(r2 == r && same(&a, &b), "thumb %04x %04x: big-endian differs", h1, h2);
			CK(kgenome_cell_decode_thumb(p, 4, va, 0, &c) == r && same(&a, &c), "thumb %04x not deterministic", h1);
			CK((a.wmask >> 16) == 0, "thumb %04x %04x writes past r15", h1, h2);
			/* the length does not need the bytes it does not have */
			one[0] = p[0]; one[1] = p[1];
			if (is32) {
				CK(kgenome_cell_decode_thumb(one, 2, va, 0, &c) == 0, "thumb %04x: a 32 bit instruction with two bytes", h1);
				CK(kgenome_cell_decode_thumb(p, 3, va, 0, &c) == 0, "thumb %04x: a 32 bit instruction with three bytes", h1);
			} else {
				CK(kgenome_cell_decode_thumb(one, 2, va, 0, &c) == 2, "thumb %04x with exactly two bytes", h1);
			}
			CK(kgenome_cell_decode_thumb(p, 1, va, 0, &c) == 0, "thumb with one byte");

			/* branches */
			if ((h1 >> 11) == 0x1cu) {                         /* B (T2) */
				uint64_t want = (va + 4u + (uint64_t)(sext(h1 & 0x7ffu, 11) * 2)) & 0xffffffffu;

				nbranch[1]++;
				CK(a.op == KGENOME_CELL_JMP && a.target_va == want, "thumb b %04x at %llx: %llx want %llx", h1,
				   (unsigned long long)va, (unsigned long long)a.target_va, (unsigned long long)want);
			} else if ((h1 >> 12) == 0xdu && ((h1 >> 8) & 0xfu) < 0xeu) {   /* B<c> (T1) */
				uint64_t want = (va + 4u + (uint64_t)(sext(h1 & 0xffu, 8) * 2)) & 0xffffffffu;

				nbranch[1]++;
				CK(a.op == KGENOME_CELL_JCC && a.target_va == want && a.cond == ((h1 >> 8) & 0xfu),
				   "thumb b<c> %04x: class %u target %llx want %llx cond %u", h1, a.op, (unsigned long long)a.target_va,
				   (unsigned long long)want, a.cond);
			} else if ((h1 >> 11) == 0x1eu) {                  /* the 32 bit branches */
				uint32_t s = (h1 >> 10) & 1u, j1 = (h2 >> 13) & 1u, j2 = (h2 >> 11) & 1u;
				uint32_t i1 = (~(j1 ^ s)) & 1u, i2 = (~(j2 ^ s)) & 1u;
				uint64_t want;

				switch (h2 & 0xd000u) {
				case 0xd000u:                              /* BL */
					want = (va + 4u + (uint64_t)sext(((uint64_t)s << 24) | ((uint64_t)i1 << 23) | ((uint64_t)i2 << 22) |
									 ((uint64_t)(h1 & 0x3ffu) << 12) | ((uint64_t)(h2 & 0x7ffu) << 1), 25)) &
					       0xffffffffu;
					nbranch[1]++;
					CK(a.op == KGENOME_CELL_CALL && a.target_va == want, "thumb bl %04x %04x at %llx: class %u %llx want %llx",
					   h1, h2, (unsigned long long)va, a.op, (unsigned long long)a.target_va, (unsigned long long)want);
					break;
				case 0x9000u:                              /* B.W (T4) */
					want = (va + 4u + (uint64_t)sext(((uint64_t)s << 24) | ((uint64_t)i1 << 23) | ((uint64_t)i2 << 22) |
									 ((uint64_t)(h1 & 0x3ffu) << 12) | ((uint64_t)(h2 & 0x7ffu) << 1), 25)) &
					       0xffffffffu;
					nbranch[1]++;
					CK(a.op == KGENOME_CELL_JMP && a.target_va == want, "thumb b.w %04x %04x: class %u %llx want %llx", h1, h2,
					   a.op, (unsigned long long)a.target_va, (unsigned long long)want);
					break;
				case 0xc000u:                              /* BLX (T2): to ARM state, the PC word aligned */
					if (!(h2 & 1u)) {
						uint64_t pc = (va + 4u) & ~3ull;

						want = (pc + (uint64_t)sext(((uint64_t)s << 24) | ((uint64_t)i1 << 23) | ((uint64_t)i2 << 22) |
									    ((uint64_t)(h1 & 0x3ffu) << 12) | ((uint64_t)((h2 >> 1) & 0x3ffu) << 2), 25)) &
						       0xffffffffu;
						nbranch[1]++;
						CK(a.op == KGENOME_CELL_CALL && a.target_va == want,
						   "thumb blx %04x %04x at %llx: class %u %llx want %llx", h1, h2, (unsigned long long)va, a.op,
						   (unsigned long long)a.target_va, (unsigned long long)want);
					}
					break;
				case 0x8000u:                              /* B<c>.W (T3) */
					if (((h1 >> 6) & 0xfu) < 0xeu) {
						want = (va + 4u + (uint64_t)sext(((uint64_t)s << 20) | ((uint64_t)j2 << 19) | ((uint64_t)j1 << 18) |
										 ((uint64_t)(h1 & 0x3fu) << 12) | ((uint64_t)(h2 & 0x7ffu) << 1), 21)) &
						       0xffffffffu;
						nbranch[1]++;
						CK(a.op == KGENOME_CELL_JCC && a.target_va == want && a.cond == ((h1 >> 6) & 0xfu),
						   "thumb b<c>.w %04x %04x: class %u %llx want %llx cond %u", h1, h2, a.op,
						   (unsigned long long)a.target_va, (unsigned long long)want, a.cond);
					}
					break;
				default:
					break;
				}
			}
		}
	}
	CK(nbranch[1] > 50000, "thumb: enough branches (%u)", nbranch[1]);
}

/* ---- AArch64 ------------------------------------------------------------------------------- */

static void t_arm64(void)
{
	unsigned i;

	for (i = 0; i < 4000000; i++) {
		uint32_t w = rnd32();
		uint64_t va = ((uint64_t)rnd32() << 8 | (rnd32() & 0xfcu)) + 0x400000u;
		uint8_t p[4];
		struct kgenome_cell_insn a, c;
		uint32_t r;
		uint64_t want = 0;
		int is = 0;
		unsigned cls = 0;

		if ((i & 7u) == 0) {                         /* force the branch space: eight of every sixty four */
			static const uint32_t top[] = { 0x14000000u, 0x94000000u, 0x54000000u, 0x34000000u, 0xb5000000u, 0x36000000u,
							0xb7000000u, 0x35000000u };

			w = (w & 0x00ffffffu) | top[(i >> 3) & 7u];
			if ((w >> 24) == 0x54u)
				w &= ~0x10u;
		}
		put_le32(p, w);
		r = kgenome_cell_decode_arm64(p, 4, va, &a);
		CK(r == 4 && a.len == 4, "a64 %08x length %u", w, r);
		CK(kgenome_cell_decode_arm64(p, 4, va, &c) == 4 && same(&a, &c), "a64 %08x not deterministic", w);
		CK((a.wmask >> 32) == 0, "a64 %08x writes past sp", w);
		if ((w >> 26) == 0x05u || (w >> 26) == 0x25u) {            /* B, BL */
			want = va + (uint64_t)(sext(w & 0x3ffffffu, 26) * 4);
			cls = (w >> 31) ? KGENOME_CELL_CALL : KGENOME_CELL_JMP;
			is = 1;
		} else if ((w >> 24) == 0x54u && !(w & 0x10u)) {           /* B.cond */
			want = va + (uint64_t)(sext((w >> 5) & 0x7ffffu, 19) * 4);
			cls = KGENOME_CELL_JCC;
			is = 1;
		} else if ((w & 0x7e000000u) == 0x34000000u) {             /* CBZ, CBNZ */
			want = va + (uint64_t)(sext((w >> 5) & 0x7ffffu, 19) * 4);
			cls = KGENOME_CELL_JCC;
			is = 1;
		} else if ((w & 0x7e000000u) == 0x36000000u) {             /* TBZ, TBNZ */
			want = va + (uint64_t)(sext((w >> 5) & 0x3fffu, 14) * 4);
			cls = KGENOME_CELL_JCC;
			is = 1;
		}
		if (is) {
			nbranch[2]++;
			CK(a.op == cls && a.target_va == want, "a64 %08x at %llx: class %u (want %u) target %llx want %llx", w,
			   (unsigned long long)va, a.op, cls, (unsigned long long)a.target_va, (unsigned long long)want);
			CK(a.o[0].kind == KGENOME_CELL_O_REL, "a64 %08x operand", w);
			if (cls == KGENOME_CELL_CALL)
				CK(a.wmask & (1ull << 30), "a64 bl %08x writes x30", w);
		}
	}
	{
		uint8_t p[4] = { 0, 0, 0, 0x14 };
		struct kgenome_cell_insn a;
		unsigned n;

		for (n = 0; n < 4; n++)
			CK(kgenome_cell_decode_arm64(p, n, 0, &a) == 0, "a64 with %u byte(s)", n);
	}
	CK(nbranch[2] > 100000, "a64: enough branches (%u)", nbranch[2]);
}

/* ---- MIPS ---------------------------------------------------------------------------------- */

static void t_mips(void)
{
	unsigned i;

	for (i = 0; i < 3000000; i++) {
		uint32_t w = rnd32();
		uint64_t va = ((uint64_t)(rnd32() & 0x0ffffffcu)) + 0x10000000u;
		uint8_t p[4], q[4];
		struct kgenome_cell_insn a, b;
		uint32_t r, r2, op;

		if ((i & 3u) == 0)
			w = (w & 0x03ffffffu) | ((2u + ((i >> 2) & 3u)) << 26);       /* J, JAL, BEQ, BNE */
		put_le32(p, w);
		put_be32(q, w);
		r = kgenome_cell_decode_mips(p, 4, va, 0, &a);
		r2 = kgenome_cell_decode_mips(q, 4, va, 1, &b);
		CK(r == 4 && r2 == 4 && a.len == 4, "mips %08x length", w);
		CK(same(&a, &b), "mips %08x big-endian differs", w);
		CK((a.wmask >> 32) == 0, "mips %08x writes past r31", w);
		op = w >> 26;
		if (op == 2u || op == 3u) {
			uint64_t want = ((va + 4u) & 0xfffffffff0000000ull) | ((uint64_t)(w & 0x3ffffffu) << 2);

			nbranch[3]++;
			CK(a.op == (op == 2u ? KGENOME_CELL_JMP : KGENOME_CELL_CALL) && a.target_va == want,
			   "mips j/jal %08x: class %u target %llx want %llx", w, a.op, (unsigned long long)a.target_va,
			   (unsigned long long)want);
			if (op == 3u)
				CK(a.wmask & (1ull << 31), "mips jal writes ra");
		} else if (op == 4u || op == 5u) {
			uint64_t want = va + 4u + (uint64_t)(sext(w & 0xffffu, 16) * 4);

			nbranch[3]++;
			CK(is_branch_class(a.op) && a.target_va == want, "mips beq/bne %08x at %llx: class %u target %llx want %llx", w,
			   (unsigned long long)va, a.op, (unsigned long long)a.target_va, (unsigned long long)want);
		}
	}
	CK(nbranch[3] > 100000, "mips: enough branches (%u)", nbranch[3]);
}

int main(void)
{
	t_arm32();
	t_thumb();
	t_arm64();
	t_mips();
	printf("  branches checked: arm %u thumb %u a64 %u mips %u\n", nbranch[0], nbranch[1], nbranch[2], nbranch[3]);
	if (fails) {
		printf("cov_decode_branch: FAILED (%u)\n", fails);
		return 1;
	}
	printf("cov_decode_branch: ok\n");
	return 0;
}
