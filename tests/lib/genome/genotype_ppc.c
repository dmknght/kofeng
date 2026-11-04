/*
 * genotype_ppc - the PowerPC decode table against what the instruction set says.
 *
 * FOUR KINDS OF EVIDENCE, none of them a transcript of another decoder's answer:
 *   1. ppc_asm_vectors.inc: words ASSEMBLED by the LLVM assembler from a source line (tools/genotype/
 *      ppc_vectors_gen.py), each with the identity and every operand the line named. The table and this file
 *      are written from the same manual; an assembler is not.
 *   2. Words worked out by hand from the instruction-form diagrams for what the assembler does not know
 *      (601 segment registers, tlbia, mftb, lswx, eciwx ...), and for the edges: sc's fixed bits, stwcx.'s
 *      Rc, the 32-bit-mode refusal of every 64-bit-only identity.
 *   3. Structural exhaustion: every six-bit primary opcode x every value of the low eleven bits (the whole
 *      extended-opcode space and the Rc/OE/LK/AA bits) x 16 patterns of the fields between: each word has
 *      an identity inside the list, a status that says what the identity says, a name, the same answer
 *      twice, and the 64-bit mode never answers less than the 32-bit one.
 *   4. A million random words (a xorshift): decode is total and deterministic and keeps the word.
 * Target arithmetic is checked at the boundaries (b +-32 MB, bc +-32 KB, AA, the 32-bit wrap).
 *
 * The check against an independent DISASSEMBLER over real code is not in the tree: it needs a second decoder
 * (reported with the change that added this file).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <genotype/ppc/ppc.h>
#include <genotype/ppc/ppc_private.h>

static unsigned kgenome_ppc_attr_of(unsigned id)
{
	return id < KGENOME_PPC_I_COUNT ? kgenome_ppc_attr[id] : 0u;
}

static int failures;

static void ok(const char *what, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

/* ---- 1. assembled vectors ---------------------------------------------------------------------- */

struct vec {
	uint32_t w;
	uint16_t id;
	uint16_t mask;                  /* which fields below are asserted */
	int64_t  f[15];                 /* rt ra rb simm bo bi lk aa rc oe sh mb me spr off */
	const char *what;
	int p64;                        /* assembled for the 64-bit architecture */
};

static const struct vec V[] = {
#include "ppc_asm_vectors.inc"
};

static int64_t field(const struct kgenome_ppc_insn *in, unsigned k)
{
	switch (k) {
	case 0: return kgenome_ppc_rt(in);
	case 1: return kgenome_ppc_ra(in);
	case 2: return kgenome_ppc_rb(in);
	case 3: return in->id == KGENOME_PPC_I_LD || in->id == KGENOME_PPC_I_LDU || in->id == KGENOME_PPC_I_LWA ||
		       in->id == KGENOME_PPC_I_STD || in->id == KGENOME_PPC_I_STDU ? kgenome_ppc_ds(in) : kgenome_ppc_simm(in);
	case 4: return kgenome_ppc_bo(in);
	case 5: return kgenome_ppc_bi(in);
	case 6: return kgenome_ppc_lk(in);
	case 7: return kgenome_ppc_aa(in);
	case 8: return kgenome_ppc_rc(in);
	case 9: return kgenome_ppc_oe(in);
	case 10: return kgenome_ppc_sh(in);
	case 11: return kgenome_ppc_mb(in);
	case 12: return kgenome_ppc_me(in);
	case 13: return kgenome_ppc_spr(in);
	default: return kgenome_ppc_branch_off(in);
	}
}

static void check_vectors(void)
{
	size_t i;
	unsigned k, bad = 0;

	for (i = 0; i < sizeof V / sizeof *V; i++) {
		struct kgenome_ppc_insn in, n32;
		enum kgenome_status st = kgenome_ppc_decode(&in, V[i].w, V[i].p64);
		int good = in.id == V[i].id && in.word == V[i].w;

		if (V[i].id == KGENOME_PPC_I_UNSUPPORTED)
			good = good && st == KGENOME_UNSUPPORTED;
		else
			good = good && st == KGENOME_OK;
		for (k = 0; good && k < 15; k++)
			if ((V[i].mask >> k & 1u) && field(&in, k) != V[i].f[k])
				good = 0;
		/* the 32-bit mode: the same word, same identity unless the identity is 64-bit-only (then INVALID) */
		(void)kgenome_ppc_decode(&n32, V[i].w, 0);
		if (kgenome_ppc_attr_of(V[i].id) & KGENOME_PPC_A_P64)
			good = good && n32.id == KGENOME_PPC_I_INVALID;
		else if (V[i].p64 || 1)
			good = good && n32.id == V[i].id;
		if (!good) {
			printf("  FAIL vector %08x %s: got %s\n", V[i].w, V[i].what, kgenome_ppc_name(in.id));
			bad++;
		}
	}
	failures += (int)bad;
	printf("  %zu assembled vectors, %u failed\n", sizeof V / sizeof *V, bad);
}

/* ---- 2. by hand, from the instruction forms -------------------------------------------------------- */

struct hand {
	uint32_t w;
	unsigned id;
	int wide;                       /* decode in 64-bit mode */
	const char *what;
};

#define H(w, id, wide, what) { w, KGENOME_PPC_I_##id, wide, what }

static const struct hand HAND[] = {
	/* what is not an instruction */
	H(0x00000000u, INVALID, 0, "all zero: primary opcode 0"),
	H(0x04000000u, INVALID, 0, "primary opcode 1 (ISA 3.1 prefix: 8 bytes, not tabled)"),
	H(0x14000000u, INVALID, 0, "primary opcode 5"),
	H(0x18000000u, INVALID, 0, "primary opcode 6"),
	H(0x24000000u, INVALID, 0, "primary opcode 9"),
	H(0x58000000u, INVALID, 0, "primary opcode 22"),
	H(0x10000000u, UNSUPPORTED, 0, "primary opcode 4 (AltiVec / SPE)"),
	H(0xe0000000u, UNSUPPORTED, 0, "primary opcode 56"),
	H(0xe4000000u, UNSUPPORTED, 0, "primary opcode 57"),
	H(0xf0000000u, UNSUPPORTED, 0, "primary opcode 60"),
	H(0xf4000000u, UNSUPPORTED, 0, "primary opcode 61"),
	H(0x44000002u, SC, 0, "sc"),
	H(0x44000022u, SC, 0, "sc 1 (the LEV field is free)"),
	H(0x44000000u, INVALID, 0, "bit 30 clear: not sc"),
	H(0x44000003u, INVALID, 0, "bit 31 set: scv, not tabled"),
	H(0x7c00012cu, INVALID, 0, "stwcx. with Rc = 0 is not an instruction"),
	H(0x7c00012du, STWCX_, 0, "stwcx. (Rc = 1)"),
	H(0x7c0001adu, STDCX_, 1, "stdcx. (Rc = 1), 64-bit"),
	H(0x7c0001acu, INVALID, 1, "stdcx. with Rc = 0"),
	H(0x7c0001adu, INVALID, 0, "stdcx. in 32-bit mode"),
	/* what the assembler does not know or spells as something else */
	H(0x7c6c42e6u, MFTB, 0, "mftb r3 (xo 371)"),
	H(0x7c0002e4u, TLBIA, 0, "tlbia (xo 370)"),
	H(0x7c6004a6u, MFSR, 0, "mfsr r3,0 (xo 595)"),
	H(0x7c6001a4u, MTSR, 0, "mtsr 0,r3 (xo 210)"),
	H(0x7c6020e6u, INVALID, 0, "xo 115 (mfvsrwz): not tabled"),
	H(0x7c602526u, MFSRIN, 0, "mfsrin r3,r4 (xo 659)"),
	H(0x7c6021e4u, MTSRIN, 0, "mtsrin r3,r4 (xo 242)"),
	H(0x7c6023acu, DCBI, 0, "dcbi (xo 470)"),
	H(0x7c6025ecu, DCBA, 0, "dcba (xo 758)"),
	H(0x7c60242au, LSWX, 0, "lswx r3,0,r4 (xo 533)"),
	H(0x7c60252au, STSWX, 0, "stswx r3,0,r4 (xo 661)"),
	H(0x7c60226cu, ECIWX, 0, "eciwx r3,0,r4 (xo 310)"),
	H(0x7c60236cu, ECOWX, 0, "ecowx r3,0,r4 (xo 438)"),
	H(0x4bfffffeu, B, 0, "ba -4 (AA, LI = -1 word)"),
	H(0x4c000064u, RFI, 0, "rfi (xo 50)"),
	H(0x4c000024u, RFID, 1, "rfid (xo 18), 64-bit"),
	H(0x4c000024u, INVALID, 0, "rfid in 32-bit mode"),
	/* 64-bit only identities are INVALID in 32-bit mode and valid in 64-bit mode */
	H(0xe8610000u, LD, 1, "ld r3,0(r1)"),
	H(0xe8610000u, INVALID, 0, "ld in 32-bit mode"),
	H(0xe8610001u, LDU, 1, "ldu"),
	H(0xe8610002u, LWA, 1, "lwa"),
	H(0xe8610003u, INVALID, 1, "primary opcode 58 with the low bits 11"),
	H(0xf8610000u, STD, 1, "std"),
	H(0xf8610001u, STDU, 1, "stdu"),
	H(0xf8610002u, INVALID, 1, "stq is not tabled"),
	H(0x78000000u, RLDICL, 1, "rldicl"),
	H(0x78000000u, INVALID, 0, "rldicl in 32-bit mode"),
	H(0x7c000214u, ADD, 0, "add (xo 266 with OE = 1: addo)"),
	H(0x7c0001d2u, MULLD, 1, "mulld (xo 233)"),
	H(0x7c0001d2u, INVALID, 0, "mulld in 32-bit mode"),
	/* the five-bit extended opcode of isel wins over the table: 0x7c00001e */
	H(0x7c00001eu, ISEL, 0, "isel"),
	H(0x7fffffdeu, ISEL, 0, "isel with every operand field set"),
	/* the forms the architecture itself calls invalid */
	H(0x2c200000u, CMPI, 1, "cmpdi 0,r0,0 (L = 1) in 64-bit mode"),
	H(0x2c200000u, INVALID, 0, "cmpi with L = 1 in 32-bit mode"),
	H(0x28200000u, CMPLI, 1, "cmpldi in 64-bit mode"),
	H(0x28200000u, INVALID, 0, "cmpli with L = 1 in 32-bit mode"),
	H(0x7c200000u, CMP, 1, "cmpd in 64-bit mode"),
	H(0x7c200000u, INVALID, 0, "cmp with L = 1 in 32-bit mode"),
	H(0x7c200040u, CMPL, 1, "cmpld in 64-bit mode"),
	H(0x7c200040u, INVALID, 0, "cmpl with L = 1 in 32-bit mode"),
	H(0x2c000000u, CMPI, 0, "cmpwi 0,r0,0"),
	H(0x4c000420u, INVALID, 0, "bcctr with BO = 0 (decrement CTR): invalid form"),
	H(0x4c000420u, INVALID, 1, "bcctr with BO = 0, 64-bit mode"),
	H(0x4e800420u, BCCTR, 0, "bctr"),
	H(0x4d000420u, INVALID, 0, "bcctr with BO = 8 (bit 2 clear): invalid form"),
	H(0x4c800420u, BCCTR, 0, "bcctr with BO = 4 (branch if CR bit false)"),
	/* floating point: the A-form and the X-form of opcode 63 do not collide */
	H(0xfc00002au, FADD, 0, "fadd"),
	H(0xfc000000u, FCMPU, 0, "fcmpu"),
	H(0xec00002au, FADDS, 0, "fadds"),
	H(0xec000000u, INVALID, 0, "opcode 59 with xo 0"),
};

static void check_hand(void)
{
	size_t i;

	for (i = 0; i < sizeof HAND / sizeof *HAND; i++) {
		struct kgenome_ppc_insn in;
		enum kgenome_status st = kgenome_ppc_decode(&in, HAND[i].w, HAND[i].wide);
		int good = in.id == HAND[i].id && in.word == HAND[i].w &&
			   st == (HAND[i].id == KGENOME_PPC_I_INVALID ? KGENOME_INVALID
				: HAND[i].id == KGENOME_PPC_I_UNSUPPORTED ? KGENOME_UNSUPPORTED : KGENOME_OK);

		if (!good) {
			printf("  FAIL hand %08x %s: got %s status %d\n", HAND[i].w, HAND[i].what,
			       kgenome_ppc_name(in.id), (int)st);
			failures++;
		}
	}
	printf("  %zu hand-worked words\n", sizeof HAND / sizeof *HAND);
}

/* ---- target arithmetic ------------------------------------------------------------------------- */

static void check_targets(void)
{
	struct kgenome_ppc_insn in;
	int has;
	uint64_t t;

	(void)kgenome_ppc_decode(&in, 0x49fffffcu, 0);          /* b +0x1fffffc, the farthest forward */
	ok("b max forward off", kgenome_ppc_branch_off(&in) == 0x1fffffc);
	ok("b max forward target", kgenome_ppc_branch_target(&in, 0x10000000u, 0, &has) == 0x11fffffcu && has);
	(void)kgenome_ppc_decode(&in, 0x4a000000u, 0);          /* b -0x2000000, the farthest back */
	ok("b max back off", kgenome_ppc_branch_off(&in) == -0x2000000);
	ok("b max back target", kgenome_ppc_branch_target(&in, 0x10000000u, 0, &has) == 0x0e000000u);
	/* the 32-bit wrap: forward past 4 GB and back past zero */
	(void)kgenome_ppc_decode(&in, 0x48000100u, 0);
	t = kgenome_ppc_branch_target(&in, 0xffffff80u, 0, &has);
	ok("b wraps at 2^32 in 32-bit mode", t == 0x80u);
	t = kgenome_ppc_branch_target(&in, 0xffffff80u, 1, &has);
	ok("b does not wrap in 64-bit mode", t == 0x100000080ull);
	(void)kgenome_ppc_decode(&in, 0x4bffff00u, 0);          /* b -0x100 */
	t = kgenome_ppc_branch_target(&in, 0x80u, 0, &has);
	ok("b back past zero wraps in 32-bit mode", t == 0xffffff80u);
	/* absolute: the displacement IS the target, sign-extended */
	(void)kgenome_ppc_decode(&in, 0x4bfffffeu, 0);          /* ba -4 */
	ok("ba -4, 32-bit", kgenome_ppc_branch_target(&in, 0x12345678u, 0, &has) == 0xfffffffcu);
	ok("ba -4, 64-bit", kgenome_ppc_branch_target(&in, 0x12345678u, 1, &has) == 0xfffffffffffffffcull);
	(void)kgenome_ppc_decode(&in, 0x48000102u, 0);          /* ba 0x100 */
	ok("ba 0x100", kgenome_ppc_branch_target(&in, 0x12345678u, 0, &has) == 0x100u);
	(void)kgenome_ppc_decode(&in, 0x48000103u, 0);          /* bla 0x100: LK does not move the target */
	ok("bla 0x100", kgenome_ppc_branch_target(&in, 0x12345678u, 0, &has) == 0x100u && kgenome_ppc_lk(&in));
	/* bc: 14-bit displacement */
	(void)kgenome_ppc_decode(&in, 0x41827ffcu, 0);          /* beq .+0x7ffc */
	ok("bc max forward", kgenome_ppc_branch_off(&in) == 0x7ffc);
	(void)kgenome_ppc_decode(&in, 0x41828000u, 0);          /* beq .-0x8000 */
	ok("bc max back", kgenome_ppc_branch_off(&in) == -0x8000);
	ok("bc max back target", kgenome_ppc_branch_target(&in, 0x10008000u, 0, &has) == 0x10000000u);
	(void)kgenome_ppc_decode(&in, 0x41820001u, 0);          /* the low bit of BD*4 is LK, not a displacement bit */
	ok("bc low bits are AA/LK", kgenome_ppc_branch_off(&in) == 0 && kgenome_ppc_lk(&in) == 1);
	(void)kgenome_ppc_decode(&in, 0x2c200000u, 1);          /* the compare's L bit and field BF */
	ok("cmp L", kgenome_ppc_cmp_l(&in) == 1 && kgenome_ppc_bf(&in) == 0);
	(void)kgenome_ppc_decode(&in, 0x2d800000u, 1);          /* cmpwi cr3 */
	ok("cmp BF", kgenome_ppc_bf(&in) == 3 && kgenome_ppc_cmp_l(&in) == 0);
	(void)kgenome_ppc_decode(&in, 0x4e800020u, 0);          /* blr: no direct target */
	(void)kgenome_ppc_branch_target(&in, 0x1000u, 0, &has);
	ok("blr has no target", !has && kgenome_ppc_branch_off(&in) == 0);
	(void)kgenome_ppc_decode(&in, 0x38600005u, 0);          /* li: not a branch */
	(void)kgenome_ppc_branch_target(&in, 0x1000u, 0, &has);
	ok("li has no target", !has);
}

/* ---- 3. structural exhaustion --------------------------------------------------------------------- */

static void check_exhaustive(void)
{
	static const uint32_t mid[16] = { 0x0000u, 0x7fffu, 0x5555u, 0x2aaau, 0x0001u, 0x0020u, 0x0400u, 0x4000u,
					  0x1f00u, 0x00f8u, 0x3e1fu, 0x7c00u, 0x0f0fu, 0x1234u, 0x6789u, 0x0842u };
	uint64_t n = 0, nvalid = 0, nuns = 0, ninv = 0, n64only = 0;
	unsigned op, lo, m;

	for (op = 0; op < 64; op++)
		for (m = 0; m < 16; m++)
			for (lo = 0; lo < 2048; lo++) {
				uint32_t w = (uint32_t)op << 26 | (mid[m] << 11) | lo;
				struct kgenome_ppc_insn a, a2, b;
				enum kgenome_status sa = kgenome_ppc_decode(&a, w, 0), sa2 = kgenome_ppc_decode(&a2, w, 0);
				enum kgenome_status sb = kgenome_ppc_decode(&b, w, 1);
				int bad = 0;

				n++;
				bad |= a.id >= KGENOME_PPC_I_COUNT || b.id >= KGENOME_PPC_I_COUNT;
				bad |= a.id != a2.id || sa != sa2 || a.word != w || b.word != w;
				bad |= kgenome_ppc_name(a.id)[0] == '?' || kgenome_ppc_name(a.id)[0] == 0;
				bad |= sa != (a.id == KGENOME_PPC_I_INVALID ? KGENOME_INVALID
					 : a.id == KGENOME_PPC_I_UNSUPPORTED ? KGENOME_UNSUPPORTED : KGENOME_OK);
				bad |= sb != (b.id == KGENOME_PPC_I_INVALID ? KGENOME_INVALID
					 : b.id == KGENOME_PPC_I_UNSUPPORTED ? KGENOME_UNSUPPORTED : KGENOME_OK);
				/* the 64-bit mode answers at least what the 32-bit one does, with the same identity */
				if (a.id != KGENOME_PPC_I_INVALID)
					bad |= b.id != a.id;
				else
					n64only += b.id != KGENOME_PPC_I_INVALID;
				/* an identity that is 64-bit only never answers in 32-bit mode */
				bad |= (kgenome_ppc_attr_of(a.id) & KGENOME_PPC_A_P64) != 0;
				/* an identity that needs Rc = 1 has it */
				bad |= (kgenome_ppc_attr_of(b.id) & KGENOME_PPC_A_RC1) && !(w & 1u);
				if (bad) {
					printf("  FAIL structural word %08x: %s / %s\n", w, kgenome_ppc_name(a.id),
					       kgenome_ppc_name(b.id));
					failures++;
					return;
				}
				if (a.id == KGENOME_PPC_I_INVALID)
					ninv++;
				else if (a.id == KGENOME_PPC_I_UNSUPPORTED)
					nuns++;
				else
					nvalid++;
			}
	printf("  structural: %llu words, %llu instruction, %llu unsupported, %llu invalid in 32-bit mode (%llu valid only in 64-bit mode)\n",
	       (unsigned long long)n, (unsigned long long)nvalid, (unsigned long long)nuns,
	       (unsigned long long)ninv, (unsigned long long)n64only);
	/* the extended-opcode space of opcode 31 is not empty and is not full */
	ok("opcode 31 has instructions and holes", nvalid > 50000 && ninv > 50000);
}

/* opcode 31 index: every one of the 1024 extended opcodes, field values 0, then the answer must not depend on bits 6..20 */
static void check_x31_independent_of_operands(void)
{
	unsigned xo, k;

	for (xo = 0; xo < 1024; xo++) {
		struct kgenome_ppc_insn base, other;
		uint32_t w0 = 31u << 26 | xo << 1;

		(void)kgenome_ppc_decode(&base, w0, 1);
		for (k = 6; k < 21; k++) {
			uint32_t w1 = w0 | 1u << (31u - k);

			(void)kgenome_ppc_decode(&other, w1, 1);
			/* an operand bit never changes the identity, except through isel's five-bit opcode (bits 26..30 = 01111) */
			if (other.id != base.id && !((w0 & 0x3eu) == 0x1eu) && !((w1 & 0x3eu) == 0x1eu)) {
				printf("  FAIL xo %u: setting operand bit %u changes %s to %s\n", xo, k,
				       kgenome_ppc_name(base.id), kgenome_ppc_name(other.id));
				failures++;
				return;
			}
		}
	}
}

/* the table's holes and Rc/OE/AA/LK bits: no identity depends on bit 0 except the two RC1 forms, sc and the 64-bit rotate forms */
static void check_rc_independent(void)
{
	uint64_t x = 0x9e3779b97f4a7c15ull;
	unsigned i;

	for (i = 0; i < 200000; i++) {
		struct kgenome_ppc_insn a, b;
		uint32_t w;

		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		w = (uint32_t)x;
		(void)kgenome_ppc_decode(&a, w & ~1u, 1);
		(void)kgenome_ppc_decode(&b, w | 1u, 1);
		if (a.id != b.id && !(kgenome_ppc_attr_of(a.id) & KGENOME_PPC_A_RC1) &&
		    !(kgenome_ppc_attr_of(b.id) & KGENOME_PPC_A_RC1) && (w >> 26) != 17 && (w >> 26) != 58 &&
		    (w >> 26) != 62 && a.id != KGENOME_PPC_I_INVALID && b.id != KGENOME_PPC_I_INVALID) {
			printf("  FAIL bit 0 changes %s to %s in %08x\n", kgenome_ppc_name(a.id), kgenome_ppc_name(b.id), w);
			failures++;
			return;
		}
	}
}

/* ---- 4. arbitrary words ----------------------------------------------------------------------------- */

static void check_random(void)
{
	uint64_t x = 0x243f6a8885a308d3ull;
	unsigned i;
	unsigned long long inv = 0, uns = 0, okc = 0;

	for (i = 0; i < 1000000; i++) {
		struct kgenome_ppc_insn a, b;
		uint32_t w;

		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		w = (uint32_t)(x >> 16);
		(void)kgenome_ppc_decode(&a, w, i & 1);
		(void)kgenome_ppc_decode(&b, w, i & 1);
		if (a.id != b.id || a.word != w || a.id >= KGENOME_PPC_I_COUNT) {
			printf("  FAIL random word %08x\n", w);
			failures++;
			return;
		}
		if (a.id == KGENOME_PPC_I_INVALID)
			inv++;
		else if (a.id == KGENOME_PPC_I_UNSUPPORTED)
			uns++;
		else
			okc++;
	}
	printf("  random: %llu instruction, %llu unsupported, %llu invalid of 1000000\n", okc, uns, inv);
}

static void check_names(void)
{
	unsigned i, j;

	ok("past the end", strcmp(kgenome_ppc_name(KGENOME_PPC_I_COUNT), "?") == 0 &&
	   kgenome_ppc_attr_of(KGENOME_PPC_I_COUNT) == 0);
	for (i = 0; i < KGENOME_PPC_I_COUNT; i++)
		for (j = i + 1; j < KGENOME_PPC_I_COUNT; j++)
			if (!strcmp(kgenome_ppc_name(i), kgenome_ppc_name(j))) {
				printf("  FAIL duplicate name %s\n", kgenome_ppc_name(i));
				failures++;
			}
}

int main(void)
{
	check_vectors();
	check_hand();
	check_targets();
	check_exhaustive();
	check_x31_independent_of_operands();
	check_rc_independent();
	check_random();
	check_names();
	printf("genotype_ppc: %s\n", failures ? "FAILED" : "all ok");
	return failures ? 1 : 0;
}
