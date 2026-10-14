/*
 * diff_ops_ext - the interpreter's BMI1/BMI2, ADX, MOVBE, CRC32, CMPXCHG8B/16B, ENTER, XLATB, AAM and AAD against the
 * host CPU (the last two, which exist only in 32-bit mode, against the manual's own algorithm, as cov_emu_int.c checks
 * the other BCD adjusts).
 *
 * The method is cov_native.h's: each case is the same bytes run natively and in the interpreter, the general registers,
 * the memory the instruction writes and the flags it DEFINES compared. A flag the manual calls undefined is masked beside
 * the instruction; ADCX, ADOX, MULX, PDEP, PEXT, RORX and the shifts touch no other flag and are compared on all of them.
 * Operands are edge values (0, 1, all ones, the sign bit, a single bit, noise) so that CF, ZF, SF and the width boundaries
 * of every instruction are met. A group the host CPU does not have (CPUID) is skipped by name, visibly.
 */

#include "cov_native.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static struct cn_stat st;
static unsigned groups, vectors;

static void finish(const char *family)
{
	cn_print(family, &st);
	CK(st.native_ok == st.cases, "%s: the host ran every vector", family);
	CK(st.unsupported == 0, "%s: carried (%u refused)", family, st.unsupported);
	CK(st.diffs == 0, "%s: equal the CPU (%u of %u differ)", family, st.diffs, st.cases);
	groups++;
	vectors += st.cases;
	memset(&st, 0, sizeof st);
}

static int host_has(unsigned leaf, unsigned reg, unsigned bit)
{
#if defined(__x86_64__)
	unsigned a, b, c, d;

	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(0));
	return (int)(((reg == 1 ? c : reg == 2 ? b : d) >> bit) & 1u);
#else
	(void)leaf; (void)reg; (void)bit;
	return 0;
#endif
}

#define BUF_A (CN_O_BUF + 0x40u)

struct code {
	uint8_t b[64];
	unsigned n;
};

static void put(struct code *c, const void *p, unsigned n)
{
	memcpy(c->b + c->n, p, n);
	c->n += n;
}

static void inputs(struct cn_io *in, unsigned w)
{
	cn_input(in, 0);
	cn_put(in, CN_O_RAX, cn_edge(w));
	cn_put(in, CN_O_RCX, cn_edge(w));
	cn_put(in, CN_O_RDX, cn_edge(w));
	cn_fill_buf(in, 0);
}

/* ---- BMI1, BMI2 ---------------------------------------------------------------------------- */

struct vexop {
	const char *nm;
	uint8_t pp, opc, modrm, vv;     /* vv: the vvvv field as written (0xe is ecx, 0xf is eax, and "not used" for RORX) */
	uint64_t mask;          /* the flags defined afterwards */
	int imm;
};

static void t_bmi(void)
{
	static const struct vexop op[] = {
		{ "andn", 0, 0xf2, 0xc2, 0xe, CN_FL_SF | CN_FL_ZF | CN_FL_CF | CN_FL_OF, 0 },
		{ "bextr", 0, 0xf7, 0xc2, 0xe, CN_FL_ZF | CN_FL_CF | CN_FL_OF, 0 },
		{ "blsr", 0, 0xf3, 0xca, 0xe, CN_FL_SF | CN_FL_ZF | CN_FL_CF | CN_FL_OF, 0 },
		{ "blsmsk", 0, 0xf3, 0xd2, 0xe, CN_FL_SF | CN_FL_ZF | CN_FL_CF | CN_FL_OF, 0 },
		{ "blsi", 0, 0xf3, 0xda, 0xe, CN_FL_SF | CN_FL_ZF | CN_FL_CF | CN_FL_OF, 0 },
		{ "bzhi", 0, 0xf5, 0xc2, 0xe, CN_FL_SF | CN_FL_ZF | CN_FL_CF | CN_FL_OF, 0 },
		{ "mulx edx,eax,ecx", 3, 0xf6, 0xd1, 0xf, CN_FL_ARITH, 0 },
		{ "mulx eax,ecx,edx", 3, 0xf6, 0xc2, 0xe, CN_FL_ARITH, 0 },
		{ "mulx eax,eax,ecx (one register)", 3, 0xf6, 0xc1, 0xf, CN_FL_ARITH, 0 },
		{ "pdep", 3, 0xf5, 0xc2, 0xe, CN_FL_ARITH, 0 },
		{ "pext", 2, 0xf5, 0xc2, 0xe, CN_FL_ARITH, 0 },
		{ "sarx", 2, 0xf7, 0xc2, 0xe, CN_FL_ARITH, 0 },
		{ "shlx", 1, 0xf7, 0xc2, 0xe, CN_FL_ARITH, 0 },
		{ "shrx", 3, 0xf7, 0xc2, 0xe, CN_FL_ARITH, 0 },
		{ "rorx", 3, 0xf0, 0xc1, 0xf, CN_FL_ARITH, 1 }
	};
	unsigned o, w, i;

	if (!host_has(7, 2, 3) || !host_has(7, 2, 8)) {
		printf("  bmi: SKIPPED (the host has no BMI1/BMI2)\n");
		return;
	}
	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (w = 0; w < 2; w++)
			for (i = 0; i < 400; i++) {
				struct cn_io in;
				struct code c;
				uint8_t v[6];
				unsigned k = 0;
				/* the 3-byte VEX form: map 2 (map 3 for RORX), W for the 64 bit operand size */
				const unsigned map = op[o].opc == 0xf0 ? 3u : 2u;
				const unsigned vv = op[o].vv;

				inputs(&in, w ? 8u : 4u);
				if (op[o].opc == 0xf7 || op[o].opc == 0xf5) {         /* control words: small counts and indexes at the edge */
					const uint64_t cnts[] = { 0, 1, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 255, 0x100, 0xff08 };

					if (cn_rng() & 1u)
						cn_put(&in, CN_O_RCX, cnts[cn_rng() % (sizeof cnts / sizeof cnts[0])] | (cn_rng() << 20));
				}
				v[k++] = 0xc4;
				v[k++] = (uint8_t)(0xe0u | map);
				v[k++] = (uint8_t)((w ? 0x80u : 0u) | (vv << 3) | op[o].pp);
				v[k++] = op[o].opc;
				v[k++] = op[o].modrm;
				c.n = 0;
				put(&c, v, k);
				if (op[o].imm) {
					const uint8_t ib = (uint8_t)(i & 63u);

					put(&c, &ib, 1);
				}
				(void)cn_case(&st, op[o].nm, c.b, c.n, &in, op[o].mask, 64, 0, 0);
			}
	finish("bmi1 and bmi2");
}

/* ---- ADX, MOVBE, CRC32 --------------------------------------------------------------------- */

static void t_adx_movbe_crc(void)
{
	static const struct { const char *nm; uint8_t b[8]; unsigned n; unsigned w; int mem; uint64_t mask; int feat; } op[] = {
		{ "adcx r32", { 0x66, 0x0f, 0x38, 0xf6, 0xc1 }, 5, 4, 0, CN_FL_ARITH, 1 },
		{ "adcx r64", { 0x66, 0x48, 0x0f, 0x38, 0xf6, 0xc1 }, 6, 8, 0, CN_FL_ARITH, 1 },
		{ "adox r32", { 0xf3, 0x0f, 0x38, 0xf6, 0xc1 }, 5, 4, 0, CN_FL_ARITH, 1 },
		{ "adox r64", { 0xf3, 0x48, 0x0f, 0x38, 0xf6, 0xc1 }, 6, 8, 0, CN_FL_ARITH, 1 },
		{ "movbe r32,[rsi]", { 0x0f, 0x38, 0xf0, 0x06 }, 4, 4, 1, CN_FL_ARITH, 2 },
		{ "movbe r64,[rsi]", { 0x48, 0x0f, 0x38, 0xf0, 0x06 }, 5, 8, 1, CN_FL_ARITH, 2 },
		{ "movbe r16,[rsi]", { 0x66, 0x0f, 0x38, 0xf0, 0x06 }, 5, 2, 1, CN_FL_ARITH, 2 },
		{ "movbe [rsi],r32", { 0x0f, 0x38, 0xf1, 0x06 }, 4, 4, 1, CN_FL_ARITH, 2 },
		{ "movbe [rsi],r64", { 0x48, 0x0f, 0x38, 0xf1, 0x06 }, 5, 8, 1, CN_FL_ARITH, 2 },
		{ "movbe [rsi],r16", { 0x66, 0x0f, 0x38, 0xf1, 0x06 }, 5, 2, 1, CN_FL_ARITH, 2 },
		{ "crc32 r32,r/m8", { 0xf2, 0x0f, 0x38, 0xf0, 0xc1 }, 5, 1, 0, CN_FL_ARITH, 3 },
		{ "crc32 r32,r/m16", { 0xf2, 0x66, 0x0f, 0x38, 0xf1, 0xc1 }, 6, 2, 0, CN_FL_ARITH, 3 },
		{ "crc32 r32,r/m32", { 0xf2, 0x0f, 0x38, 0xf1, 0xc1 }, 5, 4, 0, CN_FL_ARITH, 3 },
		{ "crc32 r64,r/m8", { 0xf2, 0x48, 0x0f, 0x38, 0xf0, 0xc1 }, 6, 1, 0, CN_FL_ARITH, 3 },
		{ "crc32 r64,r/m64", { 0xf2, 0x48, 0x0f, 0x38, 0xf1, 0xc1 }, 6, 8, 0, CN_FL_ARITH, 3 },
		{ "crc32 r32,[rsi] m32", { 0xf2, 0x0f, 0x38, 0xf1, 0x06 }, 5, 4, 1, CN_FL_ARITH, 3 }
	};
	unsigned o, i;

	for (o = 0; o < sizeof op / sizeof op[0]; o++) {
		if ((op[o].feat == 1 && !host_has(7, 2, 19)) || (op[o].feat == 2 && !host_has(1, 1, 22)) ||
		    (op[o].feat == 3 && !host_has(1, 1, 20))) {
			printf("  %s: SKIPPED (the host lacks the instruction)\n", op[o].nm);
			continue;
		}
		for (i = 0; i < 300; i++) {
			struct cn_io in;

			inputs(&in, op[o].w);
			cn_put(&in, CN_O_RSI, BUF_A);
			(void)cn_case(&st, op[o].nm, op[o].b, op[o].n, &in, op[o].mask, 64, 0, op[o].mem);
		}
	}
	finish("adcx, adox, movbe, crc32");
}

/* ---- CMPXCHG8B and CMPXCHG16B ----------------------------------------------------------------- */

static void t_cmpxchg(void)
{
	unsigned k, i;

	if (!host_has(1, 1, 13)) {
		printf("  cmpxchg16b: SKIPPED (the host lacks it)\n");
	}
	for (k = 0; k < 2; k++) {
		if (k && !host_has(1, 1, 13))
			continue;
		for (i = 0; i < 600; i++) {
			struct cn_io in;
			struct code c;
			static const uint8_t save[] = { 0x53, 0x48, 0x89, 0xd3 };      /* push rbx; mov rbx, rdx */
			static const uint8_t rest[] = { 0x5b };                         /* pop rbx */
			uint8_t x[3];
			uint64_t lo, hi;

			inputs(&in, 8);
			lo = cn_get(&in, CN_O_RAX);
			hi = cn_get(&in, CN_O_RDX);
			/* EDX:EAX is compared with memory: make it equal half the time, with the EBX:ECX replaced by RDX:RCX below */
			if (cn_rng() & 1u) {
				memcpy(in.raw + BUF_A, &lo, 8);
				memcpy(in.raw + BUF_A + 8, &hi, 8);
				if (!k) {
					lo &= 0xffffffffu;
					hi &= 0xffffffffu;
					cn_put(&in, CN_O_RAX, lo);
					cn_put(&in, CN_O_RDX, hi);
					memcpy(in.raw + BUF_A, &lo, 4);
					memcpy(in.raw + BUF_A + 4, &hi, 4);
				}
			}
			cn_put(&in, CN_O_RSI, BUF_A);
			c.n = 0;
			put(&c, save, sizeof save);
			x[0] = 0x48;
			x[1] = 0x0f;
			x[2] = 0xc7;
			if (k)
				put(&c, x, 3);
			else
				put(&c, x + 1, 2);
			{
				const uint8_t m = 0x0e;           /* cmpxchg8b/16b [rsi] */

				put(&c, &m, 1);
			}
			put(&c, rest, sizeof rest);
			(void)cn_case(&st, k ? "cmpxchg16b" : "cmpxchg8b", c.b, c.n, &in, CN_FL_ARITH, 64, 0, 1);
		}
	}
	finish("cmpxchg8b, cmpxchg16b");
}

/* ---- ENTER and XLATB ----------------------------------------------------------------------------- */

/*
 * ENTER moves RSP and RBP by amounts that do not depend on the stack's address: the case measures them as differences.
 *   push rbp; mov rbp,rsp; mov rcx,rsp; enter size,level; mov rax,rsp; sub rax,rcx; mov rdx,rbp; sub rdx,rcx; leave; pop rbp
 * so RAX is how far the stack pointer moved and RDX how far the frame pointer did, and LEAVE and POP restore both for the host
 * (RBP is callee-saved). The interpreter runs the same bytes.
 */
static void t_enter(void)
{
	static const uint8_t pre[] = { 0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xe1 };
	static const uint8_t post[] = { 0x48, 0x89, 0xe0, 0x48, 0x29, 0xc8, 0x48, 0x89, 0xea, 0x48, 0x29, 0xca, 0xc9, 0x5d,
				       0xb9, 0, 0, 0, 0 };            /* ... and mov ecx,0, which leaves the flags: RCX was the scratch */
	static const unsigned sizes[] = { 0, 8, 0x100, 0xfff8, 0xffff };
	unsigned s, level;

	for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++)
		for (level = 0; level < 5; level++) {
			struct cn_io in;
			struct code c;
			uint8_t e[4];

			cn_input(&in, 0);
			c.n = 0;
			put(&c, pre, sizeof pre);
			e[0] = 0xc8;
			e[1] = (uint8_t)sizes[s];
			e[2] = (uint8_t)(sizes[s] >> 8);
			e[3] = (uint8_t)level;
			put(&c, e, 4);
			put(&c, post, sizeof post);
			(void)cn_case(&st, "enter", c.b, c.n, &in, 0, 64, 0, 0);   /* the SUBs that measure it set the flags: not compared */
		}
	{
		struct cn_io in;
		struct code c;
		static const uint8_t x[] = { 0x53, 0x48, 0x89, 0xf3, 0xd7, 0x5b };       /* push rbx; mov rbx,rsi; xlatb; pop rbx */
		unsigned i;

		for (i = 0; i < 300; i++) {
			cn_input(&in, 0);
			cn_fill_buf(&in, 0);
			cn_put(&in, CN_O_RSI, CN_O_BUF);
			cn_put(&in, CN_O_RAX, cn_rng());
			c.n = 0;
			put(&c, x, sizeof x);
			(void)cn_case(&st, "xlatb", c.b, c.n, &in, CN_FL_ARITH, 64, 0, 0);
		}
	}
	finish("enter, xlatb");
}

/* ---- AAM and AAD: 32-bit mode only, against the manual ------------------------------------------- */

static int parity_even(unsigned v)
{
	return !(__builtin_popcount(v & 0xffu) & 1);
}

static void t_bcd(void)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned op, ah, al, bi, bad = 0, cases = 0;
	static const unsigned bases[] = { 10, 8, 16, 2, 255, 1, 7 };
	static uint8_t blank[4096];

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = 32;
	cfg.max_insn = 1000;
	e = kgenome_emu_new(&cfg);
	CK(e != NULL, "a 32 bit interpreter");
	if (!e)
		return;
	kgenome_emu_map(e, 0x400000, blank, sizeof blank, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, 0x7ff00000, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	for (op = 0; op < 2; op++)
		for (bi = 0; bi < sizeof bases / sizeof bases[0]; bi++)
			for (ah = 0; ah < 256; ah += 5)
				for (al = 0; al < 256; al += 3) {
					const uint8_t code[5] = { op ? 0xd5 : 0xd4, (uint8_t)bases[bi], 0x9c, 0x59, 0xf4 };   /* pushfd; pop ecx: the flags */
					unsigned want_al, want_ah;
					uint64_t ax, fl;

					kgenome_emu_write(e, 0x400000, code, 5);
					kgenome_emu_set_reg(e, KGENOME_EMU_RAX, 0xabcd0000u | (ah << 8) | al);
					kgenome_emu_set_reg(e, KGENOME_EMU_RSP, 0x7ff00800u);
					kgenome_emu_set_rip(e, 0x400000);
					kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 4u);
					(void)kgenome_emu_run(e);
					ax = kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
					fl = kgenome_emu_get_reg(e, KGENOME_EMU_RCX);
					if (op == 0) {
						want_ah = al / bases[bi];
						want_al = al % bases[bi];
					} else {
						want_al = (al + ah * bases[bi]) & 0xffu;
						want_ah = 0;
					}
					cases++;
					if ((ax & 0xffffffffu) != (0xabcd0000u | (want_ah << 8) | want_al) ||
					    !!(fl & CN_FL_ZF) != (want_al == 0) || !!(fl & CN_FL_SF) != ((want_al & 0x80u) != 0) ||
					    !!(fl & CN_FL_PF) != parity_even(want_al)) {
						if (!bad++)
							printf("      %s %u: ah=%u al=%u -> ax %#llx flags %#llx, want ah=%u al=%u\n", op ? "aad" : "aam",
							       bases[bi], ah, al, (unsigned long long)ax, (unsigned long long)fl, want_ah, want_al);
					}
				}
	{
		/* AAM 0 is a divide by zero: a fault, not an unsupported instruction */
		const uint8_t code[3] = { 0xd4, 0x00, 0xf4 };
		enum kgenome_emu_stop s;

		kgenome_emu_write(e, 0x400000, code, 3);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, 0x7ff00800u);
		kgenome_emu_set_rip(e, 0x400000);
		kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 4u);
		s = kgenome_emu_run(e);
		CK(s == KGENOME_EMU_STOP_FAULT, "aam 0 is a fault (%s)", kgenome_emu_stop_name(s));
	}
	printf("  %-22s %6u case(s), %u differ\n", "aam, aad (32 bit)", cases, bad);
	CK(bad == 0, "aam and aad equal the manual's algorithm (%u of %u differ)", bad, cases);
	groups++;
	vectors += cases;
	kgenome_emu_free(e);
}

int main(void)
{
	cn_rng_state = 0x4f5053455854ull;
	if (!CN_HOST) {
		printf("diff_ops_ext: SKIPPED (the host is not x86-64 Linux, so there is no reference to run)\n");
		return 0;
	}
	t_bmi();
	t_adx_movbe_crc();
	t_cmpxchg();
	t_enter();
	t_bcd();
	printf("diff_ops_ext: %u group(s), %u vector(s)\n", groups, vectors);
	CK(vectors > 5000u, "the sweep is the size it claims (%u vectors)", vectors);
	if (fails) {
		printf("diff_ops_ext: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_ops_ext: ok\n");
	return 0;
}
