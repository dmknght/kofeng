/*
 * diff_sse_x87 - the interpreter's SSE and x87 instructions against the host CPU, over the full cross product of
 * the operands that break floating point code.
 *
 * cov_emu_vec.c draws random operands. This file runs EVERY ordered pair of a fixed pool - zeros of both signs, ones,
 * the rounding ties 0.5 and 2.5, the smallest normal and a denormal, the largest finite, the 32 and 64 bit integer
 * limits and one past them, both infinities, a quiet NaN, a signalling NaN with a payload and a negative NaN - for
 * each scalar operation, so "a NaN in the second operand", "two zeros of opposite sign" and "the product of an
 * infinity and a zero" are each a vector and not a matter of luck. The 128 bit result is compared byte for byte
 * (so the lane a scalar operation must leave alone is checked), and the general registers and the flags the
 * architecture defines.
 *
 *   SSE scalar    addsd subsd mulsd divsd sqrtsd minsd maxsd, addss subss mulss divss (all pairs)
 *   SSE compare   ucomisd comisd ucomiss comiss -> EFLAGS (all pairs)
 *   SSE convert   cvtsi2sd/ss (32 and 64 bit integers), cvtsd2ss, cvtss2sd, cvttsd2si, cvttss2si (32 and 64 bit,
 *                 including every operand that does not fit: the integer indefinite)
 *   SSE integer   the logic family, pcmpeqb, psubb, punpcklbw, pshufd (all 256 immediates), pslldq/psrldq
 *                 (every count 0-17), pinsrw/pextrw (every lane), pmovmskb
 *   SSE moves     movd movq movss movsd movlps movhps movlpd movhpd movlhps movhlps, register and memory forms
 *   x87           the arithmetic in every operand order and pop form, compares into the status word and EFLAGS,
 *                 FXAM, FIST/FISTP/FISTTP at 16, 32 and 64 bits under all four rounding modes (set with FLDCW),
 *                 FRNDINT under each, FLDCW/FNSTCW round trip, and the state images: FNSTENV and FXSAVE after
 *                 stacks of 0 to 4 values (control word, status word with TOP, tag word, FOP, the register
 *                 stack, MXCSR, the xmm registers)
 *
 * x87 registers here are doubles (the interpreter's choice, documented in emu_private.h), so a result is compared
 * as a double stored back to memory - the same bits, or one unit in the last place where the hardware rounds twice -
 * and a state image only for values that are exact in both formats. Skipped, visibly, on a host that is not x86-64
 * Linux. Nothing here writes a file.
 */

#include "cov_native.h"

#include <math.h>

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
	CK(st.diffs == 0, "%s: equal the CPU bit for bit (%u of %u differ)", family, st.diffs, st.cases);
	groups++;
	vectors += st.cases;
	memset(&st, 0, sizeof st);
}

/* ---- the operand pools --------------------------------------------------------------------- */

#define ND 26u
static uint64_t dp(unsigned i)
{
	static const double v[] = { 0.0, -0.0, 1.0, -1.0, 0.5, 2.5, -2.5, 3.0, -7.25, 1e300, -1e300, 1e-310,
				    2.2250738585072014e-308, 1.7976931348623157e308, 2147483648.0, -2147483649.0,
				    2147483647.5, -2147483648.5, 9223372036854775808.0, -9223372036854775808.0,
				    4503599627370497.5 };
	uint64_t b;

	if (i < sizeof v / sizeof v[0]) {
		memcpy(&b, &v[i], 8);
		return b;
	}
	switch (i - (unsigned)(sizeof v / sizeof v[0])) {
	case 0:  return 0x7ff0000000000000ull;          /* +inf */
	case 1:  return 0xfff0000000000000ull;          /* -inf */
	case 2:  return 0x7ff8000000000000ull;          /* a quiet NaN */
	case 3:  return 0x7ff4000000000001ull;          /* a signalling NaN with a payload */
	default: return 0xfff8000000000123ull;          /* a negative quiet NaN with a payload */
	}
}

#define NF 22u
static uint32_t fp_(unsigned i)
{
	static const float v[] = { 0.0f, -0.0f, 1.0f, -1.0f, 0.5f, 2.5f, -2.5f, 3.0f, -7.25f, 1e30f, -1e30f, 1e-40f,
				   1.17549435e-38f, 3.4028234663852886e38f, 2147483648.0f, -2147483904.0f, 16777217.0f,
				   9.3e18f };
	uint32_t b;

	if (i < sizeof v / sizeof v[0]) {
		memcpy(&b, &v[i], 4);
		return b;
	}
	switch (i - (unsigned)(sizeof v / sizeof v[0])) {
	case 0:  return 0x7f800000u;
	case 1:  return 0xff800000u;
	case 2:  return 0x7fc00000u;
	default: return 0x7fa00001u;
	}
}

static uint64_t ip(unsigned i)
{
	static const uint64_t v[] = { 0, 1, 0xffffffffffffffffull, 0x7fffffffull, 0x80000000ull, 0xffffffffull, 0x7fffffffffffffffull,
				      0x8000000000000000ull, 0x1000000ull, 0x1000001ull, 0x20000000000001ull, 0x123456789abcdefull,
				      0xffffffff80000000ull, 0xfffffffffffff800ull };

	return v[i % (sizeof v / sizeof v[0])];
}

static void xin(struct cn_io *x, uint64_t lo0, uint64_t lo1, unsigned single)
{
	uint64_t a[2], b[2];

	a[0] = lo0; a[1] = cn_rng();
	b[0] = lo1; b[1] = cn_rng();
	if (single) {
		a[0] = (a[0] & 0xffffffffull) | (cn_rng() << 32);
		b[0] = (b[0] & 0xffffffffull) | (cn_rng() << 32);
	}
	memcpy(x->raw + CN_O_XMM, a, 16);
	memcpy(x->raw + CN_O_XMM + 16, b, 16);
}

#define XM_ALL 0xffffffffu

/* ---- SSE ---------------------------------------------------------------------------------- */

static void t_scalar(void)
{
	static const struct { const char *nm; uint8_t b[4]; unsigned n; unsigned single; } op[] = {
		{ "addsd", { 0xf2, 0x0f, 0x58, 0xc1 }, 4, 0 }, { "subsd", { 0xf2, 0x0f, 0x5c, 0xc1 }, 4, 0 },
		{ "mulsd", { 0xf2, 0x0f, 0x59, 0xc1 }, 4, 0 }, { "divsd", { 0xf2, 0x0f, 0x5e, 0xc1 }, 4, 0 },
		{ "sqrtsd", { 0xf2, 0x0f, 0x51, 0xc1 }, 4, 0 }, { "minsd", { 0xf2, 0x0f, 0x5d, 0xc1 }, 4, 0 },
		{ "maxsd", { 0xf2, 0x0f, 0x5f, 0xc1 }, 4, 0 },
		{ "addss", { 0xf3, 0x0f, 0x58, 0xc1 }, 4, 1 }, { "subss", { 0xf3, 0x0f, 0x5c, 0xc1 }, 4, 1 },
		{ "mulss", { 0xf3, 0x0f, 0x59, 0xc1 }, 4, 1 }, { "divss", { 0xf3, 0x0f, 0x5e, 0xc1 }, 4, 1 }
	};
	unsigned o, i, j;

	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (i = 0; i < (op[o].single ? NF : ND); i++)
			for (j = 0; j < (op[o].single ? NF : ND); j++) {
				struct cn_io in;

				cn_input(&in, 0);
				xin(&in, op[o].single ? fp_(i) : dp(i), op[o].single ? fp_(j) : dp(j), op[o].single);
				(void)cn_case(&st, op[o].nm, op[o].b, op[o].n, &in, 0, 64, XM_ALL, 0);
			}
	finish("sse scalar arithmetic");
}

static void t_compare(void)
{
	static const struct { const char *nm; uint8_t b[4]; unsigned n; unsigned single; } op[] = {
		{ "ucomisd", { 0x66, 0x0f, 0x2e, 0xc1 }, 4, 0 }, { "comisd", { 0x66, 0x0f, 0x2f, 0xc1 }, 4, 0 },
		{ "ucomiss", { 0x0f, 0x2e, 0xc1 }, 3, 1 }, { "comiss", { 0x0f, 0x2f, 0xc1 }, 3, 1 }
	};
	unsigned o, i, j;

	for (o = 0; o < 4; o++)
		for (i = 0; i < (op[o].single ? NF : ND); i++)
			for (j = 0; j < (op[o].single ? NF : ND); j++) {
				struct cn_io in;

				cn_input(&in, 0);
				xin(&in, op[o].single ? fp_(i) : dp(i), op[o].single ? fp_(j) : dp(j), op[o].single);
				(void)cn_case(&st, op[o].nm, op[o].b, op[o].n, &in, CN_FL_ARITH, 64, XM_ALL, 0);
			}
	finish("sse compares to eflags");
}

static void t_convert(void)
{
	static const struct { const char *nm; uint8_t b[5]; unsigned n; unsigned src; } op[] = {
		/* src: 0 integer in rax, 1 double in xmm1, 2 float in xmm1 */
		{ "cvtsi2sd r32", { 0xf2, 0x0f, 0x2a, 0xc0 }, 4, 0 }, { "cvtsi2sd r64", { 0xf2, 0x48, 0x0f, 0x2a, 0xc0 }, 5, 0 },
		{ "cvtsi2ss r32", { 0xf3, 0x0f, 0x2a, 0xc0 }, 4, 0 }, { "cvtsi2ss r64", { 0xf3, 0x48, 0x0f, 0x2a, 0xc0 }, 5, 0 },
		{ "cvtsd2ss", { 0xf2, 0x0f, 0x5a, 0xc1 }, 4, 1 }, { "cvtss2sd", { 0xf3, 0x0f, 0x5a, 0xc1 }, 4, 2 },
		{ "cvttsd2si r32", { 0xf2, 0x0f, 0x2c, 0xc1 }, 4, 1 }, { "cvttsd2si r64", { 0xf2, 0x48, 0x0f, 0x2c, 0xc1 }, 5, 1 },
		{ "cvttss2si r32", { 0xf3, 0x0f, 0x2c, 0xc1 }, 4, 2 }, { "cvttss2si r64", { 0xf3, 0x48, 0x0f, 0x2c, 0xc1 }, 5, 2 }
	};
	unsigned o, i, k;

	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (i = 0; i < (op[o].src == 0 ? 14u : op[o].src == 1 ? ND : NF); i++)
			for (k = 0; k < 4; k++) {
				struct cn_io in;
				uint64_t v = op[o].src == 0 ? ip(i) : op[o].src == 1 ? dp(i) : fp_(i);

				cn_input(&in, 0);
				xin(&in, cn_rng(), v, op[o].src == 2);
				cn_put(&in, CN_O_RAX, op[o].src == 0 ? v : cn_rng());
				(void)cn_case(&st, op[o].nm, op[o].b, op[o].n, &in, 0, 64, XM_ALL, 0);
			}
	finish("sse conversions");
}

static void t_integer(void)
{
	static const struct { const char *nm; uint8_t b[5]; unsigned n; } op[] = {
		{ "xorps", { 0x0f, 0x57, 0xc1 }, 3 }, { "andps", { 0x0f, 0x54, 0xc1 }, 3 }, { "andnps", { 0x0f, 0x55, 0xc1 }, 3 },
		{ "orps", { 0x0f, 0x56, 0xc1 }, 3 }, { "pxor", { 0x66, 0x0f, 0xef, 0xc1 }, 4 }, { "por", { 0x66, 0x0f, 0xeb, 0xc1 }, 4 },
		{ "pand", { 0x66, 0x0f, 0xdb, 0xc1 }, 4 }, { "pandn", { 0x66, 0x0f, 0xdf, 0xc1 }, 4 },
		{ "pcmpeqb", { 0x66, 0x0f, 0x74, 0xc1 }, 4 }, { "psubb", { 0x66, 0x0f, 0xf8, 0xc1 }, 4 },
		{ "punpcklbw", { 0x66, 0x0f, 0x60, 0xc1 }, 4 }, { "pmovmskb", { 0x66, 0x0f, 0xd7, 0xc1 }, 4 }
	};
	unsigned o, i, k;

	/* operands made of bytes that are often equal, so pcmpeqb and psubb see both outcomes in one register */
	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (i = 0; i < 200; i++) {
			struct cn_io in;
			uint8_t a[16], b[16];

			cn_input(&in, 0);
			for (k = 0; k < 16; k++) {
				a[k] = (uint8_t)(cn_rng() % 4u ? cn_rng() % 3u : cn_rng());
				b[k] = (cn_rng() & 1u) ? a[k] : (uint8_t)(cn_rng() % 3u);
			}
			memcpy(in.raw + CN_O_XMM, a, 16);
			memcpy(in.raw + CN_O_XMM + 16, b, 16);
			(void)cn_case(&st, op[o].nm, op[o].b, op[o].n, &in, 0, 64, XM_ALL, 0);
		}
	for (i = 0; i < 256; i++) {                                     /* pshufd, every immediate */
		struct cn_io in;
		uint8_t c[5] = { 0x66, 0x0f, 0x70, 0xc1, (uint8_t)i };

		cn_input(&in, 0);
		xin(&in, cn_rng(), cn_rng(), 0);
		(void)cn_case(&st, "pshufd", c, 5, &in, 0, 64, XM_ALL, 0);
	}
	for (i = 0; i < 18; i++) {                                      /* pslldq / psrldq, every count */
		struct cn_io in;
		uint8_t l[5] = { 0x66, 0x0f, 0x73, 0xf8, (uint8_t)i }, r[5] = { 0x66, 0x0f, 0x73, 0xd8, (uint8_t)i };

		for (k = 0; k < 8; k++) {
			cn_input(&in, 0);
			xin(&in, cn_rng(), cn_rng(), 0);
			(void)cn_case(&st, "pslldq", l, 5, &in, 0, 64, XM_ALL, 0);
			(void)cn_case(&st, "psrldq", r, 5, &in, 0, 64, XM_ALL, 0);
		}
	}
	for (i = 0; i < 8; i++)                                         /* pinsrw / pextrw, every lane */
		for (k = 0; k < 16; k++) {
			struct cn_io in;
			uint8_t ins[5] = { 0x66, 0x0f, 0xc4, 0xc0, (uint8_t)i }, ext[5] = { 0x66, 0x0f, 0xc5, 0xc0, (uint8_t)i };

			cn_input(&in, 0);
			xin(&in, cn_rng(), cn_rng(), 0);
			(void)cn_case(&st, "pinsrw", ins, 5, &in, 0, 64, XM_ALL, 0);
			(void)cn_case(&st, "pextrw", ext, 5, &in, 0, 64, XM_ALL, 0);
		}
	finish("sse integer and shuffles");
}

static void t_moves(void)
{
	static const struct { const char *nm; uint8_t b[5]; unsigned n; } op[] = {
		{ "movd xmm0,eax", { 0x66, 0x0f, 0x6e, 0xc0 }, 4 }, { "movq xmm0,rax", { 0x66, 0x48, 0x0f, 0x6e, 0xc0 }, 5 },
		{ "movd eax,xmm0", { 0x66, 0x0f, 0x7e, 0xc0 }, 4 }, { "movq rax,xmm0", { 0x66, 0x48, 0x0f, 0x7e, 0xc0 }, 5 },
		{ "movq xmm0,xmm1", { 0xf3, 0x0f, 0x7e, 0xc1 }, 4 },
		{ "movq xmm0,[rsi]", { 0xf3, 0x0f, 0x7e, 0x06 }, 4 }, { "movq [rsi],xmm0", { 0x66, 0x0f, 0xd6, 0x06 }, 4 },
		{ "movss xmm0,[rsi]", { 0xf3, 0x0f, 0x10, 0x06 }, 4 }, { "movss [rsi],xmm0", { 0xf3, 0x0f, 0x11, 0x06 }, 4 },
		{ "movsd xmm0,[rsi]", { 0xf2, 0x0f, 0x10, 0x06 }, 4 }, { "movsd [rsi],xmm0", { 0xf2, 0x0f, 0x11, 0x06 }, 4 },
		{ "movss xmm0,xmm1", { 0xf3, 0x0f, 0x10, 0xc1 }, 4 }, { "movsd xmm0,xmm1", { 0xf2, 0x0f, 0x10, 0xc1 }, 4 },
		{ "movlps xmm0,[rsi]", { 0x0f, 0x12, 0x06 }, 3 }, { "movlpd xmm0,[rsi]", { 0x66, 0x0f, 0x12, 0x06 }, 4 },
		{ "movlps [rsi],xmm0", { 0x0f, 0x13, 0x06 }, 3 }, { "movlpd [rsi],xmm0", { 0x66, 0x0f, 0x13, 0x06 }, 4 },
		{ "movhps xmm0,[rsi]", { 0x0f, 0x16, 0x06 }, 3 }, { "movhpd xmm0,[rsi]", { 0x66, 0x0f, 0x16, 0x06 }, 4 },
		{ "movhps [rsi],xmm0", { 0x0f, 0x17, 0x06 }, 3 }, { "movhpd [rsi],xmm0", { 0x66, 0x0f, 0x17, 0x06 }, 4 },
		{ "movlhps xmm0,xmm1", { 0x0f, 0x16, 0xc1 }, 3 }, { "movhlps xmm0,xmm1", { 0x0f, 0x12, 0xc1 }, 3 },
		{ "movups xmm1,xmm0", { 0x0f, 0x10, 0xc8 }, 3 }, { "movdqu [rsi],xmm0", { 0xf3, 0x0f, 0x7f, 0x06 }, 4 },
		{ "movdqu xmm0,[rsi]", { 0xf3, 0x0f, 0x6f, 0x06 }, 4 }, { "movaps xmm0,xmm1", { 0x0f, 0x28, 0xc1 }, 3 }
	};
	unsigned o, i;

	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (i = 0; i < 60; i++) {
			struct cn_io in;

			cn_input(&in, 0);
			cn_fill_buf(&in, 0);
			xin(&in, cn_rng(), cn_rng(), 0);
			cn_put(&in, CN_O_RAX, cn_rng());
			cn_put(&in, CN_O_RSI, CN_O_BUF + 64u);
			(void)cn_case(&st, op[o].nm, op[o].b, op[o].n, &in, 0, 64, XM_ALL, 1);
		}
	finish("sse moves");
}

/* ---- x87 ----------------------------------------------------------------------------------- */

/*
 * fninit; [pre]; fld qword [rsi] (st1); fld qword [rsi+8] (st0); <op>; fnstsw ax; then `nres` results as doubles at
 * [rsi+16] and [rsi+24]. `pre` runs after fninit, which is where a control word is loaded.
 */
static unsigned x87_code(uint8_t *c, const uint8_t *op, unsigned n, unsigned nres, const uint8_t *pre, unsigned npre)
{
	static const uint8_t init[] = { 0xdb, 0xe3, 0xdd, 0x06, 0xdd, 0x46, 0x08 };
	static const uint8_t sw[] = { 0xdf, 0xe0 };
	static const uint8_t pop0[] = { 0xdd, 0x5e, 0x10 };
	static const uint8_t pop1[] = { 0xdd, 0x5e, 0x18 };
	unsigned k = 0;

	memcpy(c, init, 1u + 1u);
	k = 2;
	if (npre) {
		memcpy(c + k, pre, npre);
		k += npre;
	}
	memcpy(c + k, init + 2, sizeof init - 2u);
	k += (unsigned)sizeof init - 2u;
	memcpy(c + k, op, n);
	k += n;
	memcpy(c + k, sw, sizeof sw);
	k += (unsigned)sizeof sw;
	if (nres > 0) {
		memcpy(c + k, pop0, sizeof pop0);
		k += (unsigned)sizeof pop0;
	}
	if (nres > 1) {
		memcpy(c + k, pop1, sizeof pop1);
		k += (unsigned)sizeof pop1;
	}
	return k;
}

static int dclose(uint64_t x, uint64_t y)
{
	double a, b;
	int64_t d;

	if (x == y)
		return 1;
	memcpy(&a, &x, 8);
	memcpy(&b, &y, 8);
	if (a != a && b != b)
		return 1;
	if (a != a || b != b)
		return 0;
	if ((x ^ y) >> 63)
		return a == b;
	d = (int64_t)x - (int64_t)y;
	return d >= -1 && d <= 1;
}

#define X87_C 0x4700u

struct x87_op {
	const char *nm;
	uint8_t b[8];
	unsigned n, nres;
	int status;                 /* compare C0..C3 (1) or C0, C2 and C3 (2: C1 is "rounded up", which a double cannot say) */
	uint64_t flags;             /* EFLAGS bits an fcomi defines */
	int exact;                  /* results bit for bit */
	unsigned memoff, memlen;    /* a region of the buffer that must match exactly */
};

static unsigned x87_bad, x87_unsup, x87_cases;
static char x87_first[3][260];
static unsigned x87_nfirst;

/* one x87 case: the two operands in the buffer, an optional prefix, and the comparison the op asks for */
static void x87_one(const struct x87_op *op, uint64_t x, uint64_t y, uint64_t iv, const uint8_t *pre, unsigned npre, uint64_t cw)
{
	struct cn_io in, a, b;
	uint8_t code[96];
	unsigned len, k;
	struct cn_emu r;
	int ok = 1;
	const char *why = "";

	cn_input(&in, 0);
	memcpy(in.raw + CN_O_BUF, &x, 8);
	memcpy(in.raw + CN_O_BUF + 8, &y, 8);
	memcpy(in.raw + CN_O_BUF + 32, &iv, 8);
	memcpy(in.raw + CN_O_BUF + 40, &cw, 8);
	cn_put(&in, CN_O_RSI, CN_O_BUF);
	len = x87_code(code, op->b, op->n, op->nres, pre, npre);
	x87_cases++;
	if (!cn_native(code, len, &in, &a))
		return;
	if (!cn_emulate(code, len, &in, &b, 64, &r) || !r.done) {
		x87_unsup++;
		if (x87_nfirst < 3)
			snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "%s: interpreter stopped (%s: %s)", op->nm,
				 kgenome_emu_stop_name(r.stop), r.detail);
		return;
	}
	for (k = 0; k < op->nres && ok; k++) {
		uint64_t u, v;

		memcpy(&u, a.raw + CN_O_BUF + 16 + 8 * k, 8);
		memcpy(&v, b.raw + CN_O_BUF + 16 + 8 * k, 8);
		if (op->exact ? u != v && !(u << 1 > 0xffe0000000000000ull && v << 1 > 0xffe0000000000000ull) : !dclose(u, v)) {
			ok = 0;
			why = "result";
		}
	}
	if (ok && op->memlen && memcmp(a.raw + CN_O_BUF + op->memoff, b.raw + CN_O_BUF + op->memoff, op->memlen)) {
		ok = 0;
		why = "memory";
	}
	if (ok && op->status && ((cn_get(&a, 48) ^ cn_get(&b, 48)) & (op->status == 2 ? 0x4500u : X87_C))) {
		ok = 0;
		why = "status word";
	}
	if (ok && op->flags && ((cn_get(&a, 88) ^ cn_get(&b, 88)) & op->flags)) {
		ok = 0;
		why = "eflags";
	}
	if (!ok) {
		x87_bad++;
		if (x87_nfirst < 3) {
			double dx, dy;

			memcpy(&dx, &x, 8);
			memcpy(&dy, &y, 8);
			snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "%s: %s differs: st1=%g st0=%g cw=%#llx native sw=%#llx emu sw=%#llx",
				 op->nm, why, dx, dy, (unsigned long long)cw, (unsigned long long)(cn_get(&a, 48) & 0xffff),
				 (unsigned long long)(cn_get(&b, 48) & 0xffff));
		}
	}
}

static void x87_finish(const char *family)
{
	unsigned i;

	printf("  %-22s %6u case(s), %u unsupported, %u differ\n", family, x87_cases, x87_unsup, x87_bad);
	for (i = 0; i < x87_nfirst; i++)
		printf("      %s\n", x87_first[i]);
	CK(x87_unsup == 0, "%s: carried (%u refused)", family, x87_unsup);
	CK(x87_bad == 0, "%s equals the CPU (%u of %u differ)", family, x87_bad, x87_cases);
	groups++;
	vectors += x87_cases;
	x87_bad = x87_unsup = x87_cases = x87_nfirst = 0;
}

/* an operand the x87 holds exactly and a double store gives back: the pool minus the values past a double's range */
#define NX 22u
static uint64_t xp(unsigned i)
{
	static const double v[] = { 0.0, -0.0, 1.0, -1.0, 2.0, 3.0, -3.0, 0.5, -0.5, 2.5, -2.5, 3.5, 1.5, 100.0, -100.0, 65536.0, 1e10, 0.1, 7.0 };

	if (i < sizeof v / sizeof v[0]) {
		uint64_t b;

		memcpy(&b, &v[i], 8);
		return b;
	}
	switch (i - (unsigned)(sizeof v / sizeof v[0])) {
	case 0:  return 0x7ff0000000000000ull;
	case 1:  return 0xfff0000000000000ull;
	default: return 0xfff8000000000000ull;
	}
}

static void t_x87_arith(void)
{
	static const struct x87_op op[] = {
		{ "fadd st0,st1", { 0xd8, 0xc1 }, 2, 2, 0, 0, 0, 0, 0 }, { "fmul st0,st1", { 0xd8, 0xc9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fsub st0,st1", { 0xd8, 0xe1 }, 2, 2, 0, 0, 0, 0, 0 }, { "fsubr st0,st1", { 0xd8, 0xe9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fdiv st0,st1", { 0xd8, 0xf1 }, 2, 2, 0, 0, 0, 0, 0 }, { "fdivr st0,st1", { 0xd8, 0xf9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fadd st1,st0", { 0xdc, 0xc1 }, 2, 2, 0, 0, 0, 0, 0 }, { "fmul st1,st0", { 0xdc, 0xc9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "dc e1", { 0xdc, 0xe1 }, 2, 2, 0, 0, 0, 0, 0 }, { "dc e9", { 0xdc, 0xe9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "dc f1", { 0xdc, 0xf1 }, 2, 2, 0, 0, 0, 0, 0 }, { "dc f9", { 0xdc, 0xf9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "faddp", { 0xde, 0xc1 }, 2, 1, 0, 0, 0, 0, 0 }, { "fmulp", { 0xde, 0xc9 }, 2, 1, 0, 0, 0, 0, 0 },
		{ "de e1", { 0xde, 0xe1 }, 2, 1, 0, 0, 0, 0, 0 }, { "de e9", { 0xde, 0xe9 }, 2, 1, 0, 0, 0, 0, 0 },
		{ "de f1", { 0xde, 0xf1 }, 2, 1, 0, 0, 0, 0, 0 }, { "de f9", { 0xde, 0xf9 }, 2, 1, 0, 0, 0, 0, 0 },
		{ "fadd m64", { 0xdc, 0x06 }, 2, 2, 0, 0, 0, 0, 0 }, { "fsub m64", { 0xdc, 0x26 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fsubr m64", { 0xdc, 0x2e }, 2, 2, 0, 0, 0, 0, 0 }, { "fdiv m64", { 0xdc, 0x36 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fdivr m64", { 0xdc, 0x3e }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fxch st1", { 0xd9, 0xc9 }, 2, 2, 0, 0, 1, 0, 0 }, { "fchs", { 0xd9, 0xe0 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fabs", { 0xd9, 0xe1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fsqrt", { 0xd9, 0xfa }, 2, 2, 0, 0, 0, 0, 0 }
	};
	unsigned o, i, j;

	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (i = 0; i < NX; i++)
			for (j = 0; j < NX; j++)
				x87_one(&op[o], xp(i), xp(j), 0, NULL, 0, 0x37f);
	x87_finish("x87 arithmetic");
}

static void t_x87_compare(void)
{
	static const struct x87_op op[] = {
		{ "fcom st1", { 0xd8, 0xd1 }, 2, 2, 1, 0, 1, 0, 0 }, { "fcomp st1", { 0xd8, 0xd9 }, 2, 1, 1, 0, 1, 0, 0 },
		{ "fcompp", { 0xde, 0xd9 }, 2, 0, 1, 0, 1, 0, 0 }, { "fucom st1", { 0xdd, 0xe1 }, 2, 2, 1, 0, 1, 0, 0 },
		{ "fucomp st1", { 0xdd, 0xe9 }, 2, 1, 1, 0, 1, 0, 0 }, { "fucompp", { 0xda, 0xe9 }, 2, 0, 1, 0, 1, 0, 0 },
		{ "ftst", { 0xd9, 0xe4 }, 2, 2, 1, 0, 1, 0, 0 }, { "fxam", { 0xd9, 0xe5 }, 2, 2, 1, 0, 1, 0, 0 },
		{ "fcomi st1", { 0xdb, 0xf1 }, 2, 2, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fucomi st1", { 0xdb, 0xe9 }, 2, 2, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fcomip st1", { 0xdf, 0xf1 }, 2, 1, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fucomip st1", { 0xdf, 0xe9 }, 2, 1, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fcmovb", { 0xda, 0xc1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmove", { 0xda, 0xc9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fcmovbe", { 0xda, 0xd1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmovu", { 0xda, 0xd9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fcmovnb", { 0xdb, 0xc1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmovne", { 0xdb, 0xc9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fcmovnbe", { 0xdb, 0xd1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmovnu", { 0xdb, 0xd9 }, 2, 2, 0, 0, 1, 0, 0 }
	};
	unsigned o, i, j;

	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (i = 0; i < NX; i++)
			for (j = 0; j < NX; j++)
				x87_one(&op[o], xp(i), xp(j), 0, NULL, 0, 0x37f);
	x87_finish("x87 compares and fcmov");
}

/* FIST, FISTP and FISTTP at 16, 32 and 64 bits, under every rounding mode the control word can select */
static void t_x87_int(void)
{
	static const struct x87_op op[] = {
		{ "fist m32", { 0xdb, 0x56, 0x30 }, 3, 2, 0, 0, 1, 0x30, 8 }, { "fistp m16", { 0xdf, 0x5e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 },
		{ "fistp m32", { 0xdb, 0x5e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 }, { "fistp m64", { 0xdf, 0x7e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 },
		{ "fisttp m16", { 0xdf, 0x4e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 }, { "fisttp m32", { 0xdb, 0x4e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 },
		{ "fisttp m64", { 0xdd, 0x4e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 }, { "frndint", { 0xd9, 0xfc }, 2, 2, 0, 0, 1, 0, 0 }
	};
	/* the operand pool for rounding: ties, near-ties, the width limits and one past them, NaN and infinity */
	static const double v[] = { 0.0, -0.0, 0.5, -0.5, 1.5, 2.5, -1.5, -2.5, 0.4999, 0.5001, 32767.0, 32767.5, 32768.0, -32768.0,
				    -32768.5, -32769.0, 2147483647.0, 2147483647.5, 2147483648.0, -2147483648.0, -2147483648.5,
				    -2147483649.0, 9.2233720368547748e18, 9223372036854775808.0, -9223372036854775808.0, 1e19, 1e300 };
	/* fldcw [rsi+40] */
	static const uint8_t pre[] = { 0xd9, 0x6e, 0x28 };
	unsigned o, i, rc, pc;

	for (o = 0; o < sizeof op / sizeof op[0]; o++)
		for (rc = 0; rc < 4; rc++)
			for (pc = 0; pc < 3; pc++)
				for (i = 0; i < sizeof v / sizeof v[0] + 3u; i++) {
					uint64_t y, iv = cn_rng();

					if (i < sizeof v / sizeof v[0])
						memcpy(&y, &v[i], 8);
					else
						y = i == sizeof v / sizeof v[0] ? 0x7ff0000000000000ull : i == sizeof v / sizeof v[0] + 1u ? 0xfff0000000000000ull
												     : 0x7ff8000000000000ull;
					x87_one(&op[o], 0x3ff0000000000000ull, y, iv, pre, sizeof pre, 0x37fu | ((uint64_t)rc << 10) | ((uint64_t)(pc == 0 ? 0u : pc == 1 ? 2u : 3u) << 8));
				}
	x87_finish("x87 integer stores, rounding");
}

/* FLDCW then FNSTCW/FNSTSW: what was loaded is read back, and the state images after stacks of values */
static void t_x87_state(void)
{
	/* fnstenv [rsi+0x100]; fxsave [rsi+0x200]; with 0 to 4 loads before them */
	static const uint8_t fl[3][4] = { { 0xdd, 0x06 }, { 0xdd, 0x46, 0x08 }, { 0xdd, 0x46, 0x10 } };
	static const double vals[] = { 0.0, 1.0, -2.0, 0.5, 3.0, 1.0e10 };
	unsigned depth, i, k, mode;

	for (depth = 0; depth <= 4; depth++)
		for (mode = 0; mode < 3; mode++)
			for (i = 0; i < 12; i++) {
				struct cn_io in, a, b;
				uint8_t code[128];
				unsigned n = 0;
				struct cn_emu r;
				double dv[4];
				uint16_t cw = (uint16_t)(0x37fu | ((cn_rng() & 3u) << 10) | ((uint64_t)(i % 3 == 0 ? 0u : i % 3 == 1 ? 2u : 3u) << 8));
				const uint8_t *ha, *hb;

				cn_input(&in, 0);
				cn_put(&in, CN_O_RSI, CN_O_BUF);
				for (k = 0; k < 4; k++) {
					dv[k] = vals[(i + k * 2u) % (sizeof vals / sizeof vals[0])];
					memcpy(in.raw + CN_O_BUF + 8u * k, &dv[k], 8);
				}
				memcpy(in.raw + CN_O_BUF + 0x2c0, &cw, 2);
				xin(&in, cn_rng(), cn_rng(), 0);
				code[n++] = 0xdb; code[n++] = 0xe3;                    /* fninit */
				code[n++] = 0xd9; code[n++] = 0xae; code[n++] = 0xc0; code[n++] = 0x02; code[n++] = 0; code[n++] = 0;   /* fldcw [rsi+0x2c0] */
				for (k = 0; k < depth; k++) {                          /* fld qword [rsi + 8k] */
					code[n++] = 0xdd; code[n++] = 0x46; code[n++] = (uint8_t)(8u * k);
				}
				(void)fl;
				if (mode == 0) {
					code[n++] = 0xd9; code[n++] = 0xb6; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;   /* fnstenv [rsi+0x100] */
				} else if (mode == 1) {
					code[n++] = 0x0f; code[n++] = 0xae; code[n++] = 0x86; code[n++] = 0x00; code[n++] = 0x02; code[n++] = 0; code[n++] = 0;   /* fxsave [rsi+0x200] */
				} else {
					code[n++] = 0xd9; code[n++] = 0xbe; code[n++] = 0x40; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;   /* fnstcw [rsi+0x140] */
					code[n++] = 0xdd; code[n++] = 0xbe; code[n++] = 0x48; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;   /* fnstsw [rsi+0x148] */
				}
				x87_cases++;
				if (!cn_native(code, n, &in, &a))
					continue;
				if (!cn_emulate(code, n, &in, &b, 64, &r) || !r.done) {
					x87_unsup++;
					continue;
				}
				ha = a.raw + CN_O_BUF;
				hb = b.raw + CN_O_BUF;
				if (mode == 0) {
					if (memcmp(ha + 0x100, hb + 0x100, 2) || memcmp(ha + 0x104, hb + 0x104, 2) || memcmp(ha + 0x108, hb + 0x108, 2)) {
						x87_bad++;
						if (x87_nfirst < 3)
							snprintf(x87_first[x87_nfirst++], sizeof x87_first[0],
								 "fnstenv depth %u: fcw/fsw/ftw native %04x/%04x/%04x emu %04x/%04x/%04x", depth,
								 ha[0x100] | ha[0x101] << 8, ha[0x104] | ha[0x105] << 8, ha[0x108] | ha[0x109] << 8,
								 hb[0x100] | hb[0x101] << 8, hb[0x104] | hb[0x105] << 8, hb[0x108] | hb[0x109] << 8);
					}
				} else if (mode == 1) {
					unsigned bad = 0;
					uint32_t mxa, mxb;

					bad |= memcmp(ha + 0x200, hb + 0x200, 2) != 0;                          /* FCW */
					bad |= memcmp(ha + 0x202, hb + 0x202, 2) != 0;                          /* FSW incl. TOP */
					bad |= ha[0x204] != hb[0x204];                                          /* abridged FTW */
					memcpy(&mxa, ha + 0x218, 4);
					memcpy(&mxb, hb + 0x218, 4);
					bad |= (mxa & 0xffc0u) != (mxb & 0xffc0u);                              /* MXCSR control bits */
					for (k = 0; k < depth; k++)                                             /* ST(k): 80 bit, stack order */
						bad |= memcmp(ha + 0x220 + 16u * k, hb + 0x220 + 16u * k, 10) != 0;
					bad |= memcmp(ha + 0x2a0, hb + 0x2a0, 32) != 0;                         /* xmm0, xmm1 */
					if (bad) {
						x87_bad++;
						if (x87_nfirst < 3)
							snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "fxsave depth %u cw %04x: image differs", depth, cw);
					}
				} else {
					if (memcmp(ha + 0x140, hb + 0x140, 2) || memcmp(ha + 0x148, hb + 0x148, 2)) {
						x87_bad++;
						if (x87_nfirst < 3)
							snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "fnstcw/fnstsw depth %u: native %04x/%04x emu %04x/%04x",
								 depth, ha[0x140] | ha[0x141] << 8, ha[0x148] | ha[0x149] << 8,
								 hb[0x140] | hb[0x141] << 8, hb[0x148] | hb[0x149] << 8);
					}
				}
			}
	x87_finish("x87 state images");
}



/*
 * THE TRANSCENDENTALS AND THE REMAINDERS: F2XM1, FSIN, FCOS, FSINCOS, FPTAN, FPATAN, FSCALE, FXTRACT, FPREM, FPREM1. The
 * registers are doubles and the interpreter computes in the host's long double, so one unit in the last place of a double
 * is allowed on FSIN, FCOS, FSINCOS, FPTAN, FPATAN and F2XM1 (the CPU's result is the 80 bit one, rounded once more on the
 * store); FSCALE, FXTRACT, FPREM and FPREM1 are exact and are compared bit for bit, with their condition codes: C2 = 1 on
 * the trigonometric functions for an operand of 2^63 or more (the operand then stays), and the quotient bits in C0 C3 C1
 * of the remainders.
 */
static void t_x87_trans(void)
{
	static const struct x87_op op[] = {
		{ "fsin", { 0xd9, 0xfe }, 2, 2, 2, 0, 0, 0, 0 }, { "fcos", { 0xd9, 0xff }, 2, 2, 2, 0, 0, 0, 0 },
		{ "fsincos", { 0xd9, 0xfb }, 2, 2, 2, 0, 0, 0, 0 }, { "fptan", { 0xd9, 0xf2 }, 2, 2, 2, 0, 0, 0, 0 },
		{ "fpatan", { 0xd9, 0xf3 }, 2, 1, 0, 0, 0, 0, 0 }, { "fscale", { 0xd9, 0xfd }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fxtract", { 0xd9, 0xf4 }, 2, 2, 0, 0, 1, 0, 0 }, { "fprem", { 0xd9, 0xf8 }, 2, 2, 1, 0, 1, 0, 0 },
		{ "fprem1", { 0xd9, 0xf5 }, 2, 2, 1, 0, 1, 0, 0 }, { "f2xm1", { 0xd9, 0xf0 }, 2, 2, 0, 0, 0, 0, 0 }
	};
	/* Arguments the CPU reduces accurately: it reduces by multiples of pi/2 with a 66 bit pi, so a large argument, or one that
	 * is near a multiple of pi/2 (pi itself as a double, 1.5707963267948966), comes back with an error far above one unit in the
	 * last place - the interpreter reduces exactly, and says so in emu_x87.c. 1e19 is out of range: the operand stays, C2 = 1. */
	static const double trig[] = { 0.0, -0.0, 0.5, -0.5, 1.0, 2.0, 3.0, 7.0, 100.0, 0.7853981633974483, 1e-300, 0.1, -2.5, 4.0, 1e19, -1e19 };
	static const double small[] = { 0.0, -0.0, 0.5, -0.5, 1.0, -1.0, 0.25, -0.25, 0.1, 0.999, 1e-10, -1e-10 };
	static const double scl[] = { 0.0, 1.0, -1.0, 2.0, 3.5, -3.5, 10.0, -10.0, 100.0, 1074.0, -1074.0, 1e4, 0.5 };
	unsigned o, i, j;

	for (o = 0; o < 4; o++)                                     /* the trigonometric functions: st0 only (st1 rides along) */
		for (i = 0; i < sizeof trig / sizeof trig[0]; i++) {
			uint64_t y;

			memcpy(&y, &trig[i], 8);
			x87_one(&op[o], xp(3), y, 0, NULL, 0, 0x37f);
		}
	for (o = 0; o < 4; o++)
		for (i = 0; i < 6; i++) {
			uint64_t y = xp(18 + i % 4);                    /* infinities and a NaN */

			x87_one(&op[o], xp(3), y, 0, NULL, 0, 0x37f);
		}
	for (i = 0; i < NX; i++)                                    /* fpatan: every pair */
		for (j = 0; j < NX; j++)
			x87_one(&op[4], xp(i), xp(j), 0, NULL, 0, 0x37f);
	for (i = 0; i < NX; i++)                                    /* fscale: st1 is the scale */
		for (j = 0; j < sizeof scl / sizeof scl[0]; j++) {
			uint64_t y;
			uint64_t s2;

			memcpy(&s2, &scl[j], 8);
			y = xp(i);
			x87_one(&op[5], s2, y, 0, NULL, 0, 0x37f);
		}
	for (i = 0; i < NX; i++)
		x87_one(&op[6], xp(1), xp(i), 0, NULL, 0, 0x37f);
	for (o = 7; o < 9; o++)                                     /* the remainders: every pair, and a few with a large quotient */
		for (i = 0; i < NX; i++)
			for (j = 0; j < NX; j++)
				x87_one(&op[o], xp(j), xp(i), 0, NULL, 0, 0x37f);
	for (i = 0; i < sizeof small / sizeof small[0]; i++) {
		uint64_t y;

		memcpy(&y, &small[i], 8);
		x87_one(&op[9], xp(3), y, 0, NULL, 0, 0x37f);
	}
	x87_finish("x87 transcendentals, remainders");
}

/*
 * FYL2X and FYL2XP1: st1 * log2(st0) and st1 * log2(st0 + 1), popped into st0. The host's log2 and log1p give a
 * double, the real instruction an extended value rounded once more when stored, so one unit in the last place is
 * allowed (x87_one's `exact` = 0) and nothing else. FYL2XP1 is defined only for |st0| < 1 - sqrt(2)/2, so its pool is
 * inside that range, plus the two zeros. A negative st0 is the invalid operation: a NaN either way.
 */
static void t_x87_log(void)
{
	static const struct x87_op op[] = {
		{ "fyl2x", { 0xd9, 0xf1 }, 2, 1, 0, 0, 0, 0, 0 }, { "fyl2xp1", { 0xd9, 0xf9 }, 2, 1, 0, 0, 0, 0, 0 }
	};
	static const double small[] = { 0.0, -0.0, 0.1, -0.1, 0.25, -0.25, 1e-10, -1e-10, 0.2928, -0.2928, 0.01, 0.123456789 };
	unsigned i, j;

	for (i = 0; i < NX; i++)
		for (j = 0; j < NX; j++)
			x87_one(&op[0], xp(i), xp(j), 0, NULL, 0, 0x37f);
	for (i = 0; i < NX; i++)
		for (j = 0; j < sizeof small / sizeof small[0]; j++) {
			uint64_t y;

			memcpy(&y, &small[j], 8);
			x87_one(&op[1], xp(i), y, 0, NULL, 0, 0x37f);
		}
	x87_finish("x87 fyl2x, fyl2xp1");
}

/*
 * FBLD and FBSTP. The loaded value is read back as a double (exact: the digits are chosen under 2^53), and the stored
 * image is compared byte for byte - the sign, the 18 digits, and the "packed decimal indefinite" for a NaN, an
 * infinity and 10^18; FBSTP is run under every rounding mode on values with a fraction.
 */
static void t_x87_bcd(void)
{
	static const double v[] = { 0.0, -0.0, 1.0, -1.0, 0.5, 1.5, 2.5, -0.5, -1.5, -2.5, 0.4999, 123456789.5, 999999999999999999.0,
				    1e18, -1e18, 9007199254740991.0, -9007199254740991.0, 4503599627370497.5, 1e30, 0.0000001 };
	unsigned i, rc, k;

	for (i = 0; i < 400; i++) {                                /* FBLD of a random 15 digit number, with a sign */
		struct cn_io in, a, b;
		struct cn_emu r;
		uint8_t code[40];
		uint8_t bcd[10] = { 0 };
		unsigned n = 0, d;
		uint64_t m = cn_rng() % 1000000000000000ull;

		for (d = 0; d < 9; d++, m /= 100u)
			bcd[d] = (uint8_t)((((m / 10u) % 10u) << 4) | (m % 10u));
		bcd[9] = (cn_rng() & 1u) ? 0x80u : 0u;
		cn_input(&in, 0);
		cn_put(&in, CN_O_RSI, CN_O_BUF);
		memcpy(in.raw + CN_O_BUF + 0x40, bcd, 10);
		code[n++] = 0xdb; code[n++] = 0xe3;                        /* fninit */
		code[n++] = 0xdf; code[n++] = 0x66; code[n++] = 0x40;      /* fbld [rsi+0x40] */
		code[n++] = 0xdd; code[n++] = 0x56; code[n++] = 0x58;      /* fst qword [rsi+0x58] */
		code[n++] = 0xdf; code[n++] = 0x76; code[n++] = 0x60;      /* fbstp [rsi+0x60] */
		x87_cases++;
		if (!cn_native(code, n, &in, &a))
			continue;
		if (!cn_emulate(code, n, &in, &b, 64, &r) || !r.done) {
			x87_unsup++;
			continue;
		}
		if (memcmp(a.raw + CN_O_BUF + 0x58, b.raw + CN_O_BUF + 0x58, 8) || memcmp(a.raw + CN_O_BUF + 0x60, b.raw + CN_O_BUF + 0x60, 10)) {
			x87_bad++;
			if (x87_nfirst < 3)
				snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "fbld/fbstp round trip differs (digits %02x%02x%02x...)",
					 bcd[8], bcd[7], bcd[6]);
		}
	}
	for (rc = 0; rc < 4; rc++)                                 /* FBSTP of a double, under each rounding mode */
		for (i = 0; i < sizeof v / sizeof v[0]; i++)
			for (k = 0; k < 2; k++) {
				struct cn_io in, a, b;
				struct cn_emu r;
				uint8_t code[40];
				unsigned n = 0;
				uint64_t u;
				uint16_t cw = (uint16_t)(0x37fu | (rc << 10));
				double dv = k ? -v[i] : v[i];

				memcpy(&u, &dv, 8);
				cn_input(&in, 0);
				cn_put(&in, CN_O_RSI, CN_O_BUF);
				memcpy(in.raw + CN_O_BUF, &u, 8);
				memcpy(in.raw + CN_O_BUF + 0x2c0, &cw, 2);
				memset(in.raw + CN_O_BUF + 0x60, 0x5a, 16);
				code[n++] = 0xdb; code[n++] = 0xe3;
				code[n++] = 0xd9; code[n++] = 0xae; code[n++] = 0xc0; code[n++] = 0x02; code[n++] = 0; code[n++] = 0;   /* fldcw [rsi+0x2c0] */
				code[n++] = 0xdd; code[n++] = 0x06;                /* fld qword [rsi] */
				code[n++] = 0xdf; code[n++] = 0x76; code[n++] = 0x60;
				x87_cases++;
				if (!cn_native(code, n, &in, &a))
					continue;
				if (!cn_emulate(code, n, &in, &b, 64, &r) || !r.done) {
					x87_unsup++;
					continue;
				}
				if (memcmp(a.raw + CN_O_BUF + 0x60, b.raw + CN_O_BUF + 0x60, 10)) {
					x87_bad++;
					if (x87_nfirst < 3)
						snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "fbstp of %g under rc %u differs: native %02x%02x.. emu %02x%02x..",
							 dv, rc, a.raw[CN_O_BUF + 0x6a - 1], a.raw[CN_O_BUF + 0x68], b.raw[CN_O_BUF + 0x6a - 1], b.raw[CN_O_BUF + 0x68]);
				}
			}
	x87_finish("x87 fbld, fbstp");
}

/*
 * THE STATE RESTORES. The host saves a state (FNSAVE, FNSTENV, FXSAVE after a stack of values under a chosen control word,
 * which ALSO leaves a condition code behind from an FCOM), the image goes into the input of the case, and the case restores
 * it and reads the machine back: FLDENV then FNSTENV, FRSTOR then the stack as doubles, FXRSTOR then FXSAVE. What a
 * restore must give is what the host's restore gives, so the two are compared field by field: control word, status word
 * with TOP, tag word (abridged for FXSAVE), the registers, MXCSR's control bits and xmm0/xmm1. FIP, FDP and FOP are the
 * address of an instruction and cannot be equal across two machines; they are not compared.
 */
static unsigned x87_make_image(uint8_t *img, unsigned mode, unsigned depth, uint16_t cw, const double *vals)
{
	struct cn_io in, out;
	uint8_t code[96];
	unsigned n = 0, k;

	cn_input(&in, 0);
	cn_put(&in, CN_O_RSI, CN_O_BUF);
	memcpy(in.raw + CN_O_BUF + 0x2c0, &cw, 2);
	for (k = 0; k < depth; k++)
		memcpy(in.raw + CN_O_BUF + 8u * k, &vals[k], 8);
	code[n++] = 0xdb; code[n++] = 0xe3;
	code[n++] = 0xd9; code[n++] = 0xae; code[n++] = 0xc0; code[n++] = 0x02; code[n++] = 0; code[n++] = 0;
	for (k = 0; k < depth; k++) {
		code[n++] = 0xdd; code[n++] = 0x46; code[n++] = (uint8_t)(8u * k);
	}
	if (depth > 1) {                                           /* fcom st1: a condition code to carry across */
		code[n++] = 0xd8; code[n++] = 0xd1;
	}
	if (mode == 0) {                                           /* fnstenv [rsi+0x100] */
		code[n++] = 0xd9; code[n++] = 0xb6; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;
	} else if (mode == 1) {                                    /* fnsave [rsi+0x100] */
		code[n++] = 0xdd; code[n++] = 0xb6; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;
	} else {                                                   /* fxsave [rsi+0x100] */
		code[n++] = 0x0f; code[n++] = 0xae; code[n++] = 0x86; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;
	}
	if (!cn_native(code, n, &in, &out))
		return 0;
	memcpy(img, out.raw + CN_O_BUF + 0x100, mode == 0 ? 28u : mode == 1 ? 108u : 512u);
	return mode == 0 ? 28u : mode == 1 ? 108u : 512u;
}

static void t_x87_restore(void)
{
	static const double vals[] = { 1.0, -2.0, 0.5, 3.0, 1.0e10, 0.0, 7.0 };
	unsigned mode, depth, i;

	for (mode = 0; mode < 3; mode++)
		for (depth = 0; depth <= 7; depth++)
			for (i = 0; i < 6; i++) {
				struct cn_io in, a, b;
				struct cn_emu r;
				uint8_t img[512], code[96];
				unsigned n = 0, k, len, bad = 0;
				uint16_t cw = (uint16_t)(0x37fu | ((unsigned)(i & 3u) << 10) | ((i & 1u) ? 0x300u : 0x200u));
				double v[7];
				const uint8_t *ha, *hb;

				for (k = 0; k < 7; k++)
					v[k] = vals[(k + i) % (sizeof vals / sizeof vals[0])];
				len = x87_make_image(img, mode, depth, cw, v);
				if (!len)
					continue;
				cn_input(&in, 0);
				cn_put(&in, CN_O_RSI, CN_O_BUF);
				memcpy(in.raw + CN_O_BUF + 0x100, img, len);
				xin(&in, cn_rng(), cn_rng(), 0);
				code[n++] = 0xdb; code[n++] = 0xe3;            /* fninit: a machine that is not the one saved */
				if (mode == 0) {                               /* fldenv [rsi+0x100]; fnstenv [rsi+0x400] */
					code[n++] = 0xd9; code[n++] = 0xa6; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;
					code[n++] = 0xd9; code[n++] = 0xb6; code[n++] = 0x00; code[n++] = 0x04; code[n++] = 0; code[n++] = 0;
				} else if (mode == 1) {                        /* frstor [rsi+0x100]; fnstenv [rsi+0x400]; fstp qword [rsi+0x500+8k] */
					code[n++] = 0xdd; code[n++] = 0xa6; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;
					code[n++] = 0xd9; code[n++] = 0xb6; code[n++] = 0x00; code[n++] = 0x04; code[n++] = 0; code[n++] = 0;
					for (k = 0; k < depth; k++) {
						code[n++] = 0xdd; code[n++] = 0x9e; code[n++] = (uint8_t)(0x00u + 8u * k); code[n++] = 0x05; code[n++] = 0; code[n++] = 0;
					}
				} else {                                       /* fxrstor [rsi+0x100]; fxsave [rsi+0x400] */
					code[n++] = 0x0f; code[n++] = 0xae; code[n++] = 0x8e; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;
					code[n++] = 0x0f; code[n++] = 0xae; code[n++] = 0x86; code[n++] = 0x00; code[n++] = 0x04; code[n++] = 0; code[n++] = 0;
				}
				x87_cases++;
				if (!cn_native(code, n, &in, &a))
					continue;
				if (!cn_emulate(code, n, &in, &b, 64, &r) || !r.done) {
					x87_unsup++;
					if (x87_nfirst < 3)
						snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "restore mode %u: interpreter stopped (%s: %s)", mode,
							 kgenome_emu_stop_name(r.stop), r.detail);
					continue;
				}
				ha = a.raw + CN_O_BUF;
				hb = b.raw + CN_O_BUF;
				if (mode != 2) {
					bad |= memcmp(ha + 0x400, hb + 0x400, 2) != 0;                  /* FCW */
					bad |= memcmp(ha + 0x404, hb + 0x404, 2) != 0;                  /* FSW with TOP */
					bad |= memcmp(ha + 0x408, hb + 0x408, 2) != 0;                  /* the tag word */
					if (mode == 1)
						for (k = 0; k < depth; k++)
							bad |= memcmp(ha + 0x500 + 8u * k, hb + 0x500 + 8u * k, 8) != 0;
				} else {
					uint32_t ma, mb;

					bad |= memcmp(ha + 0x400, hb + 0x400, 2) != 0;
					bad |= memcmp(ha + 0x402, hb + 0x402, 2) != 0;
					bad |= ha[0x404] != hb[0x404];
					memcpy(&ma, ha + 0x418, 4);
					memcpy(&mb, hb + 0x418, 4);
					bad |= (ma & 0xffc0u) != (mb & 0xffc0u);
					for (k = 0; k < depth; k++)
						bad |= memcmp(ha + 0x420 + 16u * k, hb + 0x420 + 16u * k, 10) != 0;
					bad |= memcmp(ha + 0x4a0, hb + 0x4a0, 32) != 0;                 /* xmm0, xmm1 */
				}
				if (bad) {
					x87_bad++;
					if (x87_nfirst < 3)
						snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "restore mode %u depth %u cw %04x: state differs", mode,
							 depth, cw);
				}
			}
	x87_finish("x87 fldenv, frstor, fxrstor");
}

/* FNSAVE: the 108 byte image, and the FNINIT that follows it */
static void t_x87_save(void)
{
	static const double vals[] = { 1.0, -2.0, 0.5, 3.0, 1.0e10, 0.0, 7.0 };
	unsigned depth, i;

	for (depth = 0; depth <= 7; depth++)
		for (i = 0; i < 6; i++) {
			struct cn_io in, a, b;
			struct cn_emu r;
			uint8_t code[96];
			unsigned n = 0, k, bad = 0;
			uint16_t cw = (uint16_t)(0x37fu | ((unsigned)(i & 3u) << 10));

			cn_input(&in, 0);
			cn_put(&in, CN_O_RSI, CN_O_BUF);
			memcpy(in.raw + CN_O_BUF + 0x2c0, &cw, 2);
			for (k = 0; k < depth; k++) {
				const double d = vals[(k + i) % (sizeof vals / sizeof vals[0])];

				memcpy(in.raw + CN_O_BUF + 8u * k, &d, 8);
			}
			code[n++] = 0xdb; code[n++] = 0xe3;
			code[n++] = 0xd9; code[n++] = 0xae; code[n++] = 0xc0; code[n++] = 0x02; code[n++] = 0; code[n++] = 0;
			for (k = 0; k < depth; k++) {
				code[n++] = 0xdd; code[n++] = 0x46; code[n++] = (uint8_t)(8u * k);
			}
			code[n++] = 0xdd; code[n++] = 0xb6; code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0; code[n++] = 0;    /* fnsave [rsi+0x100] */
			code[n++] = 0xd9; code[n++] = 0xbe; code[n++] = 0x40; code[n++] = 0x03; code[n++] = 0; code[n++] = 0;    /* fnstcw [rsi+0x340] */
			code[n++] = 0xdd; code[n++] = 0xbe; code[n++] = 0x48; code[n++] = 0x03; code[n++] = 0; code[n++] = 0;    /* fnstsw [rsi+0x348] */
			x87_cases++;
			if (!cn_native(code, n, &in, &a))
				continue;
			if (!cn_emulate(code, n, &in, &b, 64, &r) || !r.done) {
				x87_unsup++;
				continue;
			}
			{
				const uint8_t *ha = a.raw + CN_O_BUF, *hb = b.raw + CN_O_BUF;

				bad |= memcmp(ha + 0x100, hb + 0x100, 2) != 0;
				bad |= memcmp(ha + 0x104, hb + 0x104, 2) != 0;
				bad |= memcmp(ha + 0x108, hb + 0x108, 2) != 0;
				for (k = 0; k < depth; k++)
					bad |= memcmp(ha + 0x100 + 28u + 10u * k, hb + 0x100 + 28u + 10u * k, 10) != 0;
				bad |= memcmp(ha + 0x340, hb + 0x340, 2) != 0 || memcmp(ha + 0x348, hb + 0x348, 2) != 0;
			}
			if (bad) {
				x87_bad++;
				if (x87_nfirst < 3)
					snprintf(x87_first[x87_nfirst++], sizeof x87_first[0], "fnsave depth %u cw %04x: image or the init after it differs", depth, cw);
			}
		}
	x87_finish("x87 fnsave");
}

int main(void)
{
	cn_rng_state = 0x5353455838372121ull;
	if (!CN_HOST) {
		printf("diff_sse_x87: SKIPPED (the host is not x86-64 Linux, so there is no reference to run)\n");
		return 0;
	}
	t_scalar();
	t_compare();
	t_convert();
	t_integer();
	t_moves();
	t_x87_arith();
	t_x87_compare();
	t_x87_int();
	t_x87_state();
	t_x87_trans();
	t_x87_log();
	t_x87_bcd();
	t_x87_save();
	t_x87_restore();
	printf("diff_sse_x87: %u group(s), %u vector(s)\n", groups, vectors);
	CK(vectors > 20000u, "the sweep is the size it claims (%u vectors)", vectors);
	if (fails) {
		printf("diff_sse_x87: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_sse_x87: ok\n");
	return 0;
}
