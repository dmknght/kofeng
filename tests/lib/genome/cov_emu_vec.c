/*
 * cov_emu_vec - the interpreter's SSE and x87 instructions, against the host CPU.
 *
 * The same bytes run on the host and in the interpreter (cov_native.h) with inputs drawn from the
 * values that break float code - zeros of both signs, ones, a denormal, the largest and smallest
 * exponents, infinities, NaN, noise - and the two xmm registers, the general registers and the
 * flags the architecture defines are compared bit for bit. x87 is run on the host's 80 bit stack and
 * in the interpreter's double stack, so a result is compared as a double stored back to memory:
 * the same bits, or within one unit in the last place where the hardware rounds twice (the
 * comparison says which).
 *
 *   SSE   logic (xorps pxor por pand pandn andps orps andnps pcmpeqb psubb), scalar double and single
 *         arithmetic (add sub mul div min max sqrt), the compares into EFLAGS (ucomisd comisd
 *         ucomiss comiss), the conversions (cvtsi2sd/ss in 32 and 64 bits, cvttsd2si/ss2si, cvtsd2ss,
 *         cvtss2sd), the moves (movd movq movss movsd movlps movhps in both directions), pinsrw
 *         pextrw pmovmskb pslldq psrldq punpcklbw pshufd
 *   x87   the arithmetic in all its forms (both operand orders, the pop forms, the reversed
 *         subtract and divide), fxch, fchs fabs fsqrt frndint, the compares into the status word and
 *         into EFLAGS (fcom fcomp fcompp fucom fucomi fcomip ftst), fxam, fcmov, the constants, and
 *         the integer loads and stores
 *
 * Every difference found earlier (the upper lane of scalar SSE, MINSD/MAXSD with a NaN, the half-register moves, FCOMPP,
 * FXSAVE and the integer indefinite) is fixed and is a hard check here.
 * Skipped, visibly, on a host that is not x86-64 Linux.
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


/* ---- inputs ---------------------------------------------------------------------------- */

static uint64_t dpool(void)
{
	static const double p[] = { 0.0, -0.0, 1.0, -1.0, 0.5, 3.0, -7.25, 1e300, -1e300, 1e-310, 4.0, 9.0,
				    2.5, -2.5, 1e15, 2147483648.0, -2147483649.0, 9.3e18, -9.3e18 };
	uint64_t b;
	unsigned k = (unsigned)(cn_rng() % 24u);

	if (k < sizeof p / sizeof p[0]) {
		memcpy(&b, &p[k], 8);
		return b;
	}
	switch (k - (unsigned)(sizeof p / sizeof p[0])) {
	case 0:  return 0x7ff0000000000000ull;          /* +inf */
	case 1:  return 0xfff0000000000000ull;          /* -inf */
	case 2:  return 0xfff8000000000000ull;          /* the default NaN */
	case 3:  return 0x7ff4000000000001ull;          /* a signalling NaN with a payload */
	default: return cn_rng();
	}
}

static uint32_t fpool(void)
{
	static const float p[] = { 0.0f, -0.0f, 1.0f, -1.0f, 0.5f, 3.0f, -7.25f, 1e30f, -1e30f, 1e-40f, 2.5f,
				   16777216.0f, 3e9f };
	uint32_t b;
	unsigned k = (unsigned)(cn_rng() % 18u);

	if (k < sizeof p / sizeof p[0]) {
		memcpy(&b, &p[k], 4);
		return b;
	}
	switch (k - (unsigned)(sizeof p / sizeof p[0])) {
	case 0:  return 0x7f800000u;
	case 1:  return 0xff800000u;
	case 2:  return 0xffc00000u;
	case 3:  return 0x7fa00001u;
	default: return (uint32_t)cn_rng();
	}
}

static void xmm_in(struct cn_io *x, int single)
{
	uint64_t a[2], b[2];
	uint32_t f;

	a[0] = dpool(); a[1] = cn_rng();
	b[0] = dpool(); b[1] = cn_rng();
	if (single) {
		f = fpool(); memcpy(&a[0], &f, 4);
		f = fpool(); memcpy(&b[0], &f, 4);
		a[0] = (a[0] & 0xffffffffull) | (cn_rng() << 32);
		b[0] = (b[0] & 0xffffffffull) | (cn_rng() << 32);
	}
	memcpy(x->raw + CN_O_XMM, a, 16);
	memcpy(x->raw + CN_O_XMM + 16, b, 16);
}


/* ---- SSE ------------------------------------------------------------------------------ */

/* which output bytes are compared: xmm0 is bits 0-15, xmm1 bits 16-31 */
#define XM_ALL    0xffffffffu
#define XM_LOW64  0xffff00ffu        /* the low double of xmm0, and xmm1 untouched */
#define XM_LOW32  0xffff000fu
#define XM_UP64   0x0000ff00u        /* what a scalar double op must leave alone */
#define XM_UP96   0x0000fff0u
#define XM_NONE   0u

struct sse_op {
	const char *nm;
	uint8_t     b[8];
	unsigned    n;
	int         single;         /* the inputs are floats */
	uint64_t    flags;          /* flag bits the instruction defines */
	uint32_t    xm;             /* output bytes compared */
};

static void run_sse(const char *family, const struct sse_op *ops, unsigned nops, unsigned reps)
{
	unsigned o, i;
	int buf = !!strstr(family, "moves");

	memset(&st, 0, sizeof st);
	for (o = 0; o < nops; o++) {
		unsigned before = st.diffs + st.unsupported;

		for (i = 0; i < reps; i++) {
			struct cn_io in;
			struct cn_stat k;

			cn_input(&in, 0);
			xmm_in(&in, ops[o].single);
			if (buf) {
				cn_fill_buf(&in, 0);
				cn_put(&in, CN_O_RSI, CN_O_BUF + 64u);
			}
			(void)k;
			(void)cn_case(&st, ops[o].nm, ops[o].b, ops[o].n, &in, ops[o].flags, 64, ops[o].xm, buf);
		}
		if (buf && st.diffs + st.unsupported != before)
			printf("      %s: %u of %u case(s) differ\n          %s\n", ops[o].nm, st.diffs + st.unsupported - before, reps,
			       st.nfirst ? st.first[0] : "");
		st.nfirst = 0;
	}
	cn_print(family, &st);
	CK(st.native_ok == st.cases, "%s: the host ran every case", family);
	CK(st.unsupported == 0, "%s: carried (%u refused)", family, st.unsupported);
	CK(st.diffs == 0, "%s: equal the CPU bit for bit (%u differ)", family, st.diffs);
}

static void t_sse_logic(void)
{
	static const struct sse_op ops[] = {
		{ "xorps",   { 0x0f, 0x57, 0xc1 }, 3, 0, 0, XM_ALL },       { "xorpd", { 0x66, 0x0f, 0x57, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "andps",   { 0x0f, 0x54, 0xc1 }, 3, 0, 0, XM_ALL },       { "andnps", { 0x0f, 0x55, 0xc1 }, 3, 0, 0, XM_ALL },
		{ "orps",    { 0x0f, 0x56, 0xc1 }, 3, 0, 0, XM_ALL },       { "andpd", { 0x66, 0x0f, 0x54, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "andnpd",  { 0x66, 0x0f, 0x55, 0xc1 }, 4, 0, 0, XM_ALL }, { "orpd",  { 0x66, 0x0f, 0x56, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "pxor",    { 0x66, 0x0f, 0xef, 0xc1 }, 4, 0, 0, XM_ALL }, { "por",   { 0x66, 0x0f, 0xeb, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "pand",    { 0x66, 0x0f, 0xdb, 0xc1 }, 4, 0, 0, XM_ALL }, { "pandn", { 0x66, 0x0f, 0xdf, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "pcmpeqb", { 0x66, 0x0f, 0x74, 0xc1 }, 4, 0, 0, XM_ALL }, { "psubb", { 0x66, 0x0f, 0xf8, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "punpcklbw", { 0x66, 0x0f, 0x60, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "pshufd 1b", { 0x66, 0x0f, 0x70, 0xc1, 0x1b }, 5, 0, 0, XM_ALL },
		{ "pshufd e4", { 0x66, 0x0f, 0x70, 0xc1, 0xe4 }, 5, 0, 0, XM_ALL },
		{ "pshufd 55", { 0x66, 0x0f, 0x70, 0xc0, 0x55 }, 5, 0, 0, XM_ALL },
		{ "pslldq 3", { 0x66, 0x0f, 0x73, 0xf8, 0x03 }, 5, 0, 0, XM_ALL },
		{ "pslldq 15", { 0x66, 0x0f, 0x73, 0xf8, 0x0f }, 5, 0, 0, XM_ALL },
		{ "pslldq 16", { 0x66, 0x0f, 0x73, 0xf8, 0x10 }, 5, 0, 0, XM_ALL },
		{ "psrldq 5", { 0x66, 0x0f, 0x73, 0xd8, 0x05 }, 5, 0, 0, XM_ALL },
		{ "psrldq 16", { 0x66, 0x0f, 0x73, 0xd8, 0x10 }, 5, 0, 0, XM_ALL },
		{ "pinsrw 2", { 0x66, 0x0f, 0xc4, 0xc0, 0x02 }, 5, 0, 0, XM_ALL },
		{ "pinsrw 7", { 0x66, 0x0f, 0xc4, 0xc0, 0x07 }, 5, 0, 0, XM_ALL },
		{ "pextrw 0", { 0x66, 0x0f, 0xc5, 0xc0, 0x00 }, 5, 0, 0, XM_ALL },
		{ "pextrw 5", { 0x66, 0x0f, 0xc5, 0xc0, 0x05 }, 5, 0, 0, XM_ALL },
		{ "pmovmskb", { 0x66, 0x0f, 0xd7, 0xc0 }, 4, 0, 0, XM_ALL }
	};

	run_sse("sse logic and shuffles", ops, sizeof ops / sizeof ops[0], 60);
}

static void t_sse_arith(void)
{
	static const struct sse_op ops[] = {
		{ "addsd",  { 0xf2, 0x0f, 0x58, 0xc1 }, 4, 0, 0, XM_LOW64 }, { "mulsd", { 0xf2, 0x0f, 0x59, 0xc1 }, 4, 0, 0, XM_LOW64 },
		{ "subsd",  { 0xf2, 0x0f, 0x5c, 0xc1 }, 4, 0, 0, XM_LOW64 }, { "divsd", { 0xf2, 0x0f, 0x5e, 0xc1 }, 4, 0, 0, XM_LOW64 },
		{ "sqrtsd", { 0xf2, 0x0f, 0x51, 0xc1 }, 4, 0, 0, XM_LOW64 },
		{ "addss",  { 0xf3, 0x0f, 0x58, 0xc1 }, 4, 1, 0, XM_LOW32 }, { "mulss", { 0xf3, 0x0f, 0x59, 0xc1 }, 4, 1, 0, XM_LOW32 },
		{ "subss",  { 0xf3, 0x0f, 0x5c, 0xc1 }, 4, 1, 0, XM_LOW32 }, { "divss", { 0xf3, 0x0f, 0x5e, 0xc1 }, 4, 1, 0, XM_LOW32 },
		/* the upper lane a scalar operation must leave alone */
		{ "addsd/up",  { 0xf2, 0x0f, 0x58, 0xc1 }, 4, 0, 0, XM_UP64 }, { "mulsd/up", { 0xf2, 0x0f, 0x59, 0xc1 }, 4, 0, 0, XM_UP64 },
		{ "subsd/up",  { 0xf2, 0x0f, 0x5c, 0xc1 }, 4, 0, 0, XM_UP64 }, { "divsd/up", { 0xf2, 0x0f, 0x5e, 0xc1 }, 4, 0, 0, XM_UP64 },
		{ "sqrtsd/up", { 0xf2, 0x0f, 0x51, 0xc1 }, 4, 0, 0, XM_UP64 },
		{ "addss/up",  { 0xf3, 0x0f, 0x58, 0xc1 }, 4, 1, 0, XM_UP96 }, { "mulss/up", { 0xf3, 0x0f, 0x59, 0xc1 }, 4, 1, 0, XM_UP96 },
		{ "subss/up",  { 0xf3, 0x0f, 0x5c, 0xc1 }, 4, 1, 0, XM_UP96 }, { "divss/up", { 0xf3, 0x0f, 0x5e, 0xc1 }, 4, 1, 0, XM_UP96 },
		/* minimum and maximum: NaN and zero ordering */
		{ "minsd",  { 0xf2, 0x0f, 0x5d, 0xc1 }, 4, 0, 0, XM_LOW64 }, { "maxsd", { 0xf2, 0x0f, 0x5f, 0xc1 }, 4, 0, 0, XM_LOW64 }
	};

	run_sse("sse scalar arithmetic", ops, sizeof ops / sizeof ops[0], 160);
}

static void t_sse_compare(void)
{
	static const struct sse_op ops[] = {
		{ "ucomisd", { 0x66, 0x0f, 0x2e, 0xc1 }, 4, 0, CN_FL_ARITH, XM_ALL },
		{ "comisd",  { 0x66, 0x0f, 0x2f, 0xc1 }, 4, 0, CN_FL_ARITH, XM_ALL },
		{ "ucomiss", { 0x0f, 0x2e, 0xc1 }, 3, 1, CN_FL_ARITH, XM_ALL },
		{ "comiss",  { 0x0f, 0x2f, 0xc1 }, 3, 1, CN_FL_ARITH, XM_ALL }
	};

	run_sse("sse compares", ops, 4, 250);
}

static void t_sse_convert(void)
{
	static const struct sse_op ops[] = {
		{ "cvtsi2sd r32", { 0xf2, 0x0f, 0x2a, 0xc0 }, 4, 0, 0, XM_LOW64 },
		{ "cvtsi2sd r64", { 0xf2, 0x48, 0x0f, 0x2a, 0xc0 }, 5, 0, 0, XM_LOW64 },
		{ "cvtsi2ss r32", { 0xf3, 0x0f, 0x2a, 0xc0 }, 4, 1, 0, XM_LOW32 },
		{ "cvtsi2ss r64", { 0xf3, 0x48, 0x0f, 0x2a, 0xc0 }, 5, 1, 0, XM_LOW32 },
		{ "cvtsd2ss", { 0xf2, 0x0f, 0x5a, 0xc1 }, 4, 0, 0, XM_LOW32 },
		{ "cvtss2sd", { 0xf3, 0x0f, 0x5a, 0xc1 }, 4, 1, 0, XM_LOW64 },
		{ "cvttsd2si r64", { 0xf2, 0x48, 0x0f, 0x2c, 0xc0 }, 5, 0, 0, XM_ALL },
		{ "cvttss2si r64", { 0xf3, 0x48, 0x0f, 0x2c, 0xc0 }, 5, 1, 0, XM_ALL },
		{ "cvtsi2sd r32/up", { 0xf2, 0x0f, 0x2a, 0xc0 }, 4, 0, 0, XM_UP64 },
		{ "cvtsi2ss r32/up", { 0xf3, 0x0f, 0x2a, 0xc0 }, 4, 1, 0, XM_UP96 },
		{ "cvtss2sd/up", { 0xf3, 0x0f, 0x5a, 0xc1 }, 4, 1, 0, XM_UP64 },
		{ "cvtsd2ss/up", { 0xf2, 0x0f, 0x5a, 0xc1 }, 4, 0, 0, XM_UP96 },
		{ "cvttsd2si r32", { 0xf2, 0x0f, 0x2c, 0xc0 }, 4, 0, 0, XM_ALL },
		{ "cvttss2si r32", { 0xf3, 0x0f, 0x2c, 0xc0 }, 4, 1, 0, XM_ALL }
	};

	run_sse("sse conversions", ops, sizeof ops / sizeof ops[0], 200);
}

static void t_sse_moves(void)
{
	static const struct sse_op ops[] = {
		{ "movd xmm0,eax",  { 0x66, 0x0f, 0x6e, 0xc0 }, 4, 0, 0, XM_ALL },
		{ "movq xmm0,rax",  { 0x66, 0x48, 0x0f, 0x6e, 0xc0 }, 5, 0, 0, XM_ALL },
		{ "movd eax,xmm0",  { 0x66, 0x0f, 0x7e, 0xc0 }, 4, 0, 0, XM_ALL },
		{ "movq rax,xmm0",  { 0x66, 0x48, 0x0f, 0x7e, 0xc0 }, 5, 0, 0, XM_ALL },
		{ "movq xmm0,[rsi]", { 0xf3, 0x0f, 0x7e, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movq [rsi],xmm0", { 0x66, 0x0f, 0xd6, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movss xmm0,[rsi]", { 0xf3, 0x0f, 0x10, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movss [rsi],xmm0", { 0xf3, 0x0f, 0x11, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movsd xmm0,[rsi]", { 0xf2, 0x0f, 0x10, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movsd [rsi],xmm0", { 0xf2, 0x0f, 0x11, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movlps xmm0,[rsi]", { 0x0f, 0x12, 0x06 }, 3, 0, 0, XM_ALL },
		{ "movlpd xmm0,[rsi]", { 0x66, 0x0f, 0x12, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movlps [rsi],xmm0", { 0x0f, 0x13, 0x06 }, 3, 0, 0, XM_ALL },
		{ "movhps xmm0,[rsi]", { 0x0f, 0x16, 0x06 }, 3, 0, 0, XM_ALL },
		{ "movhps [rsi],xmm0", { 0x0f, 0x17, 0x06 }, 3, 0, 0, XM_ALL },
		{ "movhpd xmm0,[rsi]", { 0x66, 0x0f, 0x16, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movhpd [rsi],xmm0", { 0x66, 0x0f, 0x17, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movlpd [rsi],xmm0", { 0x66, 0x0f, 0x13, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movups xmm1,xmm0", { 0x0f, 0x10, 0xc8 }, 3, 0, 0, XM_ALL },
		{ "movdqu [rsi],xmm0", { 0xf3, 0x0f, 0x7f, 0x06 }, 4, 0, 0, XM_ALL },
		{ "movdqu xmm0,[rsi]", { 0xf3, 0x0f, 0x6f, 0x06 }, 4, 0, 0, XM_ALL },
		/* the register forms, which MERGE into the destination */
		{ "movss xmm0,xmm1", { 0xf3, 0x0f, 0x10, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "movsd xmm0,xmm1", { 0xf2, 0x0f, 0x10, 0xc1 }, 4, 0, 0, XM_ALL },
		{ "movlhps xmm0,xmm1", { 0x0f, 0x16, 0xc1 }, 3, 0, 0, XM_ALL }
	};

	run_sse("sse moves", ops, sizeof ops / sizeof ops[0], 40);
}

/* ---- x87 ------------------------------------------------------------------------------ */

/* the frame for a stack machine: fninit, st1 = [rsi], st0 = [rsi+8]; after the op, the status
 * word in AX, then `n` results stored as doubles at [rsi+16], [rsi+24] */
static unsigned x87_code(uint8_t *c, const uint8_t *op, unsigned n, unsigned nres, const uint8_t *pre, unsigned npre)
{
	static const uint8_t init[] = { 0xdb, 0xe3, 0xdd, 0x06, 0xdd, 0x46, 0x08 };   /* fninit; fld [rsi]; fld [rsi+8] */
	static const uint8_t sw[] = { 0xdf, 0xe0 };                                   /* fnstsw ax */
	static const uint8_t pop0[] = { 0xdd, 0x5e, 0x10 };                           /* fstp qword [rsi+16] */
	static const uint8_t pop1[] = { 0xdd, 0x5e, 0x18 };                           /* fstp qword [rsi+24] */
	unsigned k = 0;

	memcpy(c + k, init, sizeof init);
	k += (unsigned)sizeof init;
	if (npre) {
		memcpy(c + k, pre, npre);
		k += npre;
	}
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
		return 1;                       /* both NaN: the payload is not architectural here */
	if (a != a || b != b)
		return 0;
	if ((x ^ y) >> 63)
		return a == b;                  /* +0 and -0 */
	d = (int64_t)x - (int64_t)y;
	return d >= -1 && d <= 1;
}

/* a value the x87 can hold exactly and a double store gives back unchanged */
static uint64_t xpool(void)
{
	static const double p[] = { 0.0, -0.0, 1.0, -1.0, 2.0, 3.0, -3.0, 0.5, -0.5, 4.0, 9.0, 16.0, 2.5, -2.5, 3.5,
				    1.5, 100.0, -100.0, 65536.0, 1e10, 1e-10, 0.1, 7.0, 49.0, 1e300, 1e-300 };
	uint64_t b;
	unsigned k = (unsigned)(cn_rng() % 32u);

	if (k < sizeof p / sizeof p[0]) {
		memcpy(&b, &p[k], 8);
		return b;
	}
	switch (k - (unsigned)(sizeof p / sizeof p[0])) {
	case 0:  return 0x7ff0000000000000ull;
	case 1:  return 0xfff0000000000000ull;
	case 2:  return 0xfff8000000000000ull;
	default: return 0x3ff0000000000000ull;
	}
}

struct x87_op {
	const char *nm;
	uint8_t     b[8];
	unsigned    n;
	unsigned    nres;           /* values left on the stack to store */
	int         status;         /* compare the C0..C3 bits of the status word */
	uint64_t    flags;          /* the instruction writes EFLAGS (fcomi): which bits are defined */
	int         exact;          /* results must match bit for bit, not within an ulp */
	unsigned    memoff, memlen; /* a region of the data buffer (from rsi) that must match exactly */
};

#define X87_C (0x4700u)         /* C3 C2 C1 C0 (C1 is rounding/stack info: left in) */

static void run_x87(const char *family, const struct x87_op *ops, unsigned nops, unsigned reps)
{
	unsigned o, i, bad = 0, unsup = 0, cases = 0, nothing = 0;
	char first[3][240];
	unsigned nf = 0;

	for (o = 0; o < nops; o++) {
		unsigned op_bad0 = bad;
		char opmsg[300] = "";

		for (i = 0; i < reps; i++) {
			struct cn_io in, a, b;
			uint8_t code[64];
			unsigned len;
			struct cn_emu r;
			uint64_t x, y;
			unsigned k;
			int ok = 1;
			const char *why = "";

			cn_input(&in, 0);
			x = xpool();
			y = xpool();
			memcpy(in.raw + CN_O_BUF, &x, 8);
			memcpy(in.raw + CN_O_BUF + 8, &y, 8);
			{
				uint64_t iv = cn_edge(8);

				memcpy(in.raw + CN_O_BUF + 32, &iv, 8);
			}
			cn_put(&in, CN_O_RSI, CN_O_BUF);
			len = x87_code(code, ops[o].b, ops[o].n, ops[o].nres, NULL, 0);
			cases++;
			if (!cn_native(code, len, &in, &a)) {
				nothing++;
				continue;
			}
			if (!cn_emulate(code, len, &in, &b, 64, &r) || !r.done) {
				unsup++;
				if (nf < 3)
					snprintf(first[nf++], sizeof first[0], "%s: interpreter stopped (%s: %s)", ops[o].nm,
						 kgenome_emu_stop_name(r.stop), r.detail);
				continue;
			}
			for (k = 0; k < ops[o].nres; k++) {
				uint64_t u, v;

				memcpy(&u, a.raw + CN_O_BUF + 16 + 8 * k, 8);
				memcpy(&v, b.raw + CN_O_BUF + 16 + 8 * k, 8);
				if (ops[o].exact ? u != v && !(u << 1 > 0xffe0000000000000ull && v << 1 > 0xffe0000000000000ull)
						 : !dclose(u, v)) {
					ok = 0;
					why = "result";
					break;
				}
			}
			if (ok && ops[o].memlen &&
			    memcmp(a.raw + CN_O_BUF + ops[o].memoff, b.raw + CN_O_BUF + ops[o].memoff, ops[o].memlen)) {
				unsigned q = 0;
				static char mw[80];

				while (a.raw[CN_O_BUF + ops[o].memoff + q] == b.raw[CN_O_BUF + ops[o].memoff + q])
					q++;
				snprintf(mw, sizeof mw, "memory +%#x+%u native %02x emu %02x", ops[o].memoff, q,
					 a.raw[CN_O_BUF + ops[o].memoff + q], b.raw[CN_O_BUF + ops[o].memoff + q]);
				ok = 0;
				why = mw;
			}
			if (ok && ops[o].status && ((cn_get(&a, 48) ^ cn_get(&b, 48)) & X87_C)) {
				ok = 0;
				why = "status word";
			}
			if (ok && ops[o].flags && ((cn_get(&a, 88) ^ cn_get(&b, 88)) & ops[o].flags)) {
				ok = 0;
				why = "eflags";
			}
			if (!ok) {
				bad++;
				if (!opmsg[0]) {
					double dx, dy;

					memcpy(&dx, &x, 8);
					memcpy(&dy, &y, 8);
					snprintf(opmsg, sizeof opmsg, "%s: st1=%g st0=%g fl=%#llx  native sw=%#llx emu sw=%#llx", why,
						 dx, dy, (unsigned long long)cn_get(&in, 40),
						 (unsigned long long)(cn_get(&a, 48) & 0xffff), (unsigned long long)(cn_get(&b, 48) & 0xffff));
				}
				if (nf < 3) {
					double dx, dy;
					uint64_t ra = 0, rb = 0;

					memcpy(&dx, &x, 8);
					memcpy(&dy, &y, 8);
					memcpy(&ra, a.raw + CN_O_BUF + 16, 8);
					memcpy(&rb, b.raw + CN_O_BUF + 16, 8);
					snprintf(first[nf++], sizeof first[0],
						 "%s: %s differs: st1=%g st0=%g fl=%#llx  native sw=%#llx r0=%016llx  emu sw=%#llx r0=%016llx",
						 ops[o].nm, why, dx, dy, (unsigned long long)cn_get(&in, 40),
						 (unsigned long long)(cn_get(&a, 48) & 0xffff), (unsigned long long)ra,
						 (unsigned long long)(cn_get(&b, 48) & 0xffff), (unsigned long long)rb);
				}
			}
		}
		if (ops[o].memlen && bad != op_bad0)
			printf("      %s: %u of %u case(s) differ (%s)\n", ops[o].nm, bad - op_bad0, reps, opmsg);
	}
	printf("  %-22s %6u case(s), %u unsupported, %u differ\n", family, cases, unsup, bad);
	for (i = 0; i < nf; i++)
		printf("      %s\n", first[i]);
	CK(nothing == 0, "%s: the host ran every case", family);
	CK(unsup == 0, "%s: carried (%u refused)", family, unsup);
	CK(bad == 0, "%s equals the CPU (%u differ)", family, bad);
}

static void t_x87(void)
{
	static const struct x87_op arith[] = {
		{ "fadd st0,st1", { 0xd8, 0xc1 }, 2, 2, 0, 0, 0, 0, 0 },  { "fmul st0,st1", { 0xd8, 0xc9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fsub st0,st1", { 0xd8, 0xe1 }, 2, 2, 0, 0, 0, 0, 0 },  { "fsubr st0,st1", { 0xd8, 0xe9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fdiv st0,st1", { 0xd8, 0xf1 }, 2, 2, 0, 0, 0, 0, 0 },  { "fdivr st0,st1", { 0xd8, 0xf9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fadd st1,st0", { 0xdc, 0xc1 }, 2, 2, 0, 0, 0, 0, 0 },  { "fmul st1,st0", { 0xdc, 0xc9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fsub st1,st0 (dc e1)", { 0xdc, 0xe1 }, 2, 2, 0, 0, 0, 0, 0 }, { "dc e9", { 0xdc, 0xe9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "dc f1", { 0xdc, 0xf1 }, 2, 2, 0, 0, 0, 0, 0 },         { "dc f9", { 0xdc, 0xf9 }, 2, 2, 0, 0, 0, 0, 0 },
		{ "faddp", { 0xde, 0xc1 }, 2, 1, 0, 0, 0, 0, 0 },         { "fmulp", { 0xde, 0xc9 }, 2, 1, 0, 0, 0, 0, 0 },
		{ "de e1", { 0xde, 0xe1 }, 2, 1, 0, 0, 0, 0, 0 },         { "de e9", { 0xde, 0xe9 }, 2, 1, 0, 0, 0, 0, 0 },
		{ "de f1", { 0xde, 0xf1 }, 2, 1, 0, 0, 0, 0, 0 },         { "de f9", { 0xde, 0xf9 }, 2, 1, 0, 0, 0, 0, 0 },
		{ "fadd m64", { 0xdc, 0x06 }, 2, 2, 0, 0, 0, 0, 0 },      { "fmul m64", { 0xdc, 0x0e }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fsub m64", { 0xdc, 0x26 }, 2, 2, 0, 0, 0, 0, 0 },      { "fsubr m64", { 0xdc, 0x2e }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fdiv m64", { 0xdc, 0x36 }, 2, 2, 0, 0, 0, 0, 0 },      { "fdivr m64", { 0xdc, 0x3e }, 2, 2, 0, 0, 0, 0, 0 },
		{ "fxch st1", { 0xd9, 0xc9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fchs", { 0xd9, 0xe0 }, 2, 2, 0, 0, 1, 0, 0 },          { "fabs", { 0xd9, 0xe1 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fsqrt", { 0xd9, 0xfa }, 2, 2, 0, 0, 0, 0, 0 },         { "frndint", { 0xd9, 0xfc }, 2, 2, 0, 0, 1, 0, 0 }
	};
	static const struct x87_op cmp[] = {
		{ "fcom st1", { 0xd8, 0xd1 }, 2, 2, 1, 0, 1, 0, 0 },      { "fcomp st1", { 0xd8, 0xd9 }, 2, 1, 1, 0, 1, 0, 0 },
		{ "fcompp", { 0xde, 0xd9 }, 2, 0, 1, 0, 1, 0, 0 },        { "fucom st1", { 0xdd, 0xe1 }, 2, 2, 1, 0, 1, 0, 0 },
		{ "fucomp st1", { 0xdd, 0xe9 }, 2, 1, 1, 0, 1, 0, 0 },    { "fucompp", { 0xda, 0xe9 }, 2, 0, 1, 0, 1, 0, 0 },
		{ "ftst", { 0xd9, 0xe4 }, 2, 2, 1, 0, 1, 0, 0 },          { "fxam", { 0xd9, 0xe5 }, 2, 2, 1, 0, 1, 0, 0 },
		{ "fcomi st1", { 0xdb, 0xf1 }, 2, 2, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fucomi st1", { 0xdb, 0xe9 }, 2, 2, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fcomip st1", { 0xdf, 0xf1 }, 2, 1, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 },
		{ "fucomip st1", { 0xdf, 0xe9 }, 2, 1, 0, CN_FL_CF | CN_FL_PF | CN_FL_ZF, 1, 0, 0 }
	};
	static const struct x87_op cmov[] = {
		{ "fcmovb", { 0xda, 0xc1 }, 2, 2, 0, 0, 1, 0, 0 },  { "fcmove", { 0xda, 0xc9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fcmovbe", { 0xda, 0xd1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmovu", { 0xda, 0xd9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fcmovnb", { 0xdb, 0xc1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmovne", { 0xdb, 0xc9 }, 2, 2, 0, 0, 1, 0, 0 },
		{ "fcmovnbe", { 0xdb, 0xd1 }, 2, 2, 0, 0, 1, 0, 0 }, { "fcmovnu", { 0xdb, 0xd9 }, 2, 2, 0, 0, 1, 0, 0 }
	};

	static const struct x87_op misc[] = {
		{ "fld1", { 0xd9, 0xe8 }, 2, 1, 0, 0, 1, 0, 0 },    { "fldz", { 0xd9, 0xee }, 2, 1, 0, 0, 1, 0, 0 },
		{ "fldpi", { 0xd9, 0xeb }, 2, 1, 0, 0, 0, 0, 0 },   { "fldl2e", { 0xd9, 0xea }, 2, 1, 0, 0, 0, 0, 0 },
		{ "fldl2t", { 0xd9, 0xe9 }, 2, 1, 0, 0, 0, 0, 0 },  { "fldlg2", { 0xd9, 0xec }, 2, 1, 0, 0, 0, 0, 0 },
		{ "fldln2", { 0xd9, 0xed }, 2, 1, 0, 0, 0, 0, 0 },
		{ "fild m16", { 0xdf, 0x46, 0x20 }, 3, 1, 0, 0, 1, 0, 0 }, { "fild m32", { 0xdb, 0x46, 0x20 }, 3, 1, 0, 0, 1, 0, 0 },
		{ "fild m64", { 0xdf, 0x6e, 0x20 }, 3, 1, 0, 0, 1, 0, 0 },
		{ "fistp m16", { 0xdf, 0x5e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 }, { "fistp m32", { 0xdb, 0x5e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 },
		{ "fistp m64", { 0xdf, 0x7e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 }, { "fist m32", { 0xdb, 0x56, 0x30 }, 3, 2, 0, 0, 1, 0x30, 8 },
		{ "fisttp m16", { 0xdf, 0x4e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 }, { "fisttp m32", { 0xdb, 0x4e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 },
		{ "fisttp m64", { 0xdd, 0x4e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 8 },
		{ "fst m32", { 0xd9, 0x56, 0x30 }, 3, 2, 0, 0, 1, 0x30, 4 }, { "fstp m32", { 0xd9, 0x5e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 4 },
		{ "fst m64", { 0xdd, 0x56, 0x30 }, 3, 2, 0, 0, 1, 0x30, 8 },
		{ "fstp m80", { 0xdb, 0x7e, 0x30 }, 3, 1, 0, 0, 1, 0x30, 10 },
		{ "fxch+fnstsw", { 0xd9, 0xc9, 0xd9, 0xc9 }, 4, 2, 1, 0, 1, 0, 0 }
	};

	run_x87("x87 arithmetic", arith, sizeof arith / sizeof arith[0], 60);
	run_x87("x87 compares", cmp, sizeof cmp / sizeof cmp[0], 120);
	run_x87("x87 fcmov", cmov, sizeof cmov / sizeof cmov[0], 80);
	run_x87("x87 loads and stores", misc, sizeof misc / sizeof misc[0], 80);
}

/*
 * GetPC and the save areas: FNSTENV and FXSAVE report the address of the last x87 instruction, which is how a
 * position independent stub learns where it is (`fldz; fnstenv [esp-12]; pop eax`), and the rest of the state
 * - the control word, the status word with TOP, the tag word, FOP, the register stack, MXCSR and the xmm
 * registers - which a stub that saves and restores or compares it reads. Each is checked against the host's
 * own, after `fninit; fldz`, field by field. What is not compared and why: FCS and FDS (zero on CPUs that
 * deprecate them, a selector on the others), FDP (a host address), the exception flags of the status word
 * (the interpreter keeps every exception masked and does not accumulate them) and MXCSR_MASK (CPU model).
 */
static void t_getpc(void)
{
	static const struct { const char *nm; uint8_t b[16]; unsigned n; unsigned off, w; int fx; } f[] = {
		{ "fnstenv", { 0xdb, 0xe3, 0xd9, 0xee, 0xd9, 0xb6, 0x00, 0x01, 0x00, 0x00 }, 10, 12, 4, 0 },
		{ "fxsave", { 0xdb, 0xe3, 0xd9, 0xee, 0x0f, 0xae, 0x86, 0x00, 0x01, 0x00, 0x00 }, 11, 8, 4, 1 },
		{ "fxsave64", { 0xdb, 0xe3, 0xd9, 0xee, 0x48, 0x0f, 0xae, 0x86, 0x00, 0x01, 0x00, 0x00 }, 12, 8, 8, 1 }
	};
	unsigned k;

	for (k = 0; k < 3; k++) {
		struct cn_io in, a, b;
		struct cn_emu r;
		uint64_t ea = 0, eb = 0, want_emu;
		const uint8_t *ha, *hb;
		unsigned i;

		cn_input(&in, 0);
		xmm_in(&in, 0);
		cn_put(&in, CN_O_RSI, CN_O_BUF);
		if (!cn_native(f[k].b, f[k].n, &in, &a)) {
			CK(0, "%s: the host ran it", f[k].nm);
			continue;
		}
		CK(cn_emulate(f[k].b, f[k].n, &in, &b, 64, &r) && r.done, "%s: the interpreter ran it (%s)", f[k].nm, r.detail);
		ha = a.raw + CN_O_BUF + 0x100;
		hb = b.raw + CN_O_BUF + 0x100;
		memcpy(&ea, ha + f[k].off, f[k].w);
		memcpy(&eb, hb + f[k].off, f[k].w);
		want_emu = CN_CODE + cn_pre_len + 2u;       /* the FLDZ, after the FNINIT */
		if (f[k].w == 4)
			want_emu &= 0xffffffffull;
		CK(eb == want_emu, "%s: FIP is the address of the FLDZ, %#llx (got %#llx)", f[k].nm, (unsigned long long)want_emu,
		   (unsigned long long)eb);
		/* and it is the same position in the host's frame */
		{
			uint64_t want_host = (uint64_t)(uintptr_t)cn_page + cn_pre_len + 2u;

			if (f[k].w == 4)
				want_host &= 0xffffffffull;
			CK(ea == want_host, "%s: the host reports the same instruction (%#llx vs %#llx)", f[k].nm,
			   (unsigned long long)ea, (unsigned long long)want_host);
		}
		if (!f[k].fx) {
			/* the 28 byte environment: FCW @0, FSW @4, FTW @8, FOP in bits 16-26 of the dword @16 */
			CK(!memcmp(ha, hb, 2), "%s: control word equals the host's (%02x%02x vs %02x%02x)", f[k].nm, hb[1], hb[0], ha[1], ha[0]);
			CK(!memcmp(ha + 4, hb + 4, 2), "%s: status word (TOP) equals the host's (%02x%02x vs %02x%02x)", f[k].nm,
			   hb[5], hb[4], ha[5], ha[4]);
			CK(!memcmp(ha + 8, hb + 8, 2), "%s: tag word equals the host's (%02x%02x vs %02x%02x)", f[k].nm, hb[9], hb[8], ha[9], ha[8]);
			if (ha[18] | ha[17])
				CK(!memcmp(ha + 17, hb + 17, 2), "%s: FOP equals the host's", f[k].nm);
		} else {
			uint32_t mxa, mxb;

			CK(!memcmp(ha, hb, 2), "%s: control word equals the host's (%02x%02x vs %02x%02x)", f[k].nm, hb[1], hb[0], ha[1], ha[0]);
			CK(!memcmp(ha + 2, hb + 2, 2), "%s: status word (TOP) equals the host's (%02x%02x vs %02x%02x)", f[k].nm,
			   hb[3], hb[2], ha[3], ha[2]);
			CK(ha[4] == hb[4], "%s: the abridged tag word equals the host's (%02x vs %02x)", f[k].nm, hb[4], ha[4]);
			if (ha[6] | ha[7])
				CK(!memcmp(ha + 6, hb + 6, 2), "%s: FOP equals the host's", f[k].nm);
			memcpy(&mxa, ha + 24, 4);
			memcpy(&mxb, hb + 24, 4);
			CK((mxa & 0xffc0u) == (mxb & 0xffc0u), "%s: MXCSR control bits equal the host's (%#x vs %#x)", f[k].nm, mxb, mxa);
			memcpy(&mxb, hb + 28, 4);
			CK(mxb == 0xffffu, "%s: MXCSR_MASK is 0xffff (%#x)", f[k].nm, mxb);
			for (i = 0; i < 80u; i++)
				CK(ha[32 + i] == hb[32 + i] || i >= 10u * 8u, "%s: ST0 byte %u equals the host's", f[k].nm, i);
			CK(!memcmp(ha + 160, hb + 160, 32), "%s: xmm0 and xmm1 equal the host's", f[k].nm);
		}
	}
}

int main(void)
{
	cn_rng_state = 0x56454353494d4421ull;
	if (!CN_HOST) {
		printf("cov_emu_vec: SKIPPED (the host is not x86-64 Linux, so there is no reference to run)\n");
		return 0;
	}
	t_sse_logic();
	t_sse_arith();
	t_sse_compare();
	t_sse_convert();
	t_sse_moves();
	t_x87();
	t_getpc();
	if (fails) {
		printf("cov_emu_vec: FAILED (%d)\n", fails);
		return 1;
	}
	printf("cov_emu_vec: ok\n");
	return 0;
}
