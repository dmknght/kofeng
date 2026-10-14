/*
 * diff_vec_packed - the interpreter's packed SSE / MMX instructions against the host CPU. It extends diff_sse_x87.c
 * (which holds the scalar floating point, the x87 and the first vector moves) to the packed integer set, the packed
 * floating point set, the conversions and the SSE4/AES/CLMUL forms, with the same method: every case is run natively
 * and in the interpreter inside the frame of cov_native.h, and the 128 bit (or MMX) results, the general registers
 * and the flags the architecture defines are compared byte for byte.
 *
 *   packed integer   MMX and SSE2 forms of the add/sub/saturating/multiply/compare/min/max/average families, SAD, the
 *                    packs and the unpacks, the shifts by a register and by an immediate (every count that matters:
 *                    0, one less than the lane, the lane width, past it), PSHUFW/LW/HW, PSHUFB, PALIGNR, the SSSE3
 *                    horizontal and sign and abs forms, the SSE4.1 min/max/mul/blend/move-extend forms, PEXTR and
 *                    PINSR, PTEST, PCMPEQQ/GTQ, PCLMULQDQ, AES. Register source and memory source.
 *   packed float     ADD SUB MUL DIV MIN MAX SQRT for four floats and two doubles, over the pool of operands that break
 *                    floating point (zeros of both signs, ties, denormals, the largest, infinities, quiet and signalling
 *                    NaNs) - every ordered pair - and under each of the four MXCSR rounding modes (MXCSR is loaded
 *                    with LDMXCSR before the instruction and restored after it, on both sides). The scalar MIN/MAX/SQRT
 *                    of the single forms, CMPxx with every predicate, HADD/HSUB/ADDSUB, SHUFPx, UNPCKxPx, MOVSHDUP,
 *                    MOVSLDUP, MOVDDUP, BLENDx, BLENDVx, ROUNDxx, MOVMSKPx.
 *   conversions      CVTDQ2PS/PD, CVT(T)PS2DQ, CVT(T)PD2DQ, CVTPS2PD, CVTPD2PS, CVTSD2SI, CVTSS2SI, CVTSI2SD/SS under
 *                    each rounding mode, CVTPI2PS/PD and CVT(T)PS2PI/PD2PI through MMX registers.
 *
 * NOT COMPARED, because the interpreter does not model it (emu_vec_fp.c says so): the sticky exception flags of MXCSR,
 * DAZ and FTZ. Everything else an instruction defines is. Skipped, visibly, on a host that is not x86-64 Linux, and the
 * group that needs an instruction set the host does not have (CPUID) is skipped by name. Nothing here writes a file.
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

#define XM_ALL 0xffffffffu
#define BUF_A (CN_O_BUF + 0x40u)      /* the memory source operand, 16-byte aligned */
#define BUF_MM (CN_O_BUF + 0x200u)    /* where an MMX result is stored */

/* ---- operands ------------------------------------------------------------------------------ */

/* 16 bytes whose lanes are often at the edge of their width: 1, 2, 4 or 8 byte lanes of 0, 1, max, min, sign-1, ... */
static void edge_bytes(uint8_t *b)
{
	static const uint64_t e[] = { 0, 1, 0xff, 0x7f, 0x80, 0xffff, 0x7fff, 0x8000, 0x0100, 0xff00, 0xffffffffull, 0x7fffffffull,
				      0x80000000ull, 0x00010000ull, 0xffff0000ull, 0x4000, 0xc000 };
	unsigned w = 1u << (cn_rng() & 3u), k, i;

	for (k = 0; k < 16; k += w) {
		uint64_t v = (cn_rng() % 3u) ? e[cn_rng() % (sizeof e / sizeof e[0])] : cn_rng();

		for (i = 0; i < w; i++)
			b[k + i] = (uint8_t)(v >> (8u * i));
	}
}

static void put_xmm(struct cn_io *in, const uint8_t *a, const uint8_t *b)
{
	memcpy(in->raw + CN_O_XMM, a, 16);
	memcpy(in->raw + CN_O_XMM + 16, b, 16);
}

/* ---- the code of one case --------------------------------------------------------------------- */

struct code {
	uint8_t b[96];
	unsigned n;
};

static void emit(struct code *c, const void *p, unsigned n)
{
	memcpy(c->b + c->n, p, n);
	c->n += n;
}

/* the xmm form: [prefix] [REX.W] 0F [38|3A] opcode modrm [imm]; modrm 0xC1 is xmm0,xmm1 and 0x06 is xmm0,[rsi] */
static void xmm_op(struct code *c, unsigned pfx, unsigned rexw, unsigned map, unsigned opc, unsigned modrm, int imm)
{
	c->n = 0;
	if (pfx)
		c->b[c->n++] = (uint8_t)pfx;
	if (rexw)
		c->b[c->n++] = 0x48;
	c->b[c->n++] = 0x0f;
	if (map == 2)
		c->b[c->n++] = 0x38;
	if (map == 3)
		c->b[c->n++] = 0x3a;
	c->b[c->n++] = (uint8_t)opc;
	c->b[c->n++] = (uint8_t)modrm;
	if (imm >= 0)
		c->b[c->n++] = (uint8_t)imm;
}

/*
 * the MMX form: load mm0 and mm1 from the input block, run the instruction, store both and EMMS. mm0 and mm1 are
 * loaded from the xmm0/xmm1 input slots, the results land in the buffer (BUF_MM), which the case compares.
 */
static void mmx_op(struct code *c, unsigned rexw, unsigned map, unsigned opc, unsigned modrm, int imm)
{
	static const uint8_t ld[] = { 0x0f, 0x6f, 0x87, 0x00, 0x01, 0, 0,        /* movq mm0, [rdi+0x100] */
				      0x0f, 0x6f, 0x8f, 0x10, 0x01, 0, 0 };      /* movq mm1, [rdi+0x110] */
	static const uint8_t stv[] = { 0x0f, 0x7f, 0x87, 0x00, 0x03, 0, 0,       /* movq [rdi+BUF_MM-0x400+0x400..], mm0 */
				       0x0f, 0x7f, 0x8f, 0x08, 0x03, 0, 0,
				       0x0f, 0x77 };                              /* emms */
	uint8_t s[sizeof stv];

	memcpy(s, stv, sizeof s);
	s[3] = (uint8_t)(BUF_MM & 0xffu);
	s[4] = (uint8_t)(BUF_MM >> 8);
	s[10] = (uint8_t)((BUF_MM + 8u) & 0xffu);
	s[11] = (uint8_t)((BUF_MM + 8u) >> 8);
	c->n = 0;
	emit(c, ld, sizeof ld);
	if (rexw)
		c->b[c->n++] = 0x48;
	c->b[c->n++] = 0x0f;
	if (map == 2)
		c->b[c->n++] = 0x38;
	if (map == 3)
		c->b[c->n++] = 0x3a;
	c->b[c->n++] = (uint8_t)opc;
	c->b[c->n++] = (uint8_t)modrm;
	if (imm >= 0)
		c->b[c->n++] = (uint8_t)imm;
	emit(c, s, sizeof s);
}

/* wrap `op` in LDMXCSR [rdi+0x3f0] ... LDMXCSR [rdi+0x3f8] so the instruction runs under a chosen MXCSR */
static void with_mxcsr(struct code *c, const struct code *op)
{
	static const uint8_t set[] = { 0x0f, 0xae, 0x97, 0xf0, 0x03, 0, 0 }, clr[] = { 0x0f, 0xae, 0x97, 0xf8, 0x03, 0, 0 };

	c->n = 0;
	emit(c, set, sizeof set);
	emit(c, op->b, op->n);
	emit(c, clr, sizeof clr);
}

static void set_mxcsr(struct cn_io *in, unsigned rc)
{
	uint32_t v = 0x1f80u | (rc << 13), d = 0x1f80u;

	memcpy(in->raw + 0x3f0, &v, 4);
	memcpy(in->raw + 0x3f8, &d, 4);
}

static void run(const char *nm, const struct code *c, const struct cn_io *in, unsigned xmask, int cmpbuf)
{
	(void)cn_case(&st, nm, c->b, c->n, in, 0, 64, xmask, cmpbuf);
}

/* ---- packed integer --------------------------------------------------------------------------- */

struct pint {
	const char *nm;
	uint8_t pfx;        /* 0x66 for the xmm form of an 0F-map opcode */
	uint8_t map;        /* 1 (0F), 2 (0F38), 3 (0F3A) */
	uint8_t opc;
	uint8_t has_mm;     /* an MMX form exists */
	uint8_t has_xmm;
	int8_t imm;         /* -1 none, 1: a random immediate byte */
};

static const struct pint PINT[] = {
	{ "paddb", 0x66, 1, 0xfc, 1, 1, -1 }, { "paddw", 0x66, 1, 0xfd, 1, 1, -1 }, { "paddd", 0x66, 1, 0xfe, 1, 1, -1 },
	{ "paddq", 0x66, 1, 0xd4, 1, 1, -1 }, { "psubw", 0x66, 1, 0xf9, 1, 1, -1 }, { "psubd", 0x66, 1, 0xfa, 1, 1, -1 },
	{ "psubq", 0x66, 1, 0xfb, 1, 1, -1 }, { "psubb", 0x66, 1, 0xf8, 1, 1, -1 },
	{ "paddsb", 0x66, 1, 0xec, 1, 1, -1 }, { "paddsw", 0x66, 1, 0xed, 1, 1, -1 }, { "paddusb", 0x66, 1, 0xdc, 1, 1, -1 },
	{ "paddusw", 0x66, 1, 0xdd, 1, 1, -1 }, { "psubsb", 0x66, 1, 0xe8, 1, 1, -1 }, { "psubsw", 0x66, 1, 0xe9, 1, 1, -1 },
	{ "psubusb", 0x66, 1, 0xd8, 1, 1, -1 }, { "psubusw", 0x66, 1, 0xd9, 1, 1, -1 }, { "pmullw", 0x66, 1, 0xd5, 1, 1, -1 },
	{ "pmulhw", 0x66, 1, 0xe5, 1, 1, -1 }, { "pmulhuw", 0x66, 1, 0xe4, 1, 1, -1 }, { "pmuludq", 0x66, 1, 0xf4, 1, 1, -1 },
	{ "pmaddwd", 0x66, 1, 0xf5, 1, 1, -1 }, { "pcmpeqb", 0x66, 1, 0x74, 1, 1, -1 }, { "pcmpeqw", 0x66, 1, 0x75, 1, 1, -1 },
	{ "pcmpeqd", 0x66, 1, 0x76, 1, 1, -1 }, { "pcmpgtb", 0x66, 1, 0x64, 1, 1, -1 }, { "pcmpgtw", 0x66, 1, 0x65, 1, 1, -1 },
	{ "pcmpgtd", 0x66, 1, 0x66, 1, 1, -1 }, { "pminub", 0x66, 1, 0xda, 1, 1, -1 }, { "pmaxub", 0x66, 1, 0xde, 1, 1, -1 },
	{ "pminsw", 0x66, 1, 0xea, 1, 1, -1 }, { "pmaxsw", 0x66, 1, 0xee, 1, 1, -1 }, { "pavgb", 0x66, 1, 0xe0, 1, 1, -1 },
	{ "pavgw", 0x66, 1, 0xe3, 1, 1, -1 }, { "psadbw", 0x66, 1, 0xf6, 1, 1, -1 }, { "packsswb", 0x66, 1, 0x63, 1, 1, -1 },
	{ "packssdw", 0x66, 1, 0x6b, 1, 1, -1 }, { "packuswb", 0x66, 1, 0x67, 1, 1, -1 }, { "punpcklbw", 0x66, 1, 0x60, 1, 1, -1 },
	{ "punpcklwd", 0x66, 1, 0x61, 1, 1, -1 }, { "punpckldq", 0x66, 1, 0x62, 1, 1, -1 }, { "punpckhbw", 0x66, 1, 0x68, 1, 1, -1 },
	{ "punpckhwd", 0x66, 1, 0x69, 1, 1, -1 }, { "punpckhdq", 0x66, 1, 0x6a, 1, 1, -1 }, { "punpcklqdq", 0x66, 1, 0x6c, 0, 1, -1 },
	{ "punpckhqdq", 0x66, 1, 0x6d, 0, 1, -1 },
	{ "psrlw", 0x66, 1, 0xd1, 1, 1, -1 }, { "psrld", 0x66, 1, 0xd2, 1, 1, -1 }, { "psrlq", 0x66, 1, 0xd3, 1, 1, -1 },
	{ "psraw", 0x66, 1, 0xe1, 1, 1, -1 }, { "psrad", 0x66, 1, 0xe2, 1, 1, -1 }, { "psllw", 0x66, 1, 0xf1, 1, 1, -1 },
	{ "pslld", 0x66, 1, 0xf2, 1, 1, -1 }, { "psllq", 0x66, 1, 0xf3, 1, 1, -1 },
	/* SSSE3 */
	{ "pshufb", 0x66, 2, 0x00, 1, 1, -1 }, { "phaddw", 0x66, 2, 0x01, 1, 1, -1 }, { "phaddd", 0x66, 2, 0x02, 1, 1, -1 },
	{ "phaddsw", 0x66, 2, 0x03, 1, 1, -1 }, { "pmaddubsw", 0x66, 2, 0x04, 1, 1, -1 }, { "phsubw", 0x66, 2, 0x05, 1, 1, -1 },
	{ "phsubd", 0x66, 2, 0x06, 1, 1, -1 }, { "phsubsw", 0x66, 2, 0x07, 1, 1, -1 }, { "psignb", 0x66, 2, 0x08, 1, 1, -1 },
	{ "psignw", 0x66, 2, 0x09, 1, 1, -1 }, { "psignd", 0x66, 2, 0x0a, 1, 1, -1 }, { "pmulhrsw", 0x66, 2, 0x0b, 1, 1, -1 },
	{ "pabsb", 0x66, 2, 0x1c, 1, 1, -1 }, { "pabsw", 0x66, 2, 0x1d, 1, 1, -1 }, { "pabsd", 0x66, 2, 0x1e, 1, 1, -1 },
	{ "palignr", 0x66, 3, 0x0f, 1, 1, 1 },
	/* SSE4.1 / 4.2 */
	{ "pmovsxbw", 0x66, 2, 0x20, 0, 1, -1 }, { "pmovsxbd", 0x66, 2, 0x21, 0, 1, -1 }, { "pmovsxbq", 0x66, 2, 0x22, 0, 1, -1 },
	{ "pmovsxwd", 0x66, 2, 0x23, 0, 1, -1 }, { "pmovsxwq", 0x66, 2, 0x24, 0, 1, -1 }, { "pmovsxdq", 0x66, 2, 0x25, 0, 1, -1 },
	{ "pmovzxbw", 0x66, 2, 0x30, 0, 1, -1 }, { "pmovzxbd", 0x66, 2, 0x31, 0, 1, -1 }, { "pmovzxbq", 0x66, 2, 0x32, 0, 1, -1 },
	{ "pmovzxwd", 0x66, 2, 0x33, 0, 1, -1 }, { "pmovzxwq", 0x66, 2, 0x34, 0, 1, -1 }, { "pmovzxdq", 0x66, 2, 0x35, 0, 1, -1 },
	{ "pmuldq", 0x66, 2, 0x28, 0, 1, -1 }, { "pcmpeqq", 0x66, 2, 0x29, 0, 1, -1 }, { "packusdw", 0x66, 2, 0x2b, 0, 1, -1 },
	{ "pcmpgtq", 0x66, 2, 0x37, 0, 1, -1 }, { "pminsb", 0x66, 2, 0x38, 0, 1, -1 }, { "pminsd", 0x66, 2, 0x39, 0, 1, -1 },
	{ "pminuw", 0x66, 2, 0x3a, 0, 1, -1 }, { "pminud", 0x66, 2, 0x3b, 0, 1, -1 }, { "pmaxsb", 0x66, 2, 0x3c, 0, 1, -1 },
	{ "pmaxsd", 0x66, 2, 0x3d, 0, 1, -1 }, { "pmaxuw", 0x66, 2, 0x3e, 0, 1, -1 }, { "pmaxud", 0x66, 2, 0x3f, 0, 1, -1 },
	{ "pmulld", 0x66, 2, 0x40, 0, 1, -1 }, { "pblendw", 0x66, 3, 0x0e, 0, 1, 1 }, { "pblendvb", 0x66, 2, 0x10, 0, 1, -1 },
	{ "pclmulqdq", 0x66, 3, 0x44, 0, 1, 1 }
};

/* The shift counts that matter for a lane of `w` bits: 0, 1, w-1, w, w+1, 63, 64, 255 and the register form's whole qword. */
static const unsigned CNT[] = { 0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255 };

static void t_pint(void)
{
	unsigned o, i, form;

	for (o = 0; o < sizeof PINT / sizeof PINT[0]; o++) {
		const struct pint *p = &PINT[o];

		for (form = 0; form < 4; form++) {                     /* 0 xmm reg, 1 xmm mem, 2 mm reg, 3 mm mem */
			if ((form < 2 && !p->has_xmm) || (form >= 2 && !p->has_mm))
				continue;
			for (i = 0; i < 160; i++) {
				struct cn_io in;
				struct code c;
				uint8_t a[16], b[16];
				const int imm = p->imm < 0 ? -1 : (int)(cn_rng() & 0xffu);

				cn_input(&in, 0);
				cn_fill_buf(&in, 0);
				edge_bytes(a);
				edge_bytes(b);
				/* a shift's count is the low qword of the source: often small, sometimes the lane width */
				if (p->map == 1 && (p->opc == 0xd1 || p->opc == 0xd2 || p->opc == 0xd3 || p->opc == 0xe1 ||
						    p->opc == 0xe2 || p->opc == 0xf1 || p->opc == 0xf2 || p->opc == 0xf3) && (cn_rng() & 3u)) {
					memset(b, 0, 16);
					b[0] = (uint8_t)CNT[cn_rng() % (sizeof CNT / sizeof CNT[0])];
					if (!(cn_rng() & 7u))
						b[1 + (cn_rng() & 6u)] = 1;
				}
				put_xmm(&in, a, b);
				memcpy(in.raw + BUF_A, b, 16);
				cn_put(&in, CN_O_RSI, BUF_A);
				if (form < 2)
					xmm_op(&c, p->pfx, 0, p->map, p->opc, form ? 0x06u : 0xc1u, imm);
				else
					mmx_op(&c, 0, p->map, p->opc, form == 3 ? 0x06u : 0xc1u, imm);
				run(p->nm, &c, &in, form < 2 ? XM_ALL : 0u, form >= 2);
			}
		}
	}
	finish("packed integer");
}

/* the shifts by an immediate: 0F 71/72/73 /ext ib on xmm0 and mm0 */
static void t_pshift_imm(void)
{
	static const struct { const char *nm; uint8_t opc, ext; } s[] = {
		{ "psrlw ib", 0x71, 2 }, { "psraw ib", 0x71, 4 }, { "psllw ib", 0x71, 6 }, { "psrld ib", 0x72, 2 },
		{ "psrad ib", 0x72, 4 }, { "pslld ib", 0x72, 6 }, { "psrlq ib", 0x73, 2 }, { "psllq ib", 0x73, 6 }
	};
	unsigned o, i, mm;

	for (o = 0; o < sizeof s / sizeof s[0]; o++)
		for (mm = 0; mm < 2; mm++)
			for (i = 0; i < sizeof CNT / sizeof CNT[0] * 4u; i++) {
				struct cn_io in;
				struct code c;
				uint8_t a[16], b[16];
				const int imm = (int)CNT[i % (sizeof CNT / sizeof CNT[0])];

				cn_input(&in, 0);
				cn_fill_buf(&in, 0);
				edge_bytes(a);
				edge_bytes(b);
				put_xmm(&in, a, b);
				if (mm)
					mmx_op(&c, 0, 1, s[o].opc, 0xc0u | (unsigned)(s[o].ext << 3), imm);
				else
					xmm_op(&c, 0x66, 0, 1, s[o].opc, 0xc0u | (unsigned)(s[o].ext << 3), imm);
				run(s[o].nm, &c, &in, mm ? 0u : XM_ALL, (int)mm);
			}
	finish("packed shifts by an immediate");
}

/* PSHUFW (MMX), PSHUFLW, PSHUFHW: every immediate */
static void t_pshuf(void)
{
	unsigned i, k;

	for (i = 0; i < 256; i++)
		for (k = 0; k < 3; k++) {
			struct cn_io in;
			struct code c;
			uint8_t a[16], b[16];

			cn_input(&in, 0);
			cn_fill_buf(&in, 0);
			edge_bytes(a);
			edge_bytes(b);
			put_xmm(&in, a, b);
			if (k == 0) {
				mmx_op(&c, 0, 1, 0x70, 0xc1, (int)i);
				run("pshufw", &c, &in, 0u, 1);
			} else {
				xmm_op(&c, k == 1 ? 0xf2u : 0xf3u, 0, 1, 0x70, 0xc1, (int)i);
				run(k == 1 ? "pshuflw" : "pshufhw", &c, &in, XM_ALL, 0);
			}
		}
	finish("pshufw / pshuflw / pshufhw");
}

/* PEXTRB/D/Q, PINSRB/D/Q, PTEST, MASKMOVDQU */
static void t_pint_misc(void)
{
	unsigned i, k;

	for (i = 0; i < 16u * 16u; i++)
		for (k = 0; k < 6; k++) {
			struct cn_io in;
			struct code c;
			uint8_t a[16], b[16];
			const unsigned lane = i & 15u;

			cn_input(&in, 0);
			cn_fill_buf(&in, 0);
			edge_bytes(a);
			edge_bytes(b);
			put_xmm(&in, a, b);
			switch (k) {
			case 0: xmm_op(&c, 0x66, 0, 3, 0x14, 0xc8, (int)lane); run("pextrb", &c, &in, XM_ALL, 0); break;
			case 1: xmm_op(&c, 0x66, 0, 3, 0x16, 0xc8, (int)lane); run("pextrd", &c, &in, XM_ALL, 0); break;
			case 2: xmm_op(&c, 0x66, 1, 3, 0x16, 0xc8, (int)lane); run("pextrq", &c, &in, XM_ALL, 0); break;
			case 3: xmm_op(&c, 0x66, 0, 3, 0x20, 0xc1, (int)lane); run("pinsrb xmm0,ecx", &c, &in, XM_ALL, 0); break;
			case 4: xmm_op(&c, 0x66, 0, 3, 0x22, 0xc1, (int)lane); run("pinsrd xmm0,ecx", &c, &in, XM_ALL, 0); break;
			default: xmm_op(&c, 0x66, 1, 3, 0x22, 0xc1, (int)lane); run("pinsrq xmm0,rcx", &c, &in, XM_ALL, 0); break;
			}
		}
	for (i = 0; i < 400; i++) {                                    /* ptest: ZF and CF, the other flags cleared */
		struct cn_io in;
		struct code c;
		uint8_t a[16], b[16];

		cn_input(&in, 0);
		edge_bytes(a);
		if (i & 1u)
			memcpy(b, a, 16);
		else
			edge_bytes(b);
		if (i & 2u) {
			unsigned q;

			for (q = 0; q < 16; q++)
				b[q] &= a[q];
		}
		put_xmm(&in, a, b);
		xmm_op(&c, 0x66, 0, 2, 0x17, 0xc1, -1);
		(void)cn_case(&st, "ptest", c.b, c.n, &in, CN_FL_ARITH, 64, XM_ALL, 0);
	}
	finish("pextr / pinsr / ptest");
}

/* AES: every byte value through the S-boxes (a state of 16 distinct bytes, shifted), every round function */
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

static void t_aes(void)
{
	static const struct { const char *nm; uint8_t opc; int imm; } s[] = {
		{ "aesenc", 0xdc, -1 }, { "aesenclast", 0xdd, -1 }, { "aesdec", 0xde, -1 }, { "aesdeclast", 0xdf, -1 },
		{ "aesimc", 0xdb, -1 }
	};
	unsigned o, i;

	if (!host_has(1, 1, 25)) {
		printf("  aes: SKIPPED (the host has no AES-NI)\n");
		return;
	}
	for (o = 0; o < sizeof s / sizeof s[0]; o++)
		for (i = 0; i < 256; i++) {
			struct cn_io in;
			struct code c;
			uint8_t a[16], b[16];
			unsigned k;

			cn_input(&in, 0);
			for (k = 0; k < 16; k++) {
				a[k] = (uint8_t)(i + k * 17u);
				b[k] = (uint8_t)cn_rng();
			}
			put_xmm(&in, a, b);
			xmm_op(&c, 0x66, 0, 2, s[o].opc, 0xc1, -1);
			run(s[o].nm, &c, &in, XM_ALL, 0);
		}
	for (i = 0; i < 256; i++) {                                     /* AESKEYGENASSIST, every round constant */
		struct cn_io in;
		struct code c;
		uint8_t a[16], b[16];

		cn_input(&in, 0);
		edge_bytes(a);
		edge_bytes(b);
		put_xmm(&in, a, b);
		xmm_op(&c, 0x66, 0, 3, 0xdf, 0xc1, (int)i);
		run("aeskeygenassist", &c, &in, XM_ALL, 0);
	}
	finish("aes");
}

/* ---- packed floating point ------------------------------------------------------------------ */

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
	case 0:  return 0x7ff0000000000000ull;
	case 1:  return 0xfff0000000000000ull;
	case 2:  return 0x7ff8000000000000ull;
	case 3:  return 0x7ff4000000000001ull;
	default: return 0xfff8000000000123ull;
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
				      0xffffffff80000000ull, 0xfffffffffffff800ull, 0x7fffffc0ull, 0xfffffff0ull };

	return v[i % (sizeof v / sizeof v[0])];
}

/* four floats / two doubles, lane 0 and lane 1 from the pool, the rest random pool values */
static void fill_f(uint8_t *a, unsigned i0, unsigned i1)
{
	uint32_t f[4];
	unsigned k;

	f[0] = fp_(i0);
	f[1] = fp_(i1);
	for (k = 2; k < 4; k++)
		f[k] = fp_((unsigned)(cn_rng() % NF));
	memcpy(a, f, 16);
}

static void fill_d(uint8_t *a, unsigned i0)
{
	uint64_t d[2];

	d[0] = dp(i0);
	d[1] = dp((unsigned)(cn_rng() % ND));
	memcpy(a, d, 16);
}

struct pfp {
	const char *nm;
	uint8_t pfx, opc;
};

/* packed single (no prefix), packed double (66), and the scalar forms the scalar test lacks (F3 / F2) */
static const struct pfp PFP[] = {
	{ "addps", 0, 0x58 }, { "addpd", 0x66, 0x58 }, { "subps", 0, 0x5c }, { "subpd", 0x66, 0x5c },
	{ "mulps", 0, 0x59 }, { "mulpd", 0x66, 0x59 }, { "divps", 0, 0x5e }, { "divpd", 0x66, 0x5e },
	{ "minps", 0, 0x5d }, { "minpd", 0x66, 0x5d }, { "maxps", 0, 0x5f }, { "maxpd", 0x66, 0x5f },
	{ "sqrtps", 0, 0x51 }, { "sqrtpd", 0x66, 0x51 },
	{ "minss", 0xf3, 0x5d }, { "maxss", 0xf3, 0x5f }, { "sqrtss", 0xf3, 0x51 }
};

static int is_dbl(const struct pfp *p)
{
	return p->pfx == 0x66;
}

static void t_pfp(void)
{
	unsigned o, i, j, rc, memform;

	for (o = 0; o < sizeof PFP / sizeof PFP[0]; o++) {
		const struct pfp *p = &PFP[o];
		const int dbl = is_dbl(p);
		/* the rounding modes: the arithmetic ones are rounding-sensitive; MIN/MAX are not, so one mode does */
		const unsigned nrc = (p->opc == 0x5d || p->opc == 0x5f) ? 1u : 4u;

		for (rc = 0; rc < nrc; rc++)
			for (i = 0; i < (dbl ? ND : NF); i++)
				for (j = 0; j < (dbl ? ND : NF); j++) {
					struct cn_io in;
					struct code op, c;
					uint8_t a[16], b[16];

					memform = (i + j) & 1u;
					cn_input(&in, 0);
					if (dbl) {
						fill_d(a, i);
						fill_d(b, j);
					} else {
						fill_f(a, i, i);
						fill_f(b, j, j);
					}
					put_xmm(&in, a, b);
					memcpy(in.raw + BUF_A, b, 16);
					cn_put(&in, CN_O_RSI, BUF_A);
					set_mxcsr(&in, rc);
					xmm_op(&op, p->pfx, 0, 1, p->opc, memform ? 0x06u : 0xc1u, -1);
					with_mxcsr(&c, &op);
					run(p->nm, &c, &in, XM_ALL, 0);
				}
	}
	finish("packed arithmetic under every MXCSR rounding mode");
}

/* CMPPS/PD/SS/SD with every predicate, over the pool */
static void t_cmp(void)
{
	static const struct { const char *nm; uint8_t pfx; } k[] = { { "cmpps", 0 }, { "cmppd", 0x66 }, { "cmpss", 0xf3 }, { "cmpsd", 0xf2 } };
	unsigned o, pr, i, j;

	for (o = 0; o < 4; o++)
		for (pr = 0; pr < 8; pr++)
			for (i = 0; i < (o & 1u ? ND : NF); i++)
				for (j = 0; j < (o & 1u ? ND : NF); j++) {
					struct cn_io in;
					struct code c;
					uint8_t a[16], b[16];
					const int dbl = o == 1 || o == 3;

					if ((i + j) % 3u)
						continue;       /* a third of the pairs per predicate: every pair is met under some predicate */
					cn_input(&in, 0);
					if (dbl) {
						fill_d(a, i);
						fill_d(b, j);
					} else {
						fill_f(a, i, i);
						fill_f(b, j, j);
					}
					put_xmm(&in, a, b);
					xmm_op(&c, k[o].pfx, 0, 1, 0xc2, 0xc1, (int)pr);
					run(k[o].nm, &c, &in, XM_ALL, 0);
				}
	finish("cmpps / cmppd / cmpss / cmpsd");
}

/* shuffles, horizontal ops, blends, rounding, movmsk */
static void t_pfp_misc(void)
{
	static const struct { const char *nm; uint8_t pfx, map, opc; int imm; } s[] = {
		{ "haddps", 0xf2, 1, 0x7c, -1 }, { "haddpd", 0x66, 1, 0x7c, -1 }, { "hsubps", 0xf2, 1, 0x7d, -1 },
		{ "hsubpd", 0x66, 1, 0x7d, -1 }, { "addsubps", 0xf2, 1, 0xd0, -1 }, { "addsubpd", 0x66, 1, 0xd0, -1 },
		{ "unpcklps", 0, 1, 0x14, -1 }, { "unpckhps", 0, 1, 0x15, -1 }, { "unpcklpd", 0x66, 1, 0x14, -1 },
		{ "unpckhpd", 0x66, 1, 0x15, -1 }, { "movshdup", 0xf3, 1, 0x16, -1 }, { "movsldup", 0xf3, 1, 0x12, -1 },
		{ "movddup", 0xf2, 1, 0x12, -1 }, { "shufps", 0, 1, 0xc6, 1 }, { "shufpd", 0x66, 1, 0xc6, 1 },
		{ "blendps", 0x66, 3, 0x0c, 1 }, { "blendpd", 0x66, 3, 0x0d, 1 }, { "blendvps", 0x66, 2, 0x14, -1 },
		{ "blendvpd", 0x66, 2, 0x15, -1 }, { "roundps", 0x66, 3, 0x08, 1 }, { "roundpd", 0x66, 3, 0x09, 1 },
		{ "roundss", 0x66, 3, 0x0a, 1 }, { "roundsd", 0x66, 3, 0x0b, 1 }
	};
	unsigned o, i, rc;

	for (o = 0; o < sizeof s / sizeof s[0]; o++)
		for (i = 0; i < 700; i++) {
			struct cn_io in;
			struct code c, op;
			uint8_t a[16], b[16];
			int imm = s[o].imm < 0 ? -1 : (int)(cn_rng() & 0xffu);
			const int dbl = strstr(s[o].nm, "pd") != NULL || strstr(s[o].nm, "sd") != NULL;
			const int round = s[o].opc >= 0x08 && s[o].opc <= 0x0b && s[o].map == 3;

			if (round)
				imm = (int)(cn_rng() & 15u);       /* modes 0-3, MXCSR (bit 2), and the precision-suppress bit */
			cn_input(&in, 0);
			if (dbl) {
				fill_d(a, (unsigned)(cn_rng() % ND));
				fill_d(b, (unsigned)(cn_rng() % ND));
			} else {
				fill_f(a, (unsigned)(cn_rng() % NF), (unsigned)(cn_rng() % NF));
				fill_f(b, (unsigned)(cn_rng() % NF), (unsigned)(cn_rng() % NF));
			}
			if (round && !(cn_rng() & 3u)) {                 /* values with a fraction: the rounding is visible */
				double v[2] = { (double)(int)(cn_rng() % 2001u) / 8.0 - 125.0, (double)(int)(cn_rng() % 2001u) / 4.0 - 250.0 };
				float f[4];

				if (s[o].opc == 0x08 || s[o].opc == 0x0a) {
					for (rc = 0; rc < 4; rc++)
						f[rc] = (float)((double)(int)(cn_rng() % 2001u) / 8.0 - 125.0);
					memcpy(b, f, 16);
				} else {
					memcpy(b, v, 16);
				}
			}
			put_xmm(&in, a, b);
			rc = (unsigned)(cn_rng() & 3u);
			set_mxcsr(&in, rc);
			xmm_op(&op, s[o].pfx, 0, s[o].map, s[o].opc, 0xc1, imm);
			with_mxcsr(&c, &op);
			run(s[o].nm, &c, &in, XM_ALL, 0);
		}
	for (i = 0; i < 64; i++) {                                     /* movmskps / movmskpd to eax */
		struct cn_io in;
		struct code c;
		uint8_t a[16], b[16];

		cn_input(&in, 0);
		fill_f(a, (unsigned)(cn_rng() % NF), (unsigned)(cn_rng() % NF));
		fill_f(b, (unsigned)(cn_rng() % NF), (unsigned)(cn_rng() % NF));
		put_xmm(&in, a, b);
		xmm_op(&c, i & 1u ? 0x66u : 0u, 0, 1, 0x50, 0xc1, -1);
		run(i & 1u ? "movmskpd" : "movmskps", &c, &in, XM_ALL, 0);
	}
	finish("shuffles, horizontal, blend, round, movmsk");
}

/* ---- conversions ---------------------------------------------------------------------------- */

static void t_cvt(void)
{
	struct cv {
		const char *nm;
		uint8_t pfx, opc;
		unsigned src;       /* 0 ints in rcx, 1 four ints, 2 four floats, 3 two doubles */
		unsigned mmx_src, mmx_dst, rexw;
	};
	static const struct cv s[] = {
		{ "cvtdq2ps", 0, 0x5b, 1, 0, 0, 0 }, { "cvtdq2pd", 0xf3, 0xe6, 1, 0, 0, 0 }, { "cvtps2dq", 0x66, 0x5b, 2, 0, 0, 0 },
		{ "cvttps2dq", 0xf3, 0x5b, 2, 0, 0, 0 }, { "cvtpd2dq", 0xf2, 0xe6, 3, 0, 0, 0 }, { "cvttpd2dq", 0x66, 0xe6, 3, 0, 0, 0 },
		{ "cvtps2pd", 0, 0x5a, 2, 0, 0, 0 }, { "cvtpd2ps", 0x66, 0x5a, 3, 0, 0, 0 },
		{ "cvtsd2si r32", 0xf2, 0x2d, 3, 0, 0, 0 }, { "cvtsd2si r64", 0xf2, 0x2d, 3, 0, 0, 1 },
		{ "cvtss2si r32", 0xf3, 0x2d, 2, 0, 0, 0 }, { "cvtss2si r64", 0xf3, 0x2d, 2, 0, 0, 1 },
		{ "cvtsi2sd r32", 0xf2, 0x2a, 0, 0, 0, 0 }, { "cvtsi2sd r64", 0xf2, 0x2a, 0, 0, 0, 1 },
		{ "cvtsi2ss r32", 0xf3, 0x2a, 0, 0, 0, 0 }, { "cvtsi2ss r64", 0xf3, 0x2a, 0, 0, 0, 1 },
		{ "cvtpi2ps", 0, 0x2a, 1, 1, 0, 0 }, { "cvtpi2pd", 0x66, 0x2a, 1, 1, 0, 0 },
		{ "cvtps2pi", 0, 0x2d, 2, 0, 1, 0 }, { "cvttps2pi", 0, 0x2c, 2, 0, 1, 0 },
		{ "cvtpd2pi", 0x66, 0x2d, 3, 0, 1, 0 }, { "cvttpd2pi", 0x66, 0x2c, 3, 0, 1, 0 }
	};
	unsigned o, i, rc, k;

	for (o = 0; o < sizeof s / sizeof s[0]; o++)
		for (rc = 0; rc < 4; rc++)
			for (i = 0; i < 90; i++) {
				struct cn_io in;
				struct code c, op;
				uint8_t a[16], b[16];
				uint32_t w[4];
				uint64_t d[2];

				cn_input(&in, 0);
				cn_fill_buf(&in, 0);
				edge_bytes(a);
				switch (s[o].src) {
				case 0:
					cn_put(&in, CN_O_RCX, ip((unsigned)(i + rc)));
					memcpy(b, a, 16);
					break;
				case 1:
					for (k = 0; k < 4; k++)
						w[k] = (uint32_t)ip((unsigned)(i + k * 3u + rc));
					memcpy(b, w, 16);
					break;
				case 2:
					for (k = 0; k < 4; k++)
						w[k] = fp_((unsigned)((i + k * 5u) % NF));
					if (i % 5u == 0) {                         /* values that round: x.5 and near ties */
						const float f[4] = { 2.5f, -3.5f, 8388609.0f, 0.49999997f };

						memcpy(w, f, 16);
					}
					memcpy(b, w, 16);
					break;
				default:
					for (k = 0; k < 2; k++)
						d[k] = dp((unsigned)((i + k * 7u) % ND));
					if (i % 5u == 0) {
						const double dd[2] = { -2.5, 4503599627370497.5 };

						memcpy(d, dd, 16);
					}
					memcpy(b, d, 16);
					break;
				}
				put_xmm(&in, a, b);
				set_mxcsr(&in, rc);
				if (s[o].mmx_src) {
					/* cvtpi2ps/pd xmm0, mm1: load mm1 from the block first */
					static const uint8_t ld[] = { 0x0f, 0x6f, 0x8f, 0x10, 0x01, 0, 0 };

					c.n = 0;
					emit(&c, ld, sizeof ld);
					if (s[o].pfx)
						c.b[c.n++] = s[o].pfx;
					c.b[c.n++] = 0x0f;
					c.b[c.n++] = s[o].opc;
					c.b[c.n++] = 0xc1;
					c.b[c.n++] = 0x0f;
					c.b[c.n++] = 0x77;
					op = c;
				} else if (s[o].mmx_dst) {
					/* cvtps2pi mm0, xmm1; store mm0 */
					static const uint8_t stv[] = { 0x0f, 0x7f, 0x87, 0, 0, 0, 0, 0x0f, 0x77 };

					op.n = 0;
					if (s[o].pfx)
						op.b[op.n++] = s[o].pfx;
					op.b[op.n++] = 0x0f;
					op.b[op.n++] = s[o].opc;
					op.b[op.n++] = 0xc1;
					emit(&op, stv, sizeof stv);
					op.b[op.n - 6] = (uint8_t)(BUF_MM & 0xffu);
					op.b[op.n - 5] = (uint8_t)(BUF_MM >> 8);
				} else {
					xmm_op(&op, s[o].pfx, s[o].rexw, 1, s[o].opc, 0xc1u, -1);
				}
				with_mxcsr(&c, &op);
				run(s[o].nm, &c, &in, XM_ALL, (int)s[o].mmx_dst);
			}
	finish("conversions under every MXCSR rounding mode");
}


/* the random lanes of a pool fill are drawn from the whole pool: replace the NaNs among them with a finite value */
static void nonan_f(uint8_t *a)
{
	unsigned k;
	float f;

	for (k = 0; k < 4; k++) {
		memcpy(&f, a + k * 4u, 4);
		if (f != f)
			memcpy(a + k * 4u, &(float){ 1.5f }, 4);
	}
}

static void nonan_d(uint8_t *a)
{
	unsigned k;
	double d;

	for (k = 0; k < 2; k++) {
		memcpy(&d, a + k * 8u, 8);
		if (d != d)
			memcpy(a + k * 8u, &(double){ 1.5 }, 8);
	}
}

/*
 * SSE4.2 STRING COMPARES AND THE SSE4.1 ODDS AND ENDS: PCMPESTRI/M and PCMPISTRI/M with every immediate (all 256: element,
 * aggregation, polarity, output) on strings made of a few distinct bytes so that every aggregation finds something, with the
 * explicit lengths (negative and past the register included) in EAX and EDX; the index goes to ECX and the flags (CF ZF SF OF,
 * AF and PF cleared) and XMM0 are compared. PHMINPOSUW, MPSADBW (every immediate), INSERTPS (every immediate), EXTRACTPS,
 * DPPS and DPPD (every mask, over the pool, under each rounding mode).
 */
static void t_sse42(void)
{
	static const struct { const char *nm; uint8_t opc; unsigned expl; } s[] = {
		{ "pcmpestri", 0x61, 1 }, { "pcmpestrm", 0x60, 1 }, { "pcmpistri", 0x63, 0 }, { "pcmpistrm", 0x62, 0 }
	};
	unsigned o, i, k;

	if (!host_has(1, 1, 20)) {
		printf("  sse4.2: SKIPPED (the host has no SSE4.2)\n");
		return;
	}
	for (o = 0; o < 4; o++)
		for (i = 0; i < 256u * 8u; i++) {
			struct cn_io in;
			struct code c;
			uint8_t a[16], b[16];
			const unsigned imm = i & 255u;
			static const int lens[] = { 0, 1, 2, 3, 5, 7, 8, 9, 15, 16, 17, -1, -5, -16, -17, 100 };

			cn_input(&in, 0);
			for (k = 0; k < 16; k++) {
				a[k] = (uint8_t)(cn_rng() % 5u ? 'a' + cn_rng() % 4u : 0);
				b[k] = (uint8_t)(cn_rng() % 6u ? 'a' + cn_rng() % 4u : 0);
			}
			if (cn_rng() & 1u)                                    /* B holds A, so equal ordered finds it */
				memcpy(b + (cn_rng() & 3u), a, 4);
			if (imm & 1u)                                         /* words: keep the two bytes of a lane related */
				for (k = 0; k < 16; k += 2) {
					a[k + 1] = (uint8_t)(cn_rng() % 3u ? 0 : cn_rng() % 3u);
					b[k + 1] = (uint8_t)(cn_rng() % 3u ? 0 : cn_rng() % 3u);
				}
			put_xmm(&in, a, b);
			cn_put(&in, CN_O_RAX, (uint64_t)(int64_t)lens[cn_rng() % (sizeof lens / sizeof lens[0])] & 0xffffffffu);
			cn_put(&in, CN_O_RDX, (uint64_t)(int64_t)lens[cn_rng() % (sizeof lens / sizeof lens[0])] & 0xffffffffu);
			cn_put(&in, CN_O_RCX, cn_rng());
			xmm_op(&c, 0x66, 0, 3, s[o].opc, 0xc1, (int)imm);
			(void)cn_case(&st, s[o].nm, c.b, c.n, &in, CN_FL_ARITH, 64, XM_ALL, 0);
		}
	finish("pcmpestri / pcmpistri and the m forms");

	for (i = 0; i < 6000; i++) {
		struct cn_io in;
		struct code c, op;
		uint8_t a[16], b[16];
		const unsigned imm = i & 255u, which = i % 6u;

		cn_input(&in, 0);
		/* a dot product with a NaN in it is refused by the interpreter (emu_vec_fp.c): no NaN in these pools */
		if (which == 5u) {
			fill_f(a, (unsigned)(cn_rng() % (NF - 4u)), (unsigned)(cn_rng() % (NF - 4u)));
			fill_f(b, (unsigned)(cn_rng() % (NF - 4u)), (unsigned)(cn_rng() % (NF - 4u)));
			nonan_f(a);
			nonan_f(b);
		} else if (which == 4u) {
			fill_d(a, (unsigned)(cn_rng() % (ND - 3u)));
			fill_d(b, (unsigned)(cn_rng() % (ND - 3u)));
			nonan_d(a);
			nonan_d(b);
		} else {
			edge_bytes(a);
			edge_bytes(b);
		}
		put_xmm(&in, a, b);
		set_mxcsr(&in, (unsigned)(cn_rng() & 3u));
		switch (which) {
		case 0: xmm_op(&c, 0x66, 0, 2, 0x41, 0xc1, -1); run("phminposuw", &c, &in, XM_ALL, 0); break;
		case 1: xmm_op(&c, 0x66, 0, 3, 0x42, 0xc1, (int)imm); run("mpsadbw", &c, &in, XM_ALL, 0); break;
		case 2: xmm_op(&c, 0x66, 0, 3, 0x21, 0xc1, (int)imm); run("insertps", &c, &in, XM_ALL, 0); break;
		case 3: xmm_op(&c, 0x66, 0, 3, 0x17, 0xc8, (int)imm); run("extractps", &c, &in, XM_ALL, 0); break;
		case 4: xmm_op(&op, 0x66, 0, 3, 0x41, 0xc1, (int)imm); with_mxcsr(&c, &op); run("dppd", &c, &in, XM_ALL, 0); break;
		default: xmm_op(&op, 0x66, 0, 3, 0x40, 0xc1, (int)imm); with_mxcsr(&c, &op); run("dpps", &c, &in, XM_ALL, 0); break;
		}
	}
	finish("phminposuw, mpsadbw, insertps, extractps, dpps, dppd");
}

int main(void)
{
	cn_rng_state = 0x5041434b45442121ull;
	if (!CN_HOST) {
		printf("diff_vec_packed: SKIPPED (the host is not x86-64 Linux, so there is no reference to run)\n");
		return 0;
	}
	t_pint();
	t_pshift_imm();
	t_pshuf();
	t_pint_misc();
	t_aes();
	t_pfp();
	t_cmp();
	t_pfp_misc();
	t_cvt();
	t_sse42();
	printf("diff_vec_packed: %u group(s), %u vector(s)\n", groups, vectors);
	CK(vectors > 30000u, "the sweep is the size it claims (%u vectors)", vectors);
	if (fails) {
		printf("diff_vec_packed: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_vec_packed: ok\n");
	return 0;
}
