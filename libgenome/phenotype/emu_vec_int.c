/*
 * emu_vec_int.c - the packed integer instructions of MMX, SSE2, SSSE3 and SSE4.1/4.2 (and CLMUL), on the
 * 64 bit MMX registers and the 128 bit xmm registers.
 * Part of the interpreter; see emu_interp.c, emu_vec.c and emu_private.h.
 *
 * WHY THESE ARE CARRIED. The instruction histogram of the corpora (tests/lib/genome/diff_decode_cover.c, the
 * numbers in its header) puts the packed integer set first among the vector instructions a program that is
 * not a decoder-specific payload executes: compilers use PADDQ/PUNPCKLQDQ/PSRLD/PSHUFB/PALIGNR to copy,
 * hash, zero and compare, and a runtime's startup (a Go or Rust runtime, a CRT's memcpy dispatch) runs a few of
 * them before it reaches anything of the program's. One that is not carried ends the run as UNSUPPORTED at
 * the stub's first memcpy, which is how an unpacker misses a payload it could have reached.
 *
 * ONE ENGINE. An instruction is a lane width and an operation: the table in pk_class() says which, the loop in
 * pk_binary() applies it lane by lane over the 8 bytes of an MMX register or the 16 of an xmm one (the width
 * is the destination operand's). MMX and SSE forms share an id, so the register type of the operand is what
 * says how wide the instruction is. Every result is the architecture's, and the places where it is easy to be
 * wrong are written beside the code: saturation, the signed/unsigned split of the compares and min/max, the
 * shift count that is the whole low qword of the source, the unpacks that read only the low half.
 * tests/lib/genome/diff_sse_x87.c runs each of them against the host CPU.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* ---- lanes ---------------------------------------------------------------------------------- */

static inline uint64_t ld_lane(const uint8_t *p, unsigned l)
{
	uint64_t v = 0;

	memcpy(&v, p, l);                    /* little endian host: the layout is the guest's */
	return v;
}

static inline void st_lane(uint8_t *p, unsigned l, uint64_t v)
{
	memcpy(p, &v, l);
}

static inline int64_t sx_lane(uint64_t v, unsigned l)
{
	const unsigned sh = 64u - l * 8u;

	return (int64_t)(v << sh) >> sh;
}

static inline uint64_t mask_l(unsigned l)
{
	return l >= 8u ? ~0ull : (1ull << (l * 8u)) - 1u;
}

/* a signed value saturated to the signed range of `l` bytes, and an unsigned one to the unsigned range */
static inline uint64_t sat_s(int64_t v, unsigned l)
{
	const int64_t hi = (int64_t)(mask_l(l) >> 1), lo = -hi - 1;

	return (uint64_t)(v > hi ? hi : v < lo ? lo : v) & mask_l(l);
}

static inline uint64_t sat_u(int64_t v, unsigned l)
{
	const int64_t hi = (int64_t)mask_l(l);

	return (uint64_t)(v > hi ? hi : v < 0 ? 0 : v);
}

/* ---- classes ------------------------------------------------------------------------------- */

enum pk_op {
	PK_NONE,
	PK_ADD, PK_SUB, PK_ADDS, PK_ADDUS, PK_SUBS, PK_SUBUS,
	PK_MULLO, PK_MULHI, PK_MULHIU, PK_MULLD,
	PK_EQ, PK_GT,
	PK_MINU, PK_MAXU, PK_MINS, PK_MAXS, PK_AVG,
	PK_UNPKL, PK_UNPKH,
	PK_PACKSS, PK_PACKUS,
	PK_HADD, PK_HADDS, PK_HSUB, PK_HSUBS,
	PK_SIGN,
	/* not lane by lane: */
	PK_MULUDQ, PK_MULDQ, PK_MADD, PK_MADDUBS, PK_MULHRS, PK_SAD, PK_SHUFB,
	/* one operand: */
	PK_ABS,
	/* shifts by a count */
	PK_SLL, PK_SRL, PK_SRA
};

/* The class of an id, its lane width in bytes, and whether it is a two-operand arithmetic form. 0 = not mine. */
static unsigned pk_class(unsigned id, unsigned *lane)
{
	*lane = 1;
	switch (id) {
	case KGENOME_X86_I_PADDB:  return PK_ADD;
	case KGENOME_X86_I_PADDW:  *lane = 2; return PK_ADD;
	case KGENOME_X86_I_PADDD:  *lane = 4; return PK_ADD;
	case KGENOME_X86_I_PADDQ:  *lane = 8; return PK_ADD;
	case KGENOME_X86_I_PSUBW:  *lane = 2; return PK_SUB;
	case KGENOME_X86_I_PSUBD:  *lane = 4; return PK_SUB;
	case KGENOME_X86_I_PSUBQ:  *lane = 8; return PK_SUB;
	case KGENOME_X86_I_PADDSB:  return PK_ADDS;
	case KGENOME_X86_I_PADDSW:  *lane = 2; return PK_ADDS;
	case KGENOME_X86_I_PADDUSB: return PK_ADDUS;
	case KGENOME_X86_I_PADDUSW: *lane = 2; return PK_ADDUS;
	case KGENOME_X86_I_PSUBSB:  return PK_SUBS;
	case KGENOME_X86_I_PSUBSW:  *lane = 2; return PK_SUBS;
	case KGENOME_X86_I_PSUBUSB: return PK_SUBUS;
	case KGENOME_X86_I_PSUBUSW: *lane = 2; return PK_SUBUS;
	case KGENOME_X86_I_PMULLW:  *lane = 2; return PK_MULLO;
	case KGENOME_X86_I_PMULHW:  *lane = 2; return PK_MULHI;
	case KGENOME_X86_I_PMULHUW: *lane = 2; return PK_MULHIU;
	case KGENOME_X86_I_PMULLD:  *lane = 4; return PK_MULLD;
	case KGENOME_X86_I_PCMPEQW: *lane = 2; return PK_EQ;
	case KGENOME_X86_I_PCMPEQD: *lane = 4; return PK_EQ;
	case KGENOME_X86_I_PCMPEQQ: *lane = 8; return PK_EQ;
	case KGENOME_X86_I_PCMPGTB: return PK_GT;
	case KGENOME_X86_I_PCMPGTW: *lane = 2; return PK_GT;
	case KGENOME_X86_I_PCMPGTD: *lane = 4; return PK_GT;
	case KGENOME_X86_I_PCMPGTQ: *lane = 8; return PK_GT;
	case KGENOME_X86_I_PMINUB:  return PK_MINU;
	case KGENOME_X86_I_PMINUW:  *lane = 2; return PK_MINU;
	case KGENOME_X86_I_PMINUD:  *lane = 4; return PK_MINU;
	case KGENOME_X86_I_PMAXUB:  return PK_MAXU;
	case KGENOME_X86_I_PMAXUW:  *lane = 2; return PK_MAXU;
	case KGENOME_X86_I_PMAXUD:  *lane = 4; return PK_MAXU;
	case KGENOME_X86_I_PMINSB:  return PK_MINS;
	case KGENOME_X86_I_PMINSW:  *lane = 2; return PK_MINS;
	case KGENOME_X86_I_PMINSD:  *lane = 4; return PK_MINS;
	case KGENOME_X86_I_PMAXSB:  return PK_MAXS;
	case KGENOME_X86_I_PMAXSW:  *lane = 2; return PK_MAXS;
	case KGENOME_X86_I_PMAXSD:  *lane = 4; return PK_MAXS;
	case KGENOME_X86_I_PAVGB:   return PK_AVG;
	case KGENOME_X86_I_PAVGW:   *lane = 2; return PK_AVG;
	case KGENOME_X86_I_PUNPCKLBW: return PK_UNPKL;
	case KGENOME_X86_I_PUNPCKLWD: *lane = 2; return PK_UNPKL;
	case KGENOME_X86_I_PUNPCKLDQ: *lane = 4; return PK_UNPKL;
	case KGENOME_X86_I_PUNPCKLQDQ: *lane = 8; return PK_UNPKL;
	case KGENOME_X86_I_PUNPCKHBW: return PK_UNPKH;
	case KGENOME_X86_I_PUNPCKHWD: *lane = 2; return PK_UNPKH;
	case KGENOME_X86_I_PUNPCKHDQ: *lane = 4; return PK_UNPKH;
	case KGENOME_X86_I_PUNPCKHQDQ: *lane = 8; return PK_UNPKH;
	case KGENOME_X86_I_PACKSSWB: *lane = 2; return PK_PACKSS;
	case KGENOME_X86_I_PACKSSDW: *lane = 4; return PK_PACKSS;
	case KGENOME_X86_I_PACKUSWB: *lane = 2; return PK_PACKUS;
	case KGENOME_X86_I_PACKUSDW: *lane = 4; return PK_PACKUS;
	case KGENOME_X86_I_PHADDW:  *lane = 2; return PK_HADD;
	case KGENOME_X86_I_PHADDD:  *lane = 4; return PK_HADD;
	case KGENOME_X86_I_PHADDSW: *lane = 2; return PK_HADDS;
	case KGENOME_X86_I_PHSUBW:  *lane = 2; return PK_HSUB;
	case KGENOME_X86_I_PHSUBD:  *lane = 4; return PK_HSUB;
	case KGENOME_X86_I_PHSUBSW: *lane = 2; return PK_HSUBS;
	case KGENOME_X86_I_PSIGNB:  return PK_SIGN;
	case KGENOME_X86_I_PSIGNW:  *lane = 2; return PK_SIGN;
	case KGENOME_X86_I_PSIGND:  *lane = 4; return PK_SIGN;
	case KGENOME_X86_I_PMULUDQ: return PK_MULUDQ;
	case KGENOME_X86_I_PMULDQ:  return PK_MULDQ;
	case KGENOME_X86_I_PMADDWD: return PK_MADD;
	case KGENOME_X86_I_PMADDUBSW: return PK_MADDUBS;
	case KGENOME_X86_I_PMULHRSW: return PK_MULHRS;
	case KGENOME_X86_I_PSADBW:  return PK_SAD;
	case KGENOME_X86_I_PSHUFB:  return PK_SHUFB;
	case KGENOME_X86_I_PABSB:   return PK_ABS;
	case KGENOME_X86_I_PABSW:   *lane = 2; return PK_ABS;
	case KGENOME_X86_I_PABSD:   *lane = 4; return PK_ABS;
	case KGENOME_X86_I_PSLLW:   *lane = 2; return PK_SLL;
	case KGENOME_X86_I_PSLLD:   *lane = 4; return PK_SLL;
	case KGENOME_X86_I_PSLLQ:   *lane = 8; return PK_SLL;
	case KGENOME_X86_I_PSRLW:   *lane = 2; return PK_SRL;
	case KGENOME_X86_I_PSRLD:   *lane = 4; return PK_SRL;
	case KGENOME_X86_I_PSRLQ:   *lane = 8; return PK_SRL;
	case KGENOME_X86_I_PSRAW:   *lane = 2; return PK_SRA;
	case KGENOME_X86_I_PSRAD:   *lane = 4; return PK_SRA;
	default: return PK_NONE;
	}
}

/* ---- the operand frame -------------------------------------------------------------------- */

/* The width of the instruction: 8 for an MMX destination, 16 for an xmm one. 0 for anything else. */
static unsigned pk_width(const struct kgenome_emu_insn *ixp)
{
	const struct kgenome_x86_op *d = &ixp->op[0];

	if (d->type != KGENOME_X86_OP_REG)
		return 0;
	return d->rtype == KGENOME_X86_REG_MMX ? 8u : d->rtype == KGENOME_X86_REG_SSE ? 16u : 0u;
}

/* One lane of the arithmetic ops that work lane by lane. */
static uint64_t pk_lane(unsigned op, unsigned l, uint64_t a, uint64_t b)
{
	const uint64_t m = mask_l(l);

	switch (op) {
	case PK_ADD:   return (a + b) & m;
	case PK_SUB:   return (a - b) & m;
	case PK_ADDS:  return sat_s(sx_lane(a, l) + sx_lane(b, l), l);
	case PK_ADDUS: return sat_u((int64_t)(a + b), l);
	case PK_SUBS:  return sat_s(sx_lane(a, l) - sx_lane(b, l), l);
	case PK_SUBUS: return sat_u((int64_t)a - (int64_t)b, l);
	case PK_MULLO: return (uint64_t)(sx_lane(a, l) * sx_lane(b, l)) & m;
	case PK_MULLD: return (uint64_t)(sx_lane(a, l) * sx_lane(b, l)) & m;
	case PK_MULHI: return (uint64_t)((sx_lane(a, l) * sx_lane(b, l)) >> (l * 8u)) & m;
	case PK_MULHIU: return ((a * b) >> (l * 8u)) & m;
	case PK_EQ:    return a == b ? m : 0;
	case PK_GT:    return sx_lane(a, l) > sx_lane(b, l) ? m : 0;
	case PK_MINU:  return a < b ? a : b;
	case PK_MAXU:  return a > b ? a : b;
	case PK_MINS:  return sx_lane(a, l) < sx_lane(b, l) ? a : b;
	case PK_MAXS:  return sx_lane(a, l) > sx_lane(b, l) ? a : b;
	case PK_AVG:   return ((a + b + 1u) >> 1) & m;
	default:       return 0;
	}
}

/* PSIGN: the destination negated, kept or zeroed by the sign of the source lane. */
static uint64_t pk_sign(uint64_t a, uint64_t b, unsigned l)
{
	const int64_t sb = sx_lane(b, l);

	return sb < 0 ? (0 - a) & mask_l(l) : sb == 0 ? 0 : a;
}

/*
 * Everything with two vector operands. `x` is the destination read, `y` the source; `q` is the result,
 * W bytes wide. The forms that are not lane by lane have their own arm; each says what the manual says.
 */
static void pk_binary(unsigned op, unsigned l, unsigned w, const uint8_t *x, const uint8_t *y, uint8_t *q)
{
	unsigned i, n = w / l;

	memset(q, 0, 16);
	switch (op) {
	case PK_UNPKL: case PK_UNPKH: {
		/* interleave the low (or high) halves of each: the 64 bit MMX form's halves are 4 bytes */
		const unsigned half = w / 2u, base = op == PK_UNPKL ? 0u : half;

		for (i = 0; i < half / l; i++) {
			memcpy(q + (2u * i) * l, x + base + i * l, l);
			memcpy(q + (2u * i + 1u) * l, y + base + i * l, l);
		}
		return;
	}
	case PK_PACKSS: case PK_PACKUS: {
		/* l is the width of the SOURCE lane; the destination lane is half of it: x's lanes, then y's */
		const unsigned dl = l / 2u;

		for (i = 0; i < n; i++) {
			const int64_t a = sx_lane(ld_lane(x + i * l, l), l), b = sx_lane(ld_lane(y + i * l, l), l);

			st_lane(q + i * dl, dl, op == PK_PACKSS ? sat_s(a, dl) : sat_u(a, dl));
			st_lane(q + (n + i) * dl, dl, op == PK_PACKSS ? sat_s(b, dl) : sat_u(b, dl));
		}
		return;
	}
	case PK_HADD: case PK_HSUB: case PK_HADDS: case PK_HSUBS: {
		/* pairs of the destination, then pairs of the source */
		for (i = 0; i < n; i++) {
			const uint8_t *s = i < n / 2u ? x : y;
			const unsigned k = (i % (n / 2u)) * 2u;
			const int64_t a = sx_lane(ld_lane(s + k * l, l), l), b = sx_lane(ld_lane(s + (k + 1u) * l, l), l);
			int64_t r = (op == PK_HADD || op == PK_HADDS) ? a + b : a - b;

			st_lane(q + i * l, l, (op == PK_HADDS || op == PK_HSUBS) ? sat_s(r, l) : (uint64_t)r & mask_l(l));
		}
		return;
	}
	case PK_MULUDQ: case PK_MULDQ:
		/* the even doublewords, multiplied to quadwords; signed for PMULDQ */
		for (i = 0; i < w / 8u; i++) {
			const uint64_t a = ld_lane(x + i * 8u, 4), b = ld_lane(y + i * 8u, 4);
			const uint64_t r = op == PK_MULUDQ ? a * b : (uint64_t)(sx_lane(a, 4) * sx_lane(b, 4));

			st_lane(q + i * 8u, 8, r);
		}
		return;
	case PK_MADD:
		/* signed words multiplied, adjacent products summed into doublewords (wraps only for 0x8000*0x8000 twice) */
		for (i = 0; i < w / 4u; i++) {
			const int64_t p = sx_lane(ld_lane(x + i * 4u, 2), 2) * sx_lane(ld_lane(y + i * 4u, 2), 2) +
					  sx_lane(ld_lane(x + i * 4u + 2u, 2), 2) * sx_lane(ld_lane(y + i * 4u + 2u, 2), 2);

			st_lane(q + i * 4u, 4, (uint64_t)p);
		}
		return;
	case PK_MADDUBS:
		/* unsigned bytes of the destination times signed bytes of the source, pairs summed, saturated to int16 */
		for (i = 0; i < w / 2u; i++) {
			const int64_t p = (int64_t)x[i * 2u] * (int8_t)y[i * 2u] +
					  (int64_t)x[i * 2u + 1u] * (int8_t)y[i * 2u + 1u];

			st_lane(q + i * 2u, 2, sat_s(p, 2));
		}
		return;
	case PK_MULHRS:
		for (i = 0; i < w / 2u; i++) {
			const int64_t p = sx_lane(ld_lane(x + i * 2u, 2), 2) * sx_lane(ld_lane(y + i * 2u, 2), 2);

			st_lane(q + i * 2u, 2, (uint64_t)(((p >> 14) + 1) >> 1));
		}
		return;
	case PK_SAD:
		/* the sum of absolute byte differences of each 8 byte group, in the low word of its quadword */
		for (i = 0; i < w / 8u; i++) {
			unsigned k, s = 0;

			for (k = 0; k < 8u; k++) {
				const int d = (int)x[i * 8u + k] - (int)y[i * 8u + k];

				s += (unsigned)(d < 0 ? -d : d);
			}
			st_lane(q + i * 8u, 8, s);
		}
		return;
	case PK_SHUFB:
		/* each destination byte is the destination's byte named by the low bits of the source byte, or zero */
		for (i = 0; i < w; i++)
			q[i] = (y[i] & 0x80u) ? 0u : x[y[i] & (w - 1u)];
		return;
	case PK_SIGN:
		for (i = 0; i < n; i++)
			st_lane(q + i * l, l, pk_sign(ld_lane(x + i * l, l), ld_lane(y + i * l, l), l));
		return;
	case PK_ABS:
		/* one operand: the SOURCE's absolute value (x is not read) */
		for (i = 0; i < n; i++) {
			const int64_t v = sx_lane(ld_lane(y + i * l, l), l);

			st_lane(q + i * l, l, (uint64_t)(v < 0 ? -v : v) & mask_l(l));
		}
		return;
	default:
		for (i = 0; i < n; i++)
			st_lane(q + i * l, l, pk_lane(op, l, ld_lane(x + i * l, l), ld_lane(y + i * l, l)));
		return;
	}
}

/* Shifts: the count is an immediate, or the whole low quadword of the source operand. A count of the lane
 * width or more clears the lane (PSRA: fills it with the sign). */
static int pk_shift(struct kgenome_emu *e, struct kgenome_emu_insn *ixp, unsigned op, unsigned l, unsigned w)
{
	uint8_t x[16], q[16] = { 0 };
	unsigned nx, i;
	uint64_t cnt;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (ixp->op[1].type == KGENOME_X86_OP_IMM) {
		cnt = (uint64_t)ixp->op[1].v & 0xffu;
	} else {
		uint8_t y[16];
		unsigned ny;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		cnt = ld_lane(y, 8);
	}
	for (i = 0; i < w / l; i++) {
		const uint64_t a = ld_lane(x + i * l, l);
		uint64_t r;

		if (op == PK_SLL)
			r = cnt >= l * 8u ? 0 : (a << cnt) & mask_l(l);
		else if (op == PK_SRL)
			r = cnt >= l * 8u ? 0 : a >> cnt;
		else
			r = (uint64_t)(sx_lane(a, l) >> (cnt >= l * 8u ? l * 8u - 1u : cnt)) & mask_l(l);
		st_lane(q + i * l, l, r);
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, w) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- the forms with an immediate, a selector or a different shape -------------------------- */

/* PSHUFW (MMX), PSHUFLW, PSHUFHW: four words chosen by two bits each of the immediate. */
static int pk_pshuf(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16], q[16];
	unsigned ny, k, base = 0, w = pk_width(ixp);
	uint64_t sel;

	if (!w || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memcpy(q, y, 16);
	if (ixp->h.id == KGENOME_X86_I_PSHUFHW)
		base = 8;
	for (k = 0; k < 4u; k++)
		memcpy(q + base + k * 2u, y + base + ((sel >> (k * 2u)) & 3u) * 2u, 2);
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, w) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* PALIGNR: the two operands as one 2w-byte value (destination high), shifted right by imm bytes, low w kept. */
static int pk_palignr(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], cat[32] = { 0 }, q[16];
	unsigned nx, ny, w = pk_width(ixp), k;
	uint64_t sh;

	if (!w || !kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sh))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memcpy(cat, y, w);
	memcpy(cat + w, x, w);
	memset(q, 0, 16);
	for (k = 0; k < w; k++)
		q[k] = sh + k < 2u * w ? cat[sh + k] : 0;
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, w) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* PMOVSX / PMOVZX: the low elements of the source widened. The source is read at the width it has. */
static int pk_pmov(struct kgenome_emu *e, struct kgenome_emu_insn *ixp, unsigned from, unsigned to, int sign)
{
	uint8_t y[16], q[16] = { 0 };
	unsigned ny, k, n = 16u / to;
	uint64_t v;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < n; k++) {
		v = ld_lane(y + k * from, from);
		st_lane(q + k * to, to, sign ? (uint64_t)sx_lane(v, from) : v);
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* PEXTRB/D/Q and PINSRB/D/Q (the word forms are in emu_vec.c) */
static int pk_pextr(struct kgenome_emu *e, struct kgenome_emu_insn *ixp, unsigned l)
{
	uint8_t y[16];
	unsigned ny;
	uint64_t sel;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return kgenome_emu_op_wr(e, ixp, &ixp->op[0], ld_lane(y + (sel & (16u / l - 1u)) * l, l))
		       ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

static int pk_pinsr(struct kgenome_emu *e, struct kgenome_emu_insn *ixp, unsigned l)
{
	uint8_t x[16];
	unsigned nx;
	uint64_t v, sel;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &v) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	st_lane(x + (sel & (16u / l - 1u)) * l, l, v);
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* PBLENDW (immediate, one bit a word), PBLENDVB (the mask is xmm0's bytes' top bits) */
static int pk_pblend(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;
	uint64_t sel = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memcpy(q, x, 16);
	if (ixp->h.id == KGENOME_X86_I_PBLENDW) {
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		for (k = 0; k < 8u; k++)
			if ((sel >> k) & 1u)
				memcpy(q + k * 2u, y + k * 2u, 2);
	} else {
		for (k = 0; k < 16u; k++)
			if (e->xmm[0][k] & 0x80u)
				q[k] = y[k];
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* PTEST: ZF = (dst AND src) == 0, CF = (NOT dst AND src) == 0; the other flags are cleared. */
static int pk_ptest(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny, k;
	uint8_t a = 0, b = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < 16u; k++) {
		a |= (uint8_t)(x[k] & y[k]);
		b |= (uint8_t)(~x[k] & y[k]);
	}
	e->flags &= ~(uint64_t)(KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF |
				KGENOME_EMU_FL_SF | KGENOME_EMU_FL_AF);
	if (!a)
		e->flags |= KGENOME_EMU_FL_ZF;
	if (!b)
		e->flags |= KGENOME_EMU_FL_CF;
	return KGENOME_EMU_RUN_OK;
}

/* PCLMULQDQ: the carry-less product of one qword of each, selected by bits 0 and 4 of the immediate. */
static int pk_pclmul(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;
	uint64_t sel, a, b, lo = 0, hi = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	a = ld_lane(x + ((sel & 1u) ? 8 : 0), 8);
	b = ld_lane(y + ((sel & 16u) ? 8 : 0), 8);
	for (k = 0; k < 64u; k++)
		if ((b >> k) & 1u) {
			lo ^= a << k;
			if (k)
				hi ^= a >> (64u - k);
		}
	st_lane(q, 8, lo);
	st_lane(q + 8, 8, hi);
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* MASKMOVQ / MASKMOVDQU: the bytes of the source whose mask byte has its top bit set are stored at [RDI] (DS). */
static int pk_maskmov(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], m[16];
	unsigned nx, nm, k, w = pk_width(ixp);

	if (!w || !kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], m, &nm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < w; k++)
		if ((m[k] & 0x80u) && !kgenome_emu_mem_wr(e, e->gpr[KGENOME_EMU_RDI] + k, x + k, 1))
			return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/* ---- SSE4.2 string compares, MPSADBW, PHMINPOSUW -------------------------------------------------- */

/*
 * PCMPESTRI/M and PCMPISTRI/M (SDM Vol. 2): two strings of up to 16 bytes or 8 words, compared as the immediate says.
 *   imm bits 1-0  the element: unsigned byte, unsigned word, signed byte, signed word
 *   imm bits 3-2  the aggregation: equal any (is this B element one of A's), ranges (is it inside a pair of A's bounds),
 *                 equal each (the strings element by element), equal ordered (is A a substring of B, from each start)
 *   imm bits 5-4  the polarity: as is, inverted, masked as is, inverted only where B is valid
 *   imm bit 6     the output: the least or most significant index (the I forms), a bit or an element mask in XMM0 (the M forms)
 * The explicit forms take the lengths from EAX (A) and EDX (B), saturated to the element count; the implicit forms stop at the
 * first zero element. An element past a string's end is invalid, and the three flags say it: CF = the result is not empty, ZF =
 * B is shorter than the register, SF = A is, OF = the first result bit. AF and PF are cleared.
 */
static int pk_pcmpstr(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t a[16], b[16];
	unsigned na, nb, i, j, k, la, lb, n, wl;
	uint64_t imm, res = 0, res1 = 0;
	const unsigned id = ixp->h.id;
	const int expl = id == KGENOME_X86_I_PCMPESTRI || id == KGENOME_X86_I_PCMPESTRM;
	const int idx = id == KGENOME_X86_I_PCMPESTRI || id == KGENOME_X86_I_PCMPISTRI;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], a, &na) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], b, &nb) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &imm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	wl = (imm & 1u) ? 2u : 1u;
	n = 16u / wl;
	if (expl) {
		int64_t x = (int32_t)e->gpr[KGENOME_EMU_RAX], y = (int32_t)e->gpr[KGENOME_EMU_RDX];

		la = (unsigned)((x < 0 ? -x : x) > (int64_t)n ? n : (x < 0 ? -x : x));
		lb = (unsigned)((y < 0 ? -y : y) > (int64_t)n ? n : (y < 0 ? -y : y));
	} else {
		for (la = 0; la < n && ld_lane(a + la * wl, wl); la++)
			;
		for (lb = 0; lb < n && ld_lane(b + lb * wl, wl); lb++)
			;
	}
	{
		const int sg = (imm & 2u) != 0;
		const unsigned agg = (unsigned)((imm >> 2) & 3u);
#define EL(buf, q) (sg ? (int64_t)sx_lane(ld_lane((buf) + (q) * wl, wl), wl) : (int64_t)ld_lane((buf) + (q) * wl, wl))

		for (j = 0; j < n; j++) {
			int t = 0;

			if (agg == 0) {                                    /* equal any */
				for (i = 0; i < la && j < lb && !t; i++)
					t = EL(a, i) == EL(b, j);
			} else if (agg == 1) {                             /* ranges */
				for (i = 0; i + 1u < la && j < lb && !t; i += 2u)
					t = EL(a, i) <= EL(b, j) && EL(b, j) <= EL(a, i + 1u);
			} else if (agg == 2) {                             /* equal each */
				t = (j < la && j < lb) ? EL(a, j) == EL(b, j) : (j >= la && j >= lb);
			} else {                                           /* equal ordered */
				t = 1;
				for (k = 0; k + j < n && t; k++)
					t = k >= la ? 1 : (j + k >= lb ? 0 : EL(a, k) == EL(b, j + k));
			}
			if (t)
				res1 |= 1ull << j;
		}
#undef EL
	}
	res = res1;
	switch ((imm >> 4) & 3u) {
	case 1:  res = ~res1 & ((1ull << n) - 1u); break;
	case 3:  for (j = 0; j < lb; j++) res ^= 1ull << j; break;
	default: break;
	}
	e->flags &= ~(uint64_t)(KGENOME_EMU_FL_CF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_SF | KGENOME_EMU_FL_OF | KGENOME_EMU_FL_AF |
				KGENOME_EMU_FL_PF);
	if (res)
		e->flags |= KGENOME_EMU_FL_CF;
	if (lb < n)
		e->flags |= KGENOME_EMU_FL_ZF;
	if (la < n)
		e->flags |= KGENOME_EMU_FL_SF;
	if (res & 1u)
		e->flags |= KGENOME_EMU_FL_OF;
	if (idx) {
		unsigned r = n;

		if (res)
			r = (imm & 0x40u) ? 63u - (unsigned)__builtin_clzll(res) : (unsigned)__builtin_ctzll(res);
		kgenome_emu_reg_wr(e, KGENOME_EMU_RCX, 4, 0, r);
	} else {
		uint8_t q[16] = { 0 };

		if (imm & 0x40u) {
			for (j = 0; j < n; j++)
				if ((res >> j) & 1u)
					memset(q + j * wl, 0xff, wl);
		} else {
			st_lane(q, 8, res);
		}
		memcpy(e->xmm[0], q, 16);
	}
	return KGENOME_EMU_RUN_OK;
}

/* PHMINPOSUW: the smallest unsigned word of the source in word 0, the lowest index it is at in word 1, the rest zero. */
static int pk_phminpos(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16], q[16] = { 0 };
	unsigned ny, k, best = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 1; k < 8u; k++)
		if (ld_lane(y + k * 2u, 2) < ld_lane(y + best * 2u, 2))
			best = k;
	st_lane(q, 2, ld_lane(y + best * 2u, 2));
	st_lane(q + 2, 2, best);
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/*
 * MPSADBW: eight sums of absolute differences of four bytes. imm bits 1-0 pick which aligned four bytes of the source are
 * the pattern, bit 2 which four of the destination the sliding window starts at (0 or 4); word i is the sum for the window
 * that starts at the destination byte (window start + i).
 */
static int pk_mpsadbw(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, i, k;
	uint64_t imm;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &imm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	{
		const unsigned so = (unsigned)(imm & 3u) * 4u, dof = (unsigned)((imm >> 2) & 1u) * 4u;

		for (i = 0; i < 8u; i++) {
			unsigned sum = 0;

			for (k = 0; k < 4u; k++) {
				const int d = (int)x[dof + i + k] - (int)y[so + k];

				sum += (unsigned)(d < 0 ? -d : d);
			}
			st_lane(q + i * 2u, 2, sum);
		}
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- AES ------------------------------------------------------------------------------------ */

static uint8_t gmul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	unsigned i;

	for (i = 0; i < 8u; i++) {
		if (b & 1u)
			p ^= a;
		a = (uint8_t)(((unsigned)a << 1) ^ ((a & 0x80u) ? 0x1bu : 0u));
		b >>= 1;
	}
	return p;
}

/*
 * THE S-BOXES ARE COMPUTED, NOT TYPED, AND NOT KEPT. The multiplicative inverse in GF(2^8) (modulus 0x11b, found
 * through the powers of 3, which generate the field) followed by the affine map of FIPS 197 5.1.1; the inverse
 * box is its inverse. A table of 256 constants copied by hand is 256 places to be wrong, and a table filled on
 * first use is writable global state a library used from many threads must not have: so each call fills two
 * 256 byte arrays on its stack, about two thousand operations, which an instruction that is a handful of
 * times in a payload does not notice. The host's AESENC is the check (diff_sse_x87.c).
 */
struct aes_box {
	uint8_t sb[256], isb[256];
};

static void aes_box_fill(struct aes_box *bx)
{
	uint8_t ex[256], lg[256];
	unsigned i, x = 1;

	for (i = 0; i < 255u; i++) {
		ex[i] = (uint8_t)x;
		lg[x] = (uint8_t)i;
		x ^= ((x << 1) ^ ((x & 0x80u) ? 0x11bu : 0u)) & 0xffu;      /* times 3 */
		x &= 0xffu;
	}
	ex[255] = ex[0];
	for (i = 0; i < 256u; i++) {
		const unsigned inv = i ? ex[255u - lg[i]] : 0u;
		const uint8_t s = (uint8_t)(inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) ^
					    ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63u);

		bx->sb[i] = s;
		bx->isb[s] = (uint8_t)i;
	}
}

static void aes_round(const struct aes_box *bx, uint8_t *st, const uint8_t *key, int enc, int last)
{
	uint8_t t[16], u[16];
	unsigned c, r;

	if (enc) {
		/* ShiftRows, SubBytes, MixColumns (not in the last round), AddRoundKey */
		for (c = 0; c < 4u; c++)
			for (r = 0; r < 4u; r++)
				t[c * 4u + r] = bx->sb[st[((c + r) & 3u) * 4u + r]];
		if (!last) {
			for (c = 0; c < 4u; c++) {
				const uint8_t *a = t + c * 4u;

				u[c * 4u + 0] = (uint8_t)(gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]);
				u[c * 4u + 1] = (uint8_t)(a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]);
				u[c * 4u + 2] = (uint8_t)(a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3));
				u[c * 4u + 3] = (uint8_t)(gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2));
			}
			memcpy(t, u, 16);
		}
	} else {
		/* InvShiftRows, InvSubBytes, InvMixColumns (not in the last round), AddRoundKey */
		for (c = 0; c < 4u; c++)
			for (r = 0; r < 4u; r++)
				t[((c + r) & 3u) * 4u + r] = bx->isb[st[c * 4u + r]];
		if (!last) {
			for (c = 0; c < 4u; c++) {
				const uint8_t *a = t + c * 4u;

				u[c * 4u + 0] = (uint8_t)(gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9));
				u[c * 4u + 1] = (uint8_t)(gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13));
				u[c * 4u + 2] = (uint8_t)(gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11));
				u[c * 4u + 3] = (uint8_t)(gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14));
			}
			memcpy(t, u, 16);
		}
	}
	for (c = 0; c < 16u; c++)
		st[c] = (uint8_t)(t[c] ^ key[c]);
}

static int pk_aes(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;
	const unsigned id = ixp->h.id;
	struct aes_box bx;

	aes_box_fill(&bx);
	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memcpy(q, x, 16);
	switch (id) {
	case KGENOME_X86_I_AESENC:     aes_round(&bx, q, y, 1, 0); break;
	case KGENOME_X86_I_AESENCLAST: aes_round(&bx, q, y, 1, 1); break;
	case KGENOME_X86_I_AESDEC:     aes_round(&bx, q, y, 0, 0); break;
	case KGENOME_X86_I_AESDECLAST: aes_round(&bx, q, y, 0, 1); break;
	case KGENOME_X86_I_AESIMC: {
		/* InvMixColumns of the source, alone: a decryption key made from an encryption one */
		for (k = 0; k < 4u; k++) {
			const uint8_t *a = y + k * 4u;

			q[k * 4u + 0] = (uint8_t)(gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9));
			q[k * 4u + 1] = (uint8_t)(gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13));
			q[k * 4u + 2] = (uint8_t)(gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11));
			q[k * 4u + 3] = (uint8_t)(gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14));
		}
		break;
	}
	default: {                                  /* AESKEYGENASSIST xmm, xmm/m128, imm8 */
		uint64_t rcon;
		uint32_t w1, w3, r1, r3;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[2], &rcon))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		w1 = (uint32_t)ld_lane(y + 4, 4);
		w3 = (uint32_t)ld_lane(y + 12, 4);
		for (k = 0; k < 4u; k++) {
			((uint8_t *)&r1)[k] = bx.sb[(w1 >> (8u * k)) & 0xffu];
			((uint8_t *)&r3)[k] = bx.sb[(w3 >> (8u * k)) & 0xffu];
		}
		st_lane(q, 4, r1);
		st_lane(q + 4, 4, ((r1 >> 8) | (r1 << 24)) ^ (uint32_t)rcon);
		st_lane(q + 8, 4, r3);
		st_lane(q + 12, 4, ((r3 >> 8) | (r3 << 24)) ^ (uint32_t)rcon);
		break;
	}
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- the entry ------------------------------------------------------------------------------ */

/*
 * Execute the packed integer instructions; NOT_MINE for any other id. Called by kgenome_emu_run_vec for the
 * ids it does not carry itself, so the instructions it has had since before this file keep their arms.
 */
int kgenome_emu_run_vec_int(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	unsigned l, op = pk_class(ixp->h.id, &l), w;

	if (op != PK_NONE) {
		uint8_t x[16], y[16], q[16];
		unsigned nx, ny;

		w = pk_width(ixp);
		if (!w)
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (op == PK_SLL || op == PK_SRL || op == PK_SRA)
			return pk_shift(e, ixp, op, l, w);
		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		pk_binary(op, l, w, x, y, q);
		return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, w) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}
	switch (ixp->h.id) {
	case KGENOME_X86_I_PSHUFW: case KGENOME_X86_I_PSHUFLW: case KGENOME_X86_I_PSHUFHW:
		return pk_pshuf(e, ixp);
	case KGENOME_X86_I_PALIGNR:
		return pk_palignr(e, ixp);
	case KGENOME_X86_I_PMOVSXBW: return pk_pmov(e, ixp, 1, 2, 1);
	case KGENOME_X86_I_PMOVSXBD: return pk_pmov(e, ixp, 1, 4, 1);
	case KGENOME_X86_I_PMOVSXBQ: return pk_pmov(e, ixp, 1, 8, 1);
	case KGENOME_X86_I_PMOVSXWD: return pk_pmov(e, ixp, 2, 4, 1);
	case KGENOME_X86_I_PMOVSXWQ: return pk_pmov(e, ixp, 2, 8, 1);
	case KGENOME_X86_I_PMOVSXDQ: return pk_pmov(e, ixp, 4, 8, 1);
	case KGENOME_X86_I_PMOVZXBW: return pk_pmov(e, ixp, 1, 2, 0);
	case KGENOME_X86_I_PMOVZXBD: return pk_pmov(e, ixp, 1, 4, 0);
	case KGENOME_X86_I_PMOVZXBQ: return pk_pmov(e, ixp, 1, 8, 0);
	case KGENOME_X86_I_PMOVZXWD: return pk_pmov(e, ixp, 2, 4, 0);
	case KGENOME_X86_I_PMOVZXWQ: return pk_pmov(e, ixp, 2, 8, 0);
	case KGENOME_X86_I_PMOVZXDQ: return pk_pmov(e, ixp, 4, 8, 0);
	case KGENOME_X86_I_PEXTRB: return pk_pextr(e, ixp, 1);
	case KGENOME_X86_I_PEXTRD: return pk_pextr(e, ixp, 4);
	case KGENOME_X86_I_PEXTRQ: return pk_pextr(e, ixp, 8);
	case KGENOME_X86_I_PINSRB: return pk_pinsr(e, ixp, 1);
	case KGENOME_X86_I_PINSRD: return pk_pinsr(e, ixp, 4);
	case KGENOME_X86_I_PINSRQ: return pk_pinsr(e, ixp, 8);
	case KGENOME_X86_I_PBLENDW: case KGENOME_X86_I_PBLENDVB:
		return pk_pblend(e, ixp);
	case KGENOME_X86_I_PTEST:
		return pk_ptest(e, ixp);
	case KGENOME_X86_I_PCLMULQDQ:
		return pk_pclmul(e, ixp);
	case KGENOME_X86_I_PCMPESTRI: case KGENOME_X86_I_PCMPESTRM: case KGENOME_X86_I_PCMPISTRI: case KGENOME_X86_I_PCMPISTRM:
		return pk_pcmpstr(e, ixp);
	case KGENOME_X86_I_PHMINPOSUW:
		return pk_phminpos(e, ixp);
	case KGENOME_X86_I_MPSADBW:
		return pk_mpsadbw(e, ixp);
	case KGENOME_X86_I_MASKMOVQ: case KGENOME_X86_I_MASKMOVDQU:
		return pk_maskmov(e, ixp);
	case KGENOME_X86_I_AESENC: case KGENOME_X86_I_AESENCLAST: case KGENOME_X86_I_AESDEC:
	case KGENOME_X86_I_AESDECLAST: case KGENOME_X86_I_AESIMC: case KGENOME_X86_I_AESKEYGENASSIST:
		return pk_aes(e, ixp);
	case KGENOME_X86_I_EMMS: case KGENOME_X86_I_FEMMS: {
		/* EMMS marks every x87 register empty: the tag word is all ones */
		unsigned k;

		for (k = 0; k < 8u; k++)
			e->st_tag[k] = 0;
		return KGENOME_EMU_RUN_OK;
	}
	default:
		return kgenome_emu_run_vec_fp(e, ixp);
	}
}
