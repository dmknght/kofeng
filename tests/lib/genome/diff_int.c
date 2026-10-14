/*
 * diff_int - the interpreter's integer instruction set against the host CPU, systematically.
 *
 * cov_emu_int.c samples a few dozen random inputs per instruction. This file is the other kind of test:
 * for every integer opcode group the interpreter claims, EVERY pair of boundary operands (0, 1, 2, 0xF, 0x10,
 * 0x7F/0x80, the sign boundary, all ones and one less, the alternating patterns, a noise word), at each
 * operand size the instruction has (8, 16, 32 and 64 bits), with the carry flag clear and set, and the
 * counts a shift or rotate treats differently (0, 1, the width less one, the width, the width plus one, past
 * it, 255). Each vector is run on the host and in the interpreter (cov_native.h) and the general registers,
 * the memory written and the flags the architecture DEFINES are compared.
 *
 * UNDEFINED FLAGS ARE MASKED PER INSTRUCTION, from the Intel SDM, in one table (flags_of / the masks beside each
 * group), and nothing else is masked:
 *   ADD ADC SUB SBB CMP NEG INC DEC XADD CMPXCHG SCAS CMPS    CF PF AF ZF SF OF (INC and DEC leave CF, which is a
 *                                                              defined result too: unchanged)
 *   AND OR XOR TEST                                            CF=OF=0, PF ZF SF; AF undefined
 *   NOT MOV XCHG LEA MOVZX MOVSX BSWAP CBW.. CMOVcc SETcc     none modified: all six compared (unchanged)
 *   SHL SHR SAR     count 0: none modified. Else SF ZF PF; CF unless the count is >= the width (SHL/SHR);
 *                   OF for a count of 1 only; AF undefined
 *   ROL ROR RCL RCR count 0: none modified. Else CF; OF for a count of 1 only; SF ZF PF AF unchanged
 *   SHLD SHRD       as SHL for counts below the width (a count past the width of a 16 bit operand has an
 *                   undefined RESULT and is not generated)
 *   MUL IMUL        CF OF (SF ZF AF PF undefined);  DIV IDIV: all undefined
 *   BT BTS BTR BTC  CF (ZF unchanged; OF SF AF PF undefined)
 *   BSF BSR         ZF (CF OF SF AF PF undefined; the destination of a zero source is not compared)
 *   TZCNT LZCNT     CF ZF (OF SF PF AF undefined);  POPCNT: all six (CF OF SF AF PF are cleared)
 *   SAHF            CF PF AF ZF SF;  CMC STC CLC  CF (others unchanged)
 * The BCD adjusts (AAA AAS DAA DAS) exist only outside 64-bit mode and have no host to run on; they are compared
 * with the manual's algorithm over EVERY AL, four AH values and the four CF/AF states.
 *
 * Under a sanitizer the natively executed code is still plain code, so nothing is skipped; on a host that is not
 * x86-64 Linux the whole file is SKIPPED, visibly. Nothing here writes a file.
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

struct ib { uint8_t b[16]; unsigned n; };

static void build(struct ib *x, unsigned size, unsigned mand, unsigned opc, unsigned modrm, unsigned immn, uint32_t imm)
{
	unsigned i;

	x->n = 0;
	if (mand)
		x->b[x->n++] = (uint8_t)mand;
	if (size == 2)
		x->b[x->n++] = 0x66;
	if (size == 8)
		x->b[x->n++] = 0x48;
	if (opc > 0xffu)
		x->b[x->n++] = (uint8_t)(opc >> 8);
	x->b[x->n++] = (uint8_t)opc;
	x->b[x->n++] = (uint8_t)modrm;
	for (i = 0; i < immn; i++)
		x->b[x->n++] = (uint8_t)(imm >> (8 * i));
}

static const unsigned SZ[4] = { 1, 2, 4, 8 };

static uint64_t msk(unsigned size)
{
	return size >= 8 ? ~0ull : ((1ull << (size * 8u)) - 1ull);
}

#define NPOOL 14u
/* the boundary operands of a size */
static uint64_t pool(unsigned size, unsigned i)
{
	uint64_t m = msk(size);

	switch (i) {
	case 0:  return 0;
	case 1:  return 1;
	case 2:  return 2;
	case 3:  return 0xfull;
	case 4:  return 0x10ull;
	case 5:  return 0x7full & m;
	case 6:  return 0x80ull & m;
	case 7:  return m >> 1;
	case 8:  return (m >> 1) + 1ull;
	case 9:  return m - 1ull;
	case 10: return m;
	case 11: return 0x5555555555555555ull & m;
	case 12: return 0xaaaaaaaaaaaaaaaaull & m;
	default: return 0x0123456789abcdefull & m;
	}
}

/* garbage above the operand, so a write that must keep (or must clear) the upper bytes is seen */
static uint64_t junk(uint64_t v, unsigned size)
{
	return (v & msk(size)) | (cn_rng() & ~msk(size));
}

/* the flags going in: CF as asked, and noise in the rest (so an instruction that must leave a flag alone is checked) */
static void setfl(struct cn_io *in, unsigned cf)
{
	cn_put(in, CN_O_FL, ((cn_rng() & CN_FL_ARITH & ~CN_FL_CF) | (cf ? CN_FL_CF : 0ull)) | 2ull);
}

static void run(const char *name, const struct ib *x, const struct cn_io *in, uint64_t mask, int buf)
{
	(void)cn_case(&st, name, x->b, x->n, in, mask, 64, 0, buf);
}

static unsigned groups, vectors;

static void finish(const char *family)
{
	cn_print(family, &st);
	CK(st.native_ok == st.cases, "%s: the host ran every vector", family);
	CK(st.unsupported == 0, "%s: carried (%u refused)", family, st.unsupported);
	CK(st.diffs == 0, "%s: registers, memory and defined flags equal the CPU's (%u of %u differ)", family, st.diffs, st.cases);
	groups++;
	vectors += st.cases;
	memset(&st, 0, sizeof st);
}

/* ---- ALU -------------------------------------------------------------------------------- */

static const struct { unsigned opc; const char *nm; uint64_t mask; } ALU[] = {
	{ 0x01, "add", CN_FL_ARITH }, { 0x09, "or", CN_FL_ARITH & ~CN_FL_AF }, { 0x11, "adc", CN_FL_ARITH },
	{ 0x19, "sbb", CN_FL_ARITH }, { 0x21, "and", CN_FL_ARITH & ~CN_FL_AF }, { 0x29, "sub", CN_FL_ARITH },
	{ 0x31, "xor", CN_FL_ARITH & ~CN_FL_AF }, { 0x39, "cmp", CN_FL_ARITH }, { 0x85, "test", CN_FL_ARITH & ~CN_FL_AF }
};

static void t_alu_reg(void)
{
	unsigned o, z, a, b, cf, v;
	/* modrm: rax,rcx / and, for bytes, the legacy high registers (ah as destination, ah as source) */
	static const unsigned modrm[3] = { 0xc8, 0xc4, 0xe0 };

	for (o = 0; o < 9; o++)
		for (z = 0; z < 4; z++)
			for (v = 0; v < (z == 0 ? 3u : 1u); v++)
				for (a = 0; a < NPOOL; a++)
					for (b = 0; b < NPOOL; b++)
						for (cf = 0; cf < 2; cf++) {
							struct cn_io in;
							struct ib x;
							char nm[32];

							cn_input(&in, 0);
							cn_put(&in, CN_O_RAX, junk(pool(SZ[z], a), SZ[z]));
							cn_put(&in, CN_O_RCX, junk(pool(SZ[z], b), SZ[z]));
							setfl(&in, cf);
							build(&x, SZ[z], 0, z == 0 ? ALU[o].opc - 1u : ALU[o].opc, modrm[v], 0, 0);
							snprintf(nm, sizeof nm, "%s/%u", ALU[o].nm, SZ[z] * 8u);
							run(nm, &x, &in, ALU[o].mask, 0);
						}
	finish("alu register forms");
}

static void t_alu_imm(void)
{
	/* 80/81/83 /ext: add or adc sbb and sub xor cmp */
	static const struct { unsigned ext; uint64_t mask; } e[8] = {
		{ 0, CN_FL_ARITH }, { 1, CN_FL_ARITH & ~CN_FL_AF }, { 2, CN_FL_ARITH }, { 3, CN_FL_ARITH },
		{ 4, CN_FL_ARITH & ~CN_FL_AF }, { 5, CN_FL_ARITH }, { 6, CN_FL_ARITH & ~CN_FL_AF }, { 7, CN_FL_ARITH }
	};
	static const uint32_t imm[6] = { 0, 1, 0x7f, 0x80, 0xff, 0x7fffffffu };
	unsigned o, z, a, i, cf;

	for (o = 0; o < 8; o++)
		for (z = 0; z < 4; z++)
			for (a = 0; a < NPOOL; a++)
				for (i = 0; i < 6; i++)
					for (cf = 0; cf < 2; cf++) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z];

						cn_input(&in, 0);
						cn_put(&in, CN_O_RAX, junk(pool(size, a), size));
						setfl(&in, cf);
						if (size == 1)
							build(&x, 1, 0, 0x80, 0xc0u | (e[o].ext << 3), 1, imm[i]);
						else if (i < 5)    /* the sign extended imm8 form */
							build(&x, size, 0, 0x83, 0xc0u | (e[o].ext << 3), 1, imm[i]);
						else
							build(&x, size, 0, 0x81, 0xc0u | (e[o].ext << 3), size == 2 ? 2 : 4, imm[i]);
						run("alu imm", &x, &in, e[o].mask, 0);
					}
	finish("alu immediate forms");
}

static void t_alu_mem(void)
{
	unsigned o, z, a, b, dir;

	for (o = 0; o < 9; o++)
		for (z = 0; z < 4; z++)
			for (dir = 0; dir < 2; dir++)
				for (a = 0; a < NPOOL; a += 2)
					for (b = 1; b < NPOOL; b += 2) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z];
						uint64_t mv = pool(size, a);

						cn_input(&in, 0);
						cn_fill_buf(&in, 0);
						memcpy(in.raw + CN_O_BUF + 64, &mv, 8);
						cn_put(&in, CN_O_RAX, junk(pool(size, b), size));
						cn_put(&in, CN_O_RSI, CN_O_BUF + 64u);
						setfl(&in, (a + b) & 1u);
						/* op [rsi], rax (the store form) or op rax, [rsi] (the load form: opcode + 2) */
						build(&x, size, 0, (z == 0 ? ALU[o].opc - 1u : ALU[o].opc) + (dir && o != 8 ? 2u : 0u), 0x06, 0, 0);
						run("alu memory", &x, &in, ALU[o].mask, 1);
					}
	finish("alu memory forms");
}

static void t_unary(void)
{
	static const struct { unsigned opc, ext; const char *nm; } one[] = {
		{ 0xf7, 3, "neg" }, { 0xf7, 2, "not" }, { 0xff, 0, "inc" }, { 0xff, 1, "dec" }
	};
	unsigned o, z, a, cf, mem;

	for (o = 0; o < 4; o++)
		for (z = 0; z < 4; z++)
			for (a = 0; a < NPOOL; a++)
				for (cf = 0; cf < 2; cf++)
					for (mem = 0; mem < 2; mem++) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z];
						unsigned opc = one[o].opc == 0xf7 ? (size == 1 ? 0xf6u : 0xf7u) : (size == 1 ? 0xfeu : 0xffu);
						uint64_t v = pool(size, a);

						cn_input(&in, 0);
						cn_fill_buf(&in, 0);
						cn_put(&in, CN_O_RAX, junk(v, size));
						memcpy(in.raw + CN_O_BUF + 32, &v, 8);
						cn_put(&in, CN_O_RSI, CN_O_BUF + 32u);
						setfl(&in, cf);
						build(&x, size, 0, opc, (mem ? 0x00u : 0xc0u) | (one[o].ext << 3) | (mem ? 6u : 0u), 0, 0);
						run(one[o].nm, &x, &in, CN_FL_ARITH, (int)mem);
					}
	finish("neg not inc dec");
}

/* ---- shifts and rotates ------------------------------------------------------------------- */

static uint64_t shift_flags(unsigned ext, unsigned size, unsigned count)
{
	unsigned w = size * 8u, c = count & (size == 8 ? 63u : 31u);
	uint64_t m;

	if (!c)
		return CN_FL_ARITH;                        /* a zero count modifies no flag */
	if (ext < 4) {                                     /* ROL ROR RCL RCR */
		m = CN_FL_CF | CN_FL_SF | CN_FL_ZF | CN_FL_PF | CN_FL_AF;
		return c == 1 ? m | CN_FL_OF : m;
	}
	m = CN_FL_SF | CN_FL_ZF | CN_FL_PF;                /* SHL SHR SAR */
	if (ext == 7 || c < w)
		m |= CN_FL_CF;
	if (c == 1)
		m |= CN_FL_OF;
	return m;
}

static void t_shifts(void)
{
	static const struct { unsigned ext; const char *nm; } op[] = {
		{ 0, "rol" }, { 1, "ror" }, { 2, "rcl" }, { 3, "rcr" }, { 4, "shl" }, { 5, "shr" }, { 7, "sar" }
	};
	static const unsigned cnt[] = { 0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 255 };
	unsigned o, z, c, a, cf, form;

	for (o = 0; o < 7; o++)
		for (z = 0; z < 4; z++)
			for (c = 0; c < sizeof cnt / sizeof cnt[0]; c++)
				for (a = 0; a < NPOOL; a++)
					for (cf = 0; cf < 2; cf++)
						for (form = 0; form < 2; form++) {
							struct cn_io in;
							struct ib x;
							unsigned size = SZ[z];
							char nm[32];

							cn_input(&in, 0);
							cn_put(&in, CN_O_RAX, junk(pool(size, a), size));
							cn_put(&in, CN_O_RCX, junk(cnt[c], 1));
							setfl(&in, cf);
							if (form)       /* by cl */
								build(&x, size, 0, size == 1 ? 0xd2u : 0xd3u, 0xc0u | (op[o].ext << 3), 0, 0);
							else            /* by imm8 */
								build(&x, size, 0, size == 1 ? 0xc0u : 0xc1u, 0xc0u | (op[o].ext << 3), 1, cnt[c]);
							snprintf(nm, sizeof nm, "%s/%u", op[o].nm, size * 8u);
							run(nm, &x, &in, shift_flags(op[o].ext, size, cnt[c]), 0);
						}
	finish("shifts and rotates");
}

static void t_dshift(void)
{
	unsigned d, z, c, a, b, form;
	static const unsigned cnt[] = { 0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 63 };

	for (d = 0; d < 2; d++)
		for (z = 1; z < 4; z++)
			for (c = 0; c < sizeof cnt / sizeof cnt[0]; c++)
				for (a = 0; a < NPOOL; a += 3)
					for (b = 1; b < NPOOL; b += 3)
						for (form = 0; form < 2; form++) {
							struct cn_io in;
							struct ib x;
							unsigned size = SZ[z], w = size * 8u;
							unsigned k = cnt[c] & (size == 8 ? 63u : 31u);
							uint64_t mk;

							if (cnt[c] >= w && cnt[c] != 0)
								continue;       /* a count past the width: undefined result */
							cn_input(&in, 0);
							cn_put(&in, CN_O_RAX, junk(pool(size, a), size));
							cn_put(&in, CN_O_RDX, junk(pool(size, b), size));
							cn_put(&in, CN_O_RCX, cnt[c]);
							setfl(&in, (a + b) & 1u);
							mk = k ? (CN_FL_CF | CN_FL_SF | CN_FL_ZF | CN_FL_PF) | (k == 1 ? CN_FL_OF : 0ull) : CN_FL_ARITH;
							if (form)
								build(&x, size, 0, d ? 0x0fadu : 0x0fa5u, 0xd0, 0, 0);
							else
								build(&x, size, 0, d ? 0x0facu : 0x0fa4u, 0xd0, 1, cnt[c]);
							run(d ? "shrd" : "shld", &x, &in, mk, 0);
						}
	finish("shld shrd");
}

/* ---- multiply and divide ------------------------------------------------------------------- */

static void t_mul(void)
{
	unsigned z, a, b, which, f;

	for (which = 0; which < 3; which++)
		for (z = 0; z < 4; z++)
			for (a = 0; a < NPOOL; a++)
				for (b = 0; b < NPOOL; b++)
					for (f = 0; f < (which == 2 ? 3u : 1u); f++) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z];

						if (which == 2 && size == 1)
							continue;
						cn_input(&in, 0);
						cn_put(&in, CN_O_RAX, junk(pool(size, a), size));
						cn_put(&in, CN_O_RCX, junk(pool(size, b), size));
						cn_put(&in, CN_O_RDX, cn_rng());
						setfl(&in, (a ^ b) & 1u);
						if (which == 0)
							build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, 0xe1, 0, 0);          /* mul cl */
						else if (which == 1)
							build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, 0xe9, 0, 0);          /* imul cl (one operand) */
						else if (f == 0)
							build(&x, size, 0, 0x0fafu, 0xc1, 0, 0);                            /* imul rax, rcx */
						else if (f == 1)
							build(&x, size, 0, 0x6bu, 0xc1, 1, (uint32_t)pool(1, b));           /* imul rax, rcx, imm8 */
						else
							build(&x, size, 0, 0x69u, 0xc1, size == 2 ? 2 : 4, (uint32_t)pool(4, b));   /* imul rax, rcx, imm */
						run(which == 0 ? "mul" : which == 1 ? "imul1" : "imul2/3", &x, &in, CN_FL_CF | CN_FL_OF, 0);
					}
	finish("mul imul");
}

/* a divisor, a quotient and a remainder that fit, composed into the dividend the instruction reads */
static int mk_div(unsigned size, int sgn, uint64_t *lo, uint64_t *hi, uint64_t *dv)
{
	unsigned bits = size * 8u;
	uint64_t m = msk(size);
	uint64_t x = pool(size, (unsigned)(cn_rng() % NPOOL)), y = pool(size, (unsigned)(cn_rng() % NPOOL));

	if (!sgn) {
		uint64_t d = x ? x : 1, q = y, r;
		unsigned __int128 n;

		if (size == 8 && d > 1)
			q %= (UINT64_MAX / d);
		r = cn_rng() % d;
		n = (unsigned __int128)q * d + r;
		*lo = size == 1 ? (uint64_t)n & 0xffffu : (uint64_t)n & m;
		*hi = (size == 1 || size == 8) ? 0 : (uint64_t)(n >> bits) & m;
		*dv = d;
		return 1;
	} else {
		__int128 lim = (__int128)1 << (bits - 1), sd, sq, sr, n;

		sd = size == 8 ? (__int128)(int64_t)x : (__int128)(int64_t)((x ^ (uint64_t)lim) - (uint64_t)lim);
		sq = size == 8 ? (__int128)(int64_t)y : (__int128)(int64_t)((y ^ (uint64_t)lim) - (uint64_t)lim);
		if (sd == 0)
			sd = 1;
		if (size == 8) {
			if (sd < 0)
				sd = -sd;
			if (sd == 0 || sd > INT64_MAX)
				sd = 1;
			if (sq < 0)
				sq = -(sq + 1);
			sq %= (__int128)(INT64_MAX / (int64_t)sd);
			sr = (__int128)(cn_rng() % (uint64_t)sd);
		} else {
			__int128 ad = sd < 0 ? -sd : sd;

			sr = (__int128)(cn_rng() % (uint64_t)ad);
			if ((sq < 0) != (sd < 0) && sq != 0)
				sr = -sr;
			if (sq == 0)
				sr = sr < 0 ? -sr : sr;
		}
		n = sq * sd + sr;
		if (size == 8 && n < 0)
			return 0;
		/* the quotient has to fit the signed range of the size */
		if (sq >= lim || sq < -lim)
			return 0;
		*lo = size == 1 ? (uint64_t)n & 0xffffu : (uint64_t)n & m;
		*hi = (size == 1 || size == 8) ? 0 : (uint64_t)(n >> bits) & m;
		*dv = (uint64_t)sd & m;
		return 1;
	}
}

static void t_div(void)
{
	unsigned z, i, sgn;

	for (sgn = 0; sgn < 2; sgn++)
		for (z = 0; z < 4; z++)
			for (i = 0; i < 600; i++) {
				struct cn_io in;
				struct ib x;
				uint64_t lo, hi, d;
				unsigned size = SZ[z];

				cn_input(&in, 0);
				if (!mk_div(size, (int)sgn, &lo, &hi, &d))
					continue;
				cn_put(&in, CN_O_RAX, size < 4 ? lo | (cn_rng() & ~msk(size == 1 ? 2 : size)) : lo);
				cn_put(&in, CN_O_RDX, size == 1 ? cn_rng() : hi);
				cn_put(&in, CN_O_RCX, d | (size < 4 ? cn_rng() & ~msk(size) : 0));
				build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, sgn ? 0xf9u : 0xf1u, 0, 0);
				run(sgn ? "idiv" : "div", &x, &in, 0, 0);
			}
	finish("div idiv");
}

/* ---- bit tests and scans -------------------------------------------------------------------- */

static void t_bt(void)
{
	static const struct { unsigned reg, ext; const char *nm; } op[] = {
		{ 0x0fa3, 4, "bt" }, { 0x0fab, 5, "bts" }, { 0x0fb3, 6, "btr" }, { 0x0fbb, 7, "btc" }
	};
	static const int64_t off[] = { 0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 255, -1, -8, -9, -16, -17, -32, -64, -65, 200, -200 };
	unsigned o, z, a, k, form;

	for (o = 0; o < 4; o++)
		for (z = 1; z < 4; z++)
			for (a = 0; a < NPOOL; a++)
				for (k = 0; k < sizeof off / sizeof off[0]; k++)
					for (form = 0; form < 4; form++) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z];
						uint64_t v = pool(size, a);

						cn_input(&in, 0);
						cn_fill_buf(&in, 0);
						cn_put(&in, CN_O_RAX, junk(v, size));
						memcpy(in.raw + CN_O_BUF + 1024, &v, 8);
						cn_put(&in, CN_O_RCX, (uint64_t)off[k]);
						setfl(&in, (a + k) & 1u);
						if (form == 0) {         /* bt rax, rcx */
							build(&x, size, 0, op[o].reg, 0xc8, 0, 0);
						} else if (form == 1) {  /* bt rax, imm8 */
							build(&x, size, 0, 0x0fbau, 0xc0u | (op[o].ext << 3), 1, (uint32_t)off[k] & 0xffu);
						} else if (form == 2) {  /* bt [rsi], imm8 */
							cn_put(&in, CN_O_RSI, CN_O_BUF + 1024u);
							build(&x, size, 0, 0x0fbau, 0x06u | (op[o].ext << 3), 1, (uint32_t)off[k] & 0xffu);
						} else {                 /* bt [rsi], rcx: the signed bit string form */
							cn_put(&in, CN_O_RSI, CN_O_BUF + 1024u);
							build(&x, size, 0, op[o].reg, 0x0e, 0, 0);
						}
						run(op[o].nm, &x, &in, CN_FL_CF | CN_FL_ZF, form >= 2);
					}
	finish("bt bts btr btc");
}

static void t_scan(void)
{
	static const struct { unsigned pfx, opc; const char *nm; uint64_t mask; int nonzero; } op[] = {
		{ 0, 0x0fbc, "bsf", CN_FL_ZF, 1 }, { 0, 0x0fbd, "bsr", CN_FL_ZF, 1 },
		{ 0xf3, 0x0fbc, "tzcnt", CN_FL_CF | CN_FL_ZF, 0 }, { 0xf3, 0x0fbd, "lzcnt", CN_FL_CF | CN_FL_ZF, 0 },
		{ 0xf3, 0x0fb8, "popcnt", CN_FL_ARITH, 0 }
	};
	unsigned o, z, a, mem;

	for (o = 0; o < 5; o++)
		for (z = 1; z < 4; z++)
			for (a = 0; a < NPOOL; a++)
				for (mem = 0; mem < 2; mem++) {
					struct cn_io in;
					struct ib x;
					unsigned size = SZ[z];
					uint64_t v = pool(size, a);

					cn_input(&in, 0);
					cn_fill_buf(&in, 0);
					if (!v && op[o].nonzero) {
						/* BSF/BSR of zero: ZF is set and the destination is architecturally undefined */
						struct cn_io na, nb;
						struct cn_emu r;

						cn_put(&in, CN_O_RCX, 0);
						build(&x, size, op[o].pfx, op[o].opc, 0xc1, 0, 0);
						if (!cn_native(x.b, x.n, &in, &na) || !cn_emulate(x.b, x.n, &in, &nb, 64, &r) || !r.done)
							CK(0, "%s of zero ran", op[o].nm);
						else
							CK((cn_get(&na, 88) & CN_FL_ZF) && (cn_get(&nb, 88) & CN_FL_ZF), "%s/%u of zero sets ZF on both",
							   op[o].nm, size * 8u);
						continue;
					}
					cn_put(&in, CN_O_RAX, cn_rng());
					cn_put(&in, CN_O_RCX, v);
					memcpy(in.raw + CN_O_BUF, &v, 8);
					cn_put(&in, CN_O_RSI, CN_O_BUF);
					setfl(&in, (a & 1u));
					build(&x, size, op[o].pfx, op[o].opc, mem ? 0x06u : 0xc1u, 0, 0);
					run(op[o].nm, &x, &in, op[o].mask, 0);
				}
	finish("bsf bsr tzcnt lzcnt popcnt");
}

/* ---- conditions ----------------------------------------------------------------------------- */

/* the 32 states of CF, PF, ZF, SF and OF; AF is no condition's input */
static uint64_t cond_flags(unsigned s)
{
	return ((s & 1u) ? CN_FL_CF : 0ull) | ((s & 2u) ? CN_FL_PF : 0ull) | ((s & 4u) ? CN_FL_ZF : 0ull) |
	       ((s & 8u) ? CN_FL_SF : 0ull) | ((s & 16u) ? CN_FL_OF : 0ull) | 2ull;
}

static void t_conditions(void)
{
	unsigned cc, s, z, k;

	for (cc = 0; cc < 16; cc++)
		for (s = 0; s < 32; s++) {
			struct cn_io in;
			struct ib x;
			uint8_t j[8];

			/* cmovcc: 16, 32 and 64 bits, the source a register, the condition decided by the flags alone */
			for (z = 1; z < 4; z++) {
				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, cn_rng());
				cn_put(&in, CN_O_RCX, cn_rng());
				cn_put(&in, CN_O_FL, cond_flags(s) | (cn_rng() & CN_FL_AF));
				build(&x, SZ[z], 0, 0x0f40u + cc + 0u, 0xc1, 0, 0);
				run("cmovcc", &x, &in, CN_FL_ARITH, 0);
			}
			/* setcc al */
			cn_input(&in, 0);
			cn_put(&in, CN_O_RAX, cn_rng());
			cn_put(&in, CN_O_FL, cond_flags(s) | (cn_rng() & CN_FL_AF));
			x.b[0] = 0x0f;
			x.b[1] = (uint8_t)(0x90u + cc);
			x.b[2] = 0xc0;
			x.n = 3;
			run("setcc", &x, &in, CN_FL_ARITH, 0);
			/* jcc +5; mov eax, 1 ; (taken: eax stays what it was) */
			cn_input(&in, 0);
			cn_put(&in, CN_O_RAX, 0x100000000ull | (cn_rng() & 0xff));
			cn_put(&in, CN_O_FL, cond_flags(s) | (cn_rng() & CN_FL_AF));
			j[0] = (uint8_t)(0x70u + cc);
			j[1] = 5;
			j[2] = 0xb8; j[3] = 1; j[4] = 0; j[5] = 0; j[6] = 0;
			x.n = 7;
			for (k = 0; k < 7; k++)
				x.b[k] = j[k];
			run("jcc", &x, &in, CN_FL_ARITH, 0);
		}
	finish("cmovcc setcc jcc");
}

/* ---- the exchanges ------------------------------------------------------------------------- */

static void t_exchange(void)
{
	unsigned which, z, a, b, mem;

	for (which = 0; which < 3; which++)       /* cmpxchg, xadd, xchg */
		for (z = 0; z < 4; z++)
			for (a = 0; a < NPOOL; a++)
				for (b = 0; b < NPOOL; b += 2)
					for (mem = 0; mem < 2; mem++) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z];
						uint64_t v = pool(size, a);
						unsigned opc = which == 0 ? (size == 1 ? 0x0fb0u : 0x0fb1u)
							     : which == 1 ? (size == 1 ? 0x0fc0u : 0x0fc1u)
							     : (size == 1 ? 0x86u : 0x87u);

						cn_input(&in, 0);
						cn_fill_buf(&in, 0);
						cn_put(&in, CN_O_RAX, junk((a & 1u) ? v : pool(size, b), size));   /* often equal */
						cn_put(&in, CN_O_RDX, junk(v, size));
						cn_put(&in, CN_O_RCX, junk(pool(size, b), size));
						memcpy(in.raw + CN_O_BUF + 32, &v, 8);
						cn_put(&in, CN_O_RSI, CN_O_BUF + 32u);
						setfl(&in, (a + b) & 1u);
						if (mem)
							build(&x, size, 0, opc, 0x0e, 0, 0);          /* op [rsi], rcx */
						else
							build(&x, size, 0, opc, 0xca, 0, 0);          /* op rdx, rcx */
						run(which == 0 ? "cmpxchg" : which == 1 ? "xadd" : "xchg", &x, &in, CN_FL_ARITH, (int)mem);
					}
	finish("cmpxchg xadd xchg");
}

/* ---- string instructions ------------------------------------------------------------------- */

static void t_string(void)
{
	static const struct { unsigned opc8, opc; const char *nm; } op[] = {
		{ 0xa4, 0xa5, "movs" }, { 0xaa, 0xab, "stos" }, { 0xac, 0xad, "lods" }, { 0xae, 0xaf, "scas" }, { 0xa6, 0xa7, "cmps" }
	};
	static const unsigned pfx[3] = { 0, 0xf3, 0xf2 };
	unsigned o, p, z, i, df;

	for (o = 0; o < 5; o++)
		for (p = 0; p < 3; p++)
			for (z = 0; z < 4; z++)
				for (df = 0; df < 2; df++)
					for (i = 0; i < 48; i++) {
						struct cn_io in;
						struct ib x;
						unsigned size = SZ[z], cnt = i % 24u, span = 24u * size, at = (unsigned)(cn_rng() % 24u);
						uint64_t v = pool(size, i % NPOOL);

						cn_input(&in, (int)df);
						cn_fill_buf(&in, 2);
						/* the two strings equal up to `at`, so REPE/REPNE stop at every position */
						memcpy(in.raw + CN_O_BUF + 1200, in.raw + CN_O_BUF + 400, 24u * 8u);
						if (at < 24u)
							in.raw[CN_O_BUF + 1200 + at * size] ^= 1u;
						cn_put(&in, CN_O_RAX, (i & 1u) ? v : (uint64_t)(in.raw[CN_O_BUF + 400 + at * size] & 1u));
						cn_put(&in, CN_O_RCX, cnt);
						cn_put(&in, CN_O_RSI, CN_O_BUF + 400u + (df ? span - size : 0u));
						cn_put(&in, CN_O_RDI, CN_O_BUF + 1200u + (df ? span - size : 0u));
						x.n = 0;
						if (pfx[p])
							x.b[x.n++] = (uint8_t)pfx[p];
						if (size == 2)
							x.b[x.n++] = 0x66;
						if (size == 8)
							x.b[x.n++] = 0x48;
						x.b[x.n++] = (uint8_t)(size == 1 ? op[o].opc8 : op[o].opc);
						run(op[o].nm, &x, &in, CN_FL_ARITH, 1);
					}
	finish("string instructions");
}

/* ---- the single instructions that move or widen, and the flag instructions ------------------- */

static void t_misc(void)
{
	static const struct { uint8_t b[8]; unsigned n; const char *nm; uint64_t mask; } c[] = {
		{ { 0x48, 0x0f, 0xc8 }, 3, "bswap rax", CN_FL_ARITH }, { { 0x0f, 0xc8 }, 2, "bswap eax", CN_FL_ARITH },
		{ { 0x0f, 0xb6, 0xc1 }, 3, "movzx eax,cl", CN_FL_ARITH }, { { 0x0f, 0xb7, 0xc1 }, 3, "movzx eax,cx", CN_FL_ARITH },
		{ { 0x0f, 0xbe, 0xc1 }, 3, "movsx eax,cl", CN_FL_ARITH }, { { 0x0f, 0xbf, 0xc1 }, 3, "movsx eax,cx", CN_FL_ARITH },
		{ { 0x48, 0x0f, 0xb6, 0xc1 }, 4, "movzx rax,cl", CN_FL_ARITH }, { { 0x48, 0x0f, 0xb7, 0xc1 }, 4, "movzx rax,cx", CN_FL_ARITH },
		{ { 0x48, 0x0f, 0xbe, 0xc1 }, 4, "movsx rax,cl", CN_FL_ARITH }, { { 0x48, 0x0f, 0xbf, 0xc1 }, 4, "movsx rax,cx", CN_FL_ARITH },
		{ { 0x48, 0x63, 0xc1 }, 3, "movsxd rax,ecx", CN_FL_ARITH }, { { 0x66, 0x0f, 0xb6, 0xc1 }, 4, "movzx ax,cl", CN_FL_ARITH },
		{ { 0x66, 0x0f, 0xbe, 0xc1 }, 4, "movsx ax,cl", CN_FL_ARITH },
		{ { 0x98 }, 1, "cwde", CN_FL_ARITH }, { { 0x48, 0x98 }, 2, "cdqe", CN_FL_ARITH }, { { 0x66, 0x98 }, 2, "cbw", CN_FL_ARITH },
		{ { 0x99 }, 1, "cdq", CN_FL_ARITH }, { { 0x48, 0x99 }, 2, "cqo", CN_FL_ARITH }, { { 0x66, 0x99 }, 2, "cwd", CN_FL_ARITH },
		{ { 0x48, 0x91 }, 2, "xchg rax,rcx", CN_FL_ARITH }, { { 0x91 }, 1, "xchg eax,ecx", CN_FL_ARITH },
		{ { 0x9f }, 1, "lahf", CN_FL_ARITH }, { { 0x9e }, 1, "sahf", CN_FL_ARITH },
		{ { 0xf5 }, 1, "cmc", CN_FL_ARITH }, { { 0xf9 }, 1, "stc", CN_FL_ARITH }, { { 0xf8 }, 1, "clc", CN_FL_ARITH },
		{ { 0x48, 0x8d, 0x44, 0x91, 0x10 }, 5, "lea rax,[rcx+rdx*4+16]", CN_FL_ARITH },
		{ { 0x8d, 0x04, 0x51 }, 3, "lea eax,[rcx+rdx*2]", CN_FL_ARITH },
		{ { 0x66, 0x8d, 0x44, 0x91, 0x10 }, 5, "lea ax,[rcx+rdx*4+16]", CN_FL_ARITH },
		{ { 0x89, 0xc8 }, 2, "mov eax,ecx", CN_FL_ARITH }, { { 0x66, 0x89, 0xc8 }, 3, "mov ax,cx", CN_FL_ARITH },
		{ { 0x88, 0xc8 }, 2, "mov al,cl", CN_FL_ARITH }, { { 0x88, 0xe0 }, 2, "mov al,ah", CN_FL_ARITH },
		{ { 0x88, 0xc4 }, 2, "mov ah,al", CN_FL_ARITH }, { { 0x8a, 0xe1 }, 2, "mov ah,cl", CN_FL_ARITH }
	};
	unsigned o, i;

	for (o = 0; o < sizeof c / sizeof c[0]; o++)
		for (i = 0; i < 120; i++) {
			struct cn_io in;
			uint8_t code[8];

			cn_input(&in, 0);
			cn_put(&in, CN_O_RAX, pool(8, i % NPOOL) ^ (i >= NPOOL ? cn_rng() : 0));
			cn_put(&in, CN_O_RCX, pool(8, (i / 2u + 5u) % NPOOL) ^ (i >= NPOOL * 2u ? cn_rng() : 0));
			cn_put(&in, CN_O_RDX, cn_rng() & 0xffffull);
			setfl(&in, i & 1u);
			memcpy(code, c[o].b, c[o].n);
			(void)cn_case(&st, c[o].nm, code, c[o].n, &in, c[o].mask, 64, 0, 0);
		}
	finish("moves, widening, flags");
}

/* ---- the instructions with no host: AAA AAS DAA DAS against the manual's algorithm -------------- */

static void bcd_ref(unsigned op, uint32_t eax, uint32_t fl, uint32_t *oeax, uint32_t *ofl)
{
	unsigned al = eax & 0xff, ah = (eax >> 8) & 0xff, oal = al;
	int af = (fl & CN_FL_AF) != 0, cf = (fl & CN_FL_CF) != 0, ncf = 0, naf = 0;

	if (op < 2) {                                          /* AAA, AAS */
		if ((al & 15u) > 9u || af) {
			if (op == 0) { al = (al + 6u) & 0xff; ah = (ah + 1u) & 0xff; }
			else         { al = (al - 6u) & 0xff; ah = (ah - 1u) & 0xff; }
			ncf = naf = 1;
		}
		al &= 15u;
		*oeax = (eax & ~0xffffu) | (ah << 8) | al;
		*ofl = (ncf ? CN_FL_CF : 0) | (naf ? CN_FL_AF : 0);
		return;
	}
	{                                                      /* DAA, DAS */
		int sub = op == 3;

		if ((al & 15u) > 9u || af) {
			al = sub ? (al - 6u) & 0xff : (al + 6u) & 0xff;
			naf = 1;
			ncf = cf || (sub && oal < 6u) || (!sub && oal + 6u > 0xff);
		}
		if (oal > 0x99u || cf) {
			al = sub ? (al - 0x60u) & 0xff : (al + 0x60u) & 0xff;
			ncf = 1;
		}
		*oeax = (eax & ~0xffu) | al;
		*ofl = (ncf ? CN_FL_CF : 0) | (naf ? CN_FL_AF : 0) | (al == 0 ? CN_FL_ZF : 0) | ((al & 0x80u) ? CN_FL_SF : 0) |
		       ((__builtin_popcount(al) & 1) ? 0 : CN_FL_PF);
	}
}

static void t_bcd(void)
{
	static const uint8_t opc[4] = { 0x37, 0x3f, 0x27, 0x2f };
	static const char *const nm[4] = { "aaa", "aas", "daa", "das" };
	static const uint32_t ahv[4] = { 0x00, 0x01, 0x7f, 0xff };
	unsigned o, al, ahi, fs, bad;
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = 32;
	cfg.max_insn = 100000000u;
	e = kgenome_emu_new(&cfg);
	if (!e) {
		CK(0, "emulator");
		return;
	}
	kgenome_emu_map(e, CN_CODE, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X | KGENOME_EMU_W);
	kgenome_emu_map(e, CN_STACK, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	for (o = 0; o < 4; o++) {
		unsigned n = 0, ok = 0;

		bad = 0;
		for (al = 0; al < 256; al++)
			for (ahi = 0; ahi < 4; ahi++)
				for (fs = 0; fs < 4; fs++) {
					uint32_t eax = 0x12340000u | (ahv[ahi] << 8) | al, fl = 2u | ((fs & 1u) ? CN_FL_CF : 0u) | ((fs & 2u) ? CN_FL_AF : 0u);
					uint32_t want_eax, want_fl, got_eax, got_fl, defined = o < 2 ? (CN_FL_CF | CN_FL_AF) : CN_FL_ARITH & ~CN_FL_OF;
					uint8_t code[16];
					unsigned k = 0;

					code[k++] = 0x68; memcpy(code + k, &fl, 4); k += 4;     /* push imm32 */
					code[k++] = 0x9d;                                         /* popfd */
					code[k++] = opc[o];
					code[k++] = 0x9c;                                         /* pushfd */
					code[k++] = 0x5a;                                         /* pop edx */
					code[k++] = 0xf4;                                         /* hlt */
					kgenome_emu_write(e, CN_CODE, code, k);
					kgenome_emu_set_rip(e, CN_CODE);
					kgenome_emu_set_reg(e, KGENOME_EMU_RSP, CN_STACK + 0x800);
					kgenome_emu_set_reg(e, KGENOME_EMU_RAX, eax);
					kgenome_emu_set_reg(e, KGENOME_EMU_RDX, 0);
					kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 1000u);
					(void)kgenome_emu_run(e);
					n++;
					if (kgenome_emu_get_rip(e) != CN_CODE + k - 1u) {
						CK(0, "%s: the interpreter stopped (%s)", nm[o], kgenome_emu_stop_detail(e));
						kgenome_emu_free(e);
						return;
					}
					ok++;
					got_eax = (uint32_t)kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
					got_fl = (uint32_t)kgenome_emu_get_reg(e, KGENOME_EMU_RDX);
					bcd_ref(o, eax, fl, &want_eax, &want_fl);
					if (got_eax != want_eax || (got_fl & defined) != (want_fl & defined)) {
						if (!bad++)
							printf("      %s eax=%#x fl=%#x: got eax=%#x fl=%#x want eax=%#x fl=%#x\n", nm[o], eax, fl,
							       got_eax, got_fl & defined, want_eax, want_fl & defined);
					}
				}
		printf("  %-22s %6u case(s), %u differ\n", nm[o], n, bad);
		CK(bad == 0 && ok == n, "%s: all %u vectors equal the manual's algorithm (%u differ)", nm[o], n, bad);
		groups++;
		vectors += n;
	}
	kgenome_emu_free(e);
}

int main(void)
{
	cn_rng_state = 0x4449464649544e54ull;
	if (!CN_HOST) {
		printf("diff_int: SKIPPED (the host is not x86-64 Linux, so there is no reference to run)\n");
		return 0;
	}
	t_alu_reg();
	t_alu_imm();
	t_alu_mem();
	t_unary();
	t_shifts();
	t_dshift();
	t_mul();
	t_div();
	t_bt();
	t_scan();
	t_conditions();
	t_exchange();
	t_string();
	t_misc();
	t_bcd();
	printf("diff_int: %u group(s), %u vector(s)\n", groups, vectors);
	CK(vectors > 100000u, "the sweep is the size it claims (%u vectors)", vectors);
	if (fails) {
		printf("diff_int: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_int: ok\n");
	return 0;
}
