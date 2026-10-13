/*
 * hostile_decoders - the instruction decoders against every byte stream a hostile
 * file can put in front of them.
 *
 * THE PROPERTIES, asserted for each decoder entry point:
 *
 *   never reads past the length it was given   the bytes handed in end at a
 *                                              PROT_NONE page (hk.h gb_put), so a
 *                                              read one byte past n faults here
 *   never answers longer than it was given     ret <= n, len <= n, len <= 15 on x86
 *   truncation is refused, not guessed         the first n bytes of an instruction
 *                                              of L > n bytes decode to "not OK"
 *   the decode is a function of the bytes it   decoding at n == L gives the same
 *   consumed                                   instruction as decoding at n == 16
 *   accessors and the formatter stay inside    operands <= KGENOME_X86_MAX_OPS, the
 *   what they were handed                      text fits the buffer it was given
 *
 * THE STREAMS. x86: every (b0,b1) pair with a random tail, in both modes; bytes
 * drawn from the prefix/escape/VEX/EVEX/x87/far-branch set that is where decoders
 * go wrong; runs of 15..32 identical prefixes. ARM, Thumb, A64: random words and
 * the exhaustive index key spaces (every key of the first-level lookup of the
 * ARM and Thumb tables, with random fill); every length 0..16 of the byte stream
 * for every architecture the cell front end names, big- and little-endian, at
 * addresses that wrap the 64-bit space.
 *
 * Deterministic: fixed seeds. Each family runs in a forked child (hk_isolated), so
 * a fault in the product is a result of this file, not the end of it.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>
#include <genotype/arm32/arm32.h>
#include <genotype/arm32/thumb.h>
#include <genotype/arm64/arm64.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_gb G, T;       /* the code bytes and the text buffer */
static uint64_t n_decoded, n_ok;

static void bad(const char *what, uint64_t ctx)
{
	static unsigned seen;

	if (seen++ < 12)
		printf("  FAIL %s (ctx %#llx)\n", what, (unsigned long long)ctx);
	hk_fails++;
}

/* ---- x86 ---------------------------------------------------------------------------- */

static void x86_check_one(const uint8_t *s16, int mode)
{
	struct kgenome_x86_insn in, in2;
	struct kgenome_x86_op ops[KGENOME_X86_MAX_OPS];
	struct kgenome_x86_sweep sw;
	enum kgenome_status st, st2;
	unsigned n, len = 0, k, nops;

	st = kgenome_x86_decode(&in, gb_put(&G, s16, 16), 16, mode);
	n_decoded++;
	if (st == KGENOME_OK) {
		len = in.len;
		n_ok++;
		if (len < 1 || len > 15)
			bad("x86: decoded length outside 1..15", s16[0]);
		if (in.mode != mode)
			bad("x86: mode not preserved", s16[0]);
	}
	/* every shorter prefix: refused when the instruction needs more bytes; and when it
	 * has all its bytes the answer is the same instruction, read with no byte beyond it */
	for (n = 0; n <= 16; n++) {
		const uint8_t *p = gb_put(&G, s16, n);

		st2 = kgenome_x86_decode(&in2, p, n, mode);
		if (st2 == KGENOME_OK) {
			if (in2.len > n)
				bad("x86: length > bytes given", n);
			if (st == KGENOME_OK && n < len)
				bad("x86: decoded an instruction from fewer bytes than it has", n);
			if (st == KGENOME_OK && n >= len &&
			    (in2.id != in.id || in2.len != in.len || in2.flags != in.flags))
				bad("x86: answer depends on bytes past the instruction", n);
		} else if (st == KGENOME_OK && n >= len && len <= n) {
			bad("x86: refused an instruction whose every byte was given", n);
		}
	}
	if (st != KGENOME_OK)
		return;
	nops = kgenome_x86_nops(&in);
	if (nops > KGENOME_X86_MAX_OPS) {
		bad("x86: nops past the operand array", nops);
		return;
	}
	(void)kgenome_x86_cat(&in);
	(void)kgenome_x86_cond(&in);
	{
		unsigned a = kgenome_x86_asz(&in);
		if (a != 2 && a != 4 && a != 8)
			bad("x86: address size not 2, 4 or 8", a);
	}
	(void)kgenome_x86_repeated(&in);
	if (kgenome_x86_nform(&in) > nops + 0u && kgenome_x86_nform(&in) > KGENOME_X86_MAX_OPS)
		bad("x86: nform past the operand array", kgenome_x86_nform(&in));
	if (kgenome_x86_nexp(&in) > nops)
		bad("x86: more explicit operands than operands", kgenome_x86_nexp(&in));
	(void)kgenome_x86_wgpr(&in);
	memset(ops, 0, sizeof ops);
	kgenome_x86_operands(&in, ops);
	for (k = 0; k < nops; k++) {
		struct kgenome_x86_op one;
		kgenome_x86_operand(&in, k, &one);
		if (one.type != ops[k].type || one.reg != ops[k].reg || one.v != ops[k].v)
			bad("x86: operand(k) differs from operands()[k]", k);
		if (one.type > KGENOME_X86_OP_DFV)
			bad("x86: operand type out of range", one.type);
		(void)kgenome_x86_gpr_of(&one);
	}
	/* the text fits any buffer it is given: placed so the byte after cap is the guard */
	{
		static const size_t caps[] = { 0, 1, 2, 3, 8, 31, KGENOME_X86_TEXT };
		unsigned c;

		for (c = 0; c < sizeof caps / sizeof caps[0]; c++) {
			char *b = (char *)gb_put(&T, NULL, caps[c]);
			size_t r = kgenome_x86_format(&in, 0x140001000ull, b, caps[c]);

			if (r >= (caps[c] ? caps[c] : 1u) && r != 0)
				bad("x86: format wrote more than the buffer holds", caps[c]);
			if (caps[c] && r && b[r] != 0)
				bad("x86: format result not NUL terminated", caps[c]);
		}
		/* the address the instruction is shown at may be anywhere */
		{
			char *b = (char *)gb_put(&T, NULL, KGENOME_X86_TEXT);
			(void)kgenome_x86_format(&in, UINT64_MAX - 2u, b, KGENOME_X86_TEXT);
			(void)kgenome_x86_format(&in, 0, b, KGENOME_X86_TEXT);
		}
	}
	/* the sweep's view agrees with the decode */
	st2 = kgenome_x86_sweep(&sw, gb_put(&G, s16, 16), 16, mode);
	if (st2 != KGENOME_OK || sw.len != in.len || sw.id != in.id || sw.rep != in.rep)
		bad("x86: sweep disagrees with decode", in.id);
	if (sw.n > 3)
		bad("x86: sweep kept more than three operands", sw.n);
}

static const uint8_t special[] = {
	0x0f, 0x0f, 0x38, 0x3a, 0x66, 0x67, 0xf2, 0xf3, 0xf0, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65,
	0x40, 0x41, 0x48, 0x49, 0x4f, 0xc4, 0xc5, 0x62, 0x8f, 0xd5, 0xd8, 0xd9, 0xdb, 0xdd, 0xdf,
	0x9a, 0xea, 0xa0, 0xa1, 0xa2, 0xa3, 0xcd, 0xe8, 0xe9, 0xeb, 0xc2, 0xc8, 0x0f, 0x1f, 0x05,
	0xff, 0xfe, 0xf6, 0xf7, 0xc6, 0xc7, 0x80, 0x81, 0x83, 0x8d, 0x8b, 0x89, 0x00, 0xff, 0x80
};

static int fam_x86_pairs(void *arg)
{
	struct hk_rng r = { 0x1234567890abcdefull };
	unsigned b0, b1, mode, k;
	uint8_t s[16];

	(void)arg;
	for (b0 = 0; b0 < 256; b0++) {
		for (b1 = 0; b1 < 256; b1++) {
			for (mode = 32; mode <= 64; mode += 32) {
				s[0] = (uint8_t)b0;
				s[1] = (uint8_t)b1;
				for (k = 2; k < 16; k++)
					s[k] = (uint8_t)hk_next(&r);
				x86_check_one(s, (int)mode);
			}
		}
	}
	return hk_fails != 0;
}

static int fam_x86_random(void *arg)
{
	struct hk_rng r = { 0xdeadbeefcafef00dull + (uintptr_t)arg };
	unsigned it, k;
	uint8_t s[16];

	for (it = 0; it < 300000u * hk_scale(); it++) {
		for (k = 0; k < 16; k++) {
			unsigned pick = hk_below(&r, 4);
			s[k] = pick ? special[hk_below(&r, sizeof special)] : (uint8_t)hk_next(&r);
			if (k > 4 && pick == 3)
				s[k] = (uint8_t)hk_next(&r);
		}
		x86_check_one(s, (it & 1u) ? 64 : 32);
	}
	return hk_fails != 0;
}

/* a long run of one prefix byte: every length 1..32 */
static int fam_x86_prefix_runs(void *arg)
{
	static const uint8_t pre[] = { 0x66, 0x67, 0xf2, 0xf3, 0xf0, 0x2e, 0x36, 0x3e, 0x26,
				       0x64, 0x65, 0x40, 0x48, 0x4f, 0x0f, 0xc4, 0xc5, 0x62 };
	unsigned i, n, mode;
	uint8_t s[48];

	(void)arg;
	for (i = 0; i < sizeof pre; i++) {
		for (n = 1; n <= 32; n++) {
			for (mode = 32; mode <= 64; mode += 32) {
				struct kgenome_x86_insn in;
				enum kgenome_status st;

				memset(s, pre[i], sizeof s);
				if (n < sizeof s)
					s[n] = 0x90;        /* then a nop */
				st = kgenome_x86_decode(&in, gb_put(&G, s, 16), 16, (int)mode);
				if (st == KGENOME_OK && (in.len > 15 || in.len > 16))
					bad("x86: prefix run decoded past 15 bytes", n);
				/* with n prefix bytes the decoder must not read the 0x90 at s[n] when n >= 16 */
				st = kgenome_x86_decode(&in, gb_put(&G, s, n < 16 ? n : 16), n < 16 ? n : 16, (int)mode);
				if (st == KGENOME_OK && in.len > (n < 16 ? n : 16))
					bad("x86: prefix run length > bytes given", n);
			}
		}
	}
	/* modes that are neither 32 nor 64 */
	{
		static const int modes[] = { 0, 16, 1, -1, 63, 65, 128, 255, 1 << 30 };
		struct kgenome_x86_insn in;
		struct kgenome_x86_sweep sw;
		unsigned m;

		for (m = 0; m < sizeof modes / sizeof modes[0]; m++) {
			enum kgenome_status st = kgenome_x86_decode(&in, gb_put(&G, "\x90\x90\x90\x90", 4), 4, modes[m]);
			if (st == KGENOME_OK && in.len > 4)
				bad("x86: odd mode decoded past the buffer", (uint64_t)m);
			st = kgenome_x86_sweep(&sw, gb_put(&G, "\x90\x90\x90\x90", 4), 4, modes[m]);
			if (st == KGENOME_OK && sw.len > 4)
				bad("x86: odd mode sweep past the buffer", (uint64_t)m);
		}
	}
	/* zero length with a pointer that must not be dereferenced */
	{
		struct kgenome_x86_insn in;
		struct kgenome_x86_sweep sw;
		CK(kgenome_x86_decode(&in, gb_put(&G, NULL, 0), 0, 64) != KGENOME_OK);
		CK(kgenome_x86_decode(&in, NULL, 0, 64) != KGENOME_OK);
		CK(kgenome_x86_sweep(&sw, gb_put(&G, NULL, 0), 0, 32) != KGENOME_OK);
		CK(kgenome_x86_sweep(&sw, NULL, 0, 32) != KGENOME_OK);
	}
	return hk_fails != 0;
}

/* ---- the cell front end: every architecture, every length, both byte orders ------------------ */

static void cell_check(unsigned arch, int be, const uint8_t *s16, uint64_t va)
{
	unsigned n;

	for (n = 0; n <= 16; n++) {
		struct kgenome_cell_insn in;
		uint32_t r;
		unsigned k;

		memset(&in, 0xa5, sizeof in);
		r = kgenome_cell_decode(arch, be, gb_put(&G, s16, n), (uint32_t)n, va, &in);
		n_decoded++;
		if (r > n) {
			bad("cell: decoded length > bytes given", (uint64_t)arch << 8 | n);
			continue;
		}
		if (!r)
			continue;
		n_ok++;
		if (in.len != r)
			bad("cell: insn.len != returned length", arch);
		if (in.n_op > 3)
			bad("cell: more than three operands", arch);
		if (in.op >= KGENOME_CELL_OP_COUNT)
			bad("cell: op class out of range", in.op);
		for (k = 0; k < in.n_op && k < 3u; k++)
			if (in.o[k].kind > KGENOME_CELL_O_REL)
				bad("cell: operand kind out of range", in.o[k].kind);
	}
}

static int fam_cell(void *arg)
{
	struct hk_rng r = { 0x0badc0de12345678ull + (uintptr_t)arg };
	unsigned it, k, arch;
	uint8_t s[16];
	static const uint64_t vas[] = { 0, 0x1000, 0x7fffffffffffffffull, UINT64_MAX - 3u,
					UINT64_MAX, 0x80000000u, 0xfffffffcu };

	for (it = 0; it < 6000u * hk_scale(); it++) {
		for (k = 0; k < 16; k++)
			s[k] = (uint8_t)hk_next(&r);
		for (arch = 0; arch < 24; arch++) {
			cell_check(arch, (int)(it & 1u), s, vas[it % (sizeof vas / sizeof vas[0])]);
			cell_check(arch, (int)((it >> 1) & 1u), s, vas[(it / 3u) % (sizeof vas / sizeof vas[0])]);
		}
	}
	return hk_fails != 0;
}

/* each named entry directly, with the same lengths */
static int fam_cell_entries(void *arg)
{
	struct hk_rng r = { 0x5151515151515151ull };
	unsigned it, n, k;
	uint8_t s[16];

	(void)arg;
	for (it = 0; it < 30000; it++) {
		for (k = 0; k < 16; k++)
			s[k] = (uint8_t)hk_next(&r);
		for (n = 0; n <= 16; n++) {
			struct kgenome_cell_insn in;
			const uint8_t *p = gb_put(&G, s, n);
			uint64_t va = (it & 8u) ? UINT64_MAX - 7u : 0x400000u;
			uint32_t v[7];

			v[0] = kgenome_cell_decode_x86(p, n, va, 32, &in);
			v[1] = kgenome_cell_decode_x86(p, n, va, 64, &in);
			v[2] = kgenome_cell_decode_mips(p, n, va, 0, &in);
			v[3] = kgenome_cell_decode_mips(p, n, va, 1, &in);
			v[4] = kgenome_cell_decode_arm32(p, n, va, (int)(it & 1u), &in);
			v[5] = kgenome_cell_decode_thumb(p, n, va, (int)((it >> 1) & 1u), &in);
			v[6] = kgenome_cell_decode_arm64(p, n, va, &in);
			for (k = 0; k < 7; k++)
				if (v[k] > n)
					bad("cell entry: length > bytes given", (uint64_t)k << 8 | n);
			/* an odd bit width for the x86 front end */
			(void)kgenome_cell_decode_x86(p, n, va, 16, &in);
			(void)kgenome_cell_decode_x86(p, n, va, 0, &in);
			(void)kgenome_cell_decode_x86(p, n, va, 33, &in);
		}
	}
	/* NULL output / NULL bytes with zero length */
	{
		struct kgenome_cell_insn in;
		CK(kgenome_cell_decode_x86(NULL, 0, 0, 64, &in) == 0);
		CK(kgenome_cell_decode_arm64(NULL, 0, 0, &in) == 0);
		CK(kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, NULL, 0, 0, &in) == 0);
	}
	return hk_fails != 0;
}

/* An architecture the front end has no decoder for answers 0 ("a decoder that cannot answer
 * says so by returning 0 - it does not guess a length", decode.h), whatever the number. */
static int km_unknown_arch(void *arg)
{
	static const unsigned arches[] = { KGENOME_ARCH_ANY, KGENOME_ARCH_RISCV64, KGENOME_ARCH_PPC64,
		KGENOME_ARCH_SH, KGENOME_ARCH_SPARC, KGENOME_ARCH_OR1K, 0xffffu, ~0u };
	struct kgenome_cell_insn in;
	unsigned i;
	int rc = 0;

	(void)arg;
	for (i = 0; i < sizeof arches / sizeof arches[0]; i++)
		if (kgenome_cell_decode(arches[i], 0, gb_put(&G, "\x90\x90\x90\x90", 4), 4, 0, &in) != 0)
			rc = 1;
	return rc;
}

/* ---- ARM, Thumb, A64 on words ------------------------------------------------------------------- */

static void arm32_touch(uint32_t w)
{
	struct kgenome_arm32_insn in;
	volatile uint32_t sink = 0;

	if (kgenome_arm32_decode(&in, w) == KGENOME_OK && in.id >= KGENOME_ARM32_I_COUNT)
		bad("arm32: id out of range", w);
	sink += kgenome_arm32_r16(in) + kgenome_arm32_r12(in) + kgenome_arm32_r8(in) + kgenome_arm32_r0(in);
	sink += kgenome_arm32_p(in) + kgenome_arm32_u(in) + kgenome_arm32_b(in) + kgenome_arm32_wb(in) +
		kgenome_arm32_s(in) + kgenome_arm32_modimm(in) + kgenome_arm32_imm12(in) +
		kgenome_arm32_imm8_split(in) + kgenome_arm32_imm16(in) + kgenome_arm32_list(in) +
		kgenome_arm32_imm24(in) + kgenome_arm32_imm16_split(in) + kgenome_arm32_h(in) +
		kgenome_arm32_shift_type(in) + kgenome_arm32_shift_imm(in) + kgenome_arm32_rot(in);
	sink += (uint32_t)kgenome_arm32_branch_off(in);
	(void)sink;
}

static void thumb_touch(uint32_t hw0, uint32_t hw1)
{
	struct kgenome_thumb_insn in;
	volatile uint32_t sink = 0;
	unsigned len = kgenome_thumb_len(hw0);

	if (len != 2 && len != 4)
		bad("thumb: length not 2 or 4", hw0);
	if (kgenome_thumb_decode(&in, hw0, hw1) == KGENOME_OK) {
		if (in.len != len)
			bad("thumb: insn.len != kgenome_thumb_len(hw0)", hw0);
		if (len == 2 && (in.w & 0xffffu))
			bad("thumb: the second halfword of a 16-bit insn is not 0", hw0);
	}
	sink += kgenome_thumb_n_r0(in) + kgenome_thumb_n_r3(in) + kgenome_thumb_n_r6(in) + kgenome_thumb_n_r8(in) +
		kgenome_thumb_n_hi_rd(in) + kgenome_thumb_n_hi_rm(in) + kgenome_thumb_n_imm3(in) +
		kgenome_thumb_n_imm5(in) + kgenome_thumb_n_imm7(in) + kgenome_thumb_n_imm8(in) +
		kgenome_thumb_n_list(in) + kgenome_thumb_n_shift_type(in) + kgenome_thumb_n_cond(in) +
		kgenome_thumb_n_cbz_off(in) + kgenome_thumb_w_rn(in) + kgenome_thumb_w_rt(in) +
		kgenome_thumb_w_rd(in) + kgenome_thumb_w_rm(in) + kgenome_thumb_w_s(in) +
		kgenome_thumb_w_imm12(in) + kgenome_thumb_w_modimm(in) + kgenome_thumb_w_imm16(in) +
		kgenome_thumb_w_ls_imm12(in) + kgenome_thumb_w_ls_imm8(in);
	sink += (uint32_t)kgenome_thumb_n_bcond_off(in) + (uint32_t)kgenome_thumb_n_b_off(in);
	(void)sink;
}

static void arm64_touch(uint32_t w)
{
	struct kgenome_arm64_insn in, tr;
	volatile uint64_t sink = 0;
	enum kgenome_status a = kgenome_arm64_decode(&in, w), b = kgenome_arm64_decode_tree(&tr, w);

	if (a != b || in.id != tr.id)
		bad("arm64: table and tree disagree", w);
	if (a != KGENOME_OK && a != KGENOME_INVALID)
		bad("arm64: status out of range", w);
	if (kgenome_arm64_name(in.id) == NULL)
		bad("arm64: no name for a decoded id", in.id);
	sink += kgenome_arm64_lskind(&in) + kgenome_arm64_amode(&in) + kgenome_arm64_bits(&in, 3, 7) +
		kgenome_arm64_sf(&in) + kgenome_arm64_rd(&in) + kgenome_arm64_rt(&in) + kgenome_arm64_rn(&in) +
		kgenome_arm64_rm(&in) + kgenome_arm64_rs(&in) + kgenome_arm64_ra(&in) + kgenome_arm64_rt2(&in) +
		kgenome_arm64_size(&in) + kgenome_arm64_cond_branch(&in) + kgenome_arm64_cond_select(&in) +
		kgenome_arm64_addsub_imm(&in) + kgenome_arm64_movw_shift(&in) + kgenome_arm64_movw_imm(&in) +
		kgenome_arm64_immr(&in) + kgenome_arm64_imms(&in) +
		kgenome_arm64_hint(&in) + kgenome_arm64_sysreg(&in) + kgenome_arm64_imm16(&in) +
		kgenome_arm64_tbz_bit(&in) + kgenome_arm64_ldst_bytes(&in) + (uint64_t)kgenome_arm64_ldst_off(&in) +
		(uint64_t)kgenome_arm64_branch_off(&in) + (uint64_t)kgenome_arm64_adr_imm(&in);
	/* kgenome_arm64_logical_imm is for a decoded logical-immediate instruction: on any other word it shifts a
	 * 64-bit value by 64 (arm64.c:242, UB), so it is asked only of the class it is defined for */
	if (a == KGENOME_OK && (w & 0x1f800000u) == 0x12000000u)
		sink += kgenome_arm64_logical_imm(&in);
	(void)sink;
}

static int fam_arm_words(void *arg)
{
	struct hk_rng r = { 0xabcdef0123456789ull + (uintptr_t)arg };
	unsigned it, key, fill;

	/* every key of the first-level index of the ARM table, with random fill: the
	 * key is ((w >> 16) & 0xff0) | ((w >> 4) & 0xf) and the condition field */
	for (key = 0; key < 4096; key++) {
		for (fill = 0; fill < 24; fill++) {
			uint32_t w = (uint32_t)hk_next(&r);
			w = (w & ~0x0ff000f0u) | ((key & 0xff0u) << 16) | ((key & 0xfu) << 4);
			arm32_touch(w);
			arm32_touch((w & 0x0fffffffu) | 0xf0000000u);
		}
	}
	/* every 16-bit Thumb halfword, and 64 second halfwords for each 32-bit opener */
	for (it = 0; it < 65536; it++) {
		thumb_touch(it, 0);
		if (kgenome_thumb_len(it) == 4)
			for (fill = 0; fill < 64; fill++)
				thumb_touch(it, (uint32_t)hk_next(&r) & 0xffffu);
	}
	/* the wide decode called on halfwords that open a NARROW instruction, and with
	 * garbage high bits in what are meant to be halfword values */
	for (it = 0; it < 20000; it++) {
		struct kgenome_thumb_insn in;
		uint32_t h0 = (uint32_t)hk_next(&r), h1 = (uint32_t)hk_next(&r);
		(void)kgenome_thumb_decode_wide(&in, h0, h1);
		(void)kgenome_thumb_decode_narrow(&in, h0);
		(void)kgenome_thumb_decode(&in, h0, h1);
	}
	for (it = 0; it < 1500000u * hk_scale(); it++)
		arm64_touch((uint32_t)hk_next(&r));
	/* the structured space of A64: every top-11-bit prefix with random fill */
	for (key = 0; key < 2048; key++)
		for (fill = 0; fill < 64; fill++)
			arm64_touch((key << 21) | ((uint32_t)hk_next(&r) & 0x1fffffu));
	/* the id name table: valid ids have a name, ids past the end are "?" */
	CK(!strcmp(kgenome_arm64_name(0xffffu), "?"));
	CK(!strcmp(kgenome_arm64_name(~0u), "?"));
	return hk_fails != 0;
}

/* ---- the driver ------------------------------------------------------------------------------------ */

struct fam { const char *name; hk_case_fn fn; void *arg; unsigned secs; };

static int run_fam(void *p)
{
	const struct fam *f = (const struct fam *)p;
	int rc = f->fn(f->arg);

	printf("  %-30s %llu decodes, %llu ok\n", f->name, (unsigned long long)n_decoded,
	       (unsigned long long)n_ok);
	return rc;
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	static struct fam fams[] = {
		{ "x86 every byte pair", fam_x86_pairs, NULL, 120 },
		{ "x86 prefix/escape-biased random 0", fam_x86_random, (void *)0, 120 },
		{ "x86 prefix/escape-biased random 1", fam_x86_random, (void *)1, 120 },
		{ "x86 prefix runs, odd modes", fam_x86_prefix_runs, NULL, 30 },
		{ "cell: all archs, all lengths", fam_cell, (void *)0, 120 },
		{ "cell: named entries", fam_cell_entries, NULL, 60 },
		{ "arm32, thumb, a64 words", fam_arm_words, (void *)0, 120 },
	};
	unsigned i;

	gb_init(&G, 64);
	gb_init(&T, 4096);
	for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
		int sig = 0;
		double t0 = hk_now();
		enum hk_result r = hk_isolated(run_fam, &fams[i], fams[i].secs, &sig);

		printf("  %-34s %s (%.2fs)\n", fams[i].name,
		       r == HK_OK ? "ok" : r == HK_FAILED ? "FAILED" :
		       r == HK_HUNG ? "HUNG" : "CRASHED", hk_now() - t0);
		if (r != HK_OK) {
			printf("  FAIL %s: result %d signal %d\n", fams[i].name, (int)r, sig);
			hk_fails++;
		}
	}
	{
		int sig = 0;
		enum hk_result r = hk_isolated(km_unknown_arch, NULL, 10, &sig);

		KM_CHECK(r == HK_OK, "kgenome_cell_decode decodes the bytes of an architecture it has no decoder for as x86-32",
			 "celllysis/decode.c:28-30 `default:` falls to kgenome_cell_decode_x86(..., 32u) for every arch but "
			 "X86_64/ARM/ARM64/MIPS/MIPS64 (RISCV, PPC, SH, SPARC, ANY, and values outside the enum): "
			 "kgenome_cell_decode(KGENOME_ARCH_RISCV64, 0, \"\\x90\\x90\\x90\\x90\", 4, 0, &in) returns 1");
	}
	gb_free(&G);
	gb_free(&T);
	printf("hostile_decoders: %d failure(s)\n", hk_fails);
	return hk_fails != 0 || km_failed();
}
