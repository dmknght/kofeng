/*
 * emu_ops_ext.c - the integer instructions a compiler emits for a newer CPU and a few old ones a program still meets:
 * BMI1 and BMI2 (ANDN BEXTR BLSI BLSMSK BLSR BZHI MULX PDEP PEXT RORX SARX SHLX SHRX), ADCX and ADOX, MOVBE, CRC32,
 * CMPXCHG8B and CMPXCHG16B, ENTER, XLATB, AAM and AAD.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 *
 * WHY THESE. They are the integer rows of the instruction histogram that were left to stop a run as UNSUPPORTED (the
 * numbers are in tests/lib/genome/diff_decode_cover.c): RORX, MULX, SHLX, SHRX and ANDN come from code built for Haswell
 * and later (hash functions, bignum, bit scans), ADCX/ADOX from the bignum code that goes with them, MOVBE from every
 * Atom-targeted build, CMPXCHG8B from 32-bit libc locks, ENTER and XLATB from hand-written and old code, AAM and AAD
 * from 32-bit code that uses them as a divide by ten. Every one is the architecture's, flags included, and
 * tests/lib/genome/diff_ops_ext.c runs each against the host CPU on edge operands.
 *
 * A flag the manual calls undefined is left as it was: the interpreter's choice, written once here, and masked by the
 * test.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* the arithmetic flags SF ZF PF from a result of `w` bytes, CF and OF as given, AF left alone */
static void fl_zs(struct kgenome_emu *e, uint64_t r, unsigned w, int cf, int of)
{
	const uint64_t m = kgenome_emu_mask_of(w);

	r &= m;
	e->flags &= ~(uint64_t)(KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_SF | KGENOME_EMU_FL_PF);
	if (cf)
		e->flags |= KGENOME_EMU_FL_CF;
	if (of)
		e->flags |= KGENOME_EMU_FL_OF;
	if (!r)
		e->flags |= KGENOME_EMU_FL_ZF;
	if (r >> (w * 8u - 1u))
		e->flags |= KGENOME_EMU_FL_SF;
	if (!(__builtin_popcountll(r & 0xffu) & 1))
		e->flags |= KGENOME_EMU_FL_PF;
}

/* PDEP: the low bits of `src` deposited at the set bits of `mask`; PEXT: the bits of `src` at the set bits of `mask`, packed low */
static uint64_t pdep(uint64_t src, uint64_t mask)
{
	uint64_t r = 0, bit;

	for (bit = 1; mask; bit <<= 1) {
		const uint64_t low = mask & (0 - mask);

		if (src & bit)
			r |= low;
		mask &= mask - 1u;
	}
	return r;
}

static uint64_t pext(uint64_t src, uint64_t mask)
{
	uint64_t r = 0, bit;

	for (bit = 1; mask; bit <<= 1) {
		const uint64_t low = mask & (0 - mask);

		if (src & low)
			r |= bit;
		mask &= mask - 1u;
	}
	return r;
}

/* CRC-32C (Castagnoli, reflected polynomial 0x82F63B78), one byte at a time, which is what CRC32 does to its source */
static uint32_t crc32c_bytes(uint32_t crc, uint64_t v, unsigned n)
{
	unsigned i, k;

	for (i = 0; i < n; i++) {
		crc ^= (uint32_t)((v >> (8u * i)) & 0xffu);
		for (k = 0; k < 8u; k++)
			crc = (crc >> 1) ^ ((crc & 1u) ? 0x82f63b78u : 0u);
	}
	return crc;
}

static uint64_t bswap_n(uint64_t v, unsigned n)
{
	uint64_t r = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		r |= ((v >> (8u * i)) & 0xffu) << (8u * (n - 1u - i));
	return r;
}

/*
 * ENTER size, level (SDM, operand size 64 in 64-bit mode and 32 in 32-bit mode; a 16 bit stack is not carried): push the
 * frame pointer, save the new frame pointer, copy `level - 1` outer frame pointers (the display), push the new frame
 * pointer for a nested level, point the frame pointer at the saved one, and take `size` bytes of locals.
 */
static int run_enter(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint64_t size, level, frame, rsp;
	const unsigned w = e->bits == 32 ? 4u : 8u;
	unsigned k;

	if ((ixp->h.osz & 1u) || !kgenome_emu_op_rd(e, ixp, &ixp->op[0], &size) || !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &level))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	level &= 31u;
	if (!kgenome_emu_push(e, e->gpr[KGENOME_EMU_RBP]))
		return KGENOME_EMU_RUN_FAULT;
	frame = e->gpr[KGENOME_EMU_RSP];
	if (level) {
		uint64_t rbp = e->gpr[KGENOME_EMU_RBP];

		for (k = 1; k < level; k++) {
			uint64_t v = 0;

			rbp -= w;
			if (!kgenome_emu_mem_rd(e, rbp, &v, w) || !kgenome_emu_push(e, v))
				return KGENOME_EMU_RUN_FAULT;
		}
		if (!kgenome_emu_push(e, frame))
			return KGENOME_EMU_RUN_FAULT;
	}
	e->gpr[KGENOME_EMU_RBP] = e->bits == 32 ? (frame & 0xffffffffu) : frame;
	rsp = e->gpr[KGENOME_EMU_RSP] - (size & 0xffffu);
	e->gpr[KGENOME_EMU_RSP] = e->bits == 32 ? (rsp & 0xffffffffu) : rsp;
	return KGENOME_EMU_RUN_OK;
}

/*
 * Execute the instructions of the header; NOT_MINE for any other id. One arm of the dispatch in kgenome_emu_run, moved
 * out so that the loop stays readable and the instructions nobody runs often are not in it.
 */
int kgenome_emu_run_ext(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint64_t a = 0, b = 0, r;
	const unsigned w = ixp->op[0].size ? ixp->op[0].size : 4u;
	const uint64_t m = kgenome_emu_mask_of(w);
	const unsigned bits = w * 8u;

	switch (ixp->h.id) {
	/* ---- BMI1 ---------------------------------------------------------------------------------- */
	case KGENOME_X86_I_ANDN:                    /* dst = ~src1 & src2; SF ZF from it, CF = OF = 0 */
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		r = ~a & b & m;
		fl_zs(e, r, w, 0, 0);
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	case KGENOME_X86_I_BEXTR: {                 /* dst = (src >> start) & ((1 << len) - 1), start and len bytes of the control */
		uint64_t start, len;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		start = b & 0xffu;
		len = (b >> 8) & 0xffu;
		r = (start >= bits ? 0 : (a & m) >> start);
		if (len < bits)
			r &= (1ull << len) - 1u;
		fl_zs(e, r, w, 0, 0);
		e->flags &= ~(uint64_t)(KGENOME_EMU_FL_SF | KGENOME_EMU_FL_PF);       /* undefined: SF PF here as the CPU leaves them 0 */
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}
	case KGENOME_X86_I_BLSI: case KGENOME_X86_I_BLSMSK: case KGENOME_X86_I_BLSR:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		a &= m;
		if (ixp->h.id == KGENOME_X86_I_BLSI)
			r = a & (0 - a);                        /* the lowest set bit */
		else if (ixp->h.id == KGENOME_X86_I_BLSMSK)
			r = a ^ (a - 1u);                       /* a mask up to and including it */
		else
			r = a & (a - 1u);                       /* the value without it */
		r &= m;
		/* CF = source is zero (BLSI: source is NOT zero); ZF, SF from the result; BLSMSK always clears ZF; OF = 0 */
		fl_zs(e, r, w, ixp->h.id == KGENOME_X86_I_BLSI ? a != 0 : a == 0, 0);
		if (ixp->h.id == KGENOME_X86_I_BLSMSK)
			e->flags &= ~(uint64_t)KGENOME_EMU_FL_ZF;
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;

	/* ---- BMI2 ---------------------------------------------------------------------------------- */
	case KGENOME_X86_I_BZHI: {                  /* dst = src with the bits from index up cleared; CF = index past the width */
		uint64_t idx;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		idx = b & 0xffu;
		r = a & m;
		if (idx < bits)
			r &= (1ull << idx) - 1u;
		fl_zs(e, r, w, idx > bits - 1u, 0);
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}
	case KGENOME_X86_I_MULX: {                  /* (hi:lo) = rdx * src, no flags; with hi and lo the same register, hi wins */
		uint64_t d = kgenome_emu_reg_rd(e, KGENOME_EMU_RDX, w, 0), lo, hi;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[2], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		a &= m;
		if (w == 8) {
			const uint64_t al = a & 0xffffffffu, ah = a >> 32, dl = d & 0xffffffffu, dh = d >> 32;
			const uint64_t m0 = al * dl, m1 = al * dh, m2 = ah * dl;
			const uint64_t carry = ((m0 >> 32) + (m1 & 0xffffffffu) + (m2 & 0xffffffffu)) >> 32;

			lo = d * a;
			hi = ah * dh + (m1 >> 32) + (m2 >> 32) + carry;
		} else {
			const uint64_t p = (d & m) * a;

			lo = p & m;
			hi = (p >> bits) & m;
		}
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[1], lo) || !kgenome_emu_op_wr(e, ixp, &ixp->op[0], hi))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		return KGENOME_EMU_RUN_OK;
	}
	case KGENOME_X86_I_PDEP: case KGENOME_X86_I_PEXT:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		r = (ixp->h.id == KGENOME_X86_I_PDEP ? pdep(a & m, b & m) : pext(a & m, b & m)) & m;
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	case KGENOME_X86_I_RORX:                    /* rotate right by an immediate; no flags */
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		b &= bits - 1u;
		a &= m;
		r = b ? ((a >> b) | (a << (bits - b))) & m : a;
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	case KGENOME_X86_I_SARX: case KGENOME_X86_I_SHLX: case KGENOME_X86_I_SHRX:
		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		b &= bits - 1u;
		a &= m;
		if (ixp->h.id == KGENOME_X86_I_SHLX)
			r = (a << b) & m;
		else if (ixp->h.id == KGENOME_X86_I_SHRX)
			r = a >> b;
		else
			r = (uint64_t)(((int64_t)kgenome_emu_sext(a, w)) >> b) & m;
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;

	/* ---- ADX: two independent carry chains, CF for ADCX and OF for ADOX, no other flag touched --------- */
	case KGENOME_X86_I_ADCX: case KGENOME_X86_I_ADOX: {
		const uint64_t flag = ixp->h.id == KGENOME_X86_I_ADCX ? KGENOME_EMU_FL_CF : KGENOME_EMU_FL_OF;
		const uint64_t cin = (e->flags & flag) ? 1u : 0u;
		uint64_t sum;
		int carry;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		a &= m;
		b &= m;
		if (w == 8) {
			const uint64_t t = a + b;

			sum = t + cin;
			carry = t < a || sum < t;
		} else {
			sum = (a + b + cin) & m;
			carry = (int)(((a + b + cin) >> bits) & 1u);
		}
		e->flags = carry ? (e->flags | flag) : (e->flags & ~flag);
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], sum) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}

	/* ---- MOVBE: a load or store with the bytes reversed ------------------------------------------------ */
	case KGENOME_X86_I_MOVBE: {
		const struct kgenome_x86_op *src = &ixp->op[1];
		const unsigned n = ixp->op[0].size ? ixp->op[0].size : 4u;

		if (!kgenome_emu_op_rd(e, ixp, src, &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], bswap_n(a, n)) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}

	/* ---- CRC32 (SSE4.2): the CRC-32C of the source, accumulated into the destination -------------------- */
	case KGENOME_X86_I_CRC32: {
		const unsigned n = ixp->op[1].size ? ixp->op[1].size : 1u;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &a) || !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &b))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		r = crc32c_bytes((uint32_t)a, b, n);
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], r) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}

	/* ---- CMPXCHG8B, CMPXCHG16B: compare EDX:EAX (RDX:RAX) with the memory operand, then store ECX:EBX or load -- */
	case KGENOME_X86_I_CMPXCHG8B: case KGENOME_X86_I_CMPXCHG16B: {
		const unsigned n = ixp->h.id == KGENOME_X86_I_CMPXCHG8B ? 8u : 16u, half = n / 2u;
		uint8_t mem[16], want[16], put[16];
		uint64_t ea, ax = kgenome_emu_reg_rd(e, KGENOME_EMU_RAX, half, 0), dx = kgenome_emu_reg_rd(e, KGENOME_EMU_RDX, half, 0);
		uint64_t bx = kgenome_emu_reg_rd(e, KGENOME_EMU_RBX, half, 0), cx = kgenome_emu_reg_rd(e, KGENOME_EMU_RCX, half, 0);

		if (ixp->op[0].type != KGENOME_X86_OP_MEM || !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		if (n == 16u && (ea & 15u)) {
			/* a misaligned CMPXCHG16B is #GP(0) on the CPU */
			memcpy(e->fault_kind, "align", 6);
			e->fault_va = ea;
			return KGENOME_EMU_RUN_UNSUPPORTED;
		}
		if (!kgenome_emu_mem_rd(e, ea, mem, n))
			return KGENOME_EMU_RUN_FAULT;
		memcpy(want, &ax, half);
		memcpy(want + half, &dx, half);
		memcpy(put, &bx, half);
		memcpy(put + half, &cx, half);
		if (!memcmp(mem, want, n)) {
			if (!kgenome_emu_mem_wr(e, ea, put, n))
				return KGENOME_EMU_RUN_FAULT;
			e->flags |= KGENOME_EMU_FL_ZF;
		} else {
			uint64_t lo = 0, hi = 0;

			memcpy(&lo, mem, half);
			memcpy(&hi, mem + half, half);
			kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, half, 0, lo);
			kgenome_emu_reg_wr(e, KGENOME_EMU_RDX, half, 0, hi);
			e->flags &= ~(uint64_t)KGENOME_EMU_FL_ZF;
		}
		return KGENOME_EMU_RUN_OK;
	}

	case KGENOME_X86_I_ENTER:
		return run_enter(e, ixp);

	case KGENOME_X86_I_XLATB: {                 /* AL = [RBX + AL] */
		uint64_t v = 0, ea = kgenome_emu_reg_rd(e, KGENOME_EMU_RBX, e->bits == 32 ? 4u : 8u, 0) +
				     (e->gpr[KGENOME_EMU_RAX] & 0xffu);

		if (e->bits == 32)
			ea &= 0xffffffffu;
		if (!kgenome_emu_mem_rd(e, ea, &v, 1))
			return KGENOME_EMU_RUN_FAULT;
		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 1, 0, v);
		return KGENOME_EMU_RUN_OK;
	}

	/* ---- AAM, AAD (32-bit mode): ASCII adjust before a divide or after a multiply, in any base ------------ */
	case KGENOME_X86_I_AAM: case KGENOME_X86_I_AAD: {
		const unsigned al = (unsigned)(e->gpr[KGENOME_EMU_RAX] & 0xffu), ah = (unsigned)((e->gpr[KGENOME_EMU_RAX] >> 8) & 0xffu);
		unsigned nal, nah;
		uint64_t base;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[0], &base))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		base &= 0xffu;
		if (ixp->h.id == KGENOME_X86_I_AAM) {
			if (!base) {                        /* AAM 0 is a divide by zero */
				kgenome_emu_fault_de(e, 0);
				return KGENOME_EMU_RUN_UNSUPPORTED;
			}
			nah = al / (unsigned)base;
			nal = al % (unsigned)base;
		} else {
			nal = (al + ah * (unsigned)base) & 0xffu;
			nah = 0;
		}
		/* SF ZF PF from the new AL; CF, OF and AF are undefined (the CPU clears them) */
		fl_zs(e, nal, 1, 0, 0);
		e->flags &= ~(uint64_t)KGENOME_EMU_FL_AF;
		kgenome_emu_reg_wr(e, KGENOME_EMU_RAX, 2, 0, ((uint64_t)nah << 8) | nal);
		return KGENOME_EMU_RUN_OK;
	}
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
}
