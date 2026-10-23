/*
 * emu_state.c - what an instruction reads and writes: the registers, the flags, an operand
 * (register, memory, vector). The loop in emu_interp.c decides WHICH instruction
 * runs and what it does, and keeps push and pop, which it inlines; this is how the machine's visible state is addressed.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* ---- registers ------------------------------------------------------------
 *
 * x86 register writes are not uniform and the irregularity is load bearing: a
 * 32 bit write ZEROES the upper half, an 8 or 16 bit write PRESERVES it, and
 * AH/CH/DH/BH address byte one of the first four registers rather than byte
 * zero of the second four. Getting any of those wrong produces a stub that
 * runs for a while and then computes one wrong address.
 */
uint64_t kgenome_emu_mask_of(unsigned bytes)
{
	return bytes >= 8 ? ~(uint64_t)0 : ((uint64_t)1 << (bytes * 8)) - 1u;
}

/* Sign-extend the low `bytes` bytes of v to 64 bits. */
uint64_t kgenome_emu_sext(uint64_t v, unsigned bytes)
{
	uint64_t m;

	if (bytes >= 8)
		return v;
	m = (uint64_t)1 << (bytes * 8u - 1u);
	v &= kgenome_emu_mask_of(bytes);
	return (v ^ m) - m;
}


uint64_t kgenome_emu_reg_rd(const struct kgenome_emu *e, unsigned r, unsigned bytes,
		       int high8)
{
	uint64_t v;

	if (high8)
		return (e->gpr[r & 3u] >> 8) & 0xffu;
	if (r >= KGENOME_EMU_NGPR)
		return 0;
	v = e->gpr[r];
	return bytes >= 8 ? v : v & kgenome_emu_mask_of(bytes);
}

void kgenome_emu_reg_wr(struct kgenome_emu *e, unsigned r, unsigned bytes, int high8,
		   uint64_t v)
{
	if (high8) {
		unsigned i = r & 3u;

		e->gpr[i] = (e->gpr[i] & ~(uint64_t)0xff00) |
			    ((v & 0xffu) << 8);
		return;
	}
	if (r >= KGENOME_EMU_NGPR)
		return;
	if (bytes >= 8)
		e->gpr[r] = v;
	else if (bytes == 4)
		e->gpr[r] = v & 0xffffffffu;     /* zero extends - the one that bites */
	else
		e->gpr[r] = (e->gpr[r] & ~kgenome_emu_mask_of(bytes)) | (v & kgenome_emu_mask_of(bytes));
}

/* ---- flags ---------------------------------------------------------------- */

static int parity8(uint64_t v)
{
	unsigned x = (unsigned)(v & 0xffu);

	/* PF is set when the low byte has an EVEN number of set bits. Folded
	 * rather than looped: this runs for every ALU instruction. */
	x ^= x >> 4;
	x ^= x >> 2;
	x ^= x >> 1;
	return !(x & 1u);
}

/*
 * ---- THE UNDEFINED CORNER OF A 16 BIT DOUBLE SHIFT ------------------------
 *
 * SHRD and SHLD mask their count with 31, so a 16 bit form can be asked to
 * shift by 17..31 - past the operand size, where Intel calls the result
 * undefined. Real silicon still produces something, consistently, and
 * VMProtect uses exactly that as an anti-emulation trap: it folds the result
 * AND the flags into a rolling key, so an interpreter that invents either
 * value stops matching within a few instructions.
 *
 * THE VALUE IS NOT DERIVABLE. It is microarchitecture specific - XVolkolak's
 * XEmulator says so and solves it the same way, by running the instruction on
 * the host. This does that where the host is x86-64, which is the only place
 * the answer would be right anyway.
 *
 * Elsewhere the run stops on the instruction rather than guessing: a wrong
 * answer here is worse than no answer, because it is the guest's key that goes
 * wrong and the failure surfaces somewhere else entirely.
 */
#if defined(__x86_64__)
#define KGENOME_EMU_HOST_DSHIFT 1
uint16_t kgenome_emu_host_dshift16(uint16_t dst, uint16_t src, uint8_t cnt,
			      int left, uint64_t *fl)
{
	uint16_t r = dst;
	uint64_t f = 0;

	if (left)
		__asm__ volatile ("shldw %%cl, %2, %0\n\t"
				  "pushfq\n\t"
				  "popq %1"
				  : "+r"(r), "=r"(f)
				  : "r"(src), "c"(cnt)
				  : "cc");
	else
		__asm__ volatile ("shrdw %%cl, %2, %0\n\t"
				  "pushfq\n\t"
				  "popq %1"
				  : "+r"(r), "=r"(f)
				  : "r"(src), "c"(cnt)
				  : "cc");
	*fl = f;
	return r;
}
#endif

void kgenome_emu_fl_logic(struct kgenome_emu *e, uint64_t r, unsigned bytes)
{
	uint64_t m = kgenome_emu_mask_of(bytes);

	r &= m;
	e->flags &= ~(uint64_t)(KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF | KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_SF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_AF);
	if (!r)                       e->flags |= KGENOME_EMU_FL_ZF;
	if (r >> (bytes * 8u - 1u))   e->flags |= KGENOME_EMU_FL_SF;
	if (parity8(r))               e->flags |= KGENOME_EMU_FL_PF;
}

void kgenome_emu_fl_add(struct kgenome_emu *e, uint64_t a, uint64_t b, uint64_t cin,
		   unsigned bytes)
{
	uint64_t m = kgenome_emu_mask_of(bytes), r = (a + b + cin) & m;
	uint64_t sign = (uint64_t)1 << (bytes * 8u - 1u);

	kgenome_emu_fl_logic(e, r, bytes);
	/*
	 * CF is the carry out of the top bit (Intel SDM Vol. 1 A.1, ADD/ADC). The sum a+b+cin
	 * is compared with the width's mask, which cannot be exceeded when the mask is all
	 * ones (a 64 bit operand): the carry is taken from the wrap of each partial sum.
	 */
	{
		uint64_t am = a & m, s1 = am + (b & m), s2 = s1 + cin;

		if (s1 < am || s2 < s1 || (m != ~(uint64_t)0 && s2 > m))
			e->flags |= KGENOME_EMU_FL_CF;
	}
	if (~((a ^ b)) & (a ^ r) & sign)                       e->flags |= KGENOME_EMU_FL_OF;
	if (((a & 0xfu) + (b & 0xfu) + cin) > 0xfu)            e->flags |= KGENOME_EMU_FL_AF;
}

void kgenome_emu_fl_sub(struct kgenome_emu *e, uint64_t a, uint64_t b, uint64_t bin,
		   unsigned bytes)
{
	uint64_t m = kgenome_emu_mask_of(bytes), r = (a - b - bin) & m;
	uint64_t sign = (uint64_t)1 << (bytes * 8u - 1u);

	kgenome_emu_fl_logic(e, r, bytes);
	/* Borrow. The b+bin form overflows the mask only when b is all ones in
	 * the width and bin is 1 - at sz==8 that wraps to 0 and the naive a<0
	 * test misses a borrow that in fact always happens - so that one case is
	 * taken out before the comparison that would misread it. */
	if ((b & m) == m && bin)                               e->flags |= KGENOME_EMU_FL_CF;
	else if ((a & m) < (b & m) + bin)                      e->flags |= KGENOME_EMU_FL_CF;
	if ((a ^ b) & (a ^ r) & sign)                          e->flags |= KGENOME_EMU_FL_OF;
	if ((a & 0xfu) < (b & 0xfu) + bin)                     e->flags |= KGENOME_EMU_FL_AF;
}


/*
 * A destination whose value did not change still has to be written when it is a 32 bit register.
 * Intel SDM Vol. 1 3.4.1.1: in 64-bit mode a 32 bit operand-size result is zero-extended into the
 * 64 bit register, and that includes an instruction that computes nothing - a shift, rotate, SHLD
 * or SHRD whose count masks to zero, and a CMOVcc whose condition is false - so the upper half is
 * cleared. A memory destination, or a narrower register, is left as it is.
 */
void kgenome_emu_op_keep(struct kgenome_emu *e, const struct kgenome_x86_op *op, uint64_t v)
{
	if (op->type == KGENOME_X86_OP_REG && op->rtype == KGENOME_X86_REG_GPR && op->rsize == 4)
		kgenome_emu_reg_wr(e, op->reg, 4, 0, v);
}

/*
 * IMUL and MUL define CF and OF only, and set them together: both are 1 when the product does not
 * fit the destination (SDM Vol. 2, IMUL "Flags Affected"). SF, ZF, AF and PF are undefined and are
 * left as they were.
 */
void kgenome_emu_fl_cfof(struct kgenome_emu *e, int on)
{
	if (on)
		e->flags |= KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF;
	else
		e->flags &= ~(uint64_t)(KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF);
}

/*
 * THE 128 BY 64 BIT DIVIDE a 64-bit DIV is, and the division the narrower ones share with it.
 *
 * `hi`:`lo` is the dividend (RDX:RAX, EDX:EAX, DX:AX; AX alone for a byte divisor, with hi 0),
 * `d` the divisor, already known not to be zero. Returns 0 when the quotient does not fit the
 * destination - the case the CPU answers with #DE - and leaves *q and *r alone then; a quotient
 * is never truncated. No 128-bit integer type: this is the shift-and-subtract division, 64 steps
 * and only when RDX is not zero (a dividend that fits 64 bits takes the machine's own divide).
 */
static void div128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t *q, uint64_t *r)
{
	uint64_t rem = hi, quo = 0;
	unsigned i;

	for (i = 0; i < 64u; i++) {
		const uint64_t top = rem >> 63;

		rem = (rem << 1) | (lo >> 63);
		lo <<= 1;
		quo <<= 1;
		if (top || rem >= d) {
			rem -= d;
			quo |= 1u;
		}
	}
	*q = quo;
	*r = rem;
}

int kgenome_emu_div(unsigned sz, int sgn, uint64_t hi, uint64_t lo, uint64_t d, uint64_t *q, uint64_t *r)
{
	const uint64_t mask = kgenome_emu_mask_of(sz);

	if (sz == 8) {
		uint64_t qm, rm;

		if (!sgn) {
			if (hi >= d)
				return 0;
			if (!hi) {
				*q = lo / d;
				*r = lo % d;
			} else {
				div128(hi, lo, d, q, r);
			}
			return 1;
		}
		{
			const int nneg = (int64_t)hi < 0, dneg = (int64_t)d < 0;
			uint64_t nh = hi, nl = lo;
			const uint64_t dm = dneg ? 0 - d : d;

			if (nneg) {                    /* the magnitude of the 128 bit dividend */
				nl = 0 - lo;
				nh = ~hi + (lo == 0 ? 1u : 0u);
			}
			if (nh >= dm)
				return 0;
			div128(nh, nl, dm, &qm, &rm);
			if (nneg != dneg) {
				if (qm > 0x8000000000000000ull)
					return 0;
				*q = 0 - qm;
			} else {
				if (qm > 0x7fffffffffffffffull)
					return 0;
				*q = qm;
			}
			*r = nneg ? 0 - rm : rm;
			return 1;
		}
	}
	{
		const uint64_t n = sz == 1 ? lo : (hi << (sz * 8u)) | (lo & mask);

		if (!sgn) {
			*q = n / d;
			*r = n % d;
			return *q <= mask;
		}
		{
			const int64_t sn = (int64_t)kgenome_emu_sext(n, sz * 2u);
			const int64_t sd = (int64_t)kgenome_emu_sext(d, sz);

			if (sd == -1) {                /* INT64_MIN / -1 is a trap on the host */
				*q = 0 - (uint64_t)sn;
				*r = 0;
			} else {
				*q = (uint64_t)(sn / sd);
				*r = (uint64_t)(sn % sd);
			}
			return (int64_t)kgenome_emu_sext(*q, sz) == (int64_t)*q;
		}
	}
}

/*
 * #DE. Marked the way a failed memory access is, so that the same two places read it: a Windows guest's
 * handler is run for it (emu_win_exc.c names the status from the kind), and with none - and for every ELF
 * guest, no signal is delivered here - the run ends with a FAULT stop, not UNSUPPORTED.
 */
void kgenome_emu_fault_de(struct kgenome_emu *e, int overflow)
{
	memcpy(e->fault_kind, overflow ? "divovf" : "divzero", overflow ? 7u : 8u);
	e->fault_va = e->rip;
}

/*
 * A PRIVILEGED INSTRUCTION IN USER MODE. IN, OUT, CLI and STI are #GP at ring 3 and Windows turns that into
 * STATUS_PRIVILEGED_INSTRUCTION (0xc0000096) for the process's handlers. A protector executes `in eax, dx` on
 * purpose: on VMware port 0x5658 answers 'VMXh' and anywhere else it is this exception, and the handler's
 * continuing is the "no hypervisor" answer. Marked as a fault so the same two places read it as for #DE.
 */
void kgenome_emu_fault_priv(struct kgenome_emu *e)
{
	memcpy(e->fault_kind, "priv", 5u);
	e->fault_va = e->rip;
}

/* The xmm register an operand names, or NULL when it is anything else: a merging write goes to its bytes. */
uint8_t *kgenome_emu_xmm_of(struct kgenome_emu *e, const struct kgenome_x86_op *op)
{
	if (op->type != KGENOME_X86_OP_REG || op->rtype != KGENOME_X86_REG_SSE || op->reg >= 16u)
		return NULL;
	return e->xmm[op->reg];
}

/* ---- operands -------------------------------------------------------------- */

int kgenome_emu_ea_of(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		 uint64_t *out)
{
	uint64_t a = 0;

	if (op->mf & KGENOME_X86_M_RIPREL) {
		*out = e->rip + ix->h.len + (uint64_t)op->v;
		return 1;
	}
	if (op->mf & KGENOME_X86_M_BASE)
		a += kgenome_emu_reg_rd(e, op->base, op->bsz, 0);
	if (op->mf & KGENOME_X86_M_INDEX)
		a += kgenome_emu_reg_rd(e, op->index, op->isz, 0) * (op->scale ? op->scale : 1u);
	if (op->mf & KGENOME_X86_M_DISP)
		a += (uint64_t)op->v;
	/*
	 * FS AND GS ARE A BASE, NOT A REFUSAL.
	 *
	 * A Go-built packer sets its thread pointer with arch_prctl and then
	 * addresses everything through fs:. Refusing the segment stopped Ezuri
	 * 48 instructions in - the runtime saw arch_prctl fail and executed its
	 * own deliberate trap. There is one thread here, so one base each is all
	 * a segment means.
	 */
	if (op->mf & KGENOME_X86_M_SEG) {
		if (op->seg == 4)
			a += e->fs_base;
		else if (op->seg == 5)
			a += e->gs_base;
	}
	/*
	 * A 32-bit process computes addresses in 32 bits: a base+disp that runs
	 * past 4 GB wraps rather than reaching into a 64-bit address space the
	 * guest does not have. RIP-relative returned above and does not reach
	 * here, so nothing 64-bit is masked by mistake.
	 */
	if (e->bits == 32)
		a &= 0xffffffffu;
	*out = a;
	return 1;
}




/*
 * THE SEGMENT SELECTORS A WINDOWS USER MODE THREAD ACTUALLY HAS.
 *
 * Not decoration and not invented: a protector reads CS to tell a 64-bit
 * process from a 32-bit one under WOW64 - 0x33 against 0x23 - and reads DS or
 * ES to check it is in the flat model it expects. `mov bx, ds` is what stopped
 * two samples here, an MPRESS one and a Themida one, at thirteen million
 * instructions each.
 *
 * The bases are a separate matter and stay where they are: FS on 32-bit and GS
 * on 64-bit point at the TEB through kgenome_emu_set_seg_base, and everything else
 * is flat. This returns the SELECTOR, which is the number the guest sees.
 *
 * the decoder numbers them ES, CS, SS, DS, FS, GS - the same order
 * kgenome_emu_set_seg_base is called with.
 */
static uint64_t seg_selector(const struct kgenome_emu *e, unsigned r)
{
	static const uint16_t sel64[6] = {
		0x002bu, 0x0033u, 0x002bu, 0x002bu, 0x0053u, 0x002bu
	};
	static const uint16_t sel32[6] = {
		0x0023u, 0x001bu, 0x0023u, 0x0023u, 0x003bu, 0x0000u
	};

	if (r >= 6u)
		return 0;
	return e->bits == 32 ? sel32[r] : sel64[r];
}

int kgenome_emu_op_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		 uint64_t *out)
{
	unsigned sz = op->size ? op->size : 8u;

	switch (op->type) {
	case KGENOME_X86_OP_REG:
		if (op->rtype == KGENOME_X86_REG_SEG) {
			*out = seg_selector(e, op->reg);
			return 1;
		}
		if (op->rtype != KGENOME_X86_REG_GPR)
			return 0;
		*out = kgenome_emu_reg_rd(e, op->reg, op->rsize,
			      op->high8);
		return 1;
	case KGENOME_X86_OP_IMM:
		*out = (uint64_t)op->v;
		return 1;
	case KGENOME_X86_OP_CONST:
		*out = (uint64_t)op->v;
		return 1;
	case KGENOME_X86_OP_REL:
		*out = e->rip + ix->h.len + (uint64_t)op->v;
		return 1;
	case KGENOME_X86_OP_MEM: {
		uint64_t ea, v = 0;

		if (!kgenome_emu_ea_of(e, ix, op, &ea))
			return 0;
		if (sz > 8)
			return 0;                 /* vector width: not carried */
		if (!kgenome_emu_mem_rd(e, ea, &v, sz))
			return 0;
		*out = v;
		return 1;
	}
	default:
		return 0;
	}
}

/*
 * Read a vector operand into `buf`, returning its width in bytes. A register
 * operand wider than 16 is a YMM/ZMM this does not keep, and is refused rather
 * than silently truncated to its low half.
 */
int kgenome_emu_vec_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		  uint8_t *buf, unsigned *sz)
{
	unsigned n = op->size ? op->size : 16u;

	if (n > 16)
		return 0;
	memset(buf, 0, 16);
	switch (op->type) {
	case KGENOME_X86_OP_REG:
		if (op->rtype == KGENOME_X86_REG_SSE) {
			if (op->reg >= 16)
				return 0;
			memcpy(buf, e->xmm[op->reg], n);
		} else if (op->rtype == KGENOME_X86_REG_MMX) {
			if (op->reg >= 8 || n > 8)
				return 0;
			memcpy(buf, e->mmx[op->reg], n);
		} else if (op->rtype == KGENOME_X86_REG_GPR) {
			uint64_t v = kgenome_emu_reg_rd(e, op->reg,
					    op->rsize, 0);

			memcpy(buf, &v, n > 8 ? 8u : n);
		} else {
			return 0;
		}
		*sz = n;
		return 1;
	case KGENOME_X86_OP_MEM: {
		uint64_t ea;

		if (!kgenome_emu_ea_of(e, ix, op, &ea) || !kgenome_emu_mem_rd(e, ea, buf, n))
			return 0;
		*sz = n;
		return 1;
	}
	default:
		return 0;
	}
}

/*
 * Write `sz` bytes back. Writing a vector register always clears what is above
 * the bytes written, which is what the non-VEX encodings do for the 128-bit
 * register this keeps.
 */
int kgenome_emu_vec_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		  const uint8_t *buf, unsigned sz)
{
	unsigned n = op->size ? op->size : 16u;

	if (n > 16 || sz > 16)
		return 0;
	if (n > sz)
		n = sz;
	switch (op->type) {
	case KGENOME_X86_OP_REG:
		if (op->rtype == KGENOME_X86_REG_SSE) {
			if (op->reg >= 16)
				return 0;
			memset(e->xmm[op->reg], 0, 16);
			memcpy(e->xmm[op->reg], buf, n);
			return 1;
		}
		if (op->rtype == KGENOME_X86_REG_MMX) {
			/*
			 * A 64-bit register, so a 4-byte MOVD clears the top
			 * half rather than leaving what was there - which is
			 * what the instruction does and what makes the pair
			 * `movd mm, r32` / `movd r32, mm` a faithful round
			 * trip.
			 */
			if (op->reg >= 8 || n > 8)
				return 0;
			memset(e->mmx[op->reg], 0, 8);
			memcpy(e->mmx[op->reg], buf, n);
			return 1;
		}
		if (op->rtype == KGENOME_X86_REG_GPR) {
			uint64_t v = 0;

			memcpy(&v, buf, n > 8 ? 8u : n);
			kgenome_emu_reg_wr(e, op->reg,
			       op->rsize, 0, v);
			return 1;
		}
		return 0;
	case KGENOME_X86_OP_MEM: {
		uint64_t ea;

		if (!kgenome_emu_ea_of(e, ix, op, &ea))
			return 0;
		return kgenome_emu_mem_wr(e, ea, buf, n);
	}
	default:
		return 0;
	}
}

int kgenome_emu_op_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		 uint64_t v)
{
	unsigned sz = op->size ? op->size : 8u;

	switch (op->type) {
	case KGENOME_X86_OP_REG:
		if (op->rtype != KGENOME_X86_REG_GPR)
			return 0;
		kgenome_emu_reg_wr(e, op->reg, op->rsize,
		       op->high8, v);
		return 1;
	case KGENOME_X86_OP_MEM: {
		uint64_t ea;

		if (!kgenome_emu_ea_of(e, ix, op, &ea))
			return 0;
		if (sz > 8)
			return 0;
		return kgenome_emu_mem_wr(e, ea, &v, sz);
	}
	default:
		return 0;
	}
}
