/*
 * x86_fmt.c - an x86 instruction as Intel-syntax text.
 *
 * WHAT THE TEXT IS FOR. kofviewer draws it and the clipboard gets it; the
 * emulator names the instruction it could not run in it. Neither parses it back
 * for meaning - the viewer colours tokens by their first character, and that is
 * all - so what matters is that it is regular, complete and the same everywhere.
 *
 * WHAT IT PRINTS, in order: the prefixes the instruction TAKES (a REP in front of
 * an ADD is not shown, because nothing in the instruction uses it); the mnemonic;
 * padding so the operands of consecutive lines start in one column; then the
 * operands the instruction WRITES, comma separated. The operands it uses without
 * writing - the stack pointer a push moves, the flags a compare sets - are not
 * printed, as in every Intel-syntax listing.
 *
 * THE MNEMONIC AND WHICH PREFIXES SHOW come from the tables (they are facts about
 * the opcode); how a register, an immediate or a memory operand is spelled is
 * here.
 */

#include <stdio.h>
#include <string.h>

#include "x86.h"
#include "x86_int.h"

static const char *const r8_legacy[8] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
static const char *const r8_rex[16] = {
	"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
	"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
};
static const char *const r16[16] = {
	"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
	"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
};
static const char *const r32[16] = {
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
	"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};
static const char *const r64[16] = {
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};
static const char *const segn[8] = { "es", "cs", "ss", "ds", "fs", "gs", "segr6", "segr7" };

struct out {
	char *p;
	size_t n, cap;
	int bad;
};

static void put(struct out *o, const char *s)
{
	size_t l = strlen(s);

	if (o->bad || o->n + l + 1 > o->cap) {
		o->bad = 1;
		return;
	}
	memcpy(o->p + o->n, s, l + 1);
	o->n += l;
}

static void putf(struct out *o, const char *fmt, unsigned long long a)
{
	char t[48];

	snprintf(t, sizeof t, fmt, a);
	put(o, t);
}

/* A numbered register of a class that is `base` followed by the number, 0..31. */
static void put_numbered(struct out *o, const char *base, unsigned n)
{
	char t[16];

	snprintf(t, sizeof t, "%s%u", base, n);
	put(o, t);
}

/* A general register of `size` bytes. `rex` selects the byte-register spelling. */
static void put_gpr(struct out *o, unsigned n, unsigned size, int rexlike)
{
	if (n > 15) {
		o->bad = 1;
		return;
	}
	switch (size) {
	case 1: put(o, rexlike ? r8_rex[n] : (n < 8 ? r8_legacy[n] : "?")); break;
	case 2: put(o, r16[n]); break;
	case 4: put(o, r32[n]); break;
	case 8: put(o, r64[n]); break;
	default: o->bad = 1;
	}
}

static void put_reg(struct out *o, const struct gt_x86_op *op, int rexlike)
{
	switch (op->rtype) {
	case GT_X86_REG_GPR: put_gpr(o, op->reg, op->rsize, rexlike); break;
	case GT_X86_REG_SEG:
		if (op->reg > 7)
			o->bad = 1;
		else
			put(o, segn[op->reg]);
		break;
	case GT_X86_REG_FPU: if (op->reg > 7) o->bad = 1; else put_numbered(o, "st", op->reg); break;
	case GT_X86_REG_MMX: if (op->reg > 7) o->bad = 1; else put_numbered(o, "mm", op->reg); break;
	case GT_X86_REG_SSE:
		if (op->reg > 31)
			o->bad = 1;
		else if (op->rsize == 16)
			put_numbered(o, "xmm", op->reg);
		else if (op->rsize == 32)
			put_numbered(o, "ymm", op->reg);
		else if (op->rsize == 64)
			put_numbered(o, "zmm", op->reg);
		else
			o->bad = 1;
		break;
	case GT_X86_REG_CR: if (op->reg > 31) o->bad = 1; else put_numbered(o, "cr", op->reg); break;
	case GT_X86_REG_DR: if (op->reg > 31) o->bad = 1; else put_numbered(o, "dr", op->reg); break;
	case GT_X86_REG_TR: if (op->reg > 15) o->bad = 1; else put_numbered(o, "tr", op->reg); break;
	case GT_X86_REG_BND: if (op->reg > 3) o->bad = 1; else put_numbered(o, "bnd", op->reg); break;
	case GT_X86_REG_MSK: if (op->reg > 7) o->bad = 1; else put_numbered(o, "k", op->reg); break;
	case GT_X86_REG_TILE: if (op->reg > 7) o->bad = 1; else put_numbered(o, "tmm", op->reg); break;
	default: break;
	}
	if (op->count > 1) {
		char t[16];

		snprintf(t, sizeof t, "+%u", op->count - 1u);
		put(o, t);
	}
}

static void put_mem(struct out *o, const struct gt_x86_insn *I, const struct gt_x86_op *op,
		    uint64_t rip, int rexlike)
{
	/* A gather names the size of one element, not of everything it touches. */
	const unsigned size = (op->mf & GT_X86_M_VSIB) ? op->elem : op->size;
	const unsigned asz = gt_x86_asz(I);
	unsigned trim = asz == 2 ? 2u : asz == 4 ? 4u : 8u;
	uint64_t disp = (uint64_t)op->v;

	switch (size) {
	case 1: put(o, "byte ptr "); break;
	case 2: put(o, "word ptr "); break;
	case 4: put(o, "dword ptr "); break;
	case 6: put(o, "fword ptr "); break;
	case 8: put(o, "qword ptr "); break;
	case 10: put(o, "tbyte ptr "); break;
	case 16: put(o, "xmmword ptr "); break;
	case 32: put(o, "ymmword ptr "); break;
	case 48: put(o, "m384 ptr "); break;
	case 64: put(o, "zmmword ptr "); break;
	default: break;
	}
	/* A segment is named only when a prefix said so, and in 64-bit mode only fs and gs. */
	if ((op->mf & GT_X86_M_SEG) && I->segr &&
	    (I->mode != 64 || op->seg == 4 || op->seg == 5)) {
		put(o, segn[op->seg & 7]);
		put(o, ":");
	}
	put(o, "[");
	if (op->mf & GT_X86_M_BASE)
		put_gpr(o, op->base, op->bsz, rexlike);
	if (op->mf & GT_X86_M_INDEX) {
		if (op->mf & GT_X86_M_BASE)
			put(o, "+");
		if (op->isz >= 16 && (op->mf & GT_X86_M_VSIB)) {
			put_numbered(o, op->isz == 16 ? "xmm" : op->isz == 32 ? "ymm" : "zmm", op->index);
		} else {
			put_gpr(o, op->index, op->isz, rexlike);
		}
		if (op->scale != 1 && !(op->mf & GT_X86_M_MIB))
			putf(o, "*%llu", op->scale);
	}
	if (op->mf & GT_X86_M_DISP) {
		const int based = (op->mf & (GT_X86_M_BASE | GT_X86_M_INDEX)) != 0;
		uint64_t norm;

		if ((op->mf & GT_X86_M_DIRECT) || !based) {
			norm = disp;
		} else {
			/* Shown as a sign and a magnitude, at the width the bytes had. An EVEX disp8
			 * is already scaled, so its magnitude is just the absolute value. */
			if (I->sp == 3 && I->dsz == 1)
				norm = (disp >> 63) ? ~disp + 1ull : disp;
			else switch (I->dsz) {
			case 1: norm = ((disp & 0x80u) ? ~disp + 1ull : disp) & 0xffu; break;
			case 2: norm = ((disp & 0x8000u) ? ~disp + 1ull : disp) & 0xffffu; break;
			case 4: norm = ((disp & 0x80000000u) ? ~disp + 1ull : disp) & 0xffffffffu; break;
			default: norm = disp; break;
			}
		}
		if (based)
			put(o, (disp >> 63) ? "-" : "+");
		if (op->mf & GT_X86_M_RIPREL) {
			uint64_t target = disp + rip + I->len;

			if (asz == 4)
				target &= 0xffffffffu;
			putf(o, "rel 0x%llx", target);
		} else {
			if (trim < 8)
				norm &= (1ull << (8u * trim)) - 1ull;
			putf(o, "0x%llx", norm);
		}
	}
	put(o, "]");
}

size_t gt_x86_format(const struct gt_x86_insn *I, uint64_t rip, char *buf, size_t cap)
{
	const struct gt_x86_leaf *L = &gt_x86_leaves[I->leaf];
	const unsigned osz = I->osz;
	const unsigned mn = gt_x86_mnk[L->mnk][osz];
	const char *mnem = gt_x86_mnem[mn & 0xfffu];
	const unsigned wl = mn >> 12;               /* 1: 16-bit, 2: 32-bit, 3: 64-bit */
	const int lock = (I->flags & GF_X86_LOCK) != 0;
	const int rexlike = I->sp != 0 || (I->flags & GF_X86_REX) != 0;
	struct out o = { buf, 0, cap, 0 };
	unsigned k, shown = 0, nform = L->nform;

	if (!buf || cap < 32)
		return 0;
	buf[0] = 0;
	if (L->pf & GP_X86_REPC) {
		if (I->rep == 0xf3)
			put(&o, "REPZ ");
		else if (I->rep == 0xf2)
			put(&o, "REPNZ ");
	}
	if (L->pf & GP_X86_REP) {
		if (I->rep == 0xf3)
			put(&o, "REP ");
		else if (I->rep == 0xf2)
			put(&o, "REPNZ ");
	}
	{
		const int xacq = (L->pf & GP_X86_XACQ) || (lock && (L->pf2 & GQ_X86_XACQ_LOCK));
		const int xrel = (L->pf & GP_X86_XREL) || (lock && (L->pf2 & GQ_X86_XREL_LOCK));

		if (xrel)
			put(&o, "XRELEASE ");
		else if (xacq)
			put(&o, "XACQUIRE ");
	}
	/* In 32-bit mode a LOCK in front of a move to or from a control register is AMD's way
	 * of writing CR8 and is not a lock. */
	if (lock && !(I->mode == 32 && I->id == GT_X86_I_MOV_CR))
		put(&o, "LOCK ");
	if (L->pf & GP_X86_BND)
		put(&o, "BND ");
	if ((L->pf2 & GQ_X86_BHINT) && I->segr) {
		if (I->segr == 0x3e)
			put(&o, "BHT ");
		else if (I->segr == 0x2e)
			put(&o, "BHNT ");
		else if (I->segr == 0x64)
			put(&o, "BHALT ");
	}
	if ((L->pf2 & GQ_X86_DNT) && I->segr == 0x3e)
		put(&o, "DNT ");
	put(&o, mnem);
	if (!nform)
		return o.bad ? 0 : o.n;

	for (k = 0; k < nform; k++) {
		struct gt_x86_op op;

		gt_x86_operand(I, k, &op);
		if (op.type == GT_X86_OP_NONE)
			break;
		if ((op.flags & GT_X86_OF_DEFAULT) || op.type == GT_X86_OP_DFV)
			continue;
		/* The mask register an EVEX instruction names in aaa is printed as a decoration of
		 * the destination, not as an operand of its own. */
		if (op.enc == GT_X86_ENC_A && op.type == GT_X86_OP_REG && op.rtype == GT_X86_REG_MSK && k > 0)
			continue;
		if (!shown) {
			/* Operands start in column 10, or one space on if the mnemonic is longer. */
			while (o.n < 9 && !o.bad)
				put(&o, " ");
			put(&o, " ");
		} else {
			put(&o, ", ");
		}
		shown++;
		switch (op.type) {
		case GT_X86_OP_REG:
			put_reg(&o, &op, rexlike);
			break;
		case GT_X86_OP_BANK:
			break;
		case GT_X86_OP_CONST: {
			char t[24];

			snprintf(t, sizeof t, "%d", (int)op.v);
			put(&o, t);
			break;
		}
		case GT_X86_OP_IMM:
			switch (op.size) {
			case 1: putf(&o, "0x%02llx", (uint64_t)op.v & 0xffu); break;
			case 2: putf(&o, "0x%04llx", (uint64_t)op.v & 0xffffu); break;
			case 4: putf(&o, "0x%08llx", (uint64_t)op.v & 0xffffffffu); break;
			default: putf(&o, "0x%016llx", (uint64_t)op.v); break;
			}
			break;
		case GT_X86_OP_REL: {
			uint64_t dest = rip + I->len + (uint64_t)op.v;

			if (wl == 1)
				dest &= 0xffffu;
			else if (wl == 2)
				dest &= 0xffffffffu;
			putf(&o, "0x%llx", dest);
			break;
		}
		case GT_X86_OP_FAR: {
			const unsigned addr = gt_x86_lenk[L->lenk][3 * GT_X86_NOSZ + osz];
			char t[40];

			if (addr == 4)
				snprintf(t, sizeof t, "0x%04x:0x%04x", op.sel, (unsigned)(op.v & 0xffffu));
			else if (addr == 6)
				snprintf(t, sizeof t, "0x%04x:0x%08x", op.sel, (unsigned)(op.v & 0xffffffffu));
			else
				snprintf(t, sizeof t, "0x%04x:0x%016llx", op.sel, (unsigned long long)op.v);
			put(&o, t);
			break;
		}
		case GT_X86_OP_MEM:
			put_mem(&o, I, &op, rip, rexlike);
			/* An embedded broadcast: the element is repeated to fill the vector. */
			if (op.mf & GT_X86_M_BCAST)
				putf(&o, "{1to%llu}", op.elem);
			break;
		default:
			o.bad = 1;
			break;
		}
		if (I->sp == 3) {
			static const char *const round[4] = { "rn", "rd", "ru", "rz" };
			const unsigned aaa = I->evex & 7u;
			const int imm1 = gt_x86_lenk[L->lenk][osz] != 0;

			/* The mask and its zeroing belong to the destination, the first operand. */
			if (k == 0 && aaa) {
				putf(&o, "{k%llu}", aaa);
				if (I->evex & 0x80u)
					put(&o, "{z}");
			}
			/* Suppress-all-exceptions and embedded rounding sit after the last
			 * register or memory operand (before a trailing immediate). */
			if ((op.type == GT_X86_OP_MEM || op.type == GT_X86_OP_REG) &&
			    (k + 1 == nform || (k + 2 == nform && imm1))) {
				if ((L->pf & GP_X86_SAE) && !(L->pf & GP_X86_ER))
					put(&o, "{sae}");
				if (L->pf & GP_X86_ER) {
					put(&o, "{");
					put(&o, round[(I->evex >> 5) & 3u]);
					put(&o, "-sae}");
				}
			}
		}
	}
	return o.bad ? 0 : o.n;
}
