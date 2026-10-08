/*
 * x86.c - the decoder proper. A prefix scan, a walk down the generated tables to
 * the encoding's leaf, the length, and the raw displacement and immediates; and,
 * separately, an operand builder that reads the leaf's templates.
 *
 * NOTHING HERE KNOWS AN OPCODE. Every fact about what an encoding means is in the
 * tables; this file knows how x86 spells operands (ModRM, SIB, the REX bits, the
 * address and operand size rules) and how the prefixes combine. If a decode is
 * wrong, either the tables were generated wrong - re-run x86_gen.c and look at
 * what the reference said - or one of the rules below is, and the differential
 * test (tests/unit/genotype_x86.c) names which.
 *
 * THE MODE IS A CONSTANT IN THE HOT PATH. decode_core is written once and
 * instantiated for 32 and for 64, so the prefix table, the REX test and the
 * address size are folded at compile time instead of tested per instruction.
 */

#include <string.h>

#include "x86.h"
#include "x86_int.h"

/* Prefix classes. */
enum {
	P_NONE = 0, P_66, P_67, P_F0, P_F2, P_F3, P_SEG, P_REX
};

#define R16(c) c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c

static const uint8_t pfx32[256] = {
	[0x26] = P_SEG, [0x2e] = P_SEG, [0x36] = P_SEG, [0x3e] = P_SEG,
	[0x64] = P_SEG, [0x65] = P_SEG, [0x66] = P_66, [0x67] = P_67,
	[0xf0] = P_F0, [0xf2] = P_F2, [0xf3] = P_F3
};

static const uint8_t pfx64[256] = {
	[0x26] = P_SEG, [0x2e] = P_SEG, [0x36] = P_SEG, [0x3e] = P_SEG,
	[0x64] = P_SEG, [0x65] = P_SEG, [0x66] = P_66, [0x67] = P_67,
	[0xf0] = P_F0, [0xf2] = P_F2, [0xf3] = P_F3,
	[0x40] = P_REX, [0x41] = P_REX, [0x42] = P_REX, [0x43] = P_REX,
	[0x44] = P_REX, [0x45] = P_REX, [0x46] = P_REX, [0x47] = P_REX,
	[0x48] = P_REX, [0x49] = P_REX, [0x4a] = P_REX, [0x4b] = P_REX,
	[0x4c] = P_REX, [0x4d] = P_REX, [0x4e] = P_REX, [0x4f] = P_REX
};

/* ES, CS, SS, DS, FS, GS as the number a memory operand carries. */
static const uint8_t seg_of[256] = {
	[0x26] = 1, [0x2e] = 2, [0x36] = 3, [0x3e] = 4, [0x64] = 5, [0x65] = 6
};

static int64_t sx(uint64_t v, unsigned bytes)
{
	switch (bytes) {
	case 1: return (int8_t)v;
	case 2: return (int16_t)v;
	case 4: return (int32_t)v;
	}
	return (int64_t)v;
}

/* A little-endian read of `bytes` (1..8) that is safe at any alignment. */
static uint64_t rd_le(const uint8_t *p, unsigned bytes)
{
	uint64_t v = 0;

	switch (bytes) {
	case 1:
		return p[0];
	case 2: {
		uint16_t t;

		memcpy(&t, p, 2);
		return t;
	}
	case 4: {
		uint32_t t;

		memcpy(&t, p, 4);
		return t;
	}
	case 8:
		memcpy(&v, p, 8);
		return v;
	}
	{
		unsigned i;

		for (i = 0; i < bytes; i++)
			v |= (uint64_t)p[i] << (8u * i);
	}
	return v;
}

#define TRUNC_OR_BAD(lim) ((lim) < 15 ? GT_TRUNCATED : GT_INVALID)

/*
 * The checks on a register NUMBER that no table can hold, because they depend on
 * the REX bits and the prefixes and not on the opcode. They are made here, at
 * decode, and not when the operand is built: whether these bytes are an
 * instruction at all is the decoder's answer to give.
 *
 *   CR     0, 2, 3 and 4, and CR8 through REX.R (field 0 only). A LOCK in 32-bit
 *          mode is the same bit, and then any of the four.
 *   DR     0 to 7; REX.R makes it invalid.
 *   BND    0 to 3; no REX bit may extend it.
 *   MASK   k0 to k7 (the k registers of AVX-512), and the same for the AMX tiles.
 *   TILE   R (and EVEX.R') extends none and makes the instruction invalid; so does B
 *          on a tile in the r/m field; X is ignored;
 *          a vvvv above 7 is invalid.
 */
static int reg_number_ok(const struct gt_x86_leaf *L, unsigned modrm, unsigned rex,
			 unsigned vexv, unsigned xr)
{
	const struct gt_x86_tpl *t = &gt_x86_tpls[L->ops];
	unsigned k;

	for (k = 0; k < L->nops; k++, t++) {
		unsigned enc = t->te >> 4, f;

		if ((t->te & 15u) != GT_X86_OP_REG ||
		    (enc != GT_X86_ENC_R && enc != GT_X86_ENC_M && enc != GT_X86_ENC_V))
			continue;
		if (t->rtype != GT_X86_REG_CR && t->rtype != GT_X86_REG_DR &&
		    t->rtype != GT_X86_REG_BND && t->rtype != GT_X86_REG_MSK &&
		    t->rtype != GT_X86_REG_TILE)
			continue;
		f = enc == GT_X86_ENC_R ? (modrm >> 3) & 7u
		  : enc == GT_X86_ENC_M ? modrm & 7u : vexv & 15u;
		switch (t->rtype) {
		case GT_X86_REG_CR:
			if ((rex & 4) ? f != 0 : (f != 0 && (f < 2 || f > 4)))
				return 0;
			break;
		case GT_X86_REG_DR:
			if (rex & 4)
				return 0;
			break;
		case GT_X86_REG_BND:
			if (f > 3u || (rex & (enc == GT_X86_ENC_R ? 4 : 1)))
				return 0;
			break;
		default:
			/* A mask register has eight numbers, and no extension bit applies. */
			if (enc == GT_X86_ENC_V ? f > 7u : enc == GT_X86_ENC_R ? ((rex & 4) || xr)
				   : (t->rtype == GT_X86_REG_TILE && (rex & 1)))
				return 0;
			break;
		}
	}
	return 1;
}

/* The opcode bytes that may start a VEX, EVEX, XOP or REX2 prefix. */
static const uint8_t ext_op[256] = {
	[0x62] = 1, [0x8f] = 1, [0xc4] = 1, [0xc5] = 1, [0xd5] = 1
};

/* Space a decode lands in, and how many address-size variants each has. */
enum { SPACE_LEGACY, SPACE_VEX, SPACE_XOP, SPACE_EVEX };

static inline enum gt_status decode_core(struct gt_x86_insn *I, const uint8_t *p,
					 size_t n, const int mode64)
{
	const uint8_t *pfx = mode64 ? pfx64 : pfx32;
	/* One bound for the whole instruction: 15 bytes, or what the caller has. */
	const size_t lim = n < 15 ? n : 15;
	size_t i = 0;
	unsigned flags = 0;
	uint8_t rex = 0, seg = 0, segr = 0, rep = 0;
	unsigned map, opc, e, osz, asel, modrm = 0, have_modrm = 0, pp_last = 0;
	unsigned asz_bytes, rmap, sp = SPACE_LEGACY, vexv = 0, xr = 0, evex = 0, vpp = 0;
	unsigned sibv = 0;
	const struct gt_x86_leaf *L;
	const uint16_t *nodes;

	if (!lim)
		return GT_TRUNCATED;

	/* ---- prefixes ----------------------------------------------------- */
	for (;;) {
		uint8_t b, c;

		if (i >= lim)
			return TRUNC_OR_BAD(lim);
		b = p[i];
		c = pfx[b];
		if (!c)
			break;
		if (c == P_REX) {
			rex = b;
			i++;
			continue;
		}
		rex = 0;                /* a REX must be the last prefix: see opcode  */
		switch (c) {
		case P_66: flags |= GF_X86_66; break;
		case P_67: flags |= GF_X86_67; break;
		case P_F0: flags |= GF_X86_LOCK; break;
		case P_F2: flags |= GF_X86_F2; pp_last = 3; rep = b; break;
		case P_F3: flags |= GF_X86_F3; pp_last = 2; rep = b; break;
		default:
			/*
			 * WHICH SEGMENT PREFIX THE TEXT AND THE BRANCH HINTS SEE. In 32-bit
			 * mode the last one. In 64-bit mode the last FS or GS, if there is
			 * one; failing that a 3E (it doubles as do-not-track); failing that
			 * whichever came last. So `3e 26 jcc` is a taken hint and `64 2e jcc`
			 * is not an 'alt' of 2e.
			 */
			if (!mode64 || b == 0x64 || b == 0x65 ||
			    (b == 0x3e && segr != 0x64 && segr != 0x65) ||
			    (segr != 0x64 && segr != 0x65 && segr != 0x3e))
				segr = b;
			/* In 64-bit mode only FS and GS name a segment. */
			if (!mode64 || b == 0x64 || b == 0x65) {
				flags |= GF_X86_SEG;
				seg = b;
			}
			break;
		}
		i++;
	}
	if (rex)
		flags |= GF_X86_REX;

	/* ---- opcode ------------------------------------------------------- */
	opc = p[i++];
	map = 0;
	if (ext_op[opc]) {
		/*
		 * IS THIS A VEX, EVEX OR XOP PREFIX, or an ordinary instruction that
		 * happens to start with the same byte? In 64-bit mode C4, C5 and 62 are
		 * always a prefix; in 32-bit mode they are LES, LDS and BOUND unless the
		 * next byte has mod == 3. 8F is POP unless the next byte names an XOP
		 * map (8 or above).
		 */
		unsigned xop = opc == 0x8f;

		if (opc == 0xd5 && mode64)
			return GT_INVALID;      /* REX2 */
		if (opc != 0xd5 && (xop ? (i < lim && (p[i] & 0x1f) >= 8)
					: (mode64 || (i < lim && (p[i] >> 6) == 3)))) {
			unsigned b1, b2, w, r_, x_, b_, l, vv;

			/* No legacy size, repeat or lock prefix, and no REX, may precede. */
			if ((flags & (GF_X86_66 | GF_X86_F2 | GF_X86_F3 | GF_X86_LOCK)) || rex)
				return GT_INVALID;
			if (opc == 0xc5) {
				if (i + 2 > lim)
					return TRUNC_OR_BAD(lim);
				b1 = p[i];
				r_ = !(b1 & 0x80);
				x_ = 0;
				b_ = 0;
				w = 0;
				vv = (b1 >> 3) & 15u;
				l = (b1 >> 2) & 1u;
				vpp = b1 & 3u;
				map = 1;
				sp = SPACE_VEX;
				i += 1;
			} else if (opc == 0x62) {
				unsigned b3, ll, bb;

				if (i + 4 > lim)
					return TRUNC_OR_BAD(lim);
				b1 = p[i];
				b2 = p[i + 1];
				b3 = p[i + 2];
				/* P0 bit 3 and P1 bit 2 are fixed in the form this reads; the
				 * APX encodings that use them are not decoded. */
				if ((b1 & 0x08) || !(b2 & 0x04))
					return GT_INVALID;
				map = b1 & 7u;
				if (!(map == 1 || map == 2 || map == 3 || map == 5 || map == 6))
					return GT_INVALID;
				r_ = !(b1 & 0x80);
				x_ = !(b1 & 0x40);
				b_ = !(b1 & 0x20);
				xr = !(b1 & 0x10);
				w = b2 >> 7;
				vv = (b2 >> 3) & 15u;
				vpp = b2 & 3u;
				ll = (b3 >> 5) & 3u;
				bb = (b3 >> 4) & 1u;
				l = ll;
				evex = b3;
				vexv = (~vv & 15u) | (((b3 & 8) ? 0u : 1u) << 4);
				sp = SPACE_EVEX;
				osz = w | (ll << 1);
				asel = (((mode64 ? vv != 15u : (vv & 7u) != 7u) || !(b3 & 8)) ? 1u : 0u) |
				       (bb << 1) | ((b3 & 7u) ? 4u : 0u) | ((b3 >> 7) ? 8u : 0u);
				i += 3;
				goto ext_done;
			} else {
				if (i + 3 > lim)
					return TRUNC_OR_BAD(lim);
				b1 = p[i];
				b2 = p[i + 1];
				r_ = !(b1 & 0x80);
				x_ = !(b1 & 0x40);
				b_ = !(b1 & 0x20);
				map = b1 & 0x1f;
				w = b2 >> 7;
				vv = (b2 >> 3) & 15u;
				l = (b2 >> 2) & 1u;
				vpp = b2 & 3u;
				if (xop) {
					if (map > 10)
						return GT_INVALID;
					sp = SPACE_XOP;
				} else {
					/* Map 5 is the AMX tile instructions; the table
					 * has them for 64-bit mode only. */
					if (map < 1 || (map > 3 && map != 5))
						return GT_INVALID;
					sp = SPACE_VEX;
				}
				i += 2;
			}
			osz = (w << 1) | l;
			asel = vv != 15u;
			vexv = ~vv & 15u;
			/* A 32-bit process has eight registers: vvvv loses its top bit before
			 * anything asks whether it is in use. */
			if (!mode64)
				asel = (vv & 7u) != 7u;
ext_done:
			if (!mode64) {
				/* A 32-bit process has eight registers: B and R' are ignored,
				 * a vvvv above 7 loses its top bit, and an XOP that sets R or X
				 * (which VEX and EVEX cannot, or they would be LES and BOUND)
				 * is not an instruction. EVEX's V' must be clear. */
				if (sp == SPACE_XOP && (r_ || x_ || !(vv & 8u)))
					return GT_INVALID;
				if (sp == SPACE_EVEX && !(evex & 8u))
					return GT_INVALID;
				b_ = 0;
				xr = 0;
				vexv &= 7u;
			}
			rex = (uint8_t)((w << 3) | (r_ << 2) | (x_ << 1) | b_);
			if (i >= lim)
				return TRUNC_OR_BAD(lim);
			opc = p[i++];
		}
	}
	if (sp == SPACE_LEGACY) {
		if (opc == 0x0f) {
			if (i >= lim)
				return TRUNC_OR_BAD(lim);
			opc = p[i++];
			map = 1;
			if (opc == 0x38 || opc == 0x3a) {
				map = opc == 0x38 ? 2u : 3u;
				if (i >= lim)
					return TRUNC_OR_BAD(lim);
				opc = p[i++];
			} else if (opc == 0x0f) {
				return GT_INVALID;      /* 3DNow!: not yet */
			}
		}
		osz = ((rex & 8) ? 2u : 0u) | ((flags & GF_X86_66) ? 1u : 0u);
		asel = ((flags & GF_X86_67) ? 1u : 0u) | ((rex & 1u) ? 2u : 0u);
		rmap = map;
	} else {
		rmap = sp == SPACE_VEX ? (map == 5u ? 17u : 4u + map - 1u)
		     : sp == SPACE_XOP ? 7u + map - 8u : 10u + map - 1u;
	}
	I->mo = (uint8_t)i;

	/* ---- the walk ----------------------------------------------------- */
	nodes = gt_x86_space_nodes[sp];
	e = gt_x86_root[mode64][rmap][opc];
	while (e & 0x8000u) {
		const uint16_t *nd = &nodes[e & 0x7fffu];
		unsigned kind = nd[0] & 15u, idx;

		switch (kind) {
		case GK_X86_PP:
			if (sp != SPACE_LEGACY) {
				idx = vpp;
			} else if ((nd[0] >> 4) == 4u) {
				/* The root has a mandatory-66 form: F2 and F3 outrank the
				 * 66, which then stays a size prefix; alone, it is the opcode. */
				if (pp_last)
					idx = pp_last;
				else if (flags & GF_X86_66) {
					idx = 1;
					flags |= GF_X86_M66;
					osz &= 2u;
				} else {
					idx = 0;
				}
			} else {
				idx = pp_last == 2 ? 1u : pp_last == 3 ? 2u : 0u;
			}
			break;
		case GK_X86_MOD:
		case GK_X86_REG:
		case GK_X86_RM:
			if (!have_modrm) {
				if (i >= lim)
					return TRUNC_OR_BAD(lim);
				modrm = p[i];
				have_modrm = 1;
			}
			idx = kind == GK_X86_MOD ? ((modrm >> 6) == 3u ? 2u : (modrm >> 6) ? 1u : 0u)
			    : kind == GK_X86_REG ? (modrm >> 3) & 7u : modrm & 7u;
			break;
		case GK_X86_OB0:
		case GK_X86_OB1:
		case GK_X86_OB2:
			idx = (osz >> (kind - GK_X86_OB0)) & 1u;
			break;
		default:
			/* The address-size axis. Legacy: bit 0 a 67, bit 1 the REX.B that
			 * reinterprets the one opcode (0x90) that reads it. VEX and EVEX: see
			 * the encoding spaces in x86_gen.c. */
			idx = (asel >> (kind - GK_X86_AB0)) & 1u;
			break;
		}
		e = nd[1 + idx];
	}
	L = &gt_x86_leaves[e];
	if (!L->id)
		return GT_INVALID;
	if ((flags & GF_X86_LOCK) && !(L->flags & GL_X86_LOCK))
		return GT_INVALID;
	if (L->flags & GL_X86_VMASK) {
		/* Some combinations of size prefix, REX.W, address size and REX.B (or, for
		 * VEX, W, L and whether vvvv is in use) are not an instruction at all;
		 * the leaf says which. */
		const unsigned v = osz * (sp == SPACE_LEGACY ? 4u : sp == SPACE_EVEX ? 16u : 2u) + asel;

		if (!((gt_x86_vmask[L->vmk][v >> 3] >> (v & 7u)) & 1u))
			return GT_INVALID;
	}

	asz_bytes = mode64 ? ((flags & GF_X86_67) ? 4u : 8u)
			   : ((flags & GF_X86_67) ? 2u : 4u);
	/* MPX takes its addresses at 64 bits in 64-bit mode, whatever a 67 says. */
	if (mode64 && (L->id == GT_X86_I_BNDLDX || L->id == GT_X86_I_BNDSTX ||
			 L->id == GT_X86_I_BNDMK || L->id == GT_X86_I_BNDCL ||
			 L->id == GT_X86_I_BNDCU || L->id == GT_X86_I_BNDCN || L->id == GT_X86_I_BNDMOV))
		asz_bytes = 8;

	/* A mandatory 66 is not an operand-size prefix. */
	if (sp == SPACE_LEGACY && (L->mand & 1u)) {
		flags |= GF_X86_M66;
		osz &= 2u;
	}

	/* ---- ModRM, SIB, displacement, and what follows ------------------- */
	{
		unsigned dsz = 0;
		size_t tot;

		if (L->flags & GL_X86_MODRM) {
			if (!have_modrm) {
				if (i >= lim)
					return TRUNC_OR_BAD(lim);
				modrm = p[i];
			}
			i++;
			flags |= GF_X86_MODRM;
			if ((modrm >> 6) != 3u && !(L->flags & GL_X86_NOMEM)) {
				const unsigned mod = modrm >> 6, rm = modrm & 7u;

				if (asz_bytes == 2) {
					if (mod == 1)
						dsz = 1;
					else if (mod == 2 || (mod == 0 && rm == 6))
						dsz = 2;
				} else {
					unsigned sib = 0;

					if (rm == 4) {
						if (i >= lim)
							return TRUNC_OR_BAD(lim);
						sib = p[i++];
						sibv = sib;
						flags |= GF_X86_SIB;
					}
					if (mod == 1)
						dsz = 1;
					else if (mod == 2 || (mod == 0 && rm == 5) ||
						 (mod == 0 && (flags & GF_X86_SIB) && (sib & 7u) == 5u))
						dsz = 4;
					if (mode64 && mod == 0 && rm == 5)
						flags |= GF_X86_RIPREL;
				}
			}
			if ((L->flags & GL_X86_REGCHK) && !reg_number_ok(L, modrm, rex, vexv, xr))
				return GT_INVALID;
			if (L->dist) {
				/* Registers that must differ - see probe_dist in x86_gen.c. The
				 * leaf is a register form or a memory form, so only the checks
				 * that form can fail are set. */
				const unsigned reg = ((modrm >> 3) & 7u) | ((rex & 4) ? 8u : 0u) | (xr ? 16u : 0u);

				if ((modrm >> 6) == 3u) {
					const unsigned rm = (modrm & 7u) | ((rex & 1) ? 8u : 0u) |
							    ((sp == SPACE_EVEX && (rex & 2)) ? 16u : 0u);

					if (((L->dist & 1u) && reg == rm) || ((L->dist & 4u) && rm == vexv))
						return GT_INVALID;
				}
				if ((L->dist & 2u) && reg == vexv)
					return GT_INVALID;
				if ((flags & GF_X86_SIB) && (L->dist & 24u)) {
					const unsigned idx = ((sibv >> 3) & 7u) | ((rex & 2) ? 8u : 0u) |
							     ((sp == SPACE_EVEX && (vexv & 16u)) ? 16u : 0u);

					if (((L->dist & 8u) && reg == idx) || ((L->dist & 16u) && vexv == idx))
						return GT_INVALID;
				}
			}
		}
		/* Displacement, immediates, relative offset, far address and moffs:
		 * summed, not read - the bytes are kept and read when asked for. */
		tot = i + dsz + gt_x86_fix[L->lenk][osz] +
		      ((L->flags & GL_X86_MOFFS) ? asz_bytes : 0u);
		if (tot > 15)
			return GT_INVALID;
		if (tot > lim)
			return TRUNC_OR_BAD(lim);
		I->len = (uint8_t)tot;
		I->dsz = (uint8_t)dsz;
	}

	I->mode = mode64 ? 64 : 32;
	I->rex = rex;
	I->rep = rep;
	I->seg = seg;
	I->segr = segr;
	I->opc = (uint8_t)opc;
	I->id = L->id;
	I->leaf = (uint16_t)e;
	I->flags = (uint16_t)flags;
	I->osz = (uint8_t)osz;
	I->sp = (uint8_t)sp;
	I->vexv = (uint8_t)vexv;
	I->xr = (uint8_t)xr;
	I->evex = (uint8_t)evex;
	/* The bytes, for the operand builder. A whole 16 when the caller has them, as
	 * one move; the instruction's own length when it does not. */
	if (n >= 16)
		memcpy(I->code, p, 16);
	else
		memcpy(I->code, p, n);
	return GT_OK;
}

enum gt_status gt_x86_decode(struct gt_x86_insn *out, const uint8_t *p, size_t n,
			     int mode)
{
	return mode == 64 ? decode_core(out, p, n, 1) : decode_core(out, p, n, 0);
}

/* ---- attributes -------------------------------------------------------------- */

unsigned gt_x86_nops(const struct gt_x86_insn *I) { return gt_x86_leaves[I->leaf].nops; }
unsigned gt_x86_cat(const struct gt_x86_insn *I)  { return gt_x86_leaves[I->leaf].cat; }
unsigned gt_x86_cond(const struct gt_x86_insn *I) { return gt_x86_leaves[I->leaf].cond; }
unsigned gt_x86_mand(const struct gt_x86_insn *I) { return gt_x86_leaves[I->leaf].mand; }
unsigned gt_x86_nexp(const struct gt_x86_insn *I) { return gt_x86_leaves[I->leaf].nexp; }
unsigned gt_x86_nform(const struct gt_x86_insn *I) { return gt_x86_leaves[I->leaf].nform; }
unsigned gt_x86_repeated(const struct gt_x86_insn *I) { return (gt_x86_leaves[I->leaf].flags & GL_X86_REPEATED) != 0; }
unsigned gt_x86_wgpr(const struct gt_x86_insn *I) { return gt_x86_leaves[I->leaf].wgpr; }

unsigned gt_x86_osz(const struct gt_x86_insn *I)
{
	return I->osz;
}

unsigned gt_x86_asz(const struct gt_x86_insn *I)
{
	if (I->mode == 64) {
		if (I->id == GT_X86_I_BNDLDX || I->id == GT_X86_I_BNDSTX || I->id == GT_X86_I_BNDMK ||
		    I->id == GT_X86_I_BNDCL || I->id == GT_X86_I_BNDCU || I->id == GT_X86_I_BNDCN ||
		    I->id == GT_X86_I_BNDMOV)
			return 8;
		return (I->flags & GF_X86_67) ? 4u : 8u;
	}
	return (I->flags & GF_X86_67) ? 2u : 4u;
}

unsigned gt_x86_efop(const struct gt_x86_insn *I)
{
	return gt_x86_tri[gt_x86_leaves[I->leaf].opszk][gt_x86_osz(I)];
}

/* ---- operands ---------------------------------------------------------------- */

/* Register numbers get the REX extension bit only for these classes. */
static int ext_class(uint8_t rtype)
{
	return rtype == GT_X86_REG_GPR || rtype == GT_X86_REG_SSE ||
	       rtype == GT_X86_REG_CR || rtype == GT_X86_REG_DR;
}

/*
 * The raw bytes of the j-th immediate-like field of an instruction, in the order
 * they sit after the displacement: a moffs, a far address, a relative offset, a
 * first immediate, a second. `size` is how many bytes it is.
 */
static uint64_t field_of(const struct gt_x86_insn *I, const struct gt_x86_leaf *L,
			 unsigned osz, unsigned asz, unsigned j, unsigned *size)
{
	const uint8_t *lk = gt_x86_lenk[L->lenk];
	unsigned sizes[5], at = (unsigned)I->mo + ((I->flags & GF_X86_MODRM) ? 1u : 0u) +
				((I->flags & GF_X86_SIB) ? 1u : 0u) + I->dsz;
	unsigned q;

	sizes[0] = (L->flags & GL_X86_MOFFS) ? asz : 0u;
	sizes[1] = lk[3 * GT_X86_NOSZ + osz];           /* far address */
	sizes[2] = lk[2 * GT_X86_NOSZ + osz];           /* relative offset */
	sizes[3] = lk[osz];                             /* first immediate */
	sizes[4] = lk[GT_X86_NOSZ + osz];               /* second immediate */
	for (q = 0; q < 5; q++) {
		if (!sizes[q])
			continue;
		if (!j--) {
			*size = sizes[q];
			return rd_le(I->code + at, sizes[q]);
		}
		at += sizes[q];
	}
	*size = 0;
	return 0;
}

void gt_x86_operand(const struct gt_x86_insn *I, unsigned k, struct gt_x86_op *o)
{
	const struct gt_x86_leaf *L = &gt_x86_leaves[I->leaf];
	const struct gt_x86_tpl *t = &gt_x86_tpls[L->ops], *tk;
	const unsigned osz = gt_x86_osz(I), asz_bytes = gt_x86_asz(I);
	const unsigned rex = I->rex, seg = I->seg, mode64 = I->mode == 64;
	const unsigned mo = I->mo;
	const unsigned modrm = (I->flags & GF_X86_MODRM) ? I->code[mo] : 0u;
	const unsigned sib = (I->flags & GF_X86_SIB) ? I->code[mo + 1] : 0u;
	unsigned type, enc, field = 0, j;

	/* Which of the instruction's immediate-like fields is this operand's: one
	 * for each earlier operand that is an immediate, a relative offset, a far
	 * address or a moffs. A register named in an immediate byte (is4) reads the
	 * field without using it up: when an instruction also has an immediate
	 * operand, the two are halves of one byte. */
	for (j = 0; j < k; j++) {
		unsigned ty = t[j].te & 15u;

		if (ty == GT_X86_OP_IMM || ty == GT_X86_OP_REL || ty == GT_X86_OP_FAR ||
		    (ty == GT_X86_OP_MEM && (t[j].memf & 4u)))
			field++;
	}
	tk = &t[k];
	type = tk->te & 15u;
	enc = tk->te >> 4;

	o->type = (uint8_t)type;
	o->enc = (uint8_t)enc;
	o->acc = tk->acc;
	o->flags = tk->flags & 7u;
	o->size = (uint16_t)gt_x86_tri[tk->szk][osz];
	o->rtype = o->high8 = 0;
	o->rsize = 0;
	o->reg = 0;
	o->seg = o->base = o->index = o->scale = 0;
	o->bsz = o->isz = o->rawsize = o->count = 0;
	o->mf = 0;
	o->sel = 0;
	o->v = 0;
	o->elem = (uint16_t)gt_x86_tri[tk->ek][osz];
	switch (type) {
	case GT_X86_OP_REG: {
		unsigned r;

		o->rtype = tk->rtype;
		o->rsize = (uint16_t)gt_x86_tri[tk->rszk][osz];
		if (tk->ad) {
			o->rsize = (uint16_t)asz_bytes;
			o->size = (uint16_t)asz_bytes;
		}
		o->count = tk->cnt;
		switch (enc) {
		case GT_X86_ENC_R:
			r = (modrm >> 3) & 7u;
			if (tk->rtype == GT_X86_REG_CR) {
				/* decode has already refused an impossible number */
				if ((rex & 4) || (!mode64 && (I->flags & GF_X86_LOCK)))
					r |= 8u;
			} else if ((rex & 4) && ext_class(tk->rtype)) {
				r |= 8u;
			}
			/* EVEX.R' is the fifth bit of a vector register. */
			if (I->xr && tk->rtype == GT_X86_REG_SSE)
				r |= 16u;
			break;
		case GT_X86_ENC_M:
			r = modrm & 7u;
			if ((rex & 1) && ext_class(tk->rtype))
				r |= 8u;
			/* EVEX.X is the fifth bit of a vector register in the r/m field. */
			if (I->sp == SPACE_EVEX && (rex & 2) && tk->rtype == GT_X86_REG_SSE)
				r |= 16u;
			break;
		case GT_X86_ENC_O:
			r = I->opc & 7u;
			if ((rex & 1) && ext_class(tk->rtype))
				r |= 8u;
			break;
		case GT_X86_ENC_V:
			r = I->vexv & (tk->rtype == GT_X86_REG_SSE ? 31u
				       : tk->rtype == GT_X86_REG_MSK ? 7u : 15u);
			break;
		case GT_X86_ENC_L: {
			unsigned sz4;

			/* The register is in the high four bits of an immediate byte. */
			r = (unsigned)(field_of(I, L, osz, asz_bytes, field, &sz4) >> 4) & 15u;
			if (!mode64)
				r &= 7u;
			break;
		}
		case GT_X86_ENC_A:
			r = I->evex & 7u;           /* the mask register EVEX.aaa names */
			break;
		default:
			r = tk->reg;
			break;
		}
		/* A block of registers (V4FMADDPS's four) starts on a multiple of its size. */
		if (tk->cnt > 1)
			r &= ~(unsigned)(tk->cnt - 1u);
		o->reg = r;
		if (I->sp == SPACE_LEGACY && tk->rtype == GT_X86_REG_GPR && o->rsize == 1 &&
		    r >= 4 && r < 8 &&
		    (!rex || enc == GT_X86_ENC_NP || enc == GT_X86_ENC_S || enc == GT_X86_ENC_C))
			o->high8 = 1;
		break;
	}
	case GT_X86_OP_MEM:
		o->mf = (uint16_t)((unsigned)tk->memf << 8);
		if (!(tk->memf & 4u) && enc != GT_X86_ENC_M) {
			/* Implicit: the stack, a string operand, a table. */
			if (enc == GT_X86_ENC_R) {
				/* [reg]: the register in the reg field is the address (ENQCMD). */
				o->mf |= GT_X86_M_BASE;
				o->base = (uint8_t)(((modrm >> 3) & 7u) | ((rex & 4) ? 8u : 0u));
				o->bsz = (uint8_t)asz_bytes;
			} else if (tk->base != 0xffu) {
				o->mf |= GT_X86_M_BASE;
				o->base = tk->base;
				/* The stack and frame pointers follow the stack size; string
				 * and table operands the address's. */
				o->bsz = (uint8_t)(((tk->memf & 1u) || tk->base == 5u)
						   ? (mode64 ? 8u : 4u) : asz_bytes);
			}
			if (tk->reg != 0xffu && (tk->memf & 0x80u) == 0 && tk->cnt) {
				o->mf |= GT_X86_M_INDEX;
				o->index = (uint8_t)tk->reg;
				o->scale = tk->cnt;
				o->isz = (uint8_t)gt_x86_tri[tk->rawk][osz];
			}
			if (tk->seg != 0xffu) {
				o->mf |= GT_X86_M_SEG;
				/* A source string operand takes an override. */
				o->seg = (tk->seg == 3u && seg) ? (uint8_t)(seg_of[seg] - 1u) : tk->seg;
			}
		} else if (tk->memf & 4u) {                 /* moffs */
			unsigned sz;

			o->mf |= GT_X86_M_DISP | GT_X86_M_SEG;
			o->v = (int64_t)field_of(I, L, osz, asz_bytes, field, &sz);
			o->seg = seg ? (uint8_t)(seg_of[seg] - 1u) : 3u;
		} else if ((modrm >> 6) == 3u) {
			/* A register in the r/m field that names a memory operand (UMONITOR). */
			o->mf |= GT_X86_M_BASE;
			o->base = (uint8_t)((modrm & 7u) | ((rex & 1) ? 8u : 0u));
			o->bsz = (uint8_t)asz_bytes;
			o->mf |= GT_X86_M_SEG;
			o->seg = seg ? (uint8_t)(seg_of[seg] - 1u) : 3u;
		} else {
			const unsigned mod = modrm >> 6, rm = modrm & 7u;

			if (asz_bytes == 2) {
				static const uint8_t b16[8] = { 3, 3, 5, 5, 6, 7, 5, 3 };
				static const uint8_t i16[8] = { 6, 7, 6, 7, 0xff, 0xff, 0xff, 0xff };

				if (!(mod == 0 && rm == 6)) {
					o->mf |= GT_X86_M_BASE;
					o->base = b16[rm];
					o->bsz = 2;
				}
				if (i16[rm] != 0xff) {
					o->mf |= GT_X86_M_INDEX;
					o->index = i16[rm];
					o->isz = 2;
					o->scale = 1;
				}
			} else {
				const unsigned bx = (rex & 1) ? 8u : 0u;

				if (rm == 4) {
					unsigned ib = (sib >> 3) & 7u, bs = sib & 7u;

					if (rex & 2)
						ib |= 8u;
					if (tk->memf & 64u) {
						/* A gather's index is a vector register, whatever its
						 * number is - xmm4 is not "no index". */
						if (I->vexv & 16u && I->sp == SPACE_EVEX)
							ib |= 16u;
						o->mf |= GT_X86_M_INDEX;
						o->index = (uint8_t)ib;
						o->isz = (uint8_t)gt_x86_tri[tk->rszk][osz];
						o->scale = (uint8_t)(1u << (sib >> 6));
					} else if (ib != 4u) {
						o->mf |= GT_X86_M_INDEX;
						o->index = (uint8_t)ib;
						o->isz = (uint8_t)asz_bytes;
						o->scale = (uint8_t)(1u << (sib >> 6));
					}
					if (!(mod == 0 && bs == 5)) {
						o->mf |= GT_X86_M_BASE;
						o->base = (uint8_t)(bs | bx);
						o->bsz = (uint8_t)asz_bytes;
					}
				} else if (!(mod == 0 && rm == 5)) {
					o->mf |= GT_X86_M_BASE;
					o->base = (uint8_t)(rm | bx);
					o->bsz = (uint8_t)asz_bytes;
				} else if (mode64) {
					o->mf |= GT_X86_M_RIPREL;
				}
			}
			if (I->dsz) {
				const unsigned dat = mo + 1u + ((I->flags & GF_X86_SIB) ? 1u : 0u);

				o->mf |= GT_X86_M_DISP;
				o->v = sx(rd_le(I->code + dat, I->dsz), I->dsz);
				/* An EVEX disp8 counts in units of the operand's width. */
				if (I->sp == SPACE_EVEX && I->dsz == 1) {
					const unsigned scale = gt_x86_tri[tk->rawk][osz];

					if (scale)
						o->v *= (int64_t)scale;
				}
			}
			if (I->sp == SPACE_EVEX && (I->evex & 0x10u))
				o->mf |= GT_X86_M_BCAST;
			/* A segment is always named: the override, else the stack segment
			 * for an sp or bp base, else ds. lea names none. */
			if (!(tk->memf & 8u)) {
				o->mf |= GT_X86_M_SEG;
				o->seg = seg ? (uint8_t)(seg_of[seg] - 1u)
					     : ((o->mf & GT_X86_M_BASE) &&
						(o->base == 4u || o->base == 5u)) ? 2u : 3u;
			}
		}
		break;
	case GT_X86_OP_IMM: {
		unsigned rs;
		uint64_t v = field_of(I, L, osz, asz_bytes, field, &rs);

		o->rawsize = (uint8_t)rs;
		if (enc == GT_X86_ENC_L)
			o->v = (int64_t)(v & 3u);   /* the two low bits beside an is4 register */
		else if (tk->flags & (GT_X86_OF_SEXT_OP1 | GT_X86_OF_SEXT_DWS))
			o->v = sx(v, rs);
		else
			o->v = (int64_t)v;
		break;
	}
	case GT_X86_OP_REL: {
		unsigned rs;
		uint64_t v = field_of(I, L, osz, asz_bytes, field, &rs);

		o->v = sx(v, rs);
		break;
	}
	case GT_X86_OP_FAR: {
		unsigned rs;
		uint64_t v = field_of(I, L, osz, asz_bytes, field, &rs);

		o->v = (int64_t)(v & ((1ull << (8u * (rs - 2u))) - 1u));
		o->sel = (uint16_t)(v >> (8u * (rs - 2u)));
		break;
	}
	case GT_X86_OP_CONST:
		o->v = tk->reg;
		break;
	default:
		break;
	}
}

void gt_x86_operands(const struct gt_x86_insn *I, struct gt_x86_op *out)
{
	unsigned k, n = gt_x86_nops(I);

	for (k = 0; k < n; k++)
		gt_x86_operand(I, k, &out[k]);
}
