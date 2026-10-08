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

/*
 * What a first byte is, from one table per mode. P_NONE: an opcode of the one-byte
 * map that starts nothing. P_66 .. P_REX: a prefix. P_0F: the escape to the two-byte
 * map. P_EXT: a byte that may begin a VEX, EVEX, XOP or REX2 prefix. The last two
 * are not prefixes - the scan stops at them - but they are classed here so the fast
 * path in decode_core and the scan read the same table: they were a second table
 * (ext_op) and two compares.
 */
enum {
	P_NONE = 0, P_66, P_67, P_F0, P_F2, P_F3, P_SEG, P_REX, P_0F, P_EXT
};

#define IS_PREFIX(c) ((c) != P_NONE && (c) < P_0F)

#define R16(c) c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c

static const uint8_t pfx32[256] = {
	[0x26] = P_SEG, [0x2e] = P_SEG, [0x36] = P_SEG, [0x3e] = P_SEG,
	[0x64] = P_SEG, [0x65] = P_SEG, [0x66] = P_66, [0x67] = P_67,
	[0xf0] = P_F0, [0xf2] = P_F2, [0xf3] = P_F3,
	[0x0f] = P_0F,
	[0x62] = P_EXT, [0x8f] = P_EXT, [0xc4] = P_EXT, [0xc5] = P_EXT, [0xd5] = P_EXT
};

static const uint8_t pfx64[256] = {
	[0x26] = P_SEG, [0x2e] = P_SEG, [0x36] = P_SEG, [0x3e] = P_SEG,
	[0x64] = P_SEG, [0x65] = P_SEG, [0x66] = P_66, [0x67] = P_67,
	[0xf0] = P_F0, [0xf2] = P_F2, [0xf3] = P_F3,
	[0x0f] = P_0F,
	[0x62] = P_EXT, [0x8f] = P_EXT, [0xc4] = P_EXT, [0xc5] = P_EXT, [0xd5] = P_EXT,
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

/* Space a decode lands in, and how many address-size variants each has. */
enum { SPACE_LEGACY, SPACE_VEX, SPACE_XOP, SPACE_EVEX };

/*
 * THE DECODE FROM THE OPCODE ON - the tree walk, the leaf's checks, the length -
 * written once and instantiated twice by decode_core: for a legacy encoding, whose
 * VEX/EVEX state (vexv, xr, evex, vpp) is a constant here and folds away, and for
 * VEX, XOP and EVEX. MEASURED, with that state live the function ran out of
 * registers: the legacy path, which is nearly every instruction, stored and
 * reloaded the zeroes of four variables it never reads and spilled a dozen more.
 */
static inline __attribute__((always_inline))
enum gt_status decode_rest(struct gt_x86_insn *I, const uint8_t *p,
			   const size_t lim, size_t i, unsigned flags, unsigned rex,
			   unsigned seg, unsigned segr, unsigned rep, unsigned pp_last,
			   unsigned opc, unsigned rmap, unsigned osz, unsigned asel,
			   const unsigned sp, const unsigned vexv, const unsigned xr,
			   const unsigned evex, const unsigned vpp, const int mode64)
{
	unsigned e, modrm = 0, have_modrm = 0, asz_bytes, sibv = 0;
	const struct gt_x86_leaf *L;
	const uint16_t *nodes;

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
	I->asz = (uint8_t)asz_bytes;
	I->sp = (uint8_t)sp;
	I->vexv = (uint8_t)vexv;
	I->xr = (uint8_t)xr;
	I->evex = (uint8_t)evex;
	return GT_OK;
}

static inline __attribute__((always_inline))
enum gt_status decode_general(struct gt_x86_insn *I, const uint8_t *p, size_t n,
			      const int mode64)
{
	const uint8_t *pfx = mode64 ? pfx64 : pfx32;
	/* One bound for the whole instruction: 15 bytes, or what the caller has. */
	const size_t lim = n < 15 ? n : 15;
	size_t i = 0;
	unsigned flags = 0;
	uint8_t rex = 0, seg = 0, segr = 0, rep = 0;
	unsigned map, opc, osz, asel, pp_last = 0, c = P_NONE;
	unsigned rmap, sp = SPACE_LEGACY, vexv = 0, xr = 0, evex = 0, vpp = 0;

	if (!lim)
		return GT_TRUNCATED;

	/* ---- prefixes ----------------------------------------------------- */
	for (;;) {
		uint8_t b;

		if (i >= lim)
			return TRUNC_OR_BAD(lim);
		b = p[i];
		c = pfx[b];
		if (!IS_PREFIX(c))
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
	if (c == P_EXT) {
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
		/* The legacy encoding has no VEX/EVEX state: the constants fold it away. */
		return decode_rest(I, p, lim, i, flags, rex, seg, segr, rep, pp_last, opc,
				   map, osz, asel, SPACE_LEGACY, 0, 0, 0, 0, mode64);
	}
	rmap = sp == SPACE_VEX ? (map == 5u ? 17u : 4u + map - 1u)
	     : sp == SPACE_XOP ? 7u + map - 8u : 10u + map - 1u;
	return decode_rest(I, p, lim, i, flags, rex, seg, segr, rep, pp_last, opc,
			   rmap, osz, asel, sp, vexv, xr, evex, vpp, mode64);
}

/* The full prefix scan, once per mode: the path for anything the fast path declines. */
static __attribute__((noinline))
enum gt_status decode_slow32(struct gt_x86_insn *I, const uint8_t *p, size_t n)
{
	return decode_general(I, p, n, 0);
}

static __attribute__((noinline))
enum gt_status decode_slow64(struct gt_x86_insn *I, const uint8_t *p, size_t n)
{
	return decode_general(I, p, n, 1);
}

/*
 * THE COMMON INSTRUCTION, WITHOUT THE PREFIX SCAN. An instruction that begins with
 * an opcode of the one-byte map, or 0F and an opcode of the two-byte map, with at
 * most a REX in front, has no legacy prefix, no VEX state and no segment, and
 * every state variable decode_rest takes is a constant or follows from the REX.
 * MEASURED over 3.16 M decodes of the code blobs, that is the shape of
 * nearly every instruction, and the general scan cost 213 instructions executed
 * per decode on it, a third of them setting up and spilling state that was zero.
 * The bytes the fast path does not take (a prefix after the REX, a 3-byte map, an
 * extended lead, the 3DNow! escape) go to decode_general, which is the original
 * scan - so the two can only disagree on a byte this one accepts.
 */
/* What decode_fast answers when the bytes are not its kind. Not a gt_status. */
#define DECODE_DECLINED 3

static inline __attribute__((always_inline))
int decode_fast(struct gt_x86_insn *I, const uint8_t *p, size_t n, const int mode64)
{
	const uint8_t *pfx = mode64 ? pfx64 : pfx32;
	const size_t lim = n < 15 ? n : 15;
	unsigned rex = 0, opc, rmap = 0, c;
	size_t i = 1;

	if (!lim)
		return GT_TRUNCATED;
	opc = p[0];
	c = pfx[opc];
	if (c == P_REX) {
		if (lim < 2)
			return DECODE_DECLINED;
		rex = opc;
		opc = p[1];
		c = pfx[opc];
		i = 2;
	}
	if (c == P_0F) {
		if (i >= lim)
			return DECODE_DECLINED;
		opc = p[i++];
		if (opc == 0x38 || opc == 0x3a || opc == 0x0f)
			return DECODE_DECLINED;
		rmap = 1;
	} else if (c != P_NONE) {
		return DECODE_DECLINED;
	}
	return decode_rest(I, p, lim, i, rex ? GF_X86_REX : 0u, rex, 0, 0, 0, 0, opc, rmap,
			   (rex & 8) ? 2u : 0u, (rex & 1u) ? 2u : 0u, SPACE_LEGACY, 0, 0, 0, 0, mode64);
}

enum gt_status gt_x86_decode(struct gt_x86_insn *out, const uint8_t *p, size_t n,
			     int mode)
{
	int st = mode == 64 ? decode_fast(out, p, n, 1) : decode_fast(out, p, n, 0);

	if (st == DECODE_DECLINED)
		st = mode == 64 ? decode_slow64(out, p, n) : decode_slow32(out, p, n);
	if (st == GT_OK) {
		/* The bytes, for the operand builder. A whole 16 when the caller has them,
		 * as one move; what it has when it does not. */
		if (n >= 16)
			memcpy(out->code, p, 16);
		else
			memcpy(out->code, p, n);
	}
	return (enum gt_status)st;
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
	return I->asz;
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
 * WHAT AN INSTRUCTION'S OPERANDS SHARE. Everything below read it again for every
 * operand of every instruction: the leaf, the size selector, the address size
 * (which gt_x86_asz re-derived from the id each time), the ModRM and SIB bytes,
 * and the sizes of the immediate-like fields. MEASURED over a whole scan of a 7 MB
 * static ELF, building the operands one at a time was 150 instructions per
 * operand (862 M of 4.28 G), a third of them this set-up and the walk over the
 * earlier operands that found which field an operand reads. It is made ONCE per
 * instruction now, and the field an operand reads is counted as the operands go by.
 */
struct octx {
	const uint8_t *code;            /* the instruction's own bytes */
	const struct gt_x86_leaf *L;
	const struct gt_x86_tpl *t;
	unsigned osz, asz, rex, seg, mode64, mo, modrm, sib;
	unsigned flags, xr, sp, opc, vexv, evex, dsz;
};

/*
 * A COPY OF THE DECODED STRUCT'S SCALARS AND NOT A POINTER TO IT. The sweep
 * decodes into a local and builds its operands from the same local; a pointer to
 * it in here is an escape, and the decoded struct then lives in memory - stored
 * field by field, loaded back field by field - where as scalars it never leaves
 * the registers.
 */
static inline __attribute__((always_inline))
void octx_init(struct octx *c, const struct gt_x86_insn *I, const uint8_t *code)
{
	c->code = code;
	c->L = &gt_x86_leaves[I->leaf];
	c->t = &gt_x86_tpls[c->L->ops];
	c->osz = I->osz;
	c->asz = I->asz;
	c->rex = I->rex;
	c->seg = I->seg;
	c->mode64 = I->mode == 64;
	c->mo = I->mo;
	c->flags = I->flags;
	c->xr = I->xr;
	c->sp = I->sp;
	c->opc = I->opc;
	c->vexv = I->vexv;
	c->evex = I->evex;
	c->dsz = I->dsz;
	c->modrm = (I->flags & GF_X86_MODRM) ? code[c->mo] : 0u;
	c->sib = (I->flags & GF_X86_SIB) ? code[c->mo + 1] : 0u;
}

/*
 * The raw bytes of the j-th immediate-like field of an instruction, in the order
 * they sit after the displacement: a moffs, a far address, a relative offset, a
 * first immediate, a second. `size` is how many bytes it is.
 */
static inline __attribute__((always_inline))
uint64_t field_of(const struct octx *c, unsigned j, unsigned *size)
{
	const uint8_t *lk = gt_x86_lenk[c->L->lenk];
	unsigned at = c->mo + ((c->flags & GF_X86_MODRM) ? 1u : 0u) +
		      ((c->flags & GF_X86_SIB) ? 1u : 0u) + c->dsz, q;
	unsigned sizes[5];

	sizes[0] = (c->L->flags & GL_X86_MOFFS) ? c->asz : 0u;
	sizes[1] = lk[3 * GT_X86_NOSZ + c->osz];        /* far address */
	sizes[2] = lk[2 * GT_X86_NOSZ + c->osz];        /* relative offset */
	sizes[3] = lk[c->osz];                          /* first immediate */
	sizes[4] = lk[GT_X86_NOSZ + c->osz];            /* second immediate */
	for (q = 0; q < 5; q++) {
		unsigned sz = sizes[q];

		if (!sz)
			continue;
		if (!j--) {
			*size = sz;
			return rd_le(c->code + at, sz);
		}
		at += sz;
	}
	*size = 0;
	return 0;
}

/* Does operand template `t` use up one of the instruction's immediate-like fields?
 * A register named in an immediate byte (is4) reads the field without using it up:
 * when an instruction also has an immediate operand, the two are halves of one byte. */
static inline unsigned takes_field(const struct gt_x86_tpl *t)
{
	unsigned ty = t->te & 15u;

	return ty == GT_X86_OP_IMM || ty == GT_X86_OP_REL || ty == GT_X86_OP_FAR ||
	       (ty == GT_X86_OP_MEM && (t->memf & 4u));
}

/*
 * Operand k, which reads immediate-like field `field` if it reads one.
 *
 * `lean` IS A CONSTANT AT EVERY CALL, so there are two instantiations of the one
 * body and not two builders. Lean builds what gt_x86_explicit promises and not a
 * field more: type, acc and size always; for a general register its number and
 * whether it is AH..BH; for a memory operand mf and, when mf says so, base, index,
 * scale, seg and the displacement in v; for an immediate or a relative offset v.
 * Nothing else is zeroed or written - MEASURED, clearing the 56 bytes and filling
 * the fields the sweep never reads was a third of building an operand.
 */
#define XO(f, val) do { if (!lean) o->f = (val); } while (0)

static inline __attribute__((always_inline))
void build_op(struct octx *c, unsigned k, unsigned field, struct gt_x86_op *o, const int lean)
{
	const struct gt_x86_tpl *tk = &c->t[k];
	const unsigned osz = c->osz, asz_bytes = c->asz;
	const unsigned rex = c->rex, seg = c->seg, mode64 = c->mode64;
	const unsigned mo = c->mo, modrm = c->modrm, sib = c->sib;
	unsigned type, enc;

	type = tk->te & 15u;
	enc = tk->te >> 4;

	if (!lean)
		memset(o, 0, sizeof *o);
	o->type = (uint8_t)type;
	o->acc = tk->acc;
	o->size = (uint16_t)gt_x86_tri[tk->szk][osz];
	XO(enc, (uint8_t)enc);
	XO(flags, tk->flags & 7u);
	XO(elem, (uint16_t)gt_x86_tri[tk->ek][osz]);
	switch (type) {
	case GT_X86_OP_REG: {
		unsigned r, rsz = gt_x86_tri[tk->rszk][osz];

		o->rtype = tk->rtype;
		if (tk->ad) {
			rsz = asz_bytes;
			o->size = (uint16_t)asz_bytes;
		}
		XO(rsize, (uint16_t)rsz);
		XO(count, tk->cnt);
		if (lean && tk->rtype != GT_X86_REG_GPR)
			break;                      /* the sweep tracks general registers only */
		switch (enc) {
		case GT_X86_ENC_R:
			r = (modrm >> 3) & 7u;
			if (tk->rtype == GT_X86_REG_CR) {
				/* decode has already refused an impossible number */
				if ((rex & 4) || (!mode64 && (c->flags & GF_X86_LOCK)))
					r |= 8u;
			} else if ((rex & 4) && ext_class(tk->rtype)) {
				r |= 8u;
			}
			/* EVEX.R' is the fifth bit of a vector register. */
			if (c->xr && tk->rtype == GT_X86_REG_SSE)
				r |= 16u;
			break;
		case GT_X86_ENC_M:
			r = modrm & 7u;
			if ((rex & 1) && ext_class(tk->rtype))
				r |= 8u;
			/* EVEX.X is the fifth bit of a vector register in the r/m field. */
			if (c->sp == SPACE_EVEX && (rex & 2) && tk->rtype == GT_X86_REG_SSE)
				r |= 16u;
			break;
		case GT_X86_ENC_O:
			r = c->opc & 7u;
			if ((rex & 1) && ext_class(tk->rtype))
				r |= 8u;
			break;
		case GT_X86_ENC_V:
			r = c->vexv & (tk->rtype == GT_X86_REG_SSE ? 31u
				       : tk->rtype == GT_X86_REG_MSK ? 7u : 15u);
			break;
		case GT_X86_ENC_L: {
			unsigned sz4;

			/* The register is in the high four bits of an immediate byte. */
			r = (unsigned)(field_of(c, field, &sz4) >> 4) & 15u;
			if (!mode64)
				r &= 7u;
			break;
		}
		case GT_X86_ENC_A:
			r = c->evex & 7u;           /* the mask register EVEX.aaa names */
			break;
		default:
			r = tk->reg;
			break;
		}
		/* A block of registers (V4FMADDPS's four) starts on a multiple of its size. */
		if (tk->cnt > 1)
			r &= ~(unsigned)(tk->cnt - 1u);
		o->reg = r;
		o->high8 = c->sp == SPACE_LEGACY && tk->rtype == GT_X86_REG_GPR && rsz == 1 &&
			   r >= 4 && r < 8 &&
			   (!rex || enc == GT_X86_ENC_NP || enc == GT_X86_ENC_S || enc == GT_X86_ENC_C);
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
				XO(bsz, (uint8_t)asz_bytes);
			} else if (tk->base != 0xffu) {
				o->mf |= GT_X86_M_BASE;
				o->base = tk->base;
				/* The stack and frame pointers follow the stack size; string
				 * and table operands the address's. */
				XO(bsz, (uint8_t)(((tk->memf & 1u) || tk->base == 5u)
						  ? (mode64 ? 8u : 4u) : asz_bytes));
			}
			if (tk->reg != 0xffu && (tk->memf & 0x80u) == 0 && tk->cnt) {
				o->mf |= GT_X86_M_INDEX;
				o->index = (uint8_t)tk->reg;
				o->scale = tk->cnt;
				XO(isz, (uint8_t)gt_x86_tri[tk->rawk][osz]);
			}
			if (tk->seg != 0xffu) {
				o->mf |= GT_X86_M_SEG;
				/* A source string operand takes an override. */
				o->seg = (tk->seg == 3u && seg) ? (uint8_t)(seg_of[seg] - 1u) : tk->seg;
			}
		} else if (tk->memf & 4u) {                 /* moffs */
			unsigned sz;

			o->mf |= GT_X86_M_DISP | GT_X86_M_SEG;
			o->v = (int64_t)field_of(c, field, &sz);
			o->seg = seg ? (uint8_t)(seg_of[seg] - 1u) : 3u;
		} else if ((modrm >> 6) == 3u) {
			/* A register in the r/m field that names a memory operand (UMONITOR). */
			o->mf |= GT_X86_M_BASE;
			o->base = (uint8_t)((modrm & 7u) | ((rex & 1) ? 8u : 0u));
			XO(bsz, (uint8_t)asz_bytes);
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
					XO(bsz, 2);
				}
				if (i16[rm] != 0xff) {
					o->mf |= GT_X86_M_INDEX;
					o->index = i16[rm];
					XO(isz, 2);
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
						if (c->vexv & 16u && c->sp == SPACE_EVEX)
							ib |= 16u;
						o->mf |= GT_X86_M_INDEX;
						o->index = (uint8_t)ib;
						XO(isz, (uint8_t)gt_x86_tri[tk->rszk][osz]);
						o->scale = (uint8_t)(1u << (sib >> 6));
					} else if (ib != 4u) {
						o->mf |= GT_X86_M_INDEX;
						o->index = (uint8_t)ib;
						XO(isz, (uint8_t)asz_bytes);
						o->scale = (uint8_t)(1u << (sib >> 6));
					}
					if (!(mod == 0 && bs == 5)) {
						o->mf |= GT_X86_M_BASE;
						o->base = (uint8_t)(bs | bx);
						XO(bsz, (uint8_t)asz_bytes);
					}
				} else if (!(mod == 0 && rm == 5)) {
					o->mf |= GT_X86_M_BASE;
					o->base = (uint8_t)(rm | bx);
					XO(bsz, (uint8_t)asz_bytes);
				} else if (mode64) {
					o->mf |= GT_X86_M_RIPREL;
				}
			}
			if (c->dsz) {
				const unsigned dat = mo + 1u + ((c->flags & GF_X86_SIB) ? 1u : 0u);

				o->mf |= GT_X86_M_DISP;
				o->v = sx(rd_le(c->code + dat, c->dsz), c->dsz);
				/* An EVEX disp8 counts in units of the operand's width. */
				if (c->sp == SPACE_EVEX && c->dsz == 1) {
					const unsigned scale = gt_x86_tri[tk->rawk][osz];

					if (scale)
						o->v *= (int64_t)scale;
				}
			}
			if (c->sp == SPACE_EVEX && (c->evex & 0x10u))
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
		uint64_t v = field_of(c, field, &rs);

		XO(rawsize, (uint8_t)rs);
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
		uint64_t v = field_of(c, field, &rs);

		o->v = sx(v, rs);
		break;
	}
	case GT_X86_OP_FAR: {
		unsigned rs;
		uint64_t v;

		if (lean)
			break;
		v = field_of(c, field, &rs);
		o->v = (int64_t)(v & ((1ull << (8u * (rs - 2u))) - 1u));
		o->sel = (uint16_t)(v >> (8u * (rs - 2u)));
		break;
	}
	case GT_X86_OP_CONST:
		XO(v, tk->reg);
		break;
	default:
		break;
	}
}

/* The first n operands, in order: the field each reads is counted as they go by. */
static inline __attribute__((always_inline))
void build_n(const struct gt_x86_insn *I, const uint8_t *code, unsigned n, struct gt_x86_op *out,
	     const int lean)
{
	struct octx c;
	unsigned k, field = 0;

	octx_init(&c, I, code);
	for (k = 0; k < n; k++) {
		build_op(&c, k, field, &out[k], lean);
		field += takes_field(&c.t[k]);
	}
}

void gt_x86_operand(const struct gt_x86_insn *I, unsigned k, struct gt_x86_op *o)
{
	struct octx c;
	unsigned j, field = 0;

	octx_init(&c, I, I->code);
	for (j = 0; j < k; j++)
		field += takes_field(&c.t[j]);
	build_op(&c, k, field, o, 0);
}

void gt_x86_operands(const struct gt_x86_insn *I, struct gt_x86_op *out)
{
	build_n(I, I->code, gt_x86_leaves[I->leaf].nops, out, 0);
}

/*
 * THE SWEEP'S VIEW OF AN INSTRUCTION, in one call.
 *
 * Decoding, and then the explicit operands in the form a sweep reads them, with
 * nothing in between written to memory: the decoded struct is a local here and
 * the operand builder is the lean instantiation of the SAME build_op that
 * gt_x86_operand runs, so the two cannot disagree about what an operand is. The
 * adapter used to call gt_x86_decode, then gt_x86_cat, _cond, _nexp and _wgpr,
 * then gt_x86_operand once per operand, each of which read the leaf and the
 * decoded struct again and built a 56-byte operand it then took six fields from.
 * MEASURED over 190 code blobs (44.4 M instructions, one pinned core): the
 * adapter layer went from 45.4 to 33.4 ns per instruction, of which this call and
 * the adapter's move to it are the larger part; gt_x86_decode alone 17.9 -> 15.9.
 *
 * WHICH OPERANDS ARE KEPT is the sweep's own rule and is written here once: a
 * general register, a memory operand, an immediate and a relative offset; the first
 * three of them. A vector register, a segment register, a far address and a constant
 * name nothing the sweep tracks and take no slot. Every general register the
 * instruction names and writes goes in `wmask` whether or not it got a slot.
 */
static const struct gt_x86_sop g_sop_none[3] = {
	GT_X86_SOP_NONE, GT_X86_SOP_NONE, GT_X86_SOP_NONE
};

static const uint8_t g_sop_acc[4] = {
	0, GT_X86_SF_READ, GT_X86_SF_WRITE, GT_X86_SF_READ | GT_X86_SF_WRITE
};

enum gt_status gt_x86_sweep(struct gt_x86_sweep *x, const uint8_t *p, size_t n, int mode)
{
	struct gt_x86_insn I, S;
	const struct gt_x86_leaf *L;
	struct octx c;
	uint64_t wmask;
	unsigned i, nexp, k = 0, field = 0;
	int st = mode == 64 ? decode_fast(&I, p, n, 1) : decode_fast(&I, p, n, 0);

	if (st == DECODE_DECLINED) {
		/* S is the one that escapes, so I stays out of memory on the fast path. */
		st = mode == 64 ? decode_slow64(&S, p, n) : decode_slow32(&S, p, n);
		I = S;
	}
	if (st != GT_OK)
		return (enum gt_status)st;
	L = &gt_x86_leaves[I.leaf];
	x->id = I.id;
	x->cat = L->cat;
	x->len = I.len;
	x->rep = I.rep;
	x->cond = L->cond;
	wmask = L->wgpr;
	nexp = L->nexp;
	octx_init(&c, &I, p);
	/* All three absent, then each kept one fills in what it has. Building a whole
	 * operand per kept one and copying it in cost 5.14 G executed instructions against 4.89 G
	 * over 30 blobs (callgrind), so this is the cheaper of the two. */
	memcpy(x->op, g_sop_none, sizeof x->op);
	for (i = 0; i < nexp; i++) {
		struct gt_x86_op o = { 0 };
		struct gt_x86_sop *v = &x->op[k];

		build_op(&c, i, field, &o, 1);
		field += takes_field(&c.t[i]);
		if (o.type == GT_X86_OP_REG && (o.acc & GT_X86_ACC_W) &&
		    o.rtype == GT_X86_REG_GPR && o.reg < 64u)
			wmask |= 1ull << gt_x86_gpr_of(&o);
		/* Only the first three become operands. */
		if (k >= 3u)
			continue;
		switch (o.type) {
		case GT_X86_OP_REG:
			if (o.rtype != GT_X86_REG_GPR)
				continue;
			v->kind = GT_X86_SK_REG;
			v->reg = (uint8_t)gt_x86_gpr_of(&o);
			v->flags = (uint8_t)(g_sop_acc[o.acc & 3u] | (o.high8 ? GT_X86_SF_HIGH8 : 0u));
			break;
		case GT_X86_OP_IMM:
			v->kind = GT_X86_SK_IMM;
			v->imm = (uint64_t)o.v;
			v->flags = g_sop_acc[o.acc & 3u];
			break;
		case GT_X86_OP_REL:
			v->kind = GT_X86_SK_REL;
			v->imm = (uint64_t)o.v;
			v->flags = g_sop_acc[o.acc & 3u];
			break;
		case GT_X86_OP_MEM:
			v->kind = GT_X86_SK_MEM;
			if (o.mf & GT_X86_M_BASE)
				v->reg = o.base;
			if (o.mf & GT_X86_M_INDEX) {
				v->index = o.index;
				v->scale = o.scale;
			}
			if (o.mf & GT_X86_M_DISP)
				v->disp = o.v;
			if (o.mf & GT_X86_M_SEG)
				v->seg = o.seg;
			v->flags = (uint8_t)(g_sop_acc[o.acc & 3u] |
					     ((o.mf & GT_X86_M_RIPREL) ? GT_X86_SF_RIPREL : 0u));
			break;
		default:
			continue;
		}
		v->size = (uint8_t)o.size;
		k++;
	}
	x->wmask = wmask;
	x->n = (uint8_t)k;
	return GT_OK;
}
