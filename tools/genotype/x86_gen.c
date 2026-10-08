/*
 * genotype_gen - writes the opcode tables of the genotype decoder by ASKING a reference
 * decoder what each encoding means.
 *
 * WHY THE TABLES ARE MEASURED AND NOT TYPED. An x86 opcode map is a few thousand
 * facts, every one of which has to agree with what real code means, and the
 * reference decoder already agrees with the manuals on all of them. Typing the map
 * a second time is the way to disagree with it in a place nobody looks. So the
 * generator builds each encoding as bytes, decodes it, and records what came back
 * - an instruction identity, its operands and where each is encoded, whether it is
 * valid, how its size follows the prefixes - and the runtime decoder is a small
 * generic engine that reads the result.
 *
 * THIS IS A DEVELOPMENT TOOL. It links the reference decoder; the decoder that
 * ships does not, and nothing here runs at scan time. The output is checked in.
 * It is re-run only when the table layout changes, and the differential check
 * (tools/genotype/x86_diff.c) is what says the output is still right.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "bddisasm.h"

/* Variant axes of one opcode root. Collapsed or split as the data says. */
#define NPP   4     /* none, 66, F3, F2                                   */
#define NOSZ  8     /* size variants: see the encoding spaces below        */
#define NASZ  16    /* the other inner axis: see the encoding spaces below */
#define NMOD  3     /* mod 0, mod 1 (or 2), mod 3                         */
#define NREG  8
#define NRM   8

struct oprec {
	uint8_t type, enc, acc, flags;
	uint8_t rtype;          /* register type, or 0                          */
	uint16_t rsize;         /* Info.Register.Size                           */
	uint32_t reg;           /* register number (compared only if implicit)  */
	uint16_t elem;          /* a gather's element size                      */
	uint8_t high8;
	uint16_t size;          /* operand Size                                 */
	uint8_t memf;           /* memory kind bits                             */
	uint8_t seg, base;      /* implicit memory: segment, base register      */
	uint8_t rawsize;        /* immediate raw size                           */
	uint8_t cnt;
};

struct rec {
	uint8_t  valid;
	uint8_t  nops;
	uint8_t  has_modrm;
	uint8_t  cond;
	uint8_t  mand;          /* bit0 66, bit1 F2, bit2 F3 mandatory          */
	uint8_t  lenpart[8];    /* opcode, modrm, imm1, imm2, rel, addr, moff   */
	uint16_t id;
	uint8_t  opsz;          /* EfOpMode                                     */
	uint16_t cat;           /* instruction category                         */
	uint8_t  hs;            /* decoded a SIB byte                           */
	uint8_t  repeated;      /* a string instruction run under REP            */
	uint16_t mnem;          /* the reference's mnemonic string               */
	uint8_t  pf;            /* which prefixes the text shows: rep, repz/nz, bnd, xacquire, xrelease, sae, er */
	uint8_t  wl;            /* word length of the instruction: 1 16-bit, 2 32-bit, 3 64-bit */
	uint8_t  nform;         /* explicit operands in the instruction's definition */
	uint8_t  nomem;         /* ModRM is read but a memory form takes no SIB/disp */
	struct oprec op[10];
};

static const char *insn_name[2048];
static unsigned n_insn_name;
static const char *cat_name[256];

/* The mnemonic strings the reference prints, interned. Index 0 is "". */
static const char *mnem_str[4096];
static unsigned n_mnem = 1;

static uint16_t mnem_ix(const char *m)
{
	unsigned i;

	if (!m || !*m)
		return 0;
	for (i = 1; i < n_mnem; i++)
		if (!strcmp(mnem_str[i], m))
			return (uint16_t)i;
	if (n_mnem >= 4096) {
		fprintf(stderr, "too many mnemonics\n");
		exit(1);
	}
	mnem_str[n_mnem] = strdup(m);
	return (uint16_t)n_mnem++;
}
static unsigned n_cat_name;

static void load_names(const char *hdr)
{
	FILE *f = fopen(hdr, "r");
	char line[256];
	int in = 0;

	if (!f) {
		perror(hdr);
		exit(1);
	}
	while (fgets(line, sizeof line, f)) {
		if (strstr(line, "typedef enum _ND_INS_CLASS")) {
			in = 1;
			continue;
		}
		if (!in)
			continue;
		if (strstr(line, "} ND_INS_CLASS"))
			break;
		{
			char *p = strstr(line, "ND_INS_");
			char name[96];
			unsigned i = 0;

			if (!p)
				continue;
			p += 7;
			while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
			       *p == '_')
				name[i++] = *p++;
			name[i] = 0;
			if (n_insn_name < 2048)
				insn_name[n_insn_name++] = strdup(name);
		}
	}
	/* The categories: a second enum in the same header, ND_CAT_*. */
	rewind(f);
	in = 0;
	while (fgets(line, sizeof line, f)) {
		if (strstr(line, "typedef enum _ND_INS_TYPE")) {
			in = 1;
			continue;
		}
		if (!in)
			continue;
		if (strstr(line, "} ND_INS_CATEGORY") || strstr(line, "} ND_INS_TYPE"))
			break;
		{
			char *p = strstr(line, "ND_CAT_");
			char name[96];
			unsigned i = 0;

			if (!p)
				continue;
			p += 7;
			while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
			       *p == '_')
				name[i++] = *p++;
			name[i] = 0;
			if (n_cat_name < 256)
				cat_name[n_cat_name++] = strdup(name);
		}
	}
	fclose(f);
}

/* ---- probing -------------------------------------------------------------- */

/*
 * THE ENCODING SPACES. Each is its own opcode map with its own prefix byte(s),
 * and each reads the two inner axes (osz, asz) as its own variables:
 *
 *   LEGACY  osz: bit 0 a 66 that is a size prefix, bit 1 REX.W
 *           asz: bit 0 a 67, bit 1 REX.B (only 0x90 reads it)
 *   VEX     osz: bit 0 VEX.L, bit 1 VEX.W
 *           asz: bit 0 vvvv is in use (not 1111b)
 *   XOP     the same as VEX
 *   EVEX    osz: bit 0 W, bits 1-2 L'L
 *           asz: bit 0 vvvv in use, bit 1 b, bit 2 a mask (aaa != 0), bit 3 z
 *
 * Reusing two axes for all of them is what lets one tree builder serve every
 * space: the axes are collapsed when they change nothing and split when they do.
 */
enum { SP_LEGACY, SP_VEX, SP_XOP, SP_EVEX, N_SPACES };
static int SP;
static int n_osz = 4, n_asz = 4;

struct variant {
	int pp, osz, asz, lock;
	int pre;                /* a prefix byte to put first (a segment, to see how a branch takes it) */
};

/*
 * THE vvvv A PROBE USES. Some instructions are not valid unless their registers
 * differ (the complex half-precision multiplies, the AMX tile ops, a gather), so
 * a probe whose vvvv happens to equal its reg or rm field says "invalid" for a
 * reason that has nothing to do with the opcode. A probe therefore picks a vvvv
 * that cannot collide - 15 in 64-bit mode, a free one of 1..7 in 32-bit mode,
 * where only three bits count - and the collisions are measured on purpose,
 * separately, by forcing one (g_vforce) and by adding a SIB byte (g_sib).
 */
static int g_vforce = -1, g_sib = -1;

static unsigned pick_v(int mode, unsigned modrm)
{
	unsigned v, reg = (modrm >> 3) & 7u, rm = modrm & 7u;
	int mod3 = (modrm >> 6) == 3u;

	if (g_vforce >= 0)
		return (unsigned)g_vforce;
	if (mode == 64)
		return 15;
	for (v = 1; v < 8; v++)
		if (v != reg && !(mod3 && v == rm))
			return v;
	return 1;
}

static unsigned build(uint8_t *b, int mode, const struct variant *v, int map,
		      unsigned opc, unsigned modrm)
{
	unsigned n = 0;
	const unsigned vraw = (v->asz & 1) ? (~pick_v(mode, modrm) & 15u) : 15u;

	if (SP == SP_VEX || SP == SP_XOP) {
		b[n++] = SP == SP_VEX ? 0xC4 : 0x8F;
		b[n++] = (uint8_t)(0xE0 | map);
		b[n++] = (uint8_t)(((v->osz & 2) ? 0x80 : 0) | (vraw << 3) |
				   ((v->osz & 1) ? 0x04 : 0) | v->pp);
		b[n++] = (uint8_t)opc;
		b[n++] = (uint8_t)modrm;
		if (g_sib >= 0)
			b[n++] = (uint8_t)g_sib;
		memset(b + n, 0, 15);
		return n;
	}
	if (SP == SP_EVEX) {
		b[n++] = 0x62;
		b[n++] = (uint8_t)(0xF0 | map);
		b[n++] = (uint8_t)((v->osz & 1 ? 0x80 : 0) | (vraw << 3) | 0x04 | v->pp);
		b[n++] = (uint8_t)(((v->asz & 8) ? 0x80 : 0) | (((v->osz >> 1) & 3) << 5) |
				   ((v->asz & 2) ? 0x10 : 0) | 0x08 | ((v->asz & 4) ? 1 : 0));
		b[n++] = (uint8_t)opc;
		b[n++] = (uint8_t)modrm;
		if (g_sib >= 0)
			b[n++] = (uint8_t)g_sib;
		memset(b + n, 0, 15);
		return n;
	}
	if (v->pre)
		b[n++] = (uint8_t)v->pre;
	if (v->lock)
		b[n++] = 0xF0;
	if (v->asz & 1)
		b[n++] = 0x67;
	if (v->pp == 1 || (v->osz & 1))
		b[n++] = 0x66;
	if (v->pp == 2)
		b[n++] = 0xF3;
	if (v->pp == 3)
		b[n++] = 0xF2;
	if (((v->osz & 2) || (v->asz & 2)) && mode == 64)
		b[n++] = (uint8_t)(0x40 | ((v->osz & 2) ? 8 : 0) | ((v->asz & 2) ? 1 : 0));
	if (map >= 1)
		b[n++] = 0x0F;
	if (map == 2)
		b[n++] = 0x38;
	if (map == 3)
		b[n++] = 0x3A;
	b[n++] = (uint8_t)opc;
	b[n++] = (uint8_t)modrm;
	memset(b + n, 0, 15);
	return n;
}

static void extract(const INSTRUX *ix, struct rec *r)
{
	unsigned i;

	memset(r, 0, sizeof *r);
	r->valid = 1;
	r->id = (uint16_t)ix->Instruction;
	r->nops = (uint8_t)ix->OperandsCount;
	r->has_modrm = ix->HasModRm;
	r->cond = (uint8_t)ix->Condition;
	r->mand = (uint8_t)((ix->HasMandatory66 ? 1 : 0) |
			    (ix->HasMandatoryF2 ? 2 : 0) |
			    (ix->HasMandatoryF3 ? 4 : 0));
	r->opsz = (uint8_t)ix->EfOpMode;
	r->cat = (uint16_t)ix->Category;
	r->hs = ix->HasSib;
	r->repeated = ix->IsRepeated;
	r->mnem = mnem_ix(ix->Mnemonic);
	r->pf = (uint8_t)((ix->IsRepEnabled ? 1 : 0) | (ix->IsRepcEnabled ? 2 : 0) |
			  (ix->IsBndEnabled ? 4 : 0) | (ix->IsXacquireEnabled ? 8 : 0) |
			  (ix->IsXreleaseEnabled ? 16 : 0) | (ix->HasSae ? 32 : 0) | (ix->HasEr ? 64 : 0));
	r->wl = (uint8_t)(ix->WordLength == 2 ? 1 : ix->WordLength == 4 ? 2 : 3);
	r->nform = ix->ExpOperandsCount;
	r->lenpart[0] = (uint8_t)ix->OpLength;
	r->lenpart[1] = ix->HasModRm;
	/* A byte whose high four bits name a register (is4) is counted apart by the
	 * reference, but it is still an immediate-like byte of the instruction. */
	r->lenpart[2] = (uint8_t)(ix->Imm1Length ? ix->Imm1Length : (ix->HasSseImm ? 1 : 0));
	r->lenpart[3] = ix->Imm2Length;
	r->lenpart[4] = ix->RelOffsLength;
	r->lenpart[5] = ix->AddrLength;
	r->lenpart[6] = ix->MoffsetLength;
	for (i = 0; i < ix->OperandsCount && i < 10; i++) {
		const ND_OPERAND *o = &ix->Operands[i];
		struct oprec *d = &r->op[i];

		d->type = o->Type;
		d->enc = o->Encoding;
		d->acc = o->Access.Access;
		d->flags = o->Flags.Flags;
		d->size = o->Size == 0xffffffffu ? 0xffffu : (uint16_t)o->Size;
		if (o->Type == ND_OP_REG) {
			d->rtype = (uint8_t)o->Info.Register.Type;
			d->rsize = (uint16_t)o->Info.Register.Size;
			d->reg = o->Info.Register.Reg;
			d->high8 = o->Info.Register.IsHigh8;
			d->cnt = o->Info.Register.Count;
		} else if (o->Type == ND_OP_MEM) {
			const ND_OPDESC_MEMORY *m = &o->Info.Memory;

			d->memf = (uint8_t)((m->IsStack ? 1 : 0) | (m->IsString ? 2 : 0) |
					    (m->IsDirect ? 4 : 0) | (m->IsAG ? 8 : 0) |
					    (m->IsBitbase ? 16 : 0) | (m->IsMib ? 32 : 0) |
					    (m->IsVsib ? 64 : 0) | (m->IsShadowStack ? 128 : 0));
			d->seg = m->HasSeg ? (uint8_t)m->Seg : 0xff;
			d->base = m->HasBase ? (uint8_t)m->Base : 0xff;
			if (o->Encoding != ND_OPE_M) {
				d->reg = m->HasIndex ? (uint8_t)m->Index : 0xff;
				d->cnt = m->HasIndex ? (uint8_t)m->Scale : 0;
				d->rawsize = m->HasIndex ? (uint8_t)m->IndexSize : 0;
			} else {
				/* A modrm memory operand: how much an EVEX disp8 is scaled by
				 * (rawsize) and, for a gather, the width of its index vector
				 * (rsize). Both vary with the size variants, and so ride in
				 * the per-variant size tuples. */
				d->rawsize = m->HasCompDisp ? m->CompDispSize : 0;
				d->rsize = m->IsVsib ? m->IndexSize : 0;
				d->elem = m->IsVsib ? m->Vsib.ElemSize : (m->HasBroadcast ? m->Broadcast.Count : 0);
			}
		} else if (o->Type == ND_OP_IMM) {
			d->rawsize = o->Info.Immediate.RawSize;
		} else if (o->Type == ND_OP_CONST) {
			d->reg = (uint32_t)o->Info.Constant.Const;
		}
	}
}

static struct rec REC[NPP][NOSZ][NASZ][NMOD][NREG][NRM];
static uint8_t DIST[NPP][NOSZ][NASZ][2];     /* [0] memory form, [1] register form */       /* registers that must differ: see probe_dist */
/* What a LOCK or a segment prefix makes the text show: bit 0 xacquire, 1 xrelease (both under
 * LOCK), 2 a branch hint, 3 do-not-track (both under a segment prefix). */
static uint8_t PF2V[NPP][NMOD][NREG][NRM];
static uint8_t LKV[NPP][NMOD][NREG][NRM];   /* valid with a LOCK prefix         */

static int probe(int mode, int map, unsigned opc, int pp, int osz, int asz,
		 unsigned modrm, struct rec *out)
{
	uint8_t b[32];
	struct variant v = { pp, osz, asz, 0, 0 };
	INSTRUX ix;
	NDSTATUS s;
	const int cd = mode == 64 ? ND_CODE_64 : ND_CODE_32;
	const int dd = mode == 64 ? ND_DATA_64 : ND_DATA_32;

	build(b, mode, &v, map, opc, modrm);
	s = NdDecodeEx(&ix, b, 16, cd, dd);
	if (!ND_SUCCESS(s) && SP != SP_LEGACY && (asz & 1) && g_vforce < 0) {
		/* The vvvv chosen may simply be one this instruction cannot name: a mask
		 * register has eight numbers. Try the others before calling it invalid. */
		const unsigned reg = (modrm >> 3) & 7u, rm = modrm & 7u;
		int cand;

		for (cand = 0; cand < (mode == 64 ? 16 : 8) && !ND_SUCCESS(s); cand++) {
			if (!cand || (unsigned)cand == reg || ((modrm >> 6) == 3u && (unsigned)cand == rm))
				continue;
			g_vforce = cand;
			build(b, mode, &v, map, opc, modrm);
			s = NdDecodeEx(&ix, b, 16, cd, dd);
		}
		g_vforce = -1;
	}
	if (!ND_SUCCESS(s)) {
		memset(out, 0, sizeof *out);
		return 0;
	}
	extract(&ix, out);
	return 1;
}


/* ---- leaf specs: what an encoding means, with the size-dependent parts apart -- */

struct opspec {
	uint8_t type, enc, acc, flags, rtype, memf, seg, base, cnt, ad;
	uint32_t reg;
	uint16_t sz[NOSZ], rsz[NOSZ], raw[NOSZ], el[NOSZ];
};

struct leafspec {
	uint16_t id, cat;
	uint8_t  valid, nops, has_modrm, cond, mand, flags2;
	uint8_t  imm1[NOSZ], imm2[NOSZ], rel[NOSZ], addr[NOSZ], opsz[NOSZ];
	uint16_t mn[NOSZ];      /* the mnemonic, per size variant: MOVSB, MOVSW, MOVSD */
	uint8_t  p66;           /* the root has a mandatory-66 form              */
	uint8_t  lockok;        /* decodes with a LOCK prefix                    */
	uint8_t  nomem;
	uint8_t  restricted;    /* some size/address variants are not valid      */
	uint8_t  dist;          /* registers that must be different: bits 0-4     */
	uint8_t  repeated;
	uint8_t  nform;
	uint8_t  pf, pf2;       /* what the text shows: see rec.pf and PF2V */
	uint8_t  nexp;          /* operands written in the instruction, before the implicit ones */
	uint16_t wgpr;          /* general registers the instruction writes without naming */
	uint8_t  vm[16];        /* valid variants: bit osz * n_asz + asz         */
	struct opspec op[10];
};

static int implicit_reg(uint8_t enc)
{
	return enc == ND_OPE_NP || enc == ND_OPE_S || enc == ND_OPE_C ||
	       enc == ND_OPE_1 || enc == ND_OPE_E;
}

/* Shape equality of two records: everything except what depends on the operand
 * size, which is carried as a triple. */
static int shape_eq(const struct rec *a, const struct rec *b)
{
	unsigned i;

	if (a->valid != b->valid)
		return 0;
	if (!a->valid)
		return 1;
	if (a->pf != b->pf || a->nomem != b->nomem || a->repeated != b->repeated || a->nform != b->nform || a->id != b->id || a->cat != b->cat || a->nops != b->nops || a->has_modrm != b->has_modrm ||
	    a->cond != b->cond || a->mand != b->mand)
		return 0;
	for (i = 0; i < a->nops; i++) {
		const struct oprec *x = &a->op[i], *y = &b->op[i];

		if (x->type != y->type || x->enc != y->enc || x->acc != y->acc ||
		    x->flags != y->flags || x->rtype != y->rtype ||
		    x->memf != y->memf || x->cnt != y->cnt)
			return 0;
		if (implicit_reg(x->enc) && (x->type == ND_OP_REG || x->type == ND_OP_CONST) &&
		    x->reg != y->reg)
			return 0;
		if (x->type == ND_OP_MEM && x->enc != ND_OPE_M &&
		    (x->seg != y->seg || (x->enc != ND_OPE_R && x->base != y->base) ||
		     x->reg != y->reg || x->cnt != y->cnt))
			return 0;
	}
	return 1;
}

/* The full data of one record that must also agree, for a leaf to be shared
 * between two points: the sizes. */
static int cur_mode;

/* The address size, in bytes, of an asz variant. */
static unsigned asz_bytes_of(int a)
{
	int has67 = a & 1;

	return cur_mode == 64 ? (has67 ? 4u : 8u) : (has67 ? 2u : 4u);
}

/* Do two records agree on every size - or differ only where a size IS the
 * address size, as the index registers of a string instruction do? `ad`, when
 * given, is set for those operands. */
static int size_eq(const struct rec *a, const struct rec *b, int ab, uint8_t *ad)
{
	unsigned i;

	if (!a->valid)
		return 1;
	if (a->mnem != b->mnem)
		return 0;
	for (i = 0; i < a->nops; i++) {
		const struct oprec *x = &a->op[i], *y = &b->op[i];

		if (x->size == y->size && x->rsize == y->rsize && x->rawsize == y->rawsize &&
		    x->elem == y->elem)
			continue;
		if (SP == SP_LEGACY && ab >= 0 && x->type == ND_OP_REG && y->size == asz_bytes_of(ab) &&
		    y->rsize == asz_bytes_of(ab) && x->size == asz_bytes_of(0) &&
		    x->rsize == asz_bytes_of(0) && x->rawsize == y->rawsize) {
			if (ad)
				ad[i] = 1;
			continue;
		}
		return 0;
	}
	for (i = 2; i < 6; i++)
		if (a->lenpart[i] != b->lenpart[i])
			return 0;
	return a->opsz == b->opsz;
}

#define SPLIT_MARK 0xffff

static uint32_t fnv(uint32_t h, uint32_t v)
{
	return (h ^ v) * 16777619u;
}

/* A digest of everything a record says, sizes included. Two collapsed specs
 * that split must not be taken for the same split because their ids agree. */
static uint32_t rec_digest(const struct rec *q)
{
	uint32_t h = 2166136261u;
	unsigned i;

	h = fnv(h, q->valid);
	if (!q->valid)
		return h;
	h = fnv(h, q->id); h = fnv(h, q->cat); h = fnv(h, q->nops);
	h = fnv(h, q->cond); h = fnv(h, q->mand); h = fnv(h, q->has_modrm);
	h = fnv(h, q->opsz);
	h = fnv(h, q->nomem);
	h = fnv(h, q->repeated);
	h = fnv(h, q->mnem);
	h = fnv(h, q->pf);
	h = fnv(h, q->nform);
	for (i = 2; i < 6; i++)
		h = fnv(h, q->lenpart[i]);
	for (i = 0; i < q->nops; i++) {
		const struct oprec *o = &q->op[i];

		h = fnv(h, o->type); h = fnv(h, o->enc); h = fnv(h, o->acc);
		h = fnv(h, o->flags); h = fnv(h, o->rtype); h = fnv(h, o->memf);
		h = fnv(h, o->cnt); h = fnv(h, o->size); h = fnv(h, o->rsize);
		h = fnv(h, o->rawsize);
		h = fnv(h, o->elem);
		if (implicit_reg(o->enc))
			h = fnv(h, o->reg);
	}
	return h;
}

/*
 * WHICH VARIANTS A SPEC COVERS. The two inner axes are bit fields (see the
 * encoding spaces), and a leaf covers every variant whose bits agree with the
 * ones already fixed by the tree above it: `omask` says which bits of the osz
 * index are fixed, `oval` what they are fixed to, and the same for asz.
 */
struct vsel {
	unsigned omask, oval, amask, aval;
};

static int p66_of_root;

static int vsel_o(const struct vsel *v, int o) { return ((unsigned)o & v->omask) == v->oval; }
static int vsel_a(const struct vsel *v, int a) { return ((unsigned)a & v->amask) == v->aval; }

/* The spec for a point of the four tree dimensions, over the variants `vs`
 * covers. Variants whose SHAPE differs are not one spec: it is reported as a
 * split, with a digest of what differs so that two different splits are never
 * taken for the same. */
static int spec_of(int pp, int mod, int reg, int rm, const struct vsel *vs,
		   struct leafspec *ls, uint32_t *split_hash)
{
	const struct rec *base = NULL;
	uint8_t adflags[10] = { 0 };
	int o, a, ab = 0;
	unsigned i;

	memset(ls, 0, sizeof *ls);
	/* The first valid variant this covers is the one the shape is read from; an
	 * invalid one is a wildcard, and says so in the validity mask. */
	for (o = 0; o < n_osz && !base; o++)
		for (a = 0; a < n_asz && !base; a++)
			if (vsel_o(vs, o) && vsel_a(vs, a) && REC[pp][o][a][mod][reg][rm].valid) {
				base = &REC[pp][o][a][mod][reg][rm];
				ab = a;
			}
	if (!base)
		return 1;                       /* nothing valid: the dead leaf */
	for (o = 0; o < n_osz; o++) {
		if (!vsel_o(vs, o))
			continue;
		for (a = 0; a < n_asz; a++) {
			const struct rec *r;

			if (!vsel_a(vs, a))
				continue;
			r = &REC[pp][o][a][mod][reg][rm];
			if (r->valid && !shape_eq(base, r)) {
				uint32_t h = 2166136261u;
				int oo, aa;

				for (oo = 0; oo < n_osz; oo++)
					for (aa = 0; aa < n_asz; aa++)
						if (vsel_o(vs, oo) && vsel_a(vs, aa))
							h = fnv(h, rec_digest(&REC[pp][oo][aa][mod][reg][rm]));
				*split_hash = h;
				return 0;
			}
		}
	}
	ls->valid = 1;
	ls->id = base->id;
	ls->cat = base->cat;
	ls->nops = base->nops;
	ls->has_modrm = base->has_modrm;
	ls->cond = base->cond;
	ls->mand = base->mand;
	ls->p66 = (uint8_t)p66_of_root;
	ls->lockok = LKV[pp][mod][reg][rm];
	ls->nomem = base->nomem;
	ls->repeated = base->repeated;
	ls->pf = base->pf;
	ls->pf2 = PF2V[pp][mod][reg][rm];
	ls->nform = base->nform;
	/* Explicit operands come first and implicit ones after; and which general
	 * registers the implicit ones write is a fact of the opcode, so it is kept
	 * here and a sweep need not build the operands to learn it. A write to AH,
	 * CH, DH or BH is a write to the register it is the high byte of. */
	{
		int seen_implicit = 0;

		for (i = 0; i < base->nops; i++) {
			const struct oprec *x = &base->op[i];

			if (!(x->flags & 1u)) {
				if (seen_implicit) {
					fprintf(stderr, "internal: explicit operand after an implicit one\n");
					exit(1);
				}
				ls->nexp++;
				continue;
			}
			seen_implicit = 1;
			if (x->type == ND_OP_REG && x->rtype == ND_REG_GPR && (x->acc & 2u)) {
				unsigned r = x->reg;

				if (x->rsize == 1 && r >= 4 && r < 8)
					r -= 4;
				if (r < 16)
					ls->wgpr |= (uint16_t)(1u << r);
			}
		}
	}
	for (i = 0; i < base->nops; i++) {
		const struct oprec *x = &base->op[i];
		struct opspec *d = &ls->op[i];

		d->type = x->type; d->enc = x->enc; d->acc = x->acc; d->flags = x->flags;
		d->rtype = x->rtype; d->memf = x->memf; d->cnt = x->cnt;
		d->reg = (implicit_reg(x->enc) || x->type == ND_OP_CONST ||
			  (x->type == ND_OP_MEM && x->enc != ND_OPE_M)) ? x->reg : 0;
		d->seg = (x->type == ND_OP_MEM && x->enc != ND_OPE_M) ? x->seg : 0;
		d->base = (x->type == ND_OP_MEM && x->enc != ND_OPE_M && x->enc != ND_OPE_R) ? x->base : 0;
	}
	/* Registers that must differ: whatever any variant this covers requires of
	 * this form (register or memory). */
	for (o = 0; o < n_osz; o++)
		for (a = 0; a < n_asz; a++)
			if (vsel_o(vs, o) && vsel_a(vs, a) && REC[pp][o][a][mod][reg][rm].valid)
				ls->dist |= DIST[pp][o][a][mod == 2];
	/* Which variants decode at all. A variant this does not cover reads as valid,
	 * so that a leaf is the same however the tree reached it. */
	for (o = 0; o < n_osz; o++)
		for (a = 0; a < n_asz; a++) {
			const unsigned bit = (unsigned)(o * n_asz + a);
			int ok = !(vsel_o(vs, o) && vsel_a(vs, a)) ||
				 REC[pp][o][a][mod][reg][rm].valid;

			if (ok)
				ls->vm[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
			else
				ls->restricted = 1;
		}
	/* Sizes are carried per size variant; a variant the tree has fixed by a bit
	 * takes that bit's value, so the leaf is the same however it is reached. A
	 * variant with no valid address-size twin has no sizes to carry. */
	for (o = 0; o < n_osz; o++) {
		const int oe = (int)(((unsigned)o & ~vs->omask) | vs->oval);
		const struct rec *r = NULL;

		for (a = 0; a < n_asz && !r; a++)
			if (vsel_a(vs, a) && REC[pp][oe][a][mod][reg][rm].valid)
				r = &REC[pp][oe][a][mod][reg][rm];
		if (!r)
			continue;
		ls->imm1[o] = r->lenpart[2];
		ls->imm2[o] = r->lenpart[3];
		ls->rel[o] = r->lenpart[4];
		ls->addr[o] = r->lenpart[5];
		ls->opsz[o] = r->opsz;
		ls->mn[o] = (uint16_t)(r->mnem | (r->wl << 12));
		for (i = 0; i < base->nops && i < r->nops; i++) {
			ls->op[i].sz[o] = r->op[i].size;
			ls->op[i].rsz[o] = r->op[i].rsize;
			ls->op[i].raw[o] = r->op[i].rawsize;
			ls->op[i].el[o] = r->op[i].elem;
		}
	}
	/* Sizes must also agree across the asz variants this covers; if they do
	 * not, that is a split. */
	for (o = 0; o < n_osz; o++) {
		const struct rec *ref = NULL;
		int ra = 0;

		if (!vsel_o(vs, o))
			continue;
		for (a = 0; a < n_asz && !ref; a++)
			if (vsel_a(vs, a) && REC[pp][o][a][mod][reg][rm].valid) {
				ref = &REC[pp][o][a][mod][reg][rm];
				ra = a;
			}
		for (a = 0; ref && a < n_asz; a++)
			if (a != ra && vsel_a(vs, a) && REC[pp][o][a][mod][reg][rm].valid &&
			    !size_eq(ref, &REC[pp][o][a][mod][reg][rm], a, adflags)) {
				{
					/* The digest of everything covered, as for a shape split:
					 * two points that split for different reasons must not
					 * look the same to the dependence test. */
					uint32_t hh = 0x5a5a0000u ^ (uint32_t)a;
					int oo, aa;

					for (oo = 0; oo < n_osz; oo++)
						for (aa = 0; aa < n_asz; aa++)
							if (vsel_o(vs, oo) && vsel_a(vs, aa))
								hh = fnv(hh, rec_digest(&REC[pp][oo][aa][mod][reg][rm]));
					*split_hash = hh;
				}
				return 0;
			}
	}
	(void)ab;
	for (i = 0; i < base->nops; i++)
		ls->op[i].ad = adflags[i];
	return 1;
}

/* ---- leaf and node pools --------------------------------------------------- */

struct pool_leaf { struct leafspec s; };
static struct leafspec *LEAF;
static unsigned n_leaf, cap_leaf;

struct pool_node { uint8_t kind, arity; uint16_t child[16]; };
static struct pool_node *NODE;
static unsigned n_node, cap_node;

/* The tree's selectors: four outer dimensions, then one bit at a time of each
 * inner axis (see struct vsel). */
enum { K_PP, K_MOD, K_REG, K_RM, K_OB0, K_OB1, K_OB2, K_AB0, K_AB1, K_AB2, K_AB3 };

static uint32_t hash_bytes(const void *p, size_t n)
{
	const uint8_t *b = p;
	uint32_t h = 2166136261u;

	while (n--)
		h = (h ^ *b++) * 16777619u;
	return h;
}

#define HASH_BITS 16
static int32_t leaf_head[1 << HASH_BITS], node_head[1 << HASH_BITS];
static int32_t *leaf_next, *node_next;
static int hash_ready;

static void hash_init(void)
{
	memset(leaf_head, 0xff, sizeof leaf_head);
	memset(node_head, 0xff, sizeof node_head);
	hash_ready = 1;
}

static uint16_t leaf_ix(const struct leafspec *s)
{
	uint32_t h;
	int32_t i;

	if (!hash_ready)
		hash_init();
	h = hash_bytes(s, sizeof *s) & ((1u << HASH_BITS) - 1u);
	for (i = leaf_head[h]; i >= 0; i = leaf_next[i])
		if (!memcmp(&LEAF[i], s, sizeof *s))
			return (uint16_t)i;
	if (n_leaf == cap_leaf) {
		cap_leaf = cap_leaf ? cap_leaf * 2 : 1024;
		LEAF = realloc(LEAF, cap_leaf * sizeof *LEAF);
		leaf_next = realloc(leaf_next, cap_leaf * sizeof *leaf_next);
	}
	LEAF[n_leaf] = *s;
	leaf_next[n_leaf] = leaf_head[h];
	leaf_head[h] = (int32_t)n_leaf;
	if (n_leaf >= 0x7fffu) {
		fprintf(stderr, "leaf index overflows 15 bits\n");
		exit(1);
	}
	return (uint16_t)n_leaf++;
}

static uint16_t node_ix(unsigned kind, unsigned arity, const uint16_t *ch)
{
	struct pool_node nn;
	uint32_t h;
	int32_t i;

	if (!hash_ready)
		hash_init();
	memset(&nn, 0, sizeof nn);
	nn.kind = (uint8_t)kind;
	nn.arity = (uint8_t)arity;
	memcpy(nn.child, ch, arity * sizeof *ch);
	h = hash_bytes(&nn, sizeof nn) & ((1u << HASH_BITS) - 1u);
	for (i = node_head[h]; i >= 0; i = node_next[i])
		if (!memcmp(&NODE[i], &nn, sizeof nn))
			return (uint16_t)(0x8000u | (unsigned)i);
	if (n_node == cap_node) {
		cap_node = cap_node ? cap_node * 2 : 1024;
		NODE = realloc(NODE, cap_node * sizeof *NODE);
		node_next = realloc(node_next, cap_node * sizeof *node_next);
	}
	NODE[n_node] = nn;
	node_next[n_node] = node_head[h];
	node_head[h] = (int32_t)n_node;
	return (uint16_t)(0x8000u | n_node++);
}

static int rd_pp_arity;    /* 4 when the root has a mandatory 66, else 3     */
static const int pp_val3[3] = { 0, 2, 3 };

static int dim_arity(int d)
{
	switch (d) {
	case K_PP:  return rd_pp_arity;
	case K_MOD: return 3;
	case K_REG: return 8;
	case K_RM:  return 8;
	}
	return 1;
}

static int dim_value(int d, int v)
{
	return d == K_PP && rd_pp_arity == 3 ? pp_val3[v] : v;
}

static int log2i(int n)
{
	int b = 0;

	while ((1 << b) < n)
		b++;
	return b;
}

/* Does bit `b` of the osz index change the SHAPE of what these variants mean? */
static int obit_matters(int pp, int mod, int reg, int rm, const struct vsel *vs, int b)
{
	int o, a;

	for (o = 0; o < n_osz; o++) {
		if (!vsel_o(vs, o) || (o & (1 << b)))
			continue;
		for (a = 0; a < n_asz; a++)
			if (vsel_a(vs, a) && REC[pp][o][a][mod][reg][rm].valid &&
			    REC[pp][o | (1 << b)][a][mod][reg][rm].valid &&
			    !shape_eq(&REC[pp][o][a][mod][reg][rm],
				      &REC[pp][o | (1 << b)][a][mod][reg][rm]))
				return 1;
	}
	return 0;
}

static int abit_matters(int pp, int mod, int reg, int rm, const struct vsel *vs, int b)
{
	int o, a;

	for (a = 0; a < n_asz; a++) {
		if (!vsel_a(vs, a) || (a & (1 << b)))
			continue;
		for (o = 0; o < n_osz; o++) {
			const struct rec *x = &REC[pp][o][a][mod][reg][rm],
					 *y = &REC[pp][o][a | (1 << b)][mod][reg][rm];

			if (vsel_o(vs, o) && x->valid && y->valid &&
			    (!shape_eq(x, y) || !size_eq(x, y, a | (1 << b), NULL)))
				return 1;
		}
	}
	return 0;
}

/* A leaf, or a binary tree over the inner-axis bits that matter, for fully fixed
 * pp, mod, reg, rm and the variants `vs` covers. */
static uint16_t leaf_for(int pp, int mod, int reg, int rm, const struct vsel *vs)
{
	struct leafspec ls;
	uint32_t h;
	int b;

	if (spec_of(pp, mod, reg, rm, vs, &ls, &h))
		return leaf_ix(&ls);
	for (b = 0; b < log2i(n_osz); b++) {
		if ((vs->omask & (1u << b)) || !obit_matters(pp, mod, reg, rm, vs, b))
			continue;
		{
			uint16_t ch[2];
			int v;

			for (v = 0; v < 2; v++) {
				struct vsel n = *vs;

				n.omask |= 1u << b;
				n.oval |= (unsigned)v << b;
				ch[v] = leaf_for(pp, mod, reg, rm, &n);
			}
			return node_ix((unsigned)(K_OB0 + b), 2, ch);
		}
	}
	for (b = 0; b < log2i(n_asz); b++) {
		if ((vs->amask & (1u << b)) || !abit_matters(pp, mod, reg, rm, vs, b))
			continue;
		{
			uint16_t ch[2];
			int v;

			for (v = 0; v < 2; v++) {
				struct vsel n = *vs;

				n.amask |= 1u << b;
				n.aval |= (unsigned)v << b;
				ch[v] = leaf_for(pp, mod, reg, rm, &n);
			}
			return node_ix((unsigned)(K_AB0 + b), 2, ch);
		}
	}
	fprintf(stderr, "internal: unsplittable\n");
	exit(1);
}

/* Build the subtree for the free dimensions in `fix` (-1 = free). */
static uint16_t build_tree(const int *fix)
{
	int d, dim_order[4] = { K_PP, K_MOD, K_REG, K_RM };
	int k;

	for (k = 0; k < 4; k++) {
		int dd = dim_order[k];
		int v, other_free[4], nf = 0, kk;
		int idx[4];
		int dep = 0;
		int ar[4];

		if (fix[dd] >= 0)
			continue;
		for (kk = 0; kk < 4; kk++)
			if (dim_order[kk] != dd && fix[dim_order[kk]] < 0)
				other_free[nf++] = dim_order[kk];
		(void)idx; (void)ar;
		/* Enumerate assignments of the other free dims; compare across dd. */
		{
			int total = 1, t;

			for (kk = 0; kk < nf; kk++)
				total *= dim_arity(other_free[kk]);
			for (t = 0; t < total && !dep; t++) {
				int a2[4], tt = t, ref = -1;
				uint16_t first = 0;

				for (kk = 0; kk < 4; kk++)
					a2[kk] = fix[kk];
				for (kk = 0; kk < nf; kk++) {
					int ar2 = dim_arity(other_free[kk]);

					a2[other_free[kk]] = dim_value(other_free[kk], tt % ar2);
					tt /= ar2;
				}
				for (v = 0; v < dim_arity(dd); v++) {
					struct leafspec ls;
					uint32_t h;
					int ok;
					uint16_t id;

					a2[dd] = dim_value(dd, v);
					{
						static const struct vsel all = { 0, 0, 0, 0 };

						ok = spec_of(a2[K_PP], a2[K_MOD], a2[K_REG], a2[K_RM],
							     &all, &ls, &h);
					}
					if (ok)
						id = leaf_ix(&ls);
					else
						id = (uint16_t)(0x4000u | (h & 0x3fffu));
					if (ref < 0) {
						ref = 1;
						first = id;
					} else if (id != first) {
						dep = 1;
						break;
					}
				}
			}
		}
		if (dep) {
			uint16_t ch[16];
			int nfx[4], ii;

			for (ii = 0; ii < 4; ii++)
				nfx[ii] = fix[ii];
			for (v = 0; v < dim_arity(dd); v++) {
				nfx[dd] = dim_value(dd, v);
				ch[v] = build_tree(nfx);
			}
			return node_ix((unsigned)dd, (unsigned)dim_arity(dd), ch);
		}
	}
	/* Nothing free matters: one leaf. Free dims take their first value. */
	{
		int f2[4];

		for (d = 0; d < 4; d++)
			f2[d] = fix[d] >= 0 ? fix[d] : dim_value(d, 0);
		{
			static const struct vsel all = { 0, 0, 0, 0 };

			return leaf_for(f2[K_PP], f2[K_MOD], f2[K_REG], f2[K_RM], &all);
		}
	}
}


#define N_RMAPS 18
static unsigned mapnodes[4][16];
static uint16_t ROOT[2][N_RMAPS][256];

/* Diagnostics are options, not environment: --dump=SPACE,MAP,OPC prints one root's
 * tree, --distdbg=OPC the register-collision flags found for it, --verbose lists
 * the roots that cost the most nodes. */
static const char *opt_dump, *opt_distdbg;
static int opt_verbose;

static void dump_tree(unsigned ref, int ind)
{
	if (!(ref & 0x8000u)) {
		const struct leafspec *l = &LEAF[ref];

		fprintf(stderr, "%*sleaf %s nops %u\n", ind, "",
			l->valid ? insn_name[l->id] : "-", l->nops);
		return;
	}
	{
		const struct pool_node *n = &NODE[ref & 0x7fffu];
		static const char *kn[] = { "PP", "MOD", "REG", "RM", "OB0", "OB1", "OB2", "AB0", "AB1", "AB2", "AB3" };
		unsigned q;

		fprintf(stderr, "%*s%s/%u\n", ind, "", kn[n->kind], n->arity);
		for (q = 0; q < n->arity; q++)
			dump_tree(n->child[q], ind + 2);
	}
}

/* Each space's node pool, kept when the space is done. */
static struct pool_node *SPN[N_SPACES];
static unsigned SPN_N[N_SPACES];

/* Bytes the decoder never looks up as an opcode: prefixes, the escapes, and in
 * 64-bit mode the REX range. Probing them as roots would only record what the
 * reference makes of the NEXT byte. */
static int is_pseudo_root(int mode, int map, unsigned opc)
{
	if (map == 0) {
		switch (opc) {
		case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x64: case 0x65:
		case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3: case 0x0f:
			return 1;
		}
		return mode == 64 && opc >= 0x40 && opc < 0x50;
	}
	return map == 1 && (opc == 0x38 || opc == 0x3a || opc == 0x0f);
}

/* ---- emission ---------------------------------------------------------------- */

struct mnk { uint16_t v[NOSZ]; };
static struct mnk MNK[16384];
static unsigned n_mnk;

static unsigned mnk_ix(const uint16_t *v)
{
	unsigned i;

	for (i = 0; i < n_mnk; i++)
		if (!memcmp(MNK[i].v, v, sizeof MNK[i].v))
			return i;
	if (n_mnk >= 16384) {
		fprintf(stderr, "too many mnemonic tuples\n");
		exit(1);
	}
	memcpy(MNK[n_mnk].v, v, sizeof MNK[n_mnk].v);
	return n_mnk++;
}

struct tri { uint16_t v[NOSZ]; };
static struct tri TRI[256];
static unsigned n_tri;

static unsigned tri_ix(const uint16_t *v)
{
	unsigned i;

	for (i = 0; i < n_tri; i++)
		if (!memcmp(TRI[i].v, v, sizeof TRI[i].v))
			return i;
	memcpy(TRI[n_tri].v, v, sizeof TRI[n_tri].v);
	return n_tri++;
}

struct lenk { uint8_t imm1[NOSZ], imm2[NOSZ], rel[NOSZ], addr[NOSZ]; };
static struct lenk LENK[256];
static unsigned n_lenk;

static unsigned lenk_ix(const struct leafspec *s)
{
	struct lenk k;
	unsigned i;

	memcpy(k.imm1, s->imm1, NOSZ);
	memcpy(k.imm2, s->imm2, NOSZ);
	memcpy(k.rel, s->rel, NOSZ);
	memcpy(k.addr, s->addr, NOSZ);
	for (i = 0; i < n_lenk; i++)
		if (!memcmp(&LENK[i], &k, sizeof k))
			return i;
	LENK[n_lenk] = k;
	return n_lenk++;
}

struct vmrow { uint8_t b[16]; };
static struct vmrow VMROW[4096];
static unsigned n_vmrow;

static unsigned vm_ix(const uint8_t *v)
{
	unsigned i;

	for (i = 0; i < n_vmrow; i++)
		if (!memcmp(VMROW[i].b, v, 16))
			return i;
	if (n_vmrow >= 4096) {
		fprintf(stderr, "too many validity masks\n");
		exit(1);
	}
	memcpy(VMROW[n_vmrow].b, v, 16);
	return n_vmrow++;
}

struct tpl { uint8_t b[20]; };
static struct tpl *TPL;
static unsigned n_tpl, cap_tpl;

static unsigned tpl_seq(const struct leafspec *s)
{
	struct tpl seq[10];
	unsigned i, j;

	for (i = 0; i < s->nops; i++) {
		const struct opspec *o = &s->op[i];

		seq[i].b[0] = (uint8_t)(o->type | (o->enc << 4));
		seq[i].b[1] = o->acc;
		seq[i].b[2] = o->flags;
		seq[i].b[3] = o->rtype;
		seq[i].b[12] = (uint8_t)o->reg;
		seq[i].b[13] = (uint8_t)(o->reg >> 8);
		seq[i].b[14] = (uint8_t)(o->reg >> 16);
		seq[i].b[15] = (uint8_t)(o->reg >> 24);
		seq[i].b[4] = o->ad;
		seq[i].b[5] = o->memf;
		seq[i].b[6] = o->seg;
		seq[i].b[7] = o->base;
		seq[i].b[8] = o->cnt;
		seq[i].b[9] = (uint8_t)tri_ix(o->sz);
		seq[i].b[10] = (uint8_t)tri_ix(o->rsz);
		seq[i].b[11] = (uint8_t)tri_ix(o->raw);
		seq[i].b[16] = (uint8_t)tri_ix(o->el);
	}
	if (!s->nops)
		return 0;
	for (j = 0; j + s->nops <= n_tpl; j++)
		if (!memcmp(&TPL[j], seq, s->nops * sizeof seq[0]))
			return j;
	if (n_tpl + s->nops > cap_tpl) {
		cap_tpl = (cap_tpl + s->nops) * 2;
		TPL = realloc(TPL, cap_tpl * sizeof *TPL);
	}
	memcpy(&TPL[n_tpl], seq, s->nops * sizeof seq[0]);
	n_tpl += s->nops;
	return n_tpl - s->nops;
}

static void emit(const char *dir)
{
	char path[512];
	FILE *f;
	unsigned i, j, max_nops = 0;

	/* ids */
	snprintf(path, sizeof path, "%s/x86_ids.h", dir);
	f = fopen(path, "w");
	fprintf(f, "/* Generated by x86_gen.c - do not edit. */\n"
		   "#ifndef GENOTYPE_X86_IDS_H\n#define GENOTYPE_X86_IDS_H\n\nenum gt_x86_id {\n");
	for (i = 0; i < n_insn_name; i++)
		fprintf(f, "\tGT_X86_I_%s%s,\n", insn_name[i], i == 0 ? " = 0" : "");
	fprintf(f, "\tGT_X86_I__COUNT\n};\n\n");
	fprintf(f, "/* Instruction categories, the reference's numbering. */\nenum gt_x86_cat {\n");
	for (i = 0; i < n_cat_name; i++)
		fprintf(f, "\tGT_X86_C_%s%s,\n", cat_name[i], i == 0 ? " = 0" : "");
	fprintf(f, "\tGT_X86_C__COUNT\n};\n\n#endif\n");
	fclose(f);

	snprintf(path, sizeof path, "%s/x86_tab.c", dir);
	f = fopen(path, "w");
	fprintf(f, "/* Generated by x86_gen.c - do not edit. */\n"
		   "#include \"x86_int.h\"\n\n");

	/* leaves, and the pools they point into */
	{
		unsigned *lops = calloc(n_leaf ? n_leaf : 1, sizeof *lops);
		unsigned *llen = calloc(n_leaf ? n_leaf : 1, sizeof *llen);
		unsigned *lopsz = calloc(n_leaf ? n_leaf : 1, sizeof *lopsz);
		unsigned *lmnk = calloc(n_leaf ? n_leaf : 1, sizeof *lmnk);

		for (i = 0; i < n_leaf; i++) {
			if (LEAF[i].nops > max_nops)
				max_nops = LEAF[i].nops;
			lops[i] = tpl_seq(&LEAF[i]);
			llen[i] = lenk_ix(&LEAF[i]);
			{
				uint16_t t3[NOSZ];
				unsigned q3;

				for (q3 = 0; q3 < NOSZ; q3++)
					t3[q3] = LEAF[i].opsz[q3];

				lopsz[i] = tri_ix(t3);
			}
			lmnk[i] = mnk_ix(LEAF[i].mn);
		}
		fprintf(f, "const struct gt_x86_leaf gt_x86_leaves[%u] = {\n", n_leaf);
		for (i = 0; i < n_leaf; i++) {
			const struct leafspec *s = &LEAF[i];

			unsigned k, moffs = 0, regchk = 0;

			for (k = 0; k < s->nops; k++) {
				if (s->op[k].type == ND_OP_MEM && (s->op[k].memf & 4))
					moffs = 1;
				if (s->op[k].type == ND_OP_REG &&
				    (s->op[k].enc == ND_OPE_R || s->op[k].enc == ND_OPE_M ||
				     (s->op[k].enc == ND_OPE_V && (s->op[k].rtype == ND_REG_MSK || s->op[k].rtype == ND_REG_TILE))) &&
				    (s->op[k].rtype == ND_REG_CR || s->op[k].rtype == ND_REG_DR ||
				     s->op[k].rtype == ND_REG_BND || s->op[k].rtype == ND_REG_MSK ||
				     s->op[k].rtype == ND_REG_TILE))
					regchk = 1;
			}
			fprintf(f, "\t{ %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u },\n",
				s->valid ? s->id : 0, s->cat, lops[i], s->nops, s->cond,
				s->mand, (unsigned)(s->has_modrm | (moffs << 1) | ((unsigned)s->lockok << 2) |
						    ((unsigned)s->nomem << 3) | (regchk << 4) |
						    ((unsigned)s->restricted << 5) | ((unsigned)s->repeated << 6)), llen[i],
				lopsz[i], s->valid ? vm_ix(s->vm) : 0u, s->dist, s->nexp, s->wgpr, s->nform,
				lmnk[i], s->pf, s->pf2);
		}
		fprintf(f, "};\n\n");
		free(lops); free(llen); free(lopsz); free(lmnk);
	}
	fprintf(f, "const struct gt_x86_tpl gt_x86_tpls[%u] = {\n", n_tpl ? n_tpl : 1);
	for (i = 0; i < n_tpl; i++) {
		fprintf(f, "\t{ ");
		for (j = 0; j < 12; j++)
			fprintf(f, "%u, ", TPL[i].b[j]);
		fprintf(f, "%u, ", TPL[i].b[16]);
		fprintf(f, "%uu", TPL[i].b[12] | (TPL[i].b[13] << 8) | (TPL[i].b[14] << 16) |
			((unsigned)TPL[i].b[15] << 24));
		fprintf(f, " },\n");
	}
	fprintf(f, "};\n\nconst uint16_t gt_x86_tri[%u][8] = {\n", n_tri);
	for (i = 0; i < n_tri; i++)
	{
		unsigned q;

		fprintf(f, "\t{ ");
		for (q = 0; q < NOSZ; q++)
			fprintf(f, "%u%s", TRI[i].v[q], q < NOSZ - 1 ? ", " : "");
		fprintf(f, " },\n");
	}
	fprintf(f, "};\n\nconst char *const gt_x86_mnem[%u] = {\n", n_mnem);
	for (i = 0; i < n_mnem; i++)
		fprintf(f, "\t\"%s\",\n", i ? mnem_str[i] : "");
	fprintf(f, "};\n\nconst uint16_t gt_x86_mnk[%u][8] = {\n", n_mnk);
	for (i = 0; i < n_mnk; i++) {
		unsigned q;

		fprintf(f, "\t{ ");
		for (q = 0; q < NOSZ; q++)
			fprintf(f, "%u%s", MNK[i].v[q], q < NOSZ - 1 ? ", " : "");
		fprintf(f, " },\n");
	}
	fprintf(f, "};\n\nconst uint8_t gt_x86_lenk[%u][32] = {\n", n_lenk);
	for (i = 0; i < n_lenk; i++) {
		fprintf(f, "\t{ ");
		for (j = 0; j < NOSZ; j++) fprintf(f, "%u, ", LENK[i].imm1[j]);
		for (j = 0; j < NOSZ; j++) fprintf(f, "%u, ", LENK[i].imm2[j]);
		for (j = 0; j < NOSZ; j++) fprintf(f, "%u, ", LENK[i].rel[j]);
		for (j = 0; j < NOSZ; j++) fprintf(f, "%u%s", LENK[i].addr[j], j < NOSZ - 1 ? ", " : "");
		fprintf(f, " },\n");
	}
	fprintf(f, "};\n\n");

	/* The immediate-like bytes of each (tuple, size variant), summed: what a
	 * decode needs to know about the tail of an instruction without reading it. */
	fprintf(f, "const uint8_t gt_x86_fix[%u][%u] = {\n", n_lenk, NOSZ);
	for (i = 0; i < n_lenk; i++) {
		fprintf(f, "\t{ ");
		for (j = 0; j < NOSZ; j++)
			fprintf(f, "%u%s", LENK[i].imm1[j] + LENK[i].imm2[j] + LENK[i].rel[j] +
				LENK[i].addr[j], j < NOSZ - 1 ? ", " : "");
		fprintf(f, " },\n");
	}
	fprintf(f, "};\n\n");

	fprintf(f, "const uint8_t gt_x86_vmask[%u][16] = {\n", n_vmrow ? n_vmrow : 1);
	for (i = 0; i < n_vmrow; i++) {
		fprintf(f, "\t{ ");
		for (j = 0; j < 16; j++)
			fprintf(f, "%u%s", VMROW[i].b[j], j < 15 ? ", " : "");
		fprintf(f, " },\n");
	}
	if (!n_vmrow)
		fprintf(f, "\t{ 0 }\n");
	fprintf(f, "};\n\n");

	/* Nodes, flattened per encoding space: [kind | arity << 4] then the children.
	 * A space has its own table so that a reference - fifteen bits - never has
	 * to reach further than one space's worth. */
	{
		unsigned sp2, *spoff[N_SPACES];
		unsigned words[N_SPACES];

		for (sp2 = 0; sp2 < N_SPACES; sp2++) {
			spoff[sp2] = calloc(SPN_N[sp2] ? SPN_N[sp2] : 1, sizeof(unsigned));
			words[sp2] = 0;
			for (i = 0; i < SPN_N[sp2]; i++) {
				spoff[sp2][i] = words[sp2];
				words[sp2] += 1u + SPN[sp2][i].arity;
			}
			if (words[sp2] >= 0x8000u) {
				fprintf(stderr, "space %u: node table is %u words; references are 15 bits\n",
					sp2, words[sp2]);
				exit(1);
			}
			fprintf(f, "static const uint16_t nodes_%u[%u] = {\n", sp2, words[sp2] ? words[sp2] : 1);
			for (i = 0; i < SPN_N[sp2]; i++) {
				fprintf(f, "\t%u,", SPN[sp2][i].kind | (SPN[sp2][i].arity << 4));
				for (j = 0; j < SPN[sp2][i].arity; j++) {
					unsigned c = SPN[sp2][i].child[j];

					if (c & 0x8000u)
						c = 0x8000u | spoff[sp2][c & 0x7fffu];
					fprintf(f, " %u,", c);
				}
				fprintf(f, "\n");
			}
			fprintf(f, "};\n\n");
		}
		fprintf(f, "const uint16_t *const gt_x86_space_nodes[%u] = { nodes_0, nodes_1, nodes_2, nodes_3 };\n\n",
			N_SPACES);
		fprintf(f, "const uint16_t gt_x86_root[2][18][256] = {\n");
		{
			int m, mp;

			for (m = 0; m < 2; m++) {
				fprintf(f, "\t{\n");
				for (mp = 0; mp < N_RMAPS; mp++) {
					const unsigned spc = mp < 4 ? 0u : mp < 7 || mp == 17 ? 1u : mp < 10 ? 2u : 3u;

					fprintf(f, "\t\t{");
					for (i = 0; i < 256; i++) {
						unsigned c = ROOT[m][mp][i];

						if (c & 0x8000u)
							c = 0x8000u | spoff[spc][c & 0x7fffu];
						fprintf(f, "%s%u,", (i % 16) ? " " : "\n\t\t ", c);
					}
					fprintf(f, "\n\t\t},\n");
				}
				fprintf(f, "\t},\n");
			}
		}
		for (sp2 = 0; sp2 < N_SPACES; sp2++)
			free(spoff[sp2]);
		fprintf(stderr, "node words: legacy %u, vex %u, xop %u, evex %u\n",
			words[0], words[1], words[2], words[3]);
	}
	fprintf(f, "};\n");
	fclose(f);
	fprintf(stderr, "emitted: %u leaves, %u templates, %u size triples, %u length tuples, "
			"node words %u, max operands %u\n",
		n_leaf, n_tpl, n_tri, n_lenk, 0u, max_nops);
}

/*
 * WHICH REGISTERS MUST DIFFER. An instruction like VFMULCPH, a gather or an AMX
 * tile multiply is not valid when two of its registers are the same, and no
 * table indexed by opcode and modrm can say so - it depends on the register
 * NUMBERS, including the ones the prefix extends. So it is measured: for each
 * variant, with all registers distinct as the base, force one equality at a time
 * and see whether the reference stops decoding it.
 *
 *   bit 0  reg == rm (a register form)          bit 3  reg == a gather's index
 *   bit 1  reg == vvvv                          bit 4  vvvv == a gather's index
 *   bit 2  rm  == vvvv
 */
static int probe_ok(int mode, int map, unsigned opc, int pp, int osz, int asz,
		    unsigned modrm, int vforce, int sib)
{
	struct rec tmp;
	int ok;

	g_vforce = vforce;
	g_sib = sib;
	ok = probe(mode, map, opc, pp, osz, asz, modrm, &tmp);
	g_vforce = -1;
	g_sib = -1;
	return ok;
}

static void probe_dist(int mode, int map, unsigned opc)
{
	int pp, osz, asz;

	for (pp = 0; pp < NPP; pp++)
	for (osz = 0; osz < n_osz; osz++)
	for (asz = 0; asz < n_asz; asz++) {
		const unsigned rr = 0xC0u | (1u << 3) | 2u;     /* reg 1, rm 2 */
		const unsigned mm = 0x04u | (1u << 3);          /* reg 1, SIB follows */
		const int used = asz & 1;
		unsigned dr = 0, dm = 0;

		if (probe_ok(mode, map, opc, pp, osz, asz, rr, -1, -1)) {
			if (!probe_ok(mode, map, opc, pp, osz, asz, 0xC0u | (1u << 3) | 1u, -1, -1))
				dr |= 1u;
			if (used && !probe_ok(mode, map, opc, pp, osz, asz, rr, 1, -1))
				dr |= 2u;
			if (used && !probe_ok(mode, map, opc, pp, osz, asz, rr, 2, -1))
				dr |= 4u;
		}
		if (probe_ok(mode, map, opc, pp, osz, asz, mm, -1, 2 << 3)) {
			if (!probe_ok(mode, map, opc, pp, osz, asz, mm, -1, 1 << 3))
				dm |= 8u;
			if (used && !probe_ok(mode, map, opc, pp, osz, asz, mm, 2, 2 << 3))
				dm |= 16u;
		}
		DIST[pp][osz][asz][0] = (uint8_t)dm;
		DIST[pp][osz][asz][1] = (uint8_t)dr;
		if (opt_distdbg && strtoul(opt_distdbg, 0, 16) == opc && mode == 64 && (dr | dm))
			fprintf(stderr, "dist sp%d map%d %02x pp%d osz%d asz%d = reg %u mem %u\n", SP, map, opc, pp, osz, asz, dr, dm);
	}
}

/* The same collisions, put right in the table the probes filled: a record that
 * is invalid ONLY because two registers happened to be equal says nothing about
 * the opcode, so it takes its neighbour's meaning. */
static void heal_collisions(void)
{
	int pp, osz, asz, reg, mod;

	for (pp = 0; pp < NPP; pp++)
	for (osz = 0; osz < n_osz; osz++)
	for (asz = 0; asz < n_asz; asz++) {
		const unsigned d = DIST[pp][osz][asz][0] | DIST[pp][osz][asz][1];

		if (!d)
			continue;
		for (reg = 0; reg < NREG; reg++) {
			if ((d & 1u) && !REC[pp][osz][asz][2][reg][reg].valid &&
			    REC[pp][osz][asz][2][reg][(reg + 1) & 7].valid)
				REC[pp][osz][asz][2][reg][reg] = REC[pp][osz][asz][2][reg][(reg + 1) & 7];
			for (mod = 0; mod < 2; mod++)
				if ((d & 24u) && reg == 0 && !REC[pp][osz][asz][mod][0][4].valid &&
				    REC[pp][osz][asz][mod][1][4].valid)
					REC[pp][osz][asz][mod][0][4] = REC[pp][osz][asz][mod][1][4];
		}
	}
}

/* The root-map index of an encoding space's map: legacy 0-3, VEX 4-6 (maps
 * 1-3), XOP 7-9 (maps 8-10), EVEX 10-16 (maps 1-7), and VEX map 5 - the AMX
 * FP8 / TF32 tile instructions, 64-bit mode only - at 17. */
static int rmap_of(int sp, int map)
{
	switch (sp) {
	case SP_LEGACY: return map;
	case SP_VEX:    return map == 5 ? 17 : 4 + map - 1;
	case SP_XOP:    return 7 + map - 8;
	}
	return 10 + map - 1;
}

int main(int argc, char **argv)
{
	int mode, sp;
	unsigned long n_valid = 0, n_total = 0;
	static const struct { int first, last, nosz, nasz; } space[N_SPACES] = {
		{ 0, 3, 4, 4 }, { 1, 5, 4, 2 }, { 8, 10, 4, 2 }, { 1, 7, 8, 16 }
	};

	unsigned want = 0xfu;           /* bit per encoding space                   */

	if (argc < 3) {
		fprintf(stderr, "usage: x86_gen <bdx86_constants.h> <outdir> [legacy,vex,xop,evex] [--dump=S,M,OP] [--distdbg=OP] [--verbose]\n");
		return 1;
	}
	{
		int ai;

		for (ai = 3; ai < argc; ai++) {
			if (!strncmp(argv[ai], "--dump=", 7)) {
				opt_dump = argv[ai] + 7;
			} else if (!strncmp(argv[ai], "--distdbg=", 10)) {
				opt_distdbg = argv[ai] + 10;
			} else if (!strcmp(argv[ai], "--verbose")) {
				opt_verbose = 1;
			} else {
				/* a comma list of the spaces to generate */
				if (ai == 3)
					want = 0;
				if (strstr(argv[ai], "legacy")) want |= 1u << SP_LEGACY;
				if (strstr(argv[ai], "vex"))    want |= 1u << SP_VEX;
				if (strstr(argv[ai], "xop"))    want |= 1u << SP_XOP;
				if (strstr(argv[ai], "evex"))   want |= 1u << SP_EVEX;
			}
		}
	}
	{
		/* Every root starts as one invalid leaf, so a space that was not
		 * generated reads as "not an instruction" and not as leaf 0. */
		struct leafspec dead0;
		unsigned m, o2;
		uint16_t d0;

		memset(&dead0, 0, sizeof dead0);
		d0 = leaf_ix(&dead0);
		for (m = 0; m < 2; m++)
			for (o2 = 0; o2 < N_RMAPS * 256u; o2++)
				ROOT[m][o2 / 256u][o2 % 256u] = d0;
	}
	load_names(argv[1]);
	fprintf(stderr, "%u instruction names\n", n_insn_name);
	for (sp = 0; sp < N_SPACES; sp++) {
		if (!(want & (1u << sp)))
			continue;
		SP = sp;
		for (mode = 32; mode <= 64; mode += 32) {
		int map;

		n_osz = space[sp].nosz;
		n_asz = space[sp].nasz;
		for (map = space[sp].first; map <= space[sp].last; map++) {
			unsigned opc;

			for (opc = 0; opc < 256; opc++) {
				int pp, osz, asz, mod, reg, rm;
				int fix[4] = { -1, -1, -1, -1 };
				unsigned nl0 = n_leaf, nn0 = n_node;
				int any = 0;

				cur_mode = mode;
				if (sp == SP_LEGACY && is_pseudo_root(mode, map, opc))
					continue;
				p66_of_root = sp != SP_LEGACY;
				for (pp = 0; pp < NPP; pp++)
				for (osz = 0; osz < n_osz; osz++)
				for (asz = 0; asz < n_asz; asz++)
				for (mod = 0; mod < NMOD; mod++)
				for (reg = 0; reg < NREG; reg++)
				for (rm = 0; rm < NRM; rm++) {
					unsigned modrm = (unsigned)((mod == 2 ? 3 : mod) << 6 | reg << 3 | rm);
					struct rec *r = &REC[pp][osz][asz][mod][reg][rm];
					int ok = probe(mode, map, opc, pp, osz, asz, modrm, r);

					n_total++;
					if (!ok) {
						if (sp == SP_LEGACY && osz == 0 && asz == 0)
							LKV[pp][mod][reg][rm] = 0;
						continue;
					}
					n_valid++;
					any = 1;
					if (r->has_modrm && mod != 2) {
						/* Does a disp8 form carry a displacement? A ModRM that
						 * reads mod and then ignores it (a move to a control
						 * register) does not. */
						uint8_t b1[32];
						struct variant v1 = { pp, osz, asz, 0, 0 };
						INSTRUX ix1;

						build(b1, mode, &v1, map, opc, 0x40u | (unsigned)(reg << 3));
						if (ND_SUCCESS(NdDecodeEx(&ix1, b1, 16,
							mode == 64 ? ND_CODE_64 : ND_CODE_32,
							mode == 64 ? ND_DATA_64 : ND_DATA_32)))
							r->nomem = (uint8_t)(ix1.DispLength == 0 && !ix1.HasSib);
					}
					if (sp == SP_LEGACY && pp == 1 && (r->mand & 1))
						p66_of_root = 1;
					if (sp == SP_LEGACY && osz == 0 && asz == 0) {
						uint8_t b[32];
						struct variant v = { pp, 0, 0, 1, 0 };
						INSTRUX ix2;

						build(b, mode, &v, map, opc, modrm);
						LKV[pp][mod][reg][rm] = ND_SUCCESS(NdDecodeEx(&ix2, b, 16,
							mode == 64 ? ND_CODE_64 : ND_CODE_32,
							mode == 64 ? ND_DATA_64 : ND_DATA_32)) ? 1 : 0;
						PF2V[pp][mod][reg][rm] = 0;
						if (LKV[pp][mod][reg][rm])
							PF2V[pp][mod][reg][rm] |= (uint8_t)((ix2.IsXacquireEnabled ? 1 : 0) |
											   (ix2.IsXreleaseEnabled ? 2 : 0));
						{
							struct variant v3 = { pp, 0, 0, 0, 0x3E };
							INSTRUX ix3;

							build(b, mode, &v3, map, opc, modrm);
							if (ND_SUCCESS(NdDecodeEx(&ix3, b, 16,
								mode == 64 ? ND_CODE_64 : ND_CODE_32,
								mode == 64 ? ND_DATA_64 : ND_DATA_32)))
								PF2V[pp][mod][reg][rm] |= (uint8_t)((ix3.IsBhintEnabled ? 4 : 0) |
												   (ix3.IsDntEnabled ? 8 : 0));
						}
					}
				}
				if (any && sp != SP_LEGACY) {
					probe_dist(mode, map, opc);
					heal_collisions();
				} else {
					memset(DIST, 0, sizeof DIST);
				}
				/* A space with nothing valid in it for this opcode is one
				 * invalid leaf, not a tree of them. */
				if (!any) {
					struct leafspec dead;

					memset(&dead, 0, sizeof dead);
					ROOT[mode == 64][rmap_of(sp, map)][opc] = leaf_ix(&dead);
					continue;
				}
				rd_pp_arity = p66_of_root ? 4 : 3;
				ROOT[mode == 64][rmap_of(sp, map)][opc] = build_tree(fix);
				mapnodes[sp][map & 15] += n_node - nn0;
				if (opt_dump) {
					int ds, dm;
					unsigned dop;

					if (sscanf(opt_dump, "%d,%d,%x", &ds, &dm, &dop) == 3 &&
					    ds == sp && dm == map && dop == opc && mode == 64) {
						{
							int mm, oo, aa;

							for (mm = 0; mm < 3; mm++)
								for (oo = 0; oo < n_osz; oo += 2)
									for (aa = 0; aa < n_asz; aa += 5)
										fprintf(stderr, "rec mod%d osz%d asz%d: valid %d nops %u op3type %u\n", mm, oo, aa,
											REC[0][oo][aa][mm][0][0].valid, REC[0][oo][aa][mm][0][0].nops,
											REC[0][oo][aa][mm][0][0].op[3].type);
						}
						{
							static const struct vsel all0 = { 0, 0, 0, 0 };
							int mm;

							for (mm = 0; mm < 3; mm++) {
								struct leafspec lsx;
								uint32_t hx = 0;
								int okx = spec_of(1, mm, 0, 0, &all0, &lsx, &hx);

								fprintf(stderr, "spec pp1 mod%d: ok=%d hash=%x leaf=%d\n", mm, okx, hx,
									okx ? (int)leaf_ix(&lsx) : -1);
							}
						}
						fprintf(stderr, "tree sp%d map%d %02x:\n", sp, map, opc);
						dump_tree(ROOT[1][rmap_of(sp, map)][opc], 2);
					}
				}
				if (opt_verbose && (n_node - nn0) > 40)
					fprintf(stderr, "root %d sp%d map%d %02x: +%u leaves +%u nodes\n",
						mode, sp, map, opc, n_leaf - nl0, n_node - nn0);
			}
		}
		}
		/* Keep this space's nodes and start the next space with an empty pool. */
		SPN[sp] = malloc((n_node ? n_node : 1) * sizeof *SPN[sp]);
		memcpy(SPN[sp], NODE, n_node * sizeof *NODE);
		SPN_N[sp] = n_node;
		n_node = 0;
		memset(node_head, 0xff, sizeof node_head);
	}
	{
		int q, w;

		for (q = 0; q < 4; q++)
			for (w = 0; w < 16; w++)
				if (mapnodes[q][w])
					fprintf(stderr, "space %d map %d: %u nodes\n", q, w, mapnodes[q][w]);
	}
	fprintf(stderr, "probed %lu, valid %lu\n", n_total, n_valid);
	fprintf(stderr, "leaves %u, nodes %u\n", n_leaf, n_node);
	emit(argv[2]);
	return 0;
}
