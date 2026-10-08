/*
 * arm32_diff - the ARM state and Thumb state decoders (cell_decode_arm32, cell_decode_thumb) against
 * an oracle.
 *
 * A DEV TOOL, NOT A TEST: the oracle is Capstone, which this tree does not
 * ship. Built by hand, until the Makefile's celllysis-arm-diff names the new
 * file set (the decoders are now genotype's tables plus the celllysis adapters):
 *
 *   gcc -O2 -std=gnu11 -pthread -Ilibkofeng/kofcore -Ilibgenome -Ilibgenome/genotype \
 *       -I<capstone include dir> tools/celllysis/arm32_diff.c \
 *       libgenome/celllysis/decode_arm32.c libgenome/celllysis/decode_thumb.c \
 *       libgenome/celllysis/decode_arm32_common.c \
 *       libgenome/genotype/arm32/arm32_rows.c libgenome/genotype/arm32/thumb_rows.c \
 *       libgenome/genotype/arm32/arm32_index.c \
 *       <libcapstone.a> -o arm32_diff
 *
 *   arm32_diff arm32|thumb rand <millions> [seed]     uniformly random words
 *   arm32_diff arm32|thumb sys  [fills]               systematic: every opcode field
 *   arm32_diff arm32|thumb elf  <file>...             every aligned word / halfword
 *                                               of the executable code
 *   arm32_diff arm32|thumb bench <file>...            decode speed, no oracle: ns per
 *                                               instruction over .text, walked the
 *                                               way a sweep walks it (Thumb steps
 *                                               by the length it was told)
 *
 * CAPSTONE IS AN ORACLE AND NOT THE TRUTH. This compares and counts; what a
 * disagreement MEANS - who is right - is decided from the ARM ARM, per
 * category, and written down where the decoder says what it does by design.
 * The class map below (what class Capstone's instruction should be here) is
 * this tool's own table, not the decoder's.
 *
 * WHAT IS COMPARED, for an encoding both read as valid: the length; the class;
 * the branch target; the written-register mask against cs_regs_access; the
 * immediate of a mov and of an ALU instruction; the literal address of a
 * pc-relative load; the base, index, displacement and width of a memory
 * operand; and the destination and first source register. Validity itself is
 * compared first, and where our decoder answers UD and the oracle does not
 * (or the reverse) that is a category of its own.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <time.h>
#include <capstone/capstone.h>

#include "kofmod/kofsig.h"
#include "celllysis/decode.h"

enum kind {
	K_VALID_CS_ONLY, K_VALID_US_ONLY, K_VALID_US_FIELD, K_LEN, K_CLASS, K_WMASK, K_TARGET,
	K_IMM, K_LIT, K_MEM, K_REG, K_COND, K_FLAGS, K_WGAP, K_COUNT
};
static const char *const KNAME[K_COUNT] = {
	"valid in oracle, UD here", "UD in oracle, valid here (not an SBZ/SBO field)",
	"UD in oracle, valid here (oracle rejects an SBZ/SBO field)", "length",
	"class", "written registers", "branch target", "immediate",
	"literal address", "memory operand", "register operand", "condition",
	"flags", "written registers: the oracle omits an architectural write",
};

struct ex {
	uint32_t w0, w1;
	uint64_t va;
	char txt[72];
};
struct cat {
	uint64_t key, n;
	struct ex e[3];
	unsigned ne;
};
#define TBL (1u << 15)

struct stats {
	struct cat *t;
	uint64_t total, both, cs_valid, us_valid;
};

static void st_init(struct stats *s)
{
	memset(s, 0, sizeof *s);
	s->t = calloc(TBL, sizeof *s->t);
}

static struct cat *st_slot(struct stats *s, uint64_t key)
{
	uint64_t h = key * 0x9e3779b97f4a7c15ull;
	unsigned i = (unsigned)(h >> 49) & (TBL - 1u);

	while (s->t[i].n && s->t[i].key != key)
		i = (i + 1u) & (TBL - 1u);
	s->t[i].key = key;
	return &s->t[i];
}

static void st_add(struct stats *s, enum kind k, unsigned ours_op,
		   unsigned id, uint32_t aux, uint32_t w0, uint32_t w1,
		   uint64_t va, const char *txt)
{
	uint64_t key = (uint64_t)k << 56 | (uint64_t)(ours_op & 0xff) << 48 |
		       (uint64_t)(id & 0xffff) << 32 | aux;
	struct cat *c = st_slot(s, key);

	if (c->n < 3u) {
		struct ex *e = &c->e[c->ne++];

		e->w0 = w0;
		e->w1 = w1;
		e->va = va;
		snprintf(e->txt, sizeof e->txt, "%s", txt);
	}
	c->n++;
}

static void st_merge(struct stats *d, const struct stats *s)
{
	unsigned i, j;

	d->total += s->total;
	d->both += s->both;
	d->cs_valid += s->cs_valid;
	d->us_valid += s->us_valid;
	for (i = 0; i < TBL; i++) {
		struct cat *c;

		if (!s->t[i].n)
			continue;
		c = st_slot(d, s->t[i].key);
		for (j = 0; j < s->t[i].ne && c->ne < 3u; j++)
			c->e[c->ne++] = s->t[i].e[j];
		c->n += s->t[i].n;
	}
}

/* ---- the oracle's register numbering ------------------------------------ */

static int g_r[ARM_REG_ENDING + 1];

static void reg_init(void)
{
	unsigned i;

	for (i = 0; i <= ARM_REG_ENDING; i++)
		g_r[i] = -1;
	for (i = 0; i < 13; i++)
		g_r[ARM_REG_R0 + i] = (int)i;
	g_r[ARM_REG_SP] = 13;
	g_r[ARM_REG_LR] = 14;
	g_r[ARM_REG_PC] = 15;
}

static int rnum(int reg)
{
	return (reg > 0 && reg < ARM_REG_ENDING) ? g_r[reg] : -1;
}

/* ---- what class the oracle's instruction should be here ------------------ */

#define BIT(c) (1ull << (c))

static int has_pc_write(const cs_arm *d, int id)
{
	(void)id;
	return d->op_count && d->operands[0].type == ARM_OP_REG &&
	       d->operands[0].reg == ARM_REG_PC;
}

/*
 * The set of classes this decoder may answer with. 0 = no opinion.
 * `wr` is the oracle's written core registers (r0..r15 as bits).
 */
static uint64_t expect(const cs_insn *in, uint32_t wr, int thumb)
{
	const cs_arm *d = &in->detail->arm;
	const cs_arm_op *o = d->operands;
	unsigned n = d->op_count;
	int imm_last = n && o[n - 1].type == ARM_OP_IMM;
	int pcw = has_pc_write(d, (int)in->id);
	int pcl = n && o[0].type == ARM_OP_REG && o[0].reg == ARM_REG_PC;

	(void)thumb;
	switch (in->id) {
	case ARM_INS_ADC: case ARM_INS_ADD: case ARM_INS_ADDW: case ARM_INS_AND:
	case ARM_INS_EOR: case ARM_INS_ORR: case ARM_INS_SUB: case ARM_INS_SUBW:
	case ARM_INS_SBC: {
		static const struct { int id; int c; } m[] = {
			{ ARM_INS_ADC, CELL_ADC }, { ARM_INS_ADD, CELL_ADD },
			{ ARM_INS_ADDW, CELL_ADD }, { ARM_INS_AND, CELL_AND },
			{ ARM_INS_EOR, CELL_XOR }, { ARM_INS_ORR, CELL_OR },
			{ ARM_INS_SUB, CELL_SUB }, { ARM_INS_SUBW, CELL_SUB },
			{ ARM_INS_SBC, CELL_SBB },
		};
		unsigned i;
		uint64_t a = 0;

		for (i = 0; i < sizeof m / sizeof m[0]; i++)
			if (m[i].id == (int)in->id)
				a = BIT(m[i].c);
		if (pcw)
			return BIT(CELL_JMP) | BIT(CELL_PRIV);
		/* add rd, pc, #imm is an address */
		if ((in->id == ARM_INS_ADD || in->id == ARM_INS_SUB ||
		     in->id == ARM_INS_ADDW || in->id == ARM_INS_SUBW) &&
		    n >= 2 && o[1].type == ARM_OP_REG && o[1].reg == ARM_REG_PC &&
		    imm_last)
			return a | BIT(CELL_LEA);
		return a;
	}
	case ARM_INS_ADR:
		return BIT(CELL_LEA);
	case ARM_INS_CMP:
		return BIT(CELL_CMP);
	case ARM_INS_TST: case ARM_INS_TEQ:
		return BIT(CELL_TEST);
	case ARM_INS_MUL:
		return BIT(CELL_MUL);
	case ARM_INS_UDIV:
		return BIT(CELL_DIV);
	case ARM_INS_SDIV:
		return BIT(CELL_IDIV);
	case ARM_INS_MOV:
		/* movw also arrives under this id */
		if (pcw)
			return BIT(CELL_JMP) | BIT(CELL_RET) | BIT(CELL_PRIV) |
			       (imm_last ? BIT(CELL_MOV) : 0);
		return BIT(CELL_MOV) | BIT(CELL_NOP);
	case ARM_INS_MOVW:
		return pcw ? BIT(CELL_MOV) | BIT(CELL_JMP) : BIT(CELL_MOV);
	case ARM_INS_MOVT:
		return BIT(CELL_OR);
	case ARM_INS_MVN:
		if (pcw)
			return BIT(CELL_JMP) | BIT(CELL_PRIV);
		return imm_last ? BIT(CELL_MOV) : BIT(CELL_NOT) | BIT(CELL_OTHER);
	case ARM_INS_LSL:
		return pcw ? BIT(CELL_JMP) | BIT(CELL_PRIV) : BIT(CELL_SHL);
	case ARM_INS_LSR:
		return pcw ? BIT(CELL_JMP) | BIT(CELL_PRIV) : BIT(CELL_SHR);
	case ARM_INS_ASR:
		return pcw ? BIT(CELL_JMP) | BIT(CELL_PRIV) : BIT(CELL_SAR);
	case ARM_INS_ROR:
		return pcw ? BIT(CELL_JMP) | BIT(CELL_PRIV) : BIT(CELL_ROR);
	case ARM_INS_RSB:
		/* a rotated zero is spelt as two immediates: still a negate */
		if (pcw)
			return BIT(CELL_JMP) | BIT(CELL_PRIV);
		if (imm_last && (o[n - 1].imm == 0 || (n >= 4 && o[n - 2].type == ARM_OP_IMM)))
			return BIT(CELL_NEG) | BIT(CELL_OTHER);
		return BIT(CELL_OTHER);
	case ARM_INS_B:
		return d->cc == ARM_CC_AL || d->cc == ARM_CC_INVALID
		       ? BIT(CELL_JMP) : BIT(CELL_JCC);
	case ARM_INS_CBZ: case ARM_INS_CBNZ:
		return BIT(CELL_JCC);
	case ARM_INS_BL: case ARM_INS_BLX:
		return BIT(CELL_CALL);
	case ARM_INS_BX:
		return BIT(CELL_RET) | BIT(CELL_JMP);
	case ARM_INS_BXJ:
		return BIT(CELL_JMP);
	case ARM_INS_BXNS:
		return BIT(CELL_JMP) | BIT(CELL_RET);
	case ARM_INS_BLXNS:
		return BIT(CELL_CALL);
	case ARM_INS_TBB: case ARM_INS_TBH:
		return BIT(CELL_JMP);
	case ARM_INS_SUBS:
		return BIT(CELL_PRIV);
	case ARM_INS_MOVS:
		return BIT(CELL_MOV) | BIT(CELL_NOP);
	case ARM_INS_SVC:
		return BIT(CELL_SYSCALL);
	case ARM_INS_BKPT:
		return BIT(CELL_INT);
	case ARM_INS_UDF: case ARM_INS_TRAP:
		return BIT(CELL_UD);
	case ARM_INS_HINT:
	case ARM_INS_NOP: case ARM_INS_YIELD: case ARM_INS_WFE: case ARM_INS_WFI:
	case ARM_INS_SEV: case ARM_INS_SEVL: case ARM_INS_DBG:
		return BIT(CELL_NOP);
	case ARM_INS_PUSH:
		return BIT(CELL_PUSH);
	case ARM_INS_POP:
		return BIT(CELL_POP) | BIT(CELL_RET);
	case ARM_INS_LDR: case ARM_INS_LDRT: case ARM_INS_LDRD:
		if (n && o[0].type == ARM_OP_REG && o[0].reg == ARM_REG_PC)
			return BIT(CELL_JMP) | BIT(CELL_RET) |
			       (in->id == ARM_INS_LDRD ? BIT(CELL_MOV) : 0);
		/* ldr rt,[sp],#4 is pop {rt} */
		if (in->id == ARM_INS_LDR && n >= 2 && o[1].type == ARM_OP_MEM &&
		    o[1].mem.base == ARM_REG_SP)
			return BIT(CELL_MOV) | BIT(CELL_POP);
		return BIT(CELL_MOV);
	case ARM_INS_STR: case ARM_INS_STRT:
		if (in->id == ARM_INS_STR && n >= 2 && o[1].type == ARM_OP_MEM &&
		    o[1].mem.base == ARM_REG_SP)
			return BIT(CELL_MOV) | BIT(CELL_PUSH);
		return BIT(CELL_MOV);
	case ARM_INS_STRB: case ARM_INS_STRBT: case ARM_INS_STRH:
	case ARM_INS_STRHT: case ARM_INS_STRD:
		return BIT(CELL_MOV);
	case ARM_INS_LDRB: case ARM_INS_LDRBT: case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
		return BIT(CELL_MOVZX) | (pcl ? BIT(CELL_OTHER) : 0);
	case ARM_INS_LDRSB: case ARM_INS_LDRSBT: case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
		return BIT(CELL_MOVSX) | (pcl ? BIT(CELL_OTHER) : 0);
	case ARM_INS_SXTB: case ARM_INS_SXTH:
		return BIT(CELL_MOVSX);
	case ARM_INS_UXTB: case ARM_INS_UXTH:
		return BIT(CELL_MOVZX);
	case ARM_INS_LDM: case ARM_INS_LDMDA: case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
		/* a list with pc is a branch; ldmia sp! is a pop */
		{
			unsigned i;
			int pc = 0;

			for (i = 1; i < n; i++)         /* o[0] is the base */
				if (o[i].type == ARM_OP_REG && o[i].reg == ARM_REG_PC)
					pc = 1;
			if (pc)
				return BIT(CELL_JMP) | BIT(CELL_RET) | BIT(CELL_PRIV);
			return BIT(CELL_OTHER) | BIT(CELL_POP);
		}
	case ARM_INS_STM: case ARM_INS_STMDA: case ARM_INS_STMDB:
	case ARM_INS_STMIB:
		return BIT(CELL_OTHER) | BIT(CELL_PUSH);
	case ARM_INS_MSR: case ARM_INS_MRS: case ARM_INS_CPS: case ARM_INS_SETEND:
	case ARM_INS_RFEDA: case ARM_INS_RFEDB: case ARM_INS_RFEIA:
	case ARM_INS_RFEIB: case ARM_INS_SRSDA: case ARM_INS_SRSDB:
	case ARM_INS_SRSIA: case ARM_INS_SRSIB: case ARM_INS_SMC:
	case ARM_INS_HVC: case ARM_INS_ERET:
		return BIT(CELL_PRIV);
	default:
		(void)wr;
		if (pcw)
			return BIT(CELL_PRIV) | BIT(CELL_JMP) | BIT(CELL_OTHER);
		(void)pcl;
		return BIT(CELL_OTHER);
	}
}

/*
 * A write the oracle leaves out and the ARM ARM does not: the base register
 * that a load/store writes back (Capstone lists it for the plain forms and
 * not for the unprivileged T forms, the shifted post-indexed forms, STM,
 * VLDn/VSTn, VPUSH/VPOP, LDC), the Rt/Rt2 of MRC, MRRC and VMOV to core (it
 * records them as reads), and the lr that `svc` clobbers in the supervisor
 * bank (not the current one). `ow`/`cw` are ours and the oracle's.
 */
static int wgap(const cs_insn *in, uint32_t ow, uint32_t cw)
{
	const cs_arm *d = &in->detail->arm;
	uint32_t extra = ow & ~cw, miss = cw & ~ow, allow = 0;
	unsigned i;

	if (in->id == ARM_INS_SVC)
		return !extra && miss == (1u << 14);
	/* Thumb branches carry no pc in the oracle's list; ARM state's do */
	if ((in->id == ARM_INS_B || in->id == ARM_INS_BL || in->id == ARM_INS_BLX ||
	     in->id == ARM_INS_BX || in->id == ARM_INS_BXJ || in->id == ARM_INS_CBZ ||
	     in->id == ARM_INS_CBNZ || in->id == ARM_INS_BXNS ||
	     in->id == ARM_INS_BLXNS || in->id == ARM_INS_TBB || in->id == ARM_INS_TBH) &&
	    !miss && (extra == (1u << 15) || extra == ((1u << 15) | (1u << 14))))
		return 1;
	/* it lists the stored register of an unprivileged store as written */
	if ((in->id == ARM_INS_STRT || in->id == ARM_INS_STRBT ||
	     in->id == ARM_INS_STRHT) && !extra)
		return 1;
	/* a byte/halfword load into pc is a prefetch hint here, not a write */
	if ((in->id == ARM_INS_LDRB || in->id == ARM_INS_LDRH ||
	     in->id == ARM_INS_LDRSB || in->id == ARM_INS_LDRSH ||
	     in->id == ARM_INS_LDRBT || in->id == ARM_INS_LDRHT ||
	     in->id == ARM_INS_LDRSBT || in->id == ARM_INS_LDRSHT) &&
	    !extra && (miss & ~(1u << 15)) == 0 && (miss & (1u << 15)))
		return 1;
	/* a vsdot pattern with an impossible register pair is UNDEFINED; the
	 * oracle reads it as ldc2/stc2 with a written-back base */
	if ((in->id == ARM_INS_LDC2 || in->id == ARM_INS_LDC2L ||
	     in->id == ARM_INS_STC2 || in->id == ARM_INS_STC2L) && !extra &&
	    d->op_count && (d->operands[0].type == ARM_OP_PIMM || d->operands[0].type == ARM_OP_IMM) &&
	    d->operands[0].imm == 13)
		return 1;
	/* the oracle reads RFE's base register as an immediate */
	if ((in->id == ARM_INS_RFEDA || in->id == ARM_INS_RFEDB ||
	     in->id == ARM_INS_RFEIA || in->id == ARM_INS_RFEIB) && !miss)
		return 1;
	/* Rt = pc in vmov/vmrs is UNPREDICTABLE / APSR_nzcv: no register write here */
	if ((in->id == ARM_INS_VMOV || in->id == ARM_INS_VMRS) && !extra &&
	    miss == (1u << 15))
		return 1;
	/* ldrexd/ldaexd with an odd Rt: the oracle names the even pair */
	if ((in->id == ARM_INS_LDREXD || in->id == ARM_INS_LDAEXD) && !miss)
		return 1;
	if (miss)
		return 0;
	for (i = 0; i < d->op_count; i++) {
		int r;

		if (d->operands[i].type == ARM_OP_MEM) {
			r = rnum(d->operands[i].mem.base);
			if (r >= 0)
				allow |= 1u << r;
		}
		if (d->operands[i].type == ARM_OP_REG) {
			r = rnum(d->operands[i].reg);
			if (r >= 0 && (i == 0 || in->id == ARM_INS_MRC ||
				       in->id == ARM_INS_MRC2 ||
				       in->id == ARM_INS_MRRC ||
				       in->id == ARM_INS_MRRC2 ||
				       in->id == ARM_INS_VMOV ||
				       in->id == ARM_INS_VMRS))
				allow |= 1u << r;
		}
	}
	allow |= 1u << 13;              /* vpush, vpop, ldmia sp! */
	return extra && !(extra & ~allow);
}

/* ---- one comparison ------------------------------------------------------ */

struct th {
	csh h;
	cs_insn *in;
	int thumb;
	struct stats st;
	uint64_t rs;
	int reset;
	cs_insn *tmp;
};

static uint32_t rnd(struct th *t)
{
	t->rs ^= t->rs << 13;
	t->rs ^= t->rs >> 7;
	t->rs ^= t->rs << 17;
	return (uint32_t)(t->rs >> 11);
}

static int g_v8;

static void th_open(struct th *t, int thumb)
{
	t->thumb = thumb;
	if (cs_open(CS_ARCH_ARM, (thumb ? CS_MODE_THUMB : CS_MODE_ARM) | (g_v8 ? CS_MODE_V8 : 0), &t->h)) {
		fprintf(stderr, "cs_open failed\n");
		exit(2);
	}
	cs_option(t->h, CS_OPT_DETAIL, CS_OPT_ON);
	t->in = cs_malloc(t->h);
	t->tmp = cs_malloc(t->h);
	st_init(&t->st);
}

static uint32_t cs_wmask(struct th *t, const cs_insn *in)
{
	cs_regs rr, rw;
	uint8_t nr, nw, i;
	uint32_t m = 0;

	if (cs_regs_access(t->h, in, rr, &nr, rw, &nw))
		return 0;
	for (i = 0; i < nw; i++) {
		int r = rnum(rw[i]);

		if (r >= 0)
			m |= 1u << r;
	}
	return m;
}

static unsigned acc_size(unsigned id)
{
	switch (id) {
	case ARM_INS_LDRB: case ARM_INS_LDRBT: case ARM_INS_STRB:
	case ARM_INS_STRBT: case ARM_INS_LDRSB: case ARM_INS_LDRSBT:
		return 1;
	case ARM_INS_LDRH: case ARM_INS_LDRHT: case ARM_INS_STRH:
	case ARM_INS_STRHT: case ARM_INS_LDRSH: case ARM_INS_LDRSHT:
		return 2;
	case ARM_INS_LDRD: case ARM_INS_STRD:
		return 8;
	case ARM_INS_LDR: case ARM_INS_STR: case ARM_INS_LDRT: case ARM_INS_STRT:
		return 4;
	}
	return 0;
}

/*
 * Does the oracle accept this word once the fields the manual says "should be
 * zero" / "should be one" hold those values? Four nibbles are tried, each as
 * it is, 0 and 0xF: ARM state bits 3:0, 11:8, 15:12 and 19:16; Thumb-2 the second
 * halfword's 3:0, 11:8 and 15:12 and the first's 3:0. A word the oracle refuses
 * only because such a field is wrong is UNPREDICTABLE in the ARM ARM, not
 * undefined, and is counted apart.
 */
static int sbz_fixable(struct th *t, uint32_t w0, uint32_t w1, uint64_t va,
		       unsigned our_op)
{
	/*
	 * The nibbles tried. ARM state's bits 7:4 are opcode bits and are left alone;
	 * Thumb's second-halfword 7:4 and first-halfword 7:4 are not.
	 */
	static const unsigned arm32_sh[4] = { 0, 8, 12, 16 };
	static const unsigned thumb_sh[7] = { 0, 4, 8, 12, 16, 20, 24 };
	const unsigned *sh = t->thumb ? thumb_sh : arm32_sh;
	unsigned nsh = t->thumb ? 7u : 4u, total = 1, c, f, v;
	uint32_t word = t->thumb ? ((w0 & 0xffffu) << 16 | (w1 & 0xffffu)) : w0;

	for (f = 0; f < nsh; f++)
		total *= 3u;
	/* variants 0..total-1 are the nibble combinations; then the list bits */
	for (v = 1; v < total + 3u; v++) {
		uint32_t x = word;
		uint8_t b[4];
		const uint8_t *cp = b;
		size_t sz = 4;
		uint64_t ad = va;
		struct cell_insn k;

		if (v < total) {
			unsigned q = v;

			for (f = 0; f < nsh; f++, q /= 3u) {
				unsigned m = q % 3u;

				if (m == 1u)
					x &= ~(0xfu << sh[f]);
				else if (m == 2u)
					x |= 0xfu << sh[f];
			}
		} else if (t->thumb) {
			/* a register list with sp or pc in it */
			x &= ~(v == total ? 0xa000u : v == total + 1u ? 0x8000u : 0x2000u);
		} else {
			break;
		}
		if (x == word)
			continue;
		if (t->thumb) {
			b[0] = (uint8_t)(x >> 16); b[1] = (uint8_t)(x >> 24);
			b[2] = (uint8_t)x; b[3] = (uint8_t)(x >> 8);
			(void)cell_decode_thumb(b, 4, va, 0, &k);
		} else {
			b[0] = (uint8_t)x; b[1] = (uint8_t)(x >> 8);
			b[2] = (uint8_t)(x >> 16); b[3] = (uint8_t)(x >> 24);
			(void)cell_decode_arm32(b, 4, va, 0, &k);
		}
		/* the same instruction, not a neighbour that happens to decode */
		if (k.op != our_op)
			continue;
		if (cs_disasm_iter(t->h, &cp, &sz, &ad, t->tmp)) {
			if (t->tmp->id == ARM_INS_IT)
				t->reset = 1;
			return 1;
		}
	}
	(void)c;
	return 0;
}

static void check1(struct th *t, uint32_t w0, uint32_t w1, int nb, uint64_t va)
{
	uint8_t buf[4];
	const uint8_t *cp = buf;
	size_t sz = 4;
	uint64_t addr = va;
	struct cell_insn k;
	uint32_t n;
	int ok;
	char txt[72];
	const cs_insn *in = t->in;
	struct stats *s = &t->st;

	if (nb == 4 && !t->thumb) {
		buf[0] = (uint8_t)w0; buf[1] = (uint8_t)(w0 >> 8);
		buf[2] = (uint8_t)(w0 >> 16); buf[3] = (uint8_t)(w0 >> 24);
	} else {
		buf[0] = (uint8_t)w0; buf[1] = (uint8_t)(w0 >> 8);
		buf[2] = (uint8_t)w1; buf[3] = (uint8_t)(w1 >> 8);
	}
	s->total++;
	n = t->thumb ? cell_decode_thumb(buf, 4, va, 0, &k)
		     : cell_decode_arm32(buf, 4, va, 0, &k);
	ok = cs_disasm_iter(t->h, &cp, &sz, &addr, t->in) ? 1 : 0;
	if (ok) {
		snprintf(txt, sizeof txt, "%s %s", in->mnemonic, in->op_str);
		if (in->id == ARM_INS_IT)
			t->reset = 1;   /* its block state would colour the next decode */
	} else {
		snprintf(txt, sizeof txt, "(invalid)");
	}
	{
		int us_ud = (k.op == CELL_UD) || n == 0;
		/*
		 * WHERE THE WORD IS, so a category is a region of the encoding
		 * space and not one example: ARM state is cond==F, bits 27..20 and
		 * bits 7..4; Thumb is the first halfword's top twelve bits and
		 * (for a 32-bit encoding) the second's top four.
		 */
		uint32_t space = t->thumb
			? (((w0 >> 4) & 0xfffu) | (((w0 >> 11) >= 0x1du ? (w1 >> 12) + 1u : 0u) << 12))
			: (((w0 >> 28) == 15u ? 0x1000u : 0u) |
			   ((w0 >> 20) & 0xffu) << 4 | ((w0 >> 4) & 15u));

		if (ok)
			s->cs_valid++;
		if (!us_ud)
			s->us_valid++;
		if (ok && us_ud && (in->id == ARM_INS_UDF || in->id == ARM_INS_TRAP))
			return;
		if (ok && us_ud) {
			st_add(s, K_VALID_CS_ONLY, k.op, in->id, space, w0, w1, va, txt);
			return;
		}
		if (!ok && !us_ud) {
			st_add(s, sbz_fixable(t, w0, w1, va, k.op) ? K_VALID_US_FIELD
							     : K_VALID_US_ONLY,
			       k.op, 0, space, w0, w1, va, txt);
			return;
		}
		if (!ok)
			return;
	}
	s->both++;
	if (!in->detail) {
		st_add(s, K_FLAGS, k.op, in->id, 99, w0, w1, va, txt);
		return;
	}
	{
		const cs_arm *d = &in->detail->arm;
		const cs_arm_op *o = d->operands;
		unsigned nops = d->op_count;
		uint64_t acc = expect(in, 0, t->thumb);
		uint32_t cw = cs_wmask(t, in);
		uint32_t ow = (uint32_t)(k.wmask & 0xffffu);

		if (n != in->size) {
			st_add(s, K_LEN, k.op, in->id, (uint32_t)(n << 8 | in->size),
			       w0, w1, va, txt);
			return;
		}
		if (acc && !(acc & BIT(k.op)))
			st_add(s, K_CLASS, k.op, in->id, 0, w0, w1, va, txt);
		if (cw != ow && wgap(in, ow, cw))
			st_add(s, K_WGAP, k.op, in->id, 0, w0, w1, va, txt);
		else if (cw != ow)
			st_add(s, K_WMASK, k.op, in->id,
			       (ow & ~cw ? 1u : 0u) | (cw & ~ow ? 2u : 0u),
			       w0, w1, va, txt);

		/* ---- branch target ---- */
		if ((k.op == CELL_JMP || k.op == CELL_JCC || k.op == CELL_CALL) &&
		    nops && (in->id == ARM_INS_B || in->id == ARM_INS_BL ||
			     in->id == ARM_INS_BLX || in->id == ARM_INS_CBZ ||
			     in->id == ARM_INS_CBNZ)) {
			const cs_arm_op *io = &o[nops - 1];

			if (io->type == ARM_OP_IMM) {
				uint64_t want = (uint64_t)(uint32_t)io->imm & ~1ull;

				if (k.target_va != want || k.target != want ||
				    (k.flags & CELL_F_INDIRECT))
					st_add(s, K_TARGET, k.op, in->id, 0, w0, w1,
					       va, txt);
			} else if (!(k.flags & CELL_F_INDIRECT) ||
				   k.target_va != KOF_BROKEN) {
				st_add(s, K_TARGET, k.op, in->id, 1, w0, w1, va, txt);
			}
		}
		if (k.op == CELL_JCC && d->cc != ARM_CC_INVALID &&
		    in->id != ARM_INS_CBZ && in->id != ARM_INS_CBNZ &&
		    (int)k.cond != (int)d->cc - 1)
			st_add(s, K_COND, k.op, in->id, k.cond, w0, w1, va, txt);

		/* ---- immediates ---- */
		{
			unsigned q;
			int has_mem = 0;

			for (q = 0; q < nops; q++)
				has_mem |= o[q].type == ARM_OP_MEM;
			if (has_mem)
				goto no_imm;
		}
		if (k.n_op && k.o[k.n_op - 1].kind == CELL_O_IMM && nops &&
		    o[nops - 1].type == ARM_OP_IMM &&
		    (k.op == CELL_MOV || k.op == CELL_ADD || k.op == CELL_SUB ||
		     k.op == CELL_AND || k.op == CELL_OR || k.op == CELL_XOR ||
		     k.op == CELL_ADC || k.op == CELL_SBB || k.op == CELL_CMP ||
		     k.op == CELL_TEST || k.op == CELL_SHL || k.op == CELL_SHR ||
		     k.op == CELL_SAR || k.op == CELL_ROR)) {
			uint32_t want = (uint32_t)o[nops - 1].imm;

			/* a rotated immediate is spelt as value, rotation */
			if (nops >= 3 && o[nops - 2].type == ARM_OP_IMM)
				want = (uint32_t)(((uint32_t)o[nops - 2].imm >>
						   (want & 31u)) |
						  ((uint32_t)o[nops - 2].imm <<
						   ((32u - (want & 31u)) & 31u)));
			if (in->id == ARM_INS_MVN)
				want = ~want;
			if (in->id == ARM_INS_MOVT)
				want <<= 16;
			if ((uint32_t)k.o[k.n_op - 1].imm != want)
				st_add(s, K_IMM, k.op, in->id, 0, w0, w1, va, txt);
		}
no_imm:

		/* ---- memory operand ---- */
		{
			int mi = -1;
			unsigned i;

			for (i = 0; i < nops; i++)
				if (o[i].type == ARM_OP_MEM)
					mi = (int)i;
			if (mi >= 0 && (k.op == CELL_MOV || k.op == CELL_MOVZX ||
					k.op == CELL_MOVSX || k.op == CELL_JMP)) {
				const struct cell_operand *m = NULL;
				const arm_op_mem *cm = &o[mi].mem;
				unsigned q;

				for (q = 0; q < k.n_op; q++)
					if (k.o[q].kind == CELL_O_MEM)
						m = &k.o[q];
				if (!m) {
					st_add(s, K_MEM, k.op, in->id, 9, w0, w1, va, txt);
				} else {
					uint64_t litva = 0;
					int cs_lit = cm->base == ARM_REG_PC && !cm->index &&
						     in->id != ARM_INS_LDRT && in->id != ARM_INS_STRT &&
						     in->id != ARM_INS_LDRBT && in->id != ARM_INS_STRBT &&
						     in->id != ARM_INS_LDRHT && in->id != ARM_INS_STRHT &&
						     in->id != ARM_INS_LDRSBT && in->id != ARM_INS_LDRSHT;
					unsigned want = acc_size(in->id);
					int post = d->writeback && d->post_index;

					if (cs_lit && (post || d->writeback || k.n_op == 3)) {
						/* a pc base that is written back, or post-indexed,
						 * is UNPREDICTABLE: not a literal load */
					} else if (cs_lit) {
						litva = t->thumb
						    ? ((va + 4u) & ~3ull) + (uint64_t)(int64_t)cm->disp
						    : va + 8u + (uint64_t)(int64_t)cm->disp;
						if (!(m->flags & CELL_OF_RIPREL) ||
						    va + (uint64_t)m->disp != litva)
							st_add(s, K_LIT, k.op, in->id, 0, w0, w1, va, txt);
					} else {
						if (m->flags & CELL_OF_RIPREL)
							st_add(s, K_LIT, k.op, in->id, 1, w0, w1, va, txt);
						if (rnum(cm->base) != (int)m->reg)
							st_add(s, K_MEM, k.op, in->id, 1, w0, w1, va, txt);
						if (!post && !cm->index &&
						    (int64_t)cm->disp != m->disp)
							st_add(s, K_MEM, k.op, in->id, 2, w0, w1, va, txt);
						if (post && m->disp != 0)
							st_add(s, K_MEM, k.op, in->id, 6, w0, w1, va, txt);
					}
					if (cm->index ? rnum(cm->index) != (int)m->index
						      : m->index != CELL_REG_NONE)
						st_add(s, K_MEM, k.op, in->id, 3, w0, w1, va, txt);
					if (want && m->size != want)
						st_add(s, K_MEM, k.op, in->id, 4, w0, w1, va, txt);
					if (cm->index && !t->thumb && cm->lshift &&
					    m->scale != (1u << cm->lshift) &&
					    cm->lshift <= 7)
						st_add(s, K_MEM, k.op, in->id, 5, w0, w1, va, txt);
				}
			}
		}

		/* ---- destination and first source ---- */
		if (nops && o[0].type == ARM_OP_REG && k.n_op &&
		    k.o[0].kind == CELL_O_REG &&
		    k.op != CELL_PUSH && k.op != CELL_POP && k.op != CELL_RET &&
		    k.op != CELL_JMP && k.op != CELL_CALL && k.op != CELL_JCC &&
		    k.op != CELL_OTHER && k.op != CELL_PRIV && k.op != CELL_INT &&
		    k.op != CELL_SYSCALL &&
		    rnum(o[0].reg) != (int)k.o[0].reg &&
		    in->id != ARM_INS_STR && in->id != ARM_INS_STRB)
			st_add(s, K_REG, k.op, in->id, 0, w0, w1, va, txt);
		if (nops >= 3 && k.n_op == 3 && o[1].type == ARM_OP_REG &&
		    o[2].type == ARM_OP_REG && k.o[1].kind == CELL_O_REG &&
		    k.o[2].kind == CELL_O_REG && rnum(o[1].reg) == (int)k.o[2].reg &&
		    rnum(o[2].reg) == (int)k.o[1].reg && k.op == CELL_ADD) {
			/* add rd, sp, rd is add rd, rd, sp: the oracle commutes it */
		} else if (nops >= 3 && k.n_op == 3 && o[1].type == ARM_OP_REG &&
		    k.o[1].kind == CELL_O_REG && k.op != CELL_OTHER &&
		    k.op != CELL_MOV && k.op != CELL_MOVZX && k.op != CELL_MOVSX &&
		    rnum(o[1].reg) != (int)k.o[1].reg)
			st_add(s, K_REG, k.op, in->id, 1, w0, w1, va, txt);
		/* `add r0, r0, #4` is r0 += 4 here: the oracle's rn must be our rd */
		if (nops >= 3 && k.n_op == 2 && o[1].type == ARM_OP_REG &&
		    (k.op == CELL_ADD || k.op == CELL_SUB || k.op == CELL_AND ||
		     k.op == CELL_OR || k.op == CELL_XOR || k.op == CELL_ADC ||
		     k.op == CELL_SBB) &&
		    rnum(o[1].reg) != (int)k.o[0].reg &&
		    !(o[2].type == ARM_OP_REG && rnum(o[2].reg) == (int)k.o[0].reg))
			st_add(s, K_REG, k.op, in->id, 4, w0, w1, va, txt);
		if (nops == 2 && k.n_op == 2 && o[1].type == ARM_OP_REG &&
		    k.o[1].kind == CELL_O_REG &&
		    (k.op == CELL_MOV || k.op == CELL_NOT || k.op == CELL_NEG ||
		     k.op == CELL_MOVZX || k.op == CELL_MOVSX) &&
		    rnum(o[1].reg) != (int)k.o[1].reg)
			st_add(s, K_REG, k.op, in->id, 2, w0, w1, va, txt);
		if (nops == 2 && k.n_op == 1 && k.op == CELL_CALL &&
		    (k.flags & CELL_F_INDIRECT) && o[0].type == ARM_OP_REG &&
		    rnum(o[0].reg) != (int)k.o[0].reg)
			st_add(s, K_REG, k.op, in->id, 3, w0, w1, va, txt);
		/* indirect flag on register branches */
		if ((in->id == ARM_INS_BX || in->id == ARM_INS_BLX) && nops &&
		    o[0].type == ARM_OP_REG && !(k.flags & CELL_F_INDIRECT))
			st_add(s, K_FLAGS, k.op, in->id, 0, w0, w1, va, txt);
		if (k.op == CELL_SYSCALL && nops && o[0].type == ARM_OP_IMM &&
		    (uint32_t)o[0].imm != (uint32_t)k.o[0].imm)
			st_add(s, K_IMM, k.op, in->id, 1, w0, w1, va, txt);
	}
}

static void check(struct th *t, uint32_t w0, uint32_t w1, int nb, uint64_t va)
{
	check1(t, w0, w1, nb, va);
	if (t->reset) {
		cs_free(t->in, 1);
		cs_close(&t->h);
		cs_open(CS_ARCH_ARM, (t->thumb ? CS_MODE_THUMB : CS_MODE_ARM) | (g_v8 ? CS_MODE_V8 : 0), &t->h);
		cs_option(t->h, CS_OPT_DETAIL, CS_OPT_ON);
		t->in = cs_malloc(t->h);
		t->reset = 0;
	}
}

/* ---- drivers ------------------------------------------------------------- */

struct job {
	int thumb;
	int mode;               /* 0 rand 1 sys 2 elf */
	uint64_t n;             /* random: words per thread */
	unsigned fills;
	unsigned id, nth;
	uint64_t seed;
	const uint8_t *code;    /* elf */
	size_t code_n;
	uint64_t code_va;
	struct th t;
};

static void *work(void *arg)
{
	struct job *j = arg;
	struct th *t = &j->t;
	uint64_t i;
	unsigned a, b, c, f;

	th_open(t, j->thumb);
	t->rs = j->seed * 0x9e3779b97f4a7c15ull + j->id + 1u;
	for (i = 0; i < 8; i++)
		(void)rnd(t);
	if (j->mode == 0) {
		for (i = 0; i < j->n; i++) {
			uint32_t w = (rnd(t) << 11) ^ rnd(t) ^ (rnd(t) << 22);
			uint64_t va = 0x10000u + ((uint64_t)(rnd(t) & 0xffffu) << 2);

			if (j->thumb)
				check(t, w & 0xffffu, w >> 16, 4, va & ~1ull);
			else
				check(t, w, 0, 4, va);
		}
	} else if (j->mode == 1 && !j->thumb) {
		for (c = 0; c < 2; c++)
			for (a = j->id; a < 256; a += j->nth)
				for (b = 0; b < 16; b++)
					for (f = 0; f < j->fills; f++) {
						uint32_t w = (c ? 0xf0000000u : 0xe0000000u) |
							     a << 20 | b << 4 |
							     (rnd(t) & 0x000fff0fu);
						check(t, w, 0,
						      4, 0x10000u + ((uint64_t)(rnd(t) & 0xffffu) << 2));
					}
	} else if (j->mode == 1) {
		for (a = j->id; a < 65536; a += j->nth) {
			unsigned top = a >> 11;
			unsigned nf = (top >= 0x1du) ? j->fills : 1u;

			for (f = 0; f < nf; f++)
				check(t, a, rnd(t) & 0xffffu, 4,
				      0x10000u + ((uint64_t)(rnd(t) & 0xffffu) << 1));
		}
	} else {
		size_t step = j->thumb ? 2 : 4, off;

		for (off = j->id * step; off + 4 <= j->code_n; off += step * j->nth) {
			const uint8_t *p = j->code + off;
			uint32_t w0, w1 = 0;

			if (j->thumb) {
				w0 = (uint32_t)p[0] | (uint32_t)p[1] << 8;
				w1 = (uint32_t)p[2] | (uint32_t)p[3] << 8;
			} else {
				w0 = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
				     (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
			}
			check(t, w0, w1, 4, j->code_va + off);
		}
	}
	return NULL;
}

static void report(const struct stats *s, const char *title)
{
	unsigned k, i, shown;
	struct cat **v = malloc(TBL * sizeof *v);
	size_t nv = 0;

	printf("\n==== %s ====\n", title);
	printf("words %" PRIu64 "  oracle-valid %" PRIu64 "  ours-valid %" PRIu64
	       "  both %" PRIu64 "\n", s->total, s->cs_valid, s->us_valid, s->both);
	for (i = 0; i < TBL; i++)
		if (s->t[i].n)
			v[nv++] = &s->t[i];
	for (k = 0; k < K_COUNT; k++) {
		uint64_t tot = 0;
		size_t a, b;

		for (a = 0; a < nv; a++)
			if ((v[a]->key >> 56) == k)
				tot += v[a]->n;
		if (!tot)
			continue;
		printf("\n-- %s: %" PRIu64 " instances\n", KNAME[k], tot);
		/* simple selection by count */
		shown = 0;
		for (;;) {
			struct cat *best = NULL;

			for (a = 0; a < nv; a++)
				if ((v[a]->key >> 56) == k && v[a]->n &&
				    (!best || v[a]->n > best->n))
					best = v[a];
			if (!best || shown >= 400u)
				break;
			printf("  [%8" PRIu64 "] ours=%u id=%u aux=0x%x\n", best->n,
			       (unsigned)((best->key >> 48) & 0xff),
			       (unsigned)((best->key >> 32) & 0xffff),
			       (unsigned)(best->key & 0xffffffffu));
			for (b = 0; b < best->ne; b++)
				printf("      %08x %04x @%" PRIx64 "  %s\n", best->e[b].w0,
				       best->e[b].w1 & 0xffffu, best->e[b].va,
				       best->e[b].txt);
			best->n = 0;      /* consumed (the table is not used again) */
			shown++;
		}
	}
	free(v);
}

static int load_elf(const char *path, uint8_t **buf, size_t *n, uint64_t *va)
{
	FILE *f = fopen(path, "rb");
	uint8_t *img;
	long sz;
	const Elf32_Ehdr *eh;
	unsigned i;
	uint8_t *out;
	size_t on = 0;

	if (!f)
		return 0;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	img = malloc((size_t)sz);
	if (fread(img, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		free(img);
		return 0;
	}
	fclose(f);
	eh = (const Elf32_Ehdr *)img;
	if (sz < 52 || memcmp(img, ELFMAG, 4) || img[4] != 1 || img[5] != 1) {
		free(img);
		return 0;
	}
	out = malloc((size_t)sz);
	*va = 0;
	/* the largest executable section: .text, which is the code of the program */
	if (eh->e_shnum && eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf32_Shdr) <= (uint64_t)sz) {
		const Elf32_Shdr *sh = (const Elf32_Shdr *)(img + eh->e_shoff);
		int best = -1;

		for (i = 0; i < eh->e_shnum; i++) {
			if (sh[i].sh_type != SHT_PROGBITS ||
			    !(sh[i].sh_flags & SHF_EXECINSTR) ||
			    sh[i].sh_offset + (uint64_t)sh[i].sh_size > (uint64_t)sz)
				continue;
			if (best < 0 || sh[i].sh_size > sh[best].sh_size)
				best = (int)i;
		}
		if (best >= 0) {
			*va = sh[best].sh_addr;
			memcpy(out, img + sh[best].sh_offset, sh[best].sh_size);
			on = sh[best].sh_size;
		}
	}
	if (!on) {
		const Elf32_Phdr *ph = (const Elf32_Phdr *)(img + eh->e_phoff);

		for (i = 0; i < eh->e_phnum; i++) {
			if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X) ||
			    ph[i].p_offset + (uint64_t)ph[i].p_filesz > (uint64_t)sz)
				continue;
			*va = ph[i].p_vaddr;
			memcpy(out, img + ph[i].p_offset, ph[i].p_filesz);
			on = ph[i].p_filesz;
			break;
		}
	}
	free(img);
	*buf = out;
	*n = on;
	return on != 0;
}

int main(int argc, char **argv)
{
	int thumb;
	unsigned nth = 16, i;
	struct job *jobs;
	pthread_t *tid;
	struct stats tot;
	int mode;

	if (argc < 3) {
		fprintf(stderr, "usage: arm32_diff arm32|thumb rand <M> [seed] | sys [fills] | elf <file>...\n");
		return 2;
	}
	thumb = !strncmp(argv[1], "thumb", 5);
	/* "arm32v8" and "thumbv8" ask the oracle for ARMv8 */
	g_v8 = strstr(argv[1], "v8") != NULL;
	mode = !strcmp(argv[2], "rand") ? 0 : !strcmp(argv[2], "sys") ? 1 : 2;
	if (!strcmp(argv[2], "bench")) {
		int a;
		uint64_t insns = 0, sink = 0;
		double secs = 0;

		for (a = 3; a < argc; a++) {
			uint8_t *code;
			size_t cn, off;
			uint64_t va;
			unsigned rep;
			struct cell_insn k;
			struct timespec t0, t1;

			if (!load_elf(argv[a], &code, &cn, &va) || cn < 1024)
				continue;
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t0);
			for (rep = 0; rep < 200; rep++) {
				for (off = 0; off + 4 <= cn;) {
					uint32_t n = thumb
						? cell_decode_thumb(code + off, 4, va + off, 0, &k)
						: cell_decode_arm32(code + off, 4, va + off, 0, &k);

					sink += k.op + k.wmask + k.target_va;
					insns++;
					off += n;
				}
			}
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t1);
			secs += (double)(t1.tv_sec - t0.tv_sec) +
				(double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
			free(code);
		}
		printf("%s: %" PRIu64 " instructions, %.3f s, %.2f ns/instruction (checksum %" PRIx64 ")\n",
		       thumb ? "thumb" : "arm32", insns, secs, secs * 1e9 / (double)insns, sink);
		return 0;
	}
	reg_init();
	st_init(&tot);
	jobs = calloc(nth, sizeof *jobs);
	tid = calloc(nth, sizeof *tid);
	if (mode < 2) {
		uint64_t m = argc > 3 ? strtoull(argv[3], NULL, 10) : 1;
		uint64_t seed = (mode == 0 && argc > 4) ? strtoull(argv[4], NULL, 10) : 1;

		for (i = 0; i < nth; i++) {
			jobs[i].thumb = thumb;
			jobs[i].mode = mode;
			jobs[i].id = i;
			jobs[i].nth = nth;
			jobs[i].seed = seed;
			jobs[i].n = mode == 0 ? m * 1000000u / nth : 0;
			jobs[i].fills = mode == 1 ? (argc > 3 ? (unsigned)m : 256u) : 0;
			pthread_create(&tid[i], NULL, work, &jobs[i]);
		}
		for (i = 0; i < nth; i++) {
			pthread_join(tid[i], NULL);
			st_merge(&tot, &jobs[i].t.st);
		}
		report(&tot, mode == 0 ? "random" : "systematic");
		return 0;
	}
	{
		int a;

		for (a = 3; a < argc; a++) {
			uint8_t *code;
			size_t cn;
			uint64_t va;
			char title[300];

			if (!load_elf(argv[a], &code, &cn, &va)) {
				fprintf(stderr, "skip %s\n", argv[a]);
				continue;
			}
			for (i = 0; i < nth; i++) {
				memset(&jobs[i], 0, sizeof jobs[i]);
				jobs[i].thumb = thumb;
				jobs[i].mode = 2;
				jobs[i].id = i;
				jobs[i].nth = nth;
				jobs[i].code = code;
				jobs[i].code_n = cn;
				jobs[i].code_va = va;
				pthread_create(&tid[i], NULL, work, &jobs[i]);
			}
			for (i = 0; i < nth; i++) {
				pthread_join(tid[i], NULL);
				st_merge(&tot, &jobs[i].t.st);
			}
			snprintf(title, sizeof title, "%s: %zu code bytes", argv[a], cn);
			fprintf(stderr, "%s\n", title);
			free(code);
		}
		report(&tot, "elf corpus");
	}
	return 0;
}
