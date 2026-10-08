/*
 * genotype/arm64 - an AArch64 (A64 instruction set) instruction decoder.
 *
 * WHAT IT IS. AArch64 instructions are one little-endian 32-bit word, so there
 * is no length to find, no prefix and no operand-size state: the whole of
 * decoding is "which instruction is this word". That question is answered by
 * DATA - arm64_tab.c holds rows {mask, value, identity} arranged as a tree of
 * index nodes, and arm64.c does nothing but walk it: index, match, descend.
 * Nothing in the code knows an encoding.
 *
 * TWO STEPS, AS IN genotype/x86. gt_arm64_decode finds the identity
 * (GT_ARM64_I_*, arm64_ids.h) and keeps the word. Registers, immediates, the
 * addressing form and the branch offset are read out of the word by the
 * accessors below when somebody asks. Building operands is not part of decoding:
 * a sweep that wants the branches wants one offset and nothing else.
 *
 * WHAT IT KNOWS NOTHING OF. The engine's instruction classes, written-register
 * masks and operand forms. They are celllysis's (libgenome/celllysis/
 * decode_arm64.c), which turns an identity plus these accessors into them. This
 * layer includes nothing but <stdint.h> and genotype.h.
 *
 * WHAT IS DECIDED. Whether a word is allocated is decided completely for the
 * base integer instruction set, the branches and system instructions, and the
 * loads and stores (including the atomics, FEAT_LS64, FEAT_MOPS, memory tags and
 * pointer authentication). Rules a mask cannot say stay in the table's flags:
 * today only the logical-immediate bit-pattern (GT_ARM64_RF_BITMASK).
 *
 * THE VECTOR SPACES are deliberately not decoded to mnemonics. Scalar floating
 * point, Advanced SIMD, SVE and SME words are the identities FPSIMD, SVE and
 * SME - VALID, writing no general register - except the families that do write
 * one (floating point <-> integer conversions, fixed-point conversions, smov and
 * umov, and the SVE element-count, address and extract families), which have
 * rows of their own with the allocation checks that stop a word that merely
 * resembles them from claiming a register. Everywhere else a word in these
 * spaces is reported valid whether or not the architecture allocates it: a
 * vector space this size has thousands of reserved holes, and the only effect of
 * not listing them is that data in a hole reads as an instruction.
 *
 * A word that is not an instruction is the identity INVALID (status GT_INVALID);
 * udf #imm16, which is a defined instruction that always faults, is UDF (GT_OK).
 */
#ifndef KOF_GENOTYPE_ARM64_H
#define KOF_GENOTYPE_ARM64_H

#include <stdint.h>

#include "arm64_ids.h"
#include "../genotype.h"

/* A decoded instruction: its identity and the word it came from. */
struct gt_arm64_insn {
	uint32_t word;
	uint16_t id;                    /* enum gt_arm64_id */
};

/*
 * Decode one word. Always fills `out`; the status is GT_INVALID exactly when the
 * identity is GT_ARM64_I_INVALID. The word is the little-endian read of the four
 * instruction bytes.
 *
 * The first call (from any thread) builds a lookup on the top 11 bits of the
 * word from the tree in arm64_tab.c - see arm64.c - so that most words never
 * walk it. The tree stays the one source of what a word is; the lookup holds
 * nothing it does not.
 */
enum gt_status gt_arm64_decode(struct gt_arm64_insn *out, uint32_t word);

/* The tree alone, without the lookup: what gt_arm64_decode is checked against. */
enum gt_status gt_arm64_decode_tree(struct gt_arm64_insn *out, uint32_t word);
/* The tree's raw answer, before a row's check is applied: the identity and the row's flags (GT_ARM64_RF_*). */
unsigned gt_arm64_tree(uint32_t word, unsigned *flags);

/* The identity's name, for a tool or a test; "?" past the end. */
const char *gt_arm64_name(unsigned id);

/* What a load or store does with its register, and how it forms its address,
 * from the identity alone (enum gt_arm64_lskind, enum gt_arm64_amode). */
unsigned gt_arm64_lskind(const struct gt_arm64_insn *in);
unsigned gt_arm64_amode(const struct gt_arm64_insn *in);

/* ---- fields every format shares ------------------------------------------- */

static inline unsigned gt_arm64_bits(const struct gt_arm64_insn *in, unsigned lo,
				     unsigned n)
{
	return (in->word >> lo) & ((1u << n) - 1u);
}

static inline unsigned gt_arm64_sf(const struct gt_arm64_insn *in)
{
	return in->word >> 31;
}
static inline unsigned gt_arm64_rd(const struct gt_arm64_insn *in)
{
	return in->word & 31u;
}
static inline unsigned gt_arm64_rt(const struct gt_arm64_insn *in)
{
	return in->word & 31u;
}
static inline unsigned gt_arm64_rn(const struct gt_arm64_insn *in)
{
	return (in->word >> 5) & 31u;
}
static inline unsigned gt_arm64_rm(const struct gt_arm64_insn *in)
{
	return (in->word >> 16) & 31u;
}
/* Rs, the status or operand register of an exclusive, atomic or compare-and-swap */
static inline unsigned gt_arm64_rs(const struct gt_arm64_insn *in)
{
	return (in->word >> 16) & 31u;
}
/* Ra and Rt2 share bits 14:10 */
static inline unsigned gt_arm64_ra(const struct gt_arm64_insn *in)
{
	return (in->word >> 10) & 31u;
}
static inline unsigned gt_arm64_rt2(const struct gt_arm64_insn *in)
{
	return (in->word >> 10) & 31u;
}
/* size, bits 31:30, of the load/store and atomic formats */
static inline unsigned gt_arm64_size(const struct gt_arm64_insn *in)
{
	return in->word >> 30;
}
/* opc, bits 23:22, of the single-register load/store formats */
static inline unsigned gt_arm64_opc_ls(const struct gt_arm64_insn *in)
{
	return (in->word >> 22) & 3u;
}
/* the condition of a b.cond (bits 3:0) and of a conditional select/compare (15:12) */
static inline unsigned gt_arm64_cond_branch(const struct gt_arm64_insn *in)
{
	return in->word & 15u;
}
static inline unsigned gt_arm64_cond_select(const struct gt_arm64_insn *in)
{
	return (in->word >> 12) & 15u;
}

/* ---- immediates ----------------------------------------------------------- */

/* adr / adrp: the signed 21-bit immhi:immlo, in units (bytes for adr, 4096-byte pages for adrp) */
static inline int64_t gt_arm64_adr_imm(const struct gt_arm64_insn *in)
{
	uint32_t v = (((in->word >> 5) & 0x7ffffu) << 2) | ((in->word >> 29) & 3u);

	return (int64_t)(v ^ 0x100000u) - 0x100000;
}

/* add/subtract immediate: imm12, shifted left by 12 when sh (bit 22) is set */
static inline uint64_t gt_arm64_addsub_imm(const struct gt_arm64_insn *in)
{
	uint64_t imm = (in->word >> 10) & 0xfffu;

	return (in->word >> 22) & 1u ? imm << 12 : imm;
}

/* move wide: imm16 shifted into place by hw (bits 22:21) * 16 */
static inline unsigned gt_arm64_movw_shift(const struct gt_arm64_insn *in)
{
	return ((in->word >> 21) & 3u) * 16u;
}
static inline uint64_t gt_arm64_movw_imm(const struct gt_arm64_insn *in)
{
	return (uint64_t)((in->word >> 5) & 0xffffu) << gt_arm64_movw_shift(in);
}

/* bitfield and extract: immr (bits 21:16) and imms (bits 15:10) */
static inline unsigned gt_arm64_immr(const struct gt_arm64_insn *in)
{
	return (in->word >> 16) & 63u;
}
static inline unsigned gt_arm64_imms(const struct gt_arm64_insn *in)
{
	return (in->word >> 10) & 63u;
}

/*
 * The bitmask a logical-immediate instruction names (N:immr:imms, the width from
 * sf): a run of imms+1 ones rotated right by immr inside an element and
 * replicated to the register width. Defined only for an identity the decoder
 * accepted (AND_IMM, ORR_IMM, EOR_IMM, ANDS_IMM).
 */
uint64_t gt_arm64_logical_imm(const struct gt_arm64_insn *in);

/* hint number #crm:op2 of the HINT family */
static inline unsigned gt_arm64_hint(const struct gt_arm64_insn *in)
{
	return (in->word >> 5) & 0x7fu;
}

/* the 15-bit system register (op0:op1:CRn:CRm:op2 with op0 bit 0 .. ) of mrs/msr: bits 19:5 */
static inline unsigned gt_arm64_sysreg(const struct gt_arm64_insn *in)
{
	return (in->word >> 5) & 0x7fffu;
}

/* the 16-bit immediate of svc, hvc, smc, brk, hlt, dcps and udf */
static inline unsigned gt_arm64_imm16(const struct gt_arm64_insn *in)
{
	return (in->word >> 5) & 0xffffu;
}

/* ---- branches -------------------------------------------------------------- */

/*
 * The signed byte displacement of B, BL, CBZ, CBNZ, BCOND, TBZ, TBNZ and of the
 * literal loads, relative to the address of the instruction ITSELF (A64 PC-relative
 * addressing has no "+ length"). The width - 26, 19 or 14 bits, times four - is
 * the identity's.
 */
int64_t gt_arm64_branch_off(const struct gt_arm64_insn *in);

/* the bit number tbz / tbnz test: b5:b40 */
static inline unsigned gt_arm64_tbz_bit(const struct gt_arm64_insn *in)
{
	return ((in->word >> 26) & 32u) | ((in->word >> 19) & 31u);
}

/* ---- loads and stores ----------------------------------------------------- */

/*
 * Bytes one data register of a load or store moves (a pair moves two of them):
 * the access size, 16 for the Q form of a floating point register. For a literal
 * load, the size of the loaded value.
 */
unsigned gt_arm64_ldst_bytes(const struct gt_arm64_insn *in);

/*
 * The signed byte offset the instruction's address form carries, as encoded and
 * already scaled: imm12 times the size, simm9, imm7 times the register size of a
 * pair, simm9 times 16 of a tag, simm10 times 8 of ldraa/ldrab, imm19 times 4 of
 * a literal. For a post-index form it is the amount added to the base AFTER the
 * access. 0 for a form with no offset.
 */
int64_t gt_arm64_ldst_off(const struct gt_arm64_insn *in);

#endif /* KOF_GENOTYPE_ARM64_H */
