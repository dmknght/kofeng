/*
 * arm64.c - the AArch64 decoder proper: walk arm64_tab.c's tree to an identity,
 * and read fields out of the word when asked.
 *
 * NOTHING HERE KNOWS AN ENCODING. The walk is "index, match, descend"; every
 * fact about which word is which instruction is a row in the table. The one rule
 * the table cannot hold is the logical-immediate bitmask (a function of N and
 * imms that is not a mask pattern), and it is asked for by a row flag.
 *
 * The accessors that need the identity (the branch offset's width, the access
 * size of a load) are here and not in the header because they read it through a
 * range test or a table, which is not worth inlining into every caller.
 */
#include "arm64.h"
#include "arm64_private.h"

static int64_t sx(uint32_t v, unsigned bits)
{
	uint32_t m = 1u << (bits - 1u);

	return (int64_t)(v ^ m) - (int64_t)m;
}

/*
 * The N:imms pair of a logical immediate names a bitmask unless it is the
 * all-ones run or the element is wider than the register. Depends on nothing but
 * N, imms and sf, which is why it is a check and not a row per combination.
 */
static int bitmask_ok(uint32_t x)
{
	unsigned n = (x >> 22) & 1u, imms = (x >> 10) & 63u;
	unsigned v = (n << 6) | (~imms & 63u);
	unsigned len = 0, esize, levels;

	if (v < 2u)
		return 0;
	while (v >> (len + 1u))
		len++;
	esize = 1u << len;
	if (esize > ((x >> 31) ? 64u : 32u))
		return 0;
	levels = esize - 1u;
	return (imms & levels) != levels;
}

/*
 * THE TREE: index, match, descend, and the row's flags. This is the table's
 * authority; the lookup below is derived from it by the generator.
 */
static unsigned kgenome_arm64_tree(uint32_t x, unsigned *flags)
{
	const struct kgenome_arm64_node *n = &kgenome_arm64_top;
	const struct kgenome_arm64_row *r;
	unsigned id;

	for (;;) {
		unsigned k = ((x >> n->sh0) & n->m0) | (((x >> n->sh1) & n->m1) << n->n0);

		r = n->b[k];
		while ((x & r->mask) != r->val)
			r++;
		id = r->id;
		if (id < KGENOME_ARM64_NODE0)
			break;
		n = kgenome_arm64_nodes[id - KGENOME_ARM64_NODE0];
	}
	*flags = r->fl;
	return id;
}

/* KNOWN DEFECT DA-A64NEW (2026-10-28, M) [sev L]: kgenome_arm64_decode_tree answers INVALID for encodings of extensions newer than the table: CB<cc> compare-and-branch (FEAT_CMPBR), LDTP/STTP/LDTNP/STTNP (FEAT_LSUI), STLUR/LDAPUR on vector registers (FEAT_LRCPC3), MADDPT and friends (FEAT_CPA), the PRFM slc targets.
 * Trigger: words 75e6a94d (CBNE), e8878d77 (STTP), ecd74900 (LDTP), 1d88cac5 (STLUR q5), 9b7e3c45 (MADDPT). Effect: the oracle (binutils 2.47) spells each as an instruction; here they are data (a branch among them is not followed). 1966 words in 9.1M instructions of 40 corpus files, nearly all in data inside .text.
 * [widened 2026-10-29: 4,000,000 random words, 1,895,978 INVALID here, of which 102,087 the oracle spells: the five families and also ~170 more mnemonics (the LDF and STF and LDBF families, LDT, SWPT, CAST, RCW, LDCLRP, LDSETP, SWPP, MRRS, MSRR, SYSP, LDIAPP, STILP, SMAX, SMIN, UMAX, UMIN, ABS, CNT, CTZ, ST64BV, GCSSTR)]. Reproducer: Bazaar.2026.08 HEUR-Backdoor.Linux.Mirai.le-928102caaa088c6d57f9 .text 0x4aaee0, 0x4a84c0.
 * Fix: OWNER DECISION on the table's scope (which extensions, to which mnemonic), then rows and identities, each with an adapter handler in celllysis/decode_arm64.c (the formatter, arm64_fmt.c, already answers UNSUPPORTED for a word it does not spell). */
enum kgenome_status kgenome_arm64_decode_tree(struct kgenome_arm64_insn *out, uint32_t x)
{
	unsigned fl, id = kgenome_arm64_tree(x, &fl);

	if ((fl & KGENOME_ARM64_RF_BITMASK) && !bitmask_ok(x))
		id = KGENOME_ARM64_I_INVALID;
	out->word = x;
	out->id = (uint16_t)id;
	return id == KGENOME_ARM64_I_INVALID ? KGENOME_INVALID : KGENOME_OK;
}

/*
 * THE LOOKUP ON THE TOP 11 BITS: kgenome_arm64_l1, const data written from the tree by
 * tools/genotype/arm_index_gen.c (arm64_l1_tab.c; the derivation and its measurements
 * are in that file). An entry is an identity when the tree gives that identity for EVERY
 * word with those top bits, and KGENOME_ARM64_L1_MORE (send the word down the tree)
 * otherwise. tests/lib/genome/genotype_arm64.c compares it with the tree.
 * Cost per decode: one table read, a branch and the call.
 */

enum kgenome_status kgenome_arm64_decode(struct kgenome_arm64_insn *out, uint32_t x)
{
	unsigned e;

	e = kgenome_arm64_l1[x >> KGENOME_ARM64_L1_SHIFT];
	if (e == KGENOME_ARM64_L1_MORE)
		return kgenome_arm64_decode_tree(out, x);
	out->word = x;
	out->id = (uint16_t)e;
	return e == KGENOME_ARM64_I_INVALID ? KGENOME_INVALID : KGENOME_OK;
}

const char *kgenome_arm64_name(unsigned id)
{
	return id < KGENOME_ARM64_I_COUNT ? kgenome_arm64_names[id] : "?";
}

unsigned kgenome_arm64_lskind(const struct kgenome_arm64_insn *in)
{
	return kgenome_arm64_lsk[in->id];
}

unsigned kgenome_arm64_amode(const struct kgenome_arm64_insn *in)
{
	return kgenome_arm64_am[in->id];
}

uint64_t kgenome_arm64_logical_imm(const struct kgenome_arm64_insn *in)
{
	uint32_t x = in->word;
	unsigned n = (x >> 22) & 1u, imms = (x >> 10) & 63u, immr = (x >> 16) & 63u;
	unsigned dsz = (x >> 31) ? 64u : 32u;
	unsigned v = (n << 6) | (~imms & 63u);
	unsigned len = 0, esize, levels, s, r, e;
	uint64_t w, emask;

	while (v >> (len + 1u))
		len++;
	esize = 1u << len;
	levels = esize - 1u;
	s = imms & levels;
	r = immr & levels;
	emask = esize == 64u ? ~0ull : (1ull << esize) - 1u;
	w = s + 1u >= 64u ? ~0ull : (1ull << (s + 1u)) - 1u;      /* a shift by 64 is undefined */
	if (r)
		w = ((w >> r) | (w << (esize - r))) & emask;
	for (e = esize; e < dsz; e <<= 1)
		w |= w << e;
	return w;
}

int64_t kgenome_arm64_branch_off(const struct kgenome_arm64_insn *in)
{
	uint32_t x = in->word;

	if (in->id <= KGENOME_ARM64_I_BL)
		return sx(x & 0x3ffffffu, 26) * 4;
	if (in->id <= KGENOME_ARM64_I_BCOND)
		return sx((x >> 5) & 0x7ffffu, 19) * 4;
	if (in->id <= KGENOME_ARM64_I_TBNZ)
		return sx((x >> 5) & 0x3fffu, 14) * 4;
	return 0;
}

static int is_pair(unsigned id)
{
	return id >= KGENOME_ARM64_I_STNP && id <= KGENOME_ARM64_I_LDP_FP_PRE;
}

static int is_literal(unsigned id)
{
	return id >= KGENOME_ARM64_I_LDR_LIT_W && id <= KGENOME_ARM64_I_LDR_LIT_FP;
}

static int is_single(unsigned id)
{
	return id >= KGENOME_ARM64_I_STR_UOFF && id <= KGENOME_ARM64_I_LDAPURS32;
}

unsigned kgenome_arm64_ldst_bytes(const struct kgenome_arm64_insn *in)
{
	uint32_t x = in->word;
	unsigned opc = x >> 30, k = kgenome_arm64_lsk[in->id];
	int fp = k == KGENOME_ARM64_K_STORE_FP || k == KGENOME_ARM64_K_LOAD_FP;

	switch (in->id) {
	case KGENOME_ARM64_I_LDR_LIT_W:
	case KGENOME_ARM64_I_LDRSW_LIT:
		return 4;
	case KGENOME_ARM64_I_LDR_LIT_X:
		return 8;
	case KGENOME_ARM64_I_LDR_LIT_FP:
		return 4u << opc;
	case KGENOME_ARM64_I_PRFM_LIT:
		return 0;
	default:
		break;
	}
	if (is_pair(in->id)) {
		if (fp)
			return 4u << opc;
		if (opc == 1u)
			return k == KGENOME_ARM64_K_LOAD_S64 ? 4u : 16u;     /* ldpsw, stgp */
		return opc ? 8u : 4u;
	}
	if (is_single(in->id)) {
		unsigned size = x >> 30, o = (x >> 22) & 3u;

		/* the Q register is size 0 with opc 2 or 3 */
		return fp && size == 0 && o >= 2u ? 16u : 1u << size;
	}
	return 0;
}

int64_t kgenome_arm64_ldst_off(const struct kgenome_arm64_insn *in)
{
	uint32_t x = in->word;
	unsigned id = in->id;

	if (is_literal(id))
		return sx((x >> 5) & 0x7ffffu, 19) * 4;
	if (is_pair(id))
		return sx((x >> 15) & 0x7fu, 7) * (int64_t)kgenome_arm64_ldst_bytes(in);
	if (is_single(id)) {
		switch (kgenome_arm64_am[id]) {
		case KGENOME_ARM64_AM_OFFSET: {
			unsigned size = x >> 30, sh = kgenome_arm64_ldst_bytes(in) == 16u ? 4u : size;

			return (int64_t)((x >> 10) & 0xfffu) << sh;
		}
		case KGENOME_ARM64_AM_REG:
			return 0;
		default:
			return sx((x >> 12) & 0x1ffu, 9);
		}
	}
	switch (id) {
	case KGENOME_ARM64_I_LDRAA:
	case KGENOME_ARM64_I_LDRAB:
	case KGENOME_ARM64_I_LDRAA_PRE:
	case KGENOME_ARM64_I_LDRAB_PRE:
		return sx((((x >> 22) & 1u) << 9) | ((x >> 12) & 0x1ffu), 10) * 8;
	case KGENOME_ARM64_I_STG_POST: case KGENOME_ARM64_I_STG_OFF: case KGENOME_ARM64_I_STG_PRE:
	case KGENOME_ARM64_I_STZG_POST: case KGENOME_ARM64_I_STZG_OFF: case KGENOME_ARM64_I_STZG_PRE:
	case KGENOME_ARM64_I_ST2G_POST: case KGENOME_ARM64_I_ST2G_OFF: case KGENOME_ARM64_I_ST2G_PRE:
	case KGENOME_ARM64_I_STZ2G_POST: case KGENOME_ARM64_I_STZ2G_OFF: case KGENOME_ARM64_I_STZ2G_PRE:
		return sx((x >> 12) & 0x1ffu, 9) * 16;
	default:
		return 0;
	}
}
