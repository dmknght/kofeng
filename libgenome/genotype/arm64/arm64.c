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
#include <stdatomic.h>

#include "arm64.h"
#include "arm64_int.h"

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
 * authority; the lookup below is derived from it at first use.
 */
unsigned gt_arm64_tree(uint32_t x, unsigned *flags)
{
	const struct gt_arm64_node *n = &gt_arm64_top;
	const struct gt_arm64_row *r;
	unsigned id;

	for (;;) {
		unsigned k = ((x >> n->sh0) & n->m0) | (((x >> n->sh1) & n->m1) << n->n0);

		r = n->b[k];
		while ((x & r->mask) != r->val)
			r++;
		id = r->id;
		if (id < GT_ARM64_NODE0)
			break;
		n = gt_arm64_nodes[id - GT_ARM64_NODE0];
	}
	*flags = r->fl;
	return id;
}

enum gt_status gt_arm64_decode_tree(struct gt_arm64_insn *out, uint32_t x)
{
	unsigned fl, id = gt_arm64_tree(x, &fl);

	if ((fl & GT_ARM64_RF_BITMASK) && !bitmask_ok(x))
		id = GT_ARM64_I_INVALID;
	out->word = x;
	out->id = (uint16_t)id;
	return id == GT_ARM64_I_INVALID ? GT_INVALID : GT_OK;
}

/*
 * THE LOOKUP ON THE TOP 11 BITS, built from the tree by code, on first use.
 *
 * An entry is an identity when the tree would give that identity for EVERY word
 * with those top bits, and L1_MORE (send the word down the tree) otherwise. It is
 * found without running words through the tree: the top bits are the bits known,
 * a row is skipped if they contradict it, taken if they fix everything it tests,
 * and if some row ahead of the answer tests a bit that is not known, or a row
 * carries a check, the entry is MORE. A node whose key is partly unknown is
 * answered only if every bucket its key can still select agrees. That is
 * conservative - it never claims an identity the tree would not give - and
 * arm64.c's unit test compares it with the tree.
 *
 * MEASURED over 8.3 M words of real AArch64 code (118 Mirai-family ELF files),
 * one thread: the tree alone costs 12.6 ns a word; with this lookup 5.5 ns, and
 * the whole adapter path 18.3 ns against 20.0 for the decoder it replaced. The
 * lookup answers 83.3% of those words (the 17% that walk the tree are ret,
 * orr, hint, logical immediates, ldur and register-offset loads). A key of 10,
 * 9 or 8 bits more changed nothing, and an inline copy of this function in the
 * header was 0.2 ns faster, which is not worth publishing the table and the
 * flag. Cost per decode when built: one acquire load, a branch and the call.
 */
#define L1_SHIFT 21
#define L1_N (1u << (32 - L1_SHIFT))
#define L1_MORE 0xffffu

static uint16_t g_l1[L1_N];
static atomic_int g_l1_state;           /* 0 not built, 1 being built, 2 ready */

static unsigned resolve_node(const struct gt_arm64_node *n, uint32_t km, uint32_t kv);

static unsigned resolve_rows(const struct gt_arm64_row *r, uint32_t km, uint32_t kv)
{
	for (;; r++) {
		if ((kv ^ r->val) & km & r->mask)
			continue;               /* a known bit contradicts the row */
		if (r->mask & ~km)
			return L1_MORE;         /* the row tests a bit that is not known */
		if (r->fl)
			return L1_MORE;
		if (r->id >= GT_ARM64_NODE0)
			return resolve_node(gt_arm64_nodes[r->id - GT_ARM64_NODE0], km, kv);
		return r->id;
	}
}

static unsigned resolve_node(const struct gt_arm64_node *n, uint32_t km, uint32_t kv)
{
	unsigned w0 = (unsigned)__builtin_popcount(n->m0);
	unsigned nb = w0 + (unsigned)__builtin_popcount(n->m1), i;
	unsigned res = L1_MORE, kk = 0, kval = 0, fr, sub;
	int first = 1;

	/*
	 * ONLY THE KEYS THE KNOWN BITS ALLOW ARE VISITED. This tried all 2^nb keys,
	 * rebuilt each one bit by bit and then threw away the ones that contradict
	 * a known bit: MEASURED on a 95 KB A64 ELF (callgrind, whole scan 57.2 M Ir)
	 * the table build was 8.3 M Ir, 14.5% of the scan. A key bit whose position
	 * is known is fixed by it, and the free ones are enumerated as the subsets
	 * of their mask - the same keys, in the same increasing order, so the answer
	 * is the one it was.
	 */
	for (i = 0; i < nb; i++) {
		unsigned pos = i < w0 ? n->sh0 + i : n->sh1 + (i - w0);

		if ((km >> pos) & 1u) {
			kk |= 1u << i;
			kval |= ((kv >> pos) & 1u) << i;
		}
	}
	fr = (unsigned)((1ull << nb) - 1u) & ~kk;
	sub = 0;
	do {
		unsigned id = resolve_rows(n->b[kval | sub], km, kv);

		if (id == L1_MORE || (!first && id != res))
			return L1_MORE;
		res = id;
		first = 0;
		sub = (sub - fr) & fr;
	} while (sub);
	return res;
}

static void l1_build(void)
{
	unsigned k;

	for (k = 0; k < L1_N; k++)
		g_l1[k] = (uint16_t)resolve_node(&gt_arm64_top,
						 ~0u << L1_SHIFT, k << L1_SHIFT);
}

/*
 * Thread-safe and idempotent with no allocation: the thread that moves the state
 * from 0 to 1 builds into static storage and publishes with a release store;
 * the others wait for 2. The table is read-only afterwards.
 */
static void l1_init(void)
{
	int expect = 0;

	if (atomic_compare_exchange_strong_explicit(&g_l1_state, &expect, 1,
						    memory_order_acq_rel,
						    memory_order_acquire)) {
		l1_build();
		atomic_store_explicit(&g_l1_state, 2, memory_order_release);
		return;
	}
	while (atomic_load_explicit(&g_l1_state, memory_order_acquire) != 2)
		;
}

enum gt_status gt_arm64_decode(struct gt_arm64_insn *out, uint32_t x)
{
	unsigned e;

	if (__builtin_expect(atomic_load_explicit(&g_l1_state, memory_order_acquire) != 2, 0))
		l1_init();
	e = g_l1[x >> L1_SHIFT];
	if (e == L1_MORE)
		return gt_arm64_decode_tree(out, x);
	out->word = x;
	out->id = (uint16_t)e;
	return e == GT_ARM64_I_INVALID ? GT_INVALID : GT_OK;
}

const char *gt_arm64_name(unsigned id)
{
	return id < GT_ARM64_I_COUNT ? gt_arm64_names[id] : "?";
}

unsigned gt_arm64_lskind(const struct gt_arm64_insn *in)
{
	return gt_arm64_lsk[in->id];
}

unsigned gt_arm64_amode(const struct gt_arm64_insn *in)
{
	return gt_arm64_am[in->id];
}

uint64_t gt_arm64_logical_imm(const struct gt_arm64_insn *in)
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
	w = (1ull << (s + 1u)) - 1u;
	if (r)
		w = ((w >> r) | (w << (esize - r))) & emask;
	for (e = esize; e < dsz; e <<= 1)
		w |= w << e;
	return w;
}

int64_t gt_arm64_branch_off(const struct gt_arm64_insn *in)
{
	uint32_t x = in->word;

	if (in->id <= GT_ARM64_I_BL)
		return sx(x & 0x3ffffffu, 26) * 4;
	if (in->id <= GT_ARM64_I_BCOND)
		return sx((x >> 5) & 0x7ffffu, 19) * 4;
	if (in->id <= GT_ARM64_I_TBNZ)
		return sx((x >> 5) & 0x3fffu, 14) * 4;
	return 0;
}

static int is_pair(unsigned id)
{
	return id >= GT_ARM64_I_STNP && id <= GT_ARM64_I_LDP_FP_PRE;
}

static int is_literal(unsigned id)
{
	return id >= GT_ARM64_I_LDR_LIT_W && id <= GT_ARM64_I_LDR_LIT_FP;
}

static int is_single(unsigned id)
{
	return id >= GT_ARM64_I_STR_UOFF && id <= GT_ARM64_I_LDAPURS32;
}

unsigned gt_arm64_ldst_bytes(const struct gt_arm64_insn *in)
{
	uint32_t x = in->word;
	unsigned opc = x >> 30, k = gt_arm64_lsk[in->id];
	int fp = k == GT_ARM64_K_STORE_FP || k == GT_ARM64_K_LOAD_FP;

	switch (in->id) {
	case GT_ARM64_I_LDR_LIT_W:
	case GT_ARM64_I_LDRSW_LIT:
		return 4;
	case GT_ARM64_I_LDR_LIT_X:
		return 8;
	case GT_ARM64_I_LDR_LIT_FP:
		return 4u << opc;
	case GT_ARM64_I_PRFM_LIT:
		return 0;
	default:
		break;
	}
	if (is_pair(in->id)) {
		if (fp)
			return 4u << opc;
		if (opc == 1u)
			return k == GT_ARM64_K_LOAD_S64 ? 4u : 16u;     /* ldpsw, stgp */
		return opc ? 8u : 4u;
	}
	if (is_single(in->id)) {
		unsigned size = x >> 30, o = (x >> 22) & 3u;

		/* the Q register is size 0 with opc 2 or 3 */
		return fp && size == 0 && o >= 2u ? 16u : 1u << size;
	}
	return 0;
}

int64_t gt_arm64_ldst_off(const struct gt_arm64_insn *in)
{
	uint32_t x = in->word;
	unsigned id = in->id;

	if (is_literal(id))
		return sx((x >> 5) & 0x7ffffu, 19) * 4;
	if (is_pair(id))
		return sx((x >> 15) & 0x7fu, 7) * (int64_t)gt_arm64_ldst_bytes(in);
	if (is_single(id)) {
		switch (gt_arm64_am[id]) {
		case GT_ARM64_AM_OFFSET: {
			unsigned size = x >> 30, sh = gt_arm64_ldst_bytes(in) == 16u ? 4u : size;

			return (int64_t)((x >> 10) & 0xfffu) << sh;
		}
		case GT_ARM64_AM_REG:
			return 0;
		default:
			return sx((x >> 12) & 0x1ffu, 9);
		}
	}
	switch (id) {
	case GT_ARM64_I_LDRAA:
	case GT_ARM64_I_LDRAB:
	case GT_ARM64_I_LDRAA_PRE:
	case GT_ARM64_I_LDRAB_PRE:
		return sx((((x >> 22) & 1u) << 9) | ((x >> 12) & 0x1ffu), 10) * 8;
	case GT_ARM64_I_STG_POST: case GT_ARM64_I_STG_OFF: case GT_ARM64_I_STG_PRE:
	case GT_ARM64_I_STZG_POST: case GT_ARM64_I_STZG_OFF: case GT_ARM64_I_STZG_PRE:
	case GT_ARM64_I_ST2G_POST: case GT_ARM64_I_ST2G_OFF: case GT_ARM64_I_ST2G_PRE:
	case GT_ARM64_I_STZ2G_POST: case GT_ARM64_I_STZ2G_OFF: case GT_ARM64_I_STZ2G_PRE:
		return sx((x >> 12) & 0x1ffu, 9) * 16;
	default:
		return 0;
	}
}
