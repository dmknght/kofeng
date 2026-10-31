/*
 * disasm_oracle - kgenome_disasm (the one entry: bytes and an architecture in, text, length and branch target out)
 * against an independent oracle, and against hostile input.
 *
 * THE ORACLE is the GNU disassembler (libopcodes, read through gdb's `x/i` on real ELF files of the architecture, in
 * ARM-state and AArch64 code taken from the Bazaar.2026.08 corpus). It is not installed everywhere, so the oracle's
 * answers for a set of instructions are COMMITTED: tests/lib/genome/disasm_oracle_a64.inc and _a32.inc, one row per
 * (mnemonic, operand shape) the real code held - the word, the address it sat at, the oracle's text after the
 * normalisation below, and its branch target. The same differential was run over whole .text sections (40 files per
 * architecture, 9 to 11 million instructions each) when the formatters were written; the numbers are in the report
 * that came with them, not here, because a test cannot read a corpus that is not in the tree.
 *
 * NORMALISATION, the only one: both sides are folded to one case and runs of white space to one space. What the
 * oracle prints after the operands (a symbol in <>, an "@" or "//" comment) is not in the committed text.
 *
 * WHAT IS CHECKED, per committed row: the status is KGENOME_OK, the length is 4, the text equals the oracle's, a
 * direct branch carries the oracle's target and nothing else carries one; the text is the same when the word is
 * handed big-endian with `be` set (ARM); a buffer of exactly the text's size and one byte less (TRUNCATED, no write
 * past it). Then hostile input: random bytes of every length from 0 to 20 at the end of a guard page, for every
 * architecture the entry knows and one it does not (MIPS), with a text buffer that is itself against a guard page:
 * the length is within 1..max and within what was handed, the status is one of the four, the text is terminated, the
 * answer is the same twice.
 */
#include <kgenome.h>

#include <ctype.h>

#include "hk.h"

struct row {
	uint64_t va;
	uint32_t w;
	const char *text;
	uint64_t target;
	int has_target;
};

static const struct row g_a64[] = {
#include "disasm_oracle_a64.inc"
};
static const struct row g_a32[] = {
#include "disasm_oracle_a32.inc"
};

static void fold(const char *in, char *out, size_t cap)
{
	size_t n = 0;
	int sp = 1;

	for (; *in && n + 2 < cap; in++) {
		if (isspace((unsigned char)*in)) {
			sp = 1;
			continue;
		}
		if (sp && n)
			out[n++] = ' ';
		sp = 0;
		out[n++] = (char)tolower((unsigned char)*in);
	}
	out[n] = 0;
}

static void word_bytes(uint32_t w, int be, uint8_t b[4])
{
	if (be) {
		b[0] = (uint8_t)(w >> 24); b[1] = (uint8_t)(w >> 16); b[2] = (uint8_t)(w >> 8); b[3] = (uint8_t)w;
	} else {
		b[0] = (uint8_t)w; b[1] = (uint8_t)(w >> 8); b[2] = (uint8_t)(w >> 16); b[3] = (uint8_t)(w >> 24);
	}
}

static void rows(unsigned arch, const struct row *t, size_t n, int both_orders)
{
	size_t i;
	struct hk_gb g, tg;

	gb_init(&g, 16);
	gb_init(&tg, KGENOME_DISASM_TEXT_MAX);
	for (i = 0; i < n; i++) {
		int be;

		for (be = 0; be <= (both_orders ? 1 : 0); be++) {
			uint8_t b[4], *p;
			char text[KGENOME_DISASM_TEXT_MAX], want[KGENOME_DISASM_TEXT_MAX], got[KGENOME_DISASM_TEXT_MAX];
			struct kgenome_disasm_req rq;
			struct kgenome_disasm_res rs;
			size_t tl;

			word_bytes(t[i].w, be, b);
			p = gb_put(&g, b, 4);
			memset(&rq, 0, sizeof rq);
			rq.arch = arch;
			rq.be = be;
			rq.p = p;
			rq.n = 4;
			rq.va = t[i].va;
			rq.text = text;
			rq.cap = sizeof text;
			kgenome_disasm(&rq, &rs);
			fold(text, got, sizeof got);
			fold(t[i].text, want, sizeof want);
			if (rs.status != KGENOME_OK || rs.len != 4 || strcmp(got, want) != 0) {
				printf("  FAIL arch %u row %zu word %08x be %d: ours '%s' (status %d len %u) oracle '%s'\n",
				       arch, i, t[i].w, be, got, (int)rs.status, rs.len, want);
				hk_fails++;
			}
			if (rs.has_target != (uint8_t)(t[i].has_target != 0) || (rs.has_target && rs.target != t[i].target)) {
				printf("  FAIL arch %u row %zu word %08x: target %d %llx, oracle %d %llx\n", arch, i, t[i].w,
				       rs.has_target, (unsigned long long)rs.target, t[i].has_target, (unsigned long long)t[i].target);
				hk_fails++;
			}
			if (be)
				continue;
			/* the buffer of exactly the text, and one byte less: the exact fit is the same text, one short is TRUNCATED and the byte past is not written */
			tl = strlen(text);
			{
				uint8_t *tp = gb_put(&tg, text, tl + 1u);
				struct kgenome_disasm_res r2;

				rq.text = (char *)tp;
				rq.cap = tl + 1u;
				kgenome_disasm(&rq, &r2);
				CK(r2.status == KGENOME_OK && strcmp((char *)tp, text) == 0);
				tp = gb_put(&tg, text, tl);
				rq.text = (char *)tp;
				rq.cap = tl;
				kgenome_disasm(&rq, &r2);
				CK(r2.status == KGENOME_TRUNCATED);
				CK(tl == 0 || memchr(tp, 0, tl) != NULL);       /* terminated inside what it was given */
			}
		}
	}
	gb_free(&g);
	gb_free(&tg);
}

/* the answers a hostile buffer may get */
static void hostile(unsigned arch, unsigned long iters)
{
	struct hk_rng r;
	struct hk_gb g, tg;
	unsigned long it;
	unsigned max = kgenome_disasm_max_len(arch), align = kgenome_disasm_align(arch);
	static const size_t caps[] = { 0, 1, 2, 5, 12, 40, KGENOME_DISASM_TEXT_MAX };

	fz_rng_seed(&r, 0xd15a5eed00ull + arch);
	gb_init(&g, 32);
	gb_init(&tg, KGENOME_DISASM_TEXT_MAX);
	for (it = 0; it < iters; it++) {
		uint8_t src[32], *p;
		size_t n = hk_below(&r, 21u), cap = caps[hk_below(&r, sizeof caps / sizeof caps[0])], k;
		struct kgenome_disasm_req rq;
		struct kgenome_disasm_res a, b;
		char *tp;

		for (k = 0; k < sizeof src; k++)
			src[k] = (uint8_t)hk_next(&r);
		p = gb_put(&g, src, n);
		tp = (char *)gb_put(&tg, src, cap);
		memset(&rq, 0, sizeof rq);
		rq.arch = arch;
		rq.be = (int)hk_below(&r, 2);
		rq.p = p;
		rq.n = n;
		rq.va = hk_next(&r);
		rq.text = tp;
		rq.cap = cap;
		kgenome_disasm(&rq, &a);
		if (cap)
			CK(memchr(tp, 0, cap) != NULL);
		if (!kgenome_disasm_level(arch)) {
			CK(a.status == (n ? KGENOME_UNSUPPORTED : KGENOME_TRUNCATED) && a.len == 0);
			continue;
		}
		CK(a.status == KGENOME_OK || a.status == KGENOME_UNSUPPORTED || a.status == KGENOME_BAD_INPUT || a.status == KGENOME_TRUNCATED);
		if (!n) {
			CK(a.status == KGENOME_TRUNCATED && a.len == 0);
			continue;
		}
		CK(a.len >= 1u && a.len <= max);
		if (align > 1u) {
			CK(a.len == (n >= 4u ? 4u : (uint32_t)n));
		} else if (a.status == KGENOME_OK) {
			CK(a.len <= n);
		}
		if (n < 4u && align > 1u)
			CK(a.status == KGENOME_TRUNCATED);
		/* the same answer twice, and a branch target only with a flow that has one */
		rq.text = tp;
		kgenome_disasm(&rq, &b);
		CK(a.status == b.status && a.len == b.len && a.flow == b.flow && a.has_target == b.has_target && a.target == b.target);
		if (a.has_target && align > 1u)
			CK(a.flow != KGENOME_GT_FLOW_RET && a.flow != KGENOME_GT_FLOW_TRAP);
	}
	gb_free(&g);
	gb_free(&tg);
}

int main(int argc, char **argv)
{
	unsigned long iters;

	hk_args(argc, argv);
	iters = 120000ul * hk_scale();
	rows(KGENOME_ARCH_ARM64, g_a64, sizeof g_a64 / sizeof g_a64[0], 0);
	rows(KGENOME_ARCH_ARM, g_a32, sizeof g_a32 / sizeof g_a32[0], 1);
	hostile(KGENOME_ARCH_X86, iters);
	hostile(KGENOME_ARCH_X86_64, iters);
	hostile(KGENOME_ARCH_ARM, iters);
	hostile(KGENOME_ARCH_ARM64, iters);
	hostile(KGENOME_ARCH_MIPS, iters / 10ul);
	printf("disasm_oracle: %zu a64 rows, %zu a32 rows, %lu hostile buffers per architecture, %d failure(s)\n",
	       sizeof g_a64 / sizeof g_a64[0], sizeof g_a32 / sizeof g_a32[0], iters, hk_fails);
	return hk_fails != 0;
}
