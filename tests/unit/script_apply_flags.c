/*
 * script_apply_flags - the call's flags as the op reads them (op_flags in script_apply.c, the one table of KGENOME_TEXTUAL_CALL_* -> KUNCOAT_F_*).
 *
 * Two properties, each stated against the engine's own hook (kof_script_apply) with nothing of the table copied here:
 *   own     every flag an op reads is carried: REPLACE's FIRST and ICASE, TRANSLATE's RANGES (the answers are pinned by hand);
 *   foreign a flag the row set for ANOTHER op changes nothing: for every op, every combination of the eight flags gives the bytes the op's own flags give.
 * The second is what the mask in op_flags is for, and is checked over 256 combinations x every op x several subjects and parameters, so an op that began to read a bit of
 * another's would show here before it showed in a corpus.
 *
 * usage: script_apply_flags
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/analyzers/parsers/scripts/script_apply.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static int run(uint32_t op, const char *s1, const char *s2, uint32_t flags, const char *in, char *out, uint32_t cap, uint32_t *n)
{
	struct kgenome_textual_call c;

	memset(&c, 0, sizeof c);
	c.op = op;
	c.s1 = (const uint8_t *)s1;
	c.n1 = s1 ? (uint32_t)strlen(s1) : 0u;
	c.s2 = (const uint8_t *)s2;
	c.n2 = s2 ? (uint32_t)strlen(s2) : 0u;
	c.k1 = 1;
	c.k2 = 2;
	c.flags = flags;
	return kof_script_apply(NULL, &c, (const uint8_t *)in, (uint32_t)strlen(in), (uint8_t *)out, cap, n);
}

static int same_answer(uint32_t op, const char *s1, const char *s2, uint32_t fa, uint32_t fb, const char *in)
{
	char a[256], b[256];
	uint32_t na = 0, nb = 0;
	int ra = run(op, s1, s2, fa, in, a, sizeof a, &na), rb = run(op, s1, s2, fb, in, b, sizeof b, &nb);

	return ra == rb && (!ra || (na == nb && !memcmp(a, b, na)));
}

static int is(uint32_t op, const char *s1, const char *s2, uint32_t flags, const char *in, const char *want)
{
	char o[256];
	uint32_t n = 0;

	if (!run(op, s1, s2, flags, in, o, sizeof o, &n)) {
		printf("  op %u flags %x on [%s]: refused (want [%s])\n", op, flags, in, want);
		return 0;
	}
	if (n != strlen(want) || memcmp(o, want, n)) {
		printf("  op %u flags %x on [%s]: [%.*s] (want [%s])\n", op, flags, in, (int)n, o, want);
		return 0;
	}
	return 1;
}

int main(void)
{
	static const struct { uint32_t op, own; } ops[] = {
		{ KGENOME_TEXTUAL_DEC_REPLACE,   KGENOME_TEXTUAL_CALL_FIRST | KGENOME_TEXTUAL_CALL_ICASE },
		{ KGENOME_TEXTUAL_DEC_TRANSLATE, KGENOME_TEXTUAL_CALL_RANGES },
		{ KGENOME_TEXTUAL_DEC_SPLIT,     KGENOME_TEXTUAL_CALL_ICASE | KGENOME_TEXTUAL_CALL_DROPTRAIL | KGENOME_TEXTUAL_CALL_WSLIST },
		{ KGENOME_TEXTUAL_DEC_JOIN,      KGENOME_TEXTUAL_CALL_ICASE | KGENOME_TEXTUAL_CALL_DROPTRAIL | KGENOME_TEXTUAL_CALL_WSLIST },
		{ KGENOME_TEXTUAL_DEC_CUTHEAD,   KGENOME_TEXTUAL_CALL_REUSE | KGENOME_TEXTUAL_CALL_ESC },
		{ KGENOME_TEXTUAL_DEC_CUTTAIL,   KGENOME_TEXTUAL_CALL_REUSE | KGENOME_TEXTUAL_CALL_ESC },
		{ KGENOME_TEXTUAL_DEC_MAP,       KGENOME_TEXTUAL_CALL_REUSE | KGENOME_TEXTUAL_CALL_ESC },
		{ KGENOME_TEXTUAL_DEC_FORMAT,    KGENOME_TEXTUAL_CALL_REUSE | KGENOME_TEXTUAL_CALL_ESC },
		{ KGENOME_TEXTUAL_DEC_SLICE, 0 }, { KGENOME_TEXTUAL_DEC_LOWER, 0 }, { KGENOME_TEXTUAL_DEC_UPPER, 0 }, { KGENOME_TEXTUAL_DEC_REVERSE, 0 },
		{ KGENOME_TEXTUAL_DEC_REPEAT, 0 }, { KGENOME_TEXTUAL_DEC_LENGTH, 0 }, { KGENOME_TEXTUAL_DEC_B64, 0 }, { KGENOME_TEXTUAL_DEC_HEX, 0 },
	};
	static const char *const subj[] = { "aaA", "AbcABC a-c", "x,y,,", "%s\\n%s", "", "a b  c" };
	static const char *const par[][2] = { { "a", "X" }, { "a-c", "A-C" }, { ",", "" }, { "%", "\\t" }, { "", "" }, { "A", "a" } };
	size_t i, s, p;
	uint32_t f;

	/* own flags, pinned by hand */
	CK(is(KGENOME_TEXTUAL_DEC_REPLACE, "a", "X", 0, "aaA", "XXA"));
	CK(is(KGENOME_TEXTUAL_DEC_REPLACE, "a", "X", KGENOME_TEXTUAL_CALL_FIRST, "aaA", "XaA"));
	CK(is(KGENOME_TEXTUAL_DEC_REPLACE, "a", "X", KGENOME_TEXTUAL_CALL_ICASE, "aaA", "XXX"));
	CK(is(KGENOME_TEXTUAL_DEC_REPLACE, "a", "X", KGENOME_TEXTUAL_CALL_FIRST | KGENOME_TEXTUAL_CALL_ICASE, "aaA", "XaA"));
	CK(is(KGENOME_TEXTUAL_DEC_REPLACE, "A", "X", KGENOME_TEXTUAL_CALL_FIRST | KGENOME_TEXTUAL_CALL_ICASE, "aaA", "Xa" "A"));
	CK(is(KGENOME_TEXTUAL_DEC_TRANSLATE, "a-c", "A-C", 0, "abcd-", "AbCd-"));
	CK(is(KGENOME_TEXTUAL_DEC_TRANSLATE, "a-c", "A-C", KGENOME_TEXTUAL_CALL_RANGES, "abcd-", "ABCd-"));
	/* foreign flags: nothing */
	for (i = 0; i < sizeof ops / sizeof ops[0]; i++)
		for (s = 0; s < sizeof subj / sizeof subj[0]; s++)
			for (p = 0; p < sizeof par / sizeof par[0]; p++)
				for (f = 0; f < 256u; f++)
					if (!same_answer(ops[i].op, par[p][0], par[p][1], f & ops[i].own, f, subj[s])) {
						printf("  op %u, flags %x differs from own %x on [%s] params [%s][%s]\n", ops[i].op, f, f & ops[i].own, subj[s], par[p][0], par[p][1]);
						CK(0);
						f = 256u;
					}
	printf("script_apply_flags: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
