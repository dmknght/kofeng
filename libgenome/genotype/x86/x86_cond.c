/*
 * x86_cond.c - kgenome_x86_cond_text and kgenome_x86_keeps_flags: what a conditional jump asks, in words. See x86.h.
 *
 * The condition code is the instruction's own (kgenome_x86_cond: the low four bits of the opcode, as every x86 decoder numbers them), so there is one
 * table of sixteen and no per-mnemonic spelling: `je` and `jz` are the same instruction and say the same thing.
 */

#include "x86.h"

#include <stdio.h>
#include <string.h>

/* The flags a code tests, for a jump whose flags nothing here can name the setter of. */
static const char *const cc_flags[16] = {
	"OF=1 (signed overflow)",             "OF=0 (no signed overflow)",
	"CF=1 (unsigned below)",              "CF=0 (unsigned above or equal)",
	"ZF=1 (equal / zero)",                "ZF=0 (not equal / not zero)",
	"CF=1 or ZF=1 (unsigned below or equal)", "CF=0 and ZF=0 (unsigned above)",
	"SF=1 (negative)",                    "SF=0 (not negative)",
	"PF=1 (even parity)",                 "PF=0 (odd parity)",
	"SF!=OF (signed less)",               "SF=OF (signed greater or equal)",
	"ZF=1 or SF!=OF (signed less or equal)", "ZF=0 and SF=OF (signed greater)"
};

/* `a OP b` for a CMP: the operator of each code, and whether it compares as unsigned (u), signed (s) or neither (-). 0 where the code is not a comparison. */
static const struct { const char *op; char sign; } cc_cmp[16] = {
	{ 0, 0 }, { 0, 0 },
	{ "<", 'u' }, { ">=", 'u' },
	{ "==", '-' }, { "!=", '-' },
	{ "<=", 'u' }, { ">", 'u' },
	{ 0, 0 }, { 0, 0 },                  /* S, NS: the sign of the difference, spelled below */
	{ 0, 0 }, { 0, 0 },
	{ "<", 's' }, { ">=", 's' },
	{ "<=", 's' }, { ">", 's' }
};

/* The operator against zero of a code after a TEST, whose CF and OF are cleared: 0 where the answer is a constant or is not a comparison. */
static const char *test_op(unsigned cc)
{
	switch (cc) {
	case 4: case 6: return "==";         /* E; BE is CF=1 or ZF=1 and CF is 0 */
	case 5: case 7: return "!=";         /* NE; A */
	case 8: case 12: return "<";         /* S; L is SF!=OF and OF is 0 */
	case 9: case 13: return ">=";        /* NS; GE */
	case 14: return "<=";
	case 15: return ">";
	default: return NULL;
	}
}

/* The two operands of a formatted two-operand instruction, into `a` and `b`; 0 when it does not have exactly two. */
static int operands_of(const struct kgenome_x86_insn *in, uint64_t rip, char *a, char *b, size_t cap)
{
	char t[KGENOME_X86_TEXT];
	char *p, *sep;

	if (!kgenome_x86_format(in, rip, t, sizeof t))
		return 0;
	kgenome_x86_shorten(t);
	for (p = t; *p && *p != ' '; p++)
		;
	while (*p == ' ')
		p++;
	sep = strstr(p, ", ");
	if (!sep || strstr(sep + 2, ", ") || (size_t)(sep - p) >= cap || strlen(sep + 2) >= cap)
		return 0;
	memcpy(a, p, (size_t)(sep - p));
	a[sep - p] = 0;
	snprintf(b, cap, "%s", sep + 2);
	return a[0] && b[0];
}

static size_t put(char *buf, size_t cap, const char *s)
{
	size_t n = strlen(s);

	if (n + 1u > cap)
		return 0;
	memcpy(buf, s, n + 1u);
	return n;
}

static size_t from_cmp(unsigned cc, const char *a, const char *b, char *buf, size_t cap)
{
	char t[2 * KGENOME_X86_TEXT];
	int w;

	if (cc == 8 || cc == 9)
		w = snprintf(t, sizeof t, "%s - %s %s 0", a, b, cc == 8 ? "<" : ">=");
	else if (cc_cmp[cc].op)
		w = snprintf(t, sizeof t, "%s %s %s%s", a, cc_cmp[cc].op, b,
			     cc_cmp[cc].sign == 'u' ? " (unsigned)" : cc_cmp[cc].sign == 's' ? " (signed)" : "");
	else
		return 0;
	return w > 0 ? put(buf, cap, t) : 0;
}

static size_t from_test(unsigned cc, const char *a, const char *b, char *buf, size_t cap)
{
	char t[2 * KGENOME_X86_TEXT];
	const char *op = test_op(cc);
	int w;

	if (cc == 2)
		return put(buf, cap, "never taken (test clears CF)");
	if (cc == 3)
		return put(buf, cap, "always taken (test clears CF)");
	if (!op)
		return 0;
	if (!strcmp(a, b))
		w = snprintf(t, sizeof t, "%s %s 0", a, op);
	else
		w = snprintf(t, sizeof t, "(%s & %s) %s 0", a, b, op);
	return w > 0 ? put(buf, cap, t) : 0;
}

size_t kgenome_x86_cond_text(const struct kgenome_x86_insn *jcc, const struct kgenome_x86_insn *setter, uint64_t setter_rip,
			     char *buf, size_t cap)
{
	char a[KGENOME_X86_TEXT], b[KGENOME_X86_TEXT];
	unsigned cc;
	size_t n = 0;

	if (cap)
		buf[0] = 0;
	if (!jcc || jcc->id != KGENOME_X86_I_Jcc)
		return 0;
	cc = kgenome_x86_cond(jcc) & 15u;
	if (setter && (setter->id == KGENOME_X86_I_CMP || setter->id == KGENOME_X86_I_TEST) &&
	    operands_of(setter, setter_rip, a, b, sizeof a))
		n = setter->id == KGENOME_X86_I_CMP ? from_cmp(cc, a, b, buf, cap) : from_test(cc, a, b, buf, cap);
	return n ? n : put(buf, cap, cc_flags[cc]);
}

size_t kgenome_x86_cmp_text(const struct kgenome_x86_insn *in, uint64_t rip, char *buf, size_t cap)
{
	char a[KGENOME_X86_TEXT], b[KGENOME_X86_TEXT], t[2 * KGENOME_X86_TEXT];
	int w;

	if (cap)
		buf[0] = 0;
	if (!in || (in->id != KGENOME_X86_I_CMP && in->id != KGENOME_X86_I_TEST) || !operands_of(in, rip, a, b, sizeof a))
		return 0;
	if (in->id == KGENOME_X86_I_CMP)
		w = snprintf(t, sizeof t, "compare %s with %s", a, b);
	else if (!strcmp(a, b))
		w = snprintf(t, sizeof t, "compare %s with 0", a);
	else
		w = snprintf(t, sizeof t, "test %s & %s", a, b);
	return w > 0 ? put(buf, cap, t) : 0;
}

int kgenome_x86_keeps_flags(const struct kgenome_x86_insn *in)
{
	switch (in->id) {
	case KGENOME_X86_I_MOV: case KGENOME_X86_I_LEA: case KGENOME_X86_I_NOP: case KGENOME_X86_I_PUSH:
	case KGENOME_X86_I_POP: case KGENOME_X86_I_MOVZX: case KGENOME_X86_I_MOVSX: case KGENOME_X86_I_MOVSXD:
	case KGENOME_X86_I_Jcc: case KGENOME_X86_I_CMOVcc: case KGENOME_X86_I_SETcc: case KGENOME_X86_I_XCHG:
	case KGENOME_X86_I_BSWAP:
		return 1;
	default:
		return 0;
	}
}
