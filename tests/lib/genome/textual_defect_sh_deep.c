/*
 * genome / textual_defect_sh_deep - L1 of the lexer audit: the shell's WORD reader (textual/sh/sh_cmd.c) walks `"$( ... )"` and `${ ... }` groups with two
 * functions that call each other (dq_end, group_end) and had no depth bound, so `"$(` written 100000 times overflowed the stack: a text chooses how much stack a scan
 * takes. sh_lex.c bounds the same walk at SH_DEPTH; the word reader now has the same bound and SAYS when it fired.
 *
 * What is asserted: the readers RETURN on every nesting depth that fits in memory, and what they return for a group nested past the bound is a refusal that is
 * reported (kgenome_textual_cmd.deep, set only when the bound fired; `open` is the plain "does not close"), not a silent cut. The 100000-deep text is the one that
 * crashed (SIGSEGV, stack exhausted); the old tests nested 3 deep.
 *
 * Why the old tests missed it: (b) executed without a boundary input - textual_sh_groups.c nests a few levels, no test nests to a depth a file can choose.
 *
 * usage: textual_defect_sh_deep
 */

#include "textual_check.h"

/* `unit` written n times, then `tail` */
static uint8_t *rep(const char *unit, uint32_t n, const char *tail, uint32_t *len)
{
	size_t u = strlen(unit), t = strlen(tail);
	uint8_t *b = malloc(u * n + t + 1u);
	uint32_t i;

	if (!b)
		abort();
	for (i = 0; i < n; i++)
		memcpy(b + (size_t)i * u, unit, u);
	memcpy(b + (size_t)n * u, tail, t);
	*len = (uint32_t)(u * n + t);
	return b;
}

static int sink_lit(void *u, const uint8_t *p, uint32_t n) { (void)u; (void)p; (void)n; return 1; }
static int sink_var(void *u, struct kgenome_textual_range r, int q) { (void)u; (void)r; (void)q; return 1; }
static int sink_exp(void *u, struct kgenome_textual_range r, uint32_t row, const struct kgenome_textual_range *a, uint32_t n, int q)
{
	(void)u; (void)r; (void)row; (void)a; (void)n; (void)q;
	return 1;
}
static int sink_cmd(void *u, struct kgenome_textual_range r, int q) { (void)u; (void)r; (void)q; return 1; }

/* the shapes in which a group is read through the double quotes round it, and back: the two functions that called each other with no bound (a unit with no double quote
 * is followed by the group's own bracket counter and does not nest) */
static int recurses(const char *unit)
{
	return strchr(unit, '"') != NULL;
}

static void attack(const char *unit, uint32_t n, const char *tail)
{
	uint32_t len, e;
	uint8_t *b = rep(unit, n, tail, &len);
	struct kgenome_textual_cmd c;
	struct kgenome_textual_word_sink sk = { NULL, sink_lit, sink_var, sink_exp, sink_cmd };

	memset(&c, 0, sizeof c);
	CK(kgenome_textual_cmd_read(KGENOME_TEXTUAL_LANG_SH, b, 0, len, &c) == 1);
	CK(c.end <= len);
	/* none of these text closes: the word is the rest of the text, and the command SAYS so; nested past the bound it says that too (`deep`), never a silent cut */
	CK(c.open == 1 && c.end == len);
	if (!(recurses(unit) ? (n >= 64u ? c.deep == 1 : n <= 8u ? c.deep == 0 : 1) : c.deep == 0)) {
		printf("  FAIL unit [%s] x %u: deep %u\n", unit, n, c.deep);
		fails++;
	}
	e = kgenome_textual_word_read(KGENOME_TEXTUAL_LANG_SH, b, 0, len, KGENOME_TEXTUAL_CTX_WORD, &sk);
	CK(e <= len);
	e = kgenome_textual_word_read(KGENOME_TEXTUAL_LANG_SH, b, 0, len, KGENOME_TEXTUAL_CTX_OPERAND, &sk);
	CK(e <= len);
	free(b);
}

int main(void)
{
	static const char *const units[] = { "\"$(", "$(\"", "\"${", "${\"", "$(${", "${$(", "\"$(\"${", "$(`", "\"$(\\\"" };
	uint32_t k, depth;

	/* every shape of nesting, at depths on both sides of the bound (32) and far past it; 400000 is the one that cannot be walked by recursion */
	for (k = 0; k < sizeof units / sizeof units[0]; k++)
		for (depth = 1; depth <= 400000u; depth *= (depth < 64u ? 2u : 40u)) {
			attack(units[k], depth, "");
			attack(units[k], depth, "x");
		}

	/* a group that CLOSES, nested to the bound and past it: within the bound it is one word, past it the reader says so */
	for (depth = 28; depth <= 36; depth++) {
		uint32_t len, i;
		uint8_t *open_part = rep("$(", depth, "x", &len);
		uint8_t *b = malloc(len + depth + 1u);
		struct kgenome_textual_cmd c;

		if (!b)
			abort();
		memcpy(b, open_part, len);
		for (i = 0; i < depth; i++)
			b[len + i] = ')';
		memset(&c, 0, sizeof c);
		CK(kgenome_textual_cmd_read(KGENOME_TEXTUAL_LANG_SH, b, 0, len + depth, &c) == 1);
		CK(c.end <= len + depth);
		/* nested through the shell's own `$(` groups, which are counted and not followed one call each: closed, at every depth, and nothing is cut */
		CK(c.open == 0 && c.deep == 0 && c.n == 1u);
		free(b);
		free(open_part);
	}
	if (fails)
		printf("textual_defect_sh_deep: %d FAILED\n", fails);
	else
		printf("textual_defect_sh_deep: ok\n");
	return fails != 0;
}
