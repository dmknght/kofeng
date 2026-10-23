/*
 * genome / textual_defect_subst - L8 of the lexer audit: kgenome_textual_subst (textual_subst.c) promises that "ranges past the input answer 0". The check was
 * `s[i].len > n - s[i].off`, and for off > n the subtraction wraps to a huge number, so a range that begins past the input passed it and memcpy read past the
 * input (a caller that hands in a hostile range; the engine's own callers do not).
 *
 * Asserted: every range that is not inside the input, in order and past the one before, answers 0 and writes nothing - checked on a model over ALL ranges of a
 * small input (every offset and length from 0 to 9 against inputs of 0 to 5 bytes, and every ordered pair of them), and at the edges of the 32-bit space (an
 * offset near 2^32, an offset plus a length that wraps). The input is a heap buffer of exactly n bytes, so a read past it is a finding under the sanitiser, and the
 * answer is asserted without it.
 *
 * Why the old tests missed it: (b) textual_subst.c uses ranges inside the input and one or two out of order; none begins past the end.
 *
 * usage: textual_defect_subst
 */

#include "textual_check.h"

#include <signal.h>
#include <unistd.h>

/* The model: ranges must be ordered, each inside the input; the value is written as php writes it. */
static int model_ok(uint32_t n, const struct kgenome_textual_subst *s, uint32_t ns)
{
	uint64_t at = 0;
	uint32_t i;

	for (i = 0; i < ns; i++) {
		if (s[i].off < at || (uint64_t)s[i].off + s[i].len > n)
			return 0;
		at = (uint64_t)s[i].off + s[i].len;
	}
	return 1;
}

/* what is being asked, so that a fault in the library says which range did it (the old code read past the input and died here) */
static char now[160];

static void on_fault(int sig)
{
	(void)sig;
	if (write(1, now, strlen(now)) < 0)
		_exit(139);
	_exit(139);
}

static void one(uint32_t n, struct kgenome_textual_subst *s, uint32_t ns)
{
	uint8_t *in = malloc(n ? n : 1u), out[256];
	uint32_t got, i;
	int want = model_ok(n, s, ns);

	if (!in)
		abort();
	for (i = 0; i < n; i++)
		in[i] = (uint8_t)('A' + i);
	snprintf(now, sizeof now, "  FAIL (fault, signal) in kgenome_textual_subst: input %u bytes, range 0 = %u+%u%s\n", n, s[0].off, s[0].len, ns > 1u ? " and a second" : "");
	got = kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, in, n, s, ns, out, sizeof out);
	if (!!got != want) {
		printf("  FAIL n=%u ns=%u [%u+%u%s", n, ns, s[0].off, s[0].len, ns > 1u ? "," : "]");
		if (ns > 1u)
			printf(" %u+%u]", s[1].off, s[1].len);
		printf(": answered %u, the ranges are %s\n", got, want ? "valid" : "not inside the input");
		fails++;
	}
	free(in);
}

int main(void)
{
	static const uint32_t edge[] = { 0xfffffff0u, 0xffffffffu, 0x80000000u, 0x7fffffffu, 0xfffffffeu };
	uint32_t n, o1, l1, o2, l2, k;
	struct kgenome_textual_subst s[2];

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGSEGV, on_fault);
	signal(SIGBUS, on_fault);
	memset(s, 0, sizeof s);
	for (k = 0; k < 2; k++) {
		s[k].value = (const uint8_t *)"ab";
		s[k].n = 2;
	}
	for (n = 0; n <= 5; n++)
		for (o1 = 0; o1 <= 9; o1++)
			for (l1 = 0; l1 <= 9; l1++) {
				s[0].off = o1;
				s[0].len = l1;
				one(n, s, 1);
				for (o2 = 0; o2 <= 9; o2++)
					for (l2 = 0; l2 <= 9; l2++) {
						s[1].off = o2;
						s[1].len = l2;
						one(n, s, 2);
					}
			}
	/* the edges of the 32-bit space: an offset that is past any input, and an offset and length whose sum wraps */
	for (k = 0; k < sizeof edge / sizeof edge[0]; k++) {
		uint32_t j;

		for (n = 0; n <= 4; n++)
			for (j = 0; j < sizeof edge / sizeof edge[0]; j++) {
				s[0].off = edge[k];
				s[0].len = 0;
				one(n, s, 1);
				s[0].off = 0;
				s[0].len = edge[j];
				one(n, s, 1);
				s[0].off = edge[k];
				s[0].len = edge[j];
				one(n, s, 1);
				s[0].off = 1;
				s[0].len = edge[j];
				one(n, s, 1);
				s[0].off = 0;
				s[0].len = 1;
				s[1].off = edge[k];
				s[1].len = edge[j];
				one(n, s, 2);
			}
	}
	printf(fails ? "textual_defect_subst: %d FAILED\n" : "textual_defect_subst: ok\n", fails);
	return fails != 0;
}
