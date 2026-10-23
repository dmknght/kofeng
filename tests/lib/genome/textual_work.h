#ifndef KGENOME_TEST_TEXTUAL_WORK_H
#define KGENOME_TEST_TEXTUAL_WORK_H

/*
 * textual_work.h - the lexer tests' driver over the work counter (tests/lib/work_count.h): lex a text and count, build the repeated shapes the quadratic
 * defects of the lexer audit need, and compare the work at n and at 4n bytes.
 */

#include <kgenome.h>

#include "../work_count.h"

static int work_span_sink(void *u, const struct kgenome_textual_span *s)
{
	(void)u;
	(void)s;
	return 1;
}

/* the work bounds the last work_lex walk reported (kgenome_textual_lex_res.n_bound) */
static uint32_t work_bound_seen;

/* The blocks the lexer of `lang` executes (in the translation units compiled with the instrumentation) to lex `in`, delivering every span to a sink that keeps none. */
static inline uint64_t work_lex(uint32_t lang, const uint8_t *in, uint32_t n)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = lang, .sink = work_span_sink, .user = NULL };
	struct kgenome_textual_lex_res rs;

	WORK_BEGIN();
	(void)kgenome_textual_lex(&rq, &rs);
	work_bound_seen = rs.n_bound;
	return work_end();
}

/* `head`, then `unit` written `rep` times, then `tail`; the length in *len. */
static inline uint8_t *work_text(const char *head, const char *unit, uint32_t rep, const char *tail, uint32_t *len)
{
	size_t h = strlen(head), u = strlen(unit), t = strlen(tail);
	uint8_t *b = malloc(h + u * rep + t + 1u);
	uint32_t i;

	if (!b)
		abort();
	memcpy(b, head, h);
	for (i = 0; i < rep; i++)
		memcpy(b + h + u * i, unit, u);
	memcpy(b + h + u * rep, tail, t);
	*len = (uint32_t)(h + u * rep + t);
	return b;
}

/* Lex head + unit x rep + tail at about `n1` bytes and at about 4 `n1`, and say whether the work grew linearly. */
static inline int work_lex_shape(uint32_t lang, const char *what, const char *head, const char *unit, const char *tail, uint32_t n1, uint64_t per_byte)
{
	uint32_t rep1 = (uint32_t)(n1 / strlen(unit)), l1, l2;
	uint8_t *a = work_text(head, unit, rep1, tail, &l1), *b = work_text(head, unit, rep1 * 4u, tail, &l2);
	uint64_t w1 = work_lex(lang, a, l1), w2 = work_lex(lang, b, l2);

	free(a);
	free(b);
	return work_grows_linearly(what, w1, l1, w2, l2, per_byte);
}

/*
 * EVERY SHAPE OF 1 TO `maxlen` BYTES OF AN ALPHABET, repeated: the exhaustive form of "a text whose every byte is an opener". The alphabet is the language's
 * syntax (quotes, comment and heredoc openers, brackets, line breaks), `head` puts the lexer in the language's code (a page's "<%", a tag). Every unit is lexed at
 * `n1` and 4 `n1` bytes; the failures are printed (the first six) and counted. Answers the number of shapes whose work did not grow linearly.
 */
static inline int work_alphabet_shapes(uint32_t lang, const char *name, const char *head, const char *alpha, uint32_t maxlen, uint32_t n1, uint64_t per_byte)
{
	uint32_t na = (uint32_t)strlen(alpha), len, k, idx[4];
	int bad = 0, shown = 0;
	char unit[5];

	for (len = 1; len <= maxlen; len++) {
		for (k = 0; k < len; k++)
			idx[k] = 0;
		for (;;) {
			uint32_t rep1, l1, l2;
			uint8_t *a, *b;
			uint64_t w1, w2;

			for (k = 0; k < len; k++)
				unit[k] = alpha[idx[k]];
			unit[len] = 0;
			rep1 = n1 / len;
			a = work_text(head, unit, rep1, "", &l1);
			b = work_text(head, unit, rep1 * 4u, "", &l2);
			w1 = work_lex(lang, a, l1);
			w2 = work_lex(lang, b, l2);
			if (!(w2 <= 6u * w1 + 64u && w2 <= per_byte * l2)) {
				bad++;
				if (shown++ < 6) {
					uint32_t i;

					printf("  FAIL %s: head `%s` + [", name, head);
					for (i = 0; i < len; i++)
						printf((uint8_t)unit[i] >= 0x20 && (uint8_t)unit[i] < 0x7f ? "%c" : "\\x%02x", (uint8_t)unit[i]);
					printf("] repeated: %llu blocks at %u bytes, %llu at %u (x%.1f)\n", (unsigned long long)w1, l1, (unsigned long long)w2, l2,
					       (double)w2 / (double)(w1 ? w1 : 1u));
				}
			}
			free(a);
			free(b);
			for (k = 0; k < len && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == len)
				break;
		}
	}
	if (bad)
		printf("  FAIL %s: %d shapes grow faster than linearly\n", name, bad);
	return bad;
}

#endif /* KGENOME_TEST_TEXTUAL_WORK_H */
