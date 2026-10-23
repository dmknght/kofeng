#ifndef KGENOME_TEST_TEXTUAL_CHECK_H
#define KGENOME_TEST_TEXTUAL_CHECK_H

/*
 * textual_check.h - what every test of the textual part uses, once: the check macro, the way a text is
 * shown as its spans, the form as a call, and the two properties that are true of any input - the spans
 * partition it, and the form of a form is itself.
 *
 * A SPAN LIST IS READ AS ONE LINE. Each span is a kind letter and the bytes in braces:
 *
 *     M markup  T tag  C code  S string  K comment
 *     S* a backslash is an escape in it   S! not closed   S# heredoc or nowdoc  (flags in that order)
 *
 * so a case is the input and the one line it must come out as, and a wrong boundary is a line that differs
 * rather than a count. Everything here goes through <kgenome.h> and nothing else: a test of a language is a
 * test of the API.
 *
 * Every function is `static inline` so a test that uses three of them compiles clean.
 */

#include <kgenome.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

struct rend {
	const uint8_t *in;
	char    out[8192];
	size_t  w;
	uint32_t next;
	int      broken;        /* the partition invariant failed */
	uint32_t n;
};

static inline int put(struct rend *r, const char *s)
{
	size_t l = strlen(s);

	if (r->w + l >= sizeof r->out)
		return 0;
	memcpy(r->out + r->w, s, l + 1);
	r->w += l;
	return 1;
}

static inline int sink(void *u, const struct kgenome_textual_span *s)
{
	struct rend *r = u;
	static const char k[] = "MTCSK";
	char head[8];
	uint32_t i, hw = 0;

	if (s->off != r->next || !s->len || (uint64_t)s->off + s->len > r->n ||
	    (uint64_t)s->open_len + s->close_len > s->len)
		r->broken = 1;
	r->next = s->off + s->len;
	head[hw++] = k[s->kind];
	if (s->flags & KGENOME_TEXTUAL_F_INTERP)
		head[hw++] = '*';
	if (s->flags & KGENOME_TEXTUAL_F_OPEN)
		head[hw++] = '!';
	if (s->flags & KGENOME_TEXTUAL_F_HERE)
		head[hw++] = '#';
	head[hw++] = '{';
	head[hw] = 0;
	put(r, head);
	for (i = 0; i < s->len; i++) {
		char c[2] = { (char)r->in[s->off + i], 0 };

		put(r, c);
	}
	return put(r, "}");
}

static inline enum kgenome_textual_status lex(struct rend *r, const void *in, uint32_t n, uint32_t lang)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = lang, .sink = sink, .user = r };
	struct kgenome_textual_lex_res rs;
	enum kgenome_textual_status st;

	memset(r, 0, sizeof *r);
	r->in = in;
	r->n = n;
	st = kgenome_textual_lex(&rq, &rs);
	if (st != KGENOME_TEXTUAL_REFUSED && r->next != n)
		r->broken = 1;
	return st;
}

static inline void expect_lang(uint32_t lang, const char *src, const char *want)
{
	static struct rend r;

	lex(&r, src, (uint32_t)strlen(src), lang);
	if (r.broken || strcmp(r.out, want)) {
		printf("  FAIL input  %s\n       got    %s\n       wanted %s%s\n", src, r.out, want,
		       r.broken ? "\n       (and the partition broke)" : "");
		fails++;
	}
}


static uint8_t fbuf[4096], fbuf2[4096];

static inline enum kgenome_textual_status form_of(const void *in, uint32_t n, uint8_t *out, uint64_t cap,
					   uint32_t *n_out)
{
	struct kgenome_textual_form_req rq = { .in = in, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = out, .cap = cap };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st = kgenome_textual_form(&rq, &rs);

	*n_out = rs.n_out;
	return st;
}

static inline void form_lang(uint32_t lang, const char *src, const char *want)
{
	uint32_t n;
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src),
					       .lang = lang, .out = fbuf, .cap = sizeof fbuf };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st = kgenome_textual_form(&rq, &rs);

	n = rs.n_out;
	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || n != strlen(want) || memcmp(fbuf, want, n)) {
		fbuf[n < sizeof fbuf ? n : sizeof fbuf - 1u] = 0;
		printf("  FAIL form of  %s\n       got    %s\n       wanted %s\n", src, fbuf, want);
		fails++;
	}
}

/* The form of a form is itself, and the output fits its cap, on input nobody wrote. */
static inline void form_property_for(uint32_t lang, const char *alpha, uint32_t seed)
{
	uint8_t b[160];
	uint32_t s = seed, i, n, k, w1, w2, na = (uint32_t)strlen(alpha);

	for (i = 0; i < 40000u; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		enum kgenome_textual_status st;

		s = s * 1103515245u + 12345u;
		n = (s >> 16) % sizeof b;
		for (k = 0; k < n; k++) {
			s = s * 1103515245u + 12345u;
			b[k] = (uint8_t)alpha[(s >> 16) % na];
		}
		rq = (struct kgenome_textual_form_req){ .in = b, .n = n, .lang = lang, .out = fbuf,
							.cap = KGENOME_TEXTUAL_FORM_CAP(n) };
		st = kgenome_textual_form(&rq, &rs);
		w1 = rs.n_out;
		if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || w1 > KGENOME_TEXTUAL_FORM_CAP(n)) {
			printf("  FAIL form status %d or length %u on a random input of %u bytes (language %u)\n",
			       (int)st, w1, n, lang);
			fails++;
			return;
		}
		rq = (struct kgenome_textual_form_req){ .in = fbuf, .n = w1, .lang = lang, .out = fbuf2,
							.cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
		st = kgenome_textual_form(&rq, &rs);
		w2 = rs.n_out;
		if (w2 != w1 || memcmp(fbuf, fbuf2, w1)) {
			printf("  FAIL the form is not its own form (language %u), input of %u bytes:\n  ", lang, n);
			for (k = 0; k < n; k++)
				printf(b[k] >= 0x20 && b[k] < 0x7f && b[k] != '\\' ? "%c" : "\\x%02x", b[k]);
			printf("\n");
			fails++;
			return;
		}
	}
}


static inline void partition_for(uint32_t lang, const char *alpha, uint32_t seed)
{
	static struct rend r;
	uint8_t b[160];
	uint32_t s = seed, i, n, k, na = (uint32_t)strlen(alpha);

	for (i = 0; i < 40000u; i++) {
		s = s * 1103515245u + 12345u;
		n = (s >> 16) % sizeof b;
		for (k = 0; k < n; k++) {
			s = s * 1103515245u + 12345u;
			b[k] = (uint8_t)alpha[(s >> 16) % na];
		}
		lex(&r, b, n, lang);
		if (r.broken) {
			printf("  FAIL partition (language %u) on a random input of %u bytes\n", lang, n);
			fails++;
			return;
		}
	}
	/* any byte at all, not only the ones above */
	for (i = 0; i < 20000u; i++) {
		s = s * 1103515245u + 12345u;
		n = (s >> 16) % sizeof b;
		for (k = 0; k < n; k++) {
			s = s * 1103515245u + 12345u;
			b[k] = (uint8_t)(s >> 16);
		}
		if (lang == KGENOME_TEXTUAL_LANG_PHP)
			memcpy(b, "<?php ", n < 6u ? n : 6u);
		lex(&r, b, n, lang);
		if (r.broken) {
			printf("  FAIL partition (language %u) on a random byte string of %u bytes\n", lang, n);
			fails++;
			return;
		}
	}
}


#endif /* KGENOME_TEST_TEXTUAL_CHECK_H */
