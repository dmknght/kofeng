/*
 * textual_php_strings - php string literals attacked with every byte, and the join of literals attacked with every seam.
 *
 * TWO PROPERTIES, NEITHER OF THEM A LIST OF CASES.
 *
 * ROUND TRIP. Take bytes - any of the 256, drawn so that the ones a lexer can trip on come up far more often than chance
 * would give them (the quote, the backslash, "$", "{", "x", the digits, the line breaks, NUL, the bytes above 0x7f) - and
 * WRITE them as php would read them back: single quoted (only \\ and \' are escapes), double quoted (named escapes, \xH and
 * \xHH, \o to \ooo, \$ and \", every byte that is not printable written as an escape, hex and octal in whichever length keeps
 * the next byte from being read as one more digit), a heredoc, a nowdoc. The lexer finds the literal and kgenome_textual_value
 * must give back exactly the bytes that went in. The encoder is the test's own and is written from php's rules, so a value
 * that is wrong in the same way as the encoder would still have to be wrong about php.
 *
 * JOIN. The same bytes cut at random points into literals of random styles (including the empty one, one that ends in a
 * backslash, one that is nothing but an escaped quote), put together with "." and any mix of white space, comments and line
 * breaks on either side of every dot, and run through the form. Whatever the form does with them, the values of the literals
 * it leaves, read in order, are the bytes that went in; and when every piece was single quoted and none held a "$", an "@" or a
 * backslash, it left ONE literal. A join that moved a byte, dropped one or let an escape swallow its neighbour fails here with its
 * input printed.
 *
 * A KNOWN GAP, NOT PINNED: the form's seam guard (seam_ok) refuses a seam where a "$" or a backslash escape at the end of one text
 * could take what the next begins with, whatever the quote the join ends up in, and ONE refused seam keeps the whole chain of
 * literals from being joined: `'$' . '9' . '3'` stays three literals although '9' . '3' is safe. That costs completeness of the
 * folding, never a byte, which is what is checked; the sequences with those bytes are therefore only checked for their value.
 */

#include "textual_check.h"

static uint64_t rs = 0x9e3779b97f4a7c15u;

static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 32);
}

/* A byte, with the ones that matter drawn about half of the time. */
static uint8_t hot_byte(void)
{
	static const uint8_t hot[] = { '\'', '"', '\\', '$', '{', '}', 'x', 'u', 'e', 'n', 'r', 't', 'v', 'f', '0', '1', '3', '7', '8', '9', 'a', 'A', 'f', 'F',
				       'g', ' ', '\n', '\r', '\t', 0, 0x0b, 0x1b, 0x7f, 0x80, 0xff, '<', '?', '>', '/', '*', '#', ';', '.', '`', '%', 'E', 'O', 'T' };

	return rnd() & 1u ? hot[rnd() % sizeof hot] : (uint8_t)rnd();
}

struct buf {
	uint8_t b[2048];
	uint32_t n;
};

static void bput(struct buf *o, const void *p, uint32_t n)
{
	memcpy(o->b + o->n, p, n);
	o->n += n;
}

static void bputc(struct buf *o, uint8_t c)
{
	o->b[o->n++] = c;
}

static int is_hex(uint8_t c)
{
	return (c >= '0' && c <= '9') || ((c | 32u) >= 'a' && (c | 32u) <= 'f');
}

/* `v` written single quoted: only "\" and "'" are escaped. */
static void enc_sq(struct buf *o, const uint8_t *v, uint32_t n)
{
	uint32_t i;

	bputc(o, '\'');
	for (i = 0; i < n; i++) {
		if (v[i] == '\\' || v[i] == '\'')
			bputc(o, '\\');
		bputc(o, v[i]);
	}
	bputc(o, '\'');
}

/*
 * `v` written the double quoted way, inside the quotes (`quote` set) or inside a heredoc (clear: the quote is itself).
 * `next_digit` is whether the byte that will follow the escape is one the escape would absorb: a hex digit after "\x4", an octal one after "\1".
 */
static void enc_dq_body(struct buf *o, const uint8_t *v, uint32_t n, int quote)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint8_t c = v[i];
		uint8_t nx = i + 1u < n ? v[i + 1u] : 0;
		/* what comes next as written: a plain byte, or the backslash of an escape (neither is a digit) - except a plain digit */
		int plain_next_hex = i + 1u < n && is_hex(nx) && nx != '$' && nx != '\\' && nx != '"';
		int plain_next_oct = i + 1u < n && nx >= '0' && nx <= '7';
		char t[8];

		switch (c) {
		case '\\': case '$':
			bputc(o, '\\');
			bputc(o, c);
			continue;
		case '"':
			if (quote)
				bputc(o, '\\');
			bputc(o, c);
			continue;
		case '\n': bput(o, "\\n", 2); continue;
		case '\r': bput(o, "\\r", 2); continue;
		case '\t': bput(o, "\\t", 2); continue;
		case 0x0b: bput(o, "\\v", 2); continue;
		case 0x1b: bput(o, "\\e", 2); continue;
		case 0x0c: bput(o, "\\f", 2); continue;
		default:
			break;
		}
		if (c >= 0x20 && c < 0x7f && rnd() % 4u) {
			bputc(o, c);
			continue;
		}
		switch (rnd() % 3u) {
		case 0:         /* two hex digits, either case */
			snprintf(t, sizeof t, rnd() & 1u ? "\\x%02x" : "\\x%02X", c);
			bput(o, t, (uint32_t)strlen(t));
			break;
		case 1:         /* the shortest octal that the next byte cannot extend */
			if (plain_next_oct || c > 077u)
				snprintf(t, sizeof t, "\\%03o", c);
			else
				snprintf(t, sizeof t, "\\%o", c);
			bput(o, t, (uint32_t)strlen(t));
			break;
		default:        /* one hex digit when the value fits and nothing after could be a second */
			if (c < 16u && !plain_next_hex)
				snprintf(t, sizeof t, "\\x%x", c);
			else
				snprintf(t, sizeof t, "\\x%02x", c);
			bput(o, t, (uint32_t)strlen(t));
			break;
		}
	}
}

static void enc_dq(struct buf *o, const uint8_t *v, uint32_t n)
{
	bputc(o, '"');
	enc_dq_body(o, v, n, 1);
	bputc(o, '"');
}

static void shown(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		printf(p[i] >= 0x20 && p[i] < 0x7f && p[i] != '\\' ? "%c" : "\\x%02x", p[i]);
	printf("\n");
}

struct spans {
	struct kgenome_textual_span s[64];
	uint32_t n;
};

static int collect(void *u, const struct kgenome_textual_span *s)
{
	struct spans *a = u;

	if (s->kind == KGENOME_TEXTUAL_STRING && a->n < 64u)
		a->s[a->n++] = *s;
	return 1;
}

/* The string literals of `prog` in order, and their values concatenated into `out`. 0 when one has no value. */
static int values_of(const uint8_t *prog, uint32_t n, uint8_t *out, uint32_t cap, uint32_t *w, uint32_t *n_lit)
{
	struct spans a = { .n = 0 };
	struct kgenome_textual_lex_req lq = { .in = prog, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .sink = collect, .user = &a };
	struct kgenome_textual_lex_res ls;
	uint32_t i;

	*w = 0;
	kgenome_textual_lex(&lq, &ls);
	*n_lit = a.n;
	for (i = 0; i < a.n; i++) {
		struct kgenome_textual_value_req rq = { .lang = KGENOME_TEXTUAL_LANG_PHP, .lit = prog + a.s[i].off, .len = a.s[i].len,
							.open_len = a.s[i].open_len, .close_len = a.s[i].close_len,
							.flags = a.s[i].flags, .out = out + *w, .cap = cap - *w };
		struct kgenome_textual_value_res vr;

		if (kgenome_textual_value(&rq, &vr) != KGENOME_TEXTUAL_OK)
			return 0;
		*w += vr.n_out;
	}
	return 1;
}

static void round_trip(void)
{
	static const char *const style[] = { "single", "double", "heredoc", "nowdoc" };
	unsigned it, st;

	for (st = 0; st < 4u; st++)
		for (it = 0; it < 60000u; it++) {
			uint8_t v[48], got[4096];
			struct buf p = { .n = 0 };
			uint32_t n = rnd() % 40u, k, w, lits;

			for (k = 0; k < n; k++)
				v[k] = hot_byte();
			bput(&p, "<?php $a = ", 11);
			if (st == 0) {
				enc_sq(&p, v, n);
			} else if (st == 1) {
				enc_dq(&p, v, n);
			} else if (st == 2) {
				bput(&p, "<<<EOT\n", 7);
				enc_dq_body(&p, v, n, 0);
				bput(&p, "\nEOT", 4);
			} else {
				/* a nowdoc is the bytes as they are, on one line: no line break in it, and not the line that ends it */
				for (k = 0; k < n; k++)
					if (v[k] == '\n' || v[k] == '\r')
						v[k] = 'x';
				bput(&p, "<<<'EOT'\n", 9);
				bput(&p, v, n);
				bput(&p, "\nEOT", 4);
			}
			bput(&p, ";\n", 2);
			if (!values_of(p.b, p.n, got, sizeof got, &w, &lits) || lits != 1u || w != n || (n && memcmp(got, v, n))) {
				printf("  FAIL %s round trip (literals %u, value %u bytes, wanted %u): ", style[st], lits, w, n);
				shown(p.b, p.n);
				fails++;
				return;
			}
		}
}

/* ---- the join ---------------------------------------------------------------------------------- */

static void gap(struct buf *o)
{
	static const char *const g[] = { "", " ", "  ", "\n", "\t", "\r\n", "/**/", " /* a */ ", "//c\n", "# c\n", "/* ' \" */", "\f", "\n\n// x\n" };
	const char *s = g[rnd() % (sizeof g / sizeof g[0])];

	bput(o, s, (uint32_t)strlen(s));
}

static void join(void)
{
	unsigned it;

	for (it = 0; it < 120000u; it++) {
		uint8_t v[64], got[4096];
		struct buf p = { .n = 0 };
		uint32_t n = rnd() % 48u, k, w, lits, from = 0, pieces = 0;
		int all_sq = 1, guarded = 0;

		for (k = 0; k < n; k++) {
			v[k] = hot_byte();
			guarded |= v[k] == '$' || v[k] == '@' || v[k] == '\\';
		}
		bput(&p, "<?php $a = ", 11);
		for (;;) {
			uint32_t len = rnd() % 8u;

			if (len > n - from || rnd() % 5u == 0)
				len = n - from;
			if (rnd() % 7u == 0)
				len = 0;                /* an empty piece */
			if (rnd() & 1u) {
				enc_sq(&p, v + from, len);
			} else {
				enc_dq(&p, v + from, len);
				all_sq = 0;
			}
			from += len;
			pieces++;
			if (from == n && rnd() % 3u)
				break;
			if (pieces > 12u)
				break;
			gap(&p);
			bputc(&p, '.');
			gap(&p);
		}
		if (from < n) {         /* the pieces ran out before the bytes did: the last piece takes the rest */
			gap(&p);
			bputc(&p, '.');
			gap(&p);
			enc_sq(&p, v + from, n - from);
		}
		bput(&p, ";\n", 2);
		{
			struct kgenome_textual_form_req rq = { .in = p.b, .n = p.n, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = fbuf,
							       .cap = KGENOME_TEXTUAL_FORM_CAP(p.n) };
			struct kgenome_textual_form_res rr;
			enum kgenome_textual_status st = kgenome_textual_form(&rq, &rr);

			if (st != KGENOME_TEXTUAL_OK || !values_of(fbuf, rr.n_out, got, sizeof got, &w, &lits) || w != n || (n && memcmp(got, v, n))) {
				printf("  FAIL join: the form changed the bytes (status %d, %u bytes of %u): ", (int)st, w, n);
				shown(p.b, p.n);
				printf("  became: ");
				shown(fbuf, rr.n_out);
				fails++;
				return;
			}
			{
				/* what the form leaves is a form: a second pass joins nothing more and changes nothing */
				struct kgenome_textual_form_req r2 = { .in = fbuf, .n = rr.n_out, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = fbuf2,
								       .cap = KGENOME_TEXTUAL_FORM_CAP(rr.n_out) };
				struct kgenome_textual_form_res s2;

				if (kgenome_textual_form(&r2, &s2) != KGENOME_TEXTUAL_OK || s2.n_out != rr.n_out || memcmp(fbuf, fbuf2, rr.n_out)) {
					printf("  FAIL join: the form of the form is not the form: ");
					shown(p.b, p.n);
					printf("  became: ");
					shown(fbuf, rr.n_out);
					printf("  then:   ");
					shown(fbuf2, s2.n_out);
					fails++;
					return;
				}
			}
			if (all_sq && !guarded && lits != 1u) {
				printf("  FAIL join of single quoted pieces left %u literals: ", lits);
				shown(p.b, p.n);
				printf("  became: ");
				shown(fbuf, rr.n_out);
				fails++;
				return;
			}
		}
	}
}

/*
 * A SEAM THAT CANNOT BE JOINED ENDS ITS RUN AND NOTHING ELSE: the literal so far is closed, the operator stays as typed, and the
 * pieces from the refused one on are joined among themselves. Before this, one refused seam kept the whole chain from being joined.
 */
static void partial_runs(void)
{
	/* "$" then a name would read as the variable $x: refused; everything either side of it is joined */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = 'a'.'b'.'$'.'x';", "<?php $a='ab$'.'x';");
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = '$'.'9'.'3';", "<?php $a='$'.'93';");
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = 'x'.'$'.'9'.'3'.'$'.'y'.'z';", "<?php $a='x$'.'93$'.'yz';");
	/* "\x4" then "1" would read as "\x41": refused, and the pieces after it are still joined */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = \"\\x4\".\"1\".'b'.'c';", "<?php $a=\"\\x4\".'1bc';");
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = 'a' . 'b' . \"\\x4\" . \"1\" . 'q';", "<?php $a='ab'.\"\\x4\".'1q';");
	/* a refused seam at the very end leaves the last piece alone, with its own delimiters */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = 'p'.'q'.'$'.'r';", "<?php $a='pq$'.'r';");
	/* two refused seams in a row: three runs */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = '$'.'a'.'$'.'b';", "<?php $a='$'.'a$'.'b';");
	/* nothing to refuse: one literal, as before */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $a = 'a'.'b'.'c';", "<?php $a='abc';");
}

int main(void)
{
	partial_runs();
	round_trip();
	join();
	printf("textual php strings: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
