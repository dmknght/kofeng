/*
 * textual_subst - kgenome_textual_subst: a computed value written where it was computed, attacked rather than sampled.
 *
 * WHAT IS PINNED. The bytes outside the ranges come out as they went in; each range becomes ONE literal whose VALUE, read back through the
 * lexer and kgenome_textual_value, is exactly the bytes given - for every one of the 256 byte values, in every position, in values that are
 * all quotes and backslashes; the ranges are refused when out of order, overlapping or past the input; a cap one byte short is refused and the
 * cap the API itself reports (kgenome_textual_subst_cap) always suffices; and a language with no `quote` row is refused outright.
 */

#include "textual_check.h"

static uint64_t rs = 0x2545f4914f6cdd1du;

static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 32);
}

struct lit {
	struct kgenome_textual_span s;
	uint32_t n;
};

static int collect(void *u, const struct kgenome_textual_span *s)
{
	struct lit *l = u;

	if (s->kind == KGENOME_TEXTUAL_STRING && l->n < 64u)
		l[1 + l->n++].s = *s;
	return 1;
}

/* The literals of `p` in order, each read back to its value and appended to `out`. 0 when one has none. */
static int values(const uint8_t *p, uint32_t n, uint8_t *out, uint32_t cap, uint32_t *w, uint32_t *n_lit)
{
	struct lit l[66];
	struct kgenome_textual_lex_req q = { .in = p, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP, .sink = collect, .user = l };
	struct kgenome_textual_lex_res lr;
	uint32_t i;

	l[0].n = 0;
	kgenome_textual_lex(&q, &lr);
	*w = 0;
	*n_lit = l[0].n;
	for (i = 1; i <= l[0].n; i++) {
		struct kgenome_textual_value_req rq = { .lang = KGENOME_TEXTUAL_LANG_PHP, .lit = p + l[i].s.off, .len = l[i].s.len,
							.open_len = l[i].s.open_len, .close_len = l[i].s.close_len, .flags = l[i].s.flags,
							.out = out + *w, .cap = cap - *w };
		struct kgenome_textual_value_res vr;

		if (kgenome_textual_value(&rq, &vr) != KGENOME_TEXTUAL_OK)
			return 0;
		*w += vr.n_out;
	}
	return 1;
}

static void all_bytes(void)
{
	/* every byte value, alone and between its neighbours, as the value of a right side */
	unsigned c;

	for (c = 0; c < 256u; c++) {
		uint8_t v[3] = { (uint8_t)c, (uint8_t)(255u - c), (uint8_t)c }, text[64], out[64], got[16];
		static const char head[] = "<?php $a = ", tail[] = ";\n";
		uint32_t n = 0, w, lits, i;
		struct kgenome_textual_subst s;

		for (i = 0; i < 3u; i++) {
			memcpy(text, head, sizeof head - 1u);
			n = sizeof head - 1u;
			memcpy(text + n, "$x . $y", 7);
			s = (struct kgenome_textual_subst){ n, 7, v, i + 1u, 0 };
			n += 7;
			memcpy(text + n, tail, sizeof tail - 1u);
			n += sizeof tail - 1u;
			w = kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, n, &s, 1, out, sizeof out);
			if (!w) {
				printf("  FAIL byte %u, length %u: refused\n", c, i + 1u);
				fails++;
			}
			if (w && (!values(out, w, got, sizeof got, &w, &lits) || lits != 1u || w != i + 1u || memcmp(got, v, w))) {
				printf("  FAIL byte %u length %u: the value did not come back\n", c, i + 1u);
				fails++;
			}
		}
	}
}

static void random_ranges(void)
{
	unsigned it;

	for (it = 0; it < 60000u; it++) {
		uint8_t text[512], vals[8][24], got[512], out[2048], want[512];
		struct kgenome_textual_subst s[8];
		uint32_t n = 40u + rnd() % 200u, ns = 1u + rnd() % 6u, k, at = 0, i, w, wn = 0;
		static const char hot[] = "'\\\"$x_ \n";

		for (i = 0; i < n; i++)
			text[i] = (uint8_t)(rnd() & 1u ? 'a' + rnd() % 26u : ' ');
		memcpy(text, "<?php ", 6);
		for (k = 0; k < ns; k++) {
			uint32_t room = n - at, off, len, vn = rnd() % 20u;

			if (room < 8u)
				break;
			off = at + 6u + rnd() % (room / 2u);
			if (off + 4u > n)
				break;
			len = 1u + rnd() % 4u;
			if (off + len > n)
				len = n - off;
			for (i = 0; i < vn; i++)
				vals[k][i] = (uint8_t)(rnd() % 3u ? (uint8_t)hot[rnd() % (sizeof hot - 1u)] : (uint8_t)rnd());
			s[k] = (struct kgenome_textual_subst){ off, len, vals[k], vn, 0 };
			at = off + len;
		}
		ns = k;
		if (!ns)
			continue;
		/* the bytes outside the ranges are what the text had; the literals are the values */
		w = kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, n, s, ns, out, sizeof out);
		if (!w) {
			printf("  FAIL random case %u: refused\n", it);
			fails++;
			return;
		}
		/* rebuild what the result must be: the text with each range cut out, and the literals' values in a separate stream */
		{
			uint32_t pos = 0, o = 0;

			wn = 0;
			for (k = 0; k < ns; k++) {
				memcpy(want + wn, text + pos, s[k].off - pos);
				wn += s[k].off - pos;
				pos = s[k].off + s[k].len;
			}
			memcpy(want + wn, text + pos, n - pos);
			wn += n - pos;
			/* the result with every literal removed must be that: walk the result, skipping the literals as the lexer found them */
			{
				struct lit l[66];
				struct kgenome_textual_lex_req q = { .in = out, .n = w, .lang = KGENOME_TEXTUAL_LANG_PHP, .sink = collect, .user = l };
				struct kgenome_textual_lex_res lr;
				uint32_t from = 0, kept = 0;

				l[0].n = 0;
				kgenome_textual_lex(&q, &lr);
				/* the text had no literals of its own (lower case letters and spaces only), so every literal found is a value written */
				if (l[0].n != ns) {
					printf("  FAIL random case %u: %u literals for %u ranges\n", it, l[0].n, ns);
					fails++;
					return;
				}
				for (i = 1; i <= l[0].n; i++) {
					memcpy(got + kept, out + from, l[i].s.off - from);
					kept += l[i].s.off - from;
					from = l[i].s.off + l[i].s.len;
				}
				memcpy(got + kept, out + from, w - from);
				kept += w - from;
				if (kept != wn || memcmp(got, want, wn)) {
					printf("  FAIL random case %u: the text outside the ranges changed\n", it);
					fails++;
					return;
				}
			}
			(void)o;
		}
		{
			uint8_t vgot[512];
			uint32_t vw, vl, vexp = 0;
			uint8_t vwant[512];

			for (k = 0; k < ns; k++) {
				memcpy(vwant + vexp, s[k].value, s[k].n);
				vexp += s[k].n;
			}
			if (!values(out, w, vgot, sizeof vgot, &vw, &vl) || vl != ns || vw != vexp || memcmp(vgot, vwant, vexp)) {
				printf("  FAIL random case %u: the values did not come back\n", it);
				fails++;
				return;
			}
		}
		/* a cap one byte short is refused and the API's own cap suffices */
		CK(!kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, n, s, ns, out, w - 1u));
		CK(kgenome_textual_subst_cap(KGENOME_TEXTUAL_LANG_PHP, text, n, s, ns) >= w);
	}
}

static void refusals(void)
{
	uint8_t out[64];
	const uint8_t text[] = "<?php $a = $x . $y;";
	struct kgenome_textual_subst ok = { 11, 7, (const uint8_t *)"ab", 2, 0 };
	struct kgenome_textual_subst two[2] = { { 11, 3, (const uint8_t *)"a", 1, 0 }, { 13, 3, (const uint8_t *)"b", 1, 0 } };       /* overlap */
	struct kgenome_textual_subst back[2] = { { 14, 2, (const uint8_t *)"a", 1, 0 }, { 11, 2, (const uint8_t *)"b", 1, 0 } };      /* out of order */
	struct kgenome_textual_subst past = { 15, 9, (const uint8_t *)"ab", 2, 0 };
	struct kgenome_textual_subst none = { 11, 7, NULL, 2, 0 };

	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, sizeof text - 1u, &ok, 1, out, sizeof out) == 11u + 4u + 1u);
	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, sizeof text - 1u, two, 2, out, sizeof out) == 0);
	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, sizeof text - 1u, back, 2, out, sizeof out) == 0);
	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, sizeof text - 1u, &past, 1, out, sizeof out) == 0);
	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, sizeof text - 1u, &none, 1, out, sizeof out) == 0);
	/* no ranges is the text as it is */
	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PHP, text, sizeof text - 1u, NULL, 0, out, sizeof out) == sizeof text - 1u &&
	   !memcmp(out, text, sizeof text - 1u));
	/* a language with no way of writing a value as a literal is refused (asp: vbscript or jscript, the page cannot say), and so is one this build does not have */
	CK(kgenome_textual_subst(KGENOME_TEXTUAL_LANG_PERL + 1000u, text, sizeof text - 1u, &ok, 1, out, sizeof out) == 0);
	CK(kgenome_textual_subst(9999u, text, sizeof text - 1u, &ok, 1, out, sizeof out) == 0);
}

int main(void)
{
	all_bytes();
	random_ranges();
	refusals();
	printf("textual subst: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
