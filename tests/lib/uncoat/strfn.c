/*
 * strfn - the string functions of kuncoat_transform (REPLACE, TRANSLATE, SLICE, CASE, TRIM) and the RAW flag of the url
 * decode, attacked rather than sampled.
 *
 * WHAT IS CHECKED AGAINST WHAT. Every answer is compared with a reference written HERE and written differently from the
 * code under test (a quadratic scan from the left, a table walked from the end, an end index rather than a length), over
 * EVERY input of a small alphabet up to a length that exercises each branch: all strings over {a,b} to length 9 against
 * every search of one to three bytes and every replacement of nought to three, all strings over {a,b,c} to length 6 against
 * every pair list of one to three, every start and length from -12 to 12 over every prefix of a word, and the six trim bytes
 * and all 256 byte values for the case maps. The cases are exhaustive, not random, so a miss in one branch is a failure
 * with its case printed and not a coin that came up the other way.
 *
 * THE EDGE OF THE ROOM. Every answer is asked for with room for exactly it (OK, and the bytes right) and with room for one
 * byte less (OVER_BUDGET, and the guard page after the output untouched). The guard buffers of hostile_common.h end every
 * input and output flush against a PROT_NONE page, so a read or write past the stated length faults.
 *
 * THEN A FUZZ of whole steps - any algorithm of the five, any key, any numbers including INT32_MIN and INT32_MAX, any room -
 * that only asks for the contract: a status of the enum, `produced` within the room, nothing written past it.
 */

#define _GNU_SOURCE

#include "hostile_common.h"

#define BIG 70000u

static struct hv_gb gin, gout;
static uint8_t res[BIG];

static struct kuncoat_step mk(uint32_t algo, uint32_t flags, uint32_t k32, uint32_t k32b, const uint8_t *key, uint32_t klen)
{
	struct kuncoat_step s;

	memset(&s, 0, sizeof s);
	s.algo = algo;
	s.dir = KUNCOAT_DECODE;
	s.flags = flags;
	s.k32 = k32;
	s.k32b = k32b;
	s.key = key;
	s.key_len = klen;
	return s;
}

/* One call through the guard buffers; the answer is in `res`. */
static enum kuncoat_status T(const struct kuncoat_step *s, const uint8_t *in, size_t n, size_t cap, uint64_t *prod)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	uint64_t p = 0xDEADBEEFu;
	enum kuncoat_status st = kuncoat_transform(s, ip, n, op, cap, &p);

	CK(hv_status_ok(st));
	CK(p <= cap);
	CK(hv_out_canary_ok(op));
	if (p <= cap && p <= BIG)
		memcpy(res, op, (size_t)p);
	*prod = p;
	return st;
}

/*
 * The step must give exactly `want[0..wn)` with room for it, and refuse (OVER_BUDGET) with room for one less. `what` and `i`
 * name the case. A refusal leaves a PREFIX of the answer and nothing else the contract promises, so only the status and the
 * guard are checked there.
 */
static void exact(const struct kuncoat_step *s, const uint8_t *in, size_t n, const uint8_t *want, size_t wn, const char *what,
		  unsigned long i)
{
	uint64_t p;
	enum kuncoat_status st;

	if (!wn) {
		st = T(s, in, n, 1, &p);
		CKF(st == KUNCOAT_OK && p == 0, "%s %lu: an empty answer, got status %d produced %llu", what, i, (int)st, (unsigned long long)p);
		return;
	}
	st = T(s, in, n, wn, &p);
	CKF(st == KUNCOAT_OK && p == wn && !memcmp(res, want, wn), "%s %lu: status %d produced %llu of %zu (subject %.*s)", what, i,
	    (int)st, (unsigned long long)p, wn, (int)n, (const char *)in);
	st = T(s, in, n, wn - 1u ? wn - 1u : 1u, &p);
	if (wn > 1u)
		CKF(st == KUNCOAT_OVER_BUDGET, "%s %lu: one byte short must be over budget, got %d", what, i, (int)st);
	else
		CKF(st == KUNCOAT_OK || st == KUNCOAT_OVER_BUDGET, "%s %lu: status %d", what, i, (int)st);
}

/* ---- REPLACE: every subject, search and replacement over a small alphabet --------------------- */

static size_t ref_replace(const uint8_t *in, size_t n, const uint8_t *se, size_t sn, const uint8_t *re, size_t rn, uint8_t *out)
{
	size_t i = 0, w = 0, k;

	while (i < n) {
		int hit = i + sn <= n;

		for (k = 0; hit && k < sn; k++)
			hit = in[i + k] == se[k];
		if (hit) {
			memcpy(out + w, re, rn);
			w += rn;
			i += sn;
		} else {
			out[w++] = in[i++];
		}
	}
	return w;
}

/* The `idx`th string over {a,b} of length `len`, bits low to high. */
static void word2(uint8_t *o, unsigned idx, unsigned len)
{
	unsigned k;

	for (k = 0; k < len; k++)
		o[k] = (idx >> k & 1u) ? 'b' : 'a';
}

static void replace_exhaustive(void)
{
	uint8_t sub[16], se[4], re[4], key[8], want[64];
	unsigned sl, si, sel, sei, rl, ri;
	unsigned long cases = 0;

	for (sl = 0; sl <= 9u; sl++)
		for (si = 0; si < (1u << sl); si++) {
			word2(sub, si, sl);
			for (sel = 1; sel <= 3u; sel++)
				for (sei = 0; sei < (1u << sel); sei++) {
					word2(se, sei, sel);
					for (rl = 0; rl <= 3u; rl++)
						for (ri = 0; ri < (1u << rl); ri++) {
							size_t wn;
							struct kuncoat_step s;

							word2(re, ri, rl);
							memcpy(key, se, sel);
							memcpy(key + sel, re, rl);
							s = mk(KUNCOAT_ALGO_REPLACE, 0, sel, 0, key, sel + rl);
							wn = ref_replace(sub, sl, se, sel, re, rl, want);
							exact(&s, sub, sl, want, wn, "replace", cases++);
						}
				}
		}
	/* the cases that decide php's meaning, spelled out so a reference that is wrong the same way would still be caught */
	{
		static const struct { const char *in, *s, *r, *want; } K[] = {
			{ "aaa", "aa", "b", "ba" },             /* non-overlapping, from the left */
			{ "aaaa", "aa", "b", "bb" },
			{ "abab", "ab", "", "" },
			{ "hello", "l", "LL", "heLLLLo" },
			{ "ckrekatek_fuknkkction", "k", "", "create_function" },
			{ "xyz", "xyz", "xyz", "xyz" },
			{ "abc", "abcd", "x", "abc" },           /* a search longer than the subject */
			{ "a.b.c", ".", "", "abc" },
		};
		unsigned k;

		for (k = 0; k < sizeof K / sizeof K[0]; k++) {
			uint8_t kb[32];
			size_t sn = strlen(K[k].s), rn = strlen(K[k].r);
			struct kuncoat_step s;

			memcpy(kb, K[k].s, sn);
			memcpy(kb + sn, K[k].r, rn);
			s = mk(KUNCOAT_ALGO_REPLACE, 0, (uint32_t)sn, 0, kb, (uint32_t)(sn + rn));
			exact(&s, (const uint8_t *)K[k].in, strlen(K[k].in), (const uint8_t *)K[k].want, strlen(K[k].want), "replace known", k);
		}
	}
}

/* ---- TRANSLATE: every pair list over {a,b,c} --------------------------------------------------- */

static void word3(uint8_t *o, unsigned idx, unsigned len)
{
	unsigned k;

	for (k = 0; k < len; k++) {
		o[k] = (uint8_t)('a' + idx % 3u);
		idx /= 3u;
	}
}

static unsigned pow3(unsigned n)
{
	unsigned r = 1;

	while (n--)
		r *= 3u;
	return r;
}

static void translate_exhaustive(void)
{
	uint8_t sub[8], key[8], want[8];
	unsigned sl, si, k, fi, ti;
	unsigned long cases = 0;

	for (sl = 0; sl <= 6u; sl++)
		for (si = 0; si < pow3(sl); si++) {
			word3(sub, si, sl);
			for (k = 1; k <= 3u; k++)
				for (fi = 0; fi < pow3(k); fi++)
					for (ti = 0; ti < pow3(k); ti++) {
						uint8_t from[4], to[4];
						unsigned j, b;
						struct kuncoat_step s;

						word3(from, fi, k);
						word3(to, ti, k);
						memcpy(key, from, k);
						memcpy(key + k, to, k);
						/* a table walked from the LAST pair: the first one that names the byte, from the end, wins */
						for (b = 0; b < sl; b++) {
							want[b] = sub[b];
							for (j = k; j > 0; j--)
								if (from[j - 1u] == sub[b]) {
									want[b] = to[j - 1u];
									break;
								}
						}
						s = mk(KUNCOAT_ALGO_TRANSLATE, 0, k, 0, key, 2u * k);
						exact(&s, sub, sl, want, sl, "translate", cases++);
					}
		}
	{
		/* php: strtr("Hi all, I said", "ai", "eo") is "Ho ell, o seod"; a byte listed twice takes the later */
		static const uint8_t k1[] = { 'a', 'i', 'e', 'o' }, k2[] = { 'a', 'a', 'x', 'y' };
		struct kuncoat_step s = mk(KUNCOAT_ALGO_TRANSLATE, 0, 2, 0, k1, 4);

		exact(&s, (const uint8_t *)"Hi all, I said", 14, (const uint8_t *)"Ho ell, I seod", 14, "translate php", 0);
		s = mk(KUNCOAT_ALGO_TRANSLATE, 0, 2, 0, k2, 4);
		exact(&s, (const uint8_t *)"aa", 2, (const uint8_t *)"yy", 2, "translate later wins", 0);
	}
}

/* ---- SLICE: every start and length around the ends -------------------------------------------- */

/* substr as an END INDEX: the code under test counts a length; this says where it stops. */
static size_t ref_slice(const uint8_t *in, size_t n, long start, int has_len, long len, uint8_t *out)
{
	long L = (long)n, b, e;

	b = start < 0 ? (L + start < 0 ? 0 : L + start) : start;
	if (b > L)
		return 0;
	e = !has_len ? L : (len >= 0 ? b + len : L + len);
	if (e > L)
		e = L;
	if (e < b)
		e = b;
	memcpy(out, in + b, (size_t)(e - b));
	return (size_t)(e - b);
}

static void slice_exhaustive(void)
{
	static const uint8_t word[] = "abcdefgh";
	uint8_t want[16];
	unsigned long cases = 0;
	unsigned n;
	long st, ln;

	for (n = 0; n <= 8u; n++)
		for (st = -12; st <= 12; st++) {
			struct kuncoat_step s = mk(KUNCOAT_ALGO_SLICE, KUNCOAT_F_TOEND, (uint32_t)(int32_t)st, 0, NULL, 0);
			size_t wn = ref_slice(word, n, st, 0, 0, want);

			exact(&s, word, n, want, wn, "slice to end", cases++);
			for (ln = -12; ln <= 12; ln++) {
				s = mk(KUNCOAT_ALGO_SLICE, 0, (uint32_t)(int32_t)st, (uint32_t)(int32_t)ln, NULL, 0);
				wn = ref_slice(word, n, st, 1, ln, want);
				exact(&s, word, n, want, wn, "slice", cases++);
			}
		}
	{
		/* php's own manual: substr("abcdef", ...) */
		static const struct { long st; int has; long ln; const char *want; } K[] = {
			{ -1, 0, 0, "f" }, { -2, 0, 0, "ef" }, { -3, 1, 1, "d" }, { 0, 1, -1, "abcde" }, { 2, 1, -1, "cde" },
			{ 4, 1, -4, "" }, { -3, 1, -1, "de" }, { 6, 0, 0, "" }, { 7, 0, 0, "" }, { 0, 1, 0, "" }, { -9, 1, 2, "ab" },
		};
		unsigned k;

		for (k = 0; k < sizeof K / sizeof K[0]; k++) {
			struct kuncoat_step s = mk(KUNCOAT_ALGO_SLICE, K[k].has ? 0u : KUNCOAT_F_TOEND, (uint32_t)(int32_t)K[k].st,
						   (uint32_t)(int32_t)K[k].ln, NULL, 0);

			exact(&s, (const uint8_t *)"abcdef", 6, (const uint8_t *)K[k].want, strlen(K[k].want), "slice php", k);
		}
	}
	{
		/* the numbers nobody means: INT32_MIN and INT32_MAX in every place */
		static const long ext[] = { -2147483647L - 1L, -2147483647L, 2147483647L, 2147483646L };
		unsigned a, b;

		for (a = 0; a < 4u; a++)
			for (b = 0; b < 4u; b++) {
				struct kuncoat_step s = mk(KUNCOAT_ALGO_SLICE, 0, (uint32_t)(int32_t)ext[a], (uint32_t)(int32_t)ext[b], NULL, 0);
				size_t wn = ref_slice(word, 8, ext[a], 1, ext[b], want);

				exact(&s, word, 8, want, wn, "slice extreme", a * 4u + b);
			}
	}
}

/* ---- CASE and TRIM over every byte ------------------------------------------------------------ */

static void case_trim_all_bytes(void)
{
	uint8_t all[256], want[256];
	unsigned c, mode;

	for (c = 0; c < 256u; c++)
		all[c] = (uint8_t)c;
	for (mode = 0; mode < 4u; mode++) {
		struct kuncoat_step s = mk(KUNCOAT_ALGO_CASE, 0, mode, 0, NULL, 0);
		int up = mode & 1u, first = (mode & 2u) != 0;

		for (c = 0; c < 256u; c++) {
			uint8_t b = (uint8_t)c;

			if (!first || c == 0) {
				if (up && b >= 'a' && b <= 'z')
					b = (uint8_t)(b - 32u);
				if (!up && b >= 'A' && b <= 'Z')
					b = (uint8_t)(b + 32u);
			}
			want[c] = b;
		}
		exact(&s, all, 256, want, 256, "case all bytes", mode);
	}
	/* every byte that is not a letter is itself, in a 256-byte value of nothing but that byte */
	for (c = 0; c < 256u; c++) {
		uint8_t one = (uint8_t)c, w = (uint8_t)c;
		struct kuncoat_step s = mk(KUNCOAT_ALGO_CASE, 0, 1u, 0, NULL, 0);

		if (c >= 'a' && c <= 'z')
			w = (uint8_t)(c - 32u);
		exact(&s, &one, 1, &w, 1, "upper one byte", c);
	}
	{
		/* trim: exactly space \t \n \r NUL \v, from the end asked for, and a value of nothing else is empty */
		static const uint8_t ws[] = { ' ', '\t', '\n', '\r', 0, 0x0b };
		uint8_t buf[32];
		unsigned w, l, r;

		for (c = 0; c < 256u; c++) {
			int isws = c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0 || c == 0x0b;
			uint8_t b = (uint8_t)c, in3[3];
			struct kuncoat_step s = mk(KUNCOAT_ALGO_TRIM, 0, 3u, 0, NULL, 0);

			in3[0] = 'x';
			in3[1] = b;
			in3[2] = 'y';
			exact(&s, in3, 3, in3, 3, "trim keeps an inner byte", c);    /* inner bytes are never trimmed */
			in3[0] = b;
			in3[1] = 'm';
			in3[2] = b;
			if (isws)
				exact(&s, in3, 3, (const uint8_t *)"m", 1, "trim both ends", c);
			else
				exact(&s, in3, 3, in3, 3, "trim a non-space", c);
		}
		for (w = 0; w < 6u; w++)
			for (l = 0; l < 4u; l++)
				for (r = 0; r < 4u; r++) {
					uint8_t in[16], want2[16];
					size_t n = 0, wn = 0, k;
					unsigned mode2;

					for (k = 0; k < l; k++)
						in[n++] = ws[(w + k) % 6u];
					in[n++] = 'q';
					for (k = 0; k < r; k++)
						in[n++] = ws[(w + 2u * k) % 6u];
					for (mode2 = 1; mode2 <= 3u; mode2++) {
						struct kuncoat_step s = mk(KUNCOAT_ALGO_TRIM, 0, mode2, 0, NULL, 0);
						size_t from = (mode2 & 1u) ? l : 0, to = (mode2 & 2u) ? n - r : n;

						wn = to - from;
						memcpy(want2, in + from, wn);
						memcpy(buf, in, n);
						exact(&s, buf, n, want2, wn, "trim ends", w * 100u + l * 10u + r + mode2 * 1000u);
					}
				}
		/* a value of nothing but space is empty from either end */
		{
			uint8_t sp[5] = { ' ', '\t', '\n', 0, ' ' };
			struct kuncoat_step s = mk(KUNCOAT_ALGO_TRIM, 0, 1u, 0, NULL, 0);

			exact(&s, sp, 5, NULL, 0, "trim all space", 0);
		}
	}
}

/* ---- the url decode's RAW flag ---------------------------------------------------------------- */

static size_t ref_url(const uint8_t *in, size_t n, int raw, uint8_t *out)
{
	size_t i, w = 0;

	for (i = 0; i < n; i++) {
		if (in[i] == '%' && i + 2u < n) {
			int a = in[i + 1u], b = in[i + 2u];
			int va = a >= '0' && a <= '9' ? a - '0' : (a | 32) >= 'a' && (a | 32) <= 'f' ? (a | 32) - 'a' + 10 : -1;
			int vb = b >= '0' && b <= '9' ? b - '0' : (b | 32) >= 'a' && (b | 32) <= 'f' ? (b | 32) - 'a' + 10 : -1;

			if (va >= 0 && vb >= 0) {
				out[w++] = (uint8_t)(va * 16 + vb);
				i += 2u;
				continue;
			}
		}
		out[w++] = in[i] == '+' && !raw ? ' ' : in[i];
	}
	return w;
}

static void url_raw(void)
{
	static const char alpha[] = "%+a1F g";
	uint64_t seed = 0x5eed0001u;
	unsigned it;

	for (it = 0; it < 40000u; it++) {
		uint8_t in[12], want[12];
		unsigned n = hv_rng32(&seed) % 11u, k, raw;

		for (k = 0; k < n; k++)
			in[k] = (uint8_t)alpha[hv_rng32(&seed) % (sizeof alpha - 1u)];
		for (raw = 0; raw < 2u; raw++) {
			size_t wn = ref_url(in, n, (int)raw, want);
			struct kuncoat_step s = mk(KUNCOAT_ALGO_URL, KUNCOAT_F_LAX | (raw ? KUNCOAT_F_RAW : 0u), 0, 0, NULL, 0);
			uint64_t p;
			enum kuncoat_status st;

			if (!n)
				continue;
			st = T(&s, in, n, n + 1u, &p);
			CKF(st == KUNCOAT_OK && p == wn && (!wn || !memcmp(res, want, wn)), "url raw=%u case %u: status %d produced %llu wanted %zu (%.*s)",
			    raw, it, (int)st, (unsigned long long)p, wn, (int)n, (const char *)in);
		}
	}
	{
		/* the one difference, pinned: a "+" is a space for urldecode and a plus for rawurldecode */
		uint64_t p;
		struct kuncoat_step a = mk(KUNCOAT_ALGO_URL, KUNCOAT_F_LAX, 0, 0, NULL, 0), b = mk(KUNCOAT_ALGO_URL, KUNCOAT_F_LAX | KUNCOAT_F_RAW, 0, 0, NULL, 0);

		T(&a, (const uint8_t *)"a+b%2Bc", 7, 8, &p);
		CK(p == 5 && !memcmp(res, "a b+c", 5));
		T(&b, (const uint8_t *)"a+b%2Bc", 7, 8, &p);
		CK(p == 5 && !memcmp(res, "a+b+c", 5));
	}
}

/* ---- the hex decode's STRICT flag ---------------------------------------------------------------- */

/*
 * php's hex2bin reads pairs of digits and nothing else; the coding of kuncoat skips ' ' '\n' '\r' '\t' ':' ',' between them. Every string
 * over a small alphabet that has both kinds of byte, to length 7, in both modes, against a reference written here.
 */
static int hexv(uint8_t c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static void hex_strict(void)
{
	static const char alpha[] = "0aF :,\n";
	const unsigned na = (unsigned)(sizeof alpha - 1u);
	unsigned len, idx, k, strict;
	unsigned long cases = 0;

	for (len = 1; len <= 7u; len++) {
		unsigned total = 1;

		for (k = 0; k < len; k++)
			total *= na;
		for (idx = 0; idx < total; idx++) {
			uint8_t in[8], want[8];
			unsigned digits = 0, other = 0, rest = idx;
			size_t wn = 0;

			for (k = 0; k < len; k++) {
				in[k] = (uint8_t)alpha[rest % na];
				rest /= na;
				if (hexv(in[k]) >= 0)
					digits++;
				else
					other++;
			}
			for (strict = 0; strict < 2u; strict++) {
				struct kuncoat_step s = mk(KUNCOAT_ALGO_HEX, strict ? KUNCOAT_F_STRICT : 0u, 0, 0, NULL, 0);
				uint64_t p;
				enum kuncoat_status st = T(&s, in, len, len + 1u, &p);
				/* ok: an even number of digits, and (strict) nothing else */
				int ok = !(digits & 1u) && (!strict || !other);

				cases++;
				if (ok) {
					unsigned acc = 0, have = 0;

					for (k = 0, wn = 0; k < len; k++)
						if (hexv(in[k]) >= 0) {
							acc = acc << 4 | (unsigned)hexv(in[k]);
							if ((have += 4u) == 8u) {
								want[wn++] = (uint8_t)acc;
								have = 0;
							}
						}
				}
				CKF(ok ? (st == KUNCOAT_OK && p == wn && (!wn || !memcmp(res, want, wn))) : st != KUNCOAT_OK,
				    "hex strict=%u case %lu (%.*s): status %d produced %llu, %s", strict, cases, (int)len, (const char *)in, (int)st,
				    (unsigned long long)p, ok ? "wanted an answer" : "wanted a refusal");
			}
		}
	}
}

/* ---- the argument rules ----------------------------------------------------------------------- */

static void arg_rules(void)
{
	static const uint8_t key[] = "abcd";
	static const uint32_t algos[] = { KUNCOAT_ALGO_REPLACE, KUNCOAT_ALGO_TRANSLATE, KUNCOAT_ALGO_SLICE, KUNCOAT_ALGO_CASE, KUNCOAT_ALGO_TRIM };
	uint64_t p;
	unsigned a;
	struct kuncoat_step s;

	/* decode only: encode has no meaning for any of the five */
	for (a = 0; a < 5u; a++) {
		s = mk(algos[a], 0, 1, 0, key, 4);
		s.dir = KUNCOAT_ENCODE;
		CKF(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_UNSUPPORTED, "algo %u encode", algos[a]);
	}
	/* REPLACE: a key that is absent, a search of nothing, a search longer than the key */
	s = mk(KUNCOAT_ALGO_REPLACE, 0, 1, 0, NULL, 0);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	s = mk(KUNCOAT_ALGO_REPLACE, 0, 0, 0, key, 4);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	s = mk(KUNCOAT_ALGO_REPLACE, 0, 5, 0, key, 4);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	s = mk(KUNCOAT_ALGO_REPLACE, 0, 4, 0, key, 4);        /* replace "abcd" with nothing: valid */
	CK(T(&s, (const uint8_t *)"abcd", 4, 8, &p) == KUNCOAT_OK && p == 0);
	/* TRANSLATE: the key is exactly two lists */
	s = mk(KUNCOAT_ALGO_TRANSLATE, 0, 2, 0, key, 3);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	s = mk(KUNCOAT_ALGO_TRANSLATE, 0, 0, 0, key, 0);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	s = mk(KUNCOAT_ALGO_TRANSLATE, 0, 3, 0, key, 4);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	s = mk(KUNCOAT_ALGO_TRANSLATE, 0, 2, 0, NULL, 4);
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_BAD_ARG);
	/* a cap of nothing, and max_out below the answer */
	s = mk(KUNCOAT_ALGO_CASE, 0, 1, 0, NULL, 0);
	CK(T(&s, (const uint8_t *)"ab", 2, 0, &p) == KUNCOAT_OVER_BUDGET && p == 0);
	s.max_out = 1;
	CK(T(&s, (const uint8_t *)"ab", 2, 8, &p) == KUNCOAT_OVER_BUDGET && p == 1 && res[0] == 'A');
	/* an empty subject maps to nothing, with a valid step; with a bad one it is still the step that is refused */
	s = mk(KUNCOAT_ALGO_TRIM, 0, 3, 0, NULL, 0);
	CK(T(&s, (const uint8_t *)"", 0, 8, &p) == KUNCOAT_OK && p == 0);
	s = mk(KUNCOAT_ALGO_REPLACE, 0, 0, 0, key, 4);
	CK(T(&s, (const uint8_t *)"", 0, 8, &p) == KUNCOAT_BAD_ARG);
	/* growth: one byte to three, 20000 times, in a room of exactly the answer and one short of it */
	{
		static uint8_t big[20000], k3[4] = { 'a', 'x', 'y', 'z' };
		struct kuncoat_step g = mk(KUNCOAT_ALGO_REPLACE, 0, 1, 0, k3, 4);
		unsigned i;

		for (i = 0; i < sizeof big; i++)
			big[i] = 'a';
		CK(T(&g, big, sizeof big, 3u * sizeof big, &p) == KUNCOAT_OK && p == 3u * sizeof big && !memcmp(res, "xyzxyz", 6));
		CK(T(&g, big, sizeof big, 3u * sizeof big - 1u, &p) == KUNCOAT_OVER_BUDGET);
	}
}

/* ---- a fuzz of whole steps --------------------------------------------------------------------- */

static void fuzz_steps(void)
{
	static const uint32_t algos[] = { KUNCOAT_ALGO_REPLACE, KUNCOAT_ALGO_TRANSLATE, KUNCOAT_ALGO_SLICE, KUNCOAT_ALGO_CASE, KUNCOAT_ALGO_TRIM,
					  KUNCOAT_ALGO_URL, KUNCOAT_ALGO_B64, KUNCOAT_ALGO_HEX };
	uint64_t seed = 0xfeedbeefu;
	unsigned it;

	for (it = 0; it < 60000u; it++) {
		uint8_t in[40], key[24];
		unsigned n = hv_rng32(&seed) % 40u, kl = hv_rng32(&seed) % 24u, k;
		struct kuncoat_step s;
		uint64_t p;
		size_t cap = hv_rng32(&seed) % 60u;
		enum kuncoat_status st;

		for (k = 0; k < n; k++)
			in[k] = (uint8_t)hv_rng32(&seed);
		for (k = 0; k < kl; k++)
			key[k] = (uint8_t)hv_rng32(&seed);
		s = mk(algos[hv_rng32(&seed) % 8u], (hv_rng32(&seed) & 7u), hv_rng32(&seed) % 4u == 0 ? hv_rng32(&seed) : hv_rng32(&seed) % 6u,
		       hv_rng32(&seed) % 3u == 0 ? hv_rng32(&seed) : hv_rng32(&seed) % 30u, hv_rng32(&seed) % 5u ? key : NULL, kl);
		if (hv_rng32(&seed) % 6u == 0)
			s.max_out = hv_rng32(&seed) % 50u;
		st = T(&s, in, n, cap, &p);
		CKF(p <= cap || st == KUNCOAT_BAD_ARG, "fuzz %u: produced %llu of %zu", it, (unsigned long long)p, cap);
		CKF((int)st >= 0 && (int)st <= (int)KUNCOAT_BAD_ARG, "fuzz %u: status %d", it, (int)st);
	}
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, BIG) || !hv_gb_init(&gout, BIG)) {
		printf("strfn: cannot map guard buffers\n");
		return 1;
	}
	replace_exhaustive();
	translate_exhaustive();
	slice_exhaustive();
	case_trim_all_bytes();
	url_raw();
	hex_strict();
	arg_rules();
	fuzz_steps();
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("strfn");
}
