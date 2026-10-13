/*
 * api_transform - the public surface of transform.h, ciphers.h, codings.h and
 * status.h, one assertion per rule the headers state.
 *
 * What is covered here that no other test covers directly: kuncoat_cipher and
 * kuncoat_coding called on their own (the two entry points the dispatcher hides),
 * every algorithm id with a known answer computed INSIDE this file (RC4's and
 * base64's published vectors, XOR/counter/caesar/add/reverse by an independent
 * loop, the feedback and chain ciphers by an encoder written here), every status
 * the transform contract names, and the argument rules: NULL buffers, a key that
 * is absent or zero length, a caesar shift of 0 mod 26, an unknown algorithm, a
 * direction an algorithm has no inverse for, n == 0, a cap of 0, max_out smaller
 * and larger than cap.
 *
 * Every call goes through hostile_common.h's guard buffers: the input ends flush
 * against a PROT_NONE page and so does the output, so a read or a write one byte
 * past what was stated faults instead of passing.
 *
 * hostile_transform.c is the sibling that sweeps and mutates.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"

#define BIG 70000u

static struct hv_gb gin, gout;
static uint8_t res[BIG];

static struct kuncoat_step mk(uint32_t algo, uint32_t dir, uint32_t k32,
			      const uint8_t *key, uint32_t klen)
{
	struct kuncoat_step s;

	memset(&s, 0, sizeof s);
	s.algo = algo;
	s.dir = dir;
	s.k32 = k32;
	s.key = key;
	s.key_len = klen;
	return s;
}

/* One call through guard buffers; the bytes produced are copied to res. */
static enum kuncoat_status T(const struct kuncoat_step *s, const void *in, size_t n,
			     size_t cap, uint64_t *prod)
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
	if (prod)
		*prod = p;
	return st;
}

static int same(const void *a, const void *b, size_t n)
{
	return n == 0 || !memcmp(a, b, n);
}

/* ---- status.h ------------------------------------------------------------------ */

static void status_names(void)
{
	static const struct { enum kuncoat_status st; const char *name; } t[] = {
		{ KUNCOAT_OK, "ok" }, { KUNCOAT_STOPPED, "stopped" },
		{ KUNCOAT_TRUNCATED, "truncated" }, { KUNCOAT_CORRUPT, "corrupt" },
		{ KUNCOAT_UNSUPPORTED, "unsupported" },
		{ KUNCOAT_OVER_BUDGET, "over budget" }, { KUNCOAT_BAD_ARG, "bad argument" },
	};
	unsigned i, j;

	for (i = 0; i < sizeof t / sizeof t[0]; i++) {
		CK(kuncoat_status_name(t[i].st) != NULL);
		CK(!strcmp(kuncoat_status_name(t[i].st), t[i].name));
		for (j = 0; j < i; j++)
			CK(strcmp(kuncoat_status_name(t[i].st), kuncoat_status_name(t[j].st)));
	}
	/* Out-of-set values are answered "?" and never refused: the function runs on
	 * a failure path, and the pin enumerator is not a status. */
	CK(!strcmp(kuncoat_status_name(KUNCOAT__PIN_SIGNED), "?"));
	CK(!strcmp(kuncoat_status_name((enum kuncoat_status)7), "?"));
	CK(!strcmp(kuncoat_status_name((enum kuncoat_status)12345), "?"));
	CK(!strcmp(kuncoat_status_name((enum kuncoat_status)-77), "?"));
	/* The numeric values are an ABI (a module reads them). */
	CK(KUNCOAT_OK == 0 && KUNCOAT_STOPPED == 1 && KUNCOAT_TRUNCATED == 2 &&
	   KUNCOAT_CORRUPT == 3 && KUNCOAT_UNSUPPORTED == 4 && KUNCOAT_OVER_BUDGET == 5 &&
	   KUNCOAT_BAD_ARG == 6);
	CK((int)KUNCOAT__PIN_SIGNED < 0);
}

/* ---- argument rules ------------------------------------------------------------ */

static void arg_rules(void)
{
	static const uint8_t key[4] = { 1, 2, 3, 4 };
	uint8_t in[8], out[8];
	uint64_t p;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, key, 4);
	uint32_t a;

	memcpy(in, "abcdefgh", 8);
	/* NULL step / in / out: BAD_ARG, nothing read, produced still set to 0. */
	p = 99;
	CK(kuncoat_transform(NULL, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG && p == 0);
	p = 99;
	CK(kuncoat_transform(&s, NULL, 8, out, 8, &p) == KUNCOAT_BAD_ARG && p == 0);
	p = 99;
	CK(kuncoat_transform(&s, in, 8, NULL, 8, &p) == KUNCOAT_BAD_ARG && p == 0);
	/* produced may be NULL for every status. */
	CK(kuncoat_transform(NULL, in, 8, out, 8, NULL) == KUNCOAT_BAD_ARG);
	CK(kuncoat_transform(&s, in, 8, out, 8, NULL) == KUNCOAT_OK);
	CK(kuncoat_transform(&s, in, 8, out, 0, NULL) == KUNCOAT_OVER_BUDGET);

	/* keyed: no key / zero length key. The check is before the n == 0 shortcut. */
	s.key = NULL;
	p = 99;
	CK(kuncoat_transform(&s, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG && p == 0);
	CK(kuncoat_transform(&s, in, 0, out, 8, &p) == KUNCOAT_BAD_ARG);
	s.key = key;
	s.key_len = 0;
	CK(kuncoat_transform(&s, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG);
	s.algo = KUNCOAT_ALGO_RC4;
	CK(kuncoat_transform(&s, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG);
	s.key = NULL;
	s.key_len = 4;
	CK(kuncoat_transform(&s, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG);
	s.algo = KUNCOAT_ALGO_PLACEHOLDER_SUB;      /* key may be absent only if... no */
	CK(kuncoat_transform(&s, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG);
	s.key = key;
	s.key_len = 0;                              /* zero subtrahends is a plain copy */
	CK(kuncoat_transform(&s, in, 8, out, 8, &p) == KUNCOAT_OK && p == 8);

	/* caesar: a shift that is 0 mod 26 is not a coding, in both directions. */
	for (a = 0; a < 6; a++) {
		static const uint32_t k[] = { 0, 26, 52, 26u * 1000u, 0xFFFFFFFFu - 0xFFFFFFFFu % 26u,
					      26u * 165191049u };
		struct kuncoat_step c = mk(KUNCOAT_ALGO_CAESAR, a & 1u, k[a], NULL, 0);

		CKF(kuncoat_transform(&c, in, 8, out, 8, &p) == KUNCOAT_BAD_ARG,
		    "k32 %u", k[a]);
	}
	{
		struct kuncoat_step c = mk(KUNCOAT_ALGO_CAESAR, KUNCOAT_ENCODE, 1, NULL, 0);

		CK(kuncoat_transform(&c, in, 8, out, 8, &p) == KUNCOAT_OK);
	}

	/* unknown algorithm / direction. */
	{
		static const uint32_t bad[] = { 0, 7, 8, 15, 22, 23, 24, 100, 0x10000u, 0xFFFFFFFFu };
		struct kuncoat_step u;

		for (a = 0; a < sizeof bad / sizeof bad[0]; a++) {
			u = mk(bad[a], KUNCOAT_DECODE, 5, key, 4);
			p = 99;
			CKF(kuncoat_transform(&u, in, 8, out, 8, &p) == KUNCOAT_UNSUPPORTED && p == 0,
			    "algo %u", bad[a]);
			CK(kuncoat_transform(&u, in, 0, out, 8, &p) == KUNCOAT_UNSUPPORTED);
		}
		for (a = 1; a <= 21; a++) {
			static const uint32_t dirs[] = { 2, 3, 0x80000000u, 0xFFFFFFFFu };
			unsigned d;

			if (a > 6 && a < 16)
				continue;
			for (d = 0; d < 4; d++) {
				u = mk(a, dirs[d], 5, key, 4);
				CKF(kuncoat_transform(&u, in, 8, out, 8, &p) == KUNCOAT_UNSUPPORTED,
				    "algo %u dir %u", a, dirs[d]);
			}
		}
	}
	/* The three decode-only ciphers have no ENCODE. */
	{
		static const uint32_t donly[] = { KUNCOAT_ALGO_XOR_ADD32, KUNCOAT_ALGO_PLACEHOLDER_SUB,
						  KUNCOAT_ALGO_X86_SUB_CHAIN };
		struct kuncoat_step u;

		for (a = 0; a < 3; a++) {
			u = mk(donly[a], KUNCOAT_ENCODE, 0, key, 4);
			CK(kuncoat_transform(&u, in, 8, out, 8, &p) == KUNCOAT_UNSUPPORTED);
			CK(kuncoat_transform(&u, in, 0, out, 8, &p) == KUNCOAT_UNSUPPORTED);
		}
	}
	/* n == 0 is complete and empty, for every algorithm that is usable. */
	for (a = 1; a <= 21; a++) {
		struct kuncoat_step u = mk(a, KUNCOAT_DECODE, 3, key, 4);

		if (a > 6 && a < 16)
			continue;
		p = 99;
		CKF(kuncoat_transform(&u, in, 0, out, 0, &p) == KUNCOAT_OK && p == 0, "algo %u", a);
		p = 99;
		CKF(kuncoat_transform(&u, in, 0, out, 8, &p) == KUNCOAT_OK && p == 0, "algo %u", a);
	}
	/* cap 0 with input: OVER_BUDGET and nothing written. */
	for (a = 1; a <= 21; a++) {
		struct kuncoat_step u = mk(a, KUNCOAT_DECODE, 3, key, 4);

		if (a > 6 && a < 16)
			continue;
		memset(out, 0x5A, sizeof out);
		p = 99;
		CKF(kuncoat_transform(&u, in, 8, out, 0, &p) == KUNCOAT_OVER_BUDGET && p == 0,
		    "algo %u", a);
		CK(out[0] == 0x5A);
	}
}

/* max_out is the smaller of the two bounds, and 0 means "cap alone". */
static void budget_rules(void)
{
	static const uint8_t key[1] = { 0x55 };
	uint8_t in[16], expect[16];
	uint64_t p;
	unsigned i;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_ENCODE, 0, key, 1);

	for (i = 0; i < 16; i++) {
		in[i] = (uint8_t)(i * 17u);
		expect[i] = (uint8_t)(in[i] ^ 0x55u);
	}
	/* cap == n: complete. cap == n-1: OVER_BUDGET with the first n-1 bytes. */
	CK(T(&s, in, 16, 16, &p) == KUNCOAT_OK && p == 16 && same(res, expect, 16));
	CK(T(&s, in, 16, 17, &p) == KUNCOAT_OK && p == 16 && same(res, expect, 16));
	CK(T(&s, in, 16, 15, &p) == KUNCOAT_OVER_BUDGET && p == 15 && same(res, expect, 15));
	CK(T(&s, in, 16, 1, &p) == KUNCOAT_OVER_BUDGET && p == 1 && res[0] == expect[0]);
	CK(T(&s, in, 16, 60000, &p) == KUNCOAT_OK && p == 16);
	/* max_out below cap wins; above cap loses; 0 is ignored. */
	s.max_out = 5;
	CK(T(&s, in, 16, 16, &p) == KUNCOAT_OVER_BUDGET && p == 5 && same(res, expect, 5));
	s.max_out = 16;
	CK(T(&s, in, 16, 64, &p) == KUNCOAT_OK && p == 16);
	s.max_out = 15;
	CK(T(&s, in, 16, 64, &p) == KUNCOAT_OVER_BUDGET && p == 15);
	s.max_out = 1000;
	CK(T(&s, in, 16, 8, &p) == KUNCOAT_OVER_BUDGET && p == 8);
	s.max_out = ~0ull;
	CK(T(&s, in, 16, 16, &p) == KUNCOAT_OK && p == 16);
	/* An absurd cap is a ceiling, not an allocation: only 16 bytes are written. */
	{
		uint8_t out[16];

		s.max_out = 0;
		CK(kuncoat_transform(&s, in, 16, out, ~0ull, &p) == KUNCOAT_OK && p == 16);
		CK(same(out, expect, 16));
	}
}

/* ---- known answers: the keyed ciphers ------------------------------------------ */

/* An independent RC4: the textbook one, not read from the product. */
static void ref_rc4(const uint8_t *key, size_t kl, const uint8_t *in, size_t n, uint8_t *out)
{
	uint8_t S[256], t;
	unsigned a, i = 0, j = 0;
	size_t k;

	for (a = 0; a < 256; a++)
		S[a] = (uint8_t)a;
	for (a = 0, j = 0; a < 256; a++) {
		j = (j + S[a] + key[a % kl]) & 255u;
		t = S[a]; S[a] = S[j]; S[j] = t;
	}
	i = j = 0;
	for (k = 0; k < n; k++) {
		i = (i + 1u) & 255u;
		j = (j + S[i]) & 255u;
		t = S[i]; S[i] = S[j]; S[j] = t;
		out[k] = (uint8_t)(in[k] ^ S[(S[i] + S[j]) & 255u]);
	}
}

static void kat_rc4(void)
{
	/* The vectors every RC4 reference lists (Wikipedia / the draft). */
	static const struct { const char *key, *pt; uint8_t ct[14]; size_t n; } v[] = {
		{ "Key", "Plaintext", { 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3 }, 9 },
		{ "Wiki", "pedia", { 0x10, 0x21, 0xBF, 0x04, 0x20 }, 5 },
		{ "Secret", "Attack at dawn", { 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38,
						0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 }, 14 },
	};
	unsigned i;
	uint64_t p, rs = 0x9e3779b97f4a7c15ull;
	uint8_t key[600], in[700], want[700];

	for (i = 0; i < 3; i++) {
		struct kuncoat_step s = mk(KUNCOAT_ALGO_RC4, KUNCOAT_DECODE, 0,
					   (const uint8_t *)v[i].key, (uint32_t)strlen(v[i].key));

		CK(T(&s, v[i].pt, v[i].n, v[i].n, &p) == KUNCOAT_OK && p == v[i].n);
		CK(same(res, v[i].ct, v[i].n));
		s.dir = KUNCOAT_ENCODE;                 /* its own inverse */
		CK(T(&s, v[i].ct, v[i].n, v[i].n, &p) == KUNCOAT_OK && same(res, v[i].pt, v[i].n));
	}
	/* Random keys of every length that matters: 1, 2, 255, 256, 257, 300, 512, 600
	 * (a key longer than the 256-byte state is read modulo its length). */
	{
		static const unsigned kl[] = { 1, 2, 3, 16, 255, 256, 257, 300, 512, 600 };

		for (i = 0; i < sizeof kl / sizeof kl[0]; i++) {
			unsigned n = 1u + hv_rng32(&rs) % 650u, j;
			struct kuncoat_step s;

			for (j = 0; j < kl[i]; j++)
				key[j] = (uint8_t)hv_rng32(&rs);
			for (j = 0; j < n; j++)
				in[j] = (uint8_t)hv_rng32(&rs);
			ref_rc4(key, kl[i], in, n, want);
			s = mk(KUNCOAT_ALGO_RC4, KUNCOAT_DECODE, 0, key, kl[i]);
			CKF(T(&s, in, n, n, &p) == KUNCOAT_OK && p == n && same(res, want, n),
			    "key_len %u n %u", kl[i], n);
		}
	}
	/* In place, the same answer. */
	{
		uint8_t buf[64];
		struct kuncoat_step s = mk(KUNCOAT_ALGO_RC4, KUNCOAT_DECODE, 0,
					   (const uint8_t *)"Key", 3);

		memcpy(buf, "Plaintext", 9);
		CK(kuncoat_transform(&s, buf, 9, buf, 9, &p) == KUNCOAT_OK && p == 9);
		CK(same(buf, v[0].ct, 9));
	}
}

static void kat_xor(void)
{
	uint8_t key[300], in[1200], want[1200];
	uint64_t p, rs = 42;
	unsigned i, j;
	static const unsigned kl[] = { 1, 2, 3, 7, 255, 256, 299 };

	for (i = 0; i < sizeof in; i++)
		in[i] = (uint8_t)hv_rng32(&rs);
	for (i = 0; i < sizeof kl / sizeof kl[0]; i++) {
		struct kuncoat_step s;
		size_t n;

		for (j = 0; j < kl[i]; j++)
			key[j] = (uint8_t)(hv_rng32(&rs) | (j == 0));
		for (n = 0; n <= 1200; n += n < 8 ? 1u : 97u) {
			for (j = 0; j < n; j++)
				want[j] = (uint8_t)(in[j] ^ key[j % kl[i]]);
			s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, key, kl[i]);
			CKF(T(&s, in, n, n, &p) == KUNCOAT_OK && p == n && same(res, want, n),
			    "key_len %u n %zu", kl[i], n);
			s.dir = KUNCOAT_ENCODE;
			CKF(T(&s, in, n, n, &p) == KUNCOAT_OK && same(res, want, n),
			    "enc key_len %u n %zu", kl[i], n);
		}
	}
	/* A one byte key is the typed byte; a key of zeros is the identity. */
	{
		static const uint8_t k0[5] = { 0, 0, 0, 0, 0 };
		struct kuncoat_step s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, k0, 5);

		CK(T(&s, in, 100, 100, &p) == KUNCOAT_OK && same(res, in, 100));
	}
	/* XOR_COUNTER: in[i] ^ (uint8_t)(k32 + i), beyond 255 and with a wide k32. */
	{
		static const uint32_t k[] = { 0, 1, 0xFF, 0x100, 0x12345678u, 0xFFFFFFFFu };

		for (i = 0; i < 6; i++) {
			struct kuncoat_step s = mk(KUNCOAT_ALGO_XOR_COUNTER, KUNCOAT_DECODE,
						   k[i], NULL, 0);

			for (j = 0; j < 1200; j++)
				want[j] = (uint8_t)(in[j] ^ (uint8_t)(k[i] + j));
			CKF(T(&s, in, 1200, 1200, &p) == KUNCOAT_OK && p == 1200 &&
			    same(res, want, 1200), "k32 %#x", k[i]);
			s.dir = KUNCOAT_ENCODE;
			CK(T(&s, in, 1200, 1200, &p) == KUNCOAT_OK && same(res, want, 1200));
			CK(T(&s, in, 1200, 1199, &p) == KUNCOAT_OVER_BUDGET && p == 1199 &&
			   same(res, want, 1199));
		}
	}
}

static void kat_add32(void)
{
	uint32_t pt[8] = { 0x11223344u, 0x55667788u, 0xdeadbeefu, 1, 0xFFFFFFFFu, 7, 0, 0x99999999u };
	uint8_t enc[32], want[32];
	uint64_t p;
	unsigned i;
	const uint32_t key = 0xA5A55A5Au;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_XOR_ADD32, KUNCOAT_DECODE, key, NULL, 0);

	enc_add32(pt, 8, key, enc);
	for (i = 0; i < 8; i++) {
		want[4 * i] = (uint8_t)pt[i];
		want[4 * i + 1] = (uint8_t)(pt[i] >> 8);
		want[4 * i + 2] = (uint8_t)(pt[i] >> 16);
		want[4 * i + 3] = (uint8_t)(pt[i] >> 24);
	}
	/* The first zero plaintext dword (index 6) is emitted and ends it: the dword
	 * after it is never looked at. 28 bytes out of 32. */
	CK(T(&s, enc, 32, 32, &p) == KUNCOAT_OK && p == 28 && same(res, want, 28));
	CK(T(&s, enc, 32, 28, &p) == KUNCOAT_OK && p == 28);
	/* One byte less room: the zero dword does not fit. */
	CK(T(&s, enc, 32, 27, &p) == KUNCOAT_OVER_BUDGET && p == 24 && same(res, want, 24));
	CK(T(&s, enc, 32, 3, &p) == KUNCOAT_OVER_BUDGET && p == 0);
	/* Input out before the terminator: TRUNCATED, whole dwords only. */
	CK(T(&s, enc, 24, 64, &p) == KUNCOAT_TRUNCATED && p == 24 && same(res, want, 24));
	CK(T(&s, enc, 23, 64, &p) == KUNCOAT_TRUNCATED && p == 20 && same(res, want, 20));
	CK(T(&s, enc, 3, 64, &p) == KUNCOAT_TRUNCATED && p == 0);
	CK(T(&s, enc, 1, 64, &p) == KUNCOAT_TRUNCATED && p == 0);
	/* Room runs out and input remains: OVER_BUDGET, not TRUNCATED. */
	CK(T(&s, enc, 24, 8, &p) == KUNCOAT_OVER_BUDGET && p == 8);
	/* A terminator in the first dword. */
	{
		uint32_t z[2] = { 0, 5 };
		uint8_t e[8];

		enc_add32(z, 2, 0x77u, e);
		s.k32 = 0x77u;
		CK(T(&s, e, 8, 8, &p) == KUNCOAT_OK && p == 4 && !res[0] && !res[3]);
		s.k32 = key;
	}
	/* A dword that needs the feedback to come out right: wrong key, wrong bytes. */
	s.k32 = key + 1u;
	CK(T(&s, enc, 32, 32, &p) != KUNCOAT_OK || !same(res, want, 28));
}

static void kat_placeholder(void)
{
	/* template: bytes equal to `mark` are replaced, in order, by mark - sub[k]. */
	uint8_t tpl[16] = { 'A', 0x90, 'B', 0x90, 'C', 0x90, 'D', 0x90, 0x90, 'E', 0, 0, 0, 0, 0, 0 };
	static const uint8_t sub[3] = { 1, 2, 0x90 };
	uint8_t want[16];
	uint64_t p;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_PLACEHOLDER_SUB, KUNCOAT_DECODE, 0x90, sub, 3);

	memcpy(want, tpl, 16);
	want[1] = (uint8_t)(0x90 - 1);
	want[3] = (uint8_t)(0x90 - 2);
	want[5] = (uint8_t)(0x90 - 0x90);
	CK(T(&s, tpl, 16, 16, &p) == KUNCOAT_OK && p == 16 && same(res, want, 16));
	/* fewer placeholders than subtrahends: the rest are ignored. */
	{
		static const uint8_t many[40] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		struct kuncoat_step m = mk(KUNCOAT_ALGO_PLACEHOLDER_SUB, KUNCOAT_DECODE, 0x90, many, 40);

		CK(T(&m, tpl, 16, 16, &p) == KUNCOAT_OK && p == 16);
		CK(res[1] == 0x8F && res[3] == 0x8F && res[5] == 0x8F && res[7] == 0x8F && res[8] == 0x8F);
	}
	/* The output is the template's length: cap one short is OVER_BUDGET. */
	CK(T(&s, tpl, 16, 15, &p) == KUNCOAT_OVER_BUDGET && p == 15 && same(res, want, 15));
	/* key_len 0 is a copy; the placeholder byte may be any k32 (only the low byte counts). */
	s.key_len = 0;
	CK(T(&s, tpl, 16, 16, &p) == KUNCOAT_OK && same(res, tpl, 16));
	s.key_len = 3;
	s.k32 = 0xABCDEF90u;
	CK(T(&s, tpl, 16, 16, &p) == KUNCOAT_OK && same(res, want, 16));
	/* In place. */
	{
		uint8_t buf[16];

		memcpy(buf, tpl, 16);
		CK(kuncoat_transform(&s, buf, 16, buf, 16, &p) == KUNCOAT_OK && same(buf, want, 16));
	}
}

static void kat_chain(void)
{
	uint32_t pt[5] = { 0x41424344u, 0x45464748u, 0, 0xFFFFFFFFu, 0x01020304u };
	uint8_t chain[128], want[20];
	uint64_t p;
	size_t n, i;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_X86_SUB_CHAIN, KUNCOAT_DECODE, 0, NULL, 0);

	for (i = 0; i < 5; i++) {
		want[4 * i] = (uint8_t)pt[i];
		want[4 * i + 1] = (uint8_t)(pt[i] >> 8);
		want[4 * i + 2] = (uint8_t)(pt[i] >> 16);
		want[4 * i + 3] = (uint8_t)(pt[i] >> 24);
	}
	n = enc_chain(pt, 5, chain);
	chain[n] = 0xC3;                        /* ret: not part of the chain, ends it */
	/* The cap is exactly the payload. Every dword is out and the chain is complete, but
	 * the loop leaves at m == room before it has read the terminator, so it cannot
	 * tell "ended" from "more chain" and says OVER_BUDGET. */
	KM_CHECK(T(&s, chain, n + 1, 20, &p) == KUNCOAT_OK,
		 "X86_SUB_CHAIN whose payload exactly fills cap is reported OVER_BUDGET (complete answer)",
		 "SUB_CHAIN_EXACT_CAP (libuncoat/decryptors/ciphers.c sub_chain: while (at < n && m < room) exits before the terminator is read)");
	CK(p == 20 && same(res, want, 20));
	CK(T(&s, chain, n + 1, 24, &p) == KUNCOAT_OK && p == 20 && same(res, want, 20));
	CK(T(&s, chain, n + 1, 64, &p) == KUNCOAT_OK && p == 20 && same(res, want, 20));
	/* No terminator and the input is all chain: TRUNCATED, with what it had. */
	CK(T(&s, chain, n, 64, &p) == KUNCOAT_TRUNCATED && p == 20 && same(res, want, 20));
	/* A cut instruction. */
	CK(T(&s, chain, 12, 64, &p) == KUNCOAT_TRUNCATED && p == 0);
	/* Room for 4 of 5 dwords with chain left: OVER_BUDGET; room below one dword too. */
	CK(T(&s, chain, n + 1, 16, &p) == KUNCOAT_OVER_BUDGET && p == 16);
	/* transform.h: OVER_BUDGET output is "the real beginning" of the answer. The chain
	 * builds the payload downward, so the dwords it has when the room ends are the LAST
	 * of the payload, reversed: the 16 bytes are not the first 16 of the 20. */
	KM_CHECK(same(res, want, 16),
		 "X86_SUB_CHAIN OVER_BUDGET output is not the beginning of the payload (it is its tail)",
		 "SUB_CHAIN_CAP_TAIL (libuncoat/decryptors/ciphers.c sub_chain: stops after `room` pushes, which are the payload's last dwords)");
	CK(T(&s, chain, n + 1, 3, &p) == KUNCOAT_OVER_BUDGET && p == 0);
	CK(T(&s, chain, n + 1, 19, &p) == KUNCOAT_OVER_BUDGET && p == 16);
	/* The accepted dwords are the LAST pushed, reversed: a prefix of the push order. */
	{
		uint32_t two[2] = { 0x11111111u, 0x22222222u };
		uint8_t c2[64];
		size_t m = enc_chain(two, 2, c2);

		c2[m] = 0xC3;
		CK(T(&s, c2, m + 1, 12, &p) == KUNCOAT_OK && p == 8 &&
		   res[0] == 0x11 && res[4] == 0x22);
	}
	/* Pushes before the register is zeroed are not payload. */
	{
		static const uint8_t early[] = { 0x50, 0x50, 0x25, 0, 0, 0, 0, 0x50, 0xC3 };

		CK(T(&s, early, sizeof early, 64, &p) == KUNCOAT_OK && p == 4 &&
		   !res[0] && !res[1] && !res[2] && !res[3]);
	}
	/* The no-op stack bytes (push esp, pop eax, pop esp) belong to the chain. */
	{
		static const uint8_t noise[] = { 0x25, 0, 0, 0, 0, 0x54, 0x58, 0x5c, 0x50, 0x90 };

		CK(T(&s, noise, sizeof noise, 64, &p) == KUNCOAT_OK && p == 4);
	}
	/* Input that is not a chain at all ends at once, complete and empty. */
	{
		static const uint8_t junk[] = { 0x90, 0x90 };

		CK(T(&s, junk, 2, 64, &p) == KUNCOAT_OK && p == 0);
	}
}

/* ---- known answers: the codings ------------------------------------------------ */

static void kat_b64(void)
{
	static const struct { const char *pt, *enc; } v[] = {
		{ "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
		{ "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
	};
	unsigned i;
	uint64_t p;
	struct kuncoat_step e = mk(KUNCOAT_ALGO_B64, KUNCOAT_ENCODE, 0, NULL, 0);
	struct kuncoat_step d = mk(KUNCOAT_ALGO_B64, KUNCOAT_DECODE, 0, NULL, 0);

	for (i = 0; i < 7; i++) {
		size_t pl = strlen(v[i].pt), el = strlen(v[i].enc);

		CK(T(&e, v[i].pt, pl, el, &p) == KUNCOAT_OK && p == el && same(res, v[i].enc, el));
		if (el) {
			CK(T(&e, v[i].pt, pl, el - 1, &p) == KUNCOAT_OVER_BUDGET && p < el);
			CK(p % 4u == 0);                /* whole quads only */
		}
		CK(T(&d, v[i].enc, el, pl, &p) == KUNCOAT_OK && p == pl && same(res, v[i].pt, pl));
		CK(T(&d, v[i].enc, el, pl + 9, &p) == KUNCOAT_OK && p == pl);
		if (pl)
			CK(T(&d, v[i].enc, el, pl - 1, &p) == KUNCOAT_OVER_BUDGET && p == pl - 1);
	}
	/* Unpadded and wrapped text: the padding and the white space are not data. */
	CK(T(&d, "Zm9vYg", 6, 8, &p) == KUNCOAT_OK && p == 4 && same(res, "foob", 4));
	CK(T(&d, "Zm9v\r\nYmFy\n", 11, 8, &p) == KUNCOAT_OK && p == 6 && same(res, "foobar", 6));
	CK(T(&d, " \tZm9v YmFy", 11, 8, &p) == KUNCOAT_OK && p == 6);
	/* Anything else is CORRUPT, with the real prefix: a byte at a time up to the bad one. */
	CK(T(&d, "Zm9v*mFy", 8, 8, &p) == KUNCOAT_CORRUPT && p == 3 && same(res, "foo", 3));
	CK(T(&d, "Zm9v-_mFy", 9, 8, &p) == KUNCOAT_CORRUPT);    /* url alphabet is not base64 */
	CK(T(&d, "\xff", 1, 8, &p) == KUNCOAT_CORRUPT);
	CK(T(&d, "\0", 1, 8, &p) == KUNCOAT_CORRUPT);
	/* KUNCOAT_F_LAX skips them. */
	d.flags = KUNCOAT_F_LAX;
	CK(T(&d, "Zm9v*YmFy", 9, 8, &p) == KUNCOAT_OK && p == 6 && same(res, "foobar", 6));
	CK(T(&d, "\xff\xfe\x01", 3, 8, &p) == KUNCOAT_OK && p == 0);
	CK(T(&d, "Zm9v*YmFy", 9, 3, &p) == KUNCOAT_OVER_BUDGET && p == 3);
	d.flags = 0;
	/* A 6-bit group left over (a single char) decodes to nothing and is OK. */
	CK(T(&d, "Z", 1, 8, &p) == KUNCOAT_OK && p == 0);
	/* Round trip of every length 0..300 and every cap around the true size. */
	{
		uint8_t pt[300], enc[500];
		uint64_t q, rs = 5;
		unsigned n, j;

		for (j = 0; j < sizeof pt; j++)
			pt[j] = (uint8_t)hv_rng32(&rs);
		for (n = 0; n <= 300; n++) {
			size_t el = (n + 2u) / 3u * 4u;

			CKF(T(&e, pt, n, el, &q) == KUNCOAT_OK && q == el, "n %u", n);
			memcpy(enc, res, el);
			CKF(T(&d, enc, el, n, &q) == KUNCOAT_OK && q == n && same(res, pt, n), "n %u", n);
		}
	}
}

static void kat_hex(void)
{
	uint64_t p;
	struct kuncoat_step e = mk(KUNCOAT_ALGO_HEX, KUNCOAT_ENCODE, 0, NULL, 0);
	struct kuncoat_step d = mk(KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, 0, NULL, 0);
	static const uint8_t raw[] = { 0x00, 0x0f, 0xa5, 0xff, 0x10 };
	uint64_t pp;

	CK(T(&e, raw, 5, 10, &p) == KUNCOAT_OK && p == 10 && same(res, "000FA5FF10", 10));
	CK(T(&e, raw, 5, 9, &p) == KUNCOAT_OVER_BUDGET && p == 8);     /* whole bytes only */
	CK(T(&e, raw, 5, 1, &p) == KUNCOAT_OVER_BUDGET && p == 0);
	CK(T(&d, "000FA5FF10", 10, 5, &p) == KUNCOAT_OK && p == 5 && same(res, raw, 5));
	CK(T(&d, "000fa5ff10", 10, 5, &p) == KUNCOAT_OK && same(res, raw, 5));
	CK(T(&d, "00 0F:A5,FF\t10\r\n", 16, 5, &p) == KUNCOAT_OK && p == 5 && same(res, raw, 5));
	CK(T(&d, "000FA5FF10", 10, 4, &p) == KUNCOAT_OVER_BUDGET && p == 4);
	CK(T(&d, "000FA5FF10", 10, 3, &p) == KUNCOAT_OVER_BUDGET && p == 3);
	/* An odd digit is TRUNCATED and the digit is dropped. */
	CK(T(&d, "0F0", 3, 8, &p) == KUNCOAT_TRUNCATED && p == 1 && res[0] == 0x0F);
	CK(T(&d, "F", 1, 8, &p) == KUNCOAT_TRUNCATED && p == 0);
	/* A nibble split by a separator is still a byte ("A B" == 0xAB). */
	CK(T(&d, "A B", 3, 8, &p) == KUNCOAT_OK && p == 1 && res[0] == 0xAB);
	CK(T(&d, "0G", 2, 8, &p) == KUNCOAT_CORRUPT);
	CK(T(&d, "0x41", 4, 8, &p) == KUNCOAT_CORRUPT);
	CK(T(&d, ">", 1, 8, &p) == KUNCOAT_CORRUPT);   /* '>' ends ASCIIHex, not this coding */
	/* Every byte value round-trips. */
	{
		uint8_t all[256], hexed[512];
		unsigned i;

		for (i = 0; i < 256; i++)
			all[i] = (uint8_t)i;
		CK(T(&e, all, 256, 512, &pp) == KUNCOAT_OK && pp == 512);
		memcpy(hexed, res, 512);
		CK(T(&d, hexed, 512, 256, &pp) == KUNCOAT_OK && pp == 256 && same(res, all, 256));
	}
}

static void kat_url(void)
{
	uint64_t p;
	struct kuncoat_step e = mk(KUNCOAT_ALGO_URL, KUNCOAT_ENCODE, 0, NULL, 0);
	struct kuncoat_step d = mk(KUNCOAT_ALGO_URL, KUNCOAT_DECODE, 0, NULL, 0);
	unsigned c;

	/* RFC 3986 unreserved stays; everything else, '+' and ' ' included, is %XX upper. */
	CK(T(&e, "a-b_c.d~Z9", 10, 10, &p) == KUNCOAT_OK && p == 10 && same(res, "a-b_c.d~Z9", 10));
	CK(T(&e, "a b+c/", 6, 18, &p) == KUNCOAT_OK && p == 12 && same(res, "a%20b%2Bc%2F", 12));
	CK(T(&e, "a b+c/", 6, 12, &p) == KUNCOAT_OK && p == 12 && same(res, "a%20b%2Bc%2F", 12));
	CK(T(&e, "a b+c/", 6, 11, &p) == KUNCOAT_OVER_BUDGET && p == 9);
	CK(T(&e, "\xff", 1, 2, &p) == KUNCOAT_OVER_BUDGET && p == 0);
	CK(T(&e, "\xff", 1, 3, &p) == KUNCOAT_OK && p == 3 && same(res, "%FF", 3));
	for (c = 0; c < 256; c++) {
		uint8_t ch = (uint8_t)c, enc[3];
		uint64_t q;
		int unres = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			    c == '-' || c == '_' || c == '.' || c == '~';

		CKF(T(&e, &ch, 1, 3, &q) == KUNCOAT_OK && q == (unres ? 1u : 3u), "byte %u", c);
		memcpy(enc, res, 3);
		if (!unres) {
			CKF(T(&d, enc, 3, 1, &q) == KUNCOAT_OK && q == 1 && res[0] == ch, "byte %u", c);
		}
	}
	/* Decode: '+' is a space, %xx either case, at least one escape is required. */
	CK(T(&d, "a+b%20c%2b%2B", 13, 16, &p) == KUNCOAT_OK && p == 7 && same(res, "a b c++", 7));
	CK(T(&d, "a%41", 4, 8, &p) == KUNCOAT_OK && p == 2 && same(res, "aA", 2));
	CK(T(&d, "plain", 5, 8, &p) == KUNCOAT_CORRUPT);        /* no escape at all */
	CK(T(&d, "a+b", 3, 8, &p) == KUNCOAT_CORRUPT);          /* '+' alone is not an escape */
	CK(T(&d, "100%", 4, 8, &p) == KUNCOAT_TRUNCATED);       /* a cut escape */
	CK(T(&d, "a%4", 3, 8, &p) == KUNCOAT_TRUNCATED);
	CK(T(&d, "%zz1", 4, 8, &p) == KUNCOAT_CORRUPT);         /* not an escape */
	CK(T(&d, "%4g", 3, 8, &p) == KUNCOAT_CORRUPT);
	CK(T(&d, "%41%4", 5, 8, &p) == KUNCOAT_TRUNCATED && p == 1);
	CK(T(&d, "%41%41", 6, 1, &p) == KUNCOAT_OVER_BUDGET && p == 1);
	CK(T(&d, "%41%41", 6, 2, &p) == KUNCOAT_OK && p == 2);
	/* LAX keeps a stray % and needs no escape. */
	d.flags = KUNCOAT_F_LAX;
	CK(T(&d, "100%", 4, 8, &p) == KUNCOAT_OK && p == 4 && same(res, "100%", 4));
	CK(T(&d, "50%zz", 5, 8, &p) == KUNCOAT_OK && p == 5 && same(res, "50%zz", 5));
	CK(T(&d, "plain", 5, 8, &p) == KUNCOAT_OK && p == 5);
	CK(T(&d, "a+b", 3, 8, &p) == KUNCOAT_OK && p == 3 && res[1] == ' ');
	CK(T(&d, "%4", 2, 8, &p) == KUNCOAT_OK && p == 2);
	d.flags = 0;
}

static void kat_simple(void)
{
	uint8_t in[300], want[300];
	uint64_t p, rs = 77;
	unsigned i, k;
	static const uint32_t shifts[] = { 1, 3, 13, 25, 27, 52 + 7, 0x80000001u, 0xFFFFFFFFu };

	for (i = 0; i < sizeof in; i++)
		in[i] = (uint8_t)hv_rng32(&rs);
	/* ADD: dir DECODE adds, ENCODE subtracts; only the low byte of k32 counts. */
	{
		static const uint32_t ks[] = { 0, 1, 0x80, 0xFF, 0x100, 0x1234, 0xFFFFFFFFu };

		for (k = 0; k < 7; k++) {
			struct kuncoat_step d = mk(KUNCOAT_ALGO_ADD, KUNCOAT_DECODE, ks[k], NULL, 0);
			struct kuncoat_step e = mk(KUNCOAT_ALGO_ADD, KUNCOAT_ENCODE, ks[k], NULL, 0);

			for (i = 0; i < 300; i++)
				want[i] = (uint8_t)(in[i] + (uint8_t)ks[k]);
			CKF(T(&d, in, 300, 300, &p) == KUNCOAT_OK && same(res, want, 300), "k %#x", ks[k]);
			for (i = 0; i < 300; i++)
				want[i] = (uint8_t)(in[i] - (uint8_t)ks[k]);
			CKF(T(&e, in, 300, 300, &p) == KUNCOAT_OK && same(res, want, 300), "k %#x", ks[k]);
			CK(T(&d, in, 300, 299, &p) == KUNCOAT_OVER_BUDGET && p == 299);
		}
	}
	/* CAESAR: letters only, shift k32 % 26; decode shifts back. */
	{
		uint8_t txt[256];

		for (i = 0; i < 256; i++)
			txt[i] = (uint8_t)i;
		for (k = 0; k < sizeof shifts / sizeof shifts[0]; k++) {
			struct kuncoat_step e = mk(KUNCOAT_ALGO_CAESAR, KUNCOAT_ENCODE, shifts[k], NULL, 0);
			struct kuncoat_step d = mk(KUNCOAT_ALGO_CAESAR, KUNCOAT_DECODE, shifts[k], NULL, 0);
			unsigned sh = shifts[k] % 26u;
			uint8_t enc[256];

			for (i = 0; i < 256; i++) {
				uint8_t c = txt[i];

				if (c >= 'a' && c <= 'z')
					c = (uint8_t)('a' + (c - 'a' + sh) % 26u);
				else if (c >= 'A' && c <= 'Z')
					c = (uint8_t)('A' + (c - 'A' + sh) % 26u);
				want[i] = c;
			}
			CKF(T(&e, txt, 256, 256, &p) == KUNCOAT_OK && same(res, want, 256), "k %u", shifts[k]);
			memcpy(enc, res, 256);
			CKF(T(&d, enc, 256, 256, &p) == KUNCOAT_OK && same(res, txt, 256), "k %u", shifts[k]);
			/* non-letters are untouched */
			for (i = 0; i < 256; i++)
				if (!((i >= 'a' && i <= 'z') || (i >= 'A' && i <= 'Z')))
					CK(enc[i] == txt[i]);
		}
		/* rot13 is its own inverse and "Hello" -> "Uryyb". */
		{
			struct kuncoat_step r = mk(KUNCOAT_ALGO_CAESAR, KUNCOAT_ENCODE, 13, NULL, 0);

			CK(T(&r, "Hello, World", 12, 12, &p) == KUNCOAT_OK && same(res, "Uryyb, Jbeyq", 12));
			r.dir = KUNCOAT_DECODE;
			CK(T(&r, "Uryyb, Jbeyq", 12, 12, &p) == KUNCOAT_OK && same(res, "Hello, World", 12));
		}
	}
	/* REVERSE: both directions, and an exact cap is complete. */
	{
		struct kuncoat_step r = mk(KUNCOAT_ALGO_REVERSE, KUNCOAT_DECODE, 0, NULL, 0);

		for (i = 0; i < 300; i++)
			want[i] = in[299 - i];
		CK(T(&r, in, 300, 300, &p) == KUNCOAT_OK && p == 300 && same(res, want, 300));
		r.dir = KUNCOAT_ENCODE;
		CK(T(&r, in, 300, 300, &p) == KUNCOAT_OK && same(res, want, 300));
		CK(T(&r, in, 300, 299, &p) == KUNCOAT_OVER_BUDGET && p == 299 && same(res, want, 299));
		CK(T(&r, in, 1, 1, &p) == KUNCOAT_OK && p == 1 && res[0] == in[0]);
	}
}

/* ---- kuncoat_cipher / kuncoat_coding, called directly -------------------------- */

static void direct_entries(void)
{
	static const uint8_t key[2] = { 0x11, 0x22 };
	uint8_t in[16], out[32];
	uint64_t w, want_w;
	struct kuncoat_step s;
	unsigned i;

	for (i = 0; i < 16; i++)
		in[i] = (uint8_t)(i + 1);
	/* Each entry accepts its own algorithms and says UNSUPPORTED to the other's. */
	for (i = 1; i <= 21; i++) {
		int is_cipher = i >= 1 && i <= 6;
		int is_coding = i >= 16 && i <= 21;
		enum kuncoat_status c1, c2;
		uint64_t w1, w2;

		if (!is_cipher && !is_coding)
			continue;
		s = mk(i, KUNCOAT_DECODE, 3, key, 2);
		w = 0;
		c1 = kuncoat_cipher(&s, in, 16, out, 32, &w);
		w1 = w;
		w = 0;
		c2 = kuncoat_coding(&s, in, 16, out, 32, &w);
		w2 = w;
		if (is_cipher) {
			CKF(c1 != KUNCOAT_UNSUPPORTED, "cipher algo %u", i);
			CKF(c2 == KUNCOAT_UNSUPPORTED && w2 == 0, "coding got cipher algo %u", i);
		} else {
			CKF(c2 != KUNCOAT_UNSUPPORTED, "coding algo %u", i);
			CKF(c1 == KUNCOAT_UNSUPPORTED && w1 == 0, "cipher got coding algo %u", i);
		}
	}
	/* algo ids that are nothing. */
	for (i = 0; i < 4; i++) {
		static const uint32_t bad[] = { 0, 7, 15, 99 };

		s = mk(bad[i], KUNCOAT_DECODE, 3, key, 2);
		w = 0;
		CK(kuncoat_cipher(&s, in, 16, out, 32, &w) == KUNCOAT_UNSUPPORTED && w == 0);
		CK(kuncoat_coding(&s, in, 16, out, 32, &w) == KUNCOAT_UNSUPPORTED && w == 0);
	}
	/* They are the same routines the dispatcher runs: same bytes, same count. */
	s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, key, 2);
	w = 0;
	CK(kuncoat_cipher(&s, in, 16, out, 32, &w) == KUNCOAT_OK && w == 16);
	for (i = 0; i < 16; i++)
		CK(out[i] == (uint8_t)(in[i] ^ key[i & 1u]));
	s = mk(KUNCOAT_ALGO_HEX, KUNCOAT_ENCODE, 0, NULL, 0);
	w = 0;
	CK(kuncoat_coding(&s, in, 4, out, 32, &w) == KUNCOAT_OK && w == 8 && !memcmp(out, "01020304", 8));
	/* A cap short of the work is OVER_BUDGET from the entries too (no dispatcher
	 * in front of them): w is what was written. */
	w = 0;
	CK(kuncoat_coding(&s, in, 4, out, 5, &w) == KUNCOAT_OVER_BUDGET && w == 4);
	s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, key, 2);
	w = 0;
	CK(kuncoat_cipher(&s, in, 16, out, 7, &w) == KUNCOAT_OVER_BUDGET && w == 7);
	w = 0;
	CK(kuncoat_cipher(&s, in, 16, out, 0, &w) == KUNCOAT_OVER_BUDGET && w == 0);
	/* They APPEND: with *w preset the output continues at out[*w] and the first
	 * bytes are untouched. */
	memset(out, 0x77, sizeof out);
	w = 5;
	want_w = 5u + 16u;
	CK(kuncoat_cipher(&s, in, 16, out, 32, &w) == KUNCOAT_OK && w == want_w);
	CK(out[0] == 0x77 && out[4] == 0x77);
}

/* KNOWN-MISS: the status of an entry called with *w preset. */
static void direct_append_status(void)
{
	static const uint8_t key[1] = { 0x11 };
	uint8_t in[10] = { 0 }, out[32];
	uint64_t w = 5;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, key, 1);
	enum kuncoat_status r;

	/* ten input bytes, appended at out[5], with 12 bytes of room: the loop stops when
	 * *w reaches 12, after seven of the ten, and the answer should be OVER_BUDGET.
	 * transform_private.h's kuncoat_room_end(w, n) compares the ABSOLUTE write index
	 * with n, so 12 < 10 is false and the answer is OK for a cut result. */
	r = kuncoat_cipher(&s, in, 10, out, 12, &w);
	CK(w == 12);
	KM_CHECK(r == KUNCOAT_OVER_BUDGET,
		 "kuncoat_cipher(*w=5, n=10, cap=12) reports OK for a result cut at 7 of 10 bytes",
		 "ROOM_END_ABSOLUTE_INDEX (libuncoat/transform_private.h kuncoat_room_end)");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, BIG) || !hv_gb_init(&gout, BIG)) {
		printf("api_transform: cannot map guard buffers\n");
		return 1;
	}
	status_names();
	arg_rules();
	budget_rules();
	kat_rc4();
	kat_xor();
	kat_add32();
	kat_placeholder();
	kat_chain();
	kat_b64();
	kat_hex();
	kat_url();
	kat_simple();
	direct_entries();
	direct_append_status();
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("api_transform");
}
