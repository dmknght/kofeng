/*
 * hostile_transform - kuncoat_transform against input and parameters that are not
 * what a friendly caller sends.
 *
 * For every algorithm and direction a valid input is built here, then:
 *
 *   OUTPUT CAP      every cap from 0 to the true size + 3, the output buffer exactly
 *                   `cap` bytes against a PROT_NONE page: a byte written past the cap
 *                   faults. What came out must be a prefix of the full answer, and a
 *                   cap at or above the true size must give the full answer.
 *   TRUNCATION      the input cut at EVERY length, the input buffer ending at a
 *                   PROT_NONE page: a byte read past n faults.
 *   BIT FLIPS       every bit of every input byte flipped, one at a time.
 *   EXACT OUTPUT    the output buffer exactly the size of the answer and cap = 2^64-1:
 *                   the caller's buffer, not the cap, is what the decoder must not
 *                   outgrow when the stated room is a lie of "plenty".
 *   ALIASING        in == out for every algorithm (a safe, garbled answer is fine for
 *                   the ones that need separate buffers; a fault is not), and the
 *                   documented overlaps of B64 and HEX decode with out BEFORE in.
 *   RANDOM STEPS    a fixed-seed stream of steps: any algorithm id, any direction,
 *                   any flags, a key of any length in a guard buffer of exactly that
 *                   length, any max_out, any n and cap - never a fault, always a valid
 *                   status, produced never above either bound.
 *
 * Each group runs in a forked child with an alarm (hostile_common.h), so a crash or a
 * hang is reported with the case number instead of ending the runner.
 */

#define _GNU_SOURCE

#include "hostile_common.h"
#include "hostile_enc.h"

#define BIG 4096u

static struct hv_gb gin, gout, gkey;

struct kase {
	const char     *name;
	struct kuncoat_step s;
	uint8_t         in[600];
	size_t          n;
	int             prefix;     /* a prefix of the input gives a prefix of the output */
};

static uint8_t ref[BIG * 4];
static size_t  ref_len;

static enum kuncoat_status run_ref(const struct kase *k)
{
	uint64_t p = 0;
	enum kuncoat_status st = kuncoat_transform(&k->s, k->in, k->n, ref, sizeof ref, &p);

	ref_len = (size_t)p;
	return st;
}

/* ---- the cases ------------------------------------------------------------------ */

static const uint8_t KEY3[3] = { 0x6b, 0x33, 0x79 };
static uint8_t keybuf[4096];

static void add(struct kase *k, unsigned *nk, const char *name, uint32_t algo, uint32_t dir,
		uint32_t k32, const uint8_t *key, uint32_t klen, int prefix)
{
	struct kase *c = &k[(*nk)++];

	memset(c, 0, sizeof *c);
	c->name = name;
	c->s.algo = algo;
	c->s.dir = dir;
	c->s.k32 = k32;
	c->s.key = key;
	c->s.key_len = klen;
	c->prefix = prefix;
}

static unsigned build_cases(struct kase *k)
{
	unsigned nk = 0, i;
	uint8_t plain[200];
	uint32_t pt[40];
	uint64_t rs = 99;
	struct kase *c;

	hv_body(plain, sizeof plain, 5);
	for (i = 0; i < 40; i++)
		pt[i] = hv_rng32(&rs) | 1u;
	pt[37] = 0;
	for (i = 0; i < sizeof keybuf; i++)
		keybuf[i] = (uint8_t)hv_rng32(&rs);

	add(k, &nk, "xor_key", KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, KEY3, 3, 1);
	memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
	add(k, &nk, "xor_key_long", KUNCOAT_ALGO_XOR_KEY, KUNCOAT_ENCODE, 0, keybuf, 257, 1);
	memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
	add(k, &nk, "xor_counter", KUNCOAT_ALGO_XOR_COUNTER, KUNCOAT_DECODE, 0xFFFFFFF0u, NULL, 0, 1);
	memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
	add(k, &nk, "rc4", KUNCOAT_ALGO_RC4, KUNCOAT_DECODE, 0, keybuf, 300, 1);
	memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
	add(k, &nk, "xor_add32", KUNCOAT_ALGO_XOR_ADD32, KUNCOAT_DECODE, 0x1234u, NULL, 0, 1);
	k[nk - 1].n = enc_add32(pt, 40, 0x1234u, k[nk - 1].in);
	add(k, &nk, "placeholder", KUNCOAT_ALGO_PLACEHOLDER_SUB, KUNCOAT_DECODE, 0x90, keybuf, 8, 0);
	memset(plain + 20, 0x90, 6);
	memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
	add(k, &nk, "sub_chain", KUNCOAT_ALGO_X86_SUB_CHAIN, KUNCOAT_DECODE, 0, NULL, 0, 0);
	k[nk - 1].n = enc_chain(pt, 30, k[nk - 1].in);
	k[nk - 1].in[k[nk - 1].n++] = 0xC3;
	hv_body(plain, sizeof plain, 5);
	for (i = 0; i < 2; i++) {
		add(k, &nk, i ? "b64_enc" : "b64_dec", KUNCOAT_ALGO_B64, i ? KUNCOAT_ENCODE : KUNCOAT_DECODE,
		    0, NULL, 0, i == 0);
		c = &k[nk - 1];
		if (i) {
			memcpy(c->in, plain, 200); c->n = 200;
		} else {
			const char *t = "SGVsbG8sIHdvcmxkIQ==\r\nZm9vYmFyIGZvb2Jhcg==\nYWJj ZGVm";

			c->n = strlen(t); memcpy(c->in, t, c->n);
		}
		add(k, &nk, i ? "hex_enc" : "hex_dec", KUNCOAT_ALGO_HEX, i ? KUNCOAT_ENCODE : KUNCOAT_DECODE,
		    0, NULL, 0, i == 0);
		c = &k[nk - 1];
		if (i) {
			memcpy(c->in, plain, 200); c->n = 200;
		} else {
			const char *t = "48 65:6c,6C 6f\t20\r\n77 6F 72 6c 64 DEADbeef 00ff";

			c->n = strlen(t); memcpy(c->in, t, c->n);
		}
		add(k, &nk, i ? "url_enc" : "url_dec", KUNCOAT_ALGO_URL, i ? KUNCOAT_ENCODE : KUNCOAT_DECODE,
		    0, NULL, 0, i == 0);
		c = &k[nk - 1];
		if (i) {
			memcpy(c->in, plain, 200); c->n = 200;
		} else {
			const char *t = "a+b%20c%2F%3d%00%ff~-_.rest+of+it%41%42";

			c->n = strlen(t); memcpy(c->in, t, c->n);
		}
		add(k, &nk, i ? "add_enc" : "add_dec", KUNCOAT_ALGO_ADD, i ? KUNCOAT_ENCODE : KUNCOAT_DECODE,
		    0x1A5, NULL, 0, 1);
		memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
		add(k, &nk, i ? "caesar_enc" : "caesar_dec", KUNCOAT_ALGO_CAESAR,
		    i ? KUNCOAT_ENCODE : KUNCOAT_DECODE, 0x80000007u, NULL, 0, 1);
		memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
		add(k, &nk, i ? "reverse_enc" : "reverse_dec", KUNCOAT_ALGO_REVERSE,
		    i ? KUNCOAT_ENCODE : KUNCOAT_DECODE, 0, NULL, 0, 0);
		memcpy(k[nk - 1].in, plain, 200); k[nk - 1].n = 200;
	}
	return nk;
}

/* ---- one case: the sweeps -------------------------------------------------------- */

static enum kuncoat_status call(const struct kase *k, const uint8_t *src, size_t n, size_t cap,
				uint64_t maxout, uint64_t *p, uint8_t *keep)
{
	const uint8_t *ip = hv_in(&gin, src, n);
	uint8_t *op = hv_out(&gout, cap);
	const uint8_t *kp = k->s.key;
	struct kuncoat_step s = k->s;
	enum kuncoat_status st;

	if (kp) {
		uint8_t *g = hv_gb_at(&gkey, s.key_len);

		memcpy(g, kp, s.key_len);
		s.key = g;
	}
	s.max_out = maxout;
	*p = 0xABABABABull;
	st = kuncoat_transform(&s, ip, n, op, cap, p);
	CKF(hv_status_ok(st), "%s: status %d", k->name, (int)st);
	CKF(*p <= cap, "%s: produced %llu > cap %zu", k->name, (unsigned long long)*p, cap);
	CKF(hv_out_canary_ok(op), "%s: wrote before the output", k->name);
	if (keep && *p <= cap)
		memcpy(keep, op, (size_t)*p);
	return st;
}

static int sweep_case(void *arg)
{
	const struct kase *k = arg;
	enum kuncoat_status st0 = run_ref(k), st;
	size_t full = ref_len, c, n, bit;
	uint64_t p;
	static uint8_t got[BIG * 4], mut[600];
	int chain = k->s.algo == KUNCOAT_ALGO_X86_SUB_CHAIN;

	CKF(st0 == KUNCOAT_OK, "%s: the reference run is %s", k->name, kuncoat_status_name(st0));
	hv_at(1, 0);
	/* every cap */
	for (c = 0; c <= full + 3u && c <= BIG; c++) {
		hv_at(1, c);
		st = call(k, k->in, k->n, c, 0, &p, got);
		if (p <= c && p <= full && !chain)       /* sub_chain: see api_transform.c */
			CKF(!memcmp(got, ref, (size_t)p), "%s: cap %zu: not a prefix of the answer", k->name, c);
		if (st == KUNCOAT_OK)
			CKF(p == full, "%s: cap %zu: OK with %llu of %zu bytes", k->name, c,
			    (unsigned long long)p, full);
		if (c >= full + (chain ? 4u : 0u))
			CKF(st == st0 && p == full, "%s: cap %zu >= true size: %s", k->name, c,
			    kuncoat_status_name(st));
		else if (c < full)
			CKF(st != KUNCOAT_OK, "%s: cap %zu below the true size %zu: OK", k->name, c, full);
		/* max_out is the same bound as cap */
		if (c < full && c <= 64) {
			uint64_t p2;
			enum kuncoat_status s2 = call(k, k->in, k->n, full + 8u, c ? c : 1, &p2, NULL);

			CKF(p2 <= (c ? c : 1) && s2 != KUNCOAT_OK, "%s: max_out %zu: p %llu", k->name, c,
			    (unsigned long long)p2);
		}
	}
	/* exact buffer, the cap claims plenty */
	hv_at(2, 0);
	{
		uint8_t *op = hv_out(&gout, full);
		const uint8_t *ip = hv_in(&gin, k->in, k->n);
		struct kuncoat_step s = k->s;

		p = 0;
		st = kuncoat_transform(&s, ip, k->n, op, ~0ull, &p);
		CKF(st == st0 && p == full && !memcmp(op, ref, full), "%s: exact buffer, cap 2^64-1", k->name);
		s.max_out = ~0ull;
		st = kuncoat_transform(&s, ip, k->n, op, ~0ull, &p);
		CKF(st == st0 && p == full, "%s: exact buffer, max_out 2^64-1", k->name);
	}
	/* every truncation */
	for (n = 0; n <= k->n; n++) {
		hv_at(3, n);
		st = call(k, k->in, n, full + 8u, 0, &p, got);
		if (k->prefix && p <= full)
			CKF(!memcmp(got, ref, (size_t)p), "%s: input cut at %zu: not a prefix", k->name, n);
		if (n == 0)
			CKF(st == KUNCOAT_OK && p == 0, "%s: empty input", k->name);
	}
	/* every bit flip */
	for (n = 0; n < k->n; n++)
		for (bit = 0; bit < 8; bit++) {
			hv_at(4, n * 8u + bit);
			memcpy(mut, k->in, k->n);
			mut[n] ^= (uint8_t)(1u << bit);
			st = call(k, mut, k->n, full + 8u, 0, &p, NULL);
			(void)st;
		}
	return hv_fails != 0;
}

/* ---- aliasing ------------------------------------------------------------------- */

static int alias_case(void *arg)
{
	const struct kase *k = arg;
	uint64_t p, p2;
	size_t cap, n = k->n, off;
	enum kuncoat_status st, st2;
	int inplace_ok = k->s.algo == KUNCOAT_ALGO_XOR_KEY || k->s.algo == KUNCOAT_ALGO_XOR_COUNTER ||
			 k->s.algo == KUNCOAT_ALGO_RC4 || k->s.algo == KUNCOAT_ALGO_PLACEHOLDER_SUB ||
			 (k->s.dir == KUNCOAT_DECODE && (k->s.algo == KUNCOAT_ALGO_B64 ||
							k->s.algo == KUNCOAT_ALGO_HEX));
	int before_ok = k->s.dir == KUNCOAT_DECODE && (k->s.algo == KUNCOAT_ALGO_B64 ||
						       k->s.algo == KUNCOAT_ALGO_HEX);
	static uint8_t want[BIG * 4];

	(void)run_ref(k);
	memcpy(want, ref, ref_len);
	/* in == out, with the buffer as large as the larger of the two */
	for (cap = 0; cap <= n + 8u; cap += cap < 8 ? 1u : 7u) {
		size_t room = cap > n ? cap : n;
		uint8_t *buf = hv_out(&gout, room);
		struct kuncoat_step s = k->s;

		hv_at(5, cap);
		memcpy(buf, k->in, n);
		p = 0;
		st = kuncoat_transform(&s, buf, n, buf, cap, &p);
		CKF(hv_status_ok(st) && p <= cap, "%s: in place cap %zu", k->name, cap);
		if (inplace_ok && cap >= ref_len) {
			memcpy(buf, k->in, n);
			p = 0;
			st2 = kuncoat_transform(&s, buf, n, buf, cap, &p);
			CKF(st2 == KUNCOAT_OK && p == ref_len && !memcmp(buf, want, ref_len),
			    "%s: in place differs from the separate-buffer answer (cap %zu)", k->name, cap);
		}
		CK(hv_out_canary_ok(buf));
	}
	/* out BEFORE in: the write never overtakes the read */
	if (before_ok)
		for (off = 0; off <= 16; off++) {
			uint8_t *buf = hv_out(&gout, n + off);

			hv_at(6, off);
			memcpy(buf + off, k->in, n);
			p = p2 = 0;
			st = kuncoat_transform(&k->s, buf + off, n, buf, n + off, &p);
			st2 = KUNCOAT_OK;
			CKF(st == KUNCOAT_OK && p == ref_len && !memcmp(buf, want, ref_len),
			    "%s: out %zu bytes before in: wrong answer", k->name, off);
			(void)st2;
			(void)p2;
		}
	return hv_fails != 0;
}

/* ---- random steps ----------------------------------------------------------------- */

static int random_steps(void *arg)
{
	uint64_t rs = 0xC0FFEEull;

	(void)arg;
	unsigned it;
	static uint8_t bufi[BIG], rnd_key[1200];
	size_t i;

	for (i = 0; i < sizeof bufi; i++)
		bufi[i] = (uint8_t)hv_rng32(&rs);
	for (i = 0; i < sizeof rnd_key; i++)
		rnd_key[i] = (uint8_t)hv_rng32(&rs);
	for (it = 0; it < 30000u; it++) {
		struct kuncoat_step s;
		uint32_t r = hv_rng32(&rs);
		size_t n = hv_rng32(&rs) % 300u, cap = hv_rng32(&rs) % 400u, klen = 0;
		int alias = (hv_rng32(&rs) & 7u) == 0, usekey;
		const uint8_t *ip;
		uint8_t *op;
		enum kuncoat_status st;
		uint64_t p = 77;

		hv_at(7, it);
		memset(&s, 0, sizeof s);
		s.algo = (r & 3u) ? 1u + (hv_rng32(&rs) % 22u) : hv_rng32(&rs) % 40u;
		s.dir = (hv_rng32(&rs) & 15u) ? hv_rng32(&rs) & 1u : hv_rng32(&rs);
		s.flags = (hv_rng32(&rs) & 3u) ? hv_rng32(&rs) & 1u : hv_rng32(&rs);
		s.k32 = (hv_rng32(&rs) & 1u) ? hv_rng32(&rs) : hv_rng32(&rs) % 60u;
		usekey = (hv_rng32(&rs) & 7u) != 0;
		if (usekey) {
			uint32_t kk = hv_rng32(&rs) % 1100u;

			klen = kk;
			s.key = hv_gb_at(&gkey, klen);
			memcpy((uint8_t *)(uintptr_t)s.key, rnd_key, klen);
			s.key_len = (uint32_t)klen;
		} else {
			s.key_len = (hv_rng32(&rs) & 1u) ? 0u : hv_rng32(&rs) % 8u;
		}
		switch (hv_rng32(&rs) % 5u) {
		case 0: s.max_out = 0; break;
		case 1: s.max_out = hv_rng32(&rs) % 64u; break;
		case 2: s.max_out = cap; break;
		case 3: s.max_out = cap ? cap - 1u : 1u; break;
		default: s.max_out = ~0ull; break;
		}
		if (alias) {
			size_t room = cap > n ? cap : n;

			op = hv_out(&gout, room);
			memcpy(op, bufi + it % 256u, n);
			ip = op;
		} else {
			ip = hv_in(&gin, bufi + it % 256u, n);
			op = hv_out(&gout, cap);
		}
		/* A kind of input the codings accept: text, sometimes. */
		st = kuncoat_transform(&s, ip, n, op, cap, &p);
		CKF(hv_status_ok(st), "step %u: status %d", it, (int)st);
		CKF(p <= cap, "step %u: produced %llu > cap %zu", it, (unsigned long long)p, cap);
		CKF(!s.max_out || p <= s.max_out, "step %u: produced %llu > max_out %llu", it,
		    (unsigned long long)p, (unsigned long long)s.max_out);
		CKF(hv_out_canary_ok(op), "step %u: wrote before the output", it);
		if (st == KUNCOAT_BAD_ARG || st == KUNCOAT_UNSUPPORTED)
			CKF(p == 0, "step %u: %s with produced %llu", it, kuncoat_status_name(st),
			    (unsigned long long)p);
		if (hv_fails > 8)
			break;
	}
	return hv_fails != 0;
}

/* Key lengths that are the edge of what a key can be. */
static int key_edges(void *arg)
{
	static const uint32_t kl[] = { 1, 2, 255, 256, 257, 511, 4095, 4096 };
	unsigned i, a;
	uint8_t plain[300];
	uint64_t p;

	(void)arg;
	hv_body(plain, sizeof plain, 9);
	for (i = 0; i < sizeof kl / sizeof kl[0]; i++)
		for (a = 0; a < 2; a++) {
			struct kuncoat_step s;
			uint8_t *key = hv_gb_at(&gkey, kl[i]);
			const uint8_t *ip = hv_in(&gin, plain, sizeof plain);
			uint8_t *op = hv_out(&gout, sizeof plain);

			memcpy(key, keybuf, kl[i]);
			memset(&s, 0, sizeof s);
			s.algo = a ? KUNCOAT_ALGO_RC4 : KUNCOAT_ALGO_XOR_KEY;
			s.key = key;
			s.key_len = kl[i];
			hv_at(8, i * 2u + a);
			CK(kuncoat_transform(&s, ip, sizeof plain, op, sizeof plain, &p) == KUNCOAT_OK);
			CK(p == sizeof plain);
		}
	return hv_fails != 0;
}

int main(void)
{
	static struct kase kases[40];
	unsigned nk, i;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, BIG) || !hv_gb_init(&gout, BIG * 4) || !hv_gb_init(&gkey, 5000)) {
		printf("hostile_transform: cannot map guard buffers\n");
		return 1;
	}
	nk = build_cases(kases);
	for (i = 0; i < nk; i++) {
		hv_expect_clean(kases[i].name, sweep_case, &kases[i], 20);
		hv_expect_clean(kases[i].name, alias_case, &kases[i], 20);
	}
	hv_expect_clean("random steps", random_steps, NULL, 30);
	hv_expect_clean("key length edges", key_edges, NULL, 10);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	hv_gb_free(&gkey);
	return hv_done("hostile_transform");
}
