/*
 * cov_ppmd_roundtrip - the PPMd (variant H) model of ppmd.h, run in both directions.
 *
 * ppmd.c is a DECODER: nothing in the tree writes a PPMd stream and the machine has no tool that does,
 * so the model had never been driven by a stream whose answer was known. This test includes the
 * decoder's own source and adds the other half of the range coder - an encoder that walks the SAME model
 * (the same contexts, the same suballocator, the same update after each symbol) and writes the interval
 * the decoder will read back. Then a plaintext goes in one side and must come out of the other:
 *
 *   ROUND TRIP   text, noise, a long run, every byte value, a repeated phrase, at every order from 2 to 64 and with
 *                the smallest arena the format allows (1 MB), which a noisy stream exhausts: the suballocator's
 *                rare paths (gluing free blocks, expanding and shrinking units) and the model restart run, on
 *                both sides, at the same place
 *   STREAMS      a stream cut at every length ends the decode cleanly (the model says -1, the cursor stays inside
 *                the input), never reads past it, and what it produced before is the plaintext's own prefix
 *   FLIPS        bit flips and pure noise as input: symbols stay 0..255, the cursor stays inside the input, and the
 *                same input gives the same symbols twice (the model is a function of its stream)
 *   CONTINUE     kuncoat_ppmd_resume on a model that has run: the range coder restarts at a new offset and the model
 *                is the one built so far - two halves encoded as separate coder runs over one model decode to the
 *                whole
 *   REFUSALS     orders 0, 1, 65, an arena under the floor and over the format's 256 MB: not started
 *
 * The encoder is written from the decoder's own control flow (decode_bin_symbol, decode_symbol1 and
 * decode_symbol2 with the coder turned round); what makes it a test and not a tautology is that the
 * range coder is checked in both directions against symbols known beforehand, and that the model code both
 * share is exercised by streams the decoder alone would never see (a deliberately noisy, high order, tiny
 * arena stream).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../../../libuncoat/decompressors/ppmd.c"

static unsigned fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		if (fails < 30) { \
			printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
		fails++; \
	} \
} while (0)

/* ---- the encoder: the range coder turned round, over the model the decoder owns -------------- */

struct enc {
	uint8_t *out;
	size_t   n, cap;
};

static void emit(struct enc *e, uint8_t b)
{
	if (e->n < e->cap)
		e->out[e->n] = b;
	e->n++;
}

/* encode the interval [sub_low, sub_high) of `scale` and renormalise, exactly as rd_count/rd_decode/rd_normalize do */
static void rc_encode(struct kuncoat_ppmd *m, struct enc *e, uint32_t scale)
{
	m->range /= scale;
	m->low += m->range * m->sub_low;
	m->range *= m->sub_high - m->sub_low;
	while ((m->low ^ (m->low + m->range)) < RC_TOP ||
	       (m->range < RC_BOT && ((m->range = (~m->low + 1u) & (RC_BOT - 1u)), 1))) {
		emit(e, (uint8_t)(m->low >> 24));
		m->range <<= 8;
		m->low <<= 8;
	}
}

static void rc_flush(struct kuncoat_ppmd *m, struct enc *e)
{
	unsigned i;

	for (i = 0; i < 4u; i++) {
		emit(e, (uint8_t)(m->low >> 24));
		m->low <<= 8;
	}
}

static int enc_bin(struct kuncoat_ppmd *m, struct enc *e, int sym)
{
	struct context *c = ctx_at(m, m->min_context);
	uint32_t one = one_state_off(m->min_context);
	struct state *rs = st_at(m, one);
	struct context *sfx;
	uint16_t *bs;
	uint32_t idx1, idx2, bs_val, mean;

	if (!c || !rs)
		return -1;
	sfx = ctx_at(m, c->suffix);
	m->hi_bits_flag = m->hb2flag[(uint8_t)(st_at(m, m->found_state) ? st_at(m, m->found_state)->symbol : 0)];
	idx1 = (uint32_t)rs->freq - 1u;
	if (idx1 >= 128u)
		idx1 = 127u;
	idx2 = (uint32_t)m->prev_success + (uint32_t)m->ns2bsindx[(sfx ? sfx->num_stats : 1u) - 1u] +
	       (uint32_t)m->hi_bits_flag + 2u * (uint32_t)m->hb2flag[rs->symbol] + (uint32_t)((m->run_length >> 26) & 0x20);
	if (idx2 >= 64u)
		idx2 = 63u;
	bs = &m->bin_summ[idx1][idx2];
	bs_val = *bs;
	if (rs->symbol == sym) {
		m->sub_low = 0;
		m->sub_high = bs_val;
		rc_encode(m, e, BIN_SCALE);
		mean = (bs_val + (1u << (PERIOD_BITS - 2u))) >> PERIOD_BITS;
		*bs = (uint16_t)(bs_val + INTERVAL - mean);
		update_bin(m, one);
		return 0;
	}
	m->sub_low = bs_val;
	m->sub_high = BIN_SCALE;
	rc_encode(m, e, BIN_SCALE);
	mean = (bs_val + (1u << (PERIOD_BITS - 2u))) >> PERIOD_BITS;
	*bs = (uint16_t)(bs_val - mean);
	m->init_esc = exp_escape[*bs >> 10];
	m->char_mask[rs->symbol] = m->esc_count;
	m->num_masked = 1;
	m->prev_success = 0;
	return -2;
}

static int enc_sym1(struct kuncoat_ppmd *m, struct enc *e, int sym)
{
	struct context *c = ctx_at(m, m->min_context);
	uint32_t hi_cnt, i;
	struct state *s;

	if (!c)
		return -1;
	s = st_at(m, c->stats);
	if (!s)
		return -1;
	hi_cnt = s->freq;
	if (s->symbol == sym) {
		m->sub_low = 0;
		m->sub_high = hi_cnt;
		rc_encode(m, e, c->summ_freq);
		update1_0(m, c->stats);
		return 0;
	}
	m->prev_success = 0;
	for (i = 1; i < c->num_stats; i++) {
		struct state *q = st_at(m, c->stats + i * (uint32_t)sizeof(struct state));

		if (!q)
			return -1;
		hi_cnt += q->freq;
		if (q->symbol == sym) {
			m->sub_low = hi_cnt - q->freq;
			m->sub_high = hi_cnt;
			rc_encode(m, e, c->summ_freq);
			update1(m, c->stats + i * (uint32_t)sizeof(struct state));
			return 0;
		}
	}
	m->sub_low = hi_cnt;
	m->sub_high = c->summ_freq;
	rc_encode(m, e, c->summ_freq);
	m->num_masked = c->num_stats;
	m->hi_bits_flag = m->hb2flag[(uint8_t)(st_at(m, m->found_state) ? st_at(m, m->found_state)->symbol : 0)];
	for (i = 0; i < c->num_stats; i++) {
		struct state *q = st_at(m, c->stats + i * (uint32_t)sizeof(struct state));

		if (q)
			m->char_mask[q->symbol] = m->esc_count;
	}
	return -2;
}

static int enc_sym2(struct kuncoat_ppmd *m, struct enc *e, int sym)
{
	struct context *c = ctx_at(m, m->min_context);
	uint32_t hi_cnt = 0, escfreq, i, n;
	uint32_t hits[256], nh = 0;
	struct see *psee;

	if (!c)
		return -1;
	psee = make_esc_freq(m, m->min_context, (uint32_t)(c->num_stats - m->num_masked), &escfreq);
	for (i = 0; i < c->num_stats && nh < 256u; i++) {
		struct state *q = st_at(m, c->stats + i * (uint32_t)sizeof(struct state));

		if (!q)
			return -1;
		if (m->char_mask[q->symbol] == m->esc_count)
			continue;
		hi_cnt += q->freq;
		hits[nh++] = c->stats + i * (uint32_t)sizeof(struct state);
	}
	{
		uint32_t acc = 0;

		for (n = 0; n < nh; n++) {
			struct state *q = st_at(m, hits[n]);

			if (!q)
				return -1;
			acc += q->freq;
			if (q->symbol == sym) {
				m->sub_low = acc - q->freq;
				m->sub_high = acc;
				rc_encode(m, e, hi_cnt + escfreq);
				if (psee->shift < PERIOD_BITS && --psee->count == 0) {
					psee->summ = (uint16_t)(psee->summ * 2u);
					psee->count = (uint8_t)(3u << psee->shift++);
				}
				update2(m, hits[n]);
				return 0;
			}
		}
	}
	m->sub_low = hi_cnt;
	m->sub_high = hi_cnt + escfreq;
	rc_encode(m, e, hi_cnt + escfreq);
	psee->summ = (uint16_t)(psee->summ + hi_cnt + escfreq);
	for (n = 0; n < nh; n++) {
		struct state *q = st_at(m, hits[n]);

		if (q)
			m->char_mask[q->symbol] = m->esc_count;
	}
	m->num_masked = c->num_stats;
	return -2;
}

/* one symbol, the control flow of kuncoat_ppmd_next */
static int enc_next(struct kuncoat_ppmd *m, struct enc *e, int sym)
{
	struct context *c;
	struct state *fs;
	int r;

	if (!m->min_context)
		return -1;
	c = ctx_at(m, m->min_context);
	if (!c)
		return -1;
	r = (c->num_stats != 1) ? enc_sym1(m, e, sym) : enc_bin(m, e, sym);
	while (r == -2) {
		do {
			m->order_fall++;
			c = ctx_at(m, m->min_context);
			if (!c || !c->suffix)
				return -1;
			m->min_context = c->suffix;
			c = ctx_at(m, m->min_context);
			if (!c)
				return -1;
		} while (c->num_stats == (uint16_t)m->num_masked);
		r = enc_sym2(m, e, sym);
	}
	if (r < 0)
		return -1;
	fs = st_at(m, m->found_state);
	if (!fs)
		return -1;
	if (!m->order_fall && st_succ(fs) > m->text) {
		m->min_context = m->max_context = st_succ(fs);
	} else {
		update_model(m);
		if (m->esc_count == 0) {
			m->esc_count = 1;
			memset(m->char_mask, 0, sizeof m->char_mask);
		}
	}
	return sym;
}

/* start a model for encoding: the decoder's own start, then the coder reset to an empty interval */
static int enc_start(struct kuncoat_ppmd *m, int order, uint64_t asked)
{
	static const uint8_t zero[8];

	if (!kuncoat_ppmd_start_asked(m, order, asked, zero, sizeof zero, 0))
		return 0;
	m->low = 0;
	m->range = 0xffffffffu;
	return 1;
}

/* ---- the plaintexts -------------------------------------------------------------------------- */

static uint64_t rs = 0x2545f4914f6cdd1dull;

static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 24);
}

enum { T_TEXT, T_NOISE, T_RUN, T_BYTES, T_PHRASE, T_SKEW, T_COUNT };
static const char *const TN[T_COUNT] = { "text", "noise", "a long run", "every byte value", "a repeated phrase", "skewed noise" };

static size_t make(unsigned k, uint8_t *p, size_t want)
{
	size_t n = 0;
	static const char *const words[] = { "the", "model", "of", "a", "stream", "decodes", "to", "its", "own", "plaintext", "and",
					     "nothing", "else", "unless", "memory", "runs", "out" };

	switch (k) {
	case T_TEXT:
		while (n + 12 < want) {
			const char *w = words[rnd() % 17u];

			memcpy(p + n, w, strlen(w));
			n += strlen(w);
			p[n++] = (rnd() % 13u) ? ' ' : '\n';
		}
		break;
	case T_NOISE:
		for (; n < want; n++)
			p[n] = (uint8_t)rnd();
		break;
	case T_RUN:
		memset(p, 'a', want);
		n = want;
		break;
	case T_BYTES:
		for (; n < want; n++)
			p[n] = (uint8_t)(n % 256u);
		break;
	case T_PHRASE:
		for (; n + 25 < want; n += 25)
			memcpy(p + n, "PPMd variant H, order 8..", 25);
		break;
	default:
		for (; n < want; n++) {
			uint32_t r = rnd();

			p[n] = (uint8_t)((r & 7u) ? (r >> 8) % 6u : (r >> 8) % 200u);
		}
		break;
	}
	return n;
}

/* ---- the checks --------------------------------------------------------------------------------- */

static uint8_t plain[1 << 17], coded[1 << 18], back[1 << 17];

/* encode `n` plaintext bytes with a model of `order` and `asked` bytes of arena; returns the stream length (0: failed) */
static size_t encode(struct kuncoat_ppmd *m, int order, uint64_t asked, const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	struct enc e;
	size_t i;

	e.out = out;
	e.n = 0;
	e.cap = cap;
	if (!enc_start(m, order, asked))
		return 0;
	for (i = 0; i < n; i++)
		if (enc_next(m, &e, p[i]) != p[i])
			return 0;
	rc_flush(m, &e);
	return e.n <= cap ? e.n : 0;
}

/* decode up to `n` symbols; returns how many were produced */
static size_t decode(struct kuncoat_ppmd *m, int order, uint64_t asked, const uint8_t *in, size_t len, uint8_t *out, size_t n)
{
	size_t i = 0;

	if (!kuncoat_ppmd_start_asked(m, order, asked, in, len, 0))
		return 0;
	while (i < n) {
		int s = kuncoat_ppmd_next(m);

		if (s < 0)
			break;
		CK(s < 256, "a symbol past 255 (%d)", s);
		out[i++] = (uint8_t)s;
	}
	CK(kuncoat_ppmd_at(m) <= len, "the cursor %llu is past the %zu byte input", (unsigned long long)kuncoat_ppmd_at(m), len);
	return i;
}

static void t_roundtrip(void)
{
	static const int orders[] = { 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64 };
	struct kuncoat_ppmd *me = kuncoat_ppmd_new(), *md = kuncoat_ppmd_new();
	unsigned k, o, ok = 0, all = 0;
	uint64_t big_stream = 0;

	if (!me || !md) {
		CK(0, "memory");
		return;
	}
	for (k = 0; k < T_COUNT; k++)
		for (o = 0; o < sizeof orders / sizeof orders[0]; o++) {
			/* noise and skewed noise are the streams that fill a 1 MB arena: give them room to */
			size_t want = (k == T_NOISE || k == T_SKEW) ? 60000u : 12000u, n, m, got;
			uint64_t asked = 1u << 20;

			n = make(k, plain, want);
			m = encode(me, orders[o], asked, plain, n, coded, sizeof coded);
			all++;
			if (!m) {
				CK(0, "%s at order %d: the encoder failed", TN[k], orders[o]);
				continue;
			}
			got = decode(md, orders[o], asked, coded, m, back, n);
			if (got == n && !memcmp(back, plain, n))
				ok++;
			else {
				size_t d = 0;

				while (d < got && d < n && back[d] == plain[d])
					d++;
				CK(0, "%s at order %d: %zu of %zu symbols came back (first difference at %zu)", TN[k], orders[o], got, n, d);
			}
			if (k == T_NOISE && orders[o] == 64)
				big_stream = m;
		}
	CK(ok == all, "%u of %u (shape, order) pairs round-trip", ok, all);
	CK(big_stream > 30000, "the noisy order-64 stream is long (%llu bytes), so the arena was exhausted", (unsigned long long)big_stream);
	kuncoat_ppmd_free(me);
	kuncoat_ppmd_free(md);
}

/* a cut stream ends the decode cleanly, and what it gave is the plaintext's own prefix */
static void t_cuts(void)
{
	struct kuncoat_ppmd *me = kuncoat_ppmd_new(), *md = kuncoat_ppmd_new();
	size_t n, m, k, bad = 0, past = 0;

	if (!me || !md) {
		CK(0, "memory");
		return;
	}
	n = make(T_TEXT, plain, 300);
	m = encode(me, 8, 1u << 20, plain, n, coded, sizeof coded);
	CK(m > 50, "the short stream (%zu bytes)", m);
	for (k = 0; k <= m; k++) {
		size_t got = decode(md, 8, 1u << 20, coded, k, back, n);

		if (got > n || memcmp(back, plain, got))
			bad++;
		/* with fewer than the four bytes the coder starts on there is nothing to decode */
		if (k < 4 && got)
			past++;
	}
	CK(bad == 0, "%zu of %zu cuts produced bytes the plaintext does not start with", bad, m + 1);
	CK(past == 0, "a stream shorter than the coder's four byte start produces nothing");
	/* the complete stream, then the same followed by trailing bytes: the decode of n symbols is the same */
	{
		static uint8_t longer[1 << 12];

		memcpy(longer, coded, m);
		memset(longer + m, 0xa5, 64);
		CK(decode(md, 8, 1u << 20, longer, m + 64, back, n) == n && !memcmp(back, plain, n), "trailing bytes do not change the symbols");
	}
	kuncoat_ppmd_free(me);
	kuncoat_ppmd_free(md);
}

/* flips and noise: bounded, deterministic */
static void t_hostile(void)
{
	struct kuncoat_ppmd *me = kuncoat_ppmd_new(), *md = kuncoat_ppmd_new();
	static uint8_t bent[1 << 14], again[1 << 17];
	size_t n, m, i, same = 0, total = 0;
	unsigned order;

	if (!me || !md) {
		CK(0, "memory");
		return;
	}
	n = make(T_TEXT, plain, 2000);
	m = encode(me, 6, 1u << 20, plain, n, coded, sizeof coded);
	for (i = 0; i < 400; i++) {
		size_t at = rnd() % (m * 8u), g1, g2;

		memcpy(bent, coded, m);
		bent[at / 8] ^= (uint8_t)(1u << (at % 8));
		g1 = decode(md, 6, 1u << 20, bent, m, back, n + 100);
		g2 = decode(md, 6, 1u << 20, bent, m, again, n + 100);
		total++;
		if (g1 == g2 && !memcmp(back, again, g1))
			same++;
		CK(g1 <= n + 100, "a flipped stream gave more symbols than were asked (%zu)", g1);
	}
	CK(same == total, "the same flipped stream gives the same symbols twice (%zu of %zu)", same, total);
	/* noise as a stream, at every order: any bytes are a valid range-coded stream, so the model runs on them */
	for (order = 2; order <= 64; order += (order < 8 ? 1u : 14u)) {
		size_t len = 40000, g1, g2;
		unsigned j;

		for (j = 0; j < len; j++)
			bent[j % sizeof bent] = (uint8_t)rnd();
		g1 = decode(md, (int)order, 1u << 20, bent, sizeof bent, back, 30000);
		g2 = decode(md, (int)order, 1u << 20, bent, sizeof bent, again, 30000);
		CK(g1 == g2 && !memcmp(back, again, g1), "noise at order %u is deterministic (%zu, %zu symbols)", order, g1, g2);
		/* a code value outside the coder's interval is not a stream the encoder could have written: the model says so (-1)
		 * after some symbols, and does not carry on into a state no stream reaches */
		CK(g1 < 30000, "noise at order %u ends the decode (%zu symbols)", order, g1);
	}
	kuncoat_ppmd_free(me);
	kuncoat_ppmd_free(md);
}

/* the coder restarts at a new offset over the model built so far */
static void t_continue(void)
{
	struct kuncoat_ppmd *me = kuncoat_ppmd_new(), *md = kuncoat_ppmd_new();
	struct enc e1, e2;
	static uint8_t part1[1 << 15], part2[1 << 15];
	size_t n, h, i;
	uint64_t at;
	static const uint8_t zero[8];

	if (!me || !md) {
		CK(0, "memory");
		return;
	}
	n = make(T_TEXT, plain, 4000);
	h = n / 2;
	e1.out = part1; e1.n = 0; e1.cap = sizeof part1;
	e2.out = part2; e2.n = 0; e2.cap = sizeof part2;
	CK(enc_start(me, 8, 1u << 20), "the encoder starts");
	for (i = 0; i < h; i++)
		CK(enc_next(me, &e1, plain[i]) == plain[i], "first half symbol %zu", i);
	rc_flush(me, &e1);
	/* a new coder run, the model kept */
	me->low = 0;
	me->range = 0xffffffffu;
	for (; i < n; i++)
		CK(enc_next(me, &e2, plain[i]) == plain[i], "second half symbol %zu", i);
	rc_flush(me, &e2);
	/* decode: the two streams one after the other in one buffer */
	memcpy(coded, part1, e1.n);
	memcpy(coded + e1.n, part2, e2.n);
	CK(kuncoat_ppmd_start_asked(md, 8, 1u << 20, coded, e1.n + e2.n, 0), "the decoder starts");
	for (i = 0; i < h; i++)
		CK(kuncoat_ppmd_next(md) == plain[i], "decoded first half symbol %zu", i);
	at = kuncoat_ppmd_at(md);
	CK(at == e1.n, "after the first half the cursor is where the second stream begins (%llu, want %zu)", (unsigned long long)at, e1.n);
	CK(kuncoat_ppmd_resume(md, coded, e1.n + e2.n, at), "resume");
	for (; i < n; i++)
		CK(kuncoat_ppmd_next(md) == plain[i], "decoded second half symbol %zu", i);
	/* a model that was never started cannot be resumed */
	{
		struct kuncoat_ppmd *fresh = kuncoat_ppmd_new();

		CK(fresh && !kuncoat_ppmd_resume(fresh, zero, sizeof zero, 0), "resume without a model is refused");
		CK(kuncoat_ppmd_next(fresh) == -1, "next without a model is -1");
		CK(kuncoat_ppmd_at(fresh) == 0, "at() of a fresh model is 0");
		kuncoat_ppmd_free(fresh);
	}
	CK(kuncoat_ppmd_next(NULL) == -1 && kuncoat_ppmd_at(NULL) == 0 && !kuncoat_ppmd_resume(NULL, zero, 8, 0), "NULL models are refused");
	kuncoat_ppmd_free(me);
	kuncoat_ppmd_free(md);
}

static void t_refusals(void)
{
	struct kuncoat_ppmd *m = kuncoat_ppmd_new();
	static const uint8_t in[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	if (!m) {
		CK(0, "memory");
		return;
	}
	CK(!kuncoat_ppmd_start_asked(m, 0, 1u << 20, in, 8, 0), "order 0");
	CK(!kuncoat_ppmd_start_asked(m, 1, 1u << 20, in, 8, 0), "order 1");
	CK(!kuncoat_ppmd_start_asked(m, 65, 1u << 20, in, 8, 0), "order 65");
	CK(!kuncoat_ppmd_start_asked(m, -3, 1u << 20, in, 8, 0), "a negative order");
	CK(!kuncoat_ppmd_start_asked(m, 8, 100, in, 8, 0), "an arena under the floor (100 bytes)");
	CK(!kuncoat_ppmd_start_asked(m, 8, (256u << 20) + 1u, in, 8, 0), "an arena over the format's 256 MB");
	CK(!kuncoat_ppmd_start_asked(NULL, 8, 1u << 20, in, 8, 0), "no model");
	CK(!kuncoat_ppmd_start_asked(m, 8, 1u << 20, in, 3, 0), "an input shorter than the coder's start");
	CK(!kuncoat_ppmd_start_asked(m, 8, 1u << 20, in, 8, 7), "a start offset that leaves fewer than four bytes");
	CK(kuncoat_ppmd_start_asked(m, 8, 1u << 20, in, 8, 4), "a start offset with exactly four");
	CK(kuncoat_ppmd_arena_want(0) == 1u << 20 && kuncoat_ppmd_arena_want(255) == 256u << 20, "the arena a header byte asks for");
	/* an arena smaller than asked: the model reports it is over budget rather than diverging */
	CK(kuncoat_ppmd_start_asked(m, 8, 200u << 20, in, 8, 0), "an arena the build clamps is started");
	CK(!kuncoat_ppmd_over(m), "and is not over before anything ran");
	CK(!kuncoat_ppmd_over(NULL), "over() of NULL is no");
	kuncoat_ppmd_free(m);
	kuncoat_ppmd_free(NULL);
}

int main(void)
{
	t_roundtrip();
	t_cuts();
	t_hostile();
	t_continue();
	t_refusals();
	if (fails) {
		printf("cov_ppmd_roundtrip: FAILED (%u)\n", fails);
		return 1;
	}
	printf("cov_ppmd_roundtrip: ok\n");
	return 0;
}
