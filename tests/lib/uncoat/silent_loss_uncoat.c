/*
 * uncoat / silent_loss_uncoat - SILENT EVIDENCE LOSS in libuncoat, through
 * <uncoat.h> alone, linked against libkuncoat.a and nothing else.
 *
 * The invariant every test here asserts is "the FULL result, or a SIGNAL":
 *
 *   a decoder that hands back fewer bytes than the stream holds must say so -
 *   a status other than OK (STOPPED / TRUNCATED / OVER_BUDGET / CORRUPT), or,
 *   for the two decoders whose API is a bare count, a count below the ceiling.
 *
 * A test that holds documents the signal. A test that does not is a KM_CHECK
 * (tests/unit/known_miss.h): it prints KNOWN-MISS while the product is wrong
 * and FAILS with FIXED-UNEXPECTEDLY the day it is fixed, so the marker never
 * outlives the bug. The cap string of each is "<LIMIT> <file>:<line> lost:
 * <what>" and names the line of the product that drops the evidence.
 *
 * Every fixture is built in memory by the test (a tiny bit writer per format);
 * no file is read. Nothing here changes product code.
 */

#include <uncoat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../unit/known_miss.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* ---- a sink that records what it was handed --------------------------------- */

struct rec {
	uint8_t  *buf;
	uint64_t  cap;
	uint64_t  got;
	uint64_t  refuse_after;   /* refuse once this many bytes are in (0: never) */
};

static int rec_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct rec *r = user;

	if (r->got + n <= r->cap)
		memcpy(r->buf + r->got, p, n);
	r->got += n;
	if (r->refuse_after && r->got >= r->refuse_after)
		return 0;
	return 1;
}

/* ===================================================================== *
 * 1. kuncoat_transform: every cap short of the full answer must say so.  *
 * ===================================================================== */

struct tcase {
	const char *name;
	uint32_t algo, dir, flags, k32;
	const uint8_t *key;
	uint32_t key_len;
	const uint8_t *in;
	uint64_t n;
};

/* For each cap (and each max_out) below the full answer: the status is not OK,
 * the count is within the cap, and the bytes are the real beginning. */
static void sweep(const struct tcase *t)
{
	static uint8_t full[512], part[512];
	uint64_t nfull = 0, c;
	struct kuncoat_step s;
	enum kuncoat_status st;
	int bad = 0;

	memset(&s, 0, sizeof s);
	s.algo = t->algo; s.dir = t->dir; s.flags = t->flags; s.k32 = t->k32;
	s.key = t->key; s.key_len = t->key_len;
	st = kuncoat_transform(&s, t->in, t->n, full, sizeof full, &nfull);
	if (st != KUNCOAT_OK || nfull < 2u) {
		printf("  FAIL %s: the full run is %s, %llu bytes\n", t->name,
		       kuncoat_status_name(st), (unsigned long long)nfull);
		fails++;
		return;
	}
	for (c = 1; c < nfull; c++) {
		uint64_t w = 0;
		int via_max;

		for (via_max = 0; via_max < 2; via_max++) {
			memset(&s, 0, sizeof s);
			s.algo = t->algo; s.dir = t->dir; s.flags = t->flags;
			s.k32 = t->k32; s.key = t->key; s.key_len = t->key_len;
			memset(part, 0xa5, sizeof part);
			if (via_max) {
				s.max_out = c;
				st = kuncoat_transform(&s, t->in, t->n, part, sizeof part, &w);
			} else {
				st = kuncoat_transform(&s, t->in, t->n, part, c, &w);
			}
			/* the sub chain reverses its dwords in place, so a short answer is not a prefix */
			if (st == KUNCOAT_OK || w > c ||
			    (t->algo != KUNCOAT_ALGO_X86_SUB_CHAIN &&
			     memcmp(part, full, (size_t)w) != 0))
				bad++;
			/* nothing past the count was written (cap case) */
			if (!via_max && c < sizeof part && part[c] != 0xa5u)
				bad++;
		}
	}
	if (bad)
		printf("  FAIL %s: %d cap values gave OK / an overrun / a wrong prefix\n",
		       t->name, bad);
	CK(bad == 0);
}

static void transform_caps(void)
{
	static const uint8_t k3[3] = { 0x11, 0x22, 0x33 };
	static const uint8_t ph_key[2] = { 3, 5 };
	uint8_t add32_in[12], chain[5 + 3 * 6 + 1];
	uint32_t p[3] = { 0x11111111u, 0x22222222u, 0u }, key = 0xdeadbeefu, i;
	struct tcase cs[] = {
		{ "xor_key",  KUNCOAT_ALGO_XOR_KEY, KUNCOAT_DECODE, 0, 0, k3, 3,
		  (const uint8_t *)"abcdefghijkl", 12 },
		{ "xor_counter", KUNCOAT_ALGO_XOR_COUNTER, KUNCOAT_DECODE, 0, 9, 0, 0,
		  (const uint8_t *)"abcdefghijkl", 12 },
		{ "rc4", KUNCOAT_ALGO_RC4, KUNCOAT_DECODE, 0, 0, k3, 3,
		  (const uint8_t *)"abcdefghijkl", 12 },
		{ "add", KUNCOAT_ALGO_ADD, KUNCOAT_DECODE, 0, 3, 0, 0,
		  (const uint8_t *)"abcdefghijkl", 12 },
		{ "caesar", KUNCOAT_ALGO_CAESAR, KUNCOAT_DECODE, 0, 3, 0, 0,
		  (const uint8_t *)"abcDEFghi jkl", 13 },
		{ "reverse", KUNCOAT_ALGO_REVERSE, KUNCOAT_DECODE, 0, 0, 0, 0,
		  (const uint8_t *)"abcdefghijkl", 12 },
		{ "placeholder_sub", KUNCOAT_ALGO_PLACEHOLDER_SUB, KUNCOAT_DECODE, 0, 'X',
		  ph_key, 2, (const uint8_t *)"aXbXcdefgh", 10 },
		{ "b64_dec", KUNCOAT_ALGO_B64, KUNCOAT_DECODE, 0, 0, 0, 0,
		  (const uint8_t *)"YWJj\nZGVm\nZ2hp\namts\n", 20 },
		{ "b64_dec_pad", KUNCOAT_ALGO_B64, KUNCOAT_DECODE, 0, 0, 0, 0,
		  (const uint8_t *)"YWJjZGVmZ2g=", 12 },
		{ "b64_enc", KUNCOAT_ALGO_B64, KUNCOAT_ENCODE, 0, 0, 0, 0,
		  (const uint8_t *)"abcdefg", 7 },
		{ "hex_dec", KUNCOAT_ALGO_HEX, KUNCOAT_DECODE, 0, 0, 0, 0,
		  (const uint8_t *)"61 62:63,64\n65 66", 17 },
		{ "hex_enc", KUNCOAT_ALGO_HEX, KUNCOAT_ENCODE, 0, 0, 0, 0,
		  (const uint8_t *)"abcdef", 6 },
		{ "url_dec", KUNCOAT_ALGO_URL, KUNCOAT_DECODE, 0, 0, 0, 0,
		  (const uint8_t *)"a%20b+c%41d", 11 },
		{ "url_enc", KUNCOAT_ALGO_URL, KUNCOAT_ENCODE, 0, 0, 0, 0,
		  (const uint8_t *)"a b&c+d", 7 },
	};
	struct tcase t_add32 = { "xor_add32", KUNCOAT_ALGO_XOR_ADD32, KUNCOAT_DECODE, 0,
				 0xdeadbeefu, 0, 0, add32_in, 12 };
	struct tcase t_chain = { "x86_sub_chain", KUNCOAT_ALGO_X86_SUB_CHAIN,
				 KUNCOAT_DECODE, 0, 0, 0, 0, chain, sizeof chain };

	for (i = 0; i < sizeof cs / sizeof cs[0]; i++)
		sweep(&cs[i]);

	/* XOR_ADD32: the encoded form of the plaintext dwords p[], with feedback. */
	for (i = 0; i < 3u; i++) {
		uint32_t c = p[i] ^ key;

		add32_in[4u * i + 0u] = (uint8_t)c;
		add32_in[4u * i + 1u] = (uint8_t)(c >> 8);
		add32_in[4u * i + 2u] = (uint8_t)(c >> 16);
		add32_in[4u * i + 3u] = (uint8_t)(c >> 24);
		key += p[i];
	}
	sweep(&t_add32);

	/* X86_SUB_CHAIN: `and eax,0` (zeroes eax) then three `sub eax,imm ; push eax`. */
	memset(chain, 0, sizeof chain);
	chain[0] = 0x25;                                  /* and eax, 0 */
	for (i = 0; i < 3u; i++) {
		chain[5u + 6u * i] = 0x2d;                /* sub eax, imm32 */
		chain[5u + 6u * i + 1u] = (uint8_t)(0x10u * (i + 1u));
		chain[5u + 6u * i + 5u] = 0x50;           /* push eax */
	}
	chain[sizeof chain - 1u] = 0xc3;                 /* ret: not part of the chain, ends it */
	sweep(&t_chain);
}

/* ===================================================================== *
 * 2. a85 / ahx: `cap` is "at most" and the status is OK when it is hit.  *
 * ===================================================================== */

static void textcode_caps(void)
{
	uint8_t out[16];
	uint64_t n = 0;
	enum kuncoat_status st;
	/* "Man " "sure": eight bytes. */
	static const char a85[] = "9jqo^F*2M7~>";
	static const char ahx[] = "6162636465666768>";

	st = kuncoat_a85_decode((const uint8_t *)a85, sizeof a85 - 1u, out, sizeof out, &n);
	CK(st == KUNCOAT_OK && n == 8u);
	st = kuncoat_a85_decode((const uint8_t *)a85, sizeof a85 - 1u, out, 4, &n);
	KM_CHECK(!(st == KUNCOAT_OK && n < 8u),
		 "kuncoat_a85_decode with cap 4 of 8 reports OK (4 bytes, no signal)",
		 "a85 cap textcode.c:60 lost: output past `cap` is dropped, status OK");
	st = kuncoat_ahx_decode((const uint8_t *)ahx, sizeof ahx - 1u, out, sizeof out, &n);
	CK(st == KUNCOAT_OK && n == 8u);
	st = kuncoat_ahx_decode((const uint8_t *)ahx, sizeof ahx - 1u, out, 3, &n);
	KM_CHECK(!(st == KUNCOAT_OK && n < 8u),
		 "kuncoat_ahx_decode with cap 3 of 8 reports OK (3 bytes, no signal)",
		 "ahx cap textcode.c:123 lost: output past `cap` is dropped, status OK");

	/* RunLength is a sink: the receiver saying stop is STOPPED; no 128 is TRUNCATED. */
	{
		static const uint8_t rl[] = { 2, 'a', 'b', 'c', 0xfe, 'x', 128 };
		uint8_t b[64];
		struct rec r = { b, sizeof b, 0, 0 };

		st = kuncoat_rle_decode(rl, sizeof rl, rec_sink, &r, &n);
		CK(st == KUNCOAT_OK && n == 6u && r.got == 6u);
		memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b; r.refuse_after = 1;
		st = kuncoat_rle_decode(rl, sizeof rl, rec_sink, &r, &n);
		CK(st == KUNCOAT_STOPPED || st == KUNCOAT_OK); /* one chunk: refusal comes at flush */
		memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b;
		st = kuncoat_rle_decode(rl, sizeof rl - 1u, rec_sink, &r, &n);
		CK(st == KUNCOAT_TRUNCATED && n == 6u && r.got == 6u);
	}
}

/* ===================================================================== *
 * 3. inflate: sink refusal, truncation, seed longer than the window.      *
 * ===================================================================== */

struct bw {                     /* DEFLATE bit order: LSB first */
	uint8_t  b[65536 + 64];
	size_t   n;
	uint32_t acc, cnt;
};

static void bw_bits(struct bw *w, uint32_t v, uint32_t k)
{
	uint32_t i;

	for (i = 0; i < k; i++) {
		w->acc |= ((v >> i) & 1u) << w->cnt;
		if (++w->cnt == 8u) {
			w->b[w->n++] = (uint8_t)w->acc;
			w->acc = 0;
			w->cnt = 0;
		}
	}
}

static void bw_huff(struct bw *w, uint32_t code, uint32_t k)
{
	uint32_t i;

	for (i = 0; i < k; i++)         /* Huffman codes go MSB first */
		bw_bits(w, (code >> (k - 1u - i)) & 1u, 1u);
}

static void bw_flush(struct bw *w)
{
	if (w->cnt)
		bw_bits(w, 0, 8u - w->cnt);
}

static struct kuncoat_inflate inf_state;        /* 32 KB: not on the stack */

static enum kuncoat_status run_inflate(const struct kuncoat_span *seed, const uint8_t *in,
				       uint64_t n, struct rec *r, uint64_t *produced)
{
	struct kuncoat_io io;
	enum kuncoat_status st;

	memset(&io, 0, sizeof io);
	io.in.p = in;
	io.in.n = n;
	io.sink = rec_sink;
	io.user = r;
	st = kuncoat_inflate_seeded(&inf_state, seed, &io);
	*produced = io.produced;
	return st;
}

static void inflate_signals(void)
{
	static struct bw w;
	static uint8_t sink_buf[200000], seed[40000];
	struct rec r;
	uint64_t produced, i;
	enum kuncoat_status st;
	struct kuncoat_span sp;

	/* A stored block of 70 bytes cut after 40: TRUNCATED, and the 40 are delivered. */
	memset(&w, 0, sizeof w);
	bw_bits(&w, 1, 1); bw_bits(&w, 0, 2); bw_flush(&w);
	bw_bits(&w, 70, 16); bw_bits(&w, 0xffffu & ~70u, 16);
	for (i = 0; i < 40u; i++)
		bw_bits(&w, (uint32_t)('a' + i % 26u), 8);
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_inflate(0, w.b, w.n, &r, &produced);
	CK(st == KUNCOAT_TRUNCATED && produced == 40u && r.got == 40u);

	/* The same stream, whole: OK. */
	for (i = 40u; i < 70u; i++)
		bw_bits(&w, (uint32_t)('a' + i % 26u), 8);
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_inflate(0, w.b, w.n, &r, &produced);
	CK(st == KUNCOAT_OK && produced == 70u && r.got == 70u);

	/* A sink that refuses ends it STOPPED, not CORRUPT and not OK. */
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf; r.refuse_after = 1;
	st = run_inflate(0, w.b, w.n, &r, &produced);
	CK(st == KUNCOAT_STOPPED);

	/* A fixed block whose first item is `copy 3 bytes at distance 1`, behind a
	 * seed LONGER than the window. The documented contract (inflate.h) is that
	 * only the seed's TAIL matters; the byte copied must be the seed's last. */
	for (i = 0; i < sizeof seed; i++)
		seed[i] = (uint8_t)(i * 7u + 1u);
	memset(&w, 0, sizeof w);
	bw_bits(&w, 1, 1); bw_bits(&w, 1, 2);
	bw_huff(&w, 1, 7);          /* length symbol 257 = 3 */
	bw_huff(&w, 0, 5);          /* distance code 0 = 1 */
	bw_huff(&w, 0, 7);          /* end of block */
	bw_flush(&w);
	sp.p = seed; sp.n = sizeof seed;
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_inflate(&sp, w.b, w.n, &r, &produced);
	CK(st == KUNCOAT_OK && produced == 3u && r.got == 3u);
	KM_CHECK(sink_buf[0] == seed[sizeof seed - 1u],
		 "inflate_seeded with a 40000-byte seed copies the seed's HEAD, so a distance-1 match yields seed[32767], not seed[39999]",
		 "KUNCOAT_INF_WINDOW inflate.c:661 lost: seed longer than the window keeps its head, not its tail; wrong bytes, status OK");
	/* With a seed that fits, the same stream is right (control). */
	sp.n = 30000;
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_inflate(&sp, w.b, w.n, &r, &produced);
	CK(st == KUNCOAT_OK && sink_buf[0] == seed[29999]);
}

/* ===================================================================== *
 * 4. lzw: truncation and a refusing sink.                                  *
 * ===================================================================== */

static struct kuncoat_lzw lzw_state;

static void lzw_signals(void)
{
	/* 9-bit codes, MSB first: 'A' 'B' 'C' then nothing (no EOD). */
	uint8_t in[8];
	uint32_t codes[4] = { 'A', 'B', 'C', 257 };
	uint64_t acc = 0, bits = 0, n = 0, k;
	uint8_t b[16];
	struct rec r = { b, sizeof b, 0, 0 };
	enum kuncoat_status st;
	uint64_t produced = 0;

	for (k = 0; k < 4u; k++) {
		acc = (acc << 9) | codes[k];
		bits += 9u;
		while (bits >= 8u) {
			in[n++] = (uint8_t)(acc >> (bits - 8u));
			bits -= 8u;
		}
	}
	if (bits)
		in[n++] = (uint8_t)(acc << (8u - bits));
	st = kuncoat_lzw_decode(&lzw_state, in, n, rec_sink, &r, &produced);
	CK(st == KUNCOAT_OK && produced == 3u && r.got == 3u);
	/* the same minus its EOD code: 27 bits, input ends first */
	memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b;
	st = kuncoat_lzw_decode(&lzw_state, in, 3, rec_sink, &r, &produced);
	CK(st == KUNCOAT_TRUNCATED && produced == 2u && r.got == 2u);
}

/* ===================================================================== *
 * 5. lzhuf: a block that decodes N bytes and then meets a corrupt header. *
 * ===================================================================== */

static struct kuncoat_lzhuf lzh_state;

struct mw {                     /* MSB-first bit writer */
	uint8_t b[64];
	size_t  n;
	uint64_t acc;
	uint32_t cnt;
};

static void mw_bits(struct mw *w, uint32_t v, uint32_t k)
{
	uint32_t i;

	for (i = 0; i < k; i++) {
		w->acc = (w->acc << 1) | ((v >> (k - 1u - i)) & 1u);
		if (++w->cnt == 8u) {
			w->b[w->n++] = (uint8_t)w->acc;
			w->acc = 0;
			w->cnt = 0;
		}
	}
}

static void lzhuf_signals(void)
{
	struct mw w;
	uint8_t b[64];
	struct rec r;
	uint64_t produced = 0;
	enum kuncoat_status st;

	memset(&w, 0, sizeof w);
	/* One block of five symbols, every one the constant literal 'A' (a code of
	 * zero bits): blocksize 5, pretree n=0 c=0, literal tree n=0 c=0x41,
	 * position tree n=0 c=0. */
	mw_bits(&w, 5, 16);
	mw_bits(&w, 0, 5); mw_bits(&w, 0, 5);
	mw_bits(&w, 0, 9); mw_bits(&w, 0x41, 9);
	mw_bits(&w, 0, 5); mw_bits(&w, 0, 5);
	mw_bits(&w, 0, 2);                 /* pad to the byte: 56 bits */

	/* Input ends where the next header would start: TRUNCATED, and the five
	 * bytes are delivered to the sink (the "what was reached is real" rule). */
	memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b;
	st = kuncoat_lzhuf_decode(&lzh_state, KUNCOAT_LZHUF_ARJ, w.b, w.n, 10, rec_sink, &r,
				  &produced);
	CK(st == KUNCOAT_TRUNCATED && produced == 5u && r.got == 5u);

	/* Eight more zero bytes: the next block header reads blocksize 0, which is
	 * CORRUPT. The status is a signal, but the five bytes decoded before it sit
	 * in the dictionary and are never handed to the sink, while `produced`
	 * still counts them. */
	memset(w.b + w.n, 0, 8);
	memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b;
	st = kuncoat_lzhuf_decode(&lzh_state, KUNCOAT_LZHUF_ARJ, w.b, w.n + 8u, 10, rec_sink,
				  &r, &produced);
	CK(st == KUNCOAT_CORRUPT);
	CK(produced == 5u);
	KM_CHECK(r.got == produced,
		 "lzhuf CORRUPT after 5 decoded bytes: produced says 5, the sink got none",
		 "KUNCOAT_LZHUF_DICT lzhuf.c:436 lost: bytes buffered in the dictionary are not flushed on CORRUPT (only on TRUNCATED); up to dict-1 bytes dropped, status CORRUPT");
}

/* ===================================================================== *
 * 6. ovba: a cut container.                                                *
 * ===================================================================== */

static void ovba_signals(void)
{
	/* signature, a raw chunk of 4 bytes (header 0x3003), then a stray byte. */
	static const uint8_t ok[] = { 0x01, 0x03, 0x30, 'a', 'b', 'c', 'd' };
	static const uint8_t cut[] = { 0x01, 0x03, 0x30, 'a', 'b' };
	static const uint8_t stray[] = { 0x01, 0x03, 0x30, 'a', 'b', 'c', 'd', 0x55 };
	uint8_t b[16];
	struct rec r = { b, sizeof b, 0, 0 };
	uint64_t n = 0;
	enum kuncoat_status st;

	st = kuncoat_ovba_decode(ok, sizeof ok, rec_sink, &r, &n);
	CK(st == KUNCOAT_OK && n == 4u && r.got == 4u);
	memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b;
	st = kuncoat_ovba_decode(cut, sizeof cut, rec_sink, &r, &n);
	CK(st == KUNCOAT_TRUNCATED && n == 2u && r.got == 2u);
	memset(&r, 0, sizeof r); r.buf = b; r.cap = sizeof b;
	st = kuncoat_ovba_decode(stray, sizeof stray, rec_sink, &r, &n);
	CK(n == 4u);
	KM_CHECK(st != KUNCOAT_OK,
		 "ovba container with a stray byte (half a chunk header) after the last chunk reports OK",
		 "ovba trailing-header ovba.c:90 lost: `while (at + 2 <= in_len)` ignores 1 trailing byte; a cut chunk header is not TRUNCATED [Inference: low]");
}

/* ===================================================================== *
 * 7. aplib / lzmat / nrv2: the buffered decoders at their ceiling.         *
 * ===================================================================== */

static void aplib_signals(void)
{
	static const uint8_t lit[] = { 'A', 0x00, 'B', 'C', 'D', 'E' };
	static const uint8_t bad[] = { 'A', 0xe4, 0x00 };
	uint8_t out[16];
	uint64_t n = 0;
	enum kuncoat_status st;

	/* literals only: the ceiling reached is STOPPED, the input ending is TRUNCATED */
	memset(out, 0, sizeof out);
	st = kuncoat_aplib_decode(lit, sizeof lit, out, 3, &n);
	CK(st == KUNCOAT_STOPPED && n == 3u && !memcmp(out, "ABC", 3));
	st = kuncoat_aplib_decode(lit, sizeof lit, out, sizeof out, &n);
	CK(st == KUNCOAT_TRUNCATED && n >= 5u);

	/* A back reference before the start of the output: CORRUPT. The header of
	 * aplib.h says `produced` is ALWAYS set and a prefix is worth keeping; the
	 * literal 'A' was written to out[0] and is not counted. */
	memset(out, 0, sizeof out);
	st = kuncoat_aplib_decode(bad, sizeof bad, out, sizeof out, &n);
	CK(st == KUNCOAT_CORRUPT);
	CK(out[0] == 'A');
	KM_CHECK(n == 1u,
		 "aplib CORRUPT after one literal: produced is 0 although out[0] holds the decoded byte",
		 "kuncoat_aplib_decode aplib.c:166,179,193 lost: the early `return KUNCOAT_CORRUPT` paths leave *produced at 0, discarding the decoded prefix (signal CORRUPT present) [Inference: low]");
}

static void lzmat_signals(void)
{
	/* byte 0 literal, a control byte of literals, two literal bytes, input over */
	static const uint8_t in[] = { 'a', 0x00, 'b', 'c' };
	uint8_t out[100];
	uint64_t n = 0;
	enum kuncoat_status st;

	st = kuncoat_lzmat_decode(in, sizeof in, out, 3, &n);
	CK(st == KUNCOAT_OK && n == 3u);
	st = kuncoat_lzmat_decode(in, sizeof in, out, 2, &n);
	CK(n == 2u);                    /* the ceiling: reported only by `n` */
	st = kuncoat_lzmat_decode(in, sizeof in, out, sizeof out, &n);
	KM_CHECK(!(st == KUNCOAT_OK && n < sizeof out),
		 "lzmat input exhausted at 3 of a declared 100 bytes reports OK",
		 "lzmat out_cap lzmat.c:231 lost: the loop ends on `ip < in_len` and returns OK with produced < out_cap (no end marker in the format, so a cut stream is indistinguishable) [Inference: low-medium]");
}

static void nrv2_signals(void)
{
	/* 8-bit NRV2B: a tag byte of all ones = literals, then the literal bytes */
	static const uint8_t in[] = { 0xff, 'a', 'b', 'c' };
	uint8_t out[16];
	uint64_t n = 0;
	enum kuncoat_status st;

	st = kuncoat_nrv2_decode(KUNCOAT_NRV2B, 8, in, sizeof in, out, 2, &n);
	CK(st == KUNCOAT_STOPPED && n == 2u);
	st = kuncoat_nrv2_decode(KUNCOAT_NRV2B, 8, in, sizeof in, out, sizeof out, &n);
	CK(st == KUNCOAT_TRUNCATED && n == 3u);
}

/* ===================================================================== *
 * 8. lzma / lzma2.                                                         *
 * ===================================================================== */

static void lzma_signals(void)
{
	static uint8_t in[1005], out[4096];
	uint64_t n = 0;
	enum kuncoat_status st;

	/* Raw LZMA over zero bytes decodes to a long run of something; what matters
	 * is that stopping short of the stream is always said. */
	memset(in, 0, sizeof in);
	st = kuncoat_lzma_decode(3, 0, 2, in, sizeof in, out, 50, &n);
	CK(st == KUNCOAT_STOPPED && n == 50u);
	st = kuncoat_lzma_decode(3, 0, 2, in, 40, out, sizeof out, &n);
	CK(st == KUNCOAT_TRUNCATED && n < sizeof out);
	CK(kuncoat_lzma_decode(9, 0, 2, in, sizeof in, out, sizeof out, &n) == KUNCOAT_CORRUPT);
}

static void lzma2_signals(void)
{
	/* an uncompressed chunk (control 1, dictionary reset) of 3 bytes */
	static const uint8_t chunk[] = { 0x01, 0x00, 0x02, 'a', 'b', 'c' };
	static const uint8_t ended[] = { 0x01, 0x00, 0x02, 'a', 'b', 'c', 0x00 };
	static const uint8_t cutdata[] = { 0x01, 0x00, 0x02, 'a', 'b' };
	uint8_t out[64];
	uint64_t n = 0;
	enum kuncoat_status st;

	st = kuncoat_lzma2_decode(ended, sizeof ended, out, sizeof out, &n);
	CK(st == KUNCOAT_OK && n == 3u);
	st = kuncoat_lzma2_decode(ended, sizeof ended, out, 2, &n);
	CK(st == KUNCOAT_STOPPED && n == 2u);
	st = kuncoat_lzma2_decode(cutdata, sizeof cutdata, out, sizeof out, &n);
	CK(st == KUNCOAT_TRUNCATED && n == 2u);

	/* No 0x00 end byte: the stream was cut exactly at a chunk boundary. */
	st = kuncoat_lzma2_decode(chunk, sizeof chunk, out, sizeof out, &n);
	CK(n == 3u);
	KM_CHECK(st != KUNCOAT_OK,
		 "LZMA2 stream with no 0x00 end byte (cut at a chunk boundary), room left, reports OK",
		 "kuncoat_lzma2_decode lzma.c:575 lost: `while (p < in_len && at < out_cap)` leaves on input end with status OK; a missing end marker is never TRUNCATED [Inference: low]");
}

/* ===================================================================== *
 * 9. bunzip: a second concatenated stream that is cut.                     *
 * ===================================================================== */

static struct kuncoat_bunzip *bz_state;

static int bz_sink(void *user, const uint8_t *p, uint32_t n)
{
	(void)p;
	*(uint64_t *)user += n;
	return 1;
}

static void bunzip_signals(void)
{
	/* an empty stream: header, end-of-stream magic, combined CRC 0 */
	static const uint8_t empty[14] = { 'B', 'Z', 'h', '9', 0x17, 0x72, 0x45, 0x38, 0x50,
					   0x90, 0, 0, 0, 0 };
	uint8_t in[64];
	uint64_t got = 0, n = 0;
	enum kuncoat_status st;

	bz_state = malloc(sizeof *bz_state);
	if (!bz_state) {
		printf("  FAIL no memory for the bunzip state\n");
		fails++;
		return;
	}
	st = kuncoat_bunzip_decode(bz_state, empty, sizeof empty, bz_sink, &got, &n);
	CK(st == KUNCOAT_OK);
	/* the stream cut inside its end-of-stream CRC: TRUNCATED */
	st = kuncoat_bunzip_decode(bz_state, empty, 12, bz_sink, &got, &n);
	CK(st == KUNCOAT_TRUNCATED);
	/* a whole stream and then the first nine bytes of another one */
	memcpy(in, empty, sizeof empty);
	memcpy(in + sizeof empty, "BZh9\x31\x41\x59\x26\x53", 9);
	st = kuncoat_bunzip_decode(bz_state, in, sizeof empty + 9u, bz_sink, &got, &n);
	KM_CHECK(st != KUNCOAT_OK,
		 "bunzip: a concatenated second stream cut after 9 bytes reports OK",
		 "kuncoat_bunzip_decode bunzip.c:506 lost: `if (at + 10 > in_len) break;` drops a cut member header silently; the reference tool at least warns [Inference: low]");
	free(bz_state);
}

/* ===================================================================== *
 * 10. lzx: an uncompressed block asked for more than the stream holds.     *
 * ===================================================================== */

static struct kuncoat_lzx *lzx_state;

struct lw {                     /* LZX bit order: 16-bit LE words, MSB first */
	uint8_t  b[80000];
	size_t   n;
	uint32_t acc, cnt;
};

static void lw_bits(struct lw *w, uint32_t v, uint32_t k)
{
	uint32_t i;

	for (i = 0; i < k; i++) {
		w->acc = (w->acc << 1) | ((v >> (k - 1u - i)) & 1u);
		if (++w->cnt == 16u) {
			w->b[w->n++] = (uint8_t)w->acc;
			w->b[w->n++] = (uint8_t)(w->acc >> 8);
			w->acc = 0;
			w->cnt = 0;
		}
	}
}

static void lw_align(struct lw *w)
{
	if (w->cnt)
		lw_bits(w, 0, 16u - w->cnt);
}

static enum kuncoat_status run_lzx(const uint8_t *in, uint64_t n, uint64_t skip,
				   uint64_t take, struct rec *r, uint64_t *produced)
{
	struct kuncoat_lzx_req rq;
	struct kuncoat_io io;
	enum kuncoat_status st;

	rq.window_bits = 16;
	rq.skip = skip;
	rq.take = take;
	memset(&io, 0, sizeof io);
	io.in.p = in;
	io.in.n = n;
	io.sink = rec_sink;
	io.user = r;
	st = kuncoat_lzx_decode(lzx_state, &rq, &io);
	*produced = io.produced;
	return st;
}

static void lzx_signals(void)
{
	static struct lw w;
	static uint8_t sink_buf[80000];
	struct rec r;
	uint64_t produced = 0, i;
	enum kuncoat_status st;
	const uint32_t len = 70000;

	lzx_state = malloc(sizeof *lzx_state);
	if (!lzx_state) {
		printf("  FAIL no memory for the lzx state\n");
		fails++;
		return;
	}
	memset(&w, 0, sizeof w);
	lw_bits(&w, 0, 1);                      /* no E8 translation */
	lw_bits(&w, 3, 3);                      /* an uncompressed block */
	lw_bits(&w, len >> 8, 16);
	lw_bits(&w, len & 0xffu, 8);
	lw_align(&w);
	for (i = 0; i < 3u; i++) {              /* r0 r1 r2 */
		lw_bits(&w, 1, 16); lw_bits(&w, 0, 16);
	}
	for (i = 0; i < len; i++)               /* the bytes, as words (LE) */
		w.b[w.n++] = (uint8_t)(i * 13u + 5u);
	/* (the byte writer above bypassed the bit accumulator: it is empty) */

	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_lzx(w.b, w.n, 0, 100, &r, &produced);
	CK(st == KUNCOAT_OK && produced == 100u && r.got == 100u);
	CK(sink_buf[0] == 5u && sink_buf[1] == 18u);

	/* take more than the stream has: the input ends first. TRUNCATED. */
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_lzx(w.b, w.n, 0, 79000, &r, &produced);
	CK(st == KUNCOAT_TRUNCATED);
	CK(produced == len && r.got == len);

	/* skip past the end of what exists, take something: nothing came out and
	 * the status must not be OK. */
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf;
	st = run_lzx(w.b, w.n, 75000, 100, &r, &produced);
	CK(st != KUNCOAT_OK && produced == 0u);

	/* a refusing sink is STOPPED */
	memset(&r, 0, sizeof r); r.buf = sink_buf; r.cap = sizeof sink_buf; r.refuse_after = 1;
	st = run_lzx(w.b, w.n, 0, 69000, &r, &produced);
	CK(st == KUNCOAT_STOPPED);
	free(lzx_state);
}

/* ===================================================================== *
 * 11. bcj2: the bare count is the only signal.                             *
 * ===================================================================== */

static void bcj2_signals(void)
{
	static const uint8_t main_s[3] = { 'a', 'b', 'c' };
	static const uint8_t rc[5] = { 0, 0, 0, 0, 0 };
	static const uint8_t none[1] = { 0 };
	uint8_t out[16];
	struct kuncoat_bcj2_io io;

	memset(&io, 0, sizeof io);
	io.main_s.p = main_s; io.main_s.n = sizeof main_s;
	io.call_s.p = none;
	io.jump_s.p = none;
	io.rc_s.p = rc; io.rc_s.n = sizeof rc;
	io.out = out;
	io.out_cap = sizeof out;
	CK(kuncoat_bcj2_decode(&io) == 3u);        /* short of out_cap: a stream ran out */
	io.out_cap = 2;
	CK(kuncoat_bcj2_decode(&io) == 2u);
}

/* ===================================================================== *
 * 12. ppmd: the arena ceiling is silent.                                    *
 * ===================================================================== */

static void ppmd_signals(void)
{
	/* RAR's block header: the arena in MB less one. The sample set measured in
	 * ppmd.h has blocks that ask for 251 MB; the build clamps to 64 MB. A model
	 * with less memory than the encoder's restarts at a DIFFERENT point and the
	 * bytes after it are wrong. rar3.c:770 passes the clamped number straight to
	 * kuncoat_ppmd_start; nothing records that the request was cut. */
	uint64_t asked = (250u + 1u) << 20;

	CK(kuncoat_ppmd_arena_want(24) == 25u << 20);       /* the default: honoured */
	KM_CHECK(kuncoat_ppmd_arena_want(250) == asked,
		 "PPMd block asking for 251 MB is given 64 MB with no signal",
		 "ARENA_MAX ppmd.c:49 lost: kuncoat_ppmd_arena_want clamps silently and rar3.c:770 never compares; output after the first model restart diverges from the encoder's [Inference: needs a >64MB model to show]");
}

int main(void)
{
	transform_caps();
	textcode_caps();
	inflate_signals();
	lzw_signals();
	lzhuf_signals();
	ovba_signals();
	aplib_signals();
	lzmat_signals();
	nrv2_signals();
	lzma_signals();
	lzma2_signals();
	bunzip_signals();
	lzx_signals();
	bcj2_signals();
	ppmd_signals();

	printf("%s: %d failure(s), %u known miss(es)\n", __FILE__, fails, km_known());
	return fails != 0 || km_failed();
}
