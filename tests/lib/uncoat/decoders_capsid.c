/*
 * decoders_capsid - the keyed ciphers of libuncoat's transform (the ones a module can ask the host to run), against loops
 * written out the plain way here.
 *
 * The three modules that used to carry these loops are tested through the whole
 * engine (msf_xor, msf_x86); this pins the loops themselves, so a change to one
 * is caught where it is made and not three modules away. Each case states which
 * property it is about, and the reference is the arithmetic of the stub the
 * cipher was lifted from, spelled as that stub does it.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <uncoat.h>

static int failures;

/* The bytes written; the status of the last call is kept for the cases that are
 * about it. */
static enum kuncoat_status last;

static uint64_t capsid_run(const struct kuncoat_step *c, const uint8_t *in, uint64_t n,
			   uint8_t *out, uint64_t cap)
{
	uint64_t got = 0;

	last = kuncoat_transform(c, in, n, out, cap, &got);
	return got;
}

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

static void fill(uint8_t *p, unsigned n, uint32_t seed)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		seed = seed * 1103515245u + 12345u;
		p[i] = (uint8_t)(seed >> 16);
	}
}

int main(void)
{
	uint8_t in[300], out[300], ref[300];
	struct kuncoat_step c;
	unsigned i, kl;

	uint64_t got;

	memset(&c, 0, sizeof c);
	fill(in, sizeof in, 7);

	/* ---- repeating key: every key length, against the textbook loop ---- */
	for (kl = 1; kl <= 9; kl++) {
		uint8_t key[9];

		fill(key, kl, 100 + kl);
		for (i = 0; i < sizeof in; i++)
			ref[i] = (uint8_t)(in[i] ^ key[i % kl]);
		c.algo = KUNCOAT_ALGO_XOR_KEY;
		c.k32 = 0;
		c.key = key;
		c.key_len = kl;
		got = capsid_run(&c, in, sizeof in, out, sizeof out);
		check(got == sizeof in && !memcmp(out, ref, sizeof in),
		      "xor key: the keystream repeats and matches the reference");
	}

	/* ---- a constant dword is the same cipher with its four bytes ---- */
	{
		const uint32_t k = 0xa1b2c3d4u;
		uint8_t kb[4] = { 0xd4, 0xc3, 0xb2, 0xa1 };

		c.algo = KUNCOAT_ALGO_XOR_KEY;
		c.key = kb;
		c.key_len = 4;
		got = capsid_run(&c, in, 40, out, sizeof out);
		for (i = 0; i < 40; i += 4) {
			uint32_t w = (uint32_t)in[i] | ((uint32_t)in[i + 1] << 8) |
				     ((uint32_t)in[i + 2] << 16) | ((uint32_t)in[i + 3] << 24);
			uint32_t o = (uint32_t)out[i] | ((uint32_t)out[i + 1] << 8) |
				     ((uint32_t)out[i + 2] << 16) | ((uint32_t)out[i + 3] << 24);

			check(o == (w ^ k), "xor key: four bytes act as a little-endian dword");
		}
	}

	/* ---- in place, and the room it is given ---- */
	{
		uint8_t key[3] = { 1, 2, 3 }, buf[64];

		memcpy(buf, in, 64);
		c.key = key;
		c.key_len = 3;
		got = capsid_run(&c, buf, 64, buf, 64);
		check(got == 64, "in place: every byte is processed");
		for (i = 0; i < 64; i++)
			if (buf[i] != (uint8_t)(in[i] ^ key[i % 3]))
				break;
		check(i == 64, "in place: the result is the same as into another buffer");
		got = capsid_run(&c, in, 64, out, 10);
		check(got == 10, "the output room bounds what is written");
		got = capsid_run(&c, in, 5, out, 64);
		check(got == 5, "the input bounds what is read");
	}

	/* ---- counter: byte k is xored with k + start ---- */
	c.algo = KUNCOAT_ALGO_XOR_COUNTER;
	c.k32 = 1;
	c.key = 0;
	c.key_len = 0;
	got = capsid_run(&c, in, 200, out, sizeof out);
	for (i = 0; i < 200; i++)
		if (out[i] != (uint8_t)(in[i] ^ (uint8_t)(i + 1u)))
			break;
	check(got == 200 && i == 200, "counter: byte k is xored with k + 1");
	c.k32 = 250;
	got = capsid_run(&c, in, 20, out, sizeof out);
	for (i = 0; i < 20; i++)
		if (out[i] != (uint8_t)(in[i] ^ (uint8_t)(250u + i)))
			break;
	check(got == 20 && i == 20, "counter: the keystream wraps at a byte");

	/* ---- additive feedback: the key feeds on the plaintext, a zero ends it ---- */
	{
		uint8_t plain[40], enc[44];
		uint32_t key = 0x12345678u, k = key, i32;
		unsigned n = 10;                         /* ten dwords, then the zero */

		fill(plain, 40, 31);
		for (i32 = 0; i32 < n; i32++) {
			uint32_t pl = (uint32_t)plain[4 * i32] | ((uint32_t)plain[4 * i32 + 1] << 8) |
				      ((uint32_t)plain[4 * i32 + 2] << 16) |
				      ((uint32_t)plain[4 * i32 + 3] << 24);
			uint32_t cw;

			if (!pl)
				pl = 1, plain[4 * i32] = 1;      /* no early zero */
			cw = pl ^ k;
			enc[4 * i32] = (uint8_t)cw;
			enc[4 * i32 + 1] = (uint8_t)(cw >> 8);
			enc[4 * i32 + 2] = (uint8_t)(cw >> 16);
			enc[4 * i32 + 3] = (uint8_t)(cw >> 24);
			k += pl;
		}
		/* the terminating zero dword */
		enc[40] = (uint8_t)k;
		enc[41] = (uint8_t)(k >> 8);
		enc[42] = (uint8_t)(k >> 16);
		enc[43] = (uint8_t)(k >> 24);
		c.algo = KUNCOAT_ALGO_XOR_ADD32;
		c.k32 = key;
		got = capsid_run(&c, enc, sizeof enc, out, sizeof out);
		check(got == 44, "additive: stops after the zero dword, which is emitted");
		check(!memcmp(out, plain, 40), "additive: the plaintext comes back");
		check(!out[40] && !out[41] && !out[42] && !out[43],
		      "additive: the dword that ended it is zero");
		got = capsid_run(&c, enc, sizeof enc, out, 20);
		check(got == 20, "additive: the output room stops it early, on a dword");
		got = capsid_run(&c, enc, 42, out, sizeof out);
		check(got == 40, "additive: a partial dword at the end of the input is not read");
	}

	/* ---- RC4, against the published vectors ---- */
	{
		static const uint8_t key1[3] = { 'K', 'e', 'y' };
		static const uint8_t want1[9] = { 0xbb,0xf3,0x16,0xe8,0xd9,0x40,0xaf,0x0a,0xd3 };
		static const uint8_t key2[4] = { 'W', 'i', 'k', 'i' };
		static const uint8_t want2[5] = { 0x10,0x21,0xbf,0x04,0x20 };
		uint8_t zeros[16], ks[16];

		c.algo = KUNCOAT_ALGO_RC4;
		c.key = key1;
		c.key_len = 3;
		got = capsid_run(&c, (const uint8_t *)"Plaintext", 9, out, sizeof out);
		check(got == 9 && !memcmp(out, want1, 9), "rc4: Key / Plaintext");
		c.key = key2;
		c.key_len = 4;
		got = capsid_run(&c, (const uint8_t *)"pedia", 5, out, sizeof out);
		check(got == 5 && !memcmp(out, want2, 5), "rc4: Wiki / pedia");
		/* The keystream is the cipher over zeros, which is how a module reads it. */
		memset(zeros, 0, sizeof zeros);
		got = capsid_run(&c, zeros, 16, ks, sizeof ks);
		capsid_run(&c, ks, 16, out, sizeof out);
		check(got == 16 && !memcmp(out, zeros, 16), "rc4: xoring the keystream back gives zeros");
		c.key_len = 0;
		check(capsid_run(&c, zeros, 4, out, 4) == 0, "rc4: no key, nothing");
	}

	/* ---- a template with placeholders ---- */
	{
		uint8_t tpl[16], got_tpl[16], sub[5] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
		unsigned k;

		for (k = 0; k < 16; k++)
			tpl[k] = (uint8_t)(0x40 + k);
		tpl[3] = tpl[7] = tpl[12] = tpl[14] = 0xee;     /* four placeholders */
		c.algo = KUNCOAT_ALGO_PLACEHOLDER_SUB;
		c.k32 = 0xee;
		c.key = sub;
		c.key_len = 3;
		got = capsid_run(&c, tpl, sizeof tpl, got_tpl, sizeof got_tpl);
		check(got == 16, "placeholder: the output is the template's length");
		check(got_tpl[3] == (uint8_t)(0xee - 0x11) && got_tpl[7] == (uint8_t)(0xee - 0x22) &&
		      got_tpl[12] == (uint8_t)(0xee - 0x33), "placeholder: each takes its subtrahend in order");
		check(got_tpl[14] == 0xee, "placeholder: one with no subtrahend left is untouched");
		check(got_tpl[0] == tpl[0] && got_tpl[15] == tpl[15], "placeholder: the rest of the template is untouched");
		c.key_len = 5;
		got = capsid_run(&c, tpl, sizeof tpl, got_tpl, sizeof got_tpl);
		check(got == 16 && got_tpl[14] == (uint8_t)(0xee - 0x44),
		      "placeholder: more subtrahends than placeholders uses what it has");
		check(capsid_run(&c, tpl, sizeof tpl, got_tpl, 6) == 6, "placeholder: the room bounds the output");
	}

	/* ---- the sub chain: dwords pushed after eax was zeroed, last push first ---- */
	{
		uint8_t code[64], dws[16];
		uint32_t d1 = 0x11223344u, d2 = 0x55667788u, eax = 0;
		unsigned at = 0, k;

		code[at++] = 0x54;  code[at++] = 0x58;
		code[at++] = 0x2d;  memset(code + at, 0, 4);  at += 4;      /* sub eax, 0 */
		code[at++] = 0x25;  memset(code + at, 0, 4);  at += 4;      /* and eax, 0 */
		/* push d2, then d1: so the payload's first dword is d1 */
		code[at++] = 0x2d;
		for (k = 0; k < 4; k++)
			code[at + k] = (uint8_t)((eax - d2) >> (k * 8));
		at += 4;
		eax = d2;
		code[at++] = 0x50;
		code[at++] = 0x2d;
		for (k = 0; k < 4; k++)
			code[at + k] = (uint8_t)((eax - d1) >> (k * 8));
		at += 4;
		eax = d1;
		code[at++] = 0x50;
		code[at++] = 0xff;  code[at++] = 0xe4;                      /* jmp esp: the chain ends */
		c.algo = KUNCOAT_ALGO_X86_SUB_CHAIN;
		c.key = 0;
		c.key_len = 0;
		c.k32 = 0;
		got = capsid_run(&c, code, at, dws, sizeof dws);
		check(got == 8, "sub chain: two pushes, two dwords");
		check(dws[0] == 0x44 && dws[1] == 0x33 && dws[2] == 0x22 && dws[3] == 0x11 &&
		      dws[4] == 0x88 && dws[5] == 0x77 && dws[6] == 0x66 && dws[7] == 0x55,
		      "sub chain: the last push is the first dword, written little-endian");
		c.max_out = 4;
		got = capsid_run(&c, code, at, dws, sizeof dws);
		check(got == 4, "sub chain: max_out bounds what the chain may yield");
		c.max_out = 0;
	}

	/* ---- descriptors that are not ciphers answer zero ---- */
	c.algo = KUNCOAT_ALGO_NONE;
	check(capsid_run(&c, in, 8, out, 8) == 0, "no algorithm: nothing");
	c.algo = 99;
	check(capsid_run(&c, in, 8, out, 8) == 0, "an unknown algorithm: nothing");
	c.algo = KUNCOAT_ALGO_XOR_KEY;
	c.key = 0;
	c.key_len = 4;
	check(capsid_run(&c, in, 8, out, 8) == 0, "a key cipher with no key: nothing");
	c.key = in;
	c.key_len = 0;
	check(capsid_run(&c, in, 8, out, 8) == 0, "a key cipher with an empty key: nothing");
	check(capsid_run(0, in, 8, out, 8) == 0, "no descriptor: nothing");
	c.key_len = 2;
	check(capsid_run(&c, in, 0, out, 8) == 0 && capsid_run(&c, in, 8, out, 0) == 0,
	      "nothing in or no room: nothing");

	/* ---- and the status says whether the answer is the whole of it ---- */
	c.algo = KUNCOAT_ALGO_XOR_KEY;
	c.key = in;
	c.key_len = 2;
	(void)capsid_run(&c, in, 8, out, 8);
	check(last == KUNCOAT_OK, "status: a complete xor is OK");
	(void)capsid_run(&c, in, 8, out, 5);
	check(last == KUNCOAT_OVER_BUDGET, "status: a short room is OVER_BUDGET, not a silent cut");
	(void)capsid_run(&c, in, 0, out, 8);
	check(last == KUNCOAT_OK, "status: nothing in is complete and empty");
	c.key = 0;
	(void)capsid_run(&c, in, 8, out, 8);
	check(last == KUNCOAT_BAD_ARG, "status: a key cipher with no key is BAD_ARG");
	c.algo = 99;
	(void)capsid_run(&c, in, 8, out, 8);
	check(last == KUNCOAT_UNSUPPORTED, "status: an unknown algorithm is UNSUPPORTED");
	c.algo = KUNCOAT_ALGO_XOR_ADD32;
	c.k32 = 1;
	(void)capsid_run(&c, in, 42, out, sizeof out);
	check(last == KUNCOAT_TRUNCATED, "status: additive with no end dword and the input out is TRUNCATED");
	c.dir = KUNCOAT_ENCODE;
	(void)capsid_run(&c, in, 8, out, 8);
	check(last == KUNCOAT_UNSUPPORTED, "status: a cipher with no inverse refuses to encode");
	c.dir = KUNCOAT_DECODE;

	if (failures) {
		printf("decoders capsid: %d failure(s)\n", failures);
		return 1;
	}
	printf("decoders capsid: repeating key at every length, a counter, the additive "
	       "feedback and its end, in place, bounded by input and room, and "
	       "refusing what is not a cipher - ok\n");
	return 0;
}
