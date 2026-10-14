/*
 * probe_crypt_00.c - an unpacker that asks the host to run each cipher of
 * kofmod/kofdecode.h and notes the answer, so a test can check the arithmetic.
 *
 * It exercises three slots of the module ABI: capsid_apply (a cipher over the
 * module's own buffer), decrypt_peek (a cipher over a range of the object into
 * the module's buffer) and decrypt (a cipher over a range, producing a child).
 * It fires on "KOFPRB05" at offset 0; the byte at offset 8 picks the cipher and the
 * form of the call, and the ciphertext it reads is whatever the test put in the
 * object, so the test - not this file - holds the expected plaintext.
 *
 * The hostile calls are here too: a key of length 0, a NULL key with a length, an
 * algorithm that does not exist, an output buffer of 0 bytes. The descriptor is a
 * module's, so the host may not believe it.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_ANALYZE_STEP(KOF_ANALYZE_UNWRAP);
KOF_TARGET_CONTENT("Probe");

KOF_DEFINE_STR(magic, "KOFPRB05", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

static uint64_t pack8(const uint8_t *b)
{
	uint64_t v = 0;
	uint32_t i;

	for (i = 0; i < 8; i++)
		v |= (uint64_t)b[i] << (8u * i);
	return v;
}

KOF_DEFINE_UNPACK
{
	static const uint8_t key_abc[3] = { 'A', 'B', 'C' };
	static const uint8_t key_rc4[3] = { 'K', 'e', 'y' };
	static const uint8_t in7[7] = { 0, 1, 2, 3, 4, 5, 6 };
	static const uint8_t templ[5] = { 'A', 'x', 'A', 'y', 'A' };
	static const uint8_t subs[2] = { 1, 2 };
	static const uint8_t plain[9] = { 'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't' };
	static const uint8_t chain[24] = {
		0x25, 0x4a, 0x4d, 0x4e, 0x55, 0x25, 0x35, 0x32, 0x31, 0x2a, 0x2d, 0x11, 0x41, 0x52, 0x21, 0x50,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
	};
	uint8_t out[32];
	struct kof_capsid c;
	uint32_t n;

	if (!kof_find_str_at(0u, magic))
		return;
	for (n = 0; n < sizeof out; n++)
		out[n] = 0xee;

	switch (kof_u8(8)) {
	case 1:
		c.algo = KOF_CAPSID_XOR_KEY; c.k32 = 0; c.key = key_abc; c.key_len = 3; c.max_out = 0;
		n = kunp_capsid_apply(&c, in7, 7, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		kof_debug("Probe.guard", out[7]);
		break;
	case 2:
		c.algo = KOF_CAPSID_XOR_KEY; c.k32 = 0; c.key = key_abc; c.key_len = 3; c.max_out = 0;
		kof_debug("Probe.n", kunp_capsid_apply(&c, in7, 7, out, 3));
		kof_debug("Probe.b0", pack8(out));
		kof_debug("Probe.zero_cap", kunp_capsid_apply(&c, in7, 7, out, 0));
		kof_debug("Probe.zero_in", kunp_capsid_apply(&c, in7, 0, out, sizeof out));
		c.max_out = 2;
		kof_debug("Probe.max_out", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		break;
	case 3:
		c.algo = KOF_CAPSID_XOR_KEY; c.k32 = 0; c.key = key_abc; c.key_len = 0; c.max_out = 0;
		kof_debug("Probe.keylen0", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		c.key = 0; c.key_len = 3;
		kof_debug("Probe.nullkey", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		c.key = 0; c.key_len = 0xffffffffu;
		kof_debug("Probe.hugekey", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		c.algo = 99;
		kof_debug("Probe.algo99", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		c.algo = KOF_CAPSID_NONE;
		kof_debug("Probe.none", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		c.algo = 0xffffffffu;
		kof_debug("Probe.algomax", kunp_capsid_apply(&c, in7, 7, out, sizeof out));
		break;
	case 4:
		c.algo = KOF_CAPSID_XOR_COUNTER; c.k32 = 0xfe; c.key = 0; c.key_len = 0; c.max_out = 0;
		n = kunp_capsid_apply(&c, in7, 7, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		break;
	case 5:
		c.algo = KOF_CAPSID_PLACEHOLDER_SUB; c.k32 = 'A'; c.key = subs; c.key_len = 2; c.max_out = 0;
		n = kunp_capsid_apply(&c, templ, 5, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		c.key_len = 0;
		kof_debug("Probe.nosubs", kunp_capsid_apply(&c, templ, 5, out, sizeof out));
		break;
	case 6:
		c.algo = KOF_CAPSID_RC4; c.k32 = 0; c.key = key_rc4; c.key_len = 3; c.max_out = 0;
		n = kunp_capsid_apply(&c, plain, 9, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		kof_debug("Probe.b1", pack8(out + 8));
		c.key_len = 0;
		kof_debug("Probe.keylen0", kunp_capsid_apply(&c, plain, 9, out, sizeof out));
		break;
	case 7:
		c.algo = KOF_CAPSID_X86_SUB_CHAIN; c.k32 = 0; c.key = 0; c.key_len = 0; c.max_out = 0;
		n = kunp_capsid_apply(&c, chain, 24, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		break;
	case 8:
		/* a cipher over the OBJECT, from 16 to the end, into this module's buffer */
		c.algo = KOF_CAPSID_XOR_KEY; c.k32 = 0; c.key = key_abc; c.key_len = 3; c.max_out = 0;
		n = kunp_decrypt_peek(&c, 16, 7, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		kof_debug("Probe.past", kunp_decrypt_peek(&c, ctx->obj_size, 7, out, sizeof out));
		kof_debug("Probe.wrap", kunp_decrypt_peek(&c, 16, 0xffffffffffffffffull, out, sizeof out));
		kof_debug("Probe.max", kunp_decrypt_peek(&c, 0xffffffffffffffffull, 7, out, sizeof out));
		kof_debug("Probe.nocap", kunp_decrypt_peek(&c, 16, 7, out, 0));
		break;
	case 9:
		/* the same cipher, producing a child */
		c.algo = KOF_CAPSID_XOR_KEY; c.k32 = 0; c.key = key_abc; c.key_len = 3; c.max_out = 0;
		kof_debug("Probe.decrypt", kunp_decrypt(&c, 16, 7));
		kof_debug("Probe.past", kunp_decrypt(&c, ctx->obj_size, 7));
		kof_debug("Probe.done", kunp_rcstruct_done());
		break;
	case 10:
		/* the additive dword cipher, over the object */
		c.algo = KOF_CAPSID_XOR_ADD32; c.k32 = 0x11223344u; c.key = 0; c.key_len = 0; c.max_out = 0;
		n = kunp_decrypt_peek(&c, 16, 16, out, sizeof out);
		kof_debug("Probe.n", n);
		kof_debug("Probe.b0", pack8(out));
		kof_debug("Probe.b1", pack8(out + 8));
		break;
	default:
		break;
	}
}
