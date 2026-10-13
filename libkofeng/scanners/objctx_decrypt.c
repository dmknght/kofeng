/*
 * objctx_decrypt.c - a cipher a module named, run by the engine.
 *
 * WHAT THIS SERVES: the module ABI's cipher descriptor (kofmod/kofdecode.h)
 * turned into the lib's transform step, under the same budget a decoder is held
 * to. Nothing here decides what the plaintext is.
 */


#include "objctx_decomp.h"
#include <stdlib.h>

/*
 * THE MODULE ABI'S CIPHER DESCRIPTOR, as the lib's transform step.
 *
 * The descriptor and its ids (kofmod/kofdecode.h) are the engine's and stay as
 * they are for the modules built against them; the lib has its own step and its
 * own ids, and this is the one place the two meet. An id the engine does not know
 * becomes ALGO_NONE, which the lib answers UNSUPPORTED.
 *
 * What the ABI slot returns is a COUNT - the bytes produced - and 0 for "not a
 * cipher", "nothing to do" and "no room" alike, as it always did: the slot's
 * signature is what the modules compiled against. The lib's status is dropped
 * here and nowhere else.
 */
static uint64_t capsid_run(const struct kof_capsid *c, const uint8_t *in, uint64_t n,
			   uint8_t *out, uint64_t cap)
{
	struct kuncoat_step s;
	uint64_t got = 0;

	if (!c)
		return 0;
	switch (c->algo) {
	case KOF_CAPSID_XOR_KEY:         s.algo = KUNCOAT_ALGO_XOR_KEY; break;
	case KOF_CAPSID_XOR_COUNTER:     s.algo = KUNCOAT_ALGO_XOR_COUNTER; break;
	case KOF_CAPSID_XOR_ADD32:       s.algo = KUNCOAT_ALGO_XOR_ADD32; break;
	case KOF_CAPSID_PLACEHOLDER_SUB: s.algo = KUNCOAT_ALGO_PLACEHOLDER_SUB; break;
	case KOF_CAPSID_X86_SUB_CHAIN:   s.algo = KUNCOAT_ALGO_X86_SUB_CHAIN; break;
	case KOF_CAPSID_RC4:             s.algo = KUNCOAT_ALGO_RC4; break;
	default:                         s.algo = KUNCOAT_ALGO_NONE; break;
	}
	s.dir = KUNCOAT_DECODE;
	s.flags = 0;
	s.k32 = c->k32;
	s.key = c->key;
	s.key_len = c->key_len;
	s.max_out = c->max_out;
	(void)kuncoat_transform(&s, in, n, out, cap, &got);
	return got;
}

/*
 * A CIPHER A MODULE NAMED, run by the host - see kofmod/kofdecode.h.
 *
 * THE SAME BUDGET AS A DECODER'S. The plaintext is as long as the ciphertext for
 * the stream ciphers, so the room the scan has left is checked against the range
 * before anything is allocated, and the bytes are charged and released the way
 * oc_unpack_textcode's are: a module cannot decrypt its way around the ceiling a
 * decompression is held to.
 *
 * CLIPPED, NOT REFUSED, like every range a module hands in: the length came out of
 * the file, and what is really there is what gets decrypted.
 */
uint64_t oc_decrypt(const struct kof_obj_ctx *ctx, const struct kof_capsid *c,
		    uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t room, got, at;
	uint8_t *buf;
	kof_buf b;

	if (!sc->cur.src || !c)
		return 0;
	b = kof_src_buf(sc->cur.src);
	len = kof_clip_len(b.n, off, len);
	if (!len)
		return 0;
	room = oc_scan_room(sc);
	if (len > room) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	buf = malloc((size_t)len);
	if (!buf) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, len);
	got = capsid_run(c, b.p + off, len, buf, len);
	at = got ? oc_emit_all(ctx, buf, got) : 0;
	free(buf);
	oc_scan_release(sc, len);
	return at;
}

/* The same into the caller's buffer, which is also the only size involved: what a
 * hostile object declares sizes nothing here. */
uint32_t oc_decrypt_peek(const struct kof_obj_ctx *ctx, const struct kof_capsid *c,
			 uint64_t off, uint64_t len, void *out, uint32_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b;

	if (!sc->cur.src || !c || !out || !cap)
		return 0;
	b = kof_src_buf(sc->cur.src);
	len = kof_clip_len(b.n, off, len);
	if (!len)
		return 0;
	return (uint32_t)capsid_run(c, b.p + off, len, (uint8_t *)out, cap);
}

/* A cipher over the module's own bytes: no object, no scanner, no budget - the
 * caller's buffers are the only sizes. */
uint32_t oc_capsid_apply(const struct kof_capsid *c, const void *in, uint32_t n,
			 void *out, uint32_t cap)
{
	if (!in || !out)
		return 0;
	return (uint32_t)capsid_run(c, (const uint8_t *)in, n, (uint8_t *)out, cap);
}
