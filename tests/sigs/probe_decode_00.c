/*
 * probe_decode_00.c - an unpacker that asks the host to decode one coded range and makes the
 * result a child, so a test can compare the child's bytes with the plaintext it encoded.
 *
 * It fires on "KOFPRB06" at offset 0. The method id (enum kof_unp_method, including the ids that
 * carry lc/lp/pb or an LZX window) is the 32 bit word at 8, the output hint the 64 bit word at 16,
 * and the coded bytes are everything from 24 on. What the host answers is noted (the byte count
 * kunp_static_decode returns, and whether the child was made); the bytes themselves are the
 * child, which the test's own callback receives - so neither the expected plaintext nor the
 * encoder is in this file.
 *
 * What it exercises is the host's side of the static decoders: the dispatch on the method id,
 * the budget a decode is charged to, the chain-only methods, the ids it does not know, and what
 * is left of a stream that ends early or lies. Nothing here is a detection.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);
KOF_TARGET_CONTENT("Probe");

KOF_DEFINE_STR(magic, "KOFPRB06", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_UNPACK
{
	uint64_t n = ctx->obj_size;

	if (!kof_find_str_at(0u, magic) || n < 24u)
		return;
	kof_debug("Dec.ret", kunp_static_decode(kof_u32(8), 24, n - 24u, kof_u64(16)));
	kof_debug("Dec.done", kunp_rcstruct_done());
}
