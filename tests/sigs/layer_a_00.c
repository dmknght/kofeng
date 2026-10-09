/*
 * layer_a_00.c - one layer of a test cipher: four bytes of magic, four in the
 * clear, then the rest XORed with one byte.
 *
 * Three of these exist so the test can nest them in either order. They are
 * DIFFERENT MODULES with different signs and different keys, which is the case
 * the engine has to get right: a decrypt that produced a child must not be the
 * end of the object's examination - see tests/unit/decrypt_layers.c.
 */

#include <kofmod/kofsig.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_DECRYPT);
KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_CONTENT("Layer A");

KOF_DEFINE_STR(magic, "LAYA", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

#define SKIP 8u

KOF_DEFINE_UNPACK
{
	uint8_t buf[256];
	uint64_t i;
	uint32_t k = 0;

	if (!kof_find_str_at(0u, magic) || ctx->obj_size <= SKIP)
		return;
	for (i = SKIP; i < ctx->obj_size; i++) {
		buf[k++] = (uint8_t)(kof_u8(i) ^ 0x5au);
		if (k == sizeof buf) {
			if (!kunp_rcstruct_write(buf, k))
				return;
			k = 0;
		}
	}
	if (k && !kunp_rcstruct_write(buf, k))
		return;
	kunp_rcstruct_done();
}
