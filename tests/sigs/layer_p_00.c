/*
 * layer_p_00.c - a test cipher whose sign is NOT at the start: "LAYP" at offset
 * 0, twelve bytes of header, then the rest XORed with one byte.
 *
 * Three of these (D at 4, E at 8, P at 0) can all hold on one object, so the
 * test can put several modules - in two different steps - on the same bytes and
 * ask whether every one of them is asked. See tests/unit/decrypt_layers.c.
 */

#include <kofmod/kofsig.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);
KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_CONTENT("Layer P");

KOF_DEFINE_STR(magic, "LAYP", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

#define SKIP 12u

KOF_DEFINE_UNPACK
{
	uint8_t buf[256];
	uint64_t i;
	uint32_t k = 0;

	if (!kof_find_str_at(0u, magic) || ctx->obj_size <= SKIP)
		return;
	for (i = SKIP; i < ctx->obj_size; i++) {
		buf[k++] = (uint8_t)(kof_u8(i) ^ 0x77u);
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
