/*
 * layer_u_00.c - a test container: "LAYU", the length of the first member as a
 * little endian u16, then of the second, then the two members back to back.
 *
 * An UNWRAP module, so a test can put a container ahead of the cipher layers
 * and ask whether the members come out and each is then taken apart by the
 * steps that follow - the group the engine runs a tree through, not one step.
 */

#include <kofmod/kofsig.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_UNWRAP);
KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_CONTENT("Layer U");

KOF_DEFINE_STR(magic, "LAYU", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_UNPACK
{
	uint64_t l1, l2;

	if (!kof_find_str_at(0u, magic) || ctx->obj_size < 8u)
		return;
	l1 = kof_u16(4u);
	l2 = kof_u16(6u);
	if (!l1 || !l2 || 8u + l1 + l2 > ctx->obj_size)
		return;
	(void)kunp_rcstruct_window(8u, l1);
	(void)kunp_rcstruct_window(8u + l1, l2);
}
