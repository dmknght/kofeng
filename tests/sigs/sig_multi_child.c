/*
 * sig_multi_child - a container that yields three children at once.
 *
 * tests/unit/scan_logic.c needs an object that is SEVERAL objects, because the
 * questions it asks are about what happens when the walk is told to stop with
 * some of them still waiting: did the file get examined, and was it written down
 * as clean. Nothing else in the test database produces more than one child.
 *
 * The magic sits at offset 0, the first two windows are 16 bytes each, back to
 * back from offset 8, and the third runs from offset 40 to the end of the object -
 * which is where a test puts the one child that has something in it.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_ANALYZE_STEP(KOF_ANALYZE_UNWRAP);

KOF_DEFINE_STR(magic, "KOFMULTI", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_UNPACK
{
	if (!kof_find_str_at(0u, magic) || ctx->obj_size <= 40u)
		return;
	(void)kunp_rcstruct_window(8u, 16u);
	(void)kunp_rcstruct_window(24u, 16u);
	(void)kunp_rcstruct_window(40u, ctx->obj_size - 40u);
}
