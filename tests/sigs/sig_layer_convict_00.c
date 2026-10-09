/*
 * sig_layer_convict_00.c - names an object whose bytes say CONVICT.
 *
 * A named finding at the detect stage makes the engine refuse to open the object
 * (open_gate), which is the state a recovering step must still run in: a
 * convicted program is the one whose description a tool shows first.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ANY);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "LayerConvict");

KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);
KOF_DEFINE_STR(word, "CONVICT", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (kof_find_str(everything, word))
		KOF_SCAN_INFECT("Test");
}
