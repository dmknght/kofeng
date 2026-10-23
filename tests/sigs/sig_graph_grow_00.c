/*
 * sig_graph_grow_00.c - reads the diagnose graph of an object that carries a marker.
 *
 * WHY IT EXISTS. The graph block a module reads (kof_diag_graph) was allocated once per
 * scanner, sized by the FIRST object that had nodes; a later object with more nodes made the
 * builder refuse whole and the graph read as absent - a verdict over it answered "nothing"
 * with no signal. tests/unit/silent_cuts_engine.c scans a small object and then a large one
 * on the same scanner and expects this rule to see the large object's nodes.
 *
 * It fires only on an object holding the marker below, so no other fixture of the suite can
 * meet it, and only when the graph holds at least 20 nodes.
 */

#include <kofmod/kofsig.h>
#include <kofmod/kofdiagtree.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_UNKNOWN);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "GraphGrowTest");

KOF_TARGET_RANGE(everything, KOF_SCAN_ALL);
KOF_DEFINE_STR(marker, "GRAPHGROW-MARK", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	uint32_t n = 0;
	const uint8_t *g;

	if (!kof_find_str(everything, marker))
		return;
	g = kof_diag_graph(&n);
	if (kof_gr_count(g, n) >= 20u)
		{ kof_debug("GraphGrowTest#00", 0); return; }
}
