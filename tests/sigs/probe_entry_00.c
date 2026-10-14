/*
 * probe_entry_00.c - an unpacker for cabinets that takes the parsed entries by
 * index, to exercise the entry slots of the module ABI: unpack_entry
 * (kunp_static_entry), child_entry (kunp_rcstruct_child_entry) and the indices and
 * hints a module may get wrong.
 *
 * bases/decomp/cab.c does the same with the cabinet's own coding for each entry. This
 * one is for a test: it opens the first two entries as stored data and asks, around
 * them, for an entry that does not exist, an index of 2^32-1, a coding the engine
 * does not have and a size hint of 2^64-1. Each answer is a note.
 */

#include <kofmod/kofsig.h>
#include <kofmod/cab.h>

KOF_TARGET_FORMAT(KOF_FMT_CAB);
KOF_ANALYZE_STEP(KOF_ANALYZE_UNWRAP);
KOF_TARGET_CONTENT("Probe");

KOF_DEFINE_UNPACK
{
	const struct kof_cab_info *c = kof_cab(ctx);

	uint32_t cur = 0;

	if (!c || !c->valid)
		return;
	(void)kof_cab_next(ctx, &cur);         /* the table is read through the walk (see zip.c) */
	kof_debug("Probe.entries", c->n_entries);
	kof_debug("Probe.bad_index", kunp_static_entry(KOF_UNP_STORED, 99, 8));
	kof_debug("Probe.max_index", kunp_static_entry(KOF_UNP_STORED, 0xffffffffu, 8));
	kof_debug("Probe.bad_method", kunp_static_entry(0xffffu, 0, 8));
	kof_debug("Probe.e0", kunp_static_entry(KOF_UNP_STORED, 0, 8));
	kunp_rcstruct_child_entry(0);
	kof_debug("Probe.done0", kunp_rcstruct_done());
	kof_debug("Probe.e1", kunp_static_entry(KOF_UNP_STORED, 1, 16));
	kunp_rcstruct_child_entry(1);
	kof_debug("Probe.done1", kunp_rcstruct_done());
	kof_debug("Probe.hint_huge", kunp_static_entry(KOF_UNP_STORED, 0, 0xffffffffffffffffull));
}
