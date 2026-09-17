/*
 * cab.c - join the pieces of a cabinet's stored files.
 *
 * WHY A MODULE FOR THIS AT ALL, when every other file in a cabinet needs none.
 *
 * A stored file that fits inside one CFDATA block is a plain range, and the
 * host opens those generically from the entry table - see
 * kof_objtree_declared, which is why CAB, LHA and ARJ ship without a module
 * each. What that step deliberately does NOT do is scattered entries: joining
 * pieces is a copy and a budget, which is a different operation from pointing
 * at bytes that are already there, and it says so where it skips them.
 *
 * A cabinet makes that the ordinary case rather than an edge. A block holds at
 * most 32KB, so EVERY stored file larger than that has a block header in the
 * middle of it and arrives here as pieces. Without this module a scan reads a
 * cabinet's small files and silently ignores its large ones, which is the worst
 * way round.
 *
 * NOTHING IS DECODED. KOF_UNP_STORED joins and emits; a folder this build
 * cannot decode has no pieces to join and is not offered - the parse counts
 * those and says so in the view, and the file is not reported broken over them,
 * for the reason pdf.c records about codings an engine simply lacks.
 */

#include <kofmod/kofsig.h>
#include <kofmod/cab.h>

KOF_TARGET_FORMAT(KOF_FMT_CAB);
/*
 * A CONTAINER, not a packer: a cabinet carries files that were separately
 * there. Depth through it is a directory tree rather than a layer of packing,
 * and a heuristic that weighs "this was packed" must not weigh this.
 */
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

/*
 * HOW MANY CODED FILES ONE CABINET GIVES UP.
 *
 * Each costs a decode of its whole folder - see the note at the call - so this
 * bounds work rather than interest. Sixteen because a cabinet carrying a
 * payload carries it among a handful of files; the ones with hundreds are
 * installers, where the hundredth file is a resource and the budget is better
 * spent elsewhere. What is skipped is counted and said.
 */
#define CAB_CODED_MAX 16u

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_cab_info *c = kof_cab(ctx);
	uint32_t i, opened = 0, coded_done = 0, skipped = 0;

	if (!c->valid)
		return;

	for (i = 0; i < c->n_entries; i++) {
		const struct kof_entry *e = &c->entry[i];

		/* The contiguous ones are the host's - opening them here would
		 * produce every small file twice. */
		if (!(e->flags & KOF_ENT_F_SCATTERED))
			continue;

		/* The name the entry already carries, so the child is called
		 * what the cabinet calls it rather than a number. */
		kof_name_next(e->name_off, e->name_len);
		if (c->coded[i]) {
			/*
			 * A CODED FOLDER, WHICH IS A DECODE OF ALL OF IT.
			 *
			 * The pieces are the folder's blocks and the file is
			 * somewhere inside what they decode to, so out_hint
			 * carries where - see KOF_UNP_MSZIP. The parse only
			 * offers an entry for a coding the host has, so
			 * reaching here means MSZIP.
			 *
			 * ONE FOLDER DECODE PER FILE, which is why this stops
			 * after a bounded number of them: a folder holding two
			 * hundred files would otherwise be decoded two hundred
			 * times, and the budget would end the scan of the
			 * cabinet somewhere arbitrary rather than here.
			 */
			if (coded_done >= CAB_CODED_MAX) {
				skipped++;
				continue;
			}
			coded_done++;
			if (!kof_unpack_entry(KOF_UNP_MSZIP, e->index,
					      e->out_hint))
				continue;
		} else if (!kof_unpack_entry(KOF_UNP_STORED, e->index, e->len)) {
			continue;
		}
		if (!kof_child())
			break;
		opened++;
	}

	kof_debug("Cab.joined", opened);
	/* What the parse could not describe: files in a coded folder, and
	 * pieces that did not fit the pool. Reported as facts and not as
	 * damage - see the note at the top. */
	kof_debug("Cab.coded", c->n_coded);
	kof_debug("Cab.split", c->n_split);
	/* Coded files past the cap above: present, describable, and not opened
	 * by this pass. */
	kof_debug("Cab.skipped", skipped);
}
