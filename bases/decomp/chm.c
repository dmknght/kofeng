/*
 * chm.c - the pages inside a help file.
 *
 * WHY A MODULE FOR THIS. A CHM keeps its content in one LZX stream, so a page
 * is not a range of the file: it is a length at a position in what that stream
 * decodes to. The host opens carried files generically when they are ranges -
 * see kof_objtree_declared - and deliberately does not when they are not, which
 * is where this comes in. The entries in the UNCOMPRESSED section are still the
 * host's and are skipped here, or every one of them would arrive twice.
 *
 * WHAT ONE PAGE COSTS, and it is what makes this affordable to do per entry
 * rather than once. The stream restarts every `lzx_reset_interval` frames of
 * 32KB, and the parse has already worked out which restart each entry sits
 * behind - so reaching a page decodes at most one interval of run-up plus the
 * page. A cabinet's coded folder has no restarts at all and costs a decode of
 * the whole folder per file, which is why bases/decomp/cab.c stops after
 * sixteen and this does not need to stop nearly as early.
 *
 * WHAT IS NOT OPENED is what the parse could not place: a section whose
 * ControlData is missing or is not LZX, and an entry past the last row of the
 * reset table. Those are counted in the view and said below. They are not
 * engine failure - see chm.h.
 */

#include <kofmod/kofsig.h>
#include <kofmod/chm.h>

KOF_TARGET_FORMAT(KOF_FMT_CHM);
/*
 * A CONTAINER, not a packer: a help file carries pages that were separately
 * written. Depth through it is a directory tree rather than a layer of packing,
 * and a heuristic that weighs "this was packed" must not weigh this.
 */
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

/*
 * HOW MANY PAGES ONE HELP FILE GIVES UP.
 *
 * A bound on work rather than on interest, and a generous one because each page
 * costs an interval of run-up and not a whole stream - see the note at the top.
 * A help file carrying a payload carries it among tens of pages; the ones with
 * thousands are documentation, where the thousandth page is prose and the
 * budget is better spent elsewhere. What is skipped is counted and said.
 */
#define CHM_CODED_MAX 256u

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_chm_info *c = kof_chm(ctx);
	uint32_t i, opened = 0, done = 0, skipped = 0;

	if (!c->valid || !c->lzx_window_bits)
		return;

	for (i = 0; i < c->n_entries; i++) {
		const struct kof_entry *e = &c->entry[i];

		/* A plain range is the host's to open - see
		 * kof_objtree_declared - and only a coded entry is scattered. */
		if (!(e->flags & KOF_ENT_F_SCATTERED) || !e->coding[0])
			continue;
		if (done >= CHM_CODED_MAX) {
			skipped++;
			continue;
		}
		done++;
		/* The name the entry already carries, so the child is called
		 * what the help file calls it rather than a number. */
		kof_name_next(e->name_off, e->name_len);
		/*
		 * The window the file declared, which is not in the stream -
		 * see lzx.h. out_hint carries how far past the restart the page
		 * begins and how long it is.
		 */
		if (!kof_unpack_entry(e->coding[0], e->index, e->out_hint))
			continue;
		if (!kof_child())
			break;
		opened++;
	}

	kof_debug("Chm.pages", opened);
	/* Everything the section holds, and the part of it no restart point
	 * reaches. Facts and not damage - see the note at the top. */
	kof_debug("Chm.coded", c->n_compressed);
	kof_debug("Chm.unreachable", c->n_unreachable);
	kof_debug("Chm.skipped", skipped);
}
