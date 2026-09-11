/*
 * objtree.c - the object tree: which children exist, and where they come from.
 *
 * See objtree.h for why this is a unit of its own and for the order the two
 * sources of a child are consulted in.
 */

#include "objtree.h"
#include "scan.h"

/*
 * One place, so that every step of descending asks the same question of the
 * same field.
 *
 * A function rather than the test written at each site: there are several sites
 * - production, the walk that takes the children, the emulator - and a policy
 * spread over several sites is one that ends up applied at some of them. That
 * is exactly the bug this replaced: the old flag was read where children are
 * PUSHED and nowhere else, so every container was opened in full first and the
 * results were then dropped.
 *
 * AND THE FIELD IS heur_off, NOT A DEEP-SCAN FLAG OF ITS OWN. --heur 0 means
 * "name families and nothing else": no facts gathered, nothing scored, no
 * evidence produced that is not a match. What is inside a container is that
 * kind of evidence, so the caller who asked for the cheapest pass has already
 * said not to descend, and a second switch could only disagree with the first.
 *
 * NULL opt is "no policy given, so nothing is forbidden", which is what every
 * other option read on this path does with it.
 */
int kof_objtree_may_open(const struct kof_scan_option *opt)
{
	return !opt || !opt->heur_off;
}

/* ---- carried files ---------------------------------------------------------- */

/*
 * The carried files this object's structure named, opened as children.
 *
 * NO ARRAY AND NO CEILING OF ITS OWN, which is how this was first written - it
 * collected the ranges into a fixed 32 and windowed them afterwards. Two things
 * were wrong with that.
 *
 * The array existed only to hand the declared ranges to a SEARCH that would
 * then avoid them, and that search is not here any more - it belongs to the
 * database, per studied case. With nothing to hand them to, collecting them is
 * a copy for its own sake.
 *
 * And the ceiling was SILENT. A document declaring more attachments than the
 * number would have had the rest dropped with nothing said, which is the one
 * answer this engine must never give quietly. The bound that belongs here is
 * the one that already exists and already reports: kid_push refuses past
 * kids_left and records KOF_BROKEN_LIMIT, because "a container that yields more
 * children than the caller allows has not been fully examined". Adding a second
 * lower bound of my own could only hide that one.
 *
 * CLIPPED AND NOT TRUSTED. Every field in an entry was derived from bytes
 * somebody else wrote, and a parser is expected to have clipped them already -
 * but "expected to" is not a property the engine can rest a read on, and this
 * is the last place before one. A row that does not fit is DROPPED rather than
 * truncated: a truncated attachment is a different file, and scanning a
 * different file under this one's name is worse than not scanning it.
 */
uint32_t kof_objtree_declared(const struct kof_obj_ctx *ctx,
			      const struct kof_scan_option *opt)
{
	const struct kof_entry *tab = NULL;
	uint32_t n, i, made = 0;

	if (!kof_objtree_may_open(opt))
		return 0;
	if (!ctx->entries || !ctx->content || !ctx->content->window)
		return 0;
	n = ctx->entries(ctx, &tab);
	if (!tab)
		return 0;

	for (i = 0; i < n; i++) {
		const struct kof_entry *e = &tab[i];

		if (e->kind != KOF_ENT_EMBEDDED)
			continue;
		/*
		 * A chain rather than a range, so there is nothing to window.
		 *
		 * Opening one means asking resolve_entry and joining the
		 * pieces, which is a copy and a budget - a different operation
		 * from pointing at bytes that are already there. It belongs
		 * with the entry-opening path and not here, so it is skipped
		 * rather than half-done.
		 */
		if (e->flags & KOF_ENT_F_SCATTERED)
			continue;
		if (!e->len)
			continue;
		if (e->off > ctx->obj_size || e->len > ctx->obj_size - e->off)
			continue;

		/*
		 * AND ONLY IF ANYTHING WOULD LOOK INSIDE IT.
		 *
		 * AFTER THE CLIP AND NEVER BEFORE IT. Every field of this row
		 * came out of bytes somebody else wrote, `format` included, so
		 * an unvalidated row is not a policy input - it is an
		 * instruction from the file about what the engine should
		 * bother to open. Validate, then decide.
		 *
		 * A declared carried file almost always answers UNKNOWN here,
		 * which is always wanted - a parser that named the format of
		 * an attachment would be guessing. The question is asked
		 * anyway because this loop is not PDF's: a container that DOES
		 * know what it is carrying gets the same saving the
		 * decompressors get, without a second mechanism.
		 */
		if (ctx->content->fmt_wanted &&
		    !ctx->content->fmt_wanted(ctx, e->format))
			continue;

		/*
		 * THE NAME THE ENTRY ALREADY CARRIES, and this is why the entry
		 * carries it.
		 *
		 * struct kof_entry holds the name as a RANGE IN THIS OBJECT -
		 * never as a string, because the name is already in the file
		 * and a parser has nowhere to build one - and the only reason
		 * for it to be there is so the child can be named. Windowing
		 * without it produced exactly the fault this whole design
		 * exists to remove: a child with no name, which a listing shows
		 * as a number and a viewer shows as raw. Verified on a built
		 * document whose attachment declares /Type /EmbeddedFile: the
		 * entry table said "EmbeddedFile" and the child came out
		 * unnamed.
		 *
		 * UNCONDITIONALLY, including when name_len is zero, because
		 * name_next CLEARS the pending label first. Guarded on the
		 * length instead, a row with no name would leave the PREVIOUS
		 * row's label pending and the next child would wear it - the
		 * off-by-one that once put an image's name on a later content
		 * stream, where four rows of twelve were wrong and every one of
		 * them looked plausible.
		 */
		if (ctx->content->name_next)
			ctx->content->name_next(ctx, e->name_off, e->name_len);
		/*
		 * AND WHAT THE PARSER WAS WILLING TO CALL IT.
		 *
		 * The other half of the entry that was going unused. A child
		 * with no format is offered only to modules targeting unknown,
		 * which measured as every rule refused at the target test and
		 * none run - so a child nobody can name is work already done
		 * for nothing. KOF_FMT_UNKNOWN here is not a gap: it is the
		 * parser declining, which is the right answer for an
		 * attachment whose contents the container does not know, and
		 * the sniff chain then decides.
		 */
		if (ctx->content->child_format)
			ctx->content->child_format(ctx, e->format);
		/* And what it is for, which also names it when name_next above
		 * found nothing - see child_kind. */
		if (ctx->content->child_kind)
			ctx->content->child_kind(ctx, e->kind);
		/* And which entry it is, so a host can show one row for the
		 * declared extent and its content rather than two. */
		if (ctx->content->child_entry)
			ctx->content->child_entry(ctx, e->index);

		/*
		 * A window and not an emit: the bytes are in the parent
		 * already, and copying them would charge the budget for
		 * something the scanner can look at through a different offset.
		 */
		if (!ctx->content->window(ctx, e->off, e->len))
			break;      /* refused, and kid_push has said why */
		made++;
	}
	return made;
}
