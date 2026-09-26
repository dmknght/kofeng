/*
 * overlay.c - yield a PE's overlay as an object of its own.
 *
 * The first unpacker, and deliberately the simplest one that exists: the overlay
 * is bytes past everything any structure in the file claimed, the collector has
 * already worked out where it is, and producing it costs nothing at all. It is a
 * WINDOW - the child is the parent's mapping seen through a different offset, with
 * no copy, no decompression and no budget spent.
 *
 * That makes it the right thing to build the child-object machinery on. Everything
 * new gets exercised - a child is produced, it is scanned as an object in its own
 * right, its parent's mapping is kept alive exactly as long as it is needed, and
 * depth and the child count bound it - without a line of format parsing or a
 * decompressor to be wrong at the same time.
 *
 * It is also useful on its own. An installer with an archive appended, a dropper
 * carrying its payload past the last section, a signed binary with data after the
 * certificate: all of them put the interesting part in the overlay, and until now
 * the engine could see it only as bytes inside the parent rather than as an object
 * with its own format, its own regions and its own signatures.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

/* The bound appended_00.c argues for: alignment padding cannot reach a page. */
#define PAGE 4096u

/* And its entropy floor: two bits, which padding never reaches. Same number
 * and same reason - see the measurement below. */
#define MIN_EIGHTHS (8u * 2u)

/*
 * A CARVE AND NOT A CONTAINER, which is what this said and what cost two
 * things silently.
 *
 * A CONTAINER'S MEMBERS ARE DECLARED and the container is the table that
 * declares them - an archive is nothing but its entries, so what came out is
 * the subject and the wrapper is not. An overlay is the opposite: nothing
 * declares it, it is bytes past everything the file claimed, and the PE around
 * it is a complete program that happens to be carrying something. That is
 * exactly what KOF_UNP_CARVE is for, and bases/decomp/appended_00.c - the same
 * job on an ELF's unclaimed tail - has always said so.
 *
 * WHAT THE WRONG KIND COST, both of it invisible:
 *
 *   scan.c's step runner skips NORMZ when UNWRAP produced a child that was not
 *   a carve, so NO PE WITH AN OVERLAY WAS EVER NORMALISED - no unwide, no
 *   decode, on 12% of the PE corpus measured here.
 *
 *   scan.c drops heuristic findings on a parent that yielded a non-carve
 *   child, so a heuristic verdict about the PE was discarded because the PE
 *   had an overlay.
 */
KOF_UNPACK_KIND(KOF_UNP_CARVE);

KOF_TARGET_FORMAT(KOF_FMT_PE);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);

	if (!pe->valid || !pe->overlay_len)
		return;

	/*
	 * AND BIG ENOUGH TO BE A FILE.
	 *
	 * The bound appended_00.c argues for, for the same reason: alignment
	 * padding cannot reach a page, and what is left past the last section
	 * of an ordinary build is padding. Measured over 400 PE samples from
	 * the corpus: 47 carry an overlay and 20 of those are under a page -
	 * 43% of the children this module produced were a few hundred bytes of
	 * slack given a row in the tree, an identification, a budget and a pass
	 * through every module.
	 *
	 * A page is a floor and not a judgement: what sits above it is still
	 * sniffed, parsed and scanned as whatever it turns out to be.
	 */
	if (pe->overlay_len < PAGE)
		return;

	/*
	 * AND NOT PADDING, WHICH IS WHAT MOST OVERLAYS ARE.
	 *
	 * The floor above answers size and says nothing about content, and
	 * content is where this module was wrong. Measured over 300 PE samples
	 * from the corpus: 24 overlays reached a child and the engine could
	 * name three of them - a carried DLL, a ZIP and an EXE, which are
	 * exactly what this module exists to find. The other 21 it could name
	 * nothing about, and the two largest were 9 MB of zeroes and 327 KB of
	 * one byte repeated: whole objects, identified, given a budget and a
	 * pass through every module, for a run of filler that the parent
	 * already shows as KOF_SCAN_PE_OVERLAY.
	 *
	 * The same floor appended_00.c uses against the same mistake. It does
	 * not separate a packed payload from encrypted noise - nothing cheap
	 * does - but it removes the case that is certainly not a file.
	 */
	if (kof_entropy_at(pe->overlay_off, pe->overlay_len) < MIN_EIGHTHS)
		return;

	/*
	 * No length check and no bounds arithmetic here on purpose. The host
	 * clips the window to what the object actually has, so an overlay whose
	 * declared extent runs past the end yields a shorter child rather than a
	 * read past the mapping - the same rule every other byte accessor follows.
	 */
	kof_child_window(pe->overlay_off, pe->overlay_len);
}
