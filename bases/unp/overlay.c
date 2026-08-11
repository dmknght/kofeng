/*
 * unp_overlay.c - yield a PE's overlay as an object of its own.
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

KOF_TARGET_FORMAT(KOF_FMT_PE);

KOF_DEFINE_UNPACK
{
	const struct kof_pe_info *pe = kof_pe(ctx);

	if (!pe->valid || !pe->overlay_len)
		return;

	/*
	 * No length check and no bounds arithmetic here on purpose. The host
	 * clips the window to what the object actually has, so an overlay whose
	 * declared extent runs past the end yields a shorter child rather than a
	 * read past the mapping - the same rule every other byte accessor follows.
	 */
	kof_child_window(pe->overlay_off, pe->overlay_len);
}
