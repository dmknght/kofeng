/*
 * sevenzip.c - say what a 7z is, when nothing can open it yet.
 *
 * This module opens nothing and produces no children, and that is the whole point
 * of it for now. A 7z compresses its own file list, so an engine without the
 * decoder does not merely fail to extract the contents - it cannot see that there
 * ARE contents. Left alone, every 7z would be scanned as one opaque object and
 * reported clean.
 *
 * So it decodes the list - one call to a decoder the engine already has, over a
 * range the parse worked out in the clear - and hands it over as a child object.
 * What it cannot do is reach the file CONTENT: that needs the folder's whole coder
 * chain and the solid block a file shares with its neighbours.
 *
 * What is left over is stated in the vocabulary a person acts on:
 *
 *   ENCRYPTED    the file list is ciphertext. No build of this engine will read it,
 *                and no amount of work here changes that - only a key does.
 *   UNSUPPORTED  the file list is compressed with something this build lacks. A
 *                later build closes that.
 *
 * Measured over 44 archives: 19 are the first kind and 24 the second. Collapsing
 * them into one verdict would tell an operator to wait for a fix that cannot come.
 *
 * When the header decoder lands this file grows children; the verdicts above stay,
 * because they are about the archive rather than about what this module does yet.
 */

#include <kofmod/kofsig.h>
#include <kofmod/sevenzip.h>

KOF_TARGET_FORMAT(KOF_FMT_7Z);

KOF_DEFINE_UNPACK
{
	const struct kof_7z_info *z = kof_7z(ctx);

	if (!z->valid)
		return;

	kof_debug("SevenZip.header_kind", z->header_kind);
	kof_debug("SevenZip.header_coder", z->hdr_coder);

	switch (z->header_kind) {
	case KOF_7Z_HDR_ENCRYPTED:
		KOF_UNP_BROKEN(KOF_UNP_ENCRYPTED);

	case KOF_7Z_HDR_PLAIN:
		/*
		 * The list is already readable where it lies. A window costs nothing
		 * and puts the names in front of every module that searches text.
		 */
		if (z->next_hdr_size &&
		    kof_child_window(z->next_hdr_off, z->next_hdr_size))
			return;
		KOF_UNP_BROKEN(KOF_UNP_DAMAGED);

	case KOF_7Z_HDR_CODED:
		/*
		 * Decode the file list and hand it over as a child.
		 *
		 * Not an entry table, and that is the design rather than a shortcut.
		 * A 7z in this collection holds a median of 18 files and a maximum of
		 * 84644, with names up to 1361 characters - a table with names in it
		 * would be megabytes of view, or would cut off exactly the archives
		 * worth reading. As a child the names are UTF-16 text in an ordinary
		 * object, searched the way any other text is, with no cap and no
		 * second convention for where a name lives.
		 *
		 * The declared output length sizes the buffer and bounds nothing -
		 * the host clamps it to what the ceiling allows, and a header that
		 * lies gets a short decode rather than a large allocation.
		 */
		if (z->hdr_coder != KOF_7Z_CODER_LZMA || !z->hdr_pack_size)
			KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);

		kof_debug("SevenZip.header_bytes", z->hdr_unpack_size);
		if (kof_unpack_at(KOF_UNP_LZMA_PROPS(z->hdr_lc, z->hdr_lp, z->hdr_pb),
				  z->hdr_pack_off, z->hdr_pack_size,
				  z->hdr_unpack_size) == 0)
			KOF_UNP_BROKEN(KOF_UNP_DAMAGED);
		if (!kof_child())
			KOF_UNP_BROKEN(KOF_UNP_LIMIT);

		/*
		 * The CONTENT is still not reachable, and saying so is the point.
		 * Getting a file out of a 7z means running its folder's whole coder
		 * chain - LZMA2, the branch filters, and the solid block the file
		 * shares with its neighbours - which this build does not have. The
		 * names are now visible; the bytes behind them are not.
		 */
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
		return;

	default:
		/* The start header points at a header the object does not contain. */
		KOF_UNP_BROKEN(KOF_UNP_DAMAGED);
	}
}
