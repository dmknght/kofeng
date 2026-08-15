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
	uint32_t i, opened = 0, unreached = 0, method;

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
		break;

	default:
		/* The start header points at a header the object does not contain. */
		KOF_UNP_BROKEN(KOF_UNP_DAMAGED);
	}

	/*
	 * The content, one folder at a time.
	 *
	 * A folder is 7z's unit of decompression: one coder over one run of packed
	 * bytes, decoding to every file in it end to end. Emitting it whole rather
	 * than splitting it into files is the same choice the compound file module
	 * makes with a macro region - the bytes become searchable, which is what a
	 * scan wants, and cutting them into files needs a second table this does not
	 * read.
	 *
	 * Everything here was reported UNSUPPORTED until the engine grew an LZMA2
	 * decoder. Measured over 369 archives, 258 have a folder this can locate and
	 * every one of them is LZMA2; the rest chain a filter in front of the coder,
	 * which is still named rather than guessed at.
	 */
	for (i = 0; i < z->n_folders; i++) {
		const struct kof_7z_folder *fo = &z->folder[i];

		if (!fo->pack_size || !fo->unpack_size)
			continue;
		if (fo->coder != KOF_7Z_CODER_LZMA2) {
			unreached++;
			continue;
		}
		/*
		 * A filter in front of the coder is undone after it, and only the
		 * one that appears in practice is undone at all. Measured here: 334
		 * folders have no filter, 77 use the x86 branch transform, and the
		 * two that use something else are named rather than guessed at -
		 * running the coder without its transform yields bytes that look
		 * like a program and are not one.
		 */
		if (fo->filter && fo->filter != KOF_7Z_CODER_BCJ_X86) {
			kof_debug("SevenZip.filter", fo->filter);
			unreached++;
			continue;
		}
		method = fo->filter ? KOF_UNP_LZMA2_BCJ_X86 : KOF_UNP_LZMA2;
		if (kof_unpack_at(method, fo->pack_off, fo->pack_size,
				  fo->unpack_size) == 0) {
			unreached++;
			continue;
		}
		if (!kof_child())
			KOF_UNP_BROKEN(KOF_UNP_LIMIT);
		opened++;
	}

	kof_debug("SevenZip.folders", z->n_folders);
	kof_debug("SevenZip.opened", opened);

	/*
	 * A folder the parse could not place, or a coder this does not run. Named
	 * rather than passed over: an archive whose content was never looked at must
	 * not come back clean.
	 */
	if (z->anomalies & KOF_7Z_ANOM_CODER_CHAIN)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
	else if (unreached)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
	else if (z->n_folders == 0)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
}
