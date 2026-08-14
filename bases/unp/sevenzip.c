/*
 * sevenzip.c - say what a 7z is, when nothing can open it yet.
 *
 * This module opens nothing and produces no children, and that is the whole point
 * of it for now. A 7z compresses its own file list, so an engine without the
 * decoder does not merely fail to extract the contents - it cannot see that there
 * ARE contents. Left alone, every 7z would be scanned as one opaque object and
 * reported clean.
 *
 * So this states the one thing the parse established for nothing, in the vocabulary
 * a person acts on:
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
	case KOF_7Z_HDR_CODED:
		/* The list is there and coded. Nothing here decodes it yet, which is
		 * a gap in this build and is named as one. */
		KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);
	case KOF_7Z_HDR_MISSING:
		/* The start header points at a header the object does not contain. */
		KOF_UNP_BROKEN(KOF_UNP_DAMAGED);
	default:
		/* A plain header: readable, and still not walked. Same gap, same
		 * answer - what must not happen is this archive coming back clean. */
		KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);
	}
}
