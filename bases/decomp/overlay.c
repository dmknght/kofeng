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

/*
 * ---- and what the bytes say they are ------------------------------------
 *
 * SIZE AND ENTROPY CANNOT ANSWER THE QUESTION THIS MODULE HAS TO ASK.
 *
 * A page floor removes slack and an entropy floor removes filler, and both
 * were added here for exactly those cases. Neither says whether the overlay is
 * a FILE, and that is the only thing that makes it worth an object of its own.
 * Measured over 7909 PE samples in this corpus, 4060 overlays cleared both
 * floors - 51 per cent of every PE scanned - and the largest of them are
 * megabytes of opaque bytes: the sample this was reported on carries 12.5 MB
 * beginning b5 38 80 3d, which is nothing, and got a whole object, an
 * identification, a budget and a pass through every module for it.
 *
 * A WINDOW IS NOT A DISCOVERY. The child is the parent's own bytes under a
 * second name - no copy, no decode, nothing produced. It is worth making only
 * when a DIFFERENT reader will take it: a zip's members get extracted, a
 * carried PE gets parsed. When nothing will, the bytes are already reachable
 * where they are, as KOF_SCAN_PE_OVERLAY of the parent, and a rule written
 * against that region matches them today.
 *
 * SO THE TEST IS "DOES SOMETHING CLAIM IT", asked of the leading bytes. The
 * same 4060 break down as:
 *
 *     zlib                         3571     a compressed stream, opened below
 *     Rar, Zip, PE, Gzip            107     a container, handed over
 *     nothing at all                 382     left where it is
 *
 * A TABLE HERE IS A FLOOR AND NOT A SECOND IDENTIFIER. The engine's own
 * identification runs on the child after this and is the authority on what it
 * is; this only decides whether to offer one. A format missing from the list
 * is an overlay left in its parent - a miss, which the region still covers -
 * and never a wrong answer. That asymmetry is why a short list is safe here
 * and would not be safe anywhere that has to be complete.
 */
static int magic_at(const struct kof_obj_ctx *ctx, uint64_t at,
		    const char *m, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if ((uint8_t)kof_u8(at + i) != (uint8_t)m[i])
			return 0;
	return 1;
}

static int names_a_container(const struct kof_obj_ctx *ctx, uint64_t at)
{
	return magic_at(ctx, at, "MZ", 2)               ||  /* PE, and DOS   */
	       magic_at(ctx, at, "\x7f" "ELF", 4)        ||
	       magic_at(ctx, at, "PK\x03\x04", 4)        ||  /* zip           */
	       magic_at(ctx, at, "PK\x05\x06", 4)        ||  /* empty zip     */
	       magic_at(ctx, at, "Rar!", 4)             ||
	       magic_at(ctx, at, "7z\xbc\xaf\x27\x1c", 6) ||
	       magic_at(ctx, at, "MSCF", 4)             ||  /* cab           */
	       magic_at(ctx, at, "\x1f\x8b", 2)          ||  /* gzip          */
	       magic_at(ctx, at, "\xfd" "7zXZ", 6)       ||
	       magic_at(ctx, at, "BZh", 3)              ||
	       magic_at(ctx, at, "\xd0\xcf\x11\xe0", 4)  ||  /* ole           */
	       magic_at(ctx, at, "ITSF", 4)             ||  /* chm           */
	       magic_at(ctx, at, "%PDF", 4)             ||
	       magic_at(ctx, at, "{\\rt", 4)             ||  /* rtf           */
	       /* NSIS writes its own header past the last section, and the
		* four bytes before the name are the flag word. */
	       magic_at(ctx, at + 4u, "\xef\xbe\xad\xde" "Nullsoft", 12);
}

/*
 * A ZLIB STREAM IS NOT A FILE AND IS STILL WORTH OPENING - so it is opened
 * here rather than handed over.
 *
 * It is 88 per cent of everything past the last section in this corpus. A
 * window over it identifies as `unrecognised`, because raw zlib has no format
 * row in this engine; what then reads it is bases/decomp/zlibraw.c, running on
 * that child. So the tree held the compressed megabytes as one object and the
 * bytes they decode to as a second one beneath it, and the first of the two
 * said nothing the parent's own overlay region did not already say. One sample
 * reported this way carried 10.9 MB under 291 bytes of content.
 *
 * Decompressed straight out of the parent, there is one child and it is the
 * content. The two-byte header test is RFC 1950's own - the same one
 * zlibraw.c applies, and the reason that module and this one do not share a
 * line is that they are anchored differently: it reads an object that IS a
 * stream, this reads a stream that sits at a known offset inside one.
 */
static int zlib_header(const struct kof_obj_ctx *ctx, uint64_t at)
{
	uint32_t cmf = kof_u8(at), flg = kof_u8(at + 1u);

	return (cmf & 0x0fu) == 8u && (cmf >> 4) <= 7u &&
	       !(flg & 0x20u) && ((cmf << 8) | flg) % 31u == 0;
}

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
	 * A PAGE FIRST, AND IT IS NOW ONLY AN ARITHMETIC GUARD.
	 *
	 * What it was doing - removing the alignment slack an ordinary build
	 * leaves - the test below does better, because slack has no magic.
	 * It stays because everything after it reads up to sixteen bytes and
	 * a floor is cheaper than four bounds checks.
	 */
	if (pe->overlay_len < PAGE)
		return;

	/*
	 * THE COMPRESSED CASE FIRST, because it is most of them and because
	 * what it produces is content rather than a second view of the parent.
	 * Past the two header bytes; DEFLATE says where it ends.
	 */
	if (zlib_header(ctx, pe->overlay_off)) {
		if (!kof_unpack_deflate(pe->overlay_off + 2u,
					pe->overlay_len - 2u))
			return;
		if (!kof_child())
			KOF_UNP_BROKEN(KOF_UNP_LIMIT);
		return;
	}

	/*
	 * AND OTHERWISE ONLY WHAT SOMETHING WILL READ. An overlay that names
	 * no format stays in its parent, where KOF_SCAN_PE_OVERLAY already
	 * reaches it - see the note above names_a_container.
	 */
	if (!names_a_container(ctx, pe->overlay_off))
		return;

	/*
	 * No length check and no bounds arithmetic here on purpose. The host
	 * clips the window to what the object actually has, so an overlay whose
	 * declared extent runs past the end yields a shorter child rather than a
	 * read past the mapping - the same rule every other byte accessor follows.
	 */
	if (!kof_child_window(pe->overlay_off, pe->overlay_len))
		KOF_UNP_BROKEN(KOF_UNP_LIMIT);
}
