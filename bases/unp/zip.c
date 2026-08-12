/*
 * zip.c - open an archive, one child per entry.
 *
 * The module that makes depth work. Everything a document hides is hidden one layer
 * further in than the archive itself: a .docm holds word/vbaProject.bin, which is a
 * COMPOUND FILE holding the macros, so reaching the macros is zip -> child -> OLE
 * -> gather. None of that is written here. Each layer is one module that produces
 * children, and the host runs the next layer on what came out - so this file only
 * has to turn entries into objects, and the docole module never has to know it was
 * reached through a zip.
 *
 * That is also why nothing here looks at names to decide what to open. A module that
 * only opened the entries it recognised would be a module that has to be taught
 * every new packaging convention, and the layer above already decides whether a
 * document is worth opening at all.
 *
 *
 * TWO KINDS OF ENTRY, AND ONLY ONE COSTS ANYTHING
 *
 *   - STORED entries are the file, sitting in the archive in the clear. They become
 *     WINDOWS: the child is the parent's own mapping seen through an offset, so it
 *     costs no copy, no memory and no byte of budget. Measured over 8 OpenDocument
 *     files, images are 97.4% of the bytes and every one is stored - so on a
 *     document the overwhelming majority of the content is opened for nothing.
 *
 *   - Everything else has to be decoded, and only DEFLATE can be. That is not much
 *     of a gap: measured over 280 archives holding 14939 entries, deflate is 92.7%
 *     of them and 75.9% of the compressed bytes.
 *
 * What is left over is said rather than skipped. 436 of those entries were
 * encrypted, which is 14.0% of the bytes in the collection - an archive nothing can
 * read must not come back clean, and the reason it gives has to distinguish "this
 * build has no decoder" from "there is no key", because only one of them is a gap
 * somebody can close.
 *
 *
 * BREADTH
 *
 * Every child an unpacker produces is alive at once - the module runs to completion
 * before any of them is scanned - so the memory ceiling bounds the total unpacked
 * size of ONE archive rather than its largest entry. An archive of a thousand
 * entries is the shape that finds it, and the corpus has them: the largest here
 * holds 991.
 *
 * Nothing is done about that here, deliberately. The limits are the host's, emit
 * refuses when they bind, and this stops when it is refused - which is the same
 * contract every other unpacker has. Working around it in one module would mean
 * every module needs the same workaround.
 */

#include <kofmod/kofsig.h>
#include <kofmod/zip.h>

KOF_TARGET_FORMAT(KOF_FMT_ZIP | KOF_FMT_DOCZIP);

KOF_DEFINE_UNPACK
{
	const struct kof_zip_info *z = kof_zip(ctx);
	uint32_t i, unsupported = 0, opened = 0;

	if (!z->valid)
		return;

	kof_debug("Zip.kind", z->kind);
	kof_debug("Zip.entries", z->n_entries);
	kof_debug("Zip.encrypted", z->n_encrypted);

	for (i = 0; i < z->n_entries; i++) {
		const struct kof_zip_entry *e = &z->entry[i];

		/* No local header where the directory said, so there is nothing to
		 * open. The parse already recorded it; this only has to not act on a
		 * placement it does not have. */
		if (!e->data_off || !e->csize)
			continue;

		if (e->suspicious & KOF_ZIP_ENT_ENCRYPTED)
			continue;      /* counted by the parse, reported below */

		if (e->method == KOF_ZIP_M_STORE) {
			/* Free: the child is a view of bytes that already exist. */
			if (!kof_child_window(e->data_off, e->csize))
				break;
			opened++;
			continue;
		}
		if (e->method != KOF_ZIP_M_DEFLATE) {
			unsupported++;
			continue;
		}

		/*
		 * The declared uncompressed size is not passed and not consulted.
		 * DEFLATE bounds a back reference at 32KB, so the decoder runs in
		 * fixed memory whatever the output turns out to be - and the size in
		 * the header is a number the archive chose. The host's budget is what
		 * bounds this, and it does not read that field either.
		 */
		if (kof_unpack_deflate(e->data_off, e->csize) == 0) {
			/* Either the stream is not deflate at all, or a limit bound.
			 * The host records which; carrying on to the next entry is
			 * right in both cases, because one bad entry says nothing
			 * about the ones after it. */
			continue;
		}
		if (!kof_child())
			break;
		opened++;
	}

	kof_debug("Zip.opened", opened);

	/*
	 * What could not be opened, in the order that explains it.
	 *
	 * Encryption first: it is the reason that cannot be fixed by a later build,
	 * and the first reason recorded is the one kept. An archive that is both
	 * encrypted and holds a method this engine lacks is, in practice, an
	 * encrypted archive.
	 */
	if (z->n_encrypted)
		kof_unp_broken(KOF_UNP_ENCRYPTED);
	else if (unsupported)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
}
